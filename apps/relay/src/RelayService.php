<?php
class RelayService
{
    private array $config;
    private ?array $snapshotManifest = null;
    private bool $snapshotManifestLoaded = false;

    public function __construct(array $config)
    {
        $this->config = $config;
        $this->ensureCacheDir();
    }

    public function handle(): void
    {
        if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
            $this->respond(405, 'Only GET is supported.');
            return;
        }

        $this->applySecurityHeaders();
        if ($this->config['rate_limit_enabled'] ?? false) {
            $limit = $this->checkRateLimit();
            if (!$limit['allowed']) {
                if ($limit['retry_after'] !== null) {
                    header('Retry-After: ' . $limit['retry_after']);
                }
                $this->respond(429, $limit['message'], 'RATE_LIMIT');
                return;
            }
        }

        $mode = $this->normalizeMode($this->config['mode'] ?? 'hybrid');
        $path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
        $query = $_SERVER['QUERY_STRING'] ?? '';
        $fullPath = $path;
        if ($query !== '') {
            $fullPath .= '?' . $query;
        }

        if ($this->config['request_validation_enabled'] ?? false) {
            $pattern = $this->config['request_validation_pattern'] ?? '';
            if (!is_string($pattern) || $pattern === '') {
                $pattern = '/^\/[A-Za-z0-9\-._~%\/]+$/';
            }
            $match = @preg_match($pattern, $path);
            if ($match !== 1) {
                $this->respond(400, 'Invalid request path.');
                return;
            }
        }

        $rewrittenPath = $this->maybeRewritePath($path);
        if ($rewrittenPath === null) {
            $this->log('Path rewrite failed for ' . $path);
            $this->respond(404, 'Unknown subscription path.');
            return;
        }
        $path = $rewrittenPath;

        if ($path === '/healthz') {
            $this->respond(200, 'ok');
            return;
        }

        if (!$this->isClientAllowed()) {
            $this->respond(403, 'Client is not allowed.');
            return;
        }

        if (!$this->isAuthorized()) {
            $this->respond(401, 'Unauthorized.');
            return;
        }

        $cacheBaseUrl = $this->config['cache_source_base_url'] ?? '';
        if ($cacheBaseUrl === '') {
            $cacheBaseUrl = $this->config['upstream_base_url'] ?? '';
        }

        if ($cacheBaseUrl === '' && $mode === 'cold') {
            $this->respond(500, 'CACHE_SOURCE_BASE_URL is not configured.');
            return;
        }

        $cacheUrl = rtrim($cacheBaseUrl, '/') . $path;
        if ($query !== '') {
            $cacheUrl .= '?' . $query;
        }

        $bypassCache = $this->shouldBypassCache();

        if ($mode === 'cold') {
            $coldResult = $this->fetchFromCacheCold($cacheUrl, $fullPath);
            if ($coldResult['status'] === 'hit') {
                $this->outputCached($coldResult);
                return;
            }
            if ($coldResult['status'] === 'missing') {
                $this->respond(404, 'Snapshot entry not registered.');
                return;
            }
            if ($coldResult['status'] === 'expired') {
                $this->respond(410, 'Snapshot expired.');
                return;
            }
            if ($coldResult['status'] === 'error') {
                $this->respond(500, 'Unable to read cached payload.');
                return;
            }
            $this->respond(404, 'Cached payload not found.');
            return;
        }

        if ($mode === 'hybrid' && $this->config['cache_enabled'] && !$bypassCache) {
            if ($this->shouldUseFailover($cacheUrl)) {
                $cached = $this->fetchFromCache($cacheUrl);
                if ($cached !== null) {
                    $this->outputCached($cached);
                    return;
                }
            }
        }

        if ($this->config['upstream_base_url'] === '') {
            $this->respond(500, 'Upstream base URL is not configured.');
            return;
        }

        $targetUrl = rtrim($this->config['upstream_base_url'], '/') . $path;
        if ($query !== '') {
            $targetUrl .= '?' . $query;
        }

        $result = $this->proxyRequest($targetUrl);
        $httpCode = $result['info']['http_code'] ?? 0;
        if ($result['error_no'] !== 0) {
            $this->log("cURL error ({$result['error_no']}): {$result['error_msg']} for {$targetUrl}");
            if ($mode === 'hybrid') {
                $this->markFailover($cacheUrl, $httpCode, $result['error_msg'] ?? '');
            }
            $this->respond(502, 'Upstream fetch failed.');
            return;
        }

        if ($httpCode >= 500 && $mode === 'hybrid') {
            $this->markFailover($cacheUrl, $httpCode, 'Upstream returned ' . $httpCode);
        } else {
            $this->clearFailover($cacheUrl);
        }

        $response = $result['response'];
        $rawResponse = $response;
        if ($response !== '') {
            $response = $this->injectMessagesIntoResponse($response, $result['info']);
        }
        $injected = $response !== $rawResponse;

        if ($this->config['cache_enabled'] && !$bypassCache && $httpCode === 200) {
            $this->storeInCache($cacheUrl, $response, $result['info'], $injected);
            $this->maybeCleanupCache();
        }

        $this->outputResponse($response, $result['info'], $bypassCache);
    }

    private function isClientAllowed(): bool
    {
        if (empty($this->config['allowed_clients'])) {
            return true;
        }
        $clientIp = $_SERVER['REMOTE_ADDR'] ?? '';
        return in_array($clientIp, $this->config['allowed_clients'], true);
    }

    private function isAuthorized(): bool
    {
        $token = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
        if ($token !== '' && stripos($token, 'Bearer ') === 0) {
            $token = substr($token, 7);
        }

        if ($token === '' && isset($_GET['token'])) {
            $token = $_GET['token'];
        }

        if ($this->config['auth_token'] === '') {
            return true;
        }

        return hash_equals($this->config['auth_token'], $token);
    }

    private function shouldBypassCache(): bool
    {
        if (!$this->config['cache_enabled']) {
            return true;
        }

        if (isset($_GET['cache']) && $_GET['cache'] === '0') {
            return true;
        }

        $cacheControl = $_SERVER['HTTP_CACHE_CONTROL'] ?? '';
        if ($cacheControl !== '' && stripos($cacheControl, 'no-cache') !== false) {
            return true;
        }

        return false;
    }

    private function proxyRequest(string $url): array
    {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 5,
            CURLOPT_CONNECTTIMEOUT => $this->config['connect_timeout'],
            CURLOPT_TIMEOUT => $this->config['transfer_timeout'],
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_HTTPHEADER => [
                'User-Agent: RelayService/1.0',
                'Accept: */*',
                'Accept-Encoding: identity',
            ],
        ]);

        $response = curl_exec($ch);
        $errorNo = curl_errno($ch);
        $errorMsg = curl_error($ch);
        $info = curl_getinfo($ch);
        curl_close($ch);

        return [
            'response' => $response === false ? '' : $response,
            'error_no' => $errorNo,
            'error_msg' => $errorMsg,
            'info' => $info,
        ];
    }

    private function fetchFromCache(string $cacheUrl): ?array
    {
        $key = md5($cacheUrl);
        $path = $this->config['cache_dir'] . '/' . $key;
        if (!is_file($path)) {
            return null;
        }

        $stale = false;
        $ttl = $this->config['cache_ttl'];
        if ($ttl >= 0 && (time() - filemtime($path)) > $ttl) {
            $metaPath = $path . '.meta';
            if (!$this->isSnapshotValid($cacheUrl)) {
                @unlink($path);
                if (is_file($metaPath)) {
                    @unlink($metaPath);
                }
                return null;
            }
            $stale = true;
            $this->log('Serving stale snapshot cache for ' . $cacheUrl);
        }

        $content = @file_get_contents($path);
        if ($content === false) {
            return null;
        }

        $metaPath = $metaPath ?? $path . '.meta';
        $meta = ['http_code' => 200, 'content_type' => 'application/octet-stream', 'headers' => []];
        if (is_file($metaPath)) {
            $metaContent = @file_get_contents($metaPath);
            if ($metaContent !== false) {
                $meta = json_decode($metaContent, true) ?: $meta;
            }
        }

        return ['body' => $content, 'meta' => $meta, 'snapshot_stale' => $stale];
    }

    private function storeInCache(string $cacheUrl, string $response, array $info, bool $injected): void
    {
        $key = md5($cacheUrl);
        $path = $this->config['cache_dir'] . '/' . $key;
        $headerSize = $info['header_size'] ?? 0;
        $body = substr($response, $headerSize);
        $headers = substr($response, 0, $headerSize);

        @file_put_contents($path, $body, LOCK_EX);
        @file_put_contents($path . '.meta', json_encode([
            'http_code' => $info['http_code'] ?? 200,
            'content_type' => $info['content_type'] ?? 'application/octet-stream',
            'headers' => $this->headerListToArray($headers),
            'injected' => $injected,
        ]), LOCK_EX);
    }

    private function outputCached(array $cached): void
    {
        http_response_code($cached['meta']['http_code'] ?? 200);
        $cacheStatus = !empty($cached['snapshot_stale']) ? 'STALE' : 'HIT';
        header('Relay-Cache: ' . $cacheStatus);
        if (!empty($cached['meta']['content_type'])) {
            header('Content-Type: ' . $cached['meta']['content_type']);
        }
        if (!empty($cached['meta']['headers'])) {
            foreach ($cached['meta']['headers'] as $header) {
                if (stripos($header, 'content-type:') === 0) {
                    continue;
                }
                header($header, false);
            }
        }
        $this->logAccess($cached['meta']['http_code'] ?? 200, $cacheStatus);
        $body = $cached['body'];
        $messageLines = $this->getLiveInjectLinesForCache($cached['meta'] ?? []);
        if ($messageLines !== [] && !$this->alreadyInjected($body, $messageLines)) {
            $body = $this->injectMessagesIntoBody($body, $messageLines);
        }
        echo $body;
    }

    private function getLiveInjectLinesForCache(array $meta): array
    {
        $allow = (getenv('RELAY_INJECT_ON_CACHE_OUTPUT') ?: '1') === '1';
        if (!$allow) {
            return [];
        }
        if (!empty($meta['injected'])) {
            return [];
        }
        $messages = $this->config['live_inject_messages'] ?? [];
        if (!is_array($messages) || $messages === []) {
            return [];
        }
        return array_values(array_filter(array_map('trim', $messages), static fn ($value) => $value !== ''));
    }

    private function alreadyInjected(string $body, array $messageLines): bool
    {
        if ($messageLines === []) {
            return false;
        }

        if (strpos($body, "\0") !== false) {
            return false;
        }

        $prefix = implode("\n", $messageLines) . "\n";
        $trimmed = trim($body);
        if ($trimmed === '') {
            return false;
        }

        $decoded = base64_decode($trimmed, true);
        if ($decoded !== false) {
            $decodedTrimmed = rtrim($decoded, "\r\n");
            return strpos($decodedTrimmed, $prefix) === 0;
        }

        $bodyTrimmed = rtrim($body, "\r\n");
        return strpos($bodyTrimmed, $prefix) === 0;
    }

    private function outputResponse(string $response, array $info, bool $bypassCache): void
    {
        $headerSize = $info['header_size'] ?? 0;
        $headers = substr($response, 0, $headerSize);
        $body = substr($response, $headerSize);

        http_response_code($info['http_code'] ?? 502);
        $cacheStatus = $bypassCache ? 'BYPASS' : 'MISS';
        header('Relay-Cache: ' . $cacheStatus);

        foreach (explode("\r\n", $headers) as $line) {
            if (stripos($line, 'transfer-encoding:') === 0) {
                continue;
            }
            if ($line === '') {
                continue;
            }
            header($line, false);
        }

        $this->logAccess($info['http_code'] ?? 502, $cacheStatus);
        echo $body;
    }

    private function respond(int $code, string $message, string $cacheStatus = 'ERROR'): void
    {
        http_response_code($code);
        header('Content-Type: text/plain');
        $this->logAccess($code, $cacheStatus);
        echo $message;
    }

    private function headerListToArray(string $headers): array
    {
        $lines = explode("\r\n", $headers);
        $filtered = [];
        foreach ($lines as $line) {
            if ($line === '') {
                continue;
            }
            if (stripos($line, 'HTTP/') === 0) {
                continue;
            }
            if (stripos($line, 'transfer-encoding:') === 0) {
                continue;
            }
            $filtered[] = $line;
        }
        return $filtered;
    }

    private function isSnapshotValid(string $url): bool
    {
        if (empty($this->config['snapshot_allow_stale'])) {
            return false;
        }

        $manifest = $this->loadSnapshotManifest();
        if ($manifest === null) {
            return false;
        }

        if (!empty($manifest['expires_at'])) {
            $expires = strtotime((string)$manifest['expires_at']);
            if ($expires !== false && $expires < time()) {
                return false;
            }
        }

        $target = $this->normalizeSnapshotKey($url);
        foreach ($manifest['entries'] ?? [] as $entry) {
            if (!is_array($entry)) {
                continue;
            }
            if (($entry['status'] ?? null) !== 'stored') {
                continue;
            }
            $entryPath = $entry['path'] ?? null;
            if (!is_string($entryPath)) {
                continue;
            }
            if ($entryPath === $target) {
                return true;
            }
        }

        return false;
    }

    private function loadSnapshotManifest(): ?array
    {
        if ($this->snapshotManifestLoaded) {
            return $this->snapshotManifest;
        }

        $this->snapshotManifestLoaded = true;

        $path = $this->config['snapshot_manifest'] ?? '';
        if (!is_string($path) || $path === '' || !is_file($path)) {
            $this->snapshotManifest = null;
            return null;
        }

        $content = @file_get_contents($path);
        if ($content === false) {
            $this->snapshotManifest = null;
            return null;
        }

        $decoded = json_decode($content, true);
        if (!is_array($decoded)) {
            $this->snapshotManifest = null;
            return null;
        }

        $this->snapshotManifest = $decoded;
        return $this->snapshotManifest;
    }

    private function normalizeSnapshotKey(string $url): string
    {
        $parsed = parse_url($url);
        $path = $parsed['path'] ?? '/';
        $query = $parsed['query'] ?? '';
        if ($query !== '') {
            $path .= '?' . $query;
        }
        return $path;
    }

    private function fetchFromCacheCold(string $cacheUrl, string $fullPath): array
    {
        $key = md5($cacheUrl);
        $path = $this->config['cache_dir'] . '/' . $key;
        if (!is_file($path)) {
            return ['status' => 'miss'];
        }

        $status = $this->evaluateManifestStatus($fullPath);
        if ($status === 'missing') {
            return ['status' => 'missing'];
        }
        if ($status === 'expired' && empty($this->config['cache_allow_stale'])) {
            return ['status' => 'expired'];
        }

        $content = @file_get_contents($path);
        if ($content === false) {
            return ['status' => 'error'];
        }

        $metaPath = $path . '.meta';
        $meta = ['http_code' => 200, 'content_type' => 'application/octet-stream', 'headers' => []];
        if (is_file($metaPath)) {
            $metaContent = @file_get_contents($metaPath);
            if ($metaContent !== false) {
                $meta = json_decode($metaContent, true) ?: $meta;
            }
        }

        return [
            'status' => 'hit',
            'body' => $content,
            'meta' => $meta,
            'snapshot_stale' => $status === 'expired',
        ];
    }

    private function evaluateManifestStatus(string $fullPath): string
    {
        $manifest = $this->loadSnapshotManifest();
        if ($manifest === null) {
            return 'fresh';
        }

        if (!empty($manifest['expires_at'])) {
            $expires = strtotime((string)$manifest['expires_at']);
            if ($expires !== false && $expires < time()) {
                return 'expired';
            }
        }

        foreach ($manifest['entries'] ?? [] as $entry) {
            if (!is_array($entry)) {
                continue;
            }
            if (($entry['status'] ?? '') !== 'stored') {
                continue;
            }
            if (!isset($entry['path']) || !is_string($entry['path'])) {
                continue;
            }
            if ($entry['path'] === $fullPath) {
                return 'fresh';
            }
        }

        return 'missing';
    }

    private function normalizeMode(string $mode): string
    {
        $mode = strtolower(trim($mode));
        if ($mode === 'live' || $mode === 'cold' || $mode === 'hybrid') {
            return $mode;
        }
        return 'hybrid';
    }

    private function ensureCacheDir(): void
    {
        if (!is_dir($this->config['cache_dir'])) {
            @mkdir($this->config['cache_dir'], 0755, true);
        }
    }

    private function maybeRewritePath(string $path): ?string
    {
        $template = $this->config['path_template'] ?? '';
        if ($template === '') {
            return $path;
        }

        $uuid = $this->extractUuid($path);
        if ($uuid === null) {
            return null;
        }

        try {
            $rendered = vsprintf($template, [$uuid]);
        } catch (ValueError $e) {
            return null;
        }

        if ($rendered === '') {
            return null;
        }

        if ($rendered[0] !== '/') {
            $rendered = '/' . $rendered;
        }

        return $rendered;
    }

    private function extractUuid(string $path): ?string
    {
        if (preg_match('/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/', $path, $matches) !== 1) {
            return null;
        }

        return strtolower($matches[0]);
    }

    private function log(string $message): void
    {
        $line = date('c') . ' ' . $message . "\n";
        @file_put_contents($this->config['log_file'], $line, FILE_APPEND);
    }

    private function applySecurityHeaders(): void
    {
        if (empty($this->config['security_headers'])) {
            return;
        }

        header('X-Content-Type-Options: nosniff');
        header('X-Frame-Options: DENY');
        header('Referrer-Policy: strict-origin-when-cross-origin');
        header('Permissions-Policy: geolocation=(), microphone=(), camera=()');
    }

    private function getClientIp(): string
    {
        $ip = $_SERVER['HTTP_CF_CONNECTING_IP'] ?? '';
        if ($ip === '') {
            $forwarded = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '';
            if ($forwarded !== '') {
                $parts = explode(',', $forwarded);
                $ip = trim($parts[0] ?? '');
            }
        }
        if ($ip === '') {
            $ip = $_SERVER['REMOTE_ADDR'] ?? '';
        }
        return $ip;
    }

    private function checkRateLimit(): array
    {
        $clientIp = $this->getClientIp();
        if ($clientIp === '') {
            return ['allowed' => true, 'retry_after' => null, 'message' => ''];
        }

        $whitelist = $this->config['rate_limit_whitelist'] ?? [];
        if (is_array($whitelist) && in_array($clientIp, $whitelist, true)) {
            return ['allowed' => true, 'retry_after' => null, 'message' => ''];
        }

        $dir = $this->config['rate_limit_dir'] ?? '';
        if (!is_string($dir) || $dir === '') {
            return ['allowed' => true, 'retry_after' => null, 'message' => ''];
        }

        $limit = max(1, (int)($this->config['rate_limit_count'] ?? 100));
        $window = max(1, (int)($this->config['rate_limit_window'] ?? 60));
        $burst = max(1, (int)($this->config['rate_limit_burst'] ?? 20));
        $graceful = !empty($this->config['rate_limit_graceful']);

        $path = rtrim($dir, '/\\') . '/' . md5($clientIp);
        $data = ['count' => 0, 'time' => 0, 'burst' => 0, 'last_request' => 0];
        if (is_file($path)) {
            $content = @file_get_contents($path);
            if ($content !== false) {
                $decoded = json_decode($content, true);
                if (is_array($decoded)) {
                    $data = array_merge($data, $decoded);
                }
            }
        }

        $now = time();
        $diff = $now - (int)($data['time'] ?? 0);
        if ($diff > $window) {
            $data = ['count' => 1, 'time' => $now, 'burst' => 1, 'last_request' => $now];
        } else {
            $data['count'] = (int)($data['count'] ?? 0) + 1;
            $data['burst'] = (int)($data['burst'] ?? 0) + 1;
            $data['last_request'] = $now;
        }

        @file_put_contents($path, json_encode($data), LOCK_EX);

        $retryAfter = $window - $diff;
        if ($data['burst'] > $burst || $data['count'] > $limit) {
            $message = $graceful
                ? 'Rate limit exceeded. Please try again in ' . max(1, $retryAfter) . ' seconds.'
                : 'Rate limit exceeded.';
            return [
                'allowed' => false,
                'retry_after' => $graceful ? max(1, $retryAfter) : null,
                'message' => $message,
            ];
        }

        return ['allowed' => true, 'retry_after' => null, 'message' => ''];
    }

    private function logAccess(int $statusCode, string $cacheStatus): void
    {
        $logFile = $this->config['access_log_file'] ?? '';
        if (!is_string($logFile) || $logFile === '') {
            return;
        }

        $path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
        if ($path === '/healthz') {
            return;
        }

        $clientIp = $this->getClientIp();
        $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
        $uri = $_SERVER['REQUEST_URI'] ?? '/';
        $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $line = implode('|', [
            date('c'),
            $clientIp,
            $method,
            $uri,
            (string)$statusCode,
            $cacheStatus,
            $ua,
        ]) . "\n";

        @file_put_contents($logFile, $line, FILE_APPEND);
    }

    private function maybeCleanupCache(): void
    {
        $maxSizeMb = (int)($this->config['cache_max_size_mb'] ?? 0);
        if ($maxSizeMb <= 0) {
            return;
        }

        $chance = (int)($this->config['cache_cleanup_chance'] ?? 1);
        $chance = max(0, min(100, $chance));
        if ($chance === 0 || rand(1, 100) > $chance) {
            return;
        }

        $cacheDir = $this->config['cache_dir'] ?? '';
        if (!is_string($cacheDir) || !is_dir($cacheDir)) {
            return;
        }

        $files = [];
        $total = 0;
        foreach (new DirectoryIterator($cacheDir) as $file) {
            if ($file->isDot() || !$file->isFile()) {
                continue;
            }
            if ($file->getFilename() === 'snapshot_manifest.json') {
                continue;
            }
            $path = $file->getPathname();
            $size = $file->getSize();
            $total += $size;
            $files[] = [
                'path' => $path,
                'mtime' => $file->getMTime(),
                'size' => $size,
            ];
        }

        $maxBytes = $maxSizeMb * 1024 * 1024;
        if ($total <= $maxBytes) {
            return;
        }

        usort($files, static fn(array $a, array $b): int => $a['mtime'] <=> $b['mtime']);
        $target = (int)($maxBytes * 0.8);
        foreach ($files as $file) {
            if ($total <= $target) {
                break;
            }
            $path = $file['path'];
            if (is_file($path)) {
                @unlink($path);
                $total -= $file['size'];
            }
            if (substr($path, -5) === '.meta') {
                $base = substr($path, 0, -5);
                if (is_file($base)) {
                    $total -= filesize($base) ?: 0;
                    @unlink($base);
                }
            } else {
                $meta = $path . '.meta';
                if (is_file($meta)) {
                    $total -= filesize($meta) ?: 0;
                    @unlink($meta);
                }
            }
        }
    }

    private function injectMessagesIntoResponse(string $response, array $info): string
    {
        $messages = $this->config['live_inject_messages'] ?? [];
        if (!is_array($messages) || $messages === []) {
            $messages = $this->config['snapshot_inject_messages'] ?? [];
        }
        if (!is_array($messages) || $messages === []) {
            return $response;
        }

        $messageLines = array_values(array_filter(array_map('trim', $messages), static fn ($value) => $value !== ''));
        if ($messageLines === []) {
            return $response;
        }

        $headerSize = $info['header_size'] ?? 0;
        $headers = substr($response, 0, $headerSize);
        $body = substr($response, $headerSize);

        $body = $this->injectMessagesIntoBody($body, $messageLines);
        return $headers . $body;
    }

    private function injectMessagesIntoBody(string $body, array $messageLines): string
    {
        if (strpos($body, "\0") !== false) {
            return $body;
        }

        $trimmed = trim($body);
        if ($trimmed === '') {
            return $body;
        }

        $decoded = base64_decode($trimmed, true);
        if ($decoded !== false) {
            $decodedTrimmed = rtrim($decoded, "\r\n");
            $prefixed = implode("\n", $messageLines) . "\n" . $decodedTrimmed . "\n";
            return base64_encode($prefixed);
        }

        $bodyTrimmed = rtrim($body, "\r\n");
        $prefixed = implode("\n", $messageLines) . "\n" . $bodyTrimmed . "\n";
        return $prefixed;
    }

    private function shouldUseFailover(string $cacheUrl): bool
    {
        $ttl = (int)($this->config['hybrid_failover_ttl'] ?? 0);
        if ($ttl <= 0) {
            return false;
        }

        $path = $this->failoverPath($cacheUrl);
        if (!is_file($path)) {
            return false;
        }

        $content = @file_get_contents($path);
        if ($content === false) {
            return false;
        }

        $decoded = json_decode($content, true);
        if (!is_array($decoded) || empty($decoded['time'])) {
            return false;
        }

        $age = time() - (int)$decoded['time'];
        if ($age > $ttl) {
            @unlink($path);
            return false;
        }

        return true;
    }

    private function markFailover(string $cacheUrl, int $httpCode, string $message): void
    {
        $ttl = (int)($this->config['hybrid_failover_ttl'] ?? 0);
        if ($ttl <= 0) {
            return;
        }

        $payload = [
            'time' => time(),
            'http_code' => $httpCode,
            'message' => $message,
        ];

        @file_put_contents($this->failoverPath($cacheUrl), json_encode($payload), LOCK_EX);
    }

    private function clearFailover(string $cacheUrl): void
    {
        $path = $this->failoverPath($cacheUrl);
        if (is_file($path)) {
            @unlink($path);
        }
    }

    private function failoverPath(string $cacheUrl): string
    {
        $key = md5($cacheUrl);
        return rtrim($this->config['cache_dir'], '/\\') . '/' . $key . '.fail';
    }
}
