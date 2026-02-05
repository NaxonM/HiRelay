<?php
class SnapshotSeeder
{
    private array $config;

    public function __construct(array $config)
    {
        $this->config = $config;
        $this->ensureCacheDir();
    }

    public function seedFromBackup(string $backupPath, array $options = []): array
    {
        if ($backupPath === '') {
            throw new InvalidArgumentException('Backup path must be provided.');
        }

        if (!is_file($backupPath)) {
            throw new InvalidArgumentException("Backup file not found: {$backupPath}");
        }

        $decoded = json_decode((string)file_get_contents($backupPath), true);
        if (!is_array($decoded)) {
            throw new RuntimeException('Backup file is not valid JSON.');
        }

        $users = $decoded['users'] ?? [];
        if (!is_array($users) || $users === []) {
            throw new RuntimeException('Backup JSON does not contain a users array.');
        }

        $pathTemplates = $this->computePathTemplates($options);
        $ttl = $this->computeTtl($options);
        $force = (bool)($options['force'] ?? false);

        $results = [
            'generated_at' => date('c'),
            'expires_at' => $ttl > 0 ? date('c', time() + $ttl) : null,
            'backup_path' => realpath($backupPath) ?: $backupPath,
            'total_users' => count($users),
            'total_paths' => 0,
            'success' => 0,
            'skipped' => 0,
            'failures' => 0,
            'entries' => [],
        ];

        $pending = [];

        foreach ($users as $user) {
            if (!is_array($user)) {
                continue;
            }
            if (!($user['enable'] ?? false)) {
                $results['skipped']++;
                continue;
            }
            $uuid = $user['uuid'] ?? null;
            if (!is_string($uuid) || $uuid === '') {
                $results['skipped']++;
                continue;
            }

            foreach ($pathTemplates as $template) {
                $path = $this->renderPath($template, $uuid, $user);
                if ($path === null) {
                    $results['skipped']++;
                    continue;
                }
                $results['total_paths']++;
                $pending[] = [
                    'path' => $path,
                    'uuid' => $uuid,
                ];
            }
        }

        $batchResults = $this->fetchAndStoreBatch($pending, $ttl, $force);
        foreach ($batchResults as $entry) {
            $results['entries'][] = $entry;
            if ($entry['status'] === 'stored') {
                $results['success']++;
            } elseif ($entry['status'] === 'skipped') {
                $results['skipped']++;
            } else {
                $results['failures']++;
            }
        }

        $this->writeManifest($results);

        return $results;
    }

    private function ensureCacheDir(): void
    {
        $dir = $this->config['cache_dir'] ?? null;
        if (!is_string($dir) || $dir === '') {
            throw new RuntimeException('Cache directory is not configured.');
        }
        if (!is_dir($dir)) {
            if (!@mkdir($dir, 0755, true) && !is_dir($dir)) {
                throw new RuntimeException("Unable to create cache directory: {$dir}");
            }
        }
    }

    private function computePathTemplates(array $options): array
    {
        $templates = $options['path_templates'] ?? $this->config['snapshot_paths'] ?? null;
        if (is_string($templates)) {
            $templates = array_map('trim', explode(',', $templates));
        }
        if (!is_array($templates) || $templates === []) {
            $templates = ['/%s'];
        }

        $resolved = [];
        foreach ($templates as $template) {
            if (!is_string($template) || $template === '') {
                continue;
            }
            if (strpos($template, '%') === false) {
                // Support simple suffix by appending placeholder for uuid.
                $template = rtrim($template, '/') . '/%s';
            }
            $resolved[] = $template;
        }
        return $resolved;
    }

    private function computeTtl(array $options): int
    {
        $ttl = $options['ttl'] ?? $this->config['snapshot_ttl'] ?? null;
        if ($ttl === null) {
            return 0;
        }
        if (!is_numeric($ttl)) {
            throw new InvalidArgumentException('TTL must be numeric.');
        }
        return max(0, (int)$ttl);
    }

    private function renderPath(string $template, string $uuid, array $user): ?string
    {
        $replacements = [$uuid];
        if (substr_count($template, '%') > 1) {
            $replacements = [
                $uuid,
                $user['name'] ?? '',
                $user['comment'] ?? '',
            ];
        }

        try {
            $path = vsprintf($template, $replacements);
        } catch (ValueError $e) {
            return null;
        }

        if ($path === '') {
            return null;
        }

        if ($path[0] !== '/') {
            $path = '/' . $path;
        }

        return $path;
    }

    private function fetchAndStore(string $path, int $ttl, bool $force): array
    {
        $baseUrl = rtrim($this->config['snapshot_base_url'] ?? '', '/');
        if ($baseUrl === '') {
            $baseUrl = rtrim($this->config['upstream_base_url'] ?? '', '/');
        }
        if ($baseUrl === '') {
            return [
                'path' => $path,
                'status' => 'error',
                'http_code' => 0,
                'message' => 'Upstream base URL is not configured.',
            ];
        }

        $url = $baseUrl . $path;
        $cacheKey = md5($url);
        $cachePath = $this->config['cache_dir'] . '/' . $cacheKey;

        if (!$force && is_file($cachePath) && ($ttl === 0 || (time() - filemtime($cachePath) < $ttl))) {
            return [
                'path' => $path,
                'status' => 'skipped',
                'http_code' => 200,
                'message' => 'Cache entry still fresh.',
            ];
        }

        $retries = max(0, (int)($this->config['snapshot_retries'] ?? 0));
        $attempt = 0;
        $response = false;
        $errorNo = 0;
        $errorMsg = '';
        $info = [];

        while (true) {
            $ch = curl_init($url);
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_HEADER => true,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_MAXREDIRS => 5,
                CURLOPT_CONNECTTIMEOUT => $this->config['snapshot_connect_timeout'] ?? 10,
                CURLOPT_TIMEOUT => $this->config['snapshot_transfer_timeout'] ?? 30,
                CURLOPT_SSL_VERIFYPEER => true,
                CURLOPT_SSL_VERIFYHOST => 2,
                CURLOPT_HTTPHEADER => [
                    'User-Agent: RelaySnapshotSeeder/1.0',
                    'Accept: */*',
                    'Accept-Encoding: identity',
                ],
            ]);

            if (!empty($this->config['snapshot_force_ipv4']) && defined('CURL_IPRESOLVE_V4')) {
                curl_setopt($ch, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);
            }

            if (!empty($this->config['curl_proxy'])) {
                curl_setopt($ch, CURLOPT_PROXY, $this->config['curl_proxy']);
            }

            $response = curl_exec($ch);
            $errorNo = curl_errno($ch);
            $errorMsg = curl_error($ch);
            $info = curl_getinfo($ch);
            curl_close($ch);

            if ($response !== false && $errorNo === 0) {
                break;
            }

            if ($attempt >= $retries) {
                break;
            }
            $attempt++;
            usleep(200000);
        }

        if ($response === false || $errorNo !== 0) {
            return [
                'path' => $path,
                'status' => 'error',
                'http_code' => $info['http_code'] ?? 0,
                'message' => $errorMsg !== '' ? $errorMsg : 'Unknown cURL error.',
            ];
        }

        $httpCode = $info['http_code'] ?? 0;
        if ($httpCode !== 200) {
            return [
                'path' => $path,
                'status' => 'error',
                'http_code' => $httpCode,
                'message' => "Unexpected HTTP status {$httpCode} while fetching.",
            ];
        }

        $rawResponse = $response;
        $response = $this->injectMessagesIntoResponse($response, $info);
        $injected = $response !== $rawResponse;
        $this->storeCache($url, $response, $info, $injected);

        return [
            'path' => $path,
            'status' => 'stored',
            'http_code' => $httpCode,
            'message' => 'Cached successfully.',
        ];
    }

    private function fetchAndStoreBatch(array $pending, int $ttl, bool $force): array
    {
        if ($pending === []) {
            return [];
        }

        $baseUrl = rtrim($this->config['snapshot_base_url'] ?? '', '/');
        if ($baseUrl === '') {
            $baseUrl = rtrim($this->config['upstream_base_url'] ?? '', '/');
        }
        if ($baseUrl === '') {
            return array_map(static function (array $item): array {
                return [
                    'path' => $item['path'],
                    'uuid' => $item['uuid'],
                    'status' => 'error',
                    'http_code' => 0,
                    'message' => 'Upstream base URL is not configured.',
                ];
            }, $pending);
        }

        $results = [];
        $queue = [];
        foreach ($pending as $item) {
            $path = $item['path'];
            $url = $baseUrl . $path;
            $cacheKey = md5($url);
            $cachePath = $this->config['cache_dir'] . '/' . $cacheKey;

            if (!$force && is_file($cachePath) && ($ttl === 0 || (time() - filemtime($cachePath) < $ttl))) {
                $results[] = [
                    'path' => $path,
                    'uuid' => $item['uuid'],
                    'status' => 'skipped',
                    'http_code' => 200,
                    'message' => 'Cache entry still fresh.',
                ];
                continue;
            }

            $queue[] = [
                'path' => $path,
                'uuid' => $item['uuid'],
                'url' => $url,
                'attempts' => 0,
            ];
        }

        if ($queue === []) {
            return $results;
        }

        $parallel = (int)($this->config['snapshot_parallel'] ?? 8);
        if ($parallel < 1) {
            $parallel = 1;
        }
        $retries = max(0, (int)($this->config['snapshot_retries'] ?? 0));

        $multi = curl_multi_init();
        $handles = [];
        $index = 0;
        $active = null;

        $addHandle = function (array $item) use (&$multi, &$handles): void {
            $ch = curl_init($item['url']);
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_HEADER => true,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_MAXREDIRS => 5,
                CURLOPT_CONNECTTIMEOUT => $this->config['snapshot_connect_timeout'] ?? 10,
                CURLOPT_TIMEOUT => $this->config['snapshot_transfer_timeout'] ?? 30,
                CURLOPT_SSL_VERIFYPEER => true,
                CURLOPT_SSL_VERIFYHOST => 2,
                CURLOPT_HTTPHEADER => [
                    'User-Agent: RelaySnapshotSeeder/1.0',
                    'Accept: */*',
                    'Accept-Encoding: identity',
                ],
            ]);

            if (!empty($this->config['snapshot_force_ipv4']) && defined('CURL_IPRESOLVE_V4')) {
                curl_setopt($ch, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);
            }

            if (!empty($this->config['curl_proxy'])) {
                curl_setopt($ch, CURLOPT_PROXY, $this->config['curl_proxy']);
            }

            curl_multi_add_handle($multi, $ch);
            $handles[(int)$ch] = ['handle' => $ch, 'item' => $item];
        };

        while ($index < count($queue) && count($handles) < $parallel) {
            $addHandle($queue[$index]);
            $index++;
        }

        do {
            do {
                $status = curl_multi_exec($multi, $active);
            } while ($status === CURLM_CALL_MULTI_PERFORM);

            while ($info = curl_multi_info_read($multi)) {
                $ch = $info['handle'];
                $meta = $handles[(int)$ch] ?? null;
                if ($meta === null) {
                    continue;
                }

                $item = $meta['item'];
                $response = curl_multi_getcontent($ch);
                $errorNo = curl_errno($ch);
                $errorMsg = curl_error($ch);
                $infoData = curl_getinfo($ch);

                curl_multi_remove_handle($multi, $ch);
                curl_close($ch);
                unset($handles[(int)$ch]);

                if ($response === false || $errorNo !== 0) {
                    if (($item['attempts'] ?? 0) < $retries) {
                        $item['attempts'] = ($item['attempts'] ?? 0) + 1;
                        $queue[] = $item;
                    } else {
                        $results[] = [
                            'path' => $item['path'],
                            'uuid' => $item['uuid'],
                            'status' => 'error',
                            'http_code' => $infoData['http_code'] ?? 0,
                            'message' => $errorMsg !== '' ? $errorMsg : 'Unknown cURL error.',
                        ];
                    }
                } else {
                    $httpCode = $infoData['http_code'] ?? 0;
                    if ($httpCode !== 200) {
                        if (($item['attempts'] ?? 0) < $retries) {
                            $item['attempts'] = ($item['attempts'] ?? 0) + 1;
                            $queue[] = $item;
                        } else {
                            $results[] = [
                                'path' => $item['path'],
                                'uuid' => $item['uuid'],
                                'status' => 'error',
                                'http_code' => $httpCode,
                                'message' => "Unexpected HTTP status {$httpCode} while fetching.",
                            ];
                        }
                    } else {
                        $rawResponse = $response;
                        $response = $this->injectMessagesIntoResponse($response, $infoData);
                        $injected = $response !== $rawResponse;
                        $this->storeCache($item['url'], $response, $infoData, $injected);
                        $results[] = [
                            'path' => $item['path'],
                            'uuid' => $item['uuid'],
                            'status' => 'stored',
                            'http_code' => $httpCode,
                            'message' => 'Cached successfully.',
                        ];
                    }
                }

                if ($index < count($queue)) {
                    $addHandle($queue[$index]);
                    $index++;
                }
            }

            if ($active) {
                curl_multi_select($multi, 1.0);
            }
        } while ($active || count($handles) > 0);

        curl_multi_close($multi);
        return $results;
    }

    private function storeCache(string $url, string $response, array $info, bool $injected): void
    {
        $cacheKey = md5($url);
        $cachePath = $this->config['cache_dir'] . '/' . $cacheKey;
        $headerSize = $info['header_size'] ?? 0;
        $headers = substr($response, 0, $headerSize);
        $body = substr($response, $headerSize);

        @file_put_contents($cachePath, $body, LOCK_EX);
        @file_put_contents($cachePath . '.meta', json_encode([
            'http_code' => $info['http_code'] ?? 200,
            'content_type' => $info['content_type'] ?? 'application/octet-stream',
            'headers' => $this->headerListToArray($headers),
            'injected' => $injected,
        ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE), LOCK_EX);
    }

    private function injectMessagesIntoResponse(string $response, array $info): string
    {
        $messages = $this->config['snapshot_inject_messages'] ?? [];
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

    private function writeManifest(array $results): void
    {
        $manifestPath = $this->config['snapshot_manifest'] ?? $this->config['cache_dir'] . '/snapshot_manifest.json';
        @file_put_contents($manifestPath, json_encode($results, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE), LOCK_EX);
    }
}
