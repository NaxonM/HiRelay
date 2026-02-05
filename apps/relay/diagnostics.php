<?php
// Run via CLI: php diagnostics.php [options]
if (!defined('HIRELAY_BOOTSTRAPPED')) {
    require __DIR__ . '/bootstrap.php';
}
if (!isset($config) || !is_array($config)) {
    $config = require __DIR__ . '/config.php';
}

function relay_collect_diagnostics(array $config, array $options): array
{
    $connectTimeout = isset($options['connect-timeout']) ? (int)$options['connect-timeout'] : (int)($config['connect_timeout'] ?? 10);
    $transferTimeout = isset($options['timeout']) ? (int)$options['timeout'] : (int)($config['transfer_timeout'] ?? 30);
    if ($connectTimeout < 1) {
        $connectTimeout = 5;
    }
    if ($transferTimeout < 1) {
        $transferTimeout = 15;
    }

    $forceIpv4 = isset($options['force-ipv4']) || (getenv('RELAY_BACKUP_FORCE_IPV4') ?: '0') === '1';
    $backupConnectTimeout = (int)(getenv('RELAY_BACKUP_CONNECT_TIMEOUT') ?: $connectTimeout);
    $backupTransferTimeout = (int)(getenv('RELAY_BACKUP_TRANSFER_TIMEOUT') ?: $transferTimeout);
    $backupResolve = getenv('RELAY_BACKUP_RESOLVE') ?: '';
    $results = [];

    function probe_url(string $name, string $url, array $headers, bool $headOnly, int $connectTimeout, int $transferTimeout, bool $forceIpv4): array
    {
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HEADER => true,
        CURLOPT_NOBODY => $headOnly,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS => 5,
        CURLOPT_CONNECTTIMEOUT => $connectTimeout,
        CURLOPT_TIMEOUT => $transferTimeout,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_USERAGENT => 'HiRelay-Diagnostics/1.0',
        CURLOPT_HTTPHEADER => $headers,
    ]);

    if ($forceIpv4 && defined('CURL_IPRESOLVE_V4')) {
        curl_setopt($ch, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);
    }

    $response = curl_exec($ch);
    $errorNo = curl_errno($ch);
    $errorMsg = curl_error($ch);
    $info = curl_getinfo($ch);
    curl_close($ch);

    $httpCode = (int)($info['http_code'] ?? 0);
    $ok = $errorNo === 0 && $httpCode >= 200 && $httpCode < 400;

    return [
        'name' => $name,
        'url' => $url,
        'ok' => $ok,
        'http_code' => $httpCode,
        'error' => $errorNo === 0 ? '' : ($errorMsg !== '' ? $errorMsg : 'Unknown error'),
        'primary_ip' => $info['primary_ip'] ?? '',
        'total_time' => $info['total_time'] ?? 0,
        'connect_time' => $info['connect_time'] ?? 0,
        'namelookup_time' => $info['namelookup_time'] ?? 0,
        'size_download' => $info['size_download'] ?? 0,
    ];
    }

    $upstreamBase = trim((string)($config['upstream_base_url'] ?? ''));
    if ($upstreamBase !== '') {
        $results[] = probe_url(
            'upstream_base',
            $upstreamBase,
            ['Accept: */*'],
            true,
            $connectTimeout,
            $transferTimeout,
            $forceIpv4
        );
    }

    $cacheSource = trim((string)($config['cache_source_base_url'] ?? ''));
    if ($cacheSource !== '' && $cacheSource !== $upstreamBase) {
        $results[] = probe_url(
            'cache_source_base',
            $cacheSource,
            ['Accept: */*'],
            true,
            $connectTimeout,
            $transferTimeout,
            $forceIpv4
        );
    }

    $backupUrl = trim((string)(getenv('RELAY_BACKUP_API_URL') ?: ''));
    $backupKey = trim((string)(getenv('RELAY_BACKUP_API_KEY') ?: ''));
    if ($backupUrl !== '') {
        $headers = ['Accept: application/json'];
        if ($backupKey !== '') {
            $headers[] = 'Hiddify-API-Key: ' . $backupKey;
        }
        if ($backupResolve !== '') {
            $headers[] = 'X-HiRelay-Resolve: ' . $backupResolve;
        }
        $result = probe_url(
            'backup_api',
            $backupUrl,
            $headers,
            false,
            $backupConnectTimeout,
            $backupTransferTimeout,
            $forceIpv4
        );
        if ($backupKey === '') {
            $result['ok'] = false;
            $result['error'] = 'Missing RELAY_BACKUP_API_KEY.';
        }
        $results[] = $result;
    }

    $hasFailures = false;
    foreach ($results as $entry) {
        if (!$entry['ok']) {
            $hasFailures = true;
            break;
        }
    }

    return [
        'payload' => [
            'connect_timeout' => $connectTimeout,
            'transfer_timeout' => $transferTimeout,
            'backup_connect_timeout' => $backupConnectTimeout,
            'backup_transfer_timeout' => $backupTransferTimeout,
            'force_ipv4' => $forceIpv4,
            'results' => $results,
        ],
        'has_failures' => $hasFailures,
    ];
}

function relay_write_diagnostics_files(array $results, bool $hasFailures, ?string $statusPath, ?string $logPath): void
{
    $payload = $results['payload'] ?? [];
    $json = json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";

    if (is_string($statusPath) && $statusPath !== '') {
        $dir = dirname($statusPath);
        if (!is_dir($dir)) {
            @mkdir($dir, 0755, true);
        }
        @file_put_contents($statusPath, json_encode([
            'ok' => !$hasFailures,
            'message' => $hasFailures ? 'Diagnostics reported failures.' : 'Diagnostics completed successfully.',
            'updated_at' => date('c'),
            'results' => $payload['results'] ?? [],
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
    }

    if (is_string($logPath) && $logPath !== '') {
        $dir = dirname($logPath);
        if (!is_dir($dir)) {
            @mkdir($dir, 0755, true);
        }
        @file_put_contents($logPath, $json);
    }
}

$isCli = (PHP_SAPI === 'cli' || PHP_SAPI === 'phpdbg');
$isDirect = isset($_SERVER['SCRIPT_FILENAME']) && realpath($_SERVER['SCRIPT_FILENAME']) === __FILE__;

if ($isCli && $isDirect) {
    $options = getopt('', ['json', 'timeout::', 'connect-timeout::', 'force-ipv4', 'write-status::', 'write-log::']);
    $collected = relay_collect_diagnostics($config, $options);
    $payload = $collected['payload'];
    $hasFailures = $collected['has_failures'];

    $statusPath = $options['write-status'] ?? null;
    $logPath = $options['write-log'] ?? null;
    relay_write_diagnostics_files($collected, $hasFailures, is_string($statusPath) ? $statusPath : null, is_string($logPath) ? $logPath : null);

    if (isset($options['json'])) {
        echo json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
        exit($hasFailures ? 1 : 0);
    }

    echo "HiRelay diagnostics\n";
    echo "Connect timeout: {$payload['connect_timeout']}s | Transfer timeout: {$payload['transfer_timeout']}s | Force IPv4: " . (!empty($payload['force_ipv4']) ? 'yes' : 'no') . "\n\n";
    foreach ($payload['results'] ?? [] as $entry) {
        echo strtoupper((string)($entry['name'] ?? '')) . "\n";
        echo "  URL: " . ($entry['url'] ?? '') . "\n";
        echo "  OK: " . (!empty($entry['ok']) ? 'yes' : 'no') . "\n";
        echo "  HTTP: " . ($entry['http_code'] ?? 0) . "\n";
        echo "  IP: " . ($entry['primary_ip'] ?? '') . "\n";
        echo "  Time: total " . ($entry['total_time'] ?? 0) . "s | connect " . ($entry['connect_time'] ?? 0) . "s | lookup " . ($entry['namelookup_time'] ?? 0) . "\n";
        echo "  Size: " . ($entry['size_download'] ?? 0) . " bytes\n";
        if (!empty($entry['error'])) {
            echo "  Error: " . $entry['error'] . "\n";
        }
        echo "\n";
    }

    exit($hasFailures ? 1 : 0);
}
