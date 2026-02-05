#!/usr/bin/env php
<?php
require __DIR__ . '/bootstrap.php';
$config = require __DIR__ . '/config.php';

$statusPath = getenv('RELAY_UPSTREAM_STATUS_PATH') ?: __DIR__ . '/storage/upstream-status.json';
$targetUrl = getenv('RELAY_UPSTREAM_BASE_URL') ?: '';

function write_status(string $path, array $payload): void
{
    $dir = dirname($path);
    if (!is_dir($dir)) {
        @mkdir($dir, 0755, true);
    }
    @file_put_contents($path, json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
}

if ($targetUrl === '') {
    write_status($statusPath, [
        'ok' => false,
        'message' => 'Upstream URL is not configured.',
        'updated_at' => date('c'),
    ]);
    exit(1);
}

$connectTimeout = min(10, (int)($config['connect_timeout'] ?? 10));
$transferTimeout = min(15, (int)($config['transfer_timeout'] ?? 30));
if ($connectTimeout < 1) {
    $connectTimeout = 5;
}
if ($transferTimeout < 1) {
    $transferTimeout = 10;
}

$ch = curl_init($targetUrl);
curl_setopt_array($ch, [
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_NOBODY => true,
    CURLOPT_FOLLOWLOCATION => true,
    CURLOPT_MAXREDIRS => 3,
    CURLOPT_CONNECTTIMEOUT => $connectTimeout,
    CURLOPT_TIMEOUT => $transferTimeout,
    CURLOPT_SSL_VERIFYPEER => true,
    CURLOPT_SSL_VERIFYHOST => 2,
]);

$response = curl_exec($ch);
$errorNo = curl_errno($ch);
$errorMsg = curl_error($ch);
$info = curl_getinfo($ch);
curl_close($ch);

if ($response === false || $errorNo !== 0) {
    write_status($statusPath, [
        'ok' => false,
        'message' => 'Upstream check failed: ' . ($errorMsg !== '' ? $errorMsg : 'Unknown error'),
        'updated_at' => date('c'),
    ]);
    exit(1);
}

$code = (int)($info['http_code'] ?? 0);
if ($code < 200 || $code >= 400) {
    write_status($statusPath, [
        'ok' => false,
        'message' => 'Upstream check returned HTTP ' . $code . '.',
        'updated_at' => date('c'),
    ]);
    exit(1);
}

write_status($statusPath, [
    'ok' => true,
    'message' => 'Upstream reachable (HTTP ' . $code . ').',
    'updated_at' => date('c'),
]);
exit(0);
