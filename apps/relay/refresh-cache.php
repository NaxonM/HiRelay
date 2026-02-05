#!/usr/bin/env php
<?php
require __DIR__ . '/bootstrap.php';
$config = require __DIR__ . '/config.php';
require_once __DIR__ . '/src/SnapshotSeeder.php';

$stderr = defined('STDERR') ? STDERR : fopen('php://output', 'wb');
$statusPath = getenv('RELAY_REFRESH_STATUS_PATH') ?: __DIR__ . '/storage/refresh-status.json';

function write_refresh_status(string $path, array $payload): void
{
    $dir = dirname($path);
    if (!is_dir($dir)) {
        @mkdir($dir, 0755, true);
    }
    @file_put_contents($path, json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
}

function refresh_log($handle, string $message): void
{
    if (!is_resource($handle)) {
        return;
    }
    fwrite($handle, $message);
}

function refresh_print_usage(): void
{
    global $stderr;
    refresh_log($stderr, "Usage: php refresh-cache.php [--backup=path] [--paths=templ1,templ2] [--ttl=seconds] [--force]\n");
    refresh_log($stderr, "\nOptions:\n");
    refresh_log($stderr, "  --backup   Path to write the backup JSON (defaults to RELAY_SNAPSHOT_BACKUP_PATH).\n");
    refresh_log($stderr, "  --paths    Comma-separated path templates (use %s for UUID). Defaults to RELAY_SNAPSHOT_PATHS or '/%s'.\n");
    refresh_log($stderr, "  --ttl      Override snapshot TTL in seconds. Defaults to RELAY_SNAPSHOT_TTL.\n");
    refresh_log($stderr, "  --force    Refresh cache entries even if they are still fresh.\n");
}

$options = getopt('', ['backup::', 'paths::', 'ttl::', 'force', 'help', 'manual']);
if ($options === false || isset($options['help'])) {
    refresh_print_usage();
    exit(isset($options['help']) ? 0 : 1);
}

$cronEnabled = (getenv('RELAY_CRON_ENABLED') ?: '1') === '1';
if (!$cronEnabled && !isset($options['manual'])) {
    $message = 'Cron refresh is disabled.';
    refresh_log($stderr, "{$message}\n");
    write_refresh_status($statusPath, [
        'running' => false,
        'progress' => 0,
        'step' => 'disabled',
        'message' => $message,
        'updated_at' => date('c'),
    ]);
    exit(0);
}

write_refresh_status($statusPath, [
    'running' => true,
    'progress' => 5,
    'step' => 'start',
    'message' => 'Starting refresh.',
    'updated_at' => date('c'),
]);

$backupPath = $options['backup'] ?? ($config['snapshot_backup_path'] ?? '');
if (!is_string($backupPath) || $backupPath === '') {
    refresh_log($stderr, "Error: RELAY_SNAPSHOT_BACKUP_PATH or --backup is required.\n");
    write_refresh_status($statusPath, [
        'running' => false,
        'progress' => 0,
        'step' => 'error',
        'message' => 'Backup path missing.',
        'updated_at' => date('c'),
    ]);
    exit(1);
}

$apiUrl = getenv('RELAY_BACKUP_API_URL') ?: '';
$apiKey = getenv('RELAY_BACKUP_API_KEY') ?: '';
$proxy = getenv('RELAY_BACKUP_PROXY') ?: '';
$forceIpv4 = (getenv('RELAY_BACKUP_FORCE_IPV4') ?: '0') === '1';
$backupResolve = getenv('RELAY_BACKUP_RESOLVE') ?: '';
$backupConnectTimeout = (int)(getenv('RELAY_BACKUP_CONNECT_TIMEOUT') ?: ($config['connect_timeout'] ?? 10));
$backupTransferTimeout = (int)(getenv('RELAY_BACKUP_TRANSFER_TIMEOUT') ?: ($config['transfer_timeout'] ?? 30));

if ($apiUrl === '' || $apiKey === '') {
    refresh_log($stderr, "Error: RELAY_BACKUP_API_URL and RELAY_BACKUP_API_KEY are required.\n");
    write_refresh_status($statusPath, [
        'running' => false,
        'progress' => 0,
        'step' => 'error',
        'message' => 'API URL or key missing.',
        'updated_at' => date('c'),
    ]);
    exit(1);
}

$paths = $options['paths'] ?? null;
$ttl = $options['ttl'] ?? null;
$force = isset($options['force']);

$ch = curl_init($apiUrl);
$headers = [
    'Accept: application/json',
    'Hiddify-API-Key: ' . $apiKey,
];

curl_setopt_array($ch, [
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_FOLLOWLOCATION => true,
    CURLOPT_MAXREDIRS => 5,
    CURLOPT_CONNECTTIMEOUT => $backupConnectTimeout,
    CURLOPT_TIMEOUT => $backupTransferTimeout,
    CURLOPT_SSL_VERIFYPEER => true,
    CURLOPT_SSL_VERIFYHOST => 2,
    CURLOPT_USERAGENT => 'HiRelay-Refresh/1.0',
    CURLOPT_HTTPHEADER => $headers,
]);

if ($forceIpv4 && defined('CURL_IPRESOLVE_V4')) {
    curl_setopt($ch, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);
}

if ($backupResolve !== '') {
    $entries = array_filter(array_map('trim', explode(',', $backupResolve)));
    if ($entries !== []) {
        curl_setopt($ch, CURLOPT_RESOLVE, $entries);
    }
}

if ($proxy !== '') {
    curl_setopt($ch, CURLOPT_PROXY, $proxy);
}

$response = curl_exec($ch);
$errorNo = curl_errno($ch);
$errorMsg = curl_error($ch);
$info = curl_getinfo($ch);
curl_close($ch);

if ($response === false || $errorNo !== 0) {
    refresh_log($stderr, "Error: API request failed: " . ($errorMsg !== '' ? $errorMsg : 'Unknown error') . "\n");
    write_refresh_status($statusPath, [
        'running' => false,
        'progress' => 0,
        'step' => 'error',
        'message' => 'API request failed: ' . ($errorMsg !== '' ? $errorMsg : 'Unknown error'),
        'updated_at' => date('c'),
    ]);
    exit(1);
}

if (($info['http_code'] ?? 0) !== 200) {
    refresh_log($stderr, "Error: API returned HTTP " . ($info['http_code'] ?? 0) . "\n");
    write_refresh_status($statusPath, [
        'running' => false,
        'progress' => 0,
        'step' => 'error',
        'message' => 'API returned HTTP ' . ($info['http_code'] ?? 0),
        'updated_at' => date('c'),
    ]);
    exit(1);
}

$usersJson = trim($response);
if ($usersJson === '') {
    refresh_log($stderr, "Error: API response is empty.\n");
    write_refresh_status($statusPath, [
        'running' => false,
        'progress' => 0,
        'step' => 'error',
        'message' => 'API response empty.',
        'updated_at' => date('c'),
    ]);
    exit(1);
}

write_refresh_status($statusPath, [
    'running' => true,
    'progress' => 35,
    'step' => 'backup_fetched',
    'message' => 'Backup fetched.',
    'updated_at' => date('c'),
]);

$timestamp = date('c');
$backupJson = "{\n  \"generated_at\": \"{$timestamp}\",\n  \"users\": {$usersJson}\n}";

$dir = dirname($backupPath);
if (!is_dir($dir)) {
    @mkdir($dir, 0755, true);
}

if (@file_put_contents($backupPath, $backupJson) === false) {
    refresh_log($stderr, "Error: Unable to write backup file to {$backupPath}.\n");
    write_refresh_status($statusPath, [
        'running' => false,
        'progress' => 0,
        'step' => 'error',
        'message' => 'Unable to write backup file.',
        'updated_at' => date('c'),
    ]);
    exit(1);
}

write_refresh_status($statusPath, [
    'running' => true,
    'progress' => 55,
    'step' => 'seeding',
    'message' => 'Seeding cache.',
    'updated_at' => date('c'),
]);

try {
    $seeder = new SnapshotSeeder($config);
    $result = $seeder->seedFromBackup($backupPath, [
        'path_templates' => $paths,
        'ttl' => $ttl,
        'force' => $force,
    ]);
} catch (Throwable $e) {
    refresh_log($stderr, "Error: " . $e->getMessage() . "\n");
    write_refresh_status($statusPath, [
        'running' => false,
        'progress' => 0,
        'step' => 'error',
        'message' => $e->getMessage(),
        'updated_at' => date('c'),
    ]);
    exit(1);
}

fwrite(STDOUT, "Snapshot cache completed.\n");
fwrite(STDOUT, " Users processed: {$result['total_users']}\n");
fwrite(STDOUT, " Paths attempted: {$result['total_paths']}\n");
fwrite(STDOUT, " Stored: {$result['success']} | Skipped: {$result['skipped']} | Failures: {$result['failures']}\n");

$manifestPath = $config['snapshot_manifest'] ?? $config['cache_dir'] . '/snapshot_manifest.json';
fwrite(STDOUT, " Manifest written to: {$manifestPath}\n");
write_refresh_status($statusPath, [
    'running' => false,
    'progress' => 100,
    'step' => 'done',
    'message' => 'Cache refresh completed.',
    'updated_at' => date('c'),
]);
exit(0);
