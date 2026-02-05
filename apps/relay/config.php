<?php
// Paths and mode selection.
$cache_dir = getenv('RELAY_CACHE_DIR') ?: __DIR__ . '/storage/cache';
$log_file = getenv('RELAY_LOG_FILE') ?: __DIR__ . '/storage/relay.log';
$access_log_file = getenv('RELAY_ACCESS_LOG_FILE') ?: __DIR__ . '/storage/access.log';
$rate_limit_dir = getenv('RELAY_RATE_LIMIT_DIR') ?: __DIR__ . '/storage/ratelimit';
$snapshot_backup_path = getenv('RELAY_SNAPSHOT_BACKUP_PATH') ?: '';
$path_template = getenv('RELAY_PATH_TEMPLATE') ?: '';
$relay_mode = strtolower((string)(getenv('RELAY_MODE') ?: 'hybrid'));

// Snapshot seeding paths (fallback to path template if set).
$snapshot_paths_env = getenv('RELAY_SNAPSHOT_PATHS');
$snapshot_paths = $snapshot_paths_env ? array_filter(array_map('trim', explode(',', $snapshot_paths_env))) : [];
if ($snapshot_paths === [] && $path_template !== '') {
    $snapshot_paths = [$path_template];
}

if (!is_dir($cache_dir)) {
    @mkdir($cache_dir, 0755, true);
}

$log_dir = dirname($log_file);
if (!is_dir($log_dir)) {
    @mkdir($log_dir, 0755, true);
}

$access_log_dir = dirname($access_log_file);
if (!is_dir($access_log_dir)) {
    @mkdir($access_log_dir, 0755, true);
}

if (!is_dir($rate_limit_dir)) {
    @mkdir($rate_limit_dir, 0755, true);
}

if ($snapshot_backup_path !== '' && $snapshot_backup_path[0] !== '/') {
    $snapshot_backup_path = __DIR__ . '/' . ltrim($snapshot_backup_path, '/');
}

// Runtime configuration for RelayService and SnapshotSeeder.
return [
    // Upstream and access control.
    'upstream_base_url' => getenv('RELAY_UPSTREAM_BASE_URL') ?: '',
    'cache_source_base_url' => getenv('CACHE_SOURCE_BASE_URL') ?: getenv('RELAY_UPSTREAM_BASE_URL') ?: '',
    'auth_token' => getenv('RELAY_AUTH_TOKEN') ?: '',
    'allowed_clients' => getenv('RELAY_ALLOWED_CLIENTS') ? array_filter(array_map('trim', explode(',', getenv('RELAY_ALLOWED_CLIENTS')))) : [],
    // Cache behavior.
    'cache_enabled' => (getenv('RELAY_CACHE_ENABLED') ?: '1') === '1',
    'cache_ttl' => (int)(getenv('RELAY_CACHE_TTL') ?: 300),
    'cache_max_size_mb' => (int)(getenv('RELAY_CACHE_MAX_SIZE_MB') ?: 0),
    'cache_cleanup_chance' => (int)(getenv('RELAY_CACHE_CLEANUP_CHANCE') ?: 1),
    'hybrid_failover_ttl' => (int)(getenv('RELAY_HYBRID_FAILOVER_TTL') ?: 120),
    'cache_dir' => $cache_dir,
    'log_file' => $log_file,
    'access_log_file' => $access_log_file,
    // Security and protection.
    'security_headers' => (getenv('RELAY_SECURITY_HEADERS') ?: '1') === '1',
    'request_validation_enabled' => (getenv('RELAY_REQUEST_VALIDATION') ?: '0') === '1',
    'request_validation_pattern' => getenv('RELAY_REQUEST_VALIDATION_PATTERN') ?: '/^\/[A-Za-z0-9\-._~%\/]+$/',
    'rate_limit_enabled' => (getenv('RELAY_RATE_LIMIT_ENABLED') ?: '0') === '1',
    'rate_limit_count' => (int)(getenv('RELAY_RATE_LIMIT_COUNT') ?: 100),
    'rate_limit_window' => (int)(getenv('RELAY_RATE_LIMIT_WINDOW') ?: 60),
    'rate_limit_burst' => (int)(getenv('RELAY_RATE_LIMIT_BURST') ?: 20),
    'rate_limit_graceful' => (getenv('RELAY_RATE_LIMIT_GRACEFUL') ?: '1') === '1',
    'rate_limit_whitelist' => getenv('RELAY_RATE_LIMIT_WHITELIST') ? array_filter(array_map('trim', explode(',', getenv('RELAY_RATE_LIMIT_WHITELIST')))) : [],
    'rate_limit_dir' => $rate_limit_dir,
    // Upstream request behavior.
    'connect_timeout' => (int)(getenv('RELAY_CONNECT_TIMEOUT') ?: 10),
    'transfer_timeout' => (int)(getenv('RELAY_TRANSFER_TIMEOUT') ?: 30),
    'curl_proxy' => getenv('RELAY_CURL_PROXY') ?: '',
    // Snapshot seeding and inject messages.
    'snapshot_backup_path' => $snapshot_backup_path,
    'snapshot_base_url' => getenv('RELAY_SNAPSHOT_BASE_URL') ?: (getenv('CACHE_SOURCE_BASE_URL') ?: getenv('RELAY_UPSTREAM_BASE_URL') ?: ''),
    'snapshot_paths' => $snapshot_paths,
    'snapshot_ttl' => (int)(getenv('RELAY_SNAPSHOT_TTL') ?: 0),
    'snapshot_parallel' => (int)(getenv('RELAY_SNAPSHOT_PARALLEL') ?: 8),
    'snapshot_retries' => (int)(getenv('RELAY_SNAPSHOT_RETRIES') ?: 2),
    'snapshot_connect_timeout' => (int)(getenv('RELAY_SNAPSHOT_CONNECT_TIMEOUT') ?: (getenv('RELAY_CONNECT_TIMEOUT') ?: 10)),
    'snapshot_transfer_timeout' => (int)(getenv('RELAY_SNAPSHOT_TRANSFER_TIMEOUT') ?: (getenv('RELAY_TRANSFER_TIMEOUT') ?: 30)),
    'snapshot_force_ipv4' => (getenv('RELAY_SNAPSHOT_FORCE_IPV4') ?: '0') === '1',
    'snapshot_inject_messages' => array_values(array_filter([
        getenv('RELAY_SNAPSHOT_INJECT_1') ?: '',
        getenv('RELAY_SNAPSHOT_INJECT_2') ?: '',
    ], static fn ($value) => is_string($value) && $value !== '')),
    'live_inject_messages' => array_values(array_filter([
        getenv('RELAY_LIVE_INJECT_1') ?: '',
        getenv('RELAY_LIVE_INJECT_2') ?: '',
    ], static fn ($value) => is_string($value) && $value !== '')),
    'snapshot_manifest' => getenv('RELAY_SNAPSHOT_MANIFEST') ?: $cache_dir . '/snapshot_manifest.json',
    'snapshot_allow_stale' => (getenv('RELAY_SNAPSHOT_ALLOW_STALE') ?: '1') === '1',
    'cache_allow_stale' => (getenv('CACHE_ALLOW_STALE') ?: (getenv('RELAY_SNAPSHOT_ALLOW_STALE') ?: '1')) === '1',
    'debug_log_enabled' => (getenv('RELAY_DEBUG_LOG') ?: '0') === '1',
    // Path template and relay mode.
    'path_template' => $path_template,
    'mode' => $relay_mode,
];
