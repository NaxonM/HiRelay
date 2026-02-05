<?php
require_once __DIR__ . '/../bootstrap.php';
$config = require __DIR__ . '/../config.php';

session_start();

$envPath = dirname(__DIR__) . '/.env';
$refreshStatusPath = dirname(__DIR__) . '/storage/refresh-status.json';
$refreshLogPath = dirname(__DIR__) . '/storage/refresh-cache.log';
$upstreamStatusPath = dirname(__DIR__) . '/storage/upstream-status.json';
$diagnosticsStatusPath = dirname(__DIR__) . '/storage/diagnostics-status.json';
$diagnosticsLogPath = dirname(__DIR__) . '/storage/diagnostics.log';
$passwordHash = getenv('RELAY_ADMIN_PASSWORD_HASH') ?: '';
$authReady = $passwordHash !== '';
$authed = $authReady && !empty($_SESSION['relay_admin']);
$messages = $_SESSION['flash_messages'] ?? [];
$errors = $_SESSION['flash_errors'] ?? [];
unset($_SESSION['flash_messages'], $_SESSION['flash_errors']);

if (isset($_GET['status'])) {
    $statusKey = (string)$_GET['status'];
    if ($statusKey === 'refresh') {
        $payload = read_status($refreshStatusPath);
    } elseif ($statusKey === 'upstream') {
        $payload = read_status($upstreamStatusPath);
    } elseif ($statusKey === 'diagnostics') {
        $payload = read_status($diagnosticsStatusPath);
    } else {
        $payload = ['message' => 'Unknown status.'];
    }
    header('Content-Type: application/json');
    echo json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

if (isset($_POST['action'])) {
    $action = (string)$_POST['action'];

    if ($action === 'login') {
        $password = (string)($_POST['password'] ?? '');
        if ($passwordHash === '' || !password_verify($password, $passwordHash)) {
            $errors[] = 'Invalid password.';
        } else {
            $_SESSION['relay_admin'] = true;
            $authed = true;
            $messages[] = 'Logged in.';
        }
    } elseif (!$authed) {
        $errors[] = 'Not authenticated.';
    } elseif ($action === 'logout') {
        $_SESSION = [];
        session_destroy();
        $authed = false;
        $messages[] = 'Logged out.';
    } elseif ($action === 'refresh_cache') {
        $result = run_refresh_cache();
        if ($result['ok']) {
            $messages[] = $result['message'];
        } else {
            $errors[] = $result['message'];
        }
    } elseif ($action === 'check_upstream') {
        $result = check_upstream($config['upstream_base_url'] ?? '', $config);
        if ($result['ok']) {
            $messages[] = $result['message'];
        } else {
            $errors[] = $result['message'];
        }
    } elseif ($action === 'run_diagnostics') {
        $result = run_diagnostics($diagnosticsStatusPath, $diagnosticsLogPath);
        if ($result['ok']) {
            $messages[] = $result['message'];
        } else {
            $errors[] = $result['message'];
        }
    } elseif ($action === 'clear_diagnostics') {
        $result = clear_diagnostics($diagnosticsStatusPath, $diagnosticsLogPath);
        if ($result['ok']) {
            $messages[] = $result['message'];
        } else {
            $errors[] = $result['message'];
        }
    } elseif ($action === 'clear_cache') {
        $result = clear_cache_dir($config['cache_dir'] ?? '');
        if ($result['ok']) {
            $messages[] = $result['message'];
        } else {
            $errors[] = $result['message'];
        }
    } elseif ($action === 'update_mode') {
        $mode = (string)($_POST['mode'] ?? '');
        $mode = strtolower(trim($mode));
        if (!in_array($mode, ['live', 'cold', 'hybrid'], true)) {
            $errors[] = 'Invalid mode.';
        } else {
            $result = update_env_and_htaccess($envPath, dirname(__DIR__) . '/.htaccess', ['RELAY_MODE' => $mode]);
            if ($result['ok']) {
                $messages[] = 'Mode updated to ' . $mode . '.';
            } else {
                $errors[] = $result['message'];
            }
        }
    } elseif ($action === 'update_inject') {
        $updates = [
            'RELAY_LIVE_INJECT_1' => (string)($_POST['live_inject_1'] ?? ''),
            'RELAY_LIVE_INJECT_2' => (string)($_POST['live_inject_2'] ?? ''),
            'RELAY_SNAPSHOT_INJECT_1' => (string)($_POST['snapshot_inject_1'] ?? ''),
            'RELAY_SNAPSHOT_INJECT_2' => (string)($_POST['snapshot_inject_2'] ?? ''),
        ];
        $result = update_env($envPath, $updates);
        if ($result['ok']) {
            $messages[] = 'Inject messages updated.';
        } else {
            $errors[] = $result['message'];
        }
    } elseif ($action === 'update_cron_interval') {
        $interval = (string)($_POST['cron_interval'] ?? '');
        $interval = trim($interval);
        if ($interval !== '' && (!ctype_digit($interval) || (int)$interval < 1)) {
            $errors[] = 'Cron interval must be a positive integer.';
        } else {
            $enabled = isset($_POST['cron_enabled']) ? '1' : '0';
            $result = update_env($envPath, [
                'RELAY_CRON_INTERVAL_MINUTES' => $interval,
                'RELAY_CRON_ENABLED' => $enabled,
            ]);
            if ($result['ok']) {
                $messages[] = 'Cron settings updated.';
            } else {
                $errors[] = $result['message'];
            }
        }
    } elseif ($action === 'update_backup_timeouts') {
        $backupConnect = trim((string)($_POST['backup_connect_timeout'] ?? ''));
        $backupTransfer = trim((string)($_POST['backup_transfer_timeout'] ?? ''));

        if ($backupConnect !== '' && (!ctype_digit($backupConnect) || (int)$backupConnect < 1)) {
            $errors[] = 'Backup connect timeout must be a positive integer.';
        }
        if ($backupTransfer !== '' && (!ctype_digit($backupTransfer) || (int)$backupTransfer < 1)) {
            $errors[] = 'Backup transfer timeout must be a positive integer.';
        }

        if ($errors === []) {
            $result = update_env($envPath, [
                'RELAY_BACKUP_CONNECT_TIMEOUT' => $backupConnect,
                'RELAY_BACKUP_TRANSFER_TIMEOUT' => $backupTransfer,
            ]);
            if ($result['ok']) {
                $messages[] = 'Backup timeouts updated.';
            } else {
                $errors[] = $result['message'];
            }
        }
    } elseif ($action === 'update_cache_policy') {
        $neverExpire = isset($_POST['never_expire']);
        if ($neverExpire) {
            $updates = [
                'RELAY_CACHE_TTL' => '-1',
                'RELAY_SNAPSHOT_TTL' => '0',
                'RELAY_SNAPSHOT_ALLOW_STALE' => '1',
                'CACHE_ALLOW_STALE' => '1',
            ];
        } else {
            $cacheTtl = trim((string)($_POST['cache_ttl'] ?? ''));
            $snapshotTtl = trim((string)($_POST['snapshot_ttl'] ?? ''));
            if ($cacheTtl === '' || (!is_numeric($cacheTtl))) {
                $errors[] = 'Cache TTL must be a number.';
            } elseif ((int)$cacheTtl < -1) {
                $errors[] = 'Cache TTL must be -1 or greater.';
            }

            if ($snapshotTtl === '' || (!is_numeric($snapshotTtl))) {
                $errors[] = 'Snapshot TTL must be a number.';
            } elseif ((int)$snapshotTtl < 0) {
                $errors[] = 'Snapshot TTL must be 0 or greater.';
            }

            $updates = [
                'RELAY_CACHE_TTL' => $cacheTtl,
                'RELAY_SNAPSHOT_TTL' => $snapshotTtl,
                'RELAY_SNAPSHOT_ALLOW_STALE' => isset($_POST['snapshot_allow_stale']) ? '1' : '0',
                'CACHE_ALLOW_STALE' => isset($_POST['cache_allow_stale']) ? '1' : '0',
            ];
        }

        if ($errors === []) {
            $result = update_env($envPath, $updates);
            if ($result['ok']) {
                $messages[] = 'Cache expiration settings updated.';
            } else {
                $errors[] = $result['message'];
            }
        }
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $_SESSION['flash_messages'] = $messages;
    $_SESSION['flash_errors'] = $errors;
    header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?'));
    exit;
}

$cacheStats = get_cache_stats($config['cache_dir'] ?? '');
$manifestStats = get_manifest_stats($config['snapshot_manifest'] ?? '');
$accessStats = get_access_log_stats($config['access_log_file'] ?? '');

$currentMode = getenv('RELAY_MODE') ?: ($config['mode'] ?? 'hybrid');
$currentMode = strtolower(trim((string)$currentMode));

$currentLiveInject1 = getenv('RELAY_LIVE_INJECT_1') ?: '';
$currentLiveInject2 = getenv('RELAY_LIVE_INJECT_2') ?: '';
$currentSnapshotInject1 = getenv('RELAY_SNAPSHOT_INJECT_1') ?: '';
$currentSnapshotInject2 = getenv('RELAY_SNAPSHOT_INJECT_2') ?: '';
$currentCronInterval = getenv('RELAY_CRON_INTERVAL_MINUTES') ?: '';
$currentCronEnabled = (getenv('RELAY_CRON_ENABLED') ?: '1') === '1';
$currentBackupConnectTimeout = getenv('RELAY_BACKUP_CONNECT_TIMEOUT') !== false
    ? getenv('RELAY_BACKUP_CONNECT_TIMEOUT')
    : '';
$currentBackupTransferTimeout = getenv('RELAY_BACKUP_TRANSFER_TIMEOUT') !== false
    ? getenv('RELAY_BACKUP_TRANSFER_TIMEOUT')
    : '';
$currentCacheTtl = getenv('RELAY_CACHE_TTL') !== false ? getenv('RELAY_CACHE_TTL') : (string)($config['cache_ttl'] ?? '');
$currentSnapshotTtl = getenv('RELAY_SNAPSHOT_TTL') !== false ? getenv('RELAY_SNAPSHOT_TTL') : (string)($config['snapshot_ttl'] ?? '');
$currentSnapshotAllowStale = (getenv('RELAY_SNAPSHOT_ALLOW_STALE') ?: '') !== ''
    ? getenv('RELAY_SNAPSHOT_ALLOW_STALE')
    : (!empty($config['snapshot_allow_stale']) ? '1' : '0');
$currentCacheAllowStale = (getenv('CACHE_ALLOW_STALE') ?: '') !== ''
    ? getenv('CACHE_ALLOW_STALE')
    : (!empty($config['cache_allow_stale']) ? '1' : '0');
$neverExpireChecked = ((string)$currentCacheTtl === '-1')
    && ((string)$currentSnapshotTtl === '0')
    && ((string)$currentSnapshotAllowStale === '1')
    && ((string)$currentCacheAllowStale === '1');

$refreshStatus = read_status($refreshStatusPath);
$upstreamStatus = read_status($upstreamStatusPath);
$diagnosticsStatus = read_status($diagnosticsStatusPath);
$refreshLogTail = tail_log($refreshLogPath);
$upstreamLogTail = tail_log(dirname($upstreamStatusPath) . '/upstream-check.log');
$diagnosticsLogTail = tail_log($diagnosticsLogPath);

function h(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function read_status(?string $path): array
{
    if ($path === null || $path === '' || !is_file($path)) {
        return [];
    }
    $content = @file_get_contents($path);
    if ($content === false) {
        return [];
    }
    $decoded = json_decode($content, true);
    if (!is_array($decoded)) {
        return [];
    }
    return $decoded;
}

function tail_log(string $path, int $lines = 20): string
{
    if (!is_file($path)) {
        return '';
    }
    $content = @file($path, FILE_IGNORE_NEW_LINES);
    if ($content === false) {
        return '';
    }
    $slice = array_slice($content, -$lines);
    return implode("\n", $slice);
}

function update_env(string $path, array $updates): array
{
    if (!is_file($path)) {
        return ['ok' => false, 'message' => 'Missing .env file.'];
    }

    $lines = file($path, FILE_IGNORE_NEW_LINES);
    if ($lines === false) {
        return ['ok' => false, 'message' => 'Unable to read .env file.'];
    }

    $seen = [];
    foreach ($lines as $index => $line) {
        if (preg_match('/^\s*([A-Z0-9_]+)\s*=/', $line, $matches) !== 1) {
            continue;
        }
        $key = $matches[1];
        if (!array_key_exists($key, $updates)) {
            continue;
        }
        $value = $updates[$key];
        $lines[$index] = $key . '=' . $value;
        $seen[$key] = true;
    }

    foreach ($updates as $key => $value) {
        if (!isset($seen[$key])) {
            $lines[] = $key . '=' . $value;
        }
    }

    $content = implode("\n", $lines) . "\n";
    if (file_put_contents($path, $content) === false) {
        return ['ok' => false, 'message' => 'Unable to write .env file.'];
    }

    apply_env_updates($updates);

    return ['ok' => true, 'message' => 'Updated.'];
}

function apply_env_updates(array $updates): void
{
    foreach ($updates as $key => $value) {
        if (!is_string($key)) {
            continue;
        }
        if (!is_scalar($value)) {
            continue;
        }
        $stringValue = (string)$value;
        $_ENV[$key] = $stringValue;
        putenv($key . '=' . $stringValue);
    }
}

function update_env_and_htaccess(string $envPath, string $htaccessPath, array $updates): array
{
    $result = update_env($envPath, $updates);
    if (!$result['ok']) {
        return $result;
    }

    if (!is_file($htaccessPath)) {
        return $result;
    }

    $lines = file($htaccessPath, FILE_IGNORE_NEW_LINES);
    if ($lines === false) {
        return ['ok' => false, 'message' => 'Unable to read .htaccess file.'];
    }

    $seen = [];
    foreach ($lines as $index => $line) {
        if (preg_match('/^\s*SetEnv\s+([A-Z0-9_]+)\s+"?(.*?)"?\s*$/', $line, $matches) !== 1) {
            continue;
        }
        $key = $matches[1];
        if (!array_key_exists($key, $updates)) {
            continue;
        }
        $value = $updates[$key];
        $lines[$index] = 'SetEnv ' . $key . ' "' . $value . '"';
        $seen[$key] = true;
    }

    foreach ($updates as $key => $value) {
        if (!isset($seen[$key])) {
            $lines[] = 'SetEnv ' . $key . ' "' . $value . '"';
        }
    }

    $content = implode("\n", $lines) . "\n";
    if (file_put_contents($htaccessPath, $content) === false) {
        return ['ok' => false, 'message' => 'Unable to write .htaccess file.'];
    }

    return $result;
}

function resolve_php_binary(): string
{
    $override = getenv('RELAY_PHP_BINARY') ?: '';
    if ($override !== '') {
        return $override;
    }

    $binary = PHP_BINARY ?: 'php';
    if (is_string($binary) && $binary !== '' && is_executable($binary)) {
        return $binary;
    }

    if (is_file('/usr/bin/php')) {
        return '/usr/bin/php';
    }

    return 'php';
}

function run_refresh_cache(): array
{
    $script = realpath(__DIR__ . '/../refresh-cache.php');
    if ($script === false) {
        return ['ok' => false, 'message' => 'refresh-cache.php not found.'];
    }

    $disabled = explode(',', (string)ini_get('disable_functions'));
    $disabled = array_map('trim', $disabled);
    if (in_array('shell_exec', $disabled, true) || in_array('exec', $disabled, true)) {
        return ['ok' => false, 'message' => 'shell_exec/exec disabled on this host.'];
    }

    $phpBinary = resolve_php_binary();
    $command = escapeshellcmd($phpBinary) . ' ' . escapeshellarg($script) . ' --force --manual';
    $started = start_background_process($command, $GLOBALS['refreshLogPath']);
    if (!$started) {
        return ['ok' => false, 'message' => 'Failed to execute refresh-cache.php.'];
    }

    return ['ok' => true, 'message' => 'Cache refresh started.'];
}

function run_diagnostics(string $statusPath, string $logPath): array
{
    $script = realpath(__DIR__ . '/../diagnostics.php');
    if ($script === false) {
        return ['ok' => false, 'message' => 'diagnostics.php not found.'];
    }

    $disabled = explode(',', (string)ini_get('disable_functions'));
    $disabled = array_map('trim', $disabled);
    if (in_array('shell_exec', $disabled, true) || in_array('exec', $disabled, true)) {
        return ['ok' => false, 'message' => 'shell_exec/exec disabled on this host.'];
    }

    $phpBinary = resolve_php_binary();
    $command = escapeshellcmd($phpBinary) . ' ' . escapeshellarg($script) .
        ' --json --write-status=' . escapeshellarg($statusPath) . ' --write-log=' . escapeshellarg($logPath);

    $dir = dirname($statusPath);
    if (!is_dir($dir)) {
        @mkdir($dir, 0755, true);
    }
    @file_put_contents($statusPath, json_encode([
        'ok' => null,
        'message' => 'Diagnostics running... ',
        'updated_at' => date('c'),
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

    $started = start_background_process($command, $logPath);
    if ($started) {
        return ['ok' => true, 'message' => 'Diagnostics started.'];
    }

    $inlineOk = run_diagnostics_inline($statusPath, $logPath);
    if ($inlineOk) {
        return ['ok' => true, 'message' => 'Diagnostics completed.' ];
    }

    return ['ok' => false, 'message' => 'Failed to execute diagnostics.php.'];
}

function run_diagnostics_inline(string $statusPath, string $logPath): bool
{
    require_once __DIR__ . '/../diagnostics.php';
    if (!function_exists('relay_collect_diagnostics')) {
        return false;
    }

    $config = require __DIR__ . '/../config.php';
    $options = [
        'connect-timeout' => min(10, (int)($config['connect_timeout'] ?? 10)),
        'timeout' => min(20, (int)($config['transfer_timeout'] ?? 30)),
    ];
    $collected = relay_collect_diagnostics($config, $options);
    $hasFailures = (bool)($collected['has_failures'] ?? false);
    relay_write_diagnostics_files($collected, $hasFailures, $statusPath, $logPath);
    return true;
}

function start_background_process(string $command, string $logPath): bool
{
    $dir = dirname($logPath);
    if (!is_dir($dir)) {
        @mkdir($dir, 0755, true);
    }

    if (stripos(PHP_OS, 'WIN') === 0) {
        $cmd = 'start /B ' . $command . ' > ' . escapeshellarg($logPath) . ' 2>&1';
        $result = shell_exec($cmd);
        return $result !== null;
    }

    $cmd = 'nohup ' . $command . ' > ' . escapeshellarg($logPath) . ' 2>&1 &';
    $result = shell_exec($cmd);
    return $result !== null;
}

function check_upstream(string $url, array $config): array
{
    $url = trim($url);
    if ($url === '') {
        return ['ok' => false, 'message' => 'Upstream URL is not configured.'];
    }

    $connectTimeout = min(10, (int)($config['connect_timeout'] ?? 10));
    $transferTimeout = min(15, (int)($config['transfer_timeout'] ?? 30));
    if ($connectTimeout < 1) {
        $connectTimeout = 5;
    }
    if ($transferTimeout < 1) {
        $transferTimeout = 10;
    }

    $ch = curl_init($url);
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
        return ['ok' => false, 'message' => 'Upstream check failed: ' . ($errorMsg !== '' ? $errorMsg : 'Unknown error')];
    }

    $code = (int)($info['http_code'] ?? 0);
    if ($code < 200 || $code >= 400) {
        return ['ok' => false, 'message' => 'Upstream check returned HTTP ' . $code . '.'];
    }

    return ['ok' => true, 'message' => 'Upstream reachable (HTTP ' . $code . ').'];
}

function clear_cache_dir(string $cacheDir): array
{
    if ($cacheDir === '' || !is_dir($cacheDir)) {
        return ['ok' => false, 'message' => 'Cache directory not found.'];
    }

    $deleted = 0;
    foreach (new DirectoryIterator($cacheDir) as $file) {
        if ($file->isDot() || !$file->isFile()) {
            continue;
        }
        $path = $file->getPathname();
        if (@unlink($path)) {
            $deleted++;
        }
    }

    return ['ok' => true, 'message' => 'Cleared ' . $deleted . ' cache files.'];
}

function get_cache_stats(string $cacheDir): array
{
    $stats = ['files' => 0, 'bytes' => 0, 'last_modified' => null];
    if ($cacheDir === '' || !is_dir($cacheDir)) {
        return $stats;
    }

    $latest = 0;
    foreach (new DirectoryIterator($cacheDir) as $file) {
        if ($file->isDot() || !$file->isFile()) {
            continue;
        }
        $name = $file->getFilename();
        if (substr($name, -5) === '.meta' || substr($name, -5) === '.fail') {
            continue;
        }
        if ($name === 'snapshot_manifest.json') {
            continue;
        }
        $stats['files']++;
        $stats['bytes'] += $file->getSize();
        $latest = max($latest, $file->getMTime());
    }

    if ($latest > 0) {
        $stats['last_modified'] = date('c', $latest);
    }

    return $stats;
}

function get_manifest_stats(string $manifestPath): array
{
    $stats = ['generated_at' => null, 'expires_at' => null];
    if ($manifestPath === '' || !is_file($manifestPath)) {
        return $stats;
    }

    $content = @file_get_contents($manifestPath);
    if ($content === false) {
        return $stats;
    }

    $decoded = json_decode($content, true);
    if (!is_array($decoded)) {
        return $stats;
    }

    $stats['generated_at'] = $decoded['generated_at'] ?? null;
    $stats['expires_at'] = $decoded['expires_at'] ?? null;
    return $stats;
}

function get_access_log_stats(string $logFile): array
{
    $stats = ['lines' => 0, 'hits' => 0, 'stale' => 0, 'miss' => 0, 'bypass' => 0];
    if ($logFile === '' || !is_file($logFile)) {
        return $stats;
    }

    $lines = @file($logFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if ($lines === false) {
        return $stats;
    }

    $slice = array_slice($lines, -200);
    $stats['lines'] = count($slice);
    foreach ($slice as $line) {
        $parts = explode('|', $line);
        $cacheStatus = $parts[5] ?? '';
        if ($cacheStatus === 'HIT') {
            $stats['hits']++;
        } elseif ($cacheStatus === 'STALE') {
            $stats['stale']++;
        } elseif ($cacheStatus === 'MISS') {
            $stats['miss']++;
        } elseif ($cacheStatus === 'BYPASS') {
            $stats['bypass']++;
        }
    }

    return $stats;
}

function clear_diagnostics(string $statusPath, string $logPath): array
{
    $deleted = 0;
    if ($statusPath !== '' && is_file($statusPath) && @unlink($statusPath)) {
        $deleted++;
    }
    if ($logPath !== '' && is_file($logPath) && @unlink($logPath)) {
        $deleted++;
    }
    return ['ok' => true, 'message' => 'Diagnostics cleared (' . $deleted . ' files).'];
}

function format_diagnostics(array $status): string
{
    if (empty($status['results']) || !is_array($status['results'])) {
        return '';
    }
    return json_encode($status['results'], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) ?: '';
}
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>HiRelay Admin</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600&display=swap');

        :root {
            --bg: #0b1426;
            --bg-alt: #101e38;
            --card: #12223f;
            --card-border: #1f355d;
            --text: #e7edf7;
            --muted: #aab7cf;
            --accent: #3aa7ff;
            --accent-2: #1b84e7;
            --danger: #ff6b6b;
            --ok: #3ddc97;
            --code: #0e1a33;
        }

        body { font-family: 'IBM Plex Sans', 'Segoe UI', Tahoma, sans-serif; background: radial-gradient(1200px 800px at 10% -10%, #162a4a, var(--bg)); color: var(--text); margin: 0; }
        .wrap { max-width: 900px; margin: 24px auto; padding: 0 16px; }
        .card { background: var(--card); border: 1px solid var(--card-border); border-radius: 10px; padding: 16px; margin-bottom: 16px; box-shadow: 0 6px 20px rgba(5, 10, 20, 0.35); }
        h1 { margin: 0 0 12px; font-size: 22px; font-weight: 600; }
        h2 { margin: 0 0 12px; font-size: 18px; font-weight: 500; }
        .row { display: flex; gap: 12px; flex-wrap: wrap; }
        .row > div { flex: 1 1 220px; }
        label { display: block; font-size: 13px; margin-bottom: 6px; color: var(--muted); }
        input[type="text"], input[type="password"], textarea, select { width: 100%; padding: 8px; border: 1px solid var(--card-border); border-radius: 8px; background: var(--bg-alt); color: var(--text); }
        input::placeholder, textarea::placeholder { color: #7f8fb3; }
        button { padding: 8px 12px; border: 0; border-radius: 8px; background: var(--accent); color: #0b1220; cursor: pointer; font-weight: 600; }
        button.secondary { background: #2a3b5f; color: var(--text); }
        button:hover { background: var(--accent-2); }
        button.secondary:hover { background: #34496f; }
        .message { padding: 10px; border-radius: 8px; background: rgba(61, 220, 151, 0.18); border: 1px solid rgba(61, 220, 151, 0.4); margin-bottom: 10px; }
        .error { padding: 10px; border-radius: 8px; background: rgba(255, 107, 107, 0.18); border: 1px solid rgba(255, 107, 107, 0.4); margin-bottom: 10px; }
        code { background: var(--code); padding: 2px 4px; border-radius: 4px; color: #b9d7ff; }
        pre { background: var(--code); color: #d5e3ff; border-radius: 8px; padding: 10px; border: 1px solid var(--card-border); }
        .progress { background: #0e1b33; border-radius: 6px; overflow: hidden; height: 10px; margin-top: 6px; border: 1px solid var(--card-border); }
        .progress-bar { background: linear-gradient(90deg, var(--accent), #6ac6ff); height: 100%; width: 0%; transition: width 0.3s ease; }
        .actions-row { display: flex; gap: 10px; flex-wrap: wrap; }
        .actions-row form { margin: 0; }
    </style>
</head>
<body>
<div class="wrap">
    <h1>HiRelay Admin</h1>

    <?php foreach ($messages as $message): ?>
        <div class="message"><?php echo h($message); ?></div>
    <?php endforeach; ?>

    <?php foreach ($errors as $error): ?>
        <div class="error"><?php echo h($error); ?></div>
    <?php endforeach; ?>

    <?php if (!$authReady): ?>
        <div class="card">
            <strong>Admin password not set.</strong> Configure <code>RELAY_ADMIN_PASSWORD_HASH</code> in .env.
        </div>
    <?php elseif (!$authed): ?>
        <div class="card">
            <h2>Login</h2>
            <form method="post">
                <input type="hidden" name="action" value="login">
                <label>Password</label>
                <input type="password" name="password" required>
                <div style="margin-top: 10px;">
                    <button type="submit">Login</button>
                </div>
            </form>
        </div>
    <?php else: ?>
        <div class="card">
            <form method="post" style="text-align:right;">
                <input type="hidden" name="action" value="logout">
                <button type="submit" class="secondary">Logout</button>
            </form>
            <h2>Status</h2>
            <div class="row">
                <div>
                    <label>Mode</label>
                    <div><?php echo h($currentMode); ?></div>
                </div>
                <div>
                    <label>Cache files</label>
                    <div><?php echo h((string)$cacheStats['files']); ?></div>
                </div>
                <div>
                    <label>Cache size</label>
                    <div><?php echo h(number_format($cacheStats['bytes'] / 1024, 2)); ?> KB</div>
                </div>
                <div>
                    <label>Last cache file</label>
                    <div><?php echo h((string)($cacheStats['last_modified'] ?? 'n/a')); ?></div>
                </div>
                <div>
                    <label>Manifest generated</label>
                    <div><?php echo h((string)($manifestStats['generated_at'] ?? 'n/a')); ?></div>
                </div>
                <div>
                    <label>Manifest expires</label>
                    <div><?php echo h((string)($manifestStats['expires_at'] ?? 'n/a')); ?></div>
                </div>
            </div>
            <div class="row" style="margin-top: 12px;">
                <div>
                    <label>Access log (last 200)</label>
                    <div>Hits: <?php echo h((string)$accessStats['hits']); ?> | Stale: <?php echo h((string)$accessStats['stale']); ?> | Miss: <?php echo h((string)$accessStats['miss']); ?> | Bypass: <?php echo h((string)$accessStats['bypass']); ?></div>
                </div>
                <div>
                    <label>Cron interval (minutes)</label>
                    <div><?php echo h($currentCronInterval !== '' ? $currentCronInterval : 'not set'); ?></div>
                </div>
            </div>
            <div class="row" style="margin-top: 12px;">
                <div>
                    <label>Suggested cron</label>
                    <div><code><?php echo h($currentCronInterval !== '' ? '*/' . $currentCronInterval . ' * * * * /usr/bin/php /path/to/HiRelay/apps/relay/refresh-cache.php --force' : 'Set RELAY_CRON_INTERVAL_MINUTES first'); ?></code></div>
                </div>
            </div>
            <div class="row" style="margin-top: 12px;">
                <div>
                    <label>Refresh status</label>
                    <div id="refresh-status">n/a</div>
                    <div class="progress"><div class="progress-bar" id="refresh-progress"></div></div>
                </div>
                <div>
                    <label>Upstream status</label>
                    <div id="upstream-status">n/a</div>
                </div>
            </div>
        </div>

        <div class="card">
            <h2>Actions</h2>
            <div class="actions-row">
                <form method="post">
                    <input type="hidden" name="action" value="refresh_cache">
                    <button type="submit">Force cache refresh</button>
                </form>
                <form method="post">
                    <input type="hidden" name="action" value="check_upstream">
                    <button type="submit" class="secondary">Check upstream</button>
                </form>
                <form method="post">
                    <input type="hidden" name="action" value="run_diagnostics">
                    <button type="submit" class="secondary">Run diagnostics</button>
                </form>
                <form method="post">
                    <input type="hidden" name="action" value="clear_diagnostics">
                    <button type="submit" class="secondary">Clear diagnostics</button>
                </form>
                <form method="post">
                    <input type="hidden" name="action" value="clear_cache">
                    <button type="submit" class="secondary">Clear cache</button>
                </form>
            </div>
        </div>

        <div class="card">
            <h2>Diagnostics</h2>
            <div class="row">
                <div>
                    <label>Status</label>
                    <div id="diagnostics-status"><?php echo h(($diagnosticsStatus['message'] ?? '') !== '' ? (string)$diagnosticsStatus['message'] : 'n/a'); ?></div>
                    <?php if (!empty($diagnosticsStatus['updated_at'])): ?>
                        <div id="diagnostics-updated"><?php echo h((string)$diagnosticsStatus['updated_at']); ?></div>
                    <?php endif; ?>
                </div>
                <div>
                    <label>Results</label>
                    <?php $diagnosticsFormatted = format_diagnostics($diagnosticsStatus); ?>
                    <?php if ($diagnosticsFormatted !== ''): ?>
                        <pre id="diagnostics-results"><?php echo h($diagnosticsFormatted); ?></pre>
                    <?php else: ?>
                        <div id="diagnostics-results">n/a</div>
                    <?php endif; ?>
                </div>
            </div>
            <?php if (!empty($diagnosticsLogTail)): ?>
                <label>Raw output</label>
                <pre id="diagnostics-raw"><?php echo h($diagnosticsLogTail); ?></pre>
            <?php endif; ?>
        </div>

        <div class="card">
            <h2>Latest errors</h2>
            <div class="row">
                <div>
                    <label>Refresh cache</label>
                    <div><?php echo h(($refreshStatus['message'] ?? '') !== '' ? (string)$refreshStatus['message'] : 'n/a'); ?></div>
                    <?php if (!empty($refreshLogTail)): ?>
                        <pre><?php echo h($refreshLogTail); ?></pre>
                    <?php endif; ?>
                </div>
                <div>
                    <label>Upstream check</label>
                    <div><?php echo h(($upstreamStatus['message'] ?? '') !== '' ? (string)$upstreamStatus['message'] : 'n/a'); ?></div>
                    <?php if (!empty($upstreamLogTail)): ?>
                        <pre><?php echo h($upstreamLogTail); ?></pre>
                    <?php endif; ?>
                </div>
            </div>
        </div>

        <div class="card">
            <h2>Mode</h2>
            <form method="post">
                <input type="hidden" name="action" value="update_mode">
                <label>Relay mode</label>
                <select name="mode">
                    <option value="hybrid" <?php echo $currentMode === 'hybrid' ? 'selected' : ''; ?>>hybrid</option>
                    <option value="live" <?php echo $currentMode === 'live' ? 'selected' : ''; ?>>live</option>
                    <option value="cold" <?php echo $currentMode === 'cold' ? 'selected' : ''; ?>>cold</option>
                </select>
                <div style="margin-top: 10px;">
                    <button type="submit">Update mode</button>
                </div>
            </form>
        </div>

        <div class="card">
            <h2>Inject messages</h2>
            <form method="post">
                <input type="hidden" name="action" value="update_inject">
                <div class="row">
                    <div>
                        <label>Live inject 1</label>
                        <textarea name="live_inject_1" rows="2"><?php echo h($currentLiveInject1); ?></textarea>
                    </div>
                    <div>
                        <label>Live inject 2</label>
                        <textarea name="live_inject_2" rows="2"><?php echo h($currentLiveInject2); ?></textarea>
                    </div>
                </div>
                <div class="row" style="margin-top: 10px;">
                    <div>
                        <label>Snapshot inject 1</label>
                        <textarea name="snapshot_inject_1" rows="2"><?php echo h($currentSnapshotInject1); ?></textarea>
                    </div>
                    <div>
                        <label>Snapshot inject 2</label>
                        <textarea name="snapshot_inject_2" rows="2"><?php echo h($currentSnapshotInject2); ?></textarea>
                    </div>
                </div>
                <div style="margin-top: 10px;">
                    <button type="submit">Update inject messages</button>
                </div>
            </form>
        </div>

        <div class="card">
            <h2>Cache expiration</h2>
            <form method="post">
                <input type="hidden" name="action" value="update_cache_policy">
                <label>
                    <input type="checkbox" name="never_expire" value="1" <?php echo $neverExpireChecked ? 'checked' : ''; ?>>
                    Never expire cache in hybrid/cold mode
                </label>
                <div class="row" style="margin-top: 10px;">
                    <div>
                        <label>Cache TTL (seconds, -1 = never expire)</label>
                        <input type="text" name="cache_ttl" value="<?php echo h((string)$currentCacheTtl); ?>">
                    </div>
                    <div>
                        <label>Snapshot TTL (seconds, 0 = always refresh)</label>
                        <input type="text" name="snapshot_ttl" value="<?php echo h((string)$currentSnapshotTtl); ?>">
                    </div>
                </div>
                <div class="row" style="margin-top: 10px;">
                    <div>
                        <label>
                            <input type="checkbox" name="snapshot_allow_stale" value="1" <?php echo ((string)$currentSnapshotAllowStale === '1') ? 'checked' : ''; ?>>
                            Allow stale snapshot entries
                        </label>
                    </div>
                    <div>
                        <label>
                            <input type="checkbox" name="cache_allow_stale" value="1" <?php echo ((string)$currentCacheAllowStale === '1') ? 'checked' : ''; ?>>
                            Allow stale cache entries
                        </label>
                    </div>
                </div>
                <div style="margin-top: 10px;">
                    <button type="submit">Update cache policy</button>
                </div>
            </form>
        </div>

        <div class="card">
            <h2>Auto cache interval</h2>
            <form method="post">
                <input type="hidden" name="action" value="update_cron_interval">
                <label>
                    <input type="checkbox" name="cron_enabled" value="1" <?php echo $currentCronEnabled ? 'checked' : ''; ?>>
                    Enable auto cache refresh (cron)
                </label>
                <label>Minutes (for cron)</label>
                <input type="text" name="cron_interval" value="<?php echo h($currentCronInterval); ?>" placeholder="15">
                <div style="margin-top: 10px;">
                    <button type="submit">Update interval</button>
                </div>
            </form>
        </div>

        <div class="card">
            <h2>Backup API timeouts</h2>
            <form method="post">
                <input type="hidden" name="action" value="update_backup_timeouts">
                <div class="row">
                    <div>
                        <label>Backup connect timeout (seconds)</label>
                        <input type="text" name="backup_connect_timeout" value="<?php echo h((string)$currentBackupConnectTimeout); ?>" placeholder="10">
                    </div>
                    <div>
                        <label>Backup transfer timeout (seconds)</label>
                        <input type="text" name="backup_transfer_timeout" value="<?php echo h((string)$currentBackupTransferTimeout); ?>" placeholder="60">
                    </div>
                </div>
                <div style="margin-top: 10px;">
                    <button type="submit">Update backup timeouts</button>
                </div>
            </form>
        </div>
    <?php endif; ?>
</div>
<script>
    (function () {
        var refreshEl = document.getElementById('refresh-status');
        var refreshBar = document.getElementById('refresh-progress');
        var upstreamEl = document.getElementById('upstream-status');

        function updateRefresh() {
            fetch('?status=refresh', { credentials: 'same-origin' })
                .then(function (r) { return r.json(); })
                .then(function (data) {
                    if (!refreshEl || !refreshBar) return;
                    if (!data || !data.message) {
                        refreshEl.textContent = 'n/a';
                        refreshBar.style.width = '0%';
                        return;
                    }
                    var label = data.message;
                    if (data.updated_at) {
                        label += ' (' + data.updated_at + ')';
                    }
                    refreshEl.textContent = label;
                    var progress = typeof data.progress === 'number' ? data.progress : 0;
                    refreshBar.style.width = Math.max(0, Math.min(100, progress)) + '%';
                })
                .catch(function () {});
        }

        function updateUpstream() {
            fetch('?status=upstream', { credentials: 'same-origin' })
                .then(function (r) { return r.json(); })
                .then(function (data) {
                    if (!upstreamEl) return;
                    if (!data || !data.message) {
                        upstreamEl.textContent = 'n/a';
                        return;
                    }
                    var label = data.message;
                    if (data.updated_at) {
                        label += ' (' + data.updated_at + ')';
                    }
                    upstreamEl.textContent = label;
                })
                .catch(function () {});
        }

        function updateDiagnostics() {
            var statusEl = document.getElementById('diagnostics-status');
            var updatedEl = document.getElementById('diagnostics-updated');
            var resultsEl = document.getElementById('diagnostics-results');
            if (!statusEl || !resultsEl) return;
            fetch('?status=diagnostics', { credentials: 'same-origin' })
                .then(function (r) { return r.json(); })
                .then(function (data) {
                    if (!data || !data.message) {
                        statusEl.textContent = 'n/a';
                        if (updatedEl) updatedEl.textContent = '';
                        resultsEl.textContent = 'n/a';
                        return;
                    }
                    statusEl.textContent = data.message;
                    if (updatedEl) {
                        updatedEl.textContent = data.updated_at ? data.updated_at : '';
                    }
                    if (data.results) {
                        try {
                            resultsEl.textContent = JSON.stringify(data.results, null, 2);
                        } catch (e) {
                            resultsEl.textContent = 'n/a';
                        }
                    } else {
                        resultsEl.textContent = 'n/a';
                    }
                })
                .catch(function () {});
        }

        updateRefresh();
        updateUpstream();
        updateDiagnostics();
        setInterval(function () {
            updateRefresh();
            updateUpstream();
            updateDiagnostics();
        }, 3000);
    })();
</script>
</body>
</html>
