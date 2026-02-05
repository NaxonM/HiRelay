<?php
require_once __DIR__ . '/../bootstrap.php';
// Cache extraction endpoint - secured with token
// Upload cache.zip then hit this with ?token=<secret> to extract and replace storage/cache

$envToken = getenv('EXTRACT_TOKEN');
if ($envToken === false || $envToken === '') {
    $envToken = $_ENV['EXTRACT_TOKEN'] ?? '';
}
$validToken = $envToken !== '' ? $envToken : 'change-this-secret-token';
$providedToken = $_GET['token']
    ?? ($_SERVER['HTTP_X_EXTRACT_TOKEN'] ?? '')
    ?? ($_SERVER['HTTP_X_EXTRACTTOKEN'] ?? '');

header('Content-Type: application/json; charset=utf-8');

if ($providedToken === '' || !hash_equals($validToken, $providedToken)) {
    http_response_code(403);
    $debugEnabled = ($_GET['debug'] ?? '') === '1';
    $payload = [
        'message' => 'Invalid or missing token.',
        'timestamp' => date('c'),
    ];
    if ($debugEnabled) {
        $payload['token_source'] = $envToken !== '' ? 'env' : 'default';
        $payload['token_length'] = strlen($validToken);
        $payload['env_file_exists'] = is_file(dirname(__DIR__) . '/.env');
    }
    echo json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

$accountUsername = getenv('HOST_ACCOUNT_USERNAME');
if ($accountUsername === false || $accountUsername === '') {
    $accountUsername = $_ENV['HOST_ACCOUNT_USERNAME'] ?? '';
}
$accountUsername = trim((string)$accountUsername);

$customRoots = getenv('FTP_CACHE_ROOT_PATH');
if ($customRoots === false || $customRoots === '') {
    $customRoots = $_ENV['FTP_CACHE_ROOT_PATH'] ?? '';
}
$customRoots = trim((string)$customRoots);
$customCandidates = [];
if ($customRoots !== '') {
    $parts = preg_split('/[|;,]+/', $customRoots) ?: [$customRoots];
    foreach ($parts as $part) {
        $part = trim($part);
        if ($part === '') {
            continue;
        }
        if (substr($part, -1) === '/') {
            $part = rtrim($part, '/');
        }
        if ($part === '') {
            continue;
        }
        if (substr($part, -4) === '.zip') {
            $customCandidates[] = $part;
        } else {
            $customCandidates[] = $part . '/cache.zip';
        }
    }
}

if ($accountUsername === '') {
    if (empty($customCandidates)) {
        http_response_code(404);
        echo json_encode([
            'message' => 'Extract endpoint not configured for this host.',
            'timestamp' => date('c'),
        ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        exit;
    }
} elseif (!preg_match('/^[A-Za-z0-9_]+$/', $accountUsername)) {
    http_response_code(500);
    echo json_encode([
        'message' => 'HOST_ACCOUNT_USERNAME contains invalid characters.',
        'timestamp' => date('c'),
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

$zipCandidates = [__DIR__ . '/cache.zip'];

if ($accountUsername !== '') {
    $hostHomeDir = '/home/' . $accountUsername;
    $zipCandidates[] = $hostHomeDir . '/public_ftp/cache.zip';
    $zipCandidates[] = $hostHomeDir . '/cache.zip';
}

foreach ($customCandidates as $candidate) {
    $zipCandidates[] = $candidate;
}

$zipCandidates[] = '/cache.zip';
$zipCandidates = array_values(array_unique($zipCandidates));

$targetDir = __DIR__ . '/../storage/cache';

$zipPath = null;
foreach ($zipCandidates as $candidate) {
    if (is_file($candidate)) {
        $zipPath = $candidate;
        break;
    }
}

if ($zipPath === null) {
    http_response_code(404);
    echo json_encode([
        'message' => 'Cached payload not found.',
        'timestamp' => date('c'),
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

// Clear existing cache
if (is_dir($targetDir)) {
    $files = glob($targetDir . '/*');
    foreach ($files as $file) {
        if (is_file($file)) {
            @unlink($file);
        }
    }
} else {
    @mkdir($targetDir, 0755, true);
}

// Extract
$zip = new ZipArchive();
if ($zip->open($zipPath) !== true) {
    http_response_code(500);
    echo json_encode([
        'message' => 'Failed to open cache.zip.',
        'timestamp' => date('c'),
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

$extracted = $zip->extractTo($targetDir);
$zip->close();

if (!$extracted) {
    http_response_code(500);
    echo json_encode([
        'message' => 'Extraction failed.',
        'timestamp' => date('c'),
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

// Clean up zip
@unlink($zipPath);

http_response_code(200);
echo json_encode([
    'status' => 'success',
    'message' => 'Cache extracted successfully.',
    'timestamp' => date('c'),
], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
