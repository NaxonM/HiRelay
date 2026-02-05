<?php
function relay_load_env(): void
{
    $paths = [
        __DIR__ . '/.env',
        '/etc/hiddify-relay/.env',
        '/etc/relay-service/.env',
    ];
    foreach ($paths as $path) {
        if (!is_file($path)) {
            continue;
        }
        foreach (file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [] as $line) {
            if ($line === '' || $line[0] === '#') {
                continue;
            }
            if (strpos($line, '=') === false) {
                continue;
            }
            [$key, $value] = array_map('trim', explode('=', $line, 2));
            if ($key === '') {
                continue;
            }
            if (!array_key_exists($key, $_ENV)) {
                $_ENV[$key] = $value;
            }
            if (getenv($key) === false) {
                putenv($key . '=' . $value);
            }
        }
    }
}

relay_load_env();

$timezone = getenv('RELAY_TIMEZONE') ?: (ini_get('date.timezone') ?: '');
if (is_string($timezone) && $timezone !== '') {
    date_default_timezone_set($timezone);
}

if (!defined('HIRELAY_BOOTSTRAPPED')) {
    define('HIRELAY_BOOTSTRAPPED', true);
}
