#!/usr/bin/env php
<?php
require __DIR__ . '/bootstrap.php';
$config = require __DIR__ . '/config.php';
require_once __DIR__ . '/src/SnapshotSeeder.php';

function snapshot_print_usage(): void
{
    fwrite(STDERR, "Usage: php snapshot-cache.php [--backup=path] [--paths=templ1,templ2] [--ttl=seconds] [--force]\n");
    fwrite(STDERR, "\nOptions:\n");
    fwrite(STDERR, "  --backup   Path to a Hiddify backup JSON file (defaults to RELAY_SNAPSHOT_BACKUP_PATH).\n");
    fwrite(STDERR, "  --paths    Comma-separated path templates (use %s for the user UUID). Defaults to RELAY_SNAPSHOT_PATHS or '/%s'.\n");
    fwrite(STDERR, "  --ttl      Override snapshot TTL in seconds. Defaults to RELAY_SNAPSHOT_TTL.\n");
    fwrite(STDERR, "  --force    Refresh cache entries even if they are still fresh.\n");
}

$options = getopt('', ['backup::', 'paths::', 'ttl::', 'force', 'help']);
if ($options === false || isset($options['help'])) {
    snapshot_print_usage();
    exit(isset($options['help']) ? 0 : 1);
}

$backupPath = $options['backup'] ?? ($config['snapshot_backup_path'] ?? '');
if (!is_string($backupPath)) {
    $backupPath = '';
}

$paths = $options['paths'] ?? null;
$ttl = $options['ttl'] ?? null;
$force = isset($options['force']);

try {
    $seeder = new SnapshotSeeder($config);
    $result = $seeder->seedFromBackup($backupPath, [
        'path_templates' => $paths,
        'ttl' => $ttl,
        'force' => $force,
    ]);
} catch (Throwable $e) {
    fwrite(STDERR, "Error: " . $e->getMessage() . "\n");
    exit(1);
}

fwrite(STDOUT, "Snapshot cache completed.\n");
fwrite(STDOUT, " Users processed: {$result['total_users']}\n");
fwrite(STDOUT, " Paths attempted: {$result['total_paths']}\n");
fwrite(STDOUT, " Stored: {$result['success']} | Skipped: {$result['skipped']} | Failures: {$result['failures']}\n");

$manifestPath = $config['snapshot_manifest'] ?? $config['cache_dir'] . '/snapshot_manifest.json';
fwrite(STDOUT, " Manifest written to: {$manifestPath}\n");
exit(0);
