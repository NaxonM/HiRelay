# HiRelay

HiRelay is a unified relay service that can run in live, cold (prewarmed), or hybrid cache modes. The deployable app lives in `apps/relay` and should be identical between cPanel and VPS deployments.

## Repo layout
- `apps/relay/` -> deployable app (copy these contents to your web root on cPanel)
- `apps/relay/public/` -> web root entrypoints
- `apps/relay/src/` -> runtime classes
- `apps/relay/storage/` -> cache/log storage (local only)
- `tools/` -> automation scripts (VPS + cache tooling)

## Deploy model
### cPanel
- Copy the contents of `apps/relay/` into your host directory (e.g. `enter/`).
- Ensure the web root points to `public/`.
- Create a `.env` next to `public/` using `apps/relay/.env.example` as the template.
- Optionally copy `apps/relay/.htaccess.example` to `.htaccess` and adjust envs.

### VPS
Use the control script in `tools/relayctl.sh`. It deploys the repo and serves `apps/relay/public` via nginx.

Fetch the latest `relayctl.sh` from the repo:
```bash
curl -fsSL https://raw.githubusercontent.com/NaxonM/HiRelay/main/tools/relayctl.sh -o relayctl.sh
chmod +x relayctl.sh
```

## Configuration
- Do not commit `.env` or secrets.
- Use `apps/relay/.env.example` as the base.
- Logs and cache live in `apps/relay/storage/` (not committed).

## Quick start (local)
```bash
php -S 0.0.0.0:8080 -t apps/relay/public
```

## Environment variables
- RELAY_UPSTREAM_BASE_URL: Upstream server base URL (required for live/hybrid)
- CACHE_SOURCE_BASE_URL: Base URL used to build cache keys (defaults to RELAY_UPSTREAM_BASE_URL)
- RELAY_AUTH_TOKEN: Shared secret (Bearer token or ?token=)
- RELAY_ALLOWED_CLIENTS: Comma-separated allowlist of client IPs
- RELAY_CACHE_ENABLED: 1 or 0
- RELAY_CACHE_TTL: Cache lifetime in seconds (-1 = never expire)
- RELAY_CACHE_DIR: Cache directory (default apps/relay/storage/cache)
- RELAY_LOG_FILE: Log file path (default apps/relay/storage/relay.log)
- RELAY_ACCESS_LOG_FILE: Access log path (default apps/relay/storage/access.log)
- RELAY_CONNECT_TIMEOUT: Upstream connect timeout seconds
- RELAY_TRANSFER_TIMEOUT: Upstream transfer timeout seconds
- RELAY_CURL_PROXY: Optional proxy for upstream requests
- RELAY_PATH_TEMPLATE: Optional path template, use %s for UUID
- RELAY_MODE: live | cold | hybrid (default hybrid)
- RELAY_SECURITY_HEADERS: 1 or 0 (default 1)
- RELAY_REQUEST_VALIDATION: 1 or 0 (default 0)
- RELAY_REQUEST_VALIDATION_PATTERN: Regex for path validation
- RELAY_RATE_LIMIT_ENABLED: 1 or 0 (default 0)
- RELAY_RATE_LIMIT_COUNT: Max requests per window
- RELAY_RATE_LIMIT_WINDOW: Window seconds
- RELAY_RATE_LIMIT_BURST: Burst limit
- RELAY_RATE_LIMIT_GRACEFUL: 1 or 0 (default 1)
- RELAY_RATE_LIMIT_WHITELIST: Comma-separated IPs to bypass limits
- RELAY_RATE_LIMIT_DIR: Rate limit storage dir (default apps/relay/storage/ratelimit)
- RELAY_CACHE_MAX_SIZE_MB: Max cache size in MB (0 disables)
- RELAY_CACHE_CLEANUP_CHANCE: 0-100 chance per request (default 1)
- RELAY_HYBRID_FAILOVER_TTL: Seconds to serve cache after an upstream failure (default 120)
- RELAY_SNAPSHOT_BACKUP_PATH: Default backup JSON path for snapshot-cache.php
- RELAY_CRON_INTERVAL_MINUTES: Suggested cron interval for refresh-cache.php
- RELAY_SNAPSHOT_PATHS: Comma-separated path templates for seeding
- RELAY_SNAPSHOT_TTL: Snapshot freshness window seconds (0 = always refresh)
- RELAY_SNAPSHOT_PARALLEL: Parallel workers for seeding
- RELAY_SNAPSHOT_RETRIES: Retry count for seeding
- RELAY_SNAPSHOT_INJECT_1: Optional injected line for snapshot cache
- RELAY_SNAPSHOT_INJECT_2: Optional injected line for snapshot cache
- RELAY_LIVE_INJECT_1: Optional injected line for live fetches (falls back to snapshot inject)
- RELAY_LIVE_INJECT_2: Optional injected line for live fetches (falls back to snapshot inject)
- RELAY_SNAPSHOT_MANIFEST: Snapshot manifest path
- RELAY_SNAPSHOT_ALLOW_STALE: Allow serving stale snapshot entries
- CACHE_ALLOW_STALE: Allow serving expired snapshot entries in cold mode
- EXTRACT_TOKEN: Token for apps/relay/public/extract.php
- HOST_ACCOUNT_USERNAME: cPanel account username for extract.php
- FTP_CACHE_ROOT_PATH: Optional override for cache.zip discovery
- RELAY_ADMIN_PASSWORD_HASH: Password hash for /admin dashboard

## Cold cache workflow
1. Run apps/relay/snapshot-cache.php with a backup JSON to build apps/relay/storage/cache and snapshot_manifest.json.
2. Zip apps/relay/storage/cache into cache.zip.
3. Upload cache.zip to the host.
4. Call public/extract.php with ?token=YOUR_TOKEN.

## Cron-based cache refresh (host)
Use apps/relay/refresh-cache.php to fetch users from the upstream API and rebuild cache on a schedule.

Required envs:
- RELAY_BACKUP_API_URL
- RELAY_BACKUP_API_KEY
- RELAY_SNAPSHOT_BACKUP_PATH

Example cron entry:
- */15 * * * * /usr/bin/php /path/to/HiRelay/apps/relay/refresh-cache.php --force

## Endpoints
- / -> main relay
- /healthz -> health check
- /extract.php -> cache extraction endpoint (apps/relay/public/extract.php)
- /admin -> admin dashboard (apps/relay/public/admin.php)

## Admin dashboard
Set RELAY_ADMIN_PASSWORD_HASH to a bcrypt/argon hash to enable login on /admin.
Use a PHP one-liner to generate a hash:
- php -r "echo password_hash('your-password', PASSWORD_DEFAULT);"

## Notes
- The PowerShell cache automation is intended for cPanel deployments.
- VPS deployment uses relayctl.sh; ensure APP_DIR points to apps/relay if you customize paths.
