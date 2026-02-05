# Implementation Guide: Safe Injection Strategy

## Summary

The corruption of the last config happens because custom message injection was being applied to incomplete/streaming HTTP responses from the upstream. This fix implements a **safe injection strategy**:

✅ **NEW (SAFE)**: Inject only during snapshot pre-caching (cron/admin) → Store complete cached configs in database → Serve cached configs (already injected)

❌ **OLD (UNSAFE)**: Fetch from upstream → Inject into streaming response → Store → Serve

## What Changed

### 1. Configuration
Added new env var: **`RELAY_INJECT_ON_LIVE_FETCH`** (default: `0`)

```bash
# RECOMMENDED (default - safe)
RELAY_INJECT_ON_LIVE_FETCH=0
# Inject messages ONLY during snapshot caching (when configs are complete)

# LEGACY (risky - old behavior)
RELAY_INJECT_ON_LIVE_FETCH=1
# Inject messages on live upstream fetches (may corrupt last config)
```

### 2. New Workflow

#### Phase 1: Pre-caching (Safe Injection)
```
Admin clicks "Refresh Cache" or cron runs
    ↓
Fetch complete user list from backup API
    ↓
Snapshot-cache.php generates & seeds all configs
    ↓
INJECT messages into EACH COMPLETE config (safe, no streaming)
    ↓
Store caches in database with 'injected=true' flag
    ↓
Upload via FTP (if cPanel)
```

#### Phase 2: Serving (No Re-injection)
```
Client requests subscription
    ↓
Check cache (hybrid/cold mode)
    ↓
If cache hit: Serve directly (already injected, no corruption possible)
    ↓
If cache miss: Fetch from upstream raw, serve raw
    (Message injection already in cache, not needed here)
```

## Setup Instructions

### For VPS (nginx + relay service)

1. **That's it!** The default is now safe. Just run your cron job:
   ```bash
   sudo /usr/bin/php /opt/hiddify-relay/apps/relay/refresh-cache.php --force
   ```
   
   The snapshot seeder will:
   - Fetch and cache all configs
   - Inject messages WHILE caching (safe, complete data)
   - Serve injected cached configs to clients

2. If you want old unsafe behavior (live injection):
   ```bash
   # In /etc/hiddify-relay/.env
   RELAY_INJECT_ON_LIVE_FETCH=1
   ```
   (NOT RECOMMENDED - can corrupt last config)

### For cPanel/Host (PowerShell)

No changes needed! The `Update-Cache.ps1` script already:
1. Calls `snapshot-cache.php` which does the safe injection
2. Uploads the already-injected cache

Just keep running it as-is.

## Migration from Old Setup

If you currently rely on live-fetch injection:

### Step 1: Enable safe injection (default)
```bash
# Ensure this is 0 (or not set, since 0 is default)
RELAY_INJECT_ON_LIVE_FETCH=0
```

### Step 2: Set up regular pre-caching
```bash
# Run snapshot-cache.php regularly via cron (recommended every 15 mins)
*/15 * * * * /usr/bin/php /opt/hiddify-relay/apps/relay/refresh-cache.php --force
```

Or use the admin dashboard: **Relay Settings** → **Refresh Cache** button

### Step 3: Verify
1. Enable injection messages in config:
   - `RELAY_SNAPSHOT_INJECT_1=<your message>`
2. Trigger cache refresh (cron or admin button)
3. Fetch subscription - message should appear in first config
4. **Last config should NOT be corrupted** ✓

## Troubleshooting

### Message doesn't appear
- Check that `RELAY_SNAPSHOT_INJECT_1` is set
- Verify cache refresh was triggered (check logs)
- Check that `RELAY_INJECT_ON_CACHE_OUTPUT=1`

### Last config still corrupted
- Ensure `RELAY_INJECT_ON_LIVE_FETCH=0` (default)
- Force cache refresh: `php refresh-cache.php --force`
- Check if snapshot-cache.php ran successfully (look at logs)

### Want old behavior (live injection)
Edit `/etc/hiddify-relay/.env`:
```bash
RELAY_INJECT_ON_LIVE_FETCH=1
```
**WARNING**: This can corrupt last config if upstream connection is slow/interrupted

## FAQ

**Q: Why was injection on live fetches even done?**  
A: It was designed as a fallback when cache didn't exist. But it's an incomplete scenario with corrupting side effects.

**Q: Does this affect snapshot-cache.php?**  
A: No. Snapshot seeder ALWAYS injects (it has complete configs). This only affects live HTTP GET requests to the relay without pre-caching.

**Q: What if I have hybrid mode with live injection disabled?**  
A: 
- If cache exists: Serve cached (already injected from pre-warming)
- If cache misses: Serve raw from upstream (no injection, but complete data)

**Q: Will my subscribers see the message?**  
A: Yes - the message will be in each cached config since we pre-warm the cache. They'll get it every time they request the subscription.

**Q: Do I need to clear old cache?**  
A: No, but it's recommended to refresh cache at least once after upgrade so configs are re-injected safely.

## Performance

**BEFORE** (unsafe):
- Every request: Check cache → If miss, fetch upstream → Inject → Store

**AFTER** (safe):
- Pre-caching phase (off-peak): Fetch all → Inject all → Store all
- Request phase (all hits): Serve cached (instant)

Result: **Faster serving** + **No corruption** + **Predictable**
