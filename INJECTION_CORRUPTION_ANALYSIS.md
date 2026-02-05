# Injection Message Corruption Analysis & Solution

## Problem Summary

When custom message injection is enabled, the **last config in the subscription list gets corrupted**. The user's workaround (adding dummy trojan config) proves this: when injection is enabled, it corrupts the last "real" config, but works if there's a dummy config after it.

## Root Cause

### Current Flow (BROKEN)
```
Live/Hybrid Request
    ↓
[Cache miss or failover]
    ↓
Fetch from upstream (streaming response)
    ↓
INJECT into incomplete/streaming response
    ↓
Store in cache
    ↓
Output to client
```

### Why Last Config Corrupts

In `RelayService.php` line 839 (`injectMessagesIntoBody`):

```php
$decoded = base64_decode($trimmed, true);
if ($decoded !== false) {
    $decodedTrimmed = rtrim($decoded, "\r\n");  // ← Problem: trims while possibly incomplete
    $prefixed = implode("\n", $messageLines) . "\n" . $decodedTrimmed . "\n";
    return base64_encode($prefixed);
}
```

**Issue**: When the upstream response comes in via streaming:
1. cURL doesn't guarantee full body is received (transfer_timeout or network interruption)
2. base64_decode might work on incomplete base64, producing incomplete decoded configslist
3. The last config in the decoded list may be truncated
4. `rtrim()` further damages it by removing valid newlines
5. When re-encoded and stored, the last config is permanently corrupted

### Similar Issue in Snapshot Seeder
`SnapshotSeeder.php` line 507 has identical code and same vulnerability.

## Proposed Solution

**NEVER INJECT ON LIVE FETCH. Always inject on cached (complete) data.**

### New Flow (CORRECT)
```
1. CACHING PHASE (Off-peak, via cron/admin)
   ├─ Fetch complete configs from upstream
   ├─ Wait for entire response
   ├─ INJECT into complete, stored data
   ├─ Mark cache entry as "injected=true"
   └─ Store in cache

2. SERVING PHASE  
   ├─ For live requests:
   │  ├─ Check cache (cold/hybrid mode)
   │  ├─ If cache hit: serve (already injected, no re-injection)
   │  ├─ If cache miss:
   │  │  ├─ Fetch from upstream (DO NOT INJECT)
   │  │  ├─ Store in cache as "injected=false"
   │  │  └─ Serve raw
   └─ For snapshot-cached requests:
      └─ Serve with stored injected data
```

## Implementation Steps

### 1. Add "injected" Flag to Cache Metadata
Already exists in config: `'injected' => $injected` is saved in `.meta` files

### 2. Disable Live Injection
Add env var: `RELAY_INJECT_ON_LIVE_FETCH=0` (default)

When fetching from upstream in hybrid/live mode:
- **If** `RELAY_INJECT_ON_LIVE_FETCH=0` → don't inject, store as `injected=false`
- **Only** inject during pre-warming (snapshot-cache.php)

### 3. Modify RelayService.php

**OLD** (line 130-155):
```php
$response = $result['response'];
$rawResponse = $response;
if ($response !== '') {
    $response = $this->injectMessagesIntoResponse($response, $result['info']);
}
$injected = $response !== $rawResponse;
```

**NEW**:
```php
$response = $result['response'];
$rawResponse = $response;
$injected = false;

// Only inject if explicitly enabled AND mode is not live hybrid retry
$shouldInjectOnLive = (getenv('RELAY_INJECT_ON_LIVE_FETCH') ?: '0') === '1';
if ($response !== '' && $shouldInjectOnLive) {
    $response = $this->injectMessagesIntoResponse($response, $result['info']);
    $injected = $response !== $rawResponse;
}
```

### 4. Modify SnapshotSeeder (Already Correct)
- Snapshot seeder SHOULD always inject (it has complete data)
- Add check: only inject if no 'injected' flag in metadata OR 'injected' is false
- Mark output as 'injected=true' in metadata

### 5. Update Update-Cache.ps1
The PowerShell script is already correct:
- It calls `snapshot-cache.php` which injects
- Then uploads injected cache
- **No changes needed** ✓

### 6. Configuration

Add to `.env.example`:
```bash
# Injection strategy
# Set to 0 (default/recommended): Inject ONLY during snapshot caching (safe, complete data)
# Set to 1 (risky): Inject on live fetches (may corrupt last config if streaming incomplete)
RELAY_INJECT_ON_LIVE_FETCH=0
```

## Benefits

✅ **No More Corruption**: Last config never corrupted (injection only on complete cached data)  
✅ **Faster Serving**: Cached entries already injected, no re-injection per request  
✅ **More Reliable**: Pre-warming (cron) can retry; live requests fall back to raw  
✅ **Clear State**: Cache metadata clearly marks "injected" status  
✅ **Backwards Compatible**: Old `RELAY_INJECT_ON_LIVE_FETCH=1` still works if user wants to risk it

## Testing Strategy

1. Enable injection message in config
2. Set `RELAY_INJECT_ON_LIVE_FETCH=0` (default)
3. Pre-warm cache via cron or admin button
4. Fetch subscription via live request
5. Verify: message appears in first config, last config intact
6. With upstream network instability: verify last config still isn't corrupted

## Files to Modify

- `apps/relay/src/RelayService.php` (disable live injection by default)
- `apps/relay/config.php` (add new env var)
- `apps/relay/.env.example` (document new setting)
- `README.md` (update injection documentation)
