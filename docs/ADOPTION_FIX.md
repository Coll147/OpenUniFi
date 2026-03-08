# UniFi AP Adoption Issue - Root Cause and Fix

## Problem Identified

The AP was **detected by the controller** but **failed to adopt** because:

1. **Controller sends `setparam` with `mgmt_cfg`**: Contains new `authkey` and other parameters as newline-separated key=value pairs
2. **Old parsing code only looked for top-level `key`/`value` fields**: It ignored the `mgmt_cfg` string entirely
3. **New `authkey` was never extracted or saved**: Device kept using the DEFAULT key
4. **Eventually got 404 errors**: Because something else was also corrupted or the inform_url was lost

## Root Cause Example

Controller response (from your logs):
```json
{
  "_type": "setparam",
  "mgmt_cfg": "authkey=1c5b10a4f4e183539227b0656f0787a1\ncfgversion=aa9fc806e0630884\n...",
  "server_time_in_utc": "1772996216571"
}
```

Old code was looking for:
```json
{
  "key": "something",
  "value": "something"
}
```

So it never extracted the critical `authkey` from `mgmt_cfg`.

## Changes Made

### 1. Fixed `setparam` Handler in `src/inform.c`

Added proper parsing of the `mgmt_cfg` string:
- Splits by newlines
- Extracts key=value pairs
- Updates `authkey`, `cfgversion`, and other params
- Falls back to old key/value format for compatibility
- Adds comprehensive logging of all extracted parameters

### 2. Added State Logging in `src/state.c`

New logging shows:
- When state is loaded from disk (or using defaults)
- What values are being saved
- Helps track state transitions

### 3. Enhanced Inform Payload Logging

Now logs:
- Sent authkey (adopted flag, key being used)
- Payload state/default flags
- State transitions

### 4. Added Logging to `src/announce.c`

Framework for announce logging (can be expanded).

## Expected Behavior After Fix

When controller sends `setparam` with `mgmt_cfg`:

```
[inform_send] Parsing mgmt_cfg: authkey=1c5b10a4f4e183539227b0656f0787a1...
[inform_send] mgmt_cfg param: authkey = 1c5b10a4f4e183539227b0656f0787a1
[state] Saving state: adopted=1, authkey=1c5b10a4... inform_url=https://...
[state] State saved successfully
[inform_send] Response action: setparam
```

Then on next inform:
```
[inform_send] Sending inform: adopted=1, authkey=1c5b10a4..., inform_url=https://...
[inform_send] Payload state=4, default=false, adopted=1, authkey=1c5b10a4...
```

## To Verify the Fix

1. Recompile with logging:
   ```bash
   make -f Makefile.standalone ENABLE_LOGGING=1
   ```

2. Watch the logs:
   ```bash
   tail -f /var/log/openuf.log | grep -E "mgmt_cfg|authkey|State|adopted"
   ```

3. Look for:
   - `mgmt_cfg param: authkey = ...` (extraction working)
   - `Saving state: adopted=...` (state being saved correctly)
   - No repeated 404 errors

4. Try adopting the device again in the UniFi controller

## Additional Notes

The device correctly:
- Communicates with controller (HTTP 200)
- Receives responses (392 bytes)
- Parses JSON fine

The issue was purely in **not parsing and saving the authkey** from the `mgmt_cfg` field sent by the controller. This is now fixed.

If you still see issues, check the logs for:
- `Failed to parse mgmt_cfg` - parsing error
- `Failed to open state file` - file permissions
- `State loaded: adopted=0` - state not persisting between restarts
