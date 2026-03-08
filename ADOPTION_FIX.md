# UniFi AP Adoption Issue - Root Cause Analysis and Fixes

## Problem Identified

The adoption process was **stuck in a loop** because device was using the **wrong authentication key**.

### Symptoms from Logs
```
[build_payload] Payload state=1, default=true, adopted=0, x_authkey=c93aec16...
```

- `adopted=0` ✓ Correct (not yet adopted)
- `x_authkey=c93aec16` ✗ **WRONG!** Should be `ba86f2bbe107c7c57eb5f2690775c712` (DEFAULT_AUTH_KEY)

### Why This Breaks Adoption
1. Device encrypts inform packet with **wrong key** (c93aec16)
2. Controller receives packet, tries to decrypt with DEFAULT key
3. Decryption fails or controller rejects packet
4. Controller never sends `set-adopt` command
5. Device stuck in loop sending only `setparam` responses

## Root Cause #1: Incorrect `setparam` Handler

**The Bug:**
```c
// OLD CODE - WRONG!
if (!strcmp(key, "authkey")) {
    LOG("Updating authkey from mgmt_cfg");
    strncpy(st->authkey, val, sizeof(st->authkey)-1);  ← Saves WRONG key!
}
```

The code was extracting `authkey` from the `mgmt_cfg` string in `setparam` responses and **saving it even though `adopted=0`**.

**Timeline of corruption:**
```
Controller sends: setparam { mgmt_cfg: "authkey=c93aec16\nuse_aes_gcm=true\n..." }
                  ↓
Old code: "there's an authkey in mgmt_cfg, save it!"
                  ↓
Device saves: st.authkey=c93aec16, st.adopted=0 ← WRONG STATE!
                  ↓
Next inform encrypts with c93aec16 instead of DEFAULT
                  ↓  
Controller receives packet encrypted with unknown key
                  ↓
Controller never sends set-adopt command
                  ↓
Stuck in loop forever
```

**The Critical Mistake:**
The `mgmt_cfg.authkey` field is a **management configuration parameter** (device config sent by controller), NOT the **adoption key**. These are different:
- **DEFAULT_AUTH_KEY**: Used for unadopted devices to start conversation
- **mgmt_cfg.authkey**: Management parameters for already-connected devices
- **Adoption key (from set-adopt)**: The real key for encrypted communication after adoption

## Root Cause #2: Corrupted State File Persistence

If a previous run saved the wrong authkey with `adopted=0`, the device would:

1. Reboot/restart
2. Load state: `adopted=0, authkey=c93aec16` (from corrupted file)
3. Never recover unless state file is deleted

## Correct Adoption Protocol

```
STEP 1: Device Starts Unadopted
  ├─ adopted = 0
  ├─ authkey = DEFAULT (ba86f2bbe107c7c57eb5f2690775c712)
  └─ Send inform with x_authkey=DEFAULT, state=1, default=true

STEP 2: Controller Receives Unadopted Inform
  └─ Recognizes DEFAULT key, decrypts payload, sees unadopted device

STEP 3: Controller Responds with Adoption Command
  └─ Response: { _type: "cmd", cmd: "set-adopt", key: "c93aec16...", uri: "https://..." }

STEP 4: Device Processes Adoption
  ├─ Saves: adopted=1, authkey=c93aec16
  └─ Saves state to file

STEP 5: Device Sends Next Inform as Adopted
  ├─ authkey = c93aec16 (new adoption key)
  ├─ state = 4
  ├─ default = false
  └─ Encrypted with c93aec16

STEP 6: Controller Now Manages Device
  └─ Sends setstate, radio_table, vap_table, etc.
```

## Changes Implemented

### 1. **Fix setparam Handler** (`src/inform.c`—lines ~660-710)

**Changes:**
- ❌ **Removed**: Code that extracts and saves `authkey` from `mgmt_cfg`
- ✅ **Kept**: Code that extracts `cfgversion` (needed for config management)
- ✅ **Added**: Explanation comment about why authkey from mgmt_cfg is ignored

**Code:**
```c
if (!strcmp(key, "cfgversion")) {
    strncpy(st->cfgversion, val, sizeof(st->cfgversion)-1);
} else if (!strcmp(key, "mgmt_url")) {
    /* Could save mgmt_url for future use */
}
/* IMPORTANT: Do NOT save authkey from mgmt_cfg!
   Only accept authkey from set-adopt command when adopted. */
```

### 2. **Reset Authkey on Unadopted Load** (`src/state.c`—lines ~50-65)

**Purpose:** Prevent corrupted state from blocking adoption forever.

**Change:**
```c
/* If not adopted, force DEFAULT_AUTH_KEY */
if (!st->adopted) {
    LOG("Device not adopted - resetting authkey to DEFAULT");
    strncpy(st->authkey, DEFAULT_AUTH_KEY, sizeof(st->authkey) - 1);
}
```

### 3. **Unadopted Key Safety Check** (`src/inform.c`—lines ~745-755)

**Purpose:** Double-safety to catch any remaining incorrect keys during inform.

**Change:**
```c
/* When not adopted, ALWAYS use DEFAULT_AUTH_KEY */
if (!st->adopted && st->authkey[0] && strcmp(st->authkey, DEFAULT_AUTH_KEY) != 0) {
    LOG("WARNING: Device not adopted but has custom authkey! Using DEFAULT instead!");
    key_hex = DEFAULT_AUTH_KEY;
}
```

### 4. **Enhanced Logging**
- Log initial device state at startup
- Log authkey validation steps
- Show key mismatch warnings
- Track state transitions in detail

## Testing the Fix

### Test 1: Clean Device (First Time)
```bash
# Delete corrupted state
rm /etc/openuf/state.json

# Recompile with logging
make -f Makefile.standalone ENABLE_LOGGING=1

# Run daemon
/usr/sbin/openuf

# Watch logs in another terminal
tail -f /var/log/openuf.log
```

**Expected behavior:**
```
[state_load] State file not found, using defaults
[state_load] State loaded: adopted=0, authkey=ba86f...
[main] Initial device state: adopted=0, authkey=ba86f...
[inform_send] Sending inform: adopted=0, authkey=ba86f...
[build_payload] x_authkey=ba86f2bbe107c7c57eb5f2690775c712  ← CORRECT!
[inform_send] HTTP POST to http://192.168.1.2:8080/inform, status: 200
[inform_send] Parsed response JSON: {..._type:cmd, cmd:set-adopt...}
[handle_response] Handling response type: cmd
[handle_response] Adopted successfully. Key: c93aec16...
[state_save] Saving state: adopted=1, authkey=c93aec16...
```

### Test 2: Corrupted Device (Wrong Authkey)
```bash
# Simulate corrupted state from logs
cat > /etc/openuf/state.json << 'EOF'
{
  "adopted": false,
  "authkey": "c93aec16f4e183539227b0656f0787a1",
  "inform_url": "http://192.168.1.2:8080/inform",
  "cfgversion": "0",
  "mac": "80:af:ca:8f:d9:bb",
  "ip": "192.168.1.5",
  "hostname": "U6 IW"
}
EOF

# Run daemon
/usr/sbin/openuf

# Watch logs
tail -f /var/log/openuf.log
```

**Expected behavior:**
```
[state_load] Device not adopted - resetting authkey to DEFAULT
[state_load] State loaded: adopted=0, authkey=ba86f...
[main] Initial device state: adopted=0, authkey=ba86f...
[inform_send] Sending inform: adopted=0, authkey=ba86f...
[build_payload] x_authkey=ba86f2bbe107c7c57eb5f2690775c712  ← FIXED!
```

### Test 3: Verify No `setparam` Authkey Extraction
Look for this in logs - should NOT appear:
```
❌ SHOULD NOT SEE: [handle_response] mgmt_cfg param: authkey = 
```

## Verification Checklist

- [ ] When unadopted: logs show `x_authkey=ba86f2bbe107...` (DEFAULT)
- [ ] Device transitions to adopted
- [ ] Once adopted: logs show `x_authkey=c93aec16...` (adoption key)
- [ ] No "Updating authkey from mgmt_cfg" logs
- [ ] No "WARNING: Device not adopted but has custom authkey" logs
- [ ] Controller UI shows device moving from "Adoption" → "Connected"
- [ ] Device survives restart while adopted with correct key
- [ ] Corrupted state file is always corrected on device startup

## Quick Diagnostic Commands

```bash
# Check current state on device
cat /etc/openuf/state.json

# Check if authkey is wrong while unadopted
grep "adopted.*:.*false" /etc/openuf/state.json && \
grep "authkey.*:.*c93aec16" /etc/openuf/state.json && \
echo "ERROR: Corrupted state found!"

# Watch adoption process
tail -f /var/log/openuf.log | grep -E "Sending inform|set-adopt|x_authkey"

# Reset device to unadopted state
rm /etc/openuf/state.json
/etc/init.d/openuf restart
```

## Summary

**What was wrong:**
- setparam handler saved wrong key from mgmt_cfg
- Device used c93aec16 instead of DEFAULT when unadopted
- Controller never sent adoption command
- Device stuck in configuration loop

**How it's fixed:**
1. Don't extract/save authkey from mgmt_cfg (it's config, not auth)
2. Force DEFAULT_AUTH_KEY when device is unadopted
3. Only accept authkey during set-adopt command
4. Corrupted state files are automatically corrected on load
5. Double-safety check prevents encryption with wrong key

**Result:**
- Device always starts adoption with DEFAULT key
- Controller recognizes unadopted device
- Adoption command flows correctly
- Adoption completes successfully
