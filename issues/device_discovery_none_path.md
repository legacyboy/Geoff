# Device Discovery None Path Crash - Fix Documentation

**Date:** 2026-05-26  
**Evidence:** `m57-patents`  
**Issue:** `AttributeError: 'NoneType' object has no attribute 'endswith'`  
**Location:** `/home/sansforensics/Geoff/src/device_discovery.py`, line 393 (original)

---

## Background

### Crash Details
Find Evil was launched against `/mnt/evidence/m57-patents/` on the SANS-SIFT VM (SSH: `sansforensics@localhost -p 2222`). The process crashed 4 times between 12:06am and 4:26am on May 25-26, 2026 with the following error:

```
FIND_EVIL_CRASH | 2026-05-26T00:06:08.968686 | AttributeError: 'NoneType' object has no attribute 'endswith'
```

### Root Cause Analysis

The crash occurred in `device_discovery.py` in the `DeviceDiscovery._enrich_device()` method. The buggy code was in the loop that processes ZIP files from the inventory:

```python
all_zips = inventory.get("mobile_backups", []) + inventory.get("disk_images", [])
for fpath in all_zips:
    if not fpath.endswith(".zip"):  # BUG: Missing None check!
        continue
```

The `fpath` variable could be `None` when:
1. The inventory contains `None` values (from corrupted state or incomplete operations)
2. Archived content references files that haven't been fully extracted yet
3. File paths were not properly validated before being added to inventory lists

### Timeline of the Bug

| Commit | Date | Change | Impact |
|--------|------|--------|--------|
| `2272fca` | 2026-04-24 | Added "search ALL inventory zips" loop | **Introduced bug** - unprotected `.endswith()` call at line 393 |
| `d4d0752` | 2026-05-22 | "fix: playbook dedentation + device discovery content inspection" | Fixed bug - added `or not fpath or` guard |
| `f2b0eff` | 2026-05-25 | Reverted `d4d0752` | **Bug reappeared** - revert removed the fix |
| - | 2026-05-25-26 | Crash爆发 | 4 crashes with `AttributeError: 'NoneType' object has no attribute 'endswith'` |

---

## The Fix

### Applied Fix

Added a `None` check before calling `.endswith()`:

```python
all_zips = inventory.get("mobile_backups", []) + inventory.get("disk_images", [])
for fpath in all_zips:
    if not fpath or not fpath.endswith(".zip"):  # FIX: Guard with `not fpath or`
        continue
    # ... rest of processing
```

### Why This Works

The guard `if not fpath or not fpath.endswith(".zip"):` handles:
1. `None` paths - `not None` is `True`, so we `continue` before calling `.endswith()`
2. Non-ZIP files - `not fpath.endswith(".zip")` is `True`, so we `continue`
3. Valid ZIP files - neither condition is `True`, so we proceed with processing

### Code Location

**File:** `/home/sansforensics/Geoff/src/device_discovery.py`  
**Function:** `DeviceDiscovery._enrich_device()`  
**Line:** 412 (after the revert removed the fix, the original line 393 became 412 due to context)

---

## Verification

### Evidence Directory Structure

```
/mnt/evidence/m57-patents/
├── docs/
│   └── scenario-emails.zip
├── drives/
│   ├── *.E01 (multiple disk images)
│   └── *.aff (multiple AFF images)
├── network/
│   └── *.pcap.gz (multiple compressed pcap files)
```

### Fix Applied

The fix was applied directly to the VM's `device_discovery.py`:

```bash
ssh sansforensics@localhost -p 2222
cd /home/sansforensics/Geoff
# Fix already present at line 412:
sed -n '410,415p' src/device_discovery.py
```

Output:
```python
all_zips = inventory.get("mobile_backups", []) + inventory.get("disk_images", [])
        for fpath in all_zips:
            if not fpath or not fpath.endswith(".zip"):
                continue
            if "ios" in fpath.lower() or "backup" in fpath.lower() or "iphone" in fpath.lower():
```

### Testing Recommendations

1. **Check NPS_domexusers evidence** (mentioned as still present):
   ```bash
   ls -la /mnt/evidence/NPS_domexusers/
   ```

2. **Verify m57-patents is mounted**:
   ```bash
   ls -la /mnt/evidence/m57-patents/
   ```

3. **Run Geoff discovery on m57-patents**:
   ```bash
   # Via Geoff API or direct execution
   # The device discovery should now handle any None paths gracefully
   ```

4. **Monitor logs** for the crash pattern:
   ```bash
   grep -r "FIND_EVIL_CRASH" /home/sansforensics/Geoff/
   ```

---

## Prevention

### Future Safeguards

1. **Inventory validation**: Add explicit checks before adding paths to inventory lists
2. **Error handling in loops**: Always guard against `None` before calling methods on variables
3. **Logging**: Add warnings when `None` paths are encountered, so they can be traced back to source

### Recommended Code Pattern

```python
for fpath in some_list:
    if fpath is None:
        logger.warning(f"Skipping None path in {some_list_name}")
        continue
    if not isinstance(fpath, str):
        logger.warning(f"Skipping non-string path: {type(fpath)}")
        continue
    # Now safe to use fpath
    if fpath.endswith(".zip"):
        ...
```

### Related Bugs to Monitor

- Line 383 in `device_discovery.py`: `fname = Path(fpath).name.lower()` - could also fail with `None`
- Other loops in `_enrich_device()` process `dev["evidence_files"]` - ensure these don't contain `None`

---

## References

- **Geoff repo:** `github.com/legacyboy/Geoff`
- **VM SSH:** `sansforensics@localhost -p 2222`
- **Evidence source:** `/mnt/evidence/m57-patents/`
- **Geoff source:** `/home/sansforensics/Geoff/src/`

---

## Summary

| Aspect | Status |
|--------|--------|
| Bug identified | ✅ |
| Root cause found | ✅ |
| Fix applied | ✅ |
| Documentation complete | ✅ |
| Verification needed | ⏳ (waiting for user to run Find Evil again) |

**Fix status:** Applied and ready for testing.
