# Email Processing Debug - Root Cause Analysis

## Problem
PB-SIFT-023 (Email Forensics) never runs against `outlook.pst` found inside
the M57-jean disk image. Zero phishing detections in the final report.

## The Data Flow (Where It Breaks)

### Step 1: Mount & Discover (`geoff_discovery.py:_mount_and_discover`)
```
nps-2008-jean.E02 (EWF format, 10GB)
  → ewfmount succeeds → /tmp/geoff_ewf_PID/ewf1 (raw device)
  → sudo mount fails (corrupted NTFS: "Record 0 has no FILE magic")
  → fls fallback runs on ewf1 raw device
  → fls finds outlook.pst (inode listing)
  → icat extraction FAILS → extracted_path stays as "E02::outlook.pst"
  → PST added to new_evidence["email_files"] with :: path
  → PST added to nuclear_findings with full_path = :: path
  → Mount remains False → `if not mounted: continue` skips images_processed++
  → Result: nuclear_images_processed = 0, walked_disks = []
```

### Step 2: Merge into inventory (`_mount_and_discover` merge phase)
```
new_evidence["email_files"] merged into inventory["other_files"]
  → inventory["other_files"].append("/mnt/.../E02::outlook.pst")
```

### Step 3: Nuclear attribution (`find_evil()`)
```
nuclear_findings iterated → but the loop checks:
  _nf.get("image") in dev["evidence_files"]
  _nf.get("full_path") appended to dev["evidence_files"]
  
BUG: The checkpoint was created by older code that didn't populate
nuclear_findings in the fls fallback path. The current code does, but
the checkpoint was saved before the fix. So nuclear_findings is [].
```

### Step 4: device_evidence construction
```
For each dev in device_map:
  For each fpath in dev["evidence_files"]:
    If fpath in inventory["other_files"] → device_evidence[dev][other_files].append(fpath)
    
The E02::outlook.pst path IS in inventory["other_files"] (merge phase),
but is NOT in any dev["evidence_files"] (attribution skipped).
So device_evidence has no other_files for nps-2008-jean.
```

### Step 5: PB-SIFT-023 execution
```
For ev_type, step_templates in PB-SIFT-023_STEPS:
  evidence_items = device_evidence[dev_id].get(ev_type, [])  → []
  if not evidence_items: continue  ← SKIPS
  → No email steps ever run
  → 0 phishing detections
```

## Root Causes (5 bugs)

### Bug 1: fls fallback doesn't flag image as processed
- File: `geoff_discovery.py`, `_mount_and_discover()`
- Line: After the fls/sleuthkit fallback finds files, `mounted` stays False
- Effect: `if not mounted: continue` skips `images_processed += 1`
- Result: `nuclear_images_processed = 0` even when fls found dozens of files

### Bug 2: icat extraction failure for PST files
- File: `geoff_discovery.py`, fls fallback path
- Issue: When `icat` fails for PST/OST, `extracted_path` stays as `internal_ref`
  (e.g., "/mnt/evidence/jeanm57/nps-2008-jean.E02::outlook.pst")
- The `::` path is not a real filesystem path - tools can't use it
- Effect: Even if PB-SIFT-023 sees the file, it can't open it

### Bug 3: nuclear_evidence not used for attribution
- File: `geoff_pipeline.py`, `find_evil()`, nuclear attribution section
- Current: Only uses `nuclear_result.get("nuclear_findings")` for attribution
- Missing: Does NOT attribute files from `nuclear_evidence` buckets (email_files, 
  browser_artifacts, etc.) directly to devices
- Effect: When nuclear_findings is empty (old checkpoint), email files are invisible to
  device_evidence even though they exist in nuclear_evidence

### Bug 4: device_evidence built before inventory merge takes effect
- File: `geoff_pipeline.py`, `find_evil()`
- The device_evidence dict is built by checking dev["evidence_files"] against inventory
- If the merge in _mount_and_discover added paths to inventory["other_files"] but
  those paths were never added to dev["evidence_files"] (because nuclear attribution 
  found nothing), they stay invisible to the playbook loop

### Bug 5: icat may need different approach for large files on EWF
- File: `geoff_discovery.py`, fls fallback path
- `icat -o OFFSET ewf1 INODE` may fail for large PST files (>10MB)
- Need to try alternative: `icat -o OFFSET -r ewf1 INODE > output` with pipe

## Fix Plan

### Fix 1: Mark fls-fallback images as processed
In `geoff_discovery.py:_mount_and_discover()`, after the fls fallback successfully
processes at least one image:
```python
fls_image_processed = False  # flag for images processed via fls only
...
if found > 0:
    fls_image_processed = True
...
# After the for-offsets loop, before the `if not mounted:` check:
if fls_image_processed and not mounted:
    mounted = True  # or: images_processed += 1 directly
```

### Fix 2: Robust PST extraction fallback
When icat fails:
1. Try `icat` with shell redirect: `icat -o {offset} {device} {inode} > {out}`
2. If that also fails, store the fls metadata so the email specialist can try
   direct extraction later
3. Always write a log entry about the failure

### Fix 3: Nuclear attribution from nuclear_evidence
In `find_evil()`, add a fallback attribution loop that processes `nuclear_evidence`
directly when `nuclear_findings` is empty or doesn't cover all found artifacts:
```python
# Attribute nuclear evidence files directly to devices
_nuclear_ev = nuclear_result.get("nuclear_evidence", {})
for ev_bucket, paths in _nuclear_ev.items():
    for path in paths:
        # Determine which image this belongs to by matching stems
        for dev_id, dev in device_map.items():
            for ev_file in dev.get("evidence_files", []):
                if Path(ev_file).stem in path:
                    if path not in dev["evidence_files"]:
                        dev["evidence_files"].append(path)
                    break
```

### Fix 4: Validate nuclear evidence paths exist
After attribution, verify the paths exist on disk. If they use the `::` internal
reference format, log a warning and attempt alternative extraction.
