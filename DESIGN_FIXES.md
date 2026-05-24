# Geoff DFIR Framework — Design Document for 8 Fixes

**Author:** GLM 5.1 (architecture/design), Qwen3-coder (implementation review)  
**Date:** 2025-05-24  
**Status:** Draft — requires Qwen3-coder agreement before implementation

---

## Overview

This document specifies fixes for 8 identified issues in the Geoff DFIR framework.  
**Issue #6 (offset detection) is P1 and the largest fix** — it is the root cause of  
multiple downstream failures across playbooks, fallback chains, and timeline creation.

All fixes target the source at `/home/sansforensics/Geoff/src/` (running VM instance),  
with the canonical repo at `github.com/legacyboy/Geoff`.

---

## Issue #6 (P1): Filesystem Offset Detection and Caching

### Problem

When `mmls` successfully finds partition table entries, Geoff only stores the  
**first** matching partition offset in `image_offsets[img]`. If that offset is  
wrong (e.g., the first partition is a small recovery partition, not the main  
filesystem), **every subsequent tool call using `{offset}` substitution fails**:

1. `fls -o <wrong_offset>` → error → fallback chain fires
2. Fallback chain tries `offset=0` → also fails → falls to photorec carving
3. `fsstat -o <wrong_offset>` → error → unprocessable
4. `icat`, `list_files_mactime`, `list_deleted` → all fail with same bad offset
5. `log2timeline` on mounted filesystem → mount fails → no timeline
6. LLM self-heal gets called on every failed step, burning API tokens for  
   a problem that is fundamentally deterministic

The **core failure mode**: `image_offsets` maps `image_path → single_offset`,  
and there is no mechanism to:
- Try **all** partition offsets from `mmls` output
- **Validate** an offset works (via `fsstat`) before committing to it
- **Cache** the validated offset so ALL playbook steps reuse it
- **Update** the cache if a step fails with the cached offset (try next partition)

### Current Behavior (pipeline_phases.py lines 1000-1110, geoff_pipeline.py lines 2069-2380)

```
Phase 1b:
  for each disk image:
    run mmls → parse partitions
    store FIRST matching partition offset in image_offsets[img]
    if mmls fails entirely → fallback to COMMON_LEGACY_OFFSETS[0] (2048)
    
  Save checkpoint_offsets.json
  
Phase 2+ (playbook execution):
  for each step with "{offset}":
    v.replace("{offset}", str(image_offsets.get(item, 2048)))
    → if offset is wrong, step fails → fallback chain → photorec → strings
```

**What's wrong:**
1. First partition found by `mmls` may not be the main filesystem (recovery  
   partitions, EFI system partitions, etc. often come first on modern disks)
2. No `fsstat` validation — offset is stored without confirming it works
3. Single offset per image — no fallback to other partitions when step fails
4. `COMMON_LEGACY_OFFSETS` fallback (2048, 63, 0, 32256) doesn't come from  
   `mmls` output — it's a blind guess
5. Fallback chains try `offset=0` (whole-disk) which rarely works on  
   partitioned images
6. The `'_candidates'` key stores remaining offsets but is **never read** by  
   any step execution code

### Proposed Design

#### New file: `offset_cache.py`

A persistent, validated offset cache that stores **all** partition offsets  
per image, validates each one with `fsstat`, and provides the correct offset  
to any caller.

```python
class OffsetCache:
    """Persistent, validated filesystem offset cache.
    
    Stores per-image partition offsets validated by fsstat.
    Persists to <case_work_dir>/offset_cache.json for checkpoint resume.
    """
    
    def __init__(self, cache_path: Path):
        self._cache_path = cache_path
        self._entries: dict[str, OffsetEntry] = {}  # image_path -> OffsetEntry
        self._load()
    
    def get_validated_offset(self, image_path: str) -> Optional[int]:
        """Return the validated offset for an image, or None if not yet resolved."""
        entry = self._entries.get(image_path)
        if entry and entry.validated:
            return entry.primary_offset
        return None
    
    def get_all_offsets(self, image_path: str) -> list[int]:
        """Return all partition offsets from mmls, in priority order."""
        entry = self._entries.get(image_path)
        return entry.all_offsets if entry else []
    
    def mark_offset_failed(self, image_path: str, failed_offset: int) -> Optional[int]:
        """Mark an offset as failed, return next untried offset or None.
        
        Called by step executor when a tool fails with a specific offset.
        Advances to next candidate offset, validates it, and updates cache.
        """
        entry = self._entries.get(image_path)
        if not entry:
            return None
        entry.tried_offsets.add(failed_offset)
        for candidate in entry.all_offsets:
            if candidate not in entry.tried_offsets:
                if self._validate_offset(image_path, candidate):
                    entry.primary_offset = candidate
                    entry.validated = True
                    self._save()
                    return candidate
        # All offsets exhausted
        entry.exhausted = True
        self._save()
        return None
    
    def detect_and_cache(self, image_path: str, job_id: str = None) -> Optional[int]:
        """Run mmls, parse partitions, validate with fsstat, cache result.
        
        Returns the validated offset or None.
        """
        partitions = self._run_mmls(image_path, job_id)
        if not partitions:
            return None
        
        entry = OffsetEntry(
            image_path=image_path,
            all_offsets=[p['offset'] for p in partitions],
            partition_descriptions={p['offset']: p['description'] for p in partitions},
        )
        
        # Try each partition offset, validate with fsstat
        for part in partitions:
            if self._validate_offset(image_path, part['offset']):
                entry.primary_offset = part['offset']
                entry.validated = True
                entry.tried_offsets = set()
                break
        
        self._entries[image_path] = entry
        self._save()
        return entry.primary_offset if entry.validated else None
    
    def _validate_offset(self, image_path: str, offset: int) -> bool:
        """Validate that fsstat succeeds with this offset."""
        try:
            result = subprocess.run(
                ['fsstat', '-o', str(offset), image_path],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0 and 'File System Type' in result.stdout:
                return True
        except Exception:
            pass
        return False
    
    def _run_mmls(self, image_path: str, job_id: str = None) -> list[dict]:
        """Run mmls and return parsed partition list.
        Tries EWF mount for E01 images, then direct mmls,
        then mmls with explicit partition table types.
        """
        # ... (uses existing logic from pipeline Phase 1b, but returns ALL partitions)
        # Priority ordering: NTFS/ext > FAT > other > meta/unallocated
        pass
    
    def _save(self):
        """Persist cache to JSON."""
        pass
    
    def _load(self):
        """Load cache from JSON on init."""
        pass


@dataclass
class OffsetEntry:
    image_path: str
    all_offsets: list[int]           # All partition offsets from mmls
    primary_offset: Optional[int]   # Currently validated best offset
    partition_descriptions: dict    # offset -> description from mmls
    validated: bool = False
    tried_offsets: set = field(default_factory=set)
    exhausted: bool = False
```

#### Changes to `pipeline_phases.py` and `geoff_pipeline.py`

**Phase 1b rewrite** — replace the current `image_offsets` dict with `OffsetCache`:

```python
# BEFORE (current):
image_offsets = {}  # image_path -> single int
# ... complex inline detection logic ...

# AFTER (proposed):
from offset_cache import OffsetCache

offset_cache = OffsetCache(case_work_dir / "offset_cache.json")
for dev_id, dev in device_map.items():
    for img in dev.get("evidence_files", []):
        if img in inventory.get("disk_images", []):
            offset = offset_cache.detect_and_cache(img, job_id=job_id)
            if offset is not None:
                _fe_log(job_id, f"Partition offset for {Path(img).name}: sector {offset} (validated)")
            else:
                _fe_log(job_id, f"⚠ Could not validate any offset for {Path(img).name}")
```

**Step execution** — when a step fails with an offset error, try next offset:

```python
# In the playbook step execution loop (currently around line 1300+):
step_status = result.get("status", "error")
if step_status == "error" and "offset" in params:
    # Check if error is offset-related (common TSK error patterns)
    stderr_lower = result.get("stderr", "").lower()
    if any(kw in stderr_lower for kw in [
        "cannot determine", "invalid offset", "cannot find",
        "bad superblock", "invalid superblock", "mft entry",
        "dinode_lookup", "update sequence", "metadata structure"
    ]):
        current_offset = params.get("offset")
        next_offset = offset_cache.mark_offset_failed(item, current_offset)
        if next_offset is not None:
            _fe_log(job_id, f"  ↻ Offset {current_offset} failed for {Path(item).name}, trying {next_offset}")
            params["offset"] = next_offset
            # Retry the same step with new offset
            result = _run_step_via_orchestrator(module, function, params)
            step_status = result.get("status", "error")
```

**`{offset}` template resolution** — use cache instead of dict lookup:

```python
# BEFORE:
v = v.replace("{offset}", str(image_offsets.get(item, 2048)))

# AFTER:
cached = offset_cache.get_validated_offset(item)
v = v.replace("{offset}", str(cached if cached is not None else 2048))
```

#### Changes to `geoff_fallback_chains.py`

**Remove blind `offset=0` fallback** — replace with offset-aware retry:

```python
# BEFORE:
"sleuthkit.list_files": [
    {"module": "sleuthkit", "function": "list_files", "params_mod": None, "label": "fls_auto"},
    {"module": "sleuthkit", "function": "list_files", "params_mod": {"offset": 0}, "label": "fls_offset0"},
    ...
    {"module": "photorec", "function": "recover_files", ...},  # too early!
]

# AFTER:
"sleuthkit.list_files": [
    {"module": "sleuthkit", "function": "list_files", "params_mod": None, "label": "fls_auto"},
    # offset=0 removed — offset retry is handled by pipeline via OffsetCache
    {"module": "sleuthkit", "function": "analyze_partition_table", "params_mod": None, "label": "mmls_probe"},
    # Only fall to carving AFTER all offsets from cache exhausted
    {"module": "photorec", "function": "recover_files", "params_mod": None, "label": "photorec_carve"},
    {"module": "bulk_extractor", "function": "scan_image", "params_mod": None, "label": "bulk_extractor"},
    {"module": "strings", "function": "extract_strings", "params_mod": None, "label": "strings_terminal"},
],
```

Same pattern for `sleuthkit.analyze_filesystem`, `sleuthkit.list_deleted`,  
`sleuthkit.list_files_mactime`.

#### Changes to `sift_specialists.py`

**`_run_with_segments`** — when offset is provided but tool fails, do NOT  
internally try `offset=0` or remove the offset. Let the pipeline's `OffsetCache`  
handle offset retry. Currently lines 380-420 try removing the offset as a  
recovery strategy — this is counterproductive because it tries whole-disk  
mode which rarely works on partitioned images.

```python
# REMOVE this block from _run_with_segments (lines ~400-420):
# "If still failing, try direct disk access without partition offset"
# alt_args2 = list(base_args) if base_args else []
# for seg in segments:
#     alt_args2.append(seg)
# alt_raw2 = self.run(tool, alt_args2)
```

The `OffsetCache.mark_offset_failed()` at the pipeline level handles this  
properly by trying the NEXT partition from mmls, not removing the offset.

### Edge Cases

1. **E01 images**: `fsstat -o <offset> <e01>` works directly with TSK EWF  
   support. If TSK EWF is not compiled in, `detect_and_cache` falls back to  
   `ewfmount` → `mmls ewf1` → `fsstat -o <offset> ewf1` (existing Strategy 1).
2. **Images with no partition table** (raw filesystem, no MBR/GPT): `mmls`  
   will fail. `OffsetCache` should try `fsstat` with no offset (`-o 0` or  
   no `-o` flag). If that succeeds, cache offset=0 as validated.
3. **GPT with protective MBR**: `mmls` may show both the protective MBR entry  
   and GPT partitions. The `fsstat` validation step filters out the  
   protective MBR (offset 1) because `fsstat -o 1` will fail.
4. **Multiple filesystem partitions**: Cache stores ALL offsets from `mmls`.  
   The pipeline uses the first validated one. If a step needs a different  
   partition (e.g., examine the recovery partition), it can call  
   `offset_cache.get_all_offsets(image_path)` explicitly.
5. **Checkpoint resume**: `offset_cache.json` is saved alongside  
   `checkpoint_offsets.json`. On resume, `OffsetCache.__init__` loads the  
   persisted cache, so no re-detection is needed.
6. **Very large images**: `fsstat -o <offset>` is fast (< 5 seconds even on  
   100GB+ images) because it only reads the superblock/MFT. Validating all  
   partitions is negligible overhead.
7. **Corrupted MFT/superblock**: If `fsstat` fails on every offset from `mmls`,  
   `OffsetCache` marks the image as `exhausted=True`. The pipeline can then  
   fall back to carving (photorec/bulk_extractor) with high confidence that  
   carving is actually needed, not just an offset mismatch.

### Files to Change

| File | Change |
|------|--------|
| **NEW** `offset_cache.py` | OffsetCache class, OffsetEntry dataclass, persistence |
| `geoff_pipeline.py` | Replace `image_offsets` dict with `OffsetCache` in Phase 1b (~lines 2069-2380), add offset-retry in step execution loop |
| `pipeline_phases.py` | Same replacement for the simpler `image_offsets` usage in `_execute_pass2` |
| `sift_specialists.py` | Remove `offset=0` fallback from `_run_with_segments` |
| `geoff_fallback_chains.py` | Remove `params_mod: {"offset": 0}` from fallback chains |

### Backward Compatibility

- `image_offsets` dict is currently used as a plain `dict[str, int]`. The  
  `OffsetCache` provides a `to_dict()` method that returns the same format  
  for any code that still reads it directly (e.g., `_mount_and_discover`).
- `checkpoint_offsets.json` continues to be written for compatibility, but  
  `offset_cache.json` becomes the authoritative source.

---

## Issue #2 (P1): E01/EWF Support in bulk_extractor

### Problem

`BULK_EXTRACTOR_Specialist.scan_image()` passes the image path directly to  
`bulk_extractor` (line 7742). If the image is E01 format, `bulk_extractor`  
cannot read it unless compiled with EWF support. On SIFT, `bulk_extractor`  
is installed without EWF support.

Current behavior: `bulk_extractor` returns error for E01 images → step fails  
→ fallback chain has no bulk_extractor alternative → falls to strings.

### Proposed Design

**Auto-convert E01 to raw before running bulk_extractor:**

```python
class BULK_EXTRACTOR_Specialist:
    def scan_image(self, image: str, output_dir: str) -> Dict[str, Any]:
        # Detect E01 image
        if self._is_ewf_image(image):
            # Convert E01 → raw via ewfexport (available on SIFT)
            raw_path = self._convert_e01_to_raw(image, output_dir, job_id)
            if raw_path:
                scan_target = raw_path
            else:
                # ewfexport not available or failed → try ewfmount + raw access
                scan_target = self._mount_ewf_raw(image, output_dir, job_id)
                if not scan_target:
                    return {'status': 'error', 'error': 'Cannot convert E01 to raw for bulk_extractor'}
        else:
            scan_target = image
        
        # Run bulk_extractor on the raw image (existing logic)
        cmd = [self.bulk_path, '-o', output_dir, scan_target]
        ...
        
        # Cleanup: remove converted raw file after scan
        if scan_target != image:
            try: os.unlink(scan_target)
            except: pass
```

**Conversion strategy (in order):**
1. `ewfexport -o <output_dir>/raw.dd <e01_path>` — produces raw DD from E01
2. `ewfmount <e01_path> <mount_dir>` → scan `/mnt/dir/ewf1` — if TSK EWF works
3. Skip with clear error message

**Why not rebuild bulk_extractor with EWF?** Rebuilding requires libewf-dev,  
and may break the SIFT package. Auto-conversion is non-destructive and works  
with the existing SIFT toolset.

### Edge Cases

- Multi-segment E01/E02/E03: `ewfexport` handles this natively
- Very large E01 (50GB+): conversion to raw doubles storage. Add size check:  
  if raw output would exceed available disk space, skip bulk_extractor and  
  log a warning.
- Cleanup: converted raw file is deleted after scan completes

### Files to Change

| File | Change |
|------|--------|
| `sift_specialists_extended.py` | Add `_is_ewf_image()`, `_convert_e01_to_raw()`, modify `scan_image()` |

---

## Issue #8 (P1): Timeline Creation Offset Problems

### Problem

This is the **same root cause as Issue #6** but manifests specifically in  
timeline creation. `PLASO_Specialist.create_timeline()` is called during  
playbook execution with `evidence_path` that may be a disk image. If the  
offset is wrong, `log2timeline.py` cannot parse the filesystem and produces  
zero events.

Additionally, `create_timeline` and `sort_timeline` are called as separate  
playbook steps, but `sort_timeline` requires the `.plaso` file created by  
`create_timeline`. If `create_timeline` fails silently (returns 0 events),  
`sort_timeline` runs on an empty/missing file and also fails.

### Proposed Design

**1. Pass validated offset to log2timeline:**

```python
def create_timeline(self, evidence_path: str, output_file: str,
                    parsers: Optional[List[str]] = None,
                    partition_offset: Optional[int] = None) -> Dict[str, Any]:
    # If evidence is a disk image and offset is provided, mount it first
    if partition_offset is not None:
        # log2timeline.py can work with raw images + offset
        # Add --partition_offset (plaso 2024+) or mount via ewfmount/losetup
        ...
```

**2. Chain create_timeline → sort_timeline atomically:**

Add a new method `create_and_sort_timeline()` that runs both steps and  
returns combined results. The playbook definition should use this combined  
method instead of two separate steps.

**3. Validate timeline before sort:**

After `create_timeline`, check the `.plaso` file exists and has events  
(via `pinfo`). If 0 events, report failure immediately instead of running  
`sort_timeline` on an empty file.

### Files to Change

| File | Change |
|------|--------|
| `sift_specialists_extended.py` | Add `partition_offset` param to `create_timeline`, add `create_and_sort_timeline()` |
| `geoff_config.py` | Update playbook step from two steps to one combined step where applicable |
| `pipeline_phases.py` | Pass `offset_cache.get_validated_offset(item)` as `partition_offset` param |

---

## Issue #1: Strings Timeout and Targeted Search

### Problem

`STRINGS_Specialist.extract_strings()` has a hardcoded 60-second timeout.  
For large disk images (100GB+), `strings` will be killed at 60 seconds,  
producing partial/no results. Additionally, running `strings` on an entire  
disk image produces massive output with high noise — most strings from a  
raw disk are meaningless filesystem metadata.

### Proposed Design

```python
def extract_strings(self, file_path: str, min_length: int = 4,
                    encoding: str = 'ascii',
                    max_timeout: int = 600,
                    targeted_patterns: list = None) -> Dict[str, Any]:
    """Extract strings with adaptive timeout and optional targeted search.
    
    max_timeout: scaled based on file size (60s for <1GB, 300s for <10GB, 600s for >=10GB)
    targeted_patterns: if provided, filter output through these regex patterns
                       before categorization (reduces memory and noise)
    """
    file_size = os.path.getsize(file_path) if os.path.isfile(file_path) else 0
    size_gb = file_size / (1024**3)
    
    # Adaptive timeout
    if size_gb >= 10:
        timeout = min(max_timeout, 600)
    elif size_gb >= 1:
        timeout = min(max_timeout, 300)
    else:
        timeout = 60
    
    # For very large files, use strings with -t d (offset) and pipe through
    # targeted grep if patterns are provided
    if targeted_patterns and size_gb > 0.5:
        # First pass: extract strings with offsets
        # Second pass: filter through targeted patterns
        ...
```

**Also:** The playbook step `("strings", "extract_strings", {"file_path": "{image}", ...})`  
passes the **entire disk image** as `file_path`. This is almost never useful.  
Change playbook templates to pass specific extracted files or use  
`strings` as a terminal fallback only.

### Files to Change

| File | Change |
|------|--------|
| `sift_specialists.py` | Add adaptive timeout, targeted search to `extract_strings()` |
| `geoff_config.py` | Update playbook steps that pass `{image}` to strings — change to `{file}` or remove |

---

## Issue #3: Missing `files.signature_mismatch_scan` Module Routing

### Problem

Playbook PB-SIFT-008 includes step:
```python
("files", "signature_mismatch_scan", {"output_dir": "{output_dir}"}),
```

But `ExtendedOrchestrator.specialist_map` has no `"files"` key. The module  
name `"files"` doesn't map to anything. The actual module is `"file_scanner"`  
which is in the specialist_map and has a `signature_mismatch_scan()` method.

When the pipeline routes `("files", "signature_mismatch_scan", ...)`, it  
calls `orchestrator.run_playbook_step()` which looks up `"files"` in  
`specialist_map` → `None` → returns `{'status': 'error', 'error': 'Unknown module: files'}`.

### Proposed Design

**Option A (minimal):** Add module alias in `ExtendedOrchestrator.__init__`:
```python
self.specialist_map['files'] = self.file_scanner  # alias for playbook compat
```

**Option B (proper):** Change playbook step to use the real module name:
```python
# geoff_config.py PB-SIFT-008:
("file_scanner", "signature_mismatch_scan", {"output_dir": "{output_dir}"}),
```

**Recommendation:** Do **both**. Fix the playbook step to use the correct  
module name, AND add the alias so any future references to `"files"` work.  
The alias is a one-liner with zero risk.

Also: `signature_mismatch_scan` currently requires `target_file` or  
`input_dir`. The playbook passes `output_dir` but not `input_dir`. The  
function will return `"Must provide target_file or input_dir"`. Fix the  
playbook step to pass `input_dir` pointing to the case output directory  
where extracted files live:

```python
("file_scanner", "signature_mismatch_scan", {"input_dir": "{output_dir}"}),
```

### Files to Change

| File | Change |
|------|--------|
| `sift_specialists_extended.py` | Add `'files': self.file_scanner` to specialist_map |
| `geoff_config.py` | Change `"files"` → `"file_scanner"` and `"output_dir"` → `"input_dir"` in PB-SIFT-008 |

---

## Issue #4: Missing `usnjrnl.parse_usnjrnl` Module Routing

### Problem

Playbook PB-SIFT-012 includes:
```python
("usnjrnl", "parse_usnjrnl", {"image": "{image}"}),
```

But `ExtendedOrchestrator.specialist_map` has no `"usnjrnl"` key. The  
`parse_usnjrnl` function exists in `geoff_discovery.py` but is not  
registered as a specialist module.

### Proposed Design

Add a thin USNJRNL_Specialist wrapper (like FAT_RECOVERY_Specialist):

```python
class USNJRNL_Specialist:
    """Thin wrapper for $UsnJrnl change journal parsing.
    Delegates to geoff_discovery.parse_usnjrnl.
    """
    def __init__(self, evidence_base: str = None):
        self.evidence_base = evidence_base
    
    def parse_usnjrnl(self, image: str = None, journal_path: str = None,
                      partition_offset: int = None, mft_inode: int = None,
                      **kwargs) -> dict:
        try:
            from geoff_discovery import parse_usnjrnl as _parse
            records = _parse(
                journal_path=journal_path,
                image_path=image,
                partition_offset=partition_offset,
                mft_inode=mft_inode,
                job_id=kwargs.get('job_id'),
            )
            return {
                "status": "success",
                "records": records,
                "record_count": len(records),
            }
        except Exception as e:
            return {"status": "error", "error": str(e)}
```

Register in specialist_map:
```python
self.usnjrnl = USNJRNL_Specialist(evidence_base)
# In specialist_map:
'usnjrnl': self.usnjrnl,
```

**Also fix the playbook step parameters.** Currently passes `{"image": "{image}"}`  
but `parse_usnjrnl` needs either `journal_path` (for mounted volumes) or  
`image_path + partition_offset + mft_inode` (for raw images). The pipeline's  
inline usnjrnl handling (geoff_pipeline.py lines 3187-3260) already handles  
mounted volumes correctly. The playbook step should pass the offset from  
the cache:

```python
("usnjrnl", "parse_usnjrnl", {"image": "{image}", "partition_offset": "{offset}"}),
```

And `USNJRNL_Specialist.parse_usnjrnl` should try:
1. Find `$Extend/$UsnJrnl:$J` on any active mount point (existing pipeline logic)
2. If no mount, use `icat` with image + offset + inode 32 (default $UsnJrnl inode)

### Files to Change

| File | Change |
|------|--------|
| `sift_specialists_extended.py` | Add `USNJRNL_Specialist`, register in `ExtendedOrchestrator` |
| `geoff_config.py` | Update PB-SIFT-012 usnjrnl step params to include `partition_offset` |

---

## Issue #5: Missing `fat_recovery.recover_formatted_fat` Module Routing

### Problem

`FAT_RECOVERY_Specialist` exists and is registered as `'fat_recovery'` in  
the specialist_map. It has a `recover_formatted_fat` method that delegates  
to `geoff_discovery.recover_formatted_fat`. But the playbook step may not  
be wired correctly — checking if any playbook actually calls it.

Looking at playbook definitions... `FAT_RECOVERY_Specialist.recover_formatted_fat`  
accepts `disk_image`, `offset`, `disk_images`, `device_map`, `image_offsets`.  
But playbook step templates don't pass `device_map` or `image_offsets`. The  
`geoff_discovery.recover_formatted_fat` function requires `disk_images`,  
`device_map`, and `image_offsets` — all three are essential.

If a playbook calls `("fat_recovery", "recover_formatted_fat", {"image": "{image}"})`,  
the function receives `disk_image="{image}"` but not `disk_images`, `device_map`,  
or `image_offsets` → `geoff_discovery.recover_formatted_fat` gets  
`disk_images=[]` → returns immediately with no results.

### Proposed Design

The playbook step needs to receive the full context. Since `device_map` and  
`image_offsets` (now `OffsetCache`) are pipeline-level data, the step  
executor must inject them:

1. In the playbook step execution loop, detect when `fat_recovery.recover_formatted_fat`  
   is called and inject `disk_images`, `device_map`, and `image_offsets` from  
   the pipeline context.

2. Better approach: make `FAT_RECOVERY_Specialist` self-sufficient by having  
   it call `OffsetCache` to get offsets, and use `device_map` from the  
   pipeline's inventory.

```python
class FAT_RECOVERY_Specialist:
    def recover_formatted_fat(self, disk_image: str = None, 
                              disk_images: list = None,
                              device_map: dict = None,
                              image_offsets: dict = None,
                              offset_cache = None,  # NEW: OffsetCache reference
                              output_dir: str = None,
                              job_id: str = None, **kwargs) -> dict:
        # If pipeline context not provided, derive from disk_image
        if not disk_images and disk_image:
            disk_images = [disk_image]
        if not image_offsets and offset_cache:
            image_offsets = {img: offset_cache.get_validated_offset(img) 
                            for img in disk_images if offset_cache.get_validated_offset(img)}
        ...
```

### Files to Change

| File | Change |
|------|--------|
| `sift_specialists_extended.py` | Update `FAT_RECOVERY_Specialist.recover_formatted_fat` to accept `offset_cache` |
| `geoff_pipeline.py` | Inject `offset_cache` reference when calling fat_recovery steps |

---

## Issue #7: exiftool/hashdeep Timeout on Large Files

### Problem

Low priority. `exiftool` and `hashdeep` are called on evidence files without  
size-based timeout scaling. Large files (multi-GB disk images) cause these  
tools to hang for hours.

### Proposed Design

Add a size check before running exiftool/hashdeep:

```python
def exiftool_scan(self, target_path: str, ...) -> Dict[str, Any]:
    # Skip files larger than 500MB — exiftool is not useful for disk images
    if os.path.isfile(target_path) and os.path.getsize(target_path) > 500 * 1024**2:
        return {'status': 'skipped', 'reason': 'File too large for exiftool (>500MB)'}
    ...
```

Same pattern for hashdeep. These tools are designed for individual files  
(documents, photos, executables), not disk images.

### Files to Change

| File | Change |
|------|--------|
| `sift_specialists_extended.py` | Add size guards to any exiftool/hashdeep methods |

---

## Implementation Order

1. **Issue #6** — `offset_cache.py` + pipeline integration (P1, biggest impact)
2. **Issue #8** — Timeline offset fix (depends on #6, P1)
3. **Issue #2** — E01/bulk_extractor (P1, self-contained)
4. **Issue #3** — files→file_scanner alias (trivial)
5. **Issue #4** — usnjrnl specialist wrapper (moderate)
6. **Issue #1** — strings timeout (moderate)
7. **Issue #5** — fat_recovery context injection (moderate, depends on #6)
8. **Issue #7** — exiftool size guard (trivial)

---

## Testing Strategy

After implementation, re-run against the rocba evidence to validate:
1. `OffsetCache` correctly detects and validates offsets for all disk images
2. Steps that previously fell to photorec now succeed with correct offsets
3. `bulk_extractor` works on E01 images after auto-conversion
4. `file_scanner.signature_mismatch_scan` runs in PB-SIFT-008
5. `usnjrnl.parse_usnjrnl` runs in PB-SIFT-012
6. Timeline creation produces events with correct offsets
7. Strings extraction doesn't timeout on large images

The 2018 Find Evil job (fe-89443f94453b) currently running should NOT be  
restarted — test fixes on a new run or the completed rocba evidence.

---

## Agreement Required

Both GLM 5.1 (design) and Qwen3-coder (implementation) must agree on:
1. The `OffsetCache` API surface and persistence format
2. The offset-retry integration point in the step execution loop
3. The E01→raw conversion strategy for bulk_extractor
4. The module routing fixes for `files` → `file_scanner` and `usnjrnl`

If Qwen3-coder disagrees with any design decision, document the disagreement  
and the resolution before proceeding to implementation.