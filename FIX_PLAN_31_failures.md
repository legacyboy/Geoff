# Geoff Find-Evil Failure Fix Plan

**Job:** fe-5ffe8080f183 — NPS_domexusers (3-part E01 Windows XP image)
**Date:** 2026-05-22
**Author:** Steve4
**Status:** PLAN ONLY — no changes made

---

## Executive Summary

53 total "failed" entries in findings.jsonl. 5 are expected skips (AmCache on XP, ExifTool on containers). The remaining **48 failures** fall into **4 root-cause categories**, each requiring a different fix strategy. The single highest-leverage fix — adding `**kwargs` to the orchestrator's dispatch path — eliminates **29 of 48** failures (60%) by making all specialists resilient to extra params from the self-heal LLM.

---

## Failure Breakdown by Root Cause

| Category | Failures | Root Cause |
|---|---|---|
| A. KWARG-BUG | 19 | Self-heal LLM adds extra kwargs; orchestrator splats them directly; specialists don't accept them |
| B. MOUNT-BUG | 12 | VSS FUSE mounts not unmounted before temp-dir cleanup; retries hit same busy path |
| C. IMPORT-BUG | 6 | `host_correlator.py` uses `Path()` without importing `pathlib.Path` |
| D. MODULE-REG | 13 | Self-heal LLM suggests fallback modules that don't exist in orchestrator's `specialist_map` |

**Note:** The 19 KWARG-BUG failures break down further:
- `plaso.create_timeline` × 9 — extra kwargs: `partition_number`(2), `partition_offset`(3), `partition`(3), `image_type`(1)
- `plaso.sort_timeline` × 3 — extra kwarg: `output_file`
- `windows.analyze_srum` × 3 — extra kwarg: `srum_path`
- `windows.analyze_amcache` × 1 — extra kwarg: `amcache_path`
- `windows.analyze_amcache` × 2 — correct skip (XP has no AmCache) ← not a bug
- `remnux.exiftool_scan` × 3 — correct skip (can't parse container) ← not a bug
- + the 13 MODULE-REG failures are also caused by the self-heal LLM suggesting nonexistent fallback modules

The self-heal LLM is the common cause behind categories A and D — 32 of 48 failures (67%).

---

## Priority-Ordered Fix Plan

### Fix 1: Orchestrator `**kwargs` Shield (Fixes A — 19 failures, + prevents all future KWARG-BUGs)

**Priority:** P0 — highest leverage, simplest fix, prevents entire class of errors

**Problem:** `run_playbook_step()` in `sift_specialists_extended.py` line ~11090 does:
```python
func = getattr(specialist, function)
return func(**params)
```
When the self-heal LLM adds `partition_number`, `srum_path`, `output_file`, etc. to params, they get splatted into specialist functions that don't accept them, causing `TypeError: got an unexpected keyword argument`.

**Fix:** Add an `inspect`-based param filter before dispatch. Instead of `func(**params)`, introspect the function signature and only pass params it accepts:

```python
import inspect

def run_playbook_step(self, investigation_id: str, step: Dict[str, Any]) -> Dict[str, Any]:
    module = step.get('module')
    function = step.get('function')
    params = step.get('params', {})

    specialist = specialist_map.get(module)
    if specialist and hasattr(specialist, function):
        func = getattr(specialist, function)
        # Filter params to only those the function accepts
        sig = inspect.signature(func)
        accepted = set(sig.parameters.keys())
        if any(p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values()):
            filtered = params  # func has **kwargs, pass everything
        else:
            filtered = {k: v for k, v in params.items() if k in accepted}
        return func(**filtered)
    # ... rest unchanged
```

**Why this approach:** This is defensive and generic. It works for ANY specialist and ANY extra kwarg the self-heal LLM might invent. It doesn't require modifying 20+ specialist function signatures. The `inspect` call is cheap (microseconds) and cached by Python internally.

**Alternative (less preferred):** Add `**kwargs` to every specialist function that's missing it. This is fragile — any new specialist or function can be forgotten. But it's also valid as a belt-and-suspenders approach.

**Files to change:**
- `/home/sansforensics/Geoff/src/sift_specialists_extended.py` — `run_playbook_step()` method (line ~11084)

**Also apply to REMnux orchestrator** if it has a similar dispatch:
- Check `remnux_orchestrator.run_playbook_step` for the same `func(**params)` pattern

---

### Fix 2: VSS Mount Cleanup (Fixes B — 12 failures)

**Priority:** P0 — second highest impact, prevents all VSS analysis from failing

**Problem:** Two issues in the VSS specialist:

1. **`list_vss()`** uses `tempfile.TemporaryDirectory()` as a context manager. `vshadowmount` creates a FUSE mount at the temp dir. When the function returns (inside the `with` block), `TemporaryDirectory.__exit__()` tries to `os.rmdir()` the path, but FUSE still holds it → `Device or resource busy`. The retry loop then creates a NEW `TemporaryDirectory` and hits the same issue because the old mount was never cleaned up.

2. **`extract_vss_files()`** uses `tempfile.mkdtemp()` and does call `fusermount -u` + `shutil.rmtree`, but if `vshadowmount` itself fails (returning error), the `list_vss()` call inside it fails first, and the whole function errors out before the mount cleanup in `extract_vss_files` can run.

**Fix for `list_vss()`:**
```python
def list_vss(self, image: str) -> Dict[str, Any]:
    """List available Volume Shadow Copies in disk image."""
    if not self.vshadowmount_available:
        return {
            'tool': 'vshadowmount',
            'status': 'error',
            'error': 'vshadowmount not found — install libvshadow utils (xmount package)',
            'timestamp': datetime.now().isoformat(),
        }

    tmpdir = tempfile.mkdtemp()  # NOT TemporaryDirectory — we manage cleanup
    try:
        cmd = ['vshadowmount', image, tmpdir]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

        if result.returncode != 0:
            return {
                'tool': 'vshadowmount',
                'status': 'error',
                'error': 'Failed to mount image for VSS enumeration',
                'timestamp': datetime.now().isoformat(),
            }

        vss_dirs = [d.name for d in Path(tmpdir).iterdir() if d.is_dir() and d.name.startswith('vss')]
        vss_nums = [int(d.replace('vss', '')) for d in vss_dirs if d.replace('vss', '').isdigit()]

        return {
            'tool': 'vshadowmount',
            'image': image,
            'status': 'success',
            'vss_count': len(vss_nums),
            'vss_numbers': vss_nums,
            'timestamp': datetime.now().isoformat(),
        }
    finally:
        # ALWAYS unmount FUSE before cleanup, regardless of success/failure
        subprocess.run(['fusermount', '-u', tmpdir], capture_output=True, timeout=15)
        # Brief pause for FUSE to release
        time.sleep(0.5)
        shutil.rmtree(tmpdir, ignore_errors=True)
```

**Fix for `extract_vss_files()`:** Same pattern — ensure `fusermount -u` happens in a `finally` block for EVERY mount point, including the one created by `list_vss()` (which is called internally). The current code already does unmount+rmtree in the loop, but it needs `finally` guarantees and a `time.sleep(0.5)` after unmount.

**Fix for `mount_vss()`:** No changes needed — it's called by `extract_vss_files` which handles cleanup.

**Additional fix — pipeline retry awareness:** The pipeline retry loop (geoff_pipeline.py line ~4718) retries failed steps 3 times. For FUSE-mount failures, each retry creates a new temp dir without the old mount being cleaned up. Consider adding a pre-step cleanup that runs `fusermount -u /tmp/tmp*` for stale VSS mounts before retrying VSS steps. This can be done in the retry block:

```python
# In the retry loop, before retrying VSS steps:
if module == 'vss' and attempt > 0:
    # Clean up any stale FUSE mounts from previous attempt
    for d in Path('/tmp').glob('tmp*'):
        subprocess.run(['fusermount', '-u', str(d)], capture_output=True, timeout=5)
```

**Files to change:**
- `/home/sansforensics/Geoff/src/sift_specialists_extended.py` — `list_vss()` (line ~7902), `extract_vss_files()` (line ~7967)
- `/home/sansforensics/Geoff/src/geoff_pipeline.py` — retry loop (line ~4718) — optional VSS mount cleanup

---

### Fix 3: host_correlator Path Import (Fixes C — 6 failures)

**Priority:** P1 — trivial one-line fix, blocks all cross-image correlation

**Problem:** `host_correlator.py` uses `Path(output_dir)` on lines 461 and 519 but never imports `pathlib.Path`.

**Fix:** Add `from pathlib import Path` to the imports at the top of the file:

```python
# Current imports (lines 9-12):
import json
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Dict, List, Any, Optional

# Add:
from pathlib import Path
```

**Files to change:**
- `/home/sansforensics/Geoff/src/host_correlator.py` — add `from pathlib import Path` after line 12

---

### Fix 4: Self-Heal Fallback Module Validation (Fixes D — 13 failures)

**Priority:** P1 — second-highest failure count, but less critical because these are retry-branch failures, not primary-path failures

**Problem:** When a step fails and the self-heal LLM suggests a `fallback_tool` fix, `_execute_heal()` dispatches to the fallback module/function via `_run_step_via_orchestrator()`. But the LLM invents module names that don't exist in the orchestrator's `specialist_map` (e.g., `ewf_tools`, `file_system_forensics`, `tsk`, `registry_forensics`, `windows_registry`, `file_analysis`, `file_system`, `files`).

The actual failures this manifests as:
- `network_share_forensics.analyze_network_shares` → LLM fallback: `file_system_forensics`, `windows_registry`, `registry_forensics` (3 failures)
- `bulk_extractor.scan_image` → LLM fallback: `ewf_tools` (1 failure)
- `files.signature_mismatch_scan` → LLM fallback: `files`, `file_system`, `file_analysis` (3 failures)
- `usnjrnl.parse_usnjrnl` → LLM fallback: `tsk` (3 failures)
- `fat_recovery.recover_formatted_fat` → LLM fallback: `sleuthkit`, `tsk` (3 failures)

**Fix approach (two parts):**

**Part A — Validate fallback module names in `_execute_heal()`:**
Before dispatching to a fallback module, check if it exists in the orchestrator's `specialist_map`. If not, skip the fallback and return None (let the next heal strategy try):

```python
# In _execute_heal(), the fallback_tool branch:
elif fix_type == "fallback_tool":
    if not decision.fallback_module or not decision.fallback_function:
        return None
    # Validate fallback module exists before dispatching
    from sift_specialists_extended import SIFTOrchestrator  # or however it's accessed
    if decision.fallback_module not in orchestrator_specialist_modules:
        _fe_log(job_id, f"  [HEAL] Fallback module '{decision.fallback_module}' not in specialist_map — skipping")
        return None
    new_params = dict(params)
    new_params.update(decision.new_params)
    new_params["_heal_attempt"] = True
    _fe_log(job_id, f"  [HEAL] Fallback: {decision.fallback_module}.{decision.fallback_function}")
    return _run_step_via_orchestrator(
        decision.fallback_module, decision.fallback_function,
        new_params, job_id=job_id,
    )
```

**Part B — Add module alias map for common LLM hallucinations:**
The LLM consistently maps real modules to wrong names. Add an alias/normalization map:

```python
MODULE_ALIASES = {
    'tsk': 'sleuthkit',
    'file_system_forensics': 'sleuthkit',
    'file_system': 'sleuthkit',
    'file_analysis': 'sleuthkit',
    'files': 'sleuthkit',
    'ewf_tools': 'sleuthkit',
    'registry_forensics': 'registry',
    'windows_registry': 'registry',
}
```

Apply alias before validation: `resolved_module = MODULE_ALIASES.get(module, module)`.

**Files to change:**
- `/home/sansforensics/Geoff/src/geoff_self_heal.py` — `_execute_heal()` function (line ~126)
- `/home/sansforensics/Geoff/src/geoff_utils.py` or `geoff_self_heal.py` — add `MODULE_ALIASES` dict

---

### Fix 5: Self-Heal LLM Prompt Hardening (Prevents future A+D recurrences)

**Priority:** P2 — preventive, reduces future self-heal hallucination

**Problem:** The Critic/Heal LLM doesn't know the actual specialist function signatures or valid module names, so it invents params and modules.

**Fix:** Inject the specialist function signatures and valid module names into the heal LLM prompt:

```python
# In _attempt_heal() or the critic's analyze_execution_error_v2() call:
# Include available modules and function signatures in the ErrorContext
ctx.available_modules = list(specialist_map.keys())  # ['sleuthkit', 'plaso', 'vss', ...]
ctx.function_signatures = {
    'plaso.create_timeline': ['evidence_path', 'output_file', 'parsers'],
    'plaso.sort_timeline': ['storage_file', 'output_format', 'filter_str'],
    'windows.analyze_amcache': ['image', 'output_dir'],
    'windows.analyze_srum': ['image', 'output_dir'],
    # ... etc
}
```

This way the LLM can only suggest valid params and valid fallback modules.

**Files to change:**
- `/home/sansforensics/Geoff/src/geoff_critic.py` — `ErrorContext` class, `analyze_execution_error_v2()` prompt
- `/home/sansforensics/Geoff/src/geoff_self_heal.py` — `_attempt_heal()` context building
- `/home/sansforensics/Geoff/src/geoff_utils.py` — `_build_error_context()` signature enrichment

---

### Fix 6: PLASO `sort_timeline` — Accept `output_file` as Optional Alias (Belt-and-suspenders)

**Priority:** P2 — already covered by Fix 1, but good for API clarity

**Problem:** `sort_timeline()` computes `output_file` internally from `storage_file`, but the playbook and self-heal LLM both try to pass `output_file` as a kwarg. The function doesn't accept it.

**Fix:** Add `output_file` as an optional parameter to `sort_timeline()`. If provided, use it; otherwise compute it:

```python
def sort_timeline(self, storage_file: str, output_format: str = 'l2tcsv',
                  filter_str: Optional[str] = None,
                  output_file: Optional[str] = None) -> Dict[str, Any]:
    # ...
    if output_file is None:
        output_file = storage_file.replace('.plaso', f'.{output_format}')
    # ... rest unchanged
```

**Similar for `create_timeline`:** Already accepts `output_file`, so no change needed. But consider adding `partition_number`, `partition_offset`, `partition`, `image_type` as optional ignored params for API clarity:

```python
def create_timeline(self, evidence_path: str, output_file: str,
                    parsers: Optional[List[str]] = None, *,
                    partition_number: Optional[int] = None,
                    partition_offset: Optional[int] = None,
                    partition: Optional[str] = None,
                    image_type: Optional[str] = None) -> Dict[str, Any]:
    # All extra params ignored — for API compatibility with playbook templates
```

**Rationale:** This is redundant with Fix 1 but makes the function signature self-documenting. If someone calls the function directly (not via orchestrator), it won't crash.

**Files to change:**
- `/home/sansforensics/Geoff/src/sift_specialists_extended.py` — `sort_timeline()` (line ~955), `create_timeline()` (line ~872)
- Same pattern for `windows.analyze_srum()` and `windows.analyze_amcache()` — add `srum_path`/`amcache_path` as keyword-only ignored optionals

---

## Impact Summary

| Fix | Category | Failures Fixed | Effort | Risk |
|---|---|---|---|---|
| Fix 1: Orchestrator `**kwargs` shield | A | 19 | Low (10 lines) | Low |
| Fix 2: VSS mount cleanup | B | 12 | Medium (40 lines) | Low |
| Fix 3: Path import | C | 6 | Trivial (1 line) | None |
| Fix 4: Fallback module validation | D | 13 | Medium (30 lines) | Low |
| Fix 5: Heal LLM prompt hardening | A+D | Prevents future | High | Medium |
| Fix 6: Specialist `**kwargs` aliases | A | 19 (redundant w/ Fix 1) | Low | None |

**Recommended implementation order:**
1. Fix 3 (1 line, immediate)
2. Fix 1 (10 lines, unblocks 19 failures)
3. Fix 2 (40 lines, unblocks 12 failures)
4. Fix 4 (30 lines, unblocks 13 failures)
5. Fix 6 (belt-and-suspenders, optional)
6. Fix 5 (preventive, higher effort)

After Fixes 1-4, **all 48 failures are addressed**. Fix 5 prevents recurrence. Fix 6 adds defense-in-depth.

---

## Files Inventory

| File | Fixes Applied |
|---|---|
| `src/sift_specialists_extended.py` | Fix 1 (orchestrator dispatch), Fix 2 (VSS mount), Fix 6 (optional) |
| `src/host_correlator.py` | Fix 3 (Path import) |
| `src/geoff_self_heal.py` | Fix 4 (fallback validation + aliases) |
| `src/geoff_pipeline.py` | Fix 2 optional (retry VSS cleanup) |
| `src/geoff_critic.py` | Fix 5 (prompt enrichment) |
| `src/geoff_utils.py` | Fix 5 (context enrichment) |

---

## Notes

- The `bulk_extractor.scan_image` "error" (1 failure) with no specific error message may be a timeout or OOM issue — not enough info to diagnose. Not addressed in this plan.
- The 5 SKIP-OK entries (3× remnux.exiftool_scan, 2× windows.analyze_amcache on XP) are expected behavior and need no fix.
- The `time_filter_start`/`time_filter_end` kwargs in PASS2 playbook `sort_timeline` calls (PB-SIFT-102, 104) are NOT causing failures in this job run but WILL cause the same KWARG-BUG when those playbooks execute, since `sort_timeline` doesn't accept those params either. Fix 1 covers this preventively.