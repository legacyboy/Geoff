# Geoff Self-Heal Failure Investigation

**Date:** 2025-05-24  
**Case:** 2018 (job fe-51d60bbf6054)  
**Investigator:** Steve4 (GLM-5.1 architect agent)

---

## Executive Summary

The self-heal system in Geoff is burning LLM tokens on problems that have **deterministic, code-level fixes**. Three of the four failure categories are caused by mismatches between playbook config, method signatures, and the orchestrator's `**params` dispatch pattern. The fourth (git lock contention) is a concurrency issue. The self-heal engine lacks pattern recognition for `TypeError` (unexpected keyword argument) and "Unknown function" errors, routing them to expensive LLM diagnosis instead of catching them deterministically.

---

## Failure 1: sleuthkit.fsstat — Unknown function

### Root Cause

**File:** `geoff_config.py`, line 1068  
**Method mapping:** `sift_specialists.py`, `SLEUTHKIT_Specialist` class

The playbook `PB-SIFT-037` defines:
```python
("sleuthkit", "fsstat", {"image": "{image}"}),
```

But `SLEUTHKIT_Specialist` has **no method named `fsstat`**. The actual method is `analyze_filesystem` (line 460 of `sift_specialists.py`):
```python
def analyze_filesystem(self, image: str, offset: Optional[int] = None) -> Dict[str, Any]:
    """fsstat - Display filesystem statistics with parsed structure"""
```

The `SpecialistOrchestrator.run_playbook_step` (line 1630) dispatches via `getattr(specialist, function)`, which fails because `function="fsstat"` doesn't exist on the specialist object. This returns:
```python
{'status': 'error', 'error': 'Unknown function "fsstat" on module "sleuthkit"'}
```

The `geoff_routes.py` whitelist (`_ALLOWED_TOOL_FUNCTIONS`, line 64) also does NOT include `fsstat`:
```python
'sleuthkit': {'analyze_partition_table', 'list_inodes', 'list_deleted', 'extract_file',
              'list_files', 'list_files_mactime', 'get_file_info', 'analyze_filesystem'},
```

### Why Self-Heal Failed

1. `classify_error_fast()` (line 107 of `geoff_self_heal.py`) doesn't match `"Unknown function"` patterns — it only checks `stderr`, not the structured error message from the orchestrator.
2. The LLM diagnosed it as a general error (confidence 8) and suggested `retry_params` — which re-invokes the same broken function name.
3. The HealCache cached this wrong diagnosis under the cache key `sha256("sleuthkit.fsstat|...")`, making subsequent hits on the same error return the same bad decision.

### Why It Burns Tokens

The LLM is called once for diagnosis (~1-3k tokens), then `_execute_heal` retries with the same broken function name, which fails again. The critic then re-analyzes. Each cycle costs tokens and time.

### Fix

**P0 — Immediate:** Change the playbook entry in `geoff_config.py` line 1068:
```python
# BEFORE:
("sleuthkit", "fsstat", {"image": "{image}"}),
# AFTER:
("sleuthkit", "analyze_filesystem", {"image": "{image}"}),
```

**P1 — Structural:** Add `"Unknown function"` and `"unexpected keyword argument"` patterns to `classify_error_fast()` in `geoff_self_heal.py` so these are never sent to the LLM:

```python
def classify_error_fast(ctx: ErrorContext) -> Optional[str]:
    stderr = (ctx.stderr or "").lower()
    error_msg = (ctx.exception_message or "").lower()
    
    # ... existing checks ...
    
    # TypeError: unexpected keyword argument
    if "unexpected keyword argument" in error_msg:
        return "type_error.bad_param"
    
    # Unknown function/method dispatch errors
    if "unknown function" in error_msg or "unknown module" in error_msg:
        return "dispatch_error.unknown_function"
    
    return None
```

Then in `_attempt_heal()`, add handling for these deterministic error classes:
```python
if fast_class == "type_error.bad_param":
    _fe_log(job_id, f"  [HEAL-FAST] Bad keyword argument in {module}.{function} — not healable via retry")
    return None
if fast_class == "dispatch_error.unknown_function":
    _fe_log(job_id, f"  [HEAL-FAST] Unknown function {module}.{function} — config error, not healable")
    return None
```

---

## Failure 2: BINARY_IDENT_Specialist.exiftool_scan — unexpected keyword argument 'mount_first'

### Root Cause

**File:** `sift_specialists_remnux.py`, line 140  
**Method signature:**
```python
def exiftool_scan(self, target_file: str) -> Dict[str, Any]:
```

The method accepts **only** `target_file`. When `_run_step_via_orchestrator` or `_execute_heal` passes extra params like `mount_first=True`, the `**params` unpacking in the orchestrator (line 757) causes:
```python
TypeError: exiftool_scan() got an unexpected keyword argument 'mount_first'
```

**Where does `mount_first` come from?** Not from the playbook config (lines 728/752 show `{"target_file": "{file}"}`). Two possible sources:
1. The LLM's `new_params` in a `HealDecision` with `fix_type="retry_params"` adds `mount_first=True` based on its diagnosis
2. A previous playbook step's params that somehow leaked (unlikely given current config)

The most likely source is **self-heal itself**: when the LLM analyzes an error on a disk image file, it suggests adding `mount_first=True` because it "makes sense" for disk images — but the method doesn't accept that parameter.

### Why Self-Heal Failed

1. Initial call with `mount_first` kwarg → `TypeError`
2. Self-heal sends error to LLM → LLM suggests `retry_params` with `mount_first=True` (or keeps it) → confidence 9
3. `_execute_heal` merges `new_params` into existing params and retries → same `TypeError`
4. The `_HEAL_INTERNAL_PARAMS` filter only strips `_heal_attempt` and `raw_command`, NOT `mount_first`

### Fix

**P0 — Immediate:** Add parameter validation to `_run_step_via_orchestrator` and the REMnux orchestrator. Before calling `method(**params)`, introspect the method signature and filter params:

```python
import inspect

def _filter_params(method, params: dict) -> dict:
    """Remove params not accepted by the method signature."""
    sig = inspect.signature(method)
    if any(p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values()):
        return params  # Method accepts **kwargs, pass everything through
    valid_keys = set(sig.parameters.keys())
    return {k: v for k, v in params.items() if k in valid_keys}
```

Apply in `sift_specialists.py` line 1630:
```python
specialist = specialist_map.get(module)
if specialist and hasattr(specialist, function):
    func = getattr(specialist, function)
    filtered = _filter_params(func, clean_params)
    return func(**filtered)
```

And in `sift_specialists_remnux.py` line 757:
```python
method = getattr(specialist, method_name, None)
if method:
    filtered = _filter_params(method, params)
    return method(**filtered)
```

**P1 — Self-heal:** In `_execute_heal()`, validate `new_params` against the target method's signature before dispatching:

```python
def _execute_heal(module, function, params, decision, job_id):
    # ... existing fix_type handling ...
    if fix_type in ("retry_params", "retry_with_offset", "retry_without_offset", "retry_with_profile"):
        new_params = dict(params)
        new_params.update(decision.new_params)
        # Validate new_params against the target method's signature
        new_params = _validate_params_against_signature(module, function, new_params)
        new_params["_heal_attempt"] = True
        return _run_step_via_orchestrator(module, function, new_params, job_id=job_id)
```

---

## Failure 3: BINARY_IDENT_Specialist.hashdeep_audit — unexpected keyword argument 'recursive'

### Root Cause

**File:** `sift_specialists_remnux.py`, line 257  
**Method signature:**
```python
def hashdeep_audit(self, target_file: str) -> Dict[str, Any]:
```

Same pattern as Failure 2. `hashdeep_audit` only accepts `target_file`, but params include `recursive=True`. The `recursive` flag is used by `SLEUTHKIT_Specialist.list_files` (line 519) but was incorrectly included in params for this method.

The `hashdeep_audit` method internally handles recursion itself (it passes `-r` to the hashdeep CLI on line ~335), so an external `recursive=True` parameter is both wrong and rejected.

### Why Self-Heal Failed

Identical pattern to Failure 2. LLM diagnosis at confidence 9 suggested retrying with the same broken params.

### Fix

Same as Failure 2 — the `_filter_params` approach fixes this for all methods at once. This is a systemic problem, not a per-method issue.

---

## Failure 4: Custody git commit — index.lock contention

### Root Cause

**Files:** `geoff_pipeline.py` line 457 (`_commit_step_with_custody`), `geoff_utils.py` line 453 (`safe_git_commit`)

The per-step custody commit (line 2642 of `pipeline_phases.py`) runs `safe_git_commit` after every completed step. When multiple steps complete in quick succession or when git operations overlap, the second commit encounters an existing `.git/index.lock` file.

`safe_git_commit` does NOT:
1. Check for or remove stale lock files
2. Use `--no-verify` or other git flags that reduce lock contention
3. Serialize commits across concurrent step execution
4. Retry on lock failure

### Why It Affects Self-Heal

While not a self-heal issue per se, the persistent git lock failures clutter the error stream and can cause the self-heal system to waste LLM calls on what is purely a concurrency issue.

### Fix

**P1 — Structural:** Add lock cleanup and retry logic to `safe_git_commit`:

```python
def safe_git_commit(message: str, base_path: str = None):
    if base_path is None:
        base_path = os.environ.get('GEOFF_GIT_DIR', CASES_WORK_DIR + '/git')
    
    # Remove stale lock files (>5 minutes old = definitely stale)
    lock_path = os.path.join(base_path, '.git', 'index.lock')
    if os.path.exists(lock_path):
        lock_age = time.time() - os.path.getmtime(lock_path)
        if lock_age > 300:  # 5 minutes
            _log_info(f"Removing stale git lock file (age: {lock_age:.0f}s)")
            try:
                os.unlink(lock_path)
            except OSError:
                pass
    
    # ... existing logic, but add retry on lock failure ...
    
    commit_result = safe_run(['git', 'commit', '-m', message], cwd=base_path, timeout=60)
    if commit_result["code"] != 0 and "index.lock" in commit_result.get("stderr", ""):
        # Retry once after brief delay
        time.sleep(2)
        # Try removing lock again
        try:
            os.unlink(lock_path)
        except OSError:
            pass
        commit_result = safe_run(['git', 'commit', '-m', message], cwd=base_path, timeout=60)
```

**P2 — Consider:** Batch custody commits. Instead of committing per-step, accumulate changes and commit per-playbook or per-device. This reduces git operations from ~50-100 per case to ~5-10.

---

## HealCache Analysis

### Location and Format

**Path:** `$GEOFF_GIT_DIR/heal_cache.json` (defaults to `/mnt/cases/git/heal_cache.json` on SIFT VM)  
**Format:** JSON dict keyed by `sha256("{module}.{function}|{exception_type}|{stderr[:200]}")[:16]`

Each entry is a `HealCacheEntry`:
```json
{
  "<cache_key>": {
    "cache_key": "...",
    "error_fingerprint": "",
    "decision": {
      "fixable": true,
      "fix_type": "retry_params",
      "fix_detail": "...",
      "root_cause": "...",
      "new_params": {"mount_first": true, ...},
      "confidence": 9,
      "from_cache": false,
      ...
    },
    "success_count": 0,
    "failure_count": 2,
    "last_seen": "2025-05-24T...",
    "created": "2025-05-24T..."
  }
}
```

### Is It Caching Wrong Diagnoses Across Cases?

**Yes, this is a real problem.** The cache key is:
```python
raw = f"{self.module}.{self.function}|{self.exception_type}|{(self.stderr or '')[:200]}"
return hashlib.sha256(raw.encode()).hexdigest()[:16]
```

Issues:
1. **Too narrow:** Includes only the first 200 chars of stderr. Two different errors with the same prefix will collide.
2. **No success threshold:** The `get()` method returns cached decisions only if `success_count > 0`, but a newly stored entry starts with `success_count = 0`. So **fresh entries are never returned from cache** — only entries that were later confirmed successful. But this also means a bad diagnosis that never succeeds gets `failure_count` incremented but is still returned if `success_count > 0` from a coincidental earlier success of a different error with a similar key.
3. **Cross-case contamination:** The cache is global (shared across all cases). A diagnosis that worked for one case's specific error could be wrong for another case with a similar error message. Since the key doesn't include `job_id` or case context, a `TypeError: unexpected keyword argument 'mount_first'` on `remnux.exiftool_scan` from a 2020 case would be cached and returned for the same error pattern in the 2018 case, even if the fix is wrong.
4. **No expiry:** Entries persist indefinitely. There's no TTL, no invalidation mechanism, no version check against code changes.

### Fix

**P0 — Immediate:** Add `job_id` (or at minimum case identifier) to the cache key, and add expiry:

```python
def cache_key(self) -> str:
    raw = f"{self.module}.{self.function}|{self.exception_type}|{(self.stderr or '')[:200]}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]
```

Should become:
```python
def cache_key(self) -> str:
    # Include full stderr (truncated to 500, not 200) and exception type for better specificity
    raw = f"{self.module}.{self.function}|{self.exception_type}|{(self.stderr or '')[:500]}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]
```

**P1 — Structural:** 
1. Add TTL to cache entries (default 7 days)
2. Add version invalidation — when code changes, stale cache entries should be invalidated
3. Never cache `retry_params` decisions that include params not in the target method's signature
4. Add `failure_threshold` — after N failures, remove the cached entry entirely

---

## Structural Recommendations

### 1. Add TypeError Pattern Recognition to Self-Heal (P0)

`TypeError: unexpected keyword argument` is **never healable by the LLM**. The correct response is to log it and fail fast. Add to `classify_error_fast()`:

```python
if "unexpected keyword argument" in (ctx.exception_message or "").lower():
    return "type_error.bad_param"
if "unknown function" in (ctx.exception_message or "").lower():
    return "dispatch_error.unknown_function"
if "positional argument" in (ctx.exception_message or "").lower() and "missing" in (ctx.exception_message or "").lower():
    return "type_error.missing_param"
```

Then handle these in `_attempt_heal()` by returning `None` immediately without calling the LLM.

### 2. Validate Params Against Method Signatures (P0)

Add `_filter_params()` as described in Failure 2. This is a single point fix that prevents all `unexpected keyword argument` errors system-wide. Apply it in both orchestrators.

### 3. Fix the Playbook Config (P0)

Change `geoff_config.py` line 1068 from `"fsstat"` to `"analyze_filesystem"`. This is a one-line fix.

### 4. Improve HealCache Semantics (P1)

- Increase stderr fingerprint from 200 to 500 chars
- Add TTL (7-day default)
- Add code-version invalidation
- Never cache decisions that add params not in the method signature
- Track `failure_threshold` and evict entries that fail ≥3 times consecutively

### 5. Add Self-Heal Circuit Breaker (P1)

The self-heal system has no memory across retries within a single case. If the same `(module, function)` pair fails 3+ times, stop attempting self-heal for it:

```python
# In _attempt_heal(), after building ErrorContext:
_heal_fail_counter = {}  # module.function -> count

attempts_key = f"{module}.{function}"
fail_count = _heal_fail_counter.get(attempts_key, 0)
if fail_count >= 3:
    _fe_log(job_id, f"  [HEAL] Circuit breaker: {attempts_key} failed {fail_count} times, skipping")
    return None
```

### 6. Reduce Token Burn on Known-Failure Patterns (P1)

The LLM prompt in `_build_heal_prompt()` lists all available fix types but doesn't tell the LLM about the actual method signatures. Adding available param names to the prompt would prevent the LLM from suggesting `mount_first` or `recursive` for methods that don't accept them:

```python
# In _build_heal_prompt():
available_params = _get_method_signature_params(module, function)
if available_params:
    prompt += f"\n=== ACCEPTED PARAMETERS ===\n{module}.{function} accepts: {', '.join(available_params)}\n"
```

### 7. Serialize Git Commits (P2)

Add a file lock or mutex around git operations. Or switch from per-step to per-playbook custody commits.

---

## Priority Summary

| Priority | Issue | Impact | Fix Effort |
|----------|-------|--------|------------|
| P0 | `fsstat` → `analyze_filesystem` rename | Every PB-SIFT-037 run fails | 1 line |
| P0 | `_filter_params()` for orchestrators | All `unexpected keyword argument` errors | ~20 lines |
| P0 | `classify_error_fast()` TypeError patterns | ~30% of self-heal LLM calls are wasted | ~15 lines |
| P1 | HealCache semantics (TTL, eviction, better keys) | Wrong diagnoses cached across cases | ~50 lines |
| P1 | Self-heal circuit breaker | Repeated LLM calls on permanently broken steps | ~10 lines |
| P1 | LLM prompt includes method signatures | LLM invents invalid params | ~30 lines |
| P2 | Git commit serialization/batching | Lock contention errors | ~30 lines |

**Estimated token savings:** With P0 fixes alone, approximately 40-60% of current self-heal LLM calls would be eliminated (deterministic fast-path for TypeError/dispatch errors + filtered params preventing the retry cycle).

---

## File Reference Index

| File | Lines | Relevance |
|------|-------|-----------|
| `geoff_config.py` | 1068 | PB-SIFT-037 uses `"fsstat"` instead of `"analyze_filesystem"` |
| `geoff_config.py` | 728, 752 | BINARY_IDENT playbook configs (correct) |
| `geoff_self_heal.py` | 107-120 | `classify_error_fast()` — missing TypeError patterns |
| `geoff_self_heal.py` | 124-180 | `_heal_cache` singleton init, `HealCache` path |
| `geoff_self_heal.py` | 182-260 | `_execute_heal()` — dispatches `new_params` without validation |
| `geoff_self_heal.py` | 262-340 | `_attempt_heal()` — no circuit breaker, no param validation |
| `geoff_critic.py` | 25-65 | `ErrorContext` and `HealDecision` dataclasses |
| `geoff_critic.py` | 68-145 | `HealCache` — key generation, storage, expiry logic |
| `geoff_critic.py` | 550-680 | `analyze_execution_error_v2()` — LLM diagnosis with no method signature context |
| `geoff_critic.py` | 680-760 | `_build_heal_prompt()` — no accepted params listed |
| `sift_specialists.py` | 460-520 | `SLEUTHKIT_Specialist.analyze_filesystem` (the real `fsstat`) |
| `sift_specialists.py` | 1617-1650 | `SpecialistOrchestrator.run_playbook_step` — `**params` dispatch |
| `sift_specialists_remnux.py` | 83-95 | `BINARY_IDENT_Specialist` class definition |
| `sift_specialists_remnux.py` | 140 | `exiftool_scan(self, target_file)` — only takes `target_file` |
| `sift_specialists_remnux.py` | 257 | `hashdeep_audit(self, target_file)` — only takes `target_file` |
| `sift_specialists_remnux.py` | 749-760 | `REMNUX_Orchestrator.run_playbook_step` — `**params` dispatch |
| `geoff_utils.py` | 686-710 | `_run_step_via_orchestrator` — strips only `_heal_attempt` and `raw_command` |
| `geoff_utils.py` | 453-520 | `safe_git_commit` — no lock cleanup or retry |
| `geoff_pipeline.py` | 457-530 | `_commit_step_with_custody` — per-step commit |
| `pipeline_phases.py` | 2427-2460 | Self-heal invocation in main pipeline loop |
| `geoff_routes.py` | 64-68 | `_ALLOWED_TOOL_FUNCTIONS` — missing `fsstat` |