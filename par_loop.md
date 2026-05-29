# Parallel Loop Review — Claude Code Verdict

## Overall: Not ready to commit — 3 bugs

---

## Bug 1 (CRITICAL): Dead code — `execute_step_parallel` never called
The function is defined at `geoff_pipeline.py:82` but the `for item in items:` loop at line 4788 is untouched. Zero parallelism is active. The whole point of the change is unwired.

---

## Bug 2 (CRASH): `None` step_record crash on skipped items
In `_run_single` (the worker inside `execute_step_parallel`), when a step was already completed:
```python
return ("skipped", None, 0, 0, 1)  # step_record is None
```
Then the outer loop immediately tries:
```python
exec_key = _make_exec_key(module, function, item, step_record.get("params", {}))
```
`step_record` is `None` → `AttributeError: 'NoneType' object has no attribute 'get'`. Hits on every resume/re-run.

**Fix:** Guard with `if step_record is None: continue` before the cache check.

---

## Bug 3 (LOGIC): exec_cache check after execution, not before
In `_run_single`, the tool (`_execute_fallback_chain`) runs AND findings are appended to `findings_writer`/`pb_findings` BEFORE the outer loop checks `exec_cache`. So if a previous playbook already cached this result, you still:
1. Re-execute the tool
2. Write a duplicate finding to disk

The outer loop then discards the count on cache-hit, but the duplicate finding remains.

**Fix:** Move the `exec_cache.get()` check inside `_run_single`, before `_execute_fallback_chain()`, matching the serial loop pattern at lines 4932-4941.

---

## What's clean (safe to commit independently)

| File | What | Lines |
|------|------|-------|
| `geoff_utils.py` | `_ExecResultCache` lock fix | +15 around class |
| `geoff_utils.py` | `ConcurrentStepRunner` class + helpers | +154 new class |
| `geoff_pipeline.py` | `execute_step_parallel` function structure (fix bugs 2+3, wire it in) | ~146 lines |
| `geoff_pipeline.py` | `copy` + `ThreadPoolExecutor` imports | lines 30-31 |

---

## What needs work

Wiring `execute_step_parallel` into the main loop at line 4788. The inner loop is ~400 lines per item with complex control flow (self-heal, forensicator/critic, unprocessable handling). The cleanest approach: replace `for item in items:` with a call that batches items through `execute_step_parallel()` for `disk_images` and `memory_dumps` evidence types only, keeping serial for everything else.
