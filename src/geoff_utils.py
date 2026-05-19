#!/usr/bin/env python3
"""Geoff DFIR - Utility functions, logging, checkpoint, and shared state.

Auto-extracted from geoff_integrated.py monolith.
Leaf dependency: imports only from stdlib (os, sys, json, subprocess, hashlib,
pathlib, threading, time, traceback, tempfile, uuid, signal, re, datetime).
"""

import os
import sys
import json
import re
import subprocess
import hashlib
import tempfile
import threading
import time
import uuid
import traceback
import signal
from datetime import datetime
from pathlib import Path
from typing import Optional

__all__ = [
  "FindingsWriter",
  "_ExecResultCache",
  "_apply_anti_forensics_cascade",
  "_atomic_append",
  "_atomic_write",
  "_audit_append",
  "_build_connectivity_map",
  "_build_error_context",
  "_ckpt_archive_registered",
  "_ckpt_disk_walked",
  "_ckpt_load",
  "_ckpt_mark_disk_walked",
  "_ckpt_mark_phase",
  "_ckpt_phase_done",
  "_ckpt_register_archive",
  "_ckpt_save",
  "_cleanup_mounts",
  "_compact_step_result",
  "_create_update_job",
  "_detect_os",
  "_detect_os_from_devices",
  "_extract_ips_from_evidence",
  "_fe_log",
  "_fe_log_with_exception",
  "_global_exception_handler",
  "_hash_file",
  "_is_rfc1918",
  "_log_error",
  "_log_info",
  "_make_exec_key",
  "_resolve_params",
  "_run_step_via_orchestrator",
  "_run_step_with_watchdog",
  "_sanitize_tool_output",
  "_scan_completed_playbooks",
  "git_commit_action",
  "safe_git_commit",
  "safe_run",
  "validate_investigation_state"
]



# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_STDOUT_SIZE = 50 * 1024 * 1024  # 50MB
MAX_STATE_FIELD_SIZE = 100 * 1024    # 100KB
CHECKPOINT_FILE = ".geoff_checkpoint.json"
STRICT_MODE = os.environ.get("GEOFF_STRICT_MODE", "false").lower() == "true"
CASES_WORK_DIR = os.environ.get(
    "GEOFF_CASES_PATH",
    os.path.join(tempfile.gettempdir(), "geoff-cases")
)
_MAX_IN_MEMORY_FINDINGS = int(os.environ.get("GEOFF_MAX_FINDINGS", "50000"))

# ---------------------------------------------------------------------------
# Shared state (threading locks, job tracker, mount registry)
# ---------------------------------------------------------------------------

_state_lock = threading.Lock()
_log_lock = threading.Lock()
_find_evil_jobs: dict = {}  # job_id -> {status, progress, result, ...}
_active_mounts: list = []

# ---------------------------------------------------------------------------
# Function references set by importing module (orchestrator singletons)
# ---------------------------------------------------------------------------

orchestrator = None
remnux_orchestrator = None
_attempt_heal = None   # set by geoff_integrated.py to self-healing function

# ---------------------------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------------------------

def _log_info(msg: str):
    """Info-level logger — not an error."""
    try:
        print(f"[GEOFF] {msg}", file=sys.stderr)
    except BrokenPipeError:
        pass


def _fe_log(job_id: str, msg: str):
    """Append a timestamped log entry to a Find Evil job."""
    if job_id is None:
        return
    with _state_lock:
        if job_id in _find_evil_jobs:
            ts = datetime.now().strftime("%H:%M:%S")
            _find_evil_jobs[job_id].setdefault("log", []).append({"time": ts, "msg": msg})


def _fe_log_with_exception(job_id: str, msg: str, e: Exception = None):
    """Log an exception with context for Find Evil jobs."""
    if e:
        log_msg = f"{msg} Error: {e}"
        log_msg += f"\nTraceback: {traceback.format_exc()[:500]}"
    else:
        log_msg = msg
    _fe_log(job_id, log_msg)


def _log_error(msg: str, e: Exception = None, job_id: str = None):
    """Generic error logger - uses _fe_log for job contexts, print for others.
    In STRICT_MODE, re-raises the exception after logging."""
    if e:
        log_msg = f"{msg} Error: {e}"
        if job_id:
            log_msg += f"\nTraceback: {traceback.format_exc()[:500]}"
    else:
        log_msg = msg
    if job_id:
        _fe_log(job_id, log_msg)
    else:
        try:
            print(f"[GEOFF] error: {log_msg}", file=sys.stderr)
        except BrokenPipeError:
            pass
        print(f"[GEOFF] error: {log_msg}", file=sys.stderr)
    if STRICT_MODE:
        if e:
            raise e
        else:
            raise RuntimeError(msg)


# ---------------------------------------------------------------------------
# Global exception handler
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------

def _global_exception_handler(exc_type, exc_value, exc_traceback):
    """Log unhandled exceptions to /tmp/geoff_crash.log before crashing."""
    try:
        with open('/tmp/geoff_crash.log', 'a') as f:
            f.write(f"GLOBAL | {datetime.now().isoformat()} | {exc_type.__name__}\n")
            traceback.print_tb(exc_traceback, file=f)
            f.write(f"{exc_value}\n---\n")
    except Exception:
        pass  # best-effort — don't compound the crash
    sys.__excepthook__(exc_type, exc_value, exc_traceback)


# ---------------------------------------------------------------------------
# Atomic I/O and hashing (mirrored from geoff_config to keep this module a leaf)
# ---------------------------------------------------------------------------

def _hash_file(path):
    """Compute SHA-256 hash of a file for chain of custody."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            while chunk := f.read(8192):
                h.update(chunk)
        return h.hexdigest()
    except Exception as e:
        _log_error(f"hash_file failed for {path}", e)
        return "hash_failed"


def _atomic_write(path, data, mode='w'):
    """Atomically write data to path using temp file + replace."""
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    tmp = str(path) + '.tmp'
    try:
        with open(tmp, mode) as f:
            f.write(data)
        os.replace(tmp, str(path))
    except Exception as e:
        _log_error(f"atomic write failed for {path}", e)
        try:
            os.unlink(tmp)
        except OSError:
            pass
        if STRICT_MODE:
            raise


def _atomic_append(path, data):
    """Atomically append data to a file (read-existing + write-all + replace)."""
    tmp = str(path) + '.tmp'
    try:
        existing = ''
        if os.path.exists(path):
            with open(path, 'r') as f:
                existing = f.read()
        with open(tmp, 'w') as f:
            f.write(existing)
            f.write(data)
        os.replace(tmp, str(path))
    except Exception as e:
        _log_error(f"atomic append failed for {path}", e)
        try:
            os.unlink(tmp)
        except OSError:
            pass
        if STRICT_MODE:
            raise


# ---------------------------------------------------------------------------
# Checkpoint system
# ---------------------------------------------------------------------------

def _ckpt_load(case_work_dir: Path) -> dict:
    """Load checkpoint from case directory. Returns empty scaffold if not found."""
    p = Path(case_work_dir) / CHECKPOINT_FILE
    if p.exists():
        try:
            with open(p) as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            pass
    return {
        "version": 1,
        "evidence_path": "",
        "started_at": "",
        "last_updated": "",
        "phases": {},
        "extracted_archives": {},
        "walked_disks": [],
    }


def _ckpt_save(case_work_dir: Path, ckpt: dict):
    """Persist checkpoint to disk atomically."""
    ckpt["last_updated"] = datetime.now().isoformat()
    ckpt["alive_at"] = datetime.now().isoformat()
    _atomic_write(Path(case_work_dir) / CHECKPOINT_FILE, json.dumps(ckpt, indent=2, default=str))


def _ckpt_phase_done(ckpt: dict, phase: str) -> bool:
    """Check if a phase is marked complete in the checkpoint."""
    return ckpt.get("phases", {}).get(phase, {}).get("status") == "complete"


def _ckpt_mark_phase(ckpt: dict, phase: str, status: str, data_file: str = None):
    """Mark a phase's status in the checkpoint (pending/running/complete/failed)."""
    entry = {"status": status, "completed_at": datetime.now().isoformat() if status == "complete" else None}
    if data_file:
        entry["data_file"] = data_file
    ckpt.setdefault("phases", {})[phase] = entry


def _ckpt_archive_registered(ckpt: dict, archive_hash: str) -> bool:
    """Check if an archive hash is already registered in the checkpoint."""
    return archive_hash in ckpt.get("extracted_archives", {})


def _ckpt_register_archive(ckpt: dict, archive_hash: str, archive_path: str, extracted_dir: str, file_count: int = 0):
    """Register an extracted archive in the checkpoint for dedup."""
    ckpt.setdefault("extracted_archives", {})[archive_hash] = {
        "archive_path": archive_path,
        "extracted_dir": extracted_dir,
        "file_count": file_count,
        "extracted_at": datetime.now().isoformat(),
    }


def _ckpt_disk_walked(ckpt: dict, image_path: str) -> bool:
    """Check if a disk image path is already in the walked_disks list."""
    return image_path in ckpt.get("walked_disks", [])


def _ckpt_mark_disk_walked(ckpt: dict, image_path: str):
    """Record a disk image as walked so it won't be re-processed."""
    walked = ckpt.setdefault("walked_disks", [])
    if image_path not in walked:
        walked.append(image_path)


# ---------------------------------------------------------------------------
# FindingsWriter — JSONL findings storage with in-memory index
# ---------------------------------------------------------------------------

class FindingsWriter:
    """Write step-record findings to a JSONL file as they complete.

    Keeps a compact in-memory index (step_key → status) for fast idempotency
    checks, avoiding the need to scan the full findings list on every step.
    The full finding dicts are flushed to disk immediately and optionally
    accumulated in memory up to *max_in_memory* entries.
    """

    def __init__(self, jsonl_path: Path, max_in_memory: int = _MAX_IN_MEMORY_FINDINGS, job_id: str = None, resume: bool = False):
        self._path = jsonl_path
        self._max = max_in_memory
        self._job_id = job_id
        self._index: dict = {}   # step_key -> status
        self._records: list = [] # in-memory accumulation (capped)
        self._lock = threading.Lock()
        # Ensure parent dir exists
        jsonl_path.parent.mkdir(parents=True, exist_ok=True)
        if resume and jsonl_path.exists():
            self._load_existing()

    def _load_existing(self):
        """Pre-populate index from prior run.'s findings.jsonl."""
        loaded = 0
        try:
            with open(self._path) as f:
                for line in f:
                    try:
                        rec = json.loads(line)
                        sk = rec.get("step_key", "")
                        if sk:
                            self._index[sk] = rec.get("status", "")
                            loaded += 1
                    except: pass
        except: pass
        if loaded:
            _log_info(f"FindingsWriter: resumed {loaded} step records")

    def append(self, record: dict) -> None:
        step_key = record.get("step_key", "")
        status = record.get("status", "")
        with self._lock:
            self._index[step_key] = status
            if len(self._records) < self._max:
                self._records.append(record)
            elif len(self._records) == self._max:
                cap_msg = (
                    f"FindingsWriter: in-memory cap ({self._max}) reached; "
                    "further findings written to disk only."
                )
                _log_info(cap_msg)
                if self._job_id:
                    _fe_log(self._job_id, f"⚠ {cap_msg}")
        # Write to JSONL outside the lock to avoid blocking
        try:
            with open(self._path, "a") as fh:
                fh.write(json.dumps(record, default=str) + "\n")
        except OSError as exc:
            err_msg = f"FindingsWriter: failed to write {self._path}: {exc}"
            _log_info(err_msg)
            if self._job_id:
                _fe_log(self._job_id, f"⚠ {err_msg}")

    def is_completed(self, step_key: str) -> bool:
        with self._lock:
            return self._index.get(step_key) == "completed"

    def all_records(self) -> list:
        """Return all records. Combines in-memory and disk records when cap was exceeded."""
        with self._lock:
            if len(self._records) < self._max:
                return list(self._records)
            in_memory = list(self._records)
        # Cap was hit — also read overflow records from JSONL for complete results
        all_recs = list(in_memory)
        try:
            if self._path.exists():
                seen_keys = {r.get("step_key") for r in in_memory if r.get("step_key")}
                with open(self._path, 'r') as fh:
                    for line in fh:
                        line = line.strip()
                        if line:
                            try:
                                rec = json.loads(line)
                                sk = rec.get("step_key", "")
                                if sk and sk not in seen_keys:
                                    all_recs.append(rec)
                                    seen_keys.add(sk)
                            except json.JSONDecodeError:
                                continue
        except OSError as e:
            print(f"[FindingsWriter] Failed to read JSONL {self._path}: {e}", flush=True)
            return in_memory
        return all_recs


# ---------------------------------------------------------------------------
# safe_run / safe_git_commit
# ---------------------------------------------------------------------------

def safe_run(cmd, timeout=600, **kwargs):
    """Wrapper for subprocess.run with default timeout. Always returns a dict.
    Truncates stdout and stderr at MAX_STDOUT_SIZE to prevent memory blowup.
    Always includes stderr in the result for diagnostics."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, **kwargs)
        stdout = result.stdout
        stderr_out = result.stderr
        truncated = False
        if len(stdout) > MAX_STDOUT_SIZE:
            # Truncate and dump full output to file
            dump_path = os.path.join(tempfile.gettempdir(), f"geoff_stdout_{uuid.uuid4().hex[:8]}.txt")
            with open(dump_path, "w") as f:
                f.write(stdout)
            stdout = stdout[:MAX_STDOUT_SIZE] + f"\n... TRUNCATED (full output at {dump_path})"
            truncated = True
        if len(stderr_out) > MAX_STDOUT_SIZE:
            stderr_out = stderr_out[:MAX_STDOUT_SIZE] + f"\n... STDERR TRUNCATED at {MAX_STDOUT_SIZE} bytes"
        # Log non-empty stderr as diagnostics — even on success exit codes
        if stderr_out.strip():
            cmd_str = ' '.join(str(c) for c in cmd[:5])
            _log_info(f"stderr from {cmd_str}: {stderr_out[:300]}")
        return {
            "code": result.returncode,
            "stdout": stdout,
            "stderr": stderr_out,
            "truncated": truncated,
        }
    except subprocess.TimeoutExpired:
        cmd_str = ' '.join(str(c) for c in cmd[:5])
        _log_error(f"Command timed out after {timeout}s: {cmd_str}")
        return {
            "code": -1,
            "stdout": "",
            "stderr": f"Timeout after {timeout}s: {cmd_str}",
        }
    except Exception as e:
        cmd_str = ' '.join(str(c) for c in cmd[:5])
        _log_error(f"Command failed: {cmd_str}", e)
        return {
            "code": -2,
            "stdout": "",
            "stderr": str(e),
        }


def safe_git_commit(message: str, base_path: str = None):
    """Safe git commit wrapper. Returns dict with status/data/error."""
    if base_path is None:
        base_path = os.environ.get('GEOFF_GIT_DIR', CASES_WORK_DIR + '/git')

    if not os.path.isdir(base_path):
        _log_error(f"git commit: not a directory: {base_path}")
        return {"status": "failed", "error": "not a directory", "hash": None}

    # Check if we're in a git repo
    result = safe_run(['git', 'rev-parse', '--is-inside-work-tree'], cwd=base_path, timeout=10)
    if result["code"] != 0:
        _log_error(f"git commit: not a git repo: {base_path}")
        return {"status": "failed", "error": "not a git repo", "hash": None}

    # Run git add -A
    add_result = safe_run(['git', 'add', '-A'], cwd=base_path, timeout=60)
    if add_result["code"] != 0:
        _log_error(f"git add failed: {add_result['stderr'][:200]}")
        return {"status": "failed", "error": f"git add failed: {add_result['stderr'][:100]}", "hash": None}

    # Ensure git user config is set so commits don't fail with "please tell me who you are"
    safe_run(['git', 'config', 'user.email', 'geoff@geoff.dfir'], cwd=base_path, timeout=10)
    safe_run(['git', 'config', 'user.name', 'Geoff DFIR'], cwd=base_path, timeout=10)

    # Run git commit
    commit_result = safe_run(['git', 'commit', '-m', message], cwd=base_path, timeout=60)

    if commit_result["code"] == 0:
        # Extract commit hash
        hash_result = safe_run(['git', 'rev-parse', 'HEAD'], cwd=base_path, timeout=10)
        if hash_result["code"] == 0:
            commit_hash = hash_result["stdout"].strip()
            _log_info(f"Committed: {message} (hash: {commit_hash})")
            return {"status": "committed", "hash": commit_hash, "error": None}
        return {"status": "committed", "hash": None, "error": "could not get hash"}
    elif commit_result["code"] < 0:
        # Timeout or other exception from safe_run
        _log_error(f"git commit failed: {commit_result['stderr']}")
        return {"status": "failed", "error": commit_result["stderr"], "hash": None}
    elif "nothing to commit" in commit_result["stderr"].lower():
        return {"status": "noop", "hash": None, "error": None}
    else:
        _log_error(f"git commit failed: {commit_result['stderr'][:500]}")
        return {"status": "failed", "error": commit_result["stderr"][:200], "hash": None}


def git_commit_action(message: str, base_path: str = None):
    """Git commit for audit trail - now uses safe_git_commit wrapper."""
    if base_path is None:
        base_path = os.environ.get('GEOFF_GIT_DIR', CASES_WORK_DIR + '/git')

    if not os.path.isdir(base_path):
        return

    result = safe_git_commit(message, base_path)
    if result["status"] == "failed":
        _log_error(f"git commit action failed: {result.get('error', 'unknown')}")


# ---------------------------------------------------------------------------
# sanitize / exec key / resolve params / scan playbooks
# ---------------------------------------------------------------------------

def _sanitize_tool_output(output: str) -> str:
    """Sanitize tool output to prevent JSON injection and control character issues."""
    if not isinstance(output, str):
        return str(output)
    # Remove null bytes
    output = output.replace("\x00", "")
    # Remove other control characters except newline/tab
    output = "".join(c for c in output if c in "\n\t" or (ord(c) >= 32 and ord(c) < 127) or ord(c) >= 128)
    return output


def _make_exec_key(module: str, function: str, evidence_path: str, params: dict) -> str:
    """Create a deterministic dedup key for tool execution caching."""
    try:
        params_str = json.dumps(params, sort_keys=True, default=str)
    except Exception:
        params_str = str(params)
    raw = f"{module}|{function}|{evidence_path}|{params_str}"
    return hashlib.md5(raw.encode()).hexdigest()[:16]


def _resolve_params(params_template, evidence_item: str, image_offsets: dict,
                    case_work_dir, output_dir: str, os_type: str,
                    inventory: dict) -> Optional[dict]:
    """Resolve template placeholders in param dict with actual values."""
    import pathlib
    try:
        item_path = pathlib.Path(evidence_item)
        item_stem = item_path.stem
        resolved = {}
        for k, v in params_template.items():
            if isinstance(v, str):
                v = v.replace("{image}", evidence_item)
                v = v.replace("{mem}", evidence_item)
                v = v.replace("{pcap}", evidence_item)
                v = v.replace("{evtx}", evidence_item)
                v = v.replace("{evt}", evidence_item)
                v = v.replace("{syslog}", evidence_item)
                v = v.replace("{hive}", evidence_item)
                v = v.replace("{mobile}", str(item_path.parent))
                v = v.replace("{file}", evidence_item)
                v = v.replace("{output_dir}", output_dir)
                v = v.replace("{image_stem}", item_stem)
                v = v.replace("{offset}", str(image_offsets.get(evidence_item, 2048)))
            resolved[k] = v
        # Convert numeric string params to int
        for k, v in list(resolved.items()):
            if isinstance(v, str) and v.isdigit():
                resolved[k] = int(v)
            elif isinstance(v, str) and v.lower() in ('true', 'false'):
                resolved[k] = v.lower() == 'true'
        return resolved
    except Exception:
        return None


def _scan_completed_playbooks(audit_path: str):
    """Scan audit trail for already-completed playbook+device combinations."""
    completed = set()
    try:
        audit_file = Path(audit_path)
        if not audit_file.exists():
            return completed
        with open(audit_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                event = rec.get("event", "")
                if event in ("playbook_completed", "step_completed"):
                    pb = rec.get("playbook_id", "")
                    dev = rec.get("device_id", "")
                    if pb:
                        completed.add((pb, dev))
    except Exception:
        pass
    return completed


# ---------------------------------------------------------------------------
# Step watchdog / exec cache / step result compaction
# ---------------------------------------------------------------------------

class _StepTimeout(Exception):
    """Raised when a step exceeds its watchdog timeout."""
    pass


class _ExecResultCache:
    """Cache tool execution results to deduplicate across playbooks."""
    def __init__(self, path=None):
        self._cache = {}
        self._path = path
        if path and os.path.isfile(path):
            try:
                with open(path) as f:
                    self._cache = json.load(f)
            except (IOError, json.JSONDecodeError):
                self._cache = {}

    def get(self, key):
        return self._cache.get(key)

    def set(self, key, value):
        self._cache[key] = value
        if self._path:
            try:
                with open(self._path, "w") as f:
                    json.dump(self._cache, f)
            except IOError:
                pass

    def contains(self, key):
        return key in self._cache

    def keys(self):
        return self._cache.keys()

    def __contains__(self, key):
        return key in self._cache


def _run_step_with_watchdog(func, args, step_timeout=1800):
    """Run a step function with a watchdog timer. Raises _StepTimeout if exceeded."""
    if not hasattr(signal, 'SIGALRM'):
        # Windows or environments without SIGALRM — just run without watchdog
        return func(*args)

    def _handler(signum, frame):
        raise _StepTimeout(f"Step watchdog exceeded {step_timeout}s")

    old_handler = signal.signal(signal.SIGALRM, _handler)
    signal.alarm(step_timeout)
    try:
        result = func(*args)
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)
    return result


def _compact_step_result(result: dict, case_work_dir: Path) -> dict:
    """If any field in result exceeds MAX_STATE_FIELD_SIZE, spill to file and store reference."""
    if not isinstance(result, dict):
        return result
    compacted = {}
    for key, value in result.items():
        val_str = json.dumps(value, default=str) if not isinstance(value, str) else value
        if len(val_str) > MAX_STATE_FIELD_SIZE:
            # Spill to file
            spill_dir = case_work_dir / "spill"
            spill_dir.mkdir(parents=True, exist_ok=True)
            spill_path = spill_dir / f"{uuid.uuid4().hex[:8]}_{key}.json"
            _atomic_write(spill_path, val_str)
            compacted[key] = f"SPILLED:{spill_path}"
            compacted[f"{key}_spill_hash"] = _hash_file(str(spill_path))
        else:
            compacted[key] = value
    return compacted


# ---------------------------------------------------------------------------
# Orchestrator routing (uses module-level references set by importing module)
# ---------------------------------------------------------------------------

def _run_step_via_orchestrator(module: str, function: str, params: dict, *,
                                job_id: str = "") -> dict:
    """Route a step to the correct orchestrator based on module prefix.

    Steps whose module is 'remnux' (or starts with 'remnux_') go to the
    REMnux orchestrator; everything else goes to the extended SIFT orchestrator.

    On error, delegates to _attempt_heal() for LLM-powered self-healing.
    The _heal_attempt flag in params prevents infinite recursion.
    """
    # Strip internal healing params before passing to specialist methods,
    # which don't accept unexpected keyword arguments
    _HEAL_INTERNAL_PARAMS = frozenset({'_heal_attempt', 'raw_command'})
    clean_params = {k: v for k, v in params.items() if k not in _HEAL_INTERNAL_PARAMS}

    # Standard routing
    if module == "remnux" or module.startswith("remnux_"):
        step = {"function": function, "params": clean_params}
        result = remnux_orchestrator.run_playbook_step("find-evil", step)
    else:
        step = {"module": module, "function": function, "params": clean_params}
        result = orchestrator.run_playbook_step("find-evil", step)

    # LLM-powered self-healing on error (guarded against recursion)
    if result.get("status") == "error" and not params.get("_heal_attempt"):
        if _attempt_heal is not None:
            healed = _attempt_heal(module, function, params, result, job_id)
            if healed is not None:
                return healed

    return result


# ---------------------------------------------------------------------------
# _build_error_context — structured error diagnostics
# ---------------------------------------------------------------------------

def _build_error_context(module: str, function: str, params: dict,
                          error_result: dict, job_id: str,
                          prior_attempts: list = None,
                          evidence_file: str = "",
                          evidence_type: str = "",
                          os_type: str = "") -> "ErrorContext":
    """Build a structured ErrorContext from a failed step's result.

    Uses delayed import of ErrorContext from geoff_critic to avoid circular
    imports.  Returns the ErrorContext instance, or a dict stand-in if the
    real class is unavailable.
    """
    stderr = error_result.get("stderr", "")
    stdout = error_result.get("stdout", "")
    error_msg = error_result.get("error", "")
    exit_code = error_result.get("code") if isinstance(error_result, dict) else None

    # Best-effort tool command reconstruction
    tool_cmd = f"{module}.{function}({json.dumps(params, default=str)[:200]})"

    try:
        from geoff_critic import ErrorContext
        return ErrorContext(
            job_id=job_id,
            step_index=0,
            module=module,
            function=function,
            exception_type="ExecutionError",
            exception_message=str(error_msg)[:500] if error_msg else (str(stderr)[:500] if stderr else "Unknown error"),
            traceback="",
            tool_command=tool_cmd,
            params=params,
            stdout=str(stdout)[:1024],
            stderr=str(stderr)[:1024],
            exit_code=exit_code,
            evidence_file=evidence_file,
            evidence_type=evidence_type,
            os_type=os_type,
            prior_heal_attempts=prior_attempts or [],
        )
    except ImportError:
        # Fallback dict when geoff_critic not available
        return {
            "job_id": job_id, "step_index": 0, "module": module,
            "function": function, "exception_type": "ExecutionError",
            "exception_message": str(error_msg)[:500] if error_msg else (str(stderr)[:500] if stderr else "Unknown error"),
            "traceback": "", "tool_command": tool_cmd,
            "params": params, "stdout": str(stdout)[:1024],
            "stderr": str(stderr)[:1024], "exit_code": exit_code,
            "evidence_file": evidence_file, "evidence_type": evidence_type,
            "os_type": os_type, "prior_heal_attempts": prior_attempts or [],
        }


# ---------------------------------------------------------------------------
# _update_job factory (converted from closure inside find_evil)
# ---------------------------------------------------------------------------

def _create_update_job(job_id: str, start_time: float):
    """Factory that returns an _update_job closure for a specific investigation."""
    def _update_job(progress_pct: float, current_pb: str, current_step: str = "", log_msg: str = ""):
        """Push progress to the in-memory job tracker."""
        if job_id is None:
            return
        if log_msg:
            _fe_log(job_id, log_msg)
        elif current_step:
            _fe_log(job_id, f"{current_pb} > {current_step}")
        with _state_lock:
            if job_id in _find_evil_jobs:
                _find_evil_jobs[job_id]["progress_pct"] = round(progress_pct, 1)
                _find_evil_jobs[job_id]["current_playbook"] = current_pb
                _find_evil_jobs[job_id]["current_step"] = current_step
                _find_evil_jobs[job_id]["elapsed_seconds"] = round(time.time() - start_time, 1)
    return _update_job


# ---------------------------------------------------------------------------
# Audit / anti-forensics / investigation state
# ---------------------------------------------------------------------------

def _audit_append(case_work_dir, event: str, **fields):
    """Append a state-transition record to the case's audit_trail.jsonl.

    Silent best-effort: audit logging must never break an investigation.
    """
    if case_work_dir is None:
        return
    try:
        path = Path(str(case_work_dir)) / 'audit_trail.jsonl'
        record = {'ts': datetime.now().isoformat(), 'event': event, **fields}
        with open(path, 'a', encoding='utf-8') as f:
            f.write(json.dumps(record, default=str) + '\n')
    except Exception as e:
        _log_info(f"audit_trail append failed ({event}): {e}")


def _apply_anti_forensics_cascade(findings_writer) -> int:
    """Idempotently downgrade confidence on every finding and tag it as compromised.

    Safe to call repeatedly: a finding already tagged with "anti-forensics" in
    its compromised_by list is skipped, so the CONFIRMED → POSSIBLE → UNVERIFIED
    chain isn't applied twice. Returns the number of newly cascaded findings.
    """
    cascaded = 0
    for f in findings_writer.all_records():
        result = f.get("result")
        if not isinstance(result, dict):
            continue
        already = result.get("compromised_by") or []
        if "anti-forensics" in already:
            continue
        confidence = result.get("confidence", "")
        if confidence == "CONFIRMED":
            result["confidence"] = "POSSIBLE"
        elif confidence == "POSSIBLE":
            result["confidence"] = "UNVERIFIED"
        result.setdefault("compromised_by", []).append("anti-forensics")
        result["confidence_modifier"] = "downgraded-by-anti-forensics"
        cascaded += 1
    return cascaded


INVESTIGATION_SCHEMA = {
    "type": "object",
    "required": ["investigation_id", "steps", "current_step"],
    "properties": {
        "investigation_id": {"type": "string"},
        "case_name": {"type": "string"},
        "created_at": {"type": "string", "format": "date-time"},
        "updated_at": {"type": "string", "format": "date-time"},
        "current_step": {"type": "integer", "minimum": 0},
        "steps": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["index", "module", "function", "status"],
                "properties": {
                    "index": {"type": "integer"},
                    "module": {"type": "string"},
                    "function": {"type": "string"},
                    "params": {"type": "object"},
                    "status": {"type": "string", "enum": ["pending", "running", "completed", "failed", "skipped", "blocked"]},
                    "started_at": {"type": "string", "format": "date-time"},
                    "completed_at": {"type": "string", "format": "date-time"},
                    "result": {"type": "object"}
                }
            }
        }
    }
}


def validate_investigation_state(state: dict) -> bool:
    """Validate an investigation state dict against the JSON schema.

    Returns True if valid. Raises jsonschema.ValidationError on failure.
    """
    # Delayed import to keep geoff_utils a leaf
    from jsonschema import validate as jsonschema_validate, ValidationError as _ValidationError
    jsonschema_validate(instance=state, schema=INVESTIGATION_SCHEMA)
    return True


# ---------------------------------------------------------------------------
# OS detection
# ---------------------------------------------------------------------------

def _detect_os(inventory: dict) -> str:
    """Heuristic OS detection from file names."""
    all_paths = inventory["disk_images"] + inventory["other_files"]
    if any('windows' in p.lower() or 'win' in p.lower() for p in all_paths):
        return "windows"
    if any('linux' in p.lower() or 'ubuntu' in p.lower() for p in all_paths):
        return "linux"
    if any('macos' in p.lower() or 'osx' in p.lower() or 'darwin' in p.lower() for p in all_paths):
        return "macos"
    if inventory["mobile_backups"]:
        return "mobile"
    return "unknown"


def _detect_os_from_devices(device_map: dict) -> str:
    """Determine dominant OS from device map for playbook selection."""
    os_counts = {}
    for dev in device_map.values():
        os_t = dev.get("os_type", "unknown")
        os_counts[os_t] = os_counts.get(os_t, 0) + 1
    if not os_counts:
        return "unknown"
    # Return most common OS type, excluding 'network' and 'unknown'
    filtered = {k: v for k, v in os_counts.items() if k not in ("network", "unknown")}
    if filtered:
        return max(filtered, key=filtered.get)
    return "unknown"


# ---------------------------------------------------------------------------
# Mount cleanup
# ---------------------------------------------------------------------------

def _cleanup_mounts():
    """Unmount all partitions previously mounted by _mount_and_discover.

    Safe to call at any time — silently ignores failures.
    Called at the end of find_evil() for cleanup.
    """
    global _active_mounts
    if not _active_mounts:
        return
    # Unmount in reverse order (deepest first)
    for m in reversed(sorted(_active_mounts, key=len, reverse=True)):
        for attempt in range(3):
            result = subprocess.run(
                ["sudo", "umount", m],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode == 0:
                try:
                    print(f"[GEOFF] Unmounted: {m}", file=sys.stderr)
                except BrokenPipeError:
                    pass
                break
            else:
                # Device busy — wait and retry
                time.sleep(1)
        else:
            try:
                print(f"[GEOFF] Failed to unmount after retries: {m}", file=sys.stderr)
            except BrokenPipeError:
                pass
    _active_mounts = []


# ---------------------------------------------------------------------------
# Phase 10: IP / MAC / Hostname extraction & connectivity mapping
# ---------------------------------------------------------------------------

def _is_rfc1918(ip_str):
    """Check if an IP string is in RFC1918 (private) or loopback space."""
    import ipaddress
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback
    except ValueError:
        return False


def _extract_ips_from_evidence(inventory, case_work_dir):
    """Phase 10 orchestrator: extract IPs, MACs, and hostnames from all evidence.

    Returns (ips_by_device, connection_map) where:
      ips_by_device: {device_id: {ipv4: set, macs: set, hostnames: set, dns_servers: set}}
      connection_map: [{src, dst, src_device, dst_device, protocol, count, first_seen, last_seen}]
    """
    import ipaddress
    import re as _re
    from pathlib import Path as _Path
    from collections import defaultdict as _dd

    case_dir = _Path(case_work_dir)
    ips_by_device = _dd(lambda: {"ipv4": set(), "macs": set(), "hostnames": set(), "dns_servers": set()})
    connections_raw = []
    external_contacts = _dd(lambda: {"count": 0, "protocols": set(), "hostnames": set(), "first_seen": None, "last_seen": None})

    # ------------------------------------------------------------------
    # 1. Extract IPs from PCAPs via tshark
    # ------------------------------------------------------------------
    for pcap_path in inventory.get("pcaps", []) or []:
        try:
            pcap_str = str(pcap_path)
            # IP pairs
            result = safe_run(
                ["tshark", "-r", pcap_str, "-T", "fields", "-e", "ip.src", "-e", "ip.dst",
                 "-e", "_ws.col.Protocol", "-E", "separator=,", "-q"],
                timeout=600
            )
            if result.get("code") == 0 and result.get("stdout"):
                for line in result["stdout"].strip().split("\n"):
                    parts = [p.strip() for p in line.split(",")]
                    if len(parts) >= 2 and parts[0] and parts[1]:
                        src_ip, dst_ip = parts[0], parts[1]
                        proto = parts[2] if len(parts) > 2 else "unknown"
                        if src_ip.count('.') == 3 and dst_ip.count('.') == 3:
                            connections_raw.append({
                                "src": src_ip, "dst": dst_ip, "protocol": proto,
                                "source": "pcap", "pcap_file": pcap_str,
                            })

            # DNS queries
            dns_result = safe_run(
                ["tshark", "-r", pcap_str, "-Y", "dns", "-T", "fields",
                 "-e", "ip.src", "-e", "dns.qry.name", "-e", "dns.a", "-E", "separator=,", "-q"],
                timeout=600
            )
            if dns_result.get("code") == 0 and dns_result.get("stdout"):
                for line in dns_result["stdout"].strip().split("\n"):
                    parts = [p.strip() for p in line.split(",")]
                    if len(parts) >= 2 and parts[1]:
                        ip = parts[0] if parts[0] and parts[0].count('.') == 3 else None
                        hostname = parts[1].rstrip('.')
                        resolved = parts[2] if len(parts) > 2 and parts[2] else None
                        if ip:
                            ips_by_device[ip]["hostnames"].add(hostname)

            # DHCP hostnames and MACs
            dhcp_result = safe_run(
                ["tshark", "-r", pcap_str, "-Y", "dhcp", "-T", "fields",
                 "-e", "ip.src", "-e", "dhcp.option.hostname", "-e", "dhcp.option.requested_ip",
                 "-e", "dhcp.hw.mac_addr", "-E", "separator=,", "-q"],
                timeout=600
            )
            if dhcp_result.get("code") == 0 and dhcp_result.get("stdout"):
                for line in dhcp_result["stdout"].strip().split("\n"):
                    parts = [p.strip() for p in line.split(",")]
                    ip = None
                    for p_idx in range(min(3, len(parts))):
                        if parts[p_idx] and parts[p_idx].count('.') == 3:
                            ip = parts[p_idx]
                            break
                    mac = parts[3] if len(parts) > 3 and parts[3] else None
                    hostname = parts[1] if len(parts) > 1 and parts[1] and not parts[1].count('.') >= 3 else None
                    if ip:
                        if mac:
                            ips_by_device[ip]["macs"].add(mac)
                        if hostname:
                            ips_by_device[ip]["hostnames"].add(hostname)
        except Exception as e:
            _log_info(f"IP mapping PCAP tshark failed for {pcap_path}: {e}")

    # ------------------------------------------------------------------
    # 2. Extract IPs from registry hives
    # ------------------------------------------------------------------
    for hive_path in inventory.get("registry_hives", []) or []:
        try:
            import regipy.registry as _ri
            hive = _ri.RegistryHive(str(hive_path))
            try:
                sig_key = hive.get_key(r"Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures")
                for subkey in sig_key.iter_subkeys():
                    for val in subkey.iter_values():
                        vdata = str(val.value) if val.value is not None else ""
                        ips = _re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', vdata)
                        for ip in ips:
                            try:
                                ipaddress.ip_address(ip)
                                ips_by_device.setdefault(str(hive_path), {"ipv4": set(), "ipv6": set(), "macs": set(), "hostnames": set()})
                                ips_by_device[str(hive_path)]["ipv4"].add(ip)
                            except ValueError:
                                pass
            except Exception:
                pass
        except ImportError:
            _log_info("regipy not available — skipping registry IP extraction")
        except Exception as e:
            _log_info(f"IP mapping registry failed for {hive_path}: {e}")

    # ------------------------------------------------------------------
    # 3. Extract hostnames/IPs from browser history SQLite
    # ------------------------------------------------------------------
    for file_path in inventory.get("other_files", []) or []:
        fname = _Path(file_path).name.lower()
        if fname in ("places.sqlite", "history", "cookies.db", "cookies.sqlite"):
            try:
                result = safe_run(
                    ["sqlite3", str(file_path),
                     "SELECT DISTINCT url FROM moz_places WHERE url NOT LIKE '%://127.0.0.1%' LIMIT 5000;"],
                    timeout=30
                )
                if result.get("code") == 0 and result.get("stdout"):
                    for line in result["stdout"].strip().split("\n"):
                        line = line.strip()
                        if line:
                            try:
                                from urllib.parse import urlparse
                                hostname = urlparse(line).hostname
                                if hostname:
                                    try:
                                        ip = ipaddress.ip_address(hostname)
                                        ips_by_device[file_path]["ipv4"].add(str(ip))
                                    except ValueError:
                                        ips_by_device[file_path]["hostnames"].add(hostname)
                            except Exception:
                                pass
            except Exception as e:
                _log_info(f"IP mapping browser history failed for {file_path}: {e}")

    # ------------------------------------------------------------------
    # 4. Extract IPs from memory dumps (volatility netscan)
    # ------------------------------------------------------------------
    for mem_path in inventory.get("memory_dumps", []) or []:
        try:
            result = safe_run(
                ["vol", "-f", str(mem_path), "windows.netscan.NetScan", "--output", "csv"],
                timeout=600
            )
            if result.get("code") == 0 and result.get("stdout"):
                for line in result["stdout"].strip().split("\n"):
                    ips = _re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
                    for ip in ips:
                        ips_by_device[mem_path]["ipv4"].add(ip)
            # Also try netscan (vol2)
            result2 = safe_run(
                ["volatility", "-f", str(mem_path), "netscan"],
                timeout=600
            )
            if result2.get("code") == 0 and result2.get("stdout"):
                for line in result2["stdout"].strip().split("\n"):
                    ips = _re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
                    for ip in ips:
                        ips_by_device[mem_path]["ipv4"].add(ip)
        except Exception as e:
            _log_info(f"IP mapping volatility failed for {mem_path}: {e}")

    # ------------------------------------------------------------------
    # 5. Extract IPs from email artifacts (SMTP headers)
    # ------------------------------------------------------------------
    _EMAIL_HEADER_IPS = _re.compile(r'(?:Received:|X-Originating-IP:|X-Forwarded-For:)\s*.*?\b((?:\d{1,3}\.){3}\d{1,3})\b', _re.IGNORECASE)
    for file_path in inventory.get("other_files", []) or []:
        ext = _Path(file_path).suffix.lower()
        if ext in ('.eml', '.mbox', '.msg'):
            try:
                with open(file_path, 'r', errors='ignore') as f:
                    content = f.read(100000)  # First 100KB
                for match in _EMAIL_HEADER_IPS.finditer(content):
                    ip = match.group(1)
                    try:
                        ipaddress.ip_address(ip)
                        ips_by_device[file_path]["ipv4"].add(ip)
                    except ValueError:
                        pass
            except Exception as e:
                _log_info(f"IP mapping email failed for {file_path}: {e}")

    # ------------------------------------------------------------------
    # Convert sets to sorted lists for JSON serialization
    # ------------------------------------------------------------------
    ips_by_device_json = {}
    for key, val in ips_by_device.items():
        ips_by_device_json[key] = {
            "ipv4": sorted(val["ipv4"]),
            "macs": sorted(val["macs"]),
            "hostnames": sorted(val["hostnames"]),
            "dns_servers": sorted(val["dns_servers"]),
        }

    # Build connectivity map from raw connections
    connection_map = _build_connectivity_map(connections_raw, ips_by_device)

    # Store results in case work dir
    try:
        import json as _json
        _atomic_write(str(case_dir / "ips_map.json"),
                      _json.dumps(ips_by_device_json, default=str, indent=2))
        _atomic_write(str(case_dir / "connection_map.json"),
                      _json.dumps(connection_map, default=str, indent=2))
        _log_info(f"IP mapping saved: {len(ips_by_device_json)} devices, {len(connection_map)} connections")
    except Exception as e:
        _log_error(f"Failed to write IP mapping files", e)

    return ips_by_device_json, connection_map


def _build_connectivity_map(connections_raw, ips_by_device):
    """Cross-reference connections with device map to build connectivity profiles.

    Returns dict with keys:
      connection_map: [{src, dst, src_device, dst_device, protocol, count, first_seen, last_seen}]
      external_contacts: [{ip, count, protocols, hostnames, first_seen, last_seen}]
    """
    from collections import defaultdict as _dd

    # Build IP→device_id reverse map from ips_by_device
    ip_to_device = {}
    for dev_id, info in ips_by_device.items():
        for ip in info.get("ipv4", []) or []:
            ip_to_device[ip] = dev_id

    # Deduplicate and count connections
    _conn_key = _dd(lambda: {"count": 0, "protocols": set(), "first_seen": None, "last_seen": None})
    for conn in connections_raw:
        src = conn.get("src", "")
        dst = conn.get("dst", "")
        proto = conn.get("protocol", "unknown")
        if not src or not dst:
            continue
        key = f"{src}|{dst}|{proto}"
        _conn_key[key]["count"] += 1
        _conn_key[key]["protocols"].add(proto)
        _conn_key[key]["first_seen"] = _conn_key[key]["first_seen"] or conn.get("first_seen") or datetime.now().isoformat()

    connection_map = []
    external_contacts = _dd(lambda: {"count": 0, "protocols": set(), "hostnames": set()})

    for key, info in _conn_key.items():
        src, dst, proto = key.split("|")
        src_device = ip_to_device.get(src, "unknown")
        dst_device = ip_to_device.get(dst, "unknown")

        entry = {
            "src": src,
            "dst": dst,
            "src_device": src_device,
            "dst_device": dst_device,
            "protocol": proto,
            "count": info["count"],
            "first_seen": info["first_seen"],
            "last_seen": info["last_seen"] or info["first_seen"],
        }
        connection_map.append(entry)

        # Classify as external if dst is non-RFC1918
        if not _is_rfc1918(dst):
            external_contacts[dst]["count"] += info["count"]
            external_contacts[dst]["protocols"].add(proto)
            # Gather hostnames from all devices
            for dev_id, dev_info in ips_by_device.items():
                if dst in dev_info.get("hostnames", []):
                    external_contacts[dst]["hostnames"].update(dev_info["hostnames"])

    # Convert external_contacts to list
    ext_list = []
    for ip, info in external_contacts.items():
        ext_list.append({
            "ip": ip,
            "count": info["count"],
            "protocols": sorted(info["protocols"]),
            "hostnames": sorted(info["hostnames"]),
        })

    # Sort by count descending (most contacted first)
    ext_list.sort(key=lambda x: x["count"], reverse=True)

    return {
        "connection_map": connection_map,
        "external_contacts": ext_list,
    }
