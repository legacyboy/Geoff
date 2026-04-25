#!/usr/bin/env python3
"""
Geoff DFIR - Integrated with SIFT Tool Specialists
"""

import os
import json
import re
import shlex
import sys
import subprocess

# Load .env file before reading env vars
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass
import tempfile
import threading
import time
import uuid
import traceback
import hashlib

# Add src directory to path (works for both local and deployed)
SRC_DIR = os.path.dirname(os.path.abspath(__file__))
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

# STRICT_MODE - when True, re-raise exceptions after logging; when False (default), log and continue
STRICT_MODE = os.environ.get("GEOFF_STRICT_MODE", "false").lower() == "true"

# Threading locks
_log_lock = threading.Lock()
_state_lock = threading.Lock()

import requests
import hmac
from datetime import datetime
from pathlib import Path
from functools import wraps
from flask import Flask, request, jsonify, render_template_string, send_from_directory
from flask_cors import CORS

from jsonschema import validate as jsonschema_validate, ValidationError

from sift_specialists import SpecialistOrchestrator, SLEUTHKIT_Specialist, VOLATILITY_Specialist, STRINGS_Specialist
from sift_specialists_extended import ExtendedOrchestrator
from sift_specialists_remnux import REMNUX_Orchestrator
from geoff_critic import GeoffCritic, ValidationPipeline
from geoff_forensicator import ForensicatorAgent

# New modules for architecture pivot
from device_discovery import DeviceDiscovery
from host_correlator import HostCorrelator
from super_timeline import SuperTimeline
from narrative_report import NarrativeReportGenerator
from behavioral_analyzer import BehavioralAnalyzer

# ---------------------------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------------------------

# Shell metacharacters that could enable command injection via evidence paths
_UNSAFE_PATH_CHARS = re.compile(r'[;&|`$(){}[\]<>\\!\n\r\t]')


def _validate_evidence_path(path: str) -> str:
    """Validate an evidence path to prevent command injection and path traversal.

    Raises ValueError if the path contains shell metacharacters or resolves
    outside of allowed base directories.
    """
    if _UNSAFE_PATH_CHARS.search(path):
        raise ValueError(f"Evidence path contains unsafe characters and will not be processed: {path!r}")
    # Resolve real path to prevent traversal (e.g. ../../../etc/passwd)
    real_path = Path(os.path.realpath(path))
    allowed_bases = [Path(os.path.realpath(b)) for b in [EVIDENCE_BASE_DIR, CASES_WORK_DIR] if b]
    # Only enforce the base-dir check when at least one allowed base is configured.
    # Using relative_to() avoids the startswith() prefix-collision bug where
    # /mnt/evidence_real would slip past a base of /mnt/evidence.
    if allowed_bases:
        inside = False
        for base in allowed_bases:
            try:
                real_path.relative_to(base)
                inside = True
                break
            except ValueError:
                continue
        if not inside:
            raise ValueError(f"Evidence path resolves outside allowed directories: {path!r} → {real_path}")
    return path


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
    tmp = str(path) + '.tmp'
    try:
        with open(tmp, mode) as f:
            f.write(data)
        os.replace(tmp, str(path))
    except Exception as e:
        _log_error(f"atomic write failed for {path}", e)
        # Clean up temp file if it exists
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


MAX_STDOUT_SIZE = 50 * 1024 * 1024  # 50MB — prevent memory blowup from tool output

# Max findings to keep in-memory before logging a warning. Findings are always
# written to a JSONL file on disk; this limit only governs the in-memory list
# used for aggregation/reporting at the end of a job.
_MAX_IN_MEMORY_FINDINGS = int(os.environ.get("GEOFF_MAX_FINDINGS", "50000"))


class FindingsWriter:
    """Write step-record findings to a JSONL file as they complete.

    Keeps a compact in-memory index (step_key → status) for fast idempotency
    checks, avoiding the need to scan the full findings list on every step.
    The full finding dicts are flushed to disk immediately and optionally
    accumulated in memory up to *max_in_memory* entries.
    """

    def __init__(self, jsonl_path: Path, max_in_memory: int = _MAX_IN_MEMORY_FINDINGS, job_id: str = None):
        self._path = jsonl_path
        self._max = max_in_memory
        self._job_id = job_id
        self._index: dict = {}   # step_key -> status
        self._records: list = [] # in-memory accumulation (capped)
        self._lock = threading.Lock()
        # Ensure parent dir exists
        jsonl_path.parent.mkdir(parents=True, exist_ok=True)

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
        """Return all records. Falls back to disk when in-memory cap is exceeded."""
        with self._lock:
            if len(self._records) < self._max:
                return list(self._records)
        # Cap was hit — read all records from JSONL for complete results
        records = []
        try:
            if self._path.exists():
                with open(self._path, 'r') as fh:
                    for line in fh:
                        line = line.strip()
                        if line:
                            try:
                                records.append(json.loads(line))
                            except json.JSONDecodeError:
                                continue
        except OSError as e:
            print(f"[FindingsWriter] Failed to read JSONL {self._path}: {e}", flush=True)
            with self._lock:
                return list(self._records)
        return records

def _sanitize_path(path_str: str, allowed_base: str = "") -> str:
    """Sanitize file paths to prevent directory traversal attacks."""
    basename = os.path.basename(str(path_str))
    if allowed_base:
        resolved = os.path.realpath(os.path.join(allowed_base, basename))
        if not resolved.startswith(os.path.realpath(allowed_base)):
            return os.path.join(allowed_base, basename)  # Fallback to basename only
    return basename

def safe_run(cmd, timeout=300, **kwargs):
    """Wrapper for subprocess.run with default timeout. Always returns a dict.
    Truncates stdout at MAX_STDOUT_SIZE to prevent memory blowup."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, **kwargs)
        stdout = result.stdout
        truncated = False
        if len(stdout) > MAX_STDOUT_SIZE:
            # Truncate and dump full output to file
            dump_path = os.path.join(tempfile.gettempdir(), f"geoff_stdout_{uuid.uuid4().hex[:8]}.txt")
            with open(dump_path, "w") as f:
                f.write(stdout)
            stdout = stdout[:MAX_STDOUT_SIZE] + f"\n... TRUNCATED (full output at {dump_path})"
            truncated = True
        return {
            "code": result.returncode,
            "stdout": stdout,
            "stderr": result.stderr,
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
        print(f"[GEOFF] error: {log_msg}")
    if STRICT_MODE:
        if e:
            raise e
        else:
            raise RuntimeError(msg)


def _log_info(msg: str):
    """Info-level logger — not an error."""
    print(f"[GEOFF] {msg}")


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


# ---------------------------------------------------------------------------
# JSON Schema Enforcement for Investigation State
# ---------------------------------------------------------------------------

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
    jsonschema_validate(instance=state, schema=INVESTIGATION_SCHEMA)
    return True


# ---------------------------------------------------------------------------
# Directory Resolution & Configuration
# ---------------------------------------------------------------------------

def _resolve_dir(env_var, default_path, fallback_subdir):
    """Resolve a directory path, falling back to temp if default is not writable."""
    path = os.environ.get(env_var, default_path)
    try:
        Path(path).mkdir(parents=True, exist_ok=True)
        return path
    except (PermissionError, OSError):
        fallback = os.path.join(tempfile.gettempdir(), fallback_subdir)
        Path(fallback).mkdir(parents=True, exist_ok=True)
        print(f"[GEOFF] {env_var}: {path} not writable, using fallback: {fallback}")
        return fallback

EVIDENCE_BASE_DIR = _resolve_dir('GEOFF_EVIDENCE_PATH',
                               "/home/sansforensics/evidence-storage/evidence",
                               "geoff-evidence")
CASES_WORK_DIR = _resolve_dir('GEOFF_CASES_PATH',
                             "/home/sansforensics/evidence-storage/cases",
                             "geoff-cases")

# Active evidence directory for chat (set from web UI)
_active_evidence_dir: str = EVIDENCE_BASE_DIR

# ---------------------------------------------------------------------------
# Git Action Logger for Audit Trail
# ---------------------------------------------------------------------------

def git_commit_action(message: str, base_path: str = None):
    """Git commit for audit trail - now uses safe_git_commit wrapper."""
    if base_path is None:
        base_path = os.environ.get('GEOFF_GIT_DIR', CASES_WORK_DIR + '/git')

    if not os.path.isdir(base_path):
        return

    result = safe_git_commit(message, base_path)
    if result["status"] == "failed":
        _log_error(f"git commit action failed: {result.get('error', 'unknown')}")


class ActionLogger:
    """Logger for all Geoff actions with git integration"""

    def __init__(self, log_dir: str = None):
        if log_dir is None:
            log_dir = os.environ.get('GEOFF_LOGS_DIR', CASES_WORK_DIR + '/logs')
        self.log_dir = Path(log_dir)
        try:
            self.log_dir.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            _log_error("ActionLogger init mkdir", e)
            self.log_dir = Path(tempfile.gettempdir()) / 'geoff-logs'
            self.log_dir.mkdir(exist_ok=True)

        self.action_log = self.log_dir / f"actions_{datetime.now().strftime('%Y%m')}.jsonl"

    def log(self, action_type: str, details: dict, commit: bool = True):
        """Log an action with optional git commit"""
        entry = {
            'timestamp': datetime.now().isoformat(),
            'action_type': action_type,
            'details': details
        }

        # Atomic write for action log (with lock)
        try:
            log_content = json.dumps(entry) + '\n'
            with _log_lock:
                _atomic_append(self.action_log, log_content)
                # Log rotation: if file > 10MB, rotate
                try:
                    if os.path.exists(self.action_log) and os.path.getsize(self.action_log) > 10 * 1024 * 1024:
                        rotated = f"{self.action_log}.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                        os.rename(self.action_log, rotated)
                        _log_info(f"Log rotated: {rotated}")
                except Exception as rot_exc:
                    _log_info(f"action log rotation skipped: {rot_exc}")
        except Exception as e:
            _log_error(f"ActionLogger log write {self.action_log}", e)
            # Fallback to regular write
            try:
                with open(self.action_log, 'a') as f:
                    f.write(log_content)
            except Exception as e2:
                _log_error(f"ActionLogger fallback log write", e2)

        if commit:
            git_commit_action(f"{action_type}: {details.get('description', 'action')}")

        return entry


# Initialize global action logger
action_logger = ActionLogger()

# ---------------------------------------------------------------------------
# Flask App & Core Config
# ---------------------------------------------------------------------------

app = Flask(__name__)
CORS(app)

PORT = int(os.environ.get('GEOFF_PORT', 8080))

# Optional API key for protecting all non-UI endpoints.
# Set GEOFF_API_KEY in the environment or .env to enable authentication.
# When unset, auth is disabled (backwards-compatible default).
GEOFF_API_KEY = os.environ.get('GEOFF_API_KEY', '')


def _require_auth(f):
    """Decorator that enforces API key authentication when GEOFF_API_KEY is set.

    Accepts the key via:
      - X-API-Key: <key>  header
      - Authorization: Bearer <key>  header
    """
    @wraps(f)
    def _decorated(*args, **kwargs):
        if not GEOFF_API_KEY:
            return f(*args, **kwargs)
        provided = (
            request.headers.get('X-API-Key', '')
            or request.headers.get('Authorization', '').removeprefix('Bearer ').strip()
        )
        if not provided or not hmac.compare_digest(provided, GEOFF_API_KEY):
            return jsonify({'error': 'Unauthorized — provide a valid X-API-Key header'}), 401
        return f(*args, **kwargs)
    return _decorated


OLLAMA_URL = os.environ.get('OLLAMA_URL', "http://localhost:11434")
OLLAMA_API_KEY = os.environ.get('OLLAMA_API_KEY', '')

def ollama_headers():
    """Return headers for Ollama API requests.
    When OLLAMA_API_KEY is set, we call ollama.com/api directly (cloud models)
    and include Bearer auth. Otherwise, use local Ollama (which uses signin tokens).
    """
    h = {'Content-Type': 'application/json'}
    if OLLAMA_API_KEY:
        h['Authorization'] = f'Bearer {OLLAMA_API_KEY}'
    return h

def ollama_base_url():
    """Return the base URL for Ollama API calls.
    If OLLAMA_API_KEY is set, use ollama.com/api directly for cloud model access.
    Otherwise, use local Ollama (localhost:11434 or OLLAMA_URL).
    """
    if OLLAMA_API_KEY:
        return 'https://ollama.com/api'
    return OLLAMA_URL

# ---------------------------------------------------------------------------
# Model Profiles — cloud vs local
# ---------------------------------------------------------------------------
PROFILES_PATH = Path(__file__).parent.parent / "profiles.json"

def load_profile(profile_name: str) -> dict:
    """Load model profile from profiles.json.
    Env vars GEOFF_*_MODEL override profile settings.
    """
    try:
        with open(PROFILES_PATH) as f:
            profiles = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        # Fallback defaults if profiles.json missing
        profiles = {
            "cloud": {"manager": "deepseek-v3.2:cloud", "forensicator": "qwen3-coder-next:cloud", "critic": "qwen3.5:cloud"},
            "local": {"manager": "deepseek-r1:32b", "forensicator": "qwen2.5-coder:14b", "critic": "qwen2.5:14b"},
        }
    if profile_name not in profiles:
        print(f"[WARN] Unknown profile '{profile_name}', falling back to 'cloud'")
        profile_name = "cloud"
    return profiles[profile_name]

ACTIVE_PROFILE = os.environ.get('GEOFF_PROFILE', 'cloud')
_profile_models = load_profile(ACTIVE_PROFILE)

AGENT_MODELS = {
    "manager": os.environ.get('GEOFF_MANAGER_MODEL', _profile_models["manager"]),
    "forensicator": os.environ.get('GEOFF_FORENSICATOR_MODEL', _profile_models["forensicator"]),
    "critic": os.environ.get('GEOFF_CRITIC_MODEL', _profile_models["critic"]),
}

LLM_MODEL = AGENT_MODELS["manager"]

# ---------------------------------------------------------------------------
# Orchestrators
# ---------------------------------------------------------------------------

orchestrator = ExtendedOrchestrator(EVIDENCE_BASE_DIR)
remnux_orchestrator = REMNUX_Orchestrator()

# Initialize Critic for validation
geoff_critic = GeoffCritic(OLLAMA_URL, LLM_MODEL)
validation_pipeline = ValidationPipeline(orchestrator, geoff_critic)

# Initialize Forensicator for tool execution (multi-agent architecture)
geoff_forensicator = ForensicatorAgent(OLLAMA_URL)

# ---------------------------------------------------------------------------
# Find Evil Job Tracking (async)
# ---------------------------------------------------------------------------

_find_evil_jobs = {}  # job_id -> {status, progress, result, started_at, log, ...}



def _sanitize_tool_output(output: str) -> str:
    """Sanitize tool output to prevent JSON injection and control character issues."""
    if not isinstance(output, str):
        return str(output)
    # Remove null bytes
    output = output.replace("\x00", "")
    # Remove other control characters except newline/tab
    output = "".join(c for c in output if c in "\n\t" or (ord(c) >= 32 and ord(c) < 127) or ord(c) >= 128)
    return output



import signal

class _StepTimeout(Exception):
    """Raised when a step exceeds its watchdog timeout."""
    pass

def _run_step_with_watchdog(func, args, step_timeout=600):
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



MAX_STATE_FIELD_SIZE = 100 * 1024  # 100KB max for any single field in state

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

def _run_step_via_orchestrator(module: str, function: str, params: dict) -> dict:
    """Route a step to the correct orchestrator based on module prefix.

    Steps whose module is 'remnux' (or starts with 'remnux_') go to the
    REMnux orchestrator; everything else goes to the extended SIFT orchestrator.
    
    Includes self-healing: catches known error patterns and auto-corrects.
    """
    # Self-healing: SleuthKit metadata errors
    if module == "sleuthkit" and function in ["list_files", "analyze_filesystem", "list_deleted"]:
        image_path = params.get("image") or params.get("disk_image")
        offset = params.get("offset")
        
        if image_path:
            # Try execution with current params
            step = {"module": module, "function": function, "params": params}
            result = orchestrator.run_playbook_step("find-evil", step)
            
            # Check for metadata/MFT errors that need auto-correction
            if result.get("status") == "error":
                stderr = result.get("stderr", "").lower()
                error_patterns = [
                    "dinode_lookup", "update sequence", "metadata structure",
                    "mft size", "mft entry", "cannot determine file system type",
                    "error in metadata structure", "bad magic", "invalid superblock"
                ]
                
                if any(pat in stderr for pat in error_patterns):
                    _fe_log("system", f"[SELF-HEAL] Detected metadata error for {Path(image_path).name}: {stderr[:100]}")
                    
                    # Heal attempt 1: Auto-detect partition and retry with correct offset
                    try:
                        sk = SLEUTHKIT_Specialist(evidence_path=image_path)
                        mmls_result = sk.analyze_partition_table(image_path)
                        
                        if mmls_result.get("status") == "success" and mmls_result.get("partitions"):
                            # Find best partition (NTFS/ext with data)
                            best_part = None
                            for part in mmls_result["partitions"]:
                                desc = part.get("description", "").lower()
                                if any(fs in desc for fs in ["ntfs", "ext", "fat", "hfs"]):
                                    best_part = part
                                    break
                            
                            if best_part and best_part.get("start_sector"):
                                new_offset = best_part["start_sector"]
                                if new_offset != offset:
                                    _fe_log("system", f"[SELF-HEAL] Retrying {function} with auto-detected offset {new_offset}")
                                    
                                    healed_params = dict(params)
                                    healed_params["offset"] = new_offset
                                    step = {"module": module, "function": function, "params": healed_params}
                                    healed_result = orchestrator.run_playbook_step("find-evil", step)
                                    
                                    if healed_result.get("status") == "success":
                                        healed_result["_self_healed"] = True
                                        healed_result["_original_error"] = stderr[:200]
                                        healed_result["_healing_method"] = f"auto_partition_offset_{new_offset}"
                                        return healed_result
                                    
                                    # Heal attempt 2: Try without offset (direct disk access)
                                    _fe_log("system", f"[SELF-HEAL] Retrying {function} without partition offset")
                                    no_offset_params = {k: v for k, v in params.items() if k != "offset"}
                                    step = {"module": module, "function": function, "params": no_offset_params}
                                    direct_result = orchestrator.run_playbook_step("find-evil", step)
                                    
                                    if direct_result.get("status") == "success":
                                        direct_result["_self_healed"] = True
                                        direct_result["_original_error"] = stderr[:200]
                                        direct_result["_healing_method"] = "direct_disk_no_offset"
                                        return direct_result
                                    
                                    # Heal attempt 3: Try with -f ntfs override
                                    _fe_log("system", f"[SELF-HEAL] Retrying {function} with NTFS filesystem override")
                                    fs_params = dict(params)
                                    fs_params["offset"] = new_offset
                                    # Note: This requires specialist to support fs_type param
                                    step = {"module": module, "function": function, "params": fs_params}
                                    # Inject fs_type via a wrapper if needed
                                    fs_result = orchestrator.run_playbook_step("find-evil", step)
                                    
                                    if fs_result.get("status") == "success":
                                        fs_result["_self_healed"] = True
                                        fs_result["_original_error"] = stderr[:200]
                                        fs_result["_healing_method"] = "ntfs_fs_override"
                                        return fs_result
                    
                    except Exception as heal_err:
                        _fe_log("system", f"[SELF-HEAL] Healing failed: {heal_err}")
                    
                    # All healing attempts failed - mark result with healing info
                    result["_self_healing_attempted"] = True
                    result["_self_healing_failed"] = True
            
            return result
    
    # Standard routing
    if module == "remnux" or module.startswith("remnux_"):
        step = {"function": function, "params": params}
        return remnux_orchestrator.run_playbook_step("find-evil", step)
    else:
        step = {"module": module, "function": function, "params": params}
        return orchestrator.run_playbook_step("find-evil", step)


# ---------------------------------------------------------------------------
# LLM & Tool Detection
# ---------------------------------------------------------------------------

GEOFF_PROMPT = """You are G.E.O.F.F. (Git-backed Evidence Operations Forensic Framework), a professional digital forensics investigation system.

Your role is to conduct thorough, systematic forensic analysis using established methodologies and the complete SIFT toolkit.

**Available Forensic Capabilities:**

*Disk Forensics (SleuthKit):* Partition analysis, filesystem statistics, file listing/extraction, inode analysis

*Memory Forensics (Volatility):* Process enumeration, network connections, malware detection, registry analysis, memory dumping

*IOC Extraction:* String analysis, URL/IP/email extraction, registry artifact identification

*Windows Registry Analysis (RegRipper):* Hive parsing, execution history, folder access, USB device tracking, persistence mechanisms, service enumeration

*Timeline Analysis (Plaso):* Temporal event reconstruction, super timeline generation

*Network Forensics:* PCAP analysis, flow reconstruction, protocol extraction

*Log Analysis:* Windows Event Log parsing, authentication analysis, syslog examination

*Mobile Forensics:* iOS backup analysis, Android data extraction

*REMnux Malware Analysis:* Static/dynamic analysis, binary identification, unpacking, disassembly, AV scanning

**Analytical Reasoning Protocol:**
When answering a forensic question, structure your reasoning as:
1. **Hypothesis** — State what you are testing (e.g., "Testing whether persistence was established via registry Run key")
2. **Evidence** — Cite the specific artifact, tool result, file path, offset, or log entry that supports or refutes the hypothesis
3. **Assessment** — State your conclusion with confidence level ("confirmed", "likely", "possible", "no evidence")
Do not provide a raw data dump. Every claim must be traceable to a named artifact.

**Accuracy Requirements:**
- Only assert findings that are directly evidenced by a specific artifact you can name
- When citing a finding, always include: source file, tool used, and the specific field/value observed
- Use "appears to", "consistent with", or "no evidence of" for inferences vs. confirmed facts
- If the available context does not contain the answer, say explicitly: "The current evidence does not support a conclusion on this"

**Operational Protocol:**
- Respond with clear, technical accuracy
- When instructed to investigate, execute systematically without unnecessary clarification
- Report findings with supporting evidence
- Maintain chain of custody through git-backed validation
- Cite specific tools and artifacts examined

**Response Standards:**
- Professional, objective tone
- Evidence-based conclusions with explicit artifact citations
- Clear identification of IOCs and suspicious activity with source references
- Structured investigative narrative suitable for legal documentation (not a raw execution log)"""


def call_llm(user_message, context="", agent_type="manager"):
    """Call LLM via Ollama (local or remote)

    agent_type: "manager", "forensicator", or "critic" - determines which model to use
    """
    try:
        model = AGENT_MODELS.get(agent_type, AGENT_MODELS["manager"])

        full_prompt = f"{GEOFF_PROMPT}\n\n{context}\n\nUser: {user_message}\n\nGeoff:"
        response = requests.post(
            f"{ollama_base_url()}/generate",
            headers=ollama_headers(),
            json={
                "model": model,
                "prompt": full_prompt,
                "stream": False,
                "options": {"temperature": 0.3}
            },
            timeout=120
        )
        if response.status_code == 200:
            return response.json().get('response', 'Hmm, let me check that again.')
        else:
            return f"[ERROR] Ollama returned {response.status_code}: {response.text[:200]}"
    except Exception as e:
        print(f"[GEOFF] LLM Error: {e}")
        if STRICT_MODE:
            raise
        return "Having trouble connecting to Ollama. Check OLLAMA_URL setting and ensure Ollama is running."


def _call_manager_llm(prompt: str, timeout: int = 90) -> str:
    """Raw LLM call using Manager model — no GEOFF_PROMPT wrapping."""
    try:
        model = AGENT_MODELS.get("manager", AGENT_MODELS.get("default", ""))
        response = requests.post(
            f"{ollama_base_url()}/generate",
            headers=ollama_headers(),
            json={"model": model, "prompt": prompt, "stream": False,
                  "options": {"temperature": 0.1}},
            timeout=timeout,
        )
        if response.status_code == 200:
            return response.json().get("response", "")
    except Exception as e:
        print(f"[MANAGER] LLM error: {e}")
    return ""


def _manager_review_execution_plan(
    proposed_plan: list, skipped: list, inventory: dict,
    triage_findings: list, indicator_hits: list, os_type: str,
    classification: str, severity: str, job_id: str,
) -> list:
    """
    Manager LLM reviews the proposed execution plan and may reorder or amend it.
    Falls back to the proposed plan if the LLM is unavailable or returns garbage.
    """
    valid_ids = set(PLAYBOOK_STEPS.keys())
    mandatory = ["PB-SIFT-001", "PB-SIFT-002", "PB-SIFT-003", "PB-SIFT-004", "PB-SIFT-005"]

    ev_summary = {k: len(v) if isinstance(v, list) else v for k, v in inventory.items()}
    raw_categories = sorted({h.get("category", "") for h in indicator_hits if isinstance(h, dict)})[:10]

    # Sanitize values interpolated into the LLM prompt
    safe_os = str(os_type).replace("\n", " ").replace("\r", " ")[:100]
    safe_classification = str(classification).replace("\n", " ").replace("\r", " ")[:100]
    safe_severity = str(severity).replace("\n", " ").replace("\r", " ")[:50]
    hit_categories = [str(c).replace("\n", " ").replace("\r", " ")[:100] for c in raw_categories]

    prompt = f"""You are the Manager agent for a DFIR investigation. Review and optimise the execution plan.

CASE CONTEXT:
- OS: {safe_os}
- Initial classification: {safe_classification}
- Severity: {safe_severity}
- Evidence counts: {json.dumps(ev_summary)}
- Indicator categories from triage: {hit_categories}

PROPOSED EXECUTION PLAN (in order):
{json.dumps(proposed_plan)}

AVAILABLE PLAYBOOK IDs:
{json.dumps(sorted(valid_ids))}

SKIPPED (with reasons):
{json.dumps([s['id'] for s in skipped])}

Your task: return an optimised execution plan. You may reorder playbooks to address the most critical threat vectors first, remove clearly irrelevant ones, or re-include skipped ones if warranted.
Rules: {', '.join(mandatory)} are mandatory and must be present.

Respond ONLY in valid JSON (no extra text):
{{
    "approved_execution_plan": ["PB-SIFT-001", "PB-SIFT-002"],
    "reasoning": "one sentence explaining the key prioritisation decision"
}}"""

    _fe_log(job_id, "▶ Manager: reviewing execution plan…")
    raw = _call_manager_llm(prompt)
    try:
        m = re.search(r'\{.*\}', raw, re.DOTALL)
        if m:
            parsed = json.loads(m.group())
            candidate = parsed.get("approved_execution_plan", [])
            reasoning = parsed.get("reasoning", "")
            validated = [pb for pb in candidate if pb in valid_ids]
            # Guarantee mandatory playbooks are present in order
            for pb in mandatory:
                if pb in valid_ids and pb not in validated:
                    validated.insert(mandatory.index(pb), pb)
            if validated:
                _fe_log(job_id, f"  ✓ Manager approved {len(validated)}-playbook plan: {reasoning}")
                return validated
    except Exception as e:
        _fe_log(job_id, f"  ⚠ Manager plan parse error ({e}) — using proposed plan")

    _fe_log(job_id, f"  ⚠ Manager LLM unavailable — using proposed plan ({len(proposed_plan)} playbooks)")
    return proposed_plan


def _manager_generate_correction(
    module: str, function: str, result: dict,
    forensicator_notes: dict, critic_issues: list,
) -> dict:
    """
    Self-correction: Manager generates a revised analysis when Critic rejects the original.
    Returns dict with corrected analyst_note, threat_indicators, and correction_reasoning.
    Returns {} if LLM is unavailable.
    """
    result_summary = json.dumps(result, default=str)[:2000]
    issues_text = "; ".join(str(i) for i in critic_issues[:5]) if critic_issues else "sanity check failed"
    original_note = forensicator_notes.get("analyst_note") or "(none)"
    indicators = forensicator_notes.get("threat_indicators") or []

    prompt = f"""You are the Manager agent in a DFIR investigation. The Critic rejected a forensic analysis step.

STEP: {module}.{function}
TOOL RESULT (excerpt):
{result_summary}

ORIGINAL ANALYSIS: {original_note}
ORIGINAL INDICATORS: {indicators}

CRITIC ISSUES: {issues_text}

Generate a corrected analysis that:
1. Only claims what is directly supported by the tool result excerpt above
2. Does not invent file names, offsets, paths, or timestamps not present in the output
3. Uses precise language: "output contains X" not "likely Y"
4. Cites the specific artifact or field in the tool output for each claim

Respond ONLY in valid JSON (no extra text):
{{
    "analyst_note": "one precise sentence citing what the tool output actually shows",
    "threat_indicators": ["indicators directly evidenced in the output, or empty list"],
    "correction_reasoning": "brief explanation of what was wrong and what was corrected"
}}"""

    try:
        response = _call_manager_llm(prompt, timeout=60)
        m = re.search(r'\{.*\}', response, re.DOTALL)
        if m:
            return json.loads(m.group())
    except Exception as e:
        print(f"[MANAGER] Correction generation failed for {module}.{function}: {e}")
    return {}


def _self_check_chat_response(user_msg: str, context: str, response: str) -> str:
    """
    Self-correction for chat: verifies the response is grounded in available context.
    If unsupported claims are detected, regenerates once with an explicit correction prompt.
    Returns the original response if the LLM is unavailable or the response is short.
    """
    if len(response) < 80 or len(context) < 30:
        return response

    check_prompt = f"""You are a forensic accuracy reviewer. Determine whether this response makes claims NOT supported by the context.

CONTEXT:
{context[:3000]}

USER QUESTION: {user_msg[:500]}

RESPONSE TO CHECK:
{response[:2000]}

Does the response invent file names, tool outputs, findings, paths, or timestamps that are NOT present in the context above?

Respond ONLY in valid JSON:
{{"grounded": true, "issues": []}}
or
{{"grounded": false, "issues": ["list specific unsupported claims"]}}"""

    try:
        # Cloud models need longer timeout
        is_cloud = ":cloud" in AGENT_MODELS.get("manager", "") or ollama_base_url().startswith("https://")
        check_timeout = 90 if is_cloud else 30
        check_raw = _call_manager_llm(check_prompt, timeout=check_timeout)
        m = re.search(r'\{.*\}', check_raw, re.DOTALL)
        if not m:
            return response
        check_result = json.loads(m.group())
        if check_result.get("grounded", True):
            return response
        issues = check_result.get("issues") or []
        if not issues:
            return response

        # Regenerate with correction prompt
        correction_prompt = (
            f"{GEOFF_PROMPT}\n\n{context}\n\n"
            f"User: {user_msg}\n\n"
            f"Note: A prior draft response contained these accuracy issues: "
            f"{'; '.join(str(i) for i in issues[:3])}. "
            f"Provide a corrected response that only references evidence present in the context above. "
            f"If the context does not contain sufficient information, say so explicitly.\n\nGeoff:"
        )
        corrected = _call_manager_llm(correction_prompt, timeout=90)
        return corrected if corrected.strip() else response
    except Exception as corr_exc:
        _log_info(f"chat self-correction skipped: {corr_exc}")
        return response


def _extract_path_from_message(msg: str) -> str:
    """Extract a filesystem path from a chat message."""
    match = re.search(r'(/[a-zA-Z0-9._/-]+)', msg)
    if match:
        candidate = match.group(1)
        if os.path.exists(candidate):
            return candidate
    return ""


def detect_tool_request(message: str) -> dict:
    """Detect if user is asking to run a forensic tool - 100% coverage"""
    message_lower = message.lower()

    # SleuthKit patterns
    if any(word in message_lower for word in ['mmls', 'partition table', 'partition layout']):
        return {'module': 'sleuthkit', 'function': 'analyze_partition_table', 'params': {}}

    if any(word in message_lower for word in ['fsstat', 'filesystem', 'file system stats']):
        return {'module': 'sleuthkit', 'function': 'analyze_filesystem', 'params': {}}

    if any(word in message_lower for word in ['fls', 'list files', 'show files', 'directory listing']):
        return {'module': 'sleuthkit', 'function': 'list_files', 'params': {'recursive': True}}

    if any(word in message_lower for word in ['icat', 'extract file', 'get file']):
        return {'module': 'sleuthkit', 'function': 'extract_file', 'params': {}}

    if any(word in message_lower for word in ['istat', 'file info', 'inode details']):
        return {'module': 'sleuthkit', 'function': 'get_file_info', 'params': {}}

    if any(word in message_lower for word in ['ils', 'list inodes']):
        return {'module': 'sleuthkit', 'function': 'list_inodes', 'params': {}}

    # Volatility patterns
    if any(word in message_lower for word in ['volatility', 'memory dump', 'process list', 'pslist']):
        return {'module': 'volatility', 'function': 'process_list', 'params': {}}

    if any(word in message_lower for word in ['netscan', 'network connections', 'connections']):
        return {'module': 'volatility', 'function': 'network_scan', 'params': {}}

    if any(word in message_lower for word in ['malfind', 'malware', 'injected code']):
        return {'module': 'volatility', 'function': 'find_malware', 'params': {}}

    if any(word in message_lower for word in ['dump process', 'proc dump']):
        return {'module': 'volatility', 'function': 'dump_process', 'params': {}}

    # Strings patterns
    if any(word in message_lower for word in ['strings', 'extract strings', 'find iocs']):
        return {'module': 'strings', 'function': 'extract_strings', 'params': {}}

    # Registry patterns
    if any(word in message_lower for word in ['registry', 'regripper', 'hive']):
        return {'module': 'registry', 'function': 'parse_hive', 'params': {}}

    if any(word in message_lower for word in ['userassist', 'program execution']):
        return {'module': 'registry', 'function': 'extract_user_assist', 'params': {}}

    if any(word in message_lower for word in ['shellbags', 'folder access']):
        return {'module': 'registry', 'function': 'extract_shellbags', 'params': {}}

    if any(word in message_lower for word in ['usb devices', 'usbstor']):
        return {'module': 'registry', 'function': 'extract_usb_devices', 'params': {}}

    if any(word in message_lower for word in ['autoruns', 'run keys']):
        return {'module': 'registry', 'function': 'extract_autoruns', 'params': {}}

    if any(word in message_lower for word in ['services', 'service config']):
        return {'module': 'registry', 'function': 'extract_services', 'params': {}}

    if any(word in message_lower for word in ['mounted devices']):
        return {'module': 'registry', 'function': 'extract_mounted_devices', 'params': {}}

    # Timeline/Plaso patterns
    if any(word in message_lower for word in ['timeline', 'log2timeline', 'plaso']):
        return {'module': 'plaso', 'function': 'create_timeline', 'params': {}}

    if any(word in message_lower for word in ['sort timeline', 'psort']):
        return {'module': 'plaso', 'function': 'sort_timeline', 'params': {}}

    # Network patterns
    if any(word in message_lower for word in ['pcap', 'network capture', 'packet']):
        return {'module': 'network', 'function': 'analyze_pcap', 'params': {}}

    if any(word in message_lower for word in ['tcpflow', 'extract flows']):
        return {'module': 'network', 'function': 'extract_flows', 'params': {}}

    if any(word in message_lower for word in ['http extract', 'web traffic']):
        return {'module': 'network', 'function': 'extract_http', 'params': {}}

    # Log patterns
    if any(word in message_lower for word in ['evtx', 'windows event log']):
        return {'module': 'logs', 'function': 'parse_evtx', 'params': {}}

    if any(word in message_lower for word in ['syslog', 'linux log']):
        return {'module': 'logs', 'function': 'parse_syslog', 'params': {}}

    # Mobile patterns
    if any(word in message_lower for word in ['ios', 'iphone', 'ipad']):
        return {'module': 'mobile', 'function': 'analyze_ios_backup', 'params': {}}

    if any(word in message_lower for word in ['android', 'mobile']):
        return {'module': 'mobile', 'function': 'analyze_android', 'params': {}}

    # REMnux patterns
    if any(word in message_lower for word in ['remnux', 'die scan', 'detect it easy']):
        return {'module': 'remnux', 'function': 'die_scan', 'params': {}}

    if any(word in message_lower for word in ['exiftool', 'metadata']):
        return {'module': 'remnux', 'function': 'exiftool_scan', 'params': {}}

    if any(word in message_lower for word in ['clamav', 'clam scan']):
        return {'module': 'remnux', 'function': 'clamav_scan', 'params': {}}

    if any(word in message_lower for word in ['radare2', 'disassem', 'r2 ']):
        return {'module': 'remnux', 'function': 'radare2_analyze', 'params': {}}

    if any(word in message_lower for word in ['floss', 'obfuscated strings']):
        return {'module': 'remnux', 'function': 'floss_strings', 'params': {}}

    if any(word in message_lower for word in ['pdfid', 'pdf scan']):
        return {'module': 'remnux', 'function': 'pdfid_scan', 'params': {}}

    if any(word in message_lower for word in ['oledump', 'ole analysis']):
        return {'module': 'remnux', 'function': 'oledump_scan', 'params': {}}

    if any(word in message_lower for word in ['upx', 'unpack']):
        return {'module': 'remnux', 'function': 'upx_unpack', 'params': {}}

    # Investigation trigger - full playbook execution
    if any(word in message_lower for word in ['investigate', 'full analysis', 'run playbooks', 'systematic analysis']):
        return {'module': 'orchestrator', 'function': 'run_full_investigation', 'params': {}}

    return None


# ---------------------------------------------------------------------------
# Full Investigation (background worker)
# ---------------------------------------------------------------------------

def run_full_investigation(case_name: str, evidence_path: str = None):
    """Spawn background investigation worker for case with timestamped directory"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    case_work_dir = f"{case_name}_{timestamp}"
    case_work_path = Path(CASES_WORK_DIR) / case_work_dir
    try:
        case_work_path.mkdir(parents=True, exist_ok=True)
    except (PermissionError, OSError):
        case_work_path = Path(tempfile.gettempdir()) / "geoff-cases" / case_work_dir
        case_work_path.mkdir(parents=True, exist_ok=True)
        print(f"[GEOFF] Case work dir fallback: {case_work_path}")

    # Initialize git repo
    git_dir = case_work_path / ".git"
    if not git_dir.exists():
        safe_run(['git', 'init'], cwd=case_work_path, timeout=30)
        safe_run(['git', 'config', 'user.email', 'geoff@dfir.local'], cwd=case_work_path, timeout=10)
        safe_run(['git', 'config', 'user.name', 'Geoff DFIR'], cwd=case_work_path, timeout=10)
        safe_run(['git', 'config', '--local', 'safe.directory', str(case_work_path)], cwd=case_work_path, timeout=10)

    # Create subdirectories
    (case_work_path / "logs").mkdir(exist_ok=True)
    (case_work_path / "output").mkdir(exist_ok=True)
    (case_work_path / "reports").mkdir(exist_ok=True)
    (case_work_path / "timeline").mkdir(exist_ok=True)

    # Spawn find_evil pipeline in a background thread
    fe_job_id = f"inv-{case_name}-{uuid.uuid4().hex[:8]}"
    with _state_lock:
        _find_evil_jobs[fe_job_id] = {
            "status": "starting",
            "case_name": case_name,
            "evidence_path": evidence_path,
            "work_dir": str(case_work_path),
            "started_at": datetime.now().isoformat(),
            "progress_pct": 0,
        }

    def _run_find_evil_bg():
        try:
            find_evil(evidence_path, job_id=fe_job_id)
        except Exception as e:
            with _state_lock:
                _find_evil_jobs[fe_job_id]["status"] = "error"
                _find_evil_jobs[fe_job_id]["error"] = str(e)

    bg_thread = threading.Thread(target=_run_find_evil_bg, daemon=True)
    bg_thread.start()

    return {
        "status": "started",
        "case": case_name,
        "work_directory": str(case_work_path),
        "job_id": fe_job_id,
        "message": f"Investigation initiated for case: {case_name}",
        "find_evil_status": f"/find-evil/status/{fe_job_id}",
        "note": "Background investigation running via find_evil pipeline"
    }


# ---------------------------------------------------------------------------
# Evidence Helpers
# ---------------------------------------------------------------------------

def get_evidence_recursive(path, prefix=""):
    """Recursively get all files and folders"""
    items = []
    try:
        for item in sorted(os.listdir(path)):
            item_path = os.path.join(path, item)
            display_name = f"{prefix}{item}"
            if os.path.isdir(item_path):
                items.append(f"[DIR] {display_name}/")
                items.extend(get_evidence_recursive(item_path, f"{display_name}/"))
            else:
                size = os.path.getsize(item_path)
                items.append(f"{display_name} ({size} bytes)")
    except Exception as e:
        print(f"[GEOFF] Error reading evidence directory: {e}")
    return items


def get_all_cases():
    """Get ALL cases with ALL contents"""
    cases = {}
    if not os.path.exists(EVIDENCE_BASE_DIR):
        return cases
    try:
        for case_name in sorted(os.listdir(EVIDENCE_BASE_DIR)):
            case_path = os.path.join(EVIDENCE_BASE_DIR, case_name)
            if os.path.isdir(case_path):
                cases[case_name] = get_evidence_recursive(case_path)
    except Exception as e:
        print(f"Error reading cases: {e}")
    return cases


def get_available_tools_status():
    """Get status of all forensic tools"""
    return orchestrator.get_available_tools()


# ---------------------------------------------------------------------------
# Find Evil — Triage-driven playbook orchestration
# ---------------------------------------------------------------------------

# All 19 SIFT playbook IDs — always run, never cherry-pick
PLAYBOOK_NAMES = {
    "PB-SIFT-000": "Triage & Execution Planning",
    "PB-SIFT-001": "Initial Access",
    "PB-SIFT-002": "Execution",
    "PB-SIFT-003": "Persistence",
    "PB-SIFT-004": "Privilege Escalation",
    "PB-SIFT-005": "Credential Theft",
    "PB-SIFT-006": "Lateral Movement",
    "PB-SIFT-007": "Exfiltration",
    "PB-SIFT-008": "Malware Hunting",
    "PB-SIFT-009": "Ransomware",
    "PB-SIFT-010": "Living-off-the-Land",
    "PB-SIFT-011": "Web Shell",
    "PB-SIFT-012": "Anti-Forensics",
    "PB-SIFT-013": "Insider Threat",
    "PB-SIFT-014": "Linux Forensics",
    "PB-SIFT-015": "Data Staging",
    "PB-SIFT-016": "Cross-Image Correlation",
    "PB-SIFT-017": "REMnux Malware Analysis",
    "PB-SIFT-018": "Malware Analysis",
    "PB-SIFT-019": "Command & Control",
    "PB-SIFT-020": "Timeline Analysis",
    "PB-SIFT-021": "Mobile Analysis",
    "PB-SIFT-022": "Browser Forensics",
    "PB-SIFT-023": "Email Forensics",
    "PB-SIFT-024": "macOS Forensics",
}

# Triage indicators for severity classification (used for reporting, NOT for
# playbook selection — all playbooks always run regardless)
TRIAGE_PATTERNS = {
    "ransomware": [".locked", ".encrypted", ".crypt", "readme_decrypt", "how_to_decrypt",
                   "recover_files", ".locky", ".cerber", ".sage", ".globe",
                   "your_files_are", "ransom_note", "decrypt_instructions",
                   "vssadmin delete", "wbadmin delete", "bcdedit /set",
                   "wipe_mbr", "destroy_vss", "epmntdrv", "hermetic"],
    "credential_theft": ["mimikatz", "lsass", "ntds.dit", "procdump", "hashdump",
                         "creddump", "cachedump", "secretsdump", "dcsync",
                         "kerberoast", "asrep_roast", "golden ticket", "rubeus",
                         "invoke-kerberoast"],
    "lateral_movement": ["psexec", "wmic", "winrm", "sharpexec", "remcom",
                         "paexec", "cmbexec", "dcom", "atexec",
                         "nsenter", "container_escape", "docker.sock",
                         "chroot /host", "privileged_container", "pivot_root"],
    "persistence": ["autorun", "run_once", "scheduled_task", "startup",
                    "wmi_subscription", "com_hijack", "shell:",
                    "uefi", "bootkit", "flashrom", "spi_flash",
                    "survive_reinstall", "uefi_dxe", "dxe_driver"],
    "exfiltration": ["megasync", "dropbox", "onedrive", "googledrive",
                    "rsync", "scp", "sftp", "ftp_upload", "exfil",
                    "inbox_rule", "forward_to", "forwardingrule", "mailforward",
                    "s3 sync", "attacker-exfil"],
    "anti_forensics": ["eventlog_clear", "wevtutil cl", "log clear",
                      "timestomp", "timemodify", "ccleaner", "bleachbit",
                      "shred", "history -c", "drop table", "drop database",
                      "dd if=/dev/urandom", "wipe_free_space"],
    "web_shell": ["c99", "r57", "wso", "b374k", "alfa", "cmd=", "exec=",
                  "shell=", "eval(", "base64_decode", "webshell",
                  "xp_cmdshell", "sqlmap", "union select", "proxylogon"],
    "lolbin": ["certutil", "bitsadmin", "mshta", "rundll32", "regsvr32",
               "wmic", "msbuild", "installutil", "msiexec"],
    "c2": ["cobalt strike", "beacon", "covenant", "sliver", "poshc2", "empire",
            "cobaltstrike", "teamserver", "metasploit", "reverse_shell",
            ".onion", "stratum+tcp://"],
    "cryptominer": ["xmrig", "minexmr", "xmrpool", "moneroocean", "supportxmr",
                    "stratum+tcp", "cryptonight", "randomx", "monero", "coinhive",
                    "minergate", "nicehash", "pool.minexmr"],
    "rootkit": ["rootkit", "sys_call_table", "syscall_hook", "hooking",
                "hide_pid", "hide_port", "process_hide", "module_hide",
                "lkm", "kthreadd_helper", "insmod", "kernel_module",
                "LD_PRELOAD", "__intercepted_"],
    "ot_attack": ["modbus", "scada", "plc_attack", "safety_bypass", "sis_bypass",
                  "setpoint_override", "industroyer", "ot_sabotage",
                  "scada_exploit", "industrial_control", "dnp3", "iec-61850"],
}

SEVERITY_MAP = {
    "ransomware": "CRITICAL",
    "credential_theft": "HIGH",
    "lateral_movement": "HIGH",
    "persistence": "HIGH",
    "exfiltration": "HIGH",
    "anti_forensics": "HIGH",
    "web_shell": "HIGH",
    "lolbin": "MEDIUM",
    "c2": "CRITICAL",
    "cryptominer": "HIGH",
    "rootkit": "CRITICAL",
    "ot_attack": "CRITICAL",
}

# MITRE ATT&CK technique IDs per indicator category (Enterprise ATT&CK v14).
MITRE_TAGS = {
    "ransomware":        ["T1486", "T1490", "T1489"],
    "credential_theft":  ["T1003", "T1558", "T1552"],
    "lateral_movement":  ["T1021", "T1570", "T1563"],
    "persistence":       ["T1053", "T1547", "T1543", "T1542"],
    "exfiltration":      ["T1048", "T1567", "T1020"],
    "anti_forensics":    ["T1070", "T1485", "T1027"],
    "web_shell":         ["T1505.003", "T1190"],
    "lolbin":            ["T1218", "T1059", "T1053"],
    "c2":                ["T1071", "T1095", "T1573"],
    "cryptominer":       ["T1496"],
    "rootkit":           ["T1014", "T1543.003"],
    "ot_attack":         ["T0855", "T0816", "T0879"],
}

# Map each playbook to its specialist steps.
# Steps that require evidence types not present will be skipped at runtime
# (tool-missing check), but the playbook itself always "runs" (even if all
# steps are skipped).
PLAYBOOK_STEPS = {
    "PB-SIFT-000": {  # Triage & Execution Planning (always runs first)
        "memory_dumps": [
            ("volatility", "process_list", {"memory_dump": "{mem}"}),
            ("volatility", "network_scan", {"memory_dump": "{mem}"}),
            ("volatility", "find_malware", {"memory_dump": "{mem}"}),
        ],
    },
    "PB-SIFT-001": {  # Initial Access
        "pcaps": [
            ("network", "analyze_pcap", {"pcap_file": "{pcap}"}),
            ("network", "extract_http", {"pcap_file": "{pcap}"}),
        ],
        "evtx_logs": [
            ("logs", "parse_evtx", {"evtx_file": "{evtx}"}),
        ],
        "disk_images": [
            ("sleuthkit", "list_files", {"image": "{image}", "offset": "{offset}", "recursive": True}),
        ],
    },
    "PB-SIFT-002": {  # Execution
        "memory_dumps": [
            ("volatility", "process_list", {"memory_dump": "{mem}"}),
            ("volatility", "find_malware", {"memory_dump": "{mem}"}),
        ],
        "disk_images": [
            ("sleuthkit", "list_files", {"image": "{image}", "offset": "{offset}", "recursive": True}),
        ],
    },
    "PB-SIFT-003": {  # Persistence
        "registry_hives": [
            ("registry", "extract_autoruns", {"software_path": "{hive}"}),
            ("registry", "extract_services", {"system_path": "{hive}"}),
            ("registry", "extract_user_assist", {"ntuser_path": "{hive}"}),
            ("registry", "extract_shellbags", {"ntuser_path": "{hive}"}),
        ],
        "disk_images": [
            ("sleuthkit", "list_files", {"image": "{image}", "offset": "{offset}", "recursive": True}),
            ("jumplist", "parse_lnk_files", {"directory": "{image}"}),
        ],
        "memory_dumps": [
            ("volatility", "process_list", {"memory_dump": "{mem}"}),
        ],
    },
    "PB-SIFT-004": {  # Privilege Escalation
        "memory_dumps": [
            ("volatility", "process_list", {"memory_dump": "{mem}"}),
            ("volatility", "find_malware", {"memory_dump": "{mem}"}),
        ],
        "disk_images": [
            ("sleuthkit", "list_files", {"image": "{image}", "offset": "{offset}", "recursive": True}),
        ],
        "registry_hives": [
            ("registry", "extract_autoruns", {"software_path": "{hive}"}),
        ],
    },
    "PB-SIFT-005": {  # Credential Theft
        "memory_dumps": [
            ("volatility", "process_list", {"memory_dump": "{mem}"}),
            ("volatility", "find_malware", {"memory_dump": "{mem}"}),
        ],
        "disk_images": [
            ("sleuthkit", "analyze_filesystem", {"image": "{image}", "offset": "{offset}"}),
        ],
        "registry_hives": [
            ("registry", "parse_hive", {"hive_path": "{hive}"}),
        ],
    },
    "PB-SIFT-006": {  # Lateral Movement
        "pcaps": [
            ("network", "analyze_pcap", {"pcap_file": "{pcap}"}),
            ("network", "extract_flows", {"pcap_file": "{pcap}", "output_dir": "{output_dir}/flows"}),
        ],
        "evtx_logs": [
            ("logs", "parse_evtx", {"evtx_file": "{evtx}"}),
        ],
        "memory_dumps": [
            ("volatility", "network_scan", {"memory_dump": "{mem}"}),
        ],
    },
    "PB-SIFT-007": {  # Exfiltration
        "pcaps": [
            ("network", "analyze_pcap", {"pcap_file": "{pcap}"}),
            ("network", "extract_http", {"pcap_file": "{pcap}"}),
        ],
        "memory_dumps": [
            ("volatility", "network_scan", {"memory_dump": "{mem}"}),
        ],
        "evtx_logs": [
            ("logs", "parse_evtx", {"evtx_file": "{evtx}"}),
        ],
        "registry_hives": [
            ("registry", "extract_usb_devices", {"system_path": "{hive}"}),
            ("registry", "extract_mounted_devices", {"system_path": "{hive}"}),
        ],
    },
    "PB-SIFT-008": {  # Malware Hunting
        "disk_images": [
            ("sleuthkit", "analyze_partition_table", {"disk_image": "{image}"}),
            ("sleuthkit", "analyze_filesystem", {"image": "{image}", "offset": "{offset}"}),
            ("sleuthkit", "list_files", {"image": "{image}", "offset": "{offset}", "recursive": True}),
            ("strings", "extract_strings", {"file_path": "{image}", "min_length": 4, "encoding": "ascii"}),
            ("strings", "extract_strings", {"file_path": "{image}", "min_length": 8}),
        ],
        "memory_dumps": [
            ("volatility", "process_list", {"memory_dump": "{mem}"}),
            ("volatility", "find_malware", {"memory_dump": "{mem}"}),
        ],
    },
    "PB-SIFT-009": {  # Ransomware
        "evtx_logs": [
            ("logs", "parse_evtx", {"evtx_file": "{evtx}"}),
        ],
        "disk_images": [
            ("sleuthkit", "list_files", {"image": "{image}", "offset": "{offset}", "recursive": True}),
        ],
        "memory_dumps": [
            ("volatility", "process_list", {"memory_dump": "{mem}"}),
        ],
    },
    "PB-SIFT-010": {  # Living-off-the-Land
        "evtx_logs": [
            ("logs", "parse_evtx", {"evtx_file": "{evtx}"}),
        ],
        "memory_dumps": [
            ("volatility", "process_list", {"memory_dump": "{mem}"}),
        ],
        "disk_images": [
            ("sleuthkit", "list_deleted", {"image": "{image}", "offset": "{offset}"}),
        ],
    },
    "PB-SIFT-011": {  # Web Shell
        "evtx_logs": [
            ("logs", "parse_evtx", {"evtx_file": "{evtx}"}),
        ],
        "disk_images": [
            ("sleuthkit", "list_files", {"image": "{image}", "offset": "{offset}", "recursive": True}),
        ],
    },
    "PB-SIFT-012": {  # Anti-Forensics
        "evtx_logs": [
            ("logs", "parse_evtx", {"evtx_file": "{evtx}"}),
        ],
        "disk_images": [
            ("sleuthkit", "list_files", {"image": "{image}", "offset": "{offset}", "recursive": True}),
            ("sleuthkit", "analyze_filesystem", {"image": "{image}", "offset": "{offset}"}),
        ],
        "memory_dumps": [
            ("volatility", "process_list", {"memory_dump": "{mem}"}),
        ],
    },
    "PB-SIFT-013": {  # Insider Threat
        "evtx_logs": [
            ("logs", "parse_evtx", {"evtx_file": "{evtx}"}),
        ],
        "syslogs": [
            ("logs", "parse_syslog", {"log_file": "{syslog}"}),
        ],
        "pcaps": [
            ("network", "analyze_pcap", {"pcap_file": "{pcap}"}),
        ],
        "memory_dumps": [
            ("volatility", "network_scan", {"memory_dump": "{mem}"}),
        ],
    },
    "PB-SIFT-014": {  # Linux Forensics
        "syslogs": [
            ("logs", "parse_syslog", {"log_file": "{syslog}"}),
        ],
        "disk_images": [
            ("sleuthkit", "analyze_partition_table", {"disk_image": "{image}"}),
            ("sleuthkit", "list_files", {"image": "{image}", "offset": "{offset}", "recursive": True}),
        ],
    },
    "PB-SIFT-015": {  # Data Staging
        "disk_images": [
            ("sleuthkit", "list_files", {"image": "{image}", "offset": "{offset}", "recursive": True}),
            ("strings", "extract_strings", {"file_path": "{image}", "min_length": 8}),
        ],
        "pcaps": [
            ("network", "analyze_pcap", {"pcap_file": "{pcap}"}),
        ],
    },
    "PB-SIFT-016": {  # Cross-Image Correlation
        "disk_images": [
            ("plaso", "create_timeline", {"evidence_path": "{image}", "output_file": "{output_dir}/timeline_{image_stem}.plaso"}),
        ],
    },
    "PB-SIFT-017": {  # REMnux Malware Analysis — full 15-tool coverage
        # General-purpose tools run on all binary evidence types
        "other_files": [
            ("remnux", "die_scan",       {"target_file": "{file}"}),
            ("remnux", "exiftool_scan",  {"target_file": "{file}"}),
            ("remnux", "clamav_scan",    {"target_file": "{file}"}),
            ("remnux", "ssdeep_hash",    {"target_file": "{file}"}),
            ("remnux", "hashdeep_audit", {"target_file": "{file}"}),
            ("remnux", "floss_strings",  {"target_file": "{file}"}),
            ("remnux", "radare2_analyze",{"target_file": "{file}"}),
            ("remnux", "peframe_scan",   {"target_file": "{file}"}),
            ("remnux", "upx_unpack",     {"target_file": "{file}"}),
            # Document/script analysis — specialists return clean errors for wrong types
            ("remnux", "pdfid_scan",     {"target_file": "{file}"}),
            ("remnux", "pdf_parser",     {"target_file": "{file}"}),
            ("remnux", "oledump_scan",   {"target_file": "{file}"}),
            ("remnux", "js_beautify",    {"target_file": "{file}"}),
        ],
        # Memory dumps — string extraction and AV scan
        "memory_dumps": [
            ("remnux", "floss_strings",  {"target_file": "{mem}"}),
            ("remnux", "clamav_scan",    {"target_file": "{mem}"}),
            ("remnux", "ssdeep_hash",    {"target_file": "{mem}"}),
        ],
        # Disk images — AV scan and metadata
        "disk_images": [
            ("remnux", "die_scan",       {"target_file": "{image}"}),
            ("remnux", "clamav_scan",    {"target_file": "{image}"}),
            ("remnux", "exiftool_scan",  {"target_file": "{image}"}),
            ("remnux", "hashdeep_audit", {"target_file": "{image}"}),
        ],
        # Network captures — C2 infrastructure simulation check
        "pcaps": [
            ("remnux", "inetsim_check",  {"target_file": "{pcap}"}),
            ("remnux", "fakedns_check",  {"target_file": "{pcap}"}),
        ],
    },
    "PB-SIFT-018": {  # Malware Analysis SOP
        "disk_images": [
            ("plaso", "create_timeline", {"evidence_path": "{image}", "output_file": "{output_dir}/timeline_{image_stem}.plaso"}),
            ("strings", "extract_strings", {"file_path": "{image}", "min_length": 8}),
        ],
        "pcaps": [
            ("network", "analyze_pcap", {"pcap_file": "{pcap}"}),
        ],
        "memory_dumps": [
            ("volatility", "process_list", {"memory_dump": "{mem}"}),
        ],
        "evtx_logs": [
            ("logs", "parse_evtx", {"evtx_file": "{evtx}"}),
        ],
        "registry_hives": [
            ("registry", "parse_hive", {"hive_path": "{hive}"}),
        ],
        "syslogs": [
            ("logs", "parse_syslog", {"log_file": "{syslog}"}),
        ],
    },
    "PB-SIFT-020": {  # Timeline Analysis — log2timeline + mactime + psort
        "disk_images": [
            ("plaso", "create_timeline", {
                "evidence_path": "{image}",
                "output_file": "{output_dir}/timeline_{image_stem}.plaso",
            }),
            ("sleuthkit", "list_files_mactime", {
                "image": "{image}", "offset": "{offset}",
            }),
            ("plaso", "sort_timeline", {
                "storage_file": "{output_dir}/timeline_{image_stem}.plaso",
                "output_format": "json_line",
                "filter_str": None,
            }),
        ],
    },
    "PB-SIFT-019": {  # Command & Control
        "pcaps": [
            ("network", "analyze_pcap", {"pcap_file": "{pcap}"}),
            ("network", "extract_flows", {"pcap_file": "{pcap}", "output_dir": "{output_dir}/flows"}),
        ],
        "memory_dumps": [
            ("volatility", "process_list", {"memory_dump": "{mem}"}),
            ("volatility", "network_scan", {"memory_dump": "{mem}"}),
        ],
        "evtx_logs": [
            ("logs", "parse_evtx", {"evtx_file": "{evtx}"}),
        ],
        "disk_images": [
            ("sleuthkit", "list_files", {"image": "{image}", "offset": "{offset}", "recursive": True}),
            ("strings", "extract_strings", {"file_path": "{image}", "min_length": 8}),
        ],
    },
    "PB-SIFT-021": {  # Mobile Analysis
        "mobile_backups": [
            # iOS — device metadata and account inventory
            ("mobile", "analyze_ios_backup",               {"backup_path": "{mobile}"}),
            ("mobile", "extract_ios_device_info",          {"backup_dir": "{mobile}"}),
            ("mobile", "extract_ios_accounts",             {"backup_dir": "{mobile}"}),
            # iOS — communications
            ("mobile", "extract_ios_sms",                  {"backup_dir": "{mobile}"}),
            ("mobile", "extract_ios_call_history",         {"backup_dir": "{mobile}"}),
            ("mobile", "extract_ios_contacts",             {"backup_dir": "{mobile}"}),
            ("mobile", "extract_ios_mail",                 {"backup_dir": "{mobile}"}),
            ("mobile", "extract_whatsapp",                 {"source_dir": "{mobile}", "platform": "ios"}),
            ("mobile", "extract_telegram",                 {"source_dir": "{mobile}", "platform": "ios"}),
            # iOS — activity and location
            ("mobile", "extract_ios_safari_history",       {"backup_dir": "{mobile}"}),
            ("mobile", "extract_ios_location",             {"backup_dir": "{mobile}"}),
            ("mobile", "extract_ios_notifications",        {"backup_dir": "{mobile}"}),
            ("mobile", "extract_ios_usage_stats",          {"backup_dir": "{mobile}"}),
            ("mobile", "extract_mobile_photo_exif",        {"source_dir": "{mobile}", "platform": "ios"}),
            # iOS — security and credentials
            ("mobile", "extract_ios_keychain",             {"backup_dir": "{mobile}"}),
            ("mobile", "extract_ios_health",               {"backup_dir": "{mobile}"}),
            ("mobile", "detect_jailbreak_indicators",      {"backup_dir": "{mobile}", "data_dir": ""}),
            ("mobile", "run_ileapp",                       {"backup_dir": "{mobile}"}),
            # Android — device metadata and account inventory
            ("mobile", "analyze_android",                  {"data_dir": "{mobile}"}),
            ("mobile", "extract_android_device_info",      {"data_dir": "{mobile}"}),
            ("mobile", "extract_android_accounts",         {"data_dir": "{mobile}"}),
            # Android — communications
            ("mobile", "extract_android_sms",              {"data_dir": "{mobile}"}),
            ("mobile", "extract_android_call_logs",        {"data_dir": "{mobile}"}),
            ("mobile", "extract_android_contacts",         {"data_dir": "{mobile}"}),
            ("mobile", "extract_android_email",            {"data_dir": "{mobile}"}),
            ("mobile", "extract_whatsapp",                 {"source_dir": "{mobile}", "platform": "android"}),
            ("mobile", "extract_telegram",                 {"source_dir": "{mobile}", "platform": "android"}),
            # Android — activity and location
            ("mobile", "extract_android_browser_history",  {"data_dir": "{mobile}"}),
            ("mobile", "extract_android_location",         {"data_dir": "{mobile}"}),
            ("mobile", "extract_android_notifications",    {"data_dir": "{mobile}"}),
            ("mobile", "extract_android_usage_stats",      {"data_dir": "{mobile}"}),
            ("mobile", "extract_mobile_photo_exif",        {"source_dir": "{mobile}", "platform": "android"}),
            # Android — security
            ("mobile", "detect_root_indicators",           {"data_dir": "{mobile}"}),
            ("mobile", "run_aleapp",                       {"data_dir": "{mobile}"}),
        ],
    },
    "PB-SIFT-022": {  # Browser Forensics
        "disk_images": [
            ("sleuthkit", "list_files", {"image": "{image}", "offset": "{offset}", "recursive": True}),
        ],
        "other_files": [
            ("browser", "extract_history", {"db_path": "{file}"}),
            ("browser", "extract_cookies", {"db_path": "{file}"}),
            ("browser", "extract_downloads", {"db_path": "{file}"}),
            ("browser", "extract_saved_passwords", {"db_path": "{file}"}),
        ],
    },
    "PB-SIFT-023": {  # Email Forensics
        "other_files": [
            ("email", "analyze_pst", {"pst_path": "{file}"}),
            ("email", "analyze_mbox", {"mbox_path": "{file}"}),
            ("email", "analyze_eml", {"eml_path": "{file}"}),
        ],
    },
    "PB-SIFT-024": {  # macOS Forensics
        "disk_images": [
            ("sleuthkit", "analyze_filesystem", {"image": "{image}", "offset": "{offset}"}),
            ("sleuthkit", "list_files", {"image": "{image}", "offset": "{offset}", "recursive": True}),
        ],
        "syslogs": [
            ("logs", "parse_syslog", {"log_file": "{syslog}"}),
        ],
        "other_files": [
            ("macos", "parse_plist", {"plist_path": "{file}"}),
            ("macos", "parse_unified_log", {"log_path": "{file}"}),
            ("macos", "analyze_launch_agents", {"directory": "{file}"}),
        ],
    },
}


def _inventory_evidence(evidence_path: Path) -> dict:
    """Walk the evidence directory and categorise every file."""
    inventory = {
        "disk_images": [],
        "memory_dumps": [],
        "pcaps": [],
        "evtx_logs": [],
        "syslogs": [],
        "registry_hives": [],
        "mobile_backups": [],
        "other_files": [],
        "total_size_bytes": 0,
        "file_hashes": {},  # path -> sha256
    }

    disk_ext = {'.e01', '.ee01', '.e02', '.e03', '.e04', '.dd', '.raw', '.img', '.001', '.002', '.aff', '.aff4', '.ex01'}
    mem_ext  = {'.vmem', '.mem', '.dmp', '.core', '.lin'}
    pcap_ext = {'.pcap', '.pcapng', '.cap'}
    registry_names = {'ntuser.dat', 'system', 'software', 'security', 'sam', 'amcache.hve',
                      'usrclass.dat', 'default', 'system.sav', 'software.sav'}
    mobile_indicators = {'info.plist', 'manifest.db', 'manifest.plist'}
    syslog_names = {'syslog', 'auth.log', 'kern.log', 'messages', 'secure', 'auth.log.1', 'daemon.log'}

    for item in evidence_path.rglob('*'):
        if not item.is_file():
            continue
        try:
            size = item.stat().st_size
        except OSError as e:
            print(f"[GEOFF] Cannot stat {item}: {e}")
            size = 0
        inventory["total_size_bytes"] += size

        # Hash evidence files for chain of custody
        file_hash = _hash_file(str(item))
        inventory["file_hashes"][str(item)] = file_hash
        if file_hash == "hash_failed":
            inventory["integrity_failures"] = inventory.get("integrity_failures", []) + [str(item)]

        ext = item.suffix.lower()
        name_lower = item.name.lower()

        if ext in disk_ext:
            inventory["disk_images"].append(str(item))
        elif ext in mem_ext:
            inventory["memory_dumps"].append(str(item))
        elif ext in pcap_ext:
            inventory["pcaps"].append(str(item))
        elif ext == '.evtx':
            inventory["evtx_logs"].append(str(item))
        elif name_lower in registry_names:
            inventory["registry_hives"].append(str(item))
        elif name_lower in syslog_names or name_lower.startswith('syslog'):
            inventory["syslogs"].append(str(item))
        elif name_lower in mobile_indicators:
            inventory["mobile_backups"].append(str(item))
        else:
            inventory["other_files"].append(str(item))

    return inventory


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


def _is_indicator_match(haystack: str, needle: str) -> bool:
    """Match indicator patterns with word-boundary awareness.
    
    For patterns >= 5 chars: use word-boundary regex (\b).\n    For patterns < 5 chars: require exact word match (delimited by non-alphanumeric).\n    This prevents 'scp' matching inside 'descriptor', 'c99' matching C99 standard refs, etc.
    """
    needle_lower = needle.lower()
    haystack_lower = haystack.lower()
    
    if len(needle_lower) >= 5:
        # Word-boundary regex for longer patterns
        try:
            return bool(re.search(r'\b' + re.escape(needle_lower) + r'\b', haystack_lower))
        except re.error:
            return needle_lower in haystack_lower
    else:
        # Short patterns: require non-alphanumeric delimiter on both sides
        # or match at start/end of string
        pattern = re.escape(needle_lower)
        try:
            return bool(re.search(r'(?<![a-zA-Z0-9])' + pattern + r'(?![a-zA-Z0-9])', haystack_lower))
        except re.error:
            return False


def _scan_triage_indicators(inventory: dict) -> list:
    """Scan for high-signal triage patterns using filenames AND content.
    
    Phase 1: Scan file names for indicator patterns (word-boundary matching).
    Phase 2: Run strings against evidence files for keyword hits (word-boundary matching).
    Phase 3: For text-accessible evidence (logs, registry), scan directly.
    
    All hits include a 'confidence' field:
      - 'POSSIBLE': string/filename match only, not yet playbook-confirmed
      - 'CONFIRMED': would be set by playbook findings (not this function)
    """
    hits = []
    all_paths = inventory["other_files"] + inventory["disk_images"]
    
    # Minimum pattern length for content scanning — shorter patterns are too noisy
    MIN_PATTERN_LENGTH = 5
    
    # Phase 1: Filename-based scanning (word-boundary matching)
    for category, patterns in TRIAGE_PATTERNS.items():
        for pattern in patterns:
            if len(pattern) < MIN_PATTERN_LENGTH:
                continue  # Skip short patterns for content scanning
            for fpath in all_paths:
                if _is_indicator_match(fpath, pattern):
                    hits.append({"category": category, "pattern": pattern, "file": fpath,
                                 "severity": SEVERITY_MAP.get(category, "MEDIUM"),
                                 "confidence": "POSSIBLE", "source": "filename_scan",
                                 "mitre_techniques": MITRE_TAGS.get(category, [])})
                    break  # one hit per pattern is enough
    
    # Phase 2: Run strings against disk images and memory dumps
    # Skip files >2GB for triage — the malware hunting playbook runs strings properly
    MAX_TRIAGE_STRINGS_SIZE = 2 * 1024**3  # 2GB
    binary_evidence = inventory.get("disk_images", []) + inventory.get("memory_dumps", [])
    for fpath in binary_evidence:
        try:
            file_size = Path(str(fpath)).stat().st_size if Path(str(fpath)).exists() else 0
            if file_size > MAX_TRIAGE_STRINGS_SIZE:
                continue  # Too large for triage strings scan
            # Pipe through head -c to terminate early instead of timeout
            result = safe_run(
                ["bash", "-c", f"strings -n 8 {shlex.quote(str(fpath))} | head -c 500000"],
                timeout=60
            )
            if result["code"] != 0:
                continue
            content_lower = result["stdout"].lower()
            for category, keywords in TRIAGE_PATTERNS.items():
                for kw in keywords:
                    if len(kw) < MIN_PATTERN_LENGTH:
                        continue  # Skip short patterns
                    if _is_indicator_match(content_lower, kw):
                        hits.append({
                            "category": category,
                            "pattern": kw,
                            "file": str(fpath),
                            "severity": SEVERITY_MAP.get(category, "MEDIUM"),
                            "confidence": "POSSIBLE",
                            "source": "strings_scan",
                            "mitre_techniques": MITRE_TAGS.get(category, []),
                        })
                        break  # one hit per category per file
        except (subprocess.TimeoutExpired, OSError, IOError):
            continue

    # Phase 2b: strings scan on other_files that are binary (Phase 3 handles text files)
    _phase3_exts = {".evtx", ".log", ".txt", ".xml", ".json", ".csv",
                    ".sys", ".reg", ".ini", ".cfg", ".conf", ".bat",
                    ".ps1", ".vbs", ".js", ".html", ".php", ""}
    for fpath in inventory.get("other_files", []):
        if Path(str(fpath)).suffix.lower() in _phase3_exts:
            continue  # Phase 3 will do a direct content scan instead
        try:
            file_size = Path(str(fpath)).stat().st_size if Path(str(fpath)).exists() else 0
            if file_size > MAX_TRIAGE_STRINGS_SIZE:
                continue
            result = safe_run(
                ["bash", "-c", f"strings -n 8 {shlex.quote(str(fpath))} | head -c 500000"],
                timeout=60,
            )
            if result["code"] != 0:
                continue
            content_lower = result["stdout"].lower()
            for category, keywords in TRIAGE_PATTERNS.items():
                for kw in keywords:
                    if len(kw) < MIN_PATTERN_LENGTH:
                        continue
                    if _is_indicator_match(content_lower, kw):
                        hits.append({
                            "category": category,
                            "pattern": kw,
                            "file": str(fpath),
                            "severity": SEVERITY_MAP.get(category, "MEDIUM"),
                            "confidence": "POSSIBLE",
                            "source": "strings_scan_other",
                            "mitre_techniques": MITRE_TAGS.get(category, []),
                        })
                        break
        except (subprocess.TimeoutExpired, OSError, IOError):
            continue

    # Phase 3: Direct content scan for text-accessible evidence
    # Include files with no extension (e.g. 'syslog', 'messages', 'secure')
    text_extensions = {".evtx", ".log", ".txt", ".xml", ".json", ".csv",
                       ".sys", ".reg", ".ini", ".cfg", ".conf", ".bat",
                       ".ps1", ".vbs", ".js", ".html", ".php",
                       ""}  # empty ext covers: syslog, messages, auth, etc.
    max_read_bytes = 512 * 1024  # 512KB per file

    for fpath in inventory.get("evtx_logs", []) + inventory.get("syslogs", []) + \
                inventory.get("other_files", []):
        fpath_str = str(fpath)
        ext = Path(fpath_str).suffix.lower()
        if ext not in text_extensions:
            continue
        try:
            file_size = Path(fpath_str).stat().st_size
            if file_size > 5 * 1024 * 1024:  # Skip files > 5MB
                continue
            with open(fpath_str, "rb") as f:
                content = f.read(max_read_bytes)
            content_lower = content.lower().decode("utf-8", errors="ignore")
            for category, keywords in TRIAGE_PATTERNS.items():
                for kw in keywords:
                    if len(kw) < MIN_PATTERN_LENGTH:
                        continue
                    if _is_indicator_match(content_lower, kw):
                        hits.append({
                            "category": category,
                            "pattern": kw,
                            "file": fpath_str,
                            "severity": SEVERITY_MAP.get(category, "MEDIUM"),
                            "confidence": "POSSIBLE",
                            "source": "content_scan",
                            "mitre_techniques": MITRE_TAGS.get(category, []),
                        })
                        break  # one hit per category per file
        except (OSError, IOError, PermissionError):
            continue  # can't read, skip silently

    # Deduplicate: keep first hit per (category, file) pair across all phases
    seen = set()
    deduped = []
    for h in hits:
        key = (h["category"], h["file"])
        if key not in seen:
            seen.add(key)
            deduped.append(h)
    return deduped


def _reconstruct_attack_chain(findings: list, indicator_hits: list, device_map: dict) -> dict:
    """Compute dwell time and reconstruct lateral movement path from findings.

    Returns a dict with:
      - first_seen_ts: ISO timestamp of earliest artefact
      - last_seen_ts: ISO timestamp of most recent artefact
      - dwell_days: float (None if timestamps unavailable)
      - lateral_movement_path: list of device IDs in order of first activity
      - mitre_techniques_observed: deduplicated list of all ATT&CK IDs seen
      - kill_chain_phases: set of categories observed (triage + findings)
    """
    timestamps: list = []
    device_first_seen: dict = {}  # device_id -> earliest ISO ts

    for f in findings:
        for ts_key in ("started_at", "completed_at"):
            ts = f.get(ts_key)
            if ts:
                timestamps.append(ts)
        dev = f.get("device_id")
        ts = f.get("started_at") or f.get("completed_at")
        if dev and ts:
            if dev not in device_first_seen or ts < device_first_seen[dev]:
                device_first_seen[dev] = ts

    first_ts = min(timestamps) if timestamps else None
    last_ts = max(timestamps) if timestamps else None

    dwell_days = None
    if first_ts and last_ts:
        try:
            from datetime import datetime as _dt
            fmt = "%Y-%m-%dT%H:%M:%S"
            # Strip sub-second and TZ offset for simple comparison
            t0 = _dt.fromisoformat(first_ts[:19])
            t1 = _dt.fromisoformat(last_ts[:19])
            dwell_days = round((t1 - t0).total_seconds() / 86400, 2)
        except Exception as dwell_exc:
            _log_info(f"dwell calculation skipped: {dwell_exc}")

    # Lateral movement path: devices sorted by first activity
    lateral_path = sorted(device_first_seen.keys(),
                          key=lambda d: device_first_seen[d])

    # Collect all ATT&CK techniques from indicator hits
    mitre_seen: list = []
    kill_chain_phases: set = set()
    for hit in indicator_hits:
        kill_chain_phases.add(hit.get("category", ""))
        for t in hit.get("mitre_techniques", []):
            if t not in mitre_seen:
                mitre_seen.append(t)

    return {
        "first_seen_ts": first_ts,
        "last_seen_ts": last_ts,
        "dwell_days": dwell_days,
        "lateral_movement_path": lateral_path,
        "mitre_techniques_observed": mitre_seen,
        "kill_chain_phases": sorted(kill_chain_phases - {""}),
    }


def _tool_available(module: str, function: str) -> bool:
    """Quick check whether the specialist function can actually run.

    For now we assume the specialist exists and will fail gracefully if the
    underlying CLI tool is missing.  The orchestrator returns an error dict
    with status='error' in that case, which we handle as a skip.
    """
    # We always attempt the call and handle errors; this function exists so
    # callers can do an optimistic check if they want.
    return True





def find_evil(evidence_dir: str, job_id: str = None) -> dict:
    """
    Find Evil: Triage-driven forensic investigation.

    PB-SIFT-000 runs first as mandatory entry point, scanning for indicators
    and generating a structured execution plan. Only listed playbooks run.
    Evidence type and indicator hits determine which playbooks are included.

    Multi-host correlation: when multiple disk images are found, individual
    timelines are created with Plaso and then merged for cross-image
    correlation.

    Args:
        evidence_dir: Absolute path to the evidence directory to analyse.
        job_id: Optional async job ID (used for progress tracking).

    Returns:
        dict with keys: status, evidence_dir, inventory, playbooks_run,
        findings, evil_found, severity, report_path, elapsed_seconds
    """
    start_time = time.time()
    evidence_path = Path(evidence_dir)

    # Initialize variables to None early for proper None checks
    device_map = None
    user_map = None
    correlated_users = None
    all_behavioral_flags = None
    confidence_modifiers = None
    super_timeline_path = None

    if not evidence_path.exists():
        return {
            "status": "error",
            "error": f"Evidence directory not found: {evidence_dir}",
            "evidence_dir": evidence_dir,
        }

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

    # ------------------------------------------------------------------
    # Phase 1: Evidence Inventory
    # ------------------------------------------------------------------
    inventory = _inventory_evidence(evidence_path)

    # Phase 1a: Device Discovery & User Attribution
    _update_job(3, "discovery", "Identifying devices and users")
    device_disc = DeviceDiscovery(orchestrator)
    device_map, user_map = device_disc.discover(evidence_path, inventory)
    _fe_log(job_id, f"Discovered {len(device_map)} devices, {len(user_map)} users")

    # If no devices were resolved (log-only or standalone file evidence), synthesise
    # a single "unknown" device so the per-device playbook loop always runs.
    if not device_map:
        all_evidence = (
            inventory["disk_images"] + inventory["memory_dumps"] + inventory["pcaps"]
            + inventory["evtx_logs"] + inventory["syslogs"] + inventory["registry_hives"]
            + inventory["mobile_backups"] + inventory["other_files"]
        )
        device_map = {
            "host-unknown": {
                "device_id": "host-unknown",
                "device_type": "unknown",
                "owner": "unknown",
                "os_type": "unknown",
                "evidence_files": all_evidence,
            }
        }
        _fe_log(job_id, "  No devices resolved — created synthetic host-unknown device")

    for dev_id, dev in device_map.items():
        _fe_log(job_id, f"  Device: {dev_id} ({dev.get('device_type', 'unknown')}) "
                        f"owner={dev.get('owner', 'unknown')} "
                        f"files={len(dev.get('evidence_files', []))}")

    # Determine OS from dominant device type (for playbook selection)
    os_type = _detect_os_from_devices(device_map)
    # Triage indicators still useful for initial severity classification
    indicator_hits = _scan_triage_indicators(inventory)

    _update_job(5, "inventory", "Complete", log_msg="Evidence inventory complete")

    # ------------------------------------------------------------------
    # Phase 1b: Detect partition offsets for each disk image
    # ------------------------------------------------------------------
    image_offsets = {}  # image_path -> first filesystem partition offset
    # Phase 1b (revised): Detect partition offsets per device
    for dev_id, dev in device_map.items():
        for img in dev.get("evidence_files", []):
            if img in inventory.get("disk_images", []):
                try:
                    specialist = SLEUTHKIT_Specialist(evidence_path=img)
                    mmls_result = specialist.analyze_partition_table(img)
                    if mmls_result.get("status") == "success" and mmls_result.get("partitions"):
                        # Find first NTFS/ext4/HFS+ partition
                        for part in mmls_result["partitions"]:
                            desc = part.get("description", "").lower()
                            start = part.get("start_sector", 0)
                            if any(fs in desc for fs in ["ntfs", "ext", "hfs", "fat", "linux", "windows"]):
                                image_offsets[img] = start
                                _fe_log(job_id, f"Partition offset for {Path(img).name}: sector {start}")
                                break
                        if img not in image_offsets and mmls_result["partitions"]:
                            # Use first non-meta partition
                            for part in mmls_result["partitions"]:
                                start = part.get("start_sector", 0)
                                if start > 0:
                                    image_offsets[img] = start
                                    _fe_log(job_id, f"Partition offset for {Path(img).name}: sector {start} (first partition)")
                                    break
                    if img not in image_offsets:
                        # 2048 sectors (1 MiB) is the modern MBR/GPT alignment default
                        # chosen for 4K-sector drives; matches what fdisk/gdisk/Windows
                        # create since ~2009. Exotic/legacy layouts may need manual offset.
                        image_offsets[img] = 2048
                        _fe_log(job_id, f"Using default offset 2048 for {Path(img).name}")
                except Exception as e:
                    image_offsets[img] = 2048  # see note above on 1 MiB alignment
                    _fe_log(job_id, f"Partition detection failed for {Path(img).name}: {e}, using offset 2048")

    # ------------------------------------------------------------------
    # Phase 2: Prepare Case Work Directory
    # ------------------------------------------------------------------
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    case_name = evidence_path.name
    case_work_dir = Path(CASES_WORK_DIR) / f"{case_name}_findevil_{timestamp}"
    try:
        case_work_dir.mkdir(parents=True, exist_ok=True)
    except (PermissionError, OSError):
        case_work_dir = Path(tempfile.gettempdir()) / "geoff-cases" / f"{case_name}_findevil_{timestamp}"
        case_work_dir.mkdir(parents=True, exist_ok=True)
    # Create evidence separation directories
    (case_work_dir / "evidence" / "derived").mkdir(parents=True, exist_ok=True)
    
    # Write evidence manifest to evidence/raw/ (references, not copies/links)
    # Raw evidence stays in its original location — only derived artifacts go here
    manifest = {
        "evidence_dir": str(evidence_dir),
        "disk_images": inventory.get("disk_images", []),
        "memory_dumps": inventory.get("memory_dumps", []),
        "pcaps": inventory.get("pcaps", []),
        "evtx_logs": inventory.get("evtx_logs", []),
        "syslogs": inventory.get("syslogs", []),
        "registry_hives": inventory.get("registry_hives", []),
        "total_size_bytes": inventory.get("total_size_bytes", 0),
    }
    _atomic_write(case_work_dir / "evidence" / "raw" / "manifest.json", json.dumps(manifest, indent=2, default=str))

    # Write device and user maps
    _atomic_write(
        case_work_dir / "device_map.json",
        json.dumps(device_map, indent=2, default=str)
    )
    _atomic_write(
        case_work_dir / "user_map.json",
        json.dumps(user_map, indent=2, default=str)
    )
    if case_work_dir != Path(CASES_WORK_DIR) / f"{case_name}_findevil_{timestamp}":
        print(f"[FIND-EVIL] Case work dir fallback: {case_work_dir}")

    for subdir in ("output", "reports", "validations", "timeline"):
        (case_work_dir / subdir).mkdir(exist_ok=True)
    # Link derived artifacts into evidence/derived/
    try:
        (case_work_dir / "evidence" / "derived" / "output").symlink_to(case_work_dir / "output")
        (case_work_dir / "evidence" / "derived" / "timeline").symlink_to(case_work_dir / "timeline")
    except (OSError, FileExistsError):
        pass

    # Init git
    try:
        r = safe_run(['git', 'init'], cwd=case_work_dir, timeout=30)
        if r.get("code", -1) != 0:
            _fe_log(job_id, f"[WARN] git init failed (code {r.get('code')}): {r.get('stderr', '')}")
        safe_run(['git', 'config', 'user.email', 'geoff@dfir.local'], cwd=case_work_dir, timeout=10)
        safe_run(['git', 'config', 'user.name', 'Geoff DFIR'], cwd=case_work_dir, timeout=10)
        safe_run(['git', 'config', '--add', 'safe.directory', str(case_work_dir)], cwd=case_work_dir, timeout=10)
        # Write .gitignore for case directory
        with open(case_work_dir / '.gitignore', 'w') as f:
            f.write('# GEOFF case directory - evidence artifacts\n*.E01\n*.E02\n*.E03\n*.dd\n*.raw\n*.img\n*.aff\n*.vmem\n*.dmp\n*.pcap\n*.pcapng\n*.plaso\n*.json_line\n*.csv\n*.jsonl\n')
        safe_git_commit('Initial case setup', base_path=str(case_work_dir))
    except Exception as e:
        _log_error(f"git init case_work_dir {case_work_dir}", e)

    _update_job(8, "setup", "Case directory ready", log_msg=f"Case directory ready: {case_work_dir}")
    _audit_append(case_work_dir, "case_init", job_id=job_id, evidence_dir=str(evidence_dir))

    # Crash Recovery — reset any 'running' steps from previous runs
    for pb_file in case_work_dir.glob("output/*.json"):
        try:
            with open(pb_file) as f:
                pb_steps = json.load(f)
            changed = False
            for step in pb_steps:
                if step.get("status") == "running":
                    step["status"] = "failed"
                    step["error"] = "Interrupted by crash — status was 'running' on restart"
                    changed = True
            if changed:
                _atomic_write(pb_file, json.dumps(pb_steps, default=str, indent=2))
                _log_info(f"Crash recovery: reset 'running' steps in {pb_file.name} to 'failed'")
        except Exception as crash_exc:
            _log_info(f"crash recovery skipped for {pb_file.name}: {crash_exc}")

    # Disk State Reconciliation — find orphaned artifacts not tracked in state
    try:
        tracked_files = set()
        for pb_file in case_work_dir.glob("output/*.json"):
            try:
                with open(pb_file) as f:
                    pb_steps = json.load(f)
                for step in pb_steps:
                    if step.get("evidence_file"):
                        tracked_files.add(str(step["evidence_file"]))
                    result = step.get("result", {})
                    if isinstance(result, dict):
                        for art in result.get("artifacts", []):
                            tracked_files.add(str(art))
            except Exception as track_exc:
                _log_info(f"artifact tracking skipped for {pb_file.name}: {track_exc}")
        # Scan for untracked files in case work dir
        untracked = []
        for f in case_work_dir.rglob("*"):
            if f.is_file() and str(f) not in tracked_files:
                rel = f.relative_to(case_work_dir)
                if str(rel).startswith(("output/", "timeline/", "reports/")):
                    fhash = _hash_file(str(f))
                    untracked.append({"file": str(f), "hash": fhash, "note": "orphaned — not in state"})
        if untracked:
            orphan_log = case_work_dir / "untracked_artifacts.json"
            _atomic_write(orphan_log, json.dumps(untracked, indent=2, default=str))
            _log_info(f"Disk reconciliation: {len(untracked)} untracked artifacts found")
    except Exception as e:
        _log_error(f"Disk reconciliation failed: {e}")

    # ------------------------------------------------------------------
    # Phase 3: Triage & Execution Plan (PB-SIFT-000)
    # ------------------------------------------------------------------
    # Run PB-SIFT-000 (Triage) first to get the execution plan.
    # Then execute ONLY the playbooks listed in that plan.
    findings_writer = FindingsWriter(case_work_dir / "findings.jsonl", job_id=job_id)
    critic_results = []
    playbooks_run = []
    steps_completed = 0
    steps_failed = 0
    steps_skipped = 0
    steps_unverified = 0
    CONTINUE_ON_FAILURE = os.environ.get("GEOFF_CONTINUE_ON_FAILURE", "true").lower() == "true"
    _abort = False  # Set to True on failure when CONTINUE_ON_FAILURE=False

    # Evidence type shorthand
    ev = {
        "disk_images": inventory["disk_images"],
        "memory_dumps": inventory["memory_dumps"],
        "pcaps": inventory["pcaps"],
        "evtx_logs": inventory["evtx_logs"],
        "syslogs": inventory["syslogs"],
        "registry_hives": inventory["registry_hives"],
        "mobile_backups": inventory["mobile_backups"],
        "other_files": inventory["other_files"],
    }

    output_dir = str(case_work_dir / "output")

    # --- Run PB-SIFT-000 (Triage) first ---
    _update_job(9, "PB-SIFT-000", "Running triage meta-playbook", log_msg="\u25b6 PB-SIFT-000: Triage Prioritization")
    _fe_log(job_id, "\u25b6 PB-SIFT-000: Triage Prioritization")

    triage_findings = []
    triage_steps = PLAYBOOK_STEPS.get("PB-SIFT-000", {})
    for ev_type, step_templates in triage_steps.items():
        evidence_items = ev.get(ev_type, [])
        if not evidence_items:
            continue
        items = evidence_items if ev_type in ("disk_images", "memory_dumps") else evidence_items[:3]
        for item in items:
            item_stem = Path(item).stem
            for module, function, raw_params in step_templates:
                params = {}
                for k, v in raw_params.items():
                    if isinstance(v, str):
                        v = v.replace("{image}", item).replace("{mem}", item).replace("{pcap}", item)
                        v = v.replace("{evtx}", item).replace("{syslog}", item).replace("{hive}", item)
                        v = v.replace("{mobile}", str(Path(item).parent)).replace("{file}", item)
                        v = v.replace("{output_dir}", output_dir).replace("{image_stem}", item_stem)
                        v = v.replace("{offset}", str(image_offsets.get(item, 2048)))
                    params[k] = v
                for k, v in list(params.items()):
                    if isinstance(v, str) and v.isdigit():
                        params[k] = int(v)
                    elif isinstance(v, str) and v.lower() in ('true', 'false'):
                        params[k] = v.lower() == 'true'
                try:
                    result = _run_step_via_orchestrator(module, function, params)
                    triage_findings.append({"module": module, "function": function, "result": result, "status": result.get("status", "error")})
                except Exception as e:
                    _fe_log_with_exception(job_id, f"  ✗ {module}.{function} triage error", e)
                    triage_findings.append({"module": module, "function": function, "error": str(e), "status": "failed"})

    # --- Build execution plan from triage results ---
    # Determine which playbooks to run based on:
    #   1. Evidence types available
    #   2. Indicator hits from triage scans
    #   3. OS detection
    execution_plan = []
    skipped_playbooks = []
    confidence_modifiers = []
    anti_forensics_detected = False

    # Always include core playbooks
    core_playbooks = ["PB-SIFT-001", "PB-SIFT-002", "PB-SIFT-003", "PB-SIFT-004", "PB-SIFT-005"]
    for pb in core_playbooks:
        execution_plan.append(pb)

    # Include evidence-dependent playbooks
    if inventory["disk_images"]:
        execution_plan.extend(["PB-SIFT-006", "PB-SIFT-007", "PB-SIFT-008", "PB-SIFT-010", "PB-SIFT-012"])
    if inventory["pcaps"]:
        execution_plan.append("PB-SIFT-011")
    if os_type == "linux":
        execution_plan.append("PB-SIFT-014")
    if os_type == "macos":
        execution_plan.append("PB-SIFT-024")

    # Mobile analysis — auto-trigger when mobile backups are present
    if inventory["mobile_backups"]:
        execution_plan.append("PB-SIFT-021")

    # OS-agnostic playbooks
    execution_plan.extend(["PB-SIFT-009", "PB-SIFT-013"])

    # Browser forensics — always run (relevant for insider threat, credential theft, etc.)
    execution_plan.append("PB-SIFT-022")

    # Email forensics — run when email-like files are present
    email_exts = {".pst", ".ost", ".mbox", ".eml", ".msg"}
    if any(Path(f).suffix.lower() in email_exts for f in inventory["other_files"]):
        execution_plan.append("PB-SIFT-023")

    # Add malware playbooks when:
    #   a) triage output flagged a suspicious binary keyword, OR
    #   b) indicator_hits found anything evil (triage content/strings scan hit), OR
    #   c) other_files are present (dropped binaries, scripts, docs to analyse)
    suspicious_binary_found = False
    for f in triage_findings:
        result_str = json.dumps(f.get("result", f.get("error", "")), default=str).lower()
        if any(kw in result_str for kw in ["malware", "suspicious", "malicious", "trojan", "backdoor", "ransomware"]):
            suspicious_binary_found = True
            break
    malware_analysis_warranted = (
        suspicious_binary_found
        or len(indicator_hits) > 0
        or len(inventory["other_files"]) > 0
    )
    if malware_analysis_warranted:
        execution_plan.extend(["PB-SIFT-017", "PB-SIFT-018"])
    else:
        reason = "No suspicious binary, indicator hits, or standalone files found"
        skipped_playbooks.append({"id": "PB-SIFT-017", "reason": reason})
        skipped_playbooks.append({"id": "PB-SIFT-018", "reason": reason})

    # Timeline analysis — always run if disk images present (psort after log2timeline)
    if len(inventory["disk_images"]) > 0:
        execution_plan.append("PB-SIFT-020")

    # Mobile forensics — run if mobile backup artifacts detected
    if len(inventory["mobile_backups"]) > 0:
        execution_plan.append("PB-SIFT-021")
    else:
        skipped_playbooks.append({"id": "PB-SIFT-021", "reason": "No mobile backup artifacts detected"})

    # Cross-image correlation last (if multi-host)
    if len(inventory["disk_images"]) > 1:
        execution_plan.append("PB-SIFT-016")
    else:
        skipped_playbooks.append({"id": "PB-SIFT-016", "reason": "Only one disk image in scope"})

    # Classification based on indicator hits — must be computed before manager review
    hit_categories = set(h.get("category", "").lower() for h in indicator_hits if isinstance(h, dict))
    classification = "Unknown"
    severity = "MEDIUM"

    # C2 detection always runs PB-SIFT-019
    if "c2" in hit_categories:
        if "PB-SIFT-019" not in execution_plan:
            execution_plan.append("PB-SIFT-019")

    if "ransomware" in hit_categories:
        classification = "Ransomware"
        severity = "CRITICAL"
    elif "ot_attack" in hit_categories:
        classification = "OT/ICS Attack"
        severity = "CRITICAL"
    elif "rootkit" in hit_categories:
        classification = "Rootkit"
        severity = "CRITICAL"
    elif "c2" in hit_categories:
        classification = "Command & Control"
        severity = "CRITICAL"
    elif "credential_theft" in hit_categories:
        classification = "Credential Theft"
        severity = "HIGH"
    elif "lateral_movement" in hit_categories:
        classification = "Lateral Movement"
        severity = "HIGH"
    elif "web_shell" in hit_categories or "initial_access" in hit_categories:
        classification = "External Breach"
        severity = "HIGH"
    elif "cryptominer" in hit_categories:
        classification = "Cryptominer"
        severity = "HIGH"
    elif "exfiltration" in hit_categories:
        classification = "Exfiltration"
        severity = "HIGH"
    elif "persistence" in hit_categories:
        classification = "Persistence/Implant"
        severity = "HIGH"
    elif "anti_forensics" in hit_categories:
        classification = "Destructive/Anti-Forensics"
        severity = "HIGH"
    elif malware_analysis_warranted:
        classification = "Malware"
        severity = "HIGH"

    # Deduplicate while preserving order
    seen = set()
    execution_plan = [pb for pb in execution_plan if not (pb in seen or seen.add(pb))]

    # --- Manager reviews and may amend the execution plan ---
    execution_plan = _manager_review_execution_plan(
        proposed_plan=execution_plan,
        skipped=skipped_playbooks,
        inventory=inventory,
        triage_findings=triage_findings,
        indicator_hits=indicator_hits,
        os_type=os_type,
        classification=classification,
        severity=severity,
        job_id=job_id,
    )

    # Skip playbooks that can't run (missing required evidence)
    for pb_id in list(execution_plan):
        if pb_id not in PLAYBOOK_STEPS:
            execution_plan.remove(pb_id)
            skipped_playbooks.append({"id": pb_id, "reason": "Playbook has no steps defined"})

    # Evidence quality assessment
    evidence_quality = "MEDIUM"
    if inventory["disk_images"] and inventory["memory_dumps"]:
        evidence_quality = "HIGH"
    elif inventory["disk_images"]:
        evidence_quality = "MEDIUM-HIGH"
    elif inventory["syslogs"] or inventory["evtx_logs"]:
        evidence_quality = "LOW"
    else:
        evidence_quality = "VERY LOW"

    # Clock skew
    clock_skew_offset = "UNVERIFIED"
    for f in triage_findings:
        result = f.get("result", {})
        if isinstance(result, dict) and result.get("clock_skew_offset") is not None:
            clock_skew_offset = str(result["clock_skew_offset"])
            break

    # Anti-forensics confidence modifier
    for f in triage_findings:
        result_str = json.dumps(f.get("result", {}), default=str).lower()
        if any(kw in result_str for kw in ["log cleared", "event log cleared", "timestomp", "anti-forensic"]):
            confidence_modifiers.append("ANTI-FORENSICS-CONFIRMED")
            break

    # Emit the Phase 12 execution plan
    execution_plan_output = {
        "case_id": str(case_work_dir.name),
        "evidence_quality": evidence_quality,
        "clock_skew_offset": clock_skew_offset,
        "classification": classification,
        "severity": severity,
        "execution_plan": execution_plan,
        "skipped_playbooks": skipped_playbooks,
        "confidence_modifiers": confidence_modifiers,
    }
    _fe_log(job_id, f"Execution plan: {json.dumps(execution_plan)}")
    _fe_log(job_id, f"Skipped: {json.dumps([s['id'] for s in skipped_playbooks])}")
    _fe_log(job_id, f"Classification: {classification} | Severity: {severity} | Evidence: {evidence_quality}")
    if "ANTI-FORENSICS-CONFIRMED" in confidence_modifiers:
        _fe_log(job_id, "\u26a0 Anti-forensics detected — all findings will be downgraded")

    # Write execution plan to case directory
    try:
        plan_content = json.dumps(execution_plan_output, indent=2, default=str)
        _atomic_write(case_work_dir / "execution_plan.json", plan_content)
        git_commit_action("PB-SIFT-000: Triage execution plan emitted", base_path=str(case_work_dir))
    except Exception as e:
        _fe_log(job_id, f"Failed to write execution plan: {e}")

    # ------------------------------------------------------------------
    # Phase 3b: Execute Playbooks from Execution Plan (per-device)
    # ------------------------------------------------------------------
    # Build per-device evidence lookup
    device_evidence = {}  # device_id -> {ev_type: [paths]}
    for dev_id, dev in device_map.items():
        device_evidence[dev_id] = {
            "disk_images": [], "memory_dumps": [], "pcaps": [],
            "evtx_logs": [], "syslogs": [], "registry_hives": [],
            "mobile_backups": [], "other_files": [],
        }
        for fpath in dev.get("evidence_files", []):
            for ev_type in inventory:
                if isinstance(inventory[ev_type], list) and fpath in inventory[ev_type]:
                    device_evidence[dev_id][ev_type].append(fpath)

    # Identify unattributed evidence (PCAPs, logs not tied to a device)
    unattributed_ev = {}
    for ev_type, files in inventory.items():
        if not isinstance(files, list):
            continue
        unattr = [f for f in files
                  if not any(f in device_evidence[d].get(ev_type, [])
                             for d in device_evidence)]
        if unattr:
            unattributed_ev[ev_type] = unattr

    total_pb = len(execution_plan)
    for dev_id, dev in device_map.items():
        dev_ev = device_evidence[dev_id]
        _fe_log(job_id, f"\n{'='*60}")
        _fe_log(job_id, f"Processing device: {dev_id} ({dev.get('device_type', 'unknown')})")
        _fe_log(job_id, f"Owner: {dev.get('owner', 'unknown')}")
        _fe_log(job_id, f"{'='*60}")

        for pb_idx, playbook_id in enumerate(execution_plan):
            pb_progress_base = 10 + (80 * pb_idx / total_pb)  # 10–90% range for playbooks
            pb_name = PLAYBOOK_NAMES.get(playbook_id, playbook_id)
            _update_job(pb_progress_base, playbook_id, f"{dev_id}: Starting", log_msg=f"\u25b6 {playbook_id}: {pb_name} [{dev_id}]")

            pb_steps_def = PLAYBOOK_STEPS.get(playbook_id, {})
            pb_findings = []
            any_step_ran = False

            for ev_type, step_templates in pb_steps_def.items():
                if _abort:
                    break
                evidence_items = dev_ev.get(ev_type, [])
                # If no evidence of this type, skip the steps for this evidence type
                # (but the playbook still "runs" — it just has no applicable evidence)
                if not evidence_items:
                    continue

                # For some evidence types we iterate over each item; for others we
                # just use the first one (to keep runtime manageable).
                # Disk images and memory dumps: iterate all; others: first 3.
                if ev_type in ("disk_images", "memory_dumps"):
                    items = evidence_items
                else:
                    items = evidence_items[:3]

                for item in items:
                    if _abort:
                        break
                    # Validate evidence path before substitution to prevent command injection
                    try:
                        _validate_evidence_path(item)
                    except ValueError as path_err:
                        _fe_log(job_id, f"  ✗ Skipping unsafe evidence path: {path_err}")
                        continue
                    item_stem = Path(item).stem
                    for module, function, raw_params in step_templates:
                        _update_job(pb_progress_base, playbook_id, f"{module}.{function}")

                        # Build actual params by substituting placeholders
                        params = {}
                        for k, v in raw_params.items():
                            if isinstance(v, str):
                                v = v.replace("{image}", item)
                                v = v.replace("{mem}", item)
                                v = v.replace("{pcap}", item)
                                v = v.replace("{evtx}", item)
                                v = v.replace("{syslog}", item)
                                v = v.replace("{hive}", item)
                                v = v.replace("{mobile}", str(Path(item).parent))
                                v = v.replace("{file}", item)
                                v = v.replace("{output_dir}", output_dir)
                                v = v.replace("{image_stem}", item_stem)
                                v = v.replace("{offset}", str(image_offsets.get(item, 2048)))
                            params[k] = v
                        # Convert numeric string params to int
                        for k, v in list(params.items()):
                            if isinstance(v, str) and v.isdigit():
                                params[k] = int(v)
                            elif isinstance(v, str) and v.lower() in ('true', 'false'):
                                params[k] = v.lower() == 'true'

                        # Idempotent step key — derive from findings (single source of truth)
                        step_key = f"{playbook_id}:{module}:{function}:{Path(item).name}"
                        execution_hash = hashlib.md5(f"{step_key}:{json.dumps(params, sort_keys=True, default=str)}".encode()).hexdigest()[:12]

                        step_record = {
                            "playbook": playbook_id,
                            "step_key": step_key,
                            "execution_hash": execution_hash,
                            "module": module,
                            "function": function,
                            "params": params,
                            "evidence_file": item,
                            "device_id": dev_id,
                            "owner": dev.get("owner"),
                            "status": "running",
                            "started_at": datetime.now().isoformat(),
                        }

                        # Idempotency: skip if already completed with same inputs
                        if findings_writer.is_completed(step_key):
                            _fe_log(job_id, f"  ⎘ {module}.{function} already completed for {Path(item).name}")
                            continue

                        # Dependency enforcement: check playbook step requirements
                        # PLAYBOOK_STEPS entries are tuples: (module, function, params)
                        pb_steps_list = []
                        for category, steps in PLAYBOOK_STEPS.get(playbook_id, {}).items():
                            if isinstance(steps, list):
                                pb_steps_list.extend(steps)
                        step_def = next((s for s in pb_steps_list if isinstance(s, tuple) and len(s) >= 3 and s[0] == module and s[1] == function), None)
                        # Tuples don't have 'requires' — dependency checking is for future dict-based steps
                        if isinstance(step_def, dict) and step_def.get("requires"):
                            for dep in step_def["requires"]:
                                dep_completed = any(
                                    s.get("step_key", "").startswith(f"{playbook_id}:{dep}") and s.get("status") == "completed"
                                    for s in findings_writer.all_records()
                                )
                                if not dep_completed:
                                    _fe_log(job_id, f"  ⚠ {module}.{function} skipped — dependency {dep} not complete")
                                    step_record = {
                                        "playbook": playbook_id, "step_key": step_key, "execution_hash": execution_hash,
                                        "module": module, "function": function, "params": params,
                                        "evidence_file": item, "device_id": dev_id, "owner": dev.get("owner"),
                                        "status": "skipped", "error": f"dependency {dep} not met",
                                        "started_at": datetime.now().isoformat(), "completed_at": datetime.now().isoformat(),
                                    }
                                    findings_writer.append(step_record)
                                    pb_findings.append(step_record)
                                    continue

                        step_record = {
                            "playbook": playbook_id,
                            "step_key": step_key,
                            "execution_hash": execution_hash,
                            "module": module,
                            "function": function,
                            "params": params,
                            "evidence_file": item,
                            "device_id": dev_id,
                            "owner": dev.get("owner"),
                            "status": "running",
                            "retries": 0,
                            "max_retries": 2,
                            "started_at": datetime.now().isoformat(),
                        }

                        # Persist running state before execution (crash recovery)
                        try:
                            pb_output = case_work_dir / "output" / f"{playbook_id}.json"
                            pb_output.parent.mkdir(parents=True, exist_ok=True)
                            pb_findings_running = pb_findings + [step_record]
                            _atomic_write(pb_output, json.dumps(pb_findings_running, default=str, indent=2))
                        except Exception as persist_exc:
                            _log_info(f"playbook state persistence skipped for {playbook_id}: {persist_exc}")

                        # Retry logic for transient failures
                        MAX_RETRIES = 2
                        for attempt in range(MAX_RETRIES + 1):
                            try:
                                result = _run_step_via_orchestrator(module, function, params)
                                break
                            except Exception as retry_exc:
                                if attempt < MAX_RETRIES:
                                    _fe_log(job_id, f"  ↻ {module}.{function} retry {attempt+1}/{MAX_RETRIES}: {retry_exc}")
                                    time.sleep(1 * (attempt + 1))
                                    continue
                                result = {"status": "error", "error": f"Failed after {MAX_RETRIES} retries: {retry_exc}"}

                        try:
                            # Check for safe_run timeout indicators in result
                            if isinstance(result, dict) and result.get("code") is not None:
                                if result["code"] == -1:
                                    step_record["status"] = "failed"
                                    step_record["error"] = f"Timeout: {result.get('stderr', '')}"
                                    step_record["result"] = {"status": "failed", "stdout": "", "stderr": result.get('stderr', ''), "artifacts": [], "error": "timeout"}
                                    steps_failed += 1
                                    _fe_log(job_id, f"  ✗ {module}.{function} → timeout")
                                    findings_writer.append(step_record)
                                    pb_findings.append(step_record)
                                    continue
                                elif result["code"] < 0:
                                    step_record["status"] = "failed"
                                    step_record["error"] = f"Execution error: {result.get('stderr', '')}"
                                    step_record["result"] = {"status": "failed", "stdout": "", "stderr": result.get('stderr', ''), "artifacts": [], "error": "execution_error"}
                                    steps_failed += 1
                                    _fe_log(job_id, f"  ✗ {module}.{function} → execution error")
                                    findings_writer.append(step_record)
                                    pb_findings.append(step_record)
                                    continue
                        
                            step_status = result.get("status", "error")
                            # If the tool was missing, skip (not a failure)
                            if step_status == "error" and "not found" in str(result.get("error", "")).lower():
                                step_record["status"] = "skipped"
                                step_record["result"] = {"status": "skipped", "stdout": "", "stderr": "", "artifacts": [], "error": "tool not found"}
                                steps_skipped += 1
                                _fe_log(job_id, f"  ⎘ {module}.{function} skipped (tool not found)")
                            elif step_status == "success":
                                # Specialist tools return structured dicts without 'stdout'
                                # Only validate stdout for safe_run results (have 'code' key)
                                if isinstance(result, dict) and "code" in result:
                                    # safe_run result -- validate stdout
                                    stdout = result.get("stdout", "")
                                    if not stdout or len(stdout.strip()) < 10:
                                        step_record["status"] = "failed"
                                        step_record["error"] = f"Empty or invalid output from {module}.{function}"
                                        step_record["result"] = {"status": "failed", "stdout": stdout or "", "stderr": result.get('stderr', ''), "artifacts": [], "error": "empty output"}
                                        steps_failed += 1
                                    else:
                                        step_record["status"] = "completed"
                                        step_record["result"] = result
                                        steps_completed += 1
                                else:
                                    # Specialist result -- trust status=success
                                    step_record["status"] = "completed"
                                    step_record["result"] = result
                                    steps_completed += 1
                            else:
                                step_record["status"] = "failed"
                                step_record["result"] = {"status": "failed", "stdout": result.get('stdout', ''), "stderr": result.get('stderr', ''), "artifacts": [], "error": result.get('error', step_status)}
                                steps_failed += 1
                                any_step_ran = True
                                _fe_log(job_id, f"  ✗ {module}.{function} → {step_status}")

                                # CRITIC SELF-HEALING: Ask Critic to analyze and heal
                                try:
                                    _fe_log(job_id, f"  🔄 Critic analyzing failure for {module}.{function}...")
                                    healing_analysis = geoff_critic.analyze_execution_error(
                                        tool_name=f"{module}.{function}",
                                        tool_params=params,
                                        error_result=result,
                                        context={
                                            "device_id": dev_id,
                                            "os_type": os_type,
                                            "image_offsets": image_offsets,
                                            "job_id": job_id,
                                        }
                                    )
                                    
                                    if healing_analysis.get("healable") and healing_analysis.get("action") != "fail":
                                        action = healing_analysis.get("action")
                                        new_params = healing_analysis.get("new_params", params)
                                        _fe_log(job_id, f"  🩺 Critic suggests: {action} (confidence: {healing_analysis.get('confidence', 0)})")
                                        
                                        # Execute healing based on Critic's recommendation
                                        healed = False
                                        
                                        # Validate new_params before execution
                                        for key in ["hive_path", "ntuser_path", "system_path", "evidence_path", "image_path"]:
                                            if key in new_params and new_params[key]:
                                                try:
                                                    _validate_evidence_path(new_params[key])
                                                except ValueError as e:
                                                    _fe_log(job_id, f"  ⚠ Param validation failed for {key}: {e}")
                                        
                                        if action == "retry_with_offset" and new_params.get("offset") is not None:
                                            healed_result = _run_step_via_orchestrator(module, function, new_params)
                                            if healed_result.get("status") == "success":
                                                healed = True
                                                result = healed_result
                                                
                                        elif action == "retry_without_offset":
                                            no_offset_params = {k: v for k, v in new_params.items() if k != "offset"}
                                            healed_result = _run_step_via_orchestrator(module, function, no_offset_params)
                                            if healed_result.get("status") == "success":
                                                healed = True
                                                result = healed_result
                                                
                                        elif action == "retry_with_backoff":
                                            for delay in [0.5, 1.0, 2.0]:
                                                time.sleep(delay)
                                                healed_result = _run_step_via_orchestrator(module, function, new_params)
                                                if healed_result.get("status") == "success":
                                                    healed = True
                                                    result = healed_result
                                                    break
                                        
                                        elif action == "copy_then_retry":
                                            import tempfile, shutil
                                            original = new_params.get("hive_path") or new_params.get("ntuser_path")
                                            if original and Path(original).exists():
                                                tmp_name = None
                                                try:
                                                    with tempfile.NamedTemporaryFile(suffix=".hive", delete=False) as tmp:
                                                        shutil.copy2(original, tmp.name)
                                                        tmp_name = tmp.name
                                                    for key in ["hive_path", "ntuser_path", "system_path"]:
                                                        if key in new_params:
                                                            new_params[key] = tmp_name
                                                    healed_result = _run_step_via_orchestrator(module, function, new_params)
                                                    if healed_result.get("status") == "success":
                                                        healed = True
                                                        result = healed_result
                                                finally:
                                                    if tmp_name:
                                                        try:
                                                            os.unlink(tmp_name)
                                                        except OSError as unlink_exc:
                                                            _log_info(f"tmp hive unlink failed for {tmp_name}: {unlink_exc}")
                                                    
                                        elif action == "skip":
                                            _fe_log(job_id, f"  ⎘ Critic recommends skip (non-critical)")
                                            step_record["status"] = "skipped"
                                            step_record["_critic_healed"] = True
                                            step_record["_healing_strategy"] = "skip_on_critic_advice"
                                            steps_failed -= 1
                                            steps_skipped += 1
                                            
                                        if healed:
                                            step_record["status"] = "completed"
                                            step_record["result"] = result
                                            step_record["_critic_healed"] = True
                                            step_record["_healing_strategy"] = healing_analysis.get("healing_strategy")
                                            step_record["_critic_confidence"] = healing_analysis.get("confidence")
                                            steps_failed -= 1
                                            steps_completed += 1
                                            _fe_log(job_id, f"  ✓ Critic healed {module}.{function}: {healing_analysis.get('healing_strategy')}")
                                        elif action != "skip":
                                            _fe_log(job_id, f"  ✗ Critic healing failed for {module}.{function}")
                                    else:
                                        _fe_log(job_id, f"  ✗ Critic: not healable ({healing_analysis.get('error_type', 'unknown')})")
                                except Exception as heal_err:
                                    _fe_log(job_id, f"  ⚠ Critic healing error: {heal_err}")

                            # Forensicator interprets each completed step so the Critic
                            # has a real analysis to validate rather than a placeholder.
                            forensicator_notes = {}
                            if step_record.get("status") == "completed":
                                try:
                                    forensicator_notes = geoff_forensicator.interpret_step_result(
                                        playbook_id=playbook_id,
                                        module=module,
                                        function=function,
                                        params=params,
                                        result=result,
                                        device_context={"device_id": dev_id, "os_type": os_type},
                                    )
                                    step_record["forensicator"] = forensicator_notes
                                    sig = forensicator_notes.get("significance", "UNKNOWN")
                                    note = forensicator_notes.get("analyst_note") or ""
                                    if sig in ("CRITICAL", "HIGH"):
                                        _fe_log(job_id, f"  🔍 Forensicator [{sig}]: {note}")
                                    if forensicator_notes.get("follow_up_needed"):
                                        _fe_log(job_id, f"  ↳ Follow-up: {forensicator_notes.get('follow_up_reason', '')}")
                                    # Accuracy validation: evidence chain anchors each finding
                                    # to a specific artifact, tool, and observation.
                                    step_record["evidence_chain"] = {
                                        "artifact": function,
                                        "evidence_file": item,
                                        "tool": f"{module}.{function}",
                                        "playbook": playbook_id,
                                        "significance": sig,
                                        "analyst_note": forensicator_notes.get("analyst_note"),
                                        "threat_indicators": forensicator_notes.get("threat_indicators", []),
                                        "follow_up_needed": forensicator_notes.get("follow_up_needed", False),
                                        "follow_up_reason": forensicator_notes.get("follow_up_reason"),
                                    }
                                except Exception as fe:
                                    _fe_log(job_id, f"  ⚠ Forensicator unavailable for {module}.{function}: {fe}")
                                    step_record["evidence_chain"] = {
                                        "artifact": function,
                                        "evidence_file": item,
                                        "tool": f"{module}.{function}",
                                        "playbook": playbook_id,
                                        "significance": "UNKNOWN",
                                        "analyst_note": None,
                                        "threat_indicators": [],
                                        "follow_up_needed": False,
                                        "follow_up_reason": None,
                                    }

                            # Build Critic analysis string from Forensicator output so the
                            # Critic is checking a real interpretation, not a placeholder.
                            _critic_analysis = f"Find Evil auto-run: {playbook_id} → {module}.{function}"
                            if forensicator_notes.get("analyst_note"):
                                _critic_analysis += f"\nForensicator: {forensicator_notes['analyst_note']}"
                            if forensicator_notes.get("threat_indicators"):
                                _critic_analysis += f"\nThreat indicators: {', '.join(forensicator_notes['threat_indicators'])}"

                            # Critic validation — mandatory: failures are surfaced as
                            # needs_review flags rather than silently ignored.
                            try:
                                critic_val = geoff_critic.validate_tool_output(
                                    tool_name=f"{module}.{function}",
                                    tool_params=params,
                                    raw_output=json.dumps(result, default=str)[:8000],
                                    geoff_analysis=_critic_analysis,
                                )
                                step_record["critic"] = critic_val
                                critic_results.append(critic_val)
                                # Check for invalid IOCs flagged by critic
                                if isinstance(critic_val, dict) and critic_val.get("invalid_iocs"):
                                    step_record["invalid_iocs"] = critic_val["invalid_iocs"]

                                # Enforce Critic verdict with self-correction
                                if isinstance(critic_val, dict) and critic_val.get("passes_sanity") is False:
                                    issues = (critic_val.get("hallucinations") or []) + (critic_val.get("nonsense") or [])
                                    short = "; ".join(str(i) for i in issues[:2]) if issues else "sanity check failed"
                                    _fe_log(job_id, f"  ✗ Critic: {module}.{function} failed — {short}. Attempting self-correction...")

                                    # Self-correction: Manager generates revised analysis → re-validate with Critic
                                    correction = _manager_generate_correction(
                                        module=module, function=function,
                                        result=result,
                                        forensicator_notes=forensicator_notes,
                                        critic_issues=issues,
                                    )
                                    corrected = False
                                    if correction:
                                        corrected_analysis = (
                                            f"Find Evil auto-run (corrected): {playbook_id} → {module}.{function}\n"
                                            f"Corrected analysis: {correction.get('analyst_note', '')}\n"
                                            f"Corrected indicators: {', '.join(correction.get('threat_indicators', []))}"
                                        )
                                        try:
                                            critic_retry = geoff_critic.validate_tool_output(
                                                tool_name=f"{module}.{function}",
                                                tool_params=params,
                                                raw_output=json.dumps(result, default=str)[:8000],
                                                geoff_analysis=corrected_analysis,
                                            )
                                            if isinstance(critic_retry, dict) and critic_retry.get("passes_sanity") is True:
                                                # Correction accepted — update step with corrected interpretation
                                                step_record["forensicator"]["analyst_note"] = correction.get("analyst_note", forensicator_notes.get("analyst_note"))
                                                step_record["forensicator"]["threat_indicators"] = correction.get("threat_indicators", forensicator_notes.get("threat_indicators", []))
                                                step_record["self_corrected"] = True
                                                step_record["correction_reasoning"] = correction.get("correction_reasoning", "")
                                                step_record["critic"] = critic_retry
                                                critic_results.append(critic_retry)
                                                _fe_log(job_id, f"  ✓ Self-correction accepted by Critic for {module}.{function}")
                                                corrected = True
                                                _audit_append(
                                                    case_work_dir, "self_correction",
                                                    playbook_id=playbook_id, module=module, function=function,
                                                    device_id=device_id,
                                                )
                                        except Exception as retry_ce:
                                            _fe_log(job_id, f"  ⚠ Critic re-validation failed: {retry_ce}")

                                    if not corrected:
                                        # Correction failed or unavailable — demote to unverified
                                        if step_record.get("status") == "completed":
                                            step_record["status"] = "completed_unverified"
                                            step_record["needs_review"] = True
                                            steps_unverified += 1
                                        step_record["unverified_reason"] = issues[:5]
                                        _fe_log(job_id, f"  ✗ Critic: {module}.{function} UNVERIFIED — {short}")
                                        _audit_append(
                                            case_work_dir, "unverified",
                                            playbook_id=playbook_id, module=module, function=function,
                                            device_id=device_id, reason=issues[:5],
                                        )
                                elif isinstance(critic_val, dict) and critic_val.get("passes_sanity") is True:
                                    _fe_log(job_id, f"  ✓ Critic: {module}.{function} verified")
                                # Validate IOC formats from step result
                                try:
                                    result_iocs = {}
                                    if isinstance(result, dict):
                                        for ioc_key in ["iocs", "ips", "domains", "hashes", "urls", "emails"]:
                                            if ioc_key in result and isinstance(result[ioc_key], (dict, list)):
                                                result_iocs[ioc_key] = result[ioc_key] if isinstance(result[ioc_key], list) else list(result[ioc_key].values())
                                    if result_iocs:
                                        format_val = geoff_critic.validate_ioc_formats(result_iocs)
                                        if format_val.get("format_issue_count", 0) > 0:
                                            step_record["ioc_format_issues"] = format_val["format_issues"]
                                except Exception as ioc_exc:
                                    _fe_log(job_id, f"  ⚠ IOC format validation error for {module}.{function}: {ioc_exc}")
                                    step_record["ioc_format_validation_error"] = str(ioc_exc)
                                # Write validation to case validations/ directory
                                try:
                                    val_dir = case_work_dir / "validations"
                                    val_dir.mkdir(exist_ok=True)
                                    val_file = val_dir / f"{step_key.replace(':', '_')}.json"
                                    _atomic_write(val_file, json.dumps(critic_val, default=str, indent=2))
                                except OSError as write_exc:
                                    _fe_log(job_id, f"  ⚠ Could not write critic validation for {step_key}: {write_exc}")
                            except Exception as ce:
                                # Critic unavailable or errored — demote to unverified so
                                # unvalidated findings are never silently accepted.
                                _fe_log_with_exception(job_id, f"  ✗ Critic validation failed for {module}.{function}", ce)
                                step_record["critic_error"] = str(ce)
                                step_record["needs_review"] = True
                                if step_record.get("status") == "completed":
                                    step_record["status"] = "completed_unverified"
                                    steps_unverified += 1
                                _fe_log(job_id, f"  ⚠ {module}.{function} marked completed_unverified (critic unavailable)")
                        except Exception as e:
                            _fe_log_with_exception(job_id, f"  ✗ {module}.{function} step error", e)
                            step_record["status"] = "failed"
                            step_record["error"] = str(e)
                            steps_failed += 1

                        step_record["completed_at"] = datetime.now().isoformat()
                        findings_writer.append(step_record)
                        pb_findings.append(step_record)

                        # CONTINUE_ON_FAILURE enforcement
                        if step_record["status"] == "failed" and not CONTINUE_ON_FAILURE:
                            _fe_log(job_id, f"\u26a0 Step failed — stopping execution (CONTINUE_ON_FAILURE=false)")
                            # Break out of all loops
                            break

            # Check if we broke out due to failure
            if not CONTINUE_ON_FAILURE:
                failed_steps = [s for s in pb_findings if s.get("status") == "failed"]
                if failed_steps and any(s.get("step_key", "").startswith(playbook_id) for s in findings_writer.all_records()[-3:]):
                    break

            # Anti-forensics confidence cascade: if PB-SIFT-012 found indicators,
            # retroactively downgrade ALL findings and mark them compromised.
            # Uses word-boundary matching for single-word keywords to avoid false
            # positives (e.g. "del" matching "model", "delete", "delivered").
            if playbook_id == "PB-SIFT-012":
                anti_forensics_keywords = [
                    "log clear", "event log clear", "timestomp",
                    "anti-forensic", "wevtutil", "sdelete",
                    "eraser", "bleachbit", "cipher /w", "fsutil",
                    "ccleaner", "secure delete",
                ]
                anti_forensics_hit = False
                for step in pb_findings:
                    result = step.get("result", {})
                    if not isinstance(result, dict):
                        continue
                    # Check structured anti_forensics_detected field first
                    if result.get("anti_forensics_detected"):
                        anti_forensics_hit = True
                        break
                    # String match with word boundaries for single words
                    result_str = json.dumps(result, default=str).lower()
                    for kw in anti_forensics_keywords:
                        if " " in kw:
                            # Multi-word: substring match is safe
                            if kw in result_str:
                                anti_forensics_hit = True
                                break
                        else:
                            # Single-word: word boundary match to avoid false positives
                            if re.search(r'\b' + re.escape(kw) + r'\b', result_str):
                                anti_forensics_hit = True
                                break
                    if anti_forensics_hit:
                        break
                if anti_forensics_hit:
                    anti_forensics_detected = True
                    if "ANTI-FORENSICS-CONFIRMED" not in confidence_modifiers:
                        confidence_modifiers.append("ANTI-FORENSICS-CONFIRMED")
                    _fe_log(job_id, "\u26a0 PB-SIFT-012: Anti-forensics confirmed — retroactively downgrading all findings")
                    _audit_append(case_work_dir, "anti_forensics_cascade", device_id=device_id)
                    cascaded_now = _apply_anti_forensics_cascade(findings_writer)
                    _fe_log(job_id, f"  Cascade tagged {cascaded_now} existing findings (later findings will be tagged at job end)")

            playbooks_run.append({
                "playbook_id": playbook_id,
                "steps_attempted": len(pb_findings),
                "steps_completed": sum(1 for s in pb_findings if s.get("status") == "completed"),
                "steps_unverified": sum(1 for s in pb_findings if s.get("status") == "completed_unverified"),
                "steps_skipped": sum(1 for s in pb_findings if s.get("status") == "skipped"),
                "steps_failed": sum(1 for s in pb_findings if s.get("status") == "failed"),
            })
            _audit_append(
                case_work_dir, "playbook_complete",
                playbook_id=playbook_id, device_id=device_id,
                steps_attempted=len(pb_findings),
                steps_completed=sum(1 for s in pb_findings if s.get("status") == "completed"),
                steps_unverified=sum(1 for s in pb_findings if s.get("status") == "completed_unverified"),
                steps_failed=sum(1 for s in pb_findings if s.get("status") == "failed"),
            )

            # Git commit after each playbook — part of transaction, not optional
            try:
                # Write playbook findings to output dir
                pb_output = case_work_dir / "output" / f"{playbook_id}.json"
                # Compact large step results before writing
                for step in pb_findings:
                    if isinstance(step.get("result"), dict):
                        step["result"] = _compact_step_result(step["result"], case_work_dir)
                _atomic_write(pb_output, json.dumps(pb_findings, default=str, indent=2))
                git_result = safe_git_commit(f"{playbook_id}: {len(pb_findings)} steps ({steps_completed} ok, {steps_failed} fail, {steps_skipped} skip)", base_path=str(case_work_dir))
                if git_result["status"] == "failed":
                    _fe_log(job_id, f"  \u26a0 git commit failed for {playbook_id}: {git_result.get('error', 'unknown')}")
                    # In STRICT_MODE, treat git commit failure as step failure
                    if STRICT_MODE:
                        raise RuntimeError(f"Git commit failed: {git_result.get('error', 'unknown')}")
            except Exception as gce:
                _fe_log(job_id, f"  git commit failed: {gce}")
                if STRICT_MODE:
                    raise

    # End of per-device playbook loop
    # Process unattributed evidence (PCAPs, logs not tied to a device)
    if any(unattributed_ev.values()):
        _fe_log(job_id, "\nProcessing unattributed evidence...")
        for ev_type, files in unattributed_ev.items():
            if not files:
                continue
            _fe_log(job_id, f"  Unattributed {ev_type}: {len(files)} files")
            # Run relevant playbooks against unattributed evidence
            for pb_idx, playbook_id in enumerate(execution_plan):
                pb_steps_def = PLAYBOOK_STEPS.get(playbook_id, {})
                for ev_t, step_templates in pb_steps_def.items():
                    if ev_t == ev_type:
                        items = files[:3]
                        for item in items:
                            # Run steps with device_id="unattributed"
                            for module, function, params in step_templates:
                                try:
                                    step_key = f"{playbook_id}_unattributed_{module}_{function}"
                                    params_resolved = _resolve_params(params, item, image_offsets, case_work_dir, output_dir, os_type, inventory)
                                    if params_resolved is None:
                                        params_resolved = params
                                    result = orchestrator.run_playbook_step(playbook_id, {"module": module, "function": function, "params": params_resolved})
                                    findings_writer.append({
                                        "playbook": playbook_id,
                                        "module": module,
                                        "function": function,
                                        "device_id": "unattributed",
                                        "owner": None,
                                        "evidence_file": item,
                                        "status": "completed" if isinstance(result, dict) and result.get("status") == "success" else "failed",
                                        "result": result if isinstance(result, dict) else {"status": "unknown", "stdout": str(result)},
                                        "started_at": datetime.now().isoformat(),
                                        "completed_at": datetime.now().isoformat(),
                                    })
                                except Exception as e:
                                    _log_error(f"Unattributed evidence step failed: {module}.{function}", e)

    # If PB-SIFT-012 fired earlier in the plan, any findings produced by
    # later playbooks won't have been downgraded yet. Apply the cascade once
    # more now that every playbook has run. The helper is idempotent, so
    # findings already tagged by the first pass are skipped.
    if anti_forensics_detected:
        late = _apply_anti_forensics_cascade(findings_writer)
        if late:
            _fe_log(job_id, f"⚠ Anti-forensics cascade (final pass): downgraded {late} additional findings produced after PB-SIFT-012")
            _audit_append(case_work_dir, "anti_forensics_cascade_final", late_findings=late)

    # ------------------------------------------------------------------
    # Phase 3b-new: Super-Timeline Build
    # ------------------------------------------------------------------
    _update_job(90, "super-timeline", "Building unified timeline")
    try:
        super_tl = SuperTimeline()
        super_timeline_path, super_timeline_events = super_tl.build(
            device_map=device_map,
            findings=findings_writer.all_records(),
            case_work_dir=case_work_dir,
            plaso_specialist=orchestrator.plaso if hasattr(orchestrator, 'plaso') else None,
            job_id=job_id,
            fe_log_func=_fe_log,
        )
        _fe_log(job_id, f"Super-timeline: {len(super_timeline_events)} events across {len(device_map)} devices")
    except Exception as e:
        _fe_log(job_id, f"Super-timeline build failed: {e}")
        super_timeline_path = None
        super_timeline_events = []

    # ------------------------------------------------------------------
    # Phase 3c-new: Behavioral Analysis (per device)
    # ------------------------------------------------------------------
    _update_job(93, "behavioral", "Analyzing process and file behavior")
    try:
        behavioral = BehavioralAnalyzer()
        all_behavioral_flags = {}
        _all_findings = findings_writer.all_records()
        for dev_id in device_map:
            dev_findings = [f for f in _all_findings if f.get("device_id") == dev_id]
            dev_events = [e for e in super_timeline_events if e.get("device_id") == dev_id]
            flags = behavioral.analyze(
                device_id=dev_id,
                findings=dev_findings,
                timeline_events=dev_events,
                call_llm_func=call_llm,
            )
            all_behavioral_flags[dev_id] = flags
            if flags:
                _fe_log(job_id, f"  {dev_id}: {len(flags)} behavioral flags")

        # Tag super-timeline events with behavioral flags
        if hasattr(super_tl, 'apply_behavioral_flags'):
            super_tl.apply_behavioral_flags(super_timeline_events, all_behavioral_flags)
    except Exception as e:
        _fe_log(job_id, f"Behavioral analysis failed: {e}")
        all_behavioral_flags = {}

    # ------------------------------------------------------------------
    # Phase 3d-new: Cross-Host Correlation
    # ------------------------------------------------------------------
    _update_job(95, "correlation", "Correlating activity across hosts")
    try:
        correlator = HostCorrelator()
        correlated_users = correlator.correlate(
            device_map=device_map,
            user_map=user_map,
            findings=findings_writer.all_records(),
            timeline_events=super_timeline_events,
        )
        _fe_log(job_id, f"Correlated {len(correlated_users)} users across devices")
    except Exception as e:
        _fe_log(job_id, f"Cross-host correlation failed: {e}")
        correlated_users = {}
    # ------------------------------------------------------------------
    # ------------------------------------------------------------------
    # Phase 4: Aggregate Findings & Severity
    # ------------------------------------------------------------------
    _update_job(95, "reporting", "Aggregating findings", log_msg="Aggregating findings from all playbooks")

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    evil_found = False

    # From triage indicators — only POSSIBLE confidence from string/filename hits
    # evil_found requires CONFIRMED, or single CRITICAL/HIGH hit, or 2+ distinct POSSIBLE categories
    possible_categories = set()
    for hit in indicator_hits:
        sev = hit["severity"]
        confidence = hit.get("confidence", "POSSIBLE")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        if confidence == "CONFIRMED":
            evil_found = True
        elif sev in ("CRITICAL", "HIGH"):
            evil_found = True  # single high-severity hit is enough
        elif confidence == "POSSIBLE":
            possible_categories.add(hit["category"])
    if not evil_found and len(possible_categories) >= 2:
        evil_found = True

    # From behavioral flags (timeline_anomalies, suspicious persistence, etc.)
    if all_behavioral_flags:
        for dev_id, flags in all_behavioral_flags.items():
            for flag in flags:
                sev = flag.get("severity", "MEDIUM")
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
                # Timeline anomalies with off-hours activity = potential data exfil
                if flag.get("flag_type") == "timeline_anomaly":
                    severity_counts["MEDIUM"] += 1  # Boost severity
                    evil_found = True

    # From specialist results
    for f in findings_writer.all_records():
        result = f.get("result", {})
        if not isinstance(result, dict):
            continue
        # Volatility malfind
        if f.get("module") == "volatility" and f.get("function") == "find_malware":
            stdout = result.get("stdout", "")
            if stdout and "No malware" not in stdout and len(stdout.strip()) > 20:
                severity_counts["HIGH"] += 1
                evil_found = True
        # Critic flagged hallucinations — reduce confidence
        critic = f.get("critic", {})
        if isinstance(critic, dict) and not critic.get("valid", True):
            severity_counts["LOW"] += 1

    # Overall severity
    if severity_counts["CRITICAL"] > 0:
        overall_severity = "CRITICAL"
    elif severity_counts["HIGH"] > 0:
        overall_severity = "HIGH"
    elif severity_counts["MEDIUM"] > 0:
        overall_severity = "MEDIUM"
    elif severity_counts["LOW"] > 0:
        overall_severity = "LOW"
    else:
        overall_severity = "INFO"

    # Update classification for data exfiltration patterns from behavioral flags
    if all_behavioral_flags:
        for dev_id, flags in all_behavioral_flags.items():
            for flag in flags:
                if flag.get("flag_type") == "timeline_anomaly":
                    classification = "Data Exfil"
                    overall_severity = "HIGH"
                    evil_found = True
                    break
            if classification == "Data Exfil":
                break

    # Critic summary
    critic_approved = sum(1 for c in critic_results if isinstance(c, dict) and c.get("valid", False))
    critic_total = len(critic_results)
    critic_pct = (critic_approved / critic_total * 100) if critic_total > 0 else 100.0
    needs_review_count = sum(1 for f in findings_writer.all_records() if f.get("needs_review"))

    elapsed = time.time() - start_time

    # Dwell time and lateral movement chain
    try:
        attack_chain = _reconstruct_attack_chain(
            findings=findings_writer.all_records(),
            indicator_hits=indicator_hits,
            device_map=device_map if 'device_map' in dir() else {},
        )
    except Exception as _ac_err:
        _fe_log(job_id, f"Attack chain reconstruction failed: {_ac_err}")
        attack_chain = {}

    report = {
        "case_id": case_name,
        "title": f"Find Evil Report — {case_name}",
        "generated_at": datetime.now().isoformat(),
        "evidence_dir": str(evidence_dir),
        "os_type": os_type,
        "evil_found": evil_found,
        "severity": overall_severity,
        "classification": classification,
        "evidence_inventory": {
            k: v for k, v in inventory.items()
            if isinstance(v, list) and v
        },
        "severity_distribution": severity_counts,
        "indicator_hits": indicator_hits,
        "playbooks_run": playbooks_run,
        "playbooks_total": total_pb,
        "specialist_steps_executed": steps_completed + steps_failed + steps_skipped,
        "steps_completed": steps_completed,
        "steps_unverified": steps_unverified,
        "steps_failed": steps_failed,
        "steps_skipped": steps_skipped,
        "critic_approval_pct": round(critic_pct, 1),
        "steps_needs_review": needs_review_count,
        "findings_detail": findings_writer.all_records(),
        "findings_jsonl": str(findings_writer._path),
        "user_activity_summary": correlated_users if correlated_users is not None else {},
        "correlated_users": correlated_users if correlated_users is not None else {},
        "device_map": device_map if device_map is not None else {},
        "user_map": user_map if user_map is not None else {},
        "behavioral_flags_summary": {dev_id: len(flags) for dev_id, flags in all_behavioral_flags.items()} if all_behavioral_flags is not None else {},
        "behavioral_flags": {
            dev_id: [
                {k: v for k, v in flag.items() if k != "flag_id"}
                for flag in flags[:200]  # cap per device to keep JSON manageable
            ]
            for dev_id, flags in (all_behavioral_flags or {}).items()
        },
        "timeline": sorted(
            [
                {
                    "timestamp": e.get("timestamp", ""),
                    "device_id": e.get("device_id", ""),
                    "owner": e.get("owner", ""),
                    "event_type": e.get("event_type", ""),
                    "summary": e.get("summary", ""),
                    "severity": (
                        "CRITICAL" if "critical" in (e.get("suspicion_reason") or "").lower()
                        else "HIGH" if e.get("suspicious")
                        else "INFO"
                    ),
                    "suspicious": e.get("suspicious", False),
                    "suspicion_reason": e.get("suspicion_reason"),
                }
                for e in (super_timeline_events if super_timeline_events is not None else [])
                if e.get("timestamp")
            ],
            key=lambda e: (not e["suspicious"], e["timestamp"])
        )[:500],
        "elapsed_seconds": round(elapsed, 1),
        "case_work_dir": str(case_work_dir),
        "failures": [f for f in findings_writer.all_records() if f.get("status") == "failed"],
        "investigation_status": "complete" if steps_failed == 0 else "complete_with_failures",
        "confidence_modifiers": confidence_modifiers if 'confidence_modifiers' in dir() else [],
        "classification": classification if 'classification' in dir() else "Unknown",
        "evidence_inventory": {k: v for k, v in inventory.items() if isinstance(v, list)},
        "attack_chain": attack_chain,
        "llm_analysis": next((f["result"] for f in findings_writer.all_records() if f.get("playbook") == "ANALYSIS" and f.get("status") == "completed"), None),
    }

    # ------------------------------------------------------------------
    # Phase 5: Validate Investigation State (schema enforcement)
    # ------------------------------------------------------------------
    investigation_state = {
        "investigation_id": job_id or f"fe-{uuid.uuid4().hex[:8]}",
        "steps": [
            {
                "index": i,
                "module": f.get("module", "unknown"),
                "function": f.get("function", "unknown"),
                "status": f.get("status", "pending"),
                "started_at": f.get("started_at"),
                "completed_at": f.get("completed_at"),
                "result": f.get("result", {}),
            }
            for i, f in enumerate(findings_writer.all_records())
        ],
        "current_step": steps_completed + steps_failed + steps_skipped,
    }

    try:
        validate_investigation_state(investigation_state)
    except ValidationError as ve:
        report["schema_validation_warning"] = str(ve.message)

    # ------------------------------------------------------------------
    # Phase 5b: Narrative Report
    # ------------------------------------------------------------------
    _update_job(98, "narrative", "Generating human-readable report")
    try:
        narrator = NarrativeReportGenerator(call_llm_func=call_llm)
        # Collect CRITICAL/HIGH evidence anchors for traceable narrative citations
        step_evidence_anchors = [
            f["evidence_chain"]
            for f in findings_writer.all_records()
            if isinstance(f.get("evidence_chain"), dict)
            and f["evidence_chain"].get("significance") in ("CRITICAL", "HIGH")
        ][:30]
        narrative_path = narrator.generate(
            report_json=report,
            device_map=device_map if device_map is not None else {},
            user_map=user_map if user_map is not None else {},
            super_timeline_path=str(super_timeline_path) if super_timeline_path is not None and super_timeline_path else "",
            correlated_users=correlated_users if correlated_users is not None else {},
            behavioral_flags=all_behavioral_flags if all_behavioral_flags is not None else {},
            case_work_dir=case_work_dir,
            step_evidence_anchors=step_evidence_anchors,
        )
        report["narrative_report_path"] = str(narrative_path)
        _fe_log(job_id, f"Narrative report: {narrative_path}")
    except Exception as e:
        _fe_log(job_id, f"Narrative report generation failed: {e}")
        report["narrative_report_path"] = None

    # Write report
    report_path = case_work_dir / "reports" / "find_evil_report.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        report_content = json.dumps(report, indent=2, default=str)
        _atomic_write(report_path, report_content)
    except Exception as e:
        _fe_log(job_id, f"Failed to write final report: {e}")

    # Git commit final report
    try:
        git_commit_action(f"Find Evil complete: {case_name} | evil={evil_found} severity={severity}", base_path=str(case_work_dir))
    except Exception as e:
        _fe_log(job_id, f"git commit final report failed: {e}")

    # Log
    action_logger.log('FIND_EVIL', {
        'evidence_dir': evidence_dir,
        'evil_found': evil_found,
        'severity': overall_severity,
        'steps_executed': steps_completed + steps_failed + steps_skipped,
        'elapsed_seconds': round(elapsed, 1),
        'description': f"Find Evil run on {evidence_dir}",
    })

    _audit_append(
        case_work_dir, "find_evil_complete",
        job_id=job_id, case_name=case_name, evil_found=evil_found,
        severity=severity, elapsed_seconds=round(elapsed, 1),
        steps_completed=steps_completed, steps_failed=steps_failed,
        steps_skipped=steps_skipped,
    )
    _update_job(100, "complete", "Done", log_msg="\u2714 Find Evil complete")
    return report


# ---------------------------------------------------------------------------
# HTML Template (with Find Evil tab)
# ---------------------------------------------------------------------------

HTML_TEMPLATE = r"""
<!DOCTYPE html>
<html>
<head>
    <title>Geoff DFIR</title>
    <meta charset="UTF-8">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500;600&display=swap" rel="stylesheet">
    <!-- GEOFF_API_KEY_META -->
    <style>
        :root {
            --g-bg:          #0B1220;
            --g-bg-2:        #0F172A;
            --g-surface:     #1E293B;
            --g-surface-2:   #172033;
            --g-border:      #334155;
            --g-border-soft: #1F2A3F;
            --g-text:        #F1F5F9;
            --g-text-dim:    #94A3B8;
            --g-text-mute:   #64748B;
            --g-blue:        #3B82F6;
            --g-blue-soft:   #60A5FA;
            --g-green:       #10B981;
            --g-amber:       #F59E0B;
            --g-red:         #EF4444;
            --font-sans: "IBM Plex Sans", -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
            --font-mono: "IBM Plex Mono", "SF Mono", Menlo, Consolas, monospace;
            --radius: 6px;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: var(--font-sans);
            background: var(--g-bg);
            color: var(--g-text);
            height: 100vh;
            display: flex;
            flex-direction: column;
            font-size: 13px;
            line-height: 1.4;
            -webkit-font-smoothing: antialiased;
        }

        header {
            background: var(--g-bg-2);
            border-bottom: 1px solid var(--g-border-soft);
            padding: 0 16px;
            height: 48px;
            display: flex;
            align-items: center;
            gap: 20px;
            flex-shrink: 0;
        }

        .brand {
            display: flex;
            align-items: baseline;
            gap: 8px;
            font-family: var(--font-mono);
            font-weight: 600;
            letter-spacing: 0.5px;
        }

        .brand .logo {
            color: var(--g-blue-soft);
            font-size: 15px;
        }

        .brand .tag {
            color: var(--g-text-mute);
            font-size: 10px;
            letter-spacing: 1.5px;
            text-transform: uppercase;
        }

        .tabs {
            display: flex;
            gap: 2px;
            flex: 1;
        }

        .tab {
            padding: 6px 12px;
            cursor: pointer;
            color: var(--g-text-mute);
            border-radius: var(--radius);
            font-size: 12px;
            letter-spacing: 0.3px;
            transition: all 0.15s;
            border: none;
            background: none;
        }

        .tab:hover { color: var(--g-text-dim); background: var(--g-surface-2); }
        .tab.active {
            color: var(--g-blue-soft);
            background: rgba(59, 130, 246, 0.1);
        }

        .header-right {
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .status {
            display: flex;
            align-items: center;
            gap: 6px;
            color: var(--g-text-mute);
            font-family: var(--font-mono);
            font-size: 11px;
            letter-spacing: 0.3px;
        }

        .status .dot {
            width: 6px;
            height: 6px;
            border-radius: 50%;
            background: var(--g-green);
            flex-shrink: 0;
        }

        .content {
            flex: 1;
            overflow: hidden;
            display: none;
        }

        .content.active { display: flex; flex-direction: column; }

        /* Investigation output — chat messages + live log stream */
        #fe-output {
            flex: 1;
            overflow-y: auto;
            padding: 16px 20px;
            display: flex;
            flex-direction: column;
            gap: 10px;
            min-height: 0;
        }

        .message {
            max-width: 85%;
            padding: 10px 14px;
            border-radius: var(--radius);
            line-height: 1.6;
            font-size: 13px;
        }

        .message.user {
            align-self: flex-end;
            background: var(--g-blue);
            color: white;
        }

        .message.geoff {
            align-self: flex-start;
            background: var(--g-surface);
            border: 1px solid var(--g-border-soft);
            color: var(--g-text);
            white-space: pre-wrap;
        }

        .message.system {
            align-self: center;
            background: transparent;
            color: var(--g-text-mute);
            font-style: italic;
            font-size: 12px;
        }

        .message.tool-result {
            align-self: flex-start;
            background: rgba(16, 185, 129, 0.06);
            border: 1px solid rgba(16, 185, 129, 0.2);
            color: var(--g-text);
            font-family: var(--font-mono);
            font-size: 12px;
        }

        .message .label {
            font-size: 10px;
            font-weight: 600;
            margin-bottom: 4px;
            opacity: 0.7;
            text-transform: uppercase;
            letter-spacing: 0.8px;
        }

        .chat-input-area {
            padding: 12px 20px;
            background: var(--g-bg-2);
            border-top: 1px solid var(--g-border-soft);
            display: flex;
            gap: 8px;
        }

        #chat-input {
            flex: 1;
            padding: 9px 12px;
            background: var(--g-surface-2);
            border: 1px solid var(--g-border-soft);
            border-radius: var(--radius);
            color: var(--g-text);
            font-size: 13px;
            font-family: var(--font-sans);
        }

        #chat-input::placeholder { color: var(--g-text-mute); }

        #chat-input:focus {
            outline: none;
            border-color: var(--g-blue);
        }

        .send-btn {
            padding: 9px 20px;
            background: var(--g-green);
            color: white;
            border: none;
            border-radius: var(--radius);
            cursor: pointer;
            font-weight: 600;
            font-size: 13px;
            font-family: var(--font-sans);
            transition: opacity 0.15s;
        }

        .send-btn:hover { opacity: 0.85; }

        /* Evidence Styles */
        #evidence-content {
            flex: 1;
            overflow-y: auto;
            padding: 18px 20px;
        }

        .case-list {
            display: flex;
            flex-direction: column;
            gap: 12px;
        }

        .case-card {
            background: var(--g-bg-2);
            border: 1px solid var(--g-border-soft);
            border-radius: var(--radius);
            overflow: hidden;
        }

        .case-header {
            padding: 10px 14px;
            background: var(--g-surface-2);
            border-bottom: 1px solid var(--g-border-soft);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .case-name {
            font-family: var(--font-mono);
            font-weight: 600;
            color: var(--g-blue-soft);
            font-size: 12px;
        }

        .case-count {
            color: var(--g-text-mute);
            font-size: 11px;
            font-family: var(--font-mono);
        }

        .case-files {
            padding: 10px 14px;
        }

        .file-item {
            padding: 5px 0;
            border-bottom: 1px solid var(--g-border-soft);
            font-family: var(--font-mono);
            font-size: 11.5px;
            color: var(--g-text-dim);
        }

        .file-item:last-child { border-bottom: none; }

        .file-item.dir { color: var(--g-blue-soft); }
        .file-item.file { color: #A78BFA; }

        /* Find Evil Tab */
        #findevil-content {
            flex: 1;
            overflow: hidden;
            display: flex;
            flex-direction: column;
        }

        .fe-top-bar {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 9px 20px;
            background: var(--g-bg-2);
            border-bottom: 1px solid var(--g-border-soft);
            flex-shrink: 0;
        }

        .fe-top-bar label {
            color: var(--g-text-mute);
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.8px;
            white-space: nowrap;
            flex-shrink: 0;
        }

        .fe-top-bar input[type="text"] {
            flex: 1;
            padding: 7px 10px;
            background: var(--g-surface-2);
            border: 1px solid var(--g-border-soft);
            border-radius: var(--radius);
            color: var(--g-text);
            font-size: 12px;
            font-family: var(--font-mono);
        }

        .fe-top-bar input[type="text"]::placeholder { color: var(--g-text-mute); }

        .fe-top-bar input:focus {
            outline: none;
            border-color: var(--g-blue);
        }

        .fe-run-btn {
            padding: 7px 16px;
            background: var(--g-red);
            color: white;
            border: none;
            border-radius: var(--radius);
            cursor: pointer;
            font-weight: 600;
            font-size: 12px;
            font-family: var(--font-sans);
            transition: opacity 0.15s;
            white-space: nowrap;
            flex-shrink: 0;
        }

        .fe-run-btn:hover { opacity: 0.85; }
        .fe-run-btn:disabled { opacity: 0.4; cursor: not-allowed; }

        #fe-progress-area {
            flex-shrink: 0;
            padding: 10px 20px 0;
        }

        .fe-progress {
            background: var(--g-bg-2);
            border: 1px solid var(--g-border-soft);
            border-radius: var(--radius);
            padding: 10px 14px;
        }

        .fe-progress-bar {
            width: 100%;
            height: 18px;
            background: var(--g-surface);
            border-radius: 4px;
            overflow: hidden;
            margin: 8px 0;
        }

        .fe-progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #059669, var(--g-green));
            border-radius: 4px;
            transition: width 0.5s ease;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 10px;
            font-weight: 700;
            font-family: var(--font-mono);
            color: white;
            min-width: 36px;
        }

        .fe-status-text {
            color: var(--g-text-mute);
            font-size: 11.5px;
            font-family: var(--font-mono);
        }

        .fe-status-text strong {
            color: var(--g-text-dim);
            font-weight: 500;
        }

        .fe-results {
            background: var(--g-bg-2);
            border: 1px solid var(--g-border-soft);
            border-radius: var(--radius);
            padding: 14px;
        }

        .fe-severity {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 3px;
            font-weight: 600;
            font-size: 10px;
            font-family: var(--font-mono);
            letter-spacing: 0.5px;
            margin-bottom: 8px;
        }

        .fe-severity.CRITICAL { background: rgba(239,68,68,0.15);  color: #EF4444; }
        .fe-severity.HIGH     { background: rgba(245,158,11,0.15); color: #F59E0B; }
        .fe-severity.MEDIUM   { background: rgba(96,165,250,0.15); color: #60A5FA; }
        .fe-severity.LOW      { background: rgba(16,185,129,0.12); color: #10B981; }
        .fe-severity.INFO     { background: rgba(100,116,139,0.15);color: #64748B; }
        /* ORANGE classification for Data Exfil */
        .classification-Data-Exfil, .fe-severity.Data-Exfil { 
            background: rgba(251, 146, 60, 0.2); 
            color: #FB923C; 
            border: 1px solid #FB923C;
        }

        .fe-pb-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 8px;
            font-size: 12px;
        }

        .fe-pb-table th {
            text-align: left;
            padding: 7px 10px;
            border-bottom: 1px solid var(--g-border);
            color: var(--g-text-mute);
            font-weight: 500;
            letter-spacing: 0.5px;
            text-transform: uppercase;
            font-size: 10px;
        }

        .fe-pb-table td {
            padding: 5px 10px;
            border-bottom: 1px solid var(--g-border-soft);
            font-family: var(--font-mono);
            font-size: 11.5px;
        }

        .fe-pb-table .completed { color: var(--g-green); }
        .fe-pb-table .failed    { color: var(--g-red); }
        .fe-pb-table .skipped   { color: var(--g-text-mute); }

        /* Tools Panel */
        #tools-content {
            flex: 1;
            overflow-y: auto;
            padding: 18px 20px;
        }

        .tool-category {
            background: var(--g-bg-2);
            border: 1px solid var(--g-border-soft);
            border-radius: var(--radius);
            padding: 14px;
            margin-bottom: 12px;
        }

        .tool-category h3 {
            color: var(--g-blue-soft);
            margin-bottom: 10px;
            font-size: 12px;
            font-family: var(--font-mono);
            letter-spacing: 0.3px;
        }

        .tool-status {
            display: flex;
            align-items: center;
            gap: 8px;
            margin-bottom: 6px;
            font-size: 12px;
        }

        .tool-status.available   { color: var(--g-green); }
        .tool-status.unavailable { color: var(--g-red); }

        .tool-functions {
            font-family: var(--font-mono);
            font-size: 11px;
            color: var(--g-text-mute);
            margin-left: 18px;
        }

        .loading {
            text-align: center;
            padding: 40px;
            color: var(--g-text-mute);
            font-size: 12px;
        }

        /* Reports Tab */
        #reports-content {
            flex: 1;
            display: flex;
            overflow: hidden;
        }

        .reports-sidebar {
            width: 280px;
            flex-shrink: 0;
            background: var(--g-bg-2);
            border-right: 1px solid var(--g-border-soft);
            display: flex;
            flex-direction: column;
            overflow: hidden;
        }

        .reports-sidebar-header {
            padding: 10px 12px;
            border-bottom: 1px solid var(--g-border-soft);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .reports-sidebar-header h3 {
            color: var(--g-text-mute);
            font-size: 10px;
            text-transform: uppercase;
            letter-spacing: 1.2px;
            font-weight: 500;
        }

        .import-btn {
            padding: 4px 10px;
            background: none;
            color: var(--g-blue-soft);
            border: 1px solid var(--g-border);
            border-radius: 4px;
            cursor: pointer;
            font-size: 11px;
            font-family: var(--font-sans);
            white-space: nowrap;
            transition: all 0.12s;
        }

        .import-btn:hover {
            border-color: var(--g-blue);
            background: rgba(59, 130, 246, 0.08);
        }

        .reports-list {
            flex: 1;
            overflow-y: auto;
            padding: 6px;
        }

        .report-entry {
            padding: 9px 10px;
            border-radius: 4px;
            cursor: pointer;
            margin-bottom: 2px;
            border: 1px solid transparent;
            border-left: 2px solid transparent;
            transition: all 0.12s;
        }

        .report-entry:hover { background: var(--g-surface); border-color: var(--g-border-soft); }
        .report-entry.active { background: rgba(59,130,246,0.08); border-color: var(--g-border-soft); border-left-color: var(--g-blue); }

        .report-entry-name {
            font-family: var(--font-mono);
            font-size: 11.5px;
            color: var(--g-text);
            margin-bottom: 5px;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }

        .report-entry-meta {
            display: flex;
            gap: 5px;
            align-items: center;
            flex-wrap: wrap;
        }

        .report-ts {
            color: var(--g-text-mute);
            font-family: var(--font-mono);
            font-size: 10px;
            margin-top: 3px;
        }

        .evil-badge {
            display: inline-block;
            padding: 1px 6px;
            border-radius: 3px;
            font-family: var(--font-mono);
            font-size: 9px;
            font-weight: 600;
            letter-spacing: 0.5px;
        }

        .evil-badge.evil  { background: rgba(239,68,68,0.15);  color: #EF4444; }
        .evil-badge.clean { background: rgba(16,185,129,0.12); color: #10B981; }

        .reports-viewer {
            flex: 1;
            overflow-y: auto;
            padding: 18px 24px;
        }

        .reports-placeholder {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            height: 100%;
            color: var(--g-text-mute);
            font-size: 12px;
            text-align: center;
            gap: 10px;
            line-height: 1.6;
        }

        .stat-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(140px, 1fr));
            gap: 8px;
            margin-bottom: 18px;
        }

        .stat-card {
            background: var(--g-surface);
            border: 1px solid var(--g-border-soft);
            border-radius: var(--radius);
            padding: 10px 12px;
        }

        .stat-card .stat-label {
            color: var(--g-text-mute);
            font-size: 9.5px;
            text-transform: uppercase;
            letter-spacing: 0.8px;
            margin-bottom: 4px;
        }

        .stat-card .stat-value {
            color: var(--g-text);
            font-family: var(--font-mono);
            font-size: 18px;
            font-weight: 500;
            line-height: 1.1;
        }

        .report-section {
            margin-bottom: 20px;
        }

        .report-section h3 {
            font-size: 10px;
            text-transform: uppercase;
            letter-spacing: 1.2px;
            color: var(--g-text-mute);
            margin-bottom: 8px;
            padding-bottom: 6px;
            border-bottom: 1px solid var(--g-border-soft);
        }

        .chain-box {
            background: var(--g-surface);
            border: 1px solid var(--g-border-soft);
            border-radius: var(--radius);
            padding: 12px 16px;
        }

        .chain-box p {
            font-size: 12px;
            margin-bottom: 4px;
            color: var(--g-text);
            font-family: var(--font-mono);
        }

        .mitre-tag {
            display: inline-block;
            background: rgba(100,116,139,0.15);
            padding: 1px 6px;
            border-radius: 3px;
            font-family: var(--font-mono);
            font-size: 10px;
            margin: 2px;
            color: #A78BFA;
            letter-spacing: 0.3px;
        }

        .flag-box {
            background: var(--g-surface-2);
            border: 1px solid rgba(239,68,68,0.3);
            border-left: 3px solid var(--g-red);
            border-radius: var(--radius);
            padding: 10px 14px;
        }

        .flag-box p {
            color: var(--g-amber);
            font-family: var(--font-mono);
            font-size: 11.5px;
            margin-bottom: 3px;
        }

        .inv-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(130px, 1fr));
            gap: 6px;
        }

        .inv-card {
            background: var(--g-surface);
            border: 1px solid var(--g-border-soft);
            border-radius: var(--radius);
            padding: 8px 10px;
        }

        .inv-card .inv-type {
            color: var(--g-text-mute);
            font-size: 9.5px;
            text-transform: capitalize;
            letter-spacing: 0.3px;
            margin-bottom: 2px;
        }

        .inv-card .inv-count {
            color: var(--g-blue-soft);
            font-family: var(--font-mono);
            font-weight: 500;
            font-size: 18px;
            line-height: 1.1;
        }

        .raw-json-toggle {
            background: none;
            color: var(--g-text-mute);
            border: 1px solid var(--g-border);
            border-radius: 4px;
            padding: 4px 10px;
            cursor: pointer;
            font-size: 11px;
            font-family: var(--font-mono);
            transition: all 0.12s;
        }

        .raw-json-toggle:hover { color: var(--g-text); border-color: var(--g-text-mute); }

        /* Scrollbars */
        ::-webkit-scrollbar { width: 8px; height: 8px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: var(--g-border); border-radius: 4px; }
        ::-webkit-scrollbar-thumb:hover { background: var(--g-text-mute); }
    </style>
</head>
<body>
    <header>
        <div class="brand">
            <span class="logo">GEOFF</span>
            <span class="tag">DFIR Platform</span>
        </div>
        <div class="tabs">
            <div class="tab active" onclick="showTab('findevil')">Find Evil</div>
            <div class="tab" onclick="showTab('evidence')">Evidence</div>
            <div class="tab" onclick="showTab('reports')">Reports</div>
        </div>
        <div class="header-right">
            <div class="status"><span class="dot"></span>Online</div>
        </div>
    </header>

    <div id="reports" class="content">
        <div id="reports-content">
            <div class="reports-sidebar">
                <div class="reports-sidebar-header">
                    <h3>Past Cases</h3>
                    <button class="import-btn" onclick="importReportJSON()">⬆ Import JSON</button>
                </div>
                <div class="reports-list" id="reports-list">
                    <div style="padding:16px;color:#64748B;font-size:0.82rem;">Select the Reports tab to load cases.</div>
                </div>
            </div>
            <div class="reports-viewer" id="reports-viewer">
                <div class="reports-placeholder">
                    <div style="font-size:2rem;margin-bottom:8px;">📋</div>
                    <div>Select a completed case from the sidebar<br>or import a JSON report file.</div>
                </div>
            </div>
        </div>
    </div>

    <div id="evidence" class="content">
        <div id="evidence-content">
            <div class="loading">Loading evidence...</div>
        </div>
    </div>

    <div id="findevil" class="content active">
        <div id="findevil-content">

            <!-- Top bar: evidence directory + run button -->
            <div class="fe-top-bar">
                <label for="fe-evidence-dir">Evidence Directory</label>
                <input type="text" id="fe-evidence-dir" placeholder="Paste a folder name or full path…">
                <button class="fe-run-btn" id="fe-run-btn" onclick="runFindEvil()">🔍 Run Find Evil</button>
            </div>

            <!-- Progress bar — shown while a job is running -->
            <div id="fe-progress-area" style="display:none;">
                <div class="fe-progress">
                    <div class="fe-status-text">
                        <strong>Playbook:</strong> <span id="fe-pb-name">—</span> &nbsp;|
                        <strong>Step:</strong> <span id="fe-step-name">—</span> &nbsp;|
                        <strong>Elapsed:</strong> <span id="fe-elapsed">0s</span>
                    </div>
                    <div class="fe-progress-bar">
                        <div class="fe-progress-fill" id="fe-progress-fill" style="width:0%">0%</div>
                    </div>
                </div>
            </div>

            <!-- Unified output: chat messages + live log stream + results -->
            <div id="fe-output">
                <div class="message system">G.E.O.F.F. initialized. Evidence Operations Forensic Framework standing by.

Awaiting investigation directive. Provide an evidence path above or ask me anything below.</div>

                <!-- Live log stream — appended to when a job is running -->
                <div id="fe-log" style="
                    display: none;
                    background: #0B1220;
                    border: 1px solid #1F2A3F;
                    border-radius: 6px;
                    padding: 12px;
                    font-family: 'IBM Plex Mono', 'SF Mono', Menlo, monospace;
                    font-size: 11.5px;
                    color: #64748B;
                    line-height: 1.6;
                "></div>

                <!-- Results card — shown when job completes -->
                <div id="fe-results-area" style="display:none;"></div>
            </div>

            <!-- Chat input pinned at bottom -->
            <div class="chat-input-area">
                <input type="text" id="chat-input"
                       placeholder="Ask Geoff anything, or say 'start processing /path/to/evidence'..."
                       onkeypress="if(event.key==='Enter') sendChat()">
                <button class="send-btn" onclick="sendChat()">Send</button>
            </div>

        </div>
    </div>
    
    <script>
        // Authenticated fetch — adds X-API-Key header when the server set one
        const _geoffApiKey = document.querySelector('meta[name="geoff-api-key"]')?.content || '';
        function authFetch(url, opts = {}) {
            if (_geoffApiKey) {
                opts.headers = Object.assign({}, opts.headers || {}, {'X-API-Key': _geoffApiKey});
            }
            return fetch(url, opts);
        }

        // Evidence base directory (injected by server)
        const EVIDENCE_BASE_DIR = '<!-- GEOFF_EVIDENCE_BASE_DIR -->';

        // Pre-fill the evidence directory input with the server's base path
        document.addEventListener('DOMContentLoaded', () => {
            const inp = document.getElementById('fe-evidence-dir');
            if (inp && EVIDENCE_BASE_DIR) inp.value = EVIDENCE_BASE_DIR;
        });

        function showTab(tab) {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.content').forEach(c => c.classList.remove('active'));
            event.target.classList.add('active');
            document.getElementById(tab).classList.add('active');
            if (tab === 'evidence') loadEvidence();
            if (tab === 'reports') loadReports();
        }

        // ---- Reports Tab ----

        function _escHtml(s) {
            return (s || '').toString()
                .replace(/&/g,'&amp;').replace(/</g,'&lt;')
                .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
        }

        async function loadReports() {
            const list = document.getElementById('reports-list');
            list.innerHTML = '<div style="padding:12px;color:#64748B;font-size:0.85rem;">Loading...</div>';
            try {
                const res = await authFetch('/reports');
                const data = await res.json();
                const reports = data.reports || [];
                list.innerHTML = '';
                if (reports.length === 0) {
                    list.innerHTML = '<div style="padding:16px;color:#64748B;font-size:0.82rem;line-height:1.6;">No completed reports yet.<br>Run Find Evil on an evidence directory to generate one.</div>';
                    return;
                }
                reports.forEach(r => {
                    const entry = document.createElement('div');
                    entry.className = 'report-entry';
                    entry.dataset.dir = r.dir;
                    // Format timestamp: 20240115_120130 → 15/01/2024 12:01
                    let ts = '';
                    if (r.timestamp) {
                        const m = r.timestamp.match(/^(\d{4})(\d{2})(\d{2})_(\d{2})(\d{2})/);
                        if (m) ts = m[3]+'/'+m[2]+'/'+m[1]+' '+m[4]+':'+m[5];
                    }
                    entry.innerHTML =
                        '<div class="report-entry-name">' + _escHtml(r.case_name) + '</div>' +
                        '<div class="report-entry-meta">' +
                            '<span class="evil-badge ' + (r.evil_found ? 'evil' : 'clean') + '">' + (r.evil_found ? 'EVIL' : 'CLEAN') + '</span>' +
                            '<span class="fe-severity ' + _escHtml(r.severity) + '" style="font-size:0.7rem;padding:1px 6px;">' + _escHtml(r.severity) + '</span>' +
                        '</div>' +
                        (ts ? '<div class="report-ts">' + ts + '</div>' : '');
                    entry.addEventListener('click', () => {
                        document.querySelectorAll('.report-entry').forEach(e => e.classList.remove('active'));
                        entry.classList.add('active');
                        viewReport(r.dir, r.case_name);
                    });
                    // Double-click opens the graph viewer
                    entry.addEventListener('dblclick', () => {
                        const viewerUrl = '/reports/viewer?case=' + encodeURIComponent(r.dir);
                        window.open(viewerUrl, '_blank');
                    });
                    list.appendChild(entry);
                });
            } catch(e) {
                list.innerHTML = '<div style="padding:12px;color:#EF4444;font-size:0.82rem;">Error: ' + _escHtml(e.message) + '</div>';
            }
        }

        async function viewReport(caseDir, title) {
            const viewer = document.getElementById('reports-viewer');
            viewer.innerHTML = '<div class="reports-placeholder"><span>Loading report\u2026</span></div>';
            try {
                const res = await authFetch('/reports/' + encodeURIComponent(caseDir) + '/json');
                if (!res.ok) throw new Error('HTTP ' + res.status);
                const report = await res.json();
                const graphLink = '/reports/viewer?case=' + encodeURIComponent(caseDir);
                const graphBtn = '<button class="graph-open-btn" onclick="window.open(\'' + graphLink + '\', \'' + '_blank' + '\')" style="margin-bottom:12px;padding:6px 14px;background:rgba(59,130,246,0.15);border:1px solid #3b82f6;border-radius:4px;color:#60a5fa;cursor:pointer;font-size:12px;">🕸 View as Graph</button>';
                viewer.innerHTML = graphBtn + _renderReportHtml(report, title || caseDir);
            } catch(e) {
                viewer.innerHTML = '<div class="reports-placeholder"><span style="color:#EF4444;">Error: ' + _escHtml(e.message) + '</span></div>';
            }
        }

        function importReportJSON() {
            const inp = document.createElement('input');
            inp.type = 'file';
            inp.accept = '.json,application/json';
            inp.onchange = async (ev) => {
                const file = ev.target.files[0];
                if (!file) return;
                const viewer = document.getElementById('reports-viewer');
                viewer.innerHTML = '<div class="reports-placeholder"><span>Reading file\u2026</span></div>';
                try {
                    const text = await file.text();
                    const report = JSON.parse(text);
                    document.querySelectorAll('.report-entry').forEach(e => e.classList.remove('active'));
                    viewer.innerHTML = _renderReportHtml(report, file.name.replace(/\.json$/i, ''));
                } catch(e) {
                    viewer.innerHTML = '<div class="reports-placeholder"><span style="color:#EF4444;">Invalid JSON: ' + _escHtml(e.message) + '</span></div>';
                }
            };
            inp.click();
        }

        function _renderReportHtml(report, title) {
            const sev = report.severity || 'INFO';
            const evil = report.evil_found;
            const sevDist = report.severity_distribution || {};
            const chain = report.attack_chain || {};
            const mitreObs = chain.mitre_techniques_observed || [];
            const pbs = report.playbooks_run || [];
            const devMap = report.device_map || {};
            const flags = report.behavioral_flags_summary || {};
            const hits = report.indicator_hits || [];
            const inv = report.evidence_inventory || {};
            const failures = report.failures || [];
            const totalFlags = Object.values(flags).reduce((a, b) => a + b, 0);

            let h = '<div style="max-width:900px;">';

            // Header
            h += '<div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:20px;">';
            h += '<h2 style="color:#60A5FA;font-size:1.2rem;margin:0;">' + _escHtml(title) + '</h2>';
            h += '<span class="evil-badge ' + (evil ? 'evil' : 'clean') + '" style="font-size:0.85rem;padding:4px 12px;">' + (evil ? '\uD83D\uDD34 EVIL FOUND' : '\uD83D\uDFE2 CLEAN') + '</span>';
            h += '<span class="fe-severity ' + _escHtml(sev) + '">' + _escHtml(sev) + '</span>';
            h += '</div>';

            // Key stats
            const elapsed = ((report.elapsed_seconds || 0)).toFixed(1);
            const stepsFailed = pbs.reduce((a, pb) => a + (pb.steps_failed || 0), 0);
            h += '<div class="stat-grid">';
            [
                ['Classification', report.classification || '\u2014'],
                ['OS', report.os_type || '\u2014'],
                ['Elapsed', elapsed + 's'],
                ['Playbooks Run', pbs.length],
                ['Critic Approval', (report.critic_approval_pct || 0) + '%'],
                ['Steps Failed', stepsFailed],
            ].forEach(([label, val]) => {
                h += '<div class="stat-card"><div class="stat-label">' + label + '</div><div class="stat-value">' + _escHtml(String(val)) + '</div></div>';
            });
            h += '</div>';

            // Severity distribution
            const hasSev = Object.values(sevDist).some(v => v > 0);
            if (hasSev) {
                h += '<div class="report-section"><h3>Indicator Distribution</h3><div style="display:flex;gap:8px;flex-wrap:wrap;">';
                for (const [k, v] of Object.entries(sevDist)) {
                    if (v > 0) h += '<span class="fe-severity ' + _escHtml(k) + '">' + _escHtml(k) + ': ' + v + '</span>';
                }
                h += '</div></div>';
            }

            // Attack chain
            if (chain.dwell_days !== undefined || (chain.lateral_movement_path || []).length || mitreObs.length) {
                h += '<div class="report-section"><h3 style="color:#F59E0B;">\u26D3 Attack Chain</h3><div class="chain-box">';
                if (chain.first_seen_ts) h += '<p><strong>First Seen:</strong> ' + _escHtml(chain.first_seen_ts) + '</p>';
                if (chain.last_seen_ts)  h += '<p><strong>Last Seen:</strong> '  + _escHtml(chain.last_seen_ts)  + '</p>';
                if (chain.dwell_days !== undefined) h += '<p><strong>Dwell Time:</strong> ' + chain.dwell_days + ' days</p>';
                if ((chain.lateral_movement_path || []).length)
                    h += '<p><strong>Lateral Movement:</strong> ' + chain.lateral_movement_path.map(_escHtml).join(' \u2192 ') + '</p>';
                if ((chain.kill_chain_phases || []).length)
                    h += '<p><strong>Kill Chain:</strong> ' + chain.kill_chain_phases.map(_escHtml).join(', ') + '</p>';
                if (mitreObs.length) {
                    h += '<div style="margin-top:10px;"><strong style="font-size:0.82rem;color:#64748B;">MITRE Techniques Observed</strong><div style="margin-top:6px;">';
                    h += mitreObs.map(t => '<span class="mitre-tag">' + _escHtml(t) + '</span>').join('');
                    h += '</div></div>';
                }
                h += '</div></div>';
            }

            // Playbooks
            if (pbs.length > 0) {
                h += '<div class="report-section"><h3>Playbooks</h3>';
                h += '<table class="fe-pb-table"><tr><th>Playbook</th><th>Completed</th><th>Skipped</th><th>Failed</th></tr>';
                pbs.forEach(pb => {
                    h += '<tr><td>' + _escHtml(pb.playbook_id) + '</td>'
                       + '<td class="' + (pb.steps_completed > 0 ? 'completed' : '') + '">' + (pb.steps_completed||0) + '</td>'
                       + '<td class="' + (pb.steps_skipped  > 0 ? 'skipped'   : '') + '">' + (pb.steps_skipped ||0) + '</td>'
                       + '<td class="' + (pb.steps_failed   > 0 ? 'failed'    : '') + '">' + (pb.steps_failed  ||0) + '</td></tr>';
                });
                h += '</table></div>';
            }

            // Devices
            if (Object.keys(devMap).length > 0) {
                h += '<div class="report-section"><h3>Devices Discovered</h3>';
                h += '<table class="fe-pb-table"><tr><th>Device</th><th>Type</th><th>Owner</th><th>OS</th><th>Files</th></tr>';
                for (const [devId, dev] of Object.entries(devMap)) {
                    h += '<tr><td>' + _escHtml(devId) + '</td>'
                       + '<td>' + _escHtml(dev.device_type||'\u2014') + '</td>'
                       + '<td>' + _escHtml(dev.owner||'\u2014') + '</td>'
                       + '<td>' + _escHtml(dev.os_type||'\u2014') + '</td>'
                       + '<td>' + (dev.evidence_files ? dev.evidence_files.length : 0) + '</td></tr>';
                }
                h += '</table></div>';
            }

            // Users/Accounts
            const userMap = report.user_map || {};
            const userEntries = Object.entries(userMap).filter(([k, v]) => k !== 'users' && typeof v === 'object');
            if (userEntries.length > 0) {
                h += '<div class="report-section"><h3 style="color:#60A5FA;">\ud83d\udc64 Accounts Discovered</h3>';
                h += '<table class="fe-pb-table"><tr><th>Username</th><th>SID</th><th>Last Login</th><th>Profile Path</th></tr>';
                for (const [uname, udata] of userEntries) {
                    if (typeof udata !== 'object') continue;
                    h += '<tr><td><strong>' + _escHtml(uname) + '</strong></td>'
                       + '<td><code style="font-size:0.75rem;">' + _escHtml(udata.sid || udata.SID || '\u2014') + '</code></td>'
                       + '<td>' + _escHtml(udata.last_login || udata.lastLogon || '\u2014') + '</td>'
                       + '<td style="font-size:0.78rem;color:#64748B;">' + _escHtml(udata.profile_path || udata.homeDir || '\u2014') + '</td></tr>';
                }
                h += '</table></div>';
            }

            // Correlated Users / Relationships
            const corrUsers = report.correlated_users || {};
            const corrEntries = Object.entries(corrUsers).filter(([k, v]) => typeof v === 'object');
            if (corrEntries.length > 0) {
                h += '<div class="report-section"><h3 style="color:#10B981;">\ud83d\udd17 User Relationships</h3>';
                for (const [uname, cdata] of corrEntries) {
                    h += '<div style="background:rgba(16,185,129,0.1);border:1px solid #10B981;border-radius:6px;padding:12px;margin-bottom:10px;">';
                    h += '<h4 style="margin:0 0 8px 0;color:#10B981;">\ud83d\udc64 ' + _escHtml(uname) + '</h4>';
                    if (cdata.devices && cdata.devices.length > 0) {
                        h += '<p style="margin:4px 0;font-size:0.82rem;"><strong>Devices:</strong> ' + cdata.devices.map(_escHtml).join(', ') + '</p>';
                    }
                    if (cdata.activity_profile) {
                        const prof = cdata.activity_profile;
                        if (prof.total_events) {
                            h += '<p style="margin:4px 0;font-size:0.82rem;"><strong>Total Events:</strong> ' + prof.total_events + '</p>';
                        }
                        if (prof.typical_hours && prof.typical_hours.length > 0) {
                            h += '<p style="margin:4px 0;font-size:0.82rem;"><strong>Active Hours:</strong> ' + prof.typical_hours.join(', ') + '</p>';
                        }
                    }
                    if (cdata.lateral_movement_indicators && cdata.lateral_movement_indicators.length > 0) {
                        h += '<div style="margin-top:8px;padding:8px;background:rgba(239,68,68,0.1);border-radius:4px;">';
                        h += '<strong style="color:#EF4444;font-size:0.82rem;">\u26a0 Lateral Movement Detected:</strong>';
                        cdata.lateral_movement_indicators.forEach(lm => {
                            h += '<div style="font-size:0.78rem;margin-top:4px;color:#cbd5e1;">';
                            h += _escHtml(lm.from_device) + ' \u2192 ' + _escHtml(lm.to_device) + ' via ' + _escHtml(lm.method);
                            h += '</div>';
                        });
                        h += '</div>';
                    }
                    h += '</div>';
                }
                h += '</div>';
            }

            // Behavioral flags
            if (totalFlags > 0) {
                h += '<div class="report-section"><h3 style="color:#EF4444;">\u26A0 Behavioral Flags: ' + totalFlags + '</h3><div class="flag-box">';
                for (const [devId, count] of Object.entries(flags)) {
                    if (count > 0) h += '<p>' + _escHtml(devId) + ': ' + count + ' flag' + (count !== 1 ? 's' : '') + '</p>';
                }
                h += '</div></div>';
            }

            // Indicator hits
            if (hits.length > 0) {
                h += '<div class="report-section"><h3>Indicator Hits (' + hits.length + ')</h3>';
                h += '<div style="max-height:280px;overflow-y:auto;border:1px solid #1F2A3F;border-radius:6px;">';
                h += '<table class="fe-pb-table" style="margin-top:0;"><tr><th>Category</th><th>Pattern</th><th>Severity</th><th>File</th></tr>';
                const shown = hits.slice(0, 100);
                shown.forEach(hit => {
                    const sc = hit.severity || 'INFO';
                    const fileParts = (hit.file || '').replace(/\\/g,'/').split('/');
                    const shortFile = fileParts.slice(-2).join('/');
                    h += '<tr>'
                       + '<td>' + _escHtml(hit.category||'') + '</td>'
                       + '<td><code style="font-size:0.8rem;">' + _escHtml(hit.pattern||'') + '</code></td>'
                       + '<td><span class="fe-severity ' + sc + '" style="font-size:0.7rem;padding:1px 5px;">' + sc + '</span></td>'
                       + '<td style="font-size:0.78rem;color:#64748B;" title="' + _escHtml(hit.file||'') + '">' + _escHtml(shortFile) + '</td>'
                       + '</tr>';
                });
                if (hits.length > 100) h += '<tr><td colspan="4" style="color:#64748B;text-align:center;padding:8px;">\u2026 ' + (hits.length-100) + ' more hits not shown</td></tr>';
                h += '</table></div></div>';
            }

            // Evidence inventory
            const hasInv = Object.values(inv).some(v => Array.isArray(v) && v.length > 0);
            if (hasInv) {
                h += '<div class="report-section"><h3>Evidence Inventory</h3><div class="inv-grid">';
                for (const [type, items] of Object.entries(inv)) {
                    if (Array.isArray(items) && items.length > 0) {
                        h += '<div class="inv-card">'
                           + '<div class="inv-type">' + _escHtml(type.replace(/_/g,' ')) + '</div>'
                           + '<div class="inv-count">' + items.length + '</div>'
                           + '</div>';
                    }
                }
                h += '</div></div>';
            }

            // Failures
            if (failures.length > 0) {
                h += '<div class="report-section"><h3 style="color:#EF4444;">Failed Steps (' + failures.length + ')</h3>';
                failures.slice(0, 15).forEach(f => {
                    h += '<div style="background:#0F172A;border:1px solid #334155;border-radius:4px;padding:6px 10px;margin-bottom:4px;font-size:0.82rem;">'
                       + '<span style="color:#EF4444;">' + _escHtml((f.playbook||'') + ' / ' + (f.step||'')) + '</span>'
                       + (f.error ? '<span style="color:#64748B;"> \u2014 ' + _escHtml(f.error) + '</span>' : '')
                       + '</div>';
                });
                h += '</div>';
            }

            // Raw JSON toggle
            h += '<div class="report-section">';
            h += '<button class="raw-json-toggle" onclick="var p=this.nextElementSibling;p.style.display=p.style.display===\'none\'?\'block\':\'none\';this.textContent=p.style.display===\'none\'?\'{ } Show Raw JSON\':\'{ } Hide Raw JSON\';">{ } Show Raw JSON</button>';
            h += '<pre style="display:none;margin-top:8px;background:#0B1220;border:1px solid #334155;border-radius:6px;padding:14px;overflow:auto;font-size:0.75rem;color:#64748B;max-height:400px;">'
               + _escHtml(JSON.stringify(report, null, 2)) + '</pre>';
            h += '</div>';

            h += '</div>';
            return h;
        }

        // Append a message bubble to the unified output area and scroll to bottom.
        function addMessage(text, type) {
            const output = document.getElementById('fe-output');
            const div = document.createElement('div');
            div.className = 'message ' + type;
            if (type === 'user') {
                const label = document.createElement('div');
                label.className = 'label';
                label.textContent = 'You';
                div.appendChild(label);
                const body = document.createElement('span');
                body.textContent = text;
                div.appendChild(body);
            } else if (type === 'geoff') {
                const label = document.createElement('div');
                label.className = 'label';
                label.textContent = 'Geoff';
                div.appendChild(label);
                const body = document.createElement('span');
                body.style.whiteSpace = 'pre-wrap';
                body.textContent = text;
                div.appendChild(body);
            } else if (type === 'tool-result') {
                const label = document.createElement('div');
                label.className = 'label';
                label.textContent = 'Tool Output';
                div.appendChild(label);
                const body = document.createElement('span');
                body.textContent = text;
                div.appendChild(body);
            } else {
                div.textContent = text;
            }
            // Insert before the log and results divs so messages stay above them
            const logDiv = document.getElementById('fe-log');
            output.insertBefore(div, logDiv);
            output.scrollTop = output.scrollHeight;
        }

        // Placeholder shown while waiting for the server response
        let _thinkingDiv = null;
        function _showThinking() {
            _thinkingDiv = document.createElement('div');
            _thinkingDiv.className = 'message system';
            _thinkingDiv.textContent = 'Thinking...';
            const logDiv = document.getElementById('fe-log');
            document.getElementById('fe-output').insertBefore(_thinkingDiv, logDiv);
            document.getElementById('fe-output').scrollTop = document.getElementById('fe-output').scrollHeight;
        }
        function _removeThinking() {
            if (_thinkingDiv && _thinkingDiv.parentNode) {
                _thinkingDiv.parentNode.removeChild(_thinkingDiv);
            }
            _thinkingDiv = null;
        }

        async function sendChat() {
            const input = document.getElementById('chat-input');
            const text = input.value.trim();
            if (!text) return;

            input.disabled = true;
            addMessage(text, 'user');
            input.value = '';
            _showThinking();

            try {
                const res = await authFetch('/chat', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({message: text})
                });
                const data = await res.json();
                _removeThinking();

                if (data.response) addMessage(data.response, 'geoff');
                if (data.tool_result) addMessage(JSON.stringify(data.tool_result, null, 2), 'tool-result');

                // If the chat triggered a Find Evil job, start the live stream
                if (data.job_id) {
                    _startFindEvilStream(data.job_id);
                }
            } catch (e) {
                _removeThinking();
                addMessage('Error: ' + e.message, 'system');
            } finally {
                input.disabled = false;
                input.focus();
            }
        }

        // Shared helper: prepare the UI for a new streaming job
        function _startFindEvilStream(jobId) {
            const progressArea = document.getElementById('fe-progress-area');
            const logDiv = document.getElementById('fe-log');
            const resultsArea = document.getElementById('fe-results-area');

            // Reset state
            progressArea.style.display = 'block';
            logDiv.style.display = 'block';
            logDiv.innerHTML = '';
            resultsArea.style.display = 'none';
            resultsArea.innerHTML = '';

            document.getElementById('fe-pb-name').textContent = 'Starting...';
            document.getElementById('fe-step-name').textContent = '';
            document.getElementById('fe-elapsed').textContent = '0s';
            document.getElementById('fe-progress-fill').style.width = '0%';
            document.getElementById('fe-progress-fill').textContent = '0%';

            pollFindEvilStatus(jobId);
        }
        
        async function loadEvidence() {
            const container = document.getElementById('evidence-content');
            container.innerHTML = '<div class="loading">Loading...</div>';

            try {
                const res = await authFetch('/cases');
                const data = await res.json();
                const cases = data.cases || {};

                container.innerHTML = '';

                if (Object.keys(cases).length === 0) {
                    const empty = document.createElement('div');
                    empty.className = 'loading';
                    empty.textContent = 'No cases found.';
                    container.appendChild(empty);
                    return;
                }

                const list = document.createElement('div');
                list.className = 'case-list';

                for (const [caseName, files] of Object.entries(cases)) {
                    const card = document.createElement('div');
                    card.className = 'case-card';

                    const header = document.createElement('div');
                    header.className = 'case-header';
                    header.title = 'Click to load this case into Find Evil';
                    header.style.cursor = 'pointer';

                    const fullPath = EVIDENCE_BASE_DIR
                        ? EVIDENCE_BASE_DIR.replace(/\/+$/, '') + '/' + caseName
                        : caseName;

                    header.addEventListener('click', () => {
                        document.getElementById('fe-evidence-dir').value = fullPath;
                        // Notify server of active directory for chat
                        authFetch('/active-directory', {
                            method: 'POST',
                            headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify({directory: fullPath})
                        });
                        // Switch to Find Evil tab
                        document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
                        document.querySelectorAll('.content').forEach(c => c.classList.remove('active'));
                        document.querySelector('.tab[onclick*="findevil"]').classList.add('active');
                        document.getElementById('findevil').classList.add('active');
                    });

                    const nameSpan = document.createElement('span');
                    nameSpan.className = 'case-name';
                    nameSpan.textContent = '\U0001F4C1 ' + caseName;

                    const countSpan = document.createElement('span');
                    countSpan.className = 'case-count';
                    countSpan.textContent = files.length + ' items';

                    const investigateBtn = document.createElement('button');
                    investigateBtn.textContent = '🔍 Investigate';
                    investigateBtn.style.cssText = 'margin-left:8px;padding:2px 8px;font-size:11px;cursor:pointer;background:#238636;color:#fff;border:none;border-radius:4px;';
                    investigateBtn.title = 'Load into Find Evil and run';
                    investigateBtn.addEventListener('click', (e) => {
                        e.stopPropagation();
                        document.getElementById('fe-evidence-dir').value = fullPath;
                        // Notify server of active directory for chat
                        authFetch('/active-directory', {
                            method: 'POST',
                            headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify({directory: fullPath})
                        });
                        document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
                        document.querySelectorAll('.content').forEach(c => c.classList.remove('active'));
                        document.querySelector('.tab[onclick*="findevil"]').classList.add('active');
                        document.getElementById('findevil').classList.add('active');
                        runFindEvil();
                    });

                    header.appendChild(nameSpan);
                    header.appendChild(countSpan);
                    header.appendChild(investigateBtn);

                    const filesDiv = document.createElement('div');
                    filesDiv.className = 'case-files';

                    if (files.length === 0) {
                        const empty = document.createElement('div');
                        empty.className = 'file-item';
                        empty.textContent = 'Empty case';
                        filesDiv.appendChild(empty);
                    } else {
                        files.forEach(f => {
                            const isDir = f.startsWith('[DIR]');
                            const item = document.createElement('div');
                            item.className = 'file-item ' + (isDir ? 'dir' : 'file');
                            item.textContent = isDir ? f.replace('[DIR] ', '') : f;
                            filesDiv.appendChild(item);
                        });
                    }

                    card.appendChild(header);
                    card.appendChild(filesDiv);
                    list.appendChild(card);
                }

                container.appendChild(list);
            } catch (e) {
                container.innerHTML = '';
                const err = document.createElement('div');
                err.className = 'loading';
                err.textContent = 'Error loading evidence: ' + e.message;
                container.appendChild(err);
            }
        }
        
        // ---- Find Evil UI ----
        let fePollInterval = null;

        async function runFindEvil() {
            const evidenceDir = document.getElementById('fe-evidence-dir').value.trim();
            const btn = document.getElementById('fe-run-btn');

            btn.disabled = true;
            btn.textContent = '⏳ Running...';

            const label = evidenceDir || 'default evidence directory';
            addMessage('Starting Find Evil on ' + label + ' …', 'system');

            try {
                const res = await authFetch('/find-evil', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ evidence_dir: evidenceDir || '' })
                });
                const data = await res.json();

                if (data.job_id) {
                    _startFindEvilStream(data.job_id);
                } else if (data.status === 'error') {
                    showFindEvilError(data.error || 'Unknown error');
                    btn.disabled = false;
                    btn.textContent = '🔍 Run Find Evil';
                } else {
                    showFindEvilResults(data);
                    btn.disabled = false;
                    btn.textContent = '🔍 Run Find Evil';
                }
            } catch (e) {
                showFindEvilError(e.message);
                btn.disabled = false;
                btn.textContent = '🔍 Run Find Evil';
            }
        }

        function pollFindEvilStatus(jobId) {
            if (fePollInterval) clearInterval(fePollInterval);
            let lastLogIndex = 0;
            const output = document.getElementById('fe-output');

            const poll = async () => {
                try {
                    const res = await authFetch('/find-evil/status/' + jobId);
                    if (res.ok) {
                        const status = await res.json();
                        const pct = status.progress_pct || 0;
                        document.getElementById('fe-pb-name').textContent = status.current_playbook || '—';
                        document.getElementById('fe-step-name').textContent = status.current_step || '';
                        document.getElementById('fe-elapsed').textContent = (status.elapsed_seconds || 0).toFixed(0) + 's';
                        document.getElementById('fe-progress-fill').style.width = pct + '%';
                        document.getElementById('fe-progress-fill').textContent = pct + '%';

                        // Stream log entries into the log div
                        if (status.log && status.log.length > lastLogIndex) {
                            const logDiv = document.getElementById('fe-log');
                            for (let i = lastLogIndex; i < status.log.length; i++) {
                                const entry = status.log[i];
                                const line = document.createElement('div');
                                const time = entry.time || '';
                                const msg = entry.msg || '';
                                let color = '#8b949e';
                                if (msg.includes('✓') || msg.includes('complete')) color = '#3fb950';
                                else if (msg.includes('✗') || msg.includes('error') || msg.includes('fail')) color = '#f85149';
                                else if (msg.includes('▶')) color = '#d29922';
                                else if (msg.includes('⊘') || msg.includes('skip')) color = '#6e7681';
                                else if (msg.includes('needs_review') || msg.includes('⚠')) color = '#d29922';
                                line.style.color = color;
                                line.textContent = time + '  ' + msg;
                                logDiv.appendChild(line);
                            }
                            lastLogIndex = status.log.length;
                            output.scrollTop = output.scrollHeight;
                        }

                        if (status.status === 'complete') {
                            clearInterval(fePollInterval);
                            showFindEvilResults(status.result || {});
                            document.getElementById('fe-run-btn').disabled = false;
                            document.getElementById('fe-run-btn').textContent = '🔍 Run Find Evil';
                        } else if (status.status === 'error') {
                            clearInterval(fePollInterval);
                            showFindEvilError(status.error || 'Unknown error');
                            document.getElementById('fe-run-btn').disabled = false;
                            document.getElementById('fe-run-btn').textContent = '🔍 Run Find Evil';
                        }
                    }
                } catch (e) {
                    console.error('Find Evil poll error:', e);
                }
            };

            poll();
            fePollInterval = setInterval(poll, 2000);
        }

        function showFindEvilResults(report) {
            const area = document.getElementById('fe-results-area');
            area.style.display = 'block';

            const sev = report.severity || 'INFO';
            const evil = report.evil_found;
            const sevDist = report.severity_distribution || {};

            let html = '<div class="fe-results">';
            html += '<h3 style="color:#60A5FA; margin-bottom:10px;">Find Evil Report</h3>';
            html += '<div class="fe-severity ' + sev + '">' + sev + '</div>';
            html += '<p style="margin-bottom:8px;"><strong>Evil Found:</strong> ' + (evil ? '🔴 YES' : '🟢 NO') + '</p>';
            html += '<p style="margin-bottom:8px;"><strong>OS:</strong> ' + (report.os_type || 'unknown') + ' &nbsp;|&nbsp; <strong>Elapsed:</strong> ' + (report.elapsed_seconds || 0).toFixed(1) + 's</p>';

            html += '<p style="margin-bottom:6px;"><strong>Severity Distribution:</strong> ';
            for (const [k, v] of Object.entries(sevDist)) {
                if (v > 0) html += '<span class="fe-severity ' + k + '" style="font-size:0.75rem;padding:2px 8px;margin:2px;">' + k + ': ' + v + '</span> ';
            }
            html += '</p>';

            html += '<p style="margin-bottom:6px;"><strong>Critic Approval:</strong> ' + (report.critic_approval_pct || 0) + '%</p>';

            const pbs = report.playbooks_run || [];
            if (pbs.length > 0) {
                html += '<table class="fe-pb-table"><tr><th>Playbook</th><th>Completed</th><th>Skipped</th><th>Failed</th></tr>';
                pbs.forEach(pb => {
                    const cClass = pb.steps_completed > 0 ? 'completed' : '';
                    const sClass = pb.steps_skipped > 0 ? 'skipped' : '';
                    const fClass = pb.steps_failed > 0 ? 'failed' : '';
                    html += '<tr><td>' + pb.playbook_id + '</td>';
                    html += '<td class="' + cClass + '">' + pb.steps_completed + '</td>';
                    html += '<td class="' + sClass + '">' + pb.steps_skipped + '</td>';
                    html += '<td class="' + fClass + '">' + pb.steps_failed + '</td></tr>';
                });
                html += '</table>';
            }

            // Device Map
            if (report.device_map && Object.keys(report.device_map).length > 0) {
                html += '<h4 style="color:#60A5FA;margin-top:16px;">Devices Discovered</h4>';
                html += '<table class="fe-pb-table"><tr><th>Device</th><th>Type</th><th>Owner</th><th>OS</th><th>Files</th></tr>';
                for (const [devId, dev] of Object.entries(report.device_map)) {
                    html += '<tr>';
                    html += '<td>' + devId + '</td>';
                    html += '<td>' + (dev.device_type || 'unknown') + '</td>';
                    html += '<td>' + (dev.owner || '—') + '</td>';
                    html += '<td>' + (dev.os_type || '—') + '</td>';
                    html += '<td>' + (dev.evidence_files ? dev.evidence_files.length : 0) + '</td>';
                    html += '</tr>';
                }
                html += '</table>';
            }

            // Behavioral Flags Summary
            if (report.behavioral_flags_summary) {
                const total = Object.values(report.behavioral_flags_summary).reduce((a,b) => a+b, 0);
                if (total > 0) {
                    html += '<h4 style="color:#EF4444;margin-top:16px;">⚠ Behavioral Flags: ' + total + '</h4>';
                    for (const [devId, count] of Object.entries(report.behavioral_flags_summary)) {
                        if (count > 0) {
                            html += '<p style="color:#F59E0B;">' + devId + ': ' + count + ' flags</p>';
                        }
                    }
                }
            }

            if (report.case_work_dir) {
                html += '<p style="margin-top:12px;color:#64748B;font-size:0.8rem;">Case: ' + report.case_work_dir + '</p>';
            }

            html += '</div>';

            // Full narrative report section (fetched separately)
            html += '<div id="fe-report-section" style="margin-top:16px;">';
            if (report.narrative_report_path) {
                const caseName = (report.title || '').replace('Find Evil Report \u2014 ', '');
                html += '<button id="fe-report-btn" onclick="loadNarrativeReport(\'' + _escAttr(caseName) + '\')" '
                      + 'style="background:#3B82F6;color:#fff;border:none;padding:8px 18px;border-radius:6px;cursor:pointer;font-size:0.9rem;">'
                      + '\u2139\ufe0f View Full Investigation Report</button>';
                html += '<div id="fe-report-body" style="display:none;margin-top:16px;"></div>';
            }
            html += '</div>';

            area.innerHTML = html;
            // Scroll the unified output so results are visible
            const out = document.getElementById('fe-output');
            out.scrollTop = out.scrollHeight;
        }

        function _escAttr(s) {
            return (s || '').replace(/'/g, "\\'").replace(/"/g, '&quot;');
        }

        // Minimal markdown-to-HTML renderer for the narrative report
        function _md2html(md) {
            const lines = md.split('\n');
            let html = '';
            let inList = false;
            let inTable = false;
            for (let i = 0; i < lines.length; i++) {
                let ln = lines[i];
                // Close open structures on blank line
                if (ln.trim() === '') {
                    if (inList)  { html += '</ul>\n'; inList = false; }
                    if (inTable) { html += '</table>\n'; inTable = false; }
                    html += '<br>';
                    continue;
                }
                // Horizontal rule
                if (/^---+$/.test(ln.trim())) {
                    if (inList)  { html += '</ul>\n'; inList = false; }
                    if (inTable) { html += '</table>\n'; inTable = false; }
                    html += '<hr style="border-color:#334155;margin:12px 0;">\n';
                    continue;
                }
                // Headers
                const h3 = ln.match(/^### (.+)/);
                const h2 = ln.match(/^## (.+)/);
                const h1 = ln.match(/^# (.+)/);
                if (h1) { html += '<h2 style="color:#60A5FA;margin:16px 0 8px;">' + _mdInline(h1[1]) + '</h2>\n'; continue; }
                if (h2) { html += '<h3 style="color:#93C5FD;margin:14px 0 6px;">' + _mdInline(h2[1]) + '</h3>\n'; continue; }
                if (h3) { html += '<h4 style="color:#94A3B8;margin:12px 0 4px;">' + _mdInline(h3[1]) + '</h4>\n'; continue; }
                // Table row
                if (ln.startsWith('|')) {
                    if (!inTable) { html += '<table style="border-collapse:collapse;width:100%;margin:6px 0;font-size:0.82rem;">'; inTable = true; }
                    if (/^[|][-| ]+[|]$/.test(ln.trim())) continue; // separator row
                    const cells = ln.split('|').slice(1,-1);
                    html += '<tr>' + cells.map(c => '<td style="border:1px solid #334155;padding:4px 8px;">' + _mdInline(c.trim()) + '</td>').join('') + '</tr>\n';
                    continue;
                }
                if (inTable) { html += '</table>\n'; inTable = false; }
                // List item
                const li = ln.match(/^[-*] (.+)/);
                if (li) {
                    if (!inList) { html += '<ul style="margin:4px 0 4px 18px;padding:0;">'; inList = true; }
                    html += '<li style="margin:2px 0;">' + _mdInline(li[1]) + '</li>\n';
                    continue;
                }
                // Numbered list
                const ol = ln.match(/^\\d+\\. (.+)/);
                if (ol) {
                    if (inList) { html += '</ul>\n'; inList = false; }
                    html += '<p style="margin:2px 0;">' + _mdInline(ln) + '</p>\n';
                    continue;
                }
                if (inList) { html += '</ul>\n'; inList = false; }
                html += '<p style="margin:4px 0;">' + _mdInline(ln) + '</p>\n';
            }
            if (inList)  html += '</ul>\n';
            if (inTable) html += '</table>\n';
            return html;
        }

        function _mdInline(s) {
            // Escape HTML first
            s = s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
            // Bold+italic, bold, italic, code, backtick
            s = s.replace(/[*][*][*](.+?)[*][*][*]/g, '<strong><em>$1</em></strong>');
            s = s.replace(/[*][*](.+?)[*][*]/g, '<strong>$1</strong>');
            s = s.replace(/[*](.+?)[*]/g, '<em>$1</em>');
            s = s.replace(/`([^`]+)`/g, '<code style="background:#161b22;padding:1px 5px;border-radius:3px;font-size:0.85em;">$1</code>');
            return s;
        }

        async function loadNarrativeReport(caseName) {
            const btn = document.getElementById('fe-report-btn');
            const body = document.getElementById('fe-report-body');
            if (!btn || !body) return;
            btn.disabled = true;
            btn.textContent = 'Loading report\u2026';
            try {
                const resp = await authFetch('/cases/' + encodeURIComponent(caseName) + '/report');
                if (!resp.ok) {
                    body.innerHTML = '<p style="color:#EF4444;">Failed to load report (' + resp.status + ')</p>';
                    body.style.display = 'block';
                    return;
                }
                const md = await resp.text();
                body.innerHTML = '<div style="background:#0B1220;border:1px solid #334155;border-radius:6px;padding:16px;font-size:0.88rem;line-height:1.6;color:#F1F5F9;">'
                               + _md2html(md) + '</div>';
                body.style.display = 'block';
                btn.textContent = '\u25b2 Hide Report';
                btn.onclick = () => {
                    body.style.display = body.style.display === 'none' ? 'block' : 'none';
                    btn.textContent = body.style.display === 'none' ? '\u2139\ufe0f View Full Investigation Report' : '\u25b2 Hide Report';
                };
            } catch(e) {
                body.innerHTML = '<p style="color:#EF4444;">Error: ' + e.message + '</p>';
                body.style.display = 'block';
            } finally {
                btn.disabled = false;
            }
        }

        function showFindEvilError(msg) {
            const area = document.getElementById('fe-results-area');
            area.style.display = 'block';
            const p = document.createElement('div');
            p.className = 'fe-results';
            const txt = document.createElement('p');
            txt.style.cssText = 'color:#EF4444;font-weight:600;';
            txt.textContent = 'Error: ' + msg;
            p.appendChild(txt);
            area.innerHTML = '';
            area.appendChild(p);
            const out = document.getElementById('fe-output');
            out.scrollTop = out.scrollHeight;
        }
    </script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Flask Routes
# ---------------------------------------------------------------------------

@app.route('/')
def index():
    # Inject the API key (if set) into a meta tag so the UI can authenticate
    # its own fetch() calls without exposing the key in JS source.
    from markupsafe import escape as _html_escape
    key_meta = (
        f'<meta name="geoff-api-key" content="{_html_escape(GEOFF_API_KEY)}">'
        if GEOFF_API_KEY else ''
    )
    evidence_base_js = EVIDENCE_BASE_DIR.replace("'", "\\'")
    return render_template_string(
        HTML_TEMPLATE
        .replace('<!-- GEOFF_API_KEY_META -->', key_meta)
        .replace('<!-- GEOFF_EVIDENCE_BASE_DIR -->', evidence_base_js)
    )


@app.route('/chat', methods=['POST'])
@_require_auth
def chat():
    """LLM-powered chat with tool detection"""
    user_msg = ''
    try:
        data = request.json
        user_msg = data.get('message', '')

        if not user_msg:
            return jsonify({'response': 'What would you like to look at?'})

        # Check for ingestion/processing trigger
        ingest_triggers = ['start processing', 'process evidence', 'ingest',
                           'analyze evidence', 'find evil', 'begin investigation',
                           'start analysis', 'run analysis']
        user_msg_lower = user_msg.lower()
        if any(trigger in user_msg_lower for trigger in ingest_triggers):
            # Extract path if mentioned, otherwise use default
            evidence_dir = _extract_path_from_message(user_msg) or EVIDENCE_BASE_DIR

            # Reject paths with shell metacharacters
            try:
                _validate_evidence_path(evidence_dir)
            except ValueError as e:
                return jsonify({'response': f"Evidence path rejected: {e}"})

            if not Path(evidence_dir).exists():
                return jsonify({
                    'response': f"Evidence directory not found: {evidence_dir}\n"
                                f"Default: {EVIDENCE_BASE_DIR}",
                })

            # Use the existing async find_evil mechanism
            job_id = f"fe-{uuid.uuid4().hex[:12]}"
            with _state_lock:
                _find_evil_jobs[job_id] = {
                    "status": "running",
                    "progress_pct": 0.0,
                    "current_playbook": "initializing",
                    "current_step": "",
                    "elapsed_seconds": 0.0,
                    "started_at": datetime.now().isoformat(),
                    "result": None,
                    "error": None,
                    "log": [{"time": datetime.now().strftime("%H:%M:%S"),
                             "msg": f"Find Evil started from chat: {evidence_dir}"}],
                }

            def _run():
                try:
                    report = find_evil(evidence_dir, job_id=job_id)
                    with _state_lock:
                        _find_evil_jobs[job_id]["status"] = "complete"
                        _find_evil_jobs[job_id]["result"] = report
                except Exception as e:
                    with _state_lock:
                        _find_evil_jobs[job_id]["status"] = "error"
                        _find_evil_jobs[job_id]["error"] = str(e)

            threading.Thread(target=_run, daemon=True).start()

            return jsonify({
                'response': f"Roger that. Starting investigation on {evidence_dir}.\n"
                            f"Job ID: {job_id}\n"
                            f"I'll process all evidence, identify devices and users, "
                            f"build a unified timeline, and generate a narrative report.\n\n"
                            f"Poll /find-evil/status/{job_id} for progress.",
                'investigation_started': True,
                'job_id': job_id,
            })

        # Detect if user wants to run a tool
        tool_request = detect_tool_request(user_msg)
        tool_result = None
        evidence_file = None

        # Check if user mentions a case - use active evidence dir as default
        cases = get_all_cases()
        case_match = None
        files = []
        for case_name in cases.keys():
            if case_name.lower() in user_msg.lower():
                case_match = case_name
                files = cases[case_name]
                break
        
        # If no case mentioned, use active evidence directory from web UI
        if not case_match and _active_evidence_dir and _active_evidence_dir != EVIDENCE_BASE_DIR:
            try:
                active_basename = os.path.basename(_active_evidence_dir)
                if active_basename in cases:
                    case_match = active_basename
                    files = cases[active_basename]
                elif os.path.exists(_active_evidence_dir):
                    files = [f for f in os.listdir(_active_evidence_dir) if not f.startswith('.')]
                    case_match = active_basename if active_basename else "active"
            except Exception as list_exc:
                _log_info(f"active evidence directory listing skipped: {list_exc}")

        # If tool request detected, run it
        if tool_request and case_match:
            if tool_request['function'] == 'run_full_investigation':
                tool_result = run_full_investigation(case_match, evidence_file)
            else:
                # Single tool execution
                case_path = Path(EVIDENCE_BASE_DIR) / case_match
                for ext in ['.E01', '.dd', '.raw', '.mem', '.img']:
                    matches = list(case_path.rglob(f'*{ext}'))
                    if matches:
                        evidence_file = str(matches[0])
                        break

                if evidence_file:
                    tool_request['params']['disk_image'] = evidence_file
                    if 'partition' in tool_request['function']:
                        tool_request['params']['partition'] = evidence_file

                # Run the tool via Forensicator (multi-agent)
                forensicator_result = geoff_forensicator.execute_task(
                    instruction=user_msg,
                    evidence_path=evidence_file
                )

                tool_result = {
                    'module': tool_request['module'],
                    'function': tool_request['function'],
                    'params': tool_request['params'],
                    'status': 'completed',
                    'forensicator_output': forensicator_result
                }

                # Validate with Critic
                critic_validation = geoff_critic.validate_tool_output(
                    tool_name=f"{tool_request['module']}.{tool_request['function']}",
                    tool_params=tool_request['params'],
                    raw_output=json.dumps(forensicator_result.get('validated_output', {})),
                    geoff_analysis=f"Executed {tool_request['function']} on {evidence_file}"
                )

                geoff_critic.commit_validation(case_match or 'chat-session', critic_validation)
                tool_result['critic_validation'] = critic_validation

        # If investigation was started, return that status immediately
        if tool_request and tool_request['function'] == 'run_full_investigation' and tool_result:
            result = {
                'response': f"**G.E.O.F.F. Investigation Initiated**\n\n" +
                           f"Case: {tool_result.get('case', case_match)}\n" +
                           f"Work Directory: {tool_result.get('work_directory', 'N/A')}\n" +
                           f"Progress File: {tool_result.get('progress_file', 'N/A')}\n\n" +
                           f"{tool_result.get('note', '')}\n\n" +
                           f"The investigation is now running in the background. " +
                           f"Progress updates will appear every 10 seconds.",
                'tool_result': tool_result,
                'investigation_started': True,
                'case_name': tool_result.get('case', case_match)
            }
            return jsonify(result)

        # Build context for LLM
        case_info = ""
        if case_match:
            case_info = f"Case '{case_match}' has {len(files)} items.\n" + "\n".join(files)

        tool_info = """Available forensic tools:
- SleuthKit: mmls (partition), fls (list files), fsstat (filesystem), icat (extract), istat/ils (inodes)
- Volatility: process list, network scan, malware find, registry scan, process dump
- Strings: extract IOCs (URLs, IPs, emails, registry paths)
- Registry: hive parsing, UserAssist, ShellBags, USB history, autoruns, services
- Timeline: log2timeline (create), psort (sort), super timeline
- Network: pcap analysis, tcpflow, HTTP extraction
- Logs: EVTX parsing, syslog analysis
- Mobile: iOS backup, Android data
- REMnux: DIE, exiftool, ClamAV, radare2, floss, pdfid, oledump, UPX"""

        context = f"{case_info}\n\n{tool_info}"

        # CHAT-BASED HEALING: Check if user is asking about a tool error
        healing_response = None
        try:
            chat_healing = geoff_critic.analyze_chat_request(
                user_message=user_msg,
                chat_history=[],  # Could pass recent history
                current_context={"case": case_match, "files": files}
            )
            
            if chat_healing.get("is_healing_request") and chat_healing.get("can_auto_heal"):
                # User is asking about an error and Critic thinks we can heal
                _action_logger.log('CHAT_HEALING', {
                    'user_message': user_msg,
                    'detected_tool': chat_healing.get('detected_tool'),
                    'healing_action': chat_healing.get('healing_action'),
                })
                
                healing_action = chat_healing.get('healing_action')
                healing_params = chat_healing.get('healing_params', {})
                
                if healing_action and case_match:
                    # Try to execute the healing
                    healing_result = _run_step_via_orchestrator(
                        healing_params.get('module', 'sleuthkit'),
                        healing_params.get('function', 'list_files'),
                        healing_params.get('params', {})
                    )
                    
                    if healing_result.get('status') == 'success':
                        healing_response = (
                            f"✓ **Healing Successful**\n\n"
                            f"{chat_healing.get('healing_advice', '')}\n\n"
                            f"The tool that failed previously is now working. "
                            f"Here's what I found:\n\n"
                            f"```\n{healing_result.get('stdout', '')[:500]}\n```"
                        )
                    else:
                        healing_response = (
                            f"I attempted to heal the issue ({healing_action}), "
                            f"but the tool is still failing. {chat_healing.get('healing_advice', '')}"
                        )
                else:
                    # Provide healing advice without execution
                    healing_response = chat_healing.get('healing_advice', '')
        except Exception as chat_heal_err:
            # Non-critical - just continue to normal LLM flow
            pass
        
        # If healing produced a response, use it
        if healing_response:
            result = {'response': healing_response, 'healing_executed': True}
            return jsonify(result)

        # Log the chat action
        action_logger.log('CHAT', {
            'user_message': user_msg,
            'case': case_match,
            'tool_executed': tool_request['module'] + '.' + tool_request['function'] if tool_request else None,
            'description': f"Chat with {case_match or 'no case'}"
        })

        # Call LLM
        response = call_llm(user_msg, context, agent_type="manager")

        # Self-correction: verify the response is grounded in the available context
        response = _self_check_chat_response(user_msg, context, response)

        result = {'response': response}
        if tool_result:
            result['tool_result'] = tool_result

            if isinstance(tool_result, dict) and tool_result.get('status') == 'started':
                result['investigation_started'] = True
                result['case_name'] = tool_result.get('case', case_match)

            if tool_request and tool_request['function'] != 'run_full_investigation':
                print(f"[CRITIC] Validating {tool_request['module']}.{tool_request['function']}...")
                validation = geoff_critic.validate_tool_output(
                    f"{tool_request['module']}.{tool_request['function']}",
                    tool_request['params'],
                    json.dumps(tool_result),
                    response
                )
                result['critic_validation'] = validation
                result['critic_approved'] = validation.get('valid', False)

                geoff_critic.commit_validation(case_match or 'unknown', validation)

                action_logger.log('TOOL_EXECUTION', {
                    'module': tool_request['module'],
                    'function': tool_request['function'],
                    'case': case_match,
                    'evidence_file': evidence_file,
                    'description': f"Ran {tool_request['module']}.{tool_request['function']} on {case_match}",
                    'critic_valid': validation.get('valid', False)
                })

        return jsonify(result)
    except Exception as e:
        _log_error(f"chat route error: {user_msg}", e)
        return jsonify({'response': f'Error: {str(e)}'})


@app.route('/cases', methods=['GET'])
@_require_auth
def list_cases():
    """Return ALL cases with ALL files"""
    return jsonify({'cases': get_all_cases()})


@app.route('/cases/<case_name>/report', methods=['GET'])
@_require_auth
def get_case_report(case_name):
    """Return the narrative report markdown for a completed Find Evil case.

    The case_name must consist only of alphanumeric characters, hyphens, and
    underscores to prevent path traversal.
    """
    safe_name = re.sub(r'[^a-zA-Z0-9_\-]', '', case_name)
    if not safe_name:
        return jsonify({'error': 'Invalid case name'}), 400

    # Search CASES_WORK_DIR for an exact or _findevil_-separated match.
    # Use a uniform 404 for both "case not found" and "report not found" to
    # prevent enumeration of case names via response differences.
    cases_root = Path(CASES_WORK_DIR)
    report_path = None
    if cases_root.exists():
        pattern = re.compile(r'^' + re.escape(safe_name) + r'(_findevil_|$)')
        for candidate in sorted(cases_root.iterdir(), reverse=True):
            if candidate.is_dir() and pattern.match(candidate.name):
                candidate_report = candidate / "reports" / "narrative_report.md"
                if candidate_report.exists():
                    report_path = candidate_report
                    break

    if not report_path:
        return jsonify({'error': 'Report not found'}), 404

    try:
        content = report_path.read_text(encoding='utf-8')
        return content, 200, {'Content-Type': 'text/plain; charset=utf-8'}
    except OSError as e:
        _log_error("Failed to read narrative report", e)
        return jsonify({'error': 'Unable to read report'}), 500


@app.route('/reports', methods=['GET'])
@_require_auth
def list_reports():
    """List completed Find Evil cases that have a saved JSON report."""
    cases_root = Path(CASES_WORK_DIR)
    reports = []
    if cases_root.exists():
        for d in sorted(cases_root.iterdir(), reverse=True):
            if not d.is_dir():
                continue
            report_file = d / "reports" / "find_evil_report.json"
            if not report_file.exists():
                continue
            try:
                if report_file.stat().st_size > 50 * 1024 * 1024:  # 50 MB guard
                    continue
                with open(report_file) as f:
                    data = json.load(f)
                # Directory name pattern: {case_name}_findevil_{timestamp}
                dir_name = d.name
                parts = dir_name.rsplit('_findevil_', 1)
                case_display = parts[0] if len(parts) == 2 else dir_name
                timestamp_str = parts[1] if len(parts) == 2 else ''
                reports.append({
                    'dir': dir_name,
                    'case_name': case_display,
                    'timestamp': timestamp_str,
                    'evil_found': data.get('evil_found', False),
                    'severity': data.get('severity', 'INFO'),
                    'classification': data.get('classification', ''),
                    'elapsed_seconds': data.get('elapsed_seconds', 0),
                    'evidence_dir': data.get('evidence_dir', ''),
                })
            except (OSError, json.JSONDecodeError, KeyError):
                continue
    return jsonify({'reports': reports})


@app.route('/reports/<case_dir>/json', methods=['GET'])
@_require_auth
def get_report_json(case_dir):
    """Serve the find_evil_report.json for a specific case directory."""
    safe_dir = re.sub(r'[^a-zA-Z0-9_\-]', '', case_dir)
    if not safe_dir:
        return jsonify({'error': 'Invalid case directory name'}), 400
    case_path = Path(CASES_WORK_DIR) / safe_dir
    if not case_path.is_dir():
        return jsonify({'error': 'Case not found'}), 404
    # Verify resolved path stays within CASES_WORK_DIR (no traversal)
    try:
        case_path.resolve().relative_to(Path(CASES_WORK_DIR).resolve())
    except ValueError:
        return jsonify({'error': 'Invalid case directory'}), 400
    report_file = case_path / "reports" / "find_evil_report.json"
    if not report_file.exists():
        return jsonify({'error': 'Report not found'}), 404
    try:
        content = report_file.read_text(encoding='utf-8')
        return content, 200, {'Content-Type': 'application/json; charset=utf-8'}
    except OSError as e:
        _log_error("Failed to read report JSON", e)
        return jsonify({'error': 'Unable to read report'}), 500


@app.route('/reports/viewer', methods=['GET'])
@_require_auth
def viewer_html():
    """Serve the Evidence Graph viewer UI (with optional case= param)."""
    viewer_dir = Path(__file__).parent.parent / 'static' / 'geoff-viewer'
    return send_from_directory(str(viewer_dir), 'index.html')


@app.route('/static/geoff-viewer/<path:filename>', methods=['GET'])
@_require_auth
def viewer_static(filename):
    """Serve static files for the Evidence Graph viewer (CSS, JSX, sample data)."""
    viewer_dir = Path(__file__).parent.parent / 'static' / 'geoff-viewer'
    if '..' in filename or filename.startswith('/'):
        return jsonify({'error': 'Invalid path'}), 400
    return send_from_directory(str(viewer_dir), filename)


@app.route('/tools', methods=['GET'])
@_require_auth
def list_tools():
    """Return available forensic tools"""
    return jsonify({'tools': get_available_tools_status()})


@app.route('/health', methods=['GET'])
def health():
    """Basic liveness probe. Returns 200 without running the full self-check."""
    return jsonify({'status': 'ok'})


@app.route('/health/detailed', methods=['GET'])
@_require_auth
def health_detailed():
    """Run the full self-check and return JSON results."""
    try:
        from geoff_selfcheck import run_all_checks
        results = run_all_checks(
            ollama_url=ollama_base_url(),
            api_key=OLLAMA_API_KEY,
            agent_models=AGENT_MODELS,
            evidence_base=EVIDENCE_BASE_DIR,
            cases_work=CASES_WORK_DIR,
        )
        has_fail = any(r["status"] == "fail" for r in results)
        has_warn = any(r["status"] == "warn" for r in results)
        overall = "fail" if has_fail else "warn" if has_warn else "pass"
        return jsonify({"overall": overall, "checks": results})
    except Exception as e:
        _log_error("health_detailed self-check failed", e)
        return jsonify({"overall": "error", "error": "Self-check failed"}), 500


_ALLOWED_TOOL_FUNCTIONS: dict = {
    'sleuthkit':  {'analyze_partition_table', 'list_inodes', 'list_deleted', 'extract_file',
                   'list_files', 'list_files_mactime', 'get_file_info', 'analyze_filesystem'},
    'volatility': {'dump_process', 'process_list', 'scan_registry', 'find_malware', 'network_scan'},
    'strings':    {'extract_strings'},
    'registry':   {'extract_services', 'scan_all_hives', 'parse_hive', 'extract_shellbags',
                   'extract_user_assist', 'extract_mounted_devices', 'extract_usb_devices',
                   'extract_autoruns'},
    'plaso':      {'create_timeline', 'sort_timeline', 'analyze_storage'},
    'network':    {'extract_flows', 'analyze_pcap', 'extract_http'},
    'logs':       {'parse_syslog', 'parse_evtx'},
    'mobile':     {'analyze_android', 'analyze_ios_backup',
                   'extract_ios_sms', 'extract_ios_call_history', 'extract_ios_safari_history',
                   'extract_ios_contacts', 'extract_ios_mail', 'extract_ios_location',
                   'extract_ios_accounts', 'extract_ios_keychain', 'extract_ios_health',
                   'extract_ios_notifications', 'extract_ios_device_info', 'extract_ios_usage_stats',
                   'detect_jailbreak_indicators', 'detect_root_indicators', 'run_ileapp',
                   'extract_android_sms', 'extract_android_call_logs', 'extract_android_contacts',
                   'extract_android_email', 'extract_android_browser_history', 'extract_android_location',
                   'extract_android_accounts', 'extract_android_device_info',
                   'extract_android_notifications', 'extract_android_usage_stats',
                   'extract_whatsapp', 'extract_telegram',
                   'extract_mobile_photo_exif', 'recover_deleted_sqlite_messages',
                   'run_aleapp'},
    'browser':    {'extract_downloads', 'extract_cookies', 'extract_history'},
    'email':      {'analyze_mbox', 'analyze_pst', 'analyze_eml'},
    'jumplist':   {'parse_jump_lists', 'parse_lnk_files', 'parse_recent_apps'},
    'macos':      {'analyze_launch_agents', 'parse_unified_log', 'analyze_fseventsd', 'parse_plist'},
    'photorec':   {'recover_files'},
    'vss':        {'list_vss', 'extract_vss_files', 'analyze_vss_timeline', 'mount_vss'},
    'zimmerman':  {'parse_evtx_zimmerman', 'parse_mft', 'srum_parse', 'amcache_parse',
                   'shellbags_parse'},
    'remnux':     {'die_scan', 'exiftool_scan', 'peframe_scan', 'ssdeep_hash', 'hashdeep_audit',
                   'upx_unpack', 'pdfid_scan', 'pdf_parser', 'oledump_scan', 'js_beautify',
                   'radare2_analyze', 'floss_strings', 'clamav_scan'},
}


@app.route('/run-tool', methods=['POST'])
@_require_auth
def run_tool():
    """Execute a forensic tool directly"""
    module = function = ''
    try:
        data = request.json or {}
        module = str(data.get('module', '')).strip()
        function = str(data.get('function', '')).strip()
        params = data.get('params', {})

        if module not in _ALLOWED_TOOL_FUNCTIONS:
            return jsonify({'status': 'error', 'error': f"Unknown module: {module}"}), 400
        if function not in _ALLOWED_TOOL_FUNCTIONS[module]:
            return jsonify({'status': 'error', 'error': f"Function not allowed: {module}.{function}"}), 400
        if not isinstance(params, dict):
            return jsonify({'status': 'error', 'error': 'params must be an object'}), 400

        action_logger.log('TOOL_API_CALL', {
            'module': module,
            'function': function,
            'params': params,
            'description': f"API call to run {module}.{function}"
        })

        result = _run_step_via_orchestrator(module, function, params)

        action_logger.log('TOOL_API_SUCCESS', {
            'module': module,
            'function': function,
            'result_status': result.get('status'),
            'description': f"API {module}.{function} completed"
        })

        return jsonify(result)
    except Exception as e:
        _log_error(f"API {module}.{function} failed", e)
        return jsonify({'status': 'error', 'error': str(e)})


@app.route('/critic/validate', methods=['POST'])
@_require_auth
def critic_validate():
    """Manually trigger critic validation"""
    try:
        data = request.json
        tool_name = data.get('tool_name')
        tool_output = data.get('tool_output')
        geoff_analysis = data.get('geoff_analysis')
        investigation_id = data.get('investigation_id', 'manual')

        if not all([tool_name, tool_output, geoff_analysis]):
            return jsonify({'error': 'Missing required fields: tool_name, tool_output, geoff_analysis'}), 400

        validation = geoff_critic.validate_tool_output(
            tool_name,
            {},
            tool_output,
            geoff_analysis
        )

        geoff_critic.commit_validation(investigation_id, validation)

        return jsonify(validation)
    except Exception as e:
        return jsonify({'status': 'error', 'error': str(e)})


@app.route('/critic/summary/<investigation_id>', methods=['GET'])
@_require_auth
def critic_summary(investigation_id):
    """Get validation summary for investigation"""
    try:
        summary = geoff_critic.get_validation_summary(investigation_id)
        return jsonify(summary)
    except Exception as e:
        return jsonify({'status': 'error', 'error': str(e)})


@app.route('/investigation/status/<case_name>', methods=['GET'])
@_require_auth
def get_investigation_status(case_name):
    """Get status of background investigation via find_evil pipeline"""
    try:
        safe_name = re.sub(r'[^a-zA-Z0-9_\-]', '', case_name)
        if not safe_name:
            return jsonify({'status': 'error', 'error': 'Invalid case name'}), 400

        # Check active find_evil jobs — hold lock for safe iteration
        with _state_lock:
            jobs_snapshot = list(_find_evil_jobs.items())
        for job_id, job in jobs_snapshot:
            if safe_name in job_id or job.get('case_name') == safe_name:
                return jsonify({
                    'status': job.get('status', 'pending'),
                    'case': safe_name,
                    'job_id': job_id,
                    'progress_pct': job.get('progress_pct', 0),
                    'current_playbook': job.get('current_playbook'),
                    'current_step': job.get('current_step'),
                })
        # Check for completed investigation in case directory using anchored pattern
        cases_root = Path(CASES_WORK_DIR)
        report_file = None
        case_pattern = re.compile(r'^' + re.escape(safe_name) + r'(_findevil_|$)')
        if cases_root.exists():
            for d in sorted(cases_root.iterdir(), reverse=True):
                if d.is_dir() and case_pattern.match(d.name):
                    candidate = d / "reports" / "find_evil_report.json"
                    if candidate.exists():
                        report_file = candidate
                        break
        if report_file:
            return jsonify({'status': 'completed', 'case': safe_name, 'report': str(report_file)})
        return jsonify({'status': 'not_found', 'case': safe_name}), 404
    except Exception as e:
        return jsonify({'status': 'error', 'error': str(e)}), 500


@app.route('/find-evil', methods=['POST'])
@_require_auth
def find_evil_route():
    """
    POST /find-evil
    Point at an evidence directory, auto-run all 19 playbooks, find evil.

    Now returns a job_id immediately and runs async.

    Request body (JSON):
        {
            "evidence_dir": "/path/to/evidence"
        }

    Returns:
        { "job_id": "...", "status": "running" }
    """
    try:
        data = request.json or {}
        evidence_dir = data.get('evidence_dir', '').strip() or EVIDENCE_BASE_DIR

        # If not an absolute path or doesn't exist as-is, try joining with EVIDENCE_BASE_DIR
        # so the user can paste just a folder name from the evidence tab (e.g. "IR-016-CloudJack")
        if evidence_dir and not Path(evidence_dir).is_absolute():
            evidence_dir = os.path.join(EVIDENCE_BASE_DIR, evidence_dir)
        elif evidence_dir and not Path(evidence_dir).exists() and EVIDENCE_BASE_DIR:
            candidate = os.path.join(EVIDENCE_BASE_DIR, os.path.basename(evidence_dir))
            if Path(candidate).exists():
                evidence_dir = candidate

        # Reject paths containing shell metacharacters
        try:
            _validate_evidence_path(evidence_dir)
        except ValueError as e:
            return jsonify({"status": "error", "error": str(e)}), 400

        # Verify the directory exists before spawning a job
        if not Path(evidence_dir).exists():
            return jsonify({
                "status": "error",
                "error": f"Evidence directory not found: {evidence_dir}",
                "evidence_dir": evidence_dir,
            }), 404

        # Create a job ID and register it
        job_id = f"fe-{uuid.uuid4().hex[:12]}"

        with _state_lock:
            _find_evil_jobs[job_id] = {
                "status": "running",
                "progress_pct": 0.0,
                "current_playbook": "initializing",
                "current_step": "",
                "elapsed_seconds": 0.0,
                "started_at": datetime.now().isoformat(),
                "result": None,
                "error": None,
                "log": [{"time": datetime.now().strftime("%H:%M:%S"), "msg": "Find Evil job started"}],
            }

        # Spawn the find_evil run in a background thread
        def _run():
            try:
                report = find_evil(evidence_dir, job_id=job_id)
                with _state_lock:
                    _find_evil_jobs[job_id]["status"] = "complete"
                    _find_evil_jobs[job_id]["result"] = report
            except Exception as e:
                _fe_log_with_exception(job_id, "Find Evil job failed", e)
                with _state_lock:
                    _find_evil_jobs[job_id]["status"] = "error"
                    _find_evil_jobs[job_id]["error"] = str(e)

        thread = threading.Thread(target=_run, daemon=True)
        thread.start()

        return jsonify({
            "job_id": job_id,
            "status": "running",
            "evidence_dir": evidence_dir,
            "message": "Find Evil job started. Poll /find-evil/status/" + job_id + " for progress.",
        })

    except Exception as e:
        action_logger.log('FIND_EVIL_ERROR', {
            'error': str(e),
            'description': 'Find Evil route error'
        })
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500


@app.route('/find-evil/status/<job_id>', methods=['GET'])
@_require_auth
def find_evil_status(job_id):
    """
    GET /find-evil/status/<job_id>
    Returns current progress of a Find Evil job.
    """
    with _state_lock:
        job = _find_evil_jobs.get(job_id)

    if job is None:
        return jsonify({"status": "not_found", "error": f"No job with ID {job_id}"}), 404

    resp = {
        "job_id": job_id,
        "status": job["status"],
        "progress_pct": job["progress_pct"],
        "current_playbook": job["current_playbook"],
        "current_step": job["current_step"],
        "elapsed_seconds": job["elapsed_seconds"],
        "log": job.get("log", [])[-50:],  # Last 50 entries
    }

    if job["status"] == "complete":
        resp["result"] = job["result"]
    elif job["status"] == "error":
        resp["error"] = job["error"]

    return jsonify(resp)


@app.route('/find-evil/status/<job_id>', methods=['DELETE'])
@_require_auth
def find_evil_cancel(job_id):
    """
    DELETE /find-evil/status/<job_id>
    Cancel a running Find Evil job.
    """
    with _state_lock:
        job = _find_evil_jobs.get(job_id)
        
        if job is None:
            return jsonify({"status": "not_found", "error": f"No job with ID {job_id}"}), 404
        
        if job["status"] not in ("running", "initializing"):
            return jsonify({
                "status": "error",
                "error": f"Cannot cancel job in state: {job['status']}"
            }), 400
        
        # Mark as cancelled
        job["status"] = "cancelled"
        job["error"] = "Cancelled by user"
        _fe_log(job_id, f"Job {job_id} cancelled by DELETE request")

    return jsonify({
        "job_id": job_id,
        "status": "cancelled",
        "message": "Job cancelled successfully"
    })


@app.route('/find-evil', methods=['GET'])
@_require_auth
def find_evil_info():
    """GET /find-evil — Return usage info and supported playbooks"""
    playbook_list = []
    for pid, pname in PLAYBOOK_NAMES.items():
        if pid == "PB-SIFT-000":
            trigger = "Always (mandatory entry point)"
        elif pid in ("PB-SIFT-017", "PB-SIFT-018"):
            trigger = "If suspicious binary found during triage"
        elif pid == "PB-SIFT-019":
            trigger = "If C2 indicators found during triage"
        elif pid == "PB-SIFT-020":
            trigger = "If disk images present"
        elif pid == "PB-SIFT-021":
            trigger = "If mobile backup artifacts detected"
        elif pid == "PB-SIFT-016":
            trigger = "If multiple disk images found"
        else:
            trigger = "Always (kill chain order)"
        playbook_list.append({"id": pid, "name": pname, "trigger": trigger})

    return jsonify({
        'name': 'Find Evil',
        'description': 'Triage-driven forensic investigation. PB-SIFT-000 runs first, scans for indicators, and generates a structured execution plan. Only listed playbooks run — no blind execution.',
        'model': 'triage-driven',
        'usage': 'POST /find-evil with {"evidence_dir": "/path/to/evidence"}',
        'supported_evidence': [
            'Disk images (.E01, .dd, .raw, .img, .aff)',
            'Memory dumps (.vmem, .mem, .dmp)',
            'Network captures (.pcap, .pcapng)',
            'Windows Event Logs (.evtx)',
            'Syslog files (syslog, auth.log, messages)',
            'Registry hives (NTUSER.DAT, SYSTEM, SOFTWARE, SECURITY, SAM)',
        ],
        'playbooks': playbook_list,
        'pipeline': [
            '1. PB-SIFT-000: Evidence inventory & quality scoring',
            '2. Triage: OS classification & rapid indicator scanning',
            '3. Execution plan generated from triage results',
            '4. Only listed playbooks run (evidence-type dependent)',
            '5. Steps skipped if required tool is missing',
            '6. Anti-forensics confidence cascade (PB-SIFT-012)',
            '7. Critic validation of every result',
            '8. JSON Schema validation of investigation state',
            '9. Unified findings report with severity & MITRE ATT&CK mapping',
        ]
    })


@app.route('/active-directory', methods=['POST'])
@_require_auth
def set_active_directory():
    """Set the active evidence directory for chat queries"""
    global _active_evidence_dir
    try:
        data = request.json or {}
        directory = data.get('directory', '').strip()
        
        if not directory:
            return jsonify({'status': 'error', 'error': 'No directory provided'}), 400
            
        # Validate the path
        try:
            _validate_evidence_path(directory)
        except ValueError as e:
            return jsonify({'status': 'error', 'error': str(e)}), 400
            
        if not Path(directory).exists():
            return jsonify({'status': 'error', 'error': f'Directory not found: {directory}'}), 404
            
        _active_evidence_dir = directory
        return jsonify({
            'status': 'success',
            'directory': directory,
            'message': f'Active evidence directory set to: {directory}'
        })
    except Exception as e:
        return jsonify({'status': 'error', 'error': str(e)}), 500


@app.route('/active-directory', methods=['GET'])
@_require_auth
def get_active_directory():
    """Get the current active evidence directory"""
    return jsonify({
        'active_directory': _active_evidence_dir,
        'default_directory': EVIDENCE_BASE_DIR
    })


if __name__ == '__main__':
    print(f'Geoff DFIR on port {PORT}')
    print(f'Evidence source: {EVIDENCE_BASE_DIR}')
    print(f'Cases work dir: {CASES_WORK_DIR}')
    print(f'Profile: {ACTIVE_PROFILE}')
    print(f'Ollama: {ollama_base_url()}')
    if OLLAMA_API_KEY:
        print(f'Auth: API key (ollama.com cloud)')
    else:
        print(f'Auth: local (ollama signin)')
    print(f'Models: manager={AGENT_MODELS["manager"]} forensicator={AGENT_MODELS["forensicator"]} critic={AGENT_MODELS["critic"]}')
    print(f'REMnux orchestrator: loaded')

    # Self-check: verify tools, Ollama, and directories before serving
    try:
        from geoff_selfcheck import startup_check
        startup_check(
            ollama_url=ollama_base_url(),
            api_key=OLLAMA_API_KEY,
            agent_models=AGENT_MODELS,
            evidence_base=EVIDENCE_BASE_DIR,
            cases_work=CASES_WORK_DIR,
        )
    except Exception as _sc_err:
        print(f'[Geoff] Self-check unavailable: {_sc_err}', file=sys.stderr)

    app.run(host='0.0.0.0', port=PORT, debug=False, threaded=True)