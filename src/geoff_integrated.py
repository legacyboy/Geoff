#!/usr/bin/env python3
"""
Geoff DFIR - Integrated with SIFT Tool Specialists
"""

import os
import json
import re
import sys
import subprocess
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
from datetime import datetime
from pathlib import Path
from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS

from jsonschema import validate as jsonschema_validate, ValidationError

from sift_specialists import SpecialistOrchestrator, SLEUTHKIT_Specialist, VOLATILITY_Specialist, STRINGS_Specialist
from sift_specialists_extended import ExtendedOrchestrator
from sift_specialists_remnux import REMNUX_Orchestrator
from geoff_critic import GeoffCritic, ValidationPipeline
from geoff_forensicator import ForensicatorAgent

# ---------------------------------------------------------------------------
# Helper Functions
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


def _correlate_timelines(merged_timeline: str, case_work_dir, job_id: str) -> Dict[str, Any]:
    """Correlate events across multiple host images from a merged Plaso timeline.

    Uses psort json_line format and extracts username/hostname from the
    'message' field (top-level fields are unreliable in Plaso output).
    """
    if not Path(merged_timeline).exists():
        return {"error": "merged timeline not found", "path": merged_timeline}

    try:
        psort_cmd = [
            "python3", "/usr/bin/psort.py",
            "-o", "json_line",
            merged_timeline,
        ]
        result = safe_run(psort_cmd, timeout=600)

        if result["code"] != 0:
            return {"error": f"psort failed: {result.get('stderr', '')[:200]}"}

        # Regex patterns for extracting user/host from Plaso message field
        _username_patterns = [
            re.compile(r'\bAccount Name:\s*([\\\w.\-]+)', re.IGNORECASE),
            re.compile(r'\bUser Name?:\s*([\\\w.\-]+)', re.IGNORECASE),
            re.compile(r'\bLogon Name?:\s*([\\\w.\-]+)', re.IGNORECASE),
        ]
        _hostname_patterns = [
            re.compile(r'\bWorkstation Name?:\s*([\\\w.\-]+)', re.IGNORECASE),
            re.compile(r'\bComputer Name?:\s*([\\\w.\-]+)', re.IGNORECASE),
            re.compile(r'\bSource Network Address:\s*([\\\w.\-]+)', re.IGNORECASE),
        ]

        user_hosts = {}  # username -> set of hostnames
        events_sample = []
        lines_processed = 0

        for line in result["stdout"].strip().split("\n"):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue

            lines_processed += 1
            message = event.get("message", "")
            username = event.get("username", "") or ""
            hostname = event.get("hostname", "") or event.get("computer_name", "") or ""

            # Fall back to message field parsing if top-level fields empty
            if not username:
                for pat in _username_patterns:
                    m = pat.search(message)
                    if m:
                        username = m.group(1)
                        break
            if not hostname:
                for pat in _hostname_patterns:
                    m = pat.search(message)
                    if m:
                        hostname = m.group(1)
                        break

            if username and hostname:
                if username not in user_hosts:
                    user_hosts[username] = set()
                user_hosts[username].add(hostname)

            if len(events_sample) < 20:
                events_sample.append({
                    "timestamp": event.get("datetime", ""),
                    "event_type": event.get("data_type", ""),
                    "message": message[:150],
                })

        # Build cross-host correlation findings
        cross_host_users = []
        for username, hosts in user_hosts.items():
            if len(hosts) > 1:
                cross_host_users.append({
                    "user": username,
                    "hosts": sorted(hosts),
                    "risk_level": "HIGH" if len(hosts) >= 3 else "MEDIUM",
                })

        return {
            "total_events_analyzed": lines_processed,
            "unique_users": len(user_hosts),
            "cross_host_users": cross_host_users[:20],
            "cross_host_user_count": len(cross_host_users),
            "events_sample": events_sample,
        }
    except Exception as e:
        _log_error("Correlation analysis failed", e)
        return {"error": str(e)}


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
                except Exception:
                    pass  # Non-critical
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
    """
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

**Operational Protocol:**
- Respond with clear, technical accuracy
- When instructed to investigate, execute systematically without unnecessary clarification
- Report findings with supporting evidence
- Maintain chain of custody through git-backed validation
- Cite specific tools and artifacts examined

**Response Standards:**
- Professional, objective tone
- Evidence-based conclusions
- Clear identification of IOCs and suspicious activity
- Structured reporting suitable for legal documentation"""


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
        safe_run(['git', 'config', '--global', '--add', 'safe.directory', str(case_work_path)], cwd=case_work_path, timeout=10)
        safe_run(['git', 'config', '--local', 'safe.directory', str(case_work_path)], cwd=case_work_path, timeout=10)

    # Create subdirectories
    (case_work_path / "logs").mkdir(exist_ok=True)
    (case_work_path / "output").mkdir(exist_ok=True)
    (case_work_path / "reports").mkdir(exist_ok=True)
    (case_work_path / "timeline").mkdir(exist_ok=True)

    # Spawn background worker
    worker_cmd = [
        'python3',
        '/home/sansforensics/geoff_worker.py',
        case_name,
        str(case_work_path)
    ]
    if evidence_path:
        worker_cmd.append(evidence_path)

    subprocess.Popen(
        worker_cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True
    )

    return {
        "status": "started",
        "case": case_name,
        "work_directory": str(case_work_path),
        "message": f"Investigation initiated for case: {case_name}",
        "progress_file": str(case_work_path / "investigation_status.json"),
        "note": "Background investigation running. Progress updates every 10 seconds."
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
}

# Triage indicators for severity classification (used for reporting, NOT for
# playbook selection — all playbooks always run regardless)
TRIAGE_PATTERNS = {
    "ransomware": [".locked", ".encrypted", ".crypt", "readme_decrypt", "how_to_decrypt",
                   "recover_files", ".locky", ".cerber", ".sage", ".globe",
                   "your_files_are", "ransom_note", "decrypt_instructions"],
    "credential_theft": ["mimikatz", "lsass", "ntds.dit", "procdump", "hashdump",
                         "creddump", "cachedump", "secretsdump"],
    "lateral_movement": ["psexec", "wmic", "winrm", "sharpexec", "remcom",
                         "paexec", "cmbexec", "dcom", "atexec"],
    "persistence": ["autorun", "run_once", "scheduled_task", "startup",
                    "wmi_subscription", "com_hijack", "shell:"],
    "exfiltration": ["megasync", "dropbox", "onedrive", "googledrive",
                    "rsync", "scp", "sftp", "ftp_upload", "exfil"],
    "anti_forensics": ["eventlog_clear", "wevtutil cl", "log clear",
                      "timestomp", "timemodify", "ccleaner", "bleachbit"],
    "web_shell": ["c99", "r57", "wso", "b374k", "alfa", "cmd=", "exec=",
                  "shell=", "eval(", "base64_decode", "webshell"],
    "lolbin": ["certutil", "bitsadmin", "mshta", "rundll32", "regsvr32",
               "wmic", "msbuild", "installutil", "msiexec"],
    "c2": ["cobalt strike", "beacon", "covenant", "sliver", "poshc2", "empire",
            "cobaltstrike", "teamserver", "metasploit"],
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
        ],
        "disk_images": [
            ("sleuthkit", "list_files", {"image": "{image}", "offset": "{offset}", "recursive": True}),
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
    "PB-SIFT-017": {  # REMnux Malware Analysis
        "disk_images": [
            ("remnux", "die_scan", {"target_file": "{image}"}),
            ("remnux", "clamav_scan", {"target_file": "{image}"}),
        ],
        "memory_dumps": [
            ("remnux", "floss_strings", {"target_file": "{mem}"}),
        ],
        "other_files": [
            ("remnux", "exiftool_scan", {"target_file": "{file}"}),
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
    "PB-SIFT-020": {  # Timeline Analysis — psort after log2timeline
        "disk_images": [
            ("plaso", "sort_timeline", {
                "storage_file": "{output_dir}/timeline_{image_stem}.plaso",
                "output_format": "json_line",
                "filter": None,
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

    disk_ext = {'.e01', '.ee01', '.dd', '.raw', '.img', '.001', '.002', '.aff', '.aff4', '.ex01'}
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
                                 "confidence": "POSSIBLE", "source": "filename_scan"})
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
                ["bash", "-c", f"strings -n 8 {str(fpath)} | head -c 500000"],
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
                        })
                        break  # one hit per category per file
        except (subprocess.TimeoutExpired, OSError, IOError):
            continue
    
    # Phase 3: Direct content scan for text-accessible evidence
    text_extensions = {".evtx", ".log", ".txt", ".xml", ".json", ".csv",
                       ".sys", ".reg", ".ini", ".cfg", ".conf", ".bat",
                       ".ps1", ".vbs", ".js", ".html", ".php"}
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
                        })
                        break  # one hit per category per file
        except (OSError, IOError, PermissionError):
            continue  # can't read, skip silently
    
    return hits


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
    os_type = _detect_os(inventory)
    indicator_hits = _scan_triage_indicators(inventory)

    _update_job(5, "inventory", "Complete", log_msg="Evidence inventory complete")

    # ------------------------------------------------------------------
    # Phase 1b: Detect partition offsets for each disk image
    # ------------------------------------------------------------------
    image_offsets = {}  # image_path -> first filesystem partition offset
    for img in inventory.get("disk_images", []):
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
                image_offsets[img] = 2048  # fallback to common default
                _fe_log(job_id, f"Using default offset 2048 for {Path(img).name}")
        except Exception as e:
            image_offsets[img] = 2048
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
        safe_run(['git', 'init'], cwd=case_work_dir, timeout=30, check=True)
        safe_run(['git', 'config', 'user.email', 'geoff@dfir.local'], cwd=case_work_dir, timeout=10)
        safe_run(['git', 'config', 'user.name', 'Geoff DFIR'], cwd=case_work_dir, timeout=10)
        safe_run(['git', 'config', '--add', 'safe.directory', str(case_work_dir)], cwd=case_work_dir, timeout=10)
        # Write .gitignore for case directory
        with open(case_work_dir / '.gitignore', 'w') as f:
            f.write('# GEOFF case directory - evidence artifacts\n*.E01\n*.E02\n*.E03\n*.dd\n*.raw\n*.img\n*.aff\n*.vmem\n*.dmp\n*.pcap\n*.pcapng\n')
        safe_git_commit('Initial case setup', base_path=str(case_work_dir))
    except Exception as e:
        _log_error(f"git init case_work_dir {case_work_dir}", e)

    _update_job(8, "setup", "Case directory ready", log_msg=f"Case directory ready: {case_work_dir}")

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
        except Exception:
            pass  # Non-critical recovery — don't block startup

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
            except Exception:
                pass
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
    findings = []
    critic_results = []
    playbooks_run = []
    steps_completed = 0
    steps_failed = 0
    steps_skipped = 0
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
        pass  # No macOS-specific playbook; generic disk playbooks handle it

    # OS-agnostic playbooks
    execution_plan.extend(["PB-SIFT-009", "PB-SIFT-013"])

    # Add malware playbooks if suspicious binaries found
    suspicious_binary_found = False
    for f in triage_findings:
        result_str = json.dumps(f.get("result", f.get("error", "")), default=str).lower()
        if any(kw in result_str for kw in ["malware", "suspicious", "malicious", "trojan", "backdoor", "ransomware"]):
            suspicious_binary_found = True
            break
    if suspicious_binary_found:
        execution_plan.extend(["PB-SIFT-017", "PB-SIFT-018"])
    else:
        skipped_playbooks.append({"id": "PB-SIFT-017", "reason": "No suspicious binary surfaced during triage"})
        skipped_playbooks.append({"id": "PB-SIFT-018", "reason": "No suspicious binary surfaced during triage"})

    # Timeline analysis — always run if disk images present (psort after log2timeline)
    if len(inventory["disk_images"]) > 0:
        execution_plan.append("PB-SIFT-020")

    # Cross-image correlation last (if multi-host)
    if len(inventory["disk_images"]) > 1:
        execution_plan.append("PB-SIFT-016")
    else:
        skipped_playbooks.append({"id": "PB-SIFT-016", "reason": "Only one disk image in scope"})

    # Deduplicate while preserving order
    seen = set()
    execution_plan = [pb for pb in execution_plan if not (pb in seen or seen.add(pb))]

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

    # Classification based on indicator hits (indicator_hits is a list of dicts)
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
    elif suspicious_binary_found:
        classification = "Malware"
        severity = "HIGH"
    elif "exfiltration" in hit_categories:
        classification = "Exfiltration"
        severity = "MEDIUM"

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
    # Phase 3b: Execute Playbooks from Execution Plan
    # ------------------------------------------------------------------
    total_pb = len(execution_plan)
    for pb_idx, playbook_id in enumerate(execution_plan):
        pb_progress_base = 10 + (80 * pb_idx / total_pb)  # 10–90% range for playbooks
        pb_name = PLAYBOOK_NAMES.get(playbook_id, playbook_id)
        _update_job(pb_progress_base, playbook_id, "Starting", log_msg=f"\u25b6 {playbook_id}: {pb_name}")

        pb_steps_def = PLAYBOOK_STEPS.get(playbook_id, {})
        pb_findings = []
        any_step_ran = False

        for ev_type, step_templates in pb_steps_def.items():
            if _abort:
                break
            evidence_items = ev.get(ev_type, [])
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
                        "status": "running",
                        "started_at": datetime.now().isoformat(),
                    }

                    # Idempotency: skip if already completed with same inputs
                    if any(s.get("step_key") == step_key and s.get("status") == "completed" for s in findings):
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
                                for s in findings
                            )
                            if not dep_completed:
                                _fe_log(job_id, f"  ⚠ {module}.{function} skipped — dependency {dep} not complete")
                                step_record = {
                                    "playbook": playbook_id, "step_key": step_key, "execution_hash": execution_hash,
                                    "module": module, "function": function, "params": params,
                                    "evidence_file": item, "status": "skipped", "error": f"dependency {dep} not met",
                                    "started_at": datetime.now().isoformat(), "completed_at": datetime.now().isoformat(),
                                }
                                findings.append(step_record)
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
                    except Exception:
                        pass  # Non-critical — best-effort state persistence

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
                                findings.append(step_record)
                                pb_findings.append(step_record)
                                continue
                            elif result["code"] < 0:
                                step_record["status"] = "failed"
                                step_record["error"] = f"Execution error: {result.get('stderr', '')}"
                                step_record["result"] = {"status": "failed", "stdout": "", "stderr": result.get('stderr', ''), "artifacts": [], "error": "execution_error"}
                                steps_failed += 1
                                _fe_log(job_id, f"  ✗ {module}.{function} → execution error")
                                findings.append(step_record)
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

                        # Critic validation
                        try:
                            critic_val = geoff_critic.validate_tool_output(
                                tool_name=f"{module}.{function}",
                                tool_params=params,
                                raw_output=json.dumps(result, default=str)[:8000],
                                geoff_analysis=f"Find Evil auto-run: {playbook_id} → {module}.{function}",
                            )
                            step_record["critic"] = critic_val
                            critic_results.append(critic_val)
                            # Write validation to case validations/ directory
                            try:
                                val_dir = case_work_dir / "validations"
                                val_dir.mkdir(exist_ok=True)
                                val_file = val_dir / f"{step_key.replace(':', '_')}.json"
                                _atomic_write(val_file, json.dumps(critic_val, default=str, indent=2))
                            except Exception:
                                pass  # Non-critical
                        except Exception as ce:
                            _fe_log_with_exception(job_id, f"  ✗ Critic validation for {module}.{function}", ce)
                            step_record["critic_error"] = str(ce)
                    except Exception as e:
                        _fe_log_with_exception(job_id, f"  ✗ {module}.{function} step error", e)
                        step_record["status"] = "failed"
                        step_record["error"] = str(e)
                        steps_failed += 1

                    step_record["completed_at"] = datetime.now().isoformat()
                    findings.append(step_record)
                    pb_findings.append(step_record)

                    # CONTINUE_ON_FAILURE enforcement
                    if step_record["status"] == "failed" and not CONTINUE_ON_FAILURE:
                        _fe_log(job_id, f"\u26a0 Step failed — stopping execution (CONTINUE_ON_FAILURE=false)")
                        # Break out of all loops
                        break

        # Check if we broke out due to failure
        if not CONTINUE_ON_FAILURE:
            failed_steps = [s for s in pb_findings if s.get("status") == "failed"]
            if failed_steps and any(s.get("step_key", "").startswith(playbook_id) for s in findings[-3:]):
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
                confidence_modifiers.append("ANTI-FORENSICS-CONFIRMED")
                _fe_log(job_id, "\u26a0 PB-SIFT-012: Anti-forensics confirmed — retroactively downgrading all findings")
                # Downgrade all findings across ALL playbooks and mark compromised
                for f in findings:
                    if isinstance(f.get("result"), dict):
                        confidence = f["result"].get("confidence", "")
                        if confidence == "CONFIRMED":
                            f["result"]["confidence"] = "POSSIBLE"
                        elif confidence == "POSSIBLE":
                            f["result"]["confidence"] = "UNVERIFIED"
                        # Mark all findings as potentially compromised
                        if "compromised_by" not in f["result"]:
                            f["result"]["compromised_by"] = []
                        if "anti-forensics" not in f["result"]["compromised_by"]:
                            f["result"]["compromised_by"].append("anti-forensics")
                        f["result"]["confidence_modifier"] = "downgraded-by-anti-forensics"

        playbooks_run.append({
            "playbook_id": playbook_id,
            "steps_attempted": len(pb_findings),
            "steps_completed": sum(1 for s in pb_findings if s.get("status") == "completed"),
            "steps_skipped": sum(1 for s in pb_findings if s.get("status") == "skipped"),
            "steps_failed": sum(1 for s in pb_findings if s.get("status") == "failed"),
        })

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

    # ------------------------------------------------------------------
    # Phase 3b: Multi-Host Correlation
    # ------------------------------------------------------------------
    _update_job(92, "correlation", "Cross-image timeline merge", log_msg="Merging timelines across disk images")

    timeline_files = []
    if len(inventory["disk_images"]) > 1:
        # Individual timelines already created in PB-SIFT-016 / PB-SIFT-018
        # Find them in the output dir
        timeline_files = list(Path(output_dir).glob("timeline_*.plaso"))

        if len(timeline_files) > 1:
            # Merge timelines by re-running log2timeline for each image
            # into the SAME storage file. log2timeline.py takes evidence sources
            # (disk images), NOT .plaso files — so we must re-process from
            # the original images. Plaso appends to existing storage files.
            merged_output = str(case_work_dir / "timeline" / "merged.plaso")
            try:
                images_processed = 0
                for img_info in inventory.get("disk_images", []):
                    img_path = img_info if isinstance(img_info, str) else img_info.get("path", "")
                    if not img_path:
                        continue
                    merge_cmd = [
                        "python3", "/usr/bin/log2timeline.py",
                        "--status_view", "none",
                        merged_output,  # storage file (appends if exists)
                        img_path,       # evidence source
                    ]
                    merge_result = safe_run(merge_cmd, timeout=600)
                    if merge_result["code"] == 0:
                        images_processed += 1

                if images_processed > 0:
                    # Run correlation analysis on the merged timeline
                    correlation = _correlate_timelines(
                        merged_output, case_work_dir, job_id
                    )
                    findings.append({
                        "playbook": "PB-SIFT-016",
                        "module": "plaso",
                        "function": "merge_timelines",
                        "status": "completed",
                        "result": {
                            "merged_output": merged_output,
                            "source_timelines": len(timeline_files),
                            "images_processed": images_processed,
                            "correlation": correlation,
                        },
                        "started_at": datetime.now().isoformat(),
                        "completed_at": datetime.now().isoformat(),
                    })
                else:
                    findings.append({
                        "playbook": "PB-SIFT-016",
                        "module": "plaso",
                        "function": "merge_timelines",
                        "status": "failed",
                        "error": "No images could be processed for merge",
                    })
            except Exception as e:
                findings.append({
                    "playbook": "PB-SIFT-016",
                    "module": "plaso",
                    "function": "merge_timelines",
                    "status": "failed",
                    "error": str(e),
                })

    # ------------------------------------------------------------------
    # Phase 3c: User Activity Extraction (Cross-Host)
    # ------------------------------------------------------------------
    user_activity_summary = {}

    # Try to extract per-user activity from merged or individual timelines
    timeline_for_extraction = list(Path(output_dir).glob("timeline_*.plaso"))
    merged_plaso = case_work_dir / "timeline" / "merged.plaso"
    if merged_plaso.exists():
        timeline_for_extraction = [merged_plaso]

    if timeline_for_extraction:
        _update_job(93, "correlation", "Extracting user activity across hosts", log_msg="Extracting per-user activity across hosts")
        try:
            # Plaso's json_line format puts user info in the 'message' field,
            # NOT in top-level 'username'/'hostname' fields. We must parse
            # the message field with regex patterns to extract them.
            _USERNAME_PATTERNS = [
                re.compile(r'\bAccount Name:\s*([\\\w.\-]+)', re.IGNORECASE),
                re.compile(r'\bUser Name?:\s*([\\\w.\-]+)', re.IGNORECASE),
                re.compile(r'\bLogon Name?:\s*([\\\w.\-]+)', re.IGNORECASE),
                re.compile(r'\bSubject:\s*([\\\w.\-]+)', re.IGNORECASE),
            ]
            _HOSTNAME_PATTERNS = [
                re.compile(r'\bSource Network Address:\s*([\\\w.\-]+)', re.IGNORECASE),
                re.compile(r'\bWorkstation Name?:\s*([\\\w.\-]+)', re.IGNORECASE),
                re.compile(r'\bComputer Name?:\s*([\\\w.\-]+)', re.IGNORECASE),
                re.compile(r'\bSource Host:\s*([\\\w.\-]+)', re.IGNORECASE),
            ]

            # Focused event types for user activity (removed low-value 'filestat')
            user_event_types = {
                "windows:registry:userassist",
                "windows:evt:4624", "windows:evt:4625", "windows:evt:4648", "windows:evt:4688",
                "windows:evtx:4624", "windows:evtx:4625", "windows:evtx:4648", "windows:evtx:4688",
                "shell:history",
                "browser:chrome:history", "browser:firefox:history",
                "santa:execution",
            }

            for tl_path in timeline_for_extraction:
                try:
                    # Use json_line format — each line is a complete JSON object
                    psort_cmd = [
                        "python3", "/usr/bin/psort.py",
                        "-o", "json_line",
                        str(tl_path),
                    ]
                    psort_result = safe_run(psort_cmd, timeout=300)

                    if psort_result["code"] == 0 and psort_result["stdout"]:
                        for line in psort_result["stdout"].strip().split("\n"):
                            try:
                                event = json.loads(line)
                            except (json.JSONDecodeError, ValueError):
                                continue

                            # Try top-level fields first (some Plaso versions)
                            username = event.get("username", "") or ""
                            hostname = event.get("hostname", "") or event.get("computer_name", "") or ""
                            event_type = event.get("data_type", "")
                            timestamp = event.get("datetime", "")
                            message = event.get("message", "")

                            # Fall back to message field regex extraction
                            if not username:
                                for pat in _USERNAME_PATTERNS:
                                    m = pat.search(message)
                                    if m:
                                        username = m.group(1)
                                        break
                            if not hostname:
                                for pat in _HOSTNAME_PATTERNS:
                                    m = pat.search(message)
                                    if m:
                                        hostname = m.group(1)
                                        break

                            if not username:
                                continue

                            # Filter to user-relevant event types
                            if event_type not in user_event_types and event_type:
                                continue

                            user_key = f"{username}@{hostname}" if hostname else username

                            if user_key not in user_activity_summary:
                                user_activity_summary[user_key] = {
                                    "username": username,
                                    "hosts": set(),
                                    "event_types": {},
                                    "timeline": [],
                                    "lateral_movement_indicators": [],
                                }

                            user_activity_summary[user_key]["hosts"].add(hostname)
                            user_activity_summary[user_key]["event_types"][event_type] = \
                                user_activity_summary[user_key]["event_types"].get(event_type, 0) + 1

                            if len(user_activity_summary[user_key]["timeline"]) < 100:
                                user_activity_summary[user_key]["timeline"].append({
                                    "timestamp": timestamp,
                                    "event_type": event_type,
                                    "host": hostname,
                                    "detail": message[:200],
                                })

                    # Targeted queries for high-value Windows event IDs
                    # Best source for lateral movement detection
                    for evt_filter in ["4624", "4648", "4688"]:
                        try:
                            targeted_cmd = [
                                "python3", "/usr/bin/psort.py",
                                str(tl_path),
                                f"event_identifier IS {evt_filter}",
                                "-o", "json_line",
                            ]
                            targeted_result = safe_run(targeted_cmd, timeout=120)
                            if targeted_result["code"] == 0 and targeted_result["stdout"]:
                                for line in targeted_result["stdout"].strip().split("\n"):
                                    try:
                                        event = json.loads(line)
                                    except (json.JSONDecodeError, ValueError):
                                        continue

                                    message = event.get("message", "")
                                    username = event.get("username", "") or ""
                                    hostname = event.get("hostname", "") or event.get("computer_name", "") or ""

                                    # Extract from message if top-level fields empty
                                    if not username:
                                        for pat in _USERNAME_PATTERNS:
                                            m = pat.search(message)
                                            if m:
                                                username = m.group(1)
                                                break
                                    if not hostname:
                                        for pat in _HOSTNAME_PATTERNS:
                                            m = pat.search(message)
                                            if m:
                                                hostname = m.group(1)
                                                break

                                    if not username:
                                        continue
                                    user_key = f"{username}@{hostname}" if hostname else username

                                    if user_key not in user_activity_summary:
                                        user_activity_summary[user_key] = {
                                            "username": username,
                                            "hosts": set(),
                                            "event_types": {},
                                            "timeline": [],
                                            "lateral_movement_indicators": [],
                                        }

                                    # Track lateral movement: same user across multiple hosts
                                    user_activity_summary[user_key]["hosts"].add(hostname)
                                    if len(user_activity_summary[user_key]["hosts"]) > 1:
                                        user_activity_summary[user_key]["lateral_movement_indicators"].append({
                                            "type": "cross_host_activity",
                                            "user": username,
                                            "hosts": list(user_activity_summary[user_key]["hosts"]),
                                            "event": message[:200],
                                            "timestamp": event.get("datetime", ""),
                                            "event_id": evt_filter,
                                        })
                        except Exception as e:
                            _log_error(f"User activity event parsing for ID {evt_filter}", e)

                except Exception as e:
                    findings.append({
                        "playbook": "PB-SIFT-016",
                        "module": "plaso",
                        "function": "extract_user_activity",
                        "status": "failed",
                        "error": str(e),
                    })
            # Convert sets to sorted lists for JSON serialization
            for user_key in user_activity_summary:
                user_activity_summary[user_key]["hosts"] = sorted(
                    user_activity_summary[user_key]["hosts"]
                )
                # Deduplicate lateral movement indicators (max 50)
                lmi = user_activity_summary[user_key]["lateral_movement_indicators"]
                seen = set()
                deduped = []
                for indicator in lmi:
                    sig = f"{indicator.get('type','')}:{indicator.get('timestamp','')}"
                    if sig not in seen:
                        seen.add(sig)
                        deduped.append(indicator)
                    if len(deduped) >= 50:
                        break
                user_activity_summary[user_key]["lateral_movement_indicators"] = deduped

            if user_activity_summary:
                findings.append({
                    "playbook": "PB-SIFT-016",
                    "module": "plaso",
                    "function": "user_activity_extraction",
                    "status": "completed",
                    "result": {
                        "users_tracked": len(user_activity_summary),
                        "users_with_cross_host_activity": sum(
                            1 for u in user_activity_summary.values()
                            if len(u["hosts"]) > 1
                        ),
                        "lateral_movement_indicators": sum(
                            len(u["lateral_movement_indicators"])
                            for u in user_activity_summary.values()
                        ),
                    },
                    "started_at": datetime.now().isoformat(),
                    "completed_at": datetime.now().isoformat(),
                })

        except Exception as e:
            findings.append({
                "playbook": "PB-SIFT-016",
                "module": "plaso",
                "function": "user_activity_extraction",
                "status": "failed",
                "error": str(e),
            })


    # ------------------------------------------------------------------
    # Phase 3d: LLM Analysis of Findings
    # ------------------------------------------------------------------
    _update_job(94, "analysis", "Analyzing findings with LLM", log_msg="LLM analyzing collected findings for patterns and conclusions")
    try:
        # Build a condensed summary of findings for LLM context
        findings_summary = []
        for f in findings:
            if f.get("status") != "completed":
                continue
            result = f.get("result", {})
            if not isinstance(result, dict):
                continue
            summary = {
                "playbook": f.get("playbook", ""),
                "module": f.get("module", ""),
                "function": f.get("function", ""),
            }
            for key in ["total_strings", "ioc_counts", "event_count", "files_count",
                        "partitions", "processes", "connections", "suspicious",
                        "total_files", "deleted_files", "iocs", "registry_keys",
                        "confidence", "severity", "category"]:
                if key in result:
                    val = result[key]
                    if isinstance(val, (dict, list)) and len(str(val)) > 500:
                        val = str(val)[:500] + "..."
                    summary[key] = val
            findings_summary.append(summary)

        if findings_summary:
            summary_text = json.dumps(findings_summary[:50], default=str)
            if len(summary_text) > 8000:
                summary_text = summary_text[:8000] + "..."

            analysis_prompt = f"""Analyze the following forensic findings and provide:
1. KEY_FINDINGS: 3-5 most important findings with confidence (POSSIBLE/CONFIRMED)
2. ATTACK_TIMELINE: Chronological sequence of events (if timeline data exists)
3. RECOMMENDATIONS: 2-3 actionable next steps for the investigator
4. SUMMARY: One-paragraph executive summary

Findings data:
{summary_text}

Evidence type: {os_type}
Playbooks run: {', '.join(p['playbook_id'] for p in playbooks_run)}
Anti-forensics detected: {('Yes' if 'ANTI-FORENSICS-CONFIRMED' in confidence_modifiers else 'No')}

Respond in JSON format with keys: key_findings, attack_timeline, recommendations, summary"""

            llm_analysis = call_llm(analysis_prompt, context="", agent_type="manager")

            try:
                json_match = re.search(r'\{.*\}', llm_analysis, re.DOTALL)
                if json_match:
                    analysis_result = json.loads(json_match.group())
                else:
                    analysis_result = {"raw_analysis": llm_analysis}
            except (json.JSONDecodeError, ValueError):
                analysis_result = {"raw_analysis": llm_analysis}

            findings.append({
                "playbook": "ANALYSIS",
                "module": "llm",
                "function": "analyze_findings",
                "status": "completed",
                "result": analysis_result,
                "started_at": datetime.now().isoformat(),
                "completed_at": datetime.now().isoformat(),
            })
    except Exception as e:
        _log_error("LLM analysis failed", e)
        findings.append({
            "playbook": "ANALYSIS",
            "module": "llm",
            "function": "analyze_findings",
            "status": "failed",
            "error": str(e),
        })

    # ------------------------------------------------------------------
    # Phase 4: Aggregate Findings & Severity
    # ------------------------------------------------------------------
    _update_job(95, "reporting", "Aggregating findings", log_msg="Aggregating findings from all playbooks")

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    evil_found = False

    # From triage indicators — only POSSIBLE confidence from string/filename hits
    # evil_found requires CONFIRMED findings or multiple distinct-category POSSIBLE hits
    possible_categories = set()
    for hit in indicator_hits:
        sev = hit["severity"]
        confidence = hit.get("confidence", "POSSIBLE")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        if confidence == "CONFIRMED":
            evil_found = True
        elif confidence == "POSSIBLE":
            possible_categories.add(hit["category"])
    # Require 2+ distinct POSSIBLE categories to flag evil
    if not evil_found and len(possible_categories) >= 2:
        evil_found = True

    # From specialist results
    for f in findings:
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

    # Critic summary
    critic_approved = sum(1 for c in critic_results if isinstance(c, dict) and c.get("valid", False))
    critic_total = len(critic_results)
    critic_pct = (critic_approved / critic_total * 100) if critic_total > 0 else 100.0

    elapsed = time.time() - start_time

    report = {
        "title": f"Find Evil Report — {case_name}",
        "generated_at": datetime.now().isoformat(),
        "evidence_dir": str(evidence_dir),
        "os_type": os_type,
        "evil_found": evil_found,
        "severity": overall_severity,
        "severity_distribution": severity_counts,
        "indicator_hits": indicator_hits,
        "playbooks_run": playbooks_run,
        "playbooks_total": total_pb,
        "specialist_steps_executed": len(findings),
        "steps_completed": steps_completed,
        "steps_failed": steps_failed,
        "steps_skipped": steps_skipped,
        "critic_approval_pct": round(critic_pct, 1),
        "findings_detail": findings,
        "user_activity_summary": user_activity_summary,
        "elapsed_seconds": round(elapsed, 1),
        "case_work_dir": str(case_work_dir),
        "failures": [f for f in findings if f.get("status") == "failed"],
        "investigation_status": "complete" if steps_failed == 0 else "complete_with_failures",
        "confidence_modifiers": confidence_modifiers if 'confidence_modifiers' in dir() else [],
        "llm_analysis": next((f["result"] for f in findings if f.get("playbook") == "ANALYSIS" and f.get("status") == "completed"), None),
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
            for i, f in enumerate(findings)
        ],
        "current_step": len(findings),
    }

    try:
        validate_investigation_state(investigation_state)
    except ValidationError as ve:
        report["schema_validation_warning"] = str(ve.message)

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
        'steps_executed': len(findings),
        'elapsed_seconds': round(elapsed, 1),
        'description': f"Find Evil run on {evidence_dir}",
    })

    _update_job(100, "complete", "Done", log_msg="\u2714 Find Evil complete")
    return report


# ---------------------------------------------------------------------------
# HTML Template (with Find Evil tab)
# ---------------------------------------------------------------------------

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Geoff DFIR</title>
    <meta charset="UTF-8">
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #0d1117;
            color: #c9d1d9;
            height: 100vh;
            display: flex;
            flex-direction: column;
        }
        
        header {
            background: #161b22;
            border-bottom: 1px solid #30363d;
            padding: 15px 25px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        h1 { color: #58a6ff; font-size: 1.4rem; }
        h1 span { color: #8b949e; font-size: 0.7em; font-weight: normal; }
        
        .status { color: #3fb950; font-size: 0.85rem; }
        
        .tabs {
            display: flex;
            background: #161b22;
            border-bottom: 1px solid #30363d;
            padding: 0 25px;
        }
        
        .tab {
            padding: 12px 24px;
            cursor: pointer;
            color: #8b949e;
            border-bottom: 2px solid transparent;
            transition: all 0.2s;
        }
        
        .tab:hover { color: #c9d1d9; }
        .tab.active { 
            color: #58a6ff; 
            border-bottom-color: #58a6ff;
            background: #0d1117;
        }
        
        .content {
            flex: 1;
            overflow: hidden;
            display: none;
        }
        
        .content.active { display: flex; flex-direction: column; }
        
        /* Chat Styles */
        #chat-content {
            flex: 1;
            overflow-y: auto;
            padding: 20px;
            display: flex;
            flex-direction: column;
            gap: 12px;
        }
        
        .message {
            max-width: 85%;
            padding: 12px 16px;
            border-radius: 8px;
            line-height: 1.6;
            font-size: 0.95rem;
        }
        
        .message.user {
            align-self: flex-end;
            background: #1f6feb;
            color: white;
        }
        
        .message.geoff {
            align-self: flex-start;
            background: #21262d;
            border: 1px solid #30363d;
            color: #c9d1d9;
            white-space: pre-wrap;
        }
        
        .message.system {
            align-self: center;
            background: transparent;
            color: #8b949e;
            font-style: italic;
            font-size: 0.85rem;
        }
        
        .message.tool-result {
            align-self: flex-start;
            background: #1c4428;
            border: 1px solid #238636;
            color: #c9d1d9;
            font-family: 'SF Mono', Monaco, monospace;
            font-size: 0.85rem;
        }
        
        .message .label {
            font-size: 0.75rem;
            font-weight: 600;
            margin-bottom: 4px;
            opacity: 0.8;
            text-transform: uppercase;
        }
        
        .chat-input-area {
            padding: 15px 25px;
            background: #161b22;
            border-top: 1px solid #30363d;
            display: flex;
            gap: 10px;
        }
        
        #chat-input {
            flex: 1;
            padding: 12px 16px;
            background: #0d1117;
            border: 1px solid #30363d;
            border-radius: 6px;
            color: #c9d1d9;
            font-size: 0.95rem;
        }
        
        #chat-input:focus {
            outline: none;
            border-color: #58a6ff;
        }
        
        .send-btn {
            padding: 12px 24px;
            background: #238636;
            color: white;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-weight: 600;
        }
        
        .send-btn:hover { background: #2ea043; }
        
        /* Evidence Styles */
        #evidence-content {
            flex: 1;
            overflow-y: auto;
            padding: 20px 25px;
        }
        
        .case-list {
            display: flex;
            flex-direction: column;
            gap: 15px;
        }
        
        .case-card {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            overflow: hidden;
        }
        
        .case-header {
            padding: 12px 16px;
            background: #21262d;
            border-bottom: 1px solid #30363d;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .case-name {
            font-weight: 600;
            color: #58a6ff;
            font-size: 1.1rem;
        }
        
        .case-count {
            color: #8b949e;
            font-size: 0.85rem;
        }
        
        .case-files {
            padding: 12px 16px;
        }
        
        .file-item {
            padding: 6px 0;
            border-bottom: 1px solid #21262d;
            font-family: 'SF Mono', Monaco, monospace;
            font-size: 0.85rem;
            color: #c9d1d9;
        }
        
        .file-item:last-child { border-bottom: none; }
        
        .file-item.dir { color: #58a6ff; }
        .file-item.file { color: #a371f7; }
        
        /* Find Evil Tab Styles */
        #findevil-content {
            flex: 1;
            overflow-y: auto;
            padding: 20px 25px;
            display: flex;
            flex-direction: column;
            gap: 16px;
        }

        .fe-config {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 16px;
        }

        .fe-config label {
            display: block;
            color: #8b949e;
            font-size: 0.85rem;
            margin-bottom: 6px;
        }

        .fe-config input[type="text"] {
            width: 100%;
            padding: 10px 14px;
            background: #0d1117;
            border: 1px solid #30363d;
            border-radius: 6px;
            color: #c9d1d9;
            font-size: 0.95rem;
            font-family: 'SF Mono', Monaco, monospace;
        }

        .fe-config input:focus {
            outline: none;
            border-color: #58a6ff;
        }

        .fe-run-btn {
            margin-top: 12px;
            padding: 12px 28px;
            background: #da3633;
            color: white;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-weight: 700;
            font-size: 1rem;
            transition: background 0.2s;
        }

        .fe-run-btn:hover { background: #f85149; }
        .fe-run-btn:disabled { background: #484f58; cursor: not-allowed; }

        .fe-progress {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 16px;
        }

        .fe-progress-bar {
            width: 100%;
            height: 22px;
            background: #21262d;
            border-radius: 6px;
            overflow: hidden;
            margin: 10px 0;
        }

        .fe-progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #238636, #3fb950);
            border-radius: 6px;
            transition: width 0.5s ease;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 0.75rem;
            font-weight: 700;
            color: white;
            min-width: 40px;
        }

        .fe-status-text {
            color: #8b949e;
            font-size: 0.85rem;
        }

        .fe-status-text strong {
            color: #c9d1d9;
        }

        .fe-results {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 16px;
        }

        .fe-severity {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 4px;
            font-weight: 700;
            font-size: 0.85rem;
            margin-bottom: 10px;
        }

        .fe-severity.CRITICAL { background: #da3633; color: white; }
        .fe-severity.HIGH     { background: #d29922; color: #0d1117; }
        .fe-severity.MEDIUM   { background: #1f6feb; color: white; }
        .fe-severity.LOW      { background: #238636; color: white; }
        .fe-severity.INFO     { background: #30363d; color: #8b949e; }

        .fe-pb-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
            font-size: 0.85rem;
        }

        .fe-pb-table th {
            text-align: left;
            padding: 8px 10px;
            border-bottom: 1px solid #30363d;
            color: #8b949e;
        }

        .fe-pb-table td {
            padding: 6px 10px;
            border-bottom: 1px solid #21262d;
        }

        .fe-pb-table .completed { color: #3fb950; }
        .fe-pb-table .failed    { color: #f85149; }
        .fe-pb-table .skipped   { color: #8b949e; }

        /* Tools Panel (kept for reference) */
        #tools-content {
            flex: 1;
            overflow-y: auto;
            padding: 20px 25px;
        }
        
        .tool-category {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 16px;
            margin-bottom: 16px;
        }
        
        .tool-category h3 {
            color: #58a6ff;
            margin-bottom: 12px;
            font-size: 1rem;
        }
        
        .tool-status {
            display: flex;
            align-items: center;
            gap: 8px;
            margin-bottom: 8px;
            font-size: 0.9rem;
        }
        
        .tool-status.available { color: #3fb950; }
        .tool-status.unavailable { color: #f85149; }
        
        .tool-functions {
            font-family: 'SF Mono', Monaco, monospace;
            font-size: 0.8rem;
            color: #8b949e;
            margin-left: 20px;
        }
        
        .loading {
            text-align: center;
            padding: 40px;
            color: #8b949e;
        }
    </style>
</head>
<body>
    <header>
        <h1>Geoff <span>DFIR Investigation Platform</span></h1>
        <div class="status">● Online</div>
    </header>
    
    <div class="tabs">
        <div class="tab active" onclick="showTab('chat')">💬 Chat</div>
        <div class="tab" onclick="showTab('evidence')">📁 Evidence</div>
        <div class="tab" onclick="showTab('findevil')">🔍 Find Evil</div>
    </div>
    
    <div id="chat" class="content active">
        <div id="chat-content">
            <div class="message system">G.E.O.F.F. initialized. Evidence Operations Forensic Framework standing by.

Awaiting investigation directive. Provide case name or evidence path to begin systematic analysis.

Available: 32 forensic functions across 9 specialist modules + REMnux.
Playbook library: 19 PB-SIFT investigation protocols (all run, no cherry-picking).</div>
        </div>
        <div class="chat-input-area">
            <input type="text" id="chat-input" placeholder="e.g., Run mmls on the narcos disk image..." onkeypress="if(event.key==='Enter') sendChat()">
            <button class="send-btn" onclick="sendChat()">Send</button>
        </div>
    </div>
    
    <div id="evidence" class="content">
        <div id="evidence-content">
            <div class="loading">Loading evidence...</div>
        </div>
    </div>

    <div id="findevil" class="content">
        <div id="findevil-content">
            <div class="fe-config">
                <label for="fe-evidence-dir">Evidence Directory</label>
                <input type="text" id="fe-evidence-dir" placeholder="/path/to/evidence (leave blank for default)">
                <button class="fe-run-btn" id="fe-run-btn" onclick="runFindEvil()">🔍 Run Find Evil</button>
            </div>
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
                <div id="fe-log" style="
                    margin-top: 12px;
                    background: #0d1117;
                    border: 1px solid #30363d;
                    border-radius: 6px;
                    padding: 12px;
                    font-family: 'JetBrains Mono', 'Fira Code', monospace;
                    font-size: 12px;
                    color: #8b949e;
                    max-height: 400px;
                    overflow-y: auto;
                    line-height: 1.6;
                "></div>
            </div>
            <div id="fe-results-area" style="display:none;"></div>
        </div>
    </div>
    
    <script>
        function showTab(tab) {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.content').forEach(c => c.classList.remove('active'));
            event.target.classList.add('active');
            document.getElementById(tab).classList.add('active');
            if(tab === 'evidence') loadEvidence();
        }
        
        function addMessage(text, type) {
            const chat = document.getElementById('chat-content');
            const div = document.createElement('div');
            div.className = 'message ' + type;
            if(type === 'user') {
                div.innerHTML = '<div class="label">You</div>' + text;
            } else if(type === 'geoff') {
                div.innerHTML = '<div class="label">Geoff</div>' + text;
            } else if(type === 'tool-result') {
                div.innerHTML = '<div class="label">Tool Output</div>' + text;
            } else {
                div.textContent = text;
            }
            chat.appendChild(div);
            chat.scrollTop = chat.scrollHeight;
        }
        
        async function sendChat() {
            const input = document.getElementById('chat-input');
            const text = input.value.trim();
            if(!text) return;
            
            addMessage(text, 'user');
            input.value = '';
            addMessage('Looking...', 'system');
            
            try {
                const res = await fetch('/chat', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({message: text})
                });
                const data = await res.json();
                
                const chat = document.getElementById('chat-content');
                chat.removeChild(chat.lastChild);
                
                addMessage(data.response, 'geoff');
                
                if(data.tool_result) {
                    addMessage(JSON.stringify(data.tool_result, null, 2), 'tool-result');
                }
                if(data.investigation_started) {
                    addMessage('Investigation started for: ' + data.case_name + '\\nPolling progress every 10 seconds...', 'system');
                    pollInvestigationStatus(data.case_name);
                }
            } catch(e) {
                const chat = document.getElementById('chat-content');
                chat.removeChild(chat.lastChild);
                addMessage('Error: ' + e.message, 'system');
            }
        }
        
        let investigationPollInterval = null;
        
        async function pollInvestigationStatus(caseName) {
            if(investigationPollInterval) clearInterval(investigationPollInterval);
            
            const poll = async () => {
                try {
                    const res = await fetch('/investigation/status/' + caseName);
                    if(res.ok) {
                        const status = await res.json();
                        
                        if(status.status === 'complete') {
                            addMessage(
                                '**Investigation Complete**\\n' +
                                'Case: ' + status.case + '\\n' +
                                'Progress: 100%\\n' +
                                'Total Time: ' + (status.elapsed_seconds / 60).toFixed(1) + ' minutes',
                                'system'
                            );
                            clearInterval(investigationPollInterval);
                        } else if(status.status === 'running') {
                            addMessage(
                                '**Investigation Progress**\\n' +
                                'Case: ' + status.case + '\\n' +
                                'Phase: ' + status.phase + '\\n' +
                                'Tool: ' + status.current_tool + '\\n' +
                                'Progress: ' + status.progress_percent + '%\\n' +
                                'Elapsed: ' + (status.elapsed_seconds / 60).toFixed(1) + ' minutes',
                                'system'
                            );
                        } else if(status.status === 'error') {
                            addMessage('Investigation Error: ' + (status.details?.error || 'Unknown error'), 'system');
                            clearInterval(investigationPollInterval);
                        }
                    }
                } catch(e) {
                    console.error('Poll error:', e);
                }
            };
            
            poll();
            investigationPollInterval = setInterval(poll, 10000);
        }
        
        async function loadEvidence() {
            const container = document.getElementById('evidence-content');
            container.innerHTML = '<div class="loading">Loading...</div>';
            
            try {
                const res = await fetch('/cases');
                const data = await res.json();
                const cases = data.cases || {};
                
                if(Object.keys(cases).length === 0) {
                    container.innerHTML = '<div class="loading">No cases found.</div>';
                    return;
                }
                
                let html = '<div class="case-list">';
                for(const [caseName, files] of Object.entries(cases)) {
                    html += '<div class="case-card">';
                    html += '<div class="case-header">';
                    html += '<span class="case-name">📁 ' + caseName + '</span>';
                    html += '<span class="case-count">' + files.length + ' items</span>';
                    html += '</div>';
                    html += '<div class="case-files">';
                    if(files.length === 0) {
                        html += '<div class="file-item">Empty case</div>';
                    } else {
                        files.forEach(f => {
                            const isDir = f.startsWith('[DIR]');
                            const cls = isDir ? 'dir' : 'file';
                            const display = isDir ? f.replace('[DIR] ', '') : f;
                            html += '<div class="file-item ' + cls + '">' + display + '</div>';
                        });
                    }
                    html += '</div></div>';
                }
                html += '</div>';
                container.innerHTML = html;
            } catch(e) {
                container.innerHTML = '<div class="loading">Error loading evidence: ' + e.message + '</div>';
            }
        }
        
        // ---- Find Evil UI ----
        let fePollInterval = null;

        async function runFindEvil() {
            const evidenceDir = document.getElementById('fe-evidence-dir').value.trim();
            const btn = document.getElementById('fe-run-btn');
            const progressArea = document.getElementById('fe-progress-area');
            const resultsArea = document.getElementById('fe-results-area');

            btn.disabled = true;
            btn.textContent = '⏳ Running...';
            progressArea.style.display = 'block';
            resultsArea.style.display = 'none';
            resultsArea.innerHTML = '';

            document.getElementById('fe-pb-name').textContent = 'Starting...';
            document.getElementById('fe-step-name').textContent = '';
            document.getElementById('fe-elapsed').textContent = '0s';
            document.getElementById('fe-progress-fill').style.width = '0%';
            document.getElementById('fe-progress-fill').textContent = '0%';

            try {
                const res = await fetch('/find-evil', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ evidence_dir: evidenceDir || '' })
                });
                const data = await res.json();

                if (data.job_id) {
                    // Async mode — poll for progress
                    pollFindEvilStatus(data.job_id);
                } else if (data.status === 'error') {
                    showFindEvilError(data.error || 'Unknown error');
                    btn.disabled = false;
                    btn.textContent = '🔍 Run Find Evil';
                } else {
                    // Sync result (shouldn't happen but handle gracefully)
                    showFindEvilResults(data);
                    btn.disabled = false;
                    btn.textContent = '🔍 Run Find Evil';
                }
            } catch(e) {
                showFindEvilError(e.message);
                btn.disabled = false;
                btn.textContent = '🔍 Run Find Evil';
            }
        }

        function pollFindEvilStatus(jobId) {
            if(fePollInterval) clearInterval(fePollInterval);
            let lastLogIndex = 0;

            const poll = async () => {
                try {
                    const res = await fetch('/find-evil/status/' + jobId);
                    if(res.ok) {
                        const status = await res.json();
                        const pct = status.progress_pct || 0;
                        document.getElementById('fe-pb-name').textContent = status.current_playbook || '—';
                        document.getElementById('fe-step-name').textContent = status.current_step || '';
                        document.getElementById('fe-elapsed').textContent = (status.elapsed_seconds || 0).toFixed(0) + 's';
                        document.getElementById('fe-progress-fill').style.width = pct + '%';
                        document.getElementById('fe-progress-fill').textContent = pct + '%';

                        // Stream log entries
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
                                line.style.color = color;
                                line.textContent = time + '  ' + msg;
                                logDiv.appendChild(line);
                            }
                            lastLogIndex = status.log.length;
                            logDiv.scrollTop = logDiv.scrollHeight;
                        }

                        if (status.status === 'complete') {
                            clearInterval(fePollInterval);
                            const report = status.result || {};
                            showFindEvilResults(report);
                            document.getElementById('fe-run-btn').disabled = false;
                            document.getElementById('fe-run-btn').textContent = '🔍 Run Find Evil';
                        } else if (status.status === 'error') {
                            clearInterval(fePollInterval);
                            showFindEvilError(status.error || 'Unknown error');
                            document.getElementById('fe-run-btn').disabled = false;
                            document.getElementById('fe-run-btn').textContent = '🔍 Run Find Evil';
                        }
                    }
                } catch(e) {
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
            html += '<h3 style="color:#58a6ff; margin-bottom:10px;">Find Evil Report</h3>';
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

            if (report.case_work_dir) {
                html += '<p style="margin-top:12px;color:#8b949e;font-size:0.8rem;">Report: ' + report.case_work_dir + '/reports/find_evil_report.json</p>';
            }

            html += '</div>';
            area.innerHTML = html;
        }

        function showFindEvilError(msg) {
            const area = document.getElementById('fe-results-area');
            area.style.display = 'block';
            area.innerHTML = '<div class="fe-results"><p style="color:#f85149;font-weight:600;">Error: ' + msg + '</p></div>';
        }

        loadEvidence();
    </script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Flask Routes
# ---------------------------------------------------------------------------

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)


@app.route('/chat', methods=['POST'])
def chat():
    """LLM-powered chat with tool detection"""
    user_msg = ''
    try:
        data = request.json
        user_msg = data.get('message', '')

        if not user_msg:
            return jsonify({'response': 'What would you like to look at?'})

        # Detect if user wants to run a tool
        tool_request = detect_tool_request(user_msg)
        tool_result = None
        evidence_file = None

        # Check if user mentions a case
        cases = get_all_cases()
        case_match = None
        files = []
        for case_name in cases.keys():
            if case_name.lower() in user_msg.lower():
                case_match = case_name
                files = cases[case_name]
                break

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

        # Log the chat action
        action_logger.log('CHAT', {
            'user_message': user_msg,
            'case': case_match,
            'tool_executed': tool_request['module'] + '.' + tool_request['function'] if tool_request else None,
            'description': f"Chat with {case_match or 'no case'}"
        })

        # Call LLM
        response = call_llm(user_msg, context, agent_type="manager")

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
def list_cases():
    """Return ALL cases with ALL files"""
    return jsonify({'cases': get_all_cases()})


@app.route('/tools', methods=['GET'])
def list_tools():
    """Return available forensic tools"""
    return jsonify({'tools': get_available_tools_status()})


@app.route('/run-tool', methods=['POST'])
def run_tool():
    """Execute a forensic tool directly"""
    module = function = ''
    try:
        data = request.json
        module = data.get('module')
        function = data.get('function')
        params = data.get('params', {})

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
def critic_summary(investigation_id):
    """Get validation summary for investigation"""
    try:
        summary = geoff_critic.get_validation_summary(investigation_id)
        return jsonify(summary)
    except Exception as e:
        return jsonify({'status': 'error', 'error': str(e)})


@app.route('/investigation/status/<case_name>', methods=['GET'])
def get_investigation_status(case_name):
    """Get status of background investigation for polling"""
    try:
        status_file = Path(CASES_WORK_DIR) / case_name / "investigation_status.json"
        if status_file.exists():
            with open(status_file) as f:
                status = json.load(f)
            return jsonify(status)
        else:
            return jsonify({'status': 'not_found', 'case': case_name}), 404
    except Exception as e:
        return jsonify({'status': 'error', 'error': str(e)}), 500


@app.route('/find-evil', methods=['POST'])
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


@app.route('/find-evil', methods=['GET'])
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
    app.run(host='0.0.0.0', port=PORT, debug=False, threaded=True)