#!/usr/bin/env python3
"""
Geoff DFIR - Integrated with SIFT Tool Specialists
"""

import os
import json
import sys
import subprocess
import tempfile
import threading
import time
import uuid

# Add src directory to path (works for both local and deployed)
SRC_DIR = os.path.dirname(os.path.abspath(__file__))
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

import requests
from datetime import datetime
from pathlib import Path
from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS

from jsonschema import validate as jsonschema_validate, ValidationError

from sift_specialists import SpecialistOrchestrator, SLEUTHKIT_Specialist, VOLATILITY_Specialist, YARA_Specialist, STRINGS_Specialist
from sift_specialists_extended import ExtendedOrchestrator
from sift_specialists_remnux import REMNUX_Orchestrator
from geoff_critic import GeoffCritic, ValidationPipeline
from geoff_forensicator import ForensicatorAgent

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
                    "status": {"type": "string", "enum": ["pending", "running", "completed", "failed"]},
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
                               "/home/sansforensics/evidence-storage",
                               "geoff-evidence")
CASES_WORK_DIR = _resolve_dir('GEOFF_CASES_PATH',
                             "/home/sansforensics/evidence-storage/cases",
                             "geoff-cases")

# ---------------------------------------------------------------------------
# Git Action Logger for Audit Trail
# ---------------------------------------------------------------------------

def git_commit_action(message: str, base_path: str = None):
    """Git commit for audit trail"""
    if base_path is None:
        base_path = os.environ.get('GEOFF_GIT_DIR', CASES_WORK_DIR + '/git')

    if not os.path.isdir(base_path):
        return

    try:
        subprocess.run(['git', 'config', 'user.email'], cwd=base_path, capture_output=True, check=True)
    except Exception:
        subprocess.run(['git', 'config', 'user.email', 'geoff@dfir.local'], cwd=base_path, capture_output=True)
        subprocess.run(['git', 'config', 'user.name', 'Geoff DFIR'], cwd=base_path, capture_output=True)

    try:
        subprocess.run(['git', 'add', '.'], cwd=base_path, check=True, capture_output=True)
        subprocess.run(['git', 'commit', '-m', f"[GEOFF-ACTION] {message}"], cwd=base_path, capture_output=True)
        print(f"[GIT] Committed: {message}")
    except Exception:
        pass


class ActionLogger:
    """Logger for all Geoff actions with git integration"""

    def __init__(self, log_dir: str = None):
        if log_dir is None:
            log_dir = os.environ.get('GEOFF_LOGS_DIR', CASES_WORK_DIR + '/logs')
        self.log_dir = Path(log_dir)
        try:
            self.log_dir.mkdir(parents=True, exist_ok=True)
        except Exception:
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

        with open(self.action_log, 'a') as f:
            f.write(json.dumps(entry) + '\n')

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

_find_evil_jobs = {}  # job_id -> {status, progress, result, started_at, ...}
_find_evil_lock = threading.Lock()


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

*Malware Detection (YARA):* Signature-based scanning, directory-wide detection

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
                "options": {"temperature": 0.8}
            },
            timeout=120
        )
        if response.status_code == 200:
            return response.json().get('response', 'Hmm, let me check that again.')
        else:
            return f"[ERROR] Ollama returned {response.status_code}: {response.text[:200]}"
    except Exception as e:
        print(f"LLM Error: {e}")
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

    # YARA patterns
    if any(word in message_lower for word in ['yara', 'scan for malware', 'signature scan']):
        return {'module': 'yara', 'function': 'scan_file', 'params': {}}

    if any(word in message_lower for word in ['yara scan directory', 'scan folder']):
        return {'module': 'yara', 'function': 'scan_directory', 'params': {}}

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
        subprocess.run(['git', 'init'], cwd=case_work_path, capture_output=True)
        subprocess.run(['git', 'config', 'user.email', 'geoff@dfir.local'], cwd=case_work_path, capture_output=True)
        subprocess.run(['git', 'config', 'user.name', 'Geoff DFIR'], cwd=case_work_path, capture_output=True)
        subprocess.run(['git', 'config', '--global', '--add', 'safe.directory', str(case_work_path)], cwd=case_work_path, capture_output=True)
        subprocess.run(['git', 'config', '--local', 'safe.directory', str(case_work_path)], cwd=case_work_path, capture_output=True)

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
    except Exception:
        pass
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
# Find Evil — Run ALL 19 Playbooks (PB-SIFT-001 through PB-SIFT-019)
# ---------------------------------------------------------------------------

# All 19 SIFT playbook IDs — always run, never cherry-pick
ALL_PLAYBOOKS = [f"PB-SIFT-{i:03d}" for i in range(1, 20)]
# PB-SIFT-011 is skipped in the original; keep 19 IDs but the orchestrator
# may not have 011 implemented. We still attempt it.

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
}

# Map each playbook to its specialist steps.
# Steps that require evidence types not present will be skipped at runtime
# (tool-missing check), but the playbook itself always "runs" (even if all
# steps are skipped).
PLAYBOOK_STEPS = {
    "PB-SIFT-001": {  # Malware Hunting
        "disk_images": [
            ("sleuthkit", "analyze_partition_table", {"disk_image": "{image}"}),
            ("sleuthkit", "analyze_filesystem", {"image": "{image}", "offset": 2048}),
            ("sleuthkit", "list_files", {"image": "{image}", "offset": 2048, "recursive": True}),
            ("yara", "scan_file", {"target_file": "{image}"}),
            ("strings", "extract_strings", {"file_path": "{image}", "min_length": 8}),
        ],
        "memory_dumps": [
            ("volatility", "process_list", {"memory_dump": "{mem}"}),
            ("volatility", "find_malware", {"memory_dump": "{mem}"}),
        ],
    },
    "PB-SIFT-002": {  # Ransomware
        "evtx_logs": [
            ("logs", "parse_evtx", {"evtx_file": "{evtx}"}),
        ],
        "disk_images": [
            ("sleuthkit", "list_files", {"image": "{image}", "offset": 2048, "recursive": True}),
        ],
        "memory_dumps": [
            ("volatility", "process_list", {"memory_dump": "{mem}"}),
        ],
    },
    "PB-SIFT-003": {  # Lateral Movement
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
    "PB-SIFT-004": {  # Credential Theft
        "memory_dumps": [
            ("volatility", "process_list", {"memory_dump": "{mem}"}),
            ("volatility", "find_malware", {"memory_dump": "{mem}"}),
        ],
        "disk_images": [
            ("yara", "scan_file", {"target_file": "{image}"}),
        ],
        "registry_hives": [
            ("registry", "parse_hive", {"hive_path": "{hive}"}),
        ],
    },
    "PB-SIFT-005": {  # Persistence
        "registry_hives": [
            ("registry", "extract_autoruns", {"software_path": "{hive}"}),
            ("registry", "extract_services", {"system_path": "{hive}"}),
        ],
        "disk_images": [
            ("sleuthkit", "list_files", {"image": "{image}", "offset": 2048, "recursive": True}),
        ],
        "memory_dumps": [
            ("volatility", "process_list", {"memory_dump": "{mem}"}),
        ],
    },
    "PB-SIFT-006": {  # Exfiltration
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
    "PB-SIFT-007": {  # Living-off-the-Land
        "evtx_logs": [
            ("logs", "parse_evtx", {"evtx_file": "{evtx}"}),
        ],
        "memory_dumps": [
            ("volatility", "process_list", {"memory_dump": "{mem}"}),
        ],
        "disk_images": [
            ("yara", "scan_file", {"target_file": "{image}"}),
        ],
    },
    "PB-SIFT-008": {  # Initial Access
        "pcaps": [
            ("network", "analyze_pcap", {"pcap_file": "{pcap}"}),
            ("network", "extract_http", {"pcap_file": "{pcap}"}),
        ],
        "evtx_logs": [
            ("logs", "parse_evtx", {"evtx_file": "{evtx}"}),
        ],
        "disk_images": [
            ("sleuthkit", "list_files", {"image": "{image}", "offset": 2048, "recursive": True}),
        ],
    },
    "PB-SIFT-009": {  # Insider Threat
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
    "PB-SIFT-010": {  # Anti-Forensics
        "evtx_logs": [
            ("logs", "parse_evtx", {"evtx_file": "{evtx}"}),
        ],
        "disk_images": [
            ("sleuthkit", "list_files", {"image": "{image}", "offset": 2048, "recursive": True}),
            ("sleuthkit", "analyze_filesystem", {"image": "{image}", "offset": 2048}),
        ],
        "memory_dumps": [
            ("volatility", "process_list", {"memory_dump": "{mem}"}),
        ],
    },
    "PB-SIFT-011": {  # (Reserved / placeholder — still attempted)
        "disk_images": [
            ("sleuthkit", "analyze_partition_table", {"disk_image": "{image}"}),
        ],
    },
    "PB-SIFT-012": {  # Linux Forensics
        "syslogs": [
            ("logs", "parse_syslog", {"log_file": "{syslog}"}),
        ],
        "disk_images": [
            ("sleuthkit", "analyze_partition_table", {"disk_image": "{image}"}),
            ("sleuthkit", "list_files", {"image": "{image}", "offset": 2048, "recursive": True}),
        ],
    },
    "PB-SIFT-013": {  # macOS Forensics
        "disk_images": [
            ("sleuthkit", "analyze_partition_table", {"disk_image": "{image}"}),
            ("sleuthkit", "list_files", {"image": "{image}", "offset": 2048, "recursive": True}),
        ],
    },
    "PB-SIFT-014": {  # REMnux Malware Analysis
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
    "PB-SIFT-015": {  # Mobile Forensics
        "mobile_backups": [
            ("mobile", "analyze_ios_backup", {"backup_dir": "{mobile}"}),
        ],
    },
    "PB-SIFT-016": {  # Triage Prioritization (always runs)
        "memory_dumps": [
            ("volatility", "process_list", {"memory_dump": "{mem}"}),
            ("volatility", "network_scan", {"memory_dump": "{mem}"}),
            ("volatility", "find_malware", {"memory_dump": "{mem}"}),
        ],
    },
    "PB-SIFT-017": {  # Cross-Image Correlation
        "disk_images": [
            ("plaso", "create_timeline", {"evidence_path": "{image}", "output_file": "{output_dir}/timeline_{image_stem}.plaso"}),
        ],
    },
    "PB-SIFT-018": {  # Windows Deep-Dive
        "registry_hives": [
            ("registry", "extract_user_assist", {"ntuser_path": "{hive}"}),
            ("registry", "extract_shellbags", {"ntuser_path": "{hive}"}),
            ("registry", "extract_usb_devices", {"system_path": "{hive}"}),
            ("registry", "extract_mounted_devices", {"system_path": "{hive}"}),
        ],
        "evtx_logs": [
            ("logs", "parse_evtx", {"evtx_file": "{evtx}"}),
        ],
        "disk_images": [
            ("sleuthkit", "list_files", {"image": "{image}", "offset": 2048, "recursive": True}),
        ],
    },
    "PB-SIFT-019": {  # Full Correlation & Reporting
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
        except OSError:
            size = 0
        inventory["total_size_bytes"] += size

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


def _scan_triage_indicators(inventory: dict) -> list:
    """Scan file names for high-signal triage patterns (used for severity reporting)."""
    hits = []
    all_paths = inventory["other_files"] + inventory["disk_images"]
    for category, patterns in TRIAGE_PATTERNS.items():
        for pattern in patterns:
            pl = pattern.lower()
            for fpath in all_paths:
                if pl in fpath.lower():
                    hits.append({"category": category, "pattern": pattern, "file": fpath,
                                 "severity": SEVERITY_MAP.get(category, "MEDIUM")})
                    break  # one hit per pattern is enough
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
    Find Evil: Point at an evidence directory, run ALL 19 playbooks, find evil.

    Every playbook (PB-SIFT-001 through PB-SIFT-019) is executed regardless of
    evidence type.  Individual steps are skipped only when the required tool
    is not available for that step.

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

    def _update_job(progress_pct: float, current_pb: str, current_step: str = ""):
        """Push progress to the in-memory job tracker."""
        if job_id is None:
            return
        with _find_evil_lock:
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

    _update_job(5, "inventory", "Complete")

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
        print(f"[FIND-EVIL] Case work dir fallback: {case_work_dir}")

    for subdir in ("output", "reports", "validations", "timeline"):
        (case_work_dir / subdir).mkdir(exist_ok=True)

    # Init git
    try:
        subprocess.run(['git', 'init'], cwd=case_work_dir, capture_output=True, check=True)
        subprocess.run(['git', 'config', 'user.email', 'geoff@dfir.local'], cwd=case_work_dir, capture_output=True)
        subprocess.run(['git', 'config', 'user.name', 'Geoff DFIR'], cwd=case_work_dir, capture_output=True)
        subprocess.run(['git', 'config', '--add', 'safe.directory', str(case_work_dir)], cwd=case_work_dir, capture_output=True)
    except Exception:
        pass

    _update_job(8, "setup", "Case directory ready")

    # ------------------------------------------------------------------
    # Phase 3: Execute ALL 19 Playbooks
    # ------------------------------------------------------------------
    findings = []
    critic_results = []
    playbooks_run = []
    steps_completed = 0
    steps_failed = 0
    steps_skipped = 0
    total_pb = len(ALL_PLAYBOOKS)

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

    for pb_idx, playbook_id in enumerate(ALL_PLAYBOOKS):
        pb_progress_base = 10 + (80 * pb_idx / total_pb)  # 10–90% range for playbooks
        _update_job(pb_progress_base, playbook_id, "Starting")

        pb_steps_def = PLAYBOOK_STEPS.get(playbook_id, {})
        pb_findings = []
        any_step_ran = False

        for ev_type, step_templates in pb_steps_def.items():
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
                        params[k] = v

                    step_record = {
                        "playbook": playbook_id,
                        "module": module,
                        "function": function,
                        "params": params,
                        "evidence_file": item,
                        "status": "running",
                        "started_at": datetime.now().isoformat(),
                    }

                    try:
                        result = _run_step_via_orchestrator(module, function, params)
                        step_status = result.get("status", "error")
                        # If the tool was missing, skip (not a failure)
                        if step_status == "error" and "not found" in str(result.get("error", "")).lower():
                            step_record["status"] = "skipped"
                            step_record["result"] = result
                            steps_skipped += 1
                        elif step_status == "success":
                            step_record["status"] = "completed"
                            step_record["result"] = result
                            steps_completed += 1
                            any_step_ran = True
                        else:
                            step_record["status"] = "failed"
                            step_record["result"] = result
                            steps_failed += 1
                            any_step_ran = True

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
                        except Exception as ce:
                            step_record["critic_error"] = str(ce)
                    except Exception as e:
                        step_record["status"] = "failed"
                        step_record["error"] = str(e)
                        steps_failed += 1

                    step_record["completed_at"] = datetime.now().isoformat()
                    findings.append(step_record)
                    pb_findings.append(step_record)

        playbooks_run.append({
            "playbook_id": playbook_id,
            "steps_attempted": len(pb_findings),
            "steps_completed": sum(1 for s in pb_findings if s.get("status") == "completed"),
            "steps_skipped": sum(1 for s in pb_findings if s.get("status") == "skipped"),
            "steps_failed": sum(1 for s in pb_findings if s.get("status") == "failed"),
        })

    # ------------------------------------------------------------------
    # Phase 3b: Multi-Host Correlation
    # ------------------------------------------------------------------
    _update_job(92, "correlation", "Cross-image timeline merge")

    timeline_files = []
    if len(inventory["disk_images"]) > 1:
        # Individual timelines already created in PB-SIFT-017 / PB-SIFT-019
        # Find them in the output dir
        timeline_files = list(Path(output_dir).glob("timeline_*.plaso"))

        if len(timeline_files) > 1:
            # Merge with Plaso psort
            merged_output = str(case_work_dir / "timeline" / "merged_super.plaso")
            try:
                merge_cmd = [
                    "python3", "/usr/bin/log2timeline.py",
                    "--storage_file", merged_output,
                ] + [str(f) for f in timeline_files]
                subprocess.run(merge_cmd, capture_output=True, timeout=600)
                findings.append({
                    "playbook": "PB-SIFT-017",
                    "module": "plaso",
                    "function": "merge_timelines",
                    "status": "completed",
                    "result": {"merged_output": merged_output, "source_timelines": len(timeline_files)},
                    "started_at": datetime.now().isoformat(),
                    "completed_at": datetime.now().isoformat(),
                })
            except Exception as e:
                findings.append({
                    "playbook": "PB-SIFT-017",
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
    merged_plaso = case_work_dir / "timeline" / "merged_super.plaso"
    if merged_plaso.exists():
        timeline_for_extraction = [merged_plaso]

    if timeline_for_extraction:
        _update_job(93, "correlation", "Extracting user activity across hosts")
        try:
            # Use psort to extract user-relevant events from Plaso timelines
            # Focus on: file access, process execution, logins, browser history,
            # registry modifications — all keyed by username + hostname
            user_event_types = [
                "windows:registry:userassist",   # UserAssist (program execution)
                "windows:evt:4624",               # Successful logon
                "windows:evt:4625",               # Failed logon
                "windows:evt:4648",               # Explicit credential logon
                "windows:evt:4688",               # Process creation
                "windows:evtx:4624",
                "windows:evtx:4625",
                "windows:evtx:4648",
                "windows:evtx:4688",
                "shell:history",                  # Bash/shell history
                "browser:chrome:history",
                "browser:firefox:history",
                "santa:execution",                 # macOS Santa
                "filestat",                        # File stat events (if user-attributed)
            ]

            for tl_path in timeline_for_extraction:
                try:
                    # Query psort for user-attributed events
                    psort_cmd = [
                        "python3", "/usr/bin/psort.py",
                        "-o", "json",
                        str(tl_path),
                    ]
                    psort_result = subprocess.run(
                        psort_cmd,
                        capture_output=True, text=True, timeout=300
                    )

                    if psort_result.returncode == 0 and psort_result.stdout:
                        # Parse JSON output line by line
                        for line in psort_result.stdout.strip().split("\n"):
                            try:
                                event = json.loads(line)
                            except (json.JSONDecodeError, ValueError):
                                continue

                            username = event.get("username", "")
                            hostname = event.get("hostname", event.get("computer_name", ""))
                            event_type = event.get("data_type", "")
                            timestamp = event.get("datetime", "")

                            if not username:
                                continue

                            # Normalize username
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

                            # Keep last 100 events per user to avoid bloat
                            if len(user_activity_summary[user_key]["timeline"]) < 100:
                                user_activity_summary[user_key]["timeline"].append({
                                    "timestamp": timestamp,
                                    "event_type": event_type,
                                    "host": hostname,
                                    "detail": event.get("message", "")[:200],
                                })

                    # Also try a targeted psort query for login events across hosts
                    for evt_filter in ["4624", "4648", "4688"]:
                        try:
                            targeted_cmd = [
                                "python3", "/usr/bin/psort.py",
                                str(tl_path),
                                f"event_identifier IS {evt_filter}",
                                "-o", "json",
                            ]
                            targeted_result = subprocess.run(
                                targeted_cmd,
                                capture_output=True, text=True, timeout=120
                            )
                            if targeted_result.returncode == 0 and targeted_result.stdout:
                                for line in targeted_result.stdout.strip().split("\n"):
                                    try:
                                        event = json.loads(line)
                                    except (json.JSONDecodeError, ValueError):
                                        continue
                                    username = event.get("username", "")
                                    hostname = event.get("hostname", "")
                                    if not username:
                                        continue
                                    user_key = f"{username}@{hostname}" if hostname else username
                                    if user_key in user_activity_summary:
                                        # Track lateral movement: same user, different hosts
                                        if len(user_activity_summary[user_key]["hosts"]) > 1:
                                            user_activity_summary[user_key]["lateral_movement_indicators"].append({
                                                "type": "cross_host_activity",
                                                "user": username,
                                                "hosts": list(user_activity_summary[user_key]["hosts"]),
                                                "event": event.get("message", "")[:200],
                                                "timestamp": event.get("datetime", ""),
                                            })
                        except Exception:
                            pass

                except Exception as e:
                    findings.append({
                        "playbook": "PB-SIFT-017",
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
                    "playbook": "PB-SIFT-017",
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
                "playbook": "PB-SIFT-017",
                "module": "plaso",
                "function": "user_activity_extraction",
                "status": "failed",
                "error": str(e),
            })

    # ------------------------------------------------------------------
    # Phase 4: Aggregate Findings & Severity
    # ------------------------------------------------------------------
    _update_job(95, "reporting", "Aggregating findings")

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    evil_found = False

    # From triage indicators
    for hit in indicator_hits:
        sev = hit["severity"]
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        if sev in ("CRITICAL", "HIGH"):
            evil_found = True

    # From specialist results
    for f in findings:
        result = f.get("result", {})
        if not isinstance(result, dict):
            continue
        # YARA matches
        if result.get("match_count", 0) > 0:
            severity_counts["HIGH"] += 1
            evil_found = True
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
    with open(report_path, 'w') as rf:
        json.dump(report, rf, indent=2, default=str)

    # Git commit
    try:
        subprocess.run(['git', 'add', '.'], cwd=case_work_dir, capture_output=True)
        subprocess.run(['git', 'commit', '-m', f'[FIND-EVIL] Report for {case_name}'],
                       cwd=case_work_dir, capture_output=True)
    except Exception:
        pass

    # Log
    action_logger.log('FIND_EVIL', {
        'evidence_dir': evidence_dir,
        'evil_found': evil_found,
        'severity': overall_severity,
        'steps_executed': len(findings),
        'elapsed_seconds': round(elapsed, 1),
        'description': f"Find Evil run on {evidence_dir}",
    })

    _update_job(100, "complete", "Done")
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
                        <strong>Playbook:</strong> <span id="fe-pb-name">—</span> &nbsp;|&nbsp;
                        <strong>Step:</strong> <span id="fe-step-name">—</span> &nbsp;|&nbsp;
                        <strong>Elapsed:</strong> <span id="fe-elapsed">0s</span>
                    </div>
                    <div class="fe-progress-bar">
                        <div class="fe-progress-fill" id="fe-progress-fill" style="width:0%">0%</div>
                    </div>
                </div>
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
- YARA: signature scan, directory scan
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
        action_logger.log('ERROR', {'error': str(e), 'user_message': user_msg})
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
        action_logger.log('TOOL_API_ERROR', {
            'module': module,
            'function': function,
            'error': str(e),
            'description': f"API {module}.{function} failed"
        })
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

        with _find_evil_lock:
            _find_evil_jobs[job_id] = {
                "status": "running",
                "progress_pct": 0.0,
                "current_playbook": "initializing",
                "current_step": "",
                "elapsed_seconds": 0.0,
                "started_at": datetime.now().isoformat(),
                "result": None,
                "error": None,
            }

        # Spawn the find_evil run in a background thread
        def _run():
            try:
                report = find_evil(evidence_dir, job_id=job_id)
                with _find_evil_lock:
                    _find_evil_jobs[job_id]["status"] = "complete"
                    _find_evil_jobs[job_id]["result"] = report
            except Exception as e:
                with _find_evil_lock:
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
    with _find_evil_lock:
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
    }

    if job["status"] == "complete":
        resp["result"] = job["result"]
    elif job["status"] == "error":
        resp["error"] = job["error"]

    return jsonify(resp)


@app.route('/find-evil', methods=['GET'])
def find_evil_info():
    """GET /find-evil — Return usage info and supported playbooks"""
    return jsonify({
        'name': 'Find Evil',
        'description': 'Point at an evidence directory, auto-run ALL 19 playbooks, find evil with no prompting.',
        'usage': 'POST /find-evil with {"evidence_dir": "/path/to/evidence"}',
        'supported_evidence': [
            'Disk images (.E01, .dd, .raw, .img, .aff)',
            'Memory dumps (.vmem, .mem, .dmp)',
            'Network captures (.pcap, .pcapng)',
            'Windows Event Logs (.evtx)',
            'Syslog files (syslog, auth.log, messages)',
            'Registry hives (NTUSER.DAT, SYSTEM, SOFTWARE, SECURITY, SAM)',
            'Mobile backups (iOS Info.plist, Manifest.db)',
        ],
        'playbooks': [
            {'id': 'PB-SIFT-001', 'name': 'Malware Hunting', 'trigger': 'Always (all playbooks run)'},
            {'id': 'PB-SIFT-002', 'name': 'Ransomware', 'trigger': 'Always'},
            {'id': 'PB-SIFT-003', 'name': 'Lateral Movement', 'trigger': 'Always'},
            {'id': 'PB-SIFT-004', 'name': 'Credential Theft', 'trigger': 'Always'},
            {'id': 'PB-SIFT-005', 'name': 'Persistence', 'trigger': 'Always'},
            {'id': 'PB-SIFT-006', 'name': 'Exfiltration', 'trigger': 'Always'},
            {'id': 'PB-SIFT-007', 'name': 'Living-off-the-Land', 'trigger': 'Always'},
            {'id': 'PB-SIFT-008', 'name': 'Initial Access', 'trigger': 'Always'},
            {'id': 'PB-SIFT-009', 'name': 'Insider Threat', 'trigger': 'Always'},
            {'id': 'PB-SIFT-010', 'name': 'Anti-Forensics', 'trigger': 'Always'},
            {'id': 'PB-SIFT-011', 'name': 'Reserved', 'trigger': 'Always'},
            {'id': 'PB-SIFT-012', 'name': 'Linux Forensics', 'trigger': 'Always'},
            {'id': 'PB-SIFT-013', 'name': 'macOS Forensics', 'trigger': 'Always'},
            {'id': 'PB-SIFT-014', 'name': 'REMnux Malware Analysis', 'trigger': 'Always'},
            {'id': 'PB-SIFT-015', 'name': 'Mobile Forensics', 'trigger': 'Always'},
            {'id': 'PB-SIFT-016', 'name': 'Triage Prioritization', 'trigger': 'Always (runs first)'},
            {'id': 'PB-SIFT-017', 'name': 'Cross-Image Correlation', 'trigger': 'Always'},
            {'id': 'PB-SIFT-018', 'name': 'Windows Deep-Dive', 'trigger': 'Always'},
            {'id': 'PB-SIFT-019', 'name': 'Full Correlation & Reporting', 'trigger': 'Always'},
        ],
        'pipeline': [
            '1. Evidence inventory & quality scoring',
            '2. OS classification & rapid indicator triage',
            '3. ALL 19 playbooks execute (no cherry-picking)',
            '4. Steps skipped only if required tool is missing',
            '5. Multi-host correlation with Plaso timeline merge',
            '6. User activity extraction across hosts (lateral movement detection)',
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