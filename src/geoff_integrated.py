#!/usr/bin/env python3
"""
Geoff DFIR - Integrated with SIFT Tool Specialists
"""

import os
import json
import sys
import subprocess
import tempfile

# Add src directory to path (works for both local and deployed)
SRC_DIR = os.path.dirname(os.path.abspath(__file__))
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

import requests
from datetime import datetime
from pathlib import Path
from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS

from sift_specialists import SpecialistOrchestrator, SLEUTHKIT_Specialist, VOLATILITY_Specialist, YARA_Specialist, STRINGS_Specialist
from sift_specialists_extended import ExtendedOrchestrator
from geoff_critic import GeoffCritic, ValidationPipeline
from geoff_forensicator import ForensicatorAgent

# Context Window Management
class ContextManager:
    """Manages LLM context window to prevent overflow while keeping relevant info"""
    
    # qwen3-coder-next:cloud has 32K context window
    # Reserve 8K for response + system overhead
    MAX_CONTEXT_TOKENS = 24000  # ~76KB of text (3.2 chars per token for high-entropy forensic data)
    
    # Use 3.2 chars/token for high-entropy forensic data and code (more accurate than 4)
    CHARS_PER_TOKEN = 3.2
    
    def __init__(self):
        self.conversation_history = []  # Store last N exchanges for context
        self.max_history_turns = 5
    
    def estimate_tokens(self, text: str) -> int:
        """Token estimation: ~3.2 characters per token for high-entropy forensic data"""
        return int(len(text) / self.CHARS_PER_TOKEN)
    
    def truncate_text(self, text: str, max_tokens: int) -> str:
        """Truncate text to fit within token limit"""
        estimated_tokens = self.estimate_tokens(text)
        if estimated_tokens <= max_tokens:
            return text
        
        # Calculate max characters using CHARS_PER_TOKEN constant
        max_chars = int(max_tokens * self.CHARS_PER_TOKEN)
        
        # Keep beginning and end, truncate middle
        if len(text) > max_chars:
            half = max_chars // 2
            return text[:half] + "\n...[truncated for context]...\n" + text[-half:]
        return text
    
    def build_context(self, system_prompt: str, case_info: str, tool_info: str, 
                     user_message: str, evidence_files: list = None) -> str:
        """Build optimized context that fits within limits"""
        
        # Start with system prompt
        parts = [system_prompt]
        used_tokens = self.estimate_tokens(system_prompt)
        
        # Add case info with truncation for large file lists
        if evidence_files and len(evidence_files) > 50:
            # Summarize large file lists
            file_summary = f"Case has {len(evidence_files)} items. Key items:\n"
            file_summary += "\n".join(evidence_files[:30])
            file_summary += f"\n...[and {len(evidence_files) - 30} more files]"
            case_info = file_summary
        
        case_tokens = self.estimate_tokens(case_info)
        if used_tokens + case_tokens < self.MAX_CONTEXT_TOKENS * 0.6:
            parts.append(case_info)
            used_tokens += case_tokens
        else:
            # Truncate case info
            parts.append(self.truncate_text(case_info, 
                       int((self.MAX_CONTEXT_TOKENS - used_tokens) * 0.3)))
            used_tokens = self.estimate_tokens("\n".join(parts))
        
        # Add conversation history (recent exchanges)
        if self.conversation_history:
            history_text = "Recent conversation:\n"
            for turn in self.conversation_history[-self.max_history_turns:]:
                history_text += f"User: {turn['user'][:200]}\n"
                history_text += f"Geoff: {turn['geoff'][:200]}\n"
            
            history_tokens = self.estimate_tokens(history_text)
            if used_tokens + history_tokens < self.MAX_CONTEXT_TOKENS * 0.8:
                parts.append(history_text)
                used_tokens += history_tokens
        
        # Add tool info (shorter, always fits)
        remaining_tokens = self.MAX_CONTEXT_TOKENS - used_tokens
        if remaining_tokens > 500:
            parts.append(tool_info)
        
        return "\n\n".join(parts)
    
    def add_exchange(self, user_msg: str, geoff_response: str):
        """Add exchange to conversation history"""
        self.conversation_history.append({
            'user': user_msg,
            'geoff': geoff_response,
            'timestamp': datetime.now().isoformat()
        })
        
        # Keep only recent history
        if len(self.conversation_history) > self.max_history_turns * 2:
            self.conversation_history = self.conversation_history[-self.max_history_turns:]
    
    def clear_history(self):
        """Clear conversation history (e.g., new case)"""
        self.conversation_history = []

# Initialize global context manager
context_manager = ContextManager()

# Configuration - MUST be defined before ActionLogger
def _resolve_dir(env_var, default_path, fallback_subdir):
    """Resolve a directory path, falling back to temp if default is not writable."""
    path = os.environ.get(env_var, default_path)
    try:
        Path(path).mkdir(parents=True, exist_ok=True)
        return path
    except (PermissionError, OSError):
        # tempfile already imported at top
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

# Git Action Logger for audit trail - uses environment variable for path
def git_commit_action(message: str, base_path: str = None):
    """Git commit for audit trail"""
    if base_path is None:
        base_path = os.environ.get('GEOFF_GIT_DIR', CASES_WORK_DIR + '/git')
    
    # Ensure base_path exists
    if not os.path.isdir(base_path):
        return  # Can't git commit if directory doesn't exist
    
    try:
        # Configure git if not already set
        subprocess.run(['git', 'config', 'user.email'], cwd=base_path, capture_output=True, check=True)
    except:
        # Set default git config
        subprocess.run(['git', 'config', 'user.email', 'geoff@dfir.local'], cwd=base_path, capture_output=True)
        subprocess.run(['git', 'config', 'user.name', 'Geoff DFIR'], cwd=base_path, capture_output=True)
    
    try:
        subprocess.run(['git', 'add', '.'], cwd=base_path, check=True, capture_output=True)
        subprocess.run(['git', 'commit', '-m', f"[GEOFF-ACTION] {message}"], cwd=base_path, capture_output=True)
        print(f"[GIT] Committed: {message}")
    except:
        pass  # Git not available or nothing to commit

class ActionLogger:
    """Logger for all Geoff actions with git integration"""
    
    def __init__(self, log_dir: str = None):
        if log_dir is None:
            log_dir = os.environ.get('GEOFF_LOGS_DIR', CASES_WORK_DIR + '/logs')
        self.log_dir = Path(log_dir)
        try:
            self.log_dir.mkdir(parents=True, exist_ok=True)
        except:
            # Fallback to temp if permission denied
            # tempfile already imported at top
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
        
        # Append to JSONL file
        with open(self.action_log, 'a') as f:
            f.write(json.dumps(entry) + '\n')
        
        # Git commit for audit trail
        if commit:
            git_commit_action(f"{action_type}: {details.get('description', 'action')}")
        
        return entry

# Initialize global action logger
action_logger = ActionLogger()

app = Flask(__name__)
CORS(app)

# Configuration
PORT = int(os.environ.get('GEOFF_PORT', 8080))

# Ollama Configuration (local or remote)
# Local default: http://localhost:11434
# Remote example: http://localhost:11434 or https://ollama.yourserver.com
OLLAMA_URL = os.environ.get('OLLAMA_URL', "http://localhost:11434")

# Geoff Agent Models (all via Ollama)
# Change these to use different models on your Ollama instance
AGENT_MODELS = {
    "manager": os.environ.get('GEOFF_MANAGER_MODEL', "deepseek-r1:70b"),
    "forensicator": os.environ.get('GEOFF_FORENSICATOR_MODEL', "qwen2.5-coder:32b"),
    "critic": os.environ.get('GEOFF_CRITIC_MODEL', "qwen3:30b")
}

# Default model for general queries
LLM_MODEL = AGENT_MODELS["manager"]

# Initialize extended orchestrator with 100% coverage
orchestrator = ExtendedOrchestrator(EVIDENCE_BASE_DIR)

# Initialize Critic for validation
geoff_critic = GeoffCritic(OLLAMA_URL, LLM_MODEL)
validation_pipeline = ValidationPipeline(orchestrator, geoff_critic)

# Initialize Forensicator for tool execution (multi-agent architecture)
geoff_forensicator = ForensicatorAgent(OLLAMA_URL)

# Shared JSON Schema for investigation steps
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
                    "module": {
                        "type": "string",
                        "enum": ["sleuthkit", "volatility", "yara", "strings", "registry", "plaso", "network", "logs", "mobile", "chat", "analysis"]
                    },
                    "function": {"type": "string"},
                    "params": {"type": "object"},
                    "description": {"type": "string"},
                    "status": {
                        "type": "string",
                        "enum": ["pending", "running", "completed", "failed"]
                    },
                    "added_at": {"type": "string", "format": "date-time"},
                    "completed_at": {"type": "string", "format": "date-time"},
                    "result": {"type": "object"}
                }
            }
        },
        "artifacts": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "type": {"type": "string"},
                    "path": {"type": "string"},
                    "description": {"type": "string"},
                    "hash": {"type": "string"}
                }
            }
        }
    }
}

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
        # Select model based on agent type
        model = AGENT_MODELS.get(agent_type, AGENT_MODELS["manager"])
        
        full_prompt = f"{GEOFF_PROMPT}\n\n{context}\n\nUser: {user_message}\n\nGeoff:"
        response = requests.post(
            f"{OLLAMA_URL}/api/generate",
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
    
    # Investigation trigger - full playbook execution
    if any(word in message_lower for word in ['investigate', 'full analysis', 'run playbooks', 'systematic analysis']):
        return {'module': 'orchestrator', 'function': 'run_full_investigation', 'params': {}}
    
    return None

def run_full_investigation(case_name: str, evidence_path: str = None):
    """Spawn background investigation worker for case with timestamped directory"""
    import subprocess
    from datetime import datetime
    
    # Create timestamped case directory: cases/<case_name>_YYYYMMDD_HHMMSS/
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    case_work_dir = f"{case_name}_{timestamp}"
    case_work_path = Path(CASES_WORK_DIR) / case_work_dir
    try:
        case_work_path.mkdir(parents=True, exist_ok=True)
    except (PermissionError, OSError):
        # tempfile already imported at top
        case_work_path = Path(tempfile.gettempdir()) / "geoff-cases" / case_work_dir
        case_work_path.mkdir(parents=True, exist_ok=True)
        print(f"[GEOFF] Case work dir fallback: {case_work_path}")
    
    # Initialize git repo in case directory
    git_dir = case_work_path / ".git"
    if not git_dir.exists():
        subprocess.run(['git', 'init'], cwd=case_work_path, capture_output=True)
        subprocess.run(['git', 'config', 'user.email', 'geoff@dfir.local'], cwd=case_work_path, capture_output=True)
        subprocess.run(['git', 'config', 'user.name', 'Geoff DFIR'], cwd=case_work_path, capture_output=True)
        # Add safe.directory to allow commits from any process
        subprocess.run(['git', 'config', '--global', '--add', 'safe.directory', str(case_work_path)], cwd=case_work_path, capture_output=True)
        # Also set local safe.directory
        subprocess.run(['git', 'config', '--local', 'safe.directory', str(case_work_path)], cwd=case_work_path, capture_output=True)
    
    # Create subdirectories
    (case_work_path / "logs").mkdir(exist_ok=True)
    (case_work_path / "output").mkdir(exist_ok=True)
    (case_work_path / "reports").mkdir(exist_ok=True)
    (case_work_path / "timeline").mkdir(exist_ok=True)
    
    # Spawn background worker with work directory
    worker_cmd = [
        'python3', 
        '/home/sansforensics/geoff_worker.py',
        case_name,
        str(case_work_path)
    ]
    if evidence_path:
        worker_cmd.append(evidence_path)
    
    # Start in background, detached
    subprocess.Popen(
        worker_cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True
    )
    
    # Return immediate acknowledgment
    return {
        "status": "started",
        "case": case_name,
        "work_directory": str(case_work_path),
        "message": f"Investigation initiated for case: {case_name}",
        "progress_file": str(case_work_path / "investigation_status.json"),
        "note": "Background investigation running. Progress updates every 10 seconds."
    }

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
    except:
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

def find_evil(evidence_dir: str) -> dict:
    """
    Find Evil: Point at an evidence directory, auto-run playbooks, find evil with no prompting.

    Autonomous triage-to-findings pipeline:
    1. Inventory evidence (disk images, memory dumps, logs, pcaps, registry hives, mobile)
    2. Classify OS and incident type via rapid indicator triage
    3. Select and run applicable playbooks through specialists
    4. Validate every result through the Critic pipeline
    5. Produce a unified findings report with severity ratings and MITRE ATT&CK mapping

    Args:
        evidence_dir: Absolute path to the evidence directory to analyze.

    Returns:
        dict with keys: status, evidence_dir, inventory, classification, playbooks_run,
        findings, critic_summary, report_path, elapsed_seconds
    """
    import time
    import hashlib
    start_time = time.time()

    evidence_path = Path(evidence_dir)
    if not evidence_path.exists():
        return {
            "status": "error",
            "error": f"Evidence directory not found: {evidence_dir}",
            "evidence_dir": evidence_dir
        }

    # ------------------------------------------------------------------
    # Phase 1: Evidence Inventory
    # ------------------------------------------------------------------
    inventory = {
        "disk_images": [],
        "memory_dumps": [],
        "pcaps": [],
        "evtx_logs": [],
        "syslogs": [],
        "registry_hives": [],
        "mobile_backups": [],
        "other_files": [],
        "total_size_bytes": 0
    }

    disk_extensions = {'.e01', '.ee01', '.dd', '.raw', '.img', '.001', '.002', '.aff', '.aff4', '.ex01'}
    memory_extensions = {'.vmem', '.mem', '.dmp', '.core', '.lin'}
    pcap_extensions = {'.pcap', '.pcapng', '.cap'}
    evtx_pattern = '*.evtx'
    syslog_patterns = {'syslog', 'auth.log', 'kern.log', 'messages', 'secure', 'auth.log.1', 'daemon.log'}
    registry_hives = {'ntuser.dat', 'system', 'software', 'security', 'sam', 'amcache.hve',
                       'usrclass.dat', 'default', 'system.sav', 'software.sav',
                       'ntuser.dat'}
    mobile_indicators = {'info.plist', 'manifest.db', 'manifest.plist'}

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

        if ext in disk_extensions:
            inventory["disk_images"].append(str(item))
        elif ext in memory_extensions:
            inventory["memory_dumps"].append(str(item))
        elif ext in pcap_extensions:
            inventory["pcaps"].append(str(item))
        elif ext == '.evtx':
            inventory["evtx_logs"].append(str(item))
        elif name_lower in registry_hives:
            inventory["registry_hives"].append(str(item))
        elif name_lower in syslog_patterns or name_lower.startswith('syslog'):
            inventory["syslogs"].append(str(item))
        elif name_lower in mobile_indicators:
            inventory["mobile_backups"].append(str(item))
        else:
            inventory["other_files"].append(str(item))

    # Quick triage: what evidence types do we actually have?
    has_disk = len(inventory["disk_images"]) > 0
    has_memory = len(inventory["memory_dumps"]) > 0
    has_pcap = len(inventory["pcaps"]) > 0
    has_evtx = len(inventory["evtx_logs"]) > 0
    has_syslog = len(inventory["syslogs"]) > 0
    has_registry = len(inventory["registry_hives"]) > 0
    has_mobile = len(inventory["mobile_backups"]) > 0
    has_logs = has_evtx or has_syslog

    # Quality score based on evidence completeness
    evidence_score = 0.0
    if has_disk:
        evidence_score += 0.4
    if has_memory:
        evidence_score += 0.3
    if has_logs:
        evidence_score += 0.15
    if has_pcap:
        evidence_score += 0.1
    if has_registry:
        evidence_score += 0.05
    evidence_score = min(evidence_score, 1.0)

    # ------------------------------------------------------------------
    # Phase 2: OS Classification & Incident Triage
    # ------------------------------------------------------------------
    os_type = "unknown"
    indicator_hits = []  # (playbook_id, severity, description)

    # OS detection heuristics from evidence names
    if any('windows' in p.lower() or 'win' in p.lower() or p.lower().endswith(('.e01', '.dd')) for p in
           inventory["disk_images"] + inventory["other_files"]):
        os_type = "windows"
    if any('linux' in p.lower() or 'ubuntu' in p.lower() for p in
           inventory["disk_images"] + inventory["other_files"]):
        os_type = "linux"
    if any('macos' in p.lower() or 'osx' in p.lower() or 'darwin' in p.lower() for p in
           inventory["disk_images"] + inventory["other_files"]):
        os_type = "macos"
    if has_mobile:
        os_type = "mobile"

    # Rapid indicator triage — scan for high-signal patterns
    triage_patterns = {
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

    for category, patterns in triage_patterns.items():
        for pattern in patterns:
            pattern_lower = pattern.lower()
            for file_path in inventory["other_files"] + inventory["disk_images"]:
                if pattern_lower in file_path.lower():
                    indicator_hits.append((category, pattern, file_path))
                    break  # one hit per pattern is enough

    # Map indicator categories to playbooks
    playbook_map = {
        "ransomware": ["PB-SIFT-002", "PB-SIFT-008"],
        "credential_theft": ["PB-SIFT-004", "PB-SIFT-003"],
        "lateral_movement": ["PB-SIFT-003", "PB-SIFT-005"],
        "persistence": ["PB-SIFT-005", "PB-SIFT-001"],
        "exfiltration": ["PB-SIFT-006", "PB-SIFT-009"],
        "anti_forensics": ["PB-SIFT-010", "PB-SIFT-001"],
        "web_shell": ["PB-SIFT-008", "PB-SIFT-001"],
        "lolbin": ["PB-SIFT-007", "PB-SIFT-001"],
    }

    severity_map = {
        "ransomware": "CRITICAL",
        "credential_theft": "HIGH",
        "lateral_movement": "HIGH",
        "persistence": "HIGH",
        "exfiltration": "HIGH",
        "anti_forensics": "HIGH",
        "web_shell": "HIGH",
        "lolbin": "MEDIUM",
    }

    # Build prioritized playbook list (deduplicated, ordered)
    selected_playbooks = []
    seen_playbooks = set()

    # Always include triage first
    selected_playbooks.append("PB-SIFT-016")
    seen_playbooks.add("PB-SIFT-016")

    # Add playbooks triggered by indicators, ordered by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    triggered = []
    for category, pattern, path in indicator_hits:
        severity = severity_map.get(category, "MEDIUM")
        for pb in playbook_map.get(category, []):
            if pb not in seen_playbooks:
                triggered.append((severity_order.get(severity, 2), pb, category, severity))
                seen_playbooks.add(pb)

    triggered.sort(key=lambda x: x[0])
    for _, pb, cat, sev in triggered:
        selected_playbooks.append(pb)

    # Add OS-specific playbook
    os_playbooks = {"linux": "PB-SIFT-012", "macos": "PB-SIFT-013", "mobile": "PB-SIFT-015"}
    os_pb = os_playbooks.get(os_type)
    if os_pb and os_pb not in seen_playbooks:
        selected_playbooks.append(os_pb)
        seen_playbooks.add(os_pb)

    # Always run malware hunting if disk evidence exists
    if has_disk and "PB-SIFT-001" not in seen_playbooks:
        selected_playbooks.append("PB-SIFT-001")
        seen_playbooks.add("PB-SIFT-001")

    # Add correlation if multi-host
    if len(inventory["disk_images"]) > 1 and "PB-SIFT-017" not in seen_playbooks:
        selected_playbooks.append("PB-SIFT-017")
        seen_playbooks.add("PB-SIFT-017")

    # ------------------------------------------------------------------
    # Phase 3: Execute Playbooks Through Specialists
    # ------------------------------------------------------------------
    findings = []
    critic_results = []
    playbooks_run = []

    # Create case work directory for this run
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    case_name = evidence_path.name
    case_work_dir = Path(CASES_WORK_DIR) / f"{case_name}_findevil_{timestamp}"
    try:
        case_work_dir.mkdir(parents=True, exist_ok=True)
    except (PermissionError, OSError):
        # tempfile already imported at top
        case_work_dir = Path(tempfile.gettempdir()) / "geoff-cases" / f"{case_name}_findevil_{timestamp}"
        case_work_dir.mkdir(parents=True, exist_ok=True)
        print(f"[FIND-EVIL] Case work dir fallback: {case_work_dir}")
    (case_work_dir / "output").mkdir(exist_ok=True)
    (case_work_dir / "reports").mkdir(exist_ok=True)
    (case_work_dir / "validations").mkdir(exist_ok=True)

    # Init git in case dir
    try:
        subprocess.run(['git', 'init'], cwd=case_work_dir, capture_output=True, check=True)
        subprocess.run(['git', 'config', 'user.email', 'geoff@dfir.local'], cwd=case_work_dir, capture_output=True)
        subprocess.run(['git', 'config', 'user.name', 'Geoff DFIR'], cwd=case_work_dir, capture_output=True)
        subprocess.run(['git', 'config', '--add', 'safe.directory', str(case_work_dir)], cwd=case_work_dir, capture_output=True)
    except Exception:
        pass

    def _run_step(module: str, function: str, params: dict, playbook_id: str) -> dict:
        """Run a single specialist step and record the result."""
        step = {
            "module": module,
            "function": function,
            "params": params,
            "playbook": playbook_id,
            "status": "running",
            "started_at": datetime.now().isoformat()
        }
        try:
            result = orchestrator.run_playbook_step(playbook_id, step)
            step["status"] = "completed" if result.get("status") == "success" else "failed"
            step["result"] = result

            # Run critic validation on output
            try:
                critic_val = geoff_critic.validate_tool_output(
                    tool_name=f"{module}.{function}",
                    tool_params=params,
                    raw_output=json.dumps(result, default=str)[:8000],
                    geoff_analysis=f"Find Evil auto-run: {playbook_id} → {module}.{function}"
                )
                step["critic"] = critic_val
                critic_results.append(critic_val)
            except Exception as ce:
                step["critic_error"] = str(ce)
        except Exception as e:
            step["status"] = "failed"
            step["error"] = str(e)

        step["completed_at"] = datetime.now().isoformat()
        findings.append(step)
        return step

    # --- PB-SIFT-016: Triage (always runs) ---
    triage_info = {
        "playbook": "PB-SIFT-016",
        "evidence_score": evidence_score,
        "os_type": os_type,
        "indicator_hits": indicator_hits,
        "selected_playbooks": selected_playbooks
    }
    playbooks_run.append(triage_info)

    # --- Memory-First Rapid Analysis (if memory dumps exist) ---
    if has_memory:
        for mem_dump in inventory["memory_dumps"]:
            _run_step("volatility", "process_list", {"memory_dump": mem_dump}, "PB-SIFT-016")
            _run_step("volatility", "network_scan", {"memory_dump": mem_dump}, "PB-SIFT-016")
            _run_step("volatility", "find_malware", {"memory_dump": mem_dump}, "PB-SIFT-016")

    # --- Disk Analysis (if disk images exist) ---
    if has_disk:
        for disk_img in inventory["disk_images"]:
            _run_step("sleuthkit", "analyze_partition_table", {"disk_image": disk_img}, "PB-SIFT-001")
            # Try filesystem analysis on each partition offset (common offsets)
            for offset in ["63", "128", "2048", "4096", "8192"]:
                part_result = _run_step("sleuthkit", "analyze_filesystem",
                                         {"partition": f"-o {offset} {disk_img}"}, "PB-SIFT-001")
                if part_result.get("result", {}).get("status") == "success":
                    break  # Found a valid filesystem, skip remaining offsets
            _run_step("sleuthkit", "list_files", {"partition": disk_img, "recursive": True}, "PB-SIFT-001")

    # --- Registry Analysis (if registry hives exist) ---
    if has_registry:
        for hive_path in inventory["registry_hives"]:
            hive_name = Path(hive_path).name.upper()
            if 'NTUSER' in hive_name:
                _run_step("registry", "extract_user_assist", {"ntuser_path": hive_path}, "PB-SIFT-005")
                _run_step("registry", "extract_shellbags", {"ntuser_path": hive_path}, "PB-SIFT-005")
            elif 'SYSTEM' in hive_name:
                _run_step("registry", "extract_usb_devices", {"system_path": hive_path}, "PB-SIFT-005")
                _run_step("registry", "extract_services", {"system_path": hive_path}, "PB-SIFT-005")
                _run_step("registry", "extract_mounted_devices", {"system_path": hive_path}, "PB-SIFT-005")
            elif 'SOFTWARE' in hive_name:
                _run_step("registry", "extract_autoruns", {"software_path": hive_path}, "PB-SIFT-005")
            else:
                _run_step("registry", "parse_hive", {"hive_path": hive_path}, "PB-SIFT-005")

    # --- Network Analysis (if pcaps exist) ---
    if has_pcap:
        for pcap_file in inventory["pcaps"]:
            _run_step("network", "analyze_pcap", {"pcap_file": pcap_file}, "PB-SIFT-003")
            _run_step("network", "extract_http", {"pcap_file": pcap_file}, "PB-SIFT-008")
            _run_step("network", "extract_flows", {
                "pcap_file": pcap_file,
                "output_dir": str(case_work_dir / "output" / "flows")
            }, "PB-SIFT-003")

    # --- Log Analysis (if evtx/syslog exist) ---
    if has_evtx:
        for evtx_file in inventory["evtx_logs"]:
            _run_step("logs", "parse_evtx", {"evtx_file": evtx_file}, "PB-SIFT-002")
    if has_syslog:
        for log_file in inventory["syslogs"]:
            _run_step("logs", "parse_syslog", {"log_file": log_file}, "PB-SIFT-012")

    # --- YARA Scan (if disk images or memory dumps exist) ---
    if has_disk or has_memory:
        scan_targets = inventory["disk_images"] + inventory["memory_dumps"]
        for target in scan_targets[:5]:  # Limit to 5 targets for time
            _run_step("yara", "scan_file", {"target_file": target}, "PB-SIFT-001")

    # --- String/IOC Extraction (if disk images exist) ---
    if has_disk:
        for disk_img in inventory["disk_images"][:3]:
            _run_step("strings", "extract_strings", {"file_path": disk_img, "min_length": 8}, "PB-SIFT-001")

    # --- Mobile Analysis (if mobile backups exist) ---
    if has_mobile:
        for backup_dir in set(str(Path(p).parent) for p in inventory["mobile_backups"]):
            _run_step("mobile", "analyze_ios_backup", {"backup_dir": backup_dir}, "PB-SIFT-015")

    # --- Timeline (if disk images exist) ---
    if has_disk:
        for disk_img in inventory["disk_images"][:2]:
            timeline_output = str(case_work_dir / "output" / f"timeline_{Path(disk_img).stem}.plaso")
            _run_step("plaso", "create_timeline", {
                "evidence_path": disk_img,
                "output_file": timeline_output
            }, "PB-SIFT-001")

    # ------------------------------------------------------------------
    # Phase 4: Aggregate Findings & Generate Report
    # ------------------------------------------------------------------

    # Compute severity distribution
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    evil_found = False

    for category, pattern, path in indicator_hits:
        sev = severity_map.get(category, "MEDIUM")
        severity_counts[sev] += 1
        if sev in ("CRITICAL", "HIGH"):
            evil_found = True

    # Check specialist results for additional findings
    for f in findings:
        result = f.get("result", {})
        if not isinstance(result, dict):
            continue
        # YARA matches = evil
        if result.get("match_count", 0) > 0:
            severity_counts["HIGH"] += 1
            evil_found = True
        # Volatility malfind = evil
        if f.get("module") == "volatility" and f.get("function") == "find_malware":
            stdout = result.get("stdout", "")
            if stdout and "No malware" not in stdout and len(stdout.strip()) > 20:
                severity_counts["HIGH"] += 1
                evil_found = True
        # Critic flagged hallucinations — reduce confidence
        critic = f.get("critic", {})
        if isinstance(critic, dict) and not critic.get("valid", True):
            severity_counts["LOW"] += 1

    # Critic summary
    critic_approved = sum(1 for c in critic_results if isinstance(c, dict) and c.get("valid", False))
    critic_total = len(critic_results)
    critic_pct = (critic_approved / critic_total * 100) if critic_total > 0 else 100.0

    # Build unified report
    elapsed = time.time() - start_time
    report = {
        "title": f"Find Evil Report — {case_name}",
        "generated_at": datetime.now().isoformat(),
        "evidence_dir": str(evidence_dir),
        "evidence_score": round(evidence_score, 2),
        "os_type": os_type,
        "evil_found": evil_found,
        "severity_distribution": severity_counts,
        "indicator_hits": [
            {"category": cat, "pattern": pat, "file": fp, "severity": severity_map.get(cat, "MEDIUM")}
            for cat, pat, fp in indicator_hits
        ],
        "playbooks_run": selected_playbooks,
        "specialist_steps_executed": len(findings),
        "steps_succeeded": sum(1 for f in findings if f.get("status") == "completed"),
        "steps_failed": sum(1 for f in findings if f.get("status") == "failed"),
        "critic_approval_pct": round(critic_pct, 1),
        "findings_detail": findings,
        "elapsed_seconds": round(elapsed, 1),
        "case_work_dir": str(case_work_dir)
    }

    # Write report to disk
    report_path = case_work_dir / "reports" / "find_evil_report.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with open(report_path, 'w') as rf:
        json.dump(report, rf, indent=2, default=str)

    # Git commit the report
    try:
        subprocess.run(['git', 'add', '.'], cwd=case_work_dir, capture_output=True)
        subprocess.run(['git', 'commit', '-m', f'[FIND-EVIL] Report for {case_name}'],
                       cwd=case_work_dir, capture_output=True)
    except Exception:
        pass

    # Log the action
    action_logger.log('FIND_EVIL', {
        'evidence_dir': evidence_dir,
        'evil_found': evil_found,
        'steps_executed': len(findings),
        'elapsed_seconds': round(elapsed, 1),
        'description': f"Find Evil run on {evidence_dir}"
    })

    return report


def get_available_tools_status():
    """Get status of all forensic tools"""
    return orchestrator.get_available_tools()

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
        
        /* Tools Panel */
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
    </div>
    
    <div id="chat" class="content active">
        <div id="chat-content">
            <div class="message system">G.E.O.F.F. initialized. Evidence Operations Forensic Framework standing by.\n\nAwaiting investigation directive. Provide case name or evidence path to begin systematic analysis.\n\nAvailable: 32 forensic functions across 9 specialist modules.\nPlaybook library: 18 PB-SIFT investigation protocols.</div>
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
                
                // If tool was run, show result
                if(data.tool_result) {
                    addMessage(JSON.stringify(data.tool_result, null, 2), 'tool-result');
                }
                // If investigation started, begin polling
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
            // Clear any existing poll
            if(investigationPollInterval) {
                clearInterval(investigationPollInterval);
            }
            
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
            
            // Poll immediately and then every 10 seconds
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
        
        async function loadTools() {
            const container = document.getElementById('tools-content');
            container.innerHTML = '<div class="loading">Loading...</div>';
            
            try {
                const res = await fetch('/tools');
                const data = await res.json();
                const tools = data.tools || {};
                
                let html = '';
                for(const [tool, info] of Object.entries(tools)) {
                    const available = info.available === true || (typeof info.available === 'object' && Object.values(info.available).some(v => v));
                    const statusClass = available ? 'available' : 'unavailable';
                    const statusIcon = available ? '✅' : '❌';
                    
                    html += '<div class="tool-category">';
                    html += '<h3>' + tool.toUpperCase() + '</h3>';
                    html += '<div class="tool-status ' + statusClass + '">' + statusIcon + ' ' + (available ? 'Available' : 'Not Available') + '</div>';
                    
                    if(info.functions && info.functions.length > 0) {
                        html += '<div class="tool-functions">';
                        html += info.functions.join(', ');
                        html += '</div>';
                    }
                    html += '</div>';
                }
                container.innerHTML = html;
            } catch(e) {
                container.innerHTML = '<div class="loading">Error loading tools: ' + e.message + '</div>';
            }
        }
        
        loadEvidence();
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/chat', methods=['POST'])
def chat():
    """LLM-powered chat with tool detection"""
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
            # Full investigation - run all playbooks
            if tool_request['function'] == 'run_full_investigation':
                tool_result = run_full_investigation(case_match, evidence_file if 'evidence_file' in locals() else None)
            else:
                # Single tool execution
                # Find evidence file from context
                case_path = Path(EVIDENCE_BASE_DIR) / case_match
                # Look for disk images or memory dumps
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
                
                # Convert Forensicator result to tool_result format
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
                
                # Commit validation to git
                geoff_critic.commit_validation(case_match or 'chat-session', critic_validation)
                
                tool_result['critic_validation'] = critic_validation
        
        # If investigation was started, return that status immediately (skip LLM)
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
        
        # Build optimized context using ContextManager
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
- Mobile: iOS backup, Android data"""
        
        # Build optimized context
        context = context_manager.build_context(
            GEOFF_PROMPT,
            case_info,
            tool_info,
            user_msg,
            files if case_match else []
        )
        
        # Log the chat action
        action_logger.log('CHAT', {
            'user_message': user_msg,
            'case': case_match,
            'tool_executed': tool_request['module'] + '.' + tool_request['function'] if tool_request else None,
            'description': f"Chat with {case_match or 'no case'}"
        })
        
        # Call LLM
        response = call_llm(user_msg, context, agent_type="manager")
        
        # Add to conversation history (with truncation for large responses)
        context_manager.add_exchange(
            user_msg[:500],  # Truncate long user messages
            response[:1000]  # Truncate long responses
        )
        
        result = {'response': response}
        if tool_result:
            result['tool_result'] = tool_result
            
            # Check if this was an investigation start
            if isinstance(tool_result, dict) and tool_result.get('status') == 'started':
                result['investigation_started'] = True
                result['case_name'] = tool_result.get('case', case_match)
            
            # Validate tool output with Critic (skip for investigation - it's async)
            if tool_request and tool_request['function'] != 'run_full_investigation':
                print(f"[CRITIC] Validating {tool_request['module']}.{tool_request['function']}...")
                validation = geoff_critic.validate_tool_output(
                    f"{tool_request['module']}.{tool_request['function']}",
                    tool_request['params'],
                    json.dumps(tool_result),
                    response  # Geoff's analysis
                )
                result['critic_validation'] = validation
                result['critic_approved'] = validation.get('valid', False)
                
                # Commit validation to git
                geoff_critic.commit_validation(
                    case_match or 'unknown',
                    validation
                )
                
                # Log tool execution
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
    try:
        data = request.json
        module = data.get('module')
        function = data.get('function')
        params = data.get('params', {})
        
        # Log the tool execution request
        action_logger.log('TOOL_API_CALL', {
            'module': module,
            'function': function,
            'params': params,
            'description': f"API call to run {module}.{function}"
        })
        
        step = {
            'module': module,
            'function': function,
            'params': params,
            'status': 'running'
        }
        
        result = orchestrator.run_playbook_step('api-call', step)
        
        # Log successful execution
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
        
        # Run validation
        validation = geoff_critic.validate_tool_output(
            tool_name,
            {},
            tool_output,
            geoff_analysis
        )
        
        # Commit to git
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
    Point at an evidence directory, auto-run playbooks, find evil with no prompting.

    Request body (JSON):
        {
            "evidence_dir": "/path/to/evidence"
        }

    Returns:
        Full Find Evil report with inventory, classification, findings, and critic validation.
    """
    try:
        data = request.json or {}
        evidence_dir = data.get('evidence_dir', '').strip()

        if not evidence_dir:
            return jsonify({
                'status': 'error',
                'error': 'Missing required field: evidence_dir',
                'usage': 'POST {"evidence_dir": "/path/to/evidence"} to /find-evil'
            }), 400

        # Run Find Evil
        report = find_evil(evidence_dir)

        # If error (e.g., dir not found), return appropriate status
        if report.get('status') == 'error':
            return jsonify(report), 404

        return jsonify(report)

    except Exception as e:
        action_logger.log('FIND_EVIL_ERROR', {
            'error': str(e),
            'description': 'Find Evil route error'
        })
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500


@app.route('/find-evil', methods=['GET'])
def find_evil_info():
    """GET /find-evil — Return usage info and supported playbooks"""
    return jsonify({
        'name': 'Find Evil',
        'description': 'Point at an evidence directory, auto-run playbooks, find evil with no prompting.',
        'usage': 'POST /find-evil with {"evidence_dir": "/path/to/evidence"}',
        'supported_evidence': [
            'Disk images (.E01, .dd, .raw, .img, .aff)',
            'Memory dumps (.vmem, .mem, .dmp)',
            'Network captures (.pcap, .pcapng)',
            'Windows Event Logs (.evtx)',
            'Syslog files (syslog, auth.log, messages)',
            'Registry hives (NTUSER.DAT, SYSTEM, SOFTWARE, SECURITY, SAM)',
            'Mobile backups (iOS Info.plist, Manifest.db)'
        ],
        'playbooks': [
            {'id': 'PB-SIFT-016', 'name': 'Triage Prioritization', 'trigger': 'Always runs first'},
            {'id': 'PB-SIFT-001', 'name': 'Malware Hunting', 'trigger': 'Disk image present'},
            {'id': 'PB-SIFT-002', 'name': 'Ransomware', 'trigger': 'Ransomware indicators'},
            {'id': 'PB-SIFT-003', 'name': 'Lateral Movement', 'trigger': 'Lateral movement indicators'},
            {'id': 'PB-SIFT-004', 'name': 'Credential Theft', 'trigger': 'Credential theft indicators'},
            {'id': 'PB-SIFT-005', 'name': 'Persistence', 'trigger': 'Registry hives present'},
            {'id': 'PB-SIFT-006', 'name': 'Exfiltration', 'trigger': 'Exfiltration indicators'},
            {'id': 'PB-SIFT-007', 'name': 'Living-off-the-Land', 'trigger': 'LOLBin indicators'},
            {'id': 'PB-SIFT-008', 'name': 'Initial Access', 'trigger': 'Web shell indicators'},
            {'id': 'PB-SIFT-009', 'name': 'Insider Threat', 'trigger': 'Exfiltration indicators'},
            {'id': 'PB-SIFT-010', 'name': 'Anti-Forensics', 'trigger': 'Anti-forensics indicators'},
            {'id': 'PB-SIFT-012', 'name': 'Linux Forensics', 'trigger': 'Linux image detected'},
            {'id': 'PB-SIFT-013', 'name': 'macOS Forensics', 'trigger': 'macOS image detected'},
            {'id': 'PB-SIFT-015', 'name': 'Mobile Forensics', 'trigger': 'Mobile backup detected'},
            {'id': 'PB-SIFT-017', 'name': 'Cross-Image Correlation', 'trigger': 'Multiple disk images'}
        ],
        'pipeline': [
            '1. Evidence inventory & quality scoring',
            '2. OS classification & rapid indicator triage',
            '3. Playbook selection & specialist execution',
            '4. Critic validation of every result',
            '5. Unified findings report with severity & MITRE ATT&CK mapping'
        ]
    })


if __name__ == '__main__':
    print(f'Geoff DFIR on port {PORT}')
    print(f'Evidence source: {EVIDENCE_BASE_DIR}')
    print(f'Cases work dir: {CASES_WORK_DIR}')
    print(f'Ollama: {OLLAMA_URL}')
    print(f'Model: {LLM_MODEL}')
    app.run(host='0.0.0.0', port=PORT, debug=False, threaded=True)
