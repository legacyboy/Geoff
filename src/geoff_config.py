#!/usr/bin/env python3
"""Geoff DFIR - Configuration, constants, and foundational helpers.

Auto-extracted from geoff_integrated.py monolith.
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
from typing import Optional
import tempfile
import threading
import time
import uuid
import traceback
import hashlib
import tarfile
import zipfile
import gzip
import shutil

# Add src directory to path (works for both local and deployed)
SRC_DIR = os.path.dirname(os.path.abspath(__file__))
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

# STRICT_MODE - when True, re-raise exceptions after logging; when False (default), log and continue
STRICT_MODE = os.environ.get("GEOFF_STRICT_MODE", "false").lower() == "true"

# AI_EVIDENCE_CLASSIFICATION - when True, use AI-based evidence classification with self-healing
AI_EVIDENCE_CLASSIFICATION = os.environ.get("GEOFF_AI_CLASSIFICATION", "true").lower() == "true"

# Email file extensions — used to filter non-email files from email analysis dispatch
_EMAIL_EXTENSIONS = frozenset({'.eml', '.mbox', '.pst', '.ost', '.msg', '.emlx', '.dbx', '.edb'})

# Threading locks
_log_lock = threading.Lock()
_state_lock = threading.Lock()

import requests
import hmac
from collections import Counter
from datetime import datetime
from pathlib import Path
from functools import wraps
from flask import Flask, request, jsonify, render_template_string, send_from_directory, send_file, Response
from flask_cors import CORS

from jsonschema import validate as jsonschema_validate, ValidationError

from sift_specialists import SpecialistOrchestrator, SLEUTHKIT_Specialist, VOLATILITY_Specialist, STRINGS_Specialist
from sift_specialists_extended import ExtendedOrchestrator
from sift_specialists_remnux import REMNUX_Orchestrator
from geoff_critic import GeoffCritic, ValidationPipeline, HealCache, ErrorContext, HealDecision
from geoff_forensicator import ForensicatorAgent

# New modules for architecture pivot
from device_discovery import DeviceDiscovery
from host_correlator import HostCorrelator
from super_timeline import SuperTimeline
from narrative_report import NarrativeReportGenerator
from behavioral_analyzer import BehavioralAnalyzer
from evidence_classifier import AIEvidenceClassifier, classify_with_ai

__all__ = ["ACTIVE_PROFILE", "AGENT_MODELS", "AI_EVIDENCE_CLASSIFICATION", "CASES_WORK_DIR", "CHECKPOINT_FILE", "COMMON_LEGACY_OFFSETS", "EVIDENCE_BASE_DIR", "GEOFF_API_KEY", "LLM_MODEL", "MAX_STDOUT_SIZE", "MITRE_TAGS", "OLLAMA_API_KEY", "OLLAMA_URL", "PASS2_TRIGGER_PLAYBOOK_MAP", "PLAYBOOK_NAMES", "PLAYBOOK_NAMES_PASS2", "PLAYBOOK_STEPS", "PLAYBOOK_STEPS_PASS2", "PROFILES_PATH", "SRC_DIR", "STRICT_MODE", "THREAT_TAXONOMY", "_EMAIL_EXTENSIONS", "_EVIDENCE_TYPE_MAP", "_MAX_IN_MEMORY_FINDINGS", "_UNSAFE_PATH_CHARS", "_active_evidence_dir", "_atomic_append", "_atomic_write", "_hash_file", "_infer_evidence_type", "_log_lock", "_profile_models", "_resolve_dir", "_sanitize_path", "_state_lock", "_validate_evidence_path", "load_profile", "ollama_base_url", "ollama_headers"]







# ---------------------------------------------------------------------------
# Core operation constants
# ---------------------------------------------------------------------------

SRC_DIR = os.path.dirname(os.path.abspath(__file__))
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)


STRICT_MODE = os.environ.get("GEOFF_STRICT_MODE", "false").lower() == "true"

AI_EVIDENCE_CLASSIFICATION = os.environ.get("GEOFF_AI_CLASSIFICATION", "true").lower() == "true"

_EMAIL_EXTENSIONS = frozenset({'.eml', '.mbox', '.pst', '.ost', '.msg', '.emlx', '.dbx', '.edb'})


# ---------------------------------------------------------------------------
# Path validation, hashing, and atomic I/O
# ---------------------------------------------------------------------------

_UNSAFE_PATH_CHARS = re.compile(r'[;&|`$<>\!\n\r\t]')

def _validate_evidence_path(path: str) -> str:
    """Validate an evidence path to prevent command injection and path traversal.

    Raises ValueError if the path contains shell metacharacters or resolves
    outside of allowed base directories.
    """
    if _UNSAFE_PATH_CHARS.search(path):
        raise ValueError(f"Evidence path contains unsafe characters and will not be processed: {path!r}")
    # Resolve real path to prevent traversal (e.g. ../../../etc/passwd)
    real_path = Path(os.path.realpath(path))
    allowed_bases = [Path(os.path.realpath(b)) for b in [EVIDENCE_BASE_DIR, CASES_WORK_DIR, "/mnt/nas"] if b]
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
    """Atomically write data to path using temp file + replace.

    Parent directory is created on demand: callers shouldn't have to
    pre-mkdir each subdirectory of the case work dir before writing.
    """
    Path(path).parent.mkdir(parents=True, exist_ok=True)
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


# ---------------------------------------------------------------------------
# Checkpoint/Recovery System
# ---------------------------------------------------------------------------



# ---------------------------------------------------------------------------
# Checkpoint / Recovery constant
# ---------------------------------------------------------------------------

CHECKPOINT_FILE = ".geoff_checkpoint.json"


# ---------------------------------------------------------------------------
# Size / memory limits
# ---------------------------------------------------------------------------

MAX_STDOUT_SIZE = 50 * 1024 * 1024  # 50MB — prevent memory blowup from tool output
_MAX_IN_MEMORY_FINDINGS = int(os.environ.get("GEOFF_MAX_FINDINGS", "50000"))


# ---------------------------------------------------------------------------
# Path sanitization
# ---------------------------------------------------------------------------

def _sanitize_path(path_str: str, allowed_base: str = "") -> str:
    """Sanitize file paths to prevent directory traversal attacks."""
    basename = os.path.basename(str(path_str))
    if allowed_base:
        resolved = os.path.realpath(os.path.join(allowed_base, basename))
        if not resolved.startswith(os.path.realpath(allowed_base)):
            return os.path.join(allowed_base, basename)  # Fallback to basename only
    return basename



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
        print(f"[GEOFF] {env_var}: {path} not writable, using fallback: {fallback}", file=sys.stderr)
        return fallback


EVIDENCE_BASE_DIR = _resolve_dir('GEOFF_EVIDENCE_PATH',
                               "/home/sansforensics/evidence-storage/evidence",
                               "geoff-evidence")

CASES_WORK_DIR = _resolve_dir('GEOFF_CASES_PATH',
                             "/home/sansforensics/evidence-storage/cases",
                             "geoff-cases")

_active_evidence_dir: str = EVIDENCE_BASE_DIR


# ---------------------------------------------------------------------------
# API / Auth configuration
# ---------------------------------------------------------------------------

GEOFF_API_KEY = os.environ.get('GEOFF_API_KEY', '')


# ---------------------------------------------------------------------------
# Ollama API configuration
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Model Profiles
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
# Evidence type inference
# ---------------------------------------------------------------------------

_EVIDENCE_TYPE_MAP = {
    ".dd": "disk_image", ".raw": "disk_image", ".e01": "disk_image",
    ".img": "disk_image", ".vmdk": "disk_image", ".vhd": "disk_image",
    ".vhdx": "disk_image", ".qcow2": "disk_image", ".vdi": "disk_image",
    ".vmem": "memory_dump", ".mem": "memory_dump", ".dmp": "memory_dump",
    ".lime": "memory_dump", ".core": "memory_dump", ".mdmp": "memory_dump", ".hdmp": "memory_dump",
    ".pcap": "pcap", ".pcapng": "pcap", ".cap": "pcap",
    ".pcap.gz": "pcap", ".pcapng.gz": "pcap",
    ".evtx": "evtx", ".evt": "evt",
    ".hive": "hive", ".dat": "registry",
    ".eml": "email", ".mbox": "email", ".pst": "email", ".ost": "email", ".msg": "email", ".edb": "email",
    ".ab": "mobile_backups",
}

# NOTE: Virtual disk formats .vhdx, .qcow2, .vdi are NOT supported natively by
# SleuthKit tools. When these file extensions are encountered, geoff_discovery.py
# will attempt to convert them to raw format using 'qemu-img convert -O raw'
# before passing to SleuthKit operations. Ensure qemu-utils is installed.


def _infer_evidence_type(path: str) -> str:
    """Guess evidence type from file extension.

    For .img files, uses directory-name heuristics to distinguish
    memory dumps from disk images.
    For .pcap.gz / .pcapng.gz, returns 'pcap'.
    """
    if not path:
        return "unknown"
    path_lower = path.lower()
    # Compressed PCAPs: .pcap.gz / .pcapng.gz
    if path_lower.endswith('.pcap.gz') or path_lower.endswith('.pcapng.gz'):
        return "pcap"
    suffix = Path(path).suffix.lower()
    if suffix == '.img':
        # Disambiguate .img: could be disk_image or memory_dump
        parent = str(Path(path).parent.name).lower()
        if any(kw in parent for kw in ('memory', 'mem', 'ram', 'volatile')):
            return "memory_dump"
        name_lower = Path(path).name.lower()
        if any(kw in name_lower for kw in ('memory', 'mem', 'ram', 'vmem', 'dmp', 'dump',
                                            'hiberfil', 'pagefile', 'swapfile',
                                            'boomer', 'vista-beta', 'xp-laptop')):
            return "memory_dump"
    return _EVIDENCE_TYPE_MAP.get(suffix, "unknown")




# ---------------------------------------------------------------------------
# Partition offset fallbacks
# ---------------------------------------------------------------------------

COMMON_LEGACY_OFFSETS = [63, 0, 32256]


# ---------------------------------------------------------------------------
# MITRE ATT&CK Tags
# ---------------------------------------------------------------------------

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
    "phishing":          ["T1566", "T1534"],
}

# ---------------------------------------------------------------------------
# Threat Taxonomy — Multi-Label Case Classification Engine
# ---------------------------------------------------------------------------

THREAT_TAXONOMY = {
    "Malware": {"score_weight": 1.0, "indicators": ["executable", "persistence", "c2", "network_scan"]},
    "Data Leakage": {"score_weight": 1.0, "indicators": ["renamed_files", "cloud_sync", "email_exfil", "usb_copy"]},
    "Insider Threat": {"score_weight": 1.2, "indicators": ["off_hours", "anti_forensics", "renamed_files", "usb_copy", "network_share_access"]},
    "Ransomware": {"score_weight": 1.0, "indicators": ["encryption", "ransom_note", "mass_rename"]},
    "Phishing": {"score_weight": 0.8, "indicators": ["email_suspicious", "downloaded_executable", "credentials_harvesting"]},
    "APT": {"score_weight": 1.2, "indicators": ["c2", "lateral_movement", "persistence", "data_exfil", "multi_stage"]},
    "Policy Violation": {"score_weight": 0.6, "indicators": ["off_hours", "personal_software", "unauthorized_hardware"]},
}

# ---------------------------------------------------------------------------

# All 37 playbook IDs — always run, never cherry-pick
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
    "PB-SIFT-025": "Cloud & Enterprise IR",
    "PB-SIFT-026": "File Carving & Recovery",
    "PB-SIFT-027": "Memory Forensics",
    "PB-SIFT-028": "Windows Modern Artifacts",
    "PB-SIFT-029": "Encrypted Containers",
    "PB-SIFT-030": "Cloud Sync Artifacts",
    "PB-SIFT-031": "Enterprise Collaboration",
    "PB-SIFT-032": "VM Snapshot Forensics",
    "PB-SIFT-033": "Container Forensics",
    "PB-SIFT-034": "Network Device Forensics",
    "PB-SIFT-035": "Active Directory DC Forensics",
    "PB-SIFT-036": "PCAP Network Forensics",
    "PB-SIFT-037": "IoT Device Forensics",
}

# Triage indicators for severity classification (used for reporting, NOT for
# playbook selection — all playbooks always run regardless)
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
        "evt_logs": [
            ("logs", "parse_evt", {"evt_file": "{evt}"}),
        ],
        "disk_images": [
            ("sleuthkit", "list_files", {"image": "{image}", "offset": "{offset}", "recursive": True}),
            ("dc3dd", "verify_image", {"image": "{image}"}),
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
            ("scheduled", "parse_windows_scheduled_tasks", {"evidence_dir": "{image}"}),
            ("scheduled", "parse_linux_crontabs", {"evidence_dir": "{image}"}),
        ],
        "memory_dumps": [
            ("volatility", "process_list", {"memory_dump": "{mem}"}),
        ],
    },
    "PB-SIFT-004": {  # Privilege Escalation
        "memory_dumps": [
            ("volatility", "find_malware", {"memory_dump": "{mem}"}),
            ("memory", "find_injected_code", {"memory_dump": "{mem}"}),
        ],
        "disk_images": [
            ("sleuthkit", "list_files", {"image": "{image}", "offset": "{offset}", "recursive": True}),
            ("sleuthkit", "analyze_filesystem", {"image": "{image}", "offset": "{offset}"}),
        ],
        "registry_hives": [
            ("registry", "extract_autoruns", {"software_path": "{hive}"}),
            ("registry", "parse_hive", {"hive_path": "{hive}"}),
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
        "evt_logs": [
            ("logs", "parse_evt", {"evt_file": "{evt}"}),
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
        "evt_logs": [
            ("logs", "parse_evt", {"evt_file": "{evt}"}),
        ],
        "registry_hives": [
            ("registry", "extract_usb_devices", {"system_path": "{hive}"}),
            ("registry", "extract_mounted_devices", {"system_path": "{hive}"}),
            # A011 — Network Share Forensics: analyze mapped drives & MRU connections
            ("network_share_forensics", "analyze_network_shares", {"inventory": "{hive}"}),
        ],
    },
    "PB-SIFT-008": {  # Malware Hunting
        "disk_images": [
            ("sleuthkit", "analyze_partition_table", {"disk_image": "{image}"}),
            ("sleuthkit", "analyze_filesystem", {"image": "{image}", "offset": "{offset}"}),
            ("sleuthkit", "list_files", {"image": "{image}", "offset": "{offset}", "recursive": True}),
            ("strings", "extract_strings", {"file_path": "{image}", "min_length": 4, "encoding": "ascii"}),
            ("strings", "extract_strings", {"file_path": "{image}", "min_length": 8}),
            ("bulk_extractor", "scan_image", {"image": "{image}", "output_dir": "{output_dir}/bulk_extractor"}),
            # A006 — File Signature vs Extension Mismatch Detection
            ("files", "signature_mismatch_scan", {"output_dir": "{output_dir}"}),
        ],
        "memory_dumps": [
            ("volatility", "process_list", {"memory_dump": "{mem}"}),
            ("volatility", "find_malware", {"memory_dump": "{mem}"}),
        ],
    },
    "PB-SIFT-009": {  # Ransomware
        "disk_images": [
            ("sleuthkit", "list_files", {"image": "{image}", "offset": "{offset}", "recursive": True}),
            ("strings", "extract_strings", {"file_path": "{image}", "min_length": 8}),
        ],
        "memory_dumps": [
            ("volatility", "process_list", {"memory_dump": "{mem}"}),
            ("volatility", "find_malware", {"memory_dump": "{mem}"}),
        ],
        "other_files": [
            ("strings", "extract_strings", {"file_path": "{file}", "min_length": 8}),
        ],
    },
    "PB-SIFT-010": {  # Living-off-the-Land
        "evtx_logs": [
            ("logs", "parse_evtx", {"evtx_file": "{evtx}"}),
        ],
        "evt_logs": [
            ("logs", "parse_evt", {"evt_file": "{evt}"}),
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
        "evt_logs": [
            ("logs", "parse_evt", {"evt_file": "{evt}"}),
        ],
        "disk_images": [
            ("sleuthkit", "list_files", {"image": "{image}", "offset": "{offset}", "recursive": True}),
        ],
    },
    "PB-SIFT-012": {  # Anti-Forensics
        "evtx_logs": [
            ("logs", "parse_evtx", {"evtx_file": "{evtx}"}),
        ],
        "evt_logs": [
            ("logs", "parse_evt", {"evt_file": "{evt}"}),
        ],
        "disk_images": [
            ("sleuthkit", "list_files", {"image": "{image}", "offset": "{offset}", "recursive": True}),
            ("sleuthkit", "analyze_filesystem", {"image": "{image}", "offset": "{offset}"}),
            ("scheduled", "detect_backdoors", {"evidence_dir": "{image}"}),
            ("vss", "list_vss", {"image": "{image}"}),
            ("vss", "extract_vss_files", {"image": "{image}", "output_dir": "{output_dir}/vss"}),
            # A009 — Anti-Forensics Tool Signature Detection
            # Eraser: Prefetch ERASER.EXE-*.pf, Eraser task logs at %LocalAppData%\\Eraser\\*.log, UserAssist
            ("anti_forensics", "detect_eraser", {"image": "{image}"}),
            # CCleaner: Prefetch CCLEANER*.EXE-*.pf, CCleaner.ini at Program Files, UserAssist, Uninstall keys
            ("anti_forensics", "detect_ccleaner", {"image": "{image}"}),
            # SDelete: Prefetch SDELETE.EXE-*.pf, EID 4663 access_mask patterns
            ("anti_forensics", "detect_sdelete", {"image": "{image}"}),
            # General: $UsnJrnl large-scale deletion, VSS deletion artifacts
            ("anti_forensics", "detect_general_anti_forensics", {"image": "{image}"}),
            # A007 — $UsnJrnl Change Journal Forensics (parsed inline in pipeline)
            ("usnjrnl", "parse_usnjrnl", {"image": "{image}"}),
        ],
        "memory_dumps": [
            ("volatility", "process_list", {"memory_dump": "{mem}"}),
        ],
    },
    "PB-SIFT-013": {  # Insider Threat — includes USB/Removable Media forensics
        "evtx_logs": [
            ("logs", "parse_evtx", {"evtx_file": "{evtx}"}),
        ],
        "evt_logs": [
            ("logs", "parse_evt", {"evt_file": "{evt}"}),
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
        "disk_images": [
            ("fat_recovery", "recover_formatted_fat", {
                "disk_image": "{image}",
                "offset": "{offset}",
            }),
        ],
    },
    "PB-SIFT-014": {  # Linux Forensics
        "syslogs": [
            ("logs", "parse_syslog", {"log_file": "{syslog}"}),
        ],
        "disk_images": [
            ("sleuthkit", "analyze_partition_table", {"disk_image": "{image}"}),
            ("sleuthkit", "list_files", {"image": "{image}", "offset": "{offset}", "recursive": True}),
            ("scheduled", "parse_linux_crontabs", {"evidence_dir": "{image}"}),
            ("scheduled", "detect_backdoors", {"evidence_dir": "{image}"}),
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
            ("host_correlator", "merge_timelines", {"output_dir": "{output_dir}"}),
            ("host_correlator", "correlate_cross_image", {"output_dir": "{output_dir}"}),
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
        "evt_logs": [
            ("logs", "parse_evt", {"evt_file": "{evt}"}),
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
            ("zeek", "analyze_pcap", {"pcap_file": "{pcap}", "output_dir": "{output_dir}/zeek"}),
        ],
        "memory_dumps": [
            ("volatility", "process_list", {"memory_dump": "{mem}"}),
            ("volatility", "network_scan", {"memory_dump": "{mem}"}),
        ],
        "evtx_logs": [
            ("logs", "parse_evtx", {"evtx_file": "{evtx}"}),
        ],
        "evt_logs": [
            ("logs", "parse_evt", {"evt_file": "{evt}"}),
        ],
        "disk_images": [
            ("sleuthkit", "list_files", {"image": "{image}", "offset": "{offset}", "recursive": True}),
            ("strings", "extract_strings", {"file_path": "{image}", "min_length": 8}),
        ],
    },
    "PB-SIFT-021": {  # Mobile Analysis
        "mobile_backups": [
            # iOS — device metadata and account inventory
            ("mobile", "analyze_ios_backup",               {"backup_dir": "{mobile}"}),
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
            ("sleuthkit", "extract_browser_artifacts", {"image": "{image}", "offset": "{offset}"}),
        ],
        "mounted_search": [  # Post-mount IE/Edge history artifact discovery
            ("browser", "parse_ie_webcache", {
                "search_paths": [
                    "Users\\\\{user}\\\\AppData\\\\Local\\\\Microsoft\\\\Windows\\\\WebCache\\\\WebCacheV01.dat",
                    "Users\\\\{user}\\\\AppData\\\\Local\\\\Microsoft\\\\Windows\\\\History\\\\index.dat",
                ],
            }),
            ("browser", "parse_browser_search_terms", {
                "keyword_list": [
                    "leak", "exfil", "exfiltrate", "anti-forensic", "anti_forensic",
                    "wipe", "delete", "eraser", "ccleaner", "bleachbit", "shred",
                    "timestomp", "log clear", "wevtutil", "drop table",
                    "secure delete", "overwrite", "evidence wipe",
                ],
            }),
        ],
        "other_files": [
            ("browser", "extract_history", {"db_path": "{file}"}),
            ("browser", "extract_cookies", {"db_path": "{file}"}),
            ("browser", "extract_downloads", {"db_path": "{file}"}),
            ("browser", "extract_saved_passwords", {"db_path": "{file}"}),
        ],
    },
    "PB-SIFT-023": {  # Email Forensics
        "disk_images": [
            ("sleuthkit", "list_files", {"image": "{image}", "offset": "{offset}", "recursive": True}),
            ("sleuthkit", "extract_email_artifacts", {"image": "{image}", "offset": "{offset}"}),
        ],
        "mounted_search": [  # Post-mount email artifact discovery phase
            ("email", "search_email_artifacts", {
                "patterns": ["*.pst", "*.ost", "*.eml", "*.msg", "*.edb"],
                "search_paths": [
                    "Users\\{user}\\AppData\\Local\\Microsoft\\Outlook\\",
                    "Users\\{user}\\Documents\\Outlook Files\\",
                    "ProgramData\\Microsoft\\Search\\Data\\Applications\\Windows\\",
                ],
            }),
        ],
        "other_files": [  # NOTE: processes .pst/.ost/.dbx/.mbox/.eml/.msg/.edb files
            ("email", "analyze_pst", {"pst_path": "{file}"}),
            ("email", "parse_dbx", {"dbx_path": "{file}"}),
            ("email", "analyze_mbox", {"mbox_path": "{file}"}),
            ("email", "analyze_eml", {"eml_path": "{file}"}),
            ("email", "detect_phishing", {"email_dir": "{output_dir}"}),
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
    "PB-SIFT-025": {  # Cloud & Enterprise IR — cloud logs and unclassified file analysis
        "other_files": [
            ("remnux", "die_scan",       {"target_file": "{file}"}),
            ("remnux", "exiftool_scan",  {"target_file": "{file}"}),
            ("remnux", "clamav_scan",    {"target_file": "{file}"}),
            ("remnux", "ssdeep_hash",    {"target_file": "{file}"}),
            ("remnux", "floss_strings",  {"target_file": "{file}"}),
            ("remnux", "radare2_analyze",{"target_file": "{file}"}),
            ("strings", "extract_strings", {"file_path": "{file}", "min_length": 8}),
            ("logs", "scan_document_pii", {"evidence_path": "{file}"}),
            ("mobile_malware", "analyze_apk", {"apk_path": "{file}"}),
            ("mobile_malware", "analyze_ipa", {"ipa_path": "{file}"}),
            ("mobile_malware", "analyze_mobile_binary", {"binary_path": "{file}"}),
        ],
    },
    "PB-SIFT-026": {  # File Carving & Recovery — triggered automatically when needed
        "disk_images": [
            ("photorec", "recover_files", {"image": "{image}", "output_dir": "{output_dir}/carved"}),
        ],
    },
    "PB-SIFT-027": {  # Memory Forensics — triggered by .raw/.dmp/.lime/.mem files
        "memory_dumps": [
            ("memory", "analyze_memory", {"memory_dump": "{mem}", "output_dir": "{output_dir}/memory"}),
            ("memory", "extract_processes", {"memory_dump": "{mem}"}),
            ("memory", "extract_network", {"memory_dump": "{mem}"}),
            ("memory", "find_injected_code", {"memory_dump": "{mem}"}),
            ("memory", "extract_registry", {"memory_dump": "{mem}"}),
            ("memory", "extract_credentials", {"memory_dump": "{mem}"}),
        ],
    },
    "PB-SIFT-028": {  # Windows Modern Artifacts — triggered by Windows 10/11 OS
        "disk_images": [
            ("windows", "analyze_prefetch", {"image": "{image}"}),
            ("windows", "analyze_jumplists", {"image": "{image}"}),
            ("windows", "analyze_lnk", {"image": "{image}"}),
            ("windows", "analyze_amcache", {"image": "{image}"}),
            ("windows", "analyze_srum", {"image": "{image}"}),
            ("windows", "analyze_timeline", {"image": "{image}"}),
            ("windows", "analyze_defender", {"image": "{image}"}),
            ("windows", "analyze_bits", {"image": "{image}"}),
        ],
        "registry_hives": [
            ("windows", "analyze_shimcache", {"registry_hive": "{hive}"}),
        ],
    },
    "PB-SIFT-029": {  # Encrypted Containers — triggered by encrypted volume detection
        "disk_images": [
            ("crypto", "analyze_bitlocker", {"image": "{image}"}),
            ("crypto", "analyze_filevault", {"image": "{image}"}),
            ("crypto", "analyze_veracrypt", {"image": "{image}"}),
            ("crypto", "analyze_luks", {"image": "{image}"}),
            ("crypto", "search_keys", {"evidence_path": "{image}"}),
            ("crypto", "detect_encryption_anti_forensics", {"image": "{image}"}),
        ],
        "other_files": [
            ("crypto", "search_keys", {"evidence_path": "{file}"}),
        ],
    },
    "PB-SIFT-030": {  # Cloud Sync Artifacts — triggered by cloud sync DBs
        "other_files": [
            ("cloud", "analyze_onedrive", {"db_path": "{file}"}),
            ("cloud", "analyze_googledrive", {"db_path": "{file}"}),
            ("cloud", "analyze_dropbox", {"db_path": "{file}"}),
            ("cloud", "analyze_icloud", {"db_path": "{file}"}),
            ("cloud", "analyze_box", {"db_path": "{file}"}),
            ("cloud", "detect_exfiltration", {"evidence_path": "{file}"}),
            ("google_drive", "google_drive_scan", {"_phase": "gdrive"}),
        ],
    },
    "PB-SIFT-031": {  # Enterprise Collaboration — triggered by Teams/Slack/Discord/Skype/Zoom artifacts
        "other_files": [
            ("collaboration", "analyze_teams", {"db_path": "{file}"}),
            ("collaboration", "analyze_slack", {"db_path": "{file}"}),
            ("collaboration", "analyze_discord", {"db_path": "{file}"}),
            ("collaboration", "analyze_skype", {"db_path": "{file}"}),
            ("collaboration", "analyze_zoom", {"log_path": "{file}"}),
        ],
    },
    "PB-SIFT-032": {  # VM Snapshot Forensics — triggered by .vmss/.vmsn/.vmem files
        "memory_dumps": [
            ("vm", "extract_memory", {"vmem_file": "{mem}"}),
            ("vm", "detect_snapshots", {}),
        ],
        "disk_images": [
            ("vm", "extract_disk", {"image": "{image}"}),
            ("vm", "detect_escape", {"evidence_path": "{image}"}),
        ],
    },
    "PB-SIFT-033": {  # Container Forensics — triggered by Docker/container artifacts
        "other_files": [
            ("container", "enumerate", {"evidence_path": "{file}"}),
            ("container", "extract_filesystem", {"evidence_path": "{file}"}),
            ("container", "analyze_image", {"image_path": "{file}"}),
            ("container", "analyze_logs", {"log_path": "{file}"}),
            ("container", "analyze_kubernetes", {"evidence_path": "{file}"}),
            ("container", "detect_supply_chain", {"evidence_path": "{file}"}),
        ],
    },
    "PB-SIFT-034": {  # Network Device Forensics — triggered by disk_images (network device configs)
        "disk_images": [
            ("strings", "extract_strings", {"file_path": "{image}", "min_length": 4, "encoding": "ascii"}),
            ("strings", "extract_strings", {"file_path": "{image}", "min_length": 8}),
            ("sleuthkit", "list_files", {"image": "{image}", "offset": "{offset}", "recursive": True}),
        ],
        "syslogs": [
            ("logs", "parse_syslog", {"log_file": "{syslog}"}),
        ],
        "other_files": [
            ("strings", "extract_strings", {"file_path": "{file}", "min_length": 8}),
        ],
    },
    "PB-SIFT-035": {  # Active Directory DC Forensics — triggered by ntds.dit/SYSTEM/SAM artifacts
        "other_files": [
            ("sqlite", "analyze_sqlite", {"db_path": "{file}"}),
        ],
        "registry_hives": [
            ("registry", "extract_users", {"hive_path": "{hive}"}),
            ("registry", "parse_hive", {"hive_path": "{hive}"}),
        ],
    },
    # PB-SIFT-035 Note: Active Directory DC Forensics currently runs SQLite analysis
    # on other_files and registry analysis on hives. For full AD forensics, add
    # explicit NTDS.dit parsing (e.g., with ntdsxtract or libesedb) when .dit
    # files are detected in evidence. Also add a dedicated step to search for
    # NTDS.dit and SYSTEM hive pairs for credential extraction.
    "PB-SIFT-036": {  # PCAP Network Forensics — triggered by .pcap/.pcapng captures
        "pcaps": [
            ("network", "analyze_pcap", {"pcap_file": "{pcap}"}),
            ("network", "extract_http", {"pcap_file": "{pcap}"}),
            ("network", "extract_flows", {"pcap_file": "{pcap}", "output_dir": "{output_dir}/flows"}),
        ],
    },
    "PB-SIFT-037": {  # IoT Device Forensics — triggered by IoT device images/directories
        "disk_images": [
            ("sleuthkit", "list_files", {"image": "{image}", "offset": "{offset}", "recursive": True}),
            ("sleuthkit", "fsstat", {"image": "{image}"}),
        ],
        "other_files": [
            ("strings", "extract_strings", {"target_file": "{file}"}),
        ],
    },
}

# =====================================================================
# Pass 2 Playbook Definitions — timeline-intelligence-driven investigations
# =====================================================================
# These playbooks fire AFTER the super timeline is built and cross-device
# patterns are detected. They are THINNER than Pass 1 playbooks (4-8 steps
# per playbook) because they operate on focused investigation questions
# rather than comprehensive scans.
PLAYBOOK_STEPS_PASS2 = {
    "PB-SIFT-100": {  # Process Chain Investigation
        "disk_images": [
            # Reconstruct the full process chain across devices
            ("sleuthkit", "list_files", {"image": "{image}", "offset": "{offset}",
             "recursive": True,
             "filter_path": "{target_paths}",
             "time_window_start": "{time_window_start}",
             "time_window_end": "{time_window_end}"}),
            ("sleuthkit", "list_deleted", {"image": "{image}", "offset": "{offset}",
             "time_window_start": "{time_window_start}",
             "time_window_end": "{time_window_end}"}),
            # Extract process binaries for malware analysis
            # NOTE: extract_file requires manual inode specification.
            # Run list_files first, identify inodes of interest, then
            # re-run with explicit inode values via a targeted playbook.
            # The extract_file step is deferred until target_inodes is known.
        ],
        "memory_dumps": [
            ("volatility", "process_list", {"memory_dump": "{mem}"}),
            ("volatility", "dump_process", {"memory_dump": "{mem}",
             "target_pids": "{target_pids}"}),
        ],
        "pcaps": [
            ("network", "analyze_pcap", {"pcap_file": "{pcap}",
             "time_filter": "{time_window}",
             "filter_host": "{target_hosts}"}),
        ],
        "other_files": [
            # Analyze extracted binaries with REMnux
            ("remnux", "die_scan", {"target_file": "{file}"}),
            ("remnux", "clamav_scan", {"target_file": "{file}"}),
            ("remnux", "floss_strings", {"target_file": "{file}"}),
        ],
    },

    "PB-SIFT-101": {  # USB Lateral Movement Investigation
        "registry_hives": [
            ("registry", "extract_usb_devices", {"system_path": "{hive}"}),
            ("registry", "extract_mounted_devices", {"system_path": "{hive}"}),
            ("registry", "extract_user_assist", {"ntuser_path": "{hive}"}),
        ],
        "disk_images": [
            # List files accessed during USB mount window
            ("sleuthkit", "list_files", {"image": "{image}", "offset": "{offset}",
             "recursive": True,
             "time_window_start": "{time_window_start}",
             "time_window_end": "{time_window_end}"}),
            # Recover deleted files from destination
            ("sleuthkit", "list_deleted", {"image": "{image}", "offset": "{offset}",
             "time_window_start": "{time_window_start}",
             "time_window_end": "{time_window_end}"}),
            # Hash correlation between source and destination images
            # NOTE: Hash correlation (e.g. MD5/SHA1 cross-reference) should be
            # performed as a separate post-processing step comparing file hash
            # lists from both source and destination, not via raw string extraction.
            # ("sleuthkit", "hash_files", {"image": "{image}", "offset": "{offset}",
            #  "time_window_start": "{time_window_start}",
            #  "time_window_end": "{time_window_end}"}),
        ],
        "pcaps": [
            ("network", "analyze_pcap", {"pcap_file": "{pcap}",
             "time_filter": "{time_window}",
             "filter_host": "{target_hosts}"}),
        ],
    },

    "PB-SIFT-102": {  # Temporal Anomaly Investigation
        "disk_images": [
            # Extract full Plaso timeline for the anomaly window
            # GUARD: sort_timeline will be skipped gracefully at runtime if the
            # .plaso storage file does not exist (e.g. no prior log2timeline run).
            ("plaso", "sort_timeline", {
                "storage_file": "{output_dir}/timeline_{image_stem}.plaso",
                "output_format": "json_line",
                "filter_str": None,
                "time_filter_start": "{time_window_start}",
                "time_filter_end": "{time_window_end}",
            }),
            # Check for scheduled task creation in window
            ("sleuthkit", "list_files", {"image": "{image}", "offset": "{offset}",
             "recursive": True,
             "filter_path": "Windows/System32/Tasks",
             "time_window_start": "{time_window_start}",
             "time_window_end": "{time_window_end}"}),
        ],
        "memory_dumps": [
            ("volatility", "process_list", {"memory_dump": "{mem}"}),
            ("volatility", "network_scan", {"memory_dump": "{mem}"}),
        ],
        "evtx_logs": [
            ("logs", "parse_evtx", {"evtx_file": "{evtx}",
             "time_filter_start": "{time_window_start}",
             "time_filter_end": "{time_window_end}"}),
        ],
        "evt_logs": [
            ("logs", "parse_evt", {"evt_file": "{evt}",
             "time_filter_start": "{time_window_start}",
             "time_filter_end": "{time_window_end}"}),
        ],
        "pcaps": [
            ("network", "analyze_pcap", {"pcap_file": "{pcap}",
             "time_filter": "{time_window}"}),
        ],
    },

    "PB-SIFT-103": {  # IOC Cross-Reference Investigation
        "disk_images": [
            # Extract all instances of shared IOCs
            ("strings", "extract_strings", {"file_path": "{image}", "min_length": 8,
             "filter_patterns": "{ioc_patterns}"}),
            ("sleuthkit", "list_files", {"image": "{image}", "offset": "{offset}",
             "recursive": True}),
        ],
        "memory_dumps": [
            ("volatility", "find_malware", {"memory_dump": "{mem}"}),
            ("volatility", "dump_process", {"memory_dump": "{mem}",
             "target_pids": "{target_pids}"}),
        ],
        "other_files": [
            # Analyse each IOC-bearing file with REMnux
            ("remnux", "die_scan", {"target_file": "{file}"}),
            ("remnux", "exiftool_scan", {"target_file": "{file}"}),
            ("remnux", "clamav_scan", {"target_file": "{file}"}),
            ("remnux", "ssdeep_hash", {"target_file": "{file}"}),
            ("remnux", "floss_strings", {"target_file": "{file}"}),
        ],
        "pcaps": [
            ("network", "analyze_pcap", {"pcap_file": "{pcap}",
             "filter_host": "{ioc_ips}"}),
        ],
        "registry_hives": [
            # extract_autoruns reads the SOFTWARE hive; extract_services reads SYSTEM
            # Both use {hive} (substituted with actual hive file paths from evidence)
            ("registry", "extract_autoruns", {"software_path": "{hive}"}),
            ("registry", "extract_services", {"system_path": "{hive}"}),
        ],
    },

    "PB-SIFT-104": {  # Dwell Window Deep-Dive
        "disk_images": [
            # Filter Plaso queries to the dwell window
            ("plaso", "sort_timeline", {
                "storage_file": "{output_dir}/timeline_{image_stem}.plaso",
                "output_format": "json_line",
                "filter_str": None,
                "time_filter_start": "{dwell_start}",
                "time_filter_end": "{dwell_end}",
            }),
            ("sleuthkit", "list_files_mactime", {
                "image": "{image}", "offset": "{offset}",
            }),
        ],
        "memory_dumps": [
            ("volatility", "process_list", {"memory_dump": "{mem}"}),
            ("volatility", "network_scan", {"memory_dump": "{mem}"}),
            ("volatility", "find_malware", {"memory_dump": "{mem}"}),
        ],
        "evtx_logs": [
            ("logs", "parse_evtx", {"evtx_file": "{evtx}",
             "time_filter_start": "{dwell_start}",
             "time_filter_end": "{dwell_end}"}),
        ],
        "evt_logs": [
            ("logs", "parse_evt", {"evt_file": "{evt}",
             "time_filter_start": "{dwell_start}",
             "time_filter_end": "{dwell_end}"}),
        ],
        "pcaps": [
            ("network", "analyze_pcap", {"pcap_file": "{pcap}",
             "time_filter_start": "{dwell_start}",
             "time_filter_end": "{dwell_end}"}),
            ("network", "extract_flows", {"pcap_file": "{pcap}",
             "output_dir": "{output_dir}/flows",
             "time_filter_start": "{dwell_start}",
             "time_filter_end": "{dwell_end}"}),
        ],
        "registry_hives": [
            ("registry", "extract_user_assist", {"ntuser_path": "{hive}"}),
            ("registry", "extract_shellbags", {"ntuser_path": "{hive}"}),
        ],
    },
}

# Map Pass 2 trigger types to playbook IDs
PASS2_TRIGGER_PLAYBOOK_MAP = {
    "cross_device_process_chain": "PB-SIFT-100",
    "usb_lateral_movement": "PB-SIFT-101",
    "temporal_anomaly": "PB-SIFT-102",
    "off_hours_cluster": "PB-SIFT-102",
    "ioc_correlation": "PB-SIFT-103",
    "file_beaconing": "PB-SIFT-103",
    "dwell_window": "PB-SIFT-104",
}

# Pass 2 playbook names for reporting
PLAYBOOK_NAMES_PASS2 = {
    "PB-SIFT-100": "Process Chain Investigation",
    "PB-SIFT-101": "USB Lateral Movement Investigation",
    "PB-SIFT-102": "Temporal Anomaly Investigation",
    "PB-SIFT-103": "IOC Cross-Reference Investigation",
    "PB-SIFT-104": "Dwell Window Deep-Dive",
}

# Mapping of header-detected file types to inventory buckets for validation
