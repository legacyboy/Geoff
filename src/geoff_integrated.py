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
    # Use explicit path — find_dotenv() has a known crash in some python-dotenv versions
    _dotenv_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".env")
    if os.path.exists(_dotenv_path):
        load_dotenv(dotenv_path=_dotenv_path, override=True)
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
# STRICT_MODE - when True, re-raise exceptions after logging; when False (default), log and continue

# AI_EVIDENCE_CLASSIFICATION - when True, use AI-based evidence classification with self-healing

# Email file extensions — used to filter non-email files from email analysis dispatch

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

# ---------------------------------------------------------------------------
from geoff_config import *
from geoff_utils import (_global_exception_handler, safe_run, safe_git_commit,
    _fe_log, _fe_log_with_exception, _log_error, _log_info, _cleanup_mounts,
    _apply_anti_forensics_cascade, _audit_append, INVESTIGATION_SCHEMA,
    validate_investigation_state, git_commit_action, FindingsWriter)
from geoff_utils import *
from geoff_models import *
from geoff_self_heal import (_wire_attempt_heal, _audit_heal, _heal_cache)
from geoff_self_heal import *
from geoff_discovery import *

# Wire module-level references for orchestrator routing and self-healing
import geoff_utils as _gu

# Helper Functions
# ---------------------------------------------------------------------------

# Shell metacharacters that could enable command injection via evidence paths

# ---------------------------------------------------------------------------
# Global Exception Handler — catches unhandled exceptions anywhere
# ---------------------------------------------------------------------------

# _global_exception_handler, _ckpt_*, FindingsWriter → geoff_utils.py
# sys.excepthook wiring kept here
from geoff_logger import geoff_excepthook
sys.excepthook = geoff_excepthook

# safe_run, safe_git_commit, _fe_log, _fe_log_with_exception, _log_error, _log_info → geoff_utils.py
# _re_evaluate_playbooks → geoff_models.py


# _active_mounts is now in geoff_utils.py (shared via from geoff_utils import *)

# _cleanup_mounts, _apply_anti_forensics_cascade, _audit_append,
# INVESTIGATION_SCHEMA, validate_investigation_state, git_commit_action → geoff_utils.py
# ActionLogger, action_logger → geoff_models.py

# ---------------------------------------------------------------------------
# Flask App & Core Config
# ---------------------------------------------------------------------------

app = Flask(__name__)
# Disable static-file caching so browser picks up UI/CSS/JS changes
# on refresh without needing a server restart.
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
CORS(app)

PORT = int(os.environ.get('GEOFF_PORT', 8080))

# Auth decorator → geoff_routes.py (_require_auth)





# ---------------------------------------------------------------------------
# Orchestrators
# ---------------------------------------------------------------------------

orchestrator = ExtendedOrchestrator(EVIDENCE_BASE_DIR)
remnux_orchestrator = REMNUX_Orchestrator()

# Initialize Critic for validation
geoff_critic = GeoffCritic(OLLAMA_URL, AGENT_MODELS["critic"])
validation_pipeline = ValidationPipeline(orchestrator, geoff_critic)

# Initialize Forensicator for tool execution (multi-agent architecture)
geoff_forensicator = ForensicatorAgent(OLLAMA_URL)

# Wire geoff_utils module-level references for orchestrator routing & self-healing
_gu.orchestrator = orchestrator
_gu.remnux_orchestrator = remnux_orchestrator

# detect_tool_request, _extract_path_from_message → geoff_routes.py



# ---------------------------------------------------------------------------
# Investigation Pipeline
# ---------------------------------------------------------------------------
from geoff_pipeline import find_evil, run_full_investigation
import geoff_pipeline as _gpl

# Wire pipeline module-level singleton references (same pattern as geoff_utils)
_gpl.orchestrator = orchestrator
_gpl.remnux_orchestrator = remnux_orchestrator
_gpl.geoff_critic = geoff_critic
_gpl.geoff_forensicator = geoff_forensicator
import geoff_self_heal as _gsh
_gsh.geoff_critic = geoff_critic

# ---------------------------------------------------------------------------
# HTML Template (with Find Evil tab)
# ---------------------------------------------------------------------------
from geoff_templates import HTML_TEMPLATE

# ---------------------------------------------------------------------------
# Route registration — extracted to geoff_routes.py
# ---------------------------------------------------------------------------
from geoff_routes import register_routes
import geoff_routes as _gr

# Wire module-level singleton references for route handlers
_gr.orchestrator = orchestrator
_gr.remnux_orchestrator = remnux_orchestrator
_gr.geoff_critic = geoff_critic
_gr.geoff_forensicator = geoff_forensicator

# Initialize SettingsManager, apply persisted settings, wire into routes
from geoff_settings import SettingsManager as _SettingsManager
_settings_manager = _SettingsManager()
_settings_manager.apply_to_config()
_gr.settings_manager = _settings_manager

register_routes(app)



# ---------------------------------------------------------------------------
# Final wiring: connect _attempt_heal to geoff_utils after all functions exist
# ---------------------------------------------------------------------------
_wire_attempt_heal()


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

    from geoff_logger import get_logger as _get_geoff_logger
    _srv_log = _get_geoff_logger("geoff.server")
    _srv_log.info("Server starting", pid=os.getpid(), port=PORT)

    import signal as _signal
    def _sigterm_handler(signum, frame):
        _srv_log.info("Server shutting down", signal="SIGTERM")
        import sys as _sys; _sys.exit(0)
    _signal.signal(_signal.SIGTERM, _sigterm_handler)

    app.run(host='0.0.0.0', port=PORT, debug=False, threaded=True)