#!/usr/bin/env python3
"""Geoff DFIR - Flask route handlers and HTTP helpers.

Extracted from geoff_integrated.py monolith.

Pattern: all singletons and infrastructure are wired by geoff_integrated.py
after initialization, via module-level reference variables (same pattern as
geoff_utils.py and geoff_self_heal.py).

Route handlers are registered at call time via register_routes(app).
"""

import os
import json
import re
import subprocess
import threading
import time
import uuid
import hmac
from datetime import datetime
from pathlib import Path
from functools import wraps

from flask import (
    request, jsonify, render_template_string, send_from_directory,
    send_file, Response,
)
from markupsafe import escape as _html_escape

# ---------------------------------------------------------------------------
# Direct imports from sibling modules (no circular deps with geoff_integrated.py)
# ---------------------------------------------------------------------------
import geoff_config
import geoff_settings as _geoff_settings
from geoff_config import (
    GEOFF_API_KEY, EVIDENCE_BASE_DIR, CASES_WORK_DIR,
    OLLAMA_API_KEY, AGENT_MODELS, PLAYBOOK_NAMES,
    NON_REPLAYABLE_PLAYBOOKS,
    ollama_base_url,
    _UNSAFE_PATH_CHARS, _validate_evidence_path,
)
from geoff_utils import (
    _log_error, _log_info, _fe_log, _fe_log_with_exception,
    _state_lock, _find_evil_jobs, _run_step_via_orchestrator,
    _auto_cancel_stale_jobs, _start_job_heartbeat,
)
from geoff_models import action_logger, get_all_cases, get_available_tools_status
from geoff_self_heal import call_llm, _self_check_chat_response
import queue_manager as _queue_manager
from geoff_pipeline import find_evil, run_full_investigation, replay_playbook
from geoff_communications import CommunicationsAnalyzer
from geoff_stego import StegoAnalyzer
from geoff_keylogger import KeyloggerAnalyzer
from geoff_chat_aggregator import ChatAggregator
from geoff_rag import CaseRAG
from geoff_templates import HTML_TEMPLATE, NARRATIVE_REPORT_HTML

# Wire geoff_utils module reference for _save_jobs
import geoff_utils as _gu
from geoff_logger import get_logger as _get_logger
_fe_logger = _get_logger('geoff.find_evil')
_srv_logger = _get_logger('geoff.server')
_queue_logger = _get_logger('geoff.queue')

# ---------------------------------------------------------------------------
# Module-level singleton references (set by geoff_integrated.py after init)
# ---------------------------------------------------------------------------
orchestrator = None        # ExtendedOrchestrator instance
remnux_orchestrator = None  # REMNUX_Orchestrator instance
geoff_critic = None         # GeoffCritic instance
geoff_forensicator = None   # ForensicatorAgent instance
settings_manager = None    # SettingsManager instance


# ---------------------------------------------------------------------------
# Helpers — route-specific
# ---------------------------------------------------------------------------

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
    'logs':       {'parse_syslog', 'parse_evtx', 'parse_evt'},
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
    'browser':    {'extract_downloads', 'extract_cookies', 'extract_history',
                   'extract_login_data', 'extract_web_data', 'extract_session_restore',
                   'extract_firefox_key4', 'extract_firefox_formhistory', 'analyze_leveldb',
                   'extract_saved_passwords'},
    'email':      {'analyze_mbox', 'analyze_pst', 'analyze_eml',
                   'extract_attachments', 'extract_ios_envelope', 'extract_android_gmail',
                   'extract_email_provider', 'detect_auto_forward', 'analyze_received_chain'},
    'jumplist':   {'parse_jump_lists', 'parse_lnk_files', 'parse_recent_apps'},
    'macos':      {'analyze_launch_agents', 'parse_unified_log', 'analyze_fseventsd', 'parse_plist',
                   'analyze_apfs_snapshot', 'parse_spotlight', 'analyze_t2_secureboot',
                   'parse_asl_logs', 'analyze_app_bundles', 'check_gatekeeper'},
    'photorec':   {'recover_files'},
    'vss':        {'list_vss', 'extract_vss_files', 'analyze_vss_timeline', 'mount_vss'},
    'zimmerman':  {'parse_evtx_zimmerman', 'parse_mft', 'srum_parse', 'amcache_parse',
                   'shellbags_parse'},
    'remnux':     {'die_scan', 'exiftool_scan', 'peframe_scan', 'ssdeep_hash', 'hashdeep_audit',
                   'upx_unpack', 'pdfid_scan', 'pdf_parser', 'oledump_scan', 'js_beautify',
                   'radare2_analyze', 'floss_strings', 'clamav_scan'},
    'memory':     {'analyze_memory', 'extract_processes', 'extract_network',
                   'find_injected_code', 'extract_registry', 'extract_credentials'},
    'windows':    {'analyze_prefetch', 'analyze_jumplists', 'analyze_lnk',
                   'analyze_shimcache', 'analyze_amcache', 'analyze_srum',
                   'analyze_timeline', 'analyze_defender', 'analyze_bits'},
    'crypto':     {'analyze_bitlocker', 'analyze_filevault', 'analyze_veracrypt',
                   'analyze_luks', 'search_keys', 'detect_encryption_anti_forensics'},
    'cloud':      {'analyze_onedrive', 'analyze_googledrive', 'analyze_dropbox',
                   'analyze_icloud', 'analyze_box', 'detect_exfiltration'},
    'collaboration': {'analyze_teams', 'analyze_slack', 'analyze_discord',
                      'analyze_skype', 'analyze_zoom'},
    'vm':         {'detect_snapshots', 'extract_memory', 'extract_disk',
                   'analyze_config', 'detect_escape'},
    'container':  {'enumerate', 'extract_filesystem', 'analyze_image',
                   'analyze_logs', 'analyze_kubernetes', 'detect_supply_chain'},
}


def _strip_futures(obj):
    """Recursively strip non-serializable Future objects from result dicts."""
    if isinstance(obj, dict):
        keys_to_del = [k for k in obj.keys() if k.startswith('_') and ('future' in k.lower() or 'Future' in type(obj[k]).__name__)]
        for k in keys_to_del:
            del obj[k]
        for v in obj.values():
            _strip_futures(v)
    elif isinstance(obj, list):
        for item in obj:
            _strip_futures(item)


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

    if any(word in message_lower for word in ['evt', 'windows xp event log', 'legacy event log']):
        return {'module': 'logs', 'function': 'parse_evt', 'params': {}}

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
# Auth decorator
# ---------------------------------------------------------------------------

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


# ===================================================================
# Route Handler Functions
# ===================================================================

INDEX_HTML_PATH = os.path.join(os.path.dirname(os.path.abspath(os.path.dirname(__file__))), 'static', 'index.html')


def index():
    """GET / — Serve the main Geoff UI.

    Reads static/index.html at request time so UI updates (HTML/CSS/JS)
    don't require a server restart — just edit files under static/ and
    refresh the browser.  Running find-evil jobs are not interrupted.
    """
    key_meta = (
        f'<meta name="geoff-api-key" content="{_html_escape(GEOFF_API_KEY)}">'
        if GEOFF_API_KEY else ''
    )
    evidence_base_js = EVIDENCE_BASE_DIR.replace("'", "\\'")

    # Prefer the standalone file so UI updates don't need a restart.
    # Falls back to the embedded Python string if the file is missing.
    if os.path.isfile(INDEX_HTML_PATH):
        with open(INDEX_HTML_PATH, 'r', encoding='utf-8') as f:
            html = f.read()
    else:
        html = HTML_TEMPLATE

    return render_template_string(
        html
        .replace('<!-- GEOFF_API_KEY_META -->', key_meta)
        .replace('<!-- GEOFF_EVIDENCE_BASE_DIR -->', evidence_base_js)
    )


def chat():
    """POST /chat — LLM-powered chat with tool detection."""
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
            _chat_start_time = time.time()
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
                    "evidence_dir": evidence_dir,
                    "log": [{"time": datetime.now().strftime("%H:%M:%S"),
                             "msg": f"Find Evil started from chat: {evidence_dir}"}],
                }

            _start_job_heartbeat(job_id, _chat_start_time)

            def _run():
                try:
                    report = find_evil(evidence_dir, job_id=job_id)
                    with _state_lock:
                        _find_evil_jobs[job_id]["status"] = "complete"
                        _find_evil_jobs[job_id]["result"] = report
                        _gu._save_jobs()  # persist complete state
                except Exception as e:
                    with _state_lock:
                        _find_evil_jobs[job_id]["status"] = "error"
                        _find_evil_jobs[job_id]["error"] = str(e)
                    _gu._save_jobs()  # persist error state

            threading.Thread(target=_run, daemon=True).start()
            # persist initial state
            _gu._save_jobs()

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
        if not case_match and geoff_config._active_evidence_dir and geoff_config._active_evidence_dir != EVIDENCE_BASE_DIR:
            try:
                active_basename = os.path.basename(geoff_config._active_evidence_dir)
                if active_basename in cases:
                    case_match = active_basename
                    files = cases[active_basename]
                elif os.path.exists(geoff_config._active_evidence_dir):
                    files = [f for f in os.listdir(geoff_config._active_evidence_dir) if not f.startswith('.')]
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
                action_logger.log('CHAT_HEALING', {
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


def list_cases():
    """GET /cases — Return ALL cases with ALL files."""
    return jsonify({'cases': get_all_cases()})


def get_case_report(case_name):
    """GET /cases/<case_name>/report — Return the narrative report markdown for a completed Find Evil case.

    The case_name must consist only of alphanumeric characters, hyphens, and
    underscores to prevent path traversal.
    """
    safe_name = re.sub(r'[^a-zA-Z0-9_\-]', '_', case_name)
    if not safe_name:
        return jsonify({'error': 'Invalid case name'}), 400

    # Search CASES_WORK_DIR for an exact or _findevil_-separated match.
    cases_root = Path(CASES_WORK_DIR)
    report_path = None
    if cases_root.exists():
        pattern = re.compile(r'^' + re.escape(safe_name) + r'(_findevil_|$)')
        for candidate in sorted(cases_root.iterdir(), reverse=True):
            if candidate.is_dir() and pattern.match(re.sub(r"[^a-zA-Z0-9_\-]", "", candidate.name)):
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


def graph_viewer():
    """GET /reports/graph — Serve the new force-directed D3.js graph viewer."""
    viewer_path = Path(__file__).parent.parent / 'static' / 'graph_viewer.html'
    html = viewer_path.read_text(encoding='utf-8')
    if GEOFF_API_KEY:
        key_meta = f'<meta name="geoff-api-key" content="{_html_escape(GEOFF_API_KEY)}">'
        html = html.replace('<head>', '<head>\n  ' + key_meta, 1)
    return html, 200, {'Content-Type': 'text/html; charset=utf-8'}


def list_reports():
    """GET /reports — List completed Find Evil cases that have a real report (not stubs)."""
    # Scan current CASES_WORK_DIR plus the legacy evidence-storage-2 path
    scan_roots = [Path(CASES_WORK_DIR)]
    legacy_root = Path("/mnt/evidence-storage-2")
    if legacy_root.exists() and legacy_root.resolve() != Path(CASES_WORK_DIR).resolve():
        scan_roots.append(legacy_root)

    reports = []
    seen_dirs: set = set()

    for cases_root in scan_roots:
        if not cases_root.exists():
            continue
        for d in sorted(cases_root.iterdir(), reverse=True):
            if not d.is_dir():
                continue
            if '_findevil_' not in d.name:
                continue
            if d.name in seen_dirs:
                continue
            seen_dirs.add(d.name)

            # Only include cases with real report data — skip stubs
            # A proper report has either:
            #   - d / "reports" / "find_evil_report.json" (final narrative)
            #   - d / "findings.json" (findings summary)
            # .geoff_checkpoint.json alone is NOT sufficient (stub from cancelled/dead job)
            candidate_files = [
                d / "reports" / "find_evil_report.json",
                d / "findings.json",
                d / "summary.json",
            ]
            data: dict = {}
            matched_on = None
            for candidate in candidate_files:
                if not candidate.exists():
                    continue
                try:
                    if candidate.stat().st_size > 50 * 1024 * 1024:  # 50 MB guard
                        continue
                    with open(candidate) as f:
                        loaded = json.load(f)
                    if isinstance(loaded, dict):
                        data = loaded
                        matched_on = candidate.name
                        break
                except (OSError, json.JSONDecodeError):
                    continue

            # Skip stubs with no real report data — require at least elapsed_seconds > 0
            # to confirm actual work was done
            if not data or not data.get('elapsed_seconds'):
                continue

            try:
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
                    'severity': data.get('severity') or 'INFO',
                    'classification': data.get('classification', ''),
                    'elapsed_seconds': data.get('elapsed_seconds', 0),
                    'evidence_dir': data.get('evidence_dir', ''),
                })
            except (KeyError, AttributeError):
                continue

    return jsonify({'reports': reports})

def _find_case_dir(safe_dir):
    """Search CASES_WORK_DIR and legacy path for a matching case directory.
    Returns Path or None."""
    scan_roots = [Path(CASES_WORK_DIR)]
    legacy_root = Path("/mnt/evidence-storage-2")
    if legacy_root.exists() and legacy_root.resolve() != Path(CASES_WORK_DIR).resolve():
        scan_roots.append(legacy_root)

    safe_norm = re.sub(r'[^a-zA-Z0-9_\-]', '_', safe_dir)

    for root in scan_roots:
        if not root.exists():
            continue
        # Exact match first
        for candidate in sorted(root.iterdir(), reverse=True):
            if not candidate.is_dir():
                continue
            cand_norm = re.sub(r'[^a-zA-Z0-9_\-]', '_', candidate.name)
            if cand_norm == safe_norm:
                return candidate
        # Fallback: prefix-only match (case name without _findevil_ suffix)
        for candidate in sorted(root.iterdir(), reverse=True):
            if not candidate.is_dir():
                continue
            cand_norm = re.sub(r'[^a-zA-Z0-9_\-]', '_', candidate.name)
            cand_prefix = cand_norm.split('_findevil_')[0]
            if cand_prefix == safe_norm:
                return candidate
    return None


def get_report_json(case_dir):
    """GET /reports/<case_dir>/json — Serve the find_evil_report.json for a specific case directory,
    enriched with narrative report content if available."""
    safe_dir = re.sub(r'[^a-zA-Z0-9_\-]', '_', case_dir)
    if not safe_dir:
        return jsonify({'error': 'Invalid case directory name'}), 400

    case_path = _find_case_dir(safe_dir)

    if not case_path or not case_path.is_dir():
        return jsonify({'error': 'Case not found'}), 404
    report_file = case_path / "reports" / "find_evil_report.json"
    if not report_file.exists():
        return jsonify({'error': 'Report not found'}), 404
    try:
        content = report_file.read_text(encoding='utf-8')
        data = json.loads(content)
        # Enrich with narrative report content
        narrative_md = case_path / "reports" / "narrative_report.md"
        if narrative_md.exists():
            if narrative_md.stat().st_size > 10 * 1024 * 1024:
                data['narrative_report'] = None
            else:
                data['narrative_report'] = narrative_md.read_text(encoding='utf-8')
        else:
            data['narrative_report'] = None
        # Enrich with ALL sections from narrative report JSON
        narrative_json = case_path / "reports" / "narrative_report.json"
        if narrative_json.exists():
            try:
                nr_data = json.loads(narrative_json.read_text(encoding='utf-8'))
                # Copy all narrative sections into the report data
                # (don't overwrite pipeline-generated keys that are richer)
                for nr_key in [
                    'executive_summary', 'iocs', 'attack_chain',
                    'kill_chain_timeline', 'devices_and_users', 'blast_radius',
                    'dwell_time', 'evidence_confidence', 'conclusion',
                    'user_narratives', 'significant_events', 'self_corrections',
                    'failed_steps', 'findings', 'email_phishing',
                    'full_written_report', 'unprocessed_files',
                ]:
                    if nr_key in nr_data and nr_data[nr_key] is not None:
                        # Only set if pipeline didn't already populate a richer version
                        if nr_key not in data or data[nr_key] is None or data[nr_key] == '' or data[nr_key] == []:
                            data[nr_key] = nr_data[nr_key]
                        elif nr_key == 'iocs':
                            # Merge narrative IOCs into pipeline IOCs
                            pipeline_iocs = data.get('iocs', {})
                            narrative_iocs = nr_data['iocs']
                            if isinstance(pipeline_iocs, dict) and isinstance(narrative_iocs, dict):
                                for ioc_cat, ioc_vals in narrative_iocs.items():
                                    if ioc_cat not in pipeline_iocs:
                                        pipeline_iocs[ioc_cat] = ioc_vals
                                    elif isinstance(pipeline_iocs[ioc_cat], list) and isinstance(ioc_vals, list):
                                        # Merge and deduplicate
                                        existing = set(str(x) for x in pipeline_iocs[ioc_cat])
                                        for v in ioc_vals:
                                            if str(v) not in existing:
                                                pipeline_iocs[ioc_cat].append(v)
                                                existing.add(str(v))
                        elif nr_key == 'attack_chain':
                            # Merge narrative attack_chain fields into pipeline attack_chain
                            pipeline_ac = data.get('attack_chain', {})
                            narrative_ac = nr_data['attack_chain']
                            if isinstance(narrative_ac, str):
                                # Always store the narrative interpretation text separately so JS can render it
                                data['attack_chain_narrative'] = narrative_ac
                            if isinstance(pipeline_ac, dict) and isinstance(narrative_ac, dict):
                                for k, v in narrative_ac.items():
                                    if k not in pipeline_ac or pipeline_ac[k] is None:
                                        pipeline_ac[k] = v
            except (json.JSONDecodeError, OSError) as e:
                _log_error("Failed to parse narrative report JSON", e)
        # Fallback: inject timeline from super_timeline.jsonl if report has 0 events
        if not data.get('timeline'):
            tl_file = case_path / "timeline" / "super_timeline.jsonl"
            if not tl_file.exists():
                _log_info(f"Timeline fallback: file not found at {tl_file}")
            elif tl_file.stat().st_size <= 50:
                _log_info(f"Timeline fallback: file too small ({tl_file.stat().st_size} bytes) at {tl_file}")
            else:
                tl_events = []
                try:
                    with open(tl_file, 'r', encoding='utf-8', errors='replace') as f:
                        for line in f:
                            line = line.strip()
                            if line:
                                try:
                                    tl_events.append(json.loads(line))
                                    if len(tl_events) >= 10000:
                                        break
                                except (json.JSONDecodeError, ValueError):
                                    pass
                except OSError:
                    pass
                if tl_events:
                    data['timeline'] = tl_events
                    _log_info(f"Timeline fallback: loaded {len(tl_events)} events from {tl_file}")
                else:
                    _log_error(f"Timeline fallback: no valid events parsed from {tl_file}", None)
        return json.dumps(data, indent=2), 200, {'Content-Type': 'application/json; charset=utf-8'}
    except OSError as e:
        _log_error("Failed to read report JSON", e)
        return jsonify({'error': 'Unable to read report'}), 500


def download_markdown(case_dir):
    """GET /reports/<case_dir>/download/markdown — Serve narrative_report.md as a downloadable file."""
    safe_dir = re.sub(r'[^a-zA-Z0-9_\-]', '_', case_dir)
    if not safe_dir:
        return jsonify({'error': 'Invalid case directory name'}), 400

    case_path = _find_case_dir(safe_dir)

    if not case_path or not case_path.is_dir():
        return jsonify({'error': 'Case not found'}), 404
    path = case_path / 'reports' / 'narrative_report.md'
    if not path.exists():
        return jsonify({'error': 'Narrative report not found'}), 404
    return send_file(
        path,
        mimetype='text/markdown',
        as_attachment=True,
        download_name=f'{safe_dir}_report.md'
    )


def download_json(case_dir):
    """GET /reports/<case_dir>/download/json — Serve find_evil_report.json as a downloadable file."""
    safe_dir = re.sub(r'[^a-zA-Z0-9_\-]', '_', case_dir)
    if not safe_dir:
        return jsonify({'error': 'Invalid case directory name'}), 400

    # Search CASES_WORK_DIR for a matching directory (normalized match)
    cases_root = Path(CASES_WORK_DIR)
    case_path = None
    if cases_root.exists():
        safe_norm = re.sub(r'[^a-zA-Z0-9_\-]', '_', safe_dir)
        for candidate in sorted(cases_root.iterdir(), reverse=True):
            if not candidate.is_dir():
                continue
            cand_norm = re.sub(r'[^a-zA-Z0-9_\-]', '_', candidate.name)
            if cand_norm == safe_norm:
                case_path = candidate
                break
        # Fallback: prefix-only match (e.g. case name without _findevil_ suffix)
        if case_path is None:
            for candidate in sorted(cases_root.iterdir(), reverse=True):
                if not candidate.is_dir():
                    continue
                cand_norm = re.sub(r'[^a-zA-Z0-9_\-]', '_', candidate.name)
                cand_prefix = cand_norm.split('_findevil_')[0]
                if cand_prefix == safe_norm:
                    case_path = candidate
                    break

    if not case_path or not case_path.is_dir():
        return jsonify({'error': 'Case not found'}), 404
    try:
        case_path.resolve().relative_to(Path(CASES_WORK_DIR).resolve())
    except ValueError:
        return jsonify({'error': 'Invalid case directory'}), 400
    path = case_path / 'reports' / 'find_evil_report.json'
    if not path.exists():
        return jsonify({'error': 'Report not found'}), 404
    return send_file(
        path,
        mimetype='application/json',
        as_attachment=True,
        download_name=f'{safe_dir}_raw.json'
    )


def download_summary(case_dir):
    """GET /reports/<case_dir>/download/summary — Extract executive summary from narrative_report.json and serve as .md download."""
    safe_dir = re.sub(r'[^a-zA-Z0-9_\-]', '_', case_dir)
    if not safe_dir:
        return jsonify({'error': 'Invalid case directory name'}), 400

    # Search CASES_WORK_DIR for a matching directory (normalized match)
    cases_root = Path(CASES_WORK_DIR)
    case_path = None
    if cases_root.exists():
        safe_norm = re.sub(r'[^a-zA-Z0-9_\-]', '_', safe_dir)
        for candidate in sorted(cases_root.iterdir(), reverse=True):
            if not candidate.is_dir():
                continue
            cand_norm = re.sub(r'[^a-zA-Z0-9_\-]', '_', candidate.name)
            if cand_norm == safe_norm:
                case_path = candidate
                break
        # Fallback: prefix-only match (e.g. case name without _findevil_ suffix)
        if case_path is None:
            for candidate in sorted(cases_root.iterdir(), reverse=True):
                if not candidate.is_dir():
                    continue
                cand_norm = re.sub(r'[^a-zA-Z0-9_\-]', '_', candidate.name)
                cand_prefix = cand_norm.split('_findevil_')[0]
                if cand_prefix == safe_norm:
                    case_path = candidate
                    break

    if not case_path or not case_path.is_dir():
        return jsonify({'error': 'Case not found'}), 404
    try:
        case_path.resolve().relative_to(Path(CASES_WORK_DIR).resolve())
    except ValueError:
        return jsonify({'error': 'Invalid case directory'}), 400
    path = case_path / 'reports' / 'narrative_report.json'
    if not path.exists():
        return jsonify({'error': 'Narrative JSON not found'}), 404
    with open(path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    summary = data.get('executive_summary', 'No executive summary available.')
    content = f'# Executive Summary — {safe_dir}\n\n{summary}\n'
    return Response(
        content,
        mimetype='text/markdown',
        headers={'Content-Disposition': f'attachment; filename="{safe_dir}_executive_summary.md"'}
    )


def viewer_html():
    """GET /reports/viewer — Serve the Evidence Graph viewer UI (with optional case= param)."""
    viewer_dir = Path(__file__).parent.parent / 'static' / 'geoff-viewer'
    html = (viewer_dir / 'index.html').read_text(encoding='utf-8')
    if GEOFF_API_KEY:
        key_meta = f'<meta name="geoff-api-key" content="{_html_escape(GEOFF_API_KEY)}">'
        html = html.replace('<head>', '<head>\n  ' + key_meta, 1)
    return html, 200, {'Content-Type': 'text/html; charset=utf-8'}


def viewer_static(filename):
    """GET /static/geoff-viewer/<path:filename> — Serve static files for the Evidence Graph viewer."""
    viewer_dir = Path(__file__).parent.parent / 'static' / 'geoff-viewer'
    if '..' in filename or filename.startswith('/'):
        return jsonify({'error': 'Invalid path'}), 400
    return send_from_directory(str(viewer_dir), filename)


def ui_static(filename):
    """GET /static/<filename> — Serve main UI static assets (tokens.css, main.js, report.js)."""
    static_dir = Path(__file__).parent.parent / 'static'
    if '..' in filename or filename.startswith('/') or '/' in filename:
        return jsonify({'error': 'Invalid path'}), 400
    allowed = {'tokens.css', 'main.js', 'report.js'}
    if filename not in allowed:
        return jsonify({'error': 'Not found'}), 404
    return send_from_directory(str(static_dir), filename)


def narrative_report_page():
    """GET /reports/narrative — Serve the narrative report HTML (case picker or specific case view)."""
    key_meta = (
        f'<meta name="geoff-api-key" content="{_html_escape(GEOFF_API_KEY)}">'
        if GEOFF_API_KEY else ''
    )
    html = NARRATIVE_REPORT_HTML.replace('<!-- GEOFF_API_KEY_META -->', key_meta)
    return html, 200, {'Content-Type': 'text/html; charset=utf-8'}


def serve_supertimeline(case_dir):
    """GET /reports/<case_dir>/supertimeline — Serve the supertimeline.html for a case."""
    safe_dir = re.sub(r'[^a-zA-Z0-9_\-]', '_', case_dir)
    case_path = _find_case_dir(safe_dir)
    if not case_path:
        return "Case not found", 404
    st_path = case_path / "reports" / "supertimeline.html"
    if not st_path.exists():
        return "Supertimeline not generated for this case", 404
    return st_path.read_text(encoding='utf-8'), 200, {'Content-Type': 'text/html; charset=utf-8'}



def get_ip_map(case_dir):
    """GET /reports/<case_dir>/ip-map — Return IP connection map JSON for a case."""
    safe_dir = re.sub(r'[^a-zA-Z0-9_\-]', '_', case_dir)
    if not safe_dir:
        return jsonify({'error': 'Invalid case directory name'}), 400
    case_path = _find_case_dir(safe_dir)
    if not case_path or not case_path.is_dir():
        return jsonify({'error': 'Case not found'}), 404
    try:
        from geoff_ip_map import IPConnectionExtractor
        extractor = IPConnectionExtractor(case_path)
        data = extractor.extract()
        return jsonify(data)
    except Exception as e:
        _log_error("Failed to extract IP map", e)
        return jsonify({'nodes': [], 'edges': [], 'error': str(e)}), 200


def ip_map_page():
    """GET /ip-map — Serve the IP connection map visualization page."""
    html_path = Path(__file__).parent.parent / 'static' / 'ip-map.html'
    html = html_path.read_text(encoding='utf-8')
    if GEOFF_API_KEY:
        key_meta = f'<meta name="geoff-api-key" content="{_html_escape(GEOFF_API_KEY)}">'
        html = html.replace('<head>', '<head>\n  ' + key_meta, 1)
    return html, 200, {'Content-Type': 'text/html; charset=utf-8'}


def mitre_matrix():
    """GET /reports/mitre-matrix — Serve the MITRE ATT&CK matrix viewer."""
    viewer_dir = Path(__file__).parent.parent / 'static' / 'geoff-viewer' / 'components'
    return send_from_directory(str(viewer_dir), 'mitre-matrix.html')


def mitre_heatmap():
    """GET /reports/mitre-heatmap — Serve the MITRE ATT&CK interactive heatmap."""
    viewer_dir = Path(__file__).parent.parent / 'static' / 'geoff-viewer' / 'components'
    return send_from_directory(str(viewer_dir), 'mitre-heatmap.html')


def list_tools():
    """GET /tools — Return available forensic tools."""
    return jsonify({'tools': get_available_tools_status()})


def health():
    """GET /health — Basic liveness probe."""
    return jsonify({'status': 'ok'})


def health_detailed():
    """GET /health/detailed — Run the full self-check and return JSON results."""
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


def run_tool():
    """POST /run-tool — Execute a forensic tool directly."""
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


def critic_validate():
    """POST /critic/validate — Manually trigger critic validation."""
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


def critic_summary(investigation_id):
    """GET /critic/summary/<investigation_id> — Get validation summary for investigation."""
    try:
        summary = geoff_critic.get_validation_summary(investigation_id)
        return jsonify(summary)
    except Exception as e:
        return jsonify({'status': 'error', 'error': str(e)})


def get_investigation_status(case_name):
    """GET /investigation/status/<case_name> — Get status of background investigation via find_evil pipeline."""
    try:
        safe_name = re.sub(r'[^a-zA-Z0-9_\-]', '_', case_name)
        if not safe_name:
            return jsonify({'status': 'error', 'error': 'Invalid case name'}), 400

        # Check active find_evil jobs — hold lock for safe iteration
        with _state_lock:
            jobs_snapshot = list(_find_evil_jobs.items())
        for job_id, job in jobs_snapshot:
            if safe_name in job_id or job.get('case_name') == safe_name or job.get('case_name', '').replace(' ', '_') == safe_name:
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
        safe_norm = re.sub(r'[^a-zA-Z0-9_\-]', '_', safe_name)
        if cases_root.exists():
            for d in sorted(cases_root.iterdir(), reverse=True):
                if not d.is_dir():
                    continue
                cand_norm = re.sub(r'[^a-zA-Z0-9_\-]', '_', d.name)
                if cand_norm == safe_norm:
                    candidate = d / "reports" / "find_evil_report.json"
                    if candidate.exists():
                        report_file = candidate
                        break
            # Fallback: prefix-only match
            if report_file is None:
                for d in sorted(cases_root.iterdir(), reverse=True):
                    if not d.is_dir():
                        continue
                    cand_norm = re.sub(r'[^a-zA-Z0-9_\-]', '_', d.name)
                    cand_prefix = cand_norm.split('_findevil_')[0]
                    if cand_prefix == safe_norm:
                        candidate = d / "reports" / "find_evil_report.json"
                        if candidate.exists():
                            report_file = candidate
                            break
        if report_file:
            return jsonify({'status': 'completed', 'case': safe_name, 'report': str(report_file)})
        return jsonify({'status': 'not_found', 'case': safe_name}), 404
    except Exception as e:
        return jsonify({'status': 'error', 'error': str(e)}), 500


def find_evil_route():
    """
    POST /find-evil
    Point at an evidence directory, auto-run all playbooks, find evil.

    Request body (JSON):
        {"evidence_dir": "/path/to/evidence"}

    Returns:
        {"job_id": "...", "status": "running"}
    """
    try:
        # Tolerate missing/malformed JSON body — bare POST returns 400, not 500.
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify({"status": "error", "error": "Request body must be a JSON object"}), 400
        evidence_dir = data.get('evidence_dir', '').strip() or data.get('evidence_path', '').strip() or EVIDENCE_BASE_DIR

        # Reject shell-metacharacter input up front
        if _UNSAFE_PATH_CHARS.search(evidence_dir):
            return jsonify({
                "status": "error",
                "error": f"Evidence path contains unsafe characters and will not be processed: {evidence_dir!r}",
            }), 400

        # If not an absolute path or doesn't exist as-is, try joining with EVIDENCE_BASE_DIR
        if evidence_dir and not Path(evidence_dir).is_absolute():
            evidence_dir = os.path.join(EVIDENCE_BASE_DIR, evidence_dir)
        elif evidence_dir and not Path(evidence_dir).exists() and EVIDENCE_BASE_DIR:
            candidate = os.path.join(EVIDENCE_BASE_DIR, os.path.basename(evidence_dir))
            if Path(candidate).exists():
                evidence_dir = candidate

        # Reject paths that resolve outside allowed directories
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

        # Check for existing running job targeting the same evidence directory
        with _state_lock:
            for existing_job_id, existing_job in _find_evil_jobs.items():
                if existing_job.get("status") in ("running", "initializing"):
                    if existing_job.get("evidence_dir") == evidence_dir:
                        return jsonify({
                            "status": "error",
                            "error": "A job is already running for this evidence directory. Cancel it first or wait for it to complete.",
                            "existing_job_id": existing_job_id,
                        }), 409

        # Create a job ID and register it
        job_id = f"fe-{uuid.uuid4().hex[:12]}"

        _job_start_time = time.time()
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
                "evidence_dir": evidence_dir,
                "log": [{"time": datetime.now().strftime("%H:%M:%S"), "msg": "Find Evil job started"}],
            }

        _start_job_heartbeat(job_id, _job_start_time)

        # Spawn the find_evil run in a background thread
        def _run():
            try:
                _fe_logger.info('Find Evil started', job_id=job_id, evidence=evidence_dir)
                report = find_evil(evidence_dir, job_id=job_id)
                with _state_lock:
                    _find_evil_jobs[job_id]["status"] = "complete"
                    _find_evil_jobs[job_id]["result"] = report
                    _gu._save_jobs()  # persist complete state
                _fe_logger.info("Find Evil complete", job_id=job_id,
                                findings_count=len((report or {}).get("findings", [])))
                try:
                    _queue_manager.on_job_complete(job_id, report)
                except Exception:
                    pass
            except Exception as e:
                _fe_log_with_exception(job_id, "Find Evil job failed", e)
                _fe_logger.error('Find Evil failed', job_id=job_id, error=str(e), exc_info=True)
                with _state_lock:
                    _find_evil_jobs[job_id]["status"] = "error"
                    _find_evil_jobs[job_id]["error"] = str(e)
                    _gu._save_jobs()  # persist error state
                try:
                    _queue_manager.on_job_failed(job_id, str(e))
                except Exception:
                    pass

        thread = threading.Thread(target=_run, daemon=True)
        thread.start()
        # persist initial state
        _gu._save_jobs()

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


def find_evil_status_latest():
    """
    GET /find-evil/status/
    Returns all running/initializing jobs in an active_jobs array.
    If none running, falls back to the most recently started job (backward compat).
    """
    # Auto-cancel stale jobs before processing
    _auto_cancel_stale_jobs()

    with _state_lock:
        jobs_snapshot = list(_find_evil_jobs.items())

    if not jobs_snapshot:
        return jsonify({"active_jobs": [], "count": 0})

    def _sort_key(item):
        _, job = item
        ts = job.get("started_at", "")
        try:
            return datetime.fromisoformat(ts)
        except (ValueError, TypeError):
            return datetime.min

    running = [(jid, job) for jid, job in jobs_snapshot if job.get("status") in ("running", "initializing")]
    if running:
        active_jobs = [
            {
                "job_id": jid,
                "status": job["status"],
                "progress_pct": job["progress_pct"],
                "current_playbook": job["current_playbook"],
                "current_step": job["current_step"],
                "elapsed_seconds": job["elapsed_seconds"],
                "last_heartbeat": job.get("last_heartbeat"),
                "evidence_dir": job.get("evidence_dir", "unknown"),
                "log": job.get("log", [])[-50:],
            }
            for jid, job in running
        ]
        return jsonify({"active_jobs": active_jobs, "count": len(active_jobs)})

    # No running jobs — return most recent job in old format (backward compat)
    job_id, job = max(jobs_snapshot, key=_sort_key)
    resp = {
        "job_id": job_id,
        "status": job["status"],
        "progress_pct": job["progress_pct"],
        "current_playbook": job["current_playbook"],
        "current_step": job["current_step"],
        "elapsed_seconds": job["elapsed_seconds"],
        "last_heartbeat": job.get("last_heartbeat"),
        "log": job.get("log", [])[-50:],
    }
    if job["status"] == "complete":
        result = job["result"]
        if result:
            # Strip non-serializable Future objects before returning
            _strip_futures(result)
        resp["result"] = result
    elif job["status"] in ("error", "cancelled"):
        resp["error"] = job.get("error")
    return jsonify(resp)


def find_evil_status(job_id):
    """
    GET /find-evil/status/<job_id>
    Returns current progress of a Find Evil job.
    """
    # Auto-cancel stale jobs before processing
    _auto_cancel_stale_jobs()
    
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
        "last_heartbeat": job.get("last_heartbeat"),
        "log": job.get("log", [])[-50:],  # Last 50 entries
    }

    if job["status"] == "complete":
        result = job["result"]
        if result:
            _strip_futures(result)
        resp["result"] = result
    elif job["status"] == "error":
        resp["error"] = job["error"]

    return jsonify(resp)


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
        _gu._save_jobs()  # persist cancellation

    return jsonify({
        "job_id": job_id,
        "status": "cancelled",
        "message": "Job cancelled successfully"
    })


def find_evil_active():
    """GET /find-evil/active — Return any currently running Find Evil jobs.

    The UI calls this on page load to detect and display in-progress jobs.
    """
    with _state_lock:
        active = [
            {
                "job_id": jid,
                "status": job["status"],
                "progress_pct": job["progress_pct"],
                "current_playbook": job["current_playbook"],
                "current_step": job["current_step"],
                "elapsed_seconds": job["elapsed_seconds"],
                "started_at": job.get("started_at", ""),
                "evidence_dir": job.get("evidence_dir", "unknown"),
            }
            for jid, job in _find_evil_jobs.items()
            if job.get("status") in ("running", "initializing")
        ]
    
    # Auto-cancel stale jobs before returning active jobs
    _auto_cancel_stale_jobs()
    
    return jsonify({"active_jobs": active, "count": len(active)})


def find_evil_info():
    """GET /find-evil — Return usage info and supported playbooks."""
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
            'Windows Event Logs (.evtx, .evt)',
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


def set_active_directory():
    """POST /active-directory — Set the active evidence directory for chat queries."""
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

        # Write to the module-level variable via geoff_config
        geoff_config._active_evidence_dir = directory
        return jsonify({
            'status': 'success',
            'directory': directory,
            'message': f'Active evidence directory set to: {directory}'
        })
    except Exception as e:
        return jsonify({'status': 'error', 'error': str(e)}), 500


def get_active_directory():
    """GET /active-directory — Get the current active evidence directory."""
    return jsonify({
        'active_directory': geoff_config._active_evidence_dir,
        'default_directory': EVIDENCE_BASE_DIR
    })


def report_history(case_dir):
    """GET /reports/<case_dir>/history — Return git commit history as JSON."""
    safe_dir_str = re.sub(r'[^a-zA-Z0-9_\\-]', '', case_dir)
    if not safe_dir_str:
        return jsonify({"error": "Invalid case directory name"}), 400
    case_path = Path(CASES_WORK_DIR) / safe_dir_str
    if not case_path.is_dir():
        return jsonify({"error": "Case not found"}), 404
    try:
        case_path.resolve().relative_to(Path(CASES_WORK_DIR).resolve())
    except ValueError:
        return jsonify({"error": "Invalid case directory"}), 400
    git_dir = case_path / '.git'
    if not git_dir.is_dir():
        return jsonify({"error": "No git history", "commits": [], "count": 0})
    try:
        import subprocess as _sp
        result = _sp.run(
            ['git', '--git-dir', str(git_dir), '--work-tree', str(case_path),
             'log', '--format=%H|%aI|%s', '--max-count=300'],
            capture_output=True, text=True, timeout=30
        )
        commits = []
        for line in result.stdout.strip().split('\n'):
            if not line.strip():
                continue
            parts = line.split('|', 2)
            if len(parts) < 3:
                continue
            h, ts, msg = parts[0], parts[1], parts[2]
            entry = {"hash": h[:12], "timestamp": ts, "message": msg[:200], "type": "step"}
            m = re.search(r'step:\s*([^:]+):?([^\s]+)\.([^\s]+)\s+\[([^\]]+)\]\s+ev=([^\s]+)', msg)
            if m:
                entry["playbook"] = m.group(1).strip()
                entry["module"] = m.group(2)
                entry["function"] = m.group(3)
                entry["status"] = m.group(4)
                entry["ev_name"] = m.group(5)
            else:
                entry["playbook"] = msg.split(":")[0].strip()[:50]
            commits.append(entry)
        return jsonify({"commits": commits, "count": len(commits)})
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Git log timed out"}), 504
    except Exception as e:
        import traceback as _tb
        _tb.print_exc()
        return jsonify({"error": str(e)}), 500

def _inject_section_links(text):
    """Escape text and wrap report-section mentions in anchor links."""
    import html as _html
    import re as _re
    section_patterns = [
        (r'executive summary', 'summary'),
        (r'summary section', 'summary'),
        (r'findings by device', 'findings'),
        (r'the findings', 'findings'),
        (r'attack chain', 'attack-chain'),
        (r'attack narrative', 'attack-chain'),
        (r'indicators? of compromise', 'iocs'),
        (r'IOCs?', 'iocs'),
        (r'kill[\s\-]chain', 'kill-chain-timeline'),
        (r'blast radius', 'blast-radius'),
        (r'business impact', 'blast-radius'),
        (r'MITRE ATT&CK', 'mitre'),
        (r'super.?timeline', 'timeline'),
        (r'the conclusion', 'conclusion'),
    ]
    combined = '(' + '|'.join(pat for pat, _ in section_patterns) + ')'
    tokens = _re.split(combined, text, flags=_re.IGNORECASE)
    result = []
    for i, tok in enumerate(tokens):
        if i % 2 == 1:
            sid = next(
                (sid for pat, sid in section_patterns if _re.fullmatch(pat, tok, _re.IGNORECASE)),
                None
            )
            if sid:
                result.append(f'<a href="#{sid}" class="rc-section-link">{_html.escape(tok)}</a>')
            else:
                result.append(_html.escape(tok))
        else:
            result.append(_html.escape(tok))
    return ''.join(result)


def _search_case_json(question, report_json, narrative_json=None, max_chars=3000):
    """Keyword search over case JSON data to surface evidence relevant to a question.

    Returns a formatted text block (up to max_chars) of matching findings,
    indicators, user narratives, and report sections, or empty string if nothing matches.
    """
    q_lower = question.lower()

    KEYWORD_GROUPS = {
        'email':       ['email', 'phish', 'mail', 'smtp', 'imap', 'inbox', 'spoof', 'recipient', 'sender', 'attachment', 'message'],
        'process':     ['process', 'proc', 'pid', 'executable', 'binary', 'running', 'task', 'program', 'command', 'spawn'],
        'registry':    ['registry', 'regedit', 'hklm', 'hkcu', 'run key', 'runkey', 'hive', 'reg'],
        'persistence': ['persist', 'startup', 'autorun', 'cron', 'service', 'scheduled', 'boot', 'init'],
        'network':     ['network', 'connect', 'ip address', 'dns', 'socket', 'port', 'traffic', 'remote', 'c2', 'beacon', 'lateral'],
        'browser':     ['browser', 'firefox', 'chrome', 'edge', 'web', 'url', 'download', 'history'],
        'usb':         ['usb', 'removable', 'external drive', 'media', 'mount'],
        'delete':      ['delete', 'delet', 'remov', 'recycle', 'wipe', 'shred'],
        'user':        ['user', 'account', 'login', 'logon', 'auth', 'password', 'credential', 'session'],
        'file':        ['file', 'document', 'folder', 'directory', 'inode', 'created', 'modified', 'path'],
        'exfil':       ['exfil', 'data out', 'transfer', 'upload', 'leak', 'copy'],
        'malware':     ['malware', 'virus', 'trojan', 'ransomware', 'backdoor', 'rootkit', 'exploit', 'inject'],
    }

    active_groups = {g for g, terms in KEYWORD_GROUPS.items() if any(t in q_lower for t in terms)}

    # Names mentioned in question (short stopwords filtered out)
    _stopwords = {
        'the', 'who', 'what', 'when', 'how', 'did', 'was', 'were', 'has', 'have',
        'had', 'get', 'got', 'for', 'any', 'all', 'can', 'are', 'this', 'that',
        'from', 'with', 'about', 'send', 'data', 'out', 'run', 'running', 'make',
        'made', 'find', 'found', 'show', 'tell', 'give', 'their', 'them', 'they',
        'email', 'emails', 'files', 'system', 'case', 'just', 'some', 'also',
    }
    names_in_q = {
        w.strip('?,.:!()').lower()
        for w in question.split()
        if len(w.strip('?,.:!()')) >= 3
        and w.strip('?,.:!()').isalpha()
        and w.strip('?,.:!()').lower() not in _stopwords
    }

    def _relevant(text):
        tl = str(text).lower()
        if any(any(t in tl for t in KEYWORD_GROUPS[g]) for g in active_groups):
            return True
        return any(n in tl for n in names_in_q)

    matches = []  # list of (priority, text_snippet)

    # --- findings_detail: search headline + result summary ---
    for finding in (report_json.get('findings_detail') or []):
        headline = finding.get('headline') or finding.get('summary') or ''
        if not headline or not _relevant(headline):
            continue
        detail = ''
        result = finding.get('result')
        if isinstance(result, dict):
            for key in ('summary', 'narrative', 'description', 'detail', 'output', 'raw_output'):
                val = result.get(key, '')
                if isinstance(val, str) and len(val) > 20:
                    detail = val[:400]
                    break
        snippet = headline if not detail else f"{headline}\n  Detail: {detail}"
        matches.append((2, f"[finding] {snippet}"))

    # --- pass2_findings_detail ---
    for finding in (report_json.get('pass2_findings_detail') or []):
        headline = finding.get('headline') or finding.get('summary') or ''
        if headline and _relevant(headline):
            matches.append((2, f"[pass2_finding] {headline}"))

    # --- indicator_hits ---
    for hit in (report_json.get('indicator_hits') or []):
        hit_text = json.dumps(hit)[:400]
        if _relevant(hit_text):
            matches.append((2, f"[indicator] {hit_text}"))

    # --- behavioral_flags ---
    for flag in (report_json.get('behavioral_flags') or []):
        flag_text = json.dumps(flag)[:300]
        if _relevant(flag_text):
            matches.append((2, f"[behavioral_flag] {flag_text}"))

    # --- attack_chain ---
    ac = report_json.get('attack_chain')
    if ac:
        ac_text = json.dumps(ac) if not isinstance(ac, str) else ac
        if _relevant(ac_text):
            matches.append((1, f"[attack_chain] {ac_text[:600]}"))

    # --- communications_analysis ---
    comms = report_json.get('communications_analysis')
    if comms:
        comms_text = json.dumps(comms)
        if _relevant(comms_text):
            matches.append((1, f"[communications] {comms_text[:600]}"))

    # --- connection_map ---
    conn = report_json.get('connection_map')
    if conn:
        conn_text = json.dumps(conn)
        if _relevant(conn_text):
            matches.append((1, f"[connection_map] {conn_text[:500]}"))

    # --- mitre_techniques ---
    for mt in (report_json.get('mitre_techniques') or []):
        mt_text = json.dumps(mt)
        if _relevant(mt_text):
            matches.append((2, f"[mitre] {mt_text[:300]}"))

    # --- user_activity_summary ---
    uas = report_json.get('user_activity_summary')
    if uas:
        uas_text = json.dumps(uas) if not isinstance(uas, str) else uas
        if _relevant(uas_text):
            matches.append((1, f"[user_activity] {uas_text[:500]}"))

    # --- correlated_users ---
    cu = report_json.get('correlated_users')
    if cu:
        cu_text = json.dumps(cu)
        if _relevant(cu_text):
            matches.append((1, f"[correlated_users] {cu_text[:400]}"))

    # --- narrative_report.json extra sections ---
    if narrative_json:
        # user_narratives — per-user forensic prose (very rich)
        user_narratives = narrative_json.get('user_narratives') or {}
        if isinstance(user_narratives, dict):
            for uname, utext in user_narratives.items():
                utext = str(utext)
                if _relevant(utext) or uname.lower() in names_in_q:
                    matches.append((1, f"[user_narrative:{uname}] {utext[:800]}"))
        elif isinstance(user_narratives, str) and _relevant(user_narratives):
            matches.append((1, f"[user_narratives] {user_narratives[:800]}"))

        # full_written_report — search paragraph by paragraph
        fwr = narrative_json.get('full_written_report') or ''
        if fwr:
            for para in (p.strip() for p in fwr.split('\n\n') if p.strip()):
                if len(para) > 50 and _relevant(para):
                    matches.append((3, f"[report_section] {para[:500]}"))

        # iocs
        iocs = narrative_json.get('iocs') or {}
        if iocs:
            iocs_text = json.dumps(iocs) if not isinstance(iocs, str) else iocs
            if _relevant(iocs_text):
                matches.append((1, f"[iocs] {iocs_text[:400]}"))

    if not matches:
        return ""

    matches.sort(key=lambda x: -x[0])
    parts = []
    total = 0
    for _, text in matches:
        if total + len(text) > max_chars:
            remaining = max_chars - total
            if remaining > 100:
                parts.append(text[:remaining] + "...(truncated)")
            break
        parts.append(text)
        total += len(text)

    return '\n\n'.join(parts)


def report_chat(case_dir):
    """Answer questions about the investigation report using conversational RAG."""
    data = request.get_json(force=True)
    question = (data.get('question') or '').strip()
    history = data.get('history') or []

    if not question:
        return jsonify({'answer': 'No question provided.'}), 400

    safe_dir = re.sub(r'[^a-zA-Z0-9_\-]', '', case_dir)

    # --- Load find_evil_report.json (searchable case data) ---
    report_json = data.get('report_json') or {}
    if not report_json and safe_dir:
        case_path = Path(CASES_WORK_DIR) / safe_dir
        if case_path.is_dir():
            try:
                case_path.resolve().relative_to(Path(CASES_WORK_DIR).resolve())
                report_file = case_path / "reports" / "find_evil_report.json"
                if report_file.exists():
                    report_json = json.loads(report_file.read_text(encoding='utf-8'))
            except (ValueError, OSError, json.JSONDecodeError):
                pass

    # --- Load narrative_report.json (primary conversational anchor) ---
    narrative_json = {}
    narrative_text = ""
    if safe_dir:
        case_path = Path(CASES_WORK_DIR) / safe_dir
        if case_path.is_dir():
            nr_path = case_path / "reports" / "narrative_report.json"
            if nr_path.exists():
                try:
                    narrative_json = json.loads(nr_path.read_text(encoding='utf-8', errors='replace'))
                    parts = []
                    for section in ('email_phishing', 'devices_and_users', 'executive_summary',
                                    'findings', 'attack_chain', 'conclusion'):
                        val = narrative_json.get(section, '')
                        if val:
                            parts.append(val if isinstance(val, str) else json.dumps(val)[:2000])
                    narrative_text = '\n\n'.join(parts)[:8000]
                except (ValueError, OSError, json.JSONDecodeError):
                    pass
            if not narrative_text:
                nr_md = case_path / "reports" / "narrative_report.md"
                if nr_md.exists():
                    try:
                        narrative_text = nr_md.read_text(encoding='utf-8', errors='replace')[:8000]
                    except OSError:
                        pass

    # --- Pass 2: targeted keyword search over case JSON ---
    search_results = _search_case_json(
        question, report_json,
        narrative_json=narrative_json if narrative_json else None,
        max_chars=3000
    )

    # --- Quick facts block (always included) ---
    quick_facts = []
    quick_facts.append(f"Case: {report_json.get('title', 'Unknown')}")
    quick_facts.append(f"Classification: {report_json.get('classification', 'Unknown')}")
    quick_facts.append(f"Severity: {report_json.get('severity', 'Unknown')}")
    quick_facts.append(f"OS: {report_json.get('os_type', 'Unknown')}")
    for dev_id, dev in (report_json.get('device_map') or {}).items():
        owner = dev.get('owner') or 'unknown'
        hostname = dev.get('hostname') or 'unknown'
        dev_type = dev.get('device_type') or 'unknown'
        quick_facts.append(f"Device '{dev_id}': owner={owner}, hostname={hostname}, type={dev_type}")
    for user_id, user_info in (report_json.get('user_map') or {}).items():
        quick_facts.append(f"User: {user_id} -> {json.dumps(user_info)[:120]}")
    for f in (report_json.get('findings_detail') or [])[:10]:
        h = f.get('headline') or f.get('summary') or ''
        if h:
            quick_facts.append(f"Finding: {h[:120]}")
    facts_block = '\n'.join(quick_facts[:25])

    # --- Assemble two-pass context ---
    narrative_block = f"NARRATIVE REPORT (primary source):\n{narrative_text}\n\n" if narrative_text else ""
    search_block = f"SEARCH RESULTS (targeted evidence for this question):\n{search_results}\n\n" if search_results else ""
    fallback_block = f"FULL REPORT DATA:\n{json.dumps(report_json, indent=2)[:5000]}\n\n" if not narrative_text else ""
    case_context = f"{narrative_block}{search_block}{fallback_block}CASE FACTS:\n{facts_block}"

    # --- System prompt ---
    chat_system_prompt = (
        "You are Geoff, a forensic analyst answering questions about an investigation. "
        "Answer in plain conversational English. One paragraph. No bullet points, no markdown, no headers.\n\n"
        "CONTEXT HIERARCHY:\n"
        "1. NARRATIVE REPORT is the primary source — comprehensive analysis written after investigation.\n"
        "2. SEARCH RESULTS contain targeted evidence retrieved specifically for this question — "
        "if SEARCH RESULTS contradict or extend the NARRATIVE, trust the SEARCH RESULTS.\n"
        "3. CASE FACTS are ground-truth metadata (device owners, classifications, user list).\n\n"
        "RULES:\n"
        "- For phishing/email questions: check SEARCH RESULTS for email details and named recipients. "
        "The 'To' fields in flagged emails tell you exactly who received them. Name them.\n"
        "- For 'who' questions: name the specific person from device owners, user map, or email To/From fields.\n"
        "- For 'what processes/files/activity' questions: look in SEARCH RESULTS findings_detail sections.\n"
        "- If data is genuinely absent from all sources, say what IS known and name what playbook could find more.\n"
        "- Never say 'no evidence' if SEARCH RESULTS show any relevant hits — cite what you found.\n"
        "- Never hedge with 'it appears' or 'it seems' when the data directly says something.\n"
    )

    # --- Build conversation history ---
    history_lines = []
    for turn in (history or [])[-6:]:
        role = (turn.get('role') or '').strip()
        content = (turn.get('content') or '').strip()[:400]
        if role == 'user':
            history_lines.append(f"Analyst: {content}")
        elif role == 'assistant':
            history_lines.append(f"Geoff: {content}")
    user_prompt = ('\n'.join(history_lines) + f"\nAnalyst: {question}") if history_lines else question

    # --- Call LLM ---
    try:
        answer = call_llm(user_prompt, case_context, agent_type="manager", system_prompt=chat_system_prompt)
        if not answer:
            raise ValueError("empty response")
    except Exception:
        answer = _fallback_answer(question, report_json)

    # --- Playbook suggestions ---
    suggest_playbook = None
    q_lower = question.lower()
    a_lower = answer.lower()
    _playbook_hints = [
        ('PB-SIFT-005', ['shell history', 'bash history', 'shell command', 'terminal']),
        ('PB-SIFT-004', ['browser', 'firefox', 'chrome', 'web history', 'download']),
        ('PB-SIFT-006', ['network', 'connection', 'socket', 'ip address', 'dns']),
        ('PB-SIFT-007', ['persistence', 'cron', 'startup', 'autorun', 'service']),
        ('PB-SIFT-008', ['user account', 'login', 'auth', 'passwd', 'sudo']),
        ('PB-SIFT-010', ['filesystem', 'deleted file', 'inode', 'mtime']),
        ('PB-SIFT-012', ['memory', 'process', 'malware', 'inject', 'dump']),
        ('PB-SIFT-015', ['syslog', 'wtmp', 'utmp', 'auth.log', 'event log']),
        ('PB-SIFT-005', ['shell', 'bash', 'command']),
        ('PB-SIFT-004', ['browser', 'web', 'history', 'download']),
        ('PB-SIFT-008', ['user', 'account', 'log']),
    ]
    for pb_id, keywords in _playbook_hints:
        if any(kw in q_lower for kw in keywords):
            suggest_playbook = pb_id
            break
    # Also suggest a playbook when the answer says data is missing/not collected
    if not suggest_playbook:
        _missing_signals = ['not collected', 'not available', 'no data', 'not run', 'playbook', 'would require', 'deeper analysis']
        if any(sig in a_lower for sig in _missing_signals):
            for pb_id, keywords in _playbook_hints:
                if any(kw in a_lower for kw in keywords):
                    suggest_playbook = pb_id
                    break

    result = {'answer': answer, 'answer_html': _inject_section_links(answer)}
    if suggest_playbook:
        result['suggest_playbook'] = suggest_playbook
    return jsonify(result)


def get_execution_log(case_id):
    """GET /reports/execution/<case_id> — Structured execution log for a completed case."""
    safe_id = re.sub(r'[^a-zA-Z0-9_\-]', '_', case_id)
    if not safe_id:
        return jsonify({'error': 'Invalid case ID'}), 400

    case_path = _find_case_dir(safe_id)
    if not case_path:
        return jsonify({'error': 'Case not found'}), 404

    # Browser requests get HTML; API requests get JSON
    accept_html = 'text/html' in (request.headers.get('Accept') or '')

    def _read_jsonl(path, limit=5000):
        records = []
        try:
            with open(path, 'r', encoding='utf-8', errors='replace') as f:
                for i, line in enumerate(f):
                    if i >= limit:
                        break
                    line = line.strip()
                    if line:
                        try:
                            records.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass
        except OSError:
            pass
        return records

    def _read_json_file(path):
        try:
            return json.loads(Path(path).read_text(encoding='utf-8'))
        except (OSError, json.JSONDecodeError):
            return None

    result = {
        'agent_trace': None,
        'audit_trail': None,
        'findings': None,
        'critic_assessment': None,
        'manager_decision': None,
        'custody': None,
        'narrative': None,
        'metadata': {},
    }

    for key, fname in [('agent_trace', 'agent_trace.jsonl'),
                       ('audit_trail', 'audit_trail.jsonl'),
                       ('findings', 'findings.jsonl')]:
        p = case_path / fname
        if p.exists():
            result[key] = _read_jsonl(p)

    for key, fname in [('critic_assessment', 'batch_critic_assessment.json'),
                       ('manager_decision', 'manager_decision.json')]:
        p = case_path / fname
        if p.exists():
            result[key] = _read_json_file(p)

    custody_dir = case_path / 'custody'
    if custody_dir.exists() and custody_dir.is_dir():
        records = []
        for f in sorted(custody_dir.glob('*.json'))[:500]:
            rec = _read_json_file(f)
            if rec is not None:
                rec['_filename'] = f.name
                records.append(rec)
        if records:
            result['custody'] = records

    narrative_p = case_path / 'reports' / 'narrative_report.md'
    if narrative_p.exists():
        try:
            if narrative_p.stat().st_size <= 10 * 1024 * 1024:
                result['narrative'] = narrative_p.read_text(encoding='utf-8')
        except OSError:
            pass

    # Load additional judge-relevant artifacts
    for key, fname in [
        ('execution_plan', 'execution_plan.json'),
        ('dual_critic_assessment', 'dual_critic_assessment.json'),
        ('confidence_calibration', 'confidence_calibration.json'),
        ('timeline_intelligence', 'timeline_intelligence.json'),
    ]:
        p = case_path / fname
        if p.exists():
            result[key] = _read_json_file(p)

    metadata = {'case_id': safe_id, 'case_dir': str(case_path)}
    report_p = case_path / 'reports' / 'find_evil_report.json'
    if report_p.exists():
        rd = _read_json_file(report_p)
        if rd and isinstance(rd, dict):
            for k in ('elapsed_seconds', 'evidence_dir', 'evil_found',
                      'verdict', 'severity', 'classification'):
                if k in rd:
                    metadata[k] = rd[k]
            inv = rd.get('inventory', {})
            if isinstance(inv, dict):
                metadata['total_evidence_items'] = sum(
                    len(v) if isinstance(v, list) else int(v or 0)
                    for v in inv.values()
                )
    result['metadata'] = metadata

    # Load per-command execution records from commands/ directory
    commands_dir = case_path / 'commands'
    if commands_dir.exists() and commands_dir.is_dir():
        cmd_records = []
        for cf in sorted(commands_dir.glob('*.json')):
            rec = _read_json_file(cf)
            if rec:
                rec['_filename'] = cf.name
                cmd_records.append(rec)
        if cmd_records:
            result['commands'] = cmd_records

    # Load git log for full reproducibility trail
    git_log = []
    git_dir = case_path / '.git'
    if git_dir.exists():
        try:
            out = subprocess.run(
                ['git', '-C', str(case_path), 'log', '--oneline', '--all', '-500'],
                capture_output=True, text=True, timeout=10
            )
            for line in out.stdout.strip().splitlines():
                line = line.strip()
                if line:
                    git_log.append(line)
        except Exception:
            pass
    if git_log:
        result['git_log'] = git_log

    # Load provenance DAG for evidence derivation chain
    prov_path = case_path / 'provenance_dag.json'
    if prov_path.exists():
        prov_data = _read_json_file(prov_path)
        if prov_data:
            result['provenance_dag'] = prov_data

    if accept_html:
        # Render as HTML for browser viewing
        return _render_execution_log_html(result, safe_id)
    return json.dumps(result, indent=2, default=str), 200, {
        'Content-Type': 'application/json; charset=utf-8'
    }


def _render_git_log(git_log):
    """Format git log lines with color-coded hashes and messages."""
    if not git_log:
        return '<p style="padding:24px;color:#64748b;font-family:monospace">No git history found for this case.</p>'
    lines = []
    for line in git_log:
        parts = line.split(' ', 1)
        hash_str = _html_escape(parts[0]) if parts else ''
        msg_str = _html_escape(parts[1]) if len(parts) > 1 else ''
        lines.append(f'<div style="padding:3px 0"><span style="color:#f59e0b;font-family:monospace;font-size:12px">{hash_str}</span> <span style="color:#cbd5e1;font-family:monospace;font-size:12px">{msg_str}</span></div>')
    return '\n'.join(lines)


def _render_provenance_dag(prov_dag):
    """Render provenance DAG with severity filtering and analyst-readable summaries."""
    nodes = prov_dag.get('nodes', {})
    edges = prov_dag.get('edges', [])
    if not nodes and not edges:
        return '<div style="padding:24px;color:#64748b;font-family:monospace">No provenance DAG found for this case.</div>'

    to_ids = {e.get('to') for e in edges}
    source_count = sum(1 for nid in nodes if nid not in to_ids)
    finding_count = len([nid for nid in nodes if nid in to_ids])

    sev_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'OTHER': 0}
    for edge in edges:
        sig = (nodes.get(edge.get('to', ''), {}).get('metadata') or {}).get('significance', '') or ''
        if sig in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'):
            sev_counts[sig] += 1
        else:
            sev_counts['OTHER'] += 1

    critical_high = sev_counts['CRITICAL'] + sev_counts['HIGH']
    badge_color = '#f87171' if sev_counts['CRITICAL'] > 0 else ('#fbbf24' if sev_counts['HIGH'] > 0 else '#34d399')

    html = f'''<div style="padding:16px 24px;background:rgba(76,141,255,.04);border-bottom:1px solid rgba(71,85,105,.15)">
  <p style="font-size:14px;color:#cbd5e1;margin-bottom:10px"><b>Evidence Provenance DAG</b></p>
  <div style="display:flex;gap:20px;align-items:center;flex-wrap:wrap;font-family:monospace;font-size:12px">
    <span style="color:#94a3b8">{source_count} sources → {finding_count} findings across {len(edges)} steps</span>
    <span style="color:{badge_color};font-weight:600">{critical_high} CRITICAL/HIGH</span>
    <span style="color:#f59e0b">{sev_counts["MEDIUM"]} MEDIUM</span>
    <span style="color:#34d399">{sev_counts["LOW"]} LOW</span>
  </div>
</div>
<div style="padding:10px 24px;border-bottom:1px solid rgba(71,85,105,.1);display:flex;gap:8px;align-items:center;font-family:monospace">
  <span style="font-size:11px;color:#64748b">Filter:</span>
  <button onclick="dagFilter('ALL')" id="dagf-ALL" style="padding:3px 10px;font-size:11px;font-family:monospace;background:#1e293b;border:1px solid #475569;color:#94a3b8;cursor:pointer;border-radius:3px;outline:2px solid #60a5fa">ALL</button>
  <button onclick="dagFilter('CRITICAL')" id="dagf-CRITICAL" style="padding:3px 10px;font-size:11px;font-family:monospace;background:#1e293b;border:1px solid #7f1d1d;color:#f87171;cursor:pointer;border-radius:3px">CRITICAL</button>
  <button onclick="dagFilter('HIGH')" id="dagf-HIGH" style="padding:3px 10px;font-size:11px;font-family:monospace;background:#1e293b;border:1px solid #78350f;color:#fbbf24;cursor:pointer;border-radius:3px">HIGH</button>
  <button onclick="dagFilter('MEDIUM')" id="dagf-MEDIUM" style="padding:3px 10px;font-size:11px;font-family:monospace;background:#1e293b;border:1px solid #713f12;color:#f59e0b;cursor:pointer;border-radius:3px">MEDIUM</button>
  <button onclick="dagFilter('LOW')" id="dagf-LOW" style="padding:3px 10px;font-size:11px;font-family:monospace;background:#1e293b;border:1px solid #14532d;color:#34d399;cursor:pointer;border-radius:3px">LOW</button>
</div>
<script>
function dagFilter(sev) {{
  document.querySelectorAll('tr.dag-row').forEach(function(r) {{
    r.style.display = (sev === 'ALL' || r.dataset.sev === sev) ? '' : 'none';
  }});
  document.querySelectorAll('[id^="dagf-"]').forEach(function(b) {{
    b.style.outline = b.id === 'dagf-' + sev ? '2px solid #60a5fa' : 'none';
  }});
}}
</script>'''

    _SEV_COLOR = {'CRITICAL': '#f87171', 'HIGH': '#fbbf24', 'MEDIUM': '#f59e0b',
                  'LOW': '#34d399', 'NONE': '#475569', 'UNKNOWN': '#64748b', '': '#64748b'}
    rows = []
    for i, edge in enumerate(edges):
        from_id = edge.get('from', '?')
        to_id = edge.get('to', '?')
        rel = edge.get('relationship', '?')
        pb = edge.get('playbook', '')
        node_meta = (nodes.get(to_id, {}).get('metadata') or {})
        sig = node_meta.get('significance') or ''
        analyst_note = node_meta.get('analyst_note') or ''
        threat_iocs = node_meta.get('threat_indicators') or []
        sev_color = _SEV_COLOR.get(sig, '#64748b')

        finding_parts = []
        if analyst_note:
            finding_parts.append(f'<span style="color:#e2e8f0">{_html_escape(analyst_note[:140])}</span>')
        if threat_iocs:
            ioc_text = ', '.join(str(x) for x in threat_iocs[:3])
            finding_parts.append(f'<br><span style="color:#fb923c;font-size:10px">[{_html_escape(ioc_text[:100])}]</span>')
        if not finding_parts:
            finding_parts.append(f'<span style="color:#475569">{_html_escape(rel)}</span>')

        analyst_summary = node_meta.get('analyst_summary') or ''
        tool_desc = node_meta.get('tool_description') or ''
        ev_path = node_meta.get('evidence_path') or ''
        ts = node_meta.get('timestamp') or ''
        finding_count = node_meta.get('finding_count') or ''

        summary_parts = []
        if analyst_summary:
            summary_parts.append(f'<span style="color:#e2e8f0;display:block">{_html_escape(analyst_summary[:200])}</span>')
        elif analyst_note:
            summary_parts.append(f'<span style="color:#e2e8f0;display:block">{_html_escape(analyst_note[:200])}</span>')
        if tool_desc:
            summary_parts.append(f'<span style="color:#94a3b8;font-size:10px;display:block">{_html_escape(tool_desc[:120])}</span>')
        if threat_iocs:
            ioc_text = ', '.join(str(x) for x in threat_iocs[:3])
            summary_parts.append(f'<span style="color:#fb923c;font-size:10px;display:block">[IOC: {_html_escape(ioc_text[:100])}]</span>')
        if not summary_parts:
            summary_parts.append(f'<span style="color:#475569">{_html_escape(rel)}</span>')

        from_short = _html_escape((from_id.split('/')[-1] or from_id)[:55])
        ev_short = _html_escape(ev_path[:50]) if ev_path else from_short
        ts_short = _html_escape(str(ts)[:19]) if ts else ''
        rows.append(
            f'<tr class="dag-row" data-sev="{_html_escape(sig or "UNKNOWN")}" style="border-left:3px solid {sev_color}">' +
            f'<td style="color:#475569;width:36px;text-align:right;padding-right:10px">{i+1}</td>' +
            f'<td style="color:{sev_color};font-weight:600;width:76px;white-space:nowrap">{_html_escape(sig or "—")}</td>' +
            f'<td style="color:#60a5fa;max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:11px" title="{_html_escape(from_id)}">{ev_short}</td>' +
            f'<td style="color:#34d399;width:16px;text-align:center">→</td>' +
            f'<td style="color:#818cf8;max-width:130px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:11px" title="{_html_escape(to_id)}">{_html_escape(rel)}</td>' +
            f'<td style="max-width:320px">{"".join(summary_parts)}</td>' +
            f'<td style="color:#64748b;font-size:11px;white-space:nowrap">{_html_escape(pb)}</td>' +
            f'<td style="color:#94a3b8;font-size:10px;white-space:nowrap;max-width:130px;overflow:hidden;text-overflow:ellipsis" title="{_html_escape(str(ts))}">{ts_short}</td>' +
            f'<td style="color:#475569;font-size:10px;text-align:center;width:32px">{_html_escape(str(finding_count)) if finding_count else "—"}</td>' +
            f'</tr>'
        )

    html += f'''<table style="width:100%;border-collapse:collapse;font-family:monospace;font-size:12px">
<thead><tr style="position:sticky;top:52px;background:#0f172a">
  <th style="padding:10px 14px;text-align:right;font-weight:600;color:#94a3b8;border-bottom:2px solid rgba(71,85,105,.3);text-transform:uppercase;font-size:10px;width:36px">#</th>
  <th style="padding:10px 14px;text-align:left;font-weight:600;color:#94a3b8;border-bottom:2px solid rgba(71,85,105,.3);text-transform:uppercase;font-size:10px;width:76px">Severity</th>
  <th style="padding:10px 14px;text-align:left;font-weight:600;color:#94a3b8;border-bottom:2px solid rgba(71,85,105,.3);text-transform:uppercase;font-size:10px">Evidence</th>
  <th style="padding:10px 14px;border-bottom:2px solid rgba(71,85,105,.3);width:16px"></th>
  <th style="padding:10px 14px;text-align:left;font-weight:600;color:#94a3b8;border-bottom:2px solid rgba(71,85,105,.3);text-transform:uppercase;font-size:10px">Tool</th>
  <th style="padding:10px 14px;text-align:left;font-weight:600;color:#94a3b8;border-bottom:2px solid rgba(71,85,105,.3);text-transform:uppercase;font-size:10px">Analyst Summary</th>
  <th style="padding:10px 14px;text-align:left;font-weight:600;color:#94a3b8;border-bottom:2px solid rgba(71,85,105,.3);text-transform:uppercase;font-size:10px">Playbook</th>
  <th style="padding:10px 14px;text-align:left;font-weight:600;color:#94a3b8;border-bottom:2px solid rgba(71,85,105,.3);text-transform:uppercase;font-size:10px">Timestamp</th>
  <th style="padding:10px 14px;text-align:center;font-weight:600;color:#94a3b8;border-bottom:2px solid rgba(71,85,105,.3);text-transform:uppercase;font-size:10px;width:32px">N</th>
</tr></thead>
<tbody>{chr(10).join(rows)}</tbody>
</table>'''
    return html


def _render_critic_assessment(result):
    """Render critic assessment — handle missing or malformed data gracefully."""
    dual = result.get('dual_critic_assessment')
    critic = result.get('critic_assessment')
    data = dual or critic
    if not data:
        return '<div style="padding:24px;color:#64748b;font-family:monospace">No critic assessment available for this case.</div>'
    if isinstance(data, str) and 'undefined' in data.lower():
        return '<div style="padding:24px;color:#64748b;font-family:monospace">Critic assessment not yet generated for this case. Re-run the investigation with critic enabled.</div>'
    if isinstance(data, dict):
        approved = data.get('approved', data.get('critic_approved', '—'))
        rejected = data.get('rejected', data.get('critic_rejected', '—'))
        total = data.get('total', data.get('steps_reviewed', '—'))
        html = f'<div style="padding:20px 24px;background:rgba(76,141,255,.04);border-bottom:1px solid rgba(71,85,105,.15)">'
        html += f'<p style="font-size:14px;color:#cbd5e1;margin-bottom:8px"><b>Critic Assessment Summary</b></p>'
        html += f'<p style="font-size:12px;color:#94a3b8">Steps reviewed: {total} &nbsp;|&nbsp; <span style="color:#34d399">Approved: {approved}</span> &nbsp;|&nbsp; <span style="color:#f87171">Rejected: {rejected}</span></p>'
        if total and isinstance(total, (int, float)) and total > 0:
            pct = round(approved / total * 100, 1) if approved else 0
            html += f'<p style="font-size:12px;color:#94a3b8;margin-top:4px">Approval rate: <b style="color:{("#34d399" if pct >= 80 else "#fbbf24" if pct >= 50 else "#f87171")}">{pct}%</b></p>'
        html += '</div>'
        html += f'<pre style="font-family:monospace;font-size:12px;padding:16px 24px;line-height:1.6;color:#94a3b8">{_html_escape(json.dumps(data, indent=2)[:15000])}</pre>'
        return html
    return f'<pre style="font-family:monospace;font-size:12px;padding:16px 24px;line-height:1.6;color:#94a3b8">{_html_escape(json.dumps(data, indent=2)[:15000])}</pre>'


def _render_execution_log_html(result, safe_id):
    """Render execution log as a styled HTML page."""
    meta = result.get('metadata', {})
    title = meta.get('case_id', safe_id)
    audit = result.get('audit_trail') or []

    # Build audit rows — filter to significant events only
    _significant_events = {'case_init', 'playbook_start', 'playbook_complete', 'Find Evil complete',
                          'git_commit', 'extraction_start', 'error', 'fail', 'case_finalized',
                          'finding_requires_review', 'find_evil_complete', 'anti_forensics_detected',
                          'unverified', 'self_correction'}
    rows = []
    for i, entry in enumerate(audit):
        time = entry.get('ts') or entry.get('time') or entry.get('timestamp', '')
        event = entry.get('event') or ''
        msg = event or entry.get('msg') or entry.get('message', '') or str(entry)[:200]
        pb = entry.get('playbook_id') or entry.get('playbook') or ''
        sev = entry.get('severity') or ''
        if isinstance(sev, dict):
            sev = sev.get('level', sev.get('severity', ''))
        # Filter: skip routine noise
        if event and event not in _significant_events and 'playbook' not in event.lower() and 'error' not in str(msg).lower():
            continue
        # Build enriched detail cell based on event type
        detail_parts = [_html_escape(str(msg))]
        if event == 'playbook_complete':
            finding_count = entry.get('finding_count', '')
            unverified = entry.get('steps_unverified', '')
            failed = entry.get('steps_failed', '')
            hallucinations = entry.get('hallucination_count', 0)
            review_count = entry.get('requires_review_count', 0)
            critic_summary = entry.get('critic_verdict_summary') or {}
            detail_parts = [f'<b>playbook_complete</b> {_html_escape(str(pb))}']
            if finding_count:
                detail_parts.append(f'<span style="color:#34d399">{finding_count} findings</span>')
            if unverified:
                detail_parts.append(f'<span style="color:#fbbf24">{unverified} unverified</span>')
            if failed:
                detail_parts.append(f'<span style="color:#f87171">{failed} failed</span>')
            if review_count:
                detail_parts.append(f'<span style="color:#f87171">{review_count} need review</span>')
            if hallucinations:
                detail_parts.append(f'<span style="color:#fb923c">{hallucinations} hallucinations</span>')
            if critic_summary:
                cs_text = ' | '.join(f'{k}:{v}' for k, v in critic_summary.items())
                detail_parts.append(f'<span style="color:#64748b;font-size:10px">[critic: {_html_escape(cs_text[:100])}]</span>')
        elif event == 'case_init':
            ev_count = entry.get('evidence_count', '')
            ev_types = entry.get('evidence_types') or []
            ev_size = entry.get('total_size_bytes', '')
            detail_parts = ['<b>case_init</b> — evidence dir: ' + _html_escape(str(entry.get('evidence_dir','')))]
            if ev_count:
                detail_parts.append(f'<span style="color:#60a5fa">{ev_count} files</span>')
            if ev_types:
                detail_parts.append(f'<span style="color:#94a3b8">{_html_escape(", ".join(ev_types[:5]))}</span>')
            if ev_size:
                mb = round(int(ev_size) / 1048576, 1) if isinstance(ev_size, (int, float)) else ev_size
                detail_parts.append(f'<span style="color:#64748b">{mb} MB</span>')
        elif event == 'finding_requires_review':
            verdict = entry.get('verdict', '')
            reason = entry.get('verdict_reason', '')
            module = entry.get('module', '')
            func = entry.get('function', '')
            halls = entry.get('hallucinations') or []
            detail_parts = ['<b style="color:#f87171">REVIEW REQUIRED</b> — ' + _html_escape(module) + '.' + _html_escape(func)]
            if verdict:
                detail_parts.append(f'<span style="color:#fbbf24">[{_html_escape(verdict)}]</span>')
            if reason:
                detail_parts.append(f'<span style="color:#94a3b8">{_html_escape(str(reason)[:150])}</span>')
            if halls:
                detail_parts.append(f'<span style="color:#fb923c">hallucinations: {_html_escape(str(halls)[:100])}</span>')
        elif event == 'unverified':
            module = entry.get('module', '')
            func = entry.get('function', '')
            reason = entry.get('reason') or []
            detail_parts = ['<b style="color:#fbbf24">unverified</b> — ' + _html_escape(module) + '.' + _html_escape(func)]
            if reason:
                detail_parts.append(f'<span style="color:#94a3b8">{_html_escape(str(reason)[:150])}</span>')
        rows.append(f'<tr><td class="n">{i+1}</td><td class="t">{_html_escape(str(time)[:19])}</td><td class="p">{_html_escape(str(pb)[:40])}</td><td class="s {_html_escape(str(sev))}">{_html_escape(str(sev))}</td><td style="font-size:11px;line-height:1.6">{" &nbsp;|&nbsp; ".join(detail_parts)}</td></tr>')

    row_html = '\n'.join(rows) if rows else '<tr><td colspan="5" style="color:var(--g-text-mute);padding:40px;text-align:center;">No audit entries found for this case.</td></tr>'

    # Build command execution rows
    commands = result.get('commands') or []
    cmd_rows = []
    for i, cmd in enumerate(commands):
        argv = cmd.get('argv') or []
        cmd_str = ' '.join(str(a) for a in argv) if argv else str(cmd.get('command', ''))
        exit_code = cmd.get('exit_code') or cmd.get('returncode', '—')
        duration = cmd.get('duration') or cmd.get('elapsed', '')
        step = cmd.get('step') or cmd.get('step_key', '')
        if isinstance(duration, (int, float)):
            duration = f'{duration:.1f}s'
        cmd_rows.append(f'<tr><td class="n">{i+1}</td><td class="s">{_html_escape(str(exit_code))}</td><td class="p">{_html_escape(str(step))}</td><td class="t">{_html_escape(str(duration))}</td><td style="font-size:11px;word-break:break-all;">{_html_escape(str(cmd_str))}</td></tr>')

    cmd_html = '\n'.join(cmd_rows) if cmd_rows else '<tr><td colspan="5" style="color:var(--g-text-mute);padding:40px;text-align:center;">No command records found for this case.</td></tr>'

    # Build provenance DAG rows
    prov_dag = result.get('provenance_dag') or {}
    prov_nodes = prov_dag.get('nodes', {})
    prov_edges = prov_dag.get('edges', [])
    prov_rows = []
    for i, edge in enumerate(prov_edges):
        from_id = edge.get('from', '?')[:40]
        to_id = edge.get('to', '?')[:40]
        rel = edge.get('relationship', '?')
        sp = edge.get('specialist', '')
        pb = edge.get('playbook', '')
        prov_rows.append(f'<tr><td class="n">{i+1}</td><td class="p">{_html_escape(from_id)}</td><td style="color:#34d399;">→</td><td class="p">{_html_escape(to_id)}</td><td>{_html_escape(rel)}</td><td class="t">{_html_escape(sp)}</td><td class="t">{_html_escape(pb)}</td></tr>')

    prov_html = '\n'.join(prov_rows) if prov_rows else '<tr><td colspan="7" style="color:var(--g-text-mute);padding:40px;text-align:center;">No provenance DAG found for this case.</td></tr>'

    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Geoff — Execution Log — {_html_escape(title)}</title>
<link rel="stylesheet" href="/static/tokens.css">
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: #0a0f1a; color: #cbd5e1; font-family: ui-sans-serif, system-ui, sans-serif; }}
  .bar {{ position: sticky; top: 0; z-index: 10; display: flex; align-items: center; gap: 16px;
    padding: 12px 24px; background: rgba(8,13,24,.92); border-bottom: 1px solid rgba(71,85,105,.2);
    backdrop-filter: blur(8px); }}
  .bar a {{ color: #60a5fa; text-decoration: none; font-family: monospace; font-size: 13px; }}
  .bar h1 {{ font-size: 16px; font-weight: 600; }}
  .meta {{ display: flex; gap: 24px; padding: 16px 24px; font-family: monospace; font-size: 12px;
    color: #64748b; border-bottom: 1px solid rgba(71,85,105,.15); }}
  table {{ width: 100%; border-collapse: collapse; font-family: monospace; font-size: 12px; }}
  th {{ position: sticky; top: 52px; z-index: 5; background: #0f172a; padding: 10px 14px;
    text-align: left; font-weight: 600; color: #94a3b8; border-bottom: 2px solid rgba(71,85,105,.3);
    text-transform: uppercase; font-size: 10px; letter-spacing: .8px; }}
  td {{ padding: 8px 14px; border-bottom: 1px solid rgba(71,85,105,.1); vertical-align: top; }}
  tr:hover td {{ background: rgba(76,141,255,.04); }}
  td.n {{ color: #475569; width: 40px; text-align: right; padding-right: 10px; }}
  td.t {{ color: #94a3b8; white-space: nowrap; width: 90px; }}
  td.p {{ color: #60a5fa; white-space: nowrap; max-width: 140px; overflow: hidden; text-overflow: ellipsis; }}
  td.s {{ font-weight: 600; width: 70px; }}
  td.s.CRITICAL {{ color: #f87171; }}
  td.s.HIGH {{ color: #fbbf24; }}
  td.s.MEDIUM {{ color: #f59e0b; }}
  td.s.LOW {{ color: #34d399; }}
  .empty {{ padding: 40px; text-align: center; color: #475569; }}
  .tab-bar {{ display: flex; gap: 0; padding: 0 24px; border-bottom: 2px solid rgba(71,85,105,.2); }}
  .tab-btn {{ padding: 10px 18px; background: none; border: none; border-bottom: 2px solid transparent;
    margin-bottom: -2px; color: #64748b; font-family: monospace; font-size: 12px; cursor: pointer;
    transition: all .15s; }}
  .tab-btn:hover {{ color: #94a3b8; }}
  .tab-btn.active {{ color: #60a5fa; border-bottom-color: #60a5fa; }}
  .tab-panel {{ display: none; }}
  .tab-panel.active {{ display: block; }}
  .git-log {{ font-family: monospace; font-size: 12px; padding: 16px 24px; line-height: 1.8; color: #94a3b8; }}
  .git-log .hash {{ color: #f59e0b; }}
  .git-log .msg {{ color: #cbd5e1; }}
  th.gh {{ top: 106px; }}
</style>
<script>
function switchTab(name) {{ document.querySelectorAll('.tab-btn').forEach(b => b.classList.toggle('active', b.dataset.tab===name)); document.querySelectorAll('.tab-panel').forEach(p => p.classList.toggle('active', p.id===name)); }}
</script>
</head>
<body>
<div class="bar">
  <a href="/">← Geoff</a>
  <h1>Execution Log — {_html_escape(title)}</h1>
  <span style="flex:1;"></span>
  <span style="font-family:monospace;font-size:11px;color:#475569;">{len(audit)} events · {len(commands)} commands · {len(result.get('git_log') or [])} commits</span>
</div>
<div class="meta">
  <span>Classification: <b>{_html_escape(str(meta.get('classification', '—')))}</b></span>
  <span>Severity: <b>{_html_escape(str(meta.get('severity', '—')))}</b></span>
  <span>Elapsed: <b>{meta.get('elapsed_seconds', '—')}s</b></span>
  <span>Evidence: <b>{_html_escape(str(meta.get('evidence_dir', '—')))}</b></span>
</div>
<div class="tab-bar">
  <button class="tab-btn active" data-tab="tab-git" onclick="switchTab('tab-git')">Git Log ({len(result.get('git_log') or [])})</button>
  <button class="tab-btn" data-tab="tab-audit" onclick="switchTab('tab-audit')">Audit Trail</button>
  <button class="tab-btn" data-tab="tab-commands" onclick="switchTab('tab-commands')">Commands ({len(commands)})</button>
  <button class="tab-btn" data-tab="tab-prov" onclick="switchTab('tab-prov')">Provenance DAG</button>
  <button class="tab-btn" data-tab="tab-plan" onclick="switchTab('tab-plan')">Execution Plan</button>
  <button class="tab-btn" data-tab="tab-critic" onclick="switchTab('tab-critic')">Critic Assessment</button>
</div>

<div class="tab-panel" id="tab-audit">
<table>
<thead><tr><th>#</th><th>Time</th><th>Event</th><th>Severity</th><th>Detail</th></tr></thead>
<tbody>{row_html}</tbody>
</table>
</div>

<div class="tab-panel active" id="tab-git">
<div class="git-log">
{_render_git_log(result.get('git_log'))}
</div>
</div>

<div class="tab-panel" id="tab-commands">
<table>
<thead><tr class="gh"><th>#</th><th>Exit</th><th>Step</th><th>Duration</th><th>Command</th></tr></thead>
<tbody>{cmd_html}</tbody>
</table>
</div>

<div class="tab-panel" id="tab-prov">
{_render_provenance_dag(prov_dag)}
</div>

<div class="tab-panel" id="tab-plan">
<pre class="git-log">{_html_escape(json.dumps(result.get('execution_plan'), indent=2)[:20000] if result.get('execution_plan') else 'No execution plan found.')}</pre>
</div>

<div class="tab-panel" id="tab-critic">
{_render_critic_assessment(result)}
</div>
</body>
</html>'''
    return html, 200, {'Content-Type': 'text/html; charset=utf-8'}


def _fallback_answer(question, report):
    """Template fallback when LLM is unreachable."""
    q = question.lower()
    if 'verdict' in q or 'evil' in q:
        return f"Verdict: {report.get('verdict', 'unknown')}. Confidence: {report.get('confidence', 'N/A')}."
    if 'hostname' in q or 'host' in q:
        return f"Hostname: {report.get('hostname', 'N/A')}."
    if 'ioc' in q or 'indicator' in q:
        iocs = report.get('iocs', [])
        return f"IOCs found: {len(iocs)}. First few: {', '.join(str(i) for i in iocs[:5])}." if iocs else "No IOCs in report."
    return "LLM unavailable. Check the report JSON for details."



# ---------------------------------------------------------------------------
# Settings routes
# ---------------------------------------------------------------------------

def api_get_settings():
    """GET /api/settings — Return current model selections and masked API keys."""
    if settings_manager is None:
        return jsonify({'error': 'Settings manager not initialized'}), 503
    return jsonify(settings_manager.get_settings())


def api_update_models():
    """POST /api/settings/models — Update model selections at runtime."""
    if settings_manager is None:
        return jsonify({'error': 'Settings manager not initialized'}), 503
    data = request.json or {}
    manager = data.get('manager') or None
    forensicator = data.get('forensicator') or None
    critic = data.get('critic') or None
    if not any([manager, forensicator, critic]):
        return jsonify({'error': 'No model fields provided'}), 400
    settings_manager.update_models(manager=manager, forensicator=forensicator, critic=critic)
    settings_manager.apply_to_config()
    return jsonify({'status': 'ok', 'models': settings_manager.models})


def api_update_keys():
    """POST /api/settings/keys — Save API keys server-side."""
    if settings_manager is None:
        return jsonify({'error': 'Settings manager not initialized'}), 503
    data = request.json or {}
    settings_manager.update_keys(
        openai_key=data.get('openai_key'),
        claude_key=data.get('claude_key'),
        ollama_key=data.get('ollama_key'),
        deepseek_key=data.get('deepseek_key'),
    )
    settings_manager.apply_to_config()
    return jsonify({'status': 'ok'})




def replay_playbook_route():
    """POST /replay-playbook — Re-run a single playbook against existing case evidence.

    Request body (JSON):
        {
            "case":        "<case_name or job_id>",
            "playbook_id": "PB-SIFT-012",
            "force":       false        // optional: re-run even if already replayed
        }

    Returns:
        {
            "status": "complete",
            "case": "...",
            "playbook_id": "PB-SIFT-012",
            "new_findings": 12,
            "critic_approved": 10,
            "critic_rejected": 2,
            "duration_seconds": 47.3,
            "force": false
        }

    Pass-2 cross-device playbooks (PB-SIFT-100 through PB-SIFT-104) are rejected
    with a 400 error — replay is only supported for single-device playbooks.
    """
    try:
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify({"status": "error", "error": "Request body must be a JSON object"}), 400

        case = (data.get("case") or "").strip()
        playbook_id = (data.get("playbook_id") or "").strip()
        force = bool(data.get("force", False))

        if not case:
            return jsonify({"status": "error", "error": "Missing required field: case"}), 400
        if not playbook_id:
            return jsonify({"status": "error", "error": "Missing required field: playbook_id"}), 400

        if playbook_id in NON_REPLAYABLE_PLAYBOOKS:
            return jsonify({
                "status": "error",
                "error": (
                    f"{playbook_id} is a cross-device/Pass-2 playbook and cannot be "
                    "individually replayed. Re-run the full investigation instead."
                ),
            }), 400

        result = replay_playbook(case=case, playbook_id=playbook_id, force=force)

        if result.get("status") == "error":
            return jsonify(result), 404 if "not found" in result.get("error", "").lower() else 400

        return jsonify(result)

    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500



def get_communications(case_dir):
    """GET /reports/<case_dir>/communications — Communication graph + narrative from PB-SIFT-060."""
    safe_dir = re.sub(r'[^a-zA-Z0-9_\-]', '_', case_dir)
    if not safe_dir:
        return jsonify({'error': 'Invalid case directory name'}), 400

    case_path = _find_case_dir(safe_dir)
    if not case_path or not case_path.is_dir():
        return jsonify({'error': 'Case not found'}), 404

    # Try cached result first
    cached = case_path / "output" / "PB-SIFT-060_communications.json"
    if cached.exists():
        try:
            return jsonify(json.loads(cached.read_text(encoding='utf-8')))
        except (OSError, json.JSONDecodeError) as e:
            _log_error("Failed to read cached communications", e)

    # Build on-the-fly from existing findings
    try:
        findings_file = case_path / "findings.jsonl"
        findings = []
        if findings_file.exists():
            for line in findings_file.read_text(encoding='utf-8', errors='replace').splitlines():
                if line.strip():
                    try:
                        findings.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass

        report_file = case_path / "reports" / "find_evil_report.json"
        evidence_dir = ""
        if report_file.exists():
            try:
                rdata = json.loads(report_file.read_text())
                evidence_dir = rdata.get("evidence_dir", "")
            except Exception:
                pass

        analyzer = CommunicationsAnalyzer()
        result = analyzer.analyze(
            case_dir=str(case_path),
            evidence_dir=evidence_dir,
            findings=findings,
            call_llm_func=call_llm,
        )
        return jsonify(result)
    except Exception as e:
        _log_error("Communications analysis failed", e)
        return jsonify({'error': str(e)}), 500



def get_stego(case_dir):
    """GET /reports/<case_dir>/stego — Steganography report from PB-SIFT-061."""
    safe_dir = re.sub(r'[^a-zA-Z0-9_\-]', '_', case_dir)
    if not safe_dir:
        return jsonify({'error': 'Invalid case directory name'}), 400

    case_path = _find_case_dir(safe_dir)
    if not case_path or not case_path.is_dir():
        return jsonify({'error': 'Case not found'}), 404

    cached = case_path / "output" / "PB-SIFT-061_stego.json"
    if cached.exists():
        try:
            return jsonify(json.loads(cached.read_text(encoding='utf-8')))
        except (OSError, json.JSONDecodeError) as e:
            _log_error("Failed to read cached stego report", e)

    try:
        findings_file = case_path / "findings.jsonl"
        findings = []
        if findings_file.exists():
            for line in findings_file.read_text(encoding='utf-8', errors='replace').splitlines():
                if line.strip():
                    try:
                        findings.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass

        report_file = case_path / "reports" / "find_evil_report.json"
        evidence_dir = ""
        if report_file.exists():
            try:
                rdata = json.loads(report_file.read_text())
                evidence_dir = rdata.get("evidence_dir", "")
            except Exception:
                pass

        analyzer = StegoAnalyzer()
        result = analyzer.analyze(
            case_dir=str(case_path),
            evidence_dir=evidence_dir,
            findings=findings,
            call_llm_func=call_llm,
        )
        return jsonify(result)
    except Exception as e:
        _log_error("Stego analysis failed", e)
        return jsonify({'error': str(e)}), 500


def get_keylogger(case_dir):
    """GET /reports/<case_dir>/keylogger — Keylogger report from PB-SIFT-062."""
    safe_dir = re.sub(r'[^a-zA-Z0-9_\-]', '_', case_dir)
    if not safe_dir:
        return jsonify({'error': 'Invalid case directory name'}), 400

    case_path = _find_case_dir(safe_dir)
    if not case_path or not case_path.is_dir():
        return jsonify({'error': 'Case not found'}), 404

    cached = case_path / "output" / "PB-SIFT-062_keylogger.json"
    if cached.exists():
        try:
            return jsonify(json.loads(cached.read_text(encoding='utf-8')))
        except (OSError, json.JSONDecodeError) as e:
            _log_error("Failed to read cached keylogger report", e)

    try:
        findings_file = case_path / "findings.jsonl"
        findings = []
        if findings_file.exists():
            for line in findings_file.read_text(encoding='utf-8', errors='replace').splitlines():
                if line.strip():
                    try:
                        findings.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass

        analyzer = KeyloggerAnalyzer()
        result = analyzer.analyze(
            case_dir=str(case_path),
            findings=findings,
            call_llm_func=call_llm,
        )
        return jsonify(result)
    except Exception as e:
        _log_error("Keylogger analysis failed", e)
        return jsonify({'error': str(e)}), 500


def get_chat_aggregator(case_dir):
    """GET /reports/<case_dir>/chat-aggregator — Aggregated chat report from PB-SIFT-063."""
    safe_dir = re.sub(r'[^a-zA-Z0-9_\-]', '_', case_dir)
    if not safe_dir:
        return jsonify({'error': 'Invalid case directory name'}), 400

    case_path = _find_case_dir(safe_dir)
    if not case_path or not case_path.is_dir():
        return jsonify({'error': 'Case not found'}), 404

    cached = case_path / "output" / "PB-SIFT-063_chat_aggregator.json"
    if cached.exists():
        try:
            return jsonify(json.loads(cached.read_text(encoding='utf-8')))
        except (OSError, json.JSONDecodeError) as e:
            _log_error("Failed to read cached chat aggregator report", e)

    try:
        findings_file = case_path / "findings.jsonl"
        findings = []
        if findings_file.exists():
            for line in findings_file.read_text(encoding='utf-8', errors='replace').splitlines():
                if line.strip():
                    try:
                        findings.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass

        # Try to load PB-SIFT-060 result for email enrichment
        comm_cached = case_path / "output" / "PB-SIFT-060_communications.json"
        comm_result = None
        if comm_cached.exists():
            try:
                comm_result = json.loads(comm_cached.read_text(encoding='utf-8'))
            except Exception:
                pass

        analyzer = ChatAggregator()
        result = analyzer.analyze(
            case_dir=str(case_path),
            findings=findings,
            comm_result=comm_result,
            call_llm_func=call_llm,
        )
        return jsonify(result)
    except Exception as e:
        _log_error("Chat aggregator analysis failed", e)
        return jsonify({'error': str(e)}), 500


def ask_case(case_dir):
    """POST /reports/<case_dir>/ask — RAG Q&A over case findings.

    JSON body: {"question": "What were the suspects planning?"}
    """
    safe_dir = re.sub(r'[^a-zA-Z0-9_\-]', '_', case_dir)
    if not safe_dir:
        return jsonify({'error': 'Invalid case directory name'}), 400

    case_path = _find_case_dir(safe_dir)
    if not case_path or not case_path.is_dir():
        return jsonify({'error': 'Case not found'}), 404

    body = request.get_json(silent=True) or {}
    question = str(body.get("question", "")).strip()
    if not question:
        return jsonify({'error': 'Missing "question" in request body'}), 400
    if len(question) > 2000:
        return jsonify({'error': 'Question too long (max 2000 chars)'}), 400

    rebuild = bool(body.get("rebuild_index", False))

    try:
        rag = CaseRAG()
        result = rag.query(
            question=question,
            case_dir=str(case_path),
            call_llm_func=call_llm,
            rebuild=rebuild,
        )
        return jsonify(result)
    except Exception as e:
        _log_error("RAG query failed", e)
        return jsonify({'error': str(e)}), 500



# ---------------------------------------------------------------------------
# Queue API Routes
# ---------------------------------------------------------------------------

def queue_list():
    """GET /queue — List all queue items sorted by priority."""
    try:
        items = _queue_manager.get_all_items()
        running = next((i for i in items if i["status"] == "running"), None)
        # Sync running item progress from _find_evil_jobs
        if running and running.get("job_id"):
            job = _find_evil_jobs.get(running["job_id"])
            if job:
                try:
                    _queue_manager.sync_progress(
                        running["job_id"],
                        job.get("progress_pct", 0.0),
                        job.get("current_playbook", ""),
                        job.get("current_step", ""),
                        job.get("elapsed_seconds", 0.0),
                    )
                    items = _queue_manager.get_all_items()
                    running = next((i for i in items if i["status"] == "running"), None)
                except Exception:
                    pass
        next_item = next((i for i in items if i["status"] == "queued"), None)
        return jsonify({"status": "ok", "items": items, "running": running, "next": next_item})
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500


def queue_add():
    """POST /queue — Enqueue evidence directory."""
    try:
        data = request.get_json(silent=True) or {}
        evidence_dir = (data.get("evidence_dir") or data.get("evidence_path") or "").strip()
        if not evidence_dir:
            return jsonify({"status": "error", "error": "evidence_dir is required"}), 400
        if _UNSAFE_PATH_CHARS.search(evidence_dir):
            return jsonify({"status": "error", "error": "Path contains unsafe characters"}), 400
        if not Path(evidence_dir).is_absolute():
            evidence_dir = os.path.join(EVIDENCE_BASE_DIR, evidence_dir)
        try:
            _validate_evidence_path(evidence_dir)
        except ValueError as e:
            return jsonify({"status": "error", "error": str(e)}), 400
        if not Path(evidence_dir).is_dir():
            return jsonify({"status": "error", "error": f"Not a directory: {evidence_dir}"}), 404
        try:
            item = _queue_manager.enqueue(evidence_dir, created_by="user")
        except ValueError as e:
            return jsonify({"status": "error", "error": str(e)}), 409
        _queue_logger.info("Evidence enqueued", item_id=item.id, evidence=evidence_dir)
        from dataclasses import asdict
        return jsonify({"status": "queued", "item": asdict(item)}), 201
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500


def queue_remove_item(item_id):
    """DELETE /queue/<item_id> — Remove a queued (not running) item."""
    try:
        removed = _queue_manager.remove(item_id)
        return jsonify({"status": "removed", "item_id": item_id, "item": removed})
    except KeyError:
        return jsonify({"status": "error", "error": "Item not found"}), 404
    except RuntimeError as e:
        return jsonify({"status": "error", "error": str(e)}), 409
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500


def queue_cancel_item(item_id):
    """POST /queue/<item_id>/cancel — Cancel a running or queued item."""
    try:
        result = _queue_manager.cancel(item_id)
        _queue_logger.info("Job cancelled", item_id=item_id)
        return jsonify({"status": "cancelled", **result})
    except KeyError:
        return jsonify({"status": "error", "error": "Item not found"}), 404
    except RuntimeError as e:
        return jsonify({"status": "error", "error": str(e)}), 409
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500


def queue_update_item(item_id):
    """PATCH /queue/<item_id> — Update priority of a queued item."""
    try:
        data = request.get_json(silent=True) or {}
        if "priority" not in data:
            return jsonify({"status": "error", "error": "priority field required"}), 400
        priority = int(data["priority"])
        item = _queue_manager.update_priority(item_id, priority)
        return jsonify({"status": "updated", "item": item})
    except KeyError:
        return jsonify({"status": "error", "error": "Item not found"}), 404
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500


def queue_advance():
    """POST /queue/advance — Force-advance queue (cancel current, start next)."""
    try:
        result = _queue_manager.force_advance()
        _queue_logger.info("Queue advanced", next_item=result.get("next_item"))
        return jsonify(result)
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500




def _queue_start_find_evil_job(evidence_dir, job_id, created_by="auto"):
    """Start a find_evil job for the queue manager. Called by queue_manager._maybe_start_next."""
    try:
        _log_info(f"Queue auto-starting find_evil for {evidence_dir} (job {job_id})")

        with _state_lock:
            if job_id in _find_evil_jobs:
                _log_info(f"Job {job_id} already registered, skipping")
                return job_id

        from geoff_pipeline import find_evil as _find_evil
        from datetime import datetime

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
                "evidence_dir": evidence_dir,
                "log": [{"time": datetime.now().strftime("%H:%M:%S"), "msg": f"Auto-started from queue ({created_by})"}],
            }

        def _run():
            try:
                report = _find_evil(evidence_dir, job_id=job_id)
                with _state_lock:
                    _find_evil_jobs[job_id]["status"] = "complete"
                    _find_evil_jobs[job_id]["result"] = report
                _queue_manager.on_job_complete(job_id, report if report else {})
            except Exception as e:
                _fe_log_with_exception(job_id, f"find_evil failed: {e}", e)
                with _state_lock:
                    _find_evil_jobs[job_id]["status"] = "failed"
                    _find_evil_jobs[job_id]["error"] = str(e)
                _queue_manager.on_job_failed(job_id, str(e))

        t = threading.Thread(target=_run, daemon=True)
        t.start()
        _log_info(f"Queue started thread for find_evil job {job_id}")
        return job_id
    except Exception as e:
        _log_error(f"Failed to start queued find_evil job {job_id}: {e}")
        return None

def register_routes(app):
    """Register all route handlers with the Flask app.

    Called by geoff_integrated.py after all singletons are initialized
    and module-level references are wired.
    """
    # Load persisted job state on startup
    from geoff_utils import _load_jobs
    _load_jobs()
    # Initialize queue manager after _load_jobs so stale job detection works
    try:
        _queue_manager.set_start_job_fn(_queue_start_find_evil_job)
        _queue_manager.initialize()
        _srv_logger.info("Queue state loaded")
    except Exception as _qm_err:
        _log_error(f"queue_manager init failed: {_qm_err}")
    app.add_url_rule('/', 'index', index)
    app.add_url_rule('/chat', 'chat', _require_auth(chat), methods=['POST'])
    app.add_url_rule('/cases', 'list_cases', _require_auth(list_cases))
    app.add_url_rule('/cases/<case_name>/report', 'get_case_report', _require_auth(get_case_report))
    app.add_url_rule('/reports', 'list_reports', _require_auth(list_reports))
    app.add_url_rule('/reports/graph', 'graph_viewer', _require_auth(graph_viewer))
    app.add_url_rule('/reports/<case_dir>/json', 'get_report_json', _require_auth(get_report_json))
    app.add_url_rule('/reports/<case_dir>/download/markdown', 'download_markdown', _require_auth(download_markdown))
    app.add_url_rule('/reports/<case_dir>/download/json', 'download_json', _require_auth(download_json))
    app.add_url_rule('/reports/<case_dir>/download/summary', 'download_summary', _require_auth(download_summary))
    app.add_url_rule('/reports/narrative', 'narrative_report_page', _require_auth(narrative_report_page))
    app.add_url_rule('/reports/viewer', 'viewer_html', _require_auth(viewer_html))
    app.add_url_rule('/static/<filename>', 'ui_static', ui_static)
    app.add_url_rule('/static/geoff-viewer/<path:filename>', 'viewer_static', _require_auth(viewer_static))
    app.add_url_rule('/reports/<case_dir>/supertimeline', 'serve_supertimeline', _require_auth(serve_supertimeline))
    app.add_url_rule('/reports/<case_dir>/ip-map', 'get_ip_map', _require_auth(get_ip_map))
    app.add_url_rule('/ip-map', 'ip_map_page', _require_auth(ip_map_page))
    app.add_url_rule('/reports/mitre-matrix', 'mitre_matrix', _require_auth(mitre_matrix))
    app.add_url_rule('/reports/mitre-heatmap', 'mitre_heatmap', _require_auth(mitre_heatmap))
    app.add_url_rule('/tools', 'list_tools', _require_auth(list_tools))
    app.add_url_rule('/health', 'health', health)
    app.add_url_rule('/health/detailed', 'health_detailed', _require_auth(health_detailed))
    app.add_url_rule('/run-tool', 'run_tool', _require_auth(run_tool), methods=['POST'])
    app.add_url_rule('/critic/validate', 'critic_validate', _require_auth(critic_validate), methods=['POST'])
    app.add_url_rule('/critic/summary/<investigation_id>', 'critic_summary', _require_auth(critic_summary))
    app.add_url_rule('/investigation/status/<case_name>', 'get_investigation_status', _require_auth(get_investigation_status))
    app.add_url_rule('/find-evil', 'find_evil_route', _require_auth(find_evil_route), methods=['POST'])
    app.add_url_rule('/find-evil', 'find_evil_info', _require_auth(find_evil_info), methods=['GET'])
    app.add_url_rule('/find-evil/active', 'find_evil_active', _require_auth(find_evil_active), methods=['GET'])
    app.add_url_rule('/find-evil/status/', 'find_evil_status_latest', _require_auth(find_evil_status_latest), methods=['GET'])
    app.add_url_rule('/find-evil/status/<job_id>', 'find_evil_status', _require_auth(find_evil_status), methods=['GET'])
    app.add_url_rule('/find-evil/status/<job_id>', 'find_evil_cancel', _require_auth(find_evil_cancel), methods=['DELETE'])
    app.add_url_rule('/active-directory', 'set_active_directory', _require_auth(set_active_directory), methods=['POST'])
    app.add_url_rule('/active-directory', 'get_active_directory', _require_auth(get_active_directory), methods=['GET'])
    app.add_url_rule('/reports/<case_dir>/chat', 'report_chat', _require_auth(report_chat), methods=['POST'])
    app.add_url_rule('/reports/<case_dir>/history', 'report_history', _require_auth(report_history))
    app.add_url_rule('/reports/execution/<case_id>', 'get_execution_log', _require_auth(get_execution_log))
    app.add_url_rule('/api/settings', 'api_get_settings', _require_auth(api_get_settings))
    app.add_url_rule('/api/settings/models', 'api_update_models', _require_auth(api_update_models), methods=['POST'])
    app.add_url_rule('/api/settings/keys', 'api_update_keys', _require_auth(api_update_keys), methods=['POST'])
    app.add_url_rule('/replay-playbook', 'replay_playbook_route', _require_auth(replay_playbook_route), methods=['POST'])
    app.add_url_rule('/reports/<case_dir>/communications', 'get_communications', _require_auth(get_communications))
    app.add_url_rule('/reports/<case_dir>/stego', 'get_stego', _require_auth(get_stego))
    app.add_url_rule('/reports/<case_dir>/keylogger', 'get_keylogger', _require_auth(get_keylogger))
    app.add_url_rule('/reports/<case_dir>/chat-aggregator', 'get_chat_aggregator', _require_auth(get_chat_aggregator))
    app.add_url_rule('/reports/<case_dir>/ask', 'ask_case', _require_auth(ask_case), methods=['POST'])
    # Queue routes
    app.add_url_rule('/queue', 'queue_list', _require_auth(queue_list), methods=['GET'])
    app.add_url_rule('/queue', 'queue_add', _require_auth(queue_add), methods=['POST'])
    app.add_url_rule('/queue/advance', 'queue_advance', _require_auth(queue_advance), methods=['POST'])
    app.add_url_rule('/queue/<item_id>', 'queue_remove_item', _require_auth(queue_remove_item), methods=['DELETE'])
    app.add_url_rule('/queue/<item_id>', 'queue_update_item', _require_auth(queue_update_item), methods=['PATCH'])
    app.add_url_rule('/queue/<item_id>/cancel', 'queue_cancel_item', _require_auth(queue_cancel_item), methods=['POST'])
