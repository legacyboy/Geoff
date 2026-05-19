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
from geoff_config import (
    GEOFF_API_KEY, EVIDENCE_BASE_DIR, CASES_WORK_DIR,
    OLLAMA_API_KEY, AGENT_MODELS, PLAYBOOK_NAMES,
    ollama_base_url,
    _UNSAFE_PATH_CHARS, _validate_evidence_path,
)
from geoff_utils import (
    _log_error, _log_info, _fe_log, _fe_log_with_exception,
    _state_lock, _find_evil_jobs, _run_step_via_orchestrator,
)
from geoff_models import action_logger, get_all_cases, get_available_tools_status
from geoff_self_heal import call_llm, _self_check_chat_response
from geoff_pipeline import find_evil, run_full_investigation
from geoff_templates import HTML_TEMPLATE

# ---------------------------------------------------------------------------
# Module-level singleton references (set by geoff_integrated.py after init)
# ---------------------------------------------------------------------------
orchestrator = None        # ExtendedOrchestrator instance
remnux_orchestrator = None  # REMNUX_Orchestrator instance
geoff_critic = None         # GeoffCritic instance
geoff_forensicator = None   # ForensicatorAgent instance


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

def index():
    """GET / — Serve the main Geoff UI."""
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
    safe_name = re.sub(r'[^a-zA-Z0-9_\-]', '', case_name)
    if not safe_name:
        return jsonify({'error': 'Invalid case name'}), 400

    # Search CASES_WORK_DIR for an exact or _findevil_-separated match.
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


def graph_viewer():
    """GET /reports/graph — Serve the new force-directed D3.js graph viewer."""
    viewer_path = Path(__file__).parent.parent / 'static' / 'graph_viewer.html'
    html = viewer_path.read_text(encoding='utf-8')
    if GEOFF_API_KEY:
        key_meta = f'<meta name="geoff-api-key" content="{_html_escape(GEOFF_API_KEY)}">'
        html = html.replace('<head>', '<head>\n  ' + key_meta, 1)
    return html, 200, {'Content-Type': 'text/html; charset=utf-8'}


def list_reports():
    """GET /reports — List completed Find Evil cases that have a saved JSON report."""
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


def get_report_json(case_dir):
    """GET /reports/<case_dir>/json — Serve the find_evil_report.json for a specific case directory,
    enriched with narrative report content if available."""
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
        # Enrich with executive summary and IOCs from narrative report JSON
        narrative_json = case_path / "reports" / "narrative_report.json"
        if narrative_json.exists():
            try:
                nr_data = json.loads(narrative_json.read_text(encoding='utf-8'))
                if nr_data.get('executive_summary'):
                    data['executive_summary'] = nr_data['executive_summary']
                if nr_data.get('iocs'):
                    data['iocs'] = nr_data['iocs']
            except (json.JSONDecodeError, OSError):
                pass
        return json.dumps(data, indent=2), 200, {'Content-Type': 'application/json; charset=utf-8'}
    except OSError as e:
        _log_error("Failed to read report JSON", e)
        return jsonify({'error': 'Unable to read report'}), 500


def download_markdown(case_dir):
    """GET /reports/<case_dir>/download/markdown — Serve narrative_report.md as a downloadable file."""
    safe_dir = re.sub(r'[^a-zA-Z0-9_\-]', '', case_dir)
    if not safe_dir:
        return jsonify({'error': 'Invalid case directory name'}), 400
    case_path = Path(CASES_WORK_DIR) / safe_dir
    if not case_path.is_dir():
        return jsonify({'error': 'Case not found'}), 404
    try:
        case_path.resolve().relative_to(Path(CASES_WORK_DIR).resolve())
    except ValueError:
        return jsonify({'error': 'Invalid case directory'}), 400
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
    safe_dir = re.sub(r'[^a-zA-Z0-9_\-]', '', case_dir)
    if not safe_dir:
        return jsonify({'error': 'Invalid case directory name'}), 400
    case_path = Path(CASES_WORK_DIR) / safe_dir
    if not case_path.is_dir():
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
    safe_dir = re.sub(r'[^a-zA-Z0-9_\-]', '', case_dir)
    if not safe_dir:
        return jsonify({'error': 'Invalid case directory name'}), 400
    case_path = Path(CASES_WORK_DIR) / safe_dir
    if not case_path.is_dir():
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

def report_chat(case_dir):
    """Answer questions about the investigation report."""
    data = request.get_json(force=True)
    question = (data.get('question') or '').strip()
    report_json = data.get('report_json') or {}

    if not question:
        return jsonify({'answer': 'No question provided.'}), 400

    # If report_json is empty, try loading from the case directory
    if not report_json or (isinstance(report_json, dict) and not report_json):
        safe_dir = re.sub(r'[^a-zA-Z0-9_\-]', '', case_dir)
        if safe_dir:
            case_path = Path(CASES_WORK_DIR) / safe_dir
            if case_path.is_dir():
                try:
                    case_path.resolve().relative_to(Path(CASES_WORK_DIR).resolve())
                    report_file = case_path / "reports" / "find_evil_report.json"
                    if report_file.exists():
                        report_json = json.loads(report_file.read_text(encoding='utf-8'))
                except (ValueError, OSError, json.JSONDecodeError):
                    pass

    # Build prompt
    summary = json.dumps(report_json, indent=2)[:8000]  # cap context size
    system_context = (
        "You are a forensic report analyst. Answer the question based ONLY on the "
        "provided investigation data. If the answer isn't in the data, say so.\n\n"
        f"REPORT DATA:\n{summary}\n\n"
    )
    user_prompt = f"QUESTION: {question}"

    # Try LLM, fall back to data lookup
    try:
        answer = call_llm(user_prompt, system_context, agent_type="manager")
        if not answer:
            raise ValueError("empty response")
    except Exception:
        answer = _fallback_answer(question, report_json)

    return jsonify({'answer': answer})


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


def register_routes(app):
    """Register all route handlers with the Flask app.

    Called by geoff_integrated.py after all singletons are initialized
    and module-level references are wired.
    """
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
    app.add_url_rule('/reports/viewer', 'viewer_html', _require_auth(viewer_html))
    app.add_url_rule('/static/geoff-viewer/<path:filename>', 'viewer_static', _require_auth(viewer_static))
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
    app.add_url_rule('/find-evil/status/<job_id>', 'find_evil_status', _require_auth(find_evil_status), methods=['GET'])
    app.add_url_rule('/find-evil/status/<job_id>', 'find_evil_cancel', _require_auth(find_evil_cancel), methods=['DELETE'])
    app.add_url_rule('/active-directory', 'set_active_directory', _require_auth(set_active_directory), methods=['POST'])
    app.add_url_rule('/active-directory', 'get_active_directory', _require_auth(get_active_directory), methods=['GET'])
    app.add_url_rule('/reports/<case_dir>/chat', 'report_chat', _require_auth(report_chat), methods=['POST'])
    app.add_url_rule('/reports/<case_dir>/history', 'report_history', _require_auth(report_history))
