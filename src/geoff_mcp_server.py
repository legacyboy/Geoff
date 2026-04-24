#!/usr/bin/env python3
"""
Geoff MCP Server — Model Context Protocol endpoint for Geoff DFIR.

Exposes all forensic capabilities as MCP tools over streamable-HTTP transport.
Default port: 9999.  Clients connect to http://<host>:9999/mcp

Usage:
    python src/geoff_mcp_server.py                  # HTTP on 127.0.0.1:9999 (local only)
    python src/geoff_mcp_server.py --port 9999      # explicit port
    python src/geoff_mcp_server.py --stdio          # stdio transport (local clients)
    python src/geoff_mcp_server.py --host 0.0.0.0  # expose remotely (use SSH tunnel instead)
"""

import argparse
import json
import os
import sys
import threading
import time
import uuid
from pathlib import Path
from datetime import datetime
from typing import Any, Dict, List, Optional

# Ensure src/ is on the path for sibling imports
SRC_DIR = os.path.dirname(os.path.abspath(__file__))
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from dotenv import load_dotenv
load_dotenv()

from mcp.server.fastmcp import FastMCP

# ---------------------------------------------------------------------------
# Lazy imports from geoff_integrated — Flask app does NOT start here because
# the module only calls app.run() inside `if __name__ == "__main__"`.
# ---------------------------------------------------------------------------
from geoff_integrated import (
    find_evil,
    call_llm,
    get_all_cases,
    get_evidence_recursive,
    _find_evil_jobs,
    _state_lock,
    _fe_log,
    EVIDENCE_BASE_DIR,
    CASES_WORK_DIR,
    PLAYBOOK_NAMES,
)
from sift_specialists_extended import ExtendedOrchestrator

# ---------------------------------------------------------------------------
# FastMCP instance
# ---------------------------------------------------------------------------

mcp = FastMCP(
    name="Geoff DFIR",
    instructions=(
        "Geoff is a Digital Forensics and Incident Response (DFIR) assistant. "
        "Use find_evil to run a full automated investigation, poll get_job_status "
        "until complete, then fetch the report with get_case_report. "
        "Specialist tools (disk_analyze, memory_analyze, etc.) accept a module/function "
        "pair and params dict to call individual forensic tool wrappers directly."
    ),
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe_evidence_path(evidence_dir: str) -> str:
    """Resolve evidence_dir: absolute as-is, relative joined to EVIDENCE_BASE_DIR."""
    p = Path(evidence_dir)
    if not p.is_absolute():
        p = Path(EVIDENCE_BASE_DIR) / evidence_dir
    return str(p)


def _find_case_dir(cases_root: Path, safe_name: str, report_filename: str) -> Optional[Path]:
    """
    Find the most-recent case directory matching safe_name.

    Case directories use the pattern: {case_name}_findevil_{timestamp}
    We require the prefix to be followed by '_findevil_' or end-of-string to
    prevent 'IR-01' matching 'IR-016-...'.  Falls back to bare startswith only
    when no '_findevil_' separator is present (legacy dirs).
    """
    import re
    # Build a pattern that anchors safe_name at a segment boundary
    pattern = re.compile(r'^' + re.escape(safe_name) + r'(_findevil_|$)')
    matches = [
        d for d in cases_root.iterdir()
        if d.is_dir() and pattern.match(d.name)
    ]
    # Most recent first (dirs are named with timestamp suffix)
    for candidate in sorted(matches, key=lambda d: d.name, reverse=True):
        target = candidate / report_filename
        if target.exists():
            return candidate
    return None


def _spawn_find_evil(evidence_dir: str, job_id: str) -> None:
    """Background thread: run find_evil and update job state."""
    try:
        report = find_evil(evidence_dir, job_id=job_id)
        with _state_lock:
            _find_evil_jobs[job_id]["status"] = "complete"
            _find_evil_jobs[job_id]["result"] = report
    except Exception as exc:
        _fe_log(job_id, f"MCP find_evil error: {exc}")
        with _state_lock:
            _find_evil_jobs[job_id]["status"] = "error"
            _find_evil_jobs[job_id]["error"] = str(exc)


# ---------------------------------------------------------------------------
# Investigation tools
# ---------------------------------------------------------------------------

@mcp.tool()
def start_find_evil(evidence_dir: str) -> Dict[str, Any]:
    """
    Start a full triage-driven forensic investigation on an evidence directory.

    Runs all 25 SIFT playbooks (PB-SIFT-000 through PB-SIFT-024) automatically.
    Returns a job_id immediately; poll get_job_status for progress.

    Args:
        evidence_dir: Absolute path to evidence directory, or a folder name
                      relative to the configured evidence base directory.

    Returns:
        {"job_id": str, "status": "running", "evidence_dir": str}
    """
    evidence_dir = _safe_evidence_path(evidence_dir)

    if not Path(evidence_dir).exists():
        return {
            "status": "error",
            "error": f"Evidence directory not found: {evidence_dir}",
        }

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
            "log": [{"time": datetime.now().strftime("%H:%M:%S"), "msg": "MCP Find Evil job started"}],
        }

    thread = threading.Thread(target=_spawn_find_evil, args=(evidence_dir, job_id), daemon=True)
    thread.start()

    return {
        "job_id": job_id,
        "status": "running",
        "evidence_dir": evidence_dir,
        "message": f"Investigation started. Call get_job_status(job_id='{job_id}') to track progress.",
    }


@mcp.tool()
def get_job_status(job_id: str) -> Dict[str, Any]:
    """
    Poll the status of a running Find Evil job.

    Args:
        job_id: Job ID returned by start_find_evil.

    Returns:
        Job state dict including status, progress_pct, current_playbook,
        current_step, elapsed_seconds, and (when complete) result or error.
    """
    with _state_lock:
        job = _find_evil_jobs.get(job_id)

    if job is None:
        return {"status": "not_found", "error": f"No job with ID {job_id}"}

    resp: Dict[str, Any] = {
        "job_id": job_id,
        "status": job["status"],
        "progress_pct": job["progress_pct"],
        "current_playbook": job["current_playbook"],
        "current_step": job["current_step"],
        "elapsed_seconds": job["elapsed_seconds"],
        "log": job.get("log", [])[-50:],
    }
    if job["status"] == "complete":
        resp["result"] = job["result"]
    elif job["status"] == "error":
        resp["error"] = job["error"]

    return resp


@mcp.tool()
def list_cases() -> Dict[str, Any]:
    """
    List all evidence cases with their file trees.

    Returns:
        {"cases": {case_name: {files...}}}
    """
    return {"cases": get_all_cases()}


@mcp.tool()
def list_evidence(case_name: Optional[str] = None) -> Dict[str, Any]:
    """
    List evidence files.

    Args:
        case_name: Optional case name to scope the listing.
                   If omitted, lists all evidence under the evidence base directory.

    Returns:
        {"evidence": {path: metadata}}
    """
    if case_name:
        import re
        safe_case = re.sub(r"[^a-zA-Z0-9_\-]", "", case_name)
        if not safe_case:
            return {"evidence": {}, "error": "Invalid case_name"}
        base = Path(EVIDENCE_BASE_DIR) / safe_case
        # Verify resolved path stays within evidence base (no traversal)
        try:
            base.resolve().relative_to(Path(EVIDENCE_BASE_DIR).resolve())
        except ValueError:
            return {"evidence": {}, "error": "Invalid case_name"}
    else:
        base = Path(EVIDENCE_BASE_DIR)

    if not base.exists():
        return {"evidence": {}, "error": f"Path not found: {base}"}

    return {"evidence": get_evidence_recursive(str(base))}


@mcp.tool()
def get_case_report(case_name: str) -> Dict[str, Any]:
    """
    Retrieve the narrative investigation report for a completed Find Evil case.

    Args:
        case_name: Case name (e.g. "IR-016-CloudJack"). Exact or prefix match.

    Returns:
        {"report": str} with the full Markdown narrative, or {"error": str}.
    """
    import re
    safe_name = re.sub(r"[^a-zA-Z0-9_\-]", "", case_name)
    if not safe_name:
        return {"error": "Invalid case name"}

    cases_root = Path(CASES_WORK_DIR)
    if not cases_root.exists():
        return {"error": f"Cases directory not found: {CASES_WORK_DIR}"}

    candidate = _find_case_dir(cases_root, safe_name, "reports/narrative_report.md")
    if candidate is None:
        return {"error": f"No report found for case: {case_name}"}

    report_path = candidate / "reports" / "narrative_report.md"
    return {"case_dir": candidate.name, "report": report_path.read_text(encoding="utf-8")}


@mcp.tool()
def get_findings(case_name: str) -> Dict[str, Any]:
    """
    Return the structured JSON findings for a completed Find Evil case.

    Args:
        case_name: Case name prefix (e.g. "IR-016-CloudJack").

    Returns:
        The find_evil_report.json content as a dict, or {"error": str}.
    """
    import re
    safe_name = re.sub(r"[^a-zA-Z0-9_\-]", "", case_name)
    if not safe_name:
        return {"error": "Invalid case name"}

    cases_root = Path(CASES_WORK_DIR)
    if not cases_root.exists():
        return {"error": f"Cases directory not found: {CASES_WORK_DIR}"}

    candidate = _find_case_dir(cases_root, safe_name, "reports/find_evil_report.json")
    if candidate is None:
        return {"error": f"No findings JSON for case: {case_name}"}

    json_path = candidate / "reports" / "find_evil_report.json"
    if json_path.stat().st_size > 100 * 1024 * 1024:
        return {"error": "Report too large to serve via MCP"}
    with open(json_path) as f:
        return {"case_dir": candidate.name, "findings": json.load(f)}


@mcp.tool()
def list_playbooks() -> Dict[str, Any]:
    """
    List all available Find Evil playbooks with their IDs and descriptions.

    Returns:
        {"playbooks": [{"id": str, "name": str}]}
    """
    return {
        "playbooks": [
            {"id": pid, "name": pname}
            for pid, pname in PLAYBOOK_NAMES.items()
        ]
    }


# ---------------------------------------------------------------------------
# Chat / reasoning tool
# ---------------------------------------------------------------------------

@mcp.tool()
def chat(
    message: str,
    context: Optional[str] = None,
    agent_type: str = "manager",
) -> Dict[str, Any]:
    """
    Send a message to Geoff's LLM reasoning layer.

    Args:
        message: The user message or analytical question.
        context: Optional forensic context (findings JSON, log excerpts, etc.)
                 to ground the response.
        agent_type: Which agent to invoke — "manager" (default), "forensicator",
                    or "critic".

    Returns:
        {"response": str, "agent_type": str}
    """
    ctx = context or ""
    response = call_llm(message, context=ctx, agent_type=agent_type)
    return {"response": response, "agent_type": agent_type}


# ---------------------------------------------------------------------------
# Specialist tools — thin wrappers over ExtendedOrchestrator
# ---------------------------------------------------------------------------

def _run_specialist(module: str, function: str, evidence_dir: str, params: Optional[Dict] = None) -> Dict[str, Any]:
    """Internal: instantiate orchestrator and call module.function(**params)."""
    evidence_dir = _safe_evidence_path(evidence_dir)
    try:
        orch = ExtendedOrchestrator(evidence_base=evidence_dir)
        step = {"module": module, "function": function, "params": params or {}}
        result = orch.run_playbook_step("mcp-direct", step)
        return result
    except Exception as exc:
        return {"status": "error", "error": str(exc), "module": module, "function": function}


@mcp.tool()
def disk_analyze(
    function: str,
    evidence_dir: str,
    params: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Run a SleuthKit disk analysis function directly.

    Common functions: list_partitions, extract_files, recover_deleted,
    timeline_bodyfile, hash_files, mft_parse, usn_journal.

    Args:
        function: Name of the SLEUTHKIT_Specialist method to call.
        evidence_dir: Path to the evidence directory or disk image.
        params: Keyword arguments forwarded to the specialist method.

    Returns:
        Specialist result dict.
    """
    return _run_specialist("sleuthkit", function, evidence_dir, params)


@mcp.tool()
def memory_analyze(
    function: str,
    evidence_dir: str,
    params: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Run a Volatility memory analysis function directly.

    Common functions: pslist, pstree, netscan, cmdline, dlllist, malfind,
    handles, filescan, dumpfiles, shimcache, prefetch.

    Args:
        function: Name of the VOLATILITY_Specialist method to call.
        evidence_dir: Path to the directory containing the memory dump.
        params: Keyword arguments forwarded to the specialist method.

    Returns:
        Specialist result dict.
    """
    return _run_specialist("volatility", function, evidence_dir, params)


@mcp.tool()
def registry_analyze(
    function: str,
    evidence_dir: str,
    params: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Run a Registry (RegRipper) analysis function directly.

    Common functions: run_regripper, parse_hive, extract_run_keys,
    extract_services, extract_users, extract_network, extract_usb,
    extract_shellbags, extract_sam.

    Args:
        function: Name of the REGISTRY_Specialist method to call.
        evidence_dir: Path to the directory containing registry hives.
        params: Keyword arguments forwarded to the specialist method.

    Returns:
        Specialist result dict.
    """
    return _run_specialist("registry", function, evidence_dir, params)


@mcp.tool()
def network_analyze(
    function: str,
    evidence_dir: str,
    params: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Run a network (Zeek/Wireshark/tshark) analysis function directly.

    Common functions: parse_pcap, extract_connections, dns_queries,
    http_requests, extract_files, detect_anomalies, geo_ips.

    Args:
        function: Name of the NETWORK_Specialist method to call.
        evidence_dir: Path to the directory containing pcap files.
        params: Keyword arguments forwarded to the specialist method.

    Returns:
        Specialist result dict.
    """
    return _run_specialist("network", function, evidence_dir, params)


@mcp.tool()
def log_analyze(
    function: str,
    evidence_dir: str,
    params: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Run a log analysis function directly (Windows Event Logs, syslog, auth.log).

    Common functions: parse_evtx, parse_syslog, parse_auth_log,
    extract_logon_events, extract_process_events, extract_network_events,
    detect_brute_force, extract_powershell.

    Args:
        function: Name of the LOG_Specialist method to call.
        evidence_dir: Path to the directory containing log files.
        params: Keyword arguments forwarded to the specialist method.

    Returns:
        Specialist result dict.
    """
    return _run_specialist("logs", function, evidence_dir, params)


@mcp.tool()
def malware_analyze(
    function: str,
    evidence_dir: str,
    params: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Run a REMnux / YARA malware analysis function directly.

    Common functions: yara_scan, strings_extract, pe_info, detect_packers,
    extract_iocs, sandbox_detonate, capa_analyze, floss_extract.

    Args:
        function: Name of the REMNUX_Orchestrator method (via "remnux" module) to call.
        evidence_dir: Path to the directory containing files to analyse.
        params: Keyword arguments forwarded to the specialist method.

    Returns:
        Specialist result dict.
    """
    return _run_specialist("remnux", function, evidence_dir, params)


@mcp.tool()
def timeline_analyze(
    function: str,
    evidence_dir: str,
    params: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Run a Plaso / super-timeline analysis function directly.

    Common functions: create_timeline, filter_timeline, extract_events,
    search_by_keyword, correlate_artefacts.

    Args:
        function: Name of the PLASO_Specialist method to call.
        evidence_dir: Path to the evidence directory.
        params: Keyword arguments forwarded to the specialist method.

    Returns:
        Specialist result dict.
    """
    return _run_specialist("plaso", function, evidence_dir, params)


@mcp.tool()
def browser_analyze(
    function: str,
    evidence_dir: str,
    params: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Run a browser forensics analysis function directly.

    Common functions: extract_history, extract_downloads, extract_cookies,
    extract_cache, extract_passwords, extract_extensions.

    Args:
        function: Name of the BROWSER_Specialist method to call.
        evidence_dir: Path to the directory containing browser artefacts.
        params: Keyword arguments forwarded to the specialist method.

    Returns:
        Specialist result dict.
    """
    return _run_specialist("browser", function, evidence_dir, params)


@mcp.tool()
def run_specialist(
    module: str,
    function: str,
    evidence_dir: str,
    params: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Generic specialist dispatcher — call any module/function pair directly.

    Available modules: sleuthkit, volatility, strings, registry, plaso,
    network, logs, mobile, browser, email, jumplist, macos, photorec,
    vss, zimmerman, remnux.

    Args:
        module: Specialist module name (e.g. "registry", "volatility").
        function: Method name on that specialist (e.g. "run_regripper").
        evidence_dir: Path to the evidence directory.
        params: Optional keyword arguments forwarded to the method.

    Returns:
        Specialist result dict.
    """
    return _run_specialist(module, function, evidence_dir, params)


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Geoff MCP Server")
    parser.add_argument("--stdio", action="store_true", help="Use stdio transport instead of HTTP")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (HTTP mode, default 127.0.0.1)")
    parser.add_argument("--port", type=int, default=9999, help="Bind port (HTTP mode, default 9999)")
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()

    if args.stdio:
        print("[Geoff MCP] Starting in stdio transport mode", file=sys.stderr)
        mcp.run(transport="stdio")
    else:
        import uvicorn
        print(f"[Geoff MCP] Starting streamable-HTTP server on {args.host}:{args.port}", file=sys.stderr)
        print(f"[Geoff MCP] MCP endpoint: http://{args.host}:{args.port}/mcp", file=sys.stderr)
        uvicorn.run(mcp.streamable_http_app(), host=args.host, port=args.port, log_level="info")
