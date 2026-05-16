#!/usr/bin/env python3
"""Geoff DFIR - Main find_evil() investigation pipeline and phase management.

Auto-extracted from geoff_integrated.py monolith.

This module contains:
  - find_evil(): the main triage-driven investigation orchestrator
  - run_full_investigation(): background-investigation entry point
  - Pipeline helper functions: preflight, custody commits, Phase 2 triggers,
    critic batch review, forensicator batching, timeline/behavioural analysis,
    attack-chain reconstruction, and manager post-critic decision logic.

External singleton references (orchestrator, remnux_orchestrator,
geoff_critic, geoff_forensicator) are wired by geoff_integrated.py after
initialisation — same pattern as geoff_utils.py.
"""

# ---------------------------------------------------------------------------
# Standard library
# ---------------------------------------------------------------------------
import os
import sys
import json
import re
import hashlib
import tempfile
import threading
import time
import uuid
import traceback
from collections import Counter
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Third-party
# ---------------------------------------------------------------------------
import subprocess
import requests
from jsonschema import validate as jsonschema_validate, ValidationError

# ---------------------------------------------------------------------------
# External project imports (pivot architecture modules)
# ---------------------------------------------------------------------------
from device_discovery import DeviceDiscovery
from host_correlator import HostCorrelator
from super_timeline import SuperTimeline
from narrative_report import NarrativeReportGenerator
from behavioral_analyzer import BehavioralAnalyzer
from evidence_classifier import AIEvidenceClassifier, classify_with_ai

# ---------------------------------------------------------------------------
# Geoff internal modules
# ---------------------------------------------------------------------------
from geoff_config import *
from geoff_utils import *
from geoff_models import *
from geoff_self_heal import *
from geoff_discovery import *
from geoff_critic import GeoffCritic

# Wire module-level references for orchestrator routing
import geoff_utils as _gu
import geoff_self_heal as _gsh

# ---------------------------------------------------------------------------
# Module-level singleton references (set by geoff_integrated.py after init)
# ---------------------------------------------------------------------------

orchestrator = None
remnux_orchestrator = None
geoff_critic = None
geoff_forensicator = None

# ---------------------------------------------------------------------------
# Pipeline functions
# ---------------------------------------------------------------------------

def run_full_investigation(case_name: str, evidence_path: str = None):
    """Spawn background investigation worker for case with stable directory.

    Uses a hash of the evidence path to produce a stable work directory name.
    Restarting with the same evidence path resumes the investigation from the
    last checkpoint.
    """
    _ev_key = hashlib.sha256(str(Path(evidence_path).resolve()).encode()).hexdigest()[:12]
    case_work_dir = f"{case_name}_{_ev_key}"
    case_work_path = Path(CASES_WORK_DIR) / case_work_dir
    resuming = case_work_path.exists()
    try:
        case_work_path.mkdir(parents=True, exist_ok=True)
    except (PermissionError, OSError):
        case_work_path = Path(tempfile.gettempdir()) / "geoff-cases" / case_work_dir
        case_work_path.mkdir(parents=True, exist_ok=True)
        print(f"[GEOFF] Case work dir fallback: {case_work_path}", file=sys.stderr)

    # Log resume/start
    if resuming:
        print(f"[GEOFF] Resuming investigation from stable dir: {case_work_path}", file=sys.stderr)
    else:
        print(f"[GEOFF] Starting new investigation in: {case_work_path}", file=sys.stderr)

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
            find_evil(evidence_path, job_id=fe_job_id, case_work_dir=str(case_work_path))
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


# ---------------------------------------------------------------------------
# Batch Mode Helpers
# ---------------------------------------------------------------------------

def _preflight_validation(evidence_path: Path, case_work_dir: Path, job_id: str) -> list:
    """
    Preflight checks before starting a Find Evil run.
    Returns a list of warning strings (empty list = all clear).
    Raises ValueError for fatal conditions (missing evidence dir is handled by
    the caller; this function focuses on softer warnings).
    """
    warnings = []

    # Evidence directory must contain at least one file
    evidence_files = [f for f in evidence_path.rglob("*") if f.is_file()]
    if not evidence_files:
        warnings.append(f"Evidence directory {evidence_path} contains no files — inventory will be empty")

    # Verify git is available (needed for custody commits)
    git_check = safe_run(['git', '--version'], timeout=5)
    if git_check["code"] != 0:
        warnings.append("git not found in PATH — per-step custody commits will be skipped")

    # Verify case_work_dir parent is writable
    try:
        case_work_dir.parent.mkdir(parents=True, exist_ok=True)
        test_file = case_work_dir.parent / f".geoff_preflight_{uuid.uuid4().hex[:8]}"
        test_file.touch()
        test_file.unlink()
    except OSError as e:
        warnings.append(f"Case work dir parent not writable: {e}")

    if warnings:
        for w in warnings:
            _fe_log(job_id, f"  ⚠ Preflight: {w}")
    else:
        _fe_log(job_id, "  ✓ Preflight: all checks passed")
    return warnings


def _commit_step_with_custody(
    step_record: dict,
    evidence_file: str,
    case_work_dir: Path,
    job_id: str,
) -> dict:
    """
    Commit a single completed step result to git with chain-of-custody metadata.

    Writes a custody record alongside the step output, then commits.
    Returns the git commit result dict (same shape as safe_git_commit).
    Called for each completed step (~10s overhead per step for git commit).
    """
    step_key = step_record.get("step_key", "unknown")
    module = step_record.get("module", "unknown")
    function = step_record.get("function", "unknown")
    playbook_id = step_record.get("playbook", "unknown")

    # Chain-of-custody: hash evidence file + hash params
    evidence_sha256 = (
        _hash_file(evidence_file)
        if evidence_file and os.path.isfile(evidence_file)
        else "N/A"
    )
    params_hash = hashlib.sha256(
        json.dumps(step_record.get("params", {}), sort_keys=True, default=str).encode()
    ).hexdigest()[:16]

    custody = {
        "step_key": step_key,
        "playbook": playbook_id,
        "module": module,
        "function": function,
        "evidence_file": evidence_file,
        "evidence_sha256": evidence_sha256,
        "params_hash": params_hash,
        "status": step_record.get("status", "unknown"),
        "committed_at": datetime.now().isoformat(),
        "execution_hash": step_record.get("execution_hash", ""),
    }

    # Write custody sidecar to disk
    custody_dir = case_work_dir / "custody"
    custody_dir.mkdir(exist_ok=True)
    safe_key = step_key.replace(":", "_").replace("/", "_")[:120]
    custody_file = custody_dir / f"{safe_key}.json"
    try:
        _atomic_write(custody_file, json.dumps(custody, indent=2, default=str))
    except Exception as e:
        _fe_log(job_id, f"  ⚠ Custody write failed for {step_key}: {e}")

    ev_name = Path(evidence_file).name if evidence_file else "N/A"
    commit_msg = (
        f"step: {playbook_id}:{module}.{function} "
        f"[{step_record.get('status', 'unknown')}] "
        f"ev={ev_name} sha256={evidence_sha256[:12]}"
    )
    return safe_git_commit(commit_msg, base_path=str(case_work_dir))


def _run_forensicator_batch(
    execution_plan: list,
    device_map: dict,
    case_work_dir: Path,
    job_id: str,
) -> dict:
    """
    Batch mode orchestrator: logs the start of autonomous execution and returns
    metadata used by _manager_post_critic_decision.

    Actual step execution runs inside find_evil's existing per-device/playbook
    loop — per-step custody commits happen inside that loop.
    """
    total_templates = sum(
        sum(len(steps) for steps in PLAYBOOK_STEPS.get(pb, {}).values())
        for pb in execution_plan
        if pb in PLAYBOOK_STEPS
    )
    _fe_log(job_id, (
        f"  [BATCH] Autonomous execution: {len(execution_plan)} playbooks, "
        f"~{total_templates} step templates, {len(device_map)} device(s)"
    ))
    return {
        "mode": "batch",
        "playbooks_queued": len(execution_plan),
        "devices": list(device_map.keys()),
        "started_at": datetime.now().isoformat(),
    }



# =====================================================================
# Pass 2: Timeline Intelligence Analysis
# =====================================================================

def _timeline_intelligence_analysis(
    super_timeline_events: list,
    device_map: dict,
    indicator_hits: list = None,
    job_id: str = None,
    fe_log_func=None,
) -> dict:
    """Analyse the super timeline for cross-device patterns that warrant
    a second pass of targeted investigation.

    Returns a TimelineIntelligence dict with:
      - cross_device_process_chains
      - usb_lateral_movement
      - off_hours_clusters
      - file_beaconing_patterns
      - ioc_correlations
      - dwell_time_window
      - pass2_playbook_triggers
    """

    def _log(msg):
        if fe_log_func and job_id:
            fe_log_func(job_id, msg)

    intelligence = {
        "cross_device_process_chains": [],
        "usb_lateral_movement": [],
        "off_hours_clusters": [],
        "file_beaconing_patterns": [],
        "ioc_correlations": [],
        "dwell_time_window": {"first_seen": None, "last_seen": None, "dwell_days": 0},
        "pass2_playbook_triggers": [],
    }

    if not super_timeline_events or not device_map:
        return intelligence

    # Index events by device for fast lookup
    dev_events = {}
    for event in super_timeline_events:
        did = event.get("device_id", "")
        if did not in dev_events:
            dev_events[did] = []
        dev_events[did].append(event)

    # ---------------------------------------------------------------
    # 1. Cross-Device Process Chain Detection
    # ---------------------------------------------------------------
    _log("  Timeline Intel: scanning for cross-device process chains...")
    all_process_events = []
    for event in super_timeline_events:
        if event.get("event_type") in ("process_execution", "process_creation"):
            all_process_events.append(event)

    all_process_events.sort(key=lambda e: e.get("timestamp", ""))

    # Look for processes that have the same name appearing on different
    # devices within a short time window (indicating lateral movement)
    # or uncommon child-to-parent chains crossing device boundaries
    chain_keywords = ["psexec", "cmd.exe", "powershell.exe", "wmic.exe",
                      "winrm.exe", "schtasks.exe", "rundll32.exe",
                      "mshta.exe", "regsvr32.exe", "ntdsutil.exe",
                      "vssadmin.exe", "wscript.exe", "cscript.exe"]

    for proc_ev in all_process_events:
        detail = proc_ev.get("detail", {})
        proc_name = detail.get("name", "").lower() or detail.get("process_name", "").lower()
        if not proc_name:
            continue
        match_kw = None
        for kw in chain_keywords:
            if kw in proc_name:
                match_kw = kw
                break
        if not match_kw:
            continue

        # Find same or related process on other devices within 30 minutes
        ts = proc_ev.get("timestamp", "")
        try:
            from datetime import timedelta
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            window_end = dt + timedelta(minutes=30)
        except (ValueError, TypeError):
            continue

        related = []
        for other_ev in all_process_events:
            if other_ev.get("device_id") == proc_ev.get("device_id"):
                continue
            other_ts = other_ev.get("timestamp", "")
            try:
                other_dt = datetime.fromisoformat(other_ts.replace("Z", "+00:00"))
                if dt <= other_dt <= window_end:
                    other_detail = other_ev.get("detail", {})
                    other_name = other_detail.get("name", "").lower() or other_detail.get("process_name", "").lower()
                    if other_name and match_kw in other_name:
                        related.append(other_ev)
            except (ValueError, TypeError):
                continue

        if related and len(related) >= 1:
            devices_involved = list(set([proc_ev.get("device_id")] +
                                        [r.get("device_id") for r in related]))
            chain = {
                "root_process": proc_name,
                "source_device": proc_ev.get("device_id"),
                "source_timestamp": ts,
                "target_devices": list(set(r.get("device_id") for r in related)),
                "related_events": len(related),
                "devices_involved": devices_involved,
                "time_window": {
                    "start": ts,
                    "end": max(r.get("timestamp", ts) for r in related),
                },
            }
            intelligence["cross_device_process_chains"].append(chain)

            # Generate Pass 2 trigger
            trigger = {
                "trigger_id": f"trigger-chain-{proc_name}-{hash(ts) % 10000:04d}",
                "trigger_type": "cross_device_process_chain",
                "playbook_id": PASS2_TRIGGER_PLAYBOOK_MAP.get("cross_device_process_chain", "PB-SIFT-100"),
                "priority": "HIGH",
                "devices_involved": devices_involved,
                "time_window": chain["time_window"],
                "context": {
                    "root_process": proc_name,
                    "source_device": proc_ev.get("device_id"),
                    "chain_length": len(related),
                },
                "investigation_questions": [
                    f"How did {proc_name} execute on {proc_ev.get('device_id')}?",
                    f"What artifacts link {proc_name} across devices?",
                ],
            }
            # Deduplicate — one trigger per matched process keyword
            if not any(t["trigger_type"] == trigger["trigger_type"] and
                       all(d in t["devices_involved"] for d in devices_involved)
                       for t in intelligence["pass2_playbook_triggers"]):
                intelligence["pass2_playbook_triggers"].append(trigger)

    if intelligence["cross_device_process_chains"]:
        _log(f"  ✓ Found {len(intelligence['cross_device_process_chains'])} cross-device process chains")

    # ---------------------------------------------------------------
    # 2. USB Lateral Movement Detection
    # ---------------------------------------------------------------
    _log("  Timeline Intel: scanning for USB serial number correlations...")
    usb_events_by_serial = {}
    for event in super_timeline_events:
        detail = event.get("detail", {})
        key = detail.get("key", "").lower()
        value = detail.get("raw", "").lower() if isinstance(detail.get("raw"), str) else ""
        # Look for USBSTOR or mounted devices entries
        if ("usbstor" in key or "usb" in key or "mounteddevice" in key or
            "usb" in str(detail).lower()):
            # Extract serial numbers using common patterns
            for match in re.finditer(
                r'(?:VEN_[A-Fa-f0-9]{4}&PROD_[A-Fa-f0-9]{4}|[A-Fa-f0-9]{8}&[A-Fa-f0-9]{4}|[0-9A-Z]{10,})',
                str(detail)
            ):
                serial = match.group(0).upper()
                if serial not in usb_events_by_serial:
                    usb_events_by_serial[serial] = []
                usb_events_by_serial[serial].append(event)
        # Also check summary for USB references
        if "usb" in event.get("summary", "").lower():
            summary = event.get("summary", "")
            for match in re.finditer(
                r'(?:VEN_[A-Fa-f0-9]{4}&PROD_[A-Fa-f0-9]{4}|[A-Fa-f0-9]{8}&[A-Fa-f0-9]{4}|[0-9A-Z]{10,})',
                summary
            ):
                serial = match.group(0).upper()
                if serial not in usb_events_by_serial:
                    usb_events_by_serial[serial] = []
                usb_events_by_serial[serial].append(event)

    for serial, events in usb_events_by_serial.items():
        # A USB device seen on multiple hosts = lateral movement candidate
        devices_with_serial = set(e.get("device_id") for e in events)
        if len(devices_with_serial) >= 2:
            timestamps = sorted(e.get("timestamp", "") for e in events if e.get("timestamp"))
            if len(timestamps) >= 2:
                usb_movement = {
                    "serial_number": serial,
                    "devices_involved": sorted(devices_with_serial),
                    "event_count": len(events),
                    "time_window": {
                        "start": timestamps[0],
                        "end": timestamps[-1],
                    },
                }
                intelligence["usb_lateral_movement"].append(usb_movement)

                trigger = {
                    "trigger_id": f"trigger-usb-{serial[:8]}",
                    "trigger_type": "usb_lateral_movement",
                    "playbook_id": PASS2_TRIGGER_PLAYBOOK_MAP.get("usb_lateral_movement", "PB-SIFT-101"),
                    "priority": "HIGH",
                    "devices_involved": sorted(devices_with_serial),
                    "time_window": usb_movement["time_window"],
                    "context": {"serial_number": serial},
                    "investigation_questions": [
                        f"What files were accessed on USB {serial}?",
                        f"Which user performed the USB movement between {list(devices_with_serial)}?",
                    ],
                }
                intelligence["pass2_playbook_triggers"].append(trigger)

    if intelligence["usb_lateral_movement"]:
        _log(f"  ✓ Found {len(intelligence['usb_lateral_movement'])} USB lateral movement patterns")

    # ---------------------------------------------------------------
    # 3. Off-Hours Activity Clusters
    # ---------------------------------------------------------------
    _log("  Timeline Intel: scanning for off-hours activity clusters...")
    off_hours = []
    significant_types = ("process_execution", "process_creation", "file_creation",
                         "login", "network_connection", "service_change")
    for event in super_timeline_events:
        ts = event.get("timestamp", "")
        if not ts:
            continue
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            hour = dt.hour
            if hour >= 22 or hour < 5:
                if event.get("event_type") in significant_types:
                    off_hours.append(event)
        except (ValueError, TypeError):
            continue

    if len(off_hours) >= 3:
        # Cluster by 15-minute windows across devices
        clusters = {}
        for event in off_hours:
            try:
                dt = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
                # Round to 15-min window
                rounded = dt.replace(minute=(dt.minute // 15) * 15, second=0, microsecond=0)
                window_key = rounded.isoformat()[:16]
            except (ValueError, TypeError):
                continue
            if window_key not in clusters:
                clusters[window_key] = []
            clusters[window_key].append(event)

        for window_key, cluster_events in clusters.items():
            devices_in_window = set(e.get("device_id") for e in cluster_events)
            if len(devices_in_window) >= 2:
                timestamps = sorted(e.get("timestamp", "") for e in cluster_events if e.get("timestamp"))
                off_hours_cluster = {
                    "time_window": window_key,
                    "devices_involved": sorted(devices_in_window),
                    "event_count": len(cluster_events),
                    "sample_events": cluster_events[:5],
                    "time_range": {
                        "start": timestamps[0] if timestamps else "",
                        "end": timestamps[-1] if timestamps else "",
                    },
                }
                intelligence["off_hours_clusters"].append(off_hours_cluster)

                trigger = {
                    "trigger_id": f"trigger-offhours-{window_key.replace(':', '').replace('-', '')}",
                    "trigger_type": "off_hours_cluster",
                    "playbook_id": PASS2_TRIGGER_PLAYBOOK_MAP.get("off_hours_cluster", "PB-SIFT-102"),
                    "priority": "MEDIUM",
                    "devices_involved": sorted(devices_in_window),
                    "time_window": {
                        "start": timestamps[0] if timestamps else "",
                        "end": timestamps[-1] if timestamps else "",
                    },
                    "context": {"cluster_window": window_key, "sample_events": len(cluster_events)},
                    "investigation_questions": [
                        f"What triggered activity at {window_key} across {len(devices_in_window)} devices?",
                        "Were scheduled tasks or WMI subscriptions active?",
                    ],
                }
                if not any(t["trigger_type"] == trigger["trigger_type"] and
                           t.get("context", {}).get("cluster_window") == window_key
                           for t in intelligence["pass2_playbook_triggers"]):
                    intelligence["pass2_playbook_triggers"].append(trigger)

    if intelligence["off_hours_clusters"]:
        _log(f"  ✓ Found {len(intelligence['off_hours_clusters'])} off-hours clusters")

    # ---------------------------------------------------------------
    # 4. File Beaconing / Staging Patterns
    # ---------------------------------------------------------------
    _log("  Timeline Intel: scanning for file beaconing/staging patterns...")
    temp_pattern = re.compile(r'(?:\\Temp\\|/tmp/|\.tmp$|\.dat$)', re.IGNORECASE)
    file_events_by_device = {}
    for event in super_timeline_events:
        if event.get("event_type") not in ("file_creation", "file_modification",
                                            "file_deletion"):
            continue
        detail = event.get("detail", {})
        path = detail.get("path", "").lower() or event.get("summary", "").lower()
        if not temp_pattern.search(path):
            continue
        did = event.get("device_id", "")
        if did not in file_events_by_device:
            file_events_by_device[did] = []
        file_events_by_device[did].append(event)

    for did, events in file_events_by_device.items():
        if len(events) < 4:
            continue
        # Sort and look for regular intervals
        try:
            sorted_ts = []
            for e in events:
                ts = e.get("timestamp", "")
                if ts:
                    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                    sorted_ts.append((dt, e))
            sorted_ts.sort(key=lambda x: x[0])
            if len(sorted_ts) < 4:
                continue
            intervals = []
            for i in range(1, len(sorted_ts)):
                intervals.append((sorted_ts[i][0] - sorted_ts[i-1][0]).total_seconds())
            if not intervals:
                continue
            avg_interval = sum(intervals) / len(intervals)
            variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
            if avg_interval > 0 and variance ** 0.5 / avg_interval < 0.3 and len(intervals) >= 3:
                beacon = {
                    "device_id": did,
                    "file_count": len(sorted_ts),
                    "avg_interval_seconds": round(avg_interval, 1),
                    "time_window": {
                        "start": sorted_ts[0][0].isoformat()[:19] + "Z",
                        "end": sorted_ts[-1][0].isoformat()[:19] + "Z",
                    },
                }
                intelligence["file_beaconing_patterns"].append(beacon)
                # Link this to the time window trigger
                if not any(t.get("context", {}).get("device_id") == did and
                           "beacon" in t.get("trigger_id", "")
                           for t in intelligence["pass2_playbook_triggers"]):
                    trigger = {
                        "trigger_id": f"trigger-beacon-{did}",
                        "trigger_type": "file_beaconing",
                        "playbook_id": PASS2_TRIGGER_PLAYBOOK_MAP.get("file_beaconing", "PB-SIFT-103"),
                        "priority": "HIGH",
                        "devices_involved": [did],
                        "time_window": beacon["time_window"],
                        "context": beacon,
                        "investigation_questions": [
                            f"What process created the temp files on {did}?",
                            f"Is the beacon interval {avg_interval:.0f}s associated with known malware families?",
                        ],
                    }
                    intelligence["pass2_playbook_triggers"].append(trigger)
        except (ValueError, TypeError):
            continue

    if intelligence["file_beaconing_patterns"]:
        _log(f"  ✓ Found {len(intelligence['file_beaconing_patterns'])} file beaconing patterns")

    # ---------------------------------------------------------------
    # 5. Cross-Device IOC Correlation
    # ---------------------------------------------------------------
    _log("  Timeline Intel: scanning for cross-device IOC correlations...")
    # Collect IOCs from indicator hits and findings
    known_iocs = set()
    if indicator_hits:
        for hit in indicator_hits:
            if isinstance(hit, dict):
                pattern = hit.get("pattern", "")
                if pattern and len(pattern) > 4:
                    known_iocs.add(pattern.lower())

    # Look for co-occurring suspicious patterns across devices
    dev_ioc_sets = {}
    for event in super_timeline_events:
        if not event.get("suspicious"):
            continue
        did = event.get("device_id", "")
        reason = (event.get("suspicion_reason") or "").lower()
        summary = (event.get("summary") or "").lower()
        detail = event.get("detail", {})
        detail_str = str(detail).lower()

        if did not in dev_ioc_sets:
            dev_ioc_sets[did] = set()

        for ioc in known_iocs:
            if ioc in summary or ioc in detail_str or ioc in reason:
                dev_ioc_sets[did].add(ioc)

    # Find IOCs shared across multiple devices
    for ioc in known_iocs:
        devices_with_ioc = [did for did, iocs in dev_ioc_sets.items() if ioc in iocs]
        if len(devices_with_ioc) >= 2:
            ioc_corr = {
                "ioc": ioc,
                "devices_involved": sorted(devices_with_ioc),
                "device_count": len(devices_with_ioc),
            }
            intelligence["ioc_correlations"].append(ioc_corr)

            trigger = {
                "trigger_id": f"trigger-ioc-{hash(ioc) % 10000:04d}",
                "trigger_type": "ioc_correlation",
                "playbook_id": PASS2_TRIGGER_PLAYBOOK_MAP.get("ioc_correlation", "PB-SIFT-103"),
                "priority": "HIGH",
                "devices_involved": sorted(devices_with_ioc),
                "time_window": {"start": "", "end": ""},  # Full scope
                "context": {"ioc": ioc, "device_count": len(devices_with_ioc)},
                "investigation_questions": [
                    f"How was IOC '{ioc}' deployed across {len(devices_with_ioc)} devices?",
                    f"What is the deployment timeline for '{ioc}'?",
                ],
            }
            intelligence["pass2_playbook_triggers"].append(trigger)

    if intelligence["ioc_correlations"]:
        _log(f"  ✓ Found {len(intelligence['ioc_correlations'])} cross-device IOC correlations")

    # ---------------------------------------------------------------
    # 6. Dwell Time Window Calculation
    # ---------------------------------------------------------------
    _log("  Timeline Intel: calculating dwell time window...")
    all_timestamps = []
    for event in super_timeline_events:
        ts = event.get("timestamp", "")
        if not ts:
            continue
        if event.get("suspicious") or "suspicious" not in event:
            all_timestamps.append(ts)

    if all_timestamps:
        all_timestamps.sort()
        first = all_timestamps[0]
        last = all_timestamps[-1]
        try:
            t0 = datetime.fromisoformat(first.replace("Z", "+00:00")[:19])
            t1 = datetime.fromisoformat(last.replace("Z", "+00:00")[:19])
            dwell_days = round((t1 - t0).total_seconds() / 86400, 2)
        except (ValueError, TypeError):
            dwell_days = 0
        intelligence["dwell_time_window"] = {
            "first_seen": first,
            "last_seen": last,
            "dwell_days": dwell_days,
        }

    # Auto-trigger dwell window deep-dive for multi-day dwells
    if intelligence["dwell_time_window"]["dwell_days"] > 1:
        dw = intelligence["dwell_time_window"]
        trigger = {
            "trigger_id": f"trigger-dwell-{dw['dwell_days']}d",
            "trigger_type": "dwell_window",
            "playbook_id": PASS2_TRIGGER_PLAYBOOK_MAP.get("dwell_window", "PB-SIFT-104"),
            "priority": "MEDIUM",
            "devices_involved": sorted(device_map.keys()),
            "time_window": {"start": dw["first_seen"], "end": dw["last_seen"]},
            "context": {"dwell_days": dw["dwell_days"]},
            "investigation_questions": [
                "What user activity occurred across the full dwell window?",
                "Are there gaps or bursts that align with attacker behavior?",
            ],
        }
        intelligence["pass2_playbook_triggers"].append(trigger)

    _log(f"  Dwell time: {intelligence['dwell_time_window']['dwell_days']} days")
    _log(f"  Pass 2 triggers generated: {len(intelligence['pass2_playbook_triggers'])}")

    return intelligence


def _manager_review_pass2_triggers(
    triggers: list,
    pass1_findings: list,
    job_id: str = None,
    fe_log_func=None,
) -> list:
    """Manager LLM reviews Pass 2 triggers and filters/approves them.

    Calls the Manager LLM to review each trigger against Pass 1 findings.
    Has a template fallback: if LLM is unavailable, approve up to 3
    highest-priority triggers.

    Returns a list of approved triggers.
    """

    def _log(msg):
        if fe_log_func and job_id:
            fe_log_func(job_id, msg)

    if not triggers:
        _log("  Manager Pass 2 Review: no triggers to review")
        return []

    _log(f"  Manager Pass 2 Review: {len(triggers)} candidate triggers")

    # Try LLM review
    try:
        trigger_snippets = []
        for t in triggers[:10]:  # Cap at 10 for context window
            trigger_snippets.append({
                "trigger_id": t.get("trigger_id", ""),
                "trigger_type": t.get("trigger_type", ""),
                "playbook_id": t.get("playbook_id", ""),
                "priority": t.get("priority", ""),
                "devices_involved": t.get("devices_involved", []),
                "questions": t.get("investigation_questions", [])[:2],
            })

        pass1_summary = {
            "total_findings": len(pass1_findings),
            "high_critical": len([f for f in pass1_findings
                                  if isinstance(f.get("forensicator"), dict)
                                  and f["forensicator"].get("significance") in ("CRITICAL", "HIGH")]),
        }

        prompt = f"""You are the Manager. Review these Pass 2 investigation triggers.

PASS 1 SUMMARY: {json.dumps(pass1_summary)}
CANDIDATE TRIGGERS: {json.dumps(trigger_snippets, indent=2)}

Decide which triggers to pursue. Consider:
- Is the evidence strong enough to warrant a second pass?
- Do multiple triggers overlap and can be combined?
- Is the potential impact worth the additional analysis time?
- Max 3 high-priority triggers for any single investigation.

Respond ONLY in valid JSON:
{{"approved_trigger_ids": ["id1", "id2"], "reasoning": "one sentence"}}"""

        _log("  ▶ Manager: reviewing Pass 2 triggers...")
        raw = _call_manager_llm(prompt, timeout=120)
        if raw:
            m = re.search(r'\{.*\}', raw, re.DOTALL)
            if m:
                parsed = json.loads(m.group())
                approved_ids = parsed.get("approved_trigger_ids", [])
                if approved_ids:
                    approved = [t for t in triggers if t.get("trigger_id") in approved_ids]
                    _log(f"  ✓ Manager approved {len(approved)}/{len(triggers)} triggers: {parsed.get('reasoning', '')}")
                    return approved[:3]  # Cap at 3
    except Exception as e:
        _log(f"  ⚠ Manager review LLM error: {e} — using template fallback")

    # Template fallback: approve highest-priority up to 3
    _log("  ↳ Falling back to template: approve up to 3 highest-priority triggers")
    priority_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    sorted_triggers = sorted(triggers, key=lambda t: priority_order.get(t.get("priority", "LOW"), 4))

    # Deduplicate by trigger_type (only one per type)
    seen_types = set()
    approved = []
    for t in sorted_triggers:
        ttype = t.get("trigger_type", "")
        if ttype not in seen_types:
            seen_types.add(ttype)
            approved.append(t)
            if len(approved) >= 3:
                break

    _log(f"  ✓ Template fallback approved {len(approved)} triggers")
    return approved


def _execute_pass2(
    triggers: list,
    device_map: dict,
    case_work_dir: Path,
    findings_writer,
    image_offsets: dict,
    inventory: dict,
    job_id: str = None,
    fe_log_func=None,
) -> dict:
    """Execute targeted Pass 2 playbooks driven by timeline intelligence.

    Key differences from Pass 1:
    - Only triggered playbooks run (not all 33)
    - Playbooks receive time_window and device filter params
    - Plaso queries are filtered to the investigation window
    - Results feed into pass2_findings.jsonl separate from Pass 1 findings

    Returns dict with pass2 summary.
    """

    def _log(msg):
        if fe_log_func and job_id:
            fe_log_func(job_id, msg)

    if not triggers:
        _log("  Pass 2: no approved triggers — skipping")
        return {"triggers_processed": 0, "playbooks_run": [], "findings_count": 0}

    _log(f"\n{'='*60}")
    _log(f"PASS 2: Targeted Timeline-Driven Investigation")
    _log(f"{'='*60}")
    _log(f"  Approved triggers: {len(triggers)}")

    output_dir = str(case_work_dir / "output")
    pass2_findings_path = case_work_dir / "findings_pass2.jsonl"
    pass2_writer = FindingsWriter(pass2_findings_path, job_id=job_id)

    playbooks_run = []
    steps_completed = 0
    steps_failed = 0
    steps_skipped = 0

    # Build per-device evidence lookup
    device_evidence = {}
    for dev_id, dev in device_map.items():
        device_evidence[dev_id] = {
            "disk_images": [], "memory_dumps": [], "pcaps": [],
            "evtx_logs": [], "evt_logs": [], "syslogs": [], "registry_hives": [],
            "mobile_backups": [], "other_files": [],
        }
        for fpath in dev.get("evidence_files", []):
            for ev_type in inventory:
                if isinstance(inventory[ev_type], list) and fpath in inventory[ev_type]:
                    device_evidence[dev_id][ev_type].append(fpath)

    for trigger_idx, trigger in enumerate(triggers):
        playbook_id = trigger.get("playbook_id", "")
        trigger_type = trigger.get("trigger_type", "")
        pb_name = PLAYBOOK_NAMES_PASS2.get(playbook_id, playbook_id)

        if playbook_id not in PLAYBOOK_STEPS_PASS2:
            _log(f"  ✗ Pass 2: playbook {playbook_id} not defined — skipping")
            continue

        _log(f"\n  ▶ Pass 2 [{trigger_idx+1}/{len(triggers)}]: {playbook_id} ({pb_name})")
        _log(f"    Trigger: {trigger_type} | Devices: {', '.join(trigger.get('devices_involved', []))}")

        pb_steps_def = PLAYBOOK_STEPS_PASS2[playbook_id]
        pb_findings = []
        time_window = trigger.get("time_window", {})
        trigger_context = trigger.get("context", {})

        for dev_id in trigger.get("devices_involved", []):
            dev = device_map.get(dev_id)
            if not dev:
                continue
            if (playbook_id, dev_id) in completed_pb_dev:
                playbooks_run.append({"playbook_id": playbook_id, "device_id": dev_id, "steps_attempted": 0, "steps_completed": 0, "resumed": True})
                _fe_log(job_id, f"  Resume: skipping {playbook_id} [{dev_id}]")
                continue
            dev_ev = device_evidence.get(dev_id, {})

            for ev_type, step_templates in pb_steps_def.items():
                evidence_items = dev_ev.get(ev_type, [])
                if not evidence_items:
                    continue

                # Limit to first 2 items per evidence type for Pass 2
                items = evidence_items[:2]

                for item in items:
                    try:
                        _validate_evidence_path(item)
                    except ValueError:
                        continue

                    # For other_files, only invoke email analysis on actual email files.
                    if ev_type == "other_files":
                        if Path(item).suffix.lower() not in _EMAIL_EXTENSIONS:
                            continue

                    item_stem = Path(item).stem

                    for module, function, raw_params in step_templates:
                        # Build params with time window and trigger context
                        params = {}
                        for k, v in raw_params.items():
                            if isinstance(v, str):
                                v = v.replace("{image}", item)
                                v = v.replace("{mem}", item)
                                v = v.replace("{pcap}", item)
                                v = v.replace("{evtx}", item)
                                v = v.replace("{evt}", item)
                                v = v.replace("{syslog}", item)
                                v = v.replace("{hive}", item)
                                v = v.replace("{mobile}", str(Path(item).parent))
                                v = v.replace("{file}", item)
                                v = v.replace("{output_dir}", output_dir)
                                v = v.replace("{image_stem}", item_stem)
                                v = v.replace("{offset}", str(image_offsets.get(item, 2048)))
                                # Time window params
                                v = v.replace("{time_window_start}", str(time_window.get("start", "")))
                                v = v.replace("{time_window_end}", str(time_window.get("end", "")))
                                v = v.replace("{dwell_start}", str(time_window.get("start", "")))
                                v = v.replace("{dwell_end}", str(time_window.get("end", "")))
                                # Context-driven params (derived from trigger context or defaults)
                                v = v.replace("{target_inodes}", str(trigger_context.get("target_inodes", "")))
                                v = v.replace("{target_pids}", str(trigger_context.get("target_pids", "")))
                                v = v.replace("{ioc_ips}", str(trigger_context.get("ioc_ips", "")))
                                v = v.replace("{ioc_patterns}", str(trigger_context.get("ioc_patterns", trigger_context.get("ioc", ""))))
                                v = v.replace("{filter_patterns}", str(trigger_context.get("filter_patterns", "")))
                                v = v.replace("{target_hosts}", ",".join(trigger.get("devices_involved", [])))
                                v = v.replace("{target_paths}", str(trigger_context.get("target_paths", "")))
                                # Registry hive params are handled via {hive} substitution above
                                # (autoruns_hive / services_hive removed — use {hive} in playbook defs)
                            elif isinstance(v, dict):
                                v = {sk: str(sv).replace("{dwell_start}", str(time_window.get("start", "")))
                                     .replace("{dwell_end}", str(time_window.get("end", "")))
                                     .replace("{time_window}", str(time_window))
                                     .replace("{target_hosts}", ",".join(trigger.get("devices_involved", [])))
                                     for sk, sv in v.items()}
                            params[k] = v

                        # Convert numeric string params
                        for k, v_conv in list(params.items()):
                            if isinstance(v_conv, str) and v_conv.isdigit():
                                params[k] = int(v_conv)
                            elif isinstance(v_conv, str) and v_conv.lower() in ('true', 'false'):
                                params[k] = v_conv.lower() == 'true'

                        step_key = f"pass2:{playbook_id}:{module}:{function}:{Path(item).name}"
                        execution_hash = hashlib.md5(
                            f"{step_key}:{json.dumps(params, sort_keys=True, default=str)}".encode()
                        ).hexdigest()[:12]

                        # Idempotency
                        if pass2_writer.is_completed(step_key):
                            continue

                        step_record = {
                            "step_key": step_key,
                            "execution_hash": execution_hash,
                            "playbook": playbook_id,
                            "module": module,
                            "function": function,
                            "params": params,
                            "evidence_file": item,
                            "device_id": dev_id,
                            "owner": dev.get("owner"),
                            "pass": 2,
                            "trigger_type": trigger_type,
                            "trigger_id": trigger.get("trigger_id", ""),
                            "status": "running",
                            "started_at": datetime.now().isoformat(),
                        }

                        try:
                            result = _run_step_via_orchestrator(module, function, params)
                            step_status = result.get("status", "error")
                            if step_status == "error" and "not found" in str(result.get("error", "")).lower():
                                step_record["status"] = "skipped"
                                steps_skipped += 1
                            elif step_status == "success":
                                step_record["status"] = "completed"
                                steps_completed += 1
                                # Quick forensicator interpretation
                                try:
                                    if 'geoff_forensicator' in dir() or 'geoff_forensicator' in globals():
                                        fn_notes = geoff_forensicator.interpret_step_result(
                                            playbook_id=playbook_id,
                                            module=module,
                                            function=function,
                                            params=params,
                                            result=result,
                                            device_context={"device_id": dev_id},
                                        )
                                        step_record["forensicator"] = fn_notes
                                except Exception:
                                    pass
                            else:
                                step_record["status"] = "failed"
                                steps_failed += 1

                            step_record["result"] = result
                        except Exception as e:
                            step_record["status"] = "failed"
                            step_record["error"] = str(e)
                            steps_failed += 1

                        step_record["completed_at"] = datetime.now().isoformat()
                        pass2_writer.append(step_record)
                        pb_findings.append(step_record)

        playbooks_run.append({
            "playbook_id": playbook_id,
            "pass": 2,
            "trigger_type": trigger_type,
            "steps_attempted": len(pb_findings),
            "steps_completed": sum(1 for s in pb_findings if s.get("status") == "completed"),
            "steps_failed": sum(1 for s in pb_findings if s.get("status") == "failed"),
            "steps_skipped": sum(1 for s in pb_findings if s.get("status") == "skipped"),
        })

        # Write pass2 playbook output
        try:
            pb_output = case_work_dir / "output" / f"{playbook_id}_pass2.json"
            _atomic_write(pb_output, json.dumps(pb_findings, default=str, indent=2))
        except Exception:
                pass

        _log(f"    ✓ {playbook_id}: {len(pb_findings)} steps")

    pass2_findings = pass2_writer.all_records()
    _log(f"\n  Pass 2 complete: {len(playbooks_run)} playbooks, {len(pass2_findings)} findings")
    _log(f"    Completed: {steps_completed} | Failed: {steps_failed} | Skipped: {steps_skipped}")

    return {
        "triggers_processed": len(triggers),
        "playbooks_run": playbooks_run,
        "findings_count": len(pass2_findings),
        "findings": pass2_findings,
        "findings_path": str(pass2_findings_path),
        "steps_completed": steps_completed,
        "steps_failed": steps_failed,
        "steps_skipped": steps_skipped,
    }


def _batch_critic_review_all_playbooks(
    findings: list,
    playbooks_run: list,
    case_work_dir: Path,
    job_id: str,
) -> dict:
    """
    Post-execution batch Critic review: assess ALL collected findings in one pass.

    Groups findings by status and significance, asks the Critic LLM for a holistic
    assessment, and returns a structured summary that the Manager uses to decide
    whether to approve, flag, or trigger incremental replay.
    """
    completed   = [f for f in findings if f.get("status") == "completed"]
    unverified  = [f for f in findings if f.get("status") == "completed_unverified"]
    failed      = [f for f in findings if f.get("status") == "failed"]
    needs_review = [f for f in findings if f.get("needs_review")]
    high_critical = [
        f for f in completed
        if f.get("forensicator", {}).get("significance") in ("CRITICAL", "HIGH")
    ]

    summary = {
        "total_findings": len(findings),
        "completed": len(completed),
        "unverified": len(unverified),
        "failed": len(failed),
        "needs_review": len(needs_review),
        "high_critical_findings": len(high_critical),
        "playbooks_run": len(playbooks_run),
    }

    _fe_log(job_id, (
        f"  [BATCH-CRITIC] {summary['completed']} ok | "
        f"{summary['unverified']} unverified | "
        f"{summary['failed']} failed | "
        f"{summary['high_critical_findings']} HIGH/CRITICAL"
    ))

    # Build concise finding snippets for the LLM (cap at 50)
    finding_snippets = []
    for f in (high_critical + unverified)[:50]:
        finding_snippets.append({
            "step_key": f.get("step_key", ""),
            "status": f.get("status", ""),
            "significance": f.get("forensicator", {}).get("significance", "UNKNOWN"),
            "analyst_note": f.get("forensicator", {}).get("analyst_note", ""),
            "needs_review": f.get("needs_review", False),
            "unverified_reason": f.get("unverified_reason"),
        })

    prompt = f"""You are the Critic agent in a DFIR batch investigation. All playbooks have completed.
Review the batch findings summary and provide a holistic assessment.

BATCH SUMMARY:
{json.dumps(summary, indent=2)}

HIGH/CRITICAL AND UNVERIFIED FINDINGS (up to 50):
{json.dumps(finding_snippets, indent=2, default=str)}

Assess the batch:
1. Are there findings that are clearly unsupported by evidence (hallucinations)?
2. Are there HIGH/CRITICAL findings that need replay with different params?
3. Are findings sufficient to generate a report, or is the evidence too sparse?

Respond ONLY in valid JSON (no extra text):
{{
    "overall_quality": "GOOD|ACCEPTABLE|POOR",
    "hallucination_flags": ["step_key or description of suspect finding"],
    "replay_candidates": ["step_key"],
    "sufficient_for_report": true,
    "assessment_summary": "one sentence"
}}"""

    geoff_critic_instance = GeoffCritic()
    raw = geoff_critic_instance._call_critic_llm(prompt)
    batch_assessment = {}
    try:
        m = re.search(r'\{.*\}', raw, re.DOTALL)
        if m:
            batch_assessment = json.loads(m.group())
    except Exception as e:
        _fe_log(job_id, f"  ⚠ Batch critic parse error: {e} — using defaults")

    # Write batch assessment to disk
    _atomic_write(
        case_work_dir / "batch_critic_assessment.json",
        json.dumps({**summary, "llm_assessment": batch_assessment}, indent=2, default=str),
    )
    _fe_log(job_id, (
        f"  [BATCH-CRITIC] Quality: {batch_assessment.get('overall_quality', 'N/A')} | "
        f"Report: {batch_assessment.get('sufficient_for_report', True)}"
    ))
    return {**summary, "llm_assessment": batch_assessment}


def _manager_post_critic_decision(
    batch_assessment: dict,
    findings: list,
    case_work_dir: Path,
    job_id: str,
) -> dict:
    """
    Manager reviews the batch Critic assessment and decides on next action.

    Returns a decision dict with keys:
    - action:             "approve" | "flag" | "replay"
    - replay_adjustments: {step_key: {param_key: new_value}}  (populated on "replay")
    - generate_report:    bool — whether to generate the narrative report
    - reasoning:          str
    """
    llm_assessment    = batch_assessment.get("llm_assessment", {})
    overall_quality   = llm_assessment.get("overall_quality", "ACCEPTABLE")
    replay_candidates = llm_assessment.get("replay_candidates", [])
    sufficient        = llm_assessment.get("sufficient_for_report", True)

    # Fast-path: quality GOOD and nothing to replay → approve immediately
    if overall_quality == "GOOD" and not replay_candidates:
        decision = {
            "action": "approve",
            "replay_adjustments": {},
            "generate_report": sufficient,
            "reasoning": "Batch quality GOOD, no replay candidates identified by Critic",
        }
        _fe_log(job_id, f"  [MANAGER] Decision: APPROVE | Report: {decision['generate_report']}")
        _atomic_write(case_work_dir / "manager_decision.json", json.dumps(decision, indent=2))
        return decision

    # Build context for replay candidates
    replay_snippets = {}
    for sk in replay_candidates[:10]:
        rec = next((f for f in findings if f.get("step_key") == sk), {})
        replay_snippets[sk] = {
            "params": rec.get("params", {}),
            "error": rec.get("error"),
            "status": rec.get("status"),
        }

    prompt = f"""You are the Manager agent in a DFIR batch investigation. The Critic has assessed all findings.

CRITIC ASSESSMENT:
- Overall quality: {overall_quality}
- Hallucination flags: {llm_assessment.get('hallucination_flags', [])}
- Replay candidates: {replay_candidates}
- Sufficient for report: {sufficient}
- Summary: {llm_assessment.get('assessment_summary', '')}

REPLAY CANDIDATE DETAILS:
{json.dumps(replay_snippets, indent=2, default=str)}

Decide on the next action. For replay candidates provide adjusted params that may produce better results.

Respond ONLY in valid JSON (no extra text):
{{
    "action": "approve",
    "replay_adjustments": {{"step_key": {{"param_key": "new_value"}}}},
    "generate_report": true,
    "reasoning": "one sentence"
}}"""

    _fe_log(job_id, (
        f"  [MANAGER] Reviewing batch assessment "
        f"(quality={overall_quality}, {len(replay_candidates)} replay candidates)..."
    ))
    raw = _call_manager_llm(prompt, timeout=180)
    decision = {
        "action": "approve",
        "replay_adjustments": {},
        "generate_report": sufficient,
        "reasoning": "Manager LLM unavailable — defaulting to approve",
    }
    try:
        m = re.search(r'\{.*\}', raw, re.DOTALL)
        if m:
            parsed = json.loads(m.group())
            decision["action"]             = parsed.get("action", "approve")
            decision["replay_adjustments"] = parsed.get("replay_adjustments", {})
            decision["generate_report"]    = parsed.get("generate_report", sufficient)
            decision["reasoning"]          = parsed.get("reasoning", "")
    except Exception as e:
        _fe_log(job_id, f"  ⚠ Manager decision parse error: {e} — defaulting to approve")

    _fe_log(job_id, (
        f"  [MANAGER] Decision: {decision['action'].upper()} | "
        f"Report: {decision['generate_report']} | {decision['reasoning']}"
    ))
    _atomic_write(case_work_dir / "manager_decision.json", json.dumps(decision, indent=2))
    return decision


def _retry_unprocessed(
    findings_writer,
    inventory: dict,
    image_offsets: dict,
    case_work_dir: Path,
    evidence_path: Path,
    execution_plan: list,
    job_id: str = None,
    fe_log_func=None,
) -> dict:
    """Post-run retry phase for unprocessed evidence files.

    Called after the main find_evil() pipeline completes and before
    report generation.  Attempts to reprocess files that were:
      - skipped/failed with "step_skipped_or_failed"
      - capped with "item_cap_exceeded"

    Re-runs the relevant discovery/playbook steps with relaxed limits
    and logs retry attempts and results.  Updated findings are appended
    to the findings_writer so that severity counting and report
    generation include the retry results.

    Returns a summary dict: {"retried": N, "succeeded": N, "failed": N}.
    """

    def _log(msg):
        if fe_log_func and job_id:
            fe_log_func(job_id, msg)

    _log("\n\U0001F501 Post-Run Retry: reprocessing unprocessed evidence files")

    # Build the current processed-paths set from findings_writer
    processed_paths = set()
    for rec in findings_writer.all_records():
        ef = rec.get("evidence_file")
        if ef:
            processed_paths.add(str(ef))

    all_paths = _all_inventory_paths(inventory)
    unprocessed = _classify_unprocessed(
        all_paths, processed_paths, inventory, execution_plan
    )

    retryable = [
        u for u in unprocessed
        if u["reason"] in ("step_skipped_or_failed", "item_cap_exceeded")
    ]

    if not retryable:
        _log("  No retryable unprocessed files")
        return {"retried": 0, "succeeded": 0, "failed": 0}

    _log(f"  {len(retryable)} retryable files ({len(unprocessed)} total unprocessed)")

    retried = 0
    succeeded = 0
    failed = 0
    output_dir = str(case_work_dir / "output")

    for entry in retryable:
        path = entry["path"]
        ev_type = entry.get("evidence_type")
        reason = entry["reason"]

        if not Path(path).exists():
            _log(f"  \u23D8 {Path(path).name}: file gone \u2014 skip")
            continue

        # Find a playbook that covers this evidence type
        for pb_id in execution_plan:
            if pb_id not in PLAYBOOK_STEPS:
                continue
            pb_steps = PLAYBOOK_STEPS[pb_id]
            if ev_type not in pb_steps:
                continue

            step_templates = pb_steps[ev_type]
            item_stem = Path(path).stem

            # Run the first applicable step template for this evidence type
            for module, function, raw_params in step_templates[:1]:
                params = {}
                for k, v in raw_params.items():
                    if isinstance(v, str):
                        v = (
                            v.replace("{image}", path)
                             .replace("{mem}", path)
                             .replace("{pcap}", path)
                             .replace("{evtx}", path)
                             .replace("{evt}", path)
                             .replace("{syslog}", path)
                             .replace("{hive}", path)
                             .replace("{mobile}", str(Path(path).parent))
                             .replace("{file}", path)
                             .replace("{output_dir}", output_dir)
                             .replace("{image_stem}", item_stem)
                             .replace("{offset}", str(image_offsets.get(path, 2048)))
                        )
                    params[k] = v

                for k, v_conv in list(params.items()):
                    if isinstance(v_conv, str) and v_conv.isdigit():
                        params[k] = int(v_conv)
                    elif isinstance(v_conv, str) and v_conv.lower() in ("true", "false"):
                        params[k] = v_conv.lower() == "true"

                step_key = f"retry:{pb_id}:{module}:{function}:{Path(path).name}"

                try:
                    result = _run_step_via_orchestrator(module, function, params)
                    step_status = (
                        "completed" if result.get("status") == "success" else "failed"
                    )

                    record = {
                        "playbook": pb_id,
                        "step_key": step_key,
                        "module": module,
                        "function": function,
                        "params": params,
                        "evidence_file": path,
                        "status": step_status,
                        "result": result,
                        "_retry": True,
                        "_retry_reason": reason,
                        "started_at": datetime.now().isoformat(),
                        "completed_at": datetime.now().isoformat(),
                    }
                    findings_writer.append(record)
                    retried += 1

                    if step_status == "completed":
                        succeeded += 1
                        _log(
                            f"  \u2713 Retry ok: {module}.{function} \u2192 "
                            f"{Path(path).name}"
                        )
                    else:
                        failed += 1
                        _log(
                            f"  \u2717 Retry fail: {module}.{function} \u2192 "
                            f"{Path(path).name}"
                        )
                except Exception as exc:
                    failed += 1
                    retried += 1
                    _log(f"  \u2717 Retry error: {Path(path).name}: {exc}")
                break  # one step per file is enough
            break  # one playbook per file is enough

    _log(
        f"  Retry phase done: {retried} attempted, "
        f"{succeeded} ok, {failed} failed"
    )
    return {"retried": retried, "succeeded": succeeded, "failed": failed}


def find_evil(evidence_dir: str, job_id: str = None, case_work_dir: str = None) -> dict:
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
        case_work_dir: Optional path to the case work directory. If not provided,
            a stable path is derived from the evidence path hash.

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

    # --- Checkpoint/Recovery: derive or use stable case work directory ---
    if case_work_dir is None:
        _ev_key = hashlib.sha256(str(evidence_path.resolve()).encode()).hexdigest()[:12]
        _case_name = evidence_path.name
        case_work_dir = Path(CASES_WORK_DIR) / f"{_case_name}_findevil_{_ev_key}"
    else:
        case_work_dir = Path(case_work_dir)

    resuming = case_work_dir.exists() and (case_work_dir / CHECKPOINT_FILE).exists()
    ckpt = None
    if resuming:
        ckpt = _ckpt_load(case_work_dir)
        _fe_log(job_id, f"  [CKPT] Resuming from checkpoint: {case_work_dir}")
    else:
        try:
            case_work_dir.mkdir(parents=True, exist_ok=True)
        except (PermissionError, OSError):
            case_work_dir = Path(tempfile.gettempdir()) / "geoff-cases" / case_work_dir.name
            case_work_dir.mkdir(parents=True, exist_ok=True)
        ckpt = _ckpt_load(case_work_dir)
        ckpt["evidence_path"] = str(evidence_path.resolve())
        ckpt["started_at"] = datetime.now().isoformat()
        _ckpt_save(case_work_dir, ckpt)
        _fe_log(job_id, f"  [CKPT] New investigation: {case_work_dir}")

    try:

        if not evidence_path.exists():
            return {
                "status": "error",
                "error": f"Evidence directory not found: {evidence_dir}",
                "evidence_dir": evidence_dir,
            }

        # Preflight validation (non-fatal — warnings logged but execution continues)
        _case_work_dir_preview = Path(CASES_WORK_DIR) / f"{evidence_path.name}_findevil_preflight"
        try:
            _preflight_validation(evidence_path, _case_work_dir_preview, job_id)
        except Exception as _pf_err:
            _fe_log(job_id, f"  ⚠ Preflight error (non-fatal): {_pf_err}")

        # Per-step custody commits enabled
        _batch_meta = {}
        _fe_log(job_id, "  [BATCH] Per-step custody commits enabled")

        _update_job = _create_update_job(job_id, start_time)

        # ------------------------------------------------------------------
        # Phase 1: Evidence Inventory
        # ------------------------------------------------------------------
        ckpt_inventory_file = case_work_dir / "checkpoint_inventory.json"
        if _ckpt_phase_done(ckpt, "inventory"):
            inventory = json.loads(ckpt_inventory_file.read_text())
            _fe_log(job_id, "  [CKPT] Skipping inventory — loaded from checkpoint")
        else:
            _ckpt_mark_phase(ckpt, "inventory", "running")
            _ckpt_save(case_work_dir, ckpt)
            # Use AI-based classification if enabled
            if AI_EVIDENCE_CLASSIFICATION:
                try:
                    inventory = _inventory_evidence_with_ai(evidence_path, orchestrator, call_llm)
                    ai_count = len(inventory.get('ai_classified', []))
                    if ai_count > 0:
                        _fe_log(job_id, f"  AI classified {ai_count} ambiguous files")
                        for ai_item in inventory.get("ai_classified", [])[:5]:
                            _fe_log(job_id, f"    AI: {Path(ai_item['path']).name} -> {ai_item['evidence_type']} ({ai_item.get('method', 'unknown')}, conf: {ai_item.get('confidence', 0):.1f})")
                    else:
                        _fe_log(job_id, "  AI classification: no ambiguous files")
                except Exception as e:
                    _fe_log(job_id, f"  AI classification failed: {e}, falling back")
                    inventory = _inventory_evidence(evidence_path)
            else:
                inventory = _inventory_evidence(evidence_path)

            # Phase 0b: Validate classification — NEVER leave files unprocessed
            _update_job(2, "validation", "Re-checking file classifications")
            inventory = _validate_inventory_classification(inventory, job_id)
            _fe_log(job_id, f"  Validation: {len(inventory.get('other_files', []))} files remain in other_files for generic analysis")

            _atomic_write(ckpt_inventory_file, json.dumps(inventory, default=str))
            _ckpt_mark_phase(ckpt, "inventory", "complete", "checkpoint_inventory.json")
            _ckpt_save(case_work_dir, ckpt)

        # Phase 1c: Extract compressed archives
        # DFIR requires full extraction — disk space usage is expected
        if _ckpt_phase_done(ckpt, "extraction"):
            extracted_archives = inventory.get("extracted_archives", [])
            _fe_log(job_id, "  [CKPT] Skipping extraction — loaded from checkpoint")
        else:
            _ckpt_mark_phase(ckpt, "extraction", "running")
            _ckpt_save(case_work_dir, ckpt)
            _update_job(4, "extraction", "Extracting compressed archives")
            extracted_archives = []
            for archive_path in inventory.get("mobile_backups", []) + inventory.get("other_files", []):
                header_type = _detect_file_type_from_header(archive_path)
                if header_type in ("zip_archive", "gzip_archive", "tar_archive", "7zip_archive"):
                    # Checkpoint dedup: compute sha256, skip if already extracted
                    _ahash = _hash_file(archive_path)
                    if _ckpt_archive_registered(ckpt, _ahash):
                        _cached = ckpt["extracted_archives"][_ahash]
                        _cached_dir = Path(_cached["extracted_dir"])
                        if _cached_dir.exists() and any(_cached_dir.iterdir()):
                            _fe_log(job_id, f"  [CKPT] Already extracted: {Path(archive_path).name}")
                            _cached_files = _list_extracted_files(str(_cached_dir))
                            extracted_archives.append({
                                "archive": archive_path,
                                "extracted_dir": _cached["extracted_dir"],
                                "file_count": _cached.get("file_count", len(_cached_files)),
                                "files": _cached_files,
                            })
                            # Remove archive, add extracted dir to inventory
                            if archive_path in inventory.get("mobile_backups", []):
                                inventory["mobile_backups"].remove(archive_path)
                                if _cached["extracted_dir"] not in inventory["mobile_backups"]:
                                    inventory["mobile_backups"].append(_cached["extracted_dir"])
                            if archive_path in inventory.get("other_files", []):
                                inventory["other_files"].remove(archive_path)
                                if _cached["extracted_dir"] not in inventory["other_files"]:
                                    inventory["other_files"].append(_cached["extracted_dir"])
                            continue
                    result = _extract_archive(archive_path, job_id=job_id)
                    if result.get("status") in ("extracted", "already_extracted"):
                        _ckpt_register_archive(ckpt, _ahash, archive_path,
                                               result.get("extracted_dir", ""),
                                               result.get("file_count", 0))
                        _ckpt_save(case_work_dir, ckpt)
                        extracted_dir = result.get("extracted_dir")
                        extracted_files = result.get("files", [])
                        extracted_archives.append({
                            "archive": archive_path,
                            "extracted_dir": extracted_dir,
                            "file_count": result.get("file_count", 0),
                            "files": extracted_files,
                        })
                        # Add extracted files to inventory for processing
                        # CAP: Limit to first 1000 files to prevent runaway loops on massive extractions
                        # DeviceDiscovery will handle the directory contents directly
                        _file_cap = 1000
                        _added = 0
                        for fpath in extracted_files[:_file_cap]:
                            fheader = _detect_file_type_from_header(fpath)
                            if fheader == "sqlite_db":
                                if fpath not in inventory["mobile_backups"]:
                                    inventory["mobile_backups"].append(fpath)
                                    _added += 1
                            elif fheader in ("elf_binary", "pe_binary", "macho_binary"):
                                if fpath not in inventory["other_files"]:
                                    inventory["other_files"].append(fpath)
                                    _added += 1
                            else:
                                if fpath not in inventory["other_files"]:
                                    inventory["other_files"].append(fpath)
                                    _added += 1
                        if len(extracted_files) > _file_cap:
                            _fe_log(job_id, f"  ⚠ Only added first {_file_cap}/{len(extracted_files)} files to inventory (rest via DeviceDiscovery)")
                        # Remove the archive from inventory so device discovery uses extracted dir
                        if archive_path in inventory.get("mobile_backups", []):
                            inventory["mobile_backups"].remove(archive_path)
                            # Add the extracted directory as the mobile backup source
                            if extracted_dir not in inventory["mobile_backups"]:
                                inventory["mobile_backups"].append(extracted_dir)
                        if archive_path in inventory.get("other_files", []):
                            inventory["other_files"].remove(archive_path)
                            if extracted_dir not in inventory["other_files"]:
                                inventory["other_files"].append(extracted_dir)
                        _fe_log(job_id, f"  📦 Extracted {result.get('file_count')} files from {Path(archive_path).name}")
                    else:
                        _fe_log(job_id, f"  ⚠ Extraction failed for {Path(archive_path).name}: {result.get('error', 'unknown')}")

        if extracted_archives:
            _fe_log(job_id, f"  Total archives extracted: {len(extracted_archives)}")
            inventory["extracted_archives"] = extracted_archives

        # Phase 1d: Re-validate after extraction
        if not _ckpt_phase_done(ckpt, "extraction"):
            _update_job(5, "revalidation", "Re-validating after extraction")
            inventory = _validate_inventory_classification(inventory, job_id)
            _fe_log(job_id, f"  Post-extraction: {len(inventory.get('other_files', []))} files remain in other_files")
            _atomic_write(ckpt_inventory_file, json.dumps(inventory, default=str))
            _ckpt_mark_phase(ckpt, "extraction", "complete")
            _ckpt_save(case_work_dir, ckpt)

        # Phase 1e: Rebuild device map with extracted files
        ckpt_devices_file = case_work_dir / "checkpoint_devices.json"
        if _ckpt_phase_done(ckpt, "device_discovery"):
            saved = json.loads(ckpt_devices_file.read_text())
            device_map = saved.get("device_map", {})
            user_map = saved.get("user_map", {})
            _fe_log(job_id, "  [CKPT] Skipping device discovery — loaded from checkpoint")
        else:
            _ckpt_mark_phase(ckpt, "device_discovery", "running")
            _ckpt_save(case_work_dir, ckpt)
            _update_job(3, "discovery", "Identifying devices and users")
            device_disc = DeviceDiscovery(orchestrator)
            device_map, user_map = device_disc.discover(evidence_path, inventory)
            _fe_log(job_id, f"Discovered {len(device_map)} devices, {len(user_map)} users")
            _atomic_write(ckpt_devices_file, json.dumps({"device_map": device_map, "user_map": user_map}, default=str))
            _ckpt_mark_phase(ckpt, "device_discovery", "complete", "checkpoint_devices.json")
            _ckpt_save(case_work_dir, ckpt)

        # If no devices were resolved (log-only or standalone file evidence), synthesise
        # a single "unknown" device so the per-device playbook loop always runs.
        if not device_map:
            all_evidence = (
                inventory["disk_images"] + inventory["memory_dumps"] + inventory["pcaps"]
                + inventory.get("evtx_logs", []) + inventory.get("evt_logs", []) + inventory["syslogs"] + inventory["registry_hives"]
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
            # Log mobile metadata discoveries
            meta = dev.get("metadata", {})
            if "keychain_in_zip" in meta:
                _fe_log(job_id, f"    📱 Found keychain in zip: {meta['keychain_in_zip']}")
            if "contacts_in_zip" in meta:
                _fe_log(job_id, f"    📱 Found contacts in zip: {meta['contacts_in_zip']}")
            if "keychain_entries" in meta:
                _fe_log(job_id, f"    🔑 Extracted {len(meta['keychain_entries'])} keychain entries")
            if "apple_id" in meta:
                _fe_log(job_id, f"    🍎 Apple ID: {meta['apple_id']}")
            if "ios_accounts" in meta:
                _fe_log(job_id, f"    👤 iOS accounts: {len(meta['ios_accounts'])}")
            if "android_accounts" in meta:
                _fe_log(job_id, f"    🤖 Android accounts: {len(meta['android_accounts'])}")

        # Phase 1f: Update device maps with extracted archive contents
        # Mobile functions need the extracted directory, not the archive path
        extracted_archives = inventory.get("extracted_archives", [])
        for dev_id, dev in device_map.items():
            for archive_info in extracted_archives:
                archive_path = archive_info.get("archive")
                extracted_dir = archive_info.get("extracted_dir")
                # If this device has the archive in its evidence files, add extracted files
                if archive_path in dev.get("evidence_files", []):
                    extracted_files = archive_info.get("files", [])
                    # Add extracted files to device's evidence files
                    dev["evidence_files"].extend(extracted_files)
                    # Remove the archive itself from evidence files (replaced by extracted contents)
                    if archive_path in dev["evidence_files"]:
                        dev["evidence_files"].remove(archive_path)
                    _fe_log(job_id, f"  Device {dev_id}: replaced archive with {len(extracted_files)} extracted files")
                    # Update the mobile_backups list in inventory too
                    if archive_path in inventory.get("mobile_backups", []):
                        inventory["mobile_backups"].remove(archive_path)
                        inventory["mobile_backups"].extend(extracted_files)
                    _fe_log(job_id, f"  📱 Device {dev_id} evidence_files updated with extracted {Path(extracted_dir).name}")

        # Capture all inventory paths for later unprocessed-file analysis
        all_inventory_paths = _all_inventory_paths(inventory)

        # Determine OS from dominant device type (for playbook selection)
        os_type = _detect_os_from_devices(device_map)
        # Triage indicators still useful for initial severity classification
        indicator_hits = _scan_triage_indicators(inventory)

        _update_job(5, "inventory", "Complete", log_msg="Evidence inventory complete")

        # ------------------------------------------------------------------
        # Phase 1b: Detect partition offsets for each disk image
        # ------------------------------------------------------------------
        ckpt_offsets_file = case_work_dir / "checkpoint_offsets.json"
        if _ckpt_phase_done(ckpt, "partition_offsets"):
            image_offsets = json.loads(ckpt_offsets_file.read_text())
            _fe_log(job_id, "  [CKPT] Skipping partition scan — loaded from checkpoint")
        else:
            _ckpt_mark_phase(ckpt, "partition_offsets", "running")
            _ckpt_save(case_work_dir, ckpt)
        image_offsets = image_offsets if _ckpt_phase_done(ckpt, "partition_offsets") else {}  # image_path -> first filesystem partition offset
        # Phase 1b (revised): Detect partition offsets per device
        _ran_partition_scan = _ckpt_phase_done(ckpt, "partition_offsets")
        for dev_id, dev in device_map.items():
            if _ran_partition_scan:
                break
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
                            # Try direct mmls invocation as a last-resort fallback
                            try:
                                raw_mmls = subprocess.run(
                                    ['mmls', img], capture_output=True, text=True, timeout=30
                                )
                                if raw_mmls.returncode == 0:
                                    # Parse the simpler DOS/MBR format: slot: start end length desc
                                    for line in raw_mmls.stdout.splitlines():
                                        line = line.strip()
                                        m = re.match(r'^\d+:\s+(\d+)\s+(\d+)\s+(\d+)\s+(.*)', line)
                                        if m:
                                            desc = m.group(4).lower()
                                            start = int(m.group(1))
                                            if any(fs in desc for fs in ['ntfs', 'ext', 'fat', 'hfs']) and start > 0:
                                                image_offsets[img] = start
                                                _fe_log(job_id, f"Partition offset for {Path(img).name}: sector {start} (direct mmls fallback)")
                                                break
                            except Exception:
                                pass
                        if img not in image_offsets:
                            # LLM-powered self-healing for pipeline infra: partition detection
                            _pd_err = f"mmls failed to identify partitions for {Path(img).name}"
                            if mmls_result and mmls_result.get("stderr"):
                                _pd_err += f": {str(mmls_result['stderr'])[:200]}"
                            healed = _attempt_heal(
                                module="system",
                                function="detect_partitions",
                                params={"evidence_path": img},
                                error_result={"status": "error", "stderr": _pd_err},
                                job_id=job_id,
                                evidence_file=img,
                                evidence_type="disk_image",
                            )
                            if healed and (healed.get("status") in ("skipped",) or healed.get("_heal_skipped")):
                                _fe_log(job_id, f"  ⎘ [HEAL] Partition detection skipped for {Path(img).name}: {healed.get('_skip_reason', 'LLM skip')}")
                                continue
                            # Fallback: try common legacy offsets before giving up
                            image_offsets[img] = 63  # DOS/MBR legacy (pre-Vista) — most common for XP
                            _fe_log(job_id, f"Partition detection failed for {Path(img).name}, using legacy offset 63 (DOS partition table)")
                            # Store all candidates in metadata for possible auto-heal retry
                            auto_heal_candidates = image_offsets.get('_candidates', {})
                            auto_heal_candidates[img] = [
                                off for off in COMMON_LEGACY_OFFSETS
                                if off != image_offsets[img]
                            ]
                            if auto_heal_candidates:
                                image_offsets['_candidates'] = auto_heal_candidates
                    except Exception as e:
                        _fe_log(job_id, f"Partition detection crashed for {Path(img).name}: {e}")
                        # LLM-powered self-healing for partition detection crashes
                        healed = _attempt_heal(
                            module="system",
                            function="detect_partitions",
                            params={"evidence_path": img},
                            error_result={"status": "error", "stderr": str(e)[:300]},
                            job_id=job_id,
                            evidence_file=img,
                            evidence_type="disk_image",
                        )
                        if healed and (healed.get("status") in ("skipped",) or healed.get("_heal_skipped")):
                            _fe_log(job_id, f"  ⎘ [HEAL] Partition detection skipped after crash for {Path(img).name}")
                            continue
                        image_offsets[img] = 63  # DOS/MBR legacy fallback
                        _fe_log(job_id, f"  using legacy offset 63 as fallback")

        # ------------------------------------------------------------------
        # Phase 1c: Nuclear Deep Classification (filesystem walk inside disk images)
        # ------------------------------------------------------------------
        # Save partition offsets checkpoint if we just scanned
        if not _ran_partition_scan and image_offsets:
            _atomic_write(ckpt_offsets_file, json.dumps(image_offsets, default=str))
            _ckpt_mark_phase(ckpt, "partition_offsets", "complete", "checkpoint_offsets.json")
            _ckpt_save(case_work_dir, ckpt)

        # Mount & Discover — checkpoint for disk walk dedup
        ckpt_mounts_file = case_work_dir / "checkpoint_mounts.json"
        if _ckpt_phase_done(ckpt, "mount_discover"):
            nuclear_result = json.loads(ckpt_mounts_file.read_text())
            _fe_log(job_id, "  [CKPT] Skipping mount/discover — loaded from checkpoint")
        else:
            _ckpt_mark_phase(ckpt, "mount_discover", "running")
            _ckpt_save(case_work_dir, ckpt)
            nuclear_result = _mount_and_discover(inventory, image_offsets, evidence_path.name, job_id)
            # Mark walked disks in checkpoint
            for img_path in inventory.get("disk_images", []):
                _ckpt_mark_disk_walked(ckpt, str(img_path))
            _atomic_write(ckpt_mounts_file, json.dumps(nuclear_result, default=str))
            # If zero images were actually walked but disk images exist, mark as failed
            nuc_processed = nuclear_result.get("nuclear_images_processed", 0) if nuclear_result else 0
            if nuc_processed == 0 and inventory.get("disk_images", []):
                _fe_log(job_id, f"  ⚠ Mount phase found 0 items but {len(inventory.get('disk_images',[]))} disk images exist — marking as failed for retry")
                _ckpt_mark_phase(ckpt, "mount_discover", "failed", "checkpoint_mounts.json")
            else:
                _ckpt_mark_phase(ckpt, "mount_discover", "complete", "checkpoint_mounts.json")
            _ckpt_save(case_work_dir, ckpt)

        # ------------------------------------------------------------------
        # Phase 2: Prepare Case Work Directory (subdirs for stable dir)
        # ------------------------------------------------------------------
        case_name = evidence_path.name
        # Create evidence separation directories
        (case_work_dir / "evidence" / "derived").mkdir(parents=True, exist_ok=True)
        (case_work_dir / "evidence" / "raw").mkdir(parents=True, exist_ok=True)
    
        # Write evidence manifest to evidence/raw/ (references, not copies/links)
        # Raw evidence stays in its original location — only derived artifacts go here
        manifest = {
            "evidence_dir": str(evidence_dir),
            "disk_images": inventory.get("disk_images", []),
            "memory_dumps": inventory.get("memory_dumps", []),
            "pcaps": inventory.get("pcaps", []),
            "evtx_logs": inventory.get("evtx_logs", []),
            "evt_logs": inventory.get("evt_logs", []),
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
        if str(case_work_dir).startswith(tempfile.gettempdir()):
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
        exec_cache = _ExecResultCache(path=case_work_dir / "exec_cache.json")
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
            "evtx_logs": inventory.get("evtx_logs", []),
            "evt_logs": inventory.get("evt_logs", []),
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
                            v = v.replace("{evtx}", item).replace("{syslog}", item).replace("{hive}", item).replace("{evt}", item)
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
        #   4. Artifact detection inside disk images (fls output)
        execution_plan = []
        skipped_playbooks = []
        confidence_modifiers = []
        anti_forensics_detected = False

        # --- Scan triage_findings for artifacts INSIDE disk images ---
        # The fls/list_files results from PB-SIFT-001 are in triage_findings.
        # When we have disk images, key artifacts (email, browser, registry, etc.)
        # are INSIDE the image — they won't appear in inventory's top-level files.
        # We must detect them from the fls file listing.
        _disk_artifacts = {
            "email": False,       # PST/OST/DBX/EML inside image
            "browser": False,    # Browser history/cookies inside image
            "registry": False,   # Registry hives inside image
            "evtx": False,       # Event logs inside image (Vista+)
            "evt": False,        # Event logs inside image (XP/2003)
            "memory_dumps_in_image": False,  # hiberfil/pagefile inside image
        }
        _email_paths_inside = []   # Collect paths for icat extraction
        _browser_paths_inside = []

        # Patterns for detecting artifacts inside fls output
        _email_patterns = [
            ".pst", ".ost", ".dbx", ".eml", ".mbox", ".msf",
            "outlook", "thunderbird", "evolution", "kmail", "mutt", "maildir",
            "application data/microsoft/outlook",
            "local settings/application data/microsoft/outlook",
            "local settings/application data/identities",
            "application data/thunderbird",
            "windows mail",
            ".local/share/evolution", ".thunderbird/",
            ".mozilla/thunderbird", "library/mail/",
            "library/mail/v2", "library/mail/v3",
        ]
        _browser_patterns = [
            "places.sqlite", "history", "cookies.db", "cookies.sqlite",
            "chrome/user data", "firefox/profiles",
            "application data/google/chrome",
            "application data/mozilla/firefox",
            "local settings/application data/google/chrome",
            "local settings/application data/mozilla/firefox",
            "appdata/roaming/mozilla/firefox",
            "appdata/local/google/chrome",
            "appdata/roaming/microsoft/edge",
            "microsoftedge",
            # Linux
            ".config/google-chrome", ".config/chromium", ".mozilla/firefox",
            ".config/brave", ".local/share/flatpak",
            # macOS
            "library/application support/google/chrome",
            "library/application support/firefox",
            "library/application support/brave",
            "library/safari",
        ]
        _registry_patterns = [
            "software", "system", "ntuser.dat", "sam", "security", "default",
            "system32/config/software", "system32/config/system",
            "system32/config/sam", "system32/config/security",
        ]
        _evtx_patterns = [
            ".evlx", ".evtx", "system32/winevt/logs/",
        ]
        _evt_patterns = [
            ".evt", "system32/config/appevent", "system32/config/secevent",
            "system32/config/sysevent", "documents and settings",
        ]
        _memory_patterns = [
            "hiberfil.sys", "pagefile.sys", ".dmp",
        ]

        for tf in triage_findings:
            # Look for sleuthkit list_files results (fls output)
            if tf.get("module") == "sleuthkit" and tf.get("function") in ("list_files", "analyze_filesystem"):
                result = tf.get("result", {})
                # fls results may be in various formats depending on orchestrator
                # Try common result structures
                file_list = None
                if isinstance(result, dict):
                    # Could be {"files": [...]} or {"output": "..."} or {"file_list": [...]}
                    file_list = result.get("files") or result.get("file_list")
                    if file_list is None and isinstance(result.get("output"), str):
                        # fls output is a text blob — scan it directly
                        file_list = None  # will scan output string below
                        output_str = result["output"].lower()
                        for pat in _email_patterns:
                            if pat in output_str:
                                _disk_artifacts["email"] = True
                        for pat in _browser_patterns:
                            if pat in output_str:
                                _disk_artifacts["browser"] = True
                        for pat in _registry_patterns:
                            if pat in output_str:
                                _disk_artifacts["registry"] = True
                        for pat in _evtx_patterns:
                            if pat in output_str:
                                _disk_artifacts["evtx"] = True
                        for pat in _evt_patterns:
                            if pat in output_str:
                                _disk_artifacts["evt"] = True
                        for pat in _memory_patterns:
                            if pat in output_str:
                                _disk_artifacts["memory_dumps_in_image"] = True
                if isinstance(file_list, list):
                    for fentry in file_list:
                        f_str = str(fentry).lower() if isinstance(fentry, (str, dict)) else ""
                        if isinstance(fentry, dict):
                            f_str = (fentry.get("name", "") + " " + fentry.get("path", "")).lower()
                        for pat in _email_patterns:
                            if pat in f_str:
                                _disk_artifacts["email"] = True
                        for pat in _browser_patterns:
                            if pat in f_str:
                                _disk_artifacts["browser"] = True
                        for pat in _registry_patterns:
                            if pat in f_str:
                                _disk_artifacts["registry"] = True
                        for pat in _evtx_patterns:
                            if pat in f_str:
                                _disk_artifacts["evtx"] = True
                        for pat in _evt_patterns:
                            if pat in f_str:
                                _disk_artifacts["evt"] = True
                        for pat in _memory_patterns:
                            if pat in f_str:
                                _disk_artifacts["memory_dumps_in_image"] = True
            # Also scan string results from triage
            elif tf.get("module") == "strings" or tf.get("function") == "extract_strings":
                result_str = json.dumps(tf.get("result", {}), default=str).lower()
                for pat in _email_patterns[:6]:  # Only check top patterns for strings
                    if pat in result_str:
                        _disk_artifacts["email"] = True

        # Also check indicator_hits for phishing/email categories
        for hit in indicator_hits:
            if isinstance(hit, dict) and hit.get("category") in ("phishing", "email", "credential_theft"):
                _disk_artifacts["email"] = True

        # For disk images with Windows OS, assume common artifacts exist even if
        # fls output hasn't been parsed yet (PB-SIFT-001 may not have completed
        # its full recursive scan at triage time)
        has_disk_images = bool(inventory.get("disk_images"))
        if has_disk_images and os_type == "windows":
            # Windows images almost always have registry + evtx + evt + email potential
            _disk_artifacts["registry"] = True
            _disk_artifacts["evtx"] = True
            _disk_artifacts["evt"] = True
            # Don't assume email unless detected — but enable browser (common)
            _disk_artifacts["browser"] = True

        _fe_log(job_id, f"  Disk artifact detection: {_disk_artifacts}")

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

        # Browser forensics — run when browser artifacts detected
        # (Inside disk images OR as standalone files, plus always relevant)
        if _disk_artifacts.get("browser") or inventory["disk_images"]:
            execution_plan.append("PB-SIFT-022")
        else:
            # Still add browser forensics for non-disk-image cases with browser files
            execution_plan.append("PB-SIFT-022")

        # Email forensics — run when email-like files are present as standalone
        # OR when email artifacts are detected inside disk images
        email_exts = {".pst", ".ost", ".mbox", ".eml", ".msg"}
        _standalone_email = any(Path(f).suffix.lower() in email_exts for f in inventory["other_files"])
        _image_email = _disk_artifacts.get("email", False)
        if _standalone_email or _image_email:
            execution_plan.append("PB-SIFT-023")
            if _image_email:
                _fe_log(job_id, "  PB-SIFT-023: Email Forensics queued (email artifacts detected inside disk image)")
        elif has_disk_images and os_type == "windows":
            # Windows disk images: schedule email forensics proactively —
            # Outlook/Outlook Express data is common and critical for phishing cases
            execution_plan.append("PB-SIFT-023")
            _fe_log(job_id, "  PB-SIFT-023: Email Forensics queued (Windows disk image — email likely present)")
        else:
            skipped_playbooks.append({"id": "PB-SIFT-023", "reason": "No email files or email artifacts inside images"})

        # --- NEW PLAYBOOK AUTO-TRIGGERS (PB-SIFT-027 through PB-SIFT-033) ---

        # Memory forensics — triggered by memory dump files
        if inventory["memory_dumps"]:
            execution_plan.append("PB-SIFT-027")
            _fe_log(job_id, f"  PB-SIFT-027: Memory Forensics queued for {len(inventory['memory_dumps'])} memory dump(s)")

        # Windows Modern Artifacts — triggered by Windows OS + registry hives
        # (standalone OR detected inside disk images)
        if os_type == "windows" and (inventory["registry_hives"] or _disk_artifacts.get("registry")):
            execution_plan.append("PB-SIFT-028")
            _fe_log(job_id, "  PB-SIFT-028: Windows Modern Artifacts queued")
        elif has_disk_images and os_type == "windows":
            # Windows image without explicit registry detection — still queue it
            execution_plan.append("PB-SIFT-028")
            _fe_log(job_id, "  PB-SIFT-028: Windows Modern Artifacts queued (Windows disk image)")

        # Encrypted Containers — detect encrypted volume indicators
        encrypted_indicators = {
            "bitlocker": ["fvevol.sys", "bitlocker", "fvek"],
            "filevault": ["apfs encrypted", "filevault", "corestorage"],
            "veracrypt": ["veracrypt", "truecrypt", r"\.tc$"],
            "luks": ["luks", "cryptsetup", "dm-crypt"],
        }
        encrypted_detected = False
        for f in inventory.get("other_files", []):
            f_lower = str(f).lower()
            for etype, indicators in encrypted_indicators.items():
                if any(ind in f_lower for ind in indicators):
                    encrypted_detected = True
                    break
        # Also check disk images for high-entropy (potential encrypted containers)
        if not encrypted_detected:
            for f in inventory.get("disk_images", []):
                f_lower = str(f).lower()
                if any(ind in f_lower for ind in [".tc", "veracrypt", "luks", "bitlocker"]):
                    encrypted_detected = True
                    break
        if encrypted_detected:
            execution_plan.append("PB-SIFT-029")
            _fe_log(job_id, "  PB-SIFT-029: Encrypted Container analysis queued")

        # Cloud Sync Artifacts — detect cloud storage sync databases
        cloud_sync_patterns = {
            "onedrive": ["onedrive", "skydrive"],
            "googledrive": ["snapshot.db", "drivefs", "google drive"],
            "dropbox": ["filecache.db", "dropbox"],
            "icloud": ["ubiquity", "clouddocs", "icloud"],
            "box": ["box sync"],
        }
        cloud_sync_detected = False
        for f in inventory.get("other_files", []):
            f_lower = str(f).lower()
            for service, patterns in cloud_sync_patterns.items():
                if any(p in f_lower for p in patterns):
                    cloud_sync_detected = True
                    break
        if cloud_sync_detected:
            execution_plan.append("PB-SIFT-030")
            _fe_log(job_id, "  PB-SIFT-030: Cloud Sync Artifact analysis queued")

        # Enterprise Collaboration — detect Teams/Slack/Discord/Skype/Zoom artifacts
        collab_patterns = {
            "teams": ["teams", "microsoft teams"],
            "slack": ["slack"],
            "discord": ["discord"],
            "skype": ["skype", "main.db"],
            "zoom": ["zoom", "zoom.us"],
        }
        collab_detected = False
        for f in inventory.get("other_files", []):
            f_lower = str(f).lower()
            for app, patterns in collab_patterns.items():
                if any(p in f_lower for p in patterns):
                    collab_detected = True
                    break
        if collab_detected:
            execution_plan.append("PB-SIFT-031")
            _fe_log(job_id, "  PB-SIFT-031: Enterprise Collaboration analysis queued")

        # VM Snapshot Forensics — detect VM snapshot/memory files
        vm_exts = {".vmss", ".vmsn", ".vmem", ".vhdx", ".vmdk", ".qcow2", ".vmx"}
        vm_detected = False
        for f in inventory.get("memory_dumps", []) + inventory.get("other_files", []):
            if Path(f).suffix.lower() in vm_exts or Path(f).name.lower().endswith(".vmx"):
                vm_detected = True
                break
        if vm_detected:
            execution_plan.append("PB-SIFT-032")
            _fe_log(job_id, "  PB-SIFT-032: VM Snapshot Forensics queued")

        # Container Forensics — detect Docker/container artifacts
        container_patterns = {
            "docker": ["docker", "containerd", "overlay2", "config.v2.json"],
            "kubernetes": ["kubernetes", "kubectl", "kubelet", "etcd"],
            "podman": ["podman", "containers"],
        }
        container_detected = False
        for f in inventory.get("other_files", []):
            f_lower = str(f).lower()
            for runtime, patterns in container_patterns.items():
                if any(p in f_lower for p in patterns):
                    container_detected = True
                    break
        if container_detected:
            execution_plan.append("PB-SIFT-033")
            _fe_log(job_id, "  PB-SIFT-033: Container Forensics queued")

        # --- END NEW PLAYBOOK AUTO-TRIGGERS ---

        # --- NEW PLAYBOOK AUTO-TRIGGERS (PB-SIFT-027 through PB-SIFT-033) ---

        # Memory forensics — triggered by memory dump files
        if inventory["memory_dumps"]:
            execution_plan.append("PB-SIFT-027")
            _fe_log(job_id, f"  PB-SIFT-027: Memory Forensics queued for {len(inventory['memory_dumps'])} memory dump(s)")

        # Windows Modern Artifacts — triggered by Windows OS + registry hives
        if os_type == "windows" and inventory["registry_hives"]:
            execution_plan.append("PB-SIFT-028")
            _fe_log(job_id, "  PB-SIFT-028: Windows Modern Artifacts queued")

        # Encrypted Containers — detect encrypted volume indicators
        encrypted_indicators = {
            "bitlocker": ["fvevol.sys", "bitlocker", "fvek"],
            "filevault": ["apfs encrypted", "filevault", "corestorage"],
            "veracrypt": ["veracrypt", "truecrypt", r"\.tc$"],
            "luks": ["luks", "cryptsetup", "dm-crypt"],
        }
        encrypted_detected = False
        for f in inventory.get("other_files", []):
            f_lower = str(f).lower()
            for etype, indicators in encrypted_indicators.items():
                if any(ind in f_lower for ind in indicators):
                    encrypted_detected = True
                    break
        # Also check disk images for high-entropy (potential encrypted containers)
        if not encrypted_detected:
            for f in inventory.get("disk_images", []):
                f_lower = str(f).lower()
                if any(ind in f_lower for ind in [".tc", "veracrypt", "luks", "bitlocker"]):
                    encrypted_detected = True
                    break
        if encrypted_detected:
            execution_plan.append("PB-SIFT-029")
            _fe_log(job_id, "  PB-SIFT-029: Encrypted Container analysis queued")

        # Cloud Sync Artifacts — detect cloud storage sync databases
        cloud_sync_patterns = {
            "onedrive": ["onedrive", "skydrive"],
            "googledrive": ["snapshot.db", "drivefs", "google drive"],
            "dropbox": ["filecache.db", "dropbox"],
            "icloud": ["ubiquity", "clouddocs", "icloud"],
            "box": ["box sync"],
        }
        cloud_sync_detected = False
        for f in inventory.get("other_files", []):
            f_lower = str(f).lower()
            for service, patterns in cloud_sync_patterns.items():
                if any(p in f_lower for p in patterns):
                    cloud_sync_detected = True
                    break
        if cloud_sync_detected:
            execution_plan.append("PB-SIFT-030")
            _fe_log(job_id, "  PB-SIFT-030: Cloud Sync Artifact analysis queued")

        # Enterprise Collaboration — detect Teams/Slack/Discord/Skype/Zoom artifacts
        collab_patterns = {
            "teams": ["teams", "microsoft teams"],
            "slack": ["slack"],
            "discord": ["discord"],
            "skype": ["skype", "main.db"],
            "zoom": ["zoom", "zoom.us"],
        }
        collab_detected = False
        for f in inventory.get("other_files", []):
            f_lower = str(f).lower()
            for app, patterns in collab_patterns.items():
                if any(p in f_lower for p in patterns):
                    collab_detected = True
                    break
        if collab_detected:
            execution_plan.append("PB-SIFT-031")
            _fe_log(job_id, "  PB-SIFT-031: Enterprise Collaboration analysis queued")

        # VM Snapshot Forensics — detect VM snapshot/memory files
        vm_exts = {".vmss", ".vmsn", ".vmem", ".vhdx", ".vmdk", ".qcow2", ".vmx"}
        vm_detected = False
        for f in inventory.get("memory_dumps", []) + inventory.get("other_files", []):
            if Path(f).suffix.lower() in vm_exts or Path(f).name.lower().endswith(".vmx"):
                vm_detected = True
                break
        if vm_detected:
            execution_plan.append("PB-SIFT-032")
            _fe_log(job_id, "  PB-SIFT-032: VM Snapshot Forensics queued")

        # Container Forensics — detect Docker/container artifacts
        container_patterns = {
            "docker": ["docker", "containerd", "overlay2", "config.v2.json"],
            "kubernetes": ["kubernetes", "kubectl", "kubelet", "etcd"],
            "podman": ["podman", "containers"],
        }
        container_detected = False
        for f in inventory.get("other_files", []):
            f_lower = str(f).lower()
            for runtime, patterns in container_patterns.items():
                if any(p in f_lower for p in patterns):
                    container_detected = True
                    break
        if container_detected:
            execution_plan.append("PB-SIFT-033")
            _fe_log(job_id, "  PB-SIFT-033: Container Forensics queued")

        # --- END NEW PLAYBOOK AUTO-TRIGGERS ---

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

        # Generic File Analysis — ALWAYS run when unclassified files remain
        if len(inventory["other_files"]) > 0:
            execution_plan.append("PB-SIFT-025")
            _fe_log(job_id, f"  PB-SIFT-025: Generic File Analysis queued for {len(inventory['other_files'])} unclassified file(s)")
        else:
            skipped_playbooks.append({"id": "PB-SIFT-025", "reason": "No unclassified files"})

        # --- Nuclear option: use deep classification results to intelligently
        # queue playbooks based on what was ACTUALLY found inside disk images.
        # The Phase 1c nuclear walk (fls inside each mounted image) has already
        # enriched the inventory with nested images, email files, SQLite databases,
        # browser artifacts, archives, registry hives, and event logs.
        if has_disk_images:
            _nuclear_ev = nuclear_result.get("nuclear_evidence", {})
            _nuclear_found = nuclear_result.get("nuclear_findings", [])
            _fe_log(job_id, f"  Nuclear: {len(_nuclear_found)} classified items inside disk images")

            # Super Timeline (Plaso) — always run for disk images
            if "PB-SIFT-020" not in execution_plan:
                execution_plan.append("PB-SIFT-020")
                _fe_log(job_id, "  PB-SIFT-020: Force-queued (disk image present)")

            # Registry Forensics — queue if registry hives found inside
            if _nuclear_ev.get("registry_hives") or inventory["registry_hives"]:
                if "PB-SIFT-009" not in execution_plan:
                    execution_plan.append("PB-SIFT-009")
                    _fe_log(job_id, f"  PB-SIFT-009: nuclear — {len(_nuclear_ev.get('registry_hives', []))} registry hive(s) inside image")
            elif os_type == "windows":
                if "PB-SIFT-009" not in execution_plan:
                    execution_plan.append("PB-SIFT-009")
                    _fe_log(job_id, "  PB-SIFT-009: nuclear — Windows image, registry likely")

            # Browser Forensics — queue if browser artifacts found inside
            if _nuclear_ev.get("browser_artifacts") or _disk_artifacts.get("browser"):
                if "PB-SIFT-022" not in execution_plan:
                    execution_plan.append("PB-SIFT-022")
                    _fe_log(job_id, f"  PB-SIFT-022: nuclear — {len(_nuclear_ev.get('browser_artifacts', []))} browser artifact(s) inside image")
            elif os_type == "windows":
                if "PB-SIFT-022" not in execution_plan:
                    execution_plan.append("PB-SIFT-022")
                    _fe_log(job_id, "  PB-SIFT-022: nuclear — Windows image, browser likely")

            # Email Forensics — queue if email files found inside
            if _nuclear_ev.get("email_files") or _disk_artifacts.get("email"):
                if "PB-SIFT-023" not in execution_plan:
                    execution_plan.append("PB-SIFT-023")
                    _fe_log(job_id, f"  PB-SIFT-023: nuclear — {len(_nuclear_ev.get('email_files', []))} email file(s) inside image")
            elif os_type == "windows":
                if "PB-SIFT-023" not in execution_plan:
                    execution_plan.append("PB-SIFT-023")
                    _fe_log(job_id, "  PB-SIFT-023: nuclear — Windows image, email likely")

            # Malware Analysis — queue if suspicious binaries/documents found
            if _nuclear_ev.get("documents") or _nuclear_ev.get("archives_inside") or malware_analysis_warranted:
                for malware_pb in ["PB-SIFT-017", "PB-SIFT-018"]:
                    if malware_pb not in execution_plan:
                        execution_plan.append(malware_pb)
                        _fe_log(job_id, f"  {malware_pb}: nuclear — {len(_nuclear_ev.get('documents', []))} doc(s), {len(_nuclear_ev.get('archives_inside', []))} archive(s) inside image")

            # Memory Forensics — queue if memory dumps found inside image
            if _nuclear_ev.get("memory_dumps_inside") or _disk_artifacts.get("memory_dumps_in_image"):
                if "PB-SIFT-027" not in execution_plan:
                    execution_plan.append("PB-SIFT-027")
                    _fe_log(job_id, f"  PB-SIFT-027: nuclear — {len(_nuclear_ev.get('memory_dumps_inside', []))} memory dump(s) inside image")

            # Nested disk images discovered — queue for analysis
            if _nuclear_ev.get("nested_disk_images"):
                _nested_count = len(_nuclear_ev["nested_disk_images"])
                _fe_log(job_id, f"  🪆 Nested images: {_nested_count} disk image(s) found INSIDE image — these need extraction")
                # Add core playbooks if not already queued (for nested image processing)
                for core_pb in ["PB-SIFT-006", "PB-SIFT-007", "PB-SIFT-008"]:
                    if core_pb not in execution_plan:
                        execution_plan.append(core_pb)
                        _fe_log(job_id, f"  {core_pb}: nuclear — nested disk image processing")

            # OS-specific playbooks based on nuclear findings
            if os_type == "windows" and "PB-SIFT-028" not in execution_plan:
                execution_plan.append("PB-SIFT-028")
                _fe_log(job_id, "  PB-SIFT-028: nuclear — Windows Modern Artifacts")
            elif os_type == "linux" and "PB-SIFT-014" not in execution_plan:
                execution_plan.append("PB-SIFT-014")
                _fe_log(job_id, "  PB-SIFT-014: nuclear — Linux Forensics")
            elif os_type == "macos" and "PB-SIFT-024" not in execution_plan:
                execution_plan.append("PB-SIFT-024")
                _fe_log(job_id, "  PB-SIFT-024: nuclear — macOS Forensics")

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
        elif "phishing" in hit_categories:
            classification = "Phishing"
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
        elif inventory["syslogs"] or inventory.get("evtx_logs", []) or inventory.get("evt_logs", []):
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

        # --- Automatic Carving Decision ---
        # Geoff decides when to carve data from images based on evidence state
        carving_needed = False
        carving_reasons = []
    
        # 1. Disk images present but filesystem appears empty/unusual
        for img in inventory.get("disk_images", []):
            img_path = Path(str(img))
            if img_path.exists():
                size_mb = img_path.stat().st_size / (1024*1024)
                # Large image but few files = likely wiped or raw
                if size_mb > 100:
                    # Check if we got meaningful filesystem data
                    has_meaningful_data = False
                    for dev_id, dev in device_map.items():
                        dev_files = dev.get("evidence_files", [])
                        dev_img_files = [f for f in dev_files if str(f) == str(img)]
                        if len(dev_files) > 5:  # Arbitrary threshold
                            has_meaningful_data = True
                            break
                    if not has_meaningful_data:
                        carving_needed = True
                        carving_reasons.append(f"Large disk image {img_path.name} ({size_mb:.0f}MB) with minimal filesystem recovery")
    
        # 2. Raw binary dumps (NAND, mobile chip-off) that need carving
        raw_extensions = {".bin", ".img", ".raw", ".dd", ".nand"}
        for f in inventory.get("other_files", []) + inventory.get("disk_images", []):
            if Path(str(f)).suffix.lower() in raw_extensions:
                carving_needed = True
                carving_reasons.append(f"Raw binary dump detected: {Path(str(f)).name}")
    
        # 3. Anti-forensics detected → carve for deleted files
        if "ANTI-FORENSICS-CONFIRMED" in confidence_modifiers:
            carving_needed = True
            carving_reasons.append("Anti-forensics detected — carving for deleted/wiped files")
    
        # 4. Mobile backups that are raw dumps (not structured backups)
        for mb in inventory.get("mobile_backups", []):
            mb_path = Path(str(mb))
            if mb_path.is_file() and mb_path.suffix.lower() in {".bin", ".img", ".raw"}:
                carving_needed = True
                carving_reasons.append(f"Raw mobile dump: {mb_path.name}")
    
        if carving_needed:
            _fe_log(job_id, f"🔪 Carving triggered: {len(carving_reasons)} reason(s)")
            for reason in carving_reasons[:3]:
                _fe_log(job_id, f"  - {reason}")
            # Add carving playbook if not already in plan
            carving_pb = "PB-SIFT-026"  # File Carving & Recovery
            if carving_pb not in execution_plan and carving_pb in PLAYBOOK_STEPS:
                execution_plan.append(carving_pb)
                _fe_log(job_id, f"  Added {carving_pb} to execution plan")
            elif carving_pb not in PLAYBOOK_STEPS:
                # Fallback: use anti-forensics playbook's carving steps
                if "PB-SIFT-012" not in execution_plan:
                    execution_plan.append("PB-SIFT-012")
                    _fe_log(job_id, f"  Added PB-SIFT-012 (Anti-Forensics) for carving fallback")
        else:
            _fe_log(job_id, "🔪 Carving: not needed (filesystem data recovered)")

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

        # Attribute nuclear evidence files (extracted from inside disk images)
        # to their owning devices so device_evidence picks them up for playbook
        # step processing. Without this, files extracted via icat (PST, OST,
        # registry hives, etc.) sit in inventory but are invisible to the
        # per-device playbook loop.
        _nuclear_findings = nuclear_result.get("nuclear_findings", [])
        _nuclear_attributed = 0
        if _nuclear_findings:
            for _nf in _nuclear_findings:
                _nf_ev_type = _nf.get("evidence_type")
                _nf_src_img = _nf.get("image")
                _nf_full_path = _nf.get("full_path")
                if not _nf_src_img or not _nf_full_path:
                    continue
                # Find the device that owns the source disk image
                for _dev_id, _dev in device_map.items():
                    if _nf_src_img in _dev.get("evidence_files", []):
                        if _nf_full_path not in _dev["evidence_files"]:
                            _dev["evidence_files"].append(_nf_full_path)
                            _nuclear_attributed += 1
                        break
            if _nuclear_attributed:
                _fe_log(job_id, f"  ♻ Nuclear attribution: {_nuclear_attributed} extracted file(s) assigned to devices")

        # Belt-and-suspenders: attribute browser_artifacts from nuclear_evidence
        # (paths merged into inventory via mount/discover that may not have
        #  individual entries in nuclear_findings, e.g. sqlite DBs, cookies, etc.)
        _nuclear_ev = nuclear_result.get("nuclear_evidence", {})

        # --- Attribute browser artifacts ---
        _browser_arts = _nuclear_ev.get("browser_artifacts", [])
        _browser_attributed = 0
        if _browser_arts:
            for _ba_path in _browser_arts:
                if not _ba_path:
                    continue
                # Determine which disk image this browser artifact came from:
                # browser artifacts from mount points have full_paths like
                #   /home/sansforensics/cases/mounts/<case>/<img>_p<offset>/...
                # Match by checking which disk image's stem appears in the path.
                for _dev_id, _dev in device_map.items():
                    for _img in _dev.get("evidence_files", []):
                        _img_stem = Path(_img).stem
                        if _img_stem in _ba_path and _ba_path not in _dev["evidence_files"]:
                            _dev["evidence_files"].append(_ba_path)
                            _browser_attributed += 1
                            break
            if _browser_attributed:
                _fe_log(job_id, f"  ♻ Browser artifact attribution: {_browser_attributed} browser file(s) assigned to devices")

        # --- Attribute email files directly from nuclear_evidence ---
        # When nuclear_findings is empty (old checkpoint, fls-only path),
        # email files found inside disk images still exist in nuclear_evidence
        # but need attribution to devices for PB-SIFT-023 to process them.
        _email_arts = _nuclear_ev.get("email_files", [])
        _email_attributed = 0
        _email_skipped_bad_path = 0
        if _email_arts:
            for _em_path in _email_arts:
                if not _em_path:
                    continue
                # Skip internal-ref paths (:: notation) that can't be used by tools
                if "::" in str(_em_path):
                    _email_skipped_bad_path += 1
                    _fe_log(job_id, f"  ⚠ Email file {Path(str(_em_path)).name} has internal-ref path — needs icat re-extraction")
                    continue
                # Verify the file actually exists on disk
                if not Path(_em_path).exists():
                    _fe_log(job_id, f"  ⚠ Email file {_em_path} not found on disk — skipping")
                    continue
                for _dev_id, _dev in device_map.items():
                    for _img in _dev.get("evidence_files", []):
                        _img_stem = Path(_img).stem
                        if _img_stem in str(_em_path) and _em_path not in _dev["evidence_files"]:
                            _dev["evidence_files"].append(_em_path)
                            _email_attributed += 1
                            break
            if _email_attributed:
                _fe_log(job_id, f"  📧 Email file attribution: {_email_attributed} email file(s) assigned to devices")
            if _email_skipped_bad_path:
                _fe_log(job_id, f"  ⚠ {_email_skipped_bad_path} email file(s) have :: internal-ref paths — PST extraction may have failed")

        # Build per-device evidence lookup
        device_evidence = {}  # device_id -> {ev_type: [paths]}
        for dev_id, dev in device_map.items():
            device_evidence[dev_id] = {
                "disk_images": [], "memory_dumps": [], "pcaps": [],
                "evtx_logs": [], "evt_logs": [], "syslogs": [], "registry_hives": [],
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

        # Log orchestration intent before the main loop
        _batch_meta = _run_forensicator_batch(
            execution_plan=execution_plan,
            device_map=device_map,
            case_work_dir=case_work_dir,
            job_id=job_id,
        )

        for dev_id, dev in device_map.items():
            dev_ev = device_evidence[dev_id]
            _fe_log(job_id, f"\n{'='*60}")
            _fe_log(job_id, f"Processing device: {dev_id} ({dev.get('device_type', 'unknown')})")
            _fe_log(job_id, f"Owner: {dev.get('owner', 'unknown')}")
            _fe_log(job_id, f"{'='*60}")

            completed_pb_dev = _scan_completed_playbooks(str(case_work_dir / "audit_trail.jsonl"))
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

                        # For other_files, only invoke email analysis on actual email files.
                        if ev_type == "other_files":
                            if Path(item).suffix.lower() not in _EMAIL_EXTENSIONS:
                                continue

                        item_stem = Path(item).stem
                        for module, function, raw_params in step_templates:
                            # Filter mobile steps by device type
                            if playbook_id == "PB-SIFT-021":
                                device_type = (dev.get("device_type") or "").lower()
                                is_ios = device_type in ("ios_mobile", "ios")
                                is_android = device_type in ("android_mobile", "android")
                            
                                # iOS-only steps
                                if function.startswith("extract_ios_") or function in ("analyze_ios_backup", "run_ileapp"):
                                    if not is_ios:
                                        continue
                                # Android-only steps
                                elif function.startswith("extract_android_") or function in ("analyze_android", "run_aleapp"):
                                    if not is_android:
                                        continue
                                # Platform-agnostic steps (whatsapp, telegram, photo_exif) — skip if neither
                                elif function in ("extract_whatsapp", "extract_telegram", "extract_mobile_photo_exif"):
                                    if not (is_ios or is_android):
                                        continue

                            _update_job(pb_progress_base, playbook_id, f"{module}.{function}")

                            # Build actual params by substituting placeholders
                            params = {}
                            for k, v in raw_params.items():
                                if isinstance(v, str):
                                    v = v.replace("{image}", item)
                                    v = v.replace("{mem}", item)
                                    v = v.replace("{pcap}", item)
                                    v = v.replace("{evtx}", item)
                                    v = v.replace("{evt}", item)
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

                            # Dedup: skip if this exact tool+file+params already ran
                            exec_key = _make_exec_key(module, function, item, params)
                            cached = exec_cache.get(exec_key)
                            if cached is not None:
                                step_record = {"playbook": playbook_id, "module": module, "function": function, "device": dev_id, "evidence": Path(item).name, "status": "completed", "result": cached, "_deduped": True}
                                findings_writer.append(step_record)
                                pb_findings.append(step_record)
                                steps_completed += 1
                                _fe_log(job_id, f"  deduped {module}.{function} ({Path(item).name})")
                                continue
                            # Retry logic for transient failures
                            # Catches BOTH exceptions AND error-status results
                            # (orchestrator returns {"status": "error"} dicts, not exceptions)
                            MAX_RETRIES = 2
                            for attempt in range(MAX_RETRIES + 1):
                                try:
                                    result = _run_step_via_orchestrator(module, function, params, job_id=job_id)
                                except Exception as retry_exc:
                                    if attempt < MAX_RETRIES:
                                        _fe_log(job_id, f"  ↻ {module}.{function} retry {attempt+1}/{MAX_RETRIES}: {retry_exc}")
                                        time.sleep(1 * (attempt + 1))
                                        continue
                                    result = {"status": "error", "error": f"Failed after {MAX_RETRIES} retries: {retry_exc}"}
                                    break
                                # Check for error-status results (not exceptions) — retry these too
                                if isinstance(result, dict) and result.get("status") == "error":
                                    if attempt < MAX_RETRIES:
                                        err_detail = result.get("error", result.get("stderr", "unknown"))
                                        _fe_log(job_id, f"  ↻ {module}.{function} retry {attempt+1}/{MAX_RETRIES} (error: {str(err_detail)[:120]})")
                                        time.sleep(2 * (attempt + 1))
                                        continue
                                    # Last attempt gave error — keep it but mark exhausted
                                    result["_retries_exhausted"] = True
                                # Success or final failure — cache and proceed
                                if result.get("status") != "error" or attempt == MAX_RETRIES:
                                    exec_cache.set(exec_key, result)
                                    break

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

                                    # LLM-POWERED SELF-HEALING: Delegate to _attempt_heal
                                    try:
                                        _fe_log(job_id, f"  🔄 Self-heal analyzing failure for {module}.{function}...")
                                        healed = _attempt_heal(
                                            module, function, params, result, job_id,
                                            evidence_file=item,
                                            evidence_type=_infer_evidence_type(item),
                                            os_type=os_type,
                                        )
                                        if healed is not None:
                                            if healed.get("status") == "success":
                                                step_record["status"] = "completed"
                                                step_record["result"] = healed
                                                step_record["_self_healed"] = True
                                                step_record["_heal_fix_type"] = healed.get("_heal_fix_type")
                                                step_record["_heal_confidence"] = healed.get("_heal_confidence")
                                                steps_failed -= 1
                                                steps_completed += 1
                                                _fe_log(job_id, f"  ✓ Self-healed {module}.{function}: {healed.get('_heal_fix_type')}")
                                                result = healed
                                            elif healed.get("status") == "skipped":
                                                step_record["status"] = "skipped"
                                                step_record["_self_healed"] = True
                                                step_record["_healing_strategy"] = "skip_on_critic_advice"
                                                steps_failed -= 1
                                                steps_skipped += 1
                                    except Exception as heal_err:
                                        _fe_log(job_id, f"  ⚠ Self-heal error: {heal_err}")

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
                                        # Handle Ollama timeout — forensicator marks needs_review
                                        if forensicator_notes.get("needs_review") and forensicator_notes.get("error") == "ollama_timeout":
                                            step_record["needs_review"] = True
                                            step_record["unverified_reason"] = forensicator_notes.get("unverified_reason", "Ollama timeout")
                                            _fe_log(job_id, f"  ⚠ Forensicator Ollama timeout for {module}.{function} — marked needs_review")
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

                                    # Handle Ollama timeout — critic marks needs_review
                                    if isinstance(critic_val, dict) and critic_val.get("needs_review") and critic_val.get("unverified_reason"):
                                        step_record["needs_review"] = True
                                        step_record["unverified_reason"] = critic_val.get("unverified_reason", "Ollama timeout")
                                        _fe_log(job_id, f"  ⚠ Critic Ollama timeout for {module}.{function} — marked needs_review")
                                        # Skip further critic processing for this step
                                    elif isinstance(critic_val, dict) and critic_val.get("passes_sanity") is False:
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
                                                        device_id=dev_id,
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
                                                device_id=dev_id, reason=issues[:5],
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

                            # Per-step git commit with chain-of-custody metadata
                            if step_record.get("status") in (
                                "completed", "completed_unverified"
                            ):
                                _cust = _commit_step_with_custody(
                                    step_record, item, case_work_dir, job_id
                                )
                                if _cust.get("status") == "failed":
                                    _fe_log(job_id, (
                                        f"  ⚠ Custody commit failed for {step_key}: "
                                        f"{_cust.get('error', 'unknown')}"
                                    ))

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
                        _audit_append(case_work_dir, "anti_forensics_cascade", device_id=dev_id)
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
                    playbook_id=playbook_id, device_id=dev_id,
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

                # --- Adaptive re-evaluation after each playbook ---
                # Check what new artifacts were discovered and add playbooks
                # that are now applicable. Pull every thread.
                _newly_queued = _re_evaluate_playbooks(
                    playbook_id, pb_findings, execution_plan, skipped_playbooks,
                    inventory, os_type, has_disk_images, _disk_artifacts,
                    indicator_hits, job_id)
                if _newly_queued:
                    _fe_log(job_id, f"  \u27f3 Re-evaluation queued: {', '.join(_newly_queued)}")

        # End of per-device playbook loop
        # Process unattributed evidence (PCAPs, logs not tied to a device)
        if any(unattributed_ev.values()):
            _fe_log(job_id, "\nProcessing unattributed evidence...")
            for ev_type, files in unattributed_ev.items():
                if not files:
                    continue
                _fe_log(job_id, f"  Unattributed {ev_type}: {len(files)} files")
                # Run relevant playbooks against unattributed evidence
                completed_pb_dev = _scan_completed_playbooks(str(case_work_dir / "audit_trail.jsonl"))
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

        # --- Mark playbooks phase complete in checkpoint ---
        _ckpt_mark_phase(ckpt, "playbooks", "complete")
        _ckpt_save(case_work_dir, ckpt)

        # If PB-SIFT-012 fired earlier in the plan, any findings produced by
        # later playbooks won't have been downgraded yet. Apply the cascade once
        # more now that every playbook has run. The helper is idempotent, so
        # findings already tagged by the first pass are skipped.
        if anti_forensics_detected:
            late = _apply_anti_forensics_cascade(findings_writer)
            if late:
                _fe_log(job_id, f"⚠ Anti-forensics cascade (final pass): downgraded {late} additional findings produced after PB-SIFT-012")
                _audit_append(case_work_dir, "anti_forensics_cascade_final", late_findings=late)

        # Collect paths that had at least one step record them as evidence_file
        processed_paths = set()
        for rec in findings_writer.all_records():
            ef = rec.get("evidence_file")
            if ef:
                processed_paths.add(str(ef))

        # ------------------------------------------------------------------
        # Phase 68%: Transition — prepare for timeline analysis
        # ------------------------------------------------------------------
        _update_job(68, "super-timeline", "Building unified timeline from Pass 1 findings")

        # ------------------------------------------------------------------
        # Phase 70%: Super Timeline Build (moved from 90%)
        # This is now the PASS BOUNDARY — timeline intelligence drives Pass 2
        # ------------------------------------------------------------------
        _update_job(70, "super-timeline", "Building unified timeline")
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
        # Phase 73%: Timeline Intelligence Analysis (NEW)
        # Analyse cross-device patterns and generate Pass 2 triggers
        # ------------------------------------------------------------------
        _update_job(73, "timeline-intel", "Analysing cross-device patterns")
        timeline_intelligence = {}
        try:
            timeline_intelligence = _timeline_intelligence_analysis(
                super_timeline_events=super_timeline_events,
                device_map=device_map,
                indicator_hits=indicator_hits,
                job_id=job_id,
                fe_log_func=_fe_log,
            )
            # Persist timeline intelligence to disk
            _atomic_write(
                case_work_dir / "timeline_intelligence.json",
                json.dumps(timeline_intelligence, indent=2, default=str),
            )
            _fe_log(job_id, f"Timeline intelligence: {len(timeline_intelligence.get('pass2_playbook_triggers', []))} Pass 2 triggers")
        except Exception as e:
            _fe_log(job_id, f"Timeline intelligence analysis failed: {e}")
            timeline_intelligence = {"pass2_playbook_triggers": []}

        # ------------------------------------------------------------------
        # Phase 75%: Manager Review of Pass 2 Triggers (NEW)
        # Manager decides which triggers are worth pursuing
        # ------------------------------------------------------------------
        _update_job(75, "manager-review", "Reviewing Pass 2 triggers")
        pass2_triggers = timeline_intelligence.get("pass2_playbook_triggers", [])
        approved_pass2_triggers = []
        try:
            approved_pass2_triggers = _manager_review_pass2_triggers(
                triggers=pass2_triggers,
                pass1_findings=findings_writer.all_records(),
                job_id=job_id,
                fe_log_func=_fe_log,
            )
            _fe_log(job_id, f"Manager approved {len(approved_pass2_triggers)}/{len(pass2_triggers)} Pass 2 triggers")
        except Exception as e:
            _fe_log(job_id, f"Manager Pass 2 review failed: {e}")
            approved_pass2_triggers = []

        # ------------------------------------------------------------------
        # Phase 77%: Pass 2 Execution (NEW)
        # Execute targeted playbooks for approved triggers
        # ------------------------------------------------------------------
        _update_job(77, "pass2", "Executing Pass 2 investigations")
        pass2_results = {}
        try:
            pass2_results = _execute_pass2(
                triggers=approved_pass2_triggers,
                device_map=device_map,
                case_work_dir=case_work_dir,
                findings_writer=findings_writer,
                image_offsets=image_offsets,
                inventory=inventory,
                job_id=job_id,
                fe_log_func=_fe_log,
            )
            _fe_log(job_id, f"Pass 2: {len(pass2_results.get('playbooks_run', []))} playbooks, {pass2_results.get('findings_count', 0)} findings")
            # Merge Pass 2 findings into the main findings_writer so that
            # severity_counts, evil_found, findings_detail, and narrative report
            # anchors all include Pass 2 data.
            for pf in pass2_results.get('findings', []):
                if isinstance(pf, dict) and not findings_writer.is_completed(pf.get('step_key', '')):
                    findings_writer.append(pf)
        except Exception as e:
            _fe_log(job_id, f"Pass 2 execution failed: {e}")
            pass2_results = {"playbooks_run": [], "findings": []}

        # ------------------------------------------------------------------
        # Phase 80%: Batch Critic Review (now includes Pass 2 findings)
        # ------------------------------------------------------------------
        manager_decision = {"action": "approve", "replay_adjustments": {}, "generate_report": True}
        _update_job(80, "batch-critic", "Batch Critic reviewing all findings (Pass 1 + Pass 2)")
        # Pass 2 findings have already been merged into findings_writer above
        all_findings = findings_writer.all_records()
        try:
            _batch_assess = _batch_critic_review_all_playbooks(
                findings=all_findings,
                playbooks_run=playbooks_run,
                case_work_dir=case_work_dir,
                job_id=job_id,
            )
            manager_decision = _manager_post_critic_decision(
                batch_assessment=_batch_assess,
                findings=findings_writer.all_records(),
                case_work_dir=case_work_dir,
                job_id=job_id,
            )
        except Exception as _batch_err:
            _fe_log(job_id, f"  ⚠ Batch Critic/Manager failed: {_batch_err} — defaulting to approve")

        # --- Incremental Replay: re-run steps with Manager-patched params ---
        replay_adjustments = manager_decision.get("replay_adjustments", {})
        if manager_decision.get("action") == "replay" and replay_adjustments:
            _update_job(85, "replay", f"Replaying {len(replay_adjustments)} step(s) with adjusted params")
            _fe_log(job_id, f"  [REPLAY] Manager flagged {len(replay_adjustments)} step(s) for incremental replay")
            for _rk, _rparams in replay_adjustments.items():
                # Find the original step record
                _orig = next((f for f in findings_writer.all_records() if f.get("step_key") == _rk), None)
                if _orig is None:
                    _fe_log(job_id, f"  ⚠ Replay: step_key {_rk!r} not found in findings — skipping")
                    continue
                _module   = _orig.get("module", "")
                _function = _orig.get("function", "")
                _ev_file  = _orig.get("evidence_file", "")
                # Merge original params with Manager adjustments
                _merged_params = {**_orig.get("params", {}), **_rparams}
                _fe_log(job_id, f"  [REPLAY] {_module}.{_function} | adjusted params: {list(_rparams.keys())}")
                try:
                    _replay_result = _run_step_via_orchestrator(_module, _function, _merged_params)
                    _replay_status = "completed" if _replay_result.get("status") == "success" else "failed"
                    _replay_record = {
                        **_orig,
                        "params": _merged_params,
                        "result": _replay_result,
                        "status": _replay_status,
                        "replayed": True,
                        "replay_adjustments": _rparams,
                        "started_at": _orig.get("started_at"),
                        "completed_at": datetime.now().isoformat(),
                    }
                    findings_writer.append(_replay_record)
                    if _replay_status == "completed":
                        steps_completed += 1
                        _fe_log(job_id, f"  ✓ Replay succeeded: {_module}.{_function}")
                        # Commit replayed step with custody
                        _cust = _commit_step_with_custody(_replay_record, _ev_file, case_work_dir, job_id)
                        if _cust.get("status") == "failed":
                            _fe_log(job_id, f"  ⚠ Replay custody commit failed: {_cust.get('error')}")
                    else:
                        steps_failed += 1
                        _fe_log(job_id, f"  ✗ Replay failed: {_module}.{_function}")
                except Exception as _re:
                    _fe_log(job_id, f"  ✗ Replay error for {_rk}: {_re}")

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

        # Flag if no behavioral data recovered from any device
        if not all_behavioral_flags or all(len(flags) == 0 for flags in all_behavioral_flags.values()):
            _fe_log(job_id, "⚠️  No behavioral data recovered from any device — potential anti-forensics")
            if not all_behavioral_flags:
                all_behavioral_flags = {}
            all_behavioral_flags["_no_recovery"] = [{
                "flag_type": "no_recovery",
                "severity": "MEDIUM",
                "description": "No behavioral data recovered from evidence — potential anti-forensics (wiped, encrypted, or corrupted)",
                "device_id": "all"
            }]

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
        # Phase 10: IP/MAC/Hostname Extraction & Connectivity Mapping
        # ------------------------------------------------------------------
        _update_job(96, "network-map", "Building IP connectivity map")
        ips_map = {}
        connection_map_results = {}
        try:
            ips_map, connection_map_results = _extract_ips_from_evidence(inventory, case_work_dir)
            _fe_log(job_id, f"IP mapping: {len(ips_map)} device entries, {len(connection_map_results.get('connection_map', []))} connections")
        except Exception as e:
            _fe_log(job_id, f"IP mapping failed: {e}")
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
                    # No recovery = potential anti-forensics
                    if flag.get("flag_type") == "no_recovery":
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
            # Pass 2 timeline-driven investigation results
            "timeline_intelligence": {
                "cross_device_process_chains": timeline_intelligence.get("cross_device_process_chains", []),
                "usb_lateral_movement": timeline_intelligence.get("usb_lateral_movement", []),
                "off_hours_clusters": timeline_intelligence.get("off_hours_clusters", []),
                "file_beaconing_patterns": timeline_intelligence.get("file_beaconing_patterns", []),
                "ioc_correlations": timeline_intelligence.get("ioc_correlations", []),
                "dwell_time_window": timeline_intelligence.get("dwell_time_window", {}),
            },
            "pass2_triggers": [
                {
                    "trigger_id": t.get("trigger_id", ""),
                    "trigger_type": t.get("trigger_type", ""),
                    "playbook_id": t.get("playbook_id", ""),
                    "priority": t.get("priority", ""),
                    "devices_involved": t.get("devices_involved", []),
                    "approved": t.get("trigger_id") in [at.get("trigger_id") for at in approved_pass2_triggers],
                }
                for t in (pass2_triggers if 'pass2_triggers' in dir() else [])
            ],
            "pass2_playbooks_run": pass2_results.get("playbooks_run", []),
            "pass2_findings_count": pass2_results.get("findings_count", 0),
            "pass2_steps_completed": pass2_results.get("steps_completed", 0),
            "pass2_steps_failed": pass2_results.get("steps_failed", 0),
            "pass2_steps_skipped": pass2_results.get("steps_skipped", 0),
            "pass2_findings_detail": pass2_results.get("findings", []),
            # Phase 10: IP/MAC/Connectivity mapping
            "ips_map": ips_map,
            "connection_map": connection_map_results.get("connection_map", []),
            "external_contacts": connection_map_results.get("external_contacts", []),
        }

        # --- Post-run retry: reprocess unprocessed files with relaxed limits ---
        _retry_summary = _retry_unprocessed(
            findings_writer=findings_writer,
            inventory=inventory,
            image_offsets=image_offsets,
            case_work_dir=case_work_dir,
            evidence_path=evidence_path,
            execution_plan=execution_plan,
            job_id=job_id,
            fe_log_func=_fe_log,
        )
        report["post_run_retry"] = _retry_summary

        # Recompute processed paths after retry (retry may have added records)
        processed_paths = set()
        for rec in findings_writer.all_records():
            ef = rec.get("evidence_file")
            if ef:
                processed_paths.add(str(ef))

        # Compute unprocessed evidence files and categorize reasons
        unprocessed_files = _classify_unprocessed(
            all_inventory_paths, processed_paths, inventory, execution_plan
        )
        report["unprocessed_files"] = unprocessed_files
        report["unprocessed_files_count"] = len(unprocessed_files)
        reason_counts = Counter(f["reason"] for f in unprocessed_files)
        report["unprocessed_files_summary"] = dict(reason_counts)

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
        # Phase 5b: Direct Email Extraction (bypasses mount/discover)
        # ------------------------------------------------------------------
        _update_job(96, "email_extract", "Direct PST extraction from disk images")
        _email_result = _direct_email_extraction(inventory, findings_writer, case_work_dir, job_id)
        if _email_result and isinstance(_email_result, dict) and _email_result.get("email_iocs"):
            report["email_iocs"] = _email_result["email_iocs"].copy()
            report["email_direct_findings"] = True

        # ------------------------------------------------------------------
        # Phase 5c: Narrative Report
        # Gated on manager_decision['generate_report'].
        # ------------------------------------------------------------------
        _update_job(98, "narrative", "Generating human-readable report")
        _generate_narrative = manager_decision.get("generate_report", True)
        if not _generate_narrative:
            _fe_log(job_id, "  [BATCH] Manager decision: skip narrative report (insufficient evidence)")
        if _generate_narrative:
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
        else:
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

        # Mark report phase complete
        _ckpt_mark_phase(ckpt, "report", "complete")
        _ckpt_save(case_work_dir, ckpt)

    except (KeyboardInterrupt, SystemExit):
        _cleanup_mounts()
        raise
    except BaseException as e:
        with open('/tmp/geoff_crash.log', 'a') as f:
            f.write(f"FIND_EVIL_CRASH | {datetime.now().isoformat()} | {type(e).__name__}: {e}\n")
            traceback.print_exc(file=f)
            f.write("---\n")
        traceback.print_exc(file=sys.stderr)
        _fe_log(job_id if 'job_id' in dir() else None, f"  💀 FIND_EVIL CRASHED: {type(e).__name__}: {e}")
        _cleanup_mounts()
        return {
            "status": "error",
            "error": f"{type(e).__name__}: {e}",
            "evidence_dir": evidence_dir,
            "elapsed_seconds": round(time.time() - start_time, 1),
        }
    _cleanup_mounts()
    return report


def _direct_email_extraction(inventory: dict, findings_writer, case_work_dir, job_id: str = None):
    """Direct PST/OST extraction bypassing mount/discover entirely.

    For each disk image, mounts via ewfmount (E01) or reads directly (raw),
    uses fls to find .pst/.ost files, extracts them via icat, converts to
    .eml via readpst -M, and runs phishing detection. All findings are
    written to findings_writer.

    This is a completely self-contained path that does NOT depend on any
    mount/discover attribution code or virtual path resolution.
    """
    disk_images = inventory.get("disk_images", [])
    if not disk_images:
        _fe_log(job_id, "  [EMAIL_DIRECT] No disk images in inventory — skipping")
        return

    _fe_log(job_id, f"  [EMAIL_DIRECT] Direct PST scan on {len(disk_images)} disk image(s)")

    from sift_specialists_extended import EMAIL_Specialist
    email_spec = EMAIL_Specialist()

    for img_path in disk_images:
        img_name = Path(img_path).name
        img_stem = Path(img_path).stem
        _fe_log(job_id, f"  [EMAIL_DIRECT] Processing: {img_name}")

        ewf_raw_dir = None
        extract_dir = None
        try:
            ewf_raw_dir = f"/tmp/geoff_ewf_pst_{os.getpid()}_{img_stem}"
            os.makedirs(ewf_raw_dir, exist_ok=True)

            # Step 1: ewfmount for E01 or use raw device directly
            device = img_path
            ewf_result = subprocess.run(
                ["ewfmount", img_path, ewf_raw_dir],
                capture_output=True, text=True, timeout=60,
            )
            if ewf_result.returncode == 0:
                device = f"{ewf_raw_dir}/ewf1"
                _fe_log(job_id, f"    ewfmount OK → {device}")
            else:
                _fe_log(job_id, f"    ewfmount skipped (raw or non-E01), using direct path")

            # Step 2: mmls to find partition offset
            offset = 63  # default DOS/MBR
            mmls_r = subprocess.run(
                ["mmls", device],
                capture_output=True, text=True, timeout=30,
            )
            if mmls_r.returncode == 0:
                for line in mmls_r.stdout.splitlines():
                    parts = line.split()
                    if len(parts) >= 5 and parts[0].rstrip(":").isdigit():
                        try:
                            start = int(parts[2])
                            if start > 0:
                                offset = start
                                desc = " ".join(parts[4:]) if len(parts) > 4 else ""
                                _fe_log(job_id, f"    mmls partition: sector {offset} ({desc})")
                                break
                        except ValueError:
                            pass

            # Step 3: fls -r to find .pst/.ost files
            fls_r = subprocess.run(
                ["fls", "-o", str(offset), "-r", device],
                capture_output=True, text=True, timeout=300,
            )
            if fls_r.returncode != 0:
                _fe_log(job_id, f"    fls failed: {fls_r.stderr[:200]}")
                continue

            # Parse fls output lines like "r/r 12345-128-1: filename.pst"
            pst_files = []
            for line in fls_r.stdout.splitlines():
                line = line.strip()
                if not line or ":" not in line:
                    continue
                meta, fname = line.split(":", 1)
                meta = meta.strip()
                fname = fname.strip()
                if not (fname.lower().endswith('.pst') or fname.lower().endswith('.ost')):
                    continue
                inode_match = re.search(r'(\d[\d\-]+)\s*$', meta)
                if inode_match:
                    pst_files.append((inode_match.group(1), fname))

            if not pst_files:
                _fe_log(job_id, f"    No .pst/.ost files found on this image")
                continue

            _fe_log(job_id, f"    Found {len(pst_files)} PST/OST file(s)")

            extract_dir = f"/tmp/geoff_direct_pst_{os.getpid()}_{img_stem}"
            os.makedirs(extract_dir, exist_ok=True)

            for inode, fname in pst_files:
                safe_name = re.sub(r'[^a-zA-Z0-9._-]', '_', fname)
                pst_out = os.path.join(extract_dir, safe_name)
                _fe_log(job_id, f"    Extracting: {fname} (inode={inode})")

                # Step 4: icat extraction
                try:
                    with open(pst_out, "wb") as fh:
                        icat_r = subprocess.run(
                            ["icat", "-o", str(offset), device, inode],
                            stdout=fh, stderr=subprocess.PIPE, timeout=300,
                        )
                    if icat_r.returncode != 0 or os.path.getsize(pst_out) == 0:
                        _fe_log(job_id, f"      icat failed: {icat_r.stderr.decode()[:200] if icat_r.stderr else 'empty output'}")
                        continue
                except Exception as e:
                    _fe_log(job_id, f"      icat error: {e}")
                    continue

                # Step 5: readpst -M to convert to .eml
                eml_dir = os.path.join(extract_dir, f"eml_{safe_name}")
                os.makedirs(eml_dir, exist_ok=True)
                rpst_r = subprocess.run(
                    ["readpst", "-M", "-o", eml_dir, pst_out],
                    capture_output=True, text=True, timeout=300,
                )
                if rpst_r.returncode != 0:
                    _fe_log(job_id, f"      readpst failed: {rpst_r.stderr[:200]}")
                    continue

                eml_count = sum(1 for _ in Path(eml_dir).rglob("*.eml"))
                _fe_log(job_id, f"      Converted → {eml_count} .eml files")

                # Step 6: Phishing detection
                try:
                    phishing_result = email_spec.detect_phishing(eml_dir)
                    phish_findings = phishing_result.get("findings", [])
                    emails_scanned = phishing_result.get("emails_scanned", 0)
                    phishing_found = phishing_result.get("phishing_found", 0)

                    _fe_log(job_id, f"      Phishing: {emails_scanned} scanned, {phishing_found} suspicious")

                    # Step 6b: Extract email IOCs from .eml headers
                    # Aggregate IOC collections for this PST/eml set
                    email_iocs_agg = {
                        "from_addresses": [],
                        "to_addresses": [],
                        "return_paths": [],
                        "sender_ips": [],
                        "subjects": [],
                        "urls_in_body": [],
                        "return_path_mismatches": [],
                        "spoofed_domains": [],
                    }

                    import email as email_lib
                    from email import policy as email_policy

                    # Readpst outputs files without .eml extension (1, 2, 3...)
                    eml_files = list(Path(eml_dir).rglob("*.eml"))
                    eml_files += [f for f in Path(eml_dir).rglob("*") if f.is_file() and "." not in f.name and f.stat().st_size > 100]
                    for eml_file in eml_files:
                        try:
                            with open(eml_file, "rb") as fh:
                                msg = email_lib.message_from_binary_file(
                                    fh, policy=email_policy.default)

                            # Extract header fields
                            from_addr = str(msg.get("From", "")).strip()
                            to_addr = str(msg.get("To", "")).strip()
                            subject = str(msg.get("Subject", "")).strip()
                            date = str(msg.get("Date", "")).strip()
                            return_path = str(msg.get("Return-Path", "")).strip()
                            reply_to = str(msg.get("Reply-To", "")).strip()

                            # Extract From domain for spoofing check
                            from_domain = None
                            from_match = re.search(r'@([\w.-]+)', from_addr)
                            if from_match:
                                from_domain = from_match.group(1).lower().rstrip(">")

                            # Extract sender IPs from Received: headers
                            received_headers = msg.get_all("Received", [])
                            sender_ips = []
                            if received_headers:
                                for rcvd in received_headers:
                                    rcvd_str = str(rcvd)
                                    ips = re.findall(
                                        r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b',
                                        rcvd_str
                                    )
                                    for ip in ips:
                                        parts = ip.split(".")
                                        if all(0 <= int(p) <= 255 for p in parts):
                                            sender_ips.append(ip)

                            # Extract URLs from email body
                            body_text = ""
                            if msg.is_multipart():
                                for part in msg.walk():
                                    if part.get_content_type() == "text/plain":
                                        payload = part.get_payload(decode=True)
                                        if payload:
                                            try:
                                                body_text = payload.decode(
                                                    "utf-8", errors="replace")
                                            except Exception:
                                                body_text = str(payload)[:5000]
                                            break
                                    elif part.get_content_type() == "text/html":
                                        payload = part.get_payload(decode=True)
                                        if payload and not body_text:
                                            try:
                                                html = payload.decode(
                                                    "utf-8", errors="replace")
                                                body_text = re.sub(
                                                    r'<[^>]+>', ' ', html)[:5000]
                                            except Exception:
                                                pass
                            else:
                                payload = msg.get_payload(decode=True)
                                if payload:
                                    try:
                                        body_text = payload.decode(
                                            "utf-8", errors="replace")
                                    except Exception:
                                        body_text = str(payload)[:5000]

                            body_urls = list(dict.fromkeys(
                                re.findall(r'https?://[^\s<>"\')\]]+', body_text)
                            ))[:20]

                            # Collect IOCs for aggregation
                            if from_addr:
                                email_iocs_agg["from_addresses"].append(from_addr)
                            if to_addr:
                                email_iocs_agg["to_addresses"].append(to_addr)
                            if return_path:
                                email_iocs_agg["return_paths"].append(return_path)
                            if subject:
                                email_iocs_agg["subjects"].append(subject)
                            for ip in sender_ips:
                                if ip not in email_iocs_agg["sender_ips"]:
                                    email_iocs_agg["sender_ips"].append(ip)
                            for url in body_urls:
                                if url not in email_iocs_agg["urls_in_body"]:
                                    email_iocs_agg["urls_in_body"].append(url)

                            # Domain spoofing: Return-Path differs from From
                            if return_path and from_addr:
                                rp_match = re.search(r'@([\w.-]+)', return_path)
                                if rp_match:
                                    rp_domain = rp_match.group(1).lower().rstrip(">")
                                    if from_domain and rp_domain != from_domain:
                                        mismatch = {
                                            "from": from_addr,
                                            "from_domain": from_domain,
                                            "return_path": return_path,
                                            "return_path_domain": rp_domain,
                                            "eml_path": str(eml_file),
                                        }
                                        email_iocs_agg["return_path_mismatches"].append(
                                            mismatch)
                                        if from_domain not in email_iocs_agg["spoofed_domains"]:
                                            email_iocs_agg["spoofed_domains"].append(
                                                from_domain)

                        except Exception:
                            continue  # Skip malformed email files silently

                    # Deduplicate address lists
                    email_iocs_agg["from_addresses"] = list(dict.fromkeys(
                        email_iocs_agg["from_addresses"]))[:30]
                    email_iocs_agg["to_addresses"] = list(dict.fromkeys(
                        email_iocs_agg["to_addresses"]))[:30]
                    email_iocs_agg["return_paths"] = list(dict.fromkeys(
                        email_iocs_agg["return_paths"]))[:30]

                    _fe_log(job_id,
                        f"      Email IOCs: {len(email_iocs_agg['sender_ips'])} sender IP(s), "
                        f"{len(email_iocs_agg['from_addresses'])} from address(es), "
                        f"{len(email_iocs_agg['urls_in_body'])} URL(s), "
                        f"{len(email_iocs_agg['return_path_mismatches'])} R-P mismatch(es)")

                    # Build a text dump of IOCs for the regex scanner in
                    # _extract_iocs() to pick up (IPs, email addresses, URLs)
                    ioc_text_lines = []
                    for ip in email_iocs_agg["sender_ips"]:
                        ioc_text_lines.append(f"sender-ip: {ip}")
                    for addr in email_iocs_agg["from_addresses"]:
                        ioc_text_lines.append(f"from: {addr}")
                    for addr in email_iocs_agg["to_addresses"]:
                        ioc_text_lines.append(f"to: {addr}")
                    for addr in email_iocs_agg["return_paths"]:
                        ioc_text_lines.append(f"return-path: {addr}")
                    for url in email_iocs_agg["urls_in_body"]:
                        ioc_text_lines.append(f"url: {url}")
                    ioc_text = "\n".join(ioc_text_lines)

                    # Step 7: Write findings to findings_writer, enriched with IOCs
                    for pf in phish_findings:
                        step_key = (
                            f"direct_email|{img_stem}|{safe_name}|"
                            f"{pf.get('eml_path', 'unknown')}"
                        )
                        if not findings_writer.is_completed(step_key):
                            # Enrich finding with email IOCs
                            enriched_result = dict(pf)
                            enriched_result["raw_output"] = ioc_text
                            enriched_result["email_iocs"] = {
                                "sender_ips": email_iocs_agg["sender_ips"],
                                "from_addresses": email_iocs_agg["from_addresses"],
                                "to_addresses": email_iocs_agg["to_addresses"],
                                "return_paths": email_iocs_agg["return_paths"],
                                "urls_in_body": email_iocs_agg["urls_in_body"],
                                "return_path_mismatches": email_iocs_agg[
                                    "return_path_mismatches"],
                                "spoofed_domains": email_iocs_agg["spoofed_domains"],
                            }
                            findings_writer.append({
                                "step_key": step_key,
                                "playbook": "EMAIL_DIRECT",
                                "function": "detect_phishing",
                                "status": "completed",
                                "evidence_file": img_path,
                                "evidence_type": "email",
                                "source": fname,
                                "result": enriched_result,
                                "severity": (
                                    "MEDIUM" if pf.get("confidence", 0) < 0.7
                                    else "HIGH"
                                ),
                                "needs_review": True,
                                "started_at": datetime.now().isoformat(),
                                "completed_at": datetime.now().isoformat(),
                            })

                    # Write a benign scan record for audit trail (even if 0 hits),
                    # also enriched with email IOCs
                    scan_key = f"direct_email|{img_stem}|{safe_name}|scan"
                    if not findings_writer.is_completed(scan_key):
                        findings_writer.append({
                            "step_key": scan_key,
                            "playbook": "EMAIL_DIRECT",
                            "function": "email_scan",
                            "status": "completed",
                            "evidence_file": img_path,
                            "evidence_type": "email",
                            "source": fname,
                            "result": {
                                "tool": "email_scan",
                                "emails_scanned": emails_scanned,
                                "phishing_found": phishing_found,
                                "raw_output": ioc_text,
                                "email_iocs": {
                                    "sender_ips": email_iocs_agg["sender_ips"],
                                    "from_addresses": email_iocs_agg[
                                        "from_addresses"],
                                    "to_addresses": email_iocs_agg[
                                        "to_addresses"],
                                    "return_paths": email_iocs_agg[
                                        "return_paths"],
                                    "urls_in_body": email_iocs_agg[
                                        "urls_in_body"],
                                    "return_path_mismatches": email_iocs_agg[
                                        "return_path_mismatches"],
                                    "spoofed_domains": email_iocs_agg[
                                        "spoofed_domains"],
                                },
                                "note": (
                                    "No phishing indicators detected"
                                    if phishing_found == 0
                                    else (
                                        f"{phishing_found} phishing indicator(s) "
                                        f"found"
                                    )
                                ),
                            },
                            "severity": "INFO",
                            "started_at": datetime.now().isoformat(),
                            "completed_at": datetime.now().isoformat(),
                        })

                except Exception as e:
                    _fe_log(job_id, f"      Phishing detection error: {e}")

        except Exception as e:
            _fe_log(job_id, f"  [EMAIL_DIRECT] Error processing {img_name}: {e}")
        finally:
            # Cleanup temp dirs
            import shutil
            if ewf_raw_dir:
                shutil.rmtree(ewf_raw_dir, ignore_errors=True)
            if extract_dir:
                shutil.rmtree(extract_dir, ignore_errors=True)

    # Commit EMAIL_DIRECT findings and stamp source_commit on each record
    _commit_result = safe_git_commit(
        "EMAIL_DIRECT: email extraction findings committed",
        base_path=str(case_work_dir)
    )
    _email_hash = _commit_result.get("hash", "") if _commit_result else ""
    if _email_hash:
        _findings_path = case_work_dir / "findings.jsonl"
        if _findings_path.exists():
            _records = []
            for line in _findings_path.read_text().splitlines():
                if line.strip():
                    rec = json.loads(line)
                    if rec.get("playbook") == "EMAIL_DIRECT" and not rec.get("source_commit"):
                        rec["source_commit"] = _email_hash
                        rec["source_step"] = rec.get("step_key", "")
                    _records.append(rec)
            _findings_path.write_text(
                "\n".join(json.dumps(r, default=str) for r in _records) + "\n"
            )
        _fe_log(job_id, f"  [EMAIL_DIRECT] Stamped {_email_hash[:12]} on EMAIL_DIRECT findings")

    _fe_log(job_id, "  [EMAIL_DIRECT] Direct email extraction complete")
    try:
        return {"email_iocs": email_iocs_agg}
    except NameError:
        return {}


# Phase 10 functions → geoff_utils.py (_is_rfc1918, _extract_ips_from_evidence, _build_connectivity_map)
# RFC1918_NETS → also in geoff_utils (used by _is_rfc1918 via ipaddress module)


