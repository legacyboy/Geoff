#!/usr/bin/env python3
"""Geoff DFIR — Job Queue Manager.

Persistent evidence queue with auto-advance, cancel/cleanup, and priority reordering.
Thread-safe via threading.Lock. Persisted to QUEUE_FILE between restarts.
"""
import glob as _glob
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Optional, Callable

from geoff_logger import get_logger as _get_logger
_qlog = _get_logger("geoff.queue")

from geoff_logger import get_logger as _get_logger
_qlog = _get_logger("geoff.queue")

QUEUE_FILE = "/mnt/cases/.geoff_queue.json"

_lock = threading.Lock()
_start_job_fn: Optional[Callable] = None


def set_start_job_fn(fn: Callable) -> None:
    global _start_job_fn
    _start_job_fn = fn


@dataclass
class QueueItem:
    id: str
    evidence_path: str
    display_name: str
    priority: int
    status: str            # queued | running | completed | failed | cancelled
    job_id: Optional[str]
    progress_pct: float
    current_playbook: str
    current_step: str
    elapsed_seconds: float
    queued_at: str
    started_at: Optional[str]
    completed_at: Optional[str]
    result_summary: Optional[str]
    error: Optional[str]
    created_by: str        # user | auto | cron


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _log_error(msg: str) -> None:
    try:
        from geoff_utils import _log_error as _e
        _e(msg)
    except Exception:
        print(f"[queue_manager] ERROR: {msg}", flush=True)


def _log_info(msg: str) -> None:
    try:
        from geoff_utils import _log_info as _i
        _i(msg)
    except Exception:
        print(f"[queue_manager] {msg}", flush=True)


def _iso_now() -> str:
    return datetime.now().isoformat()


def _item_from_dict(d: dict) -> QueueItem:
    fields = QueueItem.__dataclass_fields__
    return QueueItem(**{k: d.get(k) for k in fields})


def _load_raw():
    """Load queue from disk. Returns (items, next_priority)."""
    try:
        p = Path(QUEUE_FILE)
        if not p.exists():
            return [], 0
        data = json.loads(p.read_text())
        if not isinstance(data, dict) or data.get("version") != 1:
            return [], 0
        items = [_item_from_dict(d) for d in data.get("items", [])]
        return items, data.get("next_priority", len(items))
    except Exception:
        return [], 0


def _save_raw(items: list, next_priority: int) -> None:
    try:
        Path(QUEUE_FILE).parent.mkdir(parents=True, exist_ok=True)
        data = {
            "version": 1,
            "items": [asdict(i) for i in items],
            "next_priority": next_priority,
        }
        tmp = QUEUE_FILE + ".tmp"
        Path(tmp).write_text(json.dumps(data, indent=2, default=str))
        os.replace(tmp, QUEUE_FILE)
    except Exception as e:
        _log_error(f"save failed: {e}")


def _any_fe_job_running() -> bool:
    """Return True if any find_evil job is currently active."""
    try:
        from geoff_utils import _find_evil_jobs, _state_lock
        with _state_lock:
            return any(
                j.get("status") in ("running", "initializing", "starting")
                for j in _find_evil_jobs.values()
            )
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def initialize() -> None:
    """On startup: detect stale running jobs, start next queued item."""
    with _lock:
        items, next_priority = _load_raw()
        changed = False
        for item in items:
            if item.status == "running":
                alive = False
                if item.job_id:
                    try:
                        from geoff_utils import _find_evil_jobs, _state_lock
                        with _state_lock:
                            job = _find_evil_jobs.get(item.job_id)
                            alive = bool(job and job.get("status") in ("running", "initializing", "starting"))
                    except Exception:
                        pass
                if not alive:
                    _log_info(f"stale job {item.id} ({item.display_name}) marked failed on startup")
                    item.status = "failed"
                    item.error = "Server restart — job did not complete"
                    item.completed_at = _iso_now()
                    changed = True
        if changed:
            _save_raw(items, next_priority)

    _maybe_start_next()


def get_all_items() -> list:
    """Return all queue items sorted by priority (ascending)."""
    with _lock:
        items, _ = _load_raw()
    return [asdict(i) for i in sorted(items, key=lambda x: x.priority)]


def enqueue(evidence_path: str, created_by: str = "user") -> QueueItem:
    """Add evidence_path to the queue. Raises ValueError on duplicate."""
    with _lock:
        items, next_priority = _load_raw()
        for item in items:
            if item.evidence_path == evidence_path and item.status in ("queued", "running"):
                raise ValueError(f"Already queued: {evidence_path}")
        new_item = QueueItem(
            id=f"job-{uuid.uuid4().hex[:12]}",
            evidence_path=evidence_path,
            display_name=Path(evidence_path).name,
            priority=next_priority,
            status="queued",
            job_id=None,
            progress_pct=0.0,
            current_playbook="",
            current_step="",
            elapsed_seconds=0.0,
            queued_at=_iso_now(),
            started_at=None,
            completed_at=None,
            result_summary=None,
            error=None,
            created_by=created_by,
        )
        items.append(new_item)
        _save_raw(items, next_priority + 1)
        _qlog.info("Evidence queued", item_id=new_item.id,
                   evidence=evidence_path, created_by=created_by)
        result = QueueItem(**asdict(new_item))

    _maybe_start_next()
    return result


def remove(item_id: str) -> dict:
    """Remove a queued (not running) item."""
    with _lock:
        items, next_priority = _load_raw()
        found = next((i for i in items if i.id == item_id), None)
        if not found:
            raise KeyError(item_id)
        if found.status == "running":
            raise RuntimeError("Cannot remove a running job — use cancel")
        items = [i for i in items if i.id != item_id]
        _save_raw(items, next_priority)
        _qlog.info("Queue item removed", item_id=item_id)
        return asdict(found)


def cancel(item_id: str) -> dict:
    """Cancel a queued or running item. Triggers cleanup if running."""
    with _lock:
        items, next_priority = _load_raw()
        found = next((i for i in items if i.id == item_id), None)
        if not found:
            raise KeyError(item_id)
        if found.status in ("completed", "failed", "cancelled"):
            raise RuntimeError(f"Cannot cancel item with status: {found.status}")
        job_id = found.job_id
        evidence_path = found.evidence_path
        found.status = "cancelled"
        found.completed_at = _iso_now()
        _save_raw(items, next_priority)

    cleaned = False
    if job_id:
        cleaned = _cleanup_job(job_id, evidence_path)

    _qlog.info("Queue item cancelled", item_id=item_id, cleaned=cleaned)
    _maybe_start_next()
    return {"item_id": item_id, "cleaned": cleaned}


def update_priority(item_id: str, priority: int) -> dict:
    """Update priority of a queued item."""
    with _lock:
        items, next_priority = _load_raw()
        found = next((i for i in items if i.id == item_id), None)
        if not found:
            raise KeyError(item_id)
        found.priority = priority
        if priority >= next_priority:
            next_priority = priority + 1
        _save_raw(items, next_priority)
        return asdict(found)


def on_job_complete(job_id: str, report: dict) -> None:
    """Called from geoff_routes.py after a find_evil job completes successfully."""
    with _lock:
        items, next_priority = _load_raw()
        found = next((i for i in items if i.job_id == job_id), None)
        if found:
            found.status = "completed"
            found.completed_at = _iso_now()
            found.progress_pct = 100.0
            found.result_summary = _extract_summary(report)
            _save_raw(items, next_priority)

    _maybe_start_next()


def on_job_failed(job_id: str, error: str) -> None:
    """Called from geoff_routes.py after a find_evil job fails."""
    with _lock:
        items, next_priority = _load_raw()
        found = next((i for i in items if i.job_id == job_id), None)
        if found:
            found.status = "failed"
            found.completed_at = _iso_now()
            found.error = str(error)[:500]
            _save_raw(items, next_priority)

    _maybe_start_next()


def force_advance() -> dict:
    """Force-advance: cancel current running job (if any), start next queued."""
    cancelled_item = None
    with _lock:
        items, next_priority = _load_raw()
        running = next((i for i in items if i.status == "running"), None)
        if running:
            running.status = "cancelled"
            running.completed_at = _iso_now()
            _save_raw(items, next_priority)
            cancelled_item = asdict(running)
            job_id_to_kill = running.job_id
            ev_path = running.evidence_path
        else:
            job_id_to_kill = None
            ev_path = None

    if not job_id_to_kill:
        try:
            from geoff_utils import _find_evil_jobs, _state_lock
            with _state_lock:
                for jid, job in _find_evil_jobs.items():
                    if job.get("status") in ("running", "initializing", "starting"):
                        job_id_to_kill = jid
                        ev_path = job.get("evidence_dir", "")
                        break
        except Exception:
            pass

    if job_id_to_kill:
        _cleanup_job(job_id_to_kill, ev_path)

    next_item = _maybe_start_next()
    _qlog.info("Queue force-advanced",
              cancelled_item=cancelled_item.get("id") if cancelled_item else None,
              next_item=next_item.get("id") if next_item else None)
    return {
        "status": "advancing",
        "next_item": next_item,
        "cancelled_item": cancelled_item,
    }
def sync_progress(job_id: str, progress_pct: float, current_playbook: str,
                  current_step: str, elapsed_seconds: float) -> None:
    """Update progress fields for a running queue item."""
    with _lock:
        items, next_priority = _load_raw()
        found = next((i for i in items if i.job_id == job_id), None)
        if found and found.status == "running":
            found.progress_pct = progress_pct
            found.current_playbook = current_playbook
            found.current_step = current_step
            found.elapsed_seconds = elapsed_seconds
            _save_raw(items, next_priority)


# ---------------------------------------------------------------------------
# Internal: start next, cleanup
# ---------------------------------------------------------------------------

def _maybe_start_next():
    """Start the next queued item if nothing is currently running. Returns new item dict or None."""
    if _any_fe_job_running():
        return None

    with _lock:
        items, next_priority = _load_raw()
        running = next((i for i in items if i.status == "running"), None)
        if running:
            return None
        queued = sorted([i for i in items if i.status == "queued"], key=lambda x: x.priority)
        if not queued:
            return None
        if _start_job_fn is None:
            _log_error("_start_job_fn not set — cannot auto-start next queue item")
            return None

        next_item = queued[0]
        try:
            job_id = _start_job_fn(next_item.evidence_path, next_item.id)
        except Exception as e:
            _log_error(f"failed to start {next_item.evidence_path}: {e}")
            next_item.status = "failed"
            next_item.error = f"Failed to start: {e}"
            next_item.completed_at = _iso_now()
            _save_raw(items, next_priority)
            return None

        next_item.status = "running"
        next_item.job_id = job_id
        next_item.started_at = _iso_now()
        _save_raw(items, next_priority)
        _log_info(f"auto-started queue item {next_item.id} ({next_item.display_name}) as job {job_id}")
        _qlog.info("Queue item auto-started", item_id=next_item.id,
                   display_name=next_item.display_name, job_id=job_id)
        return asdict(next_item)


def _extract_summary(report: dict) -> str:
    try:
        evil = report.get("evil_found", False)
        sev = report.get("severity", "UNKNOWN")
        n = len(report.get("findings", []))
        return (f"{sev} | {n} findings | EVIL FOUND" if evil else f"{sev} | {n} findings | clean")
    except Exception:
        return ""


def _cleanup_job(job_id: str, evidence_path: str) -> bool:
    """Kill processes and remove temp artifacts for a cancelled job."""
    _qlog.info("Cleanup started", job_id=job_id, evidence=evidence_path)
    cleaned = False
    try:
        # Mark job cancelled in _find_evil_jobs
        try:
            from geoff_utils import _find_evil_jobs, _state_lock
            with _state_lock:
                job = _find_evil_jobs.get(job_id)
                if job:
                    job["status"] = "cancelled"
                    job["_cancelled"] = True
        except Exception as e:
            _log_error(f"cleanup job cancel: {e}")

        ev_name = Path(evidence_path).name

        # Kill ewfmount processes related to this evidence
        try:
            result = subprocess.run(["pgrep", "-af", "ewfmount"],
                                    capture_output=True, text=True, timeout=5)
            for line in result.stdout.splitlines():
                parts = line.split(None, 1)
                if len(parts) < 2:
                    continue
                pid_str, cmdline = parts
                if ev_name in cmdline or job_id in cmdline:
                    try:
                        os.kill(int(pid_str), signal.SIGTERM)
                        _log_info(f"cleanup: SIGTERM ewfmount pid {pid_str}")
                    except Exception:
                        pass
        except Exception as e:
            _log_error(f"cleanup ewfmount kill: {e}")

        time.sleep(2)

        # Unmount geoff ewf dirs
        for ewf_dir in _glob.glob("/tmp/geoff_ewf_*"):
            try:
                subprocess.run(["fusermount", "-u", ewf_dir],
                               timeout=10, capture_output=True)
                _log_info(f"cleanup: unmounted {ewf_dir}")
            except Exception:
                pass

        # Kill orphaned processes referencing this evidence
        try:
            result = subprocess.run(["pgrep", "-f", ev_name],
                                    capture_output=True, text=True, timeout=5)
            my_pid = os.getpid()
            for pid_str in result.stdout.strip().split():
                try:
                    pid = int(pid_str)
                    if pid != my_pid:
                        os.kill(pid, signal.SIGTERM)
                except Exception:
                    pass
        except Exception:
            pass

        # Remove case work dir
        try:
            from geoff_config import CASES_WORK_DIR
            ev_name_clean = re.sub(r"[^a-zA-Z0-9_\-]", "_", ev_name)
            ev_key = hashlib.sha256(str(Path(evidence_path).resolve()).encode()).hexdigest()[:12]
            case_work_dir = Path(CASES_WORK_DIR) / f"{ev_name_clean}_findevil_{ev_key}"
            if case_work_dir.exists():
                shutil.rmtree(str(case_work_dir), ignore_errors=True)
                _log_info(f"cleanup: removed {case_work_dir}")
        except Exception as e:
            _log_error(f"cleanup case dir: {e}")

        # Remove ewf/extract temp dirs
        for pattern in ["/tmp/geoff_ewf_*", "/tmp/geoff_extract_*"]:
            for d in _glob.glob(pattern):
                try:
                    shutil.rmtree(d, ignore_errors=True)
                except Exception:
                    pass

        cleaned = True
        _qlog.info("Cleanup complete", job_id=job_id)
    except Exception as e:
        _log_error(f"cleanup unexpected: {e}")
        _qlog.error("Cleanup failed", job_id=job_id, error=str(e))

    return cleaned
