"""Faithful per-command audit logging for chain-of-custody.

Every external command Geoff executes during an investigation must be recorded
so another investigator can audit or replay the run from git. The forensic
tools are invoked from ~200 scattered ``subprocess.run`` call sites across the
specialist modules, so rather than instrument each one we install a single
process-wide wrapper around ``subprocess.run``. Every call (all 197 call sites
use ``subprocess.run`` exclusively — no ``Popen``/``call``/``os.system``) is
captured with its real argv, cwd, exit code, duration and the resolved version
of the binary that ran.

Scoping is per-investigation via a ``threading.local`` context:

* Each ``find_evil`` job runs in its own background thread, so the thread-local
  isolates concurrent investigations — each job's commands go to its own
  ``commands/`` directory.
* Within a job, steps run sequentially (the step watchdog is SIGALRM-based, not
  thread-based), so ``set_step`` can label each command with the owning step
  without races.

When no case context is active the wrapper is a transparent pass-through, so
patching ``subprocess.run`` globally is safe for the Flask server and any other
process activity.
"""

from __future__ import annotations

import json
import os
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

# The genuine subprocess.run, captured once before we patch it. All internal
# probing (tool-version lookups, etc.) goes through this so it is never logged
# and can never recurse into the wrapper.
_orig_run = subprocess.run

_ctx = threading.local()
_install_lock = threading.Lock()
_installed = False

# Process-wide cache of binary -> version string. Versions don't change during
# a run, and probing is the same regardless of which job asked, so the cache is
# shared across threads behind a lock.
_version_cache: dict[str, str] = {}
_version_lock = threading.Lock()

# Binaries we never probe for a version: shell/coreutils plumbing that is not a
# forensic tool and only adds noise. They are still logged as commands.
_SKIP_VERSION = frozenset({
    "sh", "bash", "env", "true", "false", "cat", "echo", "test", "[",
    "sleep", "kill", "sync", "rm", "cp", "mv", "mkdir", "ln", "chmod",
})


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Context management (per investigation thread)
# ---------------------------------------------------------------------------

def begin_case(commands_dir, job_id: str = "") -> None:
    """Start logging commands for the current job to ``commands_dir``."""
    _ctx.commands_dir = Path(commands_dir) if commands_dir else None
    _ctx.job_id = job_id or ""
    _ctx.step_key = ""
    _ctx.playbook = ""
    _ctx.seq = 0
    _ctx.step_tools = {}
    if _ctx.commands_dir is not None:
        try:
            _ctx.commands_dir.mkdir(parents=True, exist_ok=True)
        except Exception:
            _ctx.commands_dir = None


def set_step(step_key: str = "", playbook: str = "") -> None:
    """Label subsequent commands with the step that is about to run.

    Resets the per-step tool-version accumulator so ``get_step_tool_versions``
    reflects only the binaries executed during this step.
    """
    _ctx.step_key = step_key or ""
    _ctx.playbook = playbook or ""
    _ctx.step_tools = {}


def get_step_tool_versions() -> dict:
    """Return {tool: version} for binaries executed since the last set_step."""
    return dict(getattr(_ctx, "step_tools", {}) or {})


def end_case() -> None:
    """Stop logging for the current job thread."""
    _ctx.commands_dir = None
    _ctx.step_key = ""
    _ctx.playbook = ""
    _ctx.step_tools = {}


def _active_dir():
    return getattr(_ctx, "commands_dir", None)


# ---------------------------------------------------------------------------
# Tool-version resolution
# ---------------------------------------------------------------------------

def _probe_version(binary: str) -> str:
    """Best-effort version string for a binary. Cached, never raises."""
    base = os.path.basename(binary)
    if not base or base in _SKIP_VERSION:
        return ""
    with _version_lock:
        if base in _version_cache:
            return _version_cache[base]
    version = "unknown"
    for flag in ("--version", "-V", "-version"):
        try:
            r = _orig_run(
                [binary, flag],
                capture_output=True, text=True, timeout=5,
                stdin=subprocess.DEVNULL,
            )
            out = (r.stdout or "").strip() or (r.stderr or "").strip()
            if out:
                version = out.splitlines()[0].strip()[:160]
                break
        except Exception:
            continue
    with _version_lock:
        _version_cache[base] = version
    return version


# ---------------------------------------------------------------------------
# The subprocess.run wrapper
# ---------------------------------------------------------------------------

def _logged_run(*args, **kwargs):
    cmd = args[0] if args else kwargs.get("args")
    start = time.time()
    started_at = _now_iso()
    result = None
    exc = None
    try:
        result = _orig_run(*args, **kwargs)
        return result
    except BaseException as e:  # noqa: BLE001 - logging must not alter behaviour
        exc = e
        raise
    finally:
        if _active_dir() is not None:
            try:
                _record(cmd, kwargs, start, started_at, result, exc)
            except Exception:
                # Audit logging must never break or mask a forensic command.
                pass


def _record(cmd, kwargs, start, started_at, result, exc) -> None:
    cdir = _active_dir()
    if cdir is None:
        return

    if isinstance(cmd, (list, tuple)):
        argv = [str(c) for c in cmd]
    elif cmd is None:
        argv = []
    else:
        # shell=True string form
        argv = [str(cmd)]

    tool = os.path.basename(argv[0]) if argv else ""
    shell = bool(kwargs.get("shell", False))
    tool_version = ""
    if tool and not shell:
        tool_version = _probe_version(argv[0])
        if tool_version and tool_version != "unknown":
            try:
                _ctx.step_tools[tool] = tool_version
            except Exception:
                pass

    rec = {
        "started_at": started_at,
        "finished_at": _now_iso(),
        "duration_s": round(time.time() - start, 4),
        "job_id": getattr(_ctx, "job_id", ""),
        "playbook": getattr(_ctx, "playbook", ""),
        "step_key": getattr(_ctx, "step_key", ""),
        "tool": tool,
        "tool_version": tool_version,
        "argv": argv,
        "command": (" ".join(argv) if argv else str(cmd))[:4000],
        "cwd": str(kwargs.get("cwd") or os.getcwd()),
        "shell": shell,
        "timeout": kwargs.get("timeout"),
    }
    if exc is not None:
        rec["returncode"] = None
        rec["error"] = f"{type(exc).__name__}: {exc}"[:500]
    else:
        rec["returncode"] = getattr(result, "returncode", None)
        out = getattr(result, "stdout", None)
        err = getattr(result, "stderr", None)
        rec["stdout_bytes"] = len(out) if out is not None else 0
        rec["stderr_bytes"] = len(err) if err is not None else 0

    _ctx.seq = getattr(_ctx, "seq", 0) + 1
    fname = f"{time.time_ns()}_{_ctx.seq:06d}_cmd.json"
    tmp = cdir / (fname + ".tmp")
    final = cdir / fname
    try:
        with open(tmp, "w") as fh:
            json.dump(rec, fh, indent=2, default=str)
        os.replace(tmp, final)
    except Exception:
        try:
            if tmp.exists():
                tmp.unlink()
        except Exception:
            pass


def install() -> None:
    """Idempotently patch subprocess.run to log commands when a case is active."""
    global _installed
    with _install_lock:
        if _installed:
            return
        subprocess.run = _logged_run
        _installed = True
