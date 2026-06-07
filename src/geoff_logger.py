#!/usr/bin/env python3
"""Geoff Structured Logging System.

Rotating JSON log at /var/log/geoff/geoff.log (10MB, 5 backups, gzip).
Fallback to /tmp/geoff/geoff.log if /var/log/geoff is not writable.
Named sub-loggers: geoff.queue, geoff.find_evil, geoff.server, geoff.chat,
geoff.critic, geoff.extraction, geoff.general.
Per-job context via set_job_context() / clear_job_context().
crash() also writes to /tmp/geoff_crash.log (backward compat).
geoff_excepthook() replaces sys.excepthook.
"""
import gzip
import json
import logging
import logging.handlers
import os
import shutil
import socket
import sys
import threading
import traceback
from datetime import datetime
from pathlib import Path

_HOSTNAME = socket.gethostname()
LOG_DIR = "/var/log/geoff"
LOG_FILE = f"{LOG_DIR}/geoff.log"
CRASH_LOG = "/tmp/geoff_crash.log"

_job_context = threading.local()


class _JSONFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        extra = getattr(record, "_geoff_extra", {})
        entry = {
            "ts": datetime.fromtimestamp(record.created).astimezone().isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "module": record.module,
            "message": record.getMessage(),
            "host": _HOSTNAME,
            "pid": record.process,
            "version": 1,
        }
        if extra:
            entry["extra"] = extra
        if record.exc_info and record.exc_info[0] is not None:
            entry["traceback"] = self.formatException(record.exc_info)
        return json.dumps(entry, default=str)


def _gzip_rotator(source: str, dest: str) -> None:
    with open(source, "rb") as f_in:
        with gzip.open(dest + ".gz", "wb") as f_out:
            shutil.copyfileobj(f_in, f_out)
    os.remove(source)


def _namer(default_name: str) -> str:
    return default_name + ".gz"


def _build_handler() -> logging.Handler:
    log_path = None
    try:
        Path(LOG_DIR).mkdir(parents=True, exist_ok=True)
        probe = Path(LOG_DIR) / ".geoff_write_test"
        probe.touch()
        probe.unlink()
        log_path = LOG_FILE
    except (PermissionError, OSError):
        fallback_dir = Path("/tmp/geoff")
        fallback_dir.mkdir(parents=True, exist_ok=True)
        log_path = str(fallback_dir / "geoff.log")

    handler = logging.handlers.RotatingFileHandler(
        log_path,
        maxBytes=10 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8",
    )
    handler.rotator = _gzip_rotator
    handler.namer = _namer
    handler.setFormatter(_JSONFormatter())
    return handler


def _init_logging() -> None:
    root = logging.getLogger("geoff")
    if root.handlers:
        return
    root.setLevel(logging.DEBUG)
    try:
        root.addHandler(_build_handler())
    except Exception:
        h = logging.StreamHandler(sys.stderr)
        h.setFormatter(_JSONFormatter())
        root.addHandler(h)
    root.propagate = False


_init_logging()


class GeoffLogger:
    """Thin wrapper around a named Python logger with structured JSON output."""

    def __init__(self, name: str = "geoff.general") -> None:
        self._name = name
        self._py = logging.getLogger(name)

    def _emit(self, level: int, msg: str, kwargs: dict) -> None:
        if not self._py.isEnabledFor(level):
            return
        exc_info = kwargs.pop("exc_info", False)
        if exc_info is True:
            exc_info = sys.exc_info()
        if exc_info and exc_info[0] is None:
            exc_info = None

        job_ctx = getattr(_job_context, "data", None) or {}
        extra_data = {**job_ctx, **kwargs}

        # stacklevel=3: findCaller->_emit->info/warning/etc->caller
        fn, lno, func, sinfo = self._py.findCaller(stack_info=False, stacklevel=3)
        record = logging.LogRecord(
            name=self._name,
            level=level,
            pathname=fn,
            lineno=lno,
            msg=msg,
            args=(),
            exc_info=exc_info or None,
            func=func,
            sinfo=sinfo,
        )
        record._geoff_extra = extra_data
        self._py.handle(record)

    def info(self, msg: str, **kwargs) -> None:
        self._emit(logging.INFO, msg, kwargs)

    def warning(self, msg: str, **kwargs) -> None:
        self._emit(logging.WARNING, msg, kwargs)

    def error(self, msg: str, **kwargs) -> None:
        self._emit(logging.ERROR, msg, kwargs)

    def critical(self, msg: str, **kwargs) -> None:
        self._emit(logging.CRITICAL, msg, kwargs)

    def crash(self, msg: str, **kwargs) -> None:
        """Log at CRITICAL and append to /tmp/geoff_crash.log (backward compat)."""
        self._emit(logging.CRITICAL, msg, dict(kwargs))
        try:
            with open(CRASH_LOG, "a") as f:
                f.write(f"\n=== {datetime.now().isoformat()} | {msg} ===\n")
                traceback.print_exc(file=f)
        except Exception:
            pass


def get_logger(name: str) -> GeoffLogger:
    """Return a GeoffLogger for the given sub-logger name."""
    return GeoffLogger(name)


logger = GeoffLogger("geoff.general")


def set_job_context(job_id: str, evidence_dir: str) -> None:
    """Set per-job context appended to all subsequent log entries on this thread."""
    _job_context.data = {"job_id": job_id, "evidence_dir": evidence_dir}


def clear_job_context() -> None:
    """Clear per-job context."""
    _job_context.data = None


def geoff_excepthook(exc_type, exc_value, exc_traceback) -> None:
    """sys.excepthook replacement: structured log + /tmp/geoff_crash.log."""
    _srv = logging.getLogger("geoff.server")
    record = logging.LogRecord(
        name="geoff.server",
        level=logging.CRITICAL,
        pathname="(unhandled)",
        lineno=0,
        msg=f"Unhandled exception: {exc_type.__name__}: {exc_value}",
        args=(),
        exc_info=(exc_type, exc_value, exc_traceback),
        func="(excepthook)",
        sinfo=None,
    )
    record._geoff_extra = {}
    _srv.handle(record)
    try:
        with open(CRASH_LOG, "a") as f:
            f.write(f"\n=== {datetime.now().isoformat()} ===\n")
            traceback.print_exception(exc_type, exc_value, exc_traceback, file=f)
    except Exception:
        pass
