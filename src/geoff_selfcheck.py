#!/usr/bin/env python3
"""
Geoff DFIR — Startup Self-Check

Verifies that required tools, Python packages, Ollama models, and writable
directories are all present and functioning before (or after) Geoff starts.

Usage:
    python src/geoff_selfcheck.py          # full check, coloured output
    python src/geoff_selfcheck.py --json   # machine-readable JSON
    python src/geoff_selfcheck.py --quiet  # only print failures

Exit codes:
    0  — all checks passed (warnings allowed)
    1  — one or more WARN checks failed (non-critical tools missing)
    2  — one or more CRITICAL checks failed (Geoff will not work correctly)
"""

import argparse
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

# ---------------------------------------------------------------------------
# Colour helpers (gracefully degrade when not a TTY)
# ---------------------------------------------------------------------------

_USE_COLOUR = sys.stdout.isatty()

def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _USE_COLOUR else text

def _ok(s: str)   -> str: return _c("32", s)
def _warn(s: str) -> str: return _c("33", s)
def _fail(s: str) -> str: return _c("31", s)
def _bold(s: str) -> str: return _c("1",  s)

# ---------------------------------------------------------------------------
# Result accumulator
# ---------------------------------------------------------------------------

PASS   = "pass"
WARN   = "warn"
FAIL   = "fail"

_results: List[Dict[str, Any]] = []

def _record(category: str, name: str, status: str, detail: str = "") -> None:
    _results.append({"category": category, "name": name, "status": status, "detail": detail})


# ---------------------------------------------------------------------------
# Check helpers
# ---------------------------------------------------------------------------

def _which(binary: str) -> bool:
    return shutil.which(binary) is not None


def _run(cmd: List[str], timeout: int = 5) -> Tuple[int, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout + r.stderr).strip()
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        return -1, str(e)


def _pymod(name: str) -> bool:
    return importlib.util.find_spec(name) is not None


# ---------------------------------------------------------------------------
# Individual check groups
# ---------------------------------------------------------------------------

def check_python_deps() -> None:
    """Required and optional Python packages."""
    required = [
        ("flask",      "flask"),
        ("flask_cors", "flask-cors"),
        ("requests",   "requests"),
        ("jsonschema", "jsonschema"),
        ("git",        "gitpython"),
        ("dotenv",     "python-dotenv"),
        ("mcp",        "mcp"),
    ]
    optional = [
        ("Evtx",       "python-evtx (Windows Event Log parsing)"),
        ("yara",       "yara-python (YARA malware detection)"),
    ]
    for mod, label in required:
        if _pymod(mod):
            _record("Python packages", label, PASS)
        else:
            _record("Python packages", label, FAIL, f"pip install {label}")

    for mod, label in optional:
        if _pymod(mod):
            _record("Python packages (optional)", label, PASS)
        else:
            _record("Python packages (optional)", label, WARN, "Not installed — some features disabled")


def check_core_tools() -> None:
    """Tools Geoff uses unconditionally in every investigation."""
    critical = [
        ("strings",  ["strings", "--version"],   "binutils strings — IOC extraction"),
        ("git",      ["git", "--version"],        "git — audit trail commits"),
    ]
    for binary, probe_cmd, label in critical:
        if not _which(binary):
            _record("Core tools", label, FAIL, f"'{binary}' not found in PATH")
            continue
        rc, out = _run(probe_cmd)
        if rc == 0:
            version = out.splitlines()[0][:80] if out else "ok"
            _record("Core tools", label, PASS, version)
        else:
            _record("Core tools", label, FAIL, f"'{binary}' found but exited {rc}: {out[:200]}")


def check_disk_tools() -> None:
    """SleuthKit binaries — disk image analysis."""
    binaries = ["mmls", "fsstat", "fls", "icat", "istat", "blkls"]
    missing = [b for b in binaries if not _which(b)]
    present = [b for b in binaries if _which(b)]

    if not present:
        _record("Disk forensics (SleuthKit)", "mmls/fls/fsstat/icat", FAIL,
                "No SleuthKit binaries found — disk image analysis unavailable. "
                "Install: sudo apt install sleuthkit")
        return

    # Functional smoke test: mmls --help should exit 0 or 1 (it uses --help → 1 on some versions)
    rc, out = _run(["mmls", "-?"], timeout=5)
    if rc in (0, 1) or "mmls" in out.lower():
        _record("Disk forensics (SleuthKit)", "mmls (functional)", PASS,
                f"Present: {', '.join(present)}")
    else:
        _record("Disk forensics (SleuthKit)", "mmls (functional)", WARN,
                f"mmls returned unexpected exit {rc}")

    if missing:
        _record("Disk forensics (SleuthKit)", f"missing: {', '.join(missing)}", WARN,
                "Some disk analysis functions unavailable")


def check_memory_tools() -> None:
    """Volatility — memory forensics."""
    found = None
    for binary in ["volatility3", "vol.py", "vol"]:
        if _which(binary):
            found = binary
            break

    if not found:
        _record("Memory forensics (Volatility)", "volatility3/vol.py", WARN,
                "Not found — memory analysis unavailable. "
                "Install: pip install volatility3 or sudo apt install volatility")
        return

    rc, out = _run([found, "--help"], timeout=10)
    if rc in (0, 1) or "volatility" in out.lower():
        _record("Memory forensics (Volatility)", found, PASS, out.splitlines()[0][:80] if out else "ok")
    else:
        _record("Memory forensics (Volatility)", found, WARN,
                f"Found but unexpected exit {rc}: {out[:200]}")


def check_registry_tools() -> None:
    """RegRipper — Windows registry analysis."""
    binary = shutil.which("rip.pl") or shutil.which("rip")
    if not binary:
        _record("Registry forensics (RegRipper)", "rip.pl / rip", WARN,
                "Not found — Windows registry analysis unavailable. "
                "Install: sudo apt install regripper")
        return

    rc, out = _run([binary, "-h"], timeout=5)
    if rc in (0, 1) or "rip" in out.lower():
        _record("Registry forensics (RegRipper)", Path(binary).name, PASS)
    else:
        _record("Registry forensics (RegRipper)", Path(binary).name, WARN,
                f"Found but unexpected exit {rc}")


def check_timeline_tools() -> None:
    """Plaso — super timeline generation."""
    binaries = ["log2timeline.py", "psort.py"]
    missing = [b for b in binaries if not _which(b)]
    if missing:
        _record("Timeline analysis (Plaso)", "log2timeline.py/psort.py", WARN,
                f"Missing: {', '.join(missing)} — timeline analysis unavailable. "
                "Install: pip install plaso")
        return

    rc, out = _run(["log2timeline.py", "--version"], timeout=10)
    if rc == 0:
        _record("Timeline analysis (Plaso)", "log2timeline.py", PASS, out.strip()[:80])
    else:
        _record("Timeline analysis (Plaso)", "log2timeline.py", WARN,
                f"Found but exit {rc}: {out[:200]}")


def check_network_tools() -> None:
    """tshark/tcpflow — PCAP analysis."""
    if _which("tshark"):
        rc, out = _run(["tshark", "--version"], timeout=5)
        if rc == 0:
            _record("Network forensics (tshark)", "tshark", PASS, out.splitlines()[0][:80])
        else:
            _record("Network forensics (tshark)", "tshark", WARN, f"Found but exit {rc}")
    else:
        _record("Network forensics (tshark)", "tshark", WARN,
                "Not found — PCAP analysis unavailable. "
                "Install: sudo apt install tshark")

    if not _which("tcpflow"):
        _record("Network forensics (tcpflow)", "tcpflow", WARN,
                "Not found — flow extraction unavailable. "
                "Install: sudo apt install tcpflow")
    else:
        _record("Network forensics (tcpflow)", "tcpflow", PASS)


def check_carving_tools() -> None:
    """photorec / foremost — file carving."""
    found = [b for b in ["photorec", "foremost"] if _which(b)]
    if found:
        _record("File carving", ", ".join(found), PASS)
    else:
        _record("File carving", "photorec/foremost", WARN,
                "Not found — file carving unavailable. "
                "Install: sudo apt install testdisk foremost")


def check_strings_functional() -> None:
    """Smoke-test strings with a real temp file containing known content."""
    # Use mode=0o600 so the file is only readable by the current user while
    # the strings probe runs, eliminating the world-readable window.
    fd, tmp = tempfile.mkstemp(suffix=".bin")
    try:
        os.chmod(tmp, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(b"\x00\x00\x00GEOFF_SELFCHECK_MARKER\x00\x00")
        rc, out = _run(["strings", "-n", "8", tmp], timeout=5)
        if rc == 0 and "GEOFF_SELFCHECK_MARKER" in out:
            _record("Functional smoke tests", "strings (extracts known string)", PASS)
        else:
            _record("Functional smoke tests", "strings (extracts known string)", FAIL,
                    f"Output did not contain marker (exit {rc}): {out[:200]}")
    finally:
        Path(tmp).unlink(missing_ok=True)


def check_ollama(ollama_url: str, api_key: str, agent_models: Dict[str, str]) -> None:
    """Check Ollama connectivity and model availability."""
    import requests as _req

    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
        tags_url = "https://ollama.com/api/tags"
    else:
        tags_url = f"{ollama_url}/api/tags"

    # Connectivity
    try:
        resp = _req.get(tags_url, headers=headers, timeout=8)
        resp.raise_for_status()
        available_models = {m.get("name", m.get("model", "")) for m in resp.json().get("models", [])}
        _record("Ollama", "connectivity", PASS,
                f"{tags_url} → {resp.status_code}, {len(available_models)} models listed")
    except Exception as e:
        _record("Ollama", "connectivity", FAIL,
                f"Cannot reach {tags_url}: {e}. Ensure Ollama is running or OLLAMA_URL/OLLAMA_API_KEY is set.")
        # If we can't connect, skip model checks
        for role, model in agent_models.items():
            _record("Ollama models", f"{role}: {model}", FAIL, "Skipped — Ollama unreachable")
        return

    # Model presence
    for role, model in agent_models.items():
        base = model.split(":")[0] if ":" in model else model
        matched = any(base in m for m in available_models) or model in available_models
        if matched:
            _record("Ollama models", f"{role}: {model}", PASS)
        else:
            _record("Ollama models", f"{role}: {model}", WARN,
                    f"Model not found in tags list. Run: ollama pull {model}")

    # Quick generate smoke test with the manager model
    manager_model = agent_models.get("manager", "")
    if manager_model and api_key:
        gen_url = "https://ollama.com/api/generate"
    else:
        gen_url = f"{ollama_url}/api/generate"

    try:
        t0 = time.time()
        resp = _req.post(gen_url, headers=headers, json={
            "model": manager_model,
            "prompt": "Reply with only the word: PONG",
            "stream": False,
        }, timeout=30)
        elapsed = time.time() - t0
        if resp.status_code == 200 and resp.json().get("response"):
            _record("Ollama models", f"manager generate smoke test ({manager_model})", PASS,
                    f"{elapsed:.1f}s — response: {resp.json()['response'][:60]!r}")
        else:
            _record("Ollama models", f"manager generate smoke test ({manager_model})", WARN,
                    f"HTTP {resp.status_code}: {resp.text[:200]}")
    except Exception as e:
        _record("Ollama models", f"manager generate smoke test ({manager_model})", WARN,
                f"Smoke test failed: {e}")


def check_directories(evidence_base: str, cases_work: str) -> None:
    """Verify key directories are writable."""
    dirs = {
        "Evidence base directory": evidence_base,
        "Cases work directory":    cases_work,
        "Temp directory":          tempfile.gettempdir(),
    }
    for label, path in dirs.items():
        p = Path(path)
        try:
            p.mkdir(parents=True, exist_ok=True)
            probe = p / f".geoff_selfcheck_{os.getpid()}"
            probe.write_text("ok")
            probe.unlink()
            _record("Directories", f"{label}: {path}", PASS)
        except (OSError, PermissionError) as e:
            _record("Directories", f"{label}: {path}", FAIL, str(e))


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run_all_checks(
    ollama_url: str,
    api_key: str,
    agent_models: Dict[str, str],
    evidence_base: str,
    cases_work: str,
) -> List[Dict[str, Any]]:
    global _results
    _results = []

    check_python_deps()
    check_core_tools()
    check_strings_functional()
    check_disk_tools()
    check_memory_tools()
    check_registry_tools()
    check_timeline_tools()
    check_network_tools()
    check_carving_tools()
    check_ollama(ollama_url, api_key, agent_models)
    check_directories(evidence_base, cases_work)

    return _results


def print_report(results: List[Dict[str, Any]], quiet: bool = False) -> int:
    """Print coloured report. Returns exit code (0/1/2)."""
    by_category: Dict[str, List[Dict]] = {}
    for r in results:
        by_category.setdefault(r["category"], []).append(r)

    has_fail = any(r["status"] == FAIL for r in results)
    has_warn = any(r["status"] == WARN for r in results)

    for category, items in by_category.items():
        if quiet and all(r["status"] == PASS for r in items):
            continue
        print(_bold(f"\n{category}"))
        for r in items:
            if quiet and r["status"] == PASS:
                continue
            icon = {"pass": _ok("✓"), "warn": _warn("⚠"), "fail": _fail("✗")}[r["status"]]
            detail = f"  ({r['detail']})" if r["detail"] else ""
            print(f"  {icon}  {r['name']}{detail}")

    print()
    total  = len(results)
    passed = sum(1 for r in results if r["status"] == PASS)
    warned = sum(1 for r in results if r["status"] == WARN)
    failed = sum(1 for r in results if r["status"] == FAIL)

    if has_fail:
        status_str = _fail(f"CRITICAL FAILURES: {failed}")
        code = 2
    elif has_warn:
        status_str = _warn(f"WARNINGS: {warned}")
        code = 1
    else:
        status_str = _ok("ALL CHECKS PASSED")
        code = 0

    print(f"Self-check: {passed}/{total} passed — {status_str}")
    if has_fail:
        print(_fail("  Geoff may not function correctly. Fix the CRITICAL items above."))
    elif has_warn:
        print(_warn("  Some optional tools are missing. Core functionality is available."))

    return code


# ---------------------------------------------------------------------------
# Startup integration helper (called by geoff_integrated.py)
# ---------------------------------------------------------------------------

def startup_check(
    ollama_url: str,
    api_key: str,
    agent_models: Dict[str, str],
    evidence_base: str,
    cases_work: str,
    quiet: bool = False,
) -> None:
    """Run self-check and print results to stderr. Does not raise or exit."""
    print("[Geoff] Running startup self-check...", file=sys.stderr)
    results = run_all_checks(ollama_url, api_key, agent_models, evidence_base, cases_work)
    by_status = {PASS: 0, WARN: 0, FAIL: 0}
    for r in results:
        by_status[r["status"]] += 1

    if not quiet or by_status[FAIL] or by_status[WARN]:
        # Print just the non-passing items to stderr to avoid cluttering startup
        for r in results:
            if r["status"] == FAIL:
                detail = f" ({r['detail']})" if r["detail"] else ""
                print(f"[Geoff] FAIL  {r['category']}: {r['name']}{detail}", file=sys.stderr)
            elif r["status"] == WARN:
                detail = f" ({r['detail']})" if r["detail"] else ""
                print(f"[Geoff] WARN  {r['category']}: {r['name']}{detail}", file=sys.stderr)

    summary = (
        f"{by_status[PASS]} passed, "
        f"{by_status[WARN]} warnings, "
        f"{by_status[FAIL]} failures"
    )
    if by_status[FAIL]:
        print(f"[Geoff] Self-check: {summary} — some features may not work", file=sys.stderr)
    elif by_status[WARN]:
        print(f"[Geoff] Self-check: {summary} — optional tools missing", file=sys.stderr)
    else:
        print(f"[Geoff] Self-check: {summary}", file=sys.stderr)


# ---------------------------------------------------------------------------
# CLI entrypoint
# ---------------------------------------------------------------------------

def _load_geoff_config() -> Dict[str, Any]:
    """Load config from geoff_integrated without starting Flask."""
    try:
        # Minimal env-based config — mirrors geoff_integrated.py logic
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass

    ollama_url  = os.environ.get("OLLAMA_URL", "http://localhost:11434")
    api_key     = os.environ.get("OLLAMA_API_KEY", "")
    profile     = os.environ.get("GEOFF_PROFILE", "cloud")

    # Load profile models
    try:
        sys.path.insert(0, os.path.dirname(__file__))
        from geoff_integrated import load_profile, EVIDENCE_BASE_DIR, CASES_WORK_DIR
        profile_models = load_profile(profile)
        agent_models = {
            "manager":     os.environ.get("GEOFF_MANAGER_MODEL",     profile_models.get("manager", "")),
            "forensicator":os.environ.get("GEOFF_FORENSICATOR_MODEL",profile_models.get("forensicator", "")),
            "critic":      os.environ.get("GEOFF_CRITIC_MODEL",      profile_models.get("critic", "")),
        }
        evidence_base = EVIDENCE_BASE_DIR
        cases_work    = CASES_WORK_DIR
    except Exception:
        agent_models  = {
            "manager":      os.environ.get("GEOFF_MANAGER_MODEL",      "deepseek-r1:32b"),
            "forensicator": os.environ.get("GEOFF_FORENSICATOR_MODEL", "qwen2.5-coder:14b"),
            "critic":       os.environ.get("GEOFF_CRITIC_MODEL",       "qwen2.5:14b"),
        }
        evidence_base = os.environ.get("GEOFF_EVIDENCE_PATH", "/tmp/geoff-evidence")
        cases_work    = os.environ.get("GEOFF_CASES_PATH",    "/tmp/geoff-cases")

    return dict(
        ollama_url=ollama_url,
        api_key=api_key,
        agent_models=agent_models,
        evidence_base=evidence_base,
        cases_work=cases_work,
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Geoff DFIR self-check")
    parser.add_argument("--json",  action="store_true", help="Output JSON instead of coloured text")
    parser.add_argument("--quiet", action="store_true", help="Only print failures and warnings")
    args = parser.parse_args()

    cfg = _load_geoff_config()
    results = run_all_checks(**cfg)

    if args.json:
        print(json.dumps(results, indent=2))
        has_fail = any(r["status"] == FAIL for r in results)
        has_warn = any(r["status"] == WARN for r in results)
        sys.exit(2 if has_fail else 1 if has_warn else 0)
    else:
        code = print_report(results, quiet=args.quiet)
        sys.exit(code)
