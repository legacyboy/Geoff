#!/usr/bin/env python3
"""
geoff_console.py — Terminal console for the Geoff DFIR server.

Connects to a running geoff_integrated.py instance and provides a
readline-based chat + Find Evil streaming interface with live log output.

Usage:
    python3 scripts/geoff_console.py [--server URL] [--key KEY]

Environment / .env (auto-loaded from GEOFF_DIR or repo root):
    GEOFF_PORT      server port (default 8080)
    GEOFF_API_KEY   API key (if authentication is enabled)
"""

import argparse
import json
import os
import readline
import signal
import sys
import textwrap
import time
from pathlib import Path

try:
    import requests
except ImportError:
    print("requests not installed — run: pip install requests")
    sys.exit(1)

# ---------------------------------------------------------------------------
# ANSI colour helpers
# ---------------------------------------------------------------------------

_NO_COLOR = not sys.stdout.isatty() or os.environ.get("NO_COLOR")


def _c(code: str, text: str) -> str:
    if _NO_COLOR:
        return text
    return f"\033[{code}m{text}\033[0m"


def dim(t):    return _c("2", t)
def bold(t):   return _c("1", t)
def blue(t):   return _c("94", t)
def green(t):  return _c("92", t)
def red(t):    return _c("91", t)
def yellow(t): return _c("93", t)
def cyan(t):   return _c("96", t)
def grey(t):   return _c("90", t)
def white(t):  return _c("97", t)


# ---------------------------------------------------------------------------
# Config — load from .env then environment then CLI flags
# ---------------------------------------------------------------------------

def _load_dotenv(path: Path) -> dict:
    """Minimal .env parser (no extra dependencies)."""
    result = {}
    try:
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            result[k.strip()] = v.strip().strip('"').strip("'")
    except OSError:
        pass
    return result


def _find_geoff_dir() -> Path:
    """Walk up from this script to find the repo root (.env / profiles.json)."""
    here = Path(__file__).resolve().parent
    for candidate in [here, here.parent]:
        if (candidate / "profiles.json").exists() or (candidate / ".env").exists():
            return candidate
    return here.parent


def build_config(args) -> dict:
    geoff_dir = Path(os.environ.get("GEOFF_DIR", _find_geoff_dir()))
    env = _load_dotenv(geoff_dir / ".env")

    port = env.get("GEOFF_PORT") or os.environ.get("GEOFF_PORT") or "8080"
    server = args.server or f"http://localhost:{port}"
    key = args.key or env.get("GEOFF_API_KEY") or os.environ.get("GEOFF_API_KEY") or ""
    return {"server": server.rstrip("/"), "key": key}


# ---------------------------------------------------------------------------
# HTTP client
# ---------------------------------------------------------------------------

class GeoffClient:
    def __init__(self, server: str, api_key: str, timeout: int = 30):
        self.server = server
        self.timeout = timeout
        self._headers = {"Content-Type": "application/json"}
        if api_key:
            self._headers["X-API-Key"] = api_key

    def _url(self, path: str) -> str:
        return f"{self.server}{path}"

    def ping(self) -> bool:
        try:
            r = requests.get(self._url("/"), timeout=5)
            return r.status_code == 200
        except requests.RequestException:
            return False

    def chat(self, message: str) -> dict:
        r = requests.post(
            self._url("/chat"),
            headers=self._headers,
            json={"message": message},
            timeout=self.timeout,
        )
        r.raise_for_status()
        return r.json()

    def start_find_evil(self, evidence_dir: str = "") -> dict:
        r = requests.post(
            self._url("/find-evil"),
            headers=self._headers,
            json={"evidence_dir": evidence_dir},
            timeout=self.timeout,
        )
        r.raise_for_status()
        return r.json()

    def job_status(self, job_id: str) -> dict:
        r = requests.get(
            self._url(f"/find-evil/status/{job_id}"),
            headers=self._headers,
            timeout=self.timeout,
        )
        r.raise_for_status()
        return r.json()

    def cases(self) -> dict:
        r = requests.get(
            self._url("/cases"),
            headers=self._headers,
            timeout=self.timeout,
        )
        r.raise_for_status()
        return r.json()


# ---------------------------------------------------------------------------
# Progress bar
# ---------------------------------------------------------------------------

_BAR_WIDTH = 30

def _progress_bar(pct: float) -> str:
    filled = int(_BAR_WIDTH * pct / 100)
    bar = "█" * filled + "░" * (_BAR_WIDTH - filled)
    return f"[{bar}] {pct:.0f}%"


# ---------------------------------------------------------------------------
# Log entry rendering
# ---------------------------------------------------------------------------

def _render_log_line(entry: dict) -> str:
    t = entry.get("time", "")
    msg = entry.get("msg", "")
    prefix = dim(t + "  ") if t else ""

    if "✓" in msg or "complete" in msg.lower():
        return prefix + green(msg)
    if "✗" in msg or "fail" in msg.lower() or "error" in msg.lower():
        return prefix + red(msg)
    if "▶" in msg:
        return prefix + yellow(msg)
    if "⎘" in msg or "skip" in msg.lower():
        return prefix + grey(msg)
    if "⚠" in msg or "needs_review" in msg:
        return prefix + yellow(msg)
    return prefix + grey(msg)


# ---------------------------------------------------------------------------
# Find Evil streaming
# ---------------------------------------------------------------------------

_active_job = False   # set True while polling; Ctrl+C clears it


def stream_find_evil(client: GeoffClient, job_id: str) -> dict | None:
    """Poll /find-evil/status/<job_id> and stream log lines to stdout.

    Returns the completed report dict, or None if interrupted.
    """
    global _active_job
    _active_job = True
    last_log_index = 0
    last_pct = -1

    print()  # blank line before stream starts
    try:
        while _active_job:
            try:
                status = client.job_status(job_id)
            except requests.RequestException as e:
                print(red(f"  [poll error] {e}"))
                time.sleep(3)
                continue

            pct = float(status.get("progress_pct", 0))
            pb_name = status.get("current_playbook", "")
            step_name = status.get("current_step", "")
            elapsed = float(status.get("elapsed_seconds", 0))

            # Progress bar line (overwrite in place)
            bar_line = (
                _progress_bar(pct)
                + "  " + cyan(pb_name)
                + (dim("  >  " + step_name) if step_name else "")
                + dim(f"  {elapsed:.0f}s")
            )
            if not _NO_COLOR:
                # Move to column 0, clear line, rewrite
                sys.stdout.write(f"\r\033[K{bar_line}")
                sys.stdout.flush()
            elif pct != last_pct:
                print(bar_line)
            last_pct = pct

            # New log lines
            log = status.get("log", [])
            if len(log) > last_log_index:
                if not _NO_COLOR:
                    print()  # newline after the bar before printing entries
                for entry in log[last_log_index:]:
                    print(_render_log_line(entry))
                last_log_index = len(log)
                if not _NO_COLOR:
                    # Reprint progress bar on its own line after the log entries
                    sys.stdout.write(f"{bar_line}")
                    sys.stdout.flush()

            job_status = status.get("status")
            if job_status == "complete":
                if not _NO_COLOR:
                    print()  # newline after bar
                _active_job = False
                return status.get("result") or {}
            elif job_status == "error":
                if not _NO_COLOR:
                    print()
                print(red(f"\nJob failed: {status.get('error', 'unknown')}"))
                _active_job = False
                return None

            time.sleep(2)
    except KeyboardInterrupt:
        print()
        print(yellow("  Interrupted — job still running on server. Use /status <job_id> to reconnect."))
        _active_job = False
        return None

    return None


# ---------------------------------------------------------------------------
# Results rendering
# ---------------------------------------------------------------------------

def print_report(report: dict) -> None:
    if not report:
        return

    sev = report.get("severity", "INFO")
    evil = report.get("evil_found", False)
    sev_colors = {
        "CRITICAL": red, "HIGH": red, "MEDIUM": yellow,
        "LOW": green, "INFO": grey,
    }
    sev_fn = sev_colors.get(sev, white)

    print()
    print(bold("═" * 60))
    print(bold("  Find Evil Report"))
    print(bold("═" * 60))
    print(f"  Severity:    {sev_fn(bold(sev))}")
    print(f"  Evil Found:  {red(bold('YES')) if evil else green('NO')}")
    print(f"  OS:          {report.get('os_type', 'unknown')}")
    print(f"  Elapsed:     {report.get('elapsed_seconds', 0):.1f}s")
    print(f"  Critic:      {report.get('critic_approval_pct', 0):.0f}% approved")
    if report.get("steps_needs_review", 0):
        print(yellow(f"  Review:      {report['steps_needs_review']} steps need human review"))
    print()

    sev_dist = report.get("severity_distribution", {})
    if any(v for v in sev_dist.values()):
        parts = [f"{sev_fn(k)}: {v}" for k, v in sev_dist.items() if v]
        print(f"  Severity distribution: {', '.join(parts)}")
        print()

    pbs = report.get("playbooks_run", [])
    if pbs:
        print(bold("  Playbooks"))
        print(dim("  " + "─" * 56))
        for pb in pbs:
            pb_id = pb.get("playbook_id", "?")
            ok = pb.get("steps_completed", 0)
            sk = pb.get("steps_skipped", 0)
            fa = pb.get("steps_failed", 0)
            print(
                f"  {cyan(pb_id):<18}"
                f"  {green(str(ok))} done"
                f"  {grey(str(sk))} skipped"
                + (f"  {red(str(fa))} failed" if fa else "")
            )
        print()

    dev_map = report.get("device_map", {})
    if dev_map:
        print(bold("  Devices Discovered"))
        print(dim("  " + "─" * 56))
        for dev_id, dev in dev_map.items():
            owner = dev.get("owner") or "—"
            os_t = dev.get("os_type") or "—"
            n_files = len(dev.get("evidence_files") or [])
            print(f"  {cyan(dev_id)}  {dev.get('device_type','?')}  owner={owner}  os={os_t}  files={n_files}")
        print()

    bf = report.get("behavioral_flags_summary", {})
    total_flags = sum(bf.values()) if bf else 0
    if total_flags:
        print(yellow(bold(f"  ⚠ Behavioral Flags: {total_flags}")))
        for dev_id, count in bf.items():
            if count:
                print(yellow(f"    {dev_id}: {count} flags"))
        print()

    if report.get("narrative_report_path"):
        print(f"  📄 Narrative report: {dim(report['narrative_report_path'])}")
    if report.get("case_work_dir"):
        print(f"  📁 Case directory:   {dim(report['case_work_dir'])}")
    print(bold("═" * 60))
    print()


# ---------------------------------------------------------------------------
# Cases display
# ---------------------------------------------------------------------------

def print_cases(data: dict) -> None:
    cases = data.get("cases", {})
    if not cases:
        print(grey("  No cases found."))
        return
    print()
    for case_name, files in cases.items():
        print(f"  {blue(bold('📁 ' + case_name))}  {grey(str(len(files)) + ' items')}")
        for f in files[:20]:
            is_dir = f.startswith("[DIR]")
            label = f.replace("[DIR] ", "") if is_dir else f
            colour = cyan if is_dir else dim
            print(f"    {colour(label)}")
        if len(files) > 20:
            print(grey(f"    … {len(files) - 20} more items"))
        print()


# ---------------------------------------------------------------------------
# Help
# ---------------------------------------------------------------------------

HELP = f"""
{bold('Geoff Console Commands')}

  {cyan('/find-evil [path]')}   Run Find Evil on [path] (or default evidence dir)
  {cyan('/cases')}              List all cases and evidence files
  {cyan('/status <job_id>')}    Reconnect to a running Find Evil job
  {cyan('/help')}               Show this help
  {cyan('/quit')}               Exit

  Anything else is sent to Geoff as a chat message. You can ask:
    - {dim('"analyze /evidence/case1"')}
    - {dim('"what malware was found on device-001?"')}
    - {dim('"summarize the timeline"')}
"""


# ---------------------------------------------------------------------------
# Main REPL
# ---------------------------------------------------------------------------

HISTORY_FILE = Path.home() / ".geoff_console_history"
PROMPT = f"{bold(blue('geoff'))}> " if not _NO_COLOR else "geoff> "


def _setup_readline() -> None:
    readline.set_history_length(500)
    try:
        readline.read_history_file(HISTORY_FILE)
    except FileNotFoundError:
        pass

    # Tab completion for slash commands
    commands = ["/find-evil", "/cases", "/status", "/help", "/quit"]
    def _completer(text, state):
        options = [c for c in commands if c.startswith(text)]
        return options[state] if state < len(options) else None
    readline.set_completer(_completer)
    readline.parse_and_bind("tab: complete")


def _save_history() -> None:
    try:
        readline.write_history_file(HISTORY_FILE)
    except OSError:
        pass


def _handle_sigint(sig, frame):
    """Ctrl+C: stop active poll but don't exit."""
    global _active_job
    if _active_job:
        _active_job = False
    else:
        print()
        raise KeyboardInterrupt


def run_repl(client: GeoffClient) -> None:
    signal.signal(signal.SIGINT, _handle_sigint)
    _setup_readline()

    # Banner
    print()
    print(bold(blue("  G.E.O.F.F. Console")))
    print(dim("  Git-backed Evidence Operations Forensic Framework"))
    print(dim(f"  Connected to {client.server}"))
    print(dim("  Type /help for commands, /quit to exit"))
    print()

    while True:
        try:
            line = input(PROMPT).strip()
        except EOFError:
            print()
            break
        except KeyboardInterrupt:
            print()
            continue

        if not line:
            continue

        # ---- Commands ----
        if line in ("/quit", "quit", "exit", "/exit"):
            break

        if line in ("/help", "help"):
            print(HELP)
            continue

        if line in ("/cases", "cases"):
            try:
                print_cases(client.cases())
            except requests.RequestException as e:
                print(red(f"Error: {e}"))
            continue

        if line.startswith("/find-evil") or line.startswith("find-evil"):
            parts = line.split(None, 1)
            evidence_dir = parts[1].strip() if len(parts) > 1 else ""
            try:
                data = client.start_find_evil(evidence_dir)
                if data.get("status") == "error":
                    print(red(f"Error: {data.get('error')}"))
                    continue
                job_id = data.get("job_id")
                if not job_id:
                    print(red("Server did not return a job_id."))
                    continue
                label = evidence_dir or "default evidence directory"
                print(f"  {green('▶')} Find Evil started on {cyan(label)}")
                print(dim(f"  Job: {job_id}"))
                report = stream_find_evil(client, job_id)
                if report is not None:
                    print_report(report)
            except requests.RequestException as e:
                print(red(f"Error: {e}"))
            continue

        if line.startswith("/status"):
            parts = line.split(None, 1)
            if len(parts) < 2:
                print(yellow("Usage: /status <job_id>"))
                continue
            job_id = parts[1].strip()
            try:
                status = client.job_status(job_id)
                js = status.get("status")
                if js == "complete":
                    print_report(status.get("result") or {})
                elif js == "error":
                    print(red(f"Job failed: {status.get('error')}"))
                elif js == "not_found":
                    print(yellow(f"No job with ID {job_id}"))
                else:
                    print(f"  Job {cyan(job_id)} is {yellow(js)}")
                    report = stream_find_evil(client, job_id)
                    if report is not None:
                        print_report(report)
            except requests.RequestException as e:
                print(red(f"Error: {e}"))
            continue

        # ---- Chat (everything else) ----
        try:
            data = client.chat(line)
        except requests.RequestException as e:
            print(red(f"Error: {e}"))
            continue

        response = data.get("response", "")
        if response:
            print()
            label = bold(green("Geoff"))
            # Wrap long responses at terminal width
            width = min(os.get_terminal_size().columns - 4, 100) if sys.stdout.isatty() else 100
            for para in response.split("\n"):
                if para:
                    for wrapped in textwrap.wrap(para, width) or [para]:
                        print(f"  {wrapped}")
                else:
                    print()
            print()

        if data.get("tool_result"):
            print(dim("  [tool output]"))
            print(dim("  " + json.dumps(data["tool_result"], indent=2)[:2000]))
            print()

        # If chat triggered a Find Evil job, stream it
        if data.get("job_id"):
            job_id = data["job_id"]
            print(dim(f"  Job: {job_id}"))
            report = stream_find_evil(client, job_id)
            if report is not None:
                print_report(report)

    _save_history()
    print(dim("Goodbye."))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Geoff DFIR console — terminal interface to the Geoff server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              python3 scripts/geoff_console.py
              python3 scripts/geoff_console.py --server http://10.0.0.5:8080
              python3 scripts/geoff_console.py --server http://localhost:8080 --key mykey
        """),
    )
    parser.add_argument("--server", default="", help="Geoff server URL (default: http://localhost:<GEOFF_PORT>)")
    parser.add_argument("--key", default="", help="API key (overrides GEOFF_API_KEY env var)")
    args = parser.parse_args()

    cfg = build_config(args)
    client = GeoffClient(cfg["server"], cfg["key"])

    # Connectivity check
    if not client.ping():
        print(red(f"Cannot reach Geoff at {cfg['server']}"))
        print(dim("  Is geoff_integrated.py running?  Check GEOFF_PORT in .env."))
        sys.exit(1)

    run_repl(client)


if __name__ == "__main__":
    main()
