#!/usr/bin/env python3
"""
G.E.O.F.F. Watchdog
Monitors Geoff service and restarts if it stops responding.
Reads config from .env file in the Geoff install directory.
"""

import os
import subprocess
import time
import sys
from datetime import datetime
from pathlib import Path

try:
    import requests
except ImportError:
    print(f"[{datetime.now()}] requests not installed, installing...")
    subprocess.run([sys.executable, "-m", "pip", "install", "requests"], capture_output=True)
    import requests

# Configuration — read from environment or .env
GEOFF_DIR = os.environ.get("GEOFF_DIR", "/opt/geoff")
GEOFF_PORT = os.environ.get("GEOFF_PORT", "8080")
GEOFF_ENTRY = os.path.join(GEOFF_DIR, "src", "geoff_integrated.py")
GEOFF_LOG = os.path.join(GEOFF_DIR, "geoff.log")
GEOFF_VENV = os.path.join(GEOFF_DIR, "venv", "bin", "python3")

# Try to load .env if python-dotenv is available
env_file = Path(GEOFF_DIR) / ".env"
env_vars = {}
if env_file.exists():
    try:
        from dotenv import dotenv_values
        env_vars = dotenv_values(env_file)
    except ImportError:
        # Manual .env parsing
        for line in env_file.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, val = line.partition("=")
                env_vars[key.strip()] = val.strip().strip('"').strip("'")

CHECK_URL = f"http://localhost:{GEOFF_PORT}/"
CHECK_INTERVAL = int(os.environ.get("WATCHDOG_INTERVAL", "30"))
MAX_FAILS = int(os.environ.get("WATCHDOG_MAX_FAILS", "3"))


def check_geoff():
    """Check if Geoff is responding on the configured port."""
    try:
        response = requests.get(CHECK_URL, timeout=10)
        return response.status_code == 200
    except Exception:
        return False


def restart_geoff():
    """Restart Geoff service using the venv python and .env config."""
    print(f"[{datetime.now()}] Restarting Geoff...")

    # Kill any existing Geoff processes
    subprocess.run(["pkill", "-9", "-f", "geoff_integrated.py"], capture_output=True)
    time.sleep(2)

    # Build environment: system env + .env values
    env = dict(os.environ)
    env.update(env_vars)

    # Use venv python if available, fallback to system python3
    python_bin = GEOFF_VENV if Path(GEOFF_VENV).exists() else sys.executable

    # Start Geoff
    log_fh = open(GEOFF_LOG, "a")
    subprocess.Popen(
        [python_bin, GEOFF_ENTRY],
        env=env,
        stdout=log_fh,
        stderr=subprocess.STDOUT,
        cwd=GEOFF_DIR,
    )

    # Wait for startup
    for _ in range(10):
        time.sleep(3)
        if check_geoff():
            print(f"[{datetime.now()}] Geoff restarted successfully")
            log_fh.close()
            return True

    print(f"[{datetime.now()}] Failed to restart Geoff after 30s")
    log_fh.close()
    return False


def main():
    """Main watchdog loop."""
    print(f"[{datetime.now()}] G.E.O.F.F. Watchdog started")
    print(f"[{datetime.now()}] Monitoring {CHECK_URL} every {CHECK_INTERVAL}s")

    fail_count = 0

    while True:
        if not check_geoff():
            fail_count += 1
            print(f"[{datetime.now()}] Geoff not responding (fail {fail_count}/{MAX_FAILS})")

            if fail_count >= MAX_FAILS:
                restart_geoff()
                fail_count = 0
        else:
            fail_count = 0

        time.sleep(CHECK_INTERVAL)


if __name__ == "__main__":
    main()