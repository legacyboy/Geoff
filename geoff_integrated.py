#!/usr/bin/env python3
"""
Geoff DFIR - Entry point wrapper

This wrapper provides a thin CLI layer and delegates to the main application
in src/geoff_integrated.py. It supports --help, --version, and --check flags
for verification, then launches the full server for normal operation.
"""
import os
import sys

# Resolve the directory this script lives in
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
MAIN_MODULE = os.path.join(SCRIPT_DIR, "src", "geoff_integrated.py")


def main():
    # Handle CLI flags that don't require full server startup
    if "--help" in sys.argv or "-h" in sys.argv:
        print("Geoff DFIR - Git-backed Evidence Operations Forensic Framework")
        print()
        print("Usage: python3 geoff_integrated.py [options]")
        print()
        print("Options:")
        print("  --help       Show this help message")
        print("  --version    Show version info")
        print("  --check      Run startup checks without starting the server")
        print()
        print("The server runs on the port specified by GEOFF_PORT (default: 8080).")
        print("Configure the profile and models via .env file.")
        print()
        print("Profile options: cloud (Ollama cloud), local (self-hosted models)")
        return 0

    if "--version" in sys.argv:
        # Read version from git describe or fallback
        version = "unknown"
        try:
            import subprocess
            result = subprocess.run(
                ["git", "describe", "--tags", "--always"],
                capture_output=True, text=True, cwd=SCRIPT_DIR
            )
            if result.returncode == 0:
                version = result.stdout.strip()
        except Exception:
            pass
        print(f"Geoff DFIR v{version}")
        return 0

    if "--check" in sys.argv:
        # Run self-check only, then exit
        if os.path.exists(MAIN_MODULE):
            # Load .env if present
            try:
                from dotenv import load_dotenv
                dotenv_path = os.path.join(SCRIPT_DIR, ".env")
                if os.path.exists(dotenv_path):
                    load_dotenv(dotenv_path=dotenv_path, override=True)
            except ImportError:
                pass

            sys.path.insert(0, os.path.join(SCRIPT_DIR, "src"))
            try:
                from geoff_selfcheck import startup_check
                from geoff_integrated import ollama_base_url, OLLAMA_API_KEY, AGENT_MODELS
                evidence_base = os.environ.get("GEOFF_EVIDENCE_PATH", "/mnt/evidence")
                cases_work = os.environ.get("GEOFF_CASES_PATH", "/mnt/cases")
                startup_check(
                    ollama_url=ollama_base_url(),
                    api_key=OLLAMA_API_KEY,
                    agent_models=AGENT_MODELS,
                    evidence_base=evidence_base,
                    cases_work=cases_work,
                )
                print("Self-check passed.")
            except Exception as e:
                print(f"Self-check failed: {e}", file=sys.stderr)
                return 1
        else:
            print(f"Main module not found at {MAIN_MODULE}", file=sys.stderr)
            return 1
        return 0

    # Normal operation: delegate to src/geoff_integrated.py
    if os.path.exists(MAIN_MODULE):
        # Ensure src/ is on sys.path so sibling imports work
        sys.path.insert(0, os.path.join(SCRIPT_DIR, "src"))
        # Execute the main module directly, preserving sys.argv
        import runpy
        sys.argv = [MAIN_MODULE] + [a for a in sys.argv[1:]
                                       if a not in ("--help", "-h", "--version", "--check")]
        runpy.run_path(MAIN_MODULE, run_name="__main__")
    else:
        print(f"Error: Main module not found at {MAIN_MODULE}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    sys.exit(main())
