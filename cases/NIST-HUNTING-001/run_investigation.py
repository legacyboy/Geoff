#!/usr/bin/env python3
"""
NIST-HUNTING-001: Full Forensic Investigation Runner
Step-by-step evidence collection and analysis.
"""

import sys
import json
import subprocess
from pathlib import Path
from datetime import datetime

def run_step(step_number, step_name, script_path):
    """Execute an investigation step and capture results."""
    print(f"\n{'='*60}")
    print(f"STEP {step_number}: {step_name}")
    print(f"{'='*60}")
    
    try:
        result = subprocess.run(
            [sys.executable, str(script_path)],
            capture_output=True,
            text=True,
            timeout=120
        )
        
        print(result.stdout)
        
        if result.returncode != 0:
            print(f"[!] Step {step_number} completed with warnings:")
            print(result.stderr)
        
        return {
            "step": step_number,
            "name": step_name,
            "status": "completed",
            "timestamp": datetime.now().isoformat(),
            "output": result.stdout[-2000:] if len(result.stdout) > 2000 else result.stdout
        }
        
    except Exception as e:
        print(f"[✗] Step {step_number} failed: {e}")
        return {
            "step": step_number,
            "name": step_name,
            "status": "failed",
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }

def main():
    case_dir = Path(__file__).parent
    steps_dir = case_dir / "steps"
    findings_dir = case_dir / "findings"
    
    # Ensure directories exist
    findings_dir.mkdir(parents=True, exist_ok=True)
    
    print(f"\n{'#'*60}")
    print(f"# NIST-HUNTING-001 FORENSIC INVESTIGATION")
    print(f"# Started: {datetime.now().isoformat()}")
    print(f"# Investigator: Geoff")
    print(f"{'#'*60}")
    
    investigation_log = {
        "case_id": "NIST-HUNTING-001",
        "title": "NIST Cyber Threat Hunting Investigation",
        "started_at": datetime.now().isoformat(),
        "investigator": "Geoff",
        "steps": []
    }
    
    # Step 1: Evidence Collection
    step1 = run_step(1, "Evidence Collection & Verification", steps_dir / "step_01_evidence_collection.py")
    investigation_log["steps"].append(step1)
    
    # Step 2: Threat Analysis
    step2 = run_step(2, "Threat Taxonomy Analysis", steps_dir / "step_02_threat_analysis.py")
    investigation_log["steps"].append(step2)
    
    # Step 3: IOC Extraction
    step3 = run_step(3, "IOC Extraction & Classification", steps_dir / "step_03_ioc_extraction.py")
    investigation_log["steps"].append(step3)
    
    # Generate final report
    investigation_log["completed_at"] = datetime.now().isoformat()
    
    log_path = findings_dir / "investigation_log.json"
    with open(log_path, 'w') as f:
        json.dump(investigation_log, f, indent=2)
    
    print(f"\n{'='*60}")
    print(f"INVESTIGATION COMPLETE")
    print(f"{'='*60}")
    print(f"Log saved: {log_path}")
    print(f"Findings directory: {findings_dir}")
    print(f"\nGenerated files:")
    for f in sorted(findings_dir.glob("*")):
        print(f"  - {f.name}")

if __name__ == "__main__":
    main()
