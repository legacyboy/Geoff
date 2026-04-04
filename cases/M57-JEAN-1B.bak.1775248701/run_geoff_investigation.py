#!/usr/bin/env python3
"""
M57-JEAN-1B: Corporate Espionage Investigation
Geoff Digital Forensics - Full Investigation Runner
"""

import sys
import json
import subprocess
from pathlib import Path
from datetime import datetime

BASE_DIR = Path(__file__).parent
sys.path.insert(0, str(BASE_DIR.parent.parent))

def run_investigation_step(step_num, name, script):
    """Execute investigation step."""
    print(f"\n{'='*70}")
    print(f"STEP {step_num}: {name}")
    print(f"{'='*70}")
    
    try:
        result = subprocess.run(
            [sys.executable, str(script)],
            capture_output=True,
            text=True,
            timeout=180,
            cwd=str(BASE_DIR)
        )
        print(result.stdout)
        return {"step": step_num, "name": name, "status": "completed", "timestamp": datetime.now().isoformat()}
    except Exception as e:
        print(f"[!] Error: {e}")
        return {"step": step_num, "name": name, "status": "failed", "error": str(e), "timestamp": datetime.now().isoformat()}

def main():
    print(f"\n{'#'*70}")
    print(f"# M57-JEAN-1B: CORPORATE ESPIONAGE INVESTIGATION")
    print(f"# Geoff Digital Forensics")
    print(f"# Started: {datetime.now().isoformat()}")
    print(f"{'#'*70}")
    
    print("\n[INVESTIGATION SUMMARY]")
    print("  Case: M57-Jean Corporate Espionage")
    print("  Suspect: Jean (Senior Executive)")
    print("  Incident: Confidential salary spreadsheet leaked to competitor")
    print("  Objective: Determine HOW data was stolen - hacking or insider?")
    print("  Status: Evidence download required")
    
    # Check for evidence
    evidence_check = BASE_DIR / "evidence" / "nps-2008-jean.E01"
    if not evidence_check.exists():
        print(f"\n[!] EVIDENCE NOT FOUND")
        print(f"    Expected: {evidence_check}")
        print(f"\n    Download Instructions:")
        print(f"    1. Visit: https://digitalcorpora.org/corpora/scenarios/m57-jean/")
        print(f"    2. Download: nps-2008-jean.E01")
        print(f"    3. Download: nps-2008-jean.E02")
        print(f"    4. Place both files in: {BASE_DIR}/evidence/")
        
        # Create evidence directory
        (BASE_DIR / "evidence").mkdir(parents=True, exist_ok=True)
        print(f"\n    [Created evidence directory: {BASE_DIR}/evidence/]")
        
        return
    
    print(f"\n[✓] Evidence found: {evidence_check}")
    print(f"[✓] Starting forensic analysis...")
    
    # Run investigation steps
    # (Would run actual forensic analysis here)

if __name__ == "__main__":
    main()
