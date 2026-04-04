#!/usr/bin/env python3
"""
Run M57-Jean investigation with updated Geoff (SIFTPlanner)
Following proper procedure with evil category detection.
Must be run from /home/claw/projects/sift-challenge directory.
"""

import sys
import os

# Must run from sift-challenge directory
os.chdir('/home/claw/projects/sift-challenge')
sys.path.insert(0, '/home/claw/projects/sift-challenge')

from pathlib import Path

# Import directly from agent module files
exec(open('agent/planner.py').read())

def main():
    case_id = "M57-Jean-Geoff-2026-04-03"
    evidence_path = Path("/home/claw/cases/M57-JEAN-REAL/evidence/disk")
    
    print("=" * 70)
    print("M57-JEAN FORENSIC INVESTIGATION - GEOFF PROTOCOL")
    print("=" * 70)
    print(f"Case: {case_id}")
    print(f"Evidence: {evidence_path}")
    print(f"Evidence files: nps-2008-jean.E01 (1.5GB), nps-2008-jean.E02 (1.4GB)")
    print("=" * 70)
    print()
    
    # Initialize planner
    planner = SIFTPlanner(
        case_id=case_id,
        evidence_path=evidence_path,
        objective="Analyze disk image for signs of data exfiltration, unauthorized access, and insider threat activity. Focus on: USB activity, file transfers, browser history, and confidential document access.",
        branch="main"
    )
    
    print("[GEOFF] Starting investigation with evil category detection...")
    print("[GEOFF] Will assess: persistence, suspicious files, timeline anomalies,")
    print("         privilege abuse, process anomalies, network indicators,")
    print("         log tampering, data exfiltration, malware, anti-forensics")
    print()
    
    try:
        report = planner.investigate("Full forensic analysis of M57-Jean disk image")
        
        print("\n" + "=" * 70)
        print("INVESTIGATION COMPLETE")
        print("=" * 70)
        
        # Print evil categories found
        if 'decisions' in report:
            decisions = report['decisions']
            print(f"\nEvil Categories Found: {len(decisions.get('evil_categories_found', []))}")
            for cat in decisions.get('evil_categories_found', []):
                print(f"  - {cat}")
            
            print(f"\nPriority: {decisions.get('priority', 'N/A').upper()}")
            
            print(f"\nQuestions to Answer ({len(decisions.get('questions', []))}):")
            for q in decisions.get('questions', []):
                print(f"  ? {q}")
            
            print(f"\nRecommendations ({len(decisions.get('recommendations', []))}):")
            for r in decisions.get('recommendations', []):
                print(f"  → {r}")
            
            print(f"\nNext Actions ({len(decisions.get('next_actions', []))}):")
            for a in decisions.get('next_actions', []):
                print(f"  → {a}")
        
        print(f"\nTotal Steps: {report.get('total_steps', 0)}")
        print(f"Key Findings: {len(report.get('key_findings', []))}")
        
        # Print investigation timeline (git log)
        print("\n" + "-" * 70)
        print("GIT AUDIT TRAIL:")
        print("-" * 70)
        log = planner.evidence_tracker.get_log(20)
        for entry in log[:10]:
            print(f"[{entry['commit'][:8]}] {entry['message'].split(chr(10))[0]}")
        
        # Save report
        report_path = Path(f"/home/claw/cases/M57-JEAN-REAL/report_geoff_{case_id}.json")
        import json
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\nReport saved to: {report_path}")
        
    except Exception as e:
        print(f"\n[ERROR] Investigation failed: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
