#!/usr/bin/env python3
"""Check Geoff investigation status."""

import sys
import json
import argparse
from pathlib import Path
from datetime import datetime

BASE_DIR = Path(__file__).parent
sys.path.insert(0, str(BASE_DIR.parent))

def check_status(case_id: str):
    """Check investigation status."""
    case_dir = BASE_DIR.parent / 'cases' / case_id
    state_file = case_dir / f'{case_id}_state.json'
    plan_file = case_dir / 'plan.json'
    
    print(f"🔍 Investigation Status: {case_id}")
    print("=" * 50)
    
    if not case_dir.exists():
        print(f"❌ Case not found: {case_id}")
        return
    
    # Load state
    if state_file.exists():
        with open(state_file) as f:
            state = json.load(f)
        
        completed = sum(1 for s in state.get('steps', []) if s.get('completed'))
        total = len(state.get('steps', []))
        
        print(f"\n📊 Progress: {completed}/{total} steps ({state.get('progress_pct', 0)}%)")
        print(f"   Status: {state.get('status', 'unknown')}")
        print(f"   Last Updated: {state.get('last_updated', 'never')}")
        
        # Show completed findings
        findings_dir = case_dir / 'findings'
        if findings_dir.exists():
            findings = list(findings_dir.glob('*.md'))
            if findings:
                print(f"\n📝 Findings ({len(findings)}):")
                for f in sorted(findings):
                    print(f"   ✓ {f.name}")
        
        # Show next steps
        pending = [s for s in state.get('steps', []) if not s.get('completed')]
        if pending:
            print(f"\n⏳ Next Steps:")
            for step in pending[:3]:
                print(f"   • [{step.get('category', '?')}] {step.get('description', '?')}")
    else:
        print(f"⏳ Investigation initialized but no state yet")
        
    # Check for report
    report_file = case_dir / 'REPORT.md'
    if report_file.exists():
        print(f"\n📄 FINAL REPORT: Available at {report_file}")

def main():
    parser = argparse.ArgumentParser(description='Check Geoff status')
    parser.add_argument('case_id', help='Case identifier')
    args = parser.parse_args()
    check_status(args.case_id)

if __name__ == '__main__':
    main()
