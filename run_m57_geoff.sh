#!/bin/bash
# Run M57-Jean investigation with Geoff from sift-challenge directory

cd /home/claw/projects/sift-challenge
export PYTHONPATH=/home/claw/projects/sift-challenge

python3 -c "
from pathlib import Path
from agent.planner import SIFTPlanner
import json

case_id = 'M57-Jean-Geoff-2026-04-03'
evidence_path = Path('/home/claw/cases/M57-JEAN-REAL/evidence/disk')

print('=' * 70)
print('M57-JEAN FORENSIC INVESTIGATION - GEOFF PROTOCOL')
print('=' * 70)
print(f'Case: {case_id}')
print(f'Evidence: {evidence_path}')
print(f'Evidence files: nps-2008-jean.E01 (1.5GB), nps-2008-jean.E02 (1.4GB)')
print('=' * 70)
print()

planner = SIFTPlanner(
    case_id=case_id,
    evidence_path=evidence_path,
    objective='Analyze disk image for signs of data exfiltration, unauthorized access, and insider threat activity. Focus on: USB activity, file transfers, browser history, and confidential document access.',
    branch='main'
)

print('[GEOFF] Starting investigation with evil category detection...')
print('[GEOFF] Will assess: persistence, suspicious files, timeline anomalies,')
print('         privilege abuse, process anomalies, network indicators,')
print('         log tampering, data exfiltration, malware, anti-forensics')
print()

try:
    report = planner.investigate('Full forensic analysis of M57-Jean disk image')
    
    print()
    print('=' * 70)
    print('INVESTIGATION COMPLETE')
    print('=' * 70)
    
    if 'decisions' in report:
        decisions = report['decisions']
        print(f'\\nEvil Categories Found: {len(decisions.get(\"evil_categories_found\", []))}')
        for cat in decisions.get('evil_categories_found', []):
            print(f'  - {cat}')
        
        print(f'\\nPriority: {decisions.get(\"priority\", \"N/A\").upper()}')
        
        print(f'\\nQuestions ({len(decisions.get(\"questions\", []))}):')
        for q in decisions.get('questions', []):
            print(f'  ? {q}')
        
        print(f'\\nRecommendations ({len(decisions.get(\"recommendations\", []))}):')
        for r in decisions.get('recommendations', []):
            print(f'  -> {r}')
        
        print(f'\\nNext Actions ({len(decisions.get(\"next_actions\", []))}):')
        for a in decisions.get('next_actions', []):
            print(f'  -> {a}')
    
    print(f'\\nTotal Steps: {report.get(\"total_steps\", 0)}')
    print(f'Key Findings: {len(report.get(\"key_findings\", []))}')
    
    print('\\n' + '-' * 70)
    print('GIT AUDIT TRAIL:')
    print('-' * 70)
    log = planner.evidence_tracker.get_log(20)
    for entry in log[:10]:
        print(f'[{entry[\"commit\"][:8]}] {entry[\"message\"].split(chr(10))[0]}')
    
    report_path = Path(f'/home/claw/cases/M57-JEAN-REAL/report_geoff_{case_id}.json')
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2, default=str)
    print(f'\\nReport saved to: {report_path}')
    
except Exception as e:
    print(f'\\n[ERROR] {e}')
    import traceback
    traceback.print_exc()
"
