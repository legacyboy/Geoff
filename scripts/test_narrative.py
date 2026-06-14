#!/usr/bin/env python3
"""Test the narrative report generator with Jean case data and new truncation limits."""
import json
import sys
import os

# Add Geoff src to path
sys.path.insert(0, os.path.expanduser("/home/sansforensics/Geoff/src"))

from narrative_report import NarrativeReportGenerator

CASE_DIR = "/mnt/cases/jeanm57_findevil_b18c1b0201fa"
REPORT_PATH = f"{CASE_DIR}/reports/find_evil_report.json"

print("Loading report JSON...")
with open(REPORT_PATH) as f:
    report = json.load(f)

print(f"Report keys: {len(report)}")
print(f"Findings: {len(report.get('findings_detail', []))}")
print(f"Behavioral flags: {sum(len(v) for v in report.get('behavioral_flags', {}).values())}")
print(f"Email IOCs: {len(report.get('email_iocs', {}).get('return_path_mismatches', []))} return-path mismatches")

# Initialize generator (no LLM - template-only mode for testing)
gen = NarrativeReportGenerator(call_llm_func=None)

device_map = report.get("device_map", {})
user_map = report.get("user_map", {})

# Build step_evidence_anchors from findings_detail
findings = report.get("findings_detail", [])
step_evidence_anchors = []
for f in findings[:100]:
    chain = f.get("evidence_chain", {})
    if chain and isinstance(chain, dict):
        step_evidence_anchors.append(chain)

behavioral_flags = report.get("behavioral_flags", {})
correlated_users = report.get("correlated_users", {})

# Get unresolved critic flags
unresolved_flags = []
for f in findings:
    if f.get("critic_result") == "REJECTED" or f.get("critic_result") == "REQUIRES_REVIEW":
        unresolved_flags.append(f)

print(f"\nStep evidence anchors: {len(step_evidence_anchors)}")
print(f"Unresolved critic flags: {len(unresolved_flags)}")

# Generate the report
print("\nGenerating narrative report...")
output_path = gen.generate(
    report_json=report,
    device_map=device_map,
    user_map=user_map,
    super_timeline_path=f"{CASE_DIR}/reports/timeline.csv",
    correlated_users=correlated_users,
    behavioral_flags=behavioral_flags,
    case_work_dir=CASE_DIR,
    step_evidence_anchors=step_evidence_anchors,
    unresolved_critic_flags=unresolved_flags,
)

print(f"\nReport generated: {output_path}")
print(f"Size: {os.path.getsize(output_path)} bytes")

# Print the first 2000 chars to verify quality
with open(output_path) as f:
    content = f.read()
print("\n=== FIRST 3000 CHARS ===")
print(content[:3000])
print("\n=== LAST 1000 CHARS ===")
print(content[-1000:])

# Check for key phrases
checks = [
    "phishing", "spoof", "Return-Path", "Google Alert",
    "social engineering", "credential", "exfiltrat",
    "insider", "USB", "malware"
]
print("\n=== CONTENT CHECKS ===")
for check in checks:
    count = content.lower().count(check)
    print(f"  '{check}': {count} occurrences")