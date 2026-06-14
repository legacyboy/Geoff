#!/usr/bin/env python3
"""Test the narrative report generator with Jean case data and LLM enabled."""
import json
import sys
import os
import re

sys.path.insert(0, "/home/sansforensics/Geoff/src")
from geoff_integrated import call_llm
from narrative_report import NarrativeReportGenerator

CASE_DIR = "/mnt/cases/jeanm57_findevil_b18c1b0201fa"
REPORT_PATH = f"{CASE_DIR}/reports/find_evil_report.json"

print("Loading report JSON...")
with open(REPORT_PATH) as f:
    report = json.load(f)

print(f"Report keys: {len(report)}")
print(f"Findings: {len(report.get('findings_detail', []))}")
print(f"Email IOCs: {len(report.get('email_iocs', {}).get('return_path_mismatches', []))} return-path mismatches")

gen = NarrativeReportGenerator(call_llm_func=call_llm)

device_map = report.get("device_map", {})
user_map = report.get("user_map", {})

findings = report.get("findings_detail", [])
step_evidence_anchors = []
for f in findings[:100]:
    chain = f.get("evidence_chain", {})
    if chain and isinstance(chain, dict):
        step_evidence_anchors.append(chain)

behavioral_flags = report.get("behavioral_flags", {})
correlated_users = report.get("correlated_users", {})

print(f"\nStep evidence anchors: {len(step_evidence_anchors)}")
print("Generating narrative report with LLM...")

output_path = gen.generate(
    report_json=report,
    device_map=device_map,
    user_map=user_map,
    super_timeline_path=f"{CASE_DIR}/reports/timeline.csv",
    correlated_users=correlated_users,
    behavioral_flags=behavioral_flags,
    case_work_dir=CASE_DIR,
    step_evidence_anchors=step_evidence_anchors,
    unresolved_critic_flags=[],
)

print(f"\nReport generated: {output_path}")
print(f"Size: {os.path.getsize(output_path)} bytes")

with open(output_path) as f:
    content = f.read()

checks = ["phishing", "spoof", "Return-Path", "Google Alert",
          "social engineering", "credential", "exfiltrat",
          "insider", "USB", "malware", "jean@m57.biz"]
print("\n=== CONTENT CHECKS ===")
for check in checks:
    count = content.lower().count(check.lower())
    print(f"  {check}: {count} occurrences")

# Print executive summary
m = re.search(r"## Executive Summary.*?(?=## |\Z)", content, re.DOTALL)
if m:
    print("\n=== EXECUTIVE SUMMARY ===")
    print(m.group(0)[:3000])
else:
    # Try other section headers
    for h in ["## 1. Scope", "## Attack Narrative", "## Key Evidence"]:
        m = re.search(rf"{h}.*?(?=## |\Z)", content, re.DOTALL)
        if m:
            print(f"\n=== {h} ===")
            print(m.group(0)[:2000])
            break
    else:
        print("\n=== FIRST 3000 CHARS ===")
        print(content[:3000])
