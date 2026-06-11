# dfrws2008 Find Evil — CC5 Fix Validation Audit

**Case:** `dfrws2008_findevil_39db792957d0`
**Date:** 2026-06-11
**Auditor:** Steve (automated subagent audit)
**Verdict:** ❌ **FIXES NOT VALIDATED — Major false positive persists**

---

## Executive Summary

The dfrws2008 Find Evil run produced a **CRITICAL severity / Rootkit classification** result. This verdict is a **false positive**. Every forensic playbook that executed returned **zero findings**. The classification was driven entirely by raw string-matching indicator hits with no corroborating evidence. The 7 CC5 fixes did not prevent this outcome.

---

## 1. Evidence Overview

| Category | Count | Details |
|----------|-------|---------|
| Disk images | 0 | None found |
| Memory dumps | 1 | `challenge.mem` (Linux memory) |
| PCAPs | 1 | `suspect.pcap` |
| Other files | 196 | Linux user home directory (Firefox profile, GNOME config, etc.) |
| **Total unprocessed** | **199** | All marked "no_playbook_coverage" |

The evidence is a Linux host with a memory dump and network capture. No disk images, no Windows artifacts, no registry hives, no evtx logs.

---

## 2. Playbook Execution: Complete Failure

### 2.1 What Ran

Four playbooks produced output files: PB-SIFT-060 through PB-SIFT-063. All four returned **zero findings**:

| Playbook | Purpose | Result |
|----------|---------|--------|
| PB-SIFT-060 | Communications Analysis | 0 messages, 0 persons, 0 emails |
| PB-SIFT-061 | Steganography Detection | 0 suspects, 0 artifacts, 0 yara hits |
| PB-SIFT-062 | Keylogger/Spyware Analysis | 0 hits, 0 binary detections |
| PB-SIFT-063 | Chat & Messaging | 0 messages, 0 persons |

### 2.2 What Failed Silently

The Geoff log reveals tools ran against wrong evidence types and produced errors that were silently absorbed:

**Volatility error:**
```
stderr from vol -f .../challenge.mem windows.netscan.NetScan:
    usage: vol [-h] [-c CONFIG] [--parallelism ...]
```
Volatility was called with a Windows plugin (`windows.netscan.NetScan`) on a Linux memory dump. The command failed with a usage error.

**Tshark error:**
```
stderr from tshark -r .../suspect.pcap -Y dhcp:
    tshark: Some fields are not valid:
```
Tshark was called with invalid display filter on the pcap.

**SQLite error:**
```
stderr from sqlite3 .../.mc/history SELECT DISTINCT url FROM moz_places:
    Error: in prepare, file is not a database (26)
```
SQLite was called with a Firefox places.sqlite query on a Midnight Commander history text file.

### 2.3 Crash Recovery Failures

All four playbook output files triggered crash recovery skips:

```
crash recovery skipped for PB-SIFT-062_keylogger.json: str object has no attribute get
crash recovery skipped for PB-SIFT-061_stego.json: str object has no attribute get
crash recovery skipped for PB-SIFT-060_communications.json: str object has no attribute get
crash recovery skipped for PB-SIFT-063_chat_aggregator.json: str object has no attribute get
```

### 2.4 Evidence Type Mismatch

**199 evidence files** were classified as `other_files`, `memory_dumps`, or `pcaps` — types that have **no steps in any loaded playbook**. The unprocessed-files section confirms:

> Evidence type 'memory_dumps' has no steps in any loaded playbook
> Evidence type 'pcaps' has no steps in any loaded playbook
> Evidence type 'other_files' has no steps in any loaded playbook

Even though playbooks like PB-SIFT-027 (Memory Forensics) and PB-SIFT-014 (Linux Forensics) exist, the evidence type strings don't match what the playbook gating logic expects.

---

## 3. The Critical False Positive: Indicator Hits Driving Classification

### 3.1 Indicator Hits to CRITICAL

Despite zero playbook findings, the report states:

```json
{
  "evil_found": true,
  "severity": "CRITICAL",
  "classification": "Rootkit"
}
```

This is driven by the pipeline code at `geoff_pipeline.py:5023-5040`:

```python
hit_categories = set(h.get("category", "").lower() for h in indicator_hits ...)
# ...
elif "rootkit" in hit_categories:
    classification = "Rootkit"
    severity = "CRITICAL"
```

**A single string match in the `rootkit` category is sufficient to classify the entire case as CRITICAL, with zero corroboration required from any forensic playbook.**

### 3.2 The 17 Indicator Hits

The `indicator_hits_critic_validation.json` shows:

```json
{
  "verdict": "APPROVED",
  "verdict_reason": "The analysis claim of 17 indicator hits exactly matches the 17 lines provided...
   valid threat signature names and pattern matches (e.g., metasploit, webshell)"
}
```

The critic approved the 17 hits because they matched the raw output count. But the critic does **not** evaluate whether hits in a Linux pcap/mem context are actually malicious vs. false positives from tool references or documentation.

### 3.3 Pipeline Architecture Problem

At `geoff_pipeline.py:4815`:

```python
malware_analysis_warranted = (
    suspicious_binary_found
    or len(indicator_hits) > 0       # <-- THIS LINE
    or len(inventory["other_files"]) > 0
)
```

**Any indicator hit > 0 triggers malware analysis playbooks AND contributes to the final classification.** The indicator scan is a simple string/YARA match with no context awareness. It finds strings like "metasploit" and "webshell" in pcap data, and those alone drive a CRITICAL classification — even when every tool-run against the evidence fails or produces zero results.

---

## 4. Checklist: Specific CC5 Fix Validation

### Q1: Were there any false positive IOCs flagged?

**YES.** 17 indicator hits were flagged and approved. Hits included "metasploit" and "webshell" — likely from the pcap (where tool references appear in HTTP traffic). These 17 hits alone classified the case as CRITICAL Rootkit, despite:

- 0 forensic findings from any playbook
- All tools running against wrong evidence types
- 199/199 evidence files having no playbook coverage

### Q2: Did the gating logic correctly skip playbooks for incompatible evidence types?

**NO.** The gating logic did the opposite:

- Evidence was classified as `memory_dumps`, `pcaps`, `other_files`
- These type strings have zero playbooks that match them
- Tools still ran against wrong evidence (Windows Volatility on Linux mem, SQLite on text files)
- Errors were silently absorbed rather than surfacing the mismatch
- 199 files marked "no_playbook_coverage" — every single evidence file

### Q3: Did the REJECTED findings filtering work on severity counts?

**CANNOT EVALUATE.** The batch critic shows:

```json
{
  "total_findings": 0,
  "completed": 0,
  "playbooks_run": 0,
  "high_critical_findings": 0,
  "overall_quality": "POOR"
}
```

With 0 findings, there's nothing to filter. The critic correctly identified POOR quality and 0 playbooks run, but the severity was still driven by indicator hits outside the critic's scope.

### Q4: Did the IOC noise whitelist filter out legitimate domains?

**PARTIALLY EVALUABLE.** The connection map shows 60 external contacts with all hostnames empty and all src/dst devices set to "unknown". The external IPs include Yahoo (69.147.x.x, 209.170.x.x), Google (64.233.x.x, 72.14.x.x, 8.12.x.x), and other standard infrastructure. No obviously malicious domains appear in the contact list, suggesting either:

- The whitelist is working (noise domains were filtered), OR
- DNS resolution failed (all hostnames are empty)
- Device attribution is broken (all devices = "unknown")

### Q5: Does this run look actually clean?

**NO.** Key issues summary:

| Issue | Severity | Detail |
|-------|----------|--------|
| False positive CRITICAL classification | Critical | Rootkit classification from string hits with zero forensic corroboration |
| Evidence type classification failure | Critical | 199/199 files have no playbook coverage |
| Wrong-tool execution | High | Windows Volatility on Linux mem, SQLite on text files |
| Error absorption | High | Tool errors silently absorbed, crash recovery skips |
| Device attribution broken | Medium | All connections show "unknown" device |
| DNS resolution failure | Medium | All external contacts have empty hostnames |
| Report generated despite 0 findings | High | Manager should have rejected this |

---

## 5. Root Cause Analysis

### Primary: Indicator hits drive classification with zero corroboration

The pipeline at `geoff_pipeline.py:5023-5050` uses indicator hit **categories** to determine:

1. `evil_found` (boolean)
2. `severity` (CRITICAL/HIGH/MEDIUM/LOW)
3. `classification` (Rootkit/Ransomware/etc.)

There is **no requirement** that any forensic playbook must produce findings. A single string match in `rootkit` category means instant CRITICAL.

### Secondary: Evidence type classification doesn't match playbook expectations

The evidence classifier produces labels (`memory_dumps`, `pcaps`, `other_files`) that don't match any playbook's evidence type signatures. The 27+ playbooks in `/home/sansforensics/Geoff/playbooks/` define their own evidence type expectations, and no mapping layer connects the classifier output to playbook input requirements.

### Tertiary: Tool selection doesn't validate OS compatibility

Volatility was called with `windows.netscan.NetScan` on a Linux memory dump. The code doesn't check OS type before selecting Volatility plugins. SQLite was called on a text file with a Firefox schema. No pre-flight validation of file type vs. tool compatibility.

---

## 6. Recommendations

### Immediate (CC5 fixes needed)

1. **Corroboration gate for classification:** Require at least N findings from forensic playbooks before indicator hits can drive CRITICAL/HIGH severity. If playbooks produce 0 findings, cap severity at MEDIUM regardless of indicator hits.

2. **Evidence type to playbook mapping layer:** Create a mapping between classifier output labels and playbook evidence type expectations. `memory_dumps` should map to PB-SIFT-027 (Memory Forensics), `pcaps` should map to network analysis playbooks.

3. **OS-aware tool selection:** Before running Volatility, detect OS type from the memory dump and select the correct plugin family (`windows.*` vs `linux.*`). Validate file type before running SQLite queries.

### Short-term

4. **Surfaced tool errors:** Failed tool executions should produce visible warnings in the report, not silent absorption. The Volatility and SQLite errors should have been flagged.

5. **Minimum-findings threshold for report generation:** If ALL playbooks return 0 findings AND all evidence is unprocessed, the manager should auto-reject with a clear reasoning message.

### Long-term

6. **Indicator hit context validation:** String matches in pcaps (which may contain tool references, documentation, or research traffic) should be weighted lower than hits in executable files or persistence mechanisms.

---

## Appendix: Key File Inventory

| File | Size | Purpose |
|------|------|---------|
| `reports/find_evil_report.json` | ~77KB | Final report — CRITICAL/Rootkit false positive |
| `batch_critic_assessment.json` | 524B | Critic: 0 findings, 0 playbooks, POOR quality |
| `indicator_hits_critic_validation.json` | 605B | IOC validation: 17 hits APPROVED |
| `manager_decision.json` | 428B | Manager: replay, generate_report=false |
| `audit_trail.jsonl` | 255B | Single event: evil_found=true, CRITICAL |
| `.geoff_checkpoint.json` | 4.3KB | Checkpoint: all phases "complete" |
| `provenance_dag.json` | 32B | Empty — no nodes, no edges |
| `output/PB-SIFT-060_*.json` | 447B | Communications: 0 everything |
| `output/PB-SIFT-061_*.json` | 263B | Stego: 0 everything |
| `output/PB-SIFT-062_*.json` | 353B | Keylogger: 0 everything |
| `output/PB-SIFT-063_*.json` | 289B | Chat: 0 everything |

**Missing files:** `findings.jsonl`, `device_map.json`, `execution_plan.json` — these files were expected but do not exist in the case directory.

---

*Audit completed 2026-06-11 18:05 CDT. The 7 CC5 fixes have NOT been validated — this run has a fundamental false positive that the fixes do not address.*
