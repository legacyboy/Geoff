# PB-SIFT-020: Timeline Analysis

## Purpose
Reconstruct temporal event sequences across all evidence sources using Plaso (log2timeline) and SleuthKit (mactime). Identify temporal anomalies, correlate events across artifacts, and produce a unified super timeline for investigation.

## When to Run
- Always included in execution plan when disk images are present
- Runs after all ATTT&CK-kill-chain playbooks complete
- Provides temporal context for all other playbook findings

## Steps

### Step 1: Create Plaso Timeline
- **Tool:** plaso.create_timeline
- **Input:** Each disk image in evidence inventory
- **Output:** `.plaso` storage file per image
- **Success:** Plaso file created, pinfo confirms source count > 0
- **Failure:** Image format unsupported or corrupted → skip, log error

### Step 2: SleuthKit Mactime Body File
- **Tool:** sleuthkit.list_files_mactime
- **Input:** Each disk image with detected partition offset
- **Output:** Body file with MAC timestamps for all files
- **Success:** Non-empty body file produced
- **Failure:** Filesystem unresolvable → skip

### Step 3: Sort and Filter Timeline
- **Tool:** plaso.sort_timeline
- **Input:** Plaso storage files from Step 1
- **Output:** Sorted timeline in JSON-L format
- **Success:** Events sorted chronologically, filter applied if specified
- **Failure:** Storage file empty or corrupted → use mactime body file only

### Step 4: Analyze Timeline Storage
- **Tool:** plaso.analyze_storage
- **Input:** Plaso storage files from Step 1
- **Output:** Parser distribution, source count, date range statistics
- **Success:** Statistics report generated
- **Failure:** No parsers matched → flag for manual review

## Expected Findings
- Temporal clusters of activity (execution spikes, mass file access)
- Events occurring outside business hours or during suspicious windows
- Correlation between filesystem events and log entries
- Anti-forensics indicators (timestomping detected via MAC-B anomaly)

## Cross-References
- PB-SIFT-012 (Anti-Forensics): Timeline anomalies may indicate timestomping
- PB-SIFT-016 (Cross-Image Correlation): Timeline events feed into cross-host analysis
- PB-SIFT-009 (Ransomware): Mass encryption events visible in timeline
