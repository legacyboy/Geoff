# Geoff DFIR — Dataset Documentation

This document covers the four evidence datasets used to validate Geoff during development.
Three are from the NIST Computer Forensics Reference Data Sets (CFReDS) program; one is a
multi-device enterprise APT scenario assembled for the competition.

---

## 1. APT 2015

### Overview

| Field | Value |
|-------|-------|
| **Name** | APT 2015 |
| **Type** | Multi-device Windows enterprise incident |
| **Devices** | 4 hosts (10 disk images, 4 memory images, 3 network captures) |
| **Size** | ~90 GB |
| **Location** | `/mnt/evidence/APT 2015/` |
| **Format** | Raw disk images (c-drive directories), ZIP archives of network captures, memory dumps |

### Devices

| Hostname | Role | Files |
|----------|------|-------|
| `win2008R2-controller` | Domain controller (10.3.58.4) | c-drive, memory, network .zip |
| `win7-32-nromanoff` | User workstation (10.3.58.5) | c-drive, memory, network .zip |
| `win7-64-nfury` | User workstation (10.3.58.6) | c-drive, memory, network .zip |
| `xp-tdungan` | Legacy workstation (10.3.58.x) | c-drive, memory |

### What Geoff Found

Run completed 2026-05-23 (case directory: `/mnt/evidence-storage-2/APT_2015_findevil_50b1869b6a6a`).

- **Evil found:** YES
- **Classification:** Anti-Forensics, C2, Credential Theft, Exfiltration, Lateral Movement, LOLBin, OT/ICS Attack
- **Severity:** CRITICAL
- **Playbooks run:** 23 unique playbooks, 264 specialist steps (246 completed, 15 failed, 3 skipped)
- **MITRE techniques observed:** T1053, T1547, T1543, T1542, T0855, T0816, T0879, T1218, T1059, T1566, T1534, T1003, T1558, T1552, T1021, T1570, T1563, T1071, T1095, T1573

Key findings from the investigation:
- Persistence via scheduled tasks (T1053) and service installations (T1543) across multiple hosts
- Credential access events consistent with LSASS memory reads (T1003)
- Lateral movement via WMI/RPC (T1021) between controller and workstations
- Command-and-control traffic detected in network captures (T1071)
- OT/ICS-targeted behavior detected (T0855, T0816, T0879) — consistent with industrial control system targeting
- Anti-forensics indicator cascade triggered (findings retroactively downgraded from CONFIRMED to POSSIBLE)

**Narrative report:** `/mnt/evidence-storage-2/APT_2015_findevil_50b1869b6a6a/reports/narrative_report.md`

### Chain of Custody

Assembled locally for competition development. Not a public NIST dataset. Evidence was not
modified during analysis; custody sidecars at each step verify SHA-256 integrity.

---

## 2. M57-JEAN-REAL (NIST CFReDS)

### Overview

| Field | Value |
|-------|-------|
| **Name** | M57-Jean (NPS image pair) |
| **Source** | NIST Computer Forensics Reference Data Sets — search "M57-Jean" at https://cfreds.nist.gov/ |
| **Type** | Windows XP workstation — employee data exfiltration scenario |
| **Devices** | 1 device (1 disk image in 2 EnCase segments: E01 + E02) |
| **Size** | 2.9 GB |
| **Location** | `/mnt/evidence/jeanm57/` |
| **Format** | EnCase EWF (nps-2008-jean.E01, nps-2008-jean.E02) |
| **Owner** | "Kim" (username extracted from NTUSER.DAT) |

### Source Verification

The M57-Jean dataset is published by NIST as a reference dataset for forensic tool testing.
Download from: https://cfreds.nist.gov/all/NIST/m57-jean

The image was originally produced during the M57-Patents legal case study (2008) at Naval
Postgraduate School. It is public domain.

### What Geoff Found

A re-run was completed 2026-06-01 under the current codebase (case directory:
`$GEOFF_CASES_PATH/jeanm57_findevil_b18c1b0201fa/`).

- **Playbooks run:** PB-SIFT-001, PB-SIFT-002, PB-SIFT-003, PB-SIFT-004, PB-SIFT-005, PB-SIFT-009, PB-SIFT-010, PB-SIFT-012
- **Findings:** 49 findings across 24 completed steps
- **Self-corrections:** 2 (PB-SIFT-010: tool fallback chain; PB-SIFT-016: device discovery)
- **Anti-forensics cascade:** triggered (PB-SIFT-012 detected indicators; findings downgraded)
- **File system:** ~30,967 files indexed across E01/E02

### Chain of Custody

NIST CFReDS public domain data. SHA-256 custody sidecars for 14 completed steps are
in `$GEOFF_CASES_PATH/jeanm57_findevil_b18c1b0201fa/custody/`.

*Note: Full forensic conclusions from this run are not published here — the M57-Patents case involves real persons and the investigation data is for tool validation only.*

---

## 3. NIST CFReDS — Data Leakage Case

### Overview

| Field | Value |
|-------|-------|
| **Name** | CFReDS Data Leakage Case (2015) |
| **Source** | NIST Computer Forensics Reference Data Sets — search "Data Leakage Case" at https://cfreds.nist.gov/ |
| **Type** | Windows 7 enterprise — data exfiltration + removable media |
| **Devices** | 3 hosts (1 PC + 2 removable media) |
| **Size** | 7.1 GB |
| **Location** | `/mnt/evidence/data-leakage-case/` |
| **Format** | EnCase EWF (cfreds_2015_data_leakage_pc.E01–E04; cfreds_2015_data_leakage_rm#1.E01, rm#2) |

### Source Verification

Published by NIST as a reference dataset. Direct download: https://cfreds.nist.gov/all/NIST/DataLeakageCase

### What Geoff Found

Run completed under the current codebase (case directory:
`$GEOFF_CASES_PATH/data-leakage-case_findevil_b8a61d16ff70/`).

- **Playbooks run:** PB-SIFT-001, PB-SIFT-002, PB-SIFT-003, PB-SIFT-004, PB-SIFT-005, PB-SIFT-008
- **Devices:** `cfreds_2015_data_leakage_pc`, `cfreds_2015_data_leakage_rm#1`, `cfreds_2015_data_leakage_rm#2`
- **Findings:** 258 findings (32 completed, 1 failed, 1 skipped)
- **Self-corrections:** 0 (clean run — EWF images well-formed, no offset issues)

### Chain of Custody

NIST CFReDS public domain data. Custody sidecars are generated per-step;
see `$GEOFF_CASES_PATH/data-leakage-case_findevil_b8a61d16ff70/custody/`.

*Note: The evidence directory hash differs between runs due to path normalization; use `$GEOFF_CASES_PATH` to locate the correct case directory.*

---

## 4. NIST CFReDS — Hacking Case

### Overview

| Field | Value |
|-------|-------|
| **Name** | CFReDS Hacking Case (Dell Latitude CPi) |
| **Source** | NIST Computer Forensics Reference Data Sets — search "Hacking Case" at https://cfreds.nist.gov/ |
| **Type** | Windows 98 workstation — web server intrusion investigation |
| **Devices** | 1 host (1 disk image + 1 log file) |
| **Size** | 101 MB |
| **Location** | `/mnt/evidence/hacking-case/` |
| **Format** | EnCase EWF (4Dell_Latitude_CPi.E01) + SCHARDT.LOG |

### Source Verification

Published by NIST as a reference dataset. Direct download: https://cfreds.nist.gov/all/NIST/HackingCase

### What Geoff Found

Run completed (case directory: `$GEOFF_CASES_PATH/hacking-case_findevil_8a867556e937/`).

- **Playbooks run:** PB-SIFT-002, PB-SIFT-003, PB-SIFT-004, PB-SIFT-008, PB-SIFT-012, PB-SIFT-017, PB-SIFT-018, PB-SIFT-019
- **Device:** `SCHARDT` (hostname extracted from disk)
- **Findings:** 15 completed, 14 failed, 1 self-correction (PB-SIFT-019: C2 detection)
- **Anti-forensics cascade:** triggered

The high failure rate (14/29 steps failed) reflects that this is a Windows 98 FAT16 image —
many playbook steps that target NTFS artifacts (MFT, Registry hives at modern paths, VSS
mounts) return `not applicable` or fail gracefully. The Healer handled one C2 detection
failure via self-correction (PB-SIFT-019 module fallback). The 15 completed steps cover
file system triage, log analysis (SCHARDT.LOG), and malware artifact detection.

### Chain of Custody

NIST CFReDS public domain data. The custody sidecar mechanism was added after this
early run; re-running with the current code will produce SHA-256 custody records
at `$GEOFF_CASES_PATH/<case_dir>/custody/`.

---

## Dataset Summary

| Dataset | Type | Size | Runs | Evil Found | MITRE Techniques |
|---------|------|------|------|------------|-----------------|
| APT 2015 | Multi-device enterprise | ~90 GB | 1 | YES (CRITICAL) | 20+ techniques |
| M57-Jean-Real | Windows XP workstation | 2.9 GB | 1 | PENDING REVIEW | N/A |
| Data Leakage Case | Windows 7 + removable | 7.1 GB | 1 | PENDING REVIEW | N/A |
| Hacking Case | Windows 98 workstation | 101 MB | 1 | PENDING REVIEW | N/A |

*"PENDING REVIEW" indicates the run completed but the Manager did not generate a narrative report — likely due to insufficient LLM-driven Forensicator observations in early-version runs. Re-running with current code will produce full reports.*
