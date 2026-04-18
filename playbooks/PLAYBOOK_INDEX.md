# PLAYBOOK_INDEX.md - Threat Hunting Library

> **PB-SIFT-000 is the mandatory entry point for all cases.** Geoff must not run any other playbook until PB-SIFT-000 has completed and emitted its execution plan. The execution plan determines which playbooks to run, in what order, and which to skip.

This document tracks the specialized playbooks available for Geoff's DFIR operations.

## 🛡️ SIFT Bot Playbooks (Static Image Analysis)

Playbooks are numbered following the MITRE ATT&CK kill chain order.

| ID | Name | Focus | Status |
| :--- | :--- | :--- | :--- |
| **PB-SIFT-000** | **Triage & Execution Planning** | **Mandatory entry point. Case intake, evidence scoring, and execution plan generation.** | ✅ Active |
| **PB-SIFT-001** | Initial Access | Entry vectors, phishing, browser/email exploits, and web shell indicators. | ✅ Active |
| **PB-SIFT-002** | Execution | Process execution, LOLBins, scripting engines, and scheduled tasks. | ✅ Active |
| **PB-SIFT-003** | Persistence | Registry run keys, WMI subscriptions, COM hijacking, and bootkits. | ✅ Active |
| **PB-SIFT-004** | Privilege Escalation | Token manipulation, UAC bypass, SUID exploitation, and credential escalation. | ✅ Active |
| **PB-SIFT-005** | Credential Theft | LSASS dumping, NTDS extraction, Kerberoasting, and ticket theft. | ✅ Active |
| **PB-SIFT-006** | Lateral Movement | Pivoting, remote execution tools (psexec), and internal network mapping. | ✅ Active |
| **PB-SIFT-007** | Exfiltration | Bulk file access, staging archives, cloud uploads, and network volume analysis. | ✅ Active |
| **PB-SIFT-008** | Malware Hunting | General malware detection, static/dynamic analysis, and REMnux escalation. | ✅ Active |
| **PB-SIFT-009** | Ransomware | Mass encryption, VSS deletion, ransom notes, and impact assessment. | ✅ Active |
| **PB-SIFT-010** | Living-off-the-Land | Abuse of native binaries (LOLBins) for stealthy execution and reconnaissance. | ✅ Active |
| **PB-SIFT-011** | Web Shell | Web shell detection, web server compromise, and exploitation indicators. | ✅ Active |
| **PB-SIFT-012** | Anti-Forensics | Log clearing, file wiping, timestomping, and defense evasion. Includes confidence downgrade directive. | ✅ Active |
| **PB-SIFT-013** | Insider Threat | Data hoarding, unauthorized access, personal cloud sync, and departure patterns. | ✅ Active |
| **PB-SIFT-014** | Linux Forensics | Linux-specific persistence, rootkits, GTFO bins, and container escapes. | ✅ Active |
| **PB-SIFT-015** | Data Staging | Staged data collection, compression, and pre-exfiltration artifact analysis. | ✅ Active |
| **PB-SIFT-016** | Cross-Image Correlation | Multi-host analysis to reconstruct attack paths and calculate blast radius. Always runs last if multiple hosts. | ✅ Active |
| **PB-SIFT-017** | REMnux Malware Analysis | Static malware analysis using REMnux tools (die, peframe, pdfid, radare2, etc.). Only runs if suspicious binary surfaced. | ✅ Active |
| **PB-SIFT-018** | Malware Analysis SOP | Systematic malware analysis covering entry vector, static/dynamic analysis, and reporting. Only runs if suspicious binary surfaced. | ✅ Active |
| **PB-SIFT-019** | Command & Control | C2 infrastructure, beaconing, DNS tunneling, and persistent C2 channels. Runs when C2 indicators found in triage. | ✅ Active |
| **PB-SIFT-020** | Timeline Analysis | Temporal event reconstruction using Plaso and SleuthKit mactime. Always runs when disk images present. | ✅ Active |
| **PB-SIFT-021** | Mobile Analysis | iOS backup and Android data analysis: SMS, call logs, apps, browser history, GPS, sideloaded APKs. | ✅ Active |
| **PB-SIFT-022** | Browser Forensics | Chrome/Firefox SQLite: history, downloads, cookies, saved credential origins. Always runs. | ✅ Active |
| **PB-SIFT-023** | Email Forensics | PST/OST (readpst), mbox, EML: headers, attachments, forwarding rules, BEC patterns. | ✅ Active |
| **PB-SIFT-024** | macOS Forensics | Launch agents/daemons, Unified Log, FSEvents, plist parsing. Runs when macOS detected. | ✅ Active |

---
When starting a new case, Geoff must:
1. **Always run PB-SIFT-000 first.** No exceptions.
2. PB-SIFT-000 emits a JSON execution plan specifying which playbooks to run and in what order.
3. Execute only the playbooks listed in the `execution_plan` array, in order.
4. Do not run any playbook not in the execution plan.
5. PB-SIFT-016 must always be the last entry if more than one host is in scope.
6. PB-SIFT-017 and PB-SIFT-018 are only included if a suspicious binary is surfaced during triage.
7. PB-SIFT-019 is included when C2 indicators are found during triage.
8. PB-SIFT-020 is always included when disk images are present in the evidence inventory.
9. PB-SIFT-021 is included when mobile backup files are detected.
10. PB-SIFT-022 is always included (browser databases analysed if found).
11. PB-SIFT-023 is included when PST, OST, mbox, or EML files are present.
12. PB-SIFT-024 is included when macOS is detected as the OS.

**Location:** `playbooks/` (relative to project root)