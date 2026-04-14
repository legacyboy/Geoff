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

---

## 🚀 Usage Instructions
When starting a new case, Geoff must:
1. **Always run PB-SIFT-000 first.** No exceptions.
2. PB-SIFT-000 emits a JSON execution plan specifying which playbooks to run and in what order.
3. Execute only the playbooks listed in the `execution_plan` array, in order.
4. Do not run any playbook not in the execution plan.
5. PB-SIFT-016 must always be the last entry if more than one host is in scope.
6. PB-SIFT-017 and PB-SIFT-018 are only included if a suspicious binary is surfaced during triage.

**Location:** `/opt/geoff/playbooks/`