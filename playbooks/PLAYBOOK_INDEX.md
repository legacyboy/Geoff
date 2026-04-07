# PLAYBOOK_INDEX.md - Threat Hunting Library

This document tracks the specialized playbooks available for Geoff's DFIR operations.

## 🛡️ SIFT Bot Playbooks (Static Image Analysis)

These playbooks provide a deterministic, phase-based methodology for hunting specific threat actor behaviors within a forensic image.

| ID | Name | Focus | Status |
| :--- | :--- | :--- | :--- |
| **PB-SIFT-001** | Malware Hunting | General malware detection, static/dynamic analysis, and REMnux escalation. | ✅ Active |
| **PB-SIFT-002** | Ransomware Indicators | Mass encryption, VSS deletion, ransom notes, and impact assessment. | ✅ Active |
| **PB-SIFT-003** | Lateral Movement | Pivoting, remote execution tools (psexec), and internal network mapping. | ✅ Active |
| **PB-SIFT-004** | Credential Theft | LSASS dumping, NTDS extraction, Kerberoasting, and ticket theft. | ✅ Active |
| **PB-SIFT-005** | Persistence Mechanisms | Registry run keys, WMI subscriptions, COM hijacking, and bootkits. | ✅ Active |
| **PB-SIFT-006** | Exfiltration Indicators | Bulk file access, staging archives, cloud uploads, and network volume analysis. | ✅ Active |
| **PB-SIFT-007** | Living-off-the-Land | Abuse of native binaries (LOLBins) for stealthy execution and reconnaissance. | ✅ Active |
| **PB-SIFT-008** | Initial Access | Entry vectors, phishing, browser/email exploits, and web shell indicators. | ✅ Active |
| **PB-SIFT-009** | Insider Threat | Data hoarding, unauthorized access, personal cloud sync, and departure patterns. | ✅ Active |
| **PB-SIFT-010** | Anti-Forensics | Log clearing, file wiping, timestomping, and defense evasion. | ✅ Active |
| **PB-SIFT-011** | Cloud & SaaS Artifacts | Token theft, cloud sync abuse, M365/Azure activity, and SaaS data exfiltration. | ✅ Active |
| **PB-SIFT-012** | Linux Forensic Indicators | Linux-specific persistence, rootkits, GTFO bins, and container escapes. | ✅ Active |
| **PB-SIFT-013** | macOS Forensic Indicators | macOS-specific persistence, TCC/SIP bypass, Keychain theft, and APFS snapshots. | ✅ Active |
| **PB-SIFT-014** | Network Device Forensics | Network hardware artifacts, config analysis, and rogue device detection. | ⏳ Pending |
| **PB-SIFT-015** | Mobile Device Artifacts | iOS/Android backup analysis, spyware detection, and mobile-host connection artifacts. | ✅ Active |
| **PB-SIFT-016** | Triage Prioritization | Meta-playbook for case intake, evidence scoring, and weighted execution planning. | ✅ Active |
| **PB-SIFT-017** | Cross-Image Correlation | Multi-host analysis to reconstruct attack paths and calculate blast radius. | ✅ Active |

---

## 🚀 Usage Instructions
When starting a new case, Geoff should:
1. Identify the suspected threat type.
2. Load the corresponding `PB-SIFT-XXX` playbook.
3. Execute each phase sequentially, flagging any matches for the final report.
4. Use the "Score & Report" phase to map findings to the MITRE ATT&CK framework.

**Location:** `/home/claw/.openclaw/workspace/playbooks/`
