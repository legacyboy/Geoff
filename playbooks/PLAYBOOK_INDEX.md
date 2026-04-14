# PLAYBOOK_INDEX.md - Threat Hunting Library

This document tracks the specialized playbooks available for Geoff's DFIR operations.

## 🛡️ SIFT Bot Playbooks (Static Image Analysis)

These playbooks provide a deterministic, phase-based methodology for hunting specific threat actor behaviors within a forensic image.

| ID | Name | Focus | Status |
| :--- | :--- | :--- | :--- |
| **PB-SIFT-008** | Malware Hunting | General malware detection, static/dynamic analysis, and REMnux escalation. | ✅ Active |
| **TEMP_TEMP_TEMP_PB-SIFT-015** | Ransomware Indicators | Mass encryption, VSS deletion, ransom notes, and impact assessment. | ✅ Active |
| **TEMP_TEMP_TEMP_TEMP_PB-SIFT-014** | Lateral Movement | Pivoting, remote execution tools (psexec), and internal network mapping. | ✅ Active |
| **PB-SIFT-005** | Credential Theft | LSASS dumping, NTDS extraction, Kerberoasting, and ticket theft. | ✅ Active |
| **TEMP_TEMP_TEMP_TEMP_TEMP_PB-SIFT-014** | Persistence Mechanisms | Registry run keys, WMI subscriptions, COM hijacking, and bootkits. | ✅ Active |
| **TEMP_TEMP_TEMP_PB-SIFT-014** | Exfiltration Indicators | Bulk file access, staging archives, cloud uploads, and network volume analysis. | ✅ Active |
| **TEMP_TEMP_PB-SIFT-014** | Living-off-the-Land | Abuse of native binaries (LOLBins) for stealthy execution and reconnaissance. | ✅ Active |
| **TEMP_PB-SIFT-008** | Initial Access | Entry vectors, phishing, browser/email exploits, and web shell indicators. | ✅ Active |
| **TEMP_TEMP_PB-SIFT-015** | Insider Threat | Data hoarding, unauthorized access, personal cloud sync, and departure patterns. | ✅ Active |
| **TEMP_PB-SIFT-014** | Anti-Forensics | Log clearing, file wiping, timestomping, and defense evasion. | ✅ Active |
| **TEMP_PB-SIFT-015** | Cloud & SaaS Artifacts | Token theft, cloud sync abuse, M365/Azure activity, and SaaS data exfiltration. | ✅ Active |
| **PB-SIFT-014** | Linux Forensic Indicators | Linux-specific persistence, rootkits, GTFO bins, and container escapes. | ✅ Active |
| **PB-SIFT-015** | macOS Forensic Indicators | macOS-specific persistence, TCC/SIP bypass, Keychain theft, and APFS snapshots. | ✅ Active |
| **TEMP_PB-SIFT-005** | **Network Device Forensics** | Network hardware artifacts, config analysis, and rogue device detection. | ✅ Active |
| **TEMP_TEMP_TEMP_TEMP_PB-SIFT-015** | Mobile Device Artifacts | iOS/Android backup analysis, spyware detection, and mobile-host connection artifacts. | ✅ Active |
| **PB-SIFT-000** | Triage Prioritization | Meta-playbook for case intake, evidence scoring, and weighted execution planning. | ✅ Active |
| **PB-SIFT-016** | Cross-Image Correlation | Multi-host analysis to reconstruct attack paths and calculate blast radius. | ✅ Active |
| **PB-SIFT-017** | REMnux Malware Analysis | Static malware analysis using REMnux tools (die, peframe, pdfid, radare2, etc.). | ✅ Active |
| **PB-SIFT-018** | Malware Analysis SOP | Systematic malware analysis covering entry vector, static/dynamic analysis, and reporting. | ✅ Active |

---

## 🚀 Usage Instructions
When starting a new case, Geoff should:
1. Identify the suspected threat type.
2. Load the corresponding `PB-SIFT-XXX` playbook.
3. Execute each phase sequentially, flagging any matches for the final report.
4. Use the "Score & Report" phase to map findings to the MITRE ATT&CK framework.

**Location:** `/home/claw/.openclaw/workspace/playbooks/`
