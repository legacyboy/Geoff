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
| **PB-SIFT-004** | Privilege Escalation | Token impersonation, UAC bypass registry hijack, DLL hijacking, unquoted service paths, Linux SUID/sudo/capabilities abuse. EID 4672/4673/4703. | ✅ Active |
| **PB-SIFT-005** | Credential Theft | LSASS dumping, NTDS extraction, Kerberoasting, and ticket theft. | ✅ Active |
| **PB-SIFT-006** | Lateral Movement | Pivoting, remote execution tools (psexec), and internal network mapping. | ✅ Active |
| **PB-SIFT-007** | Exfiltration | Bulk file access, staging archives, cloud uploads, and network volume analysis. | ✅ Active |
| **PB-SIFT-008** | Malware Hunting | General malware detection, static/dynamic analysis, and REMnux escalation. | ✅ Active |
| **PB-SIFT-009** | Ransomware | Mass encryption, VSS deletion, ransom notes, and impact assessment. | ✅ Active |
| **PB-SIFT-010** | Living-off-the-Land | Abuse of native binaries (LOLBins) for stealthy execution and reconnaissance. | ✅ Active |
| **PB-SIFT-011** | Web Shell | Web shell detection via IIS/Apache/nginx log analysis, web root filesystem scan, signature strings (eval/base64_decode/cmd.exe), w3wp→cmd parent chain detection. | ✅ Active |
| **PB-SIFT-012** | Anti-Forensics | Log clearing, file wiping, timestomping, and defense evasion. Includes confidence downgrade directive. | ✅ Active |
| **PB-SIFT-013** | Insider Threat | HR-correlated behavioral analysis: off-hours bulk file access, USB staging, SRUM upload volume, print spool, UserAssist/SearchIndex, Outlook forwarding rules, EID 1102 sabotage. | ✅ Active |
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
| **PB-SIFT-025** | Cloud/Enterprise IR | M365 Unified Audit Log, Azure AD sign-in logs, OAuth app abuse, Exchange forwarding rules, SharePoint/OneDrive bulk download, AWS CloudTrail. Runs when cloud artifacts detected. | ✅ Active |
| **PB-SIFT-034** | Network Device Forensics | Router/switch/firewall config tampering, Cisco/Junos/PAN-OS/FortiGate log analysis, firmware integrity, ARP/MAC/VLAN analysis, SNMP abuse, BGP route injection. Runs when network device evidence present. | ✅ Active |
| **PB-SIFT-035** | Active Directory / DC Forensics | DCSync (EID 4662), Golden/Silver Ticket (EID 4768/4769 encryption type analysis), Kerberoasting, AS-REP Roasting, domain persistence (AdminSDHolder, DCShadow, skeleton key), GPO abuse, PtH/PtT detection. Runs when domain controller is in scope. | ✅ Active |
| **PB-SIFT-036** | PCAP & Network Forensics | Full packet capture analysis: protocol distribution, DNS tunneling, TLS JA3/JA3S fingerprinting, C2 beacon timing, data exfiltration volume, SMB lateral movement, Zeek log analysis, NetFlow. Runs when PCAP files are in evidence. | ✅ Active |
| **PB-SIFT-037** | IoT Device Forensics | Consumer IoT device analysis: smart home hubs, cameras, voice assistants (Arlo, Echo, SmartThings, Wink), firmware images, and companion app configs. Runs when IoT artifacts are detected. | ✅ Active |

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
13. PB-SIFT-025 is included when cloud-based evidence is detected: UAL exports, Azure AD logs, CloudTrail JSON, or M365 PST/OST files from cloud-joined machines.
14. PB-SIFT-034 is included when network device evidence is present: router/switch config exports, TACACS+ logs, firmware images, or Palo Alto/Fortinet/Cisco log bundles.
15. PB-SIFT-035 is included when a domain controller is in scope: NTDS.dit, DC event logs, SYSVOL forensics, or AD database files.
16. PB-SIFT-036 is included when PCAP files or Zeek log directories are in the evidence inventory.
17. PB-SIFT-037 is included when IoT device evidence is detected: smart home hub images, camera config dumps, IoT firmware files, companion app databases, or directories named after IoT devices (arlo, echo, smartthings, wink).

**Location:** `playbooks/` (relative to project root)