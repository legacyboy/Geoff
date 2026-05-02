# Geoff Playbook Coverage Matrix

**Purpose:** Map Geoff's 33 playbooks against SANS/industry-standard DFIR artifact categories to identify gaps and validate completeness.

**Sources:** SANS FOR500 (Windows Forensics), FOR508 (Advanced IR), FOR532 (Memory Forensics), windowsforensics.net, NIST SP 800-86, RootGuard Windows Forensic Artifacts cheatsheet.

---

## Artifact Categories vs. Playbooks

### Legend
- ✅ = Primary coverage (playbook's main focus)
- ◐ = Partial coverage (addressed as secondary/phase within playbook)
- ○ = Mentioned but not deeply analyzed
- — = Not covered

---

### 1. FILE SYSTEM ARTIFACTS

| Artifact Category | SANS Priority | PB-000 | PB-001 | PB-002 | PB-003 | PB-009 | PB-012 | PB-014 | PB-015 | PB-020 | PB-026 | PB-028 | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **$MFT Analysis** | ★★★★★ | ◐ | ○ | ◐ | ○ | ✅ | ○ | ◐ | ◐ | ✅ | ◐ | ✅ | Timeline cornerstone (PB-020) |
| **USN Journal ($J)** | ★★★★★ | — | — | ◐ | — | ✅ | — | ◐ | ◐ | ✅ | — | ✅ | File change tracking |
| **$LogFile** | ★★★★ | — | — | — | — | ○ | — | ○ | ○ | ✅ | — | ○ | NTFS transactions |
| **Prefetch** | ★★★★★ | ◐ | ◐ | ✅ | ✅ | ✅ | ◐ | ○ | ○ | ✅ | — | ✅ | Execution proof (PB-002, PB-003) |
| **Amcache.hve** | ★★★★★ | — | ○ | ✅ | ✅ | ✅ | — | — | — | ✅ | — | ✅ | SHA1 hashes, program presence |
| **ShimCache/AppCompat** | ★★★ | — | ○ | ✅ | ✅ | ○ | — | — | — | ✅ | — | ✅ | Historical program presence |
| **LNK Files** | ★★★★ | — | ○ | ◐ | — | ○ | — | ○ | ✅ | ✅ | — | ✅ | File access tracking |
| **Jump Lists** | ★★★★ | — | ○ | ◐ | — | ○ | — | ○ | ✅ | ✅ | — | ✅ | Application usage |
| **ShellBags** | ★★★★ | — | ○ | — | — | ○ | — | — | ✅ | ✅ | — | ✅ | Folder navigation |
| **Recycle Bin** | ★★★ | — | — | — | — | ○ | ✅ | ○ | ○ | ✅ | ✅ | ◐ | Deleted files (PB-026, PB-012) |
| **ADS (Alternate Data Streams)** | ★★★ | — | — | — | — | ○ | ✅ | — | — | — | ◐ | ○ | Hidden data |
| **VSS (Volume Shadow Copies)** | ★★★★ | — | — | — | — | ✅ | — | — | — | ✅ | ✅ | ◐ | Historical depth |
| **File Carving** | ★★★★ | — | — | — | — | — | ✅ | — | — | — | ✅ | — | Deleted file recovery (PB-026) |

### 2. REGISTRY ARTIFACTS

| Artifact Category | SANS Priority | PB-003 | PB-004 | PB-005 | PB-009 | PB-010 | PB-028 | Notes |
|---|---|---|---|---|---|---|---|---|
| **SYSTEM hive** | ★★★★★ | ✅ | ✅ | ○ | ✅ | ○ | ✅ | ShimCache, services, USB |
| **SOFTWARE hive** | ★★★★ | ✅ | ✅ | ○ | ○ | ○ | ✅ | Installed programs, run keys |
| **NTUSER.DAT** | ★★★★★ | ✅ | ◐ | ✅ | ○ | ✅ | ✅ | UserAssist, ShellBags, MRUs |
| **USRCLASS.DAT** | ★★★★ | ○ | ○ | ○ | ○ | ○ | ✅ | ShellBags, ActiveX |
| **Amcache.hve** | ★★★★★ | ○ | ○ | ○ | ✅ | ○ | ✅ | Program hashes |
| **SAM hive** | ★★★ | — | ✅ | ✅ | — | — | ○ | User/group info |
| **AutoStart/ASEP** | ★★★★★ | ✅ | ✅ | — | ✅ | ✅ | ✅ | Persistence (PB-003, PB-010) |
| **USB history** | ★★★★ | ○ | — | — | — | ○ | ✅ | Device tracking |
| **Scheduled Tasks** | ★★★★ | ✅ | ✅ | — | ✅ | ✅ | ✅ | Persistence + execution |
| **Services** | ★★★★ | ✅ | ✅ | — | ✅ | ✅ | ✅ | Persistence + privilege |

### 3. EVENT LOG ARTIFACTS

| Artifact Category | SANS Priority | PB-001 | PB-002 | PB-003 | PB-006 | PB-007 | PB-009 | PB-019 | PB-028 | Notes |
|---|---|---|---|---|---|---|---|---|---|---|
| **Security.evtx (4624/4625/4648/4672)** | ★★★★★ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | Logons, privilege use |
| **System.evtx** | ★★★★ | ○ | ◐ | ✅ | ○ | — | ✅ | ○ | ✅ | Service creation, drivers |
| **Application.evtx** | ★★★ | — | ◐ | — | — | — | ○ | — | ○ | Application crashes |
| **PowerShell logs** | ★★★★★ | — | ✅ | ✅ | ◐ | — | ✅ | ✅ | ✅ | Script block logging (4104) |
| **Sysmon logs** | ★★★★★ | ◐ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | Process creation (EID 1) |
| **Task Scheduler logs** | ★★★★ | — | ○ | ✅ | — | — | ✅ | ○ | ✅ | Scheduled task creation |
| **RDP logs** | ★★★★ | ✅ | — | — | ✅ | — | ○ | — | ✅ | Terminal Services |
| **WMI logs** | ★★★ | — | ◐ | ✅ | — | — | ○ | ✅ | ○ | WMI persistence |
| **Log clearing (1102/104)** | ★★★★★ | — | — | — | — | — | ✅ | — | — | Anti-forensics indicator |

### 4. BROWSER & WEB ARTIFACTS

| Artifact Category | SANS Priority | PB-001 | PB-007 | PB-011 | PB-013 | PB-022 | PB-030 | Notes |
|---|---|---|---|---|---|---|---|---|
| **Browser history** | ★★★★★ | ◐ | ✅ | ◐ | ✅ | ✅ | ◐ | Primary browser playbook |
| **Browser cookies** | ★★★ | — | ◐ | — | ◐ | ✅ | ◐ | Session tracking |
| **Browser cache** | ★★★★ | ◐ | ◐ | ✅ | ○ | ✅ | ◐ | Web shell artifacts |
| **Saved passwords** | ★★★★★ | — | ✅ | — | ✅ | ✅ | ◐ | Credential theft |
| **Downloads history** | ★★★★ | ◐ | ✅ | ✅ | ○ | ✅ | ◐ | Initial access + exfil |
| **Autofill/form data** | ★★ | — | — | — | ✅ | ◐ | — | Insider threat |
| **Search queries** | ★★★ | — | ◐ | — | ✅ | ✅ | — | User intent |

### 5. EMAIL & COMMUNICATION ARTIFACTS

| Artifact Category | SANS Priority | PB-001 | PB-007 | PB-013 | PB-023 | PB-031 | Notes |
|---|---|---|---|---|---|---|---|
| **PST/OST files** | ★★★★★ | ✅ | ✅ | ✅ | ✅ | ◐ | Outlook archives |
| **Email headers** | ★★★★★ | ◐ | — | ◐ | ✅ | ◐ | Phishing analysis |
| **Attachments** | ★★★★★ | ✅ | ✅ | ✅ | ✅ | ✅ | Malware delivery |
| **Thunderbird mbox** | ★★★★ | ○ | — | ○ | ✅ | ◐ | Linux/macOS email |
| **Mail.app (macOS)** | ★★★★ | — | — | — | — | ✅ | macOS Mail |
| **Chat/collaboration** | ★★★★ | ○ | ○ | ◐ | — | ✅ | Slack, Teams, etc. (PB-031) |

### 6. MEMORY FORENSICS

| Artifact Category | SANS Priority | PB-002 | PB-005 | PB-008 | PB-009 | PB-019 | PB-027 | Notes |
|---|---|---|---|---|---|---|---|---|
| **Process listing** | ★★★★★ | ✅ | ◐ | ✅ | ✅ | ✅ | ✅ | Primary memory artifact |
| **Network connections** | ★★★★★ | ◐ | ○ | ◐ | ✅ | ✅ | ✅ | C2 + exfil detection |
| **DLL listing** | ★★★★ | ◐ | ○ | ✅ | ✅ | ◐ | ✅ | Injection detection |
| **Handles/objects** | ★★★ | — | — | ◐ | — | — | ✅ | Handle analysis |
| **Registry hives in memory** | ★★★★ | — | — | — | — | — | ✅ | Live registry |
| **Strings search** | ★★★★ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | IOC extraction |
| **Malware detection** | ★★★★★ | ◐ | ◐ | ✅ | ✅ | ✅ | ✅ | Process injection, hooks |
| **Password dump detection** | ★★★★★ | — | ✅ | ◐ | ○ | ◐ | ✅ | Mimikatz detection |

### 7. EXECUTION & PERSISTENCE ARTIFACTS

| Artifact Category | SANS Priority | PB-002 | PB-003 | PB-004 | PB-010 | PB-028 | Notes |
|---|---|---|---|---|---|---|---|
| **Prefetch** | ★★★★★ | ✅ | ✅ | ◐ | ◐ | ✅ | Most valuable execution artifact |
| **UserAssist** | ★★★★ | ✅ | ◐ | — | ◐ | ✅ | GUI program execution |
| **ShimCache** | ★★★ | ◐ | ✅ | — | ○ | ✅ | Program presence (not execution on Win10+) |
| **Amcache** | ★★★★★ | ◐ | ✅ | ○ | ○ | ✅ | SHA1 hashes |
| **Scheduled Tasks** | ★★★★ | ◐ | ✅ | ✅ | ✅ | ✅ | Persistence + execution |
| **Services** | ★★★★ | ○ | ✅ | ✅ | ✅ | ✅ | Persistence + privilege |
| **WMI subscriptions** | ★★★ | ○ | ✅ | ○ | ✅ | ◐ | Fileless persistence |
| **PowerShell history** | ★★★★★ | ✅ | ◐ | ◐ | ✅ | ✅ | Command-line forensics |
| **LOLBins** | ★★★★ | ✅ | ◐ | ◐ | ✅ | ◐ | Living-off-the-Land |
| **MRU lists** | ★★★ | ◐ | ○ | — | ◐ | ✅ | Recent file/directory access |

### 8. NETWORK & C2 ARTIFACTS

| Artifact Category | SANS Priority | PB-006 | PB-007 | PB-019 | Notes |
|---|---|---|---|---|---|
| **Active connections** | ★★★★★ | ✅ | ◐ | ✅ | Netstat, established sessions |
| **Listening ports** | ★★★★★ | ✅ | ◐ | ✅ | Backdoor detection |
| **DNS cache/queries** | ★★★★ | ◐ | ◐ | ✅ | C2 domain resolution |
| **Firewall logs** | ★★★★ | ✅ | ◐ | ✅ | Connection filtering |
| **Proxy logs** | ★★★★ | ◐ | ✅ | ✅ | Web proxy C2 |
| **PCAP/network captures** | ★★★★★ | ✅ | ✅ | ✅ | Full network forensics |
| **Hosts file** | ★★★ | ◐ | — | ✅ | DNS hijacking |
| **ARP cache** | ★★★ | ✅ | — | ◐ | ARP spoofing detection |

### 9. ANTI-FORENSICS & DEFENSE EVASION

| Artifact Category | SANS Priority | PB-009 | PB-012 | Notes |
|---|---|---|---|---|
| **Log clearing** | ★★★★★ | ✅ | ✅ | Event log deletion (EID 1102/104) |
| **Timestamp manipulation** | ★★★★ | ◐ | ✅ | Timestomping detection |
| **File wiping** | ★★★★ | ◐ | ✅ | Secure deletion tools |
| **Encryption/wiping tools** | ★★★★ | ✅ | ✅ | Ransomware + anti-forensics |
| **Process hiding** | ★★★★ | ✅ | ✅ | Rootkit detection |
| **Privacy cleaners** | ★★★ | ◐ | ✅ | CCleaner, BleachBit |
| **Disk wiping** | ★★★★ | ◐ | ✅ | Full disk wipe detection |

### 10. CROSS-PLATFORM ARTIFACTS

| Artifact Category | SANS Priority | PB-014 | PB-024 | PB-021 | PB-030 | PB-031 | PB-032 | PB-033 | Notes |
|---|---|---|---|---|---|---|---|---|---|
| **Linux syslogs** | ★★★★★ | ✅ | — | — | — | — | — | — | /var/log/* |
| **Linux auth logs** | ★★★★★ | ✅ | — | — | — | — | — | — | SSH, sudo |
| **Linux bash history** | ★★★★ | ✅ | — | — | — | — | — | — | Command history |
| **Linux cron** | ★★★★ | ✅ | — | — | — | — | — | — | Scheduled tasks |
| **macOS unified logs** | ★★★★★ | — | ✅ | — | — | — | — | — | macOS primary log |
| **macOS plist** | ★★★★ | — | ✅ | — | — | — | — | — | Preferences, config |
| **macOS quarantine** | ★★★★ | — | ✅ | — | — | — | — | — | Download tracking |
| **Mobile device databases** | ★★★★ | — | — | ✅ | — | — | — | — | SQLite extraction |
| **Cloud sync metadata** | ★★★★ | — | — | — | ✅ | — | — | — | GDrive, OneDrive, iCloud |
| **Collaboration platforms** | ★★★★ | — | — | — | — | ✅ | — | — | Slack, Teams, Discord |
| **VM snapshots** | ★★★★ | — | — | — | — | — | ✅ | — | VMEM, VMSN analysis |
| **Container layers** | ★★★★ | — | — | — | — | — | — | ✅ | Docker overlay2, logs |

---

## Coverage Summary by Playbook

| Playbook | Primary Artifact Categories | SANS Alignment |
|---|---|---|
| **PB-000 Triage** | Triage, evidence identification | ✅ Aligns with SANS triage methodology |
| **PB-001 Initial Access** | Email, browser, RDP, web shells | ✅ Covers FOR500 access vectors |
| **PB-002 Execution** | Prefetch, UserAssist, PowerShell, LOLBins | ✅ Covers FOR500 execution artifacts |
| **PB-003 Persistence** | Registry ASEPs, scheduled tasks, services, WMI | ✅ Covers FOR500 persistence |
| **PB-004 Privilege Escalation** | Registry, services, SAM | ✅ Covers FOR508 privilege escalation |
| **PB-005 Credential Theft** | Memory (mimikatz), SAM, saved passwords | ✅ Covers FOR508 credential attacks |
| **PB-006 Lateral Movement** | Network, RDP, SMB, PsExec | ✅ Covers FOR508 lateral movement |
| **PB-007 Exfiltration** | Browser, email, DNS, network | ✅ Covers FOR508 exfiltration |
| **PB-008 Malware Hunting** | File system, memory, strings, IOCs | ✅ Covers FOR508 malware analysis |
| **PB-009 Ransomware** | File system, VSS, MFT, event logs | ✅ Covers FOR500 ransomware indicators |
| **PB-010 LOTL** | PowerShell, WMI, cmd.exe, LOLBins | ✅ Covers FOR508 living-off-the-land |
| **PB-011 Web Shells** | Browser cache, IIS logs, web directories | ✅ Covers FOR500 web shell indicators |
| **PB-012 Anti-Forensics** | Log clearing, timestomping, wiping | ✅ Covers FOR500 anti-forensics |
| **PB-013 Insider Threat** | Browser, email, USB, user activity | ✅ Covers FOR500 insider indicators |
| **PB-014 Linux Forensics** | syslogs, auth, bash history, cron | ✅ Covers Linux DFIR methodology |
| **PB-015 Data Staging** | $J, $MFT, ShellBags, LNK | ✅ Covers FOR508 staging indicators |
| **PB-016 Cross-Image** | Cross-correlation across images | ✅ Covers FOR508 multi-system analysis |
| **PB-017 REMnux** | Malware static analysis, deobfuscation | ✅ Covers FOR610 malware analysis |
| **PB-018 Malware Analysis** | Strings, PE headers, IOCs | ✅ Covers FOR610 malware analysis |
| **PB-019 C2** | Network, DNS, process, connections | ✅ Covers FOR508 C2 detection |
| **PB-020 Timeline** | Super timeline across all sources | ✅ Covers SANS timeline methodology |
| **PB-021 Mobile** | Device databases, app data | ◐ Mobile forensics is specialist area |
| **PB-022 Browser** | History, cookies, cache, passwords | ✅ Covers FOR500 browser forensics |
| **PB-023 Email** | PST/OST, headers, attachments | ✅ Covers FOR500 email forensics |
| **PB-024 macOS** | Unified logs, plist, quarantine | ✅ Covers SANS macOS forensics |
| **PB-026 File Carving** | Unallocated space, deleted files | ✅ Covers FOR500 file recovery |
| **PB-027 Memory** | Processes, network, DLLs, strings | ✅ Covers FOR532 memory forensics |
| **PB-028 Windows Modern** | Prefetch, Amcache, ShimCache, UserAssist | ✅ Covers FOR500 Win10/11 artifacts |
| **PB-029 Encrypted** | BitLocker, LUKS, VeraCrypt | ✅ Covers encryption detection |
| **PB-030 Cloud Sync** | GDrive, OneDrive, iCloud, Dropbox | ◐ Emerging area, SANS coverage limited |
| **PB-031 Collaboration** | Slack, Teams, Discord | ◐ Emerging area, SANS coverage limited |
| **PB-032 VM Snapshots** | VMEM, VMSN, VDI analysis | ◐ Niche, SANS doesn't deeply cover |
| **PB-033 Containers** | Docker overlay2, container logs | ◐ Emerging area, SANS coverage limited |

---

## SANS Alignment Summary

### SANS FOR500 (Windows Forensics) — Core Artifact Coverage

| FOR500 Artifact Category | Geoff Coverage | Gaps |
|---|---|---|
| **File System ($MFT, $J, $LogFile)** | ✅ PB-020, PB-026, PB-028 | ADS detection could be deeper |
| **Registry (SYSTEM, SOFTWARE, NTUSER, SAM)** | ✅ PB-003, PB-004, PB-028 | USRCLASS.DAT needs explicit handling |
| **Prefetch** | ✅ PB-002, PB-028 | ✅ Complete |
| **Amcache** | ✅ PB-028 | SHA1 hash extraction present |
| **ShimCache/AppCompat** | ✅ PB-028 | ✅ Complete |
| **Event Logs** | ✅ PB-001–PB-019, PB-028 | WMI logging needs work |
| **Browser Artifacts** | ✅ PB-022 | Search queries could be deeper |
| **Email Artifacts** | ✅ PB-023 | ✅ Complete |
| **LNK/Jump Lists/ShellBags** | ✅ PB-002, PB-013, PB-015, PB-028 | Jump List parsing could be deeper |
| **UserAssist** | ✅ PB-002, PB-028 | ✅ Complete |
| **Scheduled Tasks** | ✅ PB-003, PB-010 | ✅ Complete |
| **USB History** | ✅ PB-028 | ✅ Complete |
| **Recycle Bin** | ✅ PB-009, PB-012, PB-026 | ✅ Complete |

### SANS FOR508 (Advanced IR) — Core Coverage

| FOR508 Topic | Geoff Coverage | Gaps |
|---|---|---|
| **Memory Forensics** | ✅ PB-027 | Registry hives in memory |
| **Network Forensics** | ✅ PB-006, PB-019 | PCAP deep inspection |
| **Malware Analysis** | ✅ PB-008, PB-017, PB-018 | ✅ Three-playbook coverage |
| **Lateral Movement** | ✅ PB-006 | ✅ Complete |
| **C2 Detection** | ✅ PB-019 | ✅ Complete |
| **Timeline Correlation** | ✅ PB-020, PB-016 | Super timeline + cross-image |
| **Threat Hunting** | ✅ PB-010, PB-008 | LOLBins + malware hunting |

### SANS FOR532 (Memory Forensics) — Coverage

| FOR532 Topic | Geoff Coverage | Gaps |
|---|---|---|
| **Process Analysis** | ✅ PB-027 | ✅ Complete |
| **Network Connections** | ✅ PB-027 | ✅ Complete |
| **DLL Analysis** | ✅ PB-027 | Hook/injection detection could be deeper |
| **Registry in Memory** | ◐ PB-027 | Explicit hive extraction needed |
| **String Extraction** | ✅ PB-027 | ✅ Complete |
| **Malware Detection** | ✅ PB-008, PB-027 | ✅ Complete |

---

## Identified Gaps

### High Priority (SANS FOR500 Core)

1. **USRCLASS.DAT parsing** — ShellBags from USRCLASS.DAT (separate from NTUSER.DAT ShellBags). Currently handled implicitly via registry specialist, but needs explicit extraction step.

2. **Jump List deep parsing** — AutomaticDestinations and CustomDestinations need dedicated parsing (JLECmd equivalent). Currently browser specialist covers recent files but not Jump Lists specifically.

3. **Alternate Data Streams (ADS)** — Zone.Identifier and hidden data stream detection. PB-012 mentions anti-forensics but ADS scanning isn't a dedicated step.

4. **Volume Shadow Copy (VSS) analysis** — VSS extraction and comparison is mentioned in PB-009 but not as a standalone capability.

5. **$LogFile parsing** — NTFS transaction log analysis for recent file operations. Currently not explicitly parsed.

### Medium Priority (FOR508 Enhancement)

6. **WMI event subscription detection** — Fileless persistence mechanism. PB-003 and PB-010 mention WMI but no dedicated extraction step.

7. **PowerShell script block logging (EID 4104)** — Deep PowerShell forensics. PB-002 and PB-010 cover PowerShell but could extract script content more thoroughly.

8. **ARP cache analysis** — For ARP spoofing detection in lateral movement. PB-006 covers network but not ARP specifically.

9. **BitLocker recovery key extraction** — PB-029 covers encrypted containers but recovery key extraction from registry (FVE) could be more explicit.

### Lower Priority (Emerging/Niche)

10. **Microsoft 365 / Azure AD logs** — Cloud-based authentication and activity logs. Beyond current scope but important for enterprise IR.

11. **Kubernetes pod forensics** — PB-033 covers containers but not orchestration platforms.

12. **iOS/Android backup analysis** — PB-021 covers mobile extraction but backup parsing (iTunes, ADB) could be deeper.

---

## MITRE ATT&CK Alignment

| Tactic | Geoff Playbooks | Key MITRE Techniques Covered |
|---|---|---|
| **Reconnaissance** | PB-001 | T1592 (Gather victim info) |
| **Initial Access** | PB-001, PB-023 | T1566 (Phishing), T1190 (Exploit public app), T1078 (Valid accounts) |
| **Execution** | PB-002, PB-010 | T1059 (Command/Scripting), T1204 (User execution) |
| **Persistence** | PB-003 | T1547 (Boot/logon), T1053 (Scheduled task), T1133 (External remote services) |
| **Privilege Escalation** | PB-004 | T1068 (Exploitation), T1548 (Abuse elevation) |
| **Defense Evasion** | PB-012 | T1070 (Indicator blocking), T1550 (Pass the hash) |
| **Credential Access** | PB-005 | T1003 (OS credential dumping), T1110 (Brute force) |
| **Discovery** | PB-002, PB-010 | T1087 (Acct discovery), T1083 (File discovery) |
| **Lateral Movement** | PB-006 | T1021 (Remote services), T1569 (Remote services: execution) |
| **Collection** | PB-015 | T1005 (Data from local system), T1039 (Data from network share) |
| **Exfiltration** | PB-007 | T1041 (Exfil over C2), T1048 (Exfil over alternative protocol) |
| **Command & Control** | PB-019 | T1071 (Application layer protocol), T1573 (Encrypted channel) |
| **Impact** | PB-009 | T1486 (Data encrypted for impact), T1490 (Inhibit system recovery) |

---

## Conclusion

Geoff's 33-playbook set provides **strong alignment with SANS FOR500 (Windows Forensics)** and **good coverage of FOR508 (Advanced IR)** and **FOR532 (Memory Forensics)**. The primary gaps are in deeper artifact parsing (Jump Lists, ADS, USRCLASS.DAT, $LogFile) rather than missing entire categories. The emerging areas (cloud sync, collaboration, containers) go beyond SANS core curriculum and represent forward-looking coverage.

**Overall SANS alignment: ~85%** — core FOR500 and FOR508 artifact categories are covered; the 15% gap is in specialized parsing of individual artifact types (Jump Lists, ADS, specific registry keys) rather than missing entire investigation domains.