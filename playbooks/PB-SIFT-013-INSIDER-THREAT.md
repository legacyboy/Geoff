# PB-SIFT-013: Insider Threat Behavioral Analysis Playbook
## Insider Threat — MITRE ATT&CK T1005, T1074, T1052, T1567, T1114

**Objective:** HR-correlated behavioral forensic analysis of an employee suspected of data theft, sabotage, or unauthorized access — covering memory artifacts, timeline anomalies, removable media, data staging, browser artifacts, email/collaboration abuse, application artifacts, and sabotage indicators — using the SIFT Workstation toolset.
**Specialist:** `memory`, `registry`, `logs`, `sleuthkit`, `windows`, `zimmerman`
**MITRE Mapping:** T1005 (Data from Local System), T1074.001 (Data Staged: Local), T1052.001 (Exfiltration Over Physical Medium), T1567.002 (Exfiltration to Cloud Storage), T1114 (Email Collection), T1114.003 (Email Forwarding Rule), T1485 (Data Destruction), T1070.001 (Indicator Removal: Clear Windows Event Logs)

> **Sensitivity Notice:** Insider threat investigations are HR-sensitive. All findings, outputs, and analyst notes must be routed through the designated legal/HR stakeholder channel — not the general incident queue.

---

## Phase 1 — Memory Analysis

**Goal:** Identify processes running at capture time that indicate unauthorized data transfer, personal communication, or active exfiltration.

### 1.1 — Personal Cloud Sync & Transfer Tool Detection (`memory.extract_processes`)
- [ ] **Specialist Method:** `memory.extract_processes(image_path)`
- [ ] Flag personal cloud sync client processes: `dropbox.exe`, `googledrivesync.exe`, `OneDrive.exe` (personal tenant), `MEGAcmdServer.exe`, `BoxSync.exe`
- [ ] Flag unapproved transfer tools: `rclone.exe`, `winscp.exe`, `filezilla.exe`, `pscp.exe`, `azcopy.exe` (unapproved use)
- [ ] Flag archive creation tools: `7zG.exe`, `winrar.exe`, `winzip32.exe` — especially with command-line arguments targeting sensitive directories
- [ ] Flag bulk copy or robocopy invocations with arguments targeting removable media or network shares

### 1.2 — Personal Messaging & Communication Apps (`memory.extract_processes`)
- [ ] **Specialist Method:** `memory.extract_processes(image_path)`
- [ ] Flag personal messaging applications: `Signal.exe` (Signal Desktop), `Telegram.exe`, personal Slack workspace processes, `WhatsApp.exe`
- [ ] Flag personal email clients open to non-corporate services: browser sessions to Gmail, Yahoo Mail, Hotmail
- [ ] Capture full command-line arguments for all flagged processes — note arguments pointing to sensitive directories
- [ ] Flag screen capture tools: `SnippingTool.exe`, `greenshot.exe`, `ShareX.exe` — document exfiltration via screenshot

### 1.3 — Session Context & Network Connections (`memory.extract_processes`)
- [ ] **Specialist Method:** `memory.extract_processes(image_path)` with network connection enumeration
- [ ] Flag active outbound connections from cloud sync or transfer processes at capture time
- [ ] Note destination IPs and ports — correlate with known cloud storage CDN ranges (Dropbox, Mega, Google)
- [ ] Flag any process holding a connection to personal webmail endpoints (Gmail SMTP/IMAP, Yahoo Mail)

---

## Phase 2 — Timeline & Behavioral Analysis

**Goal:** Establish behavioral patterns consistent with insider data theft — off-hours activity, bulk access, role violations, and HR event correlation.

### 2.1 — Off-Hours Activity Detection (`logs.parse_evtx`)
- [ ] **Specialist Method:** `logs.parse_evtx(evtx_path, event_ids=[4624, 4634, 4663])`
- [ ] Extract all logon and logoff events — flag logons outside business hours (before 07:00 or after 19:00 local time, weekends, holidays)
- [ ] Flag interactive logons (Type 2) or remote logons (Type 10) during off-hours to sensitive systems
- [ ] Correlate off-hours logon timestamps with file access events (EID 4663) in the same window

### 2.2 — Bulk File Access Events (`logs.parse_evtx`)
- [ ] **Specialist Method:** `logs.parse_evtx(evtx_path, event_ids=[4663])`
- [ ] Flag bulk file access: more than 100 file open/read events in a 15-minute window across sensitive directories
- [ ] Flag access patterns traversing multiple department directories (HR, Finance, Legal, Executive, R&D, source code) within a single session
- [ ] Identify MFT $STANDARD_INFORMATION timestamps for bulk-accessed files — cross-reference with logon session window

### 2.3 — Data Hoarding Pattern Analysis
- [ ] Build a multi-week timeline of file access volume by user — flag escalating access volume in weeks preceding known HR events
- [ ] Flag access to files significantly outside the user's organizational unit or job function
- [ ] Identify peak access days — correlate with calendar events (last day before resignation, day after performance review)
- [ ] Flag accumulation of sensitive files in a user-controlled staging location (Desktop, Downloads, %TEMP%, removable media)

### 2.4 — HR Event Correlation
- [ ] Obtain HR event dates (resignation submission, termination notice, disciplinary action, performance improvement plan issuance) from the requesting stakeholder
- [ ] Overlay HR event dates onto the file access timeline — flag access spikes within 7 days before or after each HR event
- [ ] Flag access to HR/legal/finance directories by the subject user — role-violation access is elevated in significance near departure dates
- [ ] Flag access to source code repositories, password vaults, or customer data directories by non-privileged users

---

## Phase 3 — Removable Media Analysis

**Goal:** Establish USB and removable media connection history and correlate with bulk file access events.

### 3.1 — USB Connection Log Analysis (`sleuthkit.list_files`)
- [ ] **Specialist Method:** `sleuthkit.list_files(evidence_path)` targeting `C:\Windows\INF\setupapi.dev.log`
- [ ] Parse `setupapi.dev.log` for all USB device connections — extract device type, description, and connection timestamps
- [ ] Identify USB mass storage device entries: flag all `USBSTOR` device class entries with timestamps
- [ ] Flag connections of storage devices (USB drives, external HDDs) whose timestamps correlate with bulk file access windows

### 3.2 — Registry USB Device History (`registry.extract_keys`)
- [ ] **Specialist Method:** `registry.extract_keys(system_hive, "SYSTEM\\CurrentControlSet\\Enum\\USBSTOR")`
- [ ] Extract full USB device history — capture `FriendlyName`, `DeviceDesc`, `Mfg`, `ClassGUID`, and last write timestamps
- [ ] Cross-reference device first-seen and last-seen timestamps with file access timeline
- [ ] Check `HKLM\SYSTEM\CurrentControlSet\Enum\USB\` for MTP/PTP device connections — personal phone as storage device
- [ ] Check `HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices\` for additional MTP device metadata

### 3.3 — Timeline Cross-Reference (`logs.parse_evtx`)
- [ ] **Specialist Method:** `logs.parse_evtx(evtx_path, event_ids=[6416, 4663])`
- [ ] EID 6416 (New external device recognized): extract device description and timestamp — correlate with USBSTOR registry entries
- [ ] Cross-reference USB insertion timestamps with bulk file access events (EID 4663) in the same 30-minute window
- [ ] Flag overlapping windows — USB inserted, followed by bulk file access, followed by USB removal within a single session

### 3.4 — Portable Executable Artifacts (`sleuthkit.list_files`)
- [ ] **Specialist Method:** `sleuthkit.list_files(evidence_path)` targeting Prefetch and UserAssist for USB-origin executable evidence
- [ ] Flag executables run from drive letters not matching the system drive — indicates tools run directly from USB
- [ ] Check `windows.analyze_prefetch(prefetch_dir)` for executions from removable media paths (`D:\`, `E:\`, `F:\`)
- [ ] Flag executables with no corresponding installed application (no registry uninstall entry, no Program Files directory entry)

---

## Phase 4 — Data Staging Analysis

**Goal:** Identify data aggregation, archive creation, and transfer preparation activities.

### 4.1 — MFT Bulk Copy Operation Analysis (`sleuthkit.list_files`)
- [ ] **Specialist Method:** `sleuthkit.list_files(evidence_path)` with MFT timeline analysis
- [ ] Identify clusters of file creation events in user-controlled directories (Desktop, Downloads, %TEMP%, %APPDATA%) with source files from sensitive directories
- [ ] Flag MFT entries showing bulk file copies to removable media device paths
- [ ] Flag large file count creation bursts — more than 50 files created in a 10-minute window in staging areas

### 4.2 — Archive & Compression Artifacts (`sleuthkit.list_files`)
- [ ] **Specialist Method:** `sleuthkit.list_files(evidence_path)` targeting user profile, Desktop, Downloads, %TEMP%
- [ ] Enumerate archive files (`.zip`, `.7z`, `.rar`, `.tar`, `.gz`, `.tar.gz`) — flag large archives or archives with sensitive filenames
- [ ] Flag split archive sequences (`.zip.001`, `.7z.001`, `.part1.rar`) — indicate large dataset staged for transfer
- [ ] Flag encrypted archives (password-protected) with no legitimate business justification
- [ ] Check for recently deleted archives in unallocated space or Recycle Bin — attacker cleanup indicator

### 4.3 — Transfer Tool Configuration Files (`sleuthkit.list_files`)
- [ ] **Specialist Method:** `sleuthkit.list_files(evidence_path)` targeting user profile directories
- [ ] Flag `rclone.conf` in `%APPDATA%\rclone\` — extract configured remotes (personal cloud storage destinations)
- [ ] Flag WinSCP `.ini` or registry-stored sessions — check for personal or non-corporate SFTP/FTP destinations
- [ ] Flag FileZilla `recentservers.xml` and `sitemanager.xml` — extract configured site destinations
- [ ] Flag AWS CLI credential files (`%USERPROFILE%\.aws\credentials`) — unauthorized cloud storage access

### 4.4 — SRUM Network Upload Volume Analysis (`windows.analyze_srum`)
- [ ] **Specialist Method:** `windows.analyze_srum(srum_db_path)` and `zimmerman.srum_parse(srum_db, output_csv)`
- [ ] Extract per-application network usage from SRUM database (`C:\Windows\System32\sru\SRUDB.dat`)
- [ ] Flag applications with anomalously high upload (bytes sent) volume — particularly cloud sync clients or browsers
- [ ] Correlate SRUM network spike timestamps with USB connection and file access timeline events
- [ ] Flag SRUM entries for unapproved transfer tools — provides evidence of actual data volume transferred

---

## Phase 5 — Browser Artifacts

**Goal:** Identify browser-based exfiltration, personal webmail access, file upload activity, and job search behavior.

### 5.1 — Browser History Analysis (`windows.analyze_shellbags`)
- [ ] **Specialist Method:** `windows.analyze_shellbags(shellbags_path)` and browser artifact parsing
- [ ] Flag visits to personal webmail services: Gmail (`mail.google.com`), Hotmail/Outlook.com (`outlook.live.com`), Yahoo Mail (`mail.yahoo.com`)
- [ ] Flag visits to file sharing and transfer services: WeTransfer, Mega.nz, Anonfiles, SendSpace, pCloud
- [ ] Flag job search activity: LinkedIn, Indeed, Glassdoor, Monster — particularly if concentrated near HR event dates
- [ ] Flag visits to competitor company websites, recruiting agency portals, or external job boards

### 5.2 — Browser Upload Events
- [ ] Parse browser form submission and upload history artifacts — flag file upload events to non-corporate domains
- [ ] Flag large file upload events in browser network activity — POST requests with large request body size
- [ ] Cross-reference browser upload timestamps with MFT file access timestamps for the same files
- [ ] Flag uploads to file-sharing sites from browser history occurring within hours of USB activity or bulk file access

### 5.3 — Saved Credentials & Stored Data
- [ ] Parse browser saved password stores — flag credentials stored for non-corporate services (personal email, cloud storage, job boards)
- [ ] Flag browser profiles synced to personal accounts (Chrome sync to personal Google account, Firefox Sync) — data leakage via browser sync
- [ ] Check browser IndexedDB and LocalStorage for web application data from cloud storage services

---

## Phase 6 — Email & Collaboration Artifacts

**Goal:** Detect email-based exfiltration, forwarding rules, and collaboration platform misuse.

### 6.1 — Outlook Auto-Forward Rule Detection (`registry.extract_keys`)
- [ ] **Specialist Method:** `registry.extract_keys(ntuser_hive, "Software\\Microsoft\\Office\\*\\Outlook\\Preferences")`
- [ ] Extract Outlook preference keys — flag `EnableLogging`, mail profile settings, and forwarding rule indicators
- [ ] Check Outlook `rules.rwz` file or Exchange Server rules backup — parse for auto-forward rules targeting external addresses
- [ ] Flag `SentToMe` or `FromMe` rules forwarding to non-corporate email domains — **CRITICAL** exfiltration indicator

### 6.2 — PST Export & Large Email File Analysis (`sleuthkit.list_files`)
- [ ] **Specialist Method:** `sleuthkit.list_files(evidence_path)` targeting user profile and common staging directories
- [ ] Flag large `.pst` files created outside the default Outlook archive path — staged for exfiltration
- [ ] Check MFT for `.pst` file creation timestamps — flag creation events within investigation window
- [ ] Flag `.pst` files in Desktop, Downloads, %TEMP%, or removable media paths — non-standard locations indicate staging

### 6.3 — Personal Messaging Application Artifacts (`sleuthkit.list_files`)
- [ ] **Specialist Method:** `sleuthkit.list_files(evidence_path)` targeting application profile directories
- [ ] Flag Signal Desktop artifacts: `%APPDATA%\Signal\` — database contains message history if not encrypted
- [ ] Flag Telegram Desktop artifacts: `%APPDATA%\Telegram Desktop\` — flag `tdata\` for session and message artifacts
- [ ] Flag personal Slack workspace artifacts: `%APPDATA%\Slack\` — flag workspace URLs not matching corporate Slack domain
- [ ] Flag WhatsApp Desktop artifacts and note any file-sharing activity within the application

---

## Phase 7 — Application Artifacts

**Goal:** Reconstruct application execution history, document access patterns, and print activity.

### 7.1 — UserAssist MRU Analysis (`registry.extract_keys`)
- [ ] **Specialist Method:** `registry.extract_keys(ntuser_hive, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist")`
- [ ] Decode ROT13-encoded UserAssist keys — extract application execution history with run counts and last run times
- [ ] Flag execution of unapproved tools: exfiltration utilities, keyloggers, screen capture tools, personal cloud clients
- [ ] Flag execution of data discovery tools: `Everything.exe`, `Agent Ransack`, bulk file search utilities
- [ ] Cross-reference UserAssist timestamps with bulk file access and USB connection events

### 7.2 — Windows Search Index Analysis (`sleuthkit.list_files`)
- [ ] **Specialist Method:** `sleuthkit.list_files(evidence_path)` targeting `%APPDATA%\Microsoft\Search\` and Windows Search database
- [ ] Extract Windows Search index (`Windows.edb`) — flag indexed documents from sensitive directories not consistent with user's role
- [ ] Check Windows Search history for sensitive search terms: `confidential`, `salary`, `acquisition`, `merger`, `password`, `credentials`
- [ ] Flag searches for competitor names, personal cloud service names, or exfiltration tool names

### 7.3 — Print Spool Artifacts (`sleuthkit.list_files`)
- [ ] **Specialist Method:** `sleuthkit.list_files(evidence_path)` targeting `%SystemRoot%\System32\spool\PRINTERS\`
- [ ] Enumerate `.SPL` (spool) and `.SHD` (shadow) files — flag large print jobs or print jobs from sensitive document directories
- [ ] Recover deleted `.SPL` files from unallocated space — print spool artifacts persist after job completion
- [ ] Flag print jobs to physical printers at unusual hours — insider printing documents for physical removal

### 7.4 — ShellBags Directory Access History (`zimmerman.shellbags_parse`)
- [ ] **Specialist Method:** `zimmerman.shellbags_parse(hive, output_csv)` and `windows.analyze_shellbags(shellbags_path)`
- [ ] Extract ShellBags from `NTUSER.DAT` and `UsrClass.dat` — trace directory navigation history
- [ ] Flag ShellBag entries for sensitive directories outside user's normal access scope: `\\HR\`, `\\Finance\`, `\\Legal\`, source code repositories
- [ ] Note ShellBag first-access and last-access timestamps — correlate with HR event dates
- [ ] Flag ShellBag entries for removable media paths — confirm physical drive access history

---

## Phase 8 — Sabotage Indicators

**Goal:** Detect intentional destruction, tampering, or system disruption actions distinct from data theft.

### 8.1 — Mass Deletion in Sensitive Directories (`logs.parse_evtx`)
- [ ] **Specialist Method:** `logs.parse_evtx(evtx_path, event_ids=[4660, 4663])`
- [ ] EID 4660 (Object deleted) combined with EID 4663 (Object access): flag mass deletion events in shared drives, source code repositories, or production configuration directories
- [ ] Flag deletion of more than 20 files in a 5-minute window — distinguish from normal housekeeping by location and file types
- [ ] Check Recycle Bin artifacts for recently deleted sensitive files — confirm deletion source and timestamp

### 8.2 — Log Clearing & Audit Tampering (`logs.parse_evtx`)
- [ ] **Specialist Method:** `logs.parse_evtx(evtx_path, event_ids=[1102, 104, 4719])`
- [ ] EID 1102 (Audit log cleared — Security): **CRITICAL** — flag any occurrence; capture the subject account
- [ ] EID 104 (System log cleared): flag in conjunction with EID 1102 — indicates deliberate log wiping
- [ ] EID 4719 (System audit policy changed): flag audit policy disablement — attacker removing coverage before action
- [ ] Correlate log clearing timestamps with the insider's logon session and HR event dates

### 8.3 — AV/EDR Tampering (`logs.parse_evtx`)
- [ ] **Specialist Method:** `logs.parse_evtx(evtx_path, event_ids=[7036, 4688])`
- [ ] Flag stopping or disabling of AV/EDR services (EID 7036: service state change to Stopped for security service)
- [ ] Flag uninstallation of security tools via EID 4688 (`MsiExec.exe` or `setup.exe` with security product names)
- [ ] Check `HKLM\SYSTEM\CurrentControlSet\Services\` for security service `Start` value changes — flag changes from `2` (automatic) to `4` (disabled)

### 8.4 — Account & Privilege Abuse (`logs.parse_evtx`)
- [ ] **Specialist Method:** `logs.parse_evtx(evtx_path, event_ids=[4720, 4728, 4732, 4756, 4672])`
- [ ] EID 4720 (User account created): flag accounts created by non-admin users — backdoor account creation
- [ ] EID 4728/4732/4756 (User added to security/admin group): flag unauthorized group membership additions
- [ ] EID 4672 (Special privileges assigned): flag privilege grants inconsistent with the user's role
- [ ] Flag account creation timestamps relative to known departure or termination dates — persistence preparation indicator

---

## Phase 9 — Scoring & Output

**Goal:** Prioritize findings and route to appropriate stakeholders.

- [ ] **Severity Matrix:**
  - **Critical:** Confirmed data exfiltration (USB transfer confirmed, cloud upload volume confirmed, personal email receipt confirmed); log clearing (EID 1102) by subject user; mass deletion in production directories; auto-forward rule to personal email active
  - **High:** Bulk file access to role-violating directories correlated with USB insertion; archive creation with sensitive data followed by deletion; personal messaging app active with file transfer evidence; PST file staged outside default path
  - **Medium:** Off-hours logon with sensitive file access but no confirmed transfer; personal cloud client installed; job search browser activity correlated with HR event dates; UserAssist entries for unapproved tools without confirmed transfer
  - **Low:** Single off-hours logon with routine activity; personal messaging app installed but no suspicious file access; job search browser history without correlated data access anomalies

- [ ] **MITRE ATT&CK Mapping:**
  - T1005 — Data from Local System
  - T1074.001 — Data Staged: Local
  - T1052.001 — Exfiltration Over Physical Medium: Exfiltration over USB
  - T1567.002 — Exfiltration to Cloud Storage
  - T1114 — Email Collection
  - T1114.003 — Email Forwarding Rule
  - T1485 — Data Destruction
  - T1070.001 — Indicator Removal: Clear Windows Event Logs
  - T1078 — Valid Accounts (authorized access misused)
  - T1560.001 — Archive Collected Data: Archive via Utility
  - T1056.001 — Input Capture: Keylogging (if keylogger present)

- [ ] **SANS FOR500/FOR508 Alignment:** ShellBags analysis (Phase 7.4), USB artifact investigation (Phase 3), and SRUM data analysis (Phase 4.4) are FOR500 core topics. Behavioral timeline correlation and HR event overlay are FOR508 Advanced IR techniques for insider threat investigations. SANS FOR508 emphasizes SRUM as a primary tool for quantifying actual data transfer volume.

- [ ] **Structured Output:** JSON with user activity timeline, file access events, device connection records, application execution history, and severity scores
- [ ] **Analyst Handoff:** Bundle NTUSER.DAT, UsrClass.dat, SYSTEM hive, SRUDB.dat, setupapi.dev.log, Security.evtx, browser profile directories, and MFT export — route all findings through designated HR/Legal stakeholder channel
