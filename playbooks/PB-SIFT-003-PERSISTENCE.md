# TEMP_TEMP_TEMP_TEMP_TEMP_PB-SIFT-014: Persistence Mechanism Indicators Playbook
## Persistence Mechanism Indicators — Static Image Analysis

**Objective:** High-fidelity detection of persistence mechanisms used by attackers to maintain access to a system across reboots and user logoffs using the SIFT Workstation toolset.

---

### Phase 1 — Evidence Integrity
- [ ] **Hash Verification:** Verify hash of all evidence against chain of custody.
- [ ] **Integrity Check:** Flag any mismatch before proceeding.

---

### Phase 2 — Memory Analysis
- [ ] **Process Enumeration:** Enumerate processes — flag anything loaded from unusual paths or with no associated disk binary.
- [ ] **DLL Audit:** Check loaded DLLs — flag DLLs loaded from user-writable locations or with names mimicking system DLLs.
- [ ] **Thread Analysis:** Check for injected threads in long-running system processes — common persistence anchor.
- [ ] **Command Line Audit:** Check command lines — flag scheduled task or service registration commands run in-memory.
- [ ] **Parental Analysis:** Flag any process with an unusual parent that survives reboots (e.g., spawned from `winlogon.exe`).

---

### Phase 3 — Super Timeline
- [ ] **Timeline Construction:** Build full timeline across all artifact sources.
- [ ] **Registry Correlation:** Flag registry key writes to any known persistence location — correlate with process execution timestamps.
- [ ] **Event Correlation:** Flag new service or scheduled task creation timestamps.
- [ ] **DLL Drop Tracking:** Flag DLL drops in system or application directories — DLL hijacking setup.
- [ ] **Startup Modification:** Flag modification of startup folders, logon scripts, or GPO scripts.
- [ ] **Dwell Timeline:** Correlate persistence installation time with initial access vector.

---

### Phase 4 — Disk Artifacts
- [ ] **Autorun Analysis:** Check all autorun locations — flag any entry pointing to user-writable paths, temp folders, or encoded scripts.

| Location | Persistence Type |
| :--- | :--- |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` | Registry Run Key |
| `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` | User-level Run Key |
| `HKLM\SYSTEM\CurrentControlSet\Services` | Malicious Service |
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` | Winlogon hijack |
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options` | Debugger hijack |
| `HKCU\Software\Classes\ms-settings\shell\open\command` | UAC bypass persistence |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders` | Shell folder redirect |

- [ ] **Scheduled Task Audit:** Check scheduled tasks — flag tasks with encoded commands, UNC paths, or pointing to temp locations.
- [ ] **Service Audit:** Check services — flag services with random names, missing descriptions, or non-standard binary paths.
- [ ] **Startup Folder Check:** Inspect `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`.
- [ ] **DLL Hijacking Check:** Flag DLLs dropped alongside legitimate executables in writable paths.
- [ ] **WMI Repository Scan:** Flag event subscriptions (`EventFilter`, `EventConsumer`, `__FilterToConsumerBinding`).
- [ ] **COM Hijacking:** Flag `HKCU\Software\Classes\CLSID` entries overriding system COM objects.
- [ ] **Bootkit Detection:** Flag MBR or VBR modifications via low-level disk analysis.
- [ ] **Plugin/Extension Audit:** Check for malicious browser extensions or application plugins installed in user profiles.

---

### Phase 5 — Event Log Analysis
- [ ] **Service Installation:** Flag new service installation (EID 7045) — especially services with no description or random names.
- [ ] **Task Scheduling:** Flag scheduled task creation or modification (EID 4698 / 4702).
- [ ] **Registry Auditing:** Flag registry modifications to Run keys if object auditing is enabled (EID 4657).
- [ ] **LSA/Winlogon Changes:** Flag Winlogon or LSA notification package changes (EID 4616 / 4657).
- [ ] **WMI Activity:** Flag WMI subscription activity (EID 5857 / 5858 / 5859 / 5860 / 5861).
- [ ] **GPO Modification:** Flag GPO modification events (EID 5136) — attacker may persist via Group Policy.

---

### Phase 6 — YARA Scan
- [ ] **Autorun Binaries:** Scan all autorun-referenced binaries against malware rulesets.
- [ ] **WMI Repository:** Scan WMI repository for known malicious subscription patterns.
- [ ] **Task XML Analysis:** Scan scheduled task XML files for encoded or obfuscated commands.
- [ ] **Hijack Paths:** Scan DLLs in hijack-prone paths against known malicious signatures.
- [ ] **Hit Documentation:** Flag any hits with persistence type, location, and confidence level.

---

### Phase 7 — Network IOC Extraction
- [ ] **C2 Harvesting:** Extract any C2 addresses or domains referenced in persistence payloads.
- [ ] **Beacon Analysis:** Flag beaconing patterns implied by scheduled task intervals — regular outbound at fixed intervals is a strong indicator.
- [ ] **Intel Enrichment:** Enrich all extracted IOCs against threat intel feeds.

---

### Phase 8 — Score & Report
- [ ] **Aggregation:** Aggregate all flags into findings report.
- [ ] **MITRE Mapping:** Identify technique per MITRE ATT&CK:
    - **T1547.001:** Registry Run Keys
    - **T1053.005:** Scheduled Task
    - **T1543.003:** Windows Service
    - **T1547.004:** Winlogon Helper DLL
    - **T1546.003:** WMI Event Subscription
    - **T1574.001:** DLL Hijacking
    - **T1546.015:** COM Hijacking
    - **T1542.003:** Bootkit
    - **T1546.012:** Image File Execution Options
- [ ] **Persistence Timeline:** Establish persistence timeline — when was it installed, how long has the attacker had a foothold.
- [ ] **Final Output:** Score by severity — output structured findings file for analyst handoff.
