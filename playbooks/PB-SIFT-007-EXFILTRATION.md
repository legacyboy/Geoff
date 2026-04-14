# TEMP_TEMP_TEMP_PB-SIFT-014: Exfiltration Indicators Playbook
## Exfiltration Indicators — Static Image Analysis

**Objective:** High-fidelity detection and analysis of data exfiltration activity within a digital forensic image using the SIFT Workstation toolset.

---

### Phase 1 — Evidence Integrity
- [ ] **Hash Verification:** Verify hash of all evidence against chain of custody.
- [ ] **Integrity Check:** Flag any mismatch before proceeding.

---

### Phase 2 — Memory Analysis
- [ ] **Archiving Activity:** Check process memory for file archiving or compression activity — flag `zip`, `rar`, `7z` API calls in unexpected processes.
- [ ] **Staging Detection:** Check command lines — flag staging commands, bulk copy, or archive creation targeting sensitive directories.
- [ ] **Network Endpoints:** Check network connections — flag large outbound transfers or connections to cloud storage endpoints (`mega.nz`, `dropbox`, `onedrive` from non-standard processes).
- [ ] **File Handle Audit:** Flag any process with handles to large volumes of files outside its expected scope.
- [ ] **Exfiltration-over-C2:** Check for exfiltration-over-C2 patterns — flag processes with sustained outbound connections and high data volume.

---

### Phase 3 — Super Timeline
- [ ] **Timeline Construction:** Build full timeline across all artifact sources.
- [ ] **Bulk Access:** Flag bulk file access events — large number of files opened/read in a short window.
- [ ] **Archive Creation:** Flag archive file creation (`.zip`, `.rar`, `.7z`, `.tar`) created in staging directories.
- [ ] **Cleanup Patterns:** Flag archive deletion after transfer — attacker cleanup, correlate with network activity window.
- [ ] **Sensitive Directory Access:** Flag access to sensitive directories — HR, Finance, Legal, executive user profiles, source code repos.
- [ ] **Timing Correlation:** Correlate file staging timestamps with outbound network connection timestamps.

---

### Phase 4 — Disk Artifacts
- [ ] **Archive Search:** Check for archive files created in temp or unusual locations — flag size, location, and creation time.
- [ ] **Tool Execution (Prefetch):** Flag execution of `7zip`, `winrar`, `robocopy`, `xcopy`, `rclone`, `winscp`, `pscp`, `curl`, `wget`.
- [ ] **Browser Uploads:** Check browser artifacts — flag uploads via browser to cloud storage or paste sites.
- [ ] **Cloud Sync Config:** Check for use of `rclone` config files — flag any cloud sync configuration in user profiles.
- [ ] **MFT Analysis:** Check MFT for large file creation followed by deletion — staging and cleanup pattern.
- [ ] **Chunked Exfiltration:** Check for split archive sequences (`.001`, `.002`) — indicator of chunked exfiltration.
- [ ] **Removable Media:** Check USB and removable media artifacts — flag `setupapi.dev.log` and registry for device connection history.
- [ ] **Email Abuse:** Check email client artifacts — flag large attachments sent or draft folder abuse (C2 and exfil technique).

---

### Phase 5 — Event Log Analysis
- [ ] **Bulk Read Events:** Flag bulk file read activity if object auditing is enabled (EID 4663).
- [ ] **USB Insertion:** Flag removable media connection events (EID 6416) — device plug-in during incident window.
- [ ] **Tool Execution:** Flag use of `robocopy`, `xcopy`, or `rclone` via process auditing (EID 4688).
- [ ] **Firewall Anomalies:** Flag outbound firewall allow events for unusual processes (EID 5156).
- [ ] **PowerShell Transfers:** Flag PowerShell upload or transfer commands (EID 4103 / 4104) — `Invoke-WebRequest`, `Start-BitsTransfer`, `Send-MailMessage`.
- [ ] **RDP Redirection:** Flag RDP clipboard or drive redirection activity — common manual exfil technique (EID 4624 logon type 10 with drive mapping).

---

### Phase 6 — YARA Scan
- [ ] **Tool Signatures:** Scan for known exfiltration tool signatures — `rclone`, `megasync`, `exmatter`, `stealc`, `raccoon`.
- [ ] **Content Analysis:** Scan archive files found on disk for sensitive content patterns — PII, credential strings, key material.
- [ ] **Browser Cache Scan:** Scan browser cache and profile data for upload activity artifacts.
- [ ] **Hit Documentation:** Flag any hits with tool name, file location, and data type involved.

---

### Phase 7 — Network IOC Extraction
- [ ] **Destination Harvesting:** Extract all outbound IPs, domains, and URLs from disk and memory artifacts.
- [ ] **Exfiltration Sites:** Flag known exfiltration destinations — paste sites, cloud storage, file sharing services, TOR.
- [ ] **Off-Hours Activity:** Flag DNS queries for cloud sync or file transfer services made outside business hours.
- [ ] **Volume Estimation:** Calculate approximate data volume transferred where possible from network buffer artifacts.
- [ ] **Intel Enrichment:** Enrich all IOCs against threat intel feeds — flag known exfiltration infrastructure.
- [ ] **Encrypted Channels:** Flag use of encrypted channels (HTTPS/SFTP) to unknown external hosts — obscures exfil content.

---

### Phase 8 — Score & Report
- [ ] **Aggregation:** Aggregate all flags into findings report.
- [ ] **MITRE Mapping:** Identify technique per MITRE ATT&CK:
    - **T1041:** Exfiltration Over C2 Channel
    - **T1567.002:** Exfiltration to Cloud Storage
    - **T1567:** Exfiltration over Web Service
    - **T1052.001:** Exfiltration via Removable Media
    - **T1020:** Automated Exfiltration
    - **T1074.001:** Data Staged — Local
    - **T1560.001:** Archive via Utility
    - **T1048.003:** Email Exfiltration
- [ ] **Impact Estimation:** Estimate data impact — what directories/file types were accessed, approximate volume.
- [ ] **Exfiltration Timeline:** Establish exfiltration timeline — staging window, transfer window, cleanup window.
- [ ] **Final Output:** Score by severity — output structured findings file for analyst handoff.
