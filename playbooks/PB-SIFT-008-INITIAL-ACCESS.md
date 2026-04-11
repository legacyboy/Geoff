# PB-SIFT-008: Initial Access Indicators Playbook
## Initial Access Indicators — Static Image Analysis

**Objective:** High-fidelity detection and reconstruction of the initial entry vector (Patient Zero) into a compromised system using the SIFT Workstation toolset.

---

### Phase 1 — Evidence Integrity
- [ ] **Hash Verification:** Verify hash of all evidence against chain of custody.
- [ ] **Integrity Check:** Flag any mismatch before proceeding.

---

### Phase 2 — Memory Analysis
- [ ] **Parent Process Audit:** Check for browser or email client processes that spawned unexpected child processes — flag immediately.
- [ ] **Sourcing Patterns:** Flag `outlook.exe`, `thunderbird.exe`, or webmail browser tabs spawning `cmd.exe`, `powershell.exe`, or `wscript.exe`.
- [ ] **Cradle Detection:** Check command lines for download cradle patterns initiated from Office or browser processes.
- [ ] **Exploit Artifacts:** Flag exploit-related memory artifacts — heap spray patterns, ROP chain indicators, shellcode in non-executable regions.
- [ ] **Web Shell Detection:** Check for web shell processes — flag `w3wp.exe`, `httpd.exe`, or `nginx` spawning shell processes.

---

### Phase 3 — Super Timeline
- [ ] **Timeline Construction:** Build full timeline across all artifact sources.
- [ ] **Patient Zero ID:** Identify the earliest suspicious event on the image — this is the candidate patient zero timestamp.
- [ ] **Phishing Flow:** Flag document opens immediately followed by script or binary execution — phishing document indicator.
- [ ] **Tool Drop Timing:** Flag first appearance of attacker tooling on disk — correlate back to delivery mechanism.
- [ ] **Download Correlation:** Flag browser downloads of executables or archives immediately preceding malicious activity.
- [ ] **Mail/Execution Sync:** Correlate email timestamps in mail client artifacts with first execution events on disk.

---

### Phase 4 — Disk Artifacts

#### 4.1 — Email Artifacts
- [ ] **Store Analysis:** Check mail client stores — flag emails with attachments matching execution timestamps (`*.pst`, `*.ost`, `*.mbox`).
- [ ] **Attachment Audit:** Flag attachments with double extensions, macro-enabled documents, or executable types (`.doc`, `.xls`, `.js`, `.iso`, `.lnk`, `.vbs`).
- [ ] **Container Analysis:** Check for ISO / IMG / VHD mount artifacts — common phishing delivery to bypass Mark-of-the-Web.
- [ ] **Temp Folder Scan:** Check `%APPDATA%` email temp folders for extracted attachment remnants.
- [ ] **Urgency Patterns:** Flag emails from external senders with urgent language patterns in subject lines if readable.

#### 4.2 — Browser Artifacts
- [ ] **Download History:** Check browser download history — flag executables, scripts, archives, or office documents downloaded.
- [ ] **History Audit:** Check browser history for access to phishing domains, paste sites, or file sharing services.
- [ ] **Cache Scan:** Check cached files for malicious payloads or exploit kit landing pages.
- [ ] **Extension Audit:** Flag browser extension installs that coincide with the incident window.
- [ ] **Profile Theft:** Check for saved credentials or cookie theft artifacts in browser profile directories.

#### 4.3 — Office / Document Artifacts
- [ ] **Recent Files:** Check recent file lists (RecentDocs, LNK files) — flag Office documents opened prior to first malicious execution.
- [ ] **Macro Audit:** Check for macro-enabled documents in temp or download locations.
- [ ] **Macro Security:** Flag `HKCU\Software\Microsoft\Office\*\Security\VBAWarnings` registry key — value of 1 disables macro warnings.
- [ ] **Trust Records:** Check Office trust record keys — flag documents that were explicitly trusted by the user.
- [ ] **Metadata Analysis:** Check for CVE-specific exploit indicators in document metadata or embedded objects.

#### 4.4 — External Access Artifacts
- [ ] **RDP Analysis:** Check RDP artifacts — flag `Default.rdp`, RDP bitmap cache, and terminal server client registry keys for external IPs.
- [ ] **VPN Audit:** Check VPN logs or client artifacts on disk — flag unusual connection times or external IPs.
- [ ] **Service Exploitation:** Check for exposed service exploitation — IIS logs, Apache logs, Exchange logs for exploit patterns (ProxyShell, ProxyLogon, Log4Shell).
- [ ] **Web Request Anomalies:** Flag `%SystemRoot%\inetpub\logs` for web request anomalies — long URLs, unusual HTTP verbs, encoded payloads in GET/POST.
- [ ] **Web Shell Files:** Check for web shell files dropped in web-accessible directories — flag `.aspx`, `.php`, `.jsp` files with unusual creation dates.

---

### Phase 5 — Event Log Analysis
- [ ] **External Logon:** Flag first network logon from an external IP (EID 4624 logon type 3 / 10) — establishes external access timestamp.
- [ ] **Process Spawning:** Flag process creation from Office or browser parent processes (EID 4688).
- [ ] **MotW Bypass:** Flag Mark-of-the-Web bypass techniques — ISO/VHD mount events in application logs.
- [ ] **AV Alerts:** Flag Windows Defender or AV detection events around the initial access window — even if remediated, confirms delivery.
- [ ] **User Override:** Flag SmartScreen bypass or user override events in application logs.
- [ ] **Remote Activation:** Flag WMI or DCOM activation from remote hosts as initial execution vector (EID 4688 / 4624).
- [ ] **Web Shell Access:** Check IIS / web server logs for web shell access patterns — repeated POST requests to static file paths.

---

### Phase 6 — YARA Scan
- [ ] **Phishing Signatures:** Scan email attachment remnants and download directories for known phishing document signatures.
- [ ] **Web Shell Scan:** Scan web directories for known web shell signatures — China Chopper, WSO, b374k, Godzilla.
- [ ] **Container Scan:** Scan ISO / VHD mount points for malicious payload signatures.
- [ ] **Exploit Kit Detection:** Scan browser cache for exploit kit signatures.
- [ ] **Hit Documentation:** Flag any hits with delivery method, file name, location, and confidence level.

---

### Phase 7 — Network IOC Extraction
- [ ] **Source Harvesting:** Extract domains and IPs from browser history, email headers, and web server logs.
- [ ] **Phishing Domain Analysis:** Flag phishing domains — look for typosquatting, homoglyph, or lookalike domains relative to known legitimate domains.
- [ ] **First Callback:** Flag initial C2 callback destination — first outbound connection after execution timestamp.
- [ ] **Distribution Network:** Flag exploit kit infrastructure or known malware distribution network IPs.
- [ ] **Intel Enrichment:** Enrich all IOCs against threat intel — flag known phishing infrastructure, malware delivery domains.

---

### Phase 8 — Score & Report
- [ ] **Aggregation:** Aggregate all flags into findings report.
- [ ] **MITRE Mapping:** Identify technique per MITRE ATT&CK:
    - **T1566.001:** Spearphishing Attachment
    - **T1566.002:** Spearphishing Link
    - **T1204.002:** Malicious File — User Execution
    - **T1553.005:** ISO / VHD Smuggling
    - **T1190:** Exploit Public-Facing Application
    - **T1133:** External Remote Services — RDP/VPN
    - **T1505.003:** Web Shell
    - **T1189:** Drive-by Compromise
    - **T1199:** Trusted Relationship Abuse
- [ ] **Patient Zero Confirmation:** Confirm patient zero — host, user account, delivery mechanism, and timestamp.
- [ ] **Narrative Reconstruction:** Establish full initial access narrative — delivery $\rightarrow$ execution $\rightarrow$ first action on objective.
- [ ] **Final Output:** Score by severity — output structured findings file for analyst handoff.
