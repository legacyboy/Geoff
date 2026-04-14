# PB-SIFT-006: Lateral Movement Indicators Playbook
## Lateral Movement Indicators — Static Image Analysis

**Objective:** High-fidelity detection and mapping of lateral movement within a network using digital forensic images and the SIFT Workstation toolset.

---

### Phase 1 — Evidence Integrity
- [ ] **Hash Verification:** Verify hash of all evidence against chain of custody.
- [ ] **Integrity Check:** Flag any mismatch before proceeding.

---

### Phase 2 — Memory Analysis
- [ ] **Process Enumeration:** Enumerate processes — flag remote execution tools (`psexec`, `wmiexec`, `winrm`, `dcom`).
- [ ] **Credential Audit:** Check for credential material in memory — LSASS access patterns, plaintext credentials in process memory.
- [ ] **Network State:** Check network connections — flag SMB, WMI, RDP, or WinRM connections to internal hosts.
- [ ] **Command Line Audit:** Check command lines — flag remote execution syntax targeting other hostnames or IPs.
- [ ] **Auth Structure Analysis:** Flag any pass-the-hash or pass-the-ticket indicators in authentication structures.

---

### Phase 3 — Super Timeline
- [ ] **Timeline Construction:** Build full timeline across all artifact sources.
- [ ] **Logon Correlation:** Flag logon events correlated with file execution on remote systems.
- [ ] **Staging Behavior:** Flag tools dropped and executed within a short window.
- [ ] **Share Access:** Flag access to `ADMIN$`, `C$`, or `IPC$` shares.
- [ ] **Cross-Host Correlation:** Correlate timestamps across multiple hosts if multi-image analysis is in scope.

---

### Phase 4 — Disk Artifacts
- [ ] **Execution History (Prefetch):** Flag `psexec`, `wmiexec`, `paexec`, `schtasks`, `at`, `sc` execution.
- [ ] **RAT Analysis:** Check for remote admin tool artifacts — `anydesk`, `atera`, `screenconnect`, `teamviewer` installed or run from unusual paths.
- [ ] **Remote Drops:** Check MFT for tools dropped into `ADMIN$` or `C$` remotely.
- [ ] **Execution History (ShimCache/Amcache):** Flag execution of binaries not in software inventory, especially on server images.
- [ ] **WMI Persistence:** Check for WMI persistence artifacts — `%SystemRoot%\System32\wbem\Repository`.
- [ ] **Scheduled Tasks:** Check for lateral movement via scheduled tasks — tasks created referencing remote UNC paths or credentials.

---

### Phase 5 — Event Log Analysis
- [ ] **Network Logons:** Flag network logons from unexpected sources (EID 4624 logon type 3).
- [ ] **Credential Reuse:** Flag explicit credential use (EID 4648) — key indicator of credential reuse across hosts.
- [ ] **Privilege Escalation:** Flag special privilege logons (EID 4672) — admin-level access on non-admin systems.
- [ ] **Share Access:** Flag SMB share access to `ADMIN$` / `C$` (EID 5140 / 5145).
- [ ] **Remote Service Creation:** Flag remote service creation (EID 7045) — common `psexec` artifact.
- [ ] **WMI Activity:** Flag WMI activity (EID 4688 — `wmiprvse.exe` spawning child processes).
- [ ] **Remote Tasks:** Flag remote scheduled task creation (EID 4698) from a remote source account.
- [ ] **RDP Patterns:** Flag RDP session open/close patterns across multiple accounts (EID 4778 / 4779).

---

---

### Phase 6 — Network IOC Extraction
- [ ] **Internal Mapping:** Extract internal IPs and hostnames referenced in disk and memory artifacts.
- [ ] **Path Mapping:** Map movement path — identify source host, pivot points, and target hosts.
- [ ] **Reconnaissance:** Flag any use of internal scanning tools (`nmap`, `netscan`, `adrecon`) — reconnaissance before movement.
- [ ] **Port Anomalies:** Flag connections over non-standard ports for SMB/RDP/WMI.

---

### Phase 7 — Score & Report
- [ ] **Aggregation:** Aggregate all flags into findings report.
- [ ] **Chain Mapping:** Map the lateral movement chain — origin $\rightarrow$ pivot $\rightarrow$ target.
- [ ] **MITRE Mapping:** Identify technique per MITRE ATT&CK (T1021 — Remote Services, T1047 — WMI, T1570 — Lateral Tool Transfer).
- [ ] **Final Output:** Score by severity — output structured findings file for analyst handoff.
