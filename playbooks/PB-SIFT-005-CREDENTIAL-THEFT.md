# PB-SIFT-005: Credential Theft Indicators Playbook
## Credential Theft Indicators — Static Image Analysis

**Objective:** High-fidelity detection and analysis of credential harvesting and theft activity within a digital forensic image using the SIFT Workstation toolset.

---

### Phase 1 — Evidence Integrity
- [ ] **Hash Verification:** Verify hash of all evidence against chain of custody.
- [ ] **Integrity Check:** Flag any mismatch before proceeding.

---

### Phase 2 — Memory Analysis
- [ ] **LSASS Access:** Check for LSASS memory access — flag any process other than System or `lsass.exe` with a handle to LSASS.
- [ ] **Tool Detection:** Check for credential dumping tools in memory — flag `mimikatz`, `procdump`, `comsvcs.dll` MiniDump references.
- [ ] **Command Line Audit:** Check command lines — flag `sekurlsa`, `lsadump`, `dcsync`, `ntds` keywords.
- [ ] **Ticket Analysis:** Check for Kerberos ticket material — flag unusual TGT/TGS requests or golden/silver ticket artifacts.
- [ ] **Privilege Check:** Flag any process with `SeDebugPrivilege` that is not a known admin tool.

---

### Phase 3 — Super Timeline
- [ ] **Timeline Construction:** Build full timeline across all artifact sources.
- [ ] **Memory Access:** Flag access to `lsass.exe` memory within the timeline.
- [ ] **Hive Access:** Flag `NTDS.dit` or `SAM`/`SYSTEM` hive access or copying events.
- [ ] **Dump Creation:** Flag creation of dump files (`.dmp`, `.bin`, `.tmp`) in user-writable locations.
- [ ] **Harvest Correlation:** Correlate credential theft timestamps with subsequent logon events — confirms successful harvest.

---

### Phase 4 — Disk Artifacts
- [ ] **Dump File Search:** Check for dump files on disk — flag `.dmp` or suspiciously named `.tmp`/`.bin` files in temp or user paths.
- [ ] **NTDS Extraction:** Check for `NTDS.dit` copies outside of `%SystemRoot%\NTDS\` — **flag immediately as CRITICAL**.
- [ ] **Hive Copies:** Check for `SAM` and `SYSTEM` hive copies in non-standard locations.
- [ ] **Execution History (Prefetch):** Flag execution of `mimikatz`, `procdump`, `wce`, `pwdump`, `fgdump`, `secretsdump`.
- [ ] **VSS Abuse:** Check for VSS abuse — `NTDS.dit` commonly extracted via shadow copy without touching live file.
- [ ] **Registry Exports:** Check for registry exports of `HKLM\SAM`, `HKLM\SECURITY`, `HKLM\SYSTEM` via `reg save` or `reg export`.

---

### Phase 5 — Event Log Analysis
- [ ] **LSASS Events:** Flag LSASS access events (EID 4656 / 4663) — object access on `lsass.exe`.
- [ ] **DCSync Activity:** Flag DCSync activity — EID 4662 with replication directory access rights from a non-DC account.
- [ ] **Kerberoasting:** Flag Kerberoasting — EID 4769 with RC4 encryption type requests for service tickets.
- [ ] **AS-REP Roasting:** Flag AS-REP roasting — EID 4768 with pre-authentication disabled accounts.
- [ ] **Brute Force/Spray:** Flag brute force or password spray patterns — EID 4625 with multiple accounts from single source.
- [ ] **Network Auth:** Flag credential access via network (EID 4776) — NTLM authentication anomalies.
- [ ] **Registry Commands:** Flag `reg save` or `reg export` commands if process auditing is enabled (EID 4688).

---

### Phase 6 — YARA Scan
- [ ] **Tool Signatures:** Scan disk for known credential dumping tool signatures — `Mimikatz`, `LaZagne`, `Pypykatz`.
- [ ] **Pattern Matching:** Scan dump files for NTLM hash patterns or Kerberos ticket structures.
- [ ] **Module Strings:** Scan memory artifacts for `sekurlsa` or `lsadump` module strings.
- [ ] **Hit Documentation:** Flag any hits with tool name, location, and confidence level.

---

### Phase 7 — Network IOC Extraction
- [ ] **AD Enumeration:** Flag LDAP/LDAPS queries from non-standard hosts — possible AD enumeration prior to theft.
- [ ] **Replication Traffic:** Flag DCSync traffic patterns — replication requests from non-DC hosts.
- [ ] **Ticket Anomalies:** Flag Kerberos traffic anomalies — unusual ticket requests or forged PAC structures.
- [ ] **Buffer Extraction:** Extract any credential-related strings from network buffers in the image.

---

### Phase 8 — Score & Report
- [ ] **Aggregation:** Aggregate all flags into findings report.
- [ ] **MITRE Mapping:** Identify technique per MITRE ATT&CK:
    - **T1003.001:** OS Credential Dumping — LSASS
    - **T1003.002:** OS Credential Dumping — SAM
    - **T1003.003:** OS Credential Dumping — NTDS
    - **T1558.003:** Kerberoasting
    - **T1558.004:** AS-REP Roasting
    - **T1003.006:** DCSync
- [ ] **Scope Identification:** Flag which accounts are likely compromised based on artifacts.
- [ ] **Final Output:** Score by severity — output structured findings file for analyst handoff.
