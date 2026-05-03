# PB-SIFT-010: Living-off-the-Land (LOTL) Indicators Playbook
## Living-off-the-Land (LOTL) Indicators — Static Image Analysis

**Objective:** High-fidelity detection of "Living-off-the-Land" (LotL) techniques, where attackers use legitimate, pre-installed system binaries (LOLBins) to conduct malicious activity while avoiding detection by traditional antivirus/EDR.
**Specialist:** `memory, sleuthkit, registry, logs`

---

### Phase 1 — Evidence Integrity
- [ ] **Hash Verification:** Verify hash of all evidence against chain of custody.
- [ ] **Integrity Check:** Flag any mismatch before proceeding.

---

### Phase 2 — Memory Analysis
- [ ] **Process Enumeration:** Enumerate processes — flag native Windows binaries running from unexpected paths or with unusual parent processes.
- [ ] **Command Line Audit:** Check command lines of all LOLBin processes — flag encoded, obfuscated, or unusually long arguments.
- [ ] **Parentage Analysis:** Flag `powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe` spawned from Office, browser, or email processes.
- [ ] **Fileless Detection:** Check for fileless execution patterns — flag scripts or payloads running entirely in memory with no disk binary.
- [ ] **DLL Loading:** Flag `rundll32.exe` or `regsvr32.exe` loading DLLs from network paths or temp locations.

---

### Phase 3 — Super Timeline
- [ ] **Timeline Construction:** Build full timeline across all artifact sources.
- [ ] **Temporal Anomalies:** Flag LOLBin execution at unusual hours or in rapid succession.
- [ ] **Chain Analysis:** Flag chained LOLBin usage — one native tool invoking another (e.g., `cmd.exe` $\rightarrow$ `powershell.exe` $\rightarrow$ `certutil.exe`).
- [ ] **Post-Access Correlation:** Flag LOLBin execution immediately following initial access event — phishing open, RDP logon, or web shell activity.
- [ ] **Activity Mapping:** Correlate LOLBin activity with persistence installation, credential theft, or lateral movement timestamps.

---

### Phase 4 — Disk Artifacts
- [ ] **Execution History (Prefetch):** Check prefetch for execution of the following — flag any with unusual arguments or paths:

| Binary | Abuse Technique |
| :--- | :--- |
| `powershell.exe` | Encoded commands, download cradles, AMSI bypass |
| `cmd.exe` | Script execution, chaining, obfuscation |
| `wscript.exe` / `cscript.exe` | Malicious JS/VBS execution |
| `mshta.exe` | HTA payload execution |
| `rundll32.exe` | DLL execution, proxy execution |
| `regsvr32.exe` | Squiblydoo — COM scriptlet execution |
| `certutil.exe` | File download, base64 decode |
| `bitsadmin.exe` | File download, persistence |
| `msiexec.exe` | Remote MSI execution |
| `wmic.exe` | Remote execution, reconnaissance |
| `schtasks.exe` | Scheduled task creation |
| `at.exe` | Legacy task scheduling |
| `sc.exe` | Service creation and manipulation |
| `net.exe` / `net1.exe` | User/group enumeration and modification |
| `nltest.exe` | Domain trust enumeration |
| `whoami.exe` | Privilege and identity discovery |
| `ipconfig.exe` / `systeminfo.exe` | Host reconnaissance |
| `tasklist.exe` / `taskkill.exe` | Process discovery and termination |
| `reg.exe` | Registry read/write/export |
| `expand.exe` | File decompression and staging |

- [ ] **Execution History (ShimCache/Amcache):** Flag LOLBins executed in unusual sequences or from non-standard paths.
- [ ] **Script Analysis:** Check for scripts dropped on disk — flag `.ps1`, `.vbs`, `.js`, `.hta`, `.bat` in user-writable locations.
- [ ] **Obfuscation Search:** Check for encoded or obfuscated script content in temp or staging directories.
- [ ] **Decoded Output:** Check for `certutil` decoded output files — flag any binary output adjacent to encoded input files.
- [ ] **Base64 Decode Workflow:** When `-enc` or `-encodedCommand` arguments are found in EID 4688 or Prefetch:
    - **Command:** `echo '<base64_string>' | base64 -d | strings` — decode and extract readable strings
    - **Command:** `echo '<base64_string>' | base64 -d | iconv -f UTF-16LE -t UTF-8` — PowerShell `-enc` uses UTF-16LE encoding; pipe through iconv to get readable output
    - Flag URLs, IPs, file paths, and cmdlets in decoded output
    - **Command (multi-layer):** `python3 -c "import base64,sys; d=base64.b64decode(sys.argv[1]); print(d.decode('utf-16-le','ignore'))" '<base64>'`
- [ ] **PowerShell Obfuscation Pattern Detection:**
    - Flag `[char]` casting chains: `[char]73 + [char]69 + [char]88` = `IEX`
    - Flag `$env:` variable string concatenation: `$env:ComSpec[4,15,25] -join ''` = obfuscated `cmd`
    - Flag `-f` format operator: `'{0}{1}' -f 'Invoke-','Expression'`
    - Flag `[Convert]::FromBase64String` + `[Text.Encoding]::Unicode.GetString` — in-memory decode pattern
    - **Tool:** `floss` — extract obfuscated strings from binaries: `floss --no-static-strings <binary>`

---

### Phase 5 — Event Log Analysis
- [ ] **PowerShell Auditing:** Flag PowerShell script block logs with obfuscation patterns (EID 4103 / 4104) — `char()`, `join`, `replace`, `-f` format operator abuse.
- [ ] **Flagged Arguments:** Flag `powershell.exe` launched with `-nop`, `-w hidden`, `-enc`, `-noni` flags (EID 4688).
- [ ] **Unexpected Spawning:** Flag `mshta.exe` or `wscript.exe` execution from Office or browser process (EID 4688).
- [ ] **Certutil Abuse:** Flag `certutil.exe` with `-decode`, `-urlcache`, or `-split` arguments (EID 4688).
- [ ] **Squiblydoo Detection:** Flag `regsvr32.exe` with `/s /n /u /i:` pattern (EID 4688).
- [ ] **WMI Process Spawning:** Flag `wmic.exe` with process call create — remote or local process spawning (EID 4688).
- [ ] **BITS Jobs:** Flag `bitsadmin.exe` transfer job creation (EID 4688 / BITS client operational log).
- [ ] **Recon Chain:** Flag any LOLBin spawning `net.exe`, `nltest.exe`, or `whoami.exe` in sequence — reconnaissance chain.

---

---

### Phase 6 — Network IOC Extraction
- [ ] **Script/CLI Harvesting:** Extract URLs and domains from script files and command line arguments on disk.
- [ ] **Cradle Destinations:** Flag download cradle destinations — URLs passed to `certutil`, `bitsadmin`, `Invoke-WebRequest`, `curl`.
- [ ] **Remote Targets:** Flag WMI or DCOM lateral movement targets referenced in command lines.
- [ ] **Intel Enrichment:** Enrich all IOCs against threat intel feeds.
- [ ] **Infrastructure Mapping:** Flag any staging infrastructure — domains or IPs used solely for payload delivery.

---

### Phase 7 — Score & Report
- [ ] **Aggregation:** Aggregate all flags into findings report.
- [ ] **MITRE Mapping:** Identify technique per MITRE ATT&CK:
    - **T1059.001:** PowerShell
    - **T1059.003:** Windows Command Shell
    - **T1059.005:** Visual Basic / Wscript
    - **T1218.005:** Mshta
    - **T1218.011:** Rundll32
    - **T1218.010:** Regsvr32
    - **T1140:** Certutil
    - **T1197:** BITSAdmin
    - **T1047:** WMI
    - **T1218:** Signed Binary Proxy Execution
    - **T1027:** Obfuscated Files or Information
    - **T1620:** Fileless Execution
- [ ] **Chain Reconstruction:** Reconstruct attacker command chain — map full LOLBin execution sequence from initial access to final action.
- [ ] **Final Output:** Score by severity — output structured findings file for analyst handoff.
