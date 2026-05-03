# PB-SIFT-011: Web Shell Detection Playbook
## Web Shell Detection — MITRE ATT&CK T1505.003, T1190, T1059

**Objective:** High-fidelity detection and analysis of web shell implants on compromised web servers — covering log analysis, filesystem artifact examination, signature pattern matching, process parent-chain analysis, and IIS-specific artifacts — using the SIFT Workstation toolset.
**Specialist:** `sleuthkit`, `memory`, `logs`, `windows`
**MITRE Mapping:** T1505.003 (Server Software Component: Web Shell), T1190 (Exploit Public-Facing Application), T1059 (Command and Scripting Interpreter), T1059.001 (PowerShell), T1059.003 (Windows Command Shell), T1059.004 (Unix Shell)

---

## Phase 1 — Web Server Log Analysis

**Goal:** Identify anomalous HTTP requests in web server access logs that indicate web shell deployment or interaction.

### 1.1 — IIS Log Parsing (`logs.parse_evtx`)
- [ ] **Specialist Method:** `logs.parse_evtx(evtx_path)` targeting IIS `u_ex*.log` files in `C:\inetpub\logs\LogFiles\W3SVC*\`
- [ ] Parse fields: `date`, `time`, `c-ip`, `cs-method`, `cs-uri-stem`, `cs-uri-query`, `sc-status`, `sc-bytes`, `cs(User-Agent)`
- [ ] Flag all POST requests returning HTTP 200 to files with extensions `.asp`, `.aspx`, `.php`, `.jsp`, `.cfm`, `.shtml`
- [ ] Flag unusually large `sc-bytes` (response size) on POST requests — attacker receiving command output
- [ ] Flag POST requests to static asset extensions (`.jpg`, `.png`, `.gif`, `.css`, `.ico`) — web shell hidden as image or stylesheet
- [ ] Flag URIs containing script-like query strings: `?cmd=`, `?exec=`, `?c=`, `?command=`, `?pass=`, `?shell=`

### 1.2 — Apache / Nginx Log Parsing (`logs.parse_evtx`)
- [ ] **Specialist Method:** `logs.parse_evtx(evtx_path)` targeting `/var/log/apache2/access.log`, `/var/log/nginx/access.log`
- [ ] Flag POST requests to PHP/CGI scripts outside the expected web application file list
- [ ] Flag HTTP 200 responses to requests with command-injection-style query strings (`%3B`, URL-encoded semicolons, pipe characters)
- [ ] Flag requests with anomalous or minimal `User-Agent` strings: empty, `curl/`, `python-requests/`, `Go-http-client/`
- [ ] Correlate source IPs with high error rates (4xx) followed by a successful POST — indicates scanning and web shell deployment pattern

### 1.3 — Request Pattern Anomaly Analysis
- [ ] Identify single-IP POST frequency exceeding baseline — rapid successive POSTs indicate automated shell interaction
- [ ] Flag low-volume targeted POSTs (1–5 requests per session) to a specific URI — manual attacker interaction pattern
- [ ] Flag requests at unusual hours (off-hours or holiday periods) to server-side scripts
- [ ] Flag `Referer` header absent on POST requests to web application pages that normally require navigation

---

## Phase 2 — Filesystem Analysis

**Goal:** Identify web shell files on disk by location, timestamp, and extension anomalies.

### 2.1 — Web Root File Enumeration (`sleuthkit.list_files`)
- [ ] **Specialist Method:** `sleuthkit.list_files(evidence_path)` targeting:
  - `C:\inetpub\wwwroot\` (IIS default)
  - `C:\inetpub\wwwroot\*\` (virtual directories and application paths)
  - `/var/www/html/` (Apache default, Linux)
  - `/usr/share/nginx/html/` (Nginx default, Linux)
  - Custom web root paths extracted from `applicationHost.config` or `httpd.conf`
- [ ] Enumerate all `.asp`, `.aspx`, `.php`, `.jsp`, `.cfm`, `.shtml`, `.cgi` files
- [ ] Flag files created after the web application's known deployment date
- [ ] Flag files in upload directories or image/media directories with script extensions

### 2.2 — Timestamp Comparison
- [ ] Compare Created, Modified, and MFT Entry Modified times — flag files where Modified < Created (timestamp manipulation indicator)
- [ ] Compare new script file timestamps against web application deployment artifacts in MFT
- [ ] Flag script files whose timestamps do not align with any deployment or change management window
- [ ] Identify files with $STANDARD_INFORMATION and $FILE_NAME timestamp discrepancies — timestomping indicator

### 2.3 — Alternate Data Streams (`sleuthkit.list_files`)
- [ ] **Specialist Method:** `sleuthkit.list_files(evidence_path, show_ads=True)`
- [ ] Flag web files missing `Zone.Identifier` ADS — server-created files should not have Zone.Identifier; files uploaded from external sources should
- [ ] Flag unexpected ADS on web files — attacker may hide web shell content or configuration in ADS
- [ ] Cross-reference ADS creation timestamps with web access log POST timestamps

### 2.4 — Deleted File Recovery (`sleuthkit.list_files`)
- [ ] **Specialist Method:** `sleuthkit.list_files(evidence_path)` with deleted file recovery
- [ ] Recover deleted web shell files from unallocated space within web root directories
- [ ] Check Recycle Bin artifacts for recently deleted script files from web root paths
- [ ] Flag partial file carving results for script-like content patterns

---

## Phase 3 — Web Shell Signature Detection

**Goal:** Identify web shell code patterns in filesystem and memory artifacts.

### 3.1 — Code Pattern Scanning (`sleuthkit.extract_strings`)
- [ ] **Specialist Method:** `sleuthkit.extract_strings(evidence_path)` targeting web root directories for patterns:
  - `eval(` — dynamic code execution (PHP, ASP, JSP)
  - `base64_decode` — obfuscated payload delivery
  - `system($_` — PHP shell command via superglobal
  - `exec($_` — PHP exec via superglobal
  - `passthru(` — PHP passthru shell execution
  - `cmd.exe /c` — Windows command execution string
  - `powershell -` — PowerShell invocation from web shell
  - `<script runat="server">` — ASP.NET server-side script tag
  - `HttpServerUtility` — ASP.NET server object access
  - `Response.Write(shell_exec(` — PHP output of shell execution
- [ ] Flag any script file containing two or more of these patterns — high-confidence web shell

### 3.2 — Obfuscation Pattern Detection (`sleuthkit.extract_strings`)
- [ ] **Specialist Method:** `sleuthkit.extract_strings(evidence_path)` for obfuscation patterns:
  - `@eval(gzinflate` — PHP compressed+encoded web shell
  - `str_rot13` — character rotation obfuscation
  - `gzuncompress(` / `gzdeflate(` — compression-based obfuscation
  - `preg_replace(`.*/e` — PHP regex-based code execution
  - `assert(` — PHP assert-based code execution
  - `FromBase64String` — .NET Base64 decode
  - `Convert.FromBase64String` — .NET Base64 decode pattern
- [ ] Flag any file with encoded/obfuscated function chains — tier the severity by obfuscation depth

### 3.3 — China Chopper & Common Web Shell Signatures (`sleuthkit.extract_strings`)
- [ ] **Specialist Method:** `sleuthkit.extract_strings(evidence_path)` targeting known web shell fingerprints
- [ ] Flag `eval(Request.Item["` — China Chopper ASPX one-liner
- [ ] Flag `<%@ Page Language="Jscript"%>` combined with `eval(Request` — China Chopper JScript variant
- [ ] Flag `<? php @eval($_POST` or `<?php @eval($_GET` — generic PHP backdoor
- [ ] Flag files less than 500 bytes in web root with script extensions — minimalist one-liner web shells

---

## Phase 4 — Process Parent-Chain Analysis

**Goal:** Confirm web shell execution by identifying web server worker processes spawning command interpreters.

### 4.1 — Web Worker Process Children (`memory.extract_processes`)
- [ ] **Specialist Method:** `memory.extract_processes(image_path)`
- [ ] Enumerate all processes — build parent-child tree for web server worker processes
- [ ] Flag the following parent-child combinations as **CRITICAL**:
  - `w3wp.exe` spawning `cmd.exe` or `powershell.exe` (IIS)
  - `httpd.exe` spawning `cmd.exe` or `sh` (Apache Windows)
  - `nginx` spawning `sh` or `bash` (Nginx Linux)
  - `tomcat` or `java` spawning `sh`, `bash`, or `cmd.exe` (Tomcat/J2EE)
  - `php-fpm` or `php-cgi` spawning `sh` or `bash` (PHP-FPM Linux)
- [ ] Capture full command-line arguments for all flagged child processes
- [ ] Flag any grandchild processes spawned by the above (e.g., `cmd.exe` → `net.exe`, `whoami.exe`, `ipconfig.exe`)

### 4.2 — Command-Line Argument Analysis (`memory.extract_processes`)
- [ ] **Specialist Method:** `memory.extract_processes(image_path)` with `include_cmdline=True`
- [ ] Extract full command lines for all `cmd.exe`, `powershell.exe`, `sh`, `bash` processes with web server parent
- [ ] Flag encoded PowerShell commands (`-enc`, `-encodedCommand`) — obfuscated attacker commands
- [ ] Flag reconnaissance commands: `whoami`, `net user`, `net group`, `ipconfig /all`, `systeminfo`, `id`, `uname -a`
- [ ] Flag lateral movement commands: `net use`, `wmic`, `psexec`, `ssh`, `scp`

### 4.3 — Network Connections from Web Processes (`memory.extract_processes`)
- [ ] **Specialist Method:** `memory.extract_processes(image_path)` with network connection enumeration
- [ ] Flag outbound connections from `w3wp.exe`, `httpd`, or `nginx` to non-standard external IPs
- [ ] Flag reverse shell connection patterns: outbound connection from web process to high port on external IP
- [ ] Correlate connection timestamps with web access log POST timestamps

---

## Phase 5 — Event Log Correlation

**Goal:** Confirm web shell execution through Windows Event Logs.

### 5.1 — Process Creation by IIS Worker (`logs.parse_evtx`)
- [ ] **Specialist Method:** `logs.parse_evtx(evtx_path, event_ids=[4688])`
- [ ] Filter EID 4688 (Process Created) for creator subject account matching `IIS APPPOOL\*`
- [ ] Flag any `cmd.exe`, `powershell.exe`, `cscript.exe`, `wscript.exe` created under IIS application pool identity
- [ ] Capture `NewProcessName`, `CommandLine`, `ParentProcessName`, and timestamp for all flagged events
- [ ] Flag process creation chains more than two levels deep from IIS worker identity

### 5.2 — Scheduled Task Creation Post-Execution (`logs.parse_evtx`)
- [ ] **Specialist Method:** `logs.parse_evtx(evtx_path, event_ids=[4698, 4702, 4699])`
- [ ] EID 4698 (Scheduled task created): flag tasks created within minutes of a web shell interaction in the access log
- [ ] EID 4702 (Scheduled task updated): flag modifications to existing tasks following web shell access
- [ ] EID 4699 (Scheduled task deleted): flag tasks deleted shortly after creation — anti-forensic cleanup
- [ ] Cross-reference task creation timestamps with IIS log POST timestamps and EID 4688 process creation events

### 5.3 — Sysmon Web Process Events (`logs.parse_evtx`)
- [ ] **Specialist Method:** `logs.parse_evtx(sysmon_evtx, event_ids=[1, 3, 11])`
- [ ] EID 1 (Process Create): extract full command lines for processes spawned by web server workers
- [ ] EID 3 (Network Connect): flag outbound connections initiated by web server worker processes
- [ ] EID 11 (File Created): flag files created by web server worker processes outside web root (staging, persistence)

---

## Phase 6 — IIS-Specific Artifacts

**Goal:** Detect IIS configuration tampering and module implants that provide persistent web shell functionality.

### 6.1 — ApplicationHost.config Analysis (`sleuthkit.list_files`)
- [ ] **Specialist Method:** `sleuthkit.list_files(evidence_path)` targeting `%windir%\System32\inetsrv\config\applicationHost.config`
- [ ] Parse for unauthorized virtual directory additions — flag paths pointing outside the expected web root
- [ ] Flag additions to `<modules>` section — native IIS module implants provide persistent code execution
- [ ] Flag additions to `<handlers>` — new handler mappings for unusual extensions or wildcard handlers
- [ ] Compare current `applicationHost.config` with VSS shadow copy version — flag any delta

### 6.2 — ISAPI Filter & Module Detection (`registry.extract_keys`)
- [ ] **Specialist Method:** `registry.extract_keys(hive_path, key_path)` targeting:
  - `HKLM\SOFTWARE\Microsoft\InetStp\`
  - `HKLM\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters\Filter DLLs`
  - `HKLM\SYSTEM\CurrentControlSet\Services\W3SVC\`
- [ ] Flag ISAPI filters registered outside `%windir%\System32\inetsrv\`
- [ ] Flag native module DLLs registered with IIS from non-standard paths
- [ ] Correlate module registration timestamps with web shell access timestamps from IIS logs

### 6.3 — AppCmd.exe Usage (`windows.analyze_prefetch`)
- [ ] **Specialist Method:** `windows.analyze_prefetch(prefetch_dir)`
- [ ] Flag `appcmd.exe` execution — IIS command-line administration tool frequently used post-compromise
- [ ] Flag `appcmd.exe` execution run-times outside normal administrative maintenance windows
- [ ] Cross-reference `appcmd.exe` Prefetch first-run time with IIS log anomaly timestamps

### 6.4 — Web.config Modifications (`sleuthkit.list_files`)
- [ ] **Specialist Method:** `sleuthkit.list_files(evidence_path)` enumerating all `web.config` files in IIS application directories
- [ ] Flag `web.config` files modified within the incident window
- [ ] Check for `<httpHandlers>` or `<handlers>` entries pointing to malicious DLLs or scripts
- [ ] Flag `customErrors mode="Off"` additions — disabling error suppression exposes server details to attacker

---

## Phase 7 — Timeline Reconstruction

**Goal:** Establish an end-to-end attack timeline from initial exploitation to persistent access.

### 7.1 — Web Shell Deployment Timeline
- [ ] Anchor Point 1: Identify the initial exploit request in web access logs (anomalous POST or GET with exploit payload)
- [ ] Anchor Point 2: Identify the web shell file creation timestamp in MFT — correlate with Anchor Point 1 timestamp
- [ ] Anchor Point 3: Identify the first web shell interaction in access logs (POST to newly created file)
- [ ] Correlate web access log POST timestamp → EID 4688 process creation (under IIS worker identity) → filesystem artifact creation

### 7.2 — Post-Exploitation Activity Timeline
- [ ] Chain: Web shell POST → process creation (EID 4688) → outbound network connect (Sysmon EID 3) → scheduled task creation (EID 4698)
- [ ] Flag the full time delta between initial deployment and first command execution
- [ ] Identify dwell time between initial access and any lateral movement or data staging activity
- [ ] Flag any log gap or EID 1102 (audit log cleared) that obscures portions of the timeline

### 7.3 — Timeline Integration (`plaso.create_timeline`)
- [ ] **Specialist Method:** `plaso.create_timeline(evidence_paths)`
- [ ] Incorporate IIS logs, Security.evtx, Sysmon.evtx, MFT, Prefetch, and registry hives into unified timeline
- [ ] Sort and filter by web server process activity window
- [ ] Export filtered timeline artifact for analyst handoff

---

## Phase 8 — Scoring & Output

**Goal:** Prioritize findings for analyst handoff.

- [ ] **Severity Matrix:**
  - **Critical:** Web server worker process (`w3wp.exe`, `httpd`, `nginx`) spawning `cmd.exe` or shell; web shell file confirmed present in web root with command execution patterns; IIS native module implant registered
  - **High:** Web shell file identified on disk with obfuscated code; POST requests to static files returning 200 with large response bytes; scheduled task created immediately after web shell interaction; ISAPI filter from non-standard path
  - **Medium:** Suspicious script file in web root with recent timestamp but no confirmed interaction; anomalous POST pattern without confirmed 200 response; `appcmd.exe` executed outside change window
  - **Low:** Single anomalous POST request with 4xx response; script file in web root with matching deployment timestamp; legitimate admin tool execution during business hours

- [ ] **MITRE ATT&CK Mapping:**
  - T1505.003 — Server Software Component: Web Shell
  - T1190 — Exploit Public-Facing Application
  - T1059.001 — Command and Scripting Interpreter: PowerShell
  - T1059.003 — Command and Scripting Interpreter: Windows Command Shell
  - T1059.004 — Command and Scripting Interpreter: Unix Shell
  - T1036.005 — Masquerading: Match Legitimate Name or Location
  - T1053.005 — Scheduled Task/Job: Scheduled Task
  - T1546.012 — Event Triggered Execution: Image File Execution Options Injection
  - T1071.001 — Application Layer Protocol: Web Protocols (C2 via HTTP/S)

- [ ] **SANS FOR508 Alignment:** Web shell detection via parent-process chain analysis (Phase 4) is a core FOR508 Advanced Incident Response topic. IIS log analysis and file system timeline correlation are covered in FOR500 Windows Forensic Analysis as key web server compromise indicators.

- [ ] **Structured Output:** JSON with file paths, hash values, access log entries, process chains, EID records, and severity scores
- [ ] **Analyst Handoff:** Bundle IIS logs, Security.evtx, Sysmon.evtx, web root directory image, MFT export, and memory dump for deep analysis
