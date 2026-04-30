# PB-SIFT-002: Execution Indicators Playbook
## Execution Indicators — MITRE ATT&CK T1059

**Objective:** High-fidelity detection and analysis of execution techniques used by attackers to run code on a compromised system — command interpreters, scripting engines, WMI, scheduled tasks, and user-executed payloads.
**Specialist:** `sleuthkit`, `registry`, `memory`, `logs`, `windows`
**MITRE Mapping:** T1059 (Command and Scripting Interpreter), T1203 (Exploitation for Client Execution), T1204 (User Execution), T1053 (Scheduled Task/Job), T1047 (WMI)

---

## Phase 1 — Execution Artifact Inventory

**Goal:** Identify all execution-related artifacts in the image.

### 1.1 — Prefetch Analysis (`windows.analyze_prefetch`)
- [ ] Parse `C:\Windows\Prefetch\*.pf` files
- [ ] **Specialist Method:** `windows.analyze_prefetch(prefetch_dir)`
- [ ] Flag first-run timestamps, run counts, and loaded DLLs for:
  - `powershell.exe`, `pwsh.exe` (T1059.001)
  - `cmd.exe` (T1059.003)
  - `cscript.exe`, `wscript.exe` (T1059.005, T1059.007)
  - `python.exe`, `pythonw.exe` (T1059.006)
  - `wmic.exe`, `wmiprvse.exe` (T1047)
  - `schtasks.exe`, `taskeng.exe` (T1053)
  - `mshta.exe` (T1059.005, T1218.005)
  - `regsvr32.exe`, `rundll32.exe` (T1218.010, T1218.011)
- [ ] Cross-reference suspicious first-run times with incident timeline

### 1.2 — ShimCache Analysis (`windows.analyze_shimcache`)
- [ ] Extract ShimCache/AppCompatCache from SYSTEM hive
- [ ] **Specialist Method:** `windows.analyze_shimcache(system_hive)`
- [ ] Flag execution indicators for scripting hosts and LOLBAS binaries
- [ ] Note: ShimCache records path but not execution time — pair with Prefetch or Event Logs

### 1.3 — Amcache Analysis (`windows.analyze_amcache`)
- [ ] Parse `Amcache.hve` for program execution evidence
- [ ] **Specialist Method:** `windows.analyze_amcache(amcache_hive)`
- [ ] Focus on unsigned or rarely-seen binaries with execution timestamps
- [ ] Correlate SHA1 hashes with threat intelligence

### 1.4 — Scheduled Tasks (`registry.extract_keys`)
- [ ] Extract Task Scheduler registry and XML definitions
- [ ] **Specialist Method:** `registry.extract_keys(hive_path, key_path)` targeting:
  - `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks`
  - `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree`
  - `C:\Windows\System32\Tasks\` and `C:\Windows\SysWOW64\Tasks\`
- [ ] Parse `.job` files and `.xml` task definitions for malicious actions
- [ ] Flag tasks executing scripts (`*.ps1`, `*.vbs`, `*.js`, `*.bat`)

### 1.5 — WMI Repository (`sleuthkit.list_files` + `memory.extract_processes`)
- [ ] Extract `OBJECTS.DATA` from `C:\Windows\System32\wbem\Repository\`
- [ ] **Specialist Method:** `sleuthkit.list_files(evidence_path)` followed by strings analysis
- [ ] Flag embedded PowerShell or encoded commands in WMI persistence classes
- [ ] Correlate with `wmiprvse.exe` execution in Prefetch and memory

### 1.6 — PowerShell History & Logs (`sleuthkit.extract_strings`)
- [ ] Extract PowerShell command history:
  - `ConsoleHost_history.txt` paths per user profile
  - `C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`
- [ ] **Specialist Method:** `sleuthkit.extract_strings(evidence_path)` targeting history files
- [ ] Parse PowerShell Script Block Logging (Event ID 4104) if enabled
- [ ] Parse PowerShell Module Logging (Event ID 4103) if enabled
- [ ] Flag encoded commands (`-enc`, `-encodedCommand`, `FromBase64String`)
- [ ] Flag download cradles (`IEX`, `Invoke-Expression`, `Net.WebClient`, `Start-BitsTransfer`)

### 1.7 — Registry Run Keys (`registry.extract_keys`)
- [ ] Extract autorun locations from SOFTWARE and NTUSER.DAT hives:
  - `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
  - `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
  - `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
  - `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
  - `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`
- [ ] **Specialist Method:** `registry.extract_keys(hive_path, key_path)`
- [ ] Flag script-based persistence (`*.ps1`, `*.vbs`, `*.js`, `*.cmd`, `*.bat`)

### 1.8 — Winlogon & Shell Registry (`registry.extract_keys`)
- [ ] Extract Winlogon keys:
  - `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell`
  - `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit`
  - `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify`
- [ ] **Specialist Method:** `registry.extract_keys(hive_path, key_path)`
- [ ] Flag modifications to default shell (`explorer.exe`) or `userinit.exe`

### 1.9 — Service Execution (`sleuthkit.list_files` + `registry.extract_keys`)
- [ ] Extract service configurations from SYSTEM hive:
  - `HKLM\SYSTEM\CurrentControlSet\Services\`
- [ ] **Specialist Method:** `registry.extract_keys(system_hive, services_key)`
- [ ] Flag services executing scripts or non-standard binaries
- [ ] Cross-reference with `services.exe` and `svchost.exe` in memory

---

## Phase 2 — Memory-Based Execution Evidence

**Goal:** Confirm execution in volatile memory artifacts.

### 2.1 — Process Enumeration (`memory.extract_processes`)
- [ ] **Specialist Method:** `memory.extract_processes(image_path)`
- [ ] Flag presence of scripting hosts with command-line arguments:
  - `powershell.exe -enc ...`, `-nop`, `-w hidden`
  - `cmd.exe /c ...`, `/k ...`
  - `wscript.exe //B //E:vbscript ...`
  - `cscript.exe //B //E:jscript ...`
  - `mshta.exe javascript:...`, `vbscript:...`
  - `python.exe -c "..."`
- [ ] Flag parent-child anomalies (e.g., `winword.exe` spawning `powershell.exe`)

### 2.2 — DLL Injection & Loaded Modules (`memory.extract_dlls`)
- [ ] **Specialist Method:** `memory.extract_dlls(image_path)`
- [ ] Flag unusual DLLs loaded into scripting hosts
- [ ] Check for reflective DLL injection indicators in process memory

### 2.3 — Network in Memory (`memory.extract_network`)
- [ ] **Specialist Method:** `memory.extract_network(image_path)`
- [ ] Flag network connections from scripting processes
- [ ] Correlate with C2 indicators from Phase 3

### 2.4 — Command-Line Arguments (`memory.extract_processes`)
- [ ] Extract full command-line strings from process objects
- [ ] **Specialist Method:** `memory.extract_processes(image_path)` with `include_cmdline=True`
- [ ] Search for encoded commands, URLs, file paths, and suspicious parameters

---

## Phase 3 — Event Log Correlation

**Goal:** Confirm execution via Windows Event Logs.

### 3.1 — Windows Security Event Logs (`logs.parse_evtx`)
- [ ] **Specialist Method:** `logs.parse_evtx(evtx_path, event_ids=[4688, 4689, 4656, 4663])`
- [ ] Event ID 4688: Process Creation — capture command-line arguments
- [ ] Event ID 4689: Process Termination
- [ ] Filter for suspicious process names from Phase 1

### 3.2 — Sysmon Logs (`logs.parse_evtx`)
- [ ] **Specialist Method:** `logs.parse_evtx(sysmon_evtx, event_ids=[1, 3, 7, 8, 10, 11, 12, 13])`
- [ ] Event ID 1: Process Create — parent image, command line, hashes
- [ ] Event ID 3: Network Connect — detect C2 from scripts
- [ ] Event ID 7: Image Loaded — detect suspicious DLLs
- [ ] Event ID 8: CreateRemoteThread — injection detection
- [ ] Event ID 10: ProcessAccess — credential dumping attempts
- [ ] Event IDs 11/12/13: File/Registry operations by script processes

### 3.3 — PowerShell Operational Logs (`logs.parse_evtx`)
- [ ] **Specialist Method:** `logs.parse_evtx(powershell_evtx, event_ids=[4103, 4104])`
- [ ] Event ID 4104: Script Block Logging — captures entire script content
- [ ] Event ID 4103: Module Logging — captures module load events
- [ ] Decode Base64-encoded blocks automatically

### 3.4 — WMI Activity Logs (`logs.parse_evtx`)
- [ ] **Specialist Method:** `logs.parse_evtx(wmi_evtx, event_ids=[5857, 5858, 5859, 5860, 5861])`
- [ ] WMI Event Subscription creation (persistence indicator)

---

## Phase 4 — File System Evidence

**Goal:** Identify execution artifacts on disk.

### 4.1 — Script Files (`sleuthkit.list_files`)
- [ ] **Specialist Method:** `sleuthkit.list_files(evidence_path, extensions=['.ps1', '.vbs', '.js', '.bat', '.cmd', '.py', '.hta'])`
- [ ] Enumerate script files in user directories, temp folders, and suspicious paths
- [ ] Flag scripts with recent timestamps, unusual locations, or obfuscated content

### 4.2 — Download Cradles (`sleuthkit.extract_strings`)
- [ ] **Specialist Method:** `sleuthkit.extract_strings(evidence_path, patterns=['IEX', 'Invoke-Expression', 'Net.WebClient', 'Start-BitsTransfer', 'DownloadString', 'DownloadFile'])`
- [ ] Search temp directories and browser caches for downloaded scripts
- [ ] Correlate with browser history (PB-SIFT-022) if applicable

### 4.3 — Alternate Data Streams (`sleuthkit.list_files`)
- [ ] **Specialist Method:** `sleuthkit.list_files(evidence_path, show_ads=True)`
- [ ] Flag Zone.Identifier ADS from downloaded executables
- [ ] Search for hidden data in ADS on script files

---

## Phase 5 — Correlation & Timeline

**Goal:** Build unified execution timeline.

### 5.1 — Timeline Integration (`plaso.create_timeline`)
- [ ] **Specialist Method:** `plaso.create_timeline(evidence_paths)`
- [ ] Correlate Prefetch, ShimCache, Amcache, Registry, and Event Log timestamps
- [ ] Identify first execution, repeated execution, and termination times

### 5.2 — Cross-Artifact Validation
- [ ] Execution in Prefetch → Confirm in ShimCache → Confirm in Event Logs
- [ ] Memory process → Registry run key → File system script
- [ ] Flag gaps where one artifact confirms but another contradicts

---

## Phase 6 — Scoring & Output

**Goal:** Prioritize findings for analyst handoff.

- [ ] **Severity Matrix:**
  - **Critical:** PowerShell with encoded C2 commands, WMI persistence, scheduled tasks with remote payloads
  - **High:** Script execution from temp, unusual LOLBAS abuse, suspicious parent-child chains
  - **Medium:** One-time script execution, standard tool misuse, user-initiated execution
  - **Low:** Legitimate administrative scripts, standard scheduled tasks

- [ ] **MITRE ATT&CK Mapping:**
  - T1059.001 — PowerShell
  - T1059.003 — Windows Command Shell
  - T1059.005 — Visual Basic
  - T1059.006 — Python
  - T1059.007 — JavaScript
  - T1203 — Exploitation for Client Execution
  - T1204.001 — User Execution: Malicious Link
  - T1204.002 — User Execution: Malicious File
  - T1053.005 — Scheduled Task/Job: Scheduled Task
  - T1047 — Windows Management Instrumentation
  - T1218.005 — System Binary Proxy Execution: Mshta
  - T1218.010 — System Binary Proxy Execution: Regsvr32
  - T1218.011 — System Binary Proxy Execution: Rundll32

- [ ] **Structured Output:** JSON with process details, timestamps, command lines, hashes, and severity scores
- [ ] **Analyst Handoff:** Bundle memory dumps, prefetch files, registry hives, and event logs for deep analysis
