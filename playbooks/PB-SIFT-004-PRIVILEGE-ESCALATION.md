# PB-SIFT-004: Privilege Escalation Indicators Playbook
## Privilege Escalation Indicators — MITRE ATT&CK T1548, T1134, T1068, T1055, T1574

**Objective:** High-fidelity forensic detection and analysis of privilege escalation techniques — token manipulation, UAC bypass, service/binary exploitation, DLL hijacking, scheduled task abuse, and Linux SUID/capability abuse — using the SIFT Workstation toolset.
**Specialist:** `memory`, `registry`, `logs`, `sleuthkit`, `windows`
**MITRE Mapping:** T1548 (Abuse Elevation Control Mechanism), T1134 (Access Token Manipulation), T1068 (Exploitation for Privilege Escalation), T1055 (Process Injection), T1574 (Hijack Execution Flow)

---

## Phase 1 — Token & Privilege Analysis

**Goal:** Identify processes holding elevated privileges or impersonated tokens inconsistent with their parent context.

### 1.1 — Process Privilege Enumeration (`memory.extract_processes`)
- [ ] **Specialist Method:** `memory.extract_processes(image_path)` with `vol windows.privs`
- [ ] Enumerate all processes — capture privilege token sets and enabled privileges
- [ ] Flag any non-system process holding `SeDebugPrivilege` — universal process injection enabler
- [ ] Flag `SeTcbPrivilege` (Act as part of the OS) outside `lsass.exe`, `services.exe`, `winlogon.exe`
- [ ] Flag `SeLoadDriverPrivilege`, `SeRestorePrivilege`, `SeTakeOwnershipPrivilege` in user-context processes
- [ ] Cross-reference privilege holders against legitimate service account baseline

### 1.2 — SID & Group Membership Audit (`memory.extract_processes`)
- [ ] **Specialist Method:** `memory.extract_processes(image_path)` with `vol windows.getsids`
- [ ] Extract Security Identifiers (SIDs) from all process tokens
- [ ] Flag processes running under `S-1-16-12288` (High Integrity) owned by interactive user accounts
- [ ] Flag unexpected `S-1-5-18` (SYSTEM) or `S-1-5-19/20` (Network/Local Service) token ownership
- [ ] Identify impersonation tokens — flag thread-level token divergence from process token
- [ ] Note processes with both a primary token and an impersonation token at HIGH or SYSTEM level

### 1.3 — Impersonation Token Artifacts (`registry.extract_keys`)
- [ ] **Specialist Method:** `registry.extract_keys(hive_path, key_path)` targeting `HKLM\SYSTEM\CurrentControlSet\Services\`
- [ ] Check for services configured to run as user accounts with `SeImpersonatePrivilege`
- [ ] Flag Named Pipe impersonation artifacts — identify writable named pipes accessible to lower-privileged processes
- [ ] Correlate with EID 4672 (Special privileges assigned to new logon) in event logs

---

## Phase 2 — UAC Bypass Detection

**Goal:** Detect registry-based and COM-based UAC bypass techniques used to silently elevate without a UAC prompt.

### 2.1 — Registry Hijack Keys (`registry.extract_keys`)
- [ ] **Specialist Method:** `registry.extract_keys(hive_path, key_path)` targeting:
  - `HKCU\Software\Classes\ms-settings\shell\open\command`
  - `HKCU\Software\Classes\{CLSID}\shell\open\command`
  - `HKCU\Software\Classes\mscfile\shell\open\command`
  - `HKCU\Software\Classes\exefile\shell\open\command`
- [ ] Flag any value present under these keys — their existence is a UAC bypass indicator
- [ ] Capture the `DelegateExecute` value alongside `(Default)` — both are required for `fodhelper`/`eventvwr` bypass
- [ ] Note modification timestamps on all flagged keys — correlate with incident timeline

### 2.2 — Auto-Elevated Binary Prefetch (`windows.analyze_prefetch`)
- [ ] **Specialist Method:** `windows.analyze_prefetch(prefetch_dir)`
- [ ] Flag execution of auto-elevated binaries commonly abused for UAC bypass:
  - `fodhelper.exe` — T1548.002 (UAC bypass via `ms-settings` hijack)
  - `eventvwr.exe` — T1548.002 (UAC bypass via `mscfile` hijack)
  - `sdclt.exe` — T1548.002 (UAC bypass via `exefile` hijack)
  - `cmstp.exe` — T1218.003 (UAC bypass via INF auto-elevation)
  - `wscript.exe` / `cscript.exe` invoked from auto-elevated COM path
- [ ] Cross-reference first-run timestamps with registry key modification timestamps

### 2.3 — COM Object & ICMLuaUtil Detection (`registry.extract_keys`)
- [ ] **Specialist Method:** `registry.extract_keys(hive_path, key_path)` targeting `HKCU\Software\Classes\CLSID\`
- [ ] Flag CLSID registrations in HKCU that shadow entries in `HKLM\SOFTWARE\Classes\CLSID\` — COM hijack indicator
- [ ] Specifically check for `{3E5FC7F9-9A51-4367-9063-A120244FBEC7}` (ICMLuaUtil) hijack entries
- [ ] Flag any COM server registered in HKCU pointing to a non-system binary path
- [ ] Check `HKCU\Software\Classes\Wow6432Node\CLSID\` for 32-bit COM hijack entries

### 2.4 — Elevated Process Verification (`memory.extract_processes`)
- [ ] **Specialist Method:** `memory.extract_processes(image_path)`
- [ ] Identify processes with `High` integrity level spawned from `Medium` integrity parent processes
- [ ] Flag `consent.exe` invocations outside normal user-prompted elevation flow
- [ ] Flag parent-child chains: `explorer.exe` → `fodhelper.exe` → `cmd.exe` (CRITICAL indicator)

---

## Phase 3 — Service & Binary Exploitation

**Goal:** Identify misconfigured services exploitable for privilege escalation to SYSTEM.

### 3.1 — Unquoted Service Path Audit (`registry.extract_keys`)
- [ ] **Specialist Method:** `registry.extract_keys(system_hive, "SYSTEM\\CurrentControlSet\\Services")`
- [ ] Extract `ImagePath` values for all services — flag any unquoted path containing spaces (e.g., `C:\Program Files\My Service\svc.exe`)
- [ ] For each unquoted path, enumerate parent directories to identify attacker-writable positions (e.g., `C:\Program.exe`)
- [ ] Flag services running as `LocalSystem` with unquoted paths — direct SYSTEM escalation if writable

### 3.2 — Weak ACL on Service Binary Paths (`sleuthkit.list_files`)
- [ ] **Specialist Method:** `sleuthkit.list_files(evidence_path)` enumerating service binary directories
- [ ] Check effective ACLs on service executable files and their parent directories
- [ ] Flag any service binary whose directory grants `Write` or `Modify` to `Authenticated Users`, `Everyone`, or low-privileged groups
- [ ] Flag service binaries replaced or modified within the incident timeframe (MFT timestamp analysis)
- [ ] Correlate modified service binaries with service start events in System event log

### 3.3 — Writable Directories in System PATH (`registry.extract_keys`)
- [ ] **Specialist Method:** `registry.extract_keys(system_hive, "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment")`
- [ ] Extract the system `PATH` variable — enumerate all directories listed
- [ ] Flag any PATH directory that grants write access to non-administrative accounts
- [ ] Flag PATH hijacking opportunities — missing directories in PATH that an attacker could create

### 3.4 — Service Registry Permission Audit (`registry.extract_keys`)
- [ ] **Specialist Method:** `registry.extract_keys(system_hive, "SYSTEM\\CurrentControlSet\\Services")`
- [ ] Check registry key ACLs on service entries — flag keys writable by `Authenticated Users`
- [ ] Flag services with modified `Start`, `ImagePath`, or `ObjectName` values inconsistent with baseline
- [ ] Flag newly created service entries with timestamps falling within the investigation window

---

## Phase 4 — DLL Hijacking

**Goal:** Detect DLL search order abuse and sideloading used to execute attacker code in a privileged process context.

### 4.1 — DLL Search Order Abuse (`sleuthkit.list_files`)
- [ ] **Specialist Method:** `sleuthkit.list_files(evidence_path)` across application directories
- [ ] Enumerate application directories for DLLs that shadow system DLLs (`System32`, `SysWOW64`)
- [ ] Flag non-system DLLs placed in the same directory as auto-elevated or high-privilege executables
- [ ] Check for `wlbsctrl.dll`, `cryptbase.dll`, `rasapi32.dll`, `MSASN1.dll` in non-system paths — common hijack targets

### 4.2 — Loaded DLL List vs Expected Baseline (`memory.extract_processes`)
- [ ] **Specialist Method:** `memory.extract_processes(image_path)` with DLL enumeration
- [ ] For each high-integrity or SYSTEM process, enumerate loaded DLLs and their load paths
- [ ] Flag DLLs loaded from `%TEMP%`, user profile, or non-system directories into privileged processes
- [ ] Flag unsigned DLLs loaded into signed system processes — high-confidence hijack indicator
- [ ] Correlate loaded DLL paths with `sleuthkit.list_files` results to confirm physical presence on disk

### 4.3 — Sysmon DLL Load Events (`logs.parse_evtx`)
- [ ] **Specialist Method:** `logs.parse_evtx(sysmon_evtx, event_ids=[7])`
- [ ] Event ID 7 (Image Loaded): filter for DLL loads into `w3wp.exe`, `svchost.exe`, `lsass.exe`, `taskhost.exe`
- [ ] Flag DLL loads from non-standard paths (outside `C:\Windows\`, `C:\Program Files\`)
- [ ] Flag unsigned or untrusted DLLs loaded into processes running at elevated integrity levels
- [ ] Note `ImageLoaded` vs `OriginalFileName` mismatch — renamed DLL masquerading indicator

### 4.4 — WinSxS & Known DLL Bypass (`registry.extract_keys`)
- [ ] **Specialist Method:** `registry.extract_keys(hive_path, "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs")`
- [ ] Extract `KnownDLLs` list — these cannot be hijacked via search order
- [ ] Focus hijack analysis on DLLs NOT listed in `KnownDLLs`
- [ ] Flag any modification to the `KnownDLLs` registry key itself — attacker removing protection

---

## Phase 5 — Scheduled Task Privilege Abuse

**Goal:** Detect scheduled tasks configured to execute attacker-controlled payloads under elevated or SYSTEM context.

### 5.1 — Task Registry Audit (`registry.extract_keys`)
- [ ] **Specialist Method:** `registry.extract_keys(hive_path, key_path)` targeting:
  - `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks`
  - `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree`
- [ ] Enumerate all registered tasks — extract `Actions`, `Triggers`, `Principal` (run-as user), and `SecurityDescriptor`
- [ ] Flag tasks with `RunLevel=HighestAvailable` or `RunLevel=LUA` overridden to SYSTEM
- [ ] Flag tasks running as `NT AUTHORITY\SYSTEM` or `NT AUTHORITY\NETWORK SERVICE` with user-influenced action paths

### 5.2 — Task XML & Action Path Analysis (`sleuthkit.list_files`)
- [ ] **Specialist Method:** `sleuthkit.list_files(evidence_path)` targeting `C:\Windows\System32\Tasks\` and `C:\Windows\SysWOW64\Tasks\`
- [ ] Parse `.xml` task definitions — extract `<Exec>` action paths and arguments
- [ ] Flag HIGH-integrity tasks whose `<Command>` path falls in a user-writable directory
- [ ] Flag tasks invoking PowerShell with encoded commands or download cradles
- [ ] Compare task file timestamps against known-good deployment dates — flag newly created tasks

### 5.3 — Task Execution Evidence (`windows.analyze_prefetch`)
- [ ] **Specialist Method:** `windows.analyze_prefetch(prefetch_dir)`
- [ ] Flag execution of `schtasks.exe` and `taskschd.msc` within the incident window
- [ ] Cross-reference task `LastRunTime` from registry with process creation events (EID 4688)
- [ ] Flag `taskeng.exe` or `taskhostw.exe` spawning unexpected child processes

---

## Phase 6 — Linux Privilege Escalation

**Goal:** When the evidence image is a Linux host, enumerate SUID/SGID, cron, sudo, and capability misconfigurations.

### 6.1 — SUID/SGID Binary Audit (`sleuthkit.list_files`)
- [ ] **Specialist Method:** `sleuthkit.list_files(evidence_path)` with permission filter equivalent to `find / -perm -4000 -o -perm -2000 -type f`
- [ ] Enumerate all SUID (`-rwsr-xr-x`) and SGID binaries on the filesystem
- [ ] Flag non-standard SUID binaries outside `/bin`, `/usr/bin`, `/usr/sbin` — CRITICAL escalation risk
- [ ] Flag recently modified SUID binaries — timestamp within the investigation window
- [ ] Cross-reference against known legitimate SUID binary list for the OS distribution

### 6.2 — Cron & Writable Path Analysis (`sleuthkit.list_files`)
- [ ] **Specialist Method:** `sleuthkit.list_files(evidence_path)` targeting `/etc/cron*`, `/var/spool/cron/`, `/etc/crontab`
- [ ] Parse all cron job definitions — extract command paths and schedule frequency
- [ ] Flag cron jobs running as `root` whose script path is world-writable
- [ ] Flag cron jobs referencing relative command paths (no leading `/`) — PATH injection risk
- [ ] Check `/etc/cron.d/` and `/etc/cron.hourly/` for attacker-added job files

### 6.3 — Sudo Misconfiguration Artifacts (`sleuthkit.list_files`)
- [ ] **Specialist Method:** `sleuthkit.list_files(evidence_path)` targeting `/etc/sudoers` and `/etc/sudoers.d/`
- [ ] Parse `sudoers` for `NOPASSWD` entries — flag broad `ALL=(ALL) NOPASSWD:ALL` grants
- [ ] Flag `sudo -l` output artifacts in bash history — attacker reconnaissance of sudo configuration
- [ ] Check bash history files (`~/.bash_history`) for sudo exploit attempts and `sudo su` patterns
- [ ] Flag `sudoers` modifications with timestamps inside the investigation window

### 6.4 — Capabilities & LD_PRELOAD Abuse (`sleuthkit.list_files`)
- [ ] **Specialist Method:** `sleuthkit.list_files(evidence_path)` for capability-extended binaries (`getcap -r /` equivalent)
- [ ] Flag binaries with `cap_setuid`, `cap_net_raw`, `cap_dac_override`, or `cap_sys_admin` capabilities set
- [ ] Check `/etc/ld.so.preload` for injected shared libraries — LD_PRELOAD persistence indicator
- [ ] Flag `LD_PRELOAD` entries in shell profile files (`/etc/profile`, `~/.bashrc`, `~/.profile`)
- [ ] Check for injected `.so` files in `/tmp`, `/dev/shm`, or world-writable directories

---

## Phase 7 — Event Log Correlation

**Goal:** Confirm privilege escalation activity through Windows Security and System event logs.

### 7.1 — Special Privileges & Sensitive Access (`logs.parse_evtx`)
- [ ] **Specialist Method:** `logs.parse_evtx(evtx_path, event_ids=[4672, 4673, 4674])`
- [ ] EID 4672 (Special privileges assigned to new logon): flag logons where `SeDebugPrivilege`, `SeTcbPrivilege`, or `SeLoadDriverPrivilege` are assigned to non-admin accounts
- [ ] EID 4673 (Privileged service called): flag calls to sensitive services outside expected administrative context
- [ ] EID 4674 (Operation attempted on privileged object): flag failed attempts indicating privilege probing
- [ ] Correlate EID 4672 timestamps with process creation events and memory token analysis

### 7.2 — Explicit Credential & Logon Events (`logs.parse_evtx`)
- [ ] **Specialist Method:** `logs.parse_evtx(evtx_path, event_ids=[4648, 4624, 4625])`
- [ ] EID 4648 (Logon with explicit credentials): flag use of alternate credentials by interactive users — pass-the-token or runas abuse
- [ ] EID 4624 Logon Type 3 or 9: flag network logons or NewCredentials logons from unexpected accounts
- [ ] EID 4625: flag repeated authentication failures preceding a successful EID 4648 — credential brute-force followed by token theft

### 7.3 — UAC Elevation & Token Adjustment Events (`logs.parse_evtx`)
- [ ] **Specialist Method:** `logs.parse_evtx(evtx_path, event_ids=[4703, 4688])`
- [ ] EID 4703 (Token right adjusted): flag privilege enablement events — specifically `SeDebugPrivilege` enabled on user tokens
- [ ] EID 4688 (Process creation): filter for `consent.exe` invocations, then trace parent/child process chains
- [ ] Flag `consent.exe` runs not followed by expected UAC-elevated child process — silent bypass indicator
- [ ] Correlate EID 4688 timestamps with UAC bypass registry key modification timestamps from Phase 2

### 7.4 — Service Modification Events (`logs.parse_evtx`)
- [ ] **Specialist Method:** `logs.parse_evtx(system_evtx, event_ids=[7045, 7036, 4697])`
- [ ] EID 7045 (New service installed): flag any service installed outside expected change windows
- [ ] EID 4697 (Service installed in the system): cross-reference with EID 7045 for full service installation record
- [ ] EID 7036 (Service state change): correlate start/stop events for newly installed services with timeline
- [ ] Flag services installed with `LocalSystem` run-as that execute payloads from user-writable paths

---

## Phase 8 — Scoring & Output

**Goal:** Prioritize findings for analyst handoff.

- [ ] **Severity Matrix:**
  - **Critical:** Active SYSTEM token in non-system process, UAC bypass registry keys present with child process execution, SUID binary modified within incident window, unquoted service path with writable directory exploited
  - **High:** SeDebugPrivilege enabled on user-context process, COM CLSID hijack in HKCU shadowing HKLM, DLL loaded from %TEMP% into SYSTEM process, scheduled task with user-writable action path running as SYSTEM
  - **Medium:** Unquoted service paths identified but no write evidence, KnownDLL bypass candidates present, sudo NOPASSWD entries without evidence of use, cron job with writable path but no modification
  - **Low:** Auto-elevated binaries executed legitimately (no registry hijack), standard administrative privilege use, expected SUID binaries with no modification

- [ ] **MITRE ATT&CK Mapping:**
  - T1548.002 — Abuse Elevation Control Mechanism: Bypass User Account Control
  - T1548.003 — Abuse Elevation Control Mechanism: Sudo and Sudo Caching
  - T1134.001 — Access Token Manipulation: Token Impersonation/Theft
  - T1134.002 — Access Token Manipulation: Create Process with Token
  - T1068 — Exploitation for Privilege Escalation
  - T1055.001 — Process Injection: Dynamic-link Library Injection
  - T1055.002 — Process Injection: Portable Executable Injection
  - T1574.001 — Hijack Execution Flow: DLL Search Order Hijacking
  - T1574.005 — Hijack Execution Flow: Executable Installer File Permissions Weakness
  - T1574.008 — Hijack Execution Flow: Path Interception by Search Order Hijacking
  - T1053.005 — Scheduled Task/Job: Scheduled Task
  - T1543.003 — Create or Modify System Process: Windows Service

- [ ] **SANS FOR508 Alignment:** Token and privilege analysis (Phase 1) and UAC bypass registry artifacts (Phase 2) are primary indicators covered in FOR508 Advanced Incident Response. Scheduled task abuse and service hijacking are core persistence/escalation topics in FOR508 Module 3.

- [ ] **Structured Output:** JSON with process name, PID, privileges, token integrity level, registry key paths, timestamps, and severity scores
- [ ] **Analyst Handoff:** Bundle memory image, SYSTEM hive, NTUSER.DAT hives, Prefetch directory, Security.evtx, and Sysmon.evtx for deep analysis
