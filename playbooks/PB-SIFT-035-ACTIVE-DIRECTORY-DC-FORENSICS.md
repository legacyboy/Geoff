# PB-SIFT-035: Active Directory & Domain Controller Forensics
## Active Directory & Domain Controller Forensics — Domain-Level Attack Detection

**Objective:** Detection of domain-level attacks: DCSync, Pass-the-Hash, Pass-the-Ticket, Golden/Silver Ticket forgery, Kerberoasting, AS-REP Roasting, domain persistence (AdminSDHolder, DCShadow, skeleton key), and GPO abuse.
**Specialist:** `memory`, `registry`, `logs`, `sleuthkit`
**MITRE Mapping:** T1003.006 (OS Credential Dumping: DCSync), T1558 (Steal or Forge Kerberos Tickets), T1550.002 (Pass the Hash), T1550.003 (Pass the Ticket), T1207 (Rogue Domain Controller), T1484 (Domain Policy Modification), T1136.002 (Create Account: Domain Account)

---

## Phase 1 — NTDS.dit Analysis

**Goal:** Locate and analyze the Active Directory database for signs of extraction or offline attack.

### 1.1 — NTDS.dit Location & Integrity (`sleuthkit.extract_file`)
- [ ] Confirm DC role: `NTDS.dit` is **only present on Domain Controllers** at `C:\Windows\NTDS\ntds.dit`
- [ ] **Specialist Method:** `sleuthkit.extract_file(ntds_path)` to recover NTDS.dit from evidence image
- [ ] Verify NTDS.dit file size against known baseline — unexpected size reduction may indicate truncation or substitution
- [ ] Examine `C:\Windows\NTDS\` directory contents:
  - `ntds.dit` — main AD database
  - `edb.log` / `edb*.log` — transaction logs
  - `edbres00001.jrs`, `edbres00002.jrs` — reserved logs
  - `temp.edb` — temporary database (present during active writes)
- [ ] MFT `$STANDARD_INFORMATION` timestamps on `ntds.dit` — flag unexpected access/modification times

### 1.2 — VSS-Based NTDS.dit Extraction Detection (`vss.extract_vss_files`)
- [ ] **Specialist Method:** `vss.extract_vss_files(evidence_path)` to enumerate Volume Shadow Copies
- [ ] Attackers routinely extract NTDS.dit via VSS — look for the full extraction pattern:
  - `vssadmin create shadow /for=C:` or `wmic shadowcopy call create Volume='C:\'`
  - `copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyX\Windows\NTDS\ntds.dit C:\temp\`
  - `copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyX\Windows\System32\config\SYSTEM C:\temp\`
- [ ] Flag VSS creation events in Application Event Log (EID 8222 — shadow copy created)
- [ ] Search Prefetch for `VSSADMIN.EXE`, `WMIC.EXE`, `DISKSHADOW.EXE` with timestamps near incident window
- [ ] Check for `diskshadow.exe` script-mode execution (`diskshadow /s script.txt`) — used to bypass command-line detection
- [ ] MFT analysis: look for short-lived files in `C:\temp\`, `C:\Windows\Temp\`, or attacker staging directories matching `ntds.dit`, `SYSTEM`, `SECURITY` names

### 1.3 — ntdsutil / IFM Extraction (`logs.parse_evtx`)
- [ ] **Specialist Method:** `logs.parse_evtx(security_evtx, event_ids=[4688])` filtering for `ntdsutil`
- [ ] Flag `ntdsutil "ac i ntds" "ifm" "create full C:\..."` command-line pattern (Install From Media — legitimate but abused)
- [ ] Search Prefetch for `NTDSUTIL.EXE` execution evidence
- [ ] Check EID 4104 (PowerShell Script Block Logging) for `DSInternals` module imports:
  - `Import-Module DSInternals`
  - `Get-ADDBAccount`, `ConvertTo-NTHash`, `Get-BootKey`
- [ ] `ntdsutil` IFM output leaves a directory with `Active Directory\ntds.dit` and `registry\SYSTEM` — search MFT for this directory structure
- [ ] **SANS FOR508 Alignment:** NTDS.dit offline cracking is the **single most impactful credential attack** in AD environments — recovery of this artifact defines the full blast radius of the compromise

---

## Phase 2 — DCSync Detection

**Goal:** Identify unauthorized use of the MS-DRSR Directory Replication protocol to extract credentials without touching disk.

### 2.1 — Replication Rights Abuse via EID 4662 (`logs.parse_evtx`)
- [ ] **Specialist Method:** `logs.parse_evtx(security_evtx, event_ids=[4662, 4742])`
- [ ] DCSync leverages `MS-DRSR` (Directory Replication Service Remote Protocol) — no NTDS.dit file access required
- [ ] EID 4662: `Object Access: Active Directory Object Access` — flag requests containing both replication GUIDs:
  - `{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}` — DS-Replication-Get-Changes-All
  - `{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}` — DS-Replication-Get-Changes
  - `{89e95b76-444d-4c62-991a-0facbeda640c}` — DS-Replication-Get-Changes-In-Filtered-Set
- [ ] **Critical indicator:** EID 4662 with replication GUIDs originating from a **non-DC source IP** — legitimate replication only occurs between DCs
- [ ] EID 4742 (Computer Account Changed): flag unexpected attribute changes on DC computer objects
- [ ] Audit replication partner list — new replication partners that are not registered DCs = DCShadow indicator (see Phase 5)
- [ ] **SANS FOR508 Alignment:** EID 4662 with replication GUIDs from a non-DC host is a **★★★★★** fidelity indicator for DCSync — treat as confirmed compromise if found

### 2.2 — Mimikatz DCSync On-Disk Artifacts (`sleuthkit.list_files`)
- [ ] **Specialist Method:** `sleuthkit.list_files(evidence_path)` searching for Mimikatz artifacts
- [ ] Flag file system presence of: `mimikatz.exe`, `mimilib.dll`, `mimilove.exe`, `mimidrv.sys`
- [ ] Check Prefetch for `MIMIKATZ.EXE` and Amcache for SHA1 hash correlation
- [ ] Sysmon EID 10 (ProcessAccess): `lsass.exe` as target with non-standard callers — Mimikatz DCSync first enumerates via LSASS
- [ ] Search `%TEMP%` and staging directories for Mimikatz output files (contain `NTLM:` and `aes256_hmac:` strings)
- [ ] Check PowerShell history for `Invoke-Mimikatz`, `Invoke-ReflectivePEInjection`, or Base64-encoded Mimikatz stagers

---

## Phase 3 — Golden/Silver Ticket Detection

**Goal:** Identify forged Kerberos tickets that grant persistent domain access independent of account passwords.

### 3.1 — Kerberos Ticket Event Analysis (`logs.parse_evtx`)
- [ ] **Specialist Method:** `logs.parse_evtx(security_evtx, event_ids=[4768, 4769, 4771])`
- [ ] EID 4768: Kerberos Authentication Ticket (TGT) Granted — baseline normal TGT issuance pattern
- [ ] EID 4769: Kerberos Service Ticket Operations — baseline normal ST issuance pattern
- [ ] EID 4771: Kerberos Pre-Authentication Failed — flag brute-force or spray patterns

### 3.2 — Golden Ticket Indicators
- [ ] **Golden Ticket** = forged TGT signed with the KRBTGT account NTLM hash
- [ ] Flag EID 4769 entries with `Ticket Encryption Type: 0x17` (RC4_HMAC_MD5) when the environment has been migrated to AES256 (`0x12`)
- [ ] Golden Ticket TTL anomaly: legitimate TGTs have 10-hour lifetime — Golden Tickets crafted by Mimikatz default to **10 years** (`20370101000000Z`)
- [ ] Flag authentication events where the TGT renewal interval exceeds domain policy maximum (check `Default Domain Policy` → `Account Policies` → `Kerberos Policy`)
- [ ] Look for EID 4769 with service ticket requests but **no corresponding EID 4768** from the same source in the same session — indicates imported Golden Ticket, not freshly issued TGT
- [ ] Flag EID 4769 where `Client Address` differs from expected workstation assignment for that user account

### 3.3 — Silver Ticket Indicators
- [ ] **Silver Ticket** = forged Service Ticket signed with the target service account's NTLM hash — bypasses the KDC entirely
- [ ] Key indicator: EID 4769 (Service Ticket) **present** but EID 4768 (TGT) **absent** for same session — Silver Tickets do not require a TGT exchange
- [ ] Flag service ticket requests for sensitive services (`CIFS`, `HOST`, `HTTP`, `LDAP`, `MSSQLSvc`) from unexpected source hosts
- [ ] Silver Ticket leaves **no KDC log entries** — detection depends on target service logs and anomalous access patterns
- [ ] Check `msDS-SupportedEncryptionTypes` registry/AD attribute — if RC4 is disabled domain-wide, any RC4-encrypted ticket is suspicious
- [ ] **SANS FOR508 Alignment:** Silver Ticket attacks are significantly harder to detect than Golden Tickets due to the absence of KDC-side logging — endpoint and service log correlation is essential

---

## Phase 4 — Kerberoasting / AS-REP Roasting

**Goal:** Detect offline password cracking attacks against service accounts and pre-auth-disabled accounts.

### 4.1 — Kerberoasting Detection (`logs.parse_evtx`)
- [ ] **Specialist Method:** `logs.parse_evtx(security_evtx, event_ids=[4768, 4769])`
- [ ] **Kerberoasting** = requesting service tickets (EID 4769) for SPN-bearing accounts and cracking offline
- [ ] Detection pattern: **bulk EID 4769 requests with `Encryption Type: 0x17` (RC4)** from a single user account in a short time window
- [ ] Flag requests for service tickets where the requesting account has no operational need for those services
- [ ] Enumerate SPN-bearing accounts in the environment — these are Kerberoasting targets:
  - `HKLM\SYSTEM\CurrentControlSet\Services\` for locally registered SPNs
  - AD query for `servicePrincipalName` attribute (requires AD enumeration logs or LDAP traffic)
- [ ] Kerberoasting tool artifacts in Prefetch/Amcache: `GetSPNs.py` (Impacket), `Invoke-Kerberoast`, `Rubeus.exe`
- [ ] Check PowerShell EID 4104 for `Invoke-Kerberoast`, `Get-DomainSPNTicket`, or `Add-Type` loading custom assemblies

### 4.2 — AS-REP Roasting Detection (`logs.parse_evtx`)
- [ ] **AS-REP Roasting** = targeting accounts with `DONT_REQUIRE_PREAUTH` flag (`UF_DONT_REQUIRE_PREAUTH` = `0x400000`)
- [ ] Flag EID 4768 entries where `Pre-Authentication Type: 0` — this indicates pre-auth was not required and the AS-REP was issued without proof of identity
- [ ] Identify accounts with `DONT_REQUIRE_PREAUTH` set via registry or AD enumeration log evidence
- [ ] Tool artifacts: `GetNPUsers.py` (Impacket), `Invoke-ASREPRoast`, `Rubeus.exe asreproast`
- [ ] Flag bulk EID 4768 requests from a single source for multiple different accounts — enumeration pattern preceding AS-REP Roasting
- [ ] **SANS FOR508 Alignment:** AS-REP Roasting is detectable **only** when pre-auth type is logged in EID 4768 — verify `Audit Kerberos Authentication Service` is enabled in domain audit policy

---

## Phase 5 — Domain Persistence Mechanisms

**Goal:** Identify stealthy mechanisms providing long-term domain-level access that survive password resets.

### 5.1 — AdminSDHolder Abuse (`registry.extract_keys`)
- [ ] **Specialist Method:** `registry.extract_keys(hive_path, key_path)` for relevant AD-related registry artifacts
- [ ] AdminSDHolder: `CN=AdminSDHolder,CN=System,DC=<domain>` — template ACL applied to protected groups
- [ ] Flag unexpected principals in AdminSDHolder ACL — any account granted `GenericAll`, `WriteDACL`, or `WriteOwner` gains persistent control
- [ ] `SDProp` process runs every 60 minutes (adjustable via `AdminSDProtectFrequency` registry key) and propagates AdminSDHolder ACL to protected group members
- [ ] Protected groups include: Domain Admins, Enterprise Admins, Schema Admins, Administrators, Account Operators, Backup Operators, Print Operators, Server Operators, Replicator
- [ ] Flag `AdminCount=1` set on accounts that are **not** members of protected groups — indicates historical protected group membership or manual manipulation
- [ ] EID 5136 (DS Object Modified) targeting `CN=AdminSDHolder` — direct evidence of ACL modification

### 5.2 — DCShadow Detection (`logs.parse_evtx`)
- [ ] **Specialist Method:** `logs.parse_evtx(security_evtx, event_ids=[4742, 4929])`
- [ ] **DCShadow** = attacker registers a rogue DC using `MS-DRSR` to push arbitrary AD changes that bypass normal audit logs
- [ ] Detection: `nTDSDSA` object creation in `CN=Configuration,DC=<domain>` partition — EID 5137 (DS Object Created) on legitimate DCs
- [ ] Flag registration of a new DC computer object in `CN=Domain Controllers,DC=<domain>` not matching authorized DC inventory
- [ ] EID 4742: Computer Account Changed — flag `servicePrincipalName` additions adding `GC/` (Global Catalog) or `ldap/` SPNs to non-DC machines
- [ ] Replication traffic from unexpected hosts: DCShadow requires establishing replication partnerships — flag new replication partner in network traffic
- [ ] Legitimate DCShadow cleanup leaves short-lived objects — MFT/AD object creation and deletion timestamps within the same session window
- [ ] **SANS FOR508 Alignment:** DCShadow is designed to evade detection — the **absence** of expected audit logs for known changes is itself an indicator

### 5.3 — Skeleton Key Detection (`memory.extract_processes`)
- [ ] **Specialist Method:** `memory.extract_processes(image_path)` targeting `lsass.exe` memory
- [ ] **Skeleton Key** = Mimikatz `misc::skeleton` patches `lsass.exe` in memory to accept a universal master password alongside legitimate passwords — **requires Domain Admin and does not survive reboot**
- [ ] Detection: `lsass.exe` memory analysis for `msv1_0.dll` hook artifacts — look for patched RVA offsets
- [ ] Sysmon EID 8 (CreateRemoteThread) into `lsass.exe` — thread injection required to apply the patch
- [ ] Sysmon EID 10 (ProcessAccess) with `lsass.exe` as target, access rights including `PROCESS_VM_WRITE (0x0020)`
- [ ] `mimidrv.sys` driver installation (required for skeleton key on newer Windows versions) — check `HKLM\SYSTEM\CurrentControlSet\Services\` for `mimidrv` service entry

### 5.4 — SID History Injection (`logs.parse_evtx`)
- [ ] **Specialist Method:** `logs.parse_evtx(security_evtx, event_ids=[4765, 4766, 4738])`
- [ ] EID 4765: SID History was added to an account
- [ ] EID 4766: An attempt to add SID History to an account failed
- [ ] EID 4738: A user account was changed — flag `SID History` field population
- [ ] Flag `sIDHistory` attribute containing high-privilege SIDs (Domain Admins SID `S-1-5-<domain>-512`, Enterprise Admins `S-1-5-<forest>-519`)
- [ ] SID History injection requires `DS-Replication-Manage-Topology` right — correlate with EID 4662 replication permission usage

---

## Phase 6 — Pass-the-Hash / Pass-the-Ticket

**Goal:** Identify credential reuse attacks enabling lateral movement without plaintext passwords.

### 6.1 — Pass-the-Hash Detection (`logs.parse_evtx`)
- [ ] **Specialist Method:** `logs.parse_evtx(security_evtx, event_ids=[4624, 4625, 4634, 4648, 4672])`
- [ ] **Pass-the-Hash (PtH)** = using captured NTLM hash to authenticate without knowing the plaintext password
- [ ] PtH indicator: EID 4624 **Logon Type 3** (Network) with `Authentication Package: NTLM` from **workstation-to-workstation** — legitimate domain authentication uses Kerberos
- [ ] PtH lateral movement pattern: same user account authenticating from multiple different source hosts within a short time window
- [ ] Flag EID 4624 Type 3 with `Logon Process: NtLmSsp` — NTLM relay/PtH indicator in Kerberos-enabled environments
- [ ] EID 4672 (Special Privileges Assigned to New Logon) immediately following EID 4624 — privilege escalation completed via hash
- [ ] EID 4648 (Logon Using Explicit Credentials) — flag non-interactive processes using explicit alternate credentials

### 6.2 — Pass-the-Hash Tool Artifacts
- [ ] Search Prefetch/Amcache for known PtH tools: `wce.exe` (Windows Credential Editor), `mimikatz.exe`, `pth-winexe`, `crackmapexec`
- [ ] Check PowerShell EID 4104 for `sekurlsa::pth`, `Invoke-TheHash`, `Invoke-WMIExec`, `Invoke-SMBExec`
- [ ] Sysmon EID 1: processes spawned with explicit credential flags (`runas /netonly` pattern in command line)
- [ ] **SANS FOR508 Alignment:** Logon Type 3 with NTLM on a Kerberos-capable network is a **high-confidence lateral movement indicator** — normal domain traffic does not generate this pattern at volume

### 6.3 — Pass-the-Ticket Detection (`logs.parse_evtx`)
- [ ] **Specialist Method:** `logs.parse_evtx(security_evtx, event_ids=[4768, 4769, 4770])`
- [ ] **Pass-the-Ticket (PtT)** = injecting a stolen Kerberos ticket into a new session
- [ ] Key indicator: EID 4769 (Service Ticket) **present** without a preceding EID 4768 (TGT request) from the same session — imported ticket bypasses TGT issuance
- [ ] Flag `klist` command execution in Prefetch (legitimate admin tool, but confirms ticket manipulation awareness)
- [ ] Mimikatz `sekurlsa::tickets /export` and `kerberos::ptt` artifacts in PowerShell history
- [ ] Rubeus tool artifacts: `Rubeus.exe` in Prefetch/Amcache, EID 4104 for `Invoke-Rubeus`, `Rubeus asktgt`, `Rubeus ptt`

---

## Phase 7 — GPO & Domain Policy Abuse

**Goal:** Detect modifications to Group Policy Objects used to deploy malicious configurations or achieve persistence across the domain.

### 7.1 — SYSVOL & GPO File Analysis (`sleuthkit.list_files`)
- [ ] **Specialist Method:** `sleuthkit.list_files(sysvol_path)` for `C:\Windows\SYSVOL\sysvol\<domain>\Policies\`
- [ ] Each GPO is a GUID-named directory: `{GUID}\Machine\` and `{GUID}\User\`
- [ ] Flag GPO modification timestamps that do not align with expected change control windows
- [ ] Examine startup/shutdown and logon/logoff script definitions:
  - `{GUID}\Machine\Scripts\Startup\`
  - `{GUID}\User\Scripts\Logon\`
- [ ] Flag scripts pointing to attacker-controlled UNC paths (`\\external.ip\share\malware.ps1`)
- [ ] Parse `Registry.pol` files for unauthorized registry changes deployed via GPO
- [ ] Examine `ScheduledTasks.xml` in `{GUID}\Machine\Preferences\ScheduledTasks\` for malicious task definitions

### 7.2 — GPO Modification Event Detection (`logs.parse_evtx`)
- [ ] **Specialist Method:** `logs.parse_evtx(security_evtx, event_ids=[5136, 5137, 5141])`
- [ ] EID 5136: DS Object Modified — flag modifications to `groupPolicyContainer` objects in `CN=Policies,CN=System,DC=<domain>`
- [ ] EID 5137: DS Object Created — flag new GPO creation, especially if not correlating with change control records
- [ ] EID 5141: DS Object Deleted — flag GPO deletion (attacker cleaning up evidence)
- [ ] Flag `GPC-File-Sys-Path` attribute changes — indicates GPO file path redirection
- [ ] Check `CN=Policies` for GPOs linked to high-value OUs (Domain Controllers OU, privileged user OUs)

### 7.3 — NETLOGON Share & Logon Script Abuse
- [ ] Inspect `NETLOGON` share contents: `C:\Windows\SYSVOL\sysvol\<domain>\scripts\`
- [ ] Flag new or modified `.bat`, `.cmd`, `.vbs`, `.ps1` files in NETLOGON share
- [ ] MFT timestamps on NETLOGON scripts — flag modifications outside business hours
- [ ] Correlate NETLOGON script modification time with authentication surge from domain users (malicious script executing on logon)
- [ ] **SANS FOR508 Alignment:** GPO abuse is a **★★★★** persistence mechanism — a single malicious GPO can compromise every workstation in an OU simultaneously

---

## Phase 8 — Memory Analysis on DC

**Goal:** Detect in-memory attacks and extract credential material cached in DC memory.

### 8.1 — LSASS Memory Analysis (`memory.extract_credentials`)
- [ ] **Specialist Method:** `memory.extract_credentials(image_path)` targeting `lsass.exe`
- [ ] `lsass.exe` on a DC caches credentials for all recently authenticated domain users — full domain credential exposure
- [ ] Extract NTLM hashes, Kerberos tickets, and cleartext credentials (if WDigest enabled) from LSASS memory structures
- [ ] Flag `WDigest` authentication: `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential` = 1 (attacker-enabled cleartext storage)
- [ ] Look for LSASS memory dumps on disk: `lsass.dmp`, `lsass.exe.dmp`, `procdump*.dmp` in temp or staging directories

### 8.2 — Injected Code Detection (`memory.find_injected_code`)
- [ ] **Specialist Method:** `memory.find_injected_code(image_path)`
- [ ] Flag executable memory regions in `lsass.exe` that are not backed by mapped files — skeleton key injection signature
- [ ] `ntdsa.dll` hooks: compare in-memory `ntdsa.dll` export table against clean known-good version
- [ ] `samsrv.dll` patches: in-memory password filter hooks used for credential harvesting
- [ ] SAM/LSA secret extraction artifacts: memory regions containing `_MSSAMR_*` structures or `LsaOpenPolicy` remnants
- [ ] Sysmon EID 17/18 (Pipe Created/Connected): malicious named pipes used for LSASS communication

### 8.3 — Process Enumeration for DC-Specific Artifacts (`memory.extract_processes`)
- [ ] **Specialist Method:** `memory.extract_processes(image_path)`
- [ ] Enumerate processes running on DC — flag any non-standard processes for a DC role:
  - Expected: `lsass.exe`, `dns.exe`, `dfsr.exe`, `ntfrs.exe`, `ismserv.exe`, `kdc.exe` (integrated in lsass)
  - Unexpected: pentest tools, scripting hosts without admin session context, network scanners
- [ ] Flag `lsass.exe` parent — should always be `wininit.exe`; any other parent is a masquerading indicator
- [ ] Check network connections from `lsass.exe` — should only connect to other DCs for replication
- [ ] **SANS FOR508 Alignment:** Memory analysis on a DC is the **most sensitive forensic operation** — always work from an acquired memory image, never perform live analysis that could disturb evidence

---

## Phase 9 — Scoring & Output

**Goal:** Prioritize findings and produce structured output for analyst handoff.

- [ ] **Severity Matrix:**
  - **Critical:** DCSync from non-DC source, Golden Ticket with 10-year TTL or RC4 in AES environment, skeleton key injection (`lsass.exe` memory patch), NTDS.dit extraction via VSS with confirmed tool execution, DCShadow rogue DC registration
  - **High:** Kerberoasting bulk ticket requests, AS-REP Roasting against pre-auth-disabled accounts, Silver Ticket without TGT exchange, AdminSDHolder ACL modification, SID History injection, GPO modification adding startup scripts
  - **Medium:** Pass-the-Hash lateral movement (Logon Type 3 NTLM from workstation), suspicious GPO changes without change control correlation, WDigest cleartext credential storage enabled, ntdsutil IFM execution without documented backup activity
  - **Low:** Kerberos RC4 encryption in mixed-mode environments, historical `AdminCount=1` on non-privileged accounts, NETLOGON script modifications within change control windows

- [ ] **MITRE ATT&CK Mapping:**
  - T1003.006 — OS Credential Dumping: DCSync
  - T1003.003 — OS Credential Dumping: NTDS
  - T1558.001 — Steal or Forge Kerberos Tickets: Golden Ticket
  - T1558.002 — Steal or Forge Kerberos Tickets: Silver Ticket
  - T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting
  - T1558.004 — Steal or Forge Kerberos Tickets: AS-REP Roasting
  - T1550.002 — Use Alternate Authentication Material: Pass the Hash
  - T1550.003 — Use Alternate Authentication Material: Pass the Ticket
  - T1207 — Rogue Domain Controller (DCShadow)
  - T1484.001 — Domain Policy Modification: Group Policy Modification
  - T1136.002 — Create Account: Domain Account
  - T1098 — Account Manipulation (AdminSDHolder, SID History)
  - T1547 — Boot or Logon Autostart Execution (skeleton key persistence)

- [ ] **Structured Output:** JSON with DC hostname, attack type, source IP, target account, timestamp, supporting event IDs, and severity scores
- [ ] **Analyst Handoff:** Bundle NTDS.dit (if safely recoverable), SYSTEM hive, Security EVTX, Sysmon EVTX, memory image of DC lsass.exe, and SYSVOL snapshot for deep analysis
