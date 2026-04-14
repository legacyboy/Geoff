# PB-SIFT-015: macOS Forensic Indicators Playbook
## macOS Forensic Indicators — Static Image Analysis

**Objective:** High-fidelity detection and analysis of compromise indicators within a macOS digital forensic image using the SIFT Workstation toolset.

---

### Phase 1 — Evidence Integrity
- [ ] **Hash Verification:** Verify hash of all evidence against chain of custody.
- [ ] **Integrity Check:** Flag any mismatch before proceeding.
- [ ] **OS Identification:** Identify macOS version, build number, and filesystem type (APFS or HFS+).
- [ ] **Volume Mapping:** Document volume structure, Fusion Drive configuration, and FileVault status.
- [ ] **SIP Audit:** Note SIP (System Integrity Protection) status — disabled SIP is a **CRITICAL** indicator.
- [ ] **AMFI Audit:** Note AMFI (Apple Mobile File Integrity) status — disabled AMFI allows unsigned code execution.
- [ ] **Security Policy:** Document Secure Boot and T2/Apple Silicon chip security policy.

---

### Phase 2 — Memory Analysis
- [ ] **Process Audit:** Enumerate processes — flag those with no binary on disk or running from unusual paths.
- [ ] **Dylib Injection:** Check for injected dylibs — flag unexpected entries in process memory maps.
- [ ] **CLI Audit:** Check command lines — flag encoded/obfuscated bash, python, osascript, or perl.
- [ ] **Network State:** Enumerate open connections — flag outbound from non-system processes.
- [ ] **Writable Path Execution:** Flag processes running from `/tmp`, `/var/folders`, `/private/tmp`, or user-writable locations.
- [ ] **Keychain/TCC Access:** Check for processes accessing Keychain or TCC-protected resources outside expected scope.
- [ ] **XPC Audit:** Flag XPC service processes with unexpected parents or unusual binary paths.
- [ ] **Automation Abuse:** Check for `osascript` processes spawned from non-user-interactive parents.

---

### Phase 3 — Super Timeline
- [ ] **Timeline Construction:** Build full timeline using `log2timeline` (Unified Logs, FSEvents, APFS metadata).
- [ ] **Suspicious Paths:** Flag executables created/modified in `/tmp`, `/var/folders`, `/private/tmp`, `~/Downloads`, or `~/Library`.
- [ ] **Persistence Timing:** Flag LaunchAgent or LaunchDaemon plist creation/modification events.
- [ ] **Security DB Changes:** Flag changes to TCC database, Keychain, or SIP-protected directories.
- [ ] **Execution Correlation:** Correlate download timestamps with first execution events.
- [ ] **Quarantine Audit:** Flag quarantine database entries to identify source URLs.
- [ ] **APFS Snapshot Audit:** Flag snapshot creation/deletion events — potential anti-forensics.
- [ ] **Kernel Events:** Flag kernel extension load events correlated with incident window.
- [ ] **Cloud Correlation:** Correlate iCloud sync activity with sensitive file access.

---

### Phase 4 — Disk Artifacts

#### 4.1 — Persistence Artifacts
- [ ] **LaunchAgents:** Check `~/Library/LaunchAgents/`, `/Library/LaunchAgents/` — flag unusual paths/encoded commands.
- [ ] **LaunchDaemons:** Check `/Library/LaunchDaemons/`, `/System/Library/LaunchDaemons/` — flag non-Apple/non-known software.
- [ ] **Login Items:** Check `~/Library/Application Support/com.apple.backgroundtaskmanagementagent/`.
- [ ] **Periodic Scripts:** Check `/etc/periodic/` (daily, weekly, monthly) for modifications.
- [ ] **Cron Jobs:** Check `/var/at/tabs/`, `/usr/lib/cron/tabs/`.
- [ ] **emond Rules:** Check `/etc/emond.d/` for stealthy persistence.
- [ ] **Kext Audit:** Check `/Library/Extensions/` and `/System/Library/Extensions/` for unsigned/revoked/unknown kexts.
- [ ] **XPC Definitions:** Check `/Library/LaunchDaemons/` and app bundles for new registered services.
- [ ] **Dock/Finder Plists:** Check `com.apple.dock.plist` and `com.apple.finder.plist` for hidden malicious locations.
- [ ] **Login/Logout Hooks:** Check `com.apple.loginwindow` plist for legacy hook abuse.

#### 4.2 — User & Account Artifacts
- [ ] **Account Audit:** Check `/etc/passwd` and Directory Services for new/modified local accounts.
- [ ] **Local Nodes:** Check `/var/db/dslocal/nodes/Default/users/` for unauthorized account creation.
- [ ] **SSH Audit:** Check `~/.ssh/authorized_keys` for unknown public keys.
- [ ] **Sudo Audit:** Check `/etc/sudoers` for unauthorized privilege grants.
- [ ] **Hidden Users:** Identify users with UniqueID below 500 or `IsHidden` flag set.
- [ ] **Group Audit:** Check `dscl` artifacts for unauthorized additions to the admin group.

#### 4.3 — Execution & Application Artifacts
- [ ] **Unified Log Analysis:** Parse `/var/db/diagnostics/` for process execution, network, and auth events.
- [ ] **FSEvents Audit:** Check `/System/Volumes/Data/.fseventsd/` for filesystem changes.
- [ ] **Spotlight Audit:** Check recently indexed files and search queries.
- [ ] **Quarantine DB:** Check `~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`.
- [ ] **Shell History:** Check `.bash_history`, `.zsh_history`, `.zshrc` for attacker commands.
- [ ] **Code Signing:** Check `KextPolicy` and `ExecPolicy` for unsigned or ad-hoc signed code execution.
- [ ] **Gatekeeper Bypass:** Flag files with `com.apple.quarantine` attribute removed.
- [ ] **Terminal State:** Check `~/Library/Saved Application State/com.apple.Terminal.savedState/`.
- [ ] **AppleScript/Automator:** Check `~/Library/Application Scripts/` for malicious workflows.
- [ ] **Codesign Audit:** Flag binaries with invalid/revoked signatures or ad-hoc signing.

#### 4.4 — macOS LOLBin Abuse
- [ ] **Binary Audit:** Monitor shell history/logs for abuse of:
    - `osascript`, `curl`, `python3`, `ruby`, `launchctl`, `defaults`, `plutil`, `security`, `dscl`, `networksetup`, `screencapture`, `pbcopy`/`pbpaste`, `open`, `xattr`, `hdiutil`, `sqlite3`, `automator`.
- [ ] **Process Behavior:** Flag LOLBins spawning network connections or child shells.
- [ ] **Persistence Installation:** Flag `launchctl load` from user-writable paths.

#### 4.5 — Browser & Download Artifacts
- [ ] **Safari Audit:** Check history, downloads, and cache in `~/Library/Safari/`.
- [ ] **Cross-Browser Audit:** Check Chrome, Firefox, Brave profiles in `~/Library/Application Support/`.
- [ ] **Exec Downloads:** Flag downloads of executables, DMGs, PKGs, or scripts.
- [ ] **Extensions:** Check for malicious browser extensions in profile directories.
- [ ] **Safari Extensions:** Check `~/Library/Safari/Extensions/` for non-App Store sources.
- [ ] **Phishing History:** Flag access to known malware distribution URLs.
- [ ] **Session Theft:** Check saved credentials and cookie stores.

#### 4.6 — Credential & Keychain Artifacts
- [ ] **Keychain Audit:** Check `~/Library/Keychains/`, `/Library/Keychains/` for new/modified entries.
- [ ] **TCC DB Audit:** Check `/Library/Application Support/com.apple.TCC/TCC.db` for unauthorized grants.
- [ ] **Privacy Permissions:** Flag unexpected Full Disk Access, Screen Recording, or Microphone grants.
- [ ] **Keychain Harvesting:** Check for `osascript`-based prompts for admin passwords.
- [ ] **Fake Dialogs:** Identify AppleScript dialogs requesting credentials stored in history.
- [ ] **iCloud Sync:** Check for credentials synced to iCloud accessed from other devices.

#### 4.7 — iCloud & Apple Service Artifacts
- [ ] **iCloud Drive:** Check `~/Library/Mobile Documents/` for corporate data sync.
- [ ] **Account Config:** Check `~/Library/Preferences/MobileMeAccounts.plist` for non-corporate Apple IDs.
- [ ] **Sync State:** Flag iCloud Keychain enabled status.
- [ ] **Photo Library:** Check for sensitive images uploaded to iCloud.
- [ ] **Device Backups:** Check for iCloud backups of associated iOS devices.

#### 4.8 — AirDrop & Bluetooth Transfer Artifacts
- [ ] **AirDrop Received:** Check `~/Downloads/` with AirDrop metadata for unknown devices.
- [ ] **BT Pairing:** Check `/Library/Preferences/com.apple.Bluetooth.plist` for unknown paired devices.
- [ ] **AirDrop Outbound:** Check Unified Logs for large/sensitive files sent via AirDrop.
- [ ] **Policy Audit:** Flag AirDrop set to "Everyone".
- [ ] **Handoff/Clipboard:** Check for data movement via Universal Clipboard.

#### 4.9 — macOS-Specific Malware Indicators
- [ ] **Staging Paths:** Check `~/.config/`, `~/Library/Caches/`, `/private/tmp/`, `/var/root/`.
- [ ] **Binary Audit:** Flag unsigned/ad-hoc signed Mach-O binaries in user-writable locations.
- [ ] **Dylib Injection:** Check for `DYLD_INSERT_LIBRARIES` abuse in LaunchAgent/Daemon arguments.
- [ ] **C2 Patterns:** Flag reverse shell indicators in plist `ProgramArguments` keys.
- [ ] **Family Detection:** Scan for Shlayer, XCSSET, MacSpy, Coldroot, EvilQuest, RustBucket, Atomic Stealer.
- [ ] **C2 Frameworks:** Check for SwiftBelt, Apfell, or Mythic artifacts in user profiles.

---

### Phase 5 — Log Analysis
- [ ] **Unified Log Parsing:** Primary source for process execution, auth, and XPC events.
- [ ] **System Log:** Check `/var/log/system.log` for sudo usage and service crashes.
- [ ] **Auth Log:** Check `/var/log/authd.log` for authentication failures and escalations.
- [ ] **Install Log:** Check `/var/log/install.log` for software installations.
- [ ] **ASL Database:** Parse `/var/db/diagnostics/` and `/var/db/uuidtext/`.
- [ ] **Log Continuity:** Flag gaps or deletion events in the Unified Log.
- [ ] **Crash Reports:** Check Console app database for crashes correlated with exploits.
- [ ] **EDR Logs:** Check Endpoint Security framework logs for agent termination/tampering.
- [ ] **Time Machine:** Check backup history for gaps or deletions.

---

### Phase 6 — APFS Snapshot Analysis
- [ ] **Snapshot Enumeration:** Flag missing or deleted APFS snapshots.
- [ ] **Delta Analysis:** Compare current volume vs. most recent snapshot for added/modified files.
- [ ] **Recovery:** Recover deleted files from snapshots.
- [ ] **Persistence Timing:** Compare persistence locations across snapshots to identify installation date.
- [ ] **Anti-Forensics:** Flag snapshot deletion events correlated with activity.

---

---

### Phase 7 — Network IOC Extraction
- [ ] **IOC Harvesting:** Extract IPs, domains, and URLs from disk/logs/browser.
- [ ] **Persistence C2:** Flag outbound connections from LaunchAgent-backed processes.
- [ ] **DNS Audit:** Check `/etc/hosts` for unauthorized redirects.
- [ ] **Proxy Audit:** Check `~/Library/Preferences/com.apple.systemconfiguration/` for interception.
- [ ] **CLI Network Audit:** Check `networksetup` usage in shell history.
- [ ] **VPN Audit:** Check `/Library/Preferences/SystemConfiguration/` for rogue VPNs.
- [ ] **Intel Enrichment:** Enrich all IOCs against threat intel feeds.

---

### Phase 8 — Score & Report
- [ ] **Aggregation:** Aggregate all flags into findings report.
- [ ] **MITRE Mapping:**
    - **T1543.001:** LaunchAgent / LaunchDaemon Persistence
    - **T1547.015:** Login Item Persistence
    - **T1053.003:** Cron Job
    - **T1574.004:** Dylib Hijacking
    - **T1574.006:** DYLD_INSERT_LIBRARIES
    - **T1059.002:** OSA Scripting / AppleScript
    - **T1555.001:** Keychain Credential Access
    - **T1548.006:** TCC Database Abuse
    - **T1553.001:** Gatekeeper / AMFI Bypass
    - **T1564.001:** Hidden Files and Directories
    - **T1505.003:** Web Shell
    - **T1559.001:** XPC Service Abuse
    - **T1218:** macOS LOLBin Abuse
    - **T1113:** Screencapture Exfiltration
    - **T1115:** Clipboard Data Access
    - **T1052.001:** AirDrop / Bluetooth Transfer
    - **T1567.002:** iCloud Data Exfiltration
    - **T1547.006:** Kernel Extension Rootkit
    - **T1037.002:** Login / Logout Hook
- [ ] **Security Framework Audit:** Flag disabled SIP/AMFI as **CRITICAL**.
- [ ] **Attack Narrative:** Establish timeline from initial access to execution.
- [ ] **Final Output:** Score by severity and output structured findings file.
