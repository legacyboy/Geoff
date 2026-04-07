# PB-SIFT-012: Linux Forensic Indicators Playbook
## Linux Forensic Indicators — Static Image Analysis

**Objective:** High-fidelity detection and analysis of compromise indicators within a Linux-based digital forensic image using the SIFT Workstation toolset.

---

### Phase 1 — Evidence Integrity
- [ ] **Hash Verification:** Verify hash of all evidence against chain of custody.
- [ ] **Integrity Check:** Flag any mismatch before proceeding.
- [ ] **OS Identification:** Identify Linux distribution, kernel version, and filesystem type from image metadata.
- [ ] **Layout Mapping:** Document mount points, partition layout, and logical volume structure.
- [ ] **MAC Audit:** Note SELinux or AppArmor enforcement status — disabled MAC is a significant indicator.

---

### Phase 2 — Memory Analysis
- [ ] **Process Audit:** Enumerate running processes — flag processes with no associated binary on disk.
- [ ] **Fileless Detection:** Check `/proc/[pid]/exe` symlinks — flag any pointing to deleted files (`/path/to/binary (deleted)`).
- [ ] **Sourcing Patterns:** Check `/proc/[pid]/maps` — flag memory regions mapped from `/dev/shm`, `/tmp`, or `memfd`.
- [ ] **FD Analysis:** Check `/proc/[pid]/fd` — flag open file descriptors pointing to deleted files or anonymous memory regions.
- [ ] **Rootkit Detection:** Check for hidden processes visible in memory but absent from `/proc`.
- [ ] **CLI Audit:** Check command lines of all processes — flag encoded or obfuscated bash, python, perl, or ruby one-liners.
- [ ] **Network State:** Enumerate open network connections — flag outbound to unknown external IPs from non-standard processes.
- [ ] **Library Audit:** Check for injected shared libraries — flag unexpected entries in process memory maps not matching disk libraries.
- [ ] **Writable Path Execution:** Flag processes running from `/tmp`, `/dev/shm`, `/run/shm`, or other memory-backed/world-writable filesystems.
- [ ] **Memfd Analysis:** Check for `memfd_create` usage — anonymous memory file execution is a **CRITICAL** indicator.

---

### Phase 3 — Super Timeline
- [ ] **Timeline Construction:** Build full timeline across all artifact sources using `log2timeline`.
- [ ] **Temporal Anomalies:** Flag file creation or modification bursts during off-hours.
- [ ] **Suspicious Paths:** Flag executables created or modified in `/tmp`, `/var/tmp`, `/dev/shm`, `/run`, or user home directories.
- [ ] **System File Integrity:** Flag changes to critical system files — `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/cron*`, `/etc/ssh/sshd_config`.
- [ ] **Auth Correlation:** Correlate authentication log timestamps with suspicious filesystem activity.
- [ ] **Persistence Timing:** Flag cron job or systemd timer additions correlated with attacker activity window.
- [ ] **Package Audit:** Flag package installation events outside approved windows (`/var/log/dpkg.log` or `/var/log/yum.log`).
- [ ] **Kernel Events:** Flag kernel module load events correlated with the incident timeline.

---

### Phase 4 — Disk Artifacts

#### 4.1 — User & Account Artifacts
- [ ] **Account Audit:** Check `/etc/passwd` and `/etc/shadow` — flag new/modified accounts, UID 0, or empty password fields.
- [ ] **Privilege Audit:** Check `/etc/sudoers` and `/etc/sudoers.d/` — flag unauthorized sudo grants or `NOPASSWD` entries.
- [ ] **SSH Key Audit:** Check `/home/*/.ssh/authorized_keys` and `/root/.ssh/authorized_keys` — flag unknown public keys.
- [ ] **Account Layout:** Check for newly created accounts with home directories in non-standard locations.
- [ ] **SSH Config:** Check `/etc/ssh/sshd_config` — flag `PermitRootLogin yes` or non-standard `AuthorizedKeysFile` paths.
- [ ] **Host Key Audit:** Check for SSH host key regeneration — may indicate system rebuild or key theft.

#### 4.2 — Persistence Artifacts
- [ ] **Cron Analysis:** Check all cron locations (`/etc/cron*`, `/var/spool/cron/*`) — flag entries pointing to temp or unusual paths.
- [ ] **Systemd Unit Audit:** Check `/etc/systemd/system/`, `/usr/lib/systemd/system/`, and user units — flag new/modified services.
- [ ] **Systemd Timer Audit:** Check `/etc/systemd/system/*.timer` — flag timers invoking non-standard binaries.
- [ ] **Init/RC Analysis:** Check `/etc/rc.local`, `/etc/init.d/`, and `/etc/init/` for malicious startup entries.
- [ ] **LD_PRELOAD Detection:** Check `/etc/ld.so.preload` — any entry here is a **CRITICAL** rootkit indicator.
- [ ] **Library Path Audit:** Check `/etc/ld.so.conf.d/` — flag new files adding attacker-controlled paths.
- [ ] **Shell Configs:** Check `/etc/profile`, `/etc/bashrc`, `~/.bashrc`, `~/.bash_profile`, `~/.zshrc`, `~/.zshenv` — flag malicious commands/cradles.
- [ ] **PAM Audit:** Check for malicious PAM modules in `/etc/pam.d/` and `/lib/security/` — credential harvesting.
- [ ] **Backdoor Services:** Check `xinetd`/`inetd` configuration files for backdoor service definitions.
- [ ] **D-Bus Audit:** Check `/etc/dbus-1/system.d/` and `/usr/share/dbus-1/system-services/` for new service definitions.
- [ ] **Udev Rules:** Check `/etc/udev/rules.d/` — flag rules executing scripts on device events.

#### 4.3 — Execution Artifacts
- [ ] **Shell History:** Check `.bash_history`, `.zsh_history` — flag attacker commands.
- [ ] **Anti-Forensics:** Flag history truncation, deletion, or `HISTFILE=/dev/null` in shell configs.
- [ ] **Authentication Logs:** Check `/var/log/auth.log` or `/var/log/secure` — flag SSH logons, sudo usage, and su events.
- [ ] **Login History:** Check `wtmp`, `btmp`, and `lastlog` — flag logon anomalies and unknown source IPs.
- [ ] **SUID/SGID Audit:** Check for SUID/SGID binaries added outside package management.
- [ ] **World-Writable Binaries:** Check for world-writable executables in system paths.
- [ ] **Package Log Audit:** Check `/var/log/dpkg.log`, `/var/log/apt/`, `/var/log/yum.log` — flag unexpected package changes.
- [ ] **Install Script Abuse:** Flag pre/post-install script abuse in package management.

#### 4.4 — GTFO Bin Abuse
- [ ] **LOLBin Audit:** Check bash history and audit logs for abuse of:
    - `python`/`python3`, `perl`, `awk`, `find`, `vim`/`vi`/`nano`, `tar`, `curl`, `wget`, `nmap`, `less`/`more`, `env`, `strace`, `ltrace`, `dd`, `socat`, `nc`/`ncat`.
- [ ] **Privilege Risk:** Flag any SUID binary in the GTFO bin list.
- [ ] **Event Correlation:** Correlate GTFO bin usage with privilege escalation events in auth logs.

#### 4.5 — Web Server & Application Artifacts
- [ ] **Log Analysis:** Check Apache/Nginx/HTTPD logs for web shell access patterns.
- [ ] **Request Patterns:** Flag POST requests to static file paths — web shell indicator.
- [ ] **Script Audit:** Check web-accessible directories for PHP, Perl, Python, or Ruby scripts with unusual creation dates.
- [ ] **Log Integrity:** Check `/var/log/apache2/`, `/var/log/nginx/` — flag log gaps or truncation.
- [ ] **Config Tampering:** Flag `.htaccess` modifications redirecting traffic or enabling script execution.
- [ ] **CGI Audit:** Check for CGI scripts added to `cgi-bin` outside change management.

#### 4.6 — Rootkit & Kernel Indicators
- [ ] **Proc Inconsistency:** Check `/proc` filesystem structure — flag inconsistencies between process lists and running process count.
- [ ] **Hidden Files:** Check for hidden files/directories starting with `.` beyond standard dotfiles or using Unicode lookalikes.
- [ ] **Module Audit:** Check `/proc/modules`, `/sys/module` — flag unsigned or unknown recently loaded modules.
- [ ] **Module Config:** Check `/etc/modules` and `/etc/modules-load.d/` — flag unauthorized entries.
- [ ] **Binary Integrity:** Compare hashes of `ls`, `ps`, `netstat`, `find`, `ss`, `top` against known-good hashes via `debsums` or `rpm -V`.
- [ ] **LDPRELOAD Check:** Flag `/etc/ld.so.preload` existence as **CRITICAL**.
- [ ] **DNS Hijacking:** Check `/etc/hosts` for unauthorized entries — C2 redirection or security tool blocking.
- [ ] **Kernel Hardening:** Check `/proc/sys/kernel/modules_disabled` — flag if set to 0 when policy requires 1.

#### 4.7 — Container & Virtualization Artifacts
- [ ] **Docker Socket:** Check for `/var/run/docker.sock` access outside container management tools.
- [ ] **Container Config:** Check `/var/lib/docker/containers/` — flag privileged mode, host network, or host PID namespace.
- [ la **Image Provenance:** Flag container images pulled from untrusted registries in manifest files.
- [ ] **Namespace Abuse:** Check for `unshare`, `nsenter` usage in bash history or audit logs.
- [ ] **Cgroup Escape:** Flag writes to `/sys/fs/cgroup/release_agent` or `/proc/[pid]/cgroup` anomalies.
- [ ] **K8s Artifacts:** Check for `kubectl` config files, service account tokens in unexpected locations.

---

### Phase 5 — Log Analysis
- [ ] **Auth Audit:** Check `/var/log/auth.log` or `/var/log/secure` — flag brute force, remote logons, and su/sudo usage.
- [ ] **System Logs:** Check `/var/log/syslog` or `/var/log/messages` — flag service starts, crashes, and kernel messages.
- [ ] **Login History:** Check `/var/log/wtmp` and `/var/log/btmp` — flag logon history and failed patterns.
- [ ] **Rotation Audit:** Flag log rotation anomalies — logs rotated or truncated outside scheduled window.
- [ ] **Auditd Analysis:** Check `/var/log/audit/audit.log` — flag privilege escalation, file access, execve, and module load events.
- [ ] **Audit Config:** Check `/etc/audit/audit.rules` and `/etc/audit/rules.d/` — flag disabled or tampered rules.
- [ ] **Auditd Stability:** Flag auditd service stop or configuration change events.
- [ ] **App Logs:** Check database, mail server, FTP logs for exploitation or exfiltration indicators.
- [ ] **Kernel Logs:** Check `/var/log/kern.log` — flag kernel panics, oops, or unexpected module loads.
- [ ] **Cron Logs:** Flag cron execution logs for unexpected job runs (`/var/log/cron` or syslog).

---

### Phase 6 — YARA Scan
- [ ] **Binary Scan:** Scan all binaries in `/tmp`, `/var/tmp`, `/dev/shm`, `/run`, and home directories against malware rulesets.
- [ ] **Web Shell Scan:** Scan web directories for known Linux web shell signatures.
- [ ] **Rootkit Scan:** Scan kernel modules for known rootkit signatures (Diamorphine, Reptile, Azazel, Necurs).
- [ ] **Script Analysis:** Scan bash history and script files for known attacker tool patterns and reverse shell one-liners.
- [ ] **Family Detection:** Scan for known Linux malware families (Mirai, Gafgyt, Tsunami, Skidmap, HiddenWasp, Symbiote).
- [ ] **Library Audit:** Scan shared libraries in `/lib`, `/lib64`, `/usr/lib` for tampering or injection.
- [ ] **Hit Documentation:** Flag any hits with file path, rule name, malware family, and confidence level.

---

### Phase 7 — Network IOC Extraction
- [ ] **IOC Harvesting:** Extract all IPs, domains, and URLs from disk and log artifacts.
- [ ] **Connection Audit:** Flag outbound connection destinations from network log artifacts and `/proc/net/tcp` artifacts.
- [ ] **Hosts Audit:** Check `/etc/hosts` for unauthorized entries — C2 redirection or security tool blocking.
- [ ] **Firewall Analysis:** Check `iptables`/`nftables` rules saved to disk — flag rules allowing unexpected inbound access.
- [ ] **Namespace Analysis:** Check for network namespace configurations — attacker may create isolated network namespaces.
- [ ] **Interface Audit:** Check for rogue network interfaces or VLAN configurations added outside change management.
- [ ] **Intel Enrichment:** Enrich all IOCs against threat intel feeds.

---

### Phase 8 — Score & Report
- [ ] **Aggregation:** Aggregate all flags into findings report.
- [ ] **MITRE Mapping:** Identify technique per MITRE ATT&CK:
    - **T1098.004:** SSH Authorized Keys
    - **T1059.004:** Unix Shell
    - **T1053.003:** Cron Job Persistence
    - **T1543.002:** Systemd Service / Timer
    - **T1574.006:** LD_PRELOAD / ld.so.conf Rootkit
    - **T1548.001:** SUID / SGID Abuse
    - **T1505.003:** Web Shell
    - **T1556.003:** Modify Authentication Process — PAM
    - **T1564.001:** Hidden Files and Directories
    - **T1547.006:** Kernel Module / Rootkit
    - **T1611:** Container Escape
    - **T1059.004:** GTFO Bin Abuse / LOLBin
    - **T1546.004:** D-Bus / udev Persistence
    - **T1620:** Fileless Execution — memfd_create
    - **T1070.002:** Indicator Removal — Log Tampering
    - **T1562.012:** Auditd Tampering
- [ ] **Attack Narrative:** Establish attack timeline — initial access through persistence and execution.
- [ ] **Final Output:** Score by severity — output structured findings file for analyst handoff.
