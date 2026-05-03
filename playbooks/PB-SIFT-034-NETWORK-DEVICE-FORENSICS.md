# PB-SIFT-034: Network Device Forensics Playbook
## Network Device Forensics — Routers, Switches, Firewalls

**Objective:** Forensic analysis of network infrastructure device compromise: unauthorized access, configuration tampering, firmware implants, rogue devices, and malicious traffic patterns across Cisco IOS/NX-OS, Juniper Junos, Palo Alto PAN-OS, and Fortinet FortiGate platforms.
**Specialist:** `logs`, `sleuthkit`, `network`, `pcap`
**MITRE Mapping:** T1542.005 (Pre-OS Boot: TFTP Boot), T1601 (Modify System Image), T1600 (Weaken Encryption), T1557 (Adversary-in-the-Middle), T1090 (Proxy), T1020 (Automated Exfiltration)

---

## Phase 1 — Evidence Integrity

**Goal:** Verify the integrity of all collected artifacts before analysis to maintain forensic soundness.

### 1.1 — Hash Verification of Configuration Exports
- [ ] Verify cryptographic hashes (SHA-256) of all exported configuration files against chain of custody documentation
- [ ] **Specialist Method:** `sleuthkit.hash_file(config_export_path)` for each configuration artifact
- [ ] Flag: any hash mismatch between collected artifact and chain of custody record — do not proceed without resolution
- [ ] Document the collection method for each artifact (console capture, TFTP export, API pull, screen capture)
- [ ] Note whether configurations were captured live (running-config) or from a backup — live capture is preferred

### 1.2 — PCAP Integrity Verification
- [ ] Verify packet captures from mirror ports, network TAPs, or inline capture devices
- [ ] **Specialist Method:** `sleuthkit.hash_file(pcap_path)` — verify PCAP hash pre- and post-analysis
- [ ] Confirm PCAP completeness — check for dropped packets indicator in capture metadata
- [ ] Verify capture interface and VLAN scope — ensure all relevant traffic segments were captured
- [ ] Validate capture timestamps against NTP-synchronized reference — flag clock skew >1 second

### 1.3 — Log Export Integrity
- [ ] Hash all syslog exports, TACACS+/RADIUS log files, and vendor-specific log archives
- [ ] **Specialist Method:** `sleuthkit.hash_file(log_export_path)` for each log file
- [ ] Document log retention period and any known gaps (device reboots, log rotation, syslog server failures)
- [ ] Flag: log timestamps that are inconsistent with known device uptime or maintenance windows

---

## Phase 2 — Configuration Analysis

**Goal:** Detect configuration tampering, backdoor accounts, unauthorized access paths, and weakened security controls.

### 2.1 — Running vs. Startup Configuration Comparison
- [ ] Compare `running-config` against `startup-config` — discrepancies indicate unsaved attacker changes or volatile persistence
- [ ] **Specialist Method:** `logs.parse_evtx(config_diff_output)` or direct text diff analysis
- [ ] Flag: presence of accounts, ACL entries, routes, or tunnel configurations in running-config absent from startup-config
- [ ] Flag: missing entries in startup-config absent from running-config (attacker may have removed startup entries to prevent rebooting persistent changes)
- [ ] Flag: configuration last-modified timestamp does not match expected change management records

### 2.2 — Unauthorized Account Audit
- [ ] Extract all local user accounts from device configuration
- [ ] Compare against authorized user list and privileged access management (PAM) records
- [ ] Flag: accounts not in the authorized user list
- [ ] Flag: accounts with `privilege 15` (Cisco) or equivalent super-user level not approved in PAM
- [ ] Flag: accounts using default credentials (`admin/admin`, `cisco/cisco`, `enable/enable`)
- [ ] Flag: accounts with password hashes using weak algorithms (Cisco Type 7 — reversible; Juniper MD5 — deprecated)
- [ ] Flag: accounts with SSH keys not registered in the authorized key inventory

### 2.3 — Backdoor & Covert Access Detection
- [ ] Scan for unauthorized tunnel configurations:
  - GRE tunnels (`interface tunnel`) to unexpected destinations
  - IP-in-IP encapsulation tunnels
  - SSH port forwards (`GatewayPorts yes` on network devices supporting SSH server)
  - IPsec tunnels to non-enterprise peer IPs
- [ ] Flag: ACL entries with `permit any any` or overly broad permit rules on sensitive interfaces
- [ ] Flag: hidden SNMP community strings — compare against documented communities
- [ ] Flag: `ip helper-address` or `ip forward-protocol` pointing to unauthorized servers (TFTP/DHCP redirection)
- [ ] Flag: `ip nat` rules translating traffic to or from unexpected external addresses

### 2.4 — Management Plane Security Review
- [ ] Audit management access protocols enabled on device:
  - Telnet (unencrypted — flag as HIGH if enabled on any interface)
  - HTTP management (unencrypted — flag as HIGH)
  - SNMP v1/v2c (unauthenticated read/write — flag as HIGH)
  - Unrestricted SSH access (no source ACL applied)
- [ ] Flag: management access permitted from source IPs not in the authorized management network range
- [ ] Flag: VTY lines without ACL (`access-class` in Cisco IOS) restricting source addresses
- [ ] Flag: console/AUX port with no authentication or `no exec-timeout`
- [ ] Flag: AAA not configured (`no aaa new-model` in Cisco IOS — command authorization not enforced)

### 2.5 — DNS & NTP Audit
- [ ] Extract configured DNS server IPs and NTP server IPs from device configuration
- [ ] Compare against authorized DNS/NTP infrastructure list
- [ ] Flag: DNS servers redirected to attacker-controlled IPs (DNS hijacking for C2)
- [ ] Flag: NTP servers pointing to non-authoritative or untrusted sources (timestamp manipulation)
- [ ] Note: NTP tampering affects log timestamp reliability — flag for analyst review

### 2.6 — Cryptographic Weakness Assessment
- [ ] Audit enabled cipher suites and key exchange algorithms for SSH, TLS, and IPsec
- [ ] Flag: SSHv1 enabled (deprecated, vulnerable to MITM)
- [ ] Flag: weak ciphers in SSH config (`arcfour`, `3des-cbc`, `blowfish-cbc`)
- [ ] Flag: IPsec with DES or 3DES encryption, MD5 integrity (MITRE T1600)
- [ ] Flag: TLS 1.0/1.1 enabled on HTTPS management interfaces
- [ ] Flag: SNMP v1/v2c — no authentication, no encryption (T1600)

---

## Phase 3 — Log Analysis

**Goal:** Reconstruct attacker actions via device logs, authentication records, and command audit trails.

### 3.1 — Syslog Review (`logs.parse_evtx`)
- [ ] Ingest all available syslog records from centralized syslog server and local device buffer
- [ ] **Specialist Method:** `logs.parse_evtx(syslog_export_path)` or direct text parsing
- [ ] Flag: severity 0–2 (Emergency, Alert, Critical) messages during incident window
- [ ] Flag: repeated interface flaps (`%LINEPROTO-5-UPDOWN`) — cable disconnect, loop, or attack indicator
- [ ] Flag: `%SYS-5-CONFIG_I` — configuration change logged (who changed what)
- [ ] Flag: CPU/memory threshold alerts (`%SYS-2-MALLOCFAIL`, `%SYS-3-OVERRUN`) — DoS or malware resource consumption
- [ ] Flag: authentication failure bursts (`%SEC-6-IPACCESSLOGP`, `%LOGIN-1-QUIET_MODE_ON`)

### 3.2 — Authentication & Command Audit Logs
- [ ] Extract TACACS+/RADIUS accounting records if AAA is deployed
- [ ] **Specialist Method:** `logs.parse_evtx(aaa_log_path)` for TACACS+/RADIUS exports
- [ ] Flag: successful logins from unexpected source IPs or at anomalous times
- [ ] Flag: `enable` privilege escalation events from standard user accounts
- [ ] Flag: command authorization failures — commands attempted but blocked
- [ ] If TACACS+ command accounting is enabled, extract full command history per session:
  - Flag: `debug ip packet` — packet inspection enabling (data collection)
  - Flag: `copy running-config tftp://` — configuration exfiltration
  - Flag: `write erase` / `no startup-config` — configuration wiping
  - Flag: `reload in` commands — scheduled device reboot (covering tracks)
  - Flag: embedded-event-manager (EEM) applet creation — automation/persistence

### 3.3 — VPN & Tunnel Session Logs
- [ ] Extract VPN session logs (IPsec, SSL-VPN, GRE) from device
- [ ] **Specialist Method:** `logs.parse_evtx(vpn_log_path)` for VPN session records
- [ ] Flag: VPN sessions from unexpected geographic locations or source IPs
- [ ] Flag: session durations far outside the normal range (very short — automated probing; very long — persistent tunnel)
- [ ] Flag: simultaneous VPN sessions for the same user identity from different IPs
- [ ] Flag: new VPN peer IPs not in the authorized peer list

### 3.4 — Connection & Traffic Logs
- [ ] Review firewall/router connection log exports for anomalous traffic patterns
- [ ] **Specialist Method:** `logs.parse_evtx(connection_log_path)` with IP aggregation analysis
- [ ] Flag: high-volume outbound connections to single external IP (potential C2 or exfiltration)
- [ ] Flag: outbound connections on unusual ports from internal infrastructure (DNS tunneling on non-53, ICMP tunneling)
- [ ] Flag: internal-to-internal traffic not consistent with normal east-west patterns (lateral movement)
- [ ] Flag: connections to known Tor exit nodes, bulletproof hosting ASNs, or threat intelligence IOC IPs

---

## Phase 4 — Vendor-Specific Artifact Analysis

**Goal:** Extract and analyze platform-specific forensic artifacts for Cisco IOS/NX-OS, Juniper Junos, Palo Alto PAN-OS, and Fortinet FortiGate.

### 4.1 — Cisco IOS / NX-OS Artifacts (`logs.parse_evtx`)
- [ ] Extract `show logging` output — Cisco internal logging buffer
- [ ] **Specialist Method:** `logs.parse_evtx(cisco_syslog_path)` for exported Cisco syslog data
- [ ] Extract and analyze `show version` — verify IOS version, uptime, and last reload reason
- [ ] Flag: `Reload reason: Reload command` without corresponding change record — unexpected reboot
- [ ] Flag: `Reload reason: Reload by system` — potential crash from exploitation
- [ ] Extract `show running-config` and `show startup-config` for Phase 2 comparison
- [ ] Extract AAA debug logs if `debug aaa authentication` was enabled during incident
- [ ] Cisco NX-OS specific: `show accounting log` — command accounting if NX-OS AAA configured
- [ ] Cisco IOS-XE specific: `show platform integrity` — Secure Boot attestation (detect firmware tampering, T1601)
- [ ] Extract `show ip arp` — ARP table snapshot for Phase 5.1
- [ ] Extract `show mac address-table` — MAC table for Phase 5.2
- [ ] Flag: `%ROMMON` messages in syslog — ROM Monitor access indicates physical access or TFTP boot attack (T1542.005)
- [ ] Flag: `%IOS_RESILIENCE` configuration changes — persistence mechanism via IOS Resilience Feature
- [ ] Check for TCL scripts embedded in flash: `dir flash:*.tcl` — attacker-planted backdoor scripts
- [ ] Check for EEM applets in running-config: `event manager applet` — automated execution persistence

### 4.2 — Juniper Junos Artifacts (`logs.parse_evtx`)
- [ ] Extract Junos system log from `/var/log/messages` and `/var/log/interactive-commands`
- [ ] **Specialist Method:** `logs.parse_evtx(junos_syslog_path)` for Junos log export
- [ ] Extract `show system uptime` and `show version` for baseline comparison
- [ ] Extract `show system commit` — lists all configuration commits with timestamp and user
- [ ] Flag: commits by unexpected users or outside authorized change windows
- [ ] Flag: `rollback` operations — configuration reversal (may indicate attacker removing traces or restoring after testing)
- [ ] Extract `show log interactive-commands` — CLI command history per session (Junos logs all interactive commands)
- [ ] Flag: `request system software add` — software package installation (potential backdoor installation, T1601)
- [ ] Flag: `set system scripts` — SLAX/Python automation scripts (persistence)
- [ ] Flag: `set system services` changes enabling unexpected services (Telnet, FTP, TFTP)
- [ ] Extract `/var/db/scripts/` — Junos commit/event/op scripts (persistence location)
- [ ] Junos Routing Engine: extract `show route` and `show bgp summary` for Phase 5.3 and 5.4

### 4.3 — Palo Alto PAN-OS Artifacts (`logs.parse_evtx`)
- [ ] Export Traffic Logs, Threat Logs, and Configuration Audit Logs from Panorama or local device
- [ ] **Specialist Method:** `logs.parse_evtx(paloalto_log_path)` for PAN-OS log exports
- [ ] Traffic Log analysis:
  - Flag: `allowed` connections to threat intelligence IOC IPs or domains
  - Flag: high session counts from single source IP (scanning/exfiltration)
  - Flag: unusual applications detected on non-standard ports
- [ ] Threat Log analysis:
  - Flag: `vulnerability` and `wildfire-virus` severity Critical/High events — exploitation attempts
  - Flag: `spyware` signatures triggered from inside to outside — malware C2
  - Flag: `url-filtering` blocks on C2 categories (command-and-control, malware, dynamic-dns)
- [ ] Configuration Audit Log analysis:
  - Extract configuration changes from `Monitor > Logs > Configuration`
  - Flag: changes by unexpected administrators or service accounts
  - Flag: Security policy changes allowing broad `any-any` rules
  - Flag: changes to certificate profiles, authentication profiles, or admin accounts
- [ ] Extract `show system info` — PAN-OS version, serial, uptime
- [ ] Verify PAN-OS version against known CVEs — especially CVE-2024-3400 (command injection) and similar critical vulnerabilities
- [ ] Extract GlobalProtect VPN logs for Phase 3.3
- [ ] Check for custom threat signatures or security profile modifications — attacker may weaken detection

### 4.4 — Fortinet FortiGate Artifacts (`logs.parse_evtx`)
- [ ] Export FortiGate event logs, traffic logs, and VPN logs from FortiAnalyzer or local disk
- [ ] **Specialist Method:** `logs.parse_evtx(fortigate_log_path)` for FortiGate log exports
- [ ] Event Log analysis:
  - Flag: `event_type=admin` — administrative actions (login, config changes, password changes)
  - Flag: `action=login` with `status=failed` repeated — brute force attempts
  - Flag: `action=login` with `status=success` from unexpected source IPs
  - Flag: `event_type=system` changes to NTP, DNS, or routing
- [ ] Traffic Log analysis — similar to PAN-OS Phase 4.3
- [ ] VPN Log analysis:
  - Extract SSL-VPN and IPsec tunnel session logs
  - Flag: sessions from unexpected source IPs or geographic locations
  - Flag: CVE-2022-42475, CVE-2023-27997 exploitation indicators (FortiOS SSL-VPN heap overflow)
- [ ] Extract `get system status` — FortiOS version for CVE correlation
- [ ] Check for `execute` commands in event logs — direct CLI execution by admin accounts
- [ ] Check for FGFM (FortiManager) management connections to unexpected FortiManager IPs
- [ ] Verify firmware integrity: `execute verify image` output against Fortinet published hashes

---

## Phase 5 — Network Mapping & Topology Analysis

**Goal:** Reconstruct network topology at time of compromise to identify unauthorized devices, routes, and ARP anomalies.

### 5.1 — ARP Table Analysis
- [ ] Export ARP tables from all routers and Layer-3 switches in scope
- [ ] **Specialist Method:** `logs.parse_evtx(arp_table_export)` or direct text parsing
- [ ] Flag: duplicate IP-to-MAC mappings (same IP appearing with two different MACs) — ARP poisoning indicator (T1557)
- [ ] Flag: duplicate MAC-to-IP mappings (same MAC answering for multiple IPs) — ARP spoofing/proxy
- [ ] Cross-reference MAC addresses against vendor OUI database — flag unknown or suspicious vendors
- [ ] Flag: ARP entries for router gateway IPs with MACs not matching the authorized router hardware inventory

### 5.2 — MAC Address Table Audit
- [ ] Export MAC address tables from all Layer-2 switches in scope
- [ ] Compare against authorized device asset inventory (MAC → port → device name)
- [ ] Flag: MAC addresses not in the asset inventory appearing on production ports
- [ ] Flag: multiple MAC addresses appearing on access ports (should typically be 1 per port — indicates hub, switch, or unauthorized device)
- [ ] Flag: port-security violations (`show port-security interface` on Cisco)
- [ ] Correlate rogue MAC addresses with ARP table to determine IP address of unauthorized device

### 5.3 — Routing Table Review
- [ ] Export routing tables from all routers in scope (`show ip route`, `show route`)
- [ ] Compare against baseline routing table if available
- [ ] Flag: unexpected static routes added by attackers (e.g., `ip route 0.0.0.0 0.0.0.0 [attacker-IP]` — traffic hijacking)
- [ ] Flag: routes pointing to non-enterprise next-hop IPs
- [ ] Flag: routes for internal networks advertised toward the Internet (data leakage risk)
- [ ] Flag: floating static routes with administrative distance suggesting failover bypass

### 5.4 — BGP Route Injection Detection
- [ ] Export BGP routing tables and BGP peer status from all BGP-speaking devices
- [ ] **Specialist Method:** `logs.parse_evtx(bgp_log_path)` for BGP peer state change messages
- [ ] Flag: new BGP peers established during or after incident window
- [ ] Flag: unexpected route advertisements received from established peers — BGP hijack indicator
- [ ] Flag: route advertisements for IP space not owned by the organization or authorized upstreams
- [ ] Flag: `BGP_NEIGHBOR_CHANGE` messages for peer flaps during incident window
- [ ] Cross-reference advertised prefixes against RIR (ARIN, RIPE, APNIC) ownership data
- [ ] Flag: route leaks — internal prefixes appearing in external BGP tables (visible via BGP route monitoring services)

### 5.5 — VLAN Analysis
- [ ] Export VLAN database and trunking configuration from all switches
- [ ] Flag: unauthorized VLAN IDs added to trunk ports (VLAN hopping preparation)
- [ ] Flag: VLAN configurations changed to route sensitive VLANs to unexpected trunks
- [ ] Flag: native VLAN mismatches on trunk links (double-tagging VLAN hopping vector)
- [ ] Flag: dynamic trunking protocol (DTP) enabled on access ports — allows trunk negotiation by unauthorized device
- [ ] Correlate VLAN changes with configuration audit log timestamps

---

## Phase 6 — Firmware Analysis

**Goal:** Verify firmware integrity and detect implanted or modified system images (MITRE T1601).

### 6.1 — Version & Integrity Verification (`sleuthkit.extract_strings`)
- [ ] Extract running firmware version from `show version`, `get system status`, or equivalent
- [ ] **Specialist Method:** `sleuthkit.extract_strings(firmware_image_path)` for extracted firmware binary analysis
- [ ] Compare firmware version/build against official vendor release notes and known-good hash databases
- [ ] Flag: firmware version not found in vendor's official release list — potential implant (T1601)
- [ ] Flag: firmware build date inconsistent with official release date for that version

### 6.2 — CVE Mapping
- [ ] Map identified firmware version to CVE databases (NVD, vendor security advisories)
- [ ] Flag: critical/high CVEs with public exploit code available for identified firmware version
- [ ] Document potential exploitation vectors (remote code execution, authentication bypass, privilege escalation)
- [ ] Cross-reference flagged CVE exploitation methods with log artifacts from Phase 3 to confirm exploitation

### 6.3 — Firmware Binary Analysis (`sleuthkit.extract_strings`)
- [ ] Extract firmware image from TFTP backup or flash filesystem if accessible
- [ ] **Specialist Method:** `sleuthkit.extract_strings(firmware_image_path)` targeting suspicious strings
- [ ] Search extracted firmware for:
  - Hardcoded IP addresses not in vendor documentation
  - Base64-encoded strings (potential obfuscated payloads)
  - Non-standard shell commands or reverse shell patterns
  - Unexpected SSH authorized keys embedded in image
- [ ] Compare firmware file hash against vendor-published MD5/SHA-256 checksums
- [ ] Flag: any firmware modification — treat as full device compromise requiring hardware replacement

### 6.4 — Secure Boot & Image Signing Verification
- [ ] For Cisco IOS-XE: `show platform integrity` — verifies boot image signature chain
- [ ] For Palo Alto PAN-OS: check `System > Dashboard` for software integrity status
- [ ] For Fortinet: `execute verify image` against Fortinet code signing certificate
- [ ] Flag: any integrity verification failure — indicates modified boot image (T1601)
- [ ] Flag: ROMMON access artifacts in logs — indicates boot-level tampering (T1542.005)
- [ ] Note: TFTP boot attack (T1542.005) — attacker boots device from attacker-controlled TFTP server image, bypassing local integrity checks

---

## Phase 7 — Rogue Device Detection

**Goal:** Identify unauthorized network devices, access points, and shadow IT infrastructure.

### 7.1 — Unauthorized Device Scan
- [ ] Compare all MAC addresses from Phase 5.2 against authorized asset inventory
- [ ] **Specialist Method:** `logs.parse_evtx(dhcp_log_path)` for DHCP lease records — reveals all devices that requested addresses
- [ ] Flag: MAC addresses not in asset inventory receiving DHCP leases
- [ ] Cross-reference DHCP lease timestamps with incident window
- [ ] Flag: devices with short DHCP lease times suggesting intentional transient presence

### 7.2 — Rogue Access Point Detection
- [ ] Query wireless infrastructure for detected neighboring SSIDs and BSSIDs
- [ ] Compare detected BSSIDs against authorized wireless AP inventory
- [ ] Flag: SSIDs matching or similar to corporate SSID from unauthorized BSSID (evil twin AP)
- [ ] Flag: ad-hoc wireless networks detected in enterprise areas
- [ ] Correlate rogue AP BSSID with switch MAC address tables to identify physical port location

### 7.3 — Unauthorized DHCP & Gateway Detection
- [ ] Analyze DHCP server logs for unexpected DHCP OFFER or DHCP ACK from unauthorized servers
- [ ] Flag: DHCP OFFER messages not originating from authorized DHCP server IPs
- [ ] Flag: DHCP options advertising different default gateway than authorized (MITM setup)
- [ ] Flag: DHCP options advertising different DNS servers than authorized (DNS hijacking setup)
- [ ] Cross-reference with syslog DHCP snooping violations if configured

### 7.4 — Port Security & Physical Access Audit
- [ ] Extract port-security violation logs from all access layer switches
- [ ] Flag: ports with security violations during incident window — unauthorized device plugged in
- [ ] Flag: unused ports that became active during incident window (physical access indicator)
- [ ] Cross-reference active port changes with physical access log records (badge access, CCTV timestamps if available)
- [ ] Flag: `sticky` MAC address changes on ports — port-security bypass attempt

---

## Phase 8 — SNMP Abuse Detection

**Goal:** Identify SNMP community string abuse and unauthorized SNMP-based reconnaissance or configuration modification.

### 8.1 — SNMP Community String Audit
- [ ] Extract all configured SNMP community strings from device configuration
- [ ] Flag: read-write (`RW`) community strings configured — allows full configuration modification via SNMP
- [ ] Flag: community strings matching default values (`public`, `private`, `community`, device hostname)
- [ ] Flag: SNMP v1/v2c configured — no authentication, community strings in cleartext on wire
- [ ] Cross-reference community strings against PCAP data — flag if cleartext community strings observed in traffic capture

### 8.2 — SNMP Access Anomaly Detection
- [ ] Review SNMP access control lists and permitted management source IPs
- [ ] Flag: SNMP queries from IPs not in the authorized management network
- [ ] Extract SNMP trap destinations — flag traps being sent to unexpected external IPs (data exfiltration via SNMP trap)
- [ ] **Specialist Method:** `logs.parse_evtx(snmp_log_path)` if SNMP access logging is enabled
- [ ] Flag: `SNMP-5-COLDSTART` or `SNMP-5-WARMSTART` traps — device reboots (potential firmware flash)
- [ ] Flag: SNMP `SET` operations — configuration modification via SNMP (requires RW community)
- [ ] Note: SNMP v3 with authPriv provides authentication and encryption — if v1/v2c is required, treat all intercepted traffic as potentially compromised

---

## Phase 9 — PCAP Correlation

**Goal:** Correlate network traffic captures with device log findings to confirm attack vectors and data exfiltration.

### 9.1 — PCAP Acquisition & Analysis
- [ ] Confirm PCAP scope covers the incident window and relevant network segments
- [ ] Cross-reference with PB-SIFT-036 for full PCAP forensics methodology
- [ ] **Specialist Method:** `pcap.analyze_traffic(pcap_path)` for protocol and flow analysis
- [ ] Filter PCAP for traffic to/from flagged IPs from log analysis (Phase 3.4)
- [ ] Extract and reconstruct TCP sessions involving device management ports (22, 23, 80, 443, 161, 162)

### 9.2 — Protocol Anomaly Detection in PCAP
- [ ] Flag: Telnet sessions to device management IPs — plaintext credential capture
- [ ] Flag: SNMPv1/v2c GET/SET operations — extract community strings from plaintext traffic
- [ ] Flag: TFTP sessions to/from device IPs — firmware upload/download (T1542.005, T1601)
- [ ] Flag: unusual ICMP traffic to/from devices (ICMP tunneling for C2, T1090)
- [ ] Flag: DNS queries from network devices to non-authorized DNS servers (DNS hijacking confirmation)
- [ ] Flag: BGP session establishment with unauthorized peer IPs (Phase 5.4 confirmation)

### 9.3 — Exfiltration Pattern Detection in PCAP
- [ ] Identify high-volume outbound flows from internal IPs to single external destination
- [ ] Flag: large outbound transfers on ports 53 (DNS tunneling), 443 (HTTPS), or ICMP (covert channels)
- [ ] Flag: protocol anomalies: DNS queries with unusually long labels (DNS tunneling), HTTP with encoded payloads in URI
- [ ] Correlate exfiltration flow timestamps with device configuration change events (Phase 2.1)
- [ ] Cross-reference PCAP findings with Phase 7 (Exfiltration playbook PB-SIFT-007) if data theft is confirmed

---

## Phase 10 — Timeline Construction

**Goal:** Build a unified, chronological attack timeline across all network device artifacts.

### 10.1 — Event Correlation (`plaso.create_timeline`)
- [ ] Align all timestamped artifacts into a single master timeline:
  - Syslog events (Phase 3.1)
  - Authentication events (Phase 3.2)
  - Configuration changes (Phase 2.1, vendor-specific Phase 4)
  - BGP/routing anomalies (Phase 5.3, 5.4)
  - PCAP flow timestamps (Phase 9)
- [ ] **Specialist Method:** `plaso.create_timeline(evidence_paths)` incorporating log exports and PCAP metadata
- [ ] Normalize all timestamps to UTC — flag any devices with clock skew against NTP reference

### 10.2 — Causality Mapping
- [ ] Map initial access vector (e.g., SSH brute force, CVE exploitation, SNMP abuse) to first attacker action
- [ ] Trace configuration changes to subsequent network anomalies (e.g., backdoor tunnel creation → outbound C2 traffic)
- [ ] Identify dwell time: first unauthorized access timestamp to discovery/containment
- [ ] Correlate network device compromise timestamps with broader enterprise endpoint IR timeline (PB-SIFT-016)

### 10.3 — External Log Correlation
- [ ] Match device syslog timestamps with external NetFlow or IPFIX records from network collector
- [ ] Correlate device authentication logs with enterprise Active Directory authentication logs (EID 4624/4625)
- [ ] Cross-reference with SOC SIEM alert timestamps to identify detection gaps
- [ ] Flag: evidence of log deletion or manipulation (Phase 1.3) that creates gaps in timeline

---

## Phase 11 — Scoring & Output

**Goal:** Prioritize findings for network engineering, SOC, and executive analyst handoff.

- [ ] **Severity Matrix:**
  - **Critical:** Confirmed firmware modification or implant (T1601); CloudTrail-equivalent log deletion (`no logging` or log wipe); BGP route injection confirmed redirecting external traffic; ROMMON access indicating physical or boot-level compromise (T1542.005); read-write SNMP community exposed with confirmed SET operations; device rebooted from attacker-controlled TFTP image (T1542.005)
  - **High:** Unauthorized admin account with privilege 15 confirmed; running-config vs startup-config discrepancy with malicious additions; VPN session from unauthorized geographic location with confirmed data access; ARP poisoning confirmed via PCAP; Conditional Access equivalent (ACL) bypass confirmed; encryption weakened on IPsec tunnels (T1600); rogue device confirmed on production network segment
  - **Medium:** Weak SNMP community strings (no confirmed exploitation); legacy authentication protocols enabled (Telnet, HTTP, SNMPv1); NTP/DNS configuration pointing to unauthorized servers (no confirmed abuse); failed privilege escalation attempts; VLAN hopping indicators without confirmed exploitation
  - **Low:** Outdated but unpatched firmware without confirmed exploitation; minor configuration deviations from hardening baseline; historical failed authentication attempts without success; unused ports with activity far outside incident window

- [ ] **MITRE ATT&CK Mapping:**
  - T1542.005 — Pre-OS Boot: TFTP Boot
  - T1601 — Modify System Image
  - T1601.001 — Modify System Image: Patch System Image
  - T1601.002 — Modify System Image: Downgrade System Image
  - T1600 — Weaken Encryption
  - T1600.001 — Weaken Encryption: Reduce Key Space
  - T1600.002 — Weaken Encryption: Disable Crypto Hardware
  - T1557 — Adversary-in-the-Middle
  - T1557.002 — Adversary-in-the-Middle: ARP Cache Poisoning
  - T1090 — Proxy
  - T1090.001 — Proxy: Internal Proxy
  - T1020 — Automated Exfiltration
  - T1078 — Valid Accounts
  - T1078.001 — Valid Accounts: Default Accounts
  - T1110 — Brute Force
  - T1110.001 — Brute Force: Password Guessing
  - T1046 — Network Service Discovery
  - T1040 — Network Sniffing
  - T1190 — Exploit Public-Facing Application (CVE exploitation of device management interface)
  - T1133 — External Remote Services (VPN abuse)
  - T1005 — Data from Local System (configuration exfiltration via SNMP/TFTP)

- [ ] **Structured Output:** JSON with per-device finding summaries, flagged configurations, authentication anomalies, firmware integrity status, and severity scores
- [ ] **Analyst Handoff:** Bundle running-config exports, syslog archives, PCAP files, firmware image hashes, ARP/MAC table exports, and BGP routing tables for senior analyst and network engineering review
