# PB-SIFT-014: Network Device Forensics Playbook
## Network Hardware Analysis — Routers, Switches, Firewalls, Access Points

**Objective:** High-fidelity forensic analysis of network infrastructure devices to identify unauthorized access, configuration tampering, rogue devices, and malicious traffic patterns.

---

### Phase 1 — Evidence Integrity
- [ ] **Hash Verification:** Verify hashes of all exported configuration files, log dumps, and firmware images against the chain of custody.
- [ ] **Integrity Check:** Flag any mismatch in hash values before proceeding with analysis.
- [ ] **Capture Validation:** Ensure packet captures (PCAPs) from mirror ports or TAPs are complete and not truncated.

---

### Phase 2 — Configuration Analysis
- [ ] **Config Comparison:** Compare `running-config` vs `startup-config` — flag discrepancies indicating unsaved changes or volatile persistence.
- [ ] **Account Audit:** Review local user accounts and passwords — flag unauthorized accounts, default credentials, or shared admin accounts.
- [ ] **Backdoor Detection:** Scan for unauthorized tunnels (GRE, SSH, VPN), unexpected "permit any" rules in ACLs, or hidden SNMP communities.
- [ ] **Management Plane Review:** Check for unauthorized management access (Telnet, HTTP, SSH) enabled from unexpected source IPs.
- [ ] **DNS/NTP Audit:** Verify DNS and NTP settings — flag redirection to rogue servers used for C2 or timestamp manipulation.

---

### Phase 3 — Log Analysis
- [ ] **Syslog Review:** Analyze centralized and local syslogs for critical errors, interface flaps, or repeated authentication failures.
- [ ] **Authentication Logs:** Flag successful logins from unexpected IPs or at anomalous times (EID/Message correlation).
- [ ] **Connection Logs:** Review firewall/router connection logs for high-volume outbound traffic to unknown external IPs.
- [ ] **Command Audit Logs:** If enabled, review `archive log` or `TACACS+/RADIUS` logs to identify specific commands executed by attackers.
- [ ] **VPN/Tunnel Logs:** Analyze VPN session logs for unauthorized tunnel establishment or anomalous session durations.

---

### Phase 4 — Firmware Analysis
- [ ] **Version Verification:** Compare running firmware version/build against official vendor releases — flag unofficial or modified versions.
- [ ] **CVE Mapping:** Map the identified firmware version to known vulnerabilities (CVEs) to determine potential entry vectors.
- [ ] **Binary Analysis:** If possible, extract firmware image and scan for embedded malicious scripts, hardcoded credentials, or webshells.
- [ ] **Checksum Validation:** Verify the firmware image checksum against the vendor's provided hash.

---

### Phase 5 — Network Mapping
- [ ] **ARP Table Analysis:** Export ARP tables — flag IP-to-MAC mismatches or unexpected duplicate MAC addresses (ARP spoofing).
- [ ] **MAC Table Audit:** Review switch MAC address tables — identify ports hosting unexpected device types or unauthorized vendors.
- [ ] **Routing Table Review:** Analyze routing tables for static routes pointing to malicious gateways or unexpected "black holes."
- [ ] **VLAN Analysis:** Check for VLAN hopping indicators or unauthorized VLAN assignments to sensitive ports.

---

### Phase 6 — Rogue Device Detection
- [ ] **Unauthorized Device Scan:** Compare current connected devices against the official asset inventory.
- [ ] **Rogue AP Detection:** Identify unauthorized wireless access points via SSID scanning or MAC address correlation on switch ports.
- [ ] **Shadow IT Identification:** Flag devices performing unauthorized DHCP services or acting as unauthorized gateways.
- [ ] **Port Security Audit:** Review `sticky` MAC addresses or port-security violations on switches.

---

### Phase 7 — Timeline Construction
- [ ] **Event Correlation:** Align syslogs, authentication events, and configuration change timestamps into a master timeline.
- [ ] **Causality Mapping:** Correlate configuration changes with subsequent network anomalies or data exfiltration patterns.
- [ ] **External Correlation:** Match device timestamps with external firewall logs or NetFlow data from the rest of the environment.

---

### Phase 8 — Score & Report
- [ ] **Aggregation:** Consolidate all flags (config, logs, firmware, rogue devices) into a comprehensive findings report.
- [ ] **Impact Analysis:** Determine the scope of the compromise (e.g., full network visibility, data interception, or denial of service).
- [ ] **MITRE Mapping:** Map findings to MITRE ATT&CK techniques (e.g., T1542.001 — Pre-boot Execution, T1557 — Adversary-in-the-Middle, T1078 — Valid Accounts).
- [ ] **Final Output:** Score by severity (Low/Med/High/Critical) — provide structured remediation steps for the network engineering team.