# PB-SIFT-019: Command & Control Detection Playbook
## C2 Infrastructure — Static Image Analysis

**Objective:** High-fidelity detection of command-and-control infrastructure, beaconing behavior, DNS tunneling, and persistent C2 channels within a forensic image. This playbook runs when C2 indicators are identified during triage (PB-SIFT-000) or when network artifacts suggest active C2 communication.

---

### Phase 1 — Evidence Integrity
- [ ] **Hash Verification:** Verify hash of all evidence against chain of custody.
- [ ] **Integrity Check:** Flag any mismatch before proceeding.

---

### Phase 2 — Network State Extraction
- [ ] **Established Connections:** Extract all established and listening network connections from memory (`vol.py windows.netscan.NetScan`).
- [ ] **DNS Cache:** Extract DNS resolver cache (`vol.py windows.dnscache.DnsCache`).
- [ ] **Connection Timeline:** Map network connection timestamps to timeline.
- [ ] **Beacon Detection:** Identify periodic outbound connections — flag connections with regular intervals (beacon behavior).
- [ ] **Uncommon Ports:** Flag connections to non-standard ports (not 80, 443, 53, 25, 22).
- [ ] **Long-Duration Connections:** Flag connections with extended duration — potential persistent C2 channels.

---

### Phase 3 — C2 Tool & Infrastructure Detection
- [ ] **Known C2 Binaries:** Scan for known C2 tool signatures — Cobalt Strike, Covenant, Sliver, Mythic, Metasploit, Empire, PoshC2.
- [ ] **C2 Framework Artifacts:** Check for Beacon configuration artifacts, named pipes, and mutexes.
- [ ] **DNS Tunneling:** Check for abnormal DNS query patterns — high-length subdomains, excessive TXT queries, unusual base64 in responses.
- [ ] **HTTPS C2:** Check for connections to low-reputation domains with cert analysis — self-signed certs, recently registered domains, Let's Encrypt on suspicious IPs.
- [ ] **Process Injection C2:** Check for processes with injected code — flag `rundll32.exe`, `svchost.exe`, or `explorer.exe` making outbound network connections.
- [ ] **Scheduled C2:** Check scheduled tasks and WMI subscriptions for C2 persistence callbacks.

---

### Phase 4 — Host-Based C2 Indicators
- [ ] **Autorun C2:** Check Run/RunOnce keys for C2 callback commands or encoded PowerShell.
- [ ] **Service C2:** Check for services with unusual binary paths or services connecting outbound.
- [ ] **Persistence Registry:** Check WMI event subscriptions, COM hijacks, and shell extensions for C2 callback mechanisms.
- [ ] **LOLBins as C2:** Flag LOLBin network activity — `certutil -urlcache`, `bitsadmin /transfer`, `mshta http`, `msiexec /i http`.
- [ ] **Encoded Commands:** Flag Base64-encoded PowerShell commands in process history, especially those containing `IEX`, `DownloadString`, `DownloadData`.

---

### Phase 5 — PCAP & Log Correlation (if available)
- [ ] **Traffic Volume Analysis:** Identify hosts with outbound traffic volume spikes during off-hours.
- [ ] **TLS Fingerprinting:** Extract TLS SNI values and JA3 hashes from PCAP for C2 server identification.
- [ ] **DNS Pattern Analysis:** Identify domains with algorithmic naming patterns (DGA), high query frequency, or new fast-flux domains.
- [ ] **Proxy Log Review:** Check proxy logs for CONNECT method to suspicious destinations.
- [ ] **Firewall Log Review:** Check firewall logs for outbound connections to known C2 IP ranges.
- [ ] **Event Correlation:** Correlate EID 4624 (logon) with EID 3 (network connection in Sysmon) for C2 callback timing.

---

### Phase 6 — C2 Infrastructure Mapping
- [ ] **C2 Server Identification:** Map all identified C2 IPs/domains to infrastructure — hosting provider, AS, geolocation, registration date.
- [ ] **Kill Chain Position:** Map each C2 artifact to the kill chain stage — initial access, persistence, lateral movement, exfiltration.
- [ ] **Second-Stage Payloads:** Identify any downloaded payloads from C2 servers — flag binaries, scripts, or DLLs pulled from C2.
- [ ] **Lateral C2:** Check if C2 tools were used for lateral movement — `psexec` from C2, `winrm` to other hosts, WMI remote execution.
- [ ] **Data Flow Mapping:** Map data flow from host → C2 server to determine what was exfiltrated.

---

### Phase 7 — Score & Report
- [ ] **Aggregation:** Aggregate all flags into findings report.
- [ ] **MITRE Mapping:** Identify technique per MITRE ATT&CK:
    - **T1071.001:** Application Layer Protocol — Web Protocols
    - **T1071.004:** Application Layer Protocol — DNS
    - **T1573.001:** Encrypted Channel — Symmetric Cryptography
    - **T1573.002:** Encrypted Channel — Asymmetric Cryptography
    - **T1105:** Ingress Tool Transfer
    - **T1571:** Non-Standard Port
    - **T1008:** Fallback Channels
    - **T1568.002:** Dynamic Resolution — Domain Generation Algorithms
    - **T1568.003:** Dynamic Resolution — DNS Calculation
- [ ] **Severity Scoring:** Score by severity — any confirmed C2 channel is **CRITICAL**.
- [ ] **Confidence Assessment:** High confidence if beacon pattern + known C2 tool + network artifacts all agree.
- [ ] **C2 Summary:** Produce C2 infrastructure summary with IPs, domains, protocols, and kill chain positions.
- [ ] **Final Output:** Output structured findings file for analyst handoff.