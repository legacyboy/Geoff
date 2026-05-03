# PB-SIFT-019: Command & Control Detection Playbook
## C2 Infrastructure — Static Image Analysis

**Objective:** High-fidelity detection of command-and-control infrastructure, beaconing behavior, DNS tunneling, and persistent C2 channels within a forensic image. This playbook runs when C2 indicators are identified during triage (PB-SIFT-000) or when network artifacts suggest active C2 communication.
**Specialist:** `memory, network, registry, logs`

---

### Phase 1 — Evidence Integrity
- [ ] **Hash Verification:** Verify hash of all evidence against chain of custody.
- [ ] **Integrity Check:** Flag any mismatch before proceeding.

---

### Phase 2 — Network State Extraction
- [ ] **Established Connections:** Extract all established and listening network connections from memory (`memory.extract_network`).
- [ ] **DNS Cache:** Extract DNS resolver cache (network DNS cache analysis).
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
    - **Command:** `tshark -r <file.pcap> -T fields -e frame.time -e ip.src -e ip.dst -e tls.handshake.ja3 -e tls.handshake.ja3s -e tls.handshake.extensions_server_name -Y "tls.handshake.type == 1 or tls.handshake.type == 2" 2>/dev/null`
    - Known C2 JA3 hashes to flag: Cobalt Strike default `72a589da586844d7f0818ce684948eea`, Metasploit `d0ec4b50a944b182f739f6e4113fa7eb`
    - Flag: SNI mismatch with certificate CN/SAN — C2 traffic hiding under legitimate SNI
    - Flag: TLS to IP address (no SNI / IP in SNI field) — direct-IP C2 without domain fronting
- [ ] **DNS Tunneling Detection:**
    - **Command:** `tshark -r <file.pcap> -T fields -e frame.time -e ip.src -e dns.qry.name -e dns.resp.type -Y dns | awk 'length($3) > 50'` — flag subdomains >50 chars
    - **Command:** `tshark -r <file.pcap> -T fields -e dns.qry.name -Y "dns.qry.type == 16"` — DNS TXT record queries (tunneling exfil channel)
    - Flag: high unique subdomain count under same domain — DGA or DNS C2 beaconing
    - Flag: Shannon entropy of subdomain >3.5 — encoded data in DNS labels
    - Flag: query volume >1000/hour to a single domain — C2 polling
- [ ] **DGA Detection:**
    - Flag domains with 12+ character random-looking second-level domain (SLD) with no WHOIS history
    - **Command:** `tshark -r <file.pcap> -T fields -e dns.qry.name -Y "dns.flags.rcode == 3"` — NXDOMAIN storm from DGA enumeration
    - Clusters of NXDOMAIN responses from a single source = DGA enumeration in progress
- [ ] **Beacon Timing Analysis:**
    - **Command:** `tshark -r <file.pcap> -T fields -e frame.time_epoch -e ip.dst -Y "tcp.flags.syn==1 and not tcp.flags.ack==1" | sort -k2 | awk '...'` — extract SYN timestamps per destination
    - Low jitter (stddev < 10% of interval) on connections to same external IP = C2 beacon
- [ ] **Proxy Log Review:** Check proxy logs for CONNECT method to suspicious destinations.
- [ ] **Firewall Log Review:** Check firewall logs for outbound connections to known C2 IP ranges.
- [ ] **Event Correlation:** Correlate EID 4624 (logon) with EID 3 (network connection in Sysmon) for C2 callback timing.
- **SANS FOR572 Alignment:** TLS JA3 fingerprinting and DNS tunneling detection are **★★★★★** — the primary techniques for identifying encrypted C2 in PCAPs. SANS FOR572 (Advanced Network Forensics) emphasises these as core skills.

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