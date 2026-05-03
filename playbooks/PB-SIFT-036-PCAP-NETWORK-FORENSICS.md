# PB-SIFT-036: PCAP & Network Forensics
## PCAP & Network Forensics — Attack Traffic Reconstruction & C2 Detection

**Objective:** Deep packet analysis using PCAP files, Zeek/Bro logs, NetFlow records, and firewall logs to reconstruct attack network activity, identify C2 channels, detect data exfiltration, and map lateral movement.
**Specialist:** `memory` (network connections), `logs` (Zeek/firewall)
**MITRE Mapping:** T1071 (Application Layer Protocol), T1573 (Encrypted Channel), T1048 (Exfiltration Over Alternative Protocol), T1095 (Non-Application Layer Protocol), T1090 (Proxy), T1041 (Exfiltration Over C2 Channel)

---

## Phase 1 — PCAP Triage & Overview

**Goal:** Validate PCAP integrity, establish scope, and identify top-priority traffic for deeper analysis.

### 1.1 — File Validation & Metadata
- [ ] Validate capture file format and integrity: `capinfos <file.pcap>`
  - Record: capture duration, total packet count, average/peak data rates, capture type (full packet vs header-only), encapsulation type
- [ ] Flag captures with unexpectedly low packet counts or short duration relative to incident window — may indicate incomplete capture or evidence gap
- [ ] Verify PCAP timestamps align with incident timeline — check for timezone offsets or clock skew between capture host and event logs
- [ ] For large PCAPs (>1 GB): split by time window or host before deep analysis:
  - By time: `editcap -A "2024-01-15 08:00:00" -B "2024-01-15 10:00:00" in.pcap window.pcap`
  - By host: `tcpdump -r in.pcap -w out.pcap host X.X.X.X`
- [ ] **Tool:** `capinfos`, `editcap`, `tcpdump`

### 1.2 — Protocol Distribution Analysis
- [ ] Protocol hierarchy: `tshark -r <file.pcap> -qz io,phs`
  - Flag unusual protocol ratios (e.g., high ICMP volume, DNS traffic exceeding 5% of total, raw TCP without recognized application layer)
- [ ] Conversation listing by bytes: `tshark -r <file.pcap> -qz conv,tcp`
  - Identify top talkers — hosts exchanging the most data are primary analysis targets
- [ ] Quick IOC extraction — top destination IPs and ports:
  - `tshark -r <file.pcap> -T fields -e ip.dst -e tcp.dstport | sort | uniq -c | sort -rn | head -50`
- [ ] Identify non-standard port usage: HTTP on non-80/443, DNS on non-53, SSH on non-22 — C2 often uses alternate ports to blend with firewall rules
- [ ] Flag internal-to-internal traffic on ports typically reserved for internet-facing services — lateral movement indicator
- [ ] **Tool:** `tshark`, `capinfos`, `editcap`, `tcpdump`
- [ ] **SANS FOR572 Alignment:** Protocol distribution anomalies are the **fastest triage signal** — a PCAP with 40% DNS traffic from a single host warrants immediate DNS tunnel investigation

---

## Phase 2 — DNS Analysis

**Goal:** Detect DNS-based C2 channels, tunneling, and DGA beaconing.

### 2.1 — DNS Query Extraction & Baseline
- [ ] Extract all DNS queries with timestamps and responses:
  - `tshark -r <file.pcap> -T fields -e frame.time -e ip.src -e dns.qry.name -e dns.resp.addr -Y dns`
- [ ] Establish baseline: what DNS servers are used, what domains are queried most frequently
- [ ] Flag queries to non-organizational DNS servers from internal hosts — DNS bypass indicator
- [ ] **Tool:** `tshark -Y dns`, Zeek `dns.log`

### 2.2 — DGA (Domain Generation Algorithm) Detection
- [ ] Flag high-entropy domain names: domains with **Shannon entropy > 3.5** are DGA indicators
  - Legitimate domains: `google.com` (entropy ~2.8), DGA domains: `xkqzmbvrtpl.com` (entropy ~4.2)
- [ ] Flag domains with high consonant-to-vowel ratios — DGA characteristic
- [ ] Flag domains with no historical resolution (NXDOMAIN storm) from a single host — DGA enumeration where the bot cycles through generated domains seeking the live C2
- [ ] Correlate NXDOMAIN responses with successful resolutions that immediately follow — the successful resolution is the active C2 domain
- [ ] **Tool:** `tshark -Y dns`, Zeek `dns.log`, custom entropy calculation scripts

### 2.3 — DNS Tunneling Detection
- [ ] Flag long subdomain labels (>50 characters per label) — data encoded in subdomain = DNS tunneling
- [ ] Flag many unique subdomains of the same parent domain from a single host within a short window — data exfil or C2 via DNS subdomain encoding
- [ ] Flag TXT record queries — primary mechanism for DNS tunneling return channel (C2 commands returned in TXT responses)
- [ ] Flag uncommon record types from internal hosts: `NULL`, `ANY` queries, `PTR` queries to non-RFC1918 space
- [ ] Measure DNS payload sizes — legitimate DNS queries rarely exceed 100 bytes; tunneled queries often exceed 200 bytes
- [ ] Known DNS tunneling tools: `dnscat2` (uses NULL and TXT records), `iodine` (uses NULL/CNAME/TXT/MX), `dns2tcp`
- [ ] **Tool:** `tshark -Y dns`, Zeek `dns.log`, `dnscat2` traffic pattern matching

### 2.4 — DNS over HTTPS (DoH) Detection
- [ ] Flag HTTPS connections to known DoH providers — used by malware to hide DNS queries from network monitoring:
  - Google: `8.8.8.8:443`, `8.8.4.4:443`
  - Cloudflare: `1.1.1.1:443`, `1.0.0.1:443`
  - Quad9: `9.9.9.9:443`
- [ ] Extract SNI values from TLS ClientHello: `tshark -T fields -e tls.handshake.extensions_server_name -Y "tls.handshake.type==1"`
- [ ] Flag SNI values matching `dns.google`, `cloudflare-dns.com`, `dns.quad9.net` from unexpected hosts
- [ ] **SANS FOR572 Alignment:** DoH adoption by malware families is increasing rapidly — always check for DoH to known resolvers as part of DNS triage

---

## Phase 3 — HTTP/HTTPS Analysis

**Goal:** Extract C2 communication artifacts, identify malware user-agents, and detect exfiltration over web protocols.

### 3.1 — HTTP Object Extraction & Artifact Recovery
- [ ] Extract HTTP transferred objects to disk: `tshark -r <file.pcap> --export-objects http,/output/dir/`
- [ ] Examine extracted files: compute hashes and compare against threat intelligence
- [ ] Reassemble TCP streams for full HTTP conversation context: `tcpflow -r <pcap> -o output/`
- [ ] Flag HTTP responses delivering PE executables, scripts, or archives to internal hosts
- [ ] **Tool:** `tshark`, `tcpflow -r <pcap> -o output/`, NetworkMiner (passive reassembly)

### 3.2 — User-Agent Analysis
- [ ] Extract all unique User-Agent strings: `tshark -r <file.pcap> -T fields -e http.user_agent | sort | uniq -c | sort -rn`
- [ ] Flag known malware User-Agent strings (Cobalt Strike default: `Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)`)
- [ ] Flag empty or minimal User-Agent strings — automated tools often omit or truncate UAs
- [ ] Flag `curl/`, `wget/`, `python-requests/`, `Go-http-client/` from hosts that should not run these tools
- [ ] Flag User-Agent strings with unusual version numbers or formatting inconsistencies
- [ ] Correlate anomalous UAs with source host — if a workstation is generating `curl` traffic, investigate immediately

### 3.3 — URI & POST Body Analysis
- [ ] Flag base64 content in query strings — encoded C2 commands or stolen data
- [ ] Flag URI patterns associated with common C2 frameworks:
  - Cobalt Strike: `/submit.php`, `/jquery-3.3.1.min.js`, `/updates.rss`, `/match` (malleable C2 default profiles)
  - Metasploit: `/TqykA`, `/pxCx`, `/UXdv` (random-looking URIs)
  - Empire: `/admin/get.php`, `/news.php`, `/login/process.php`
- [ ] Flag large HTTP POST bodies (>10KB) to URIs with no corresponding large GET — outbound data exfiltration pattern
- [ ] Extract POST body content for manual review when size exceeds baseline for that endpoint
- [ ] **Tool:** `tshark`, `tcpflow`

### 3.4 — TLS Fingerprinting & Certificate Analysis
- [ ] JA3 client fingerprinting (identifies TLS client library): `tshark -r <file.pcap> -T fields -e tls.handshake.ja3 -Y "tls.handshake.type==1"`
- [ ] JA3S server fingerprinting: `tshark -r <file.pcap> -T fields -e tls.handshake.ja3s -Y "tls.handshake.type==2"`
- [ ] Cross-reference JA3 hashes against known malware signatures (Cobalt Strike default JA3: `72a7c4ade54dd1eba4f5a4a6e08efad6`)
- [ ] TLS certificate analysis for suspicious indicators:
  - `tshark -T fields -e tls.handshake.certificate -Y "tls.handshake.type==11"`
  - Flag self-signed certificates (issuer == subject)
  - Flag certificates with validity period < 90 days or > 825 days
  - Flag suspicious CN/SAN values (IP addresses as CN, `localhost`, generic strings like `example.com`)
  - Flag certificates issued by unknown/untrusted CAs
- [ ] SNI mismatch: flag TLS connections where SNI does not match certificate CN/SAN — evasion technique
- [ ] **SANS FOR572 Alignment:** JA3/JA3S fingerprinting is a **★★★★** detection technique — even encrypted C2 traffic has a distinctive TLS fingerprint based on cipher suite ordering and extensions

---

## Phase 4 — C2 Beaconing Detection

**Goal:** Identify automated callback traffic through timing and behavioral analysis.

### 4.1 — Beacon Timing Analysis
- [ ] Extract connection timestamps per destination IP: `tshark -r <pcap> -T fields -e frame.time_epoch -e ip.dst -e tcp.dstport -Y "tcp.flags.syn==1 and tcp.flags.ack==0" | sort -k2,3`
- [ ] Calculate inter-connection intervals for each unique destination — **low standard deviation = beacon**
- [ ] Legitimate user traffic: highly variable inter-request timing; automated beacon: timing jitter < 10% of sleep interval
- [ ] Flag connections with > 5 repeating intervals within ±5 seconds of a fixed period (common beacon intervals: 60s, 300s, 3600s)
- [ ] Account for jitter: Cobalt Strike malleable C2 supports `jitter` parameter (±% of sleep) — look for normally distributed timing rather than purely fixed intervals
- [ ] **Tool:** `tshark` with timestamp extraction, Python/awk for statistical analysis, Zeek `conn.log`

### 4.2 — Cobalt Strike Indicators
- [ ] Default malleable C2 profile URIs: `/submit.php`, `/jquery-3.3.1.min.js`, `/updates`, `/pixel`
- [ ] Default `Content-Type: application/octet-stream` on HTTP GET requests (reversed from normal semantics)
- [ ] Cobalt Strike Beacon size patterns: staging traffic characteristic 4096/8192-byte response sizes
- [ ] HTTPS C2: check for Cobalt Strike's default self-signed certificate (`O=cobaltstrike, C=US` or random attributes)
- [ ] DNS Beacon: very regular DNS queries (every N seconds ±jitter) to a single short domain
- [ ] SMB Beacon: `\\pipe\msagent_<hex>` named pipe patterns on lateral movement targets

### 4.3 — Other C2 Framework Indicators
- [ ] Metasploit Meterpreter: TLS certificate with `Subject: C=US, ST=CA, L=SF` default, random 4-char URI segments
- [ ] Empire/Covenant: HTTPS C2 with long-lived sessions, periodic POST requests with base64 bodies
- [ ] ICMP tunneling: `tshark -Y icmp -T fields -e ip.src -e ip.dst -e icmp.type -e frame.len` — flag ICMP Echo payloads > 64 bytes or non-standard ICMP types (not 8/0)
- [ ] DNS beaconing: regular DNS queries at fixed intervals from single host — see Phase 2 for extraction methodology
- [ ] **Tool:** `tshark`, Zeek `notice.log`, Zeek `conn.log`
- [ ] **SANS FOR572 Alignment:** C2 beacon detection requires **statistical analysis across time** — a single connection is not a beacon; the pattern across hundreds of connections reveals the automated callback

---

## Phase 5 — Data Exfiltration Detection

**Goal:** Identify outbound data transfers indicative of intellectual property theft or credential harvesting.

### 5.1 — Upload Volume Analysis
- [ ] Quantify outbound bytes per destination:
  - `tshark -r <pcap> -T fields -e ip.src -e ip.dst -e frame.len | awk '{sum[$1"→"$2]+=$3} END {for(k in sum) print sum[k], k}' | sort -rn | head -30`
- [ ] Flag large data transfers (>100 MB) to external IPs not associated with known cloud storage or business services
- [ ] Flag large transfers outside business hours — exfiltration often occurs off-hours to avoid detection
- [ ] Establish upload baseline: compare outbound transfer volumes on incident day vs prior 7-day average
- [ ] **Tool:** `tshark`, NetworkMiner, `tcpflow`

### 5.2 — Protocol-Specific Exfiltration Detection
- [ ] DNS exfiltration: calculate total bytes in DNS query subdomain labels per destination domain — >10 KB/hour is suspicious
- [ ] HTTPS POST exfiltration: flag POST request bodies > 1 MB to non-CDN external IPs
- [ ] ICMP exfiltration: sum ICMP payload bytes per destination — legitimate ICMP ping is 32-56 bytes; exfiltration accumulates MB over time
- [ ] SMB exfiltration to external IPs: `tshark -Y "smb2.cmd==9" -T fields -e ip.src -e ip.dst` (SMB2 Write requests to external IPs)
- [ ] FTP/TFTP: flag any outbound FTP/TFTP connections (unusual in modern environments without explicit need)

### 5.3 — File Extraction from PCAP
- [ ] Extract transferred files from all supported protocols:
  - `tshark -r <pcap> --export-objects http,/output/http/`
  - `tshark -r <pcap> --export-objects smb,/output/smb/`
  - `tshark -r <pcap> --export-objects tftp,/output/tftp/`
- [ ] Compute SHA256 hashes of all extracted files and compare against threat intelligence
- [ ] Flag archives (ZIP/RAR/7z magic bytes) in upload streams — compression before exfiltration
  - ZIP magic: `PK\x03\x04`; RAR magic: `Rar!\x1A\x07`; 7z magic: `7z\xBC\xAF`
- [ ] Flag encrypted containers — large files with high entropy (>7.5 bits/byte) in outbound streams
- [ ] **Tool:** `tshark`, NetworkMiner, `tcpflow`
- [ ] **SANS FOR572 Alignment:** File extraction from PCAP is the **most direct evidence** of exfiltration — recovered files may contain staging archives, stolen credentials, or documents confirming scope

---

## Phase 6 — Lateral Movement in Network

**Goal:** Map attacker movement between internal hosts using network traffic patterns.

### 6.1 — SMB Lateral Movement Detection
- [ ] SMB filename analysis: `tshark -Y smb2 -T fields -e ip.src -e ip.dst -e smb2.filename`
- [ ] Flag access to administrative shares: `ADMIN$`, `C$`, `IPC$` — attacker lateral movement indicators
- [ ] Flag `PSEXESVC` file creation in `ADMIN$\PSEXESVC.exe` — PsExec lateral movement
- [ ] Flag SMB named pipe connections to lateral movement pipes:
  - `\pipe\svcctl` — PsExec service control
  - `\pipe\atsvc` — AT Scheduler
  - `\pipe\winreg` — Remote Registry
  - `\pipe\msagent_*` — Cobalt Strike SMB Beacon
- [ ] Flag `net use \\target\C$` patterns: SMB tree connects to C$ or ADMIN$ from non-server hosts
- [ ] **Tool:** `tshark -Y smb2`, Zeek `smb_files.log`

### 6.2 — WMI / DCOM Lateral Movement Detection
- [ ] Flag traffic to TCP/135 (RPC Endpoint Mapper) between internal hosts — WMI/DCOM first contact
- [ ] Follow TCP/135 sessions: dynamic high port allocation follows — flag multiple rapid connections to new high ports from same source after a TCP/135 conversation
- [ ] WMI remote execution: RPC traffic to `\pipe\winmgmt` named pipe or `DCOM` OXID resolution patterns
- [ ] Flag `wmiprvse.exe` spawning unusual child processes (correlate with Sysmon EID 1 if available)

### 6.3 — RDP Lateral Movement Detection
- [ ] Flag TCP/3389 connections between internal hosts — especially workstation-to-workstation RDP (unusual in most environments)
- [ ] Flag RDP connections on non-standard ports (attackers often tunnel RDP or use alternate ports)
- [ ] Flag new source IPs establishing RDP to internal hosts during incident window
- [ ] RDP connection volume: multiple unique sources connecting to the same target in short succession = RDP spray
- [ ] Correlate RDP source IPs with authentication events in Windows Security Event Log (EID 4624 Type 10)

### 6.4 — Kerberos Lateral Movement Mapping
- [ ] TGS requests map attacker service access: `tshark -Y kerberos -T fields -e ip.src -e kerberos.CNameString -e kerberos.sname`
- [ ] Sequence of Kerberos TGS requests from a single source reveals attacker's lateral path: each unique SPN requested corresponds to a system the attacker attempted to access
- [ ] Flag Kerberos traffic originating from hosts that are not the registered account's workstation
- [ ] **Tool:** `tshark -Y "smb2 or kerberos"`, Zeek `conn.log`, Zeek `smb_files.log`
- [ ] **SANS FOR572 Alignment:** SMB + Kerberos traffic correlation provides a **complete map of lateral movement** — every `ADMIN$` access and every TGS request is a breadcrumb in the attacker's path

---

## Phase 7 — Zeek/Bro Log Analysis

**Goal:** Leverage Zeek's parsed logs for efficient high-level traffic analysis when full PCAP is available.

### 7.1 — conn.log Analysis
- [ ] Top connections by bytes: `zeek-cut id.orig_h id.resp_h id.resp_p proto orig_bytes resp_bytes < conn.log | sort -t$'\t' -k6 -rn | head -30`
- [ ] Long-duration connections: `zeek-cut id.orig_h id.resp_h duration < conn.log | sort -t$'\t' -k3 -rn | head -20`
  - Flag persistent low-volume connections (C2 keepalive sessions often run for hours/days)
- [ ] Flag connections with `conn_state` of `S0` (SYN sent, no response) in volume — port scanning
- [ ] Flag connections with `conn_state` of `REJ` — firewall denials being probed
- [ ] **Tool:** `zeek-cut`, `grep`, `awk` on Zeek log files

### 7.2 — dns.log Analysis
- [ ] Extract query/response pairs: `zeek-cut query qtype_name answers < dns.log | sort | uniq -c | sort -rn`
- [ ] NXDOMAIN rate per source: `grep "NXDOMAIN" dns.log | zeek-cut id.orig_h query | sort | awk '{count[$1]++} END {for(h in count) print count[h], h}' | sort -rn`
- [ ] Long subdomain detection: `zeek-cut query < dns.log | awk 'length($1) > 50'`
- [ ] TXT record queries: `grep "TXT" dns.log | zeek-cut id.orig_h query`

### 7.3 — http.log Analysis
- [ ] User-agent enumeration: `zeek-cut user_agent < http.log | sort | uniq -c | sort -rn`
- [ ] Top URIs: `zeek-cut host uri < http.log | sort | uniq -c | sort -rn | head -50`
- [ ] Large responses (potential staging payloads): `zeek-cut id.orig_h host uri resp_body_len < http.log | awk '$4 > 1000000' | sort -t$'\t' -k4 -rn`

### 7.4 — ssl.log Analysis
- [ ] JA3 hash enumeration: `zeek-cut id.orig_h ja3 ja3s server_name < ssl.log | sort | uniq -c | sort -rn`
- [ ] Certificate validity issues: `zeek-cut id.orig_h id.resp_h server_name validation_status < ssl.log | grep -v "^ok"`
- [ ] SNI vs certificate subject mismatch: flag connections where `server_name` does not match the certificate CN

### 7.5 — files.log and notice.log Analysis
- [ ] Extract file hashes: `zeek-cut fuid md5 sha1 filename mime_type < files.log | grep -v "^-"`
  - Cross-reference SHA1 hashes against threat intelligence feeds
- [ ] Review `notice.log` for automated Zeek detections: scan detection, connection anomalies, known bad indicator matches
- [ ] Review `weird.log` for protocol anomalies: malformed packets, unexpected protocol state transitions, application layer violations
- [ ] **SANS FOR572 Alignment:** Zeek `files.log` with SHA1 hashes is a **direct bridge between network forensics and malware analysis** — extracted hashes can immediately confirm known-bad indicators without full PCAP reconstruction

---

## Phase 8 — NetFlow / Firewall Log Analysis

**Goal:** Perform network forensics when full PCAP capture is unavailable, using metadata-only sources.

### 8.1 — NetFlow 5-Tuple Analysis
- [ ] NetFlow 5-tuple: source IP, destination IP, source port, destination port, protocol — no payload, but sufficient for behavioral analysis
- [ ] Top flow pairs by bytes: `nfdump -r <netflow_file> -s record/bytes -n 50`
- [ ] Flag small regular flows (beaconing signature): frequent connections with 100-500 bytes transferred each — keepalive C2 pattern
- [ ] Flag large one-time flows (exfiltration signature): single flows transferring >100 MB
- [ ] Outbound flows on unusual ports: `nfdump -r <netflow_file> -f "proto tcp and port not in [80, 443, 22, 25, 53]" -s dstport/flows`
- [ ] **Tool:** `nfdump`, direct log parsing with `grep`/`awk`

### 8.2 — Firewall Log Analysis
- [ ] Deny-to-allow ratio per source host: a sudden decrease in denies from a host that previously generated many denies may indicate firewall rule modification or bypass
- [ ] Flag outbound connections from internal hosts that have never communicated externally before
- [ ] Flag deny events followed immediately by allow events on same 5-tuple — possible firewall rule manipulation
- [ ] GeoIP correlation: flag flows to unexpected countries based on organization's business footprint
  - Flag connections to known hosting providers commonly used for attack infrastructure (AS numbers associated with bulletproof hosting)
- [ ] Flag long-lived firewall sessions (>24 hours) — persistent C2 or data exfiltration staging sessions
- [ ] **Tool:** Direct log parsing, `nfdump` for NetFlow files, `geoiplookup` for country correlation

### 8.3 — Evidence Gap Handling
- [ ] Document all periods not covered by available captures — gaps in coverage are forensically significant
- [ ] Correlate NetFlow/firewall metadata with DNS logs to partially reconstruct web traffic without PCAP
- [ ] Use endpoint artifacts (browser history, DNS cache, proxy logs, Windows network event logs) to fill PCAP gaps
- [ ] Flag any evidence of capture evasion: traffic at very low rates, segmented connections, protocol-level fragmentation
- [ ] **SANS FOR572 Alignment:** NetFlow analysis is **not a fallback** — it is the primary network forensics method in most enterprise environments; treat PCAP as the bonus artifact, not the default

---

## Phase 9 — Scoring & Output

**Goal:** Prioritize findings and produce structured output for analyst handoff.

- [ ] **Severity Matrix:**
  - **Critical:** Active C2 beacon identified with statistical confidence (low-jitter periodic callback), confirmed data exfiltration (files extracted from PCAP or >100 MB outbound to external IP), DNS tunneling with data volume evidence, ICMP/non-standard protocol tunneling
  - **High:** JA3 fingerprint matching known malware, self-signed TLS certificate to external IP with regular access pattern, SMB `ADMIN$`/`C$` lateral movement between internal hosts, DGA traffic with NXDOMAIN storm followed by successful resolution, bulk Kerberos TGS requests (Kerberoasting traffic)
  - **Medium:** Anomalous User-Agent strings, large HTTPS POST bodies to unexpected destinations, RDP connections between workstations, DNS queries with long subdomains (>50 chars) not confirmed as tunneling, outbound traffic on non-standard ports
  - **Low:** Minor protocol anomalies in Zeek `weird.log`, single NXDOMAIN instances, outbound connections to new destinations within expected protocols

- [ ] **MITRE ATT&CK Mapping:**
  - T1071.001 — Application Layer Protocol: Web Protocols (HTTP/HTTPS C2)
  - T1071.004 — Application Layer Protocol: DNS (DNS C2/tunneling)
  - T1573.001 — Encrypted Channel: Symmetric Cryptography
  - T1573.002 — Encrypted Channel: Asymmetric Cryptography (TLS C2)
  - T1048.001 — Exfiltration Over Alternative Protocol: DNS
  - T1048.002 — Exfiltration Over Alternative Protocol: Asymmetric Encrypted Non-C2 Protocol
  - T1048.003 — Exfiltration Over Alternative Protocol: Unencrypted Non-C2 Protocol
  - T1095 — Non-Application Layer Protocol (ICMP tunneling)
  - T1090.001 — Proxy: Internal Proxy
  - T1090.002 — Proxy: External Proxy
  - T1041 — Exfiltration Over C2 Channel
  - T1219 — Remote Access Software (RDP lateral movement)
  - T1021.002 — Remote Services: SMB/Windows Admin Shares (lateral movement)

- [ ] **Structured Output:** JSON with source/destination IPs, ports, protocols, data volumes, timestamps, JA3 hashes, extracted file hashes, beacon statistics, and severity scores
- [ ] **Analyst Handoff:** Bundle relevant PCAP slices (filtered by attacker IP and time window), extracted files, Zeek logs, DNS query export, and JA3/JA3S hash report for threat intelligence cross-reference
