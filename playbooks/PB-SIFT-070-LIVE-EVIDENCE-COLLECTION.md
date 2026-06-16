# PB-SIFT-070: Live Evidence Collection
## Volatile & Live-System Acquisition — Order-of-Volatility Triage

**Classification:** SIFT Bot - Live Acquisition
**Objective:** Acquire volatile and live-system evidence from a running host using
open-source tooling, preserving order of volatility and chain of custody, and
producing artifacts in formats that Geoff's static-analysis playbooks can ingest.
**Specialist:** `volatility, sleuthkit, logs, network`

**Trigger Conditions:**
- A running host is in scope (not a dead disk image) — live IR engagement, suspected
  active intrusion, or evidence that would be lost on shutdown (encrypted volumes
  mounted, malware resident only in memory, active C2 session).
- Operator explicitly requests live/triage collection rather than (or before) a full
  forensic disk image.
- Encrypted disk with no recovery key, where the volume is currently unlocked.

> **Scope.** This playbook covers *acquisition only*. It does not analyse the evidence
> it collects — it hands artifacts to the analysis playbooks listed in Phase 7. Run
> this playbook on the live host (or via a remote agent); run the analysis playbooks
> afterward against the collected artifacts on the SIFT workstation.

---

### Phase 0 — Pre-Acquisition & Authorization

**Goal:** Establish authority, environment, and a defensible custody baseline before
touching the target.

- [ ] **Authorization check:** Confirm written authorization / legal hold scope for the
      target host. Record the authorizing party, case ID, and time window.
- [ ] **Operator notes:** Record acquisition operator, date/time (UTC + local with
      offset), timezone of the target, and the reason live collection was chosen over
      dead-disk imaging.
- [ ] **Trusted tooling:** Run collection tools from read-only, hash-verified media
      (USB/mounted ISO) — never from the target's own filesystem. The target's `ps`,
      `netstat`, `ls`, and `tasklist` may be trojaned (cross-reference PB-SIFT-014 §4.6).
- [ ] **Output target:** Write all collected evidence to external removable media or a
      network share, **never** to the target's own disk (avoids overwriting unallocated
      space and slack). Note destination path/volume serial.
- [ ] **System clock skew:** Record the target's current time vs a trusted reference
      (NTP / operator watch) so collected timestamps can be normalized later.
- [ ] **Footprint acknowledgement:** Note that live collection necessarily alters the
      target (loaded tools, memory, access times). Document the minimal footprint chosen.

---

### Phase 1 — Order of Volatility (RFC 3227)

**Goal:** Collect evidence from most-volatile to least-volatile so transient state is
not lost. Execute the phases below **in order**:

1. **Phase 2** — CPU/registers, cache, RAM (volatile memory)
2. **Phase 3** — Network state, routing, ARP, live connections, packet capture
3. **Phase 4** — Running processes, loaded modules, open handles, logged-on users
4. **Phase 5** — Live disk / triage artifact collection (logs, registry, filesystem)
5. **Phase 6** — Full live disk image (least volatile, longest running)

- [ ] **Confirm ordering:** Do not start disk imaging (Phase 6) before memory (Phase 2)
      unless memory acquisition is impossible — imaging churns cache and may swap out the
      very processes under investigation.

---

### Phase 2 — Volatile Memory Acquisition (most volatile)

**Goal:** Capture physical RAM before any other action. Output feeds **PB-SIFT-027
(Memory Forensics)** for Volatility analysis.

**Windows (OSS tools):**
- [ ] **WinPmem:** `winpmem_mini_x64_rc2.exe physmem.raw` — acquire physical memory to a
      raw image. (WinPmem is the open-source acquirer maintained alongside Velociraptor.)
- [ ] **Alternative — Velociraptor:** `velociraptor.exe artifacts collect
      Windows.Memory.Acquisition` to produce a memory image plus collection metadata.
- [ ] **Pagefile/swap:** Note that `pagefile.sys` / `hiberfil.sys` are collected in
      Phase 5 (triage) — flag them for `volatility` pagefile correlation.

**Linux (OSS tools):**
- [ ] **AVML:** `avml memory.lime` — Microsoft's open-source (MIT) acquirer; produces a
      LiME-format image that Volatility 3 ingests directly. Preferred — no kernel module
      build required.
- [ ] **LiME:** build and `insmod lime.ko "path=/mnt/evidence/mem.lime format=lime"` when
      AVML is unavailable. Match the module to the running kernel version.
- [ ] **/proc/kcore fallback:** If no acquirer loads, note `/proc/kcore` as a last-resort
      live source.

**macOS:**
- [ ] **SIP caveat:** Full RAM acquisition on modern macOS is constrained by System
      Integrity Protection. Record SIP status (`csrutil status`). Where a supported
      acquirer is unavailable, prioritize the live triage collection in Phase 5.

- [ ] **Hash immediately:** SHA-256 the memory image the moment acquisition completes and
      record it in chain of custody (PB-SIFT custody sidecar). Re-hash after transfer.

---

### Phase 3 — Live Network State

**Goal:** Capture transient network state and (optionally) live traffic. Packet capture
output feeds **PB-SIFT-036 (PCAP Network Forensics)**.

- [ ] **Active connections:**
    - Linux/macOS: `ss -tunap` (preferred) or `netstat -anp` — capture listening + active
      sockets with owning PID.
    - Windows: `netstat -anob` — connections with owning process.
- [ ] **Routing & ARP:** `ip route`, `ip neigh` / `arp -a`, `ip addr` — capture routing
      table, ARP cache, interface config (catches rogue routes / ARP spoofing).
- [ ] **DNS cache:** `ipconfig /displaydns` (Windows) / `systemd-resolve --statistics` or
      `nscd` cache where present — feeds **PB-SIFT-050 (DNS Forensics)**.
- [ ] **Live packet capture (OSS):** `tcpdump -i any -s 0 -w /mnt/evidence/capture.pcap`
      or `dumpcap -i any -w capture.pcap` (Wireshark). Time-box the capture and record
      start/stop times. Optionally run `zeek -i <iface>` for protocol logs.
- [ ] **Firewall state:** `iptables-save` / `nft list ruleset` (Linux), `netsh advfirewall
      show allprofiles` (Windows) — flag rules permitting unexpected inbound/outbound.

---

### Phase 4 — Running Processes, Modules & Sessions

**Goal:** Snapshot the live execution state. Use OSS tooling and prefer structured output
(JSON) so it can be diffed against memory-derived process lists from PB-SIFT-027.

- [ ] **Process list:** `ps auxww` (Linux/macOS) / `tasklist /v` (Windows). Capture full
      command lines, PIDs, PPIDs, and start times.
- [ ] **Process-to-binary:** Linux — `ls -l /proc/*/exe` to map PIDs to on-disk binaries;
      flag `(deleted)` targets (fileless execution — cross-ref PB-SIFT-014 §2).
- [ ] **Open files/handles:** `lsof -n -P` (Linux/macOS) — open files, sockets, deleted
      files still held open.
- [ ] **Loaded modules/drivers:** `lsmod` + `/proc/modules` (Linux) — flag unsigned or
      unknown modules (rootkit indicator).
- [ ] **Logged-on users & sessions:** `who`, `w`, `last` (Linux/macOS) / `query user`,
      `query session` (Windows).
- [ ] **osquery snapshot (OSS):** Run `osqueryi` queries for `processes`, `listening_ports`,
      `kernel_modules`, `logged_in_users`, `process_open_sockets` and export as JSON.
      This structured snapshot is the live counterpart to EDR telemetry and feeds
      **PB-SIFT-037 (EDR Telemetry Analysis)**.
- [ ] **Scheduled tasks/services:** `systemctl list-timers`, `crontab -l`, `/etc/cron*`
      (Linux) / `schtasks /query /fo LIST /v`, `sc query` (Windows) — feeds
      **PB-SIFT-003 (Persistence)**.

---

### Phase 5 — Live Triage Artifact Collection

**Goal:** Collect the high-value on-disk artifacts (logs, registry, filesystem metadata,
browser/email data) into a single triage package, without imaging the whole disk. This is
the core of "what we can process": every artifact below maps to an existing analysis
playbook (see Phase 7).

**Cross-platform OSS collectors (choose one as primary, note which was used):**
- [ ] **Velociraptor offline collector (OSS, AGPL):** build a collector with the
      `Windows.KapeFiles.Targets` (triage) or platform triage artifacts; produces a
      single ZIP with collection log and per-file hashes. Cross-platform.
- [ ] **UAC — Unix-like Artifacts Collector (OSS, MIT):** `./uac -p full /mnt/evidence` on
      Linux/macOS/ESXi/Solaris/AIX — produces a tar/zip of logs, configs, and live state.
- [ ] **CyLR (OSS):** `CyLR -o /mnt/evidence` — fast live-response collection on Windows
      and Linux into a ZIP.

**Specific artifact targets (collected by the tools above or manually):**
- [ ] **Windows event logs:** `C:\Windows\System32\winevt\Logs\*.evtx` → **PB-SIFT-001/002/
      004/005 + PB-SIFT-035** (event-log-driven detections).
- [ ] **Registry hives:** `SYSTEM`, `SOFTWARE`, `SAM`, `SECURITY`, `NTUSER.DAT`,
      `UsrClass.dat` → **PB-SIFT-003 (Persistence)**, **PB-SIFT-028 (Windows Modern
      Artifacts)**. Live hives must be collected via raw read / VSS (do not `copy` locked
      hives) — Velociraptor/CyLR use raw NTFS reads.
- [ ] **Linux logs & config:** `/var/log/*`, `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`,
      `~/.ssh/`, shell histories, cron, systemd units → **PB-SIFT-014 (Linux Forensics)**.
- [ ] **macOS artifacts:** Unified Logs (`log collect`), `/var/log`, LaunchAgents/Daemons,
      plists → **PB-SIFT-024 (macOS Forensics)**.
- [ ] **Browser data:** Chrome/Firefox/Edge profile SQLite (history, downloads, cookies)
      → **PB-SIFT-022 (Browser Forensics)**.
- [ ] **Email stores:** PST/OST, mbox, local Maildir → **PB-SIFT-023 (Email Forensics)**.
- [ ] **Filesystem timeline source:** Collect `$MFT` / `$LogFile` / `$UsnJrnl` (NTFS) or
      run a live `fls`/`mac-robber` body file → **PB-SIFT-020 (Timeline Analysis)** (Plaso /
      mactime).
- [ ] **Prefetch / SRUM / Amcache:** `C:\Windows\Prefetch`, `SRUDB.dat`, `Amcache.hve`
      → **PB-SIFT-002 (Execution)**, **PB-SIFT-013 (Insider Threat)**.
- [ ] **Pagefile/hiberfil/swap:** collect for memory correlation (PB-SIFT-027).

---

### Phase 6 — Live Disk Imaging (least volatile)

**Goal:** When a full image is required and the system cannot be shut down, image the disk
live with OSS imagers. Output feeds **every static disk playbook** (PB-SIFT-001–014, 020,
026, 029, etc.).

- [ ] **Mounted-volume note:** Record which encrypted volumes are currently unlocked — a
      live image of an unlocked volume captures plaintext that a dead image would not
      (cross-ref **PB-SIFT-029 Encrypted Containers**).
- [ ] **Image with OSS tools:**
    - `dc3dd if=/dev/sdX hash=sha256 log=image.log of=/mnt/evidence/disk.raw` — dd variant
      with built-in hashing/logging.
    - `dcfldd if=/dev/sdX hash=sha256 hashlog=hash.txt of=disk.raw` — alternative.
    - `ewfacquire /dev/sdX` (libewf) — produce an E01 with embedded hashes/metadata.
    - `guymager` — OSS GUI imager (E01/raw) when a console is available.
- [ ] **Write-blocking:** Where physically possible use a hardware write blocker; for live
      logical sources document that no write blocker was possible and why.
- [ ] **Verify:** Confirm the imager's acquisition hash matches a post-image verification
      hash. Record both.

---

### Phase 7 — Custody, Verification & Handoff

**Goal:** Make every collected artifact defensible and route it to the playbook that
processes it.

- [ ] **Hash everything:** SHA-256 every output file (memory image, pcap, triage ZIP, disk
      image, osquery JSON). Record into the per-case chain-of-custody sidecar.
- [ ] **Collection manifest:** Emit a manifest listing each artifact, its tool + version,
      acquisition start/stop time (UTC), operator, source host, and hash.
- [ ] **Handoff routing table** — declare which analysis playbook consumes each artifact:

    | Collected artifact | Format | Downstream analysis playbook |
    |--------------------|--------|------------------------------|
    | Physical memory | `.raw` / `.lime` | PB-SIFT-027 Memory Forensics |
    | Packet capture | `.pcap` | PB-SIFT-036 PCAP Network Forensics |
    | DNS cache | text/json | PB-SIFT-050 DNS Forensics |
    | osquery snapshot | `.json` | PB-SIFT-037 EDR Telemetry Analysis |
    | Windows event logs | `.evtx` | PB-SIFT-001/002/004/005, PB-SIFT-035 |
    | Registry hives | hive | PB-SIFT-003, PB-SIFT-028 |
    | Linux logs/config | files | PB-SIFT-014 Linux Forensics |
    | macOS unified logs/plists | files | PB-SIFT-024 macOS Forensics |
    | Browser SQLite | `.sqlite` | PB-SIFT-022 Browser Forensics |
    | Email stores | PST/OST/mbox | PB-SIFT-023 Email Forensics |
    | `$MFT`/body file | filesystem | PB-SIFT-020 Timeline Analysis |
    | Prefetch/SRUM/Amcache | artifacts | PB-SIFT-002, PB-SIFT-013 |
    | Full disk image | `.raw`/`E01` | All static disk playbooks |

- [ ] **Triage handoff:** After collection, the operator runs **PB-SIFT-000 (Triage &
      Execution Planning)** against the collected artifacts to build the analysis execution
      plan, exactly as for any other evidence set.

---

### Phase 8 — MITRE ATT&CK Mapping (Collection Coverage)

This playbook is an acquisition step; the indicators it *enables detection of* map to:

- **T1003** OS Credential Dumping — surfaced via memory (PB-SIFT-027) + registry hives.
- **T1059** Command & Scripting Interpreter — process command lines (Phase 4).
- **T1071** Application Layer Protocol (C2) — live pcap (Phase 3) → PB-SIFT-036/019.
- **T1547 / T1053 / T1543** Persistence — services, cron, scheduled tasks (Phase 4/5).
- **T1014 / T1027** Rootkit / Obfuscation — loaded modules + memory (Phase 4/2).
- **T1620** Reflective/Fileless Execution — deleted-binary process maps (Phase 4) +
  memory (PB-SIFT-027).

**SANS FOR508 Alignment:** Live response and order-of-volatility acquisition are
**★★★★★** — memory and live network state are unrecoverable post-shutdown; collecting
them correctly is the foundation every downstream playbook depends on.
