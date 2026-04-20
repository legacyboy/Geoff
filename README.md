# GEOFF
## Git-backed Evidence Operations Forensic Framework

```
    ╔═══════════════════════════════════════════════════════════════╗
    ║  ██████╗ ███████╗ ██████╗ ███████╗███████╗                   ║
    ║  ██╔════╝ ██╔════╝██╔═══██╗██╔════╝██╔════╝                   ║
    ║  ██║  ███╗█████╗  ██║   ██║█████╗  █████╗                     ║
    ║  ██║   ██║██╔══╝  ██║   ██║██╔══╝  ██╔══╝                     ║
    ║  ╚██████╔╝███████╗╚██████╔╝██║     ██║                        ║
    ║   ╚═════╝ ╚══════╝ ╚═════╝ ╚═╝     ╚═╝                        ║
    ║                                                               ║
    ║        "Follow every thread"                                  ║
    ╚═══════════════════════════════════════════════════════════════╝
```

**Your digital forensics colleague with multi-agent analysis, device-centric investigation, and narrative reporting.**

---

## What is GEOFF?

GEOFF is a **multi-agent conversational DFIR platform** with three specialized AI agents, device-aware evidence processing, behavioral analysis, and LLM-generated narrative reports.

### The Multi-Agent Team

| Agent | Role | Cloud Model | Local Model |
|-------|------|-------------|-------------|
| **Manager** | Orchestrates investigations, strategic decisions | deepseek-v3.2:cloud | deepseek-r1:32b |
| **Forensicator** | Executes forensic tools, extracts artifacts | qwen3-coder-next:cloud | qwen2.5-coder:14b |
| **Critic** | Validates output for hallucinations and accuracy | qwen3.5:cloud | qwen2.5:14b |

**Workflow:**
```
User → Manager → Forensicator → Tools → Critic ──────────────── Git → Report
                                              ↓                       ↑
                                    Self-Correction Loop  ────────────┘
                                    (Manager revises if Critic rejects)
                                              ↓
                                    Behavioral Analyzer
                                              ↓
                                    Super Timeline + Correlation
                                              ↓
                                    Narrative Report (LLM-written, artifact-cited)
```

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│              GEOFF Web Interface (Flask)                 │
│  Find Evil + Chat • Evidence Browser • Narrative Report  │
└──────────────────────────┬──────────────────────────────┘
                           │
         ┌─────────────────┼─────────────────┐
         ▼                 ▼                 ▼
  ┌─────────────┐   ┌─────────────┐   ┌──────────────┐
  │ Device      │   │ Behavioral  │   │ Super        │
  │ Discovery   │   │ Analyzer    │   │ Timeline     │
  └──────┬──────┘   └──────┬──────┘   └──────┬───────┘
         │                 │                  │
         └────────┬────────┘                  │
                  ▼                           ▼
         ┌──────────────┐            ┌──────────────┐
         │ Host         │            │ Narrative    │
         │ Correlator   │            │ Report Gen   │
         └──────────────┘            └──────────────┘
                  │
         ┌────────┴────────┐
         ▼                 ▼
  ┌───────────────┐  ┌──────────────┐
  │ Extended      │  │ Critic +     │
  │ Orchestrator  │  │ Validation   │
  └───────┬───────┘  └──────────────┘
          │
   ┌───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┐
   ▼   ▼   ▼   ▼   ▼   ▼   ▼   ▼   ▼   ▼   ▼
Sleuth Vol Reg Plaso Net Logs Mob REMnux Brow Mail macOS
```

### Key Architecture Concepts

**Device-Centric Processing:** Evidence is grouped by device, not by file type. Each device gets its own playbook execution, its own findings, and its own behavioral analysis. Cross-device correlation ties it all together.

**Behavioral Analysis (Replaces YARA):** Instead of static signature matching, GEOFF uses 10 deterministic behavioral checks plus LLM-assisted assessment:
- Process path/parent validation (svchost.exe from temp? → flag)
- Suspicious spawn chains (Word → cmd.exe → flag)
- Network anomalies (notepad.exe with connections → flag)
- Timestomp detection (created > modified → flag)
- Beaconing detection (regular-interval C2 connections → flag)
- Persistence pointing to temp directories → flag
- Off-hours activity clustering → flag
- Typosquatting process names (scvhost.exe → flag)
- Temp directory executables → flag
- Registry Run keys to unusual locations → flag

**Super Timeline:** Unified timeline across all devices and evidence types — Plaso events, EVTX logs, SleuthKit file timestamps, network connections — all normalized to a common schema, sorted, and tagged with device_id and behavioral flags.

**Narrative Reports:** LLM-generated human-readable investigation reports with executive summary, per-user narratives, timeline of significant events, and recommendations. All claims in the Attack Chain Synthesis are required to cite a specific evidence anchor (tool + artifact + finding) from the find_evil pipeline. The narrative is prohibited from speculating beyond verified evidence.

---

## Find Evil

**One command. Zero prompting. Full auto-triage.**

### Command Line (fastest)

```bash
# Run an investigation
geoff-find-evil /path/to/evidence

# Save full JSON report to a file
geoff-find-evil /path/to/evidence -o report.json

# Pipe JSON to jq for scripting
geoff-find-evil /path/to/evidence --json | jq '.classification'

# Disable colour (for log files / CI)
geoff-find-evil /path/to/evidence --no-color

# Fail hard on any step error
geoff-find-evil /path/to/evidence --strict
```

**Exit codes:** `0` = clean, `1` = evil found, `2` = error

**Example output:**
```
  Geoff DFIR — Find Evil
  Evidence: /evidence/IR-016-CloudJack

08:42:01  ▶ PB-SIFT-000: Triage Prioritization
08:42:01    Classification: Exfiltration | Severity: HIGH
08:42:02  ▶ PB-SIFT-001: Initial Access [host-unknown]
08:42:03  ▶ PB-SIFT-005: Credential Theft [host-unknown]
...

┌────────────────────────────────────────────────────────────┐
│           GEOFF FIND EVIL — INVESTIGATION COMPLETE         │
├────────────────────────────────────────────────────────────┤
│  Evil found:           YES                                 │
│  Classification:       Exfiltration                        │
│  Severity:             HIGH                                │
│  Playbooks run:        14                                  │
│  Steps completed:      47  (0 failed)                      │
│  Elapsed:              12.3s                               │
│  MITRE techniques:     T1048, T1567, T1020                 │
│  Case directory:       /tmp/geoff-cases/IR-016-...         │
└────────────────────────────────────────────────────────────┘
```

### HTTP API

```bash
curl -X POST http://localhost:8080/find-evil \
  -H 'Content-Type: application/json' \
  -d '{"evidence_dir": "/path/to/evidence"}'
```

### Chat

Or via chat: `"Geoff, start processing /path/to/evidence"`

### Pipeline

1. **Inventory** — catalog every artifact (disk images, memory dumps, pcaps, logs, registry hives, mobile backups)
2. **Device Discovery** — group evidence by device, extract hostnames, identify owners, build device_map and user_map
3. **Triage** — PB-SIFT-000 rapid indicator scan; Manager LLM reviews and approves execution plan
4. **Playbook Execution** (per-device) — run each selected playbook against each device's evidence
5. **Forensicator Interpretation** — for each completed step, Forensicator LLM assesses significance and builds `evidence_chain` with specific artifact, tool, and finding
6. **Critic Validation + Self-Correction** — every step validated; on failure, Manager generates a corrected analysis and Critic re-validates; only demotes to `completed_unverified` if correction also fails
7. **Super Timeline** — unified timeline across all devices and evidence types
8. **Behavioral Analysis** — per-device anomaly detection (process, file, network, persistence, timeline)
9. **Host Correlation** — cross-device user activity, lateral movement detection
10. **Narrative Report** — LLM-written investigative narrative with explicit artifact citations from evidence anchors
11. **Git Commit** — every step committed for full reproducibility

### What Triggers Each Playbook

| Evidence / Indicator | Playbook(s) | Severity |
|:---|:---|:---|
| Ransom notes, encrypted extensions | PB-SIFT-009, PB-SIFT-001 | CRITICAL |
| Credential dumping, LSASS access | PB-SIFT-005, PB-SIFT-006 | HIGH |
| Lateral movement (PsExec, WMI) | PB-SIFT-006, PB-SIFT-003 | HIGH |
| Persistence (autoruns, scheduled tasks) | PB-SIFT-003, PB-SIFT-008 | HIGH |
| Exfiltration (cloud sync, bulk staging) | PB-SIFT-007, PB-SIFT-013 | HIGH |
| Anti-forensics (log clearing, timestomp) | PB-SIFT-012 | HIGH |
| Web shells, SQLi payloads | PB-SIFT-001, PB-SIFT-008 | HIGH |
| LOLBin abuse (certutil, mshta, rundll32) | PB-SIFT-010, PB-SIFT-008 | MEDIUM |
| Multiple disk images (correlation) | PB-SIFT-016 | HIGH |
| Malware sample | PB-SIFT-017, PB-SIFT-018, PB-SIFT-019 | HIGH |

### MITRE ATT&CK Tagging

Every indicator hit is tagged with relevant ATT&CK technique IDs:

| Category | MITRE Techniques |
|:---------|:----------------|
| Ransomware | T1486, T1490, T1489 |
| Credential Theft | T1003, T1558, T1552 |
| Lateral Movement | T1021, T1570, T1563 |
| Persistence | T1053, T1547, T1543, T1542 |
| Exfiltration | T1048, T1567, T1020 |
| Anti-Forensics | T1070, T1485, T1027 |
| Web Shell | T1505.003, T1190 |
| LOLBin | T1218, T1059, T1053 |
| C2 | T1071, T1095, T1573 |
| Cryptominer | T1496 |
| Rootkit | T1014, T1543.003 |
| OT/ICS Attack | T0855, T0816, T0879 |

The final report includes `attack_chain.mitre_techniques_observed` — a deduplicated list of all techniques seen across the investigation.

### Attack Chain Reconstruction

The report includes a `attack_chain` field:

```json
{
  "first_seen_ts": "2024-01-10T08:00:00",
  "last_seen_ts":  "2024-01-15T12:01:00",
  "dwell_days":    5.17,
  "lateral_movement_path": ["host-A", "host-B", "host-C"],
  "mitre_techniques_observed": ["T1003", "T1021", "T1048"],
  "kill_chain_phases": ["credential_theft", "lateral_movement", "exfiltration"]
}
```

### Anti-Forensics Cascade

When PB-SIFT-012 detects anti-forensics indicators, it **retroactively downgrades all findings** across all devices:
- CONFIRMED → POSSIBLE
- POSSIBLE → UNVERIFIED
- All findings marked `compromised_by: ["anti-forensics"]`

This prevents false confidence in evidence that may have been tampered with.

## Web Interface

Start the server then open **http://localhost:8080**.

```bash
python src/geoff_integrated.py
```

The UI has three tabs:

### 🔍 Find Evil

The evidence directory input is pre-filled with the server's configured evidence path so you always know what the default is. Edit it to point anywhere, or paste just a subfolder name — Geoff resolves it against the base path automatically.

```
/home/sansforensics/evidence-storage/evidence/IR-016-CloudJack
                    ↑ pre-filled                ↑ or just paste this
```

### 📁 Evidence

Lists every subfolder in your evidence directory. Each entry has two ways to kick off an investigation:

- **Click the folder name** — copies the full path into the Find Evil input and switches to that tab, ready to run
- **Click 🔍 Investigate** — does the same and immediately starts the run

No copy-pasting paths. No switching tabs manually.

### 💬 Chat

Conversational interface. Talk to Geoff directly or say things like `"start processing IR-016-CloudJack"` and it will route to Find Evil automatically.

---

## Tool Coverage

### Forensic Tools by Category

| Category | Specialist | Tools | Functions |
|----------|-----------|-------|----------|
| **Disk** | sleuthkit | SleuthKit (mmls, fls, fsstat, icat, istat, ils, blkls, blkcat, blkcalc, blkstat, ifind, ffind, tsk_recover) | Partition detection, filesystem analysis, file extraction, deleted file recovery, block-level analysis |
| **Recovery** | photorec | PhotoRec, Foremost, Scalpel | File carving from unallocated space, deleted file recovery, fragmented file recovery |
| **Memory** | volatility | Volatility3 | pslist, netscan, malfind, registry hive extraction, process dump |
| **IOC Extraction** | strings | strings, bulk_extractor, floss | URL, IP, email, credit card, registry path extraction |
| **Registry** | registry | RegRipper (rip.pl), Python-Registry | Hive parsing, UserAssist, ShellBags, USB, autoruns, services, mounted devices |
| **Windows Analysis** | zimmerman | Eric Zimmerman Tools (EvtxECmd, MFTECmd, bstrings, ShellBagsExplorer, AmcacheParser, SRUMDB2) | Event log parsing, MFT timeline, string extraction, shellbag analysis, AmCache execution history, SRUM resource usage |
| **VSS** | vss | vshadowmount, ewfmount | Shadow copy enumeration, VSS mounting, file extraction from shadow copies, cross-VSS timeline |
| **Timeline** | plaso | Plaso (log2timeline, psort, pinfo) | Super timeline creation, filtering, timezone-aware correlation |
| **Event Logs** | logs | python-evtx, EvtxECmd (Zimmerman) | Windows Event Log parsing, syslog analysis |
| **Network** | network | tshark, tcpflow | PCAP analysis, flow extraction, HTTP traffic reconstruction, DNS analysis |
| **Mobile** | mobile | Pure-Python (plistlib, sqlite3), iLEAPP, ALEAPP | iOS backup analysis (23 functions), Android data extraction (20+ functions), jailbreak/root detection, WhatsApp/Telegram extraction, photo EXIF/GPS |
| **Browser** | browser | SQLite3 (Chrome/Firefox DBs) | History, cookies, downloads, saved password origins |
| **Email** | email | readpst, mailbox, email (stdlib) | PST/OST conversion, mbox parsing, .eml header extraction |
| **Jump Lists / LNK** | jumplist | LnkParse3, RegRipper | LNK file metadata, jump lists, RecentDocs, TypedPaths |
| **macOS** | macos | plistlib, log(1), fsevents_parser | Plist parsing, Unified Log, LaunchAgents/Daemons, FSEvents |
| **Malware** | remnux | REMnux suite (die, exiftool, peframe, oledump, pdfid, upx, r2, clamav, ssdeep, hashdeep) | 15 tool wrappers, 5 specialist classes |
| **Hashing** | remnux | hashdeep, ssdeep | Fuzzy hashing, audit mode verification |
| **Binary** | remnux | exiftool, upx, radare2, die, peframe | Metadata extraction, unpacking, disassembly, PE analysis |
| **Antivirus** | remnux | ClamAV | Signature-based malware detection |

### SANS SIFT Workstation Compatibility

Geoff targets the **SANS SIFT Workstation** (Ubuntu 22.04 Jammy) as its primary runtime environment. The following SIFT tools are leveraged:

| SIFT Tool | Geoff Specialist | Status |
|-----------|----------------|--------|
| SleuthKit | sleuthkit | ✅ Full coverage |
| Volatility3 | volatility | ✅ Installed via pip (not in SIFT apt — see [Issue #628](https://github.com/teamdfir/sift/issues/628)) |
| PhotoRec | photorec | ✅ Batch mode with foremost/scalpel fallback |
| RegRipper | registry | ✅ Full coverage |
| Plaso | plaso | ✅ Full coverage |
| tshark | network | ✅ Non-interactive installer |
| tcpflow | network | ✅ Full coverage |
| vshadowmount | vss | ✅ Full coverage |
| ewfmount | sleuthkit/vss | ✅ E01 mounting support |
| bulk_extractor | strings | ✅ Full coverage |
| hashdeep/ssdeep | remnux | ✅ Full coverage |
| Zimmerman Tools | zimmerman | ✅ Auto-download via installer |
| REMnux | remnux | ✅ Full coverage |
| Scalpel/Foremost | photorec | ✅ Carving fallback chain |
| ClamAV | remnux | ✅ Full coverage |
| dotnet | zimmerman | ✅ Required for Zimmerman DLLs |

**Note:** Volatility3 was removed from the SIFT 2026.03.24 release due to installer crashes from community plugin git cloning ([teamdfir/sift#628](https://github.com/teamdfir/sift/issues/628)). Geoff's installer works around this by installing Volatility3 directly via pip.

**YARA has been intentionally removed.** Static signature matching provides limited forensic value compared to behavioral analysis.

### Recently Added Tools (Mobile Forensics Expansion)

The following mobile forensic capabilities were added in the latest update:

| Tool/Method | Platform | Description |
|-------------|----------|-------------|
| `extract_ios_keychain` | iOS | Extract passwords, certificates from KeychainDomain.plist |
| `extract_ios_health` | iOS | Parse HealthKit databases (HealthExport.db, Health.db) |
| `extract_ios_notifications` | iOS | Extract notification history from SpringBoard |
| `extract_ios_usage_stats` | iOS | Parse app usage statistics |
| `extract_android_notifications` | Android | Parse notification_log from settings.db |
| `extract_android_usage_stats` | Android | Parse /data/system/usagestats/ XML files |
| `detect_jailbreak_indicators` | iOS | Detect Cydia, Zebra, Sileo, TrollStore, Dopamine |
| `detect_root_indicators` | Android | Detect Magisk, SuperSU, busybox, su binary |
| `run_ileapp` | iOS | iLEAPP integration wrapper |
| `run_aleapp` | Android | ALEAPP integration wrapper |
| `extract_whatsapp` | Both | WhatsApp message extraction (iOS & Android) |
| `extract_telegram` | Both | Telegram message extraction (iOS & Android) |
| `recover_deleted_sqlite_messages` | Both | WAL/journal recovery for deleted messages |
| `extract_mobile_photo_exif` | Both | EXIF/GPS extraction from DCIM |

**Total Mobile Functions:** 23 iOS + 20+ Android = 43+ mobile forensic methods

---

## Novel Contribution

GEOFF is a new autonomous DFIR platform built on top of the SANS SIFT Workstation. This section documents what is novel versus what it builds on.

### Built On (pre-existing)

| Component | Source |
|-----------|--------|
| Forensic tools (mmls, fls, fsstat, icat, strings, vol.py, rip.pl, log2timeline, tshark, etc.) | SANS SIFT Workstation |
| PhotoRec, Foremost, Scalpel | Pre-existing open source |
| Volatility3 | Pre-existing open source |
| Eric Zimmerman Tools (EvtxECmd, MFTECmd, etc.) | Pre-existing open source |
| RegRipper | Pre-existing open source |
| Plaso | Pre-existing open source |
| REMnux malware analysis tools (die, exiftool, oledump, pdfid, etc.) | Pre-existing open source |
| Flask, requests, Python stdlib | Pre-existing open source |

### Novel Contribution (created during hackathon, April 15–June 15 2026)

**1. Three-agent autonomous pipeline**
A Manager / Forensicator / Critic architecture where no human is in the loop. The Manager plans and reviews the execution plan. The Forensicator interprets each tool result and assesses threat significance. The Critic validates every output for hallucinations and accuracy. All three agents communicate via structured JSON and are wired into a single deterministic pipeline — none of this exists in SIFT or any of the upstream tools.

**2. Self-correction loop**
When the Critic rejects a Forensicator interpretation, the Manager automatically generates a corrected analysis grounded only in what the raw tool output actually shows. The Critic re-validates. The step is only demoted to `completed_unverified` if the correction also fails. Chat responses go through an independent grounding check and are regenerated if ungrounded claims are detected. This is novel — SIFT tools have no self-validation capability.

**3. Evidence chain (per-finding traceability)**
Every completed step record carries an `evidence_chain` dict linking the finding to a specific artifact, evidence file, specialist tool, and Forensicator observation. The narrative report receives these anchors and is required to cite them explicitly. No SIFT tool or prior DFIR framework produces this structured traceability automatically.

**4. Device-centric investigation architecture**
Evidence is grouped by device (not by file type), with each device getting its own playbook execution, behavioral analysis, and correlated findings. Cross-device lateral movement detection and a unified super-timeline are built from the per-device outputs. This device-centric model is not present in SIFT.

**5. 25-playbook MITRE ATT&CK-aligned execution engine**
PB-SIFT-000 through PB-SIFT-024 cover the full kill chain (initial access → execution → persistence → privilege escalation → credential access → lateral movement → exfiltration → impact). PB-SIFT-000 is a mandatory triage meta-playbook that generates the execution plan dynamically based on evidence type, OS detection, and indicator hits. The Manager LLM reviews and approves the plan before execution begins.

**6. Behavioral analysis engine (replaces YARA)**
Ten deterministic behavioral checks (process path/parent validation, spawn chain analysis, beaconing detection, timestomp detection, typosquatting, temp-directory executables, off-hours clustering, etc.) replace static YARA signature matching. Each flag includes a severity rating, MITRE ATT&CK technique tag, and supporting evidence dict.

**7. LLM-generated investigative narrative with artifact citations**
The `NarrativeReportGenerator` produces an 8-section human-readable investigation report driven by the Manager LLM, including an attack chain synthesis that maps findings to MITRE techniques, assesses attribution, and requires every factual claim to cite a specific evidence anchor from the pipeline. No SIFT tool produces narrative output of this kind.

**8. Git-backed reproducibility**
Every step execution, Critic validation, and state transition is committed to a per-case git repository. The case directory structure, findings.jsonl stream, validations/ directory, and audit_trail.jsonl collectively form a full forensic chain of custody that can be independently verified or re-run.

---

## Competition Compliance

GEOFF is designed to meet three core requirements for autonomous forensic investigation:

### Self-Correction

The agent detects and resolves errors or inconsistencies in its own output **without human intervention**:

**In `find_evil()`:** When the Critic rejects a step (`passes_sanity=False`), the Manager LLM is called to generate a corrected analysis grounded only in what the tool output actually shows. The Critic re-validates the corrected analysis. If it passes, the step is accepted and marked `self_corrected: true`. Only if the correction also fails is the step demoted to `completed_unverified`. The original and corrected analyses are both stored in the step record.

**In chat:** After each LLM response, a lightweight grounding check verifies the response does not assert claims absent from the available case context. If unsupported claims are detected, the response is regenerated once with an explicit correction prompt before being returned to the user.

### Accuracy Validation

All findings are traceable to specific artifacts, files, offsets, and log entries:

- **Evidence chain:** Every completed `find_evil` step record includes an `evidence_chain` dict:
  ```json
  {
    "artifact": "fls_list_files",
    "evidence_file": "/evidence/disk.E01",
    "tool": "sleuthkit.fls_list_files",
    "playbook": "PB-SIFT-002",
    "significance": "HIGH",
    "analyst_note": "Output shows cmd.exe spawned from winword.exe at inode 54321",
    "threat_indicators": ["cmd.exe spawned from Office process"]
  }
  ```
- **Narrative citations:** The attack chain synthesis receives the top 30 CRITICAL/HIGH evidence anchors and is required to cite each factual claim as `(source: <tool> on <file>)`.
- **Chat accuracy:** The GEOFF_PROMPT requires that every assertion names the source artifact, tool used, and specific observed value. Inferences use qualified language ("appears to", "consistent with").

### Analytical Reasoning

Output is structured as an investigative narrative, not a raw execution log:

- **GEOFF_PROMPT** enforces a Hypothesis → Evidence → Assessment structure for all chat responses. Claims without evidence citations are prohibited.
- **Narrative reports** require investigative prose with explicit evidence citations in each section — Attack Narrative, Key Evidence, MITRE mapping, and Recommended Actions all anchor to named artifacts from the evidence chain.
- **Attack chain synthesis** is prohibited from speculating beyond the verified evidence anchors; it must write "Insufficient evidence to assess" for sections not supported by the data.

---

## The Critic Pipeline

Every tool execution is validated:

```
Forensicator Output → Critic Validation ─── pass ──→ Git Commit
       ↓                    ↓
  Raw output              fail
  interpreted               ↓
                    Manager Self-Correction
                    (revised analysis)
                            ↓
                    Critic Re-Validation ─── pass ──→ completed_corrected
                            ↓ fail
                    completed_unverified (needs_review: true)
```

**Critic checks for:**
- Hallucinations (claims not in raw output)
- Obvious nonsense (impossible values, contradictions)
- Invalid IOC formats (malformed IPs, hashes, timestamps)
- False positives (benign flagged as suspicious)

**IOC Format Validation:** The critic validates extracted IOCs against expected formats — IP addresses, MD5/SHA1/SHA256 hashes, URLs, and email addresses.

**Mandatory validation:** If the Critic is unavailable or errors, the step is flagged `needs_review: true` rather than silently accepted. The final report includes a `steps_needs_review` count and `steps_unverified` count. Steps are never silently passed without validation.

---

## Device Discovery

GEOFF identifies devices and owners from evidence using a priority strategy:

1. **Directory structure** — `evidence/PC1/`, `evidence/phone/` → separate devices
2. **Hostname extraction** — Windows SYSTEM hive → ComputerName, Linux `/etc/hostname`, iOS Info.plist
3. **Username extraction** — Windows `Users/` directories, NTUSER.DAT paths, EVTX Computer fields
4. **Owner correlation** — Normalize usernames (strip domains, lowercase), match across devices
5. **Fallback** — Evidence filename stem as device ID

Output: `device_map.json` + `user_map.json` in the case directory.

---

## Playbook Library

25 PB-SIFT playbooks organized by MITRE ATT&CK kill chain:

| ID | Playbook | Phase | Auto-triggered when |
|----|----------|-------|---------------------|
| PB-SIFT-000 | Triage (mandatory entry point) | Triage | Always |
| PB-SIFT-001 | Initial Access | Initial Access | Always (core) |
| PB-SIFT-002 | Execution | Execution | Always (core) |
| PB-SIFT-003 | Persistence | Persistence | Always (core) — UserAssist, ShellBags, LNK files |
| PB-SIFT-004 | Privilege Escalation | Privilege Escalation | Always (core) |
| PB-SIFT-005 | Credential Access | Credential Access | Always (core) |
| PB-SIFT-006 | Lateral Movement | Lateral Movement | Disk images present |
| PB-SIFT-007 | Exfiltration | Exfiltration | Disk images — USB devices, mounted drives |
| PB-SIFT-008 | Malware Hunting | Impact | Disk images present |
| PB-SIFT-009 | Ransomware | Impact | Always |
| PB-SIFT-010 | Living-off-the-Land | Execution | Disk images present |
| PB-SIFT-011 | Web Shell Detection | Defense Evasion | PCAPs present |
| PB-SIFT-012 | Anti-Forensics | Defense Evasion | Disk images present |
| PB-SIFT-013 | Insider Threat | Collection | Always |
| PB-SIFT-014 | Linux Forensics | Discovery | OS detected as linux |
| PB-SIFT-015 | Data Staging | Collection | Disk images present |
| PB-SIFT-016 | Cross-Image Correlation | Lateral Movement | 2+ disk images |
| PB-SIFT-017 | REMnux Malware Analysis | Impact | Suspicious files / indicator hits |
| PB-SIFT-018 | Malware Analysis SOP | Impact | Suspicious files / indicator hits |
| PB-SIFT-019 | Command & Control | Command & Control | C2 indicators detected |
| PB-SIFT-020 | Timeline Analysis | Collection | Disk images present |
| PB-SIFT-021 | Mobile Analysis | Collection | Mobile backup files detected |
| PB-SIFT-022 | Browser Forensics | Collection | Always (browser DBs analysed if found) |
| PB-SIFT-023 | Email Forensics | Collection | .pst/.ost/.mbox/.eml files present |
| PB-SIFT-024 | macOS Forensics | Discovery | OS detected as macos |

**PB-SIFT-000 is mandatory** — it runs first, performs triage, and emits the execution plan. Only playbooks in the execution plan are run.

---

## Reproducibility

Every investigation is fully reproducible:

1. **Git History** — Every action, validation, and finding committed per-playbook
2. **Validation Files** — Stored in `validations/` with full critic results
3. **Command Logging** — Every command executed logged to `commands/` subdirectory
4. **Evidence Manifest** — `evidence/raw/manifest.json` references source evidence (no copies)
5. **Audit Trail** — `audit_trail.jsonl` records all state transitions
6. **Behavioral Flags** — All anomaly detections stored with evidence and explanation

---

## MCP Server

Geoff exposes all forensic capabilities as an [MCP (Model Context Protocol)](https://modelcontextprotocol.io/) server, allowing any MCP-compatible AI client (Claude Desktop, custom agents) to invoke the full investigation pipeline remotely.

### Starting the MCP Server

```bash
# HTTP transport — binds 127.0.0.1 by default (local only)
python src/geoff_mcp_server.py

# Custom port
python src/geoff_mcp_server.py --port 9999

# stdio transport (local clients, direct pipe)
python src/geoff_mcp_server.py --stdio
```

MCP endpoint: `http://127.0.0.1:9999/mcp`

### Remote Access (SSH Tunnel)

The server binds `127.0.0.1` only — no token required because the network is the auth layer.
Remote analysts connect via SSH tunnel:

```bash
# On the analyst's machine
ssh -L 9999:localhost:9999 user@sift-workstation

# Then point your MCP client at:
http://localhost:9999/mcp
```

### MCP Tools

| Tool | Description |
|------|-------------|
| `start_find_evil` | Launch a full triage investigation; returns `job_id` immediately |
| `get_job_status` | Poll progress of a running investigation |
| `list_cases` | List all evidence cases with file trees |
| `list_evidence` | List evidence files (optionally scoped to a case) |
| `get_case_report` | Fetch the Markdown narrative report for a completed case |
| `get_findings` | Fetch the structured JSON findings for a completed case |
| `list_playbooks` | List all 19+ SIFT playbooks with IDs and names |
| `chat` | Send a reasoning question to Geoff's LLM layer |
| `disk_analyze` | Call a SleuthKit specialist function directly |
| `memory_analyze` | Call a Volatility memory analysis function directly |
| `registry_analyze` | Call a RegRipper registry analysis function directly |
| `network_analyze` | Call a Zeek/tshark network analysis function directly |
| `log_analyze` | Call a log analysis function directly (EVTX, syslog, auth.log) |
| `malware_analyze` | Call a REMnux/YARA malware analysis function directly |
| `timeline_analyze` | Call a Plaso super-timeline function directly |
| `browser_analyze` | Call a browser forensics function directly |
| `run_specialist` | Generic dispatcher — call any module/function pair |

### Example: Full Investigation via MCP

```python
# 1. Start investigation
result = mcp_client.call_tool("start_find_evil", {"evidence_dir": "/cases/IR-016"})
job_id = result["job_id"]

# 2. Poll until complete
while True:
    status = mcp_client.call_tool("get_job_status", {"job_id": job_id})
    if status["status"] in ("complete", "error"):
        break
    time.sleep(10)

# 3. Retrieve narrative report
report = mcp_client.call_tool("get_case_report", {"case_name": "IR-016"})
print(report["report"])
```

### Claude Desktop Integration

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "geoff-dfir": {
      "command": "python",
      "args": ["/path/to/Geoff/src/geoff_mcp_server.py", "--stdio"]
    }
  }
}
```

---

## Quick Start

### Installation

**Cloud profile (default) — no local GPU needed:**
```bash
curl -sSL https://raw.githubusercontent.com/legacyboy/Geoff/main/install.sh | bash
```

**Local profile — pulls ~40GB of models:**
```bash
curl -sSL https://raw.githubusercontent.com/legacyboy/Geoff/main/install.sh | bash -s -- --profile local
```

**Other options:**
```bash
# Custom install directory
curl -sSL https://raw.githubusercontent.com/legacyboy/Geoff/main/install.sh | bash -s -- --dir /opt/geoff

# Skip Ollama model pulls
curl -sSL https://raw.githubusercontent.com/legacyboy/Geoff/main/install.sh | bash -s -- --skip-ollama

# Skip system dependencies
curl -sSL https://raw.githubusercontent.com/legacyboy/Geoff/main/install.sh | bash -s -- --skip-deps

# Private repo
git clone https://github.com/legacyboy/Geoff.git
cd Geoff && chmod +x install.sh && ./install.sh --profile local
```

### Model Profiles

Switch between cloud and local with a single flag:

| Agent | Cloud Profile | Local Profile |
|-------|--------------|---------------|
| **Manager** | deepseek-v3.2:cloud | deepseek-r1:32b |
| **Forensicator** | qwen3-coder-next:cloud | qwen2.5-coder:14b |
| **Critic** | qwen3.5:cloud | qwen2.5:14b |

```bash
# Switch at runtime
GEOFF_PROFILE=cloud python3 src/geoff_integrated.py
GEOFF_PROFILE=local python3 src/geoff_integrated.py

# Override individual models
GEOFF_PROFILE=local GEOFF_CRITIC_MODEL=qwen2.5:32b python3 src/geoff_integrated.py
```

### Local Model Provenance

Local models use **HuggingFace GGUF files with SHA256 verification**:

```toml
[models.deepseek-r1-32b]
url = "https://huggingface.co/.../deepseek-r1-32b.gguf"
sha256 = "abc123..."
```

The installer downloads, verifies, and creates Ollama modelfiles automatically.

### Manual Setup

```bash
pip install -r requirements.txt

export OLLAMA_URL="http://localhost:11434"
export GEOFF_PROFILE=cloud

# Optional: require API key on all endpoints
export GEOFF_API_KEY="your-secret-key"

# Optional: server port (default 8080)
export GEOFF_PORT=8080

# Or override individual models
export GEOFF_MANAGER_MODEL="deepseek-v3.2:cloud"
export GEOFF_FORENSICATOR_MODEL="qwen3-coder-next:cloud"
export GEOFF_CRITIC_MODEL="qwen3.5:cloud"

python src/geoff_integrated.py
```

### Access

| Method | How |
|--------|-----|
| **CLI** | `geoff-find-evil /path/to/evidence` — no server required |
| **Web UI** | http://localhost:8080 |
| **Console** | `python3 bin/geoff_console.py` |
| **Evidence tab** | Click any folder → auto-populates Find Evil input |
| **One-click** | Click 🔍 Investigate on any evidence folder to run immediately |
| **Chat** | `"start processing IR-016-CloudJack"` routes to Find Evil automatically |

---

## Interfaces

### Web UI

Three tabs:

**Find Evil** (default) — the main investigation console. Contains:
- Evidence directory input + **Run Find Evil** button at the top
- Live progress bar (playbook / step / elapsed time) while a job runs
- Unified scrollable output: chat message bubbles + streaming step-by-step log + results card
- Chat input pinned at the bottom — ask questions or trigger investigations in natural language

**Evidence** — browse all cases and their files.

Chat and Find Evil share the same streaming output. Whether you click the button or type `"analyze /cases/incident42"` in the chat box, you get the same live log.

### Console UI

A terminal REPL with identical functionality — no browser needed:

```bash
python3 bin/geoff_console.py
python3 bin/geoff_console.py --server http://10.0.0.5:8080 --key myapikey
```

Auto-loads `GEOFF_PORT` and `GEOFF_API_KEY` from `.env`.

```
geoff> analyze /cases/laptop.E01
  ▶ Starting investigation on /cases/laptop.E01
  Job: fe-a3b9c1

[████████░░░░░░░░░░░░░░░░░░░░░░] 27%  PB-SIFT-001  >  fls_list_files  42s
14:32:01  ▶ PB-SIFT-000: Triage Prioritization
14:32:03  ✓ inventory complete — 1 disk, 0 memory
14:32:05  ✗ fls_list_files failed — tool not found

geoff> /cases
geoff> /find-evil /mnt/evidence
geoff> /status fe-a3b9c1      # reconnect to a running job
geoff> /quit
```

Commands: `/find-evil [path]` · `/cases` · `/status <job_id>` · `/help` · `/quit`  
Ctrl+C stops polling the current job without exiting. `NO_COLOR=1` disables ANSI output.

### API

**Find Evil — CLI (no server needed):**
```bash
# Basic run
geoff-find-evil /cases/incident42

# Save JSON report
geoff-find-evil /cases/incident42 -o /cases/incident42/report.json

# Script-friendly: JSON to stdout, evil-found = exit 1
geoff-find-evil /cases/incident42 --json | jq '{evil:.evil_found, sev:.severity}'
```

**Find Evil — HTTP API:**
```bash
curl -X POST http://localhost:8080/find-evil \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: yourkey' \
  -d '{"evidence_dir": "/path/to/evidence"}'
# → { "job_id": "fe-abc123", "status": "running" }

curl http://localhost:8080/find-evil/status/fe-abc123 \
  -H 'X-API-Key: yourkey'
```

### REST API Endpoints

All endpoints accept/return JSON. Optional `X-API-Key` or `Authorization: Bearer` header if `GEOFF_API_KEY` is set.

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| GET | `/` | Web UI (HTML) | Optional |
| GET | `/health` | Service health check | No |
| GET | `/health/detailed` | Detailed system status | Optional |
| POST | `/chat` | LLM chat with tool detection | Yes* |
| POST | `/find-evil` | Start investigation | Yes* |
| GET | `/find-evil?job_id=` | Get job status | Yes* |
| GET | `/find-evil/status/<job_id>` | Get job status | Yes* |
| GET | `/cases` | List all cases | Yes* |
| GET | `/cases/<case_name>/report` | Get case report (MD or JSON) | Yes* |
| GET | `/reports` | List all reports | Yes* |
| GET | `/reports/<case_dir>/json` | Get structured findings | Yes* |
| GET | `/reports/viewer` | HTML report viewer | Optional |
| GET | `/tools` | List available forensic tools | Optional |
| POST | `/run-tool` | Execute a specific tool | Yes* |
| POST | `/critic/validate` | Validate tool output | Yes* |
| GET | `/critic/summary/<inv_id>` | Get validation summary | Yes* |
| GET | `/investigation/status/<case>` | Investigation state | Yes* |

*Required if `GEOFF_API_KEY` is configured.

### Example: Full Investigation via REST

```bash
# 1. Start investigation
JOB=$(curl -s -X POST http://localhost:8080/find-evil \
  -H 'Content-Type: application/json' \
  -d '{"evidence_dir": "/cases/IR-016"}')
JOB_ID=$(echo $JOB | jq -r '.job_id')
echo "Started: $JOB_ID"

# 2. Poll until complete
while true; do
  STATUS=$(curl -s "http://localhost:8080/find-evil/status/$JOB_ID")
  echo "$(date): $(echo $STATUS | jq -r '.status') - $(echo $STATUS | jq -r '.progress_pct')%"
  [[ $(echo $STATUS | jq -r '.status') == "complete" ]] && break
  [[ $(echo $STATUS | jq -r '.status') == "error" ]] && break
  sleep 10
done

# 3. Get narrative report
curl -s "http://localhost:8080/cases/IR-016/report"
```

**Chat:**
```bash
curl -X POST http://localhost:8080/chat \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: yourkey' \
  -d '{"message": "Start processing /cases/incident42"}'
```

**Geoff will:**
1. Detect the request (tool execution or investigation)
2. Execute via the appropriate specialist
3. Validate with Critic (marks `needs_review` if Critic unavailable)
4. Run behavioral analysis
5. Build super timeline
6. Generate narrative report
7. Commit everything to git

---

## Security

### API Authentication

Set `GEOFF_API_KEY` in `.env` to require authentication on all API endpoints:

```bash
echo "GEOFF_API_KEY=your-secret-key" >> .env
```

Pass the key via header:
```bash
curl -H 'X-API-Key: your-secret-key' http://localhost:8080/find-evil ...
# or
curl -H 'Authorization: Bearer your-secret-key' http://localhost:8080/find-evil ...
```

The web UI reads the key from a server-injected `<meta>` tag and includes it automatically in all fetch requests. When `GEOFF_API_KEY` is unset, authentication is disabled (backwards-compatible default for local use).

### Evidence Path Validation

All evidence paths are validated against a strict allowlist before use. Paths containing shell metacharacters (`;`, `&`, `|`, `` ` ``, `$`, `()`, etc.) are rejected to prevent command injection via maliciously named evidence files.

### Memory Safety

Findings are streamed to `findings.jsonl` on disk as each step completes rather than accumulated in memory. A compact in-memory index handles idempotency checks. This prevents OOM crashes on large evidence sets. The cap is configurable via `GEOFF_MAX_FINDINGS` (default: 50,000 in-memory entries).

---

## Case Directory Structure

```
case_work_dir/
├── device_map.json          # Device grouping + metadata
├── user_map.json            # User-to-device mapping
├── execution_plan.json      # Triage-generated plan
├── findings.jsonl           # All step records, streamed to disk as they complete
├── output/
│   ├── PB-SIFT-008.json     # Per-playbook findings (best-effort snapshot)
│   └── PB-SIFT-012.json
├── validations/
│   └── step_key.json        # Per-step critic results
├── commands/
│   └── timestamp_cmd.json   # Command audit log
├── evidence/
│   ├── raw/
│   │   └── manifest.json   # References to source evidence
│   └── derived/             # Symlinks to output/timeline
├── timeline/
│   └── super_timeline.jsonl # Unified timeline
├── reports/
│   ├── find_evil_report.json
│   └── narrative_report.md  # LLM-written summary
├── spill/                    # Oversized step results
└── audit_trail.jsonl         # State transition log
```

---

## License

MIT License - See LICENSE file

---

## The Name

**GEOFF** = **Git-backed Evidence Operations Forensic Framework**

Your digital forensics colleague. Still pronounced "Geoff."

---

*Built for DFIR professionals who need multi-agent analysis with behavioral detection and narrative reporting.*