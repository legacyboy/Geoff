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
User → Manager → Forensicator → Tools → Critic → Git → Report
                                              ↓
                                    Behavioral Analyzer
                                              ↓
                                    Super Timeline + Correlation
                                              ↓
                                    Narrative Report (LLM-written)
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

**Narrative Reports:** LLM-generated human-readable investigation reports with executive summary, per-user narratives, timeline of significant events, and recommendations.

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
3. **Triage** — PB-SIFT-000 rapid indicator scan, generates execution plan
4. **Playbook Execution** (per-device) — run each selected playbook against each device's evidence
5. **Super Timeline** — unified timeline across all devices and evidence types
6. **Behavioral Analysis** — per-device anomaly detection (process, file, network, persistence, timeline)
7. **Host Correlation** — cross-device user activity, lateral movement detection
8. **Critic Validation** — every step validated for hallucinations and accuracy
9. **Narrative Report** — LLM-written human-readable report
10. **Git Commit** — every step committed for full reproducibility

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
| **Mobile** | mobile | Pure-Python (plistlib, sqlite3) | iOS backup analysis, Android data extraction |
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

---

## The Critic Pipeline

Every tool execution is validated:

```
Forensicator Output → Critic Validation → Git Commit
       ↓                    ↓                  ↓
  Raw output        Hallucination       validations/
  interpreted       detection           <step_key>.json
```

**Critic checks for:**
- Hallucinations (claims not in raw output)
- Obvious nonsense (impossible values, contradictions)
- Invalid IOC formats (malformed IPs, hashes, timestamps)
- False positives (benign flagged as suspicious)

**IOC Format Validation:** The critic validates extracted IOCs against expected formats — IP addresses, MD5/SHA1/SHA256 hashes, URLs, and email addresses.

**Mandatory validation:** If the Critic is unavailable or errors, the step is flagged `needs_review: true` rather than silently accepted. The final report includes a `steps_needs_review` count. Steps are never silently passed without validation.

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