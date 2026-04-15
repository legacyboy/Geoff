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
│  Find Evil • Chat • Evidence Browser • Narrative Report │
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
   ┌──────┼──────┬──────┬──────┬──────┬──────┬──────┐
   ▼      ▼      ▼      ▼      ▼      ▼      ▼      ▼
 SleuthKit Vol  Registry  Plaso  Net   Logs  Mobile  REMnux
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

**One endpoint. Zero prompting. Full auto-triage.**

```
curl -X POST http://localhost:8080/find-evil \
  -H 'Content-Type: application/json' \
  -d '{"evidence_dir": "/path/to/evidence"}'
```

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

### Anti-Forensics Cascade

When PB-SIFT-012 detects anti-forensics indicators, it **retroactively downgrades all findings** across all devices:
- CONFIRMED → POSSIBLE
- POSSIBLE → UNVERIFIED
- All findings marked `compromised_by: ["anti-forensics"]`

This prevents false confidence in evidence that may have been tampered with.

---

## Tool Coverage

| Category | Tools | Functions |
|----------|-------|-----------|
| **Disk** | SleuthKit (mmls, fls, fsstat, icat, istat, ils) | Partition detection, filesystem analysis, file extraction |
| **Memory** | Volatility3 | pslist, netscan, malware detection, registry, dump |
| **IOC Extraction** | strings | URL, IP, email, registry path extraction |
| **Registry** | RegRipper | Hive parsing, UserAssist, ShellBags, USB, autoruns, services |
| **Timeline** | Plaso (log2timeline, psort) | Timeline creation, filtering, correlation |
| **Network** | tshark, tcpflow | PCAP analysis, flow extraction, HTTP traffic |
| **Logs** | python-evtx | Windows Event Log, syslog parsing |
| **Mobile** | iLEAPP-style | iOS backup, Android data analysis |
| **Malware** | REMnux (die, exiftool, peframe, oledump, etc.) | 15 tool wrappers, 5 specialist classes |

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

20 PB-SIFT playbooks organized by MITRE ATT&CK kill chain:

| ID | Playbook | Phase |
|----|----------|-------|
| PB-SIFT-000 | Triage (mandatory entry point) | Triage |
| PB-SIFT-001 | Initial Access | Initial Access |
| PB-SIFT-002 | Execution | Execution |
| PB-SIFT-003 | Persistence | Persistence |
| PB-SIFT-004 | Privilege Escalation | Privilege Escalation |
| PB-SIFT-005 | Credential Access | Credential Access |
| PB-SIFT-006 | Lateral Movement | Lateral Movement |
| PB-SIFT-007 | Exfiltration | Exfiltration |
| PB-SIFT-008 | Malware Hunting | Impact |
| PB-SIFT-009 | Ransomware | Impact |
| PB-SIFT-010 | Living-off-the-Land | Execution |
| PB-SIFT-011 | Browser Forensics | Collection |
| PB-SIFT-012 | Anti-Forensics | Defense Evasion |
| PB-SIFT-013 | Insider Threat | Collection |
| PB-SIFT-014 | Linux | Discovery |
| PB-SIFT-015 | macOS | Discovery |
| PB-SIFT-016 | Correlation | Command & Control |
| PB-SIFT-017 | REMnux Malware Analysis | Impact |
| PB-SIFT-018 | Malware Analysis SOP | Impact |
| PB-SIFT-019 | Command & Control | Command & Control |
| PB-SIFT-020 | Timeline Analysis | Collection |

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

# Or override per-agent
export GEOFF_MANAGER_MODEL="deepseek-v3.2:cloud"
export GEOFF_FORENSICATOR_MODEL="qwen3-coder-next:cloud"
export GEOFF_CRITIC_MODEL="qwen3.5:cloud"

python src/geoff_integrated.py
```

### Access

- **Web UI**: http://localhost:8080
- **Chat**: Conversational interface with tool execution + evidence ingestion
- **Find Evil**: Autonomous investigation mode
- **Narrative Report**: Human-readable investigation summary

---

## Usage

**Find Evil (Autonomous):**
```
curl -X POST http://localhost:8080/find-evil \
  -H 'Content-Type: application/json' \
  -d '{"evidence_dir": "/path/to/evidence"}'
```

**Chat Commands:**
```
"Start processing /cases/incident42"
"Run mmls on the narcos disk image"
"Extract strings from the malware sample"
"Show me the timeline for this incident"
```

**Geoff will:**
1. Detect the request (tool execution or investigation)
2. Execute via the appropriate specialist
3. Validate with Critic
4. Run behavioral analysis
5. Build super timeline
6. Generate narrative report
7. Commit everything to git

---

## Case Directory Structure

```
case_work_dir/
├── device_map.json          # Device grouping + metadata
├── user_map.json            # User-to-device mapping
├── execution_plan.json      # Triage-generated plan
├── output/
│   ├── PB-SIFT-008.json     # Per-playbook findings
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