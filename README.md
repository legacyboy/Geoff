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

**Your digital forensics colleague with comprehensive tool coverage and built-in quality assurance.**

---

## What is GEOFF?

GEOFF is a **multi-agent conversational DFIR platform** with three specialized AI agents working together:

**The Multi-Agent Team:**
- **Manager** (DeepSeek R1 70B) - Orchestrates investigations, makes strategic decisions
- **Forensicator** (Qwen 2.5 Coder 32B) - Executes forensic tools
- **Critic** (Qwen3 30B) - Validates all outputs for hallucinations and accuracy

**Workflow:**
```
User → Manager → Forensicator → Tools → Critic → Git → Report
```

**Key Capabilities:**
- **Find Evil** — point at an evidence directory, auto-run playbooks, find evil with no prompting
- **32 forensic functions** across 9 specialist modules
- **Critic validation** (Critic reviews all Forensicator output for accuracy)
- **Git-backed** every action committed for reproducibility

---

## Tool Coverage

| Category | Tools | Functions |
|----------|-------|-----------|
| **Disk** | SleuthKit (mmls, fls, fsstat, icat, istat, ils) | Partition, filesystem, file extraction |
| **Memory** | Volatility3 | Process list, network, malware, registry, dump |
| **Malware** | YARA | Signature scan, directory scan |
| **IOC Extraction** | strings | URL, IP, email, registry path extraction |
| **Registry** | RegRipper | Hive parsing, UserAssist, ShellBags, USB history, autoruns, services |
| **Timeline** | Plaso (log2timeline, psort, pinfo) | Super timeline creation and analysis |
| **Network** | tshark, tcpflow | PCAP analysis, flow extraction, HTTP traffic |
| **Logs** | python-evtx | Windows Event Logs, syslog parsing |
| **Mobile** | iLEAPP-style | iOS backup, Android data analysis |

**Total: 32 functions across 9 specialist modules**

### REMnux Tool Coverage Status

GEOFF is designed to work with REMnux malware analysis tools. Current integration status:

| Category | Tools | Purpose | Status |
|----------|-------|---------|--------|
| **Static Analysis** | `die`, `exiftool`, `peframe`, `upx` | Binary identification, metadata, PE structure, unpacking | ✅ Wrappers Available |
| **Dynamic Analysis** | `fakedns`, `inetsim`, `wireshark` | Network simulation, traffic capture | 🛠️ Requires REMnux Install |
| **Memory Forensics** | `vol.py`, `rekall` | Memory dump analysis | ✅ Via Volatility3 (built-in) |
| **Network Analysis** | `wireshark`, `tcpflow`, `ngrep` | PCAP inspection, flow reconstruction | ✅ Via tshark/tcpflow (built-in) |
| **Malware Detection** | `clamav`, `yara` | Signature-based detection, custom rules | ✅ Via YARA (built-in) |
| **Web Analysis** | `js-beautify`, `burp` | JavaScript deobfuscation, web proxy | 🛠️ Requires REMnux Install |
| **Document Analysis** | `pdfid`, `pdf-parser`, `oledump` | PDF and Office document inspection | ✅ Wrappers Available |
| **Crypto** | `ssdeep`, `hashdeep` | Fuzzy hashing, file integrity | ✅ Wrappers Available |
| **Utilities** | `radare2`, `gdb` | Disassembly, debugging | ✅ Wrappers Available |

**Note:** GEOFF provides 32 built-in forensic functions. REMnux tools provide additional specialized analysis when installed on the SIFT workstation.

---

## The Critic Pipeline

Every tool execution is validated:

```
Geoff Tool Execution → Critic Validation → Git Commit
         ↓                    ↓                  ↓
    Raw output        Hallucination      validations/
    interpreted       detection          <case>_<timestamp>.json
```

**Critic checks for:**
- Hallucinations (claims not in raw output)
- False positives (benign flagged as suspicious)
- Missed findings (critical items overlooked)
- IOC verification (confirms extracted IOCs exist)

---

## Find Evil

**One endpoint. Zero prompting. Full auto-triage.**

```
curl -X POST http://localhost:8080/find-evil \
  -H 'Content-Type: application/json' \
  -d '{"evidence_dir": "/path/to/evidence"}'
```

Find Evil is GEOFF's autonomous investigation mode. Point it at a directory of evidence and it:

1. **Inventories** every artifact — disk images, memory dumps, pcaps, logs, registry hives, mobile backups
2. **Classifies** the OS and incident type via rapid indicator triage
3. **Selects** the right playbooks automatically (ransomware → PB-SIFT-009, web shell → PB-SIFT-001, etc.)
4. **Executes** each playbook step through the 9 specialist modules
5. **Validates** every result through the Critic pipeline
6. **Reports** a unified findings report with severity ratings, evidence scores, and critic approval

**What triggers each playbook:**

| Evidence / Indicator | Playbook(s) | Severity |
|:---|:---|:---|
| Ransom notes, encrypted extensions | PB-SIFT-009, PB-SIFT-001 | CRITICAL |
| Credential dumping tools, LSASS access | PB-SIFT-005, PB-SIFT-006 | HIGH |
| Lateral movement tools (PsExec, WMI) | PB-SIFT-006, PB-SIFT-003 | HIGH |
| Persistence (autoruns, scheduled tasks) | PB-SIFT-003, PB-SIFT-008 | HIGH |
| Exfiltration (cloud sync, bulk staging) | PB-SIFT-007, PB-SIFT-013 | HIGH |
| Anti-forensics (log clearing, timestomping) | PB-SIFT-012, PB-SIFT-008 | HIGH |
| Web shells, SQLi payloads | PB-SIFT-001, PB-SIFT-008 | HIGH |
| LOLBin abuse (certutil, mshta, rundll32) | PB-SIFT-010, PB-SIFT-008 | MEDIUM |
| Linux image detected | PB-SIFT-014 | HIGH |
| macOS image detected | PB-SIFT-015 | HIGH |
| Mobile backup detected | PB-SIFT-006 | HIGH |
| Multiple disk images | PB-SIFT-016 | HIGH |
| REMnux static analysis needed | PB-SIFT-017 | HIGH |
| Malware sample requiring full SOP | PB-SIFT-018 | HIGH |
| Any disk image present | PB-SIFT-008 | (baseline) |

**API Reference:**

```
GET  /find-evil          → Usage info + supported playbooks
POST /find-evil          → Run Find Evil
     Body: {"evidence_dir": "/path/to/evidence"}
     Response: Full report (inventory, classification, findings, critic summary)
```

**Response includes:**
- `evil_found` — boolean, true if CRITICAL/HIGH indicators detected
- `severity_distribution` — counts by severity level
- `evidence_score` — 0.0–1.0 quality score
- `critic_approval_pct` — percentage of results Critic-validated
- `findings_detail` — per-step results with critic validation
- `case_work_dir` — path to the full case directory with git-backed audit trail

---

## Playbook Library

19 PB-SIFT playbooks for structured investigations:

- PB-SIFT-008: Malware Hunting
- PB-SIFT-009: Ransomware
- PB-SIFT-006: Lateral Movement
- PB-SIFT-005: Credential Theft
- PB-SIFT-003: Persistence
- PB-SIFT-007: Exfiltration
- PB-SIFT-010: Living-off-the-Land
- PB-SIFT-001: Initial Access
- PB-SIFT-013: Insider Threat
- PB-SIFT-012: Anti-Forensics
- PB-SIFT-015: Cloud & SaaS
- PB-SIFT-014: Linux
- PB-SIFT-015: macOS
- PB-SIFT-004: Network Device Forensics
- PB-SIFT-006: Mobile
- PB-SIFT-000: Triage
- PB-SIFT-016: Correlation
- PB-SIFT-017: REMnux Malware Analysis
- PB-SIFT-018: Malware Analysis SOP

---

## Reproducibility

Every investigation is fully reproducible:

1. **Git History** - Every action and validation committed
2. **Validation Files** - Stored in `validations/` with full results
3. **Action Logging** - JSONL logs of all operations

Another investigator can:
```bash
git clone <repo>
cd validations/
# Review step-by-step validations
# Re-run same commands
# Compare results
```

---

## Quick Start

### Requirements

**System Requirements:**
- Python 3.10+
- Ollama (for LLM inference)
- SIFT/REMnux tools (SleuthKit, Volatility3, YARA, etc.)
- 8GB+ RAM for local models, or just an Ollama connection for cloud

### Installation

**Cloud profile (default) — uses cloud-hosted Ollama models, no local GPU needed:**
```bash
curl -sSL https://raw.githubusercontent.com/legacyboy/Geoff/main/install.sh | bash
```

**Local profile — pulls ~40GB of models to run everything locally:**
```bash
curl -sSL https://raw.githubusercontent.com/legacyboy/Geoff/main/install.sh | bash -s -- --profile local
```

**Other options:**
```bash
# Install to a custom directory
curl -sSL https://raw.githubusercontent.com/legacyboy/Geoff/main/install.sh | bash -s -- --dir /opt/geoff

# Skip Ollama model pulls (if already installed)
curl -sSL https://raw.githubusercontent.com/legacyboy/Geoff/main/install.sh | bash -s -- --skip-ollama

# Skip system dependency installs
curl -sSL https://raw.githubusercontent.com/legacyboy/Geoff/main/install.sh | bash -s -- --skip-deps

# Private repo — clone and run manually
git clone https://github.com/legacyboy/Geoff.git
cd Geoff
chmod +x install.sh
./install.sh --profile local
```

### Model Profiles

GEOFF uses three AI agents, each with a specific model. Switch between cloud and local with a single flag:

| Agent | Cloud Profile | Local Profile |
|-------|--------------|---------------|
| **Manager** | deepseek-v3.2:cloud | deepseek-r1:32b |
| **Forensicator** | qwen3-coder-next:cloud | qwen2.5-coder:14b |
| **Critic** | qwen3.5:cloud | qwen2.5:14b |

Switch profiles at runtime without reinstalling:
```bash
# Use cloud models
GEOFF_PROFILE=cloud python3 src/geoff_integrated.py

# Use local models
GEOFF_PROFILE=local python3 src/geoff_integrated.py

# Override individual models
GEOFF_PROFILE=local GEOFF_CRITIC_MODEL=qwen2.5:32b python3 src/geoff_integrated.py
```

### Manual Setup (Advanced)
```bash
pip install -r requirements.txt

# Ollama Configuration
export OLLAMA_URL="http://localhost:11434"  # or remote Ollama server

# Profile selection
export GEOFF_PROFILE=cloud  # or: local

# Or override individual models
export GEOFF_MANAGER_MODEL="deepseek-v3.2:cloud"
export GEOFF_FORENSICATOR_MODEL="qwen3-coder-next:cloud"
export GEOFF_CRITIC_MODEL="qwen3.5:cloud"

python src/geoff_integrated.py
```

**Remote Ollama Example:**
```bash
# Point to remote Ollama server
export OLLAMA_URL="http://192.168.1.100:11434"
# Models referenced by name on that server
export GEOFF_MANAGER_MODEL="deepseek-r1:70b"
```

### Access
- Web UI: http://localhost:8080
- Chat: Conversational interface with tool execution
- Evidence: Browse cases and files
- Tools: View available forensic tools

---

## Usage

**Find Evil (Autonomous):**
```
curl -X POST http://localhost:8080/find-evil \
  -H 'Content-Type: application/json' \
  -d '{"evidence_dir": "/path/to/evidence"}'
```
No prompting. Just results.

**Chat with Geoff:**
```
"Run mmls on the narcos case"
"Extract strings from the malware sample"
"Show me the timeline for this incident"
"What registry hives are in the Windows image?"
```

**Geoff will:**
1. Detect the tool request
2. Execute the appropriate specialist
3. Validate with Critic
4. Commit to git
5. Return results with validation status

---

## Architecture

```
┌─────────────────────────────────────────────┐
│           GEOFF Web Interface          │
│  (Flask + Chat + Evidence Browser)           │
└──────────────────┬──────────────────────────┘
                   │
    ┌──────────────┼──────────────┐
    ▼              ▼              ▼
┌──────────┐         ┌──────────┐
│ Action   │         │ Critic   │
│ Logger   │         │ Validator│
└────┬─────┘         └────┬─────┘
     │                    │
     └─────────┬──────────┘
               │
     ┌─────────┴──────────┐
     ▼                    ▼
┌───────────────┐    ┌──────────────┐
│ Extended      │    │ Validation   │
│ Orchestrator  │    │ Pipeline     │
└───────┬───────┘    └──────────────┘
        │
    ┌───┴───┬────┬────┬────┬────┬────┬────┬────┐
    ▼       ▼    ▼    ▼    ▼    ▼    ▼    ▼    ▼
┌──────┐┌────┐┌────┐┌────┐┌────┐┌────┐┌────┐┌────┐
│Sleuth││Vol ││YARA││Reg ││Plaso││Net ││Logs││Mobile│
│Kit   ││    ││    ││    ││     ││    ││    ││      │
└──────┘└────┘└────┘└────┘└─────┘└────┘└────┘└─────┘
```

### Investigation State Validation

GEOFF uses a shared JSON Schema to validate investigation steps across all agents:

```json
{
  "type": "object",
  "required": ["investigation_id", "steps", "current_step"],
  "properties": {
    "investigation_id": {"type": "string"},
    "case_name": {"type": "string"},
    "created_at": {"type": "string", "format": "date-time"},
    "updated_at": {"type": "string", "format": "date-time"},
    "current_step": {"type": "integer", "minimum": 0},
    "steps": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["index", "module", "function", "status"],
        "properties": {
          "index": {"type": "integer"},
          "module": {"type": "string"},
          "function": {"type": "string"},
          "params": {"type": "object"},
          "status": {"type": "string", "enum": ["pending", "running", "completed", "failed"]},
          "started_at": {"type": "string", "format": "date-time"},
          "completed_at": {"type": "string", "format": "date-time"},
          "result": {"type": "object"}
        }
      }
    }
  }
}
```

This schema ensures:
- **Cross-agent consistency** - All agents use same investigation structure
- **State validation** - Required fields prevent incomplete investigations
- **Reproducibility** - Complete audit trail of every step
- **Error recovery** - Failed steps tracked with full context

---

## License

MIT License - See LICENSE file

---

## The Name

**GEOFF** = **Git-backed Evidence Operations Forensic Framework**

Your digital forensics colleague. Still pronounced "Geoff."

---

*Built for DFIR professionals who need 100% tool coverage with built-in quality assurance.*

<!-- test comment: direct push to main verified 2026-04-12 -->
