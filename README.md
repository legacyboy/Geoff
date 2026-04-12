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
- **Forensicator** (Qwen 2.5 Coder 32B) - Executes forensic tools with self-validation
- **Critic** (Qwen3 30B) - Validates all outputs for hallucinations and accuracy

**Workflow:**
```
User → Manager → Forensicator → Tools → Critic → Git → Report
```

**Key Capabilities:**
- **Find evil and malicious activity** using playbooks as investigation guides
- **32 forensic functions** across 9 specialist modules
- **Double validation** (Forensicator self-check + Critic review)
- **Git-backed** every action committed for reproducibility
- **24K context window** with smart truncation

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
| **Static Analysis** | `die`, `exiftool`, `peframe`, `upx` | Binary identification, metadata, PE structure, unpacking | 🛠️ Requires REMnux Install |
| **Dynamic Analysis** | `fakedns`, `inetsim`, `wireshark` | Network simulation, traffic capture | 🛠️ Requires REMnux Install |
| **Memory Forensics** | `vol.py`, `rekall` | Memory dump analysis | ✅ Via Volatility3 (built-in) |
| **Network Analysis** | `wireshark`, `tcpflow`, `ngrep` | PCAP inspection, flow reconstruction | ✅ Via tshark/tcpflow (built-in) |
| **Malware Detection** | `clamav`, `yara` | Signature-based detection, custom rules | ✅ Via YARA (built-in) |
| **Web Analysis** | `js-beautify`, `burp` | JavaScript deobfuscation, web proxy | 🛠️ Requires REMnux Install |
| **Document Analysis** | `pdfid`, `pdf-parser`, `oledump` | PDF and Office document inspection | 🛠️ Requires REMnux Install |
| **Crypto** | `ssdeep`, `hashdeep` | Fuzzy hashing, file integrity | 🛠️ Requires REMnux Install |
| **Utilities** | `radare2`, `gdb` | Disassembly, debugging | 🛠️ Requires REMnux Install |

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

## Playbook Library

18 PB-SIFT playbooks for structured investigations:

- PB-SIFT-001: Malware Hunting
- PB-SIFT-002: Ransomware
- PB-SIFT-003: Lateral Movement
- PB-SIFT-004: Credential Theft
- PB-SIFT-005: Persistence
- PB-SIFT-006: Exfiltration
- PB-SIFT-007: Living-off-the-Land
- PB-SIFT-008: Initial Access
- PB-SIFT-009: Insider Threat
- PB-SIFT-010: Anti-Forensics
- PB-SIFT-011: Cloud & SaaS
- PB-SIFT-012: Linux
- PB-SIFT-013: macOS
- PB-SIFT-014: Network Device Forensics
- PB-SIFT-015: Mobile
- PB-SIFT-016: Triage
- PB-SIFT-017: Correlation

---

## Reproducibility

Every investigation is fully reproducible:

1. **Git History** - Every action and validation committed
2. **Validation Files** - Stored in `validations/` with full results
3. **Context Management** - 24K token window, conversation history retained
4. **Action Logging** - JSONL logs of all operations

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

**Pinned Versions for Forensic Repeatability:**

| Component | Version/Digest | Purpose |
|-----------|---------------|---------|
| **Ollama binary** | v0.6.5 | Local LLM inference engine |
| **Ollama model** | gemma3:4b (digest: `aeda25e63ebd`) | Default Geoff model |
| **Geoff** | v0.1.0 | DFIR investigation framework |

These exact versions ensure identical behavior across installations for chain of custody and evidence integrity.

**System Requirements:**
- Python 3.10+
- Ollama (versions pinned above)
- SIFT Tools (SleuthKit, Volatility3, YARA, etc.)

### Installation (Public Repo - when available)
```bash
curl -fsSL https://raw.githubusercontent.com/legacyboy/Geoff/main/installer/install.sh | bash
```

### Installation (Private Repo - current)
```bash
git clone https://github.com/legacyboy/Geoff.git
cd Geoff/installer
./install.sh
```

### Manual Setup (Advanced)
```bash
pip install -r requirements.txt

# Ollama Configuration (local or remote)
export OLLAMA_URL="http://localhost:11434"  # or remote: http://your-ollama-server:11434

# Agent Models (via Ollama)
export GEOFF_MANAGER_MODEL="deepseek-r1:70b"
export GEOFF_FORENSICATOR_MODEL="qwen2.5-coder:32b"  
export GEOFF_CRITIC_MODEL="qwen3:30b"

# Other settings
export GEOFF_EVIDENCE_PATH="/path/to/evidence"
export GEOFF_PORT=8080

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
┌─────────┐  ┌──────────┐  ┌──────────┐
│Context  │  │ Action   │  │ Critic   │
│Manager  │  │ Logger   │  │ Validator│
└────┬────┘  └────┬─────┘  └────┬─────┘
     │            │             │
     └────────────┼─────────────┘
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

## Training

GEOFF includes CTF training data:
- 27 writeup files from 29 sources
- Memory, disk, network, malware forensics
- Real-world scenarios and methodologies

---

## License

MIT License - See LICENSE file

---

## The Name

**GEOFF** = **Git-backed Evidence Operations Forensic Framework**

Your digital forensics colleague. Still pronounced "Geoff."

---

*Built for DFIR professionals who need 100% tool coverage with built-in quality assurance.*
