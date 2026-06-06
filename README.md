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

**License:** Apache 2.0 — see [LICENSE](LICENSE).

---

## What is GEOFF?

GEOFF is a **multi-agent conversational DFIR platform** with three specialized AI agents, device-aware evidence processing, behavioral analysis, and LLM-generated narrative reports.

## Agentic Framework

Geoff's primary execution engine is the **Geoff Triad** — a three-agent autonomous loop that plans, executes, observes, critiques, and self-corrects without per-step human approval. The competition rules permit "comparable agentic architectures" alongside Claude Code and OpenClaw; the Geoff Triad is that architecture.

### The agents

- **Manager** — receives the high-level goal ("find evil in this evidence"), reviews triage output, builds and amends the execution plan, decides post-execution actions (approve / flag / replay). Implementation: `src/geoff_self_heal.py::_manager_review_execution_plan`, `src/geoff_pipeline.py::_manager_post_critic_decision`.
- **Forensicator** — selects forensic tools per playbook step, interprets each tool's output into a structured analyst note (significance + threat indicators + evidence chain). Implementation: `src/geoff_forensicator.py::call_forensicator_llm`.
- **Critic** — validates every finding for hallucinations and inconsistency, diagnoses failed tool runs into structured `HealDecision`s, and flags steps that need replay. Implementation: `src/geoff_critic.py` and `src/geoff_self_heal.py::_attempt_heal`.

A fourth role — **Healer** — is the Critic operating in error-recovery mode (`_attempt_heal` → `_execute_heal`). It is the same model with a different prompt; surfaced separately in the agent trace because it has its own audit class.

### The Multi-Agent Team

| Agent | Role | Cloud Model | Local Model |
|-------|------|-------------|-------------|
| **Manager** | Orchestrates investigations, strategic decisions | deepseek-v4-pro:cloud | deepseek-r1:32b |
| **Forensicator** | Executes forensic tools, extracts artifacts | qwen3-coder-next:cloud | qwen2.5-coder:14b |
| **Critic** | Validates output for hallucinations and accuracy | qwen3.5:cloud | qwen2.5:14b |
| **Critic 2** | Independent parallel validation (different architecture) | gemma4:31b-cloud | gemma4:31b-cloud |

**Workflow:**
```
User → Manager → Preflight Validation
                      ↓
               Forensicator runs ALL steps autonomously
               (per-step custody commits to git)
                      ↓
               Dual Critic (GeoffCriticPool) validates ALL findings
               — Critic 1 (qwen3.5:cloud) + Critic 2 (gemma4:31b-cloud)
               — Confidence: VERY_HIGH / HIGH / MEDIUM / LOW
                      ↓
               Batch Critic reviews ALL findings at once
               (holistic cross-step correlation)
                      ↓
               Manager decision: approve / flag / replay
                      ↓ (if replay)
               Incremental Replay (patched params, affected steps only)
                      ↓
               Adaptive Pass 2 — intelligence-driven follow-up selection
                      ↓
               Behavioral Analyzer + Super Timeline + Correlation
                      ↓
               Narrative Report (gated by Manager approval)
```

### Capability comparison

| Capability | Claude Code | OpenClaw | **Geoff Triad** |
|------------|-------------|----------|------------------|
| Goal-directed planning | ✅ single agent | ✅ single agent | ✅ **dedicated planner agent (Manager)** |
| Tool selection at runtime | ✅ | ✅ | ✅ Forensicator chooses per-step from 49 playbooks |
| Observation → reasoning loop | ✅ | ✅ | ✅ Forensicator analyst note → Critic validation |
| Self-critique | ⚠ via prompt | ⚠ via prompt | ✅ **dual parallel critics + batch holistic review** |
| Autonomous error recovery | ⚠ retry only | ⚠ retry only | ✅ **`_attempt_heal` with fast-path + LLM diagnosis** |
| Multi-agent specialization | ❌ | ❌ | ✅ **three distinct roles, three model profiles** |
| Persistent memory | session context | session context | ✅ **git-backed per-case repo with custody sidecars** |
| Reproducible audit trail | ❌ | partial | ✅ **per-step SHA-256 custody + commands log + audit_trail.jsonl** |
| Pluggable LLM backend | Anthropic-only | Ollama-only | Ollama (cloud or local), profile-switchable |
| Runs on SIFT Workstation | requires net + key | yes | yes (cloud or local) |

### Why a custom triad instead of Claude Code or OpenClaw

DFIR investigations require three properties that single-agent frameworks struggle to provide:

1. **Separation of concerns.** Tool execution (Forensicator), validation (Critic), and decision-making (Manager) come from different model temperaments. We use different models per role (`profiles.json`) — a coder model for tool selection, a general-reasoning model for critique, a planner model for decisions.
2. **Holistic cross-step critique.** A per-step LLM check misses inconsistencies between findings. The Geoff Critic reviews all findings in one pass (`_batch_critic_review_all_playbooks`), which catches hallucinations a single-agent loop cannot.
3. **Forensic chain of custody.** Every step commits to a per-case git repository with a SHA-256-of-evidence custody sidecar. This is a forensic non-negotiable; bolted onto a general-purpose agent framework it becomes fragile, but it's primary in Geoff.

---

## Architecture Overview

### Geoff Triad — Three-Agent Pipeline

The core execution engine is the **Geoff Triad**: three specialized agents that plan, execute, validate, and self-correct without per-step human approval.

```
User → Manager → Preflight Validation
                      ↓
               Forensicator runs ALL steps autonomously
               (per-step custody commits to git)
                      ↓
               Dual Critic (GeoffCriticPool) validates in parallel
               — Critic 1 (qwen3.5:cloud) + Critic 2 (gemma4:31b-cloud)
               — Confidence: VERY_HIGH / HIGH / MEDIUM / LOW
                      ↓
               Batch Critic reviews ALL findings at once
               (holistic cross-step correlation)
                      ↓
               Manager decision: approve / flag / replay
                      ↓ (if replay)
               Incremental Replay (patched params, affected steps only)
                      ↓
               Adaptive Pass 2 — score remaining playbooks
               (intelligence-driven follow-up selection)
                      ↓
               Behavioral Analyzer + Super Timeline + Correlation
                      ↓
               ProvenanceDAG — evidence derivation tracking
                      ↓
               Narrative Report (gated by Manager approval)
```

#### Component Boundaries

| Component | Boundary | Notes |
|-----------|----------|-------|
| **MCP Server** | `127.0.0.1:9999` only | Network is the auth layer; remote access via SSH tunnel |
| **Evidence paths** | Path validation allowlist | Shell metacharacters rejected before any tool call (`src/geoff_routes.py`) |
| **SIFT tool execution** | Subprocess calls with validated args | Tools read evidence; they do not write to the evidence directory |
| **Case work directory** | Separate from evidence | All output (findings, custody sidecars, git repo) goes to `GEOFF_WORK_DIR`, never back into evidence |
| **LLM backend** | Ollama API at `OLLAMA_URL` | All three agents call the same endpoint; model profiles configured per-agent |

#### Security Boundaries

| Boundary | Enforcement type | Mechanism |
|----------|-----------------|-----------|
| Evidence path injection prevention | **Architectural (code-enforced)** | `src/geoff_routes.py` validates paths against shell metacharacter blocklist before any subprocess call |
| API authentication | **Architectural (code-enforced)** | `GEOFF_API_KEY` bearer token on all HTTP endpoints; absent = local-only unauthenticated mode |
| MCP network isolation | **Architectural (code-enforced)** | Server binds `127.0.0.1` only; no unauthenticated remote access |
| Evidence non-modification | **Detective (custody, not preventive)** | SHA-256 custody sidecars record evidence state per-step; modification is detectable but not prevented at the OS level |
| Chat response grounding | **Architectural (code-enforced)** | `_self_check_chat_response` regenerates responses that assert claims absent from case context |

#### Guardrail Types

**Code-enforced (structural) guardrails** — a misbehaving model cannot bypass these:
- Evidence path allowlist validation
- Per-step git commit (append-only; steps cannot be deleted without detection)
- SHA-256 custody sidecars (tamper-evident chain of custody)
- `127.0.0.1`-only MCP bind
- API key enforcement

**Prompt-enforced guardrails** — depend on the model following instructions:
- Forensicator: prohibited from speculating beyond tool output
- Narrative report: required to cite evidence anchors; prohibited from asserting unverified claims
- Chat: `Hypothesis → Evidence → Assessment` reasoning protocol
- Attack chain synthesis: must write "Insufficient evidence to assess" for unsupported sections

**Important disclosure:** Narrative report generation has no structural backstop equivalent to `_self_check_chat_response`. A model that ignores its system prompt could assert unsupported claims in the report. Chat responses have structural regeneration; narrative reports rely solely on prompt instructions. See `docs/ACCURACY_REPORT.md` for the full accuracy assessment.

---

### Component Architecture Diagram

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
  ┌──────┤ Host         │            │ Narrative    │
  │      │ Correlator   │            │ Report Gen   │
  │      └──────────────┘            └──────────────┘
  │               │
  ▼               ▼
┌──────────┐ ┌──────────────────┐
│ Proven-  │ │ Dual Critic Pool │
│ ance DAG │ │ (Qwen + Gemma)   │
└──────────┘ └──────────────────┘
          │
   ┌───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┐
   ▼   ▼   ▼   ▼   ▼   ▼   ▼   ▼   ▼   ▼   ▼   ▼   ▼
Sleuth Vol Reg Plaso Net Logs Mob REMnux Brow Mail macOS
  DNS  YARA  Hash  Cloud  EDR  AD  IoT  VM  Container
```

### Key Architecture Concepts

**Device-Centric Processing:** Evidence is grouped by device, not by file type. Each device gets its own playbook execution, its own findings, and its own behavioral analysis. Cross-device correlation ties it all together.

**Modular Specialist Architecture:** DNS forensics, YARA scanning, hash correlation, dual-critic validation, adaptive playbook generation, confidence calibration, provenance tracking, and adaptive Pass 2 are each implemented as dedicated modules (`geoff_dns_forensics.py`, `geoff_yara.py`, `geoff_hash_correlation.py`, `geoff_dual_critic.py`, `geoff_adaptive_playbook.py`, `geoff_confidence.py`, `geoff_provenance.py`, `geoff_adaptive_pass2.py`).

**Behavioral Analysis:** Geoff uses 10 deterministic behavioral checks plus LLM-assisted assessment:
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

1. **Preflight** — validate evidence directory, git availability, writable paths
2. **Inventory** — catalog every artifact (disk images, memory dumps, pcaps, logs, registry hives, mobile backups)
3. **Device Discovery** — group evidence by device, extract hostnames, identify owners, build device_map and user_map
4. **Triage** — PB-SIFT-000 rapid indicator scan; Manager LLM reviews and approves execution plan
5. **Autonomous Batch Execution** — Forensicator runs ALL selected playbooks end-to-end without per-step Manager gates; each completed step is committed to git with a chain-of-custody sidecar (`custody/<step_key>.json`)
6. **Dual Critic Validation** — GeoffCriticPool runs two critics in parallel for each finding; confidence levels (VERY_HIGH / HIGH / MEDIUM / LOW) drive review decisions
7. **Batch Critic Review** — after all playbooks complete, Critic reviews all findings in one pass, grouped by significance; finds cross-step correlations and flags hallucinations or replay candidates
8. **Manager Decision** — Manager reviews Critic assessment and chooses `approve`, `flag`, or `replay`; saves `manager_decision.json`
9. **Incremental Replay** (if requested) — only affected steps re-run with Manager-patched params; new outputs committed with custody metadata. Replay can also be triggered manually via `POST /replay-playbook` with adjusted parameters.
10. **Adaptive Pass 2** — scores remaining playbooks against Pass 1 findings; selects follow-up playbooks when Pass 1 uncovered leads worth chasing
11. **Super Timeline** — unified timeline across all devices and evidence types
12. **Behavioral Analysis** — per-device anomaly detection (process, file, network, persistence, timeline)
13. **Host Correlation** — cross-device user activity, lateral movement detection
14. **IP Map** — interactive VisJS network graph of all IP connections (GET `/reports/<case>/ip-map`)
15. **Provenance DAG** — full evidence derivation tracking from source artifacts through every transform
16. **Narrative Report** — gated on Manager approval; LLM-written investigative narrative with explicit artifact citations

### Configuration Reference

Key environment variables and their defaults:

| Variable | Default | Description |
|----------|---------|-------------|
| `GEOFF_MAX_WORKERS` | `3` | Max parallel threads for evidence processing. Increase for large multi-image cases on high-core machines with a local Ollama; decrease if you hit Ollama connection limits. Set in `.env` or `export GEOFF_MAX_WORKERS=3`. |
| `OLLAMA_URL` | `http://localhost:11434` | Ollama API endpoint. Use `http://localhost:11434` for local Ollama with Cloud signin. |
| `GEOFF_PROFILE` | `cloud` | Model profile: `cloud` uses Ollama Cloud models (requires `ollama signin`); `local` runs models on local GPU. |
| `GEOFF_API_KEY` | _(empty — auth disabled)_ | Shared secret for HTTP API authentication. Set to enable `X-API-Key` / `Bearer` header checks. |
| `GEOFF_EVIDENCE_PATH` | `/mnt/evidence` | Evidence root directory (typically a NAS mount, read-only). |
| `GEOFF_CASES_PATH` | `/mnt/cases` | Case output directory (local fast storage recommended). |
| `GEOFF_CRITIC2_MODEL` | _(same as GEOFF_CRITIC_MODEL)_ | Second critic model for dual-critic pool. Defaults to the primary critic model. |
| `EVIDENCE_BASE_DIR` | `/mnt/evidence` | Alias for `GEOFF_EVIDENCE_PATH` (used by UI). |
| `CASES_WORK_DIR` | `/mnt/cases` | Alias for `GEOFF_CASES_PATH` (used by UI). |

Copy `.env.example` to `.env` and edit to taste:

```bash
cp .env.example .env
# Edit GEOFF_MAX_WORKERS, OLLAMA_URL, etc.
```

**Minimal `.env` for cloud profile on SIFT VM:**

```bash
OLLAMA_URL=http://localhost:11434
GEOFF_PROFILE=cloud
GEOFF_EVIDENCE_PATH=/mnt/evidence
GEOFF_CASES_PATH=/mnt/cases
# No OLLAMA_API_KEY needed — Ollama Cloud auth is handled by `ollama signin`
```

### What Triggers Each Playbook

| Evidence / Indicator | Playbook(s) | Severity |
|:---|:---|:---|
| Ransom notes, encrypted extensions | PB-SIFT-009, PB-SIFT-001 | CRITICAL |
| Credential dumping, LSASS access | PB-SIFT-005, PB-SIFT-006 | HIGH |
| Lateral movement (PsExec, WMI) | PB-SIFT-006, PB-SIFT-003 | HIGH |
| Persistence (autoruns, scheduled tasks) | PB-SIFT-003, PB-SIFT-008 | HIGH |
| Exfiltration (cloud sync, bulk staging) | PB-SIFT-007, PB-SIFT-013 | HIGH |
| Anti-forensics (log clearing, timestomp) | PB-SIFT-012 | HIGH |
| Web shells, SQLi payloads | PB-SIFT-001, PB-SIFT-038 | HIGH |
| LOLBin abuse (certutil, mshta, rundll32) | PB-SIFT-010, PB-SIFT-008 | MEDIUM |
| Memory dumps (.raw, .dmp, .lime) | PB-SIFT-027 | HIGH |
| DNS anomalies (DGA, tunneling) | PB-SIFT-050 | HIGH |
| Known malware signatures | PB-SIFT-051 (YARA) | HIGH |
| Unknown file classification | PB-SIFT-052 (Hash + NSRL) | MEDIUM |
| Multiple disk images (correlation) | PB-SIFT-016 | HIGH |
| Malware sample | PB-SIFT-017, PB-SIFT-018, PB-SIFT-019 | HIGH |
| EDR telemetry logs | PB-SIFT-037 | HIGH |
| Active Directory artifacts | PB-SIFT-035 | HIGH |
| PCAP captures | PB-SIFT-036 | HIGH |

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

### 📁 Evidence

Lists every subfolder in your evidence directory. Each entry has two ways to kick off an investigation:

- **Click the folder name** — copies the full path into the Find Evil input and switches to that tab, ready to run
- **Click 🔍 Investigate** — does the same and immediately starts the run

No copy-pasting paths. No switching tabs manually.

### 💬 Chat

Conversational interface. Talk to Geoff directly or say things like `"start processing IR-016-CloudJack"` and it will route to Find Evil automatically.

### 📊 MITRE ATT&CK Visualizations

Interactive matrix and heatmap views mapping all investigation findings to the MITRE ATT&CK framework. Accessible via `GET /reports/mitre-matrix` and `GET /reports/mitre-heatmap`.

---

## Tool Coverage

### Forensic Tools by Category

| Category | Specialist | Tools | Functions |
|----------|-----------|-------|----------|
| **Disk** | sleuthkit | SleuthKit (mmls, fls, fsstat, icat, istat, ils, blkls, blkcat, blkcalc, blkstat, ifind, ffind, tsk_recover) | Partition detection, filesystem analysis, file extraction, deleted file recovery, block-level analysis |
| **Recovery** | photorec | PhotoRec, Foremost, Scalpel | File carving from unallocated space, deleted file recovery, fragmented file recovery |
| **Memory** | volatility | Volatility3 | pslist, netscan, malfind, dll_list, handles, mutantscan, apihooks, modscan, vadinfo, procdump, memmap, registry hive extraction, process dump |
| **IOC Extraction** | strings | strings, bulk_extractor, floss | URL, IP, email, credit card, registry path extraction |
| **Registry** | registry | RegRipper (rip.pl), Python-Registry | Hive parsing, UserAssist, ShellBags, USB, autoruns, services, mounted devices |
| **Windows Analysis** | zimmerman | Eric Zimmerman Tools (EvtxECmd, MFTECmd, bstrings, ShellBagsExplorer, AmcacheParser, SRUMDB2) | Event log parsing, MFT timeline, string extraction, shellbag analysis, AmCache execution history, SRUM resource usage |
| **VSS** | vss | vshadowmount, ewfmount | Shadow copy enumeration, VSS mounting, file extraction from shadow copies, cross-VSS timeline |
| **Timeline** | plaso | Plaso (log2timeline, psort, pinfo) | Super timeline creation, filtering, timezone-aware correlation |
| **Event Logs** | logs | python-evtx, EvtxECmd (Zimmerman) | Windows Event Log parsing, syslog analysis |
| **Network** | network | tshark, tcpflow | PCAP analysis, flow extraction, HTTP traffic reconstruction, DNS analysis |
| **DNS** | dns | DNS_Specialist | DGA detection (Shannon entropy), DNS tunneling detection, PCAP DNS extraction |
| **YARA** | yara | YARA_Specialist | 5 built-in rule sets (PE overlay, encoded PowerShell, ransomware, credential dumping, webshell), file/directory/memory/disk scanning |
| **Hash** | hash | HASH_Specialist | SHA-256/MD5/SHA1 file hashing, directory hashing, NSRL lookup |
| **DNS** | dns | DNS_Specialist | DGA detection (Shannon entropy), DNS tunneling detection, PCAP DNS extraction |
| **YARA** | yara | YARA_Specialist | 5 built-in rule sets (PE overlay, encoded PowerShell, ransomware, credential dumping, webshell), file/directory/memory/disk scanning |
| **Hash** | hash | HASH_Specialist | SHA-256/MD5/SHA1 file hashing, directory hashing, NSRL lookup |
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
| YARA | yara | ✅ Built-in rule sets + custom rules support |
| dotnet | zimmerman | ✅ Required for Zimmerman DLLs |

**Note:** Volatility3 was removed from the SIFT 2026.03.24 release due to installer crashes from community plugin git cloning ([teamdfir/sift#628](https://github.com/teamdfir/sift/issues/628)). Geoff's installer works around this by installing Volatility3 directly via pip.

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

**Total Mobile Functions:** 15 iOS + 13 Android + 4 cross-platform = 32 mobile forensic methods

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
| YARA | Pre-existing open source |
| Flask, requests, Python stdlib | Pre-existing open source |

### Novel Contribution (created during hackathon, April 15–June 15 2026)

**1. Three-agent autonomous pipeline**
A Manager / Forensicator / Critic architecture where no human is in the loop. The Manager plans and reviews the execution plan. The Forensicator interprets each tool result and assesses threat significance. The Critic validates every output for hallucinations and accuracy. All three agents communicate via structured JSON and are wired into a single deterministic pipeline — none of this exists in SIFT or any of the upstream tools.

**2. Multi-Critic dual validation (GeoffCriticPool)**
Two independent Critic instances run in parallel on each finding — using different model architectures (Qwen vs Gemma) for genuinely independent validation. Agreement patterns produce confidence levels (VERY_HIGH when both approve, LOW when both challenge). Disagreement triggers mandatory human review. This goes beyond single-critic validation and catches findings that one model alone would miss or wrongly approve.

**3. Batch self-correction loop**
The Forensicator runs all playbooks autonomously without per-step gates. After execution, the Batch Critic reviews all findings in one pass — enabling cross-step correlation that per-step validation misses — and flags hallucinations or replay candidates. The Manager then decides: approve, flag for review, or trigger incremental replay with adjusted parameters (only affected steps re-run). Chat responses go through an independent grounding check. This is novel — SIFT tools have no self-validation capability.

**4. Evidence chain and Provenance DAG**
Every completed step record carries an `evidence_chain` dict linking the finding to a specific artifact, evidence file, specialist tool, and Forensicator observation. The ProvenanceDAG tracks the full derivation graph: source evidence → extracted artifacts → derived findings. Every node in the graph records its source, transform, and output path, providing complete traceability from any finding back to the original evidence. No SIFT tool or prior DFIR framework produces this structured provenance automatically.

**5. Device-centric investigation architecture**
Evidence is grouped by device (not by file type), with each device getting its own playbook execution, behavioral analysis, and correlated findings. Cross-device lateral movement detection and a unified super-timeline are built from the per-device outputs. This device-centric model is not present in SIFT.

**6. 49-playbook MITRE ATT&CK-aligned execution engine**
PB-SIFT-000 through PB-SIFT-104 cover the full kill chain (initial access → execution → persistence → privilege escalation → credential access → lateral movement → exfiltration → impact) plus specialized playbooks for cloud, memory forensics, DNS, YARA, hash correlation, EDR, Active Directory, IoT, containers, and VM snapshots. PB-SIFT-000 is a mandatory triage meta-playbook that generates the execution plan dynamically based on evidence type, OS detection, and indicator hits. The Manager LLM reviews and approves the plan before execution begins. Adaptive Pass 2 can dynamically add follow-up playbooks when Pass 1 findings suggest additional investigation paths.

**7. Adaptive Playbook Generation**
The AdaptivePlaybook class composes investigation plans for findings that don't match any existing playbook. When the triage step discovers an indicator without a dedicated playbook, the system dynamically selects relevant specialist functions and builds a custom playbook on the fly. This means Geoff can investigate novel threat patterns without manual playbook authoring.

**8. Confidence Calibration**
The ConfidenceCalibrator tracks critic agreement patterns across an investigation and produces per-finding confidence scores. Findings validated by both critics get VERY_HIGH confidence; findings where critics disagree get MEDIUM and are flagged for review. This calibrated confidence is persisted and available in the final report, giving analysts a meaningful signal about which findings to trust most.

**9. Behavioral analysis engine**
Ten deterministic behavioral checks (process path/parent validation, spawn chain analysis, beaconing detection, timestomp detection, typosquatting, temp-directory executables, off-hours clustering, etc.) replace static signature matching. Each flag includes a severity rating, MITRE ATT&CK technique tag, and supporting evidence dict.

**10. LLM-generated investigative narrative with artifact citations**
The `NarrativeReportGenerator` produces an 8-section human-readable investigation report driven by the Manager LLM, including an attack chain synthesis that maps findings to MITRE techniques, assesses attribution, and requires every factual claim to cite a specific evidence anchor from the pipeline. No SIFT tool produces narrative output of this kind.

**11. Git-backed reproducibility with per-step chain of custody**
Every step execution is committed to a per-case git repository immediately on completion (not at the end of the run). Each commit includes a `custody/<step_key>.json` sidecar with the SHA-256 hash of the evidence file, a SHA-256 hash of the step parameters, a timestamp, and the tool version. The `ChainOfCustodyLog` uses Merkle hash-chained JSONL — each record includes the SHA-256 hash of the previous record, forming a tamper-evident chain. Evidence intake hashes all source files at case start, and pre/post verification detects any modification during processing. The findings.jsonl stream, validations/ directory, batch_critic_assessment.json, manager_decision.json, and audit_trail.jsonl collectively form a full forensic audit trail that can be independently verified or re-run.

**12. IP Map visualization**
Interactive VisJS network graph showing all IP connections discovered across an investigation. Internal/external/multicast nodes are color-coded. Edge labels show protocol and port. Accessible via GET `/reports/<case>/ip-map` or the report viewer.

**13. MITRE ATT&CK matrix and heatmap**
Interactive visualizations mapping all investigation findings to the MITRE ATT&CK framework. Accessible via GET `/reports/mitre-matrix` and GET `/reports/mitre-heatmap`.

---

## Competition Compliance

GEOFF is designed to meet three core requirements for autonomous forensic investigation:

### Self-Correction

The agent detects and resolves errors or inconsistencies in its own output **without human intervention**:

**At step execution time (tool self-healing):** When a forensic tool call fails, the error is first classified deterministically — tool not found, permission denied, mount failure, SQLite lock — and fixed without LLM involvement. Missing tools are installed automatically (`sudo apt-get install -y sleuthkit`, `pip3 install volatility3`, etc.) and the step is retried. Only errors that cannot be resolved deterministically are escalated to the Healer (Critic in recovery mode) for LLM diagnosis. A token-bucket rate limiter prevents heal loops from flooding the LLM backend. This fast path handles the most common field errors — tools absent from a fresh SIFT image — without interrupting the investigation.

**In `find_evil()`:** After all playbooks complete, the Batch Critic reviews every finding holistically. If quality is below `GOOD` or replay candidates are identified, the Manager LLM generates adjusted parameters and triggers incremental replay — re-running only the affected steps without repeating the full investigation. Steps flagged by the Critic as unverified are marked `needs_review: true` and the final report includes `steps_needs_review` and `steps_unverified` counts.

**Dual-critic validation:** The GeoffCriticPool runs two independent critics in parallel. When they disagree, findings are flagged with MEDIUM confidence and `needs_review: true`. This catches errors that a single critic would miss.

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
- **Provenance DAG:** Every finding links back through a derivation graph to the original source evidence. `ProvenanceDAG.finding_provenance()` returns the full chain from source → extracted artifact → derived finding.
- **Narrative citations:** The attack chain synthesis receives the top 30 CRITICAL/HIGH evidence anchors and is required to cite each factual claim as `(source: <tool> on <file>)`.
- **Chat accuracy:** The GEOFF_PROMPT requires that every assertion names the source artifact, tool used, and specific observed value. Inferences use qualified language ("appears to", "consistent with").
- **Confidence calibration:** Per-finding confidence scores (VERY_HIGH / HIGH / MEDIUM / LOW) based on critic agreement patterns give analysts a quantitative signal about finding reliability.

### Analytical Reasoning

Output is structured as an investigative narrative, not a raw execution log:

- **GEOFF_PROMPT** enforces a Hypothesis → Evidence → Assessment structure for all chat responses. Claims without evidence citations are prohibited.
- **Narrative reports** require investigative prose with explicit evidence citations in each section — Attack Narrative, Key Evidence, MITRE mapping, and Recommended Actions all anchor to named artifacts from the evidence chain.
- **Attack chain synthesis** is prohibited from speculating beyond the verified evidence anchors; it must write "Insufficient evidence to assess" for sections not supported by the data.

---

## The Critic Pipeline

Geoff uses a **dual-critic + batch review** model — two critics run in parallel on each finding, then a batch review covers all findings holistically:

```
Forensicator runs ALL steps autonomously
  (each step committed to git with custody sidecar)
          ↓
GeoffCriticPool validates in parallel
  • Critic A + Critic B review each finding independently
  • BOTH_APPROVE → VERY_HIGH confidence
  • ONE_APPROVES → HIGH confidence
  • ONE_CHALLENGES → MEDIUM confidence (flag for review)
  • BOTH_CHALLENGE → LOW / likely false-positive
          ↓
Batch Critic reviews ALL findings in one pass
  • Groups by status: completed / unverified / failed
  • Focuses on HIGH/CRITICAL + unverified findings (up to 50)
  • Checks for hallucinations, cross-step inconsistencies, replay needs
  • Outputs: batch_critic_assessment.json
          ↓
ConfidenceCalibrator records agreement stats
  • Per-finding confidence persisted to case_work_dir
          ↓
Manager reviews Critic assessment + confidence scores
  • GOOD quality + no replay → APPROVE immediately
  • Otherwise → LLM decides: approve / flag / replay
  • Outputs: manager_decision.json
          ↓ (if replay)
Incremental replay — patch params, re-run affected steps only
  (idempotency via findings_writer.is_completed(); new custody commits)
          ↓
Narrative report generated only if Manager approves
```

**Batch Critic checks for:**
- Hallucinations (step claims not supported by tool output)
- HIGH/CRITICAL findings that need replay with different params
- Whether findings are sufficient to generate a report

**Performance:** ~20 LLM calls per 12-playbook run vs. 60+ in per-step mode (~3x speedup). The Critic sees the full picture, enabling cross-step correlation that per-step validation misses.

**If Critic LLM is unavailable:** defaults to `overall_quality: ACCEPTABLE`, `sufficient_for_report: true`, and Manager approves — execution continues rather than blocking. Steps remain tagged `needs_review: true` in the findings.

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

## Parallel Evidence Processing

GEOFF handles large evidence collections — multiple disk images, PCAPs, mobile backups, and log archives from multiple hosts — without blocking or losing progress.

### Multiple Evidence Directories

Pass any top-level directory. GEOFF classifies and groups everything inside it:

- **Subdirectory layout** — `evidence/PC1/`, `evidence/phone/` → each becomes a separate device with its own playbook execution
- **Flat layout** — `disk1.E01`, `disk2.E01` side by side → correlated as separate devices; cross-image playbook PB-SIFT-016 auto-triggers
- **Mixed** — disk images + PCAPs + mobile backups → classified by type, grouped by device, each stream processed in parallel

Device discovery runs first and produces `device_map.json`, so every step output is stamped with the originating host before playbooks begin.

### Checkpoint / Resume

Investigation state is persisted to `.geoff_checkpoint.json` in the case directory after each phase. If a run is interrupted — power loss, OOM, Ctrl-C — re-run the same command to resume:

```bash
geoff-find-evil /evidence/IR-016   # interrupted mid-run
geoff-find-evil /evidence/IR-016   # resumes from last completed phase
```

The checkpoint tracks phase status (`pending / running / complete / failed`), which disk images have been walked, and which archives have been extracted (keyed by content SHA-256 to prevent double-extraction). Per-step idempotency (`findings_writer.is_completed(step_key)`) means a resumed run skips steps already committed to git individually, not just whole phases.

### Execution Cache Dedup

When two playbooks request the same tool on the same evidence file with identical parameters, the second call returns the cached result without spawning a subprocess:

1. Cache key = MD5(`module` + `function` + `evidence_path` + `params`)
2. First execution: result stored in `_ExecResultCache`, persisted to the case directory
3. Repeat request: cached result returned immediately; a `deduped` record is written to findings

This eliminates redundant invocations across playbooks — common when multiple playbooks each want `fls_list_files` or `strings` on the same image.

### Parallel Execution

Steps against different evidence items run concurrently via a thread pool. Set `GEOFF_MAX_WORKERS` (default: 3) to control concurrency. Each worker deep-copies its parameters to avoid shared mutable state; a per-`(module, function, evidence_item)` lock prevents the same call from running twice simultaneously across workers.

---

## Playbook Library

49 PB-SIFT playbooks organized by MITRE ATT&CK kill chain plus specialized analysis:

| ID | Playbook | Phase | Auto-triggered when |
|----|----------|-------|---------------------|
| PB-SIFT-000 | Triage (mandatory entry point) | Triage | Always |
| PB-SIFT-001 | Initial Access | Initial Access | Always (core) |
| PB-SIFT-002 | Execution | Execution | Always (core) |
| PB-SIFT-003 | Persistence | Persistence | Always (core) |
| PB-SIFT-004 | Privilege Escalation | Privilege Escalation | Always (core) |
| PB-SIFT-005 | Credential Theft | Credential Access | Always (core) |
| PB-SIFT-006 | Lateral Movement | Lateral Movement | Disk images present |
| PB-SIFT-007 | Exfiltration | Exfiltration | Disk images — USB devices, mounted drives |
| PB-SIFT-008 | Malware Hunting | Impact | Disk images present |
| PB-SIFT-009 | Ransomware | Impact | Always |
| PB-SIFT-010 | Living-off-the-Land | Execution | Disk images present |
| PB-SIFT-011 | Impact/Data Destruction | Impact | Disk images present |
| PB-SIFT-012 | Anti-Forensics | Defense Evasion | Disk images present |
| PB-SIFT-013 | Data from Cloud/Network Share | Collection | Always |
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
| PB-SIFT-025 | Cloud & Enterprise IR | Collection | Cloud logs detected |
| PB-SIFT-026 | File Carving & Recovery | Collection | Automatic when needed |
| PB-SIFT-027 | Memory Forensics | Collection | .raw/.dmp/.lime/.mem files |
| PB-SIFT-028 | Windows Modern Artifacts | Collection | Windows 10/11 detected |
| PB-SIFT-029 | Encrypted Containers | Defense Evasion | Encrypted volumes detected |
| PB-SIFT-030 | Cloud Sync Artifacts | Collection | Cloud sync DBs detected |
| PB-SIFT-031 | Enterprise Collaboration | Collection | Teams/Slack/Discord/Skype/Zoom artifacts |
| PB-SIFT-032 | VM Snapshot Forensics | Collection | .vmss/.vmsn/.vmem files |
| PB-SIFT-033 | Container Forensics | Collection | Docker/container artifacts |
| PB-SIFT-034 | Network Device Forensics | Collection | Disk images (network device configs) |
| PB-SIFT-035 | Active Directory DC Forensics | Credential Access | ntds.dit/SYSTEM/SAM artifacts |
| PB-SIFT-036 | PCAP Network Forensics | Collection | .pcap/.pcapng files |
| PB-SIFT-037 | EDR Telemetry Analysis | Detection | JSON/CSV/log files from EDR agents |
| PB-SIFT-038 | Web Shell Indicators | Initial Access | IIS/Apache logs or web server images |
| PB-SIFT-039 | Insider Threat Behavioral Analysis | Collection | Windows registry/logon artifacts |
| PB-SIFT-040 | IoT Device Forensics | Collection | IoT device images/directories |
| PB-SIFT-050 | DNS Forensics | Collection | PCAPs with DNS queries |
| PB-SIFT-051 | YARA Scanning | Detection | Any evidence (disk images, memory dumps, directories) |
| PB-SIFT-052 | Hash Correlation & NSRL | Collection | Any evidence (file hashing + NSRL lookup) |
| PB-SIFT-100 | Process Chain Investigation | Investigation | Process chain indicators from triage |
| PB-SIFT-101 | USB Lateral Movement Investigation | Investigation | USB device indicators |
| PB-SIFT-102 | Temporal Anomaly Investigation | Investigation | Timeline anomalies detected |
| PB-SIFT-103 | IOC Cross-Reference Investigation | Investigation | IOC hits from triage |
| PB-SIFT-104 | Dwell Window Deep-Dive | Investigation | Extended dwell time indicators |

**PB-SIFT-000 is mandatory** — it runs first, performs triage, and emits the execution plan. Only playbooks in the execution plan are run. **Adaptive Pass 2** may add follow-up playbooks after Pass 1 completes.

---

## Reproducibility

Every investigation is fully reproducible:

1. **Per-step git commits** — Each step is committed immediately on completion with a chain-of-custody sidecar (`custody/<step_key>.json`)
2. **Custody sidecars** — SHA-256 hash of evidence file + SHA-256 hash of step parameters + timestamp for every step
3. **Provenance DAG** — Full evidence derivation graph stored in `provenance_dag.json`
4. **Batch Critic record** — `batch_critic_assessment.json` documents the post-execution quality assessment
5. **Manager decision record** — `manager_decision.json` documents the Manager's approve/replay decision and reasoning
6. **Validation Files** — Per-step critic results in `validations/`
7. **Command Logging** — Every command executed logged to `commands/`
8. **Evidence Manifest** — `evidence/raw/manifest.json` references source evidence (no copies)
9. **Audit Trail** — `audit_trail.jsonl` records all state transitions
10. **Behavioral Flags** — All anomaly detections stored with evidence and explanation
11. **Confidence Scores** — Per-finding confidence from dual-critic agreement persisted in case directory

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
| `list_playbooks` | List all 49 SIFT playbooks with IDs and names |
| `chat` | Send a reasoning question to Geoff's LLM layer |
| `disk_analyze` | Call a SleuthKit specialist function directly |
| `memory_analyze` | Call a Volatility memory analysis function directly |
| `registry_analyze` | Call a RegRipper registry analysis function directly |
| `network_analyze` | Call a Zeek/tshark network analysis function directly |
| `log_analyze` | Call a log analysis function directly (EVTX, syslog, auth.log) |
| `malware_analyze` | Call a REMnux malware analysis function directly |
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

# After installation, sign into Ollama Cloud (one-time):
ollama signin
# This authorizes the local Ollama service to use cloud models.
# No API key needed in .env — auth is handled by the Ollama service.
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
| **Manager** | deepseek-v4-flash:cloud | deepseek-r1:32b |
| **Forensicator** | qwen3-coder-next:cloud | qwen2.5-coder:14b |
| **Critic** | qwen3.5:cloud | qwen2.5:14b |

**Cloud profile authentication:** Run `ollama signin` once after installation. This stores your Ollama Cloud credentials in the local Ollama service. No `OLLAMA_API_KEY` environment variable is needed — the signed-in Ollama daemon proxies cloud model requests automatically.

**Local profile:** Models run on your GPU. No internet required during investigation. Pull ~40GB on first run.

```bash
# Switch at runtime
GEOFF_PROFILE=cloud python3 src/geoff_integrated.py
GEOFF_PROFILE=local python3 src/geoff_integrated.py

# Override individual models
GEOFF_PROFILE=local GEOFF_CRITIC_MODEL=qwen2.5:32b python3 src/geoff_integrated.py

# Second critic model (dual-critic pool)
GEOFF_CRITIC2_MODEL=gemma4:31b-cloud python3 src/geoff_integrated.py
```

**Evidence and case directories:**

```bash
# Evidence: NAS mount (read-only source of truth)
export GEOFF_EVIDENCE_PATH=/mnt/evidence

# Cases: local NVMe (fast I/O for investigation output)
export GEOFF_CASES_PATH=/mnt/cases
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

# 1. Install and start Ollama (systemd service)
curl -fsSL https://ollama.ai/install.sh | sh
sudo systemctl enable --now ollama

# 2. Sign into Ollama Cloud (one-time, persisted by the service)
ollama signin
# Enter your Ollama Cloud credentials when prompted.
# This authorizes the local Ollama service to pull and run cloud models.
# No OLLAMA_API_KEY needed in .env — the signin handles auth.

# 3. Configure Geoff
export OLLAMA_URL="http://localhost:11434"
export GEOFF_PROFILE=cloud

# Optional: require API key on HTTP endpoints
export GEOFF_API_KEY="your-secret-key"

# Optional: server port (default 8080)
export GEOFF_PORT=8080

# Or override individual models
export GEOFF_MANAGER_MODEL="deepseek-v4-flash:cloud"
export GEOFF_FORENSICATOR_MODEL="qwen3-coder-next:cloud"
export GEOFF_CRITIC_MODEL="qwen3.5:cloud"
export GEOFF_CRITIC2_MODEL="gemma4:31b-cloud"  # second critic (different architecture for independent validation)

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

[████████░░░░░░░░░░░░░░░░░░░░░] 27%  PB-SIFT-001  >  fls_list_files  42s
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
| GET | `/find-evil` | Get latest job status | Yes* |
| GET | `/find-evil/active` | Get active job | Yes* |
| GET | `/find-evil/status/<job_id>` | Get job status | Yes* |
| DELETE | `/find-evil/status/<job_id>` | Cancel running job | Yes* |
| GET | `/cases` | List all cases | Yes* |
| GET | `/cases/<case_name>/report` | Get case report (MD or JSON) | Yes* |
| GET | `/reports` | List all reports | Yes* |
| GET | `/reports/graph` | Report dependency graph | Yes* |
| GET | `/reports/<case_dir>/json` | Get structured findings | Yes* |
| GET | `/reports/<case_dir>/download/markdown` | Download Markdown report | Yes* |
| GET | `/reports/<case_dir>/download/json` | Download JSON report | Yes* |
| GET | `/reports/<case_dir>/download/summary` | Download summary | Yes* |
| GET | `/reports/<case_dir>/supertimeline` | Get super timeline | Yes* |
| GET | `/reports/<case_dir>/ip-map` | IP connection map (VisJS JSON) | Yes* |
| GET | `/reports/<case_dir>/chat` | Chat about a specific report | Yes* |
| GET | `/reports/<case_dir>/history` | Report history | Yes* |
| GET | `/reports/narrative` | Narrative report page | Yes* |
| GET | `/reports/viewer` | HTML report viewer | Yes* |
| GET | `/reports/execution/<case_id>` | Get execution log | Yes* |
| GET | `/reports/mitre-matrix` | MITRE ATT&CK matrix visualization | Yes* |
| GET | `/reports/mitre-heatmap` | MITRE ATT&CK heatmap visualization | Yes* |
| POST | `/replay-playbook` | Replay a playbook with adjusted parameters | Yes* |
| GET | `/tools` | List available forensic tools | Optional |
| POST | `/run-tool` | Execute a specific tool | Yes* |
| POST | `/critic/validate` | Validate tool output | Yes* |
| GET | `/critic/summary/<inv_id>` | Get validation summary | Yes* |
| GET | `/investigation/status/<case>` | Investigation state | Yes* |
| POST | `/active-directory` | Set active directory evidence | Yes* |
| GET | `/active-directory` | Get active directory evidence | Yes* |
| GET | `/api/settings` | Get application settings | Yes* |
| POST | `/api/settings/models` | Update model configuration | Yes* |
| POST | `/api/settings/keys` | Update API keys | Yes* |

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

**Replay a playbook:**
```bash
curl -X POST http://localhost:8080/replay-playbook \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: yourkey' \
  -d '{
    "case_name": "my-case",
    "playbook_id": "PB-SIFT-001",
    "adjustments": {
      "offset": 2048,
      "evidence_file": "/mnt/evidence/case/disk.E01"
    }
  }'
```

**IP Map:**
```bash
curl -s "http://localhost:8080/reports/my-case/ip-map" | jq '.nodes | length'
```

**Geoff will:**
1. Detect the request (tool execution or investigation)
2. Execute via the appropriate specialist
3. Validate with Dual Critic (confidence: VERY_HIGH / HIGH / MEDIUM / LOW)
4. Run behavioral analysis
5. Build super timeline
6. Record provenance in ProvenanceDAG
7. Generate narrative report
8. Commit everything to git

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
├── .geoff_checkpoint.json        # Checkpoint state for resume-on-interrupt
├── device_map.json               # Device grouping + metadata
├── user_map.json                 # User-to-device mapping
├── execution_plan.json           # Triage-generated plan
├── findings.jsonl                # All step records, streamed to disk as they complete
├── batch_critic_assessment.json  # Post-execution Critic review (quality, hallucination flags)
├── manager_decision.json         # Manager action: approve / flag / replay + reasoning
├── provenance_dag.json           # Evidence derivation graph (ProvenanceDAG)
├── confidence_scores.json        # Per-finding confidence from dual-critic agreement
├── custody/
│   └── <step_key>.json           # Per-step chain-of-custody: evidence SHA-256, params hash, timestamp
├── output/
│   ├── PB-SIFT-008.json          # Per-playbook findings (best-effort snapshot)
│   └── PB-SIFT-012.json
├── validations/
│   └── step_key.json             # Per-step critic results
├── commands/
│   └── timestamp_cmd.json        # Command audit log
├── evidence/
│   ├── raw/
│   │   └── manifest.json        # References to source evidence
│   └── derived/                  # Symlinks to output/timeline
├── timeline/
│   └── super_timeline.jsonl      # Unified timeline
├── reports/
│   ├── find_evil_report.json
│   └── narrative_report.md       # LLM-written summary (only if Manager approves)
├── spill/                         # Oversized step results
└── audit_trail.jsonl              # State transition log
```

---

## License

Apache 2.0 License — see [LICENSE](LICENSE)

---

## The Name

**GEOFF** = **Git-backed Evidence Operations Forensic Framework**

Your digital forensics colleague. Still pronounced "Geoff."

---

*Built for DFIR professionals who need multi-agent analysis with behavioral detection, dual-critic validation, and narrative reporting.*