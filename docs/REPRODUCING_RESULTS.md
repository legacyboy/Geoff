# Reproducing Geoff Investigation Results

This document gives step-by-step instructions for running Geoff against each of the four
documented datasets. A SANS SIFT Workstation (Ubuntu 22.04) is the target environment.
Expected outputs are shown for each dataset so you can verify your run matches.

---

## Prerequisites

1. **SIFT Workstation** — Ubuntu 22.04 (SIFT 2026.x). Download from https://www.sans.org/tools/sift-workstation/
2. **Git** — `sudo apt-get install -y git`
3. **Python 3.12+** — included in SIFT
4. **Internet access** (first run only — self-heal will install missing tools on demand)
5. **Ollama** — see Step 2 below for installation

**Note on tool gaps:** Not all tools referenced by playbooks are installed by `install.sh`.
The self-heal fast-path installs missing tools automatically on first use via `apt-get install`.
This requires internet access on the first run. Subsequent runs on the same machine will use
the already-installed tools. See `docs/TRY_IT_OUT.md` for the full list of auto-installed tools.

---

## Step 1 — Clone and install Geoff

```bash
git clone https://github.com/legacyboy/Geoff.git
cd Geoff
chmod +x install.sh
./install.sh
```

The installer creates the `geoff-find-evil` command on your PATH. Verify:

```bash
which geoff-find-evil
geoff-find-evil --help
```

---

## Step 2 — Configure Ollama

**Cloud profile (recommended for first run):**

```bash
# Install Ollama (systemd service)
curl -fsSL https://ollama.ai/install.sh | sh
sudo systemctl enable --now ollama

# Sign into Ollama Cloud (one-time)
ollama signin
# Enter your Ollama Cloud credentials when prompted.
# No API key needed in .env — the signin handles auth automatically.
```

**Cloud profile models:**
- Manager: `deepseek-v4-flash:cloud`
- Forensicator: `qwen3-coder-next:cloud`
- Critic: `qwen3.5:cloud`

**Local profile (no internet required during investigation, ~40 GB models):**

```bash
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull deepseek-r1:32b       # Manager
ollama pull qwen2.5-coder:14b     # Forensicator
ollama pull qwen2.5:14b           # Critic
```

---

## Step 3 — Configure `.env`

```bash
cp .env.example .env
```

Edit `.env` to set your values:

```bash
# Cloud profile (Ollama Cloud via local service)
OLLAMA_URL=http://localhost:11434
GEOFF_PROFILE=cloud
GEOFF_EVIDENCE_PATH=/mnt/evidence
GEOFF_CASES_PATH=/mnt/cases
# No OLLAMA_API_KEY needed — use `ollama signin` to authenticate

# Optional: require API key on HTTP endpoints
# GEOFF_API_KEY=your-secret-key

# Or local profile (GPU models)
# OLLAMA_URL=http://localhost:11434
# GEOFF_PROFILE=local
# GEOFF_EVIDENCE_PATH=/mnt/evidence
# GEOFF_CASES_PATH=/mnt/cases
# GEOFF_WORK_DIR=/tmp/geoff-cases
# GEOFF_LOG_LEVEL=INFO
```

---

## Step 4 — Download the datasets

### NIST CFReDS — M57-Jean-Real

```bash
# Download from NIST CFReDS
mkdir -p /mnt/evidence/jeanm57
cd /mnt/evidence/jeanm57
# Visit https://cfreds.nist.gov/all/NIST/m57-jean for the current download link
# Files: nps-2008-jean.E01, nps-2008-jean.E02 (~8 GB total)
```

### NIST CFReDS — Data Leakage Case

```bash
mkdir -p /mnt/evidence/data-leakage-case
cd /mnt/evidence/data-leakage-case
# Visit https://cfreds.nist.gov/all/NIST/DataLeakageCase
# Files: cfreds_2015_data_leakage_pc.E01-E04, cfreds_2015_data_leakage_rm#1.E01, rm#2 (~15 GB)
```

### NIST CFReDS — Hacking Case

```bash
mkdir -p /mnt/evidence/hacking-case
cd /mnt/evidence/hacking-case
# Visit https://cfreds.nist.gov/all/NIST/HackingCase
# Files: 4Dell_Latitude_CPi.E01, SCHARDT.LOG (~4 GB)
```

---

## Step 5 — Run against each dataset

### Pre-run spoliation baseline

Before running, record the evidence SHA-256 baseline:

```bash
# Install hashdeep if not present
sudo apt-get install -y hashdeep

# Record baseline (run once before investigation)
hashdeep -rl /mnt/evidence/jeanm57 > /tmp/jeanm57_before.hash
```

### Run M57-Jean-Real

```bash
export GEOFF_WORK_DIR=/tmp/geoff-cases

geoff-find-evil /mnt/evidence/jeanm57 \
    --agent-trace \
    --show-agents \
    2>&1 | tee /tmp/jeanm57_run.log
```

**Expected output sequence:**
```
[Manager] Reviewing triage output...
[Manager] approved_execution_plan: ["PB-SIFT-001", "PB-SIFT-002", ...]
[Forensicator] PB-SIFT-001: sleuthkit.list_files — nps-2008-jean.E01
[Critic A] step verdict: ACCEPTABLE
[Critic B] step verdict: ACCEPTABLE
[Pool] Confidence: VERY_HIGH
[Forensicator] PB-SIFT-001: sleuthkit.list_files — nps-2008-jean.E02
...
[Healer] self_correction on PB-SIFT-010: fls_auto fails → fls_offset0 retry
...
[Critic] batch assessment: GOOD / 0 hallucination flags
[Manager] decision: approve
Narrative report written to: /tmp/geoff-cases/jeanm57_findevil_<id>/reports/narrative_report.md
```

**Expected artifacts:**

```bash
CASE_DIR=$(ls -td /tmp/geoff-cases/jeanm57_*/ | head -1)
ls $CASE_DIR
# Expected:
#   audit_trail.jsonl  (state transitions)
#   agent_trace.jsonl  (per-event prompt/response excerpts)
#   findings.jsonl     (~25 lines)
#   batch_critic_assessment.json
#   manager_decision.json
#   provenance_dag.json  (evidence derivation graph)
#   confidence_scores.json  (dual-critic agreement scores)
#   custody/           (~24 JSON sidecars)
#   reports/narrative_report.md
wc -l $CASE_DIR/findings.jsonl
# Expected: ~25 lines
```

### Post-run spoliation check

```bash
hashdeep -rl /mnt/evidence/jeanm57 > /tmp/jeanm57_after.hash
diff /tmp/jeanm57_before.hash /tmp/jeanm57_after.hash
# Expected: no differences (evidence unmodified)
```

### Run Data Leakage Case

```bash
hashdeep -rl /mnt/evidence/data-leakage-case > /tmp/dlc_before.hash

geoff-find-evil /mnt/evidence/data-leakage-case \
    --agent-trace \
    --show-agents \
    2>&1 | tee /tmp/dlc_run.log

hashdeep -rl /mnt/evidence/data-leakage-case > /tmp/dlc_after.hash
diff /tmp/dlc_before.hash /tmp/dlc_after.hash
# Expected: no differences
```

**Expected artifacts:** ~34 findings, 3 devices discovered (cfreds_2015_data_leakage_pc, rm#1, rm#2).

### Run Hacking Case

```bash
hashdeep -rl /mnt/evidence/hacking-case > /tmp/hacking_before.hash

geoff-find-evil /mnt/evidence/hacking-case \
    --agent-trace \
    --show-agents \
    2>&1 | tee /tmp/hacking_run.log

hashdeep -rl /mnt/evidence/hacking-case > /tmp/hacking_after.hash
diff /tmp/hacking_before.hash /tmp/hacking_after.hash
```

**Expected note:** The Hacking Case uses a Windows 98 FAT16 image. Expect 14–15 step failures
for playbooks that require NTFS artifacts (MFT, Registry hives at modern paths, VSS). These are
expected failures — the Healer handles them and marks the steps as `not_applicable` rather than
propagating errors. The investigation still completes with file triage, log analysis, and
malware detection steps.

---

## Step 6 — Verify findings match

After each run, verify the expected artifacts are present and populated:

```bash
python3 - <<'EOF'
import json, os, sys

CASE_DIR = sorted([f for f in os.listdir('/tmp/geoff-cases') 
                   if 'jeanm57' in f], reverse=True)[0]
path = f'/tmp/geoff-cases/{CASE_DIR}'

print(f"Case directory: {path}")

# Required artifacts
required = ['findings.jsonl', 'audit_trail.jsonl', 'agent_trace.jsonl',
            'batch_critic_assessment.json', 'manager_decision.json',
            'provenance_dag.json', 'confidence_scores.json']
for f in required:
    fpath = f'{path}/{f}'
    if os.path.exists(fpath):
        size = os.path.getsize(fpath)
        print(f"PASS: {f} ({size:,} bytes)")
    else:
        print(f"FAIL: {f} missing")

# Custody sidecars
custody = os.listdir(f'{path}/custody') if os.path.exists(f'{path}/custody') else []
print(f"Custody sidecars: {len(custody)} files")

# Narrative report
rpt = f'{path}/reports/narrative_report.md'
if os.path.exists(rpt):
    words = len(open(rpt).read().split())
    print(f"PASS: narrative_report.md ({words} words)")
else:
    print("FAIL: narrative_report.md missing")

# Verify JSON/JSONL integrity
for f in ['findings.jsonl', 'audit_trail.jsonl']:
    errors = 0
    with open(f'{path}/{f}') as fh:
        for i, line in enumerate(fh, 1):
            if line.strip():
                try: json.loads(line)
                except: errors += 1
    print(f"JSON valid: {f} — {errors} errors")
EOF
```

---

## Step 7 — Checkpoint resume test

To verify checkpoint/resume works:

```bash
# Start a run and interrupt it
geoff-find-evil /mnt/evidence/jeanm57 &
PID=$!
sleep 30
kill -INT $PID   # Ctrl-C equivalent

# Re-run the same command
geoff-find-evil /mnt/evidence/jeanm57 --agent-trace --show-agents

# Verify it resumed rather than restarting
# The output should say "resuming from checkpoint" or skip already-completed steps
grep "resume\|checkpoint\|already completed" /tmp/geoff-cases/jeanm57*/audit_trail.jsonl
```

---

## Step 8 — Verify new features

### Provenance DAG

After any run, check the evidence derivation graph:

```bash
jq . /tmp/geoff-cases/*/provenance_dag.json | less
# Should contain nodes for source evidence + derived artifacts
```

### Confidence Scores

```bash
jq . /tmp/geoff-cases/*/confidence_scores.json
# Should show per-finding confidence levels (VERY_HIGH, HIGH, MEDIUM, LOW)
```

### IP Map

```bash
# Start the web server and navigate to the IP map:
python src/geoff_integrated.py
# Open: http://localhost:8080/reports/<case-dir>/ip-map
# Or fetch the JSON:
curl http://localhost:8080/reports/<case-dir>/ip-map | jq '.nodes | length'
```

### YARA Scanning

If the evidence set contains disk images, PB-SIFT-051 (YARA Scanning) runs automatically.
Check for YARA matches in the findings:

```bash
jq 'select(.step_key | contains("yara"))' /tmp/geoff-cases/*/findings.jsonl
```

### Hash Correlation + NSRL

PB-SIFT-052 hashes files and looks up SHA-1 in the NSRL database.
Check hash findings:

```bash
jq 'select(.step_key | contains("hash"))' /tmp/geoff-cases/*/findings.jsonl
```

### MITRE Matrix

```bash
# After running the web server:
curl http://localhost:8080/reports/mitre-matrix
# Interactive HTML matrix mapping all findings to ATT&CK techniques
```

---

## Known Issues and Expected Failures

| Issue | Dataset | Resolution |
|-------|---------|-----------|
| `fls_auto` fails on EWF partition offset | M57-Jean-Real, Data Leakage | Expected — Healer falls back to `fls_offset0`, then `mmls_probe`. Investigation continues. |
| NTFS-specific steps fail on FAT16 image | Hacking Case | Expected — Windows 98 image does not have MFT/Registry paths modern playbooks expect. Marked `not_applicable`. |
| Tool not installed: `iLEAPP`, `foremost`, `yara`, etc. | All | Expected on first run — Healer installs via apt-get and retries. Requires internet. |
| `playbook_run` count appears lower than expected | All | Playbooks with zero applicable steps are counted as "run" with 0 steps. This is correct. |
| Anti-forensics cascade downgrades findings | M57-Jean-Real, Hacking Case | Expected and correct — PB-SIFT-012 detected anti-forensics indicators; all findings retroactively marked POSSIBLE. |
| YARA reports `yara binary not found` | All (first run) | Self-heal installs `yara` via `apt-get install -y yara` and retries. |
| NSRL lookup returns no results | All | Expected if no NSRL database is configured. The HASH_Specialist logs the lookup attempt but continues. |

---

## Where to Find Results

After a successful run:

```bash
CASE_DIR=$(ls -td /tmp/geoff-cases/*/ | head -1)

# Narrative report (human-readable)
cat $CASE_DIR/reports/narrative_report.md

# Structured findings
cat $CASE_DIR/findings.jsonl | python3 -c "
import sys,json
for l in sys.stdin:
    if l.strip():
        d = json.loads(l)
        if d.get('status') == 'completed':
            print(d.get('step_key',''), '|', d.get('significance',''), '|', 
                  str(d.get('analyst_note',''))[:60])
"

# Manager decision
cat $CASE_DIR/manager_decision.json | python3 -m json.tool

# Critic assessment
cat $CASE_DIR/batch_critic_assessment.json | python3 -m json.tool

# Provenance DAG (evidence derivation)
cat $CASE_DIR/provenance_dag.json | python3 -m json.tool

# Confidence scores
cat $CASE_DIR/confidence_scores.json | python3 -m json.tool

# Agent trace (requires --agent-trace flag)
head -5 $CASE_DIR/agent_trace.jsonl | python3 -c "
import sys,json
for l in sys.stdin:
    if l.strip():
        d = json.loads(l)
        print(d.get('timestamp','')[:19], d.get('agent',''), d.get('event_type',''))
"
```