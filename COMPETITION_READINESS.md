# GEOFF Competition Readiness Assessment

**Date:** 2026-06-01  
**Repo:** github.com/legacyboy/Geoff (public)  
**Assessor:** Claude Sonnet 4.6  
**Branch assessed:** main (HEAD `afb74cb`)

---

## Readiness Matrix

| # | Deliverable | Status | Gap |
|---|-------------|--------|-----|
| 1 | Code Repository | 🟡 YELLOW | API key in git history; internal dev files in HEAD; uncommitted changes to 7 core files |
| 2 | Demo Video | 🔴 RED | Does not exist; evidence exists on NAS but no recorded demo |
| 3 | Architecture Diagram | 🟡 YELLOW | Exists in README/docs as text/ASCII; no standalone visual artifact (PNG/PDF) |
| 4 | Written Project Description (Devpost) | 🔴 RED | Does not exist; no challenges/learnings/next-steps narrative |
| 5 | Dataset Documentation | 🟡 YELLOW | M57-Patents run documented in issues/; chain of custody and reproducibility instructions missing |
| 6 | Accuracy Report | 🟡 YELLOW | Detailed audit exists in HEAD (COMBINED_AUDIT_REPORT.md) but not judge-formatted; critic FP cases documented |
| 7 | Try-It-Out Instructions | 🟡 YELLOW | README Quick Start is solid; missing `.env.example`; installer has documented tool gaps |
| 8 | Agent Execution Logs | 🔴 RED | Protocol documented but no sample logs (findings.jsonl, agent_trace.jsonl, batch_critic_assessment.json) checked into repo |

---

## Detailed Assessment

---

### 1. Code Repository — 🟡 YELLOW

**Current state:**

- README (53 KB): Excellent. Covers architecture, three-agent design, all 25+ playbooks, SIFT compatibility table, Quick Start, REST API, MCP server, security, and reproducibility. Professionally written.
- License: Apache 2.0 at `LICENSE` — correctly referenced at top of README. ✅
- Installation instructions: Present and comprehensive (`install.sh` + Manual Setup section). ✅
- SIFT workstation: Extensively documented with per-tool compatibility table and Volatility3 workaround note. ✅
- `requirements.txt`: Present (Flask, GitPython, MCP, dotenv, etc.). ✅
- `docs/AGENT_PROTOCOL.md`: Full JSON schema spec for all four agent roles. ✅

**Gaps:**

1. **API key in git history — CRITICAL SECURITY ISSUE.** The `.env` file containing `OLLAMA_API_KEY=7be76563b7a04e93989180aa36aa6504.UscdScTsKD5tNfd1EAd_0_uN` was committed in at least two historical commits (`0b5322c`, and earlier). Commit `8660bcbc` (2026-05-22) acknowledged this and said "Rotate the OLLAMA_API_KEY immediately," but the identical key value is STILL present in the local `.env` today (2026-06-01). Since the repo is **public**, the key is visible to anyone with `git log -p`. Either (a) the key was never rotated and is still live — a credentials leak — or (b) it was rotated but the same key string was put back into `.env`. Either way, this needs to be confirmed and resolved before submission.

2. **Internal development files tracked in git HEAD.** Running `git show HEAD` would reveal these files to anyone who clones the repo: `CLAUDE_REVIEW.md`, `COMBINED_AUDIT_REPORT.md`, `DESIGN_FIXES.md`, `EVIDENCE_AUDIT.md`, `EVIDENCE_AUDIT_CLAUDE.md`, `FIX_PLAN_31_failures.md`, `GEOFF_SYSTEMIC_AUDIT.md`, `IMPLEMENTATION_PLAN.md`, `IMPLEMENTATION_PLAN_QWEN.md`, `QA_RESULTS.md`, `SELF_HEAL_INVESTIGATION.md`, `TEST_RESULTS_ARCH_PIVOT.md`, `VALIDATION_REPORT.md`, `par_loop.md`. These are internal development/audit artifacts. Judges will see them. They reveal offset detection failures, design pivots, and QA regressions — legitimate work, but unfiltered. They're deleted locally but still in HEAD; a `git rm` commit is needed.

3. **7 core source files modified but not committed.** `git status` shows `src/geoff_pipeline.py`, `src/geoff_routes.py`, `src/geoff_templates.py`, `src/geoff_utils.py`, `src/pipeline_phases.py`, `src/sift_specialists_extended.py`, `src/super_timeline.py`, `static/index.html`, `static/main.js`, `static/tokens.css` all modified. If a judge clones the repo they get different code than what's running locally. This is a credibility issue.

4. **No `.env.example`.** The `8660bcbc` commit message said to add one, but it was never created. A new user cloning the repo has no guidance on what environment variables are required.

5. **Backup files in working tree** (`src/geoff_routes.py.current`, `src/geoff_templates.py.current`, `static/main.js.current`). These are untracked and won't appear in the repo, but the working tree is messy.

6. **`node_modules/` directory** (54 subdirectories) is in the working tree. `node_modules` should be gitignored. Check whether it's tracked.

**Minimum work to go GREEN:**
- Confirm API key is rotated (contact Ollama API provider or invalidate at their console)
- `git rm` all internal dev files from HEAD; commit as a cleanup
- Commit the 7 modified source files (or explicitly document why they're diverged)
- Create `.env.example` with placeholder values and document required variables

---

### 2. Demo Video — 🔴 RED

**Current state:**

No demo video exists anywhere in the repo or documentation. There is no `demo/` directory, no link to a video, no screen recording.

**What evidence and infrastructure exists for demo:**

- M57-Patents: 86 disk images on NAS (`/mnt/nas-multimedia/evidence`). A run was confirmed in `issues/m57_findevil_glm_audit.md` (2026-05-27): 158 MB findings.jsonl, 210 findings, 133 validation files, running through PB-SIFT-001. This is a real, live case.
- `scripts/check_m57_downloads.py` + `scripts/monitor_m57.sh` — tooling for the M57 run already exists.
- Self-correction is demonstrated: the `issues/m57_findevil_glm_audit.md` shows `sleuthkit.list_files: fls_auto fails → fls_offset0 fails → mmls_probe succeeds` — the designed fail-forward chain firing on real evidence. The Phase 1 Critic rejection for hallucination (claiming file paths were "Offsets") is also documented.
- Checkpoint/resume: supported in code and testable.
- The `--agent-trace --show-agents` CLI flags produce color-coded per-agent output — visually compelling for a demo.

**Suggested 5-minute demo script:**

```
0:00-0:30  Setup: "This is Geoff on SIFT workstation, M57-Patents case"
           Show: ls /mnt/nas-multimedia/evidence (real NAS-mounted evidence)

0:30-1:30  Start investigation: geoff-find-evil /mnt/nas-multimedia/evidence/m57-patents --agent-trace --show-agents
           Show: Manager planning output, Triage PB-SIFT-000 classifying evidence,
           [Manager] approved_execution_plan printed to terminal

1:30-2:30  Self-correction in action:
           Show a run where fls_auto fails → Healer fires → retry_with_offset succeeds
           Narrate: "No human intervention — Critic diagnoses the EWF offset, Healer patches params and retries"

2:30-3:30  Checkpoint resume:
           Kill the job mid-run (Ctrl-C). Re-run same command. Show it resumes at the last completed step.
           Narrate: "Git-backed state — every completed step is a commit, so interruptions don't lose work"

3:30-4:30  Batch Critic review:
           Show batch_critic_assessment.json after completion — hallucination_flags, replay_candidates
           Show manager_decision.json — approve/flag/replay decision

4:30-5:00  Output:
           Show narrative_report.md excerpt — attack chain synthesis with artifact citations
```

**Minimum work to go GREEN:**
- Record the 5-minute demo (screen capture of terminal + web UI on SIFT workstation VM)
- Requires: confirmed working run against M57-Patents or smaller known-good evidence set; `--agent-trace` flag tested; narrative_report.md generated

---

### 3. Architecture Diagram — 🟡 YELLOW

**Current state:**

- README contains an ASCII block diagram showing the six-component layout (Device Discovery, Behavioral Analyzer, Super Timeline, Host Correlator, Narrative Report Gen, Extended Orchestrator). Adequate for a technical reader.
- `docs/AGENT_PROTOCOL.md` contains a full state machine diagram (text-based) showing every agent transition and the artifact written at each step. This is the best architecture documentation in the repo.
- `COMPETITION_COMPLIANCE.md` maps each competition rule to exact code file + line number.

**What's documented:**
- Pattern: **multi-agent orchestrator pipeline** — Manager plans, Forensicator executes, Critic validates, Healer recovers. Not ambiguous.
- Security boundaries: MCP server binds `127.0.0.1:9999` only (network is the auth layer); evidence path validation strips shell metacharacters; `GEOFF_API_KEY` for API auth. Documented in README Security section.
- Prompt-based vs. architectural guardrails: **partially distinguished.** The README notes evidence path validation is code-enforced (architectural). The Forensicator's prohibition on speculation is prompt-enforced (GEOFF_PROMPT). But no single document draws this distinction explicitly for a judge.

**Gaps:**

1. **No visual architecture diagram** (PNG/PDF/SVG). Judges expecting a diagram to include in a Devpost submission will find only ASCII art. Mermaid or draw.io export would significantly improve this.

2. **Security boundary distinction not explicit.** Prompt-based guardrails (Forensicator system prompt, GEOFF_PROMPT citation requirements) vs. code-enforced guardrails (path validation, API auth, 127.0.0.1 bind) are not called out side-by-side anywhere. This matters for accuracy questions about whether the evidence integrity guarantees are enforceable.

3. **Evidence read-only enforcement.** The README states paths are validated before use. But there is no architectural read-only mount of the evidence directory — the tool can technically write to evidence paths if a tool invocation is misconfigured. Custody sidecars verify evidence SHA-256 *after* analysis, which detects modification but doesn't prevent it. This gap should be disclosed rather than left implicit.

**Minimum work to go GREEN:**
- Export the `docs/AGENT_PROTOCOL.md` state machine as a visual diagram (Mermaid renders on GitHub, or a single draw.io file)
- Add a one-paragraph "Guardrails" section distinguishing prompt-enforced from code-enforced constraints

---

### 4. Written Project Description (Devpost) — 🔴 RED

**Current state:**

Does not exist. No Devpost draft, no structured project narrative.

**What needs to be written:**

A Devpost-format submission typically requires:

| Section | Content needed | Source material available |
|---------|---------------|--------------------------|
| **What it does** | Multi-agent autonomous DFIR platform | README §What is GEOFF + §Find Evil |
| **How we built it** | Three-agent triad, Ollama backend, SIFT toolchain, git custody | README §Agentic Framework, COMPETITION_COMPLIANCE.md |
| **Challenges we ran into** | Offset detection cascade (two competing code paths, ewfmount resource leaks), checkpoint caching masking wrong offsets | GEOFF_SYSTEMIC_AUDIT.md (in HEAD), COMBINED_AUDIT_REPORT.md (in HEAD) |
| **Accomplishments we're proud of** | Batch Critic holistic review, device-centric model, per-step git custody | README §Novel Contribution |
| **What we learned** | Mount-then-walk fragility; prompt-based self-critique misses cross-step inconsistencies without dedicated Critic | COMBINED_AUDIT_REPORT.md |
| **What's next** | Unified offset detection, real PB-004/PB-011/PB-013 content, cloud IR playbook | SANS-PLAYBOOK-GAP-ANALYSIS.md |

**Design decisions to address:**
- Why Ollama instead of Anthropic (portability: runs local on SIFT, no key required)
- Why batch Critic instead of per-step (cross-step correlation, ~3x LLM call reduction)
- Why git instead of a database for case state (reproducibility, tamper detection, standard forensic idiom)
- Autonomous execution: why no per-step human gate (competition requirement; the Manager gate at triage provides the only human checkpoint before batch execution begins)

**Minimum work to go GREEN:**
- Write the 6-section Devpost narrative (~800-1200 words) — this is a day's work but all source material exists in the repo

---

### 5. Dataset Documentation — 🟡 YELLOW

**Current state:**

- **M57-Patents:** Most thoroughly tested. `issues/m57_findevil_glm_audit.md` documents a real run (2026-05-27): 86 disk images, 210 findings, 158 MB findings.jsonl, 133 validation files. Source: NIST/Digital Corpora (public). Chain of custody: not documented in submission materials.
- **Data Leakage:** Mentioned in `QA_RESULTS.md` batch 1 as a completed job, but result fields are empty (the QA report shows blank Result fields for most Data Leakage checks), suggesting incomplete run or empty output.
- **APT 2015:** Referenced in `GEOFF_EVIDENCE_PATH=/mnt/nas-multimedia/evidence` NAS path, but no documented investigation output.
- `scripts/check_m57_downloads.py` and `scripts/monitor_m57.sh` provide infrastructure to re-run M57.

**Gaps:**

1. **No dataset README or `datasets/` directory** — a judge cannot verify which datasets were used, where to download them, or how to configure Geoff to run against them.
2. **Chain of custody for test datasets not documented.** M57-Patents is NIST public domain data. This should be stated. Source URL, download date, and SHA-256 of the downloaded images should be recorded.
3. **What Geoff found in each dataset is not summarized.** The M57 audit documents the investigation infrastructure but not the forensic findings (what evil was found, which MITRE techniques, which Critic flags). The narrative report from the completed M57 run (if any) should be included.
4. **Reproducibility instructions for a judge.** A judge cannot replicate the M57 run without: (a) knowing where to download the evidence, (b) how to set `GEOFF_EVIDENCE_PATH`, (c) which command to run. This should be a single `docs/REPRODUCING_RESULTS.md` file.

**Minimum work to go GREEN:**
- Write `docs/DATASETS.md`: dataset name, source URL, SHA-256, what Geoff found, Critic assessment
- Write `docs/REPRODUCING_RESULTS.md`: step-by-step for a judge on SIFT workstation (download → mount → configure → run)
- Extract the M57 narrative report (if generated) and commit it to `docs/sample_reports/`

---

### 6. Accuracy Report — 🟡 YELLOW

**Current state:**

Two detailed internal audit reports exist in git HEAD (deleted locally, but visible to anyone who clones):

- `COMBINED_AUDIT_REPORT.md` (2026-05-24): identifies offset detection as CRITICAL, ewfmount resource leaks as CRITICAL, classification blind spots (other_files black hole), RAR never extracted, silent failures. Two independent agents (Claude Sonnet 4.6 + Qwen 3.5 397B) reached the same conclusions.
- `GEOFF_SYSTEMIC_AUDIT.md` (2026-05-24): detailed code-level analysis of the offset detection cascade, checkpoint caching masking errors, single-offset-per-image limitation.
- `issues/m57_findevil_glm_audit.md` (2026-05-27): Phase 1 Critic REJECTED the initial inventory analysis for hallucination ("claiming file paths were 'Offsets'") — this is a documented self-correction event with specifics.

**Specific items the assessment asked about:**

| Item | Finding |
|------|---------|
| Critic "nonsense" / "invalid_iocs" flags | Documented: m57 audit shows Critic rejected Phase 1 output for hallucination; `COMBINED_AUDIT_REPORT.md` cites "drop table" misclassified as SQL in host context |
| Missed artifacts (EVTX, memory, LOLBins) | SANS-PLAYBOOK-GAP-ANALYSIS.md Part 3 lists specific missing techniques (PowerShell 4104 multi-block reassembly, WMI OBJECTS.DATA, JA3/JA3S, LOLBin obfuscation decoding) |
| Hallucinated claims | Critic caught: "claiming file paths were Offsets" on M57 run; "drop table" as SQL in host context in COMBINED_AUDIT |
| Evidence integrity approach | SHA-256 custody sidecars per step (architectural). Evidence path injection prevention via metacharacter stripping (architectural). Narrative citation requirement (prompt-enforced). |
| Prompt-based restrictions a model could ignore | YES — the narrative report's prohibition on speculating beyond evidence is prompt-enforced, not structurally enforced. A model that ignores the system prompt could hallucinate claims. No retry/rejection mechanism for this at report generation time (unlike chat, which has `_self_check_chat_response`). |
| Spoliation testing | NOT documented. Custody sidecars record SHA-256 of evidence at step time. Whether the SHA-256 was verified against a pre-investigation baseline is not documented. No evidence that evidence directories were verified as unmodified after a full run. |

**Gaps:**

1. **No judge-facing accuracy report.** The audit material is in internal dev notes. A judge needs a clean one-pager: what false positives were observed, what was missed, what was caught by self-correction, what the known limitations are.
2. **Spoliation testing not performed or documented.** Running `hashdeep -ra /evidence` before and after a Geoff investigation would demonstrate evidence integrity. This has not been done.
3. **Narrative generation self-check gap.** Chat responses are grounded-checked by `_self_check_chat_response`. Narrative reports are not. This asymmetry should be disclosed.

**Minimum work to go GREEN:**
- Write `docs/ACCURACY_REPORT.md`: one structured document covering FP rate, missed artifacts, hallucination incidents (with specific examples), evidence integrity approach and its limits, known gaps
- Run a hashdeep pre/post check on a test evidence set and document the result

---

### 7. Try-It-Out Instructions — 🟡 YELLOW

**Current state:**

README Quick Start section is good:
```bash
curl -sSL https://raw.githubusercontent.com/legacyboy/Geoff/main/install.sh | bash
```
Four entry points documented (CLI, Web UI, Console, MCP). Manual setup environment variables listed. Model profiles (cloud vs. local) documented.

**Gaps:**

1. **No `.env.example`.** Commit `8660bcbc` said to create one. It doesn't exist. A judge cloning the repo sees `.env` in `.gitignore` with no template showing what variables are required or what values to use. They must read `docs/AGENT_PROTOCOL.md §8` or the README Manual Setup section to find env var names.

2. **Installer tool gaps (documented, not fixed).** `docs/SANS-PLAYBOOK-GAP-ANALYSIS.md Part 2` identifies 20+ tools referenced by playbooks that the installer never installs: `iLEAPP`, `ALEAPP`, `foremost`, `scalpel`, `zeek`, `tcpflow`, `libbde-utils`, `readpst`, `libguestfs-tools`, `qemu-utils`, `apfs-fuse`, `plyvel`, `pefile`, `python-magic`, `lief`, `WxTCmd`, `RecentFileCacheParser`, `RBCmd`, `SQLECmd`, `dive`. A judge running a full investigation will hit self-heal events or silent failures for any playbook that calls these tools.

3. **Playbook content mismatches (documented, not fixed).** `docs/SANS-PLAYBOOK-GAP-ANALYSIS.md Part 1` identifies three playbooks with wrong content:
   - PB-004 (labeled Privilege Escalation) actually contains network device forensics
   - PB-011 (labeled Web Shell Detection) actually contains insider threat
   - PB-013 (labeled Insider Threat) actually contains cloud/SaaS artifacts
   A judge running a web shell investigation will get insider threat analysis.

4. **`test_install.sh` deleted locally but tracked in HEAD.** The smoke test script is gone from the working tree. Whether the installer actually passes CI is unknown.

5. **No SIFT workstation VM image or verified baseline.** The instructions assume a SIFT workstation but don't direct the judge to the SIFT download or state which SIFT version was tested (2026.03.24 is referenced in passing).

**Minimum work to go GREEN:**
- Create `.env.example` with placeholder values for all 7 required env vars
- Add a note in Quick Start about the three mislabeled playbooks (PB-004/011/013) so a judge isn't confused by unexpected output
- Either fix the installer tool gaps (20 lines of `apt-get install -y`) or document them clearly as "known gaps, self-heal will install on demand"
- Restore or rewrite `test_install.sh`

---

### 8. Agent Execution Logs — 🔴 RED

**Current state:**

The logging infrastructure is thoroughly designed and documented:
- `audit_trail.jsonl` — state transitions with timestamps
- `agent_trace.jsonl` — produced by `--agent-trace` flag, contains per-agent prompt/response excerpts
- `batch_critic_assessment.json` — post-execution Critic review
- `manager_decision.json` — Manager approve/flag/replay decision
- `findings.jsonl` — per-step Forensicator observations + Critic verdicts
- `custody/<step_key>.json` — SHA-256 chain of custody
- `validations/<step_key>.json` — per-step Critic verdicts

**Gaps:**

1. **Zero sample logs in the repository.** There are no example files showing what these look like with real data. A judge reading the README must trust the documentation rather than verify it against actual output.

2. **The M57-Patents run produced real output** (`/mnt/evidence-storage-2/m57-patents_findevil_a36d505e8542/` on the NAS, 158 MB findings.jsonl), but none of it is captured in the repo.

3. **`agent_trace.jsonl` has never been demonstrated.** The `--agent-trace --show-agents` flag is documented in `COMPETITION_COMPLIANCE.md §Demonstration` but no sample trace is available to verify it actually works and produces the claimed output.

4. **No timestamps or token usage in sample logs.** The protocol spec documents these fields but their presence in real output is unverified.

5. **Traceability chain is unverified end-to-end.** The claim that "findings can be traced back to specific tool executions" is well-documented architecturally but no sample `custody/` sidecar paired with a `findings.jsonl` record is provided.

**Minimum work to go GREEN:**
- Run `geoff-find-evil` with `--agent-trace --show-agents` on a small evidence set (the Data Leakage case, or a synthetic test)
- Commit sanitized sample output to `docs/sample_logs/`: one `agent_trace.jsonl` excerpt, one `batch_critic_assessment.json`, one `manager_decision.json`, one `custody/<step_key>.json` paired with its `findings.jsonl` record, one `audit_trail.jsonl`
- These can be from a synthetic/toy evidence set if NAS evidence can't be redistributed

---

## Priority Ranking

Work prioritized by: (1) disqualification risk, (2) judging rubric weight, (3) effort.

| Priority | Item | Effort | Risk if skipped |
|----------|------|--------|----------------|
| **P1** | Confirm API key rotated; clean git history scan | 2 hours | Security disqualification; credential leak |
| **P2** | Commit the 7 modified source files (or create a "release" tag at clean commit) | 1 hour | Judge clones different code than what's running |
| **P3** | Write Devpost project description | 1 day | Required deliverable; no submission without it |
| **P4** | Record 5-minute demo video | 1-2 days | Demo is a required deliverable; highest judging visibility |
| **P5** | Commit sample agent execution logs | 2-4 hours | Audit trail claims unverifiable without examples |
| **P6** | Create `.env.example` | 30 min | Judge cannot run without knowing required vars |
| **P7** | `git rm` internal dev files from HEAD | 1 hour | Messy; reveals internal failures but not disqualifying |
| **P8** | Write `docs/ACCURACY_REPORT.md` | 4-6 hours | Judge needs structured accuracy assessment |
| **P9** | Write `docs/DATASETS.md` + `docs/REPRODUCING_RESULTS.md` | 3-4 hours | Reproducibility is a scoring criterion |
| **P10** | Export architecture state machine as Mermaid/visual | 2-3 hours | Helpful but ASCII diagram in AGENT_PROTOCOL.md is adequate |
| **P11** | Fix PB-004/011/013 content mismatches | 2-3 days | Correctness issue but labeled in gap analysis already |
| **P12** | Fix installer tool gaps | 4-8 hours | Self-heal partially covers this; not a blocker |

---

## Key Risks

### Risk 1 — API key in git history (CRITICAL)
The `OLLAMA_API_KEY` value `7be76563b7a04e93989180aa36aa6504.UscdScTsKD5tNfd1EAd_0_uN` appears in commits `0b5322c` and the diff to `8660bcbc`. The repo is public. Anyone running `git log -p` can extract this key. The local `.env` has the same value today, suggesting the key was never rotated despite the commit message saying to do so. **Action required: confirm with Ollama provider whether this key is valid; if yes, rotate it immediately and optionally clean git history with `git filter-repo`.**

### Risk 2 — No demo video
The competition likely requires a demo. Without one, the submission is a code drop with documentation. Evidence and infrastructure for a compelling demo exist (M57-Patents case, real self-correction events documented, `--agent-trace` flag). This is a time-bounded risk — feasible to fix but requires a working SIFT workstation session.

### Risk 3 — Uncommitted working tree divergence
Core files (`geoff_pipeline.py`, `geoff_routes.py`, `geoff_templates.py`, and 7 others) are modified locally but not committed. If judges evaluate the committed code and it differs from the running system, self-correction claims may not hold. A tag at a known-good working state would eliminate this risk.

### Risk 4 — Playbook label mismatches
PB-004 (Privilege Escalation) contains network device forensics content; PB-011 (Web Shell) contains insider threat; PB-013 (Insider Threat) contains cloud artifacts. A judge running a web shell or privilege escalation scenario will observe behavior misaligned with the playbook label. This is documented in `docs/SANS-PLAYBOOK-GAP-ANALYSIS.md` but not fixed. Recommend either fixing the three playbooks or prominently noting the limitation in README Known Issues.

### Risk 5 — Evidence integrity claims partially prompt-enforced
The narrative report's prohibition on speculation beyond verified evidence is enforced only in the system prompt — a model that ignores instructions can still hallucinate claims in the report. Unlike chat responses (which have `_self_check_chat_response` regeneration), narrative generation has no structural backstop. If a judge probes accuracy claims, this asymmetry may surface. Recommend disclosing it in the accuracy report and/or extending the self-check to narrative generation.

### Risk 6 — Installer tool gaps
20+ tools referenced by playbooks are not installed by `install.sh`. On a clean SIFT workstation, playbooks calling `iLEAPP`, `ALEAPP`, `foremost`, `zeek`, `readpst`, and 15+ others will fail on first invocation. The self-heal fast-path handles `tool_missing` deterministically (`apt-get install -y <tool>`), so most will auto-install and retry. But this adds latency and requires internet access during the investigation. If the demo environment is air-gapped, this could stall.

---

## What's Already Strong (Don't Change)

- **README quality** — among the best project documentation seen. Comprehensive, accurate, well-structured. Do not simplify or shorten it.
- **COMPETITION_COMPLIANCE.md** — every competition rule mapped to exact code file + line number. This is exactly what judges need.
- **AGENT_PROTOCOL.md** — full JSON schema spec, state machine, failure modes for all four agents. Strong technical credibility.
- **Novel contribution section** — eight clearly differentiated contributions, each with a one-paragraph justification. This is the core of the Devpost "how we built it" section.
- **Git-backed custody architecture** — the per-step commit + SHA-256 sidecar design is genuinely novel for DFIR tooling and well-explained.
- **25+ playbooks** — coverage breadth is a real strength even with the content mismatches in 3 of 25.
