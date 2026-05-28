# Agentic Defense Plan — Protocol SIFT Competition Alignment

**Audience:** an implementing agent picking up this work cold.
**Branch:** `claude/fervent-cray-GWs6Y` (already current).
**Do not merge to `main`.** Push commits to the branch above. The owner will open a PR.

---

## 1. Background and stance

Geoff is being entered in a competition with this requirement:

> *"Entrants must submit a working software application that extends Protocol SIFT's autonomous incident response capability using an agentic framework as the primary execution engine. Claude Code and OpenClaw are the preferred frameworks, **though comparable agentic architectures are permitted**. ... Projects must run on or integrate with the SANS SIFT Workstation using Claude Code or OpenClaw as the agentic framework."*

We are **not** wrapping Geoff in Claude Code or OpenClaw. We are defending Geoff's existing Manager / Forensicator / Critic loop as a **comparable agentic architecture** under the softening clause.

The owner's three judging criteria the project must demonstrate:

1. **Self-correction** — the agent detects and resolves errors or inconsistencies in its own output without human intervention.
2. **Accuracy validation** — all findings are traceable to specific artifacts, files, offsets, or log entries.
3. **Analytical reasoning** — output is presented as a structured investigative narrative, not a raw execution log.

Geoff already satisfies all three. The work in this plan is **making the agentic claim explicit, named, defensible, and visible** — not rebuilding anything.

### Hard constraints

- **Do not** add Claude Code, OpenClaw, Anthropic SDK, or OpenAI SDK as a runtime dependency. The execution engine stays as-is.
- **Do not** rename `Manager`/`Forensicator`/`Critic` or refactor `geoff_pipeline.py`, `geoff_self_heal.py`, `geoff_critic.py`, or `narrative_report.py`. These are the defense's evidence — leave the code alone except where Track 3 explicitly says to edit.
- **Do not** create new abstractions, helper modules, or refactors not listed here.
- **Do not** post a PR. Commit and push only.
- **Do not** invent capabilities that don't exist. Every claim added to a document must be backed by a concrete `file:line` citation that you have verified by reading the file. If you cannot cite it, do not claim it.

### What counts as success

A judge reading the repo cold can, within five minutes:
- Find the section that names the agentic framework and describes it.
- Find a `COMPETITION_COMPLIANCE.md` that maps each rule to a code location.
- Find a `docs/AGENT_PROTOCOL.md` that documents the agent contract.
- Run `geoff-find-evil <path> --agent-trace` and see the agent loop reasoning, not just a tool log.
- Search the repo for "OpenClaw" and get **zero hits** in active files.

---

## 2. Execution order

Do these in order. Each track is independently committable. Push after each track.

1. **Track A — Repository cleanup.** Remove dead OpenClaw references. ~1–2h.
2. **Track B — Competition compliance document.** New file at repo root. ~2–3h.
3. **Track C — Agentic Framework section in README.** Insert near top of README. ~3–4h.
4. **Track D — Agent protocol spec.** New file in `docs/`. ~4–6h.
5. **Track E — Runtime agent visibility.** Add `--agent-trace` and `--show-agents` flags. ~3–4h.

Total budget: ~2–3 focused days. If short on time, do A, B, C, E first; D can be lighter.

---

## 3. Track A — Repository cleanup

**Goal:** eliminate evidence that contradicts the "Geoff is a deliberate agentic architecture" claim. Right now `grep -rn OpenClaw` returns hits in installer docs and test scripts that describe a gateway architecture that does not exist in `src/`.

### A.1 Audit current OpenClaw references

Run:
```bash
grep -rn "OpenClaw\|openclaw\|\.openclaw\|claw@" /home/user/Geoff/ --exclude-dir=.git --exclude-dir=archive
```

You should see hits in (verify by reading each file before editing):
- `test_install.sh` — header comment "Designed to be run by OpenClaw cron every 30 min" and `/home/claw/.openclaw/workspace/...` paths.
- `VALIDATION_REPORT.md` — CI-5 finding mentions `/home/claw/.openclaw/workspace/geoff-private`.
- `installer/README.md` — entire file describes an OpenClaw gateway architecture.
- `installer/PROGRESS.md` — same.

The current `src/` codebase does **not** import or invoke OpenClaw. Confirm with:
```bash
grep -rn "openclaw\|OpenClaw\|claude-code\|Claude Code\|claude_code" /home/user/Geoff/src/
```
Expect zero matches. If you find matches, **stop and report** — the assumption underlying this plan is wrong.

### A.2 Move legacy installer to an archive subdirectory

The `installer/` directory documents a stale OpenClaw-based path. Do not delete (it may have historical value). Move and label it:

```bash
mkdir -p /home/user/Geoff/legacy
git -C /home/user/Geoff mv installer legacy/installer-pre-pivot
```

Then create `/home/user/Geoff/legacy/README.md` with this exact content:

```markdown
# Legacy Materials

Pre-pivot artifacts kept for historical reference only. **Not part of the current Geoff execution engine.**

- `installer-pre-pivot/` — early installer that wrapped an OpenClaw gateway. The current execution engine is the Geoff Triad Agent loop driven directly from `src/geoff_pipeline.py` and `src/geoff_self_heal.py`; install with the root-level `install.sh`.
```

### A.3 Rewrite `test_install.sh` header

Open `/home/user/Geoff/test_install.sh`. Read the first 15 lines. Replace the OpenClaw references with neutral wording. Specifically:

- Remove "Designed to be run by OpenClaw cron every 30 min" — replace with `# Designed to be run periodically (e.g. via cron) to verify install.sh on a clean SIFT base image`.
- Replace any `/home/claw/.openclaw/workspace/projects/Geoff` paths with `/home/sansforensics/geoff-install-test` or accept an `INSTALL_TEST_ROOT` env var.
- Replace any `/home/claw/.openclaw/workspace/Geoff` paths the same way.

Verify after editing:
```bash
grep -n "openclaw\|claw" /home/user/Geoff/test_install.sh
```
Should be empty.

### A.4 Patch `VALIDATION_REPORT.md`

Open `/home/user/Geoff/VALIDATION_REPORT.md`. Find the CI-5 finding (line ~104). Rewrite it to drop the `/home/claw/.openclaw/workspace/geoff-private` path reference. The finding itself (hardcoded base_path in `geoff_critic.py::commit_validation()`) may still be valid — keep the finding but use a generic path example.

Verify after editing:
```bash
grep -n "openclaw\|/home/claw" /home/user/Geoff/VALIDATION_REPORT.md
```
Should be empty.

### A.5 Final audit

```bash
grep -rn "OpenClaw\|openclaw" /home/user/Geoff/ --exclude-dir=.git --exclude-dir=legacy
```
Expect zero matches. The only place "OpenClaw" should appear in the repository after Track A is inside `legacy/`.

### A.6 Commit

```
chore: archive OpenClaw-era installer + scrub stale framework references

The current execution engine is the Geoff Triad agent loop (Manager /
Forensicator / Critic) in src/. The installer/ directory and a few
script/doc headers still referenced an early OpenClaw gateway design
that was never wired into src/. Moved installer/ to legacy/ and
removed stale references from test_install.sh and VALIDATION_REPORT.md.
```

---

## 4. Track B — Competition compliance document

**Goal:** give judges a single page that maps each competition rule to a code location they can verify.

### B.1 Create `/home/user/Geoff/COMPETITION_COMPLIANCE.md`

Use this exact structure. Replace every `<verify>` placeholder by reading the cited file and confirming the line number / function name is current. **Do not paste a citation you have not personally verified by `Read`-ing the file.**

```markdown
# Competition Compliance — Protocol SIFT Autonomous IR

Geoff is entered under the rule clause permitting **comparable agentic architectures** in lieu of Claude Code or OpenClaw. This document maps each competition requirement to the code, configuration, or output artifact that satisfies it.

## Rule 1 — Agentic framework as the primary execution engine

**Requirement.** A working software application that uses an agentic framework as the primary execution engine.

**How Geoff satisfies it.** Geoff's execution engine is the **Geoff Triad Agent Loop**, an autonomous three-agent architecture:

| Agent | Role | Implementation |
|-------|------|----------------|
| Manager | Plans, reviews, and decides | `src/geoff_self_heal.py:_manager_review_execution_plan` (line <verify>), `src/geoff_pipeline.py:_manager_post_critic_decision` (line <verify>) |
| Forensicator | Selects tools, interprets results | `src/geoff_forensicator.py:call_forensicator_llm` (line <verify>), batch dispatch in `src/geoff_pipeline.py:_run_forensicator_batch` (line <verify>) |
| Critic | Validates, flags, triggers replay | `src/geoff_critic.py` (whole file), `src/geoff_pipeline.py:_batch_critic_review_all_playbooks` (line <verify>) |

The loop runs autonomously after a single user invocation. Entry points:

- CLI: `bin/geoff-find-evil <evidence_dir>`
- HTTP: `POST /find-evil`
- MCP: `start_find_evil` tool in `src/geoff_mcp_server.py`
- Console: `bin/geoff_console.py`

See `docs/AGENT_PROTOCOL.md` for the full agent contract.

## Rule 2 — Self-correction without human intervention

**Requirement.** The agent detects and resolves errors or inconsistencies in its own output without human intervention.

**Three independent self-correction mechanisms:**

1. **Per-step self-healing.** `src/geoff_self_heal.py:_attempt_heal` (line <verify>) — on tool failure, the Critic LLM diagnoses the error, emits a `HealDecision` (fix_type, fix_detail, confidence), `_execute_heal` runs the remedy, `_audit_heal` records the outcome. Deterministic fast-paths for `tool_missing`, `mount_error`, and `permission_error` skip the LLM where appropriate.
2. **Batch Critic + Manager replay.** After all playbooks execute, `_batch_critic_review_all_playbooks` (line <verify>) reviews every finding for hallucinations and cross-step inconsistencies. `_manager_post_critic_decision` (line <verify>) chooses `approve | flag | replay`. Replay re-runs only affected steps with Manager-patched params.
3. **Chat grounding check.** `src/geoff_self_heal.py:_self_check_chat_response` (line <verify>) verifies every chat response cites only present-in-context evidence and regenerates once with a correction prompt if unsupported claims are detected.

Every self-correction is audit-logged to `case_work_dir/audit_trail.jsonl` with an event class (e.g. `SELF_HEAL`).

## Rule 3 — Accuracy validation; findings traceable to artifacts

**Requirement.** All findings traceable to specific artifacts, files, offsets, or log entries.

**Traceability stack:**

| Layer | Artifact | Location |
|-------|----------|----------|
| Per-step custody | SHA-256 of evidence + SHA-256 of params + tool_version + timestamp | `case_work_dir/custody/<step_key>.json` (written by `_commit_step_with_custody`, `geoff_pipeline.py:457`) |
| Evidence chain | `{artifact, evidence_file, tool, playbook, significance, analyst_note}` on every finding | embedded in each `findings.jsonl` record |
| Command log | Every shell invocation with argv, cwd, stdout/stderr digests | `case_work_dir/commands/<timestamp>_<cmd>.json` (driven by `src/command_logger.py`) |
| Validation log | Per-step Critic verdict | `case_work_dir/validations/<step_key>.json` |
| Narrative citations | `(source: <tool> on <file>)` required for every factual claim in attack chain synthesis | enforced in `src/narrative_report.py` (function <verify>) |

Reproducibility: every step is committed to a per-case git repository immediately on completion. A reviewer can `git log` the case directory to replay the investigation.

## Rule 4 — Analytical reasoning, not raw execution log

**Requirement.** Output presented as a structured investigative narrative.

**How Geoff satisfies it.**

- The narrative report (`reports/narrative_report.md`) is generated by `src/narrative_report.py` and follows an 8-section structure: Executive Summary, Attack Narrative, Key Evidence, MITRE Mapping, Per-User Findings, Timeline of Significant Events, Recommended Actions, Caveats.
- The GEOFF_PROMPT (`src/geoff_self_heal.py:GEOFF_PROMPT`, line <verify>) enforces a Hypothesis → Evidence → Assessment reasoning protocol on every chat response.
- The attack chain synthesis is forbidden from speculating beyond verified evidence anchors. If support is absent, the report must write *"Insufficient evidence to assess"*.
- The raw execution log lives separately in `findings.jsonl` and `audit_trail.jsonl`; the narrative is the analyst-facing deliverable.

## Rule 5 — SIFT Workstation / Linux platform

**Requirement.** Built on Linux terminal / SIFT Workstation environment.

- `install.sh` targets Ubuntu 22.04 Jammy (the SIFT 2026.x base) and installs the SIFT-equivalent toolchain: SleuthKit, Plaso, Volatility3 (pip — see [teamdfir/sift#628](https://github.com/teamdfir/sift/issues/628)), Zimmerman Tools, RegRipper, REMnux suite, tshark, tcpflow, bulk_extractor, hashdeep/ssdeep.
- All execution paths are CLI-first: `geoff-find-evil`, `geoff_console.py`, `geoff_mcp_server.py`, and a Flask HTTP API.
- The MCP server in `src/geoff_mcp_server.py` lets remote analysts drive Geoff from a Claude Desktop or Claude Code MCP client over an SSH tunnel — satisfying the "remote endpoints via MCP" data-type clause.

## Rule 6 — Working install + run

**Requirement.** Successfully installed and running consistently.

- `install.sh` is the canonical installer (root level, not the archived `legacy/installer-pre-pivot/`).
- `test_install.sh` runs a clean-install smoke test.
- Four independent entry points (CLI, HTTP, MCP, console) all hit the same `find_evil` pipeline, so the agent loop is exercised four different ways.

## Demonstration

`geoff-find-evil <evidence_dir> --agent-trace --show-agents` produces:

1. Color-coded per-agent log lines (`[Manager]`, `[Forensicator]`, `[Critic]`, `[Healer]`).
2. A `case_work_dir/agent_trace.jsonl` stream containing every planning prompt, observation, critic verdict, manager decision, and heal event with timestamps.

This trace is the per-run evidence that the agent loop — not a static pipeline — is the execution engine.
```

### B.2 Verification

After writing the file:
```bash
grep -c "<verify>" /home/user/Geoff/COMPETITION_COMPLIANCE.md
```
Should be `0`. Every `<verify>` placeholder must have been replaced with a real, verified line number.

### B.3 Commit

```
docs: add COMPETITION_COMPLIANCE.md mapping each rule to code

Single-page document for competition judges that maps each Protocol SIFT
requirement (agentic framework, self-correction, accuracy validation,
analytical reasoning, SIFT platform, install/run) to specific code paths
and output artifacts.
```

---

## 5. Track C — README "Agentic Framework" section

**Goal:** the README must, in its top third, name and frame Geoff's agentic architecture and compare it to Claude Code / OpenClaw on capability axes. Right now the README never uses the word "agentic" or compares to either framework.

### C.1 Insert location

Open `/home/user/Geoff/README.md`. Find the existing section heading `## What is GEOFF?` (around line 21). The new section goes **between** `## What is GEOFF?` and `### The Multi-Agent Team` — i.e. immediately after the one-line description, before the agent table.

### C.2 Section content

Use this exact structure. Edit prose for naturalness but keep every header and the capability matrix.

```markdown
## Agentic Framework

Geoff's primary execution engine is the **Geoff Triad** — a three-agent autonomous loop that plans, executes, observes, critiques, and self-corrects without per-step human approval. The competition rules permit "comparable agentic architectures" alongside Claude Code and OpenClaw; the Geoff Triad is that architecture.

### The agents

- **Manager** — receives the high-level goal ("find evil in this evidence"), reviews triage output, builds and amends the execution plan, decides post-execution actions (approve / flag / replay). Implementation: `src/geoff_self_heal.py::_manager_review_execution_plan`, `src/geoff_pipeline.py::_manager_post_critic_decision`.
- **Forensicator** — selects forensic tools per playbook step, interprets each tool's output into a structured analyst note (significance + threat indicators + evidence chain). Implementation: `src/geoff_forensicator.py::call_forensicator_llm`.
- **Critic** — validates every finding for hallucinations and inconsistency, diagnoses failed tool runs into structured `HealDecision`s, and flags steps that need replay. Implementation: `src/geoff_critic.py` and `src/geoff_self_heal.py::_attempt_heal`.

A fourth role — **Healer** — is the Critic operating in error-recovery mode (`_attempt_heal` → `_execute_heal`). It is the same model with a different prompt; surfaced separately in the agent trace because it has its own audit class.

All three agents communicate via structured JSON messages. The full protocol is in [`docs/AGENT_PROTOCOL.md`](docs/AGENT_PROTOCOL.md).

### Capability comparison

| Capability | Claude Code | OpenClaw | **Geoff Triad** |
|------------|-------------|----------|------------------|
| Goal-directed planning | ✅ single agent | ✅ single agent | ✅ **dedicated planner agent (Manager)** |
| Tool selection at runtime | ✅ | ✅ | ✅ Forensicator chooses per-step from 25 playbooks |
| Observation → reasoning loop | ✅ | ✅ | ✅ Forensicator analyst note → Critic validation |
| Self-critique | ⚠ via prompt | ⚠ via prompt | ✅ **dedicated Critic agent + batch holistic review** |
| Autonomous error recovery | ⚠ retry only | ⚠ retry only | ✅ **`_attempt_heal` with fast-path + LLM diagnosis** |
| Multi-agent specialization | ❌ | ❌ | ✅ **three distinct roles, three model profiles** |
| Persistent memory | session context | session context | ✅ **git-backed per-case repo with custody sidecars** |
| Reproducible audit trail | ❌ | partial | ✅ **per-step SHA-256 custody + commands log + audit_trail.jsonl** |
| Pluggable LLM backend | Anthropic-only | Ollama-only | Ollama (cloud or local), profile-switchable |
| Runs on SIFT Workstation | requires net + key | yes | yes (cloud or local) |

Geoff matches Claude Code and OpenClaw on every agentic primitive and exceeds them on multi-agent specialization, dedicated self-correction, and reproducibility.

### Why a custom triad instead of Claude Code or OpenClaw

DFIR investigations require three properties that single-agent frameworks struggle to provide:

1. **Separation of concerns.** Tool execution (Forensicator), validation (Critic), and decision-making (Manager) come from different model temperaments. We use different models per role (`profiles.json`) — a coder model for tool selection, a general-reasoning model for critique, a planner model for decisions.
2. **Holistic cross-step critique.** A per-step LLM check misses inconsistencies between findings. The Geoff Critic reviews all findings in one pass (`_batch_critic_review_all_playbooks`), which catches hallucinations a single-agent loop cannot.
3. **Forensic chain of custody.** Every step commits to a per-case git repository with a SHA-256-of-evidence custody sidecar. This is a forensic non-negotiable; bolted onto a general-purpose agent framework it becomes fragile, but it's primary in Geoff.
```

### C.3 Verification

After inserting:
```bash
grep -n "Agentic Framework\|Geoff Triad" /home/user/Geoff/README.md
```
Should show at least four hits (section header, two in body, table caption row).

Re-read your own insertion. Confirm every cited function actually exists at the file path given.

### C.4 Commit

```
docs(README): add Agentic Framework section naming the Geoff Triad

The README never named the agent architecture or compared it to the
competition's preferred frameworks (Claude Code, OpenClaw). New section
introduces the Geoff Triad (Manager / Forensicator / Critic + Healer),
maps each role to its implementation, and lays out a capability matrix
versus Claude Code and OpenClaw.
```

---

## 6. Track D — Agent protocol specification

**Goal:** turn the Triad from "code that happens to use three LLMs" into a **framework with a published contract**. A framework has a spec; a script does not.

### D.1 Create `/home/user/Geoff/docs/AGENT_PROTOCOL.md`

Required sections, in order:

1. **Overview** — one paragraph: what the Triad is, what problem it solves, who the agents are.
2. **State machine** — a diagram (ASCII) of the loop: `triage → plan → execute → observe → critique → decide → (replay | approve | flag) → narrate`. Each transition labeled with the agent that owns it.
3. **Agent contracts** — for each of Manager, Forensicator, Critic, Healer:
   - Role and responsibilities.
   - System prompt (copy from code; cite the source file and line).
   - Input message schema (Python dict structure).
   - Output message schema (the JSON the agent must emit).
   - Failure mode: what happens if the LLM call times out or returns malformed output. Cite the fallback in code.
4. **Message types** — define the canonical JSON shapes:
   - `ExecutionPlan` — output of triage + Manager review.
   - `ForensicatorObservation` — analyst note, significance, threat_indicators, evidence_chain.
   - `CriticVerdict` — verdict, verdict_reason, needs_review, replay_recommended.
   - `HealDecision` — fixable, fix_type, fix_detail, root_cause, confidence, llm_model. (Already a dataclass — cite it.)
   - `ManagerDecision` — action (approve|flag|replay), reasoning, replay_targets.
   - `BatchCriticAssessment` — overall_quality, sufficient_for_report, replay_candidates, hallucination_flags.
5. **Persistence model** — list every file written by the loop with purpose and format:
   - `case_work_dir/execution_plan.json`
   - `case_work_dir/findings.jsonl`
   - `case_work_dir/custody/<step_key>.json`
   - `case_work_dir/validations/<step_key>.json`
   - `case_work_dir/commands/<timestamp>_<cmd>.json`
   - `case_work_dir/batch_critic_assessment.json`
   - `case_work_dir/manager_decision.json`
   - `case_work_dir/audit_trail.jsonl`
   - `case_work_dir/agent_trace.jsonl` (from Track E)
   - `case_work_dir/reports/narrative_report.md`
6. **Self-correction sub-protocol** — a sequence diagram of the error recovery loop, from tool failure through `classify_error_fast` → fast-path or LLM diagnosis → `_execute_heal` → `_audit_heal`.
7. **Replay sub-protocol** — how `_manager_post_critic_decision` chooses replay targets, how params are patched, how `findings_writer.is_completed()` provides idempotency.
8. **Model backend** — current backend is Ollama (cloud or local). Profile switch via `GEOFF_PROFILE`. Per-agent model override via `GEOFF_MANAGER_MODEL`, `GEOFF_FORENSICATOR_MODEL`, `GEOFF_CRITIC_MODEL`. Note that the protocol is backend-agnostic — any chat-completion API can implement it.

### D.2 Source material

Pull the prompts and schemas **from the code**, not from memory:
- `src/geoff_self_heal.py:GEOFF_PROMPT` (line <verify>)
- `src/geoff_self_heal.py:_manager_review_execution_plan` prompt (line <verify>)
- `src/geoff_pipeline.py:_batch_critic_review_all_playbooks` prompt (line <verify>)
- `src/geoff_pipeline.py:_manager_post_critic_decision` prompt (line <verify>)
- `src/geoff_critic.py:HealDecision` dataclass (line <verify>)

Quote the prompts in fenced code blocks. Cite each by file:line. **Do not paraphrase prompts; copy them.**

### D.3 Verification

```bash
test -f /home/user/Geoff/docs/AGENT_PROTOCOL.md && wc -l /home/user/Geoff/docs/AGENT_PROTOCOL.md
```
Expect 250–500 lines. If <150, the spec is too thin; expand.

```bash
grep -c "src/geoff_" /home/user/Geoff/docs/AGENT_PROTOCOL.md
```
Expect ≥10 citations.

### D.4 Commit

```
docs: publish AGENT_PROTOCOL.md — formal spec for the Geoff Triad

State machine, per-agent contracts (Manager / Forensicator / Critic /
Healer), message schemas, persistence model, self-correction and replay
sub-protocols. Every prompt and schema is quoted from src/ with a
file:line citation so reviewers can verify the spec against the
implementation.
```

---

## 7. Track E — Runtime agent visibility

**Goal:** today's CLI output reads as a tool log. Add `--agent-trace` (writes a structured JSONL) and `--show-agents` (prefixes log lines with the agent role). Both expose information **that already exists** — no new agent logic.

### E.1 Files to edit

Primary edits in:
- `/home/user/Geoff/bin/geoff-find-evil` — add the two flags.
- `/home/user/Geoff/src/geoff_utils.py` — extend `_fe_log` (or wherever the central log emitter lives — verify by reading) to accept an `agent` keyword and prefix accordingly.
- `/home/user/Geoff/src/geoff_pipeline.py` and `/home/user/Geoff/src/geoff_self_heal.py` — call sites where the existing `_fe_log` lines are emitted, add an `agent="Manager"` / `"Forensicator"` / `"Critic"` / `"Healer"` keyword.

**Do not** rename `_fe_log` or change its signature destructively. Add an optional `agent: str | None = None` parameter with a default of `None` so existing call sites are unaffected.

### E.2 `--show-agents` behavior

When `--show-agents` is passed (or env `GEOFF_SHOW_AGENTS=1`), every log line that has an `agent=` tag is prefixed with a colored role tag, e.g.:

```
14:32:01  [Manager]    ▶ Reviewing execution plan…
14:32:05  [Forensicator]  ▶ sleuthkit.fls_list_files
14:32:08  [Critic]     ✓ Verdict: ACCEPTABLE
14:32:10  [Healer]     ⊘ tool_missing → installed via apt
```

Color map (use the same ANSI helpers already in `bin/geoff-find-evil`):
- Manager: cyan
- Forensicator: green
- Critic: yellow
- Healer: magenta

When the flag is **not** set, behavior is unchanged.

### E.3 `--agent-trace` behavior

When `--agent-trace` is passed (or always, when env `GEOFF_AGENT_TRACE=1`), open `case_work_dir/agent_trace.jsonl` and write a JSON object per agent event with this schema:

```json
{
  "ts": "2026-05-28T14:32:01.123456",
  "agent": "Manager",
  "event": "plan_review",
  "job_id": "fe-abc123",
  "prompt_excerpt": "first 200 chars of the prompt",
  "response_excerpt": "first 200 chars of the response",
  "outcome": "approved_12_playbook_plan",
  "ref": {"file": "execution_plan.json"}
}
```

Event types to emit (minimum):
- `Manager`: `plan_review`, `post_critic_decision`, `pass2_review`
- `Forensicator`: `observation` (once per step)
- `Critic`: `step_verdict`, `batch_assessment`
- `Healer`: `heal_attempt`, `heal_outcome`

Each event must be appended atomically (use the existing `_atomic_append` helper in `geoff_config.py` — verify it exists). Prompts and responses should be truncated to 500 chars in the trace to keep file size reasonable; the full prompt/response is already on disk in `validations/`, `manager_decision.json`, etc.

### E.4 CLI help text

Update the docstring at the top of `bin/geoff-find-evil` to document the two new flags. Also update README options block (the "Command Line (fastest)" section, around line 110).

### E.5 Verification

Run a smoke test against a small evidence directory:
```bash
mkdir -p /tmp/agent-trace-test
echo "fake" > /tmp/agent-trace-test/dummy.txt
python3 /home/user/Geoff/bin/geoff-find-evil /tmp/agent-trace-test --agent-trace --show-agents 2>&1 | head -40
```

Confirm:
- Output lines are prefixed with `[Manager]` / `[Forensicator]` / `[Critic]` (color or plain).
- `case_work_dir/agent_trace.jsonl` exists and is valid JSONL (each line parses as JSON).
- Behavior without the flags is unchanged: `python3 bin/geoff-find-evil /tmp/agent-trace-test 2>&1 | head -10` matches pre-change output line-for-line aside from any unrelated startup messages.

If you cannot run the smoke test (no LLM backend, no tools installed), at minimum confirm:
- The flags are accepted by `argparse` and appear in `--help`.
- The new keyword on `_fe_log` does not break existing call sites (run `python3 -c "import sys; sys.path.insert(0,'src'); import geoff_pipeline"` and confirm no import error).

### E.6 Commit

```
feat: --agent-trace and --show-agents flags expose the Triad loop

Existing Manager / Forensicator / Critic / Healer reasoning is already
captured in validations/, manager_decision.json, batch_critic_assessment.json,
and audit_trail.jsonl. New flags surface it at the CLI:

  --show-agents   prefixes every log line with its agent role (color-tagged)
  --agent-trace   writes case_work_dir/agent_trace.jsonl with per-event
                  prompt/response excerpts, outcomes, and refs to the
                  full artifact on disk

No agent logic changes; this is pure observability.
```

---

## 8. After all tracks

### 8.1 Final repository smoke test

```bash
# No OpenClaw refs outside legacy/
grep -rn "OpenClaw\|openclaw" /home/user/Geoff/ --exclude-dir=.git --exclude-dir=legacy
# Expect: empty

# Top-level competition file present
ls /home/user/Geoff/COMPETITION_COMPLIANCE.md /home/user/Geoff/docs/AGENT_PROTOCOL.md
# Expect: both files listed

# README mentions the framework
grep -c "Agentic Framework\|Geoff Triad\|comparable agentic" /home/user/Geoff/README.md
# Expect: >= 3

# CLI flags exist
grep -n "agent-trace\|show-agents" /home/user/Geoff/bin/geoff-find-evil
# Expect: at least one match for each

# Repo still imports cleanly
python3 -c "import sys; sys.path.insert(0,'/home/user/Geoff/src'); import geoff_pipeline; import geoff_self_heal; import geoff_critic; print('OK')"
# Expect: OK
```

### 8.2 Push and stop

```bash
git -C /home/user/Geoff push -u origin claude/fervent-cray-GWs6Y
```

Do **not** open a PR. The owner will review the branch and open the PR themselves.

### 8.3 Hand-back report

In your final message, report:
- Which tracks completed.
- Which tracks were skipped or partially done and why.
- The smoke test results from 8.1.
- Any `<verify>` placeholders you could not resolve (these indicate the underlying code may have changed; flag them so the owner can investigate).
- Total commits pushed.

Do not summarize the plan itself — the owner has it. Report on execution.

---

## 9. Anti-scope-creep checklist

If you find yourself doing any of the following, **stop and ask the owner**:

- Adding a dependency to `requirements.txt`.
- Editing `geoff_pipeline.py`, `geoff_self_heal.py`, `geoff_critic.py`, `narrative_report.py`, or any specialist in `sift_specialists*.py` for reasons other than the `agent=` kwarg addition in Track E.
- Renaming any function, class, or file.
- Writing new tests (out of scope for this plan).
- Creating documentation files not listed above.
- Editing anything in `legacy/` after Track A moves it there.
- Changing `install.sh` or `Requirements.txt`.
- Modifying `profiles.json` or adding a new model backend.
- Pushing to any branch other than `claude/fervent-cray-GWs6Y`.

If you complete all five tracks and have time remaining, **stop and hand back** — do not invent additional work. The owner will direct any follow-on changes.
