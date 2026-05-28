# Geoff Triad — Agent Protocol Specification

**Version:** 1.0  
**Status:** Authoritative — describes the live implementation in `src/`

---

## 1. Overview

The **Geoff Triad** is a three-agent autonomous loop for digital forensic incident response. It solves the core DFIR problem of reliably executing dozens of forensic tool steps, detecting hallucinations and failures at each step, and producing a legally defensible narrative — without per-step human supervision.

The three principal agents are:

- **Manager** — strategic planner and gatekeeper. Builds the execution plan before analysis begins and decides whether findings are approvable, need flagging, or require replay after analysis ends.
- **Forensicator** — tactical executor. Selects the right tool call per step, interprets raw tool output into a structured analyst note (significance + threat indicators + evidence chain).
- **Critic** — validator and error recoverer. Validates every step output for hallucinations and inconsistency; diagnoses failed tool runs and emits structured `HealDecision`s; performs a holistic batch review after all playbooks complete.

A fourth operational mode — **Healer** — is the Critic running in error-recovery mode (`_attempt_heal` → `_execute_heal`). It is the same model with a different prompt; it is surfaced separately in the agent trace because it has its own audit class (`SELF_HEAL`) and own idempotency path.

All agent communication is via structured JSON. There is no natural-language hand-off between agents. Every decision is committed to disk immediately upon emission.

---

## 2. State machine

```
User invocation
      │
      ▼
  [MANAGER] triage_review ──────────────────────────────────────────────┐
  _manager_review_execution_plan()                                       │
  src/geoff_self_heal.py:754                                             │
      │                                                                  │
      ▼  approved_execution_plan[]                                       │
  ┌──────────────────────────────────┐                                   │
  │  for each playbook in plan:      │                                   │
  │                                  │                                   │
  │   [FORENSICATOR] observation     │                                   │
  │   call_forensicator_llm()        │                                   │
  │   src/geoff_forensicator.py:82   │                                   │
  │         │                        │                                   │
  │         ▼  ForensicatorObservation                                   │
  │   [CRITIC] step_verdict          │                                   │
  │   geoff_critic.py (whole file)   │◄── on tool failure:              │
  │         │                        │    [HEALER] _attempt_heal()       │
  │         │  CriticVerdict         │    src/geoff_self_heal.py:354     │
  │         ▼                        │                                   │
  │   commit to git repo             │                                   │
  │   _commit_step_with_custody()    │                                   │
  │   src/geoff_pipeline.py:457      │                                   │
  └──────────────────────────────────┘                                   │
      │                                                                  │
      ▼  all playbooks complete                                          │
  [CRITIC] batch_assessment                                              │
  _batch_critic_review_all_playbooks()                                   │
  src/geoff_pipeline.py:1382                                             │
      │                                                                  │
      ▼  BatchCriticAssessment                                           │
  [MANAGER] post_critic_decision                                         │
  _manager_post_critic_decision()                                        │
  src/geoff_pipeline.py:1503                                             │
      │                                                                  │
      ├── "approve" ──► narrate (NarrativeReportGenerator.generate())    │
      ├── "flag"    ──► narrate with caveats                             │
      └── "replay"  ──► re-run affected steps with patched params ───────┘
```

Each transition is owned by the agent named at that node. No transition is implicit; each produces a JSON artifact written to `case_work_dir/`.

---

## 3. Agent contracts

### 3.1 Manager

**Role and responsibilities:**
- Pre-analysis: reviews the triage-generated execution plan; may reorder, add, or remove playbooks.
- Post-analysis: receives the Critic's batch assessment; decides `approve | flag | replay`.
- On replay: supplies adjusted params for each replay candidate.

**System prompt** (from `src/geoff_self_heal.py:GEOFF_PROMPT`, line 466):

```
You are G.E.O.F.F. (Git-backed Evidence Operations Forensic Framework), a professional
digital forensics investigation system.

Your role is to conduct thorough, systematic forensic analysis using established
methodologies and the complete SIFT toolkit.

[... tool capability list ...]

Analytical Reasoning Protocol:
When answering a forensic question, structure your reasoning as:
1. Hypothesis — State what you are testing
2. Evidence — Cite the specific artifact, tool result, file path, offset, or log entry
3. Assessment — State your conclusion with confidence level

Do not provide a raw data dump. Every claim must be traceable to a named artifact.

Accuracy Requirements:
- Only assert findings that are directly evidenced by a specific artifact you can name
- When citing a finding, always include: source file, tool used, and the specific
  field/value observed
- Use "appears to", "consistent with", or "no evidence of" for inferences vs. confirmed facts
```

**Pre-analysis input message schema** (passed to `_manager_review_execution_plan`, `src/geoff_self_heal.py:754`):

```python
{
    "proposed_plan":    list[str],   # ["PB-SIFT-001", "PB-SIFT-002", ...]
    "skipped":          list[dict],  # [{"id": "PB-SIFT-010", "reason": "..."}]
    "inventory":        dict,        # evidence counts per type
    "triage_findings":  list[dict],  # indicator hits from triage scan
    "indicator_hits":   list[dict],
    "os_type":          str,
    "classification":   str,
    "severity":         str,
    "job_id":           str,
}
```

**Pre-analysis output schema** (JSON extracted from `_manager_review_execution_plan` return):

```json
{
    "approved_execution_plan": ["PB-SIFT-001", "PB-SIFT-002"],
    "reasoning": "one sentence explaining the key prioritisation decision"
}
```

**Post-analysis input message schema** (passed to `_manager_post_critic_decision`, `src/geoff_pipeline.py:1503`):

```python
{
    "batch_assessment": dict,   # BatchCriticAssessment (see §4)
    "findings":         list,   # all findings records
    "case_work_dir":    Path,
    "job_id":           str,
}
```

**Post-analysis output schema** (written to `case_work_dir/manager_decision.json`):

```json
{
    "action":             "approve | flag | replay",
    "replay_adjustments": {"step_key": {"param_key": "new_value"}},
    "generate_report":    true,
    "reasoning":          "one sentence",
    "critic_executed":    true,
    "manager_executed":   true,
    "auto_approved":      false,
    "auto_approve_reason": null
}
```

**Failure mode:** If the Manager LLM is unavailable or returns malformed JSON, `_manager_post_critic_decision` (`src/geoff_pipeline.py:1580`) defaults to `action: "approve"` with `auto_approved: true` and `auto_approve_reason: "manager_llm_unavailable"`. This fail-open behavior is explicitly recorded in `manager_decision.json` so the audit trail distinguishes real approvals from forced defaults.

---

### 3.2 Forensicator

**Role and responsibilities:**
- For each playbook step: receives raw tool output; interprets it into a structured analyst note with significance rating, threat indicators, and evidence chain items.
- Does not validate its own output — that is the Critic's job.
- Calls the Ollama LLM configured as `GEOFF_FORENSICATOR_MODEL` (default: `qwen3-coder-next:cloud`).

**System prompt context** (constructed at `src/geoff_pipeline.py:_run_forensicator_batch`, line 530):
The Forensicator receives a prompt containing: the playbook name and step, the tool module and function, the raw tool output (stdout/stderr), and evidence context. It is asked to respond in JSON with the schema below. There is no fixed Forensicator-level system prompt constant; the per-step prompt is assembled inline.

**Input message schema:**

```python
{
    "playbook_id":    str,       # e.g. "PB-SIFT-003"
    "step_key":       str,       # e.g. "volatility.list_processes"
    "module":         str,
    "function":       str,
    "params":         dict,
    "tool_output":    str,       # raw stdout/stderr from the specialist
    "evidence_file":  str,
    "evidence_type":  str,
    "os_type":        str,
}
```

**Output schema** (ForensicatorObservation):

```json
{
    "analyst_note":      "one precise sentence citing what the tool output shows",
    "significance":      "CRITICAL | HIGH | MEDIUM | LOW | INFO | NONE",
    "threat_indicators": ["list of specific IOC strings or artifact descriptions"],
    "evidence_chain":    [
        {
            "artifact":      "filename or registry key or memory offset",
            "evidence_file": "path to evidence on disk",
            "tool":          "module.function",
            "playbook":      "PB-SIFT-003",
            "significance":  "HIGH",
            "analyst_note":  "what this artifact shows"
        }
    ]
}
```

**Failure mode:** If `call_forensicator_llm` (`src/geoff_forensicator.py:82`) returns `None` (LLM unavailable after 30 min retry), the step is marked `needs_review: true` with `unverified_reason: "llm_unavailable"`. The step is still committed to the findings record but flagged for the Critic's batch review.

---

### 3.3 Critic

**Role and responsibilities:**
- Per-step validation: verifies each Forensicator observation for hallucinations (claims not backed by tool output), inconsistencies, and sanity (e.g. a CRITICAL finding with no threat indicators).
- Batch holistic review: after all playbooks complete, reviews all findings in one pass for cross-step inconsistencies.
- Error diagnosis: in Healer mode, diagnoses failed tool runs and emits `HealDecision`s with prescribed fix types.

**Per-step validation prompt** (from `src/geoff_critic.py:392`):

```
You are a forensic validation critic. Your job is to issue an explicit verdict on
whether this tool output and analysis are trustworthy.
```

**Error diagnosis prompt** (from `src/geoff_critic.py:888`, used in Healer mode):

```
You are the Geoff Critic, an expert DFIR forensic analyst. A forensic pipeline step
has failed. Your task: diagnose the error and prescribe a fix.

=== FAILED STEP ===
{ctx.to_prompt_block()}

=== AVAILABLE FIX TYPES ===
- retry_params          Modify params dict and retry the same tool
- retry_with_offset     Change the partition offset (sleuthkit only)
- retry_without_offset  Remove offset param (sleuthkit only)
- retry_with_profile    Change Volatility profile or TSK filesystem type
- retry_with_backoff    Retry with 0.5s/1s/2s delays (SQLite busy errors)
- copy_then_retry       Copy locked file to temp, retry on copy
- fallback_tool         Use a different specialist or function entirely
- adjust_command        Modify the raw shell command string
- skip_file             Mark this evidence file as unprocessable and continue
- skip_step             Mark this step as non-critical and skip it
- fail                  Cannot heal; propagate failure
```

**Batch review input message** (passed to `_batch_critic_review_all_playbooks`, `src/geoff_pipeline.py:1382`):

```python
{
    "findings":      list[dict],   # all findings from all playbooks
    "playbooks_run": list[str],
    "case_work_dir": Path,
    "job_id":        str,
}
```

**Batch review output schema** (BatchCriticAssessment, written to `case_work_dir/batch_critic_assessment.json`):

```json
{
    "overall_quality":        "GOOD | ACCEPTABLE | POOR",
    "hallucination_flags":    ["step_key or description of suspect finding"],
    "replay_candidates":      ["step_key"],
    "sufficient_for_report":  true,
    "assessment_summary":     "one sentence",
    "critic_executed":        true,
    "critic_unavailable_reason": null
}
```

**CriticVerdict per-step output schema:**

```json
{
    "verdict":              "ACCEPTABLE | NEEDS_REVIEW | REJECTED",
    "verdict_reason":       "one sentence",
    "needs_review":         false,
    "replay_recommended":   false
}
```

**Failure mode:** If the Critic LLM is unavailable, `_batch_critic_review_all_playbooks` (`src/geoff_pipeline.py:1469`) records `critic_executed: false` and `critic_unavailable_reason` in the assessment JSON. The Manager then receives this flag and records `auto_approved: true` in its decision. Both artifacts preserve the audit chain even in degraded mode.

---

### 3.4 Healer

**Role:** the Critic operating in error-recovery mode. Invoked by `_attempt_heal` (`src/geoff_self_heal.py:354`) when a tool step returns a failure status. The Healer is not a separate agent; it is `GeoffCritic.analyze_execution_error_v2()` (`src/geoff_critic.py:849`) with an error-diagnosis prompt.

**Input:** an `ErrorContext` dataclass built from the failed step's module, function, params, stdout, stderr, and prior heal attempts.

**Output:** a `HealDecision` dataclass (`src/geoff_critic.py:91`):

```python
@dataclass
class HealDecision:
    fixable:            bool = False
    fix_type:           str = "fail"      # see fix type list above
    fix_detail:         str = ""
    root_cause:         str = ""
    new_params:         dict = field(default_factory=dict)
    fallback_module:    Optional[str] = None
    fallback_function:  Optional[str] = None
    adjusted_command:   Optional[str] = None
    skip_reason:        Optional[str] = None
    confidence:         int = 0           # 0-10
    llm_model:          str = ""
    latency_ms:         int = 0
    from_cache:         bool = False
```

**Failure mode:** if the Healer LLM is unavailable, `_attempt_heal` returns `None` and the step is marked failed. The caller records the failed step in `audit_trail.jsonl` with `event: SELF_HEAL, outcome: failed`.

---

## 4. Message types

### ExecutionPlan

Produced by triage + Manager pre-analysis review. Written to `case_work_dir/execution_plan.json`.

```json
{
    "approved_execution_plan": ["PB-SIFT-001", "PB-SIFT-002", "..."],
    "reasoning": "one sentence",
    "skipped": [{"id": "PB-SIFT-010", "reason": "no network evidence"}]
}
```

### ForensicatorObservation

Produced per step. Embedded in `findings.jsonl` records.

```json
{
    "analyst_note":      "string — what the tool output shows",
    "significance":      "CRITICAL | HIGH | MEDIUM | LOW | INFO | NONE",
    "threat_indicators": ["string"],
    "evidence_chain":    [{"artifact": "...", "evidence_file": "...", "tool": "...", "playbook": "...", "significance": "...", "analyst_note": "..."}]
}
```

### CriticVerdict

Per-step verdict. Written to `case_work_dir/validations/<step_key>.json`.

```json
{
    "verdict":            "ACCEPTABLE | NEEDS_REVIEW | REJECTED",
    "verdict_reason":     "string",
    "needs_review":       false,
    "replay_recommended": false
}
```

### HealDecision

Emitted by the Healer. Logged to `audit_trail.jsonl` on every heal attempt.

```python
# Defined as dataclass in src/geoff_critic.py:91
HealDecision(
    fixable=True,
    fix_type="retry_with_offset",
    fix_detail="offset=2048",
    root_cause="wrong_partition_offset",
    confidence=8,
    llm_model="qwen3.5:cloud",
)
```

### ManagerDecision

Post-Critic manager decision. Written to `case_work_dir/manager_decision.json`.

```json
{
    "action":             "approve | flag | replay",
    "replay_adjustments": {"step_key": {"param_key": "new_value"}},
    "generate_report":    true,
    "reasoning":          "string",
    "critic_executed":    true,
    "manager_executed":   true,
    "auto_approved":      false,
    "auto_approve_reason": null
}
```

### BatchCriticAssessment

Holistic post-execution Critic review. Written to `case_work_dir/batch_critic_assessment.json`.

```json
{
    "overall_quality":        "GOOD | ACCEPTABLE | POOR",
    "hallucination_flags":    ["string"],
    "replay_candidates":      ["step_key"],
    "sufficient_for_report":  true,
    "assessment_summary":     "string",
    "total_findings":         42,
    "completed":              38,
    "unverified":             3,
    "failed":                 1,
    "high_critical_findings": 5,
    "critic_executed":        true,
    "critic_unavailable_reason": null
}
```

---

## 5. Persistence model

Every artifact written by the loop is append-only or written atomically. The case directory is itself a git repository; every step commits on completion, creating a tamper-evident audit trail.

| File | Written by | Format | Purpose |
|------|-----------|--------|---------|
| `case_work_dir/execution_plan.json` | `_manager_review_execution_plan` | JSON | Manager's approved playbook order with reasoning |
| `case_work_dir/findings.jsonl` | `FindingsWriter` (`src/geoff_utils.py:313`) | JSONL | One record per step: status, forensicator observation, critic verdict, params, evidence chain |
| `case_work_dir/custody/<step_key>.json` | `_commit_step_with_custody` (`src/geoff_pipeline.py:457`) | JSON | SHA-256 of evidence file + SHA-256 of params + tool_version + timestamp — chain of custody sidecar |
| `case_work_dir/validations/<step_key>.json` | `GeoffCritic` | JSON | Per-step CriticVerdict |
| `case_work_dir/commands/<timestamp>_<cmd>.json` | `src/command_logger.py` | JSON | Every shell invocation with argv, cwd, stdout/stderr truncated digests |
| `case_work_dir/batch_critic_assessment.json` | `_batch_critic_review_all_playbooks` (`src/geoff_pipeline.py:1382`) | JSON | Holistic Critic review of all findings |
| `case_work_dir/manager_decision.json` | `_manager_post_critic_decision` (`src/geoff_pipeline.py:1503`) | JSON | Manager's approve/flag/replay decision with reasoning |
| `case_work_dir/audit_trail.jsonl` | `action_logger` throughout pipeline | JSONL | Every significant event: `SELF_HEAL`, `MANAGER_DECISION`, `BATCH_CRITIC`, `REPLAY`, etc. with timestamps |
| `case_work_dir/agent_trace.jsonl` | `--agent-trace` flag (Track E) | JSONL | Per-event prompt/response excerpts, outcomes, refs to full artifacts |
| `case_work_dir/reports/narrative_report.md` | `NarrativeReportGenerator.generate()` (`src/narrative_report.py:455`) | Markdown | 8-section analyst-facing narrative; only generated when Manager approves |

---

## 6. Self-correction sub-protocol

```
tool step fails
      │
      ▼
classify_error_fast(ctx)
src/geoff_self_heal.py (called from _attempt_heal:373)
      │
      ├── "permission_error" ──► return None (not healable)
      │
      ├── "tool_missing" ──────► _fast_heal("tool_missing", ...)
      │                          deterministic: apt-get install <tool>
      │
      ├── "mount_error*" ──────► _fast_heal("mount_error*", ...)
      │                          deterministic: fix mount args
      │
      └── other / unknown ──────► check _heal_cache
                                        │
                              cache hit │ cache miss
                                  ↓         ↓
                              use cached   GeoffCritic.analyze_execution_error_v2(ctx)
                              HealDecision src/geoff_critic.py:849
                                           │
                                           ▼ HealDecision
                                    _execute_heal(module, function, params,
                                                  decision, job_id)
                                    src/geoff_self_heal.py:257
                                           │
                                           ▼
                                    _audit_heal(job_id, ...)
                                    src/geoff_self_heal.py:438
                                    → audit_trail.jsonl event: SELF_HEAL
```

Fast-paths (`tool_missing`, `mount_error`) bypass the LLM for deterministic environmental fixes. For all other error classes, the Critic LLM diagnoses and the result is cached by `ErrorContext.cache_key()` (a SHA-256 of module + function + exception_type + stderr prefix) so subsequent identical errors skip the LLM.

---

## 7. Replay sub-protocol

When `_manager_post_critic_decision` (`src/geoff_pipeline.py:1503`) returns `action: "replay"`:

1. `replay_adjustments` contains `{step_key: {param_key: new_value}}` for each step to re-run with patched params.
2. The replay loop iterates over `replay_adjustments.keys()`.
3. Before re-running a step, `FindingsWriter.is_completed(step_key)` (`src/geoff_utils.py:376`) is checked — if already completed with a non-failed status, the step is skipped (idempotency guard).
4. The patched step runs through the full Forensicator → Critic → custody-commit path again.
5. The replay produces a second `manager_decision.json` (overwriting the first) once the Critic reviews the replayed findings.
6. `audit_trail.jsonl` records a `REPLAY` event for each replayed step with the original and patched params.

---

## 8. Model backend

**Current backend:** Ollama (cloud or local). All three agents use the Ollama `/generate` API. Authentication via `OLLAMA_API_KEY` env var; remote endpoint via `OLLAMA_URL`.

**Per-agent model selection:**

| Agent | Env var override | Default (cloud profile) | Default (local profile) |
|-------|-----------------|------------------------|------------------------|
| Manager | `GEOFF_MANAGER_MODEL` | `deepseek-v3.2:cloud` | `deepseek-r1:32b` |
| Forensicator | `GEOFF_FORENSICATOR_MODEL` | `qwen3-coder-next:cloud` | `qwen2.5-coder:14b` |
| Critic | `GEOFF_CRITIC_MODEL` | `qwen3.5:cloud` | `qwen2.5:14b` |

Profile switch: `GEOFF_PROFILE=cloud|local` (reads `profiles.json` at startup).

**Backend-agnostic protocol:** the agent protocol itself — the JSON message schemas in §4, the state machine in §2, the persistence model in §5 — is backend-agnostic. Any API that accepts a prompt string and returns a completion (OpenAI-compatible, Anthropic, Ollama) can implement it by adapting the `call_llm` / `call_forensicator_llm` / `_call_critic_llm` shims in `src/geoff_self_heal.py`, `src/geoff_forensicator.py`, and `src/geoff_critic.py` respectively.
