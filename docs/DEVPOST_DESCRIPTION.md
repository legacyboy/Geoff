# GEOFF — Devpost Project Description
*Draft for Dan to edit before submission. Word count target: 800–1200 words.*

---

## What it does

GEOFF (Git-backed Evidence Operations Forensic Framework) is an autonomous multi-agent digital forensic investigation platform that runs a full DFIR triage-to-narrative pipeline on raw evidence without per-step human intervention. You point it at a directory of disk images, memory dumps, PCAPs, and logs; it classifies the evidence, builds an investigation plan, executes 25 MITRE ATT&CK-aligned forensic playbooks using the full SANS SIFT toolchain, validates its own findings for hallucinations, self-corrects on tool failures, and writes a structured investigative narrative with explicit evidence citations. The investigation produces a legally-defensible audit trail: a per-case git repository where every completed step is a git commit with a SHA-256 chain-of-custody sidecar, a batch Critic assessment, a Manager decision record, and an 8-section narrative report — all traceable back to specific artifacts, offsets, and log entries in the original evidence.

---

## How we built it

The execution engine is the **Geoff Triad**: three specialized LLM agents with distinct roles.

**Manager** (deepseek-r1:32b / deepseek-v3.2:cloud) plans the investigation. After the mandatory triage playbook (PB-SIFT-000) scans the evidence and identifies indicators, the Manager reviews the proposed execution plan — reordering, adding, or removing playbooks based on evidence type and severity — and approves it before a single forensic tool runs. After execution completes, the Manager reviews the Critic's holistic assessment and chooses to approve findings, flag them for human review, or trigger incremental replay with adjusted parameters for specific failed steps.

**Forensicator** (qwen2.5-coder:14b / qwen3-coder-next:cloud) is the tactical executor. For each playbook step, it receives raw tool output from the SIFT toolchain and produces a structured analyst note: significance rating, threat indicators, and an evidence chain linking the finding to a named artifact, evidence file, tool, and observation. It does not validate its own work — that is the Critic's explicit role.

**Critic** (qwen2.5:14b / qwen3.5:cloud) validates everything. Per-step, it checks each Forensicator observation for hallucinations (claims not backed by tool output) and flags steps for replay. After all playbooks complete, it performs a **batch holistic review** of every finding in a single pass — enabling cross-step correlation that per-step validation cannot catch. The batch review produces a `batch_critic_assessment.json` with hallucination flags, replay candidates, and an overall quality rating that the Manager acts on.

A fourth mode — **Healer** — is the Critic in error-recovery mode. On tool failure, a deterministic fast-path handles the most common field errors (missing tools installed automatically via `apt-get`, mount parameter errors fixed structurally). Only failures that can't be resolved deterministically are escalated to the Healer LLM, which diagnoses the error and emits a `HealDecision` (fix_type, new_params, confidence) that the pipeline executes and commits to the audit trail.

All three agents communicate via structured JSON. The entire state is persisted to a per-case git repository: every step commits on completion, making the investigation checkpointable (resume after power loss or OOM), reproducible (replay any step from the git history), and tamper-evident (SHA-256 custody sidecars at each commit).

**Technology stack:** Python 3.10, Flask, Ollama (cloud or local LLM backend), SANS SIFT Workstation toolchain (SleuthKit, Volatility3, RegRipper, Plaso, Zimmerman Tools, REMnux, tshark, bulk_extractor, hashdeep), MCP server for Claude Desktop / Claude Code integration.

**Key design decisions:**
- **Ollama over Anthropic:** Geoff runs on the SIFT workstation at the scene. A local Ollama backend means no cloud API key is needed in the field; the same tool works air-gapped. The cloud profile uses hosted models for speed when internet is available.
- **Batch Critic over per-step:** A per-step check misses cross-step inconsistencies — a finding about a registry key in Step 3 that contradicts a finding about the same process in Step 7. The batch Critic sees all findings at once and catches these correlations. It also reduces LLM calls by ~3x compared to per-step validation.
- **Git over a database:** Every step committed to a per-case git repository is a forensic idiom. The history is tamper-evident, reproducible on any machine with git, and integrates naturally with the SHA-256 custody chain. A database would require migration tooling and doesn't give you `git log` for free.
- **Manager gate only at triage:** The competition requires autonomous execution. The Manager's single human-approved checkpoint is after triage — before batch execution begins. Everything after that is autonomous, with the Manager reviewing Critic output and deciding to approve, flag, or replay without asking the human again.

---

## Challenges we ran into

**Offset detection for EWF/EnCase images (April–May 2026).** The NTFS filesystem is not always at sector 0 of an E01 disk image. Our initial implementation assumed a single partition at a fixed offset. Real-world M57-Patents evidence (86 disk images, ~89 GB) exposed three competing code paths: `fls_auto`, `fls_offset0`, and `mmls_probe`, each making different assumptions about the partition table. We designed a fail-forward chain — `fls_auto → fls_offset0 → mmls_probe` — and resolved a critical bug (2026-05-19) where `ewfmount` resource leaks caused stale mount point references to cascade into all subsequent steps. The M57 run on 2026-05-27 confirmed the chain firing correctly: 18 self-correction events across 86 images, each recovering rather than failing.

**Hallucination handling at scale.** The initial M57 Phase 1 Critic validation rejected the entire inventory analysis for hallucination — the Forensicator was claiming "file paths were Offsets," a factual error. This was caught by the dedicated Critic agent on 2026-05-27, not by a prompt instruction. A separate incident (2026-05-24, documented in our audit) flagged `DROP TABLE` syntax found in a Windows host registry being misclassified as SQL injection. These incidents shaped our understanding of where hallucination appears in real forensic workflows and drove improvements to the Forensicator's prompt constraints.

**EVTX parsing edge cases (2026-06-01).** Windows EVTX binary format has several encoding edge cases — multi-block PowerShell 4104 events, corrupt channel names, events with null Computer fields — that caused silent failures in log analysis. We added explicit error handling and a fallback chain to python-evtx when EvtxECmd returns malformed output.

**Self-correction loop design.** Early versions treated every tool failure as an LLM problem. Under load, this created heal loops that flooded the LLM backend and generated identical HealDecisions for deterministic errors (missing tool, wrong mount path). We added a deterministic fast-path that handles `tool_missing` (apt-get install), `mount_error`, and `permission_error` without LLM involvement, plus an error hash cache that skips the LLM for repeated identical failures. This reduced LLM heal calls by ~80% in field testing.

---

## What we learned

**Dedicated self-critique is not redundant.** A model reviewing its own output within the same context window is not the same as a separate model reviewing it cold. The batch Critic, running after all playbooks complete, caught cross-step inconsistencies that neither the Forensicator nor a per-step check would have found — specifically, conflicting claims about the same artifact appearing in separate playbook outputs. Specialization matters.

**Prompt-enforced guardrails are insufficient for forensic claims.** The Forensicator's prohibition on speculation is in the system prompt. A model that misinterprets tool output still hallucinates within the prompt constraint. The batch Critic's structural rejection — a separate model, separate context, explicit verdict — is what actually catches these failures. We rely on prompt enforcement for narrative generation (no structural backstop there) and have disclosed this gap.

**Git is a better forensic database than a database.** The ability to `git log` an investigation, `git show` a specific step commit, or `git diff` two replay runs turned out to be genuinely useful for debugging and for explaining findings to non-technical stakeholders.

---

## What's next

- Fix the three mislabeled playbooks (PB-004, PB-011, PB-013) — the content is wrong for the labeled scenario (e.g., PB-004 contains network device forensics instead of privilege escalation).
- Extend structural self-check to narrative report generation — currently narrative grounding is prompt-enforced only.
- Unified partition offset detection: eliminate the `fls_auto / fls_offset0 / mmls_probe` three-way cascade with a single mmls-first approach.
- Cloud IR playbook (PB-SIFT-025): AWS CloudTrail, Azure Sentinel, GCP Audit Logs — the toolchain exists but the playbook is not yet wired.
- Memory artifact classification: `volatility malfind` output for PE-injected regions classified as `OTHER` in the current inventory schema.

---

## Accomplishments we're proud of

**The custody chain.** Every step in every investigation is a git commit with a SHA-256 hash of the evidence file, the step parameters, the tool version, and a timestamp. This is a forensic non-negotiable — you cannot present findings in court if you cannot prove the evidence was not modified after collection. We built this in from the start, not bolted on afterward.

**Checkpoint/resume.** An 89 GB evidence set across 86 disk images takes hours. Power loss, OOM, and operator error are real. The per-step git commit means a resumed run picks up exactly where it left off — not at the phase boundary, but at the individual tool call boundary.

**The Critic's hallucination catch on M57.** On our first real-world evidence run (2026-05-27), the Critic caught a factual error in the Forensicator's output before it reached the Manager or the narrative report. This was not a test — it was a live investigation on 89 GB of NIST-published evidence. The self-correction mechanism worked exactly as designed in the field, not just in unit tests.

**25-playbook MITRE ATT&CK coverage.** From initial access through exfiltration and impact, including mobile forensics (32 methods), macOS forensics, malware analysis (REMnux), cross-image lateral movement, and anti-forensics detection. PB-SIFT-000 generates the execution plan dynamically from the evidence — a judge running a ransomware case gets a different plan than a judge running an insider threat case.
