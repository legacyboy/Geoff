# GEOFF — Devpost Project Description

---

## What it does

GEOFF (Git-backed Evidence Operations Forensic Framework) is an autonomous multi-agent digital forensic investigation platform that runs a full DFIR triage-to-narrative pipeline on raw evidence without per-step human intervention. You point it at a directory of disk images, memory dumps, PCAPs, and logs; it classifies the evidence, builds an investigation plan, executes 49 MITRE ATT&CK-aligned forensic playbooks using the full SANS SIFT toolchain, validates its own findings through dual-critic validation with confidence scoring, self-corrects on tool failures, tracks evidence provenance through a derivation DAG, and writes a structured investigative narrative with explicit evidence citations. The investigation produces a legally-defensible audit trail: a per-case git repository where every completed step is a git commit with a SHA-256 chain-of-custody sidecar, a batch Critic assessment, a Manager decision record, a Provenance DAG, confidence scores from dual-critic agreement, and an 8-section narrative report — all traceable back to specific artifacts, offsets, and log entries in the original evidence.

---
## Human authors notes

This project started over a bunch of mojitos in a pool in Mexico.  I had just setup OpenClaw before I left and was playing around with what I could do with it and saw a posting announcing the competition.  The idea of Geoff and its architecture is all mine, git, playbooks, critic, healing. But I wrote absolutely nothing besides some documentation and architecture designs for the project.  I have been using a variety of models to do the work, GLM5.1, Deepseek, Qwen (multiple), Kimi, ChatGPT and recently Claude. Some worked better than others; others worked much much worse and caused all sorts of chaos.

I tried multiple approaches to development, I had Claude act as an architect and direct others, working with the agents in teams, and individual efforts being validated by another agent. I ended up preferring individual agents spawned by a manager agent on OpenClaw that monitored them and then passed the final work off to another for validation. I found great success with the non-frontier agents; GLM5.1 was very capable but expensive. Qwen and its derivatives were some of my favorites. DeepSeek I found very capable, flash was ok, Pro was impressive.

Could I have written this without them?

Not to this level, I had a functional system with no gui before I got on a plane. Then the gui, the gui and its connection to the backend are beyond what I could have done on my own. Not just in 60 days, I am not sure if I had the time or the inclination to do it at all.


### What I am proud of


## Git back end

I was about 5 mojitos into the morning, I still think this is a good idea. My agents have extended it further but it opens many doors to new features. Teaming, history tracking are all enabled with git in the back.

## Playbooks

The playbooks were a necessity, it almost acts like a set of guard rails to keep Geoff on task. But it also makes it extensible. We can add new skills by playbooks and if there are tools missing, it should be able to recognize that and install them. If there are new evidence types, we can just give Geoff a new playbook and off it goes.

## Multi agents and the Critic

Initially, my plan was to leverage OpenClaw as a base and use it for my agents. To be blunt I have no idea if even did, but eventually I ended up with the current architecture which works fine. This is one of my biggest criticisms of vibe coding right now. It just adds things without asking, even when I am very specific, it will add new features and buttons without being prompted. It makes testing an adventure since I never know what I am going to find.

The dual-critic pool was a natural extension — running two critics in parallel catches errors that one model alone would miss. The confidence scoring (VERY_HIGH down to LOW) gives analysts a real signal about which findings to trust.

## Checkpoints

Sadly, this was a late addition, I had a release that was very unstable and it was tedious to restart.  I could have resolved this sooner, but it was not as painful as it was when I finally did.

## Challenges with Vibecoding

Having the agents check everything into a git repo is a must at every single step. I had several cases where we were going on one part of the applcation and the report page was altered. I would rate working with current non-frontier models between workable and terrifying.

---

## How we built it

The execution engine is the **Geoff Triad**: three specialized LLM agents with distinct roles.

**Manager** (deepseek-r1:32b / deepseek-v4-flash:cloud) plans the investigation. After the mandatory triage playbook (PB-SIFT-000) scans the evidence and identifies indicators, the Manager reviews the proposed execution plan — reordering, adding, or removing playbooks based on evidence type and severity — and approves it before a single forensic tool runs. After execution completes, the Manager reviews the Critic's holistic assessment and confidence scores from the dual-critic pool, then chooses to approve findings, flag them for human review, or trigger incremental replay with adjusted parameters for specific failed steps.

**Forensicator** (qwen2.5-coder:14b / qwen3-coder-next:cloud) is the tactical executor. For each playbook step, it receives raw tool output from the SIFT toolchain and produces a structured analyst note: significance rating, threat indicators, and an evidence chain linking the finding to a named artifact, evidence file, tool, and observation. It does not validate its own work — that is the Critic's explicit role.

**Critic** (qwen2.5:14b / qwen3.5:cloud) validates everything. The **GeoffCriticPool** runs two independent critics in parallel for each finding. Agreement patterns produce confidence levels: VERY_HIGH when both approve, MEDIUM when they disagree (flagged for review), LOW when both challenge. Per-step, each critic checks the Forensicator observation for hallucinations and flags steps for replay. After all playbooks complete, the batch Critic performs a **holistic review** of every finding in a single pass — enabling cross-step correlation that per-step validation cannot catch. The batch review produces a `batch_critic_assessment.json` with hallucination flags, replay candidates, and an overall quality rating that the Manager acts on.

**Healer** — is the Critic in error-recovery mode. On tool failure, a deterministic fast-path handles the most common field errors (missing tools installed automatically via `apt-get`, mount parameter errors fixed structurally). Only failures that can't be resolved deterministically are escalated to the Healer LLM, which diagnoses the error and emits a `HealDecision` (fix_type, new_params, confidence) that the pipeline executes and commits to the audit trail.

**New capabilities added during the competition:**

- **DNS Forensics Specialist (PB-SIFT-050):** DGA detection via Shannon entropy scoring of domain names, DNS tunneling detection from PCAP captures (high TXT record ratios, unusually long subdomains). Provides per-domain DGA scores and per-PCAP tunneling alerts.

- **YARA Integration (PB-SIFT-051):** 5 built-in YARA rule sets covering the most common forensic indicators — Suspicious PE Overlay, Base64 Encoded PowerShell, Ransomware Note Keywords, Credential Dumping Strings, and Webshell Keywords. Scans disk images, memory dumps, directories, and individual files. Custom rules can be added by placing `.yar` files in the rules directory.

- **Hash Correlation + NSRL (PB-SIFT-052):** SHA-256/MD5/SHA1 file hashing with NSRL (National Software Reference Library) lookup. Identifies known operating system and application files, reducing false positives by filtering standard files from investigation findings.

- **Memory Analysis Expansion (PB-SIFT-027):** 8 new Volatility3 plugins beyond the original set — dll_list, handles, mutantscan, apihooks, modscan, vadinfo, procdump, and memmap. Provides deeper memory forensics coverage for advanced malware and rootkit detection.

- **Multi-Critic (GeoffCriticPool):** Two independent critics run in parallel on each finding. When both approve → VERY_HIGH confidence. When they disagree → MEDIUM confidence, flagged for human review. When both challenge → LOW confidence, likely false-positive. Agreement statistics are persisted for post-investigation analysis.

- **Adaptive Playbook Generation:** When triage discovers an indicator without a dedicated playbook, the AdaptivePlaybook class dynamically composes a custom investigation by selecting relevant specialist functions based on finding type and evidence characteristics. Geoff can investigate novel threat patterns without manual playbook authoring.

- **Confidence Calibration:** The ConfidenceCalibrator tracks critic agreement patterns and produces per-finding confidence scores that are persisted alongside findings. This gives analysts a meaningful, quantitative signal about which findings to trust most.

- **Evidence Provenance DAG:** The ProvenanceDAG tracks the full derivation graph from source evidence through every transform. Every node records its source, transform type, and output path. `finding_provenance()` returns the complete chain from any finding back to the original source evidence.

- **Intelligence-Driven Pass 2 (AdaptivePass2):** After Pass 1 completes, the system scores remaining playbooks against Pass 1 findings. If Pass 1 uncovered leads worth chasing (score above threshold), additional follow-up playbooks are selected and run automatically. This adaptive follow-up catches threats that the initial triage didn't anticipate.

- **IP Map Visualization:** Interactive VisJS network graph showing all IP connections discovered across an investigation. Nodes are color-coded by type (internal, external, multicast). Edges show protocol and port. Accessible via the web UI or direct API call (GET `/reports/<case>/ip-map`).

- **Replay Playbook API:** Per-playbook rerun with adjusted parameters via POST `/replay-playbook`. Uses the same idempotency guards and custody commit path as the internal replay mechanism. Allows targeted re-investigation without re-running the entire case.

- **MITRE ATT&CK Matrix & Heatmap:** Interactive visualizations mapping all investigation findings to the MITRE ATT&CK framework. Provides at-a-glance coverage analysis and technique density heatmaps.

All three agents communicate via structured JSON. The entire state is persisted to a per-case git repository: every step commits on completion, making the investigation checkpointable (resume after power loss or OOM), reproducible (replay any step from the git history), and tamper-evident (SHA-256 custody sidecars at each commit).

**Technology stack:** Python 3.12, Flask, Ollama (cloud or local LLM backend), SANS SIFT Workstation toolchain (SleuthKit, Volatility3, RegRipper, Plaso, Zimmerman Tools, REMnux, tshark, bulk_extractor, hashdeep, YARA), MCP server for Claude Desktop / Claude Code integration.

**Key design decisions:**
- **Ollama:** Geoff runs on the SIFT workstation at the scene. A local Ollama backend means no cloud API key is needed in the field; the same tool works air-gapped. The cloud profile uses hosted models for speed when internet is available.
- **Batch Critic over per-step:** A per-step check misses cross-step inconsistencies — a finding about a registry key in Step 3 that contradicts a finding about the same process in Step 7. The batch Critic sees all findings at once and catches these correlations. It also reduces LLM calls by ~3x compared to per-step validation.
- **Dual Critic over single Critic:** Two independent critics catch errors that one model alone would miss or wrongly approve. Disagreement is surfaced as MEDIUM confidence with mandatory human review, preventing single-model blind spots.
- **Git over a database:** Every step committed to a per-case git repository is a forensic idiom. The history is tamper-evident, reproducible on any machine with git, and integrates naturally with the SHA-256 custody chain. A database would require migration tooling and doesn't give you `git log` for free.
- **Manager gate only at triage:** The competition requires autonomous execution. The Manager's single human-approved checkpoint is after triage — before batch execution begins. Everything after that is autonomous, with the Manager reviewing Critic output and deciding to approve, flag, or replay without asking the human again.
- **Provenance DAG:** Full evidence derivation tracking from source to finding. Court-admissible investigations require chain of custody at every step; the ProvenanceDAG automates this tracking and makes it queryable.

---

## Challenges we ran into

**Offset detection for EWF/EnCase images (April–May 2026).** The NTFS filesystem is not always at sector 0 of an E01 disk image. Our initial implementation assumed a single partition at a fixed offset. Real-world M57-Patents evidence (86 disk images, ~89 GB) exposed three competing code paths: `fls_auto`, `fls_offset0`, and `mmls_probe`, each making different assumptions about the partition table. We designed a fail-forward chain — `fls_auto → fls_offset0 → mmls_probe` — and resolved a critical bug (2026-05-19) where `ewfmount` resource leaks caused stale mount point references to cascade into all subsequent steps. The M57 run on 2026-05-27 confirmed the chain firing correctly: 18 self-correction events across 86 images, each recovering rather than failing.

**Hallucination handling at scale.** The initial M57 Phase 1 Critic validation rejected the entire inventory analysis for hallucination — the Forensicator was claiming "file paths were Offsets," a factual error. This was caught by the dedicated Critic agent on 2026-05-27, not by a prompt instruction. A separate incident (2026-05-24, documented in our audit) flagged `DROP TABLE` syntax found in a Windows host registry being misclassified as SQL injection. These incidents shaped our understanding of where hallucination appears in real forensic workflows and drove improvements to the Forensicator's prompt constraints.

**EVTX parsing edge cases (2026-06-01).** Windows EVTX binary format has several encoding edge cases — multi-block PowerShell 4104 events, corrupt channel names, events with null Computer fields — that caused silent failures in log analysis. We added explicit error handling and a fallback chain to python-evtx when EvtxECmd returns malformed output.

**Self-correction loop design.** Early versions treated every tool failure as an LLM problem. Under load, this created heal loops that flooded the LLM backend and generated identical HealDecisions for deterministic errors (missing tool, wrong mount path). We added a deterministic fast-path that handles `tool_missing` (apt-get install), `mount_error`, and `permission_error` without LLM involvement, plus an error hash cache that skips the LLM for repeated identical failures. This reduced LLM heal calls by ~80% in field testing.

**Dual-critic disagreement resolution.** When two critics disagree on a finding, the system must decide what to do. We chose a conservative approach: disagreement → MEDIUM confidence → flagged for human review. This means the system errs on the side of surfacing uncertain findings rather than hiding them. The agreement statistics (`GeoffCriticPool.get_agreement_stats()`) let us tune the system over time.

---

## What we learned

**Dedicated self-critique is not redundant.** A model reviewing its own output within the same context window is not the same as a separate model reviewing it cold. The batch Critic, running after all playbooks complete, caught cross-step inconsistencies that neither the Forensicator nor a per-step check would have found — specifically, conflicting claims about the same artifact appearing in separate playbook outputs. Specialization matters.

**Two critics are better than one.** The dual-critic pool catches findings that a single model would wrongly approve. Disagreement between critics is itself a valuable signal — it means the finding is ambiguous or the evidence is weak, and surfacing that ambiguity is better than hiding it.

**Prompt-enforced guardrails are insufficient for forensic claims.** The Forensicator's prohibition on speculation is in the system prompt. A model that misinterprets tool output still hallucinates within the prompt constraint. The batch Critic's structural rejection — a separate model, separate context, explicit verdict — is what actually catches these failures. We rely on prompt enforcement for narrative generation (no structural backstop there) and have disclosed this gap.

**Provenance tracking is essential, not optional.** Court-admissible investigations require demonstrating that every finding traces back to specific evidence. The ProvenanceDAG automates what would otherwise be a manual, error-prone process of tracking which tool produced which output from which input.

**Git is a better forensic database than a database.** The ability to `git log` an investigation, `git show` a specific step commit, or `git diff` two replay runs turned out to be genuinely useful for debugging and for explaining findings to non-technical stakeholders.

---

## What's next

- **Multi-endpoint team investigations** — Geoff agents running across multiple machines simultaneously, sharing evidence and coordinating playbook execution. Currently we are experiencing IO bound issues processing multiple large images. But with multiple endpoints working in teams we can increase speed greatly. A single manager LLM should be able to do this, move the evidence around and coordinate the execution. Containerizing Geoff and SIFT should help here.
- **Real-time collaborative analysis** — multiple analysts watching the same live investigation, commenting on findings, and pinning evidence while Geoff updates the report in real-time, turning solo forensics into a team sport. Using git or GitHub this is possible.
- **Cloud-native deployment** — Geoff as a fully containerized service with a web dashboard, user authentication, case management, and evidence upload via browser, so any analyst on any machine can open a case without touching a command line.
- **ML-driven triage ranking** — a classifier trained on prior case outcomes that automatically scores and ranks findings by likelihood of being malicious, so the analyst sees the most important evidence at the top of every report.
- **Live incident response collection** — not just post-mortem forensics on disk images, but live acquisition from running systems via WinRM and SSH, with Geoff deploying lightweight collectors to pull memory, process trees, and network state before the attacker cleans up.
- **Model flexibility** — Right now we have the 3(6) default models, the ability to use different providers and models in dropdowns would be helpful for future proofing.

---

## Accomplishments we're proud of

**The custody chain.** Every step in every investigation is a git commit with a SHA-256 hash of the evidence file, the step parameters, the tool version, and a timestamp. This is a forensic non-negotiable — you cannot present findings in court if you cannot prove the evidence was not modified after collection. We built this in from the start, not bolted on afterward.

**The Provenance DAG.** Beyond per-step custody, we now track the full evidence derivation graph. Any finding can be traced back through every transform to the original source evidence. This is the level of traceability that real forensic investigations demand.

**Checkpoint/resume.** An 89 GB evidence set across 86 disk images takes hours. Power loss, OOM, and operator error are real. The per-step git commit means a resumed run picks up exactly where it left off — not at the phase boundary, but at the individual tool call boundary.

**The Critic's hallucination catch on M57.** On our first real-world evidence run (2026-05-27), the Critic caught a factual error in the Forensicator's output before it reached the Manager or the narrative report. This was not a test — it was a live investigation on 89 GB of NIST-published evidence. The self-correction mechanism worked exactly as designed in the field, not just in unit tests.

**49-playbook MITRE ATT&CK coverage.** From initial access through exfiltration and impact, including memory forensics (8 volatility plugins), DNS forensics (DGA + tunneling), YARA scanning (5 rule sets), hash correlation + NSRL, mobile forensics (32 methods), macOS forensics, malware analysis (REMnux), cross-image lateral movement, anti-forensics detection, EDR telemetry, Active Directory, IoT, containers, and VM snapshots. PB-SIFT-000 generates the execution plan dynamically from the evidence — a judge running a ransomware case gets a different plan than a judge running an insider threat case.

**Adaptive Pass 2.** The ability to dynamically select follow-up playbooks after Pass 1 completes means Geoff doesn't just run a fixed plan — it adapts to what it finds. If Pass 1 reveals DNS anomalies, DNS forensics gets queued. If it finds memory injection indicators, deeper volatility plugins get selected. The investigation evolves based on evidence, not just initial triage.