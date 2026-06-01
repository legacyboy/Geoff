# GEOFF — Devpost Project Description

---

## What it does

GEOFF (Git-backed Evidence Operations Forensic Framework) is an autonomous multi-agent digital forensic investigation platform that runs a full DFIR triage-to-narrative pipeline on raw evidence without per-step human intervention. You point it at a directory of disk images, memory dumps, PCAPs, and logs; it classifies the evidence, builds an investigation plan, executes 25 MITRE ATT&CK-aligned forensic playbooks using the full SANS SIFT toolchain, validates its own findings for hallucinations, self-corrects on tool failures, and writes a structured investigative narrative with explicit evidence citations. The investigation produces a legally-defensible audit trail: a per-case git repository where every completed step is a git commit with a SHA-256 chain-of-custody sidecar, a batch Critic assessment, a Manager decision record, and an 8-section narrative report — all traceable back to specific artifacts, offsets, and log entries in the original evidence.

---
## Human authors notes
This project started over a bunch of mojitos in a pool in Mexico.  I had just setup OpenClaw before I left and was playing around with what I could do with it and saw a posting announcing the competition.  The idea of Geoff and its architecture is all mine, git, playbooks, critic, healing. But I wrote absolutely nothing besides some documentation and architecture designs for the project.  I have been using a variety of models to do the work, GLM5.1, Deepseek, Qwen (multiple), Kimi, ChatGPT and recently Claude. Some worked better than others; others worked much much worse and caused all sorts of chaos. 

  

I tried multiple approaches to development, I had Claude act as an architect and direct others, working with the agents in teams, and individual efforts being validated by another agent. I ended up preferring individual agents spawned by a manager agent on OpenClaw that monitored them and then passed the final work off to another for validation. I found great success with the non-frontier agents; GLM5.1 was very capable but expensive. Qwen and its derivatives were some of my favorites. DeepSeek I found very capable, flash was ok, Pro was impressive. 

  

Could I have written this without them?  

 

Not to this level, I had a functional system with no gui before I got on a plane. Then the gui, the gui and its connection to the backend are beyond what I could have done on my own. Not just in 60 days, I am not sure if I had the time or the inclination to do it at all. 

  

### What I am proud of 

  

## git back end 

I was about 5 mojitos into the morning, I still think this is a good idea. My agents have extended it further but it opens many doors to new features. 

  

## Playbooks 

The playbooks were a necessity, it almost acts like a set of guard rails to keep Geoff on task. But it also makes it extensible. We can add new playbooks and if there are tools missing, it should be able to recognize that and install them. If there are new evidence types, we can just give Geoff a new playbook and off it goes. 

  

## Multi agents and the Critic 

Initially, my plan was to leverage OpenClaw as a base and use it for my agents. To be blunt I have no idea if even did, but eventually I ended up with the current architecture which works fine. This is one of my biggest criticisms of vibe coding right now. It just adds things without asking, even when I am very specific, it will add new features and buttons without being prompted. It makes testing an adventure since I never know what I am going to find. 

  

## Checkpoints 

Sadly, this was a late addition, I had a release that was very unstable and it was tedious to restart.  I could have resolved this sooner, but it was not as painful as it was when I finally did. 

---

## How we built it

The execution engine is the **Geoff Triad**: three specialized LLM agents with distinct roles.

**Manager** (deepseek-r1:32b / deepseek-v3.2:cloud) plans the investigation. After the mandatory triage playbook (PB-SIFT-000) scans the evidence and identifies indicators, the Manager reviews the proposed execution plan — reordering, adding, or removing playbooks based on evidence type and severity — and approves it before a single forensic tool runs. After execution completes, the Manager reviews the Critic's holistic assessment and chooses to approve findings, flag them for human review, or trigger incremental replay with adjusted parameters for specific failed steps.

**Forensicator** (qwen2.5-coder:14b / qwen3-coder-next:cloud) is the tactical executor. For each playbook step, it receives raw tool output from the SIFT toolchain and produces a structured analyst note: significance rating, threat indicators, and an evidence chain linking the finding to a named artifact, evidence file, tool, and observation. It does not validate its own work — that is the Critic's explicit role.

**Critic** (qwen2.5:14b / qwen3.5:cloud) validates everything. Per-step, it checks each Forensicator observation for hallucinations (claims not backed by tool output) and flags steps for replay. After all playbooks complete, it performs a **batch holistic review** of every finding in a single pass — enabling cross-step correlation that per-step validation cannot catch. The batch review produces a `batch_critic_assessment.json` with hallucination flags, replay candidates, and an overall quality rating that the Manager acts on.

**Healer** — is the Critic in error-recovery mode. On tool failure, a deterministic fast-path handles the most common field errors (missing tools installed automatically via `apt-get`, mount parameter errors fixed structurally). Only failures that can't be resolved deterministically are escalated to the Healer LLM, which diagnoses the error and emits a `HealDecision` (fix_type, new_params, confidence) that the pipeline executes and commits to the audit trail.

All three agents communicate via structured JSON. The entire state is persisted to a per-case git repository: every step commits on completion, making the investigation checkpointable (resume after power loss or OOM), reproducible (replay any step from the git history), and tamper-evident (SHA-256 custody sidecars at each commit).

**Technology stack:** Python 3.10, Flask, Ollama (cloud or local LLM backend), SANS SIFT Workstation toolchain (SleuthKit, Volatility3, RegRipper, Plaso, Zimmerman Tools, REMnux, tshark, bulk_extractor, hashdeep), MCP server for Claude Desktop / Claude Code integration.

**Key design decisions:**
- **Ollama:** Geoff runs on the SIFT workstation at the scene. A local Ollama backend means no cloud API key is needed in the field; the same tool works air-gapped. The cloud profile uses hosted models for speed when internet is available.
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

- **Close installer tool gaps.** 13+ apt packages (foremost, scalpel, zeek, bulk_extractor, dc3dd, guestmount, bdeinfo, readpst, apfs-fuse, and others) and 8 pip packages (plyvel, pefile, lief, pyinstxtractor, uncompyle6, python-magic, construct, pycdc) are cited by playbooks but never installed by install.sh. A clean SIFT install will hit missing-tool failures in at least a dozen playbooks.
- **Add Web Shell Indicators playbook.** Relabeling PB-011 removed web shell coverage from the library entirely. No playbook currently correlates IIS/Apache access logs for anomalous POSTs to static files, scans web directories for newly created .asp/.php/.aspx files, or traces `w3wp.exe → cmd.exe` parent-child process chains.
- **Add Insider Threat behavioral analysis playbook.** Relabeling PB-013 removed insider threat coverage. Print spooler job history, Windows Search index (Windows.edb), UserAssist MRU timeline, clipboard artifacts, and behavioral baselining (off-hours access, volume anomalies) are now absent from the library.
- **Stitch multi-block PowerShell 4104 events.** Heavily obfuscated PowerShell commands split across multiple EventID 4104 messages (via `ScriptBlockId` + `MessageNumber` continuation) are returned as truncated fragments. The full decoded script is never reassembled. This is a documented gap in the EVTX parser.
- **Close RAR archive handling gap.** `.rar` evidence containers are not extracted during preprocessing. Files inside RAR archives bypass all playbook analysis — none of the evidence inventory, classification, or forensic tool steps ever see their contents.

---

## Accomplishments we're proud of

**The custody chain.** Every step in every investigation is a git commit with a SHA-256 hash of the evidence file, the step parameters, the tool version, and a timestamp. This is a forensic non-negotiable — you cannot present findings in court if you cannot prove the evidence was not modified after collection. We built this in from the start, not bolted on afterward.

**Checkpoint/resume.** An 89 GB evidence set across 86 disk images takes hours. Power loss, OOM, and operator error are real. The per-step git commit means a resumed run picks up exactly where it left off — not at the phase boundary, but at the individual tool call boundary.

**The Critic's hallucination catch on M57.** On our first real-world evidence run (2026-05-27), the Critic caught a factual error in the Forensicator's output before it reached the Manager or the narrative report. This was not a test — it was a live investigation on 89 GB of NIST-published evidence. The self-correction mechanism worked exactly as designed in the field, not just in unit tests.

**25-playbook MITRE ATT&CK coverage.** From initial access through exfiltration and impact, including mobile forensics (32 methods), macOS forensics, malware analysis (REMnux), cross-image lateral movement, and anti-forensics detection. PB-SIFT-000 generates the execution plan dynamically from the evidence — a judge running a ransomware case gets a different plan than a judge running an insider threat case.
