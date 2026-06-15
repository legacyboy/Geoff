# Geoff Demo Video Script — 5 Minutes

## SEGMENT 1: What is Geoff (0:00-0:30)

**On screen:** Geoff README with ASCII art logo, scrolling to architecture diagram

**Narration:**
Geoff is a multi-agent digital forensics platform. Three AI agents — a Manager, a Forensicator, and a Critic — work together autonomously to find evil in evidence. No human approval needed between steps. Everything is git-committed for chain of custody. Let me show you how it works.

---

## SEGMENT 2: Install & Setup (0:30-1:15)

**On screen:** Terminal — curl install command, .env config, browser opening to Geoff UI

**Narration:**
Installation is one command. Curl the install script, pipe it to bash, choose your profile. I'm using cloud models with an API key — paste it in the dot-env file and Geoff routes directly to Ollama Cloud. No GPU needed.

Start Geoff, open the browser. The web UI is live at localhost port 8080. Clean dashboard, ready for evidence.

---

## SEGMENT 3: Live Run — Find Evil (1:15-3:15)

**On screen:** Geoff UI — selecting evidence, job starting, real-time progress dashboard with playbook steps appearing, forensicator notes, batch critic

**Narration:**
Let's run a real investigation. I'll point Geoff at a network forensics PCAP — twelve megabytes of captured traffic. Hit Find Evil.

The Manager scans the evidence, classifies it as network traffic, and builds an execution plan. Seven playbooks: protocol analysis, DNS mining, connection mapping, string extraction, timeline construction.

Watch the Forensicator work. Each playbook step runs a forensic tool — tshark, strings, bulk_extractor — and the Forensicator interprets the output. It doesn't just dump raw data. It writes analyst notes: what was found, why it matters, what threat indicators are present.

Seventeen steps execute. The Batch Critic reviews every finding — verifying claims, flagging anything unsubstantiated. Zero failures. Zero hallucinations.

---

## SEGMENT 4: Results (3:15-4:30)

**On screen:** Completed report — narrative report scrolling, super timeline, MITRE matrix, git log

**Narration:**
The job completes in under three minutes. Here's what we get.

A narrative report — human-readable, structured, with an executive summary and detailed findings. A super timeline correlating every event across all evidence sources. MITRE ATT&CK mapping if threats are detected.

And here's the git log. Every single action — every tool execution, every agent decision, every file written — is committed with a cryptographic hash. This is your chain of custody. Immutable. Auditable. Court-ready.

---

## SEGMENT 5: What Makes Geoff Different (4:30-5:00)

**On screen:** Architecture diagram — three agents in a loop, git commits flowing, self-healing playbooks

**Narration:**
Three things set Geoff apart.

First, the autonomous agent loop. Manager plans, Forensicator executes, Critic verifies. They self-correct without waiting for a human.

Second, device-centric processing. Geoff classifies evidence by type — disk image, memory dump, PCAP — and selects the right tools automatically. No manual tool selection.

Third, everything is git-backed. Every finding, every report, every intermediate file is version-controlled. You can replay any investigation step-by-step from the git history.

Geoff doesn't replace the forensic analyst. It's the analyst's colleague — the one who never sleeps, never skips a step, and documents everything.

---

## TIMING BREAKDOWN
- Segment 1 (Intro): 30s — 85 words
- Segment 2 (Install): 45s — 95 words
- Segment 3 (Live Run): 120s — 180 words
- Segment 4 (Results): 75s — 120 words
- Segment 5 (Outro): 30s — 95 words
- **Total: 300s (5:00) — ~575 words**
