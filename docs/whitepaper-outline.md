# GEOFF: A Multi-Agent Self-Validating Pipeline for Autonomous Digital Forensic Triage

**Working white paper outline.** Section headers, the argument each section needs to make, and a list of the figures/tables that should appear. Bracketed `[TODO]` markers flag content the codebase doesn't yet support and that would have to be produced before submission.

---

## Abstract (~250 words, last to write)

One sentence problem. One sentence approach. One sentence on the three novel contributions (multi-agent pipeline, evidence chain, behavioral analysis replacing YARA). One sentence on the empirical result — needs evaluation numbers from § 6 before this can be written. One sentence positioning vs SIFT and SOAR.

---

## 1. Introduction

- DFIR triage today: an analyst with SIFT, a stack of evidence, and a multi-day backlog. State the bottleneck — interpretation, not tool execution.
- Existing automation (SOAR playbooks, YARA scans, commercial triage suites) addresses execution but not interpretation, and offers no traceability between a finding and the artifact it came from.
- Contribution claim — restate the eight items from the README's "Novel Contribution" section in the form of a numbered list, ranked by importance:
  1. Three-agent pipeline (Manager / Forensicator / Critic) with self-correction.
  2. Per-finding evidence chain with required citation in the narrative report.
  3. Behavioral-analysis engine replacing YARA signature matching.
  4. Anti-forensics confidence cascade.
  5. Device-centric evidence model with cross-device correlation.
  6. 25-playbook MITRE ATT&CK execution engine with mandatory triage entrypoint.
  7. Git-backed reproducibility per case.
  8. LLM-generated narrative report grounded in the evidence chain.
- Figure 1: end-to-end pipeline diagram (already in README; convert to TikZ or vector).

---

## 2. Threat Model and Scope

- **In scope.** Post-incident analysis of acquired evidence — disk images, memory dumps, pcaps, log archives, mobile backups. Goal: surface MITRE ATT&CK techniques, build a kill chain, ground every claim in a specific artifact.
- **Out of scope.** Live response, EDR/XDR replacement, malware reverse engineering beyond static metadata.
- **Trust boundaries.**
  - Evidence is untrusted. Mitigations: shell-metacharacter rejection, `Path.relative_to` containment, no `shell=True`, content-based file-type sniffing rather than extension trust.
  - LLM output is untrusted. Mitigations: Critic re-validation, IOC format checks, grounding check on chat responses, anti-forensics cascade as a confidence dampener.
  - Local network is the auth boundary for the MCP server (binds to 127.0.0.1; SSH tunnel for remote analysts).
- **Adversarial scenarios** the design defends against:
  - Anti-forensics cascade catches log-clearing / timestomp / sdelete artifacts that would otherwise produce false-confident findings.
  - Critic catches LLM hallucinations — the empirical hallucination rate goes here once measured.
- Table 1: trust-boundary matrix — actor × asset × mitigation.

---

## 3. Architecture

### 3.1 The three-agent pipeline

- Manager: planning, execution-plan approval, self-correction prompt generation.
- Forensicator: tool-output interpretation, threat-significance assessment, evidence chain construction.
- Critic: hallucination detection, IOC format validation, structural sanity.
- Why three agents instead of one: separation of "what does this output mean" (Forensicator) from "is that interpretation grounded in the raw output" (Critic) lets us re-prompt only the interpretation when it fails, without invalidating planning state.
- Figure 2: data flow showing Forensicator output → Critic → either commit-to-git or self-correction loop.

### 3.2 Evidence chain (per-finding traceability)

- Schema of the evidence chain dict (artifact, evidence_file, tool, playbook, significance, analyst_note, threat_indicators).
- Why structured citation matters: the narrative report's attack chain synthesis requires every factual claim to cite a specific anchor, which prevents the report from drifting into ungrounded plausible-sounding prose.
- Figure 3: an example chain from disk-image → fls inode → forensicator note → narrative citation.

### 3.3 Device-centric processing

- Evidence is grouped by device, not by file type. Per-device playbook execution, per-device behavioral analysis, then cross-device correlation.
- Discovery strategy: directory structure → hostname extraction (SYSTEM hive ComputerName, Linux `/etc/hostname`, iOS Info.plist) → username merge with normalization (strip domain, lowercase) → fallback to evidence filename stem.
- Output: `device_map.json` and `user_map.json`. Both JSON-serializable, both committed to per-case git history.

### 3.4 Behavioral analysis (replacing YARA)

- Ten deterministic checks (process path, spawn chains, network anomalies, timestomp, beaconing, persistence-to-temp, off-hours clustering, typosquatting, temp-dir executables, registry Run keys).
- Each flag carries severity + MITRE technique + supporting evidence dict.
- Why behavioral over signatures: signatures generalize poorly across malware families; behavior is what the kill chain requires regardless of payload identity.

### 3.5 Anti-forensics cascade

- PB-SIFT-012 detects log-clear / timestomp / sdelete / wevtutil indicators using word-boundary matched keyword search and a structured `anti_forensics_detected` field.
- On detection, every existing finding is downgraded one confidence step (CONFIRMED → POSSIBLE → UNVERIFIED) and tagged `compromised_by: ["anti-forensics"]`.
- The cascade is idempotent (re-application is a no-op once the tag is present), and runs again as a final pass after the playbook loop ends so findings produced by playbooks scheduled after PB-SIFT-012 are also caught.

### 3.6 Reproducibility

- Per-case git repository, every playbook completion committed.
- `findings.jsonl` streamed to disk so OOM is bounded.
- `audit_trail.jsonl` records six event types: `case_init`, `playbook_complete`, `self_correction`, `unverified`, `anti_forensics_cascade`, `find_evil_complete`.
- The case directory is the chain of custody: independent re-runs from the same evidence + same model versions should land on a comparable narrative report; we measure this in § 6.4.

---

## 4. Implementation

- ~6,000 lines of Python (`src/geoff_integrated.py` is the orchestrator, with specialist modules for SleuthKit, Volatility, RegRipper, Plaso, Zimmerman, REMnux, mobile, browser, email, macOS).
- Three deployment surfaces from the same orchestrator:
  - CLI (`bin/geoff-find-evil`) for offline batch use.
  - Flask web UI on `:8080`.
  - MCP server for AI-client integration (Claude Desktop, custom agents) over HTTP+SSE on `:9999`.
- Cloud / local model profile switch via `GEOFF_PROFILE`.
- Auth: optional `GEOFF_API_KEY`, constant-time compared via `hmac.compare_digest`.
- Tested at 354 unit tests across 12 test files; not a coverage metric, but a regression-baseline metric.

---

## 5. Related Work

- **SIFT Workstation.** The runtime substrate. Provides tools, not interpretation.
- **Plaso / log2timeline.** Super-timeline construction from heterogeneous sources. We use it; we add per-finding citation.
- **YARA / sigma rules.** Static signature matching. We argue behavioral analysis is the right primitive for kill-chain reconstruction.
- **SOAR platforms (Splunk SOAR, Cortex XSOAR).** Playbook execution. Different goal — ticketing/orchestration, not forensic interpretation.
- **LLM agents for security.** Recent work on LLM red teaming and SOC-assistant agents. Position Geoff as DFIR-specific and ground-truth-anchored via the evidence chain.
- **Reproducible computational research.** Position the per-case git repo and audit trail as borrowing from the reproducible-research literature (Kanwal et al., Stodden et al.).

---

## 6. Evaluation `[TODO — this is the gap; below is the design we'd run]`

The evaluation needs to support three claims: (1) Geoff matches an expert SIFT workflow on technique recall, (2) the Critic catches LLM hallucinations at a measurable rate, (3) the anti-forensics cascade reduces false-confident findings. None of this exists in the codebase yet — these are the experiments that have to be run.

### 6.1 Datasets `[TODO]`

- Public DFIR datasets — candidates: NIST CFReDS, DFRWS Rodeo, Magnet weekly CTF cases, CFReDS hacking cases. Pick 5-10 cases covering varied attack patterns (ransomware, lateral movement, insider, web shell).
- Ground truth: published walkthroughs.

### 6.2 Baselines `[TODO]`

- B1: vanilla SIFT analyst workflow — assume an analyst runs the same SIFT tools (SleuthKit, Volatility, Plaso, RegRipper) and produces a written report. Approximate this from the published walkthroughs.
- B2: SIFT + YARA + sigma — same but with signature-based detection bolted on.
- B3: Geoff with single-agent (Manager only, no Critic) ablation — measures the contribution of the Critic.
- B4: full Geoff three-agent pipeline.

### 6.3 Metrics `[TODO]`

- **Technique recall.** Of the MITRE techniques present in the case ground truth, what fraction does each system surface?
- **Technique precision.** Of techniques claimed, what fraction are in the ground truth?
- **Citation grounding rate.** Of factual claims in Geoff's narrative report, what fraction map to a specific evidence-chain anchor that an analyst can verify? (Sample 50 claims per case, expert-verify.)
- **Hallucination rate.** Of Forensicator interpretations, what fraction did the Critic reject? Of those, what fraction would have been wrong? (Manual audit on a sample.)
- **Wall-clock time.** Geoff vs an analyst's reported triage time.
- **Reproducibility.** Run Geoff three times on the same case; measure overlap of techniques surfaced and key evidence anchors.

### 6.4 Ablation studies `[TODO]`

- Critic on vs off — does precision drop measurably without the Critic?
- Anti-forensics cascade on vs off — on cases that contain anti-forensics indicators, does the cascade reduce false-confident CONFIRMED findings?
- Behavioral analyzer vs YARA — on cases with novel-strain malware, does behavioral analysis catch it and YARA miss it?
- Cloud vs local model profile — does the local 14B/32B profile reach the same conclusions as the cloud profile? Measure agreement on technique list.

### 6.5 Threats to validity `[TODO]`

- Public DFIR datasets are curated and may not represent the messiness of real cases.
- Ground truth is the published walkthrough, which is itself analyst-produced; "Geoff agrees with the walkthrough" is not the same as "Geoff is correct."
- LLM non-determinism — every result needs N≥3 runs and a confidence interval.

---

## 7. Discussion

- **Where Geoff helps.** First-pass triage on backlogs, junior analyst training (the narrative report shows the reasoning), reproducibility audits, multi-device cases where cross-correlation is the bottleneck.
- **Where Geoff doesn't.** Novel malware reverse engineering, attribution, anything requiring a court-room expert testimony — the Critic + grounding mitigate but don't eliminate hallucination risk.
- **Cost.** Cloud profile: ~1-3 cents per finding at current Anthropic / DeepSeek pricing for the volumes seen on the test cases. Local profile: GPU-bound, no per-token cost.
- **Honest limitations.**
  - Mobile coverage is iOS/Android backups; live extraction is not implemented.
  - The Critic is itself an LLM; we mitigate with structural checks (IOC format, schema validation) but a sufficiently confident wrong Forensicator + permissive Critic will produce a wrong-and-confident finding.
  - The anti-forensics cascade is keyword-driven; an attacker who clears logs without leaving the keywords (e.g. via a custom binary) won't trigger it.

---

## 8. Conclusion

One paragraph. Restate the contribution. Restate the empirical result (filled in once § 6 is done). Point to the open-source release.

---

## Appendices

- **A. Playbook catalogue.** Table of all 25 PB-SIFT playbooks with MITRE phase, trigger condition, and step count.
- **B. Specialist coverage.** Table of forensic-tool specialists with the underlying tools they wrap.
- **C. Schemas.** Evidence chain dict, finding record, audit trail event types.
- **D. Case directory layout.** Tree diagram with file purposes.
- **E. Reproducing the evaluation.** Hash-verified dataset URLs, model versions used (cloud + local), exact command lines, expected output hashes.

---

## Submission targets, by fit

- **USENIX Security / Usenix Enigma** — strong fit if the evaluation lands an interesting hallucination-rate or reproducibility result.
- **DFRWS / DFRWS-EU** — natural fit (forensics audience), lower bar on novelty in the ML side.
- **ACSAC** — applied security, system papers welcome.
- **arXiv first**, peer-reviewed venue second — given the hackathon timeline (April-June 2026 per README), an arXiv preprint with the evaluation numbers is the fastest path to citation.

---

## What's blocking submission today

1. **Evaluation section is empty.** All eight novelty claims rely on it. Estimated effort: 2-4 weeks of someone running cases and tabulating, plus the LLM cost.
2. **No baseline comparison code.** Need a script that takes a case and produces "vanilla SIFT analyst would have done X" — most likely by parsing the published walkthrough.
3. **Dataset choice.** Pick 5-10 cases up front and lock them in; otherwise the evaluation drifts.
4. **Author list, affiliations, IRB.** Out of scope here but needed before submission.
