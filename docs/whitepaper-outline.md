# GEOFF: A Multi-Agent Self-Validating Pipeline for Autonomous Digital Forensic Triage

**Working white paper outline.** Section headers, the argument each section needs to make, and a list of the figures/tables that should appear. Bracketed `[TODO]` markers flag content the codebase doesn't yet support and that would have to be produced before submission.

---

## Abstract (~250 words, last to write)

One sentence problem. One sentence approach. One sentence on the three novel contributions (multi-agent pipeline, evidence chain, behavioral analysis replacing YARA). One sentence on the empirical result — needs evaluation numbers from § 6 before this can be written. One sentence on the evaluation: Geoff matches or exceeds manual SIFT analyst findings on public DFIR datasets, with measurable hallucination rate.

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

- **Manual DFIR practice.** The dominant approach — an experienced analyst with SIFT/EnCase/FTK, working evidence by evidence, writing findings by hand. No automation of interpretation. This is our primary comparison point (§ 6).
- **SIFT Workstation.** The runtime substrate. Provides tools, not interpretation. Geoff automates the SIFT workflow end-to-end.
- **Plaso / log2timeline.** Super-timeline construction from heterogeneous sources. We use it; we add per-finding citation and behavioral flagging on top.
- **LLM agents for security.** PentestGPT, TaskWeaver, AutoGPT-for-IR. These generalize across security tasks; Geoff is DFIR-specific and ground-truth-anchored via the evidence chain.
- **Reproducible computational research.** Per-case git repo and audit trail borrow from the reproducible-research literature (Kanwal et al., Stodden et al.).

---

## 6. Evaluation `[TODO — this is the gap; below is the design we'd run]`

The evaluation answers one question: **Does Geoff find what a human analyst would find, and does it invent things that aren't there?** We compare Geoff directly against manual SIFT investigations — the same tools, the same evidence, the same ground truth.

### 6.1 Datasets `[TODO]`

Public DFIR datasets with published walkthroughs that serve as ground truth:
- NIST CFReDS hacking case (already in evidence pool)
- NIST CFReDS data leakage case (already in evidence pool)
- M57 Jean phishing case (already in evidence pool)
- DFRWS 2017 IoT challenge (already downloaded)
- Magnet CTF weekly cases (2-3 selected for coverage)

Each case must have a published walkthrough or expert-produced findings list that constitutes ground truth.

### 6.2 Baseline: Manual SIFT Investigation `[TODO]`

For each case, the baseline is a human analyst working the same evidence with SIFT tools (SleuthKit, Volatility, Plaso, RegRipper, Zimmerman tools). Ground truth is derived from:
- Published case walkthroughs (CFReDS, DFRWS, Magnet)
- Where walkthroughs are unavailable, an experienced analyst produces findings independently

The comparison is apples-to-apples: same tools, same evidence, same MITRE technique taxonomy.

### 6.3 Metrics

| Metric | Definition |
|--------|------------|
| **Finding recall** | % of ground-truth findings that Geoff surfaces |
| **Finding precision** | % of Geoff's findings that match ground truth |
| **False positive rate** | Geoff findings not in ground truth / total Geoff findings |
| **Hallucination rate** | Geoff claims with no evidence-chain anchor (invented artifacts) / total Geoff claims |
| **Time to triage** | Geoff wall-clock vs analyst's reported or estimated triage time |
| **Narrative quality** | Blind expert rating (1-5) comparing Geoff's report to the analyst's, on completeness, accuracy, and actionability |

### 6.4 Methodology

1. Run Geoff on each case (N≥3 runs per case to measure reproducibility)
2. Extract Geoff's findings, map each to MITRE ATT&CK technique
3. Compare against ground truth: count matches (TP), missed findings (FN), invented findings (FP), and ungrounded claims (hallucinations)
4. For narrative quality: present Geoff's report and the analyst's report (anonymized, randomized order) to 2-3 experienced DFIR analysts for blind rating
5. Report mean and 95% CI across all cases for each metric

### 6.5 Threats to validity `[TODO]`

- Public DFIR datasets are curated and may not represent the messiness of real cases.
- Ground truth is the published walkthrough, which is itself analyst-produced; "Geoff agrees with the walkthrough" is not the same as "Geoff is correct."
- LLM non-determinism — every result needs N≥3 runs and a confidence interval.
- The Critic is itself an LLM; we mitigate with structural checks (IOC format, schema validation) but a sufficiently confident wrong Forensicator + permissive Critic will produce a wrong-and-confident finding.
- The anti-forensics cascade is keyword-driven; an attacker who clears logs without leaving the keywords (e.g. via a custom binary) won't trigger it.

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

1. **Evaluation section is empty.** All novelty claims rely on it. Estimated effort: 2-4 weeks of running cases and tabulating findings against ground truth, plus LLM cost.
2. **Ground truth walkthroughs.** Need to formalize findings for each dataset case into a structured MITRE-mapped list that Geoff's output can be compared against.
3. **Dataset choice.** Pick 5-10 cases up front and lock them in; otherwise the evaluation drifts.
4. **Author list, affiliations, IRB.** Out of scope here but needed before submission.
