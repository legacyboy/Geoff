# Geoff DFIR — Accuracy Report

**Date:** 2026-06-14 (updated)  
**Version:** v1.2  

---

## 1. False Positive Incidents

### 1.1 Critic "nonsense" / "invalid_iocs" flags

The Critic is designed to catch findings that are structurally invalid or unsupported by tool output. Observed false positive patterns from the M57-Patents and Data Leakage case runs:

**Incident 1 — `DROP TABLE` classified as SQL injection in host context (2026-05-24)**

During internal audit testing (2026-05-24), the Forensicator produced a finding that classified `DROP TABLE` syntax found in Windows Registry string data as an SQL injection indicator. The registry value was a legitimate software installation string that contained the phrase incidentally. The Batch Critic flagged this as `invalid_iocs` — the finding had no network context, no database process, and no corroborating evidence. The Manager replayed the step with adjusted parameters that filtered registry string extraction for host-context relevance.

*(Traceable in git history: the `COMBINED_AUDIT_REPORT.md` containing the full audit was removed from HEAD in the cleanup commit `951df39` but is accessible via `git show 951df39^:COMBINED_AUDIT_REPORT.md`.)*

**Lesson:** String-extraction-based IOC detection (bulk_extractor, strings) produces false positives when applied to registry or filesystem string data without host context. The Critic's cross-step correlation catches this; per-step validation alone would not.

**Incident 2 — CDN IP ranges flagged as C2 indicators**

Bulk IOC extraction flagged large numbers of well-known CDN IP addresses (Akamai, Cloudflare ranges) as potential C2 communication indicators. Fixed 2026-05-19 (commit `6946547`) with an expanded CDN IP blocklist and URL filtering. The Critic's hallucination check would catch unsupported claims about "C2 communication with CDN IPs" in the Forensicator's analyst note, but the root issue is upstream in the IOC extraction phase.

**Incident 3 — Registry key path false positives in Run key analysis**

PB-SIFT-003 (Persistence) flagged standard Windows Run key entries (Microsoft Teams, Windows Defender) as persistence indicators. Fixed in commit `6946547` (2026-05-19) with a registry key allowlist. Prior to this fix, the Forensicator was producing HIGH-significance findings for standard autorun entries.

---

## 2. Missed Artifacts

The following artifact categories are documented gaps where Geoff either fails silently or produces incomplete findings:

### 2.1 EVTX Parsing Edge Cases

**Prior to 2026-06-01 fix:**
- Multi-block PowerShell Script Block Log events (EventID 4104 with `ScriptBlockId` + `MessageNumber` continuation) were parsed as individual fragments, missing the full decoded script.
- Events with null `Computer` fields caused parser exceptions in python-evtx.
- Corrupt channel names in malformed EVTX files caused EvtxECmd to produce zero output with no error indication.

**Status:** Fixed in the 2026-06-01 commit (part of "EVTX error handling" fix group). Error handling now falls back to python-evtx when EvtxECmd returns malformed output.

**Remaining gap:** Multi-block PowerShell 4104 reassembly (stitching `MessageNumber` fragments into the complete script) is not implemented. This means heavily obfuscated PowerShell commands split across multiple 4104 events may appear as truncated fragments. Known outstanding gaps: encoded command decoding (`certutil -decode`, base64 PowerShell), LOLBin obfuscation patterns (`mshta.exe` with `javascript:` URI, `rundll32.exe` with unsigned DLL), and WMI OBJECTS.DATA persistence parsing.

### 2.2 Memory Dump Classification Edge Cases

**Prior to 2026-06-01 fix:**
- Raw memory dump files (`.img` extension) were misclassified by the evidence inventory as `OTHER` instead of `memory`, causing them to bypass the Volatility playbook trigger.
- PE-injected memory regions (`malfind` output) were classified as `OTHER` in the inventory schema.

**Status:** Fixed in the 2026-06-01 commit. `.mans` files (FTK Imager memory captures) are now classified as memory dumps directly. `.img` files are probed via Volatility `imageinfo` to confirm memory image type before classification.

### 2.3 LOLBin Detection Gaps

The following missing technique coverage was identified in PB-SIFT-010 (Living-off-the-Land) as of 2026-05-03:
- Encoded command decoding (`certutil -decode`, base64 PowerShell) — no automated decoding step
- LOLBin obfuscation patterns (`mshta.exe` with `javascript:` URI, `rundll32.exe` with unsigned DLL)
- WMI OBJECTS.DATA persistence — no `python-cim` or equivalent parsing step

These are technique-without-tool gaps: the playbook identifies the category but doesn't provide a tool command to detect specific patterns.

### 2.4 RAR Archive Handling

Prior to recent fixes, `.rar` archives were never extracted during evidence preprocessing. Files inside `.rar` archives were not analyzed by any playbook. Current status: RAR extraction was not confirmed fixed at the time of this report.

---

## 3. Hallucination Incidents (Documented Critic Catches)

### 3.1 M57-Patents Phase 1 — "File paths as Offsets" (2026-05-27)

**What happened:** During the first real-world M57-Patents investigation run (2026-05-27, case `/mnt/evidence-storage-2/m57-patents_findevil_a36d505e8542`), the Forensicator's Phase 1 inventory analysis was REJECTED by the Critic for hallucination. The Forensicator was claiming that file paths extracted by SleuthKit were "partition offsets" — a factual error. File paths and byte offsets are distinct concepts; the Forensicator was conflating them.

**How it was caught:** The Critic's per-step validation review (phase1_critic_validation.json in the case directory) rejected the entire inventory analysis with verdict `REJECTED` and verdict_reason documenting the specific factual error.

**What happened next:** The pipeline replayed the step. The corrected analysis correctly labeled the SleuthKit `fls` output as file paths and the `mmls` output as partition offsets. The investigation proceeded correctly on 86 disk images.

**Why this matters:** This catch happened on a live 89 GB evidence set, not in testing. The hallucination involved a fundamental confusion between file paths and partition offsets — if uncaught, it would have produced nonsensical findings for all 86 images.

### 3.2 DROP TABLE / SQL Injection Misclassification

Described in §1.1 above. The Forensicator classified incidental registry string data as SQL injection evidence. The Batch Critic caught the cross-context mismatch and flagged it as `hallucination_flag`. The Manager replayed the step.

### 3.3 Confidence Scope Creep in Analyst Notes

The Forensicator occasionally produces analyst notes that escalate significance beyond what tool output supports — e.g., labeling a suspicious executable as CRITICAL based on a single `strings` hit, when the significance should be MEDIUM pending further analysis. The Critic's batch review catches these when they appear as cross-step inconsistencies (a CRITICAL finding in PB-SIFT-001 that no subsequent playbook corroborates).

---

## 4. Evidence Integrity Approach

### 4.1 SHA-256 Chain of Custody (Architectural)

Every completed step commits to a per-case git repository with a custody sidecar at `custody/<step_key>.json`. The sidecar contains:

```json
{
    "step_key": "PB-SIFT-001:sleuthkit:list_files:disk.E01",
    "evidence_file": "/mnt/evidence/disk.E01",
    "evidence_sha256": "abc123...",
    "params_sha256": "def456...",
    "tool_version": "sleuthkit-4.12.1",
    "timestamp": "2026-05-01T14:46:52Z"
}
```

This means any modification to the evidence file after the step ran will produce a SHA-256 mismatch. The custody chain is tamper-evident but **detective, not preventive** — it detects modification, it does not prevent it.

### 4.2 Evidence Path Validation (Architectural)

All evidence paths submitted to Geoff are validated against a strict allowlist before any subprocess is called (`src/geoff_routes.py`). Paths containing shell metacharacters (`;`, `&`, `|`, `` ` ``, `$`, `()`, newlines, `..`) are rejected. This prevents command injection via maliciously named evidence files.

This is a **code-enforced architectural guardrail** — no prompt instruction is involved.

### 4.3 Evidence Non-Modification (Detective, Not Preventive)

Geoff does not mount the evidence directory read-only at the OS level. All tool output goes to `GEOFF_WORK_DIR` (the case directory), not back into the evidence directory. However, if a tool were misconfigured to write into the evidence path, it would not be blocked architecturally.

The SHA-256 custody sidecar detects this after the fact. For competition purposes, the evidence directories were verified unmodified by inspection. A formal hashdeep pre/post comparison is described in `docs/REPRODUCING_RESULTS.md §Post-run spoliation check`.

### 4.4 Spoliation Testing

A hashdeep pre/post protocol is documented in `docs/REPRODUCING_RESULTS.md`. The protocol:

```bash
# Before investigation
hashdeep -rl /path/to/evidence > evidence_before.hash

# Run investigation (Geoff writes to GEOFF_WORK_DIR, not evidence path)
geoff-find-evil /path/to/evidence

# After investigation
hashdeep -rl /path/to/evidence > evidence_after.hash
diff evidence_before.hash evidence_after.hash
# Expected: no differences
```

This test was performed manually during development runs and confirmed no modifications to evidence directories. It is not currently automated in `install.sh` or CI.

---

## 5. Self-Correction Mechanism and Effectiveness

### 5.1 Three Independent Mechanisms

**Mechanism 1 — Per-step deterministic self-heal**

Fast-path handles the most common field errors without LLM involvement:
- `tool_missing`: `sudo apt-get install -y <tool>`, retry
- `mount_error`: adjust mount parameters, retry
- `permission_error`: not healable, mark failed

Effectiveness in development runs: ~80% of tool failures are deterministic (missing tools) and handled by the fast-path without LLM involvement.

**Mechanism 2 — Batch Critic + Manager replay**

After all playbooks complete, the Batch Critic reviews all findings holistically. Hallucination flags and replay candidates trigger incremental replay with Manager-adjusted parameters. Only affected steps re-run; completed steps are skipped (idempotency guard).

Observed self-correction events across documented runs:
- 18 self-corrections on M57-Patents (86 images) — all offset detection fallbacks
- 2 self-corrections on M57-Jean-Real (EWF offset + device discovery)
- 1 self-correction on Hacking Case (C2 detection module fallback)
- 1 hallucination-triggered replay on M57-Patents Phase 1 (Forensicator rejected; step replayed)

**Mechanism 3 — Chat grounding check**

After each chat response, `_self_check_chat_response` (`src/geoff_self_heal.py:900`) verifies the response does not assert claims absent from case context. If unsupported claims are detected, the response is regenerated once with a correction prompt.

### 5.2 Limitations

**The batch Critic does not regenerate the narrative report.** If the Manager approves but the narrative report generation produces hallucinated claims, there is no retry mechanism. The narrative's prohibition on speculation beyond verified evidence is prompt-enforced only.

**The error hash cache can mask healing improvements.** The cache key is `SHA256(module + function + exception_type + stderr_prefix)`. If the same error recurs after a fix is deployed, the cache returns the old HealDecision until manually cleared (`_heal_cache` in `src/geoff_self_heal.py`).

---

## 6. Narrative Generation Self-Check Gap

**This is a known, disclosed limitation — partially mitigated 2026-06-10.**

Chat responses go through an independent grounding check (`_self_check_chat_response`) that verifies responses cite only present-in-context evidence. If the check fails, the response is regenerated once.

Narrative reports (`narrative_report.md`) do **not** go through this structural check. The narrative is generated by `NarrativeReportGenerator.generate()` (`src/narrative_report.py:455`) with a system prompt that:
- Requires every factual claim to cite a specific evidence anchor
- Prohibits speculation beyond verified findings
- Requires "Insufficient evidence to assess" for unsupported sections

These are **prompt-enforced constraints only**. A model that does not follow its system prompt can still produce uncited claims in the narrative report. There is no code path that checks the narrative output against the evidence chain and regenerates if claims are unsupported.

**2026-06-10 mitigation:** The Executive Summary prompt previously contained a destructive instruction that told the LLM to state "no email or phishing indicators were found" when the `email_direct_findings` list was empty — even when phishing evidence existed elsewhere in the report. This caused the M57-Jean executive summary to contradict its own detailed findings (3 spoofed phishing emails were identified in the Email & Phishing section but the Executive Summary claimed none). Fixed by: (a) populating `email_direct_findings` from multiple sources (findings_detail + email_iocs + EMAIL_DIRECT), (b) feeding `email_phishing_indicators` context with spoofed domains and Return-Path mismatches directly to the LLM, and (c) replacing the destructive prompt instruction with a requirement to report actual findings. All commits traceable in git log.

This asymmetry is intentional in the current implementation — narrative regeneration on failure would require either (a) parsing the narrative to extract claims, or (b) a separate Critic pass against the narrative draft. Neither is implemented.

**Impact:** A judge should treat narrative report claims as human-readable summaries subject to prompt-level accuracy constraints, not as structurally-verified facts. All underlying findings in `findings.jsonl` and the evidence chain remain structurally traceable regardless of the narrative quality.

---

## 7. Known Limitations

| Limitation | Category | Impact | Status |
|------------|----------|--------|--------|
| Three mislabeled playbooks (PB-004, PB-011, PB-013) | Content correctness | A judge running privilege escalation gets network device output | Fixed 2026-06-10: (1) PB-SIFT-004 had credential theft tools (lsadump, extract_credentials, extract_sam_users) removed — those belong in PB-SIFT-005. (2) PB-SIFT-011 was incorrectly triggered by PCAP evidence; removed wrong trigger in pipeline, fixed artifact map to PB-SIFT-036. (3) PB-SIFT-013 was mislabeled on FAT recovery findings; reclassified to PB-SIFT-026 (file carving) and PB-SIFT-012 (anti-forensics). |
| Multi-block PowerShell 4104 reassembly | Artifact coverage | Split obfuscated PowerShell appears as fragments | Fixed 2026-06-10: reassembly code existed but was broken — `result["reassembled_scripts"]` assigned to a CompletedProcess object (silently dropped), and the return dict omitted the fields. Fixed to use local vars and included in return value. |
| Narrative self-check gap | Accuracy validation | Narrative claims not structurally verified | Known; partially mitigated 2026-06-10 |
| LOLBin obfuscation decoding | Artifact coverage | Encoded LOLBin commands not decoded automatically | Known; technique-without-tool gap |
| WMI OBJECTS.DATA parsing | Artifact coverage | WMI persistence artifacts not parsed | Known; no `python-cim` integration |
| RAR extraction | Evidence coverage | RAR archives not extracted | Fixed 2026-06-10: added RAR magic byte detection (Rar!\x1a\x07 for v4 and v5+) to _detect_file_type_from_header and added "rar_archive" to extraction dispatch. _extract_archive() already handled RAR via rarfile/unrar. |
| Evidence non-modification prevention | Evidence integrity | OS-level read-only mount not implemented; detective only via SHA-256 | Known; disclosed above |
| Self-heal cache staleness | Self-correction | Cached HealDecisions persist after code fixes | Fixed 2026-06-10: HealCache.get() now enforces a 30-day TTL (entries older than _DEFAULT_TTL_DAYS treated as misses). Set GEOFF_HEAL_CACHE_BUST=1 for immediate manual bust. Override TTL with GEOFF_HEAL_CACHE_TTL_DAYS=N. |
| Installer tool gaps (20+ tools) | Installation | Missing tools auto-installed on demand; requires internet | Documented; self-heal mitigates |
| JA3/JA3S TLS fingerprinting | Network analysis | No JA3 hash extraction from PCAP | Fixed 2026-06-10: added network.extract_tls_fingerprints (tshark ja3/ja3s fields) to PB-SIFT-036 (PCAP Network Forensics). Already present in PB-SIFT-019 (C2). |

---

## 8. Report Suppression Incident (2026-06-10)

### 8.1 What Happened

A four-case batch run (jeanm57, dfrws2008, google-drive-case, network-forensics) completed all investigations successfully but produced **zero narrative reports**. Every case's `manager_decision.json` contained `"generate_report": false` despite `action: approve`.

**Root cause chain:**
1. Volatility memory forensics tools were being executed against E01 disk images (a tool-to-evidence mismatch)
2. Per-step critics correctly flagged these as `REJECTED` — volatility cannot analyze disk images without a memory dump
3. A "Critic hard gate" (commit `f6cbe5a8`, 2026-06-02) was designed to block report generation when any step had unresolved critic flags — intended as a quality safeguard
4. The hard gate triggered on every case because every E01-based investigation hit volatility-on-disk-image rejections
5. The Manager LLM inherited `sufficient_for_report: False` from the batch critic assessment and returned `generate_report: false` — even when it correctly chose `action: approve`

**The bug:** `action: approve` and `generate_report: false` is a contradiction. Approval means the investigation produced sufficient evidence to report on. The hard gate conflated "tool had issues" with "investigation had no evidence".

### 8.2 How It Was Caught

Manual inspection of case directories revealed every `manager_decision.json` had `generate_report: false`. The batch critic assessment files showed all 4 cases rated `POOR` quality with `sufficient_for_report: False`, driven entirely by volatility-on-disk rejections — not by absence of actual findings. The jeanm57 case had found 3 spoofed phishing emails but couldn't report them.

### 8.3 Resolution

The `_manager_post_critic_decision()` function was changed to unconditionally generate reports. The manager can still flag or replay steps for quality, but suppression now requires explicit action. A `_TOOL_EVIDENCE_COMPAT` guard was added to the playbook execution loop preventing volatility tools from even attempting disk-only images, registry tools from running on PCAPs, and network tools from targeting disk images — eliminating the critic rejections at their source rather than suppressing their downstream effects.

### 8.4 Lesson

Quality gates that suppress output are dangerous when their triggers are noisy. The critic hard gate was correct in intent but wrong in execution — it blocked legitimate outputs because borderline tool failures looked identical to investigation failures. The fix addresses both the gate (always generate reports) and the noise source (prevent mismatched tool-evidence pairings).

---

## 9. Executive Summary — Phishing Contradiction (2026-06-10)

### 9.1 What Happened

The M57-Jean-Real investigation correctly identified **3 spoofed phishing emails** (from `alison@m57.biz` and `tuckgorge@gmail.com`, relayed via `xy.dreamhostps.com`, MITRE T1566.002 Spearphishing Link) in the detailed Email & Phishing section of the narrative report. However, the Executive Summary stated: *"No direct email findings (e.g., targeted phishing campaigns) were flagged."*

This is a **contradiction within the same report** — the detailed findings proved phishing existed, the summary claimed it didn't. A judge reading only the Executive Summary would conclude the case found nothing.

### 9.2 Root Cause

The `_generate_executive_summary()` function built its email context from `findings_detail` entries filtered for `playbook == "EMAIL_DIRECT"`. However, EMAIL_DIRECT findings are stored in `findings.jsonl` but not propagated to the `findings_detail` list within `find_evil_report.json`. The filter returned an empty list. The LLM prompt then contained an explicit instruction:

> *"CRITICAL RULE: If the email_direct_findings list is empty, state clearly that no email or phishing indicators were found."*

The LLM obeyed. The phishing evidence existed elsewhere in the report — the LLM was just explicitly told it didn't.

### 9.3 Resolution

The email context was rebuilt to pull from multiple sources: `findings_detail`, `email_iocs` from `find_evil_report.json`, and `email_direct_findings`. A new `email_phishing_indicators` context object (with spoofed domains, Return-Path mismatches, email counts, and phishing detection flags) was fed directly to the LLM. The destructive prompt instruction was replaced with a requirement to report whatever the data shows. The report was regenerated and now correctly states: *"Email spoofing confirmed — 3 emails identified with Return-Path mismatch between gmail.com/m57.biz and xy.dreamhostps.com."*

### 9.4 Lesson

Prompt instructions that tell the LLM what to say about the *absence* of data are dangerous when the data the instruction checks is incomplete. The instruction should have been about what the data *does* show, not about what it *doesn't*. The fix inverts the logic: show the LLM everything you have, tell it to report what's there.

---

## 10. IOC Relevance — String Extraction Noise (2026-06-14)

### 10.1 What Happened

During the hacking-case investigation (NIST CFReDS), the narrative report claimed **528 URLs** and **197 email addresses** were extracted as IOCs. Manual inspection revealed both numbers were hallucinated by the narrative LLM — the actual aggregate from `findings.jsonl` was **6,855 URLs** and **3,090 emails**. However, the real numbers are arguably worse: 6,855 "URLs" from string extraction on a disk image is functionally useless to an investigator.

### 10.2 Root Cause — Two Bugs

**Bug 1 — Narrative hallucination:** The narrative report generator (`narrative_report.py`) fabricated IOC counts instead of aggregating from the findings data. The LLM was prompted with summary context but not the actual IOC totals, so it invented plausible-sounding numbers (528, 197) that were wrong in both directions.

**Bug 2 — No relevance gate on IOC extraction:** PB-SIFT-009 (String Extraction & IOC Pattern Matching) runs `strings` on extracted files, then applies regex patterns for URLs, emails, IPs, and file paths. Every match is recorded as an IOC with zero context filtering. A URL to `http://www.ethereal.com` in a help file, an email address in a DLL copyright string, and `C:\WINDOWS\system32\mspaint.exe` as a file path are all treated identically to actual C2 infrastructure. The result is thousands of "IOCs" where 99.9% are benign artifacts of the operating system and installed software.

**What makes an actual IOC:**
- Appears in a suspicious context (malware strings, injected process, C2 channel)
- Tied to a known threat (threat intel feed match)
- Anomalous for the environment (unusual domain, foreign TLD, encoded/obfuscated)
- Temporally correlated with the attack timeline

Geoff's current implementation does none of these. It is pattern-matching without relevance triage.

### 10.3 Impact

- Investigators receive thousands of false positive "IOCs" with no way to distinguish signal from noise
- The narrative report either hallucinates counts or reports useless aggregates
- A judge or reviewer seeing "6,855 URLs extracted" gets no actionable intelligence
- The IOC extraction step consumes processing time and LLM inference budget producing valueless output

### 10.4 Required Fix

PB-SIFT-009 needs a relevance gate before recording an IOC. Options:
1. **LLM triage:** Feed extracted strings to the Forensicator for contextual relevance assessment ("Is this URL likely related to the incident or is it a benign software artifact?")
2. **Threat intel cross-reference:** Check extracted domains/URLs against known threat feeds (OTX, MISP, URLhaus) — only record matches
3. **Context-aware extraction:** Only extract IOCs from files in suspicious locations (temp dirs, AppData, browser caches, email attachments) rather than every file on disk
4. **Deduplication + ranking:** Deduplicate across all extracted files and rank by frequency/anomaly score — surface the top N rather than all 6,855

### 10.5 Interim Mitigation

The hacking-case narrative report was manually corrected on 2026-06-14 to replace hallucinated counts with actual aggregate numbers. This is a stopgap — the underlying extraction and reporting bugs remain.

---

## 11. Evidence Caps Audit (2026-06-10)

### 10.1 What Was Found

A line-by-line audit of the email and communications evidence pipeline (`geoff_pipeline.py`, `sift_specialists_extended.py`, `geoff_communications.py`, `narrative_report.py`) discovered **14 separate data truncation caps**. Key findings:

| Cap | Impact |
|-----|--------|
| `eml_files[:500]` in phishing detection | Emails 501+ silently skipped for phishing analysis |
| `body_text[:2000]` in detect_phishing | Email bodies truncated at 2,000 characters — content beyond was invisible to phishing heuristics |
| `body_excerpt[:200]` in IOC regex scanner | IOCs appearing after character 200 in any email body were never detected |
| `from/to/return_path[:30]` | If a PST had 31+ unique senders, the 31st was silently dropped from the IOC record |
| `messages[:200]` in geoff_communications.py | All communications output capped at 200 messages total — anything beyond unrecoverable |
| 8 additional caps on SMTP/IMAP/IRC body text and TCP stream enumeration | Progressive data loss at every layer of the communications pipeline |

### 10.2 Evidence Deletion

The `_direct_email_extraction()` finally block was previously deleting all extracted EML/PST files after processing (`shutil.rmtree(extract_dir)`). The structured data survived in findings.jsonl, but the raw extracted evidence was unrecoverable for audit or review.

### 10.3 Resolution

All 14 caps removed. Extracted evidence is now copied to `case_work_dir/extracted_emails/<stem>/` before temp directory cleanup. Spoofed email mismatch records now include `body_text`, `subject`, and `to` fields (previously missing, causing blank content in the report's spoofing section).

---


## 12. Self-Heal Failure Analysis (2026-06-13)

### 12.1 REMnux Self-Heal

During the hacking-case investigation (fe-2f1f1356ebeb), two self-heal events fired for REMnux tools:

| Playbook Step | Self-Heal Attempt | Fix Type | Confidence | Outcome |
|---------------|-------------------|----------|------------|---------|
| `remnux.inetsim_check` | LLM-driven | `retry_params` — blamed wrong evidence segment (.E02 instead of .E01) | 9/10 | FAILED |
| `remnux.fakedns_check` | LLM-driven | `fallback_tool` — claimed "incompatible with raw EnCase evidence file segments" | 8/10 | FAILED |

Both tools were installed on the system at the time:
- `inetsim` at `/usr/bin/inetsim` (apt package version 1.3.2)
- `fakedns` at `/home/sansforensics/.local/bin/fakedns` (Python script)

The self-heal incorrectly diagnosed both failures as evidence-path issues (wrong E01 split segment, incompatible file format). The actual root cause was that the `remnux_orchestrator` singleton within the pipeline was `None` — the pipeline's REMnux module lacks a local fallback path that invokes the installed tools directly.

### 12.2 Impact

Each failed self-heal consumed ~120 seconds attempting `sudo apt-get install inetsim` and `pip3 install fakedns` before timing out. This added 4+ minutes of dead time per evidence device. The self-heal LLM wasted inference budget on a tool-provisioning problem it couldn't solve.

### 12.3 Resolution

The erroneous `_TOOL_INSTALL_CMDS` entries for `inetsim` and `fakedns` were removed from `geoff_self_heal.py` in commit `d0f0bc45`. The tools remain on the system — the self-heal no longer wastes time trying to re-install them.

### 12.4 Lesson

The self-heal system needs a **verification step** before attempting fixes. The LLM confidently hallucinated root causes (9/10 and 8/10 confidence scores) because it was prompted to diagnose from evidence metadata (E01 split segment extensions, file types) rather than checking whether the tool exists on the system first. A pre-flight check (`which inetsim && which fakedns`) would have shown both tools present and redirected the self-heal to a plumbing fix instead of an install fix.

---


## 13. Known Limitations (continued)

---

*This report was produced from direct inspection of the Geoff codebase, case run artifacts on the development NAS, and the internal audit documentation that was in git HEAD prior to the 2026-06-01 cleanup commit. Updated 2026-06-10 with new incident reports, caps audit, and philosophy section. All incidents cited are traceable to specific commits, case directories, or file paths referenced above. All §§8-10 incidents were discovered, diagnosed, and fixed during the 2026-06-10 testing session; a five-case batch run is currently executing with all fixes active.*
