# Geoff DFIR — Accuracy Report

**Date:** 2026-06-01  
**Version:** v1.0 (tagged at competition-submission HEAD)  
**Purpose:** Judge-facing structured assessment of Geoff's accuracy, self-correction effectiveness, evidence integrity approach, and known limitations.

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

**This is a known, disclosed limitation.**

Chat responses go through an independent grounding check (`_self_check_chat_response`) that verifies responses cite only present-in-context evidence. If the check fails, the response is regenerated once.

Narrative reports (`narrative_report.md`) do **not** go through this structural check. The narrative is generated by `NarrativeReportGenerator.generate()` (`src/narrative_report.py:455`) with a system prompt that:
- Requires every factual claim to cite a specific evidence anchor
- Prohibits speculation beyond verified findings
- Requires "Insufficient evidence to assess" for unsupported sections

These are **prompt-enforced constraints only**. A model that does not follow its system prompt can still produce uncited claims in the narrative report. There is no code path that checks the narrative output against the evidence chain and regenerates if claims are unsupported.

This asymmetry is intentional in the current implementation — narrative regeneration on failure would require either (a) parsing the narrative to extract claims, or (b) a separate Critic pass against the narrative draft. Neither is implemented.

**Impact:** A judge should treat narrative report claims as human-readable summaries subject to prompt-level accuracy constraints, not as structurally-verified facts. All underlying findings in `findings.jsonl` and the evidence chain remain structurally traceable regardless of the narrative quality.

---

## 7. Known Limitations

| Limitation | Category | Impact | Status |
|------------|----------|--------|--------|
| Three mislabeled playbooks (PB-004, PB-011, PB-013) | Content correctness | A judge running privilege escalation gets network device output | Known; disclosed; not fixed |
| Multi-block PowerShell 4104 reassembly | Artifact coverage | Split obfuscated PowerShell appears as fragments | Known; not implemented |
| Narrative self-check gap | Accuracy validation | Narrative claims not structurally verified | Known; disclosed above |
| LOLBin obfuscation decoding | Artifact coverage | Encoded LOLBin commands not decoded automatically | Known; technique-without-tool gap |
| WMI OBJECTS.DATA parsing | Artifact coverage | WMI persistence artifacts not parsed | Known; no `python-cim` integration |
| RAR extraction | Evidence coverage | RAR archives not extracted | Known; not confirmed fixed |
| Evidence non-modification prevention | Evidence integrity | OS-level read-only mount not implemented; detective only via SHA-256 | Known; disclosed above |
| Self-heal cache staleness | Self-correction | Cached HealDecisions persist after code fixes | Known; requires manual cache clear |
| Installer tool gaps (20+ tools) | Installation | Missing tools auto-installed on demand; requires internet | Documented; self-heal mitigates |
| JA3/JA3S TLS fingerprinting | Network analysis | No JA3 hash extraction from PCAP | Known; technique-without-tool gap |

---

*This report was produced from direct inspection of the Geoff codebase, case run artifacts on the development NAS, and the internal audit documentation that was in git HEAD prior to the 2026-06-01 cleanup commit. All incidents cited are traceable to specific commits, case directories, or file paths referenced above.*
