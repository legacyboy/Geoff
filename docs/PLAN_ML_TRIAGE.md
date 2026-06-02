# ML-Driven Triage Ranking — Technical Plan

**Status:** Draft  
**Scope:** Scoring and ranking findings by likelihood of being malicious so the analyst sees the most important evidence first in every report, on **every case from the first run** — no training data, no cold-start problem.

---

## Core Design Principle

Geoff must work out of the box on case zero. The analyst deploys, runs a case, gets a report sorted by relevance — no prior data needed. This means the approach is **LLM-based zero-shot scoring**, not supervised learning.

The `significance` field (CRITICAL/HIGH/MEDIUM/LOW/NONE) already exists in every finding from `GeoffForensicator.interpret_result()`. The gap is ordering: the report renders findings in playbook execution order. The fix is to sort by significance + a few deterministic rules before rendering.

Training a classifier requires labeled data from past cases. That's a future enhancement, not a requirement for MVP.

---

## Approach: LLM-Powered Zero-Shot Scoring

### What already exists

Every step record has:
```json
{
  "playbook": "PB-SIFT-008",
  "step_key": "PB-SIFT-008:sleuthkit:list_files:disk.E01",
  "status": "completed",
  "result": { ... raw specialist output ... },
  "annotations": {
    "significance": "HIGH",
    "threat_indicators": ["svchost.exe spawning cmd.exe"],
    "follow_up_needed": true,
    "analyst_note": "Memory process list shows svchost.exe spawning cmd.exe"
  }
}
```

The Forensicator assigns significance per-step. The batch Critic already reviews all findings together and produces a holistic assessment. Neither is used for reordering the report.

### What to change (minimal)

**1. Sort findings by significance before rendering**

In `narrative_report.py:NarrativeReportGenerator.generate()` — after all findings are collected but before the markdown template is populated, sort the findings list by significance weight:

```
SIGNIFICANCE_WEIGHT = {
    "CRITICAL": 100,
    "HIGH": 75,
    "MEDIUM": 50,
    "LOW": 25,
    "NONE": 0
}
```

Steps sorted descending. Steps with equal weight ordered by playbook number (PB-000 before PB-001), preserving tool-install/logistical steps at their natural position.

**2. Significance boost rules (deterministic)**

Before sorting, apply simple rule-based boosts to the significance weight:

| Rule | Boost | Example |
|------|-------|---------|
| Step returned `anomalous_process` field | +25 | Process chain detection |
| Step returned `yara_hits` > 0 | +30 | Malware scan |
| Step returned `infected_files` > 0 | +40 | Malware confirmed |
| Step returned `known_malicious_hashes` > 0 | +50 | Hash match |
| Step is a `skipped` or `failed` | -50 | No useful output |
| Step was `self_healed` and outcome is available | +0 | Already handled |
| Step found `suspicious_connections` | +25 | Network indicator |
| Inference confidence from Forensicator | +0 to +20 | LLM confidence signal |
| Finding relates to credential extraction | +15 | High-value IOC |
| Finding relates to rootkit detection | +35 | Critical IOC |

These rules examine the raw `result` dict keys and values. No LLM call needed — pure Python checks in `_compute_step_priority()`.

**3. Section-level significance**

In addition to per-step scoring, each playbook section accumulates a section score (max of its step scores). Sections with higher max scores float to the top of the report. This groups related high-significance findings together (e.g., all memory analysis findings for injected code appear before all file listings).

### Implementation plan

**Files to modify:**

- `src/narrative_report.py` — add `_compute_step_priority()` that returns a weight for each step, and `_sort_findings_by_priority()` that sorts the findings list by that weight. Call before markdown generation.

**Function signatures (approximate):**

```python
def _compute_step_priority(self, step_record: dict) -> int:
    """Compute a priority score (0-150) for a single step record.
    Uses step annotations + result content + deterministic rule checks.
    No LLM calls."""
    weight = SIGNIFICANCE_WEIGHT.get(
        step_record.get("annotations", {}).get("significance", "NONE"), 0
    )
    result = step_record.get("result", {})
    
    # Keyword-based boosts
    if result.get("yara_hits"):
        weight += 30
    if result.get("known_malicious_hashes"):
        weight += 50
    if result.get("infected_files"):
        weight += 40
    if result.get("suspicious_connections"):
        weight += 25
    if step_record.get("status") in ("skipped", "failed"):
        weight -= 50
    
    return max(0, weight)


def _sort_findings_by_priority(self, organized_findings: dict) -> dict:
    """Sort within and between playbook sections by priority score."""
    # Compute section max score, sort sections descending
    # Within each section, sort steps descending
    return sorted_findings
```

**No new files.** No new LLM dependencies. No training pipeline. No database.

### Summary

12 lines of priority weights + 40 lines of sorting logic + 20 lines of rule boosts. Deployable in under an hour. Works on case #1. No cold start. No training data. Can be extended with a classifier later when enough labeled cases exist.

---

## Future: Labeled Classifier (Phase 2)

Only when there are 100+ labeled cases with analyst triage feedback (thumbs up/down on individual findings, analyst corrections saved to the case git repo) should a classifier enter the picture. At that point:

- Export case findings + labels from the case git repos
- Train a lightweight scikit-learn GradientBoostingClassifier on ~30 features
- Use classifier output to adjust the zero-shot priority score (blend, not replace)
- ONNX export for portability
- SQLite `TriageDB` stores feature vectors for future retraining

But this is a Q3 2026 enhancement, not a Devpost requirement.