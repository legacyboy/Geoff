# ML-Driven Triage Ranking — Technical Plan

**Status:** Draft  
**Scope:** Scoring and ranking findings by likelihood of being malicious so the analyst sees the most important evidence first in every report.

---

## Background and Problem Statement

The current pipeline executes all 40+ Pass 1 playbooks and annotates each step with a `significance` field (CRITICAL/HIGH/MEDIUM/LOW/NONE) assigned by the Forensicator LLM in `geoff_forensicator.py:interpret_result()`. The narrative report (`narrative_report.py:NarrativeReportGenerator.generate()`) renders findings in playbook execution order, not relevance order. With 37–100+ completed steps per case, a CRITICAL finding from PB-SIFT-027 may appear far below LOW findings from PB-SIFT-001.

The goal is a `triage_score` (0.0–1.0) on every finding, with the report sorted descending by score. The plan is phased: start with zero-shot scoring that requires no training data, accumulate labels from analyst interactions, then train a lightweight classifier when enough data exists.

---

## 1. Training Data Source

### Existing signal in case output

Every completed investigation writes step records to a JSONL file via `findings_writer.append(step_record)` in `geoff_pipeline.py`. Each `step_record` contains:

```json
{
  "playbook": "PB-SIFT-008",
  "step_key": "PB-SIFT-008:sleuthkit:list_files:disk.E01",
  "execution_hash": "abc123def456",
  "module": "sleuthkit",
  "function": "list_files",
  "params": {"image": "/mnt/evidence/disk.E01", "offset": 2048, "recursive": true},
  "evidence_file": "/mnt/evidence/disk.E01",
  "device_id": "dev-0",
  "status": "completed",
  "result": { ... raw specialist output ... },
  "_self_healed": false,
  "_heal_fix_type": null
}
```

The Forensicator LLM annotates each result with (`geoff_forensicator.py` line ~404):
```json
{
  "significance": "HIGH",
  "threat_indicators": ["svchost.exe spawning cmd.exe", "unusual parent process"],
  "follow_up_needed": true,
  "follow_up_reason": "process chain requires deeper analysis",
  "analyst_note": "Memory process list shows svchost.exe spawning cmd.exe, consistent with LOLBin execution"
}
```

The self-heal audit trail (`_audit_heal()` in `geoff_self_heal.py`) logs `SELF_HEAL` events to the action logger with `fix_type`, `confidence`, and `outcome`. Steps that were healed to `skipped` status are weak evidence at best.

### Usable labels

| Source | Label quality | Availability |
|---|---|---|
| `significance` field (CRITICAL/HIGH/MEDIUM/LOW/NONE) | Medium — LLM may hallucinate | Immediate, every case |
| `_self_healed` + `outcome=skipped` | Weak negative signal | Immediate |
| `follow_up_needed` flag | Soft positive signal | Immediate |
| Analyst confirmation/dismissal (new API, Phase 2) | High — ground truth | After Phase 2 ships |
| `THREAT_TAXONOMY` score_weight × indicator match count | Derived signal | Immediate |

The cold-start problem is real: the first few cases have no analyst labels. The Phase 1 and Phase 2 approaches below do not require them.

---

## 2. Feature Extraction

### Per-finding features

The following features are extractable from every `step_record` without additional tooling.

**Categorical (one-hot or ordinal):**
- `playbook_id`: PB-SIFT-000 through PB-SIFT-039, PB-SIFT-100 through PB-SIFT-104
- `playbook_category`: derived from `PLAYBOOK_NAMES` in `geoff_config.py` (e.g., "Persistence", "Malware Hunting", "Credential Theft")
- `module`: sleuthkit, volatility, registry, network, logs, remnux, mobile, etc.
- `function`: process_list, find_malware, extract_autoruns, analyze_prefetch, etc.
- `evidence_type`: inferred from `evidence_file` extension via `_infer_evidence_type()` in `geoff_config.py` (disk_image, memory_dump, pcap, evtx, registry_hive, email)
- `significance_ordinal`: NONE=0, LOW=1, MEDIUM=2, HIGH=3, CRITICAL=4, UNKNOWN=-1

**Boolean:**
- `follow_up_needed`: from forensicator annotation
- `_self_healed`: step required healing before completing
- `_heal_skipped`: step was healed by skipping (weak negative — likely no real finding)
- `is_pass2`: playbook ID ≥ PB-SIFT-100 (Pass 2 = targeted investigation, higher base rate of findings)

**Count/numeric:**
- `threat_indicator_count`: `len(threat_indicators)`
- `indicator_term_matches`: count of `threat_indicators` terms that appear in `THREAT_TAXONOMY` indicator lists (e.g., "persistence", "c2", "lolbin")
- `threat_taxonomy_max_weight`: max `score_weight` across matching taxonomy categories
- `analyst_note_len`: length of `analyst_note` text (longer = more findings described)
- `result_stdout_len`: byte length of `result.stdout` (proxy for output richness)

**Text (embeddings or bag-of-words):**
- `threat_indicators` joined as text → TF-IDF over the full corpus, or embed with sentence-transformers
- `analyst_note` → same

**Derived from indicator term patterns:**
- Process names in `threat_indicators` matching known LOLBin list (powershell, certutil, mshta, regsvr32, wmic, cscript, wscript, rundll32, schtasks, cmd.exe)
- Registry key paths matching persistence locations (Run, RunOnce, Services, Winlogon)
- File paths in suspicious directories (Temp, AppData\Roaming, ProgramData, System32 with non-Microsoft PE)
- IP addresses matched against `_KNOWN_CDN_PREFIXES` from `narrative_report.py` (CDN IPs are near-certain non-findings)

---

## 3. Model Approach

### Hardware constraint

Target: SIFT VM, 16 GB RAM. No GPU. Model must score a full case (100–500 findings) in under 10 seconds. This rules out any transformer fine-tuning at inference time.

### Phase 1 — LLM-assisted zero-shot score (no training data required)

Map the existing `significance` field and `THREAT_TAXONOMY` weights to a numeric score:

```python
_SIG_BASE = {"CRITICAL": 0.95, "HIGH": 0.80, "MEDIUM": 0.50, "LOW": 0.20, "NONE": 0.02, "UNKNOWN": 0.10}

def zero_shot_score(finding: dict) -> float:
    notes = finding.get("forensicator_notes", {})
    sig = notes.get("significance", "UNKNOWN")
    base = _SIG_BASE.get(sig, 0.10)
    
    # Boost for taxonomy indicator matches
    indicators = notes.get("threat_indicators", [])
    indicator_text = " ".join(indicators).lower()
    max_weight = 0.0
    for cat, entry in THREAT_TAXONOMY.items():
        if any(ind in indicator_text for ind in entry["indicators"]):
            max_weight = max(max_weight, entry["score_weight"])
    boost = min(0.15, max_weight * 0.15)
    
    # Penalty for self-healed-to-skipped findings
    if finding.get("_heal_skipped"):
        return 0.02
    
    return min(1.0, base + boost)
```

This is a 20-line function. Integrate it at the end of `find_evil()` in `geoff_pipeline.py`, after all Forensicator annotations are complete, writing `triage_score` back into each step record.

**Risk:** `significance` from the Forensicator LLM is noisy. A CRITICAL from `remnux.die_scan` returning "PE file detected" is not equivalent to a CRITICAL from `volatility.find_malware` returning injected code.  
**Mitigation:** Boost by playbook category using a prior weight table (see Phase 2).

### Phase 2 — Rule-enriched scoring with feature accumulation

Add a `TriageScorer` class in a new file `src/triage_scorer.py`:

```python
class TriageScorer:
    PLAYBOOK_PRIORS = {
        "PB-SIFT-004": 0.85,  # Privilege Escalation — high base rate
        "PB-SIFT-005": 0.85,  # Credential Theft
        "PB-SIFT-027": 0.80,  # Memory Forensics
        "PB-SIFT-008": 0.75,  # Malware Hunting
        "PB-SIFT-003": 0.70,  # Persistence
        "PB-SIFT-009": 0.90,  # Ransomware
        "PB-SIFT-001": 0.45,  # Initial Access — broad, many benign hits
        "PB-SIFT-022": 0.30,  # Browser Forensics — mostly benign
        ...
    }
    
    def score(self, finding: dict) -> float:
        ...
```

Playbook priors are derived from expert judgment initially; replaced by empirical base rates once labeled data accumulates.

**Also in Phase 2:** Add Flask endpoint `POST /api/cases/<case_id>/findings/<step_key>/label` that writes `{"label": "malicious"|"benign", "analyst_id": ..., "timestamp": ...}` to `TriageDB` (SQLite). This is the label collection mechanism.

At this point, every scored finding writes its feature vector + zero-shot score to the DB. When the analyst labels it, the feature vector is already present. No retroactive feature extraction needed.

### Phase 3 — Supervised classifier (after ~50 labeled cases)

**Model selection:**

`GradientBoostingClassifier` from scikit-learn is the right call here:
- Handles mixed numeric/categorical features without preprocessing pain
- Trains in seconds on <10,000 examples
- Produces calibrated probabilities with `calibration.CalibratedClassifierCV`
- Fits in ~10 MB serialized

**Not** a neural network, transformer, or ONNX tiny-LLM. The feature space is well-structured and low-dimensional (~30 features). LLM fine-tuning is ruled out by the hardware constraint and the training data volume (50 cases is not enough for fine-tuning stability).

**Feature vector (concrete):**
```python
features = {
    "playbook_idx": int,          # ordinal index of playbook in execution order
    "playbook_prior": float,      # from PLAYBOOK_PRIORS table
    "module_hash": int,           # hashed module name (20 buckets)
    "function_hash": int,         # hashed function name (50 buckets)
    "evidence_type_idx": int,     # 0=disk, 1=memory, 2=pcap, 3=evtx, 4=hive, 5=email, 6=other
    "significance_ordinal": int,  # 0–4
    "follow_up_needed": bool,
    "self_healed": bool,
    "heal_skipped": bool,
    "is_pass2": bool,
    "indicator_count": int,
    "taxonomy_match_count": int,
    "taxonomy_max_weight": float,
    "lolbin_match": bool,
    "persistence_key_match": bool,
    "suspicious_path_match": bool,
    "cdn_ip_match": bool,         # negative feature
    "note_len_bucket": int,       # 0=none, 1=short, 2=medium, 3=long
    "stdout_len_bucket": int,
    # TF-IDF top-20 indicator terms as binary columns
}
```

**Training loop** (`src/triage_trainer.py`):
```python
from triage_db import TriageDB
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.calibration import CalibratedClassifierCV
import joblib

db = TriageDB(...)
X, y = db.get_labeled_features()  # SQL join features table with labels table
clf = CalibratedClassifierCV(GradientBoostingClassifier(n_estimators=100, max_depth=4))
clf.fit(X, y)
joblib.dump(clf, CASES_WORK_DIR / "ml_triage/model.pkl")
```

**ONNX export** (`skl2onnx`) for portability if deployment environment differs from training environment. Store alongside pickle: `model.onnx`.

**Retraining trigger:** Batch retrain when `len(new_labels_since_last_train) >= 20`. Called from the Flask label endpoint in `geoff_integrated.py` (or as a cron). Runs in a background thread; new model replaces old atomically via `_atomic_write()`.

### Phase 4 — Active learning (optional, after Phase 3 is stable)

Identify findings where the model's probability is in the range [0.3, 0.7] — maximum uncertainty — and surface them in the report as "needs analyst review." The Flask UI can show a review queue. Analyst labels feed back into Phase 3 retraining. This closes the loop without requiring labeling of every finding.

---

## 4. Integration into the Pipeline

### Where the scorer hooks in

**Option A (preferred):** End of `find_evil()` in `geoff_pipeline.py`, after all playbook steps complete and Forensicator annotations are written, before `NarrativeReportGenerator.generate()` is called.

```python
# geoff_pipeline.py — near the end of find_evil(), before generate()
scorer = TriageScorer(model_path=CASES_WORK_DIR / "ml_triage/model.pkl")
for finding in all_findings:
    finding["triage_score"] = scorer.score(finding)
all_findings.sort(key=lambda f: f["triage_score"], reverse=True)
```

This is the cleanest hook: all data is available, sorting happens before report generation, and the scorer has no side effects on earlier pipeline phases.

**Option B:** Inside `NarrativeReportGenerator.generate()`, which already receives the full `report_json`. The `_generate_behavioral_findings()` section (not shown but exists in `narrative_report.py`) would sort by `triage_score` before rendering.

Option A is preferred because it scores once and the sorted order is available to all report consumers (markdown, JSON, future API).

### Score propagation to the report

`NarrativeReportGenerator.generate()` already groups findings by severity in the behavioral findings section. After scoring, change the sort key:

```python
# Before: sorted by playbook execution order
# After:
findings_to_render.sort(key=lambda f: f.get("triage_score", 0.0), reverse=True)
```

Add a score badge to each finding in the markdown output:
```
### [CRITICAL] Memory — Volatility: find_malware  `score: 0.97`
```

### Analyst override

The Flask API gains an endpoint:
```
POST /api/cases/<case_id>/findings/<step_key>/label
Body: {"label": "malicious"|"benign", "override_score": 0.0|1.0}
```

The `override_score` immediately replaces `triage_score` in the case's JSON result, re-renders the report section, and writes to `TriageDB` for training.

---

## 5. Feedback Loop

### Collection

`TriageDB` (SQLite at `CASES_WORK_DIR/ml_triage/labels.db`) has two tables:

```sql
CREATE TABLE features (
    step_key TEXT PRIMARY KEY,
    case_id TEXT,
    feature_json TEXT,         -- JSON-encoded feature dict
    triage_score REAL,
    zero_shot_score REAL,
    created_at TEXT
);

CREATE TABLE labels (
    step_key TEXT PRIMARY KEY,
    case_id TEXT,
    label INTEGER,             -- 1=malicious, 0=benign
    analyst_id TEXT,
    created_at TEXT,
    FOREIGN KEY (step_key) REFERENCES features(step_key)
);
```

### Retraining cadence

- Minimum 20 new labels since last training run before retraining
- Minimum 100 total labeled examples before switching from Phase 2 (rule-based) to Phase 3 (classifier)
- Triggered in background thread from the label endpoint; new model written atomically
- Version tracked by `model_version` column in a `metadata` table; logged to action_logger

### Implicit feedback (future)

Analyst report download/export time as a proxy for engagement. If a case is exported quickly after generation, high-ranked findings were probably correct. Weak signal only; don't use without explicit label confirmation.

---

## 6. Database and Storage

```
CASES_WORK_DIR/
  ml_triage/
    labels.db          -- SQLite (features + labels + metadata)
    model.pkl          -- joblib serialized sklearn model
    model.onnx         -- ONNX export for portability
    model_v{N}.pkl     -- versioned backups (keep last 3)
    tfidf_vocab.json   -- TF-IDF vocabulary for indicator term features
```

SQLite is the right choice here. It's already used by several specialists (`sqlite3` imported in `sift_specialists_extended.py`), requires no daemon, and handles concurrent reads fine. The only write path is the label endpoint (low frequency) and batch retraining (single-threaded).

The `HealCache` in `geoff_critic.py` (backed by a JSON file at `CASES_WORK_DIR/git/heal_cache.json`) is the precedent pattern for case-level persistent caching. `TriageDB` follows the same principle but uses SQLite for queryability.

---

## 7. Implementation Order

### Phase 1 — Zero-shot scoring (est. 1–2 days)

1. Add `zero_shot_score(finding)` function to new file `src/triage_scorer.py`
2. Hook into `find_evil()` in `geoff_pipeline.py` after all Forensicator annotations are written
3. Sort `all_findings` by `triage_score` descending before calling `NarrativeReportGenerator.generate()`
4. Add `triage_score` and score badge to the behavioral findings section in `narrative_report.py`

Deliverable: Report shows most-likely-malicious findings first. No training data required. Works on first case.

### Phase 2 — Rule enrichment + label collection (est. 1 week)

1. Expand `TriageScorer` with `PLAYBOOK_PRIORS` table and structured feature extraction (LOLBin match, persistence key match, CDN IP match)
2. Add `TriageDB` SQLite class in `src/triage_db.py`
3. Write feature vector to DB for every scored finding (even before labeling)
4. Add `POST /api/cases/<case_id>/findings/<step_key>/label` endpoint in `geoff_integrated.py`
5. Add analyst label UI: minimal — a thumbs up/down button on each finding in the report web view

Deliverable: Labels accumulate passively during normal case work. No analyst training required.

### Phase 3 — Supervised classifier (when ≥100 labeled findings from ≥10 cases)

1. Write `src/triage_trainer.py` with scikit-learn training loop
2. Add `POST /api/ml/retrain` admin endpoint (or trigger automatically from label endpoint when threshold met)
3. `TriageScorer.score()` checks for `model.pkl` presence; if found, uses classifier; falls back to rule-based if model missing or version mismatch
4. Log model version and per-case accuracy (precision/recall at threshold 0.5) to action_logger

Deliverable: Model improves with each case. Zero-shot baseline is automatically replaced once classifier is better.

### Phase 4 — Active learning queue (optional, after Phase 3)

1. Surface findings with `0.3 ≤ triage_score ≤ 0.7` in a "review queue" section of the report
2. Prioritize uncertain findings for analyst attention
3. Feed labels back into Phase 3 retraining

---

## 8. Alternatives Considered

### Rule-based scoring only (no ML)

**Pro:** Deterministic, auditable, no cold-start problem, no model versioning complexity.  
**Con:** Misses patterns not anticipated by the rule author. A novel malware family that doesn't hit any LOLBin or persistence terms will score LOW even if the analyst notes are screaming. Can't improve from case outcomes.  
**Verdict:** Use as Phase 2 baseline and fallback, not as the long-term solution.

### LLM-only scoring (extend the Forensicator prompt to output a numeric score)

**Pro:** Already partially exists via `significance` field. Can reason about arbitrary indicator combinations.  
**Con:** Expensive — adds one LLM call per finding (100–500 calls per case). Non-reproducible (same inputs → different scores across runs). Can't be retrained on analyst feedback without fine-tuning. Slow for the SIFT VM if using a local Qwen model.  
**Verdict:** The `significance` field is already the LLM's scoring output; use it as an input feature to the ML model rather than as a final score.

### Skip scoring, use existing self-heal severity ordering

**Con:** Self-heal decisions (`fix_type`, `confidence`) indicate tool reliability, not finding severity. A finding that required three healing attempts might still be CRITICAL.  
**Verdict:** Use `_self_healed` and `_heal_skipped` as features (negative signal), not as a sorting key.

### Tiny LLM fine-tune (e.g., Qwen-1.5B fine-tuned on labeled findings)

**Pro:** Could capture nuanced semantic patterns in `analyst_note` text.  
**Con:** Requires GPU for fine-tuning. 16GB RAM on SIFT VM is borderline for inference even with quantization. Needs thousands of labeled examples for stable fine-tuning. Overkill for the problem.  
**Verdict:** Out of scope until the dataset has >5,000 labeled findings. Revisit in Phase 4+.

---

## Summary of Files to Create/Modify

| File | Action | Phase |
|---|---|---|
| `src/triage_scorer.py` | Create — `TriageScorer` class with zero-shot and rule-based scoring | 1 |
| `src/geoff_pipeline.py` | Modify — call scorer after Forensicator annotations, before report generation | 1 |
| `src/narrative_report.py` | Modify — sort findings by `triage_score`, add score badge | 1 |
| `src/triage_db.py` | Create — `TriageDB` SQLite class for features and labels | 2 |
| `src/geoff_integrated.py` | Modify — add `/api/cases/<id>/findings/<key>/label` endpoint | 2 |
| `src/triage_trainer.py` | Create — sklearn training loop, `POST /api/ml/retrain` | 3 |
