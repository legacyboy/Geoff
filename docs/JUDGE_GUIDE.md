# Judge's Guide to Geoff's Cognition

This document maps every JSONL record type in `audit_trail.jsonl` to specific rubric
criteria, explains the trace chain, and tells judges exactly how to verify each
5-star feature.

---

## 1. The Trace Chain — How to Read It

Every record in `audit_trail.jsonl` carries two fields that connect the dots:

| Field | Meaning |
|-------|---------|
| `trace_id` | UUID for this specific record/decision |
| `parent_trace_id` | UUID of the record that spawned this one |

The root of every investigation is a record of `type: investigation_start` whose
`parent_trace_id` is `null`. From there, every hypothesis, failure, correlation,
and verification links back to a parent.

**To visualize the full chain:**
```bash
python3 src/render_timeline.py \
  --input /path/to/case_work_dir/audit_trail.jsonl \
  --output /tmp/timeline.html
```
Open `/tmp/timeline.html` in any browser. Color legend:
- **Blue** — Hypothesis (what Geoff planned to investigate)
- **Orange** — Recovery Arc (what Geoff did when a step failed)
- **Green** — Correlation Event (cross-source links Geoff identified)
- **Purple** — Claim Verification (accuracy gate: VERIFIED / HALLUCINATED / UNSUPPORTED)

---

## 2. Record Type Reference

### `investigation_start`
**Rubric**: Autonomy, Transparency  
**When written**: Once, at the very start of `find_evil()`.  
**Key fields**: `investigation_id`, `evidence_dir`, `trace_id` (becomes the root for all child traces).

**To verify**: `grep '"type": "investigation_start"' audit_trail.jsonl | head -1`

---

### `hypothesis`
**Rubric**: C1 (Hypothesis-Driven Reasoning), Autonomy  
**When written**: Before every tool invocation in the main investigation loop.  
Each `hypothesis` record captures Geoff's *intent* before execution, not just the result after.

**Key fields**:
- `hypothesis` — natural language statement of what is being investigated
- `selected_tool` — `module.function` being invoked
- `reasoning` — why this tool was chosen for this evidence type
- `trace_id` — unique ID for this hypothesis (referenced by downstream records)
- `parent_trace_id` — the investigation's root trace_id

**To verify C1** (hypothesis-driven reasoning):
```bash
grep '"type": "hypothesis"' audit_trail.jsonl | wc -l
# Should equal approximately the number of tool invocations
```

---

### `recovery_arc`
**Rubric**: C1 (Self-Correction), Resilience  
**When written**: When a tool invocation returns empty output or times out.  
Geoff doesn't silently skip — it logs its reasoning for recovery.

**Key fields**:
- `parent_trace_id` — the `trace_id` of the failed hypothesis
- `failure_reason` — what went wrong
- `recovery_strategy` — what Geoff decided to do next
- `new_hypothesis` — the revised investigation plan

**To verify self-correction**:
```bash
grep '"type": "recovery_arc"' audit_trail.jsonl | python3 -c \
  "import sys,json; [print(json.loads(l)['failure_reason']) for l in sys.stdin]"
```

---

### `correlation_event`
**Rubric**: C3 (Cross-Source Correlation), Synthesis  
**When written**: After all data collection, before report generation.  
Two sources generate these:
1. **LLM-identified correlations** — the Correlator sends evidence summaries to the
   LLM and asks it to find causal/correlated/identity relationships.
2. **Deterministic correlations** — multiple tools analyzing the same artifact file
   on the same device are automatically linked.

**Key fields**:
- `linked_trace_ids` — array of `trace_id`s being correlated
- `relationship_type` — `CAUSAL` | `CORRELATED` | `IDENTITY`
- `description` — human-readable explanation
- `confidence` — 0.0–1.0

**To verify C3**:
```bash
grep '"type": "correlation_event"' audit_trail.jsonl | \
  python3 -c "import sys,json; recs=list(map(json.loads,sys.stdin)); \
  print(f'{len(recs)} correlations; types: {set(r[\"relationship_type\"] for r in recs)}')"
```

---

### `claim_verification`
**Rubric**: C2 (Accuracy / Anti-Hallucination), Trust  
**When written**: Before the narrative report, after all evidence collection.  
Every proposed claim (IOC, attack chain stage, CRITICAL finding note) is checked:
does it have a `trace_id` that exists in the actual evidence store?

**Key fields**:
- `claim_text` — the proposed claim being evaluated
- `source_trace_ids` — trace_ids the claim is attributed to
- `verification_status` — one of:
  - `VERIFIED` — claim backed by a real evidence trace
  - `UNSUPPORTED` — trace_ids referenced but not in evidence store
  - `HALLUCINATED` — no evidence trace at all
- `reasoning` — why this verdict was assigned
- `corrective_action` — what to do about non-VERIFIED claims

**To verify C2 accuracy** (the key judge instruction):
```bash
# Count by verification status
grep '"type": "claim_verification"' audit_trail.jsonl | \
  python3 -c "import sys,json,collections; \
  recs=list(map(json.loads,sys.stdin)); \
  print(collections.Counter(r['verification_status'] for r in recs))"

# See all HALLUCINATED claims
grep '"type": "claim_verification"' audit_trail.jsonl | \
  python3 -c "import sys,json; \
  [print(r['claim_text']) for r in map(json.loads,sys.stdin) if r['verification_status']=='HALLUCINATED']"
```

A high VERIFIED ratio proves Geoff's claims are grounded. Zero HALLUCINATED records
means every claim in the final report traces to an artifact.

---

## 3. End-to-End Verification Walkthrough

To fully audit one investigation:

```bash
CASE_DIR=/home/sansforensics/Geoff/case_work/<case_id>
JSONL=$CASE_DIR/audit_trail.jsonl

# 1. Confirm trace chain exists
echo "=== Record type counts ==="
python3 -c "
import json, collections
recs = [json.loads(l) for l in open('$JSONL') if l.strip()]
print(collections.Counter(r.get('type','unknown') for r in recs))
"

# 2. Pick a hypothesis trace_id and follow it
TRACE=$(grep '"type": "hypothesis"' $JSONL | head -1 | python3 -c "import sys,json; print(json.loads(sys.stdin.read())['trace_id'])")
echo "=== Trace chain for $TRACE ==="
python3 -c "
import json
recs = [json.loads(l) for l in open('$JSONL') if l.strip()]
chain = [r for r in recs if r.get('trace_id') == '$TRACE' or r.get('parent_trace_id') == '$TRACE']
for r in chain: print(r.get('type'), '->', r.get('trace_id','')[:8])
"

# 3. Check claim accuracy
python3 -c "
import json, collections
recs = [json.loads(l) for l in open('$JSONL') if l.strip() and json.loads(l).get('type') == 'claim_verification']
print(collections.Counter(r['verification_status'] for r in recs))
"

# 4. Render the visual timeline
python3 /home/sansforensics/Geoff/src/render_timeline.py \
  --input $JSONL --output /tmp/timeline.html
echo "Open /tmp/timeline.html in a browser"
```

---

## 4. Rubric Mapping Summary

| Rubric Criterion | Record Type(s) | Key Field |
|-----------------|----------------|-----------|
| C1: Hypothesis-driven | `hypothesis` | `hypothesis`, `selected_tool`, `reasoning` |
| C1: Self-correction | `recovery_arc` | `failure_reason`, `recovery_strategy` |
| C2: Claim accuracy | `claim_verification` | `verification_status`, `source_trace_ids` |
| C3: Cross-source | `correlation_event` | `linked_trace_ids`, `relationship_type` |
| C6: Visualization | HTML output | `render_timeline.py --input ... --output ...` |
| Transparency | All records | `trace_id`, `parent_trace_id` |

---

*Generated for the Geoff 5-star competition submission.*
