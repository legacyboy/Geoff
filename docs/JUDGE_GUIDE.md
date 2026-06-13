# Judge's Guide to Geoff's Cognition

This document maps every JSONL record type in `audit_trail.jsonl` to specific rubric
criteria, explains the trace chain, and tells judges exactly how to verify each
5-star feature.

---

## 0. Geoff's Cognitive Architecture

Geoff's investigation pipeline follows this staged reasoning architecture:

```
Manager
  └─► Forensicator (multi-agent: one per device × evidence type)
        └─► Critic (per-step validation + batch review)
              └─► Correlator (C3: cross-source evidence linking)
                    └─► ClaimVerifier (C2: accuracy gate before report)
                          └─► Narrative (final human-readable report)
```

Each transition in this chain is logged to `audit_trail.jsonl` with a `trace_id`
and `parent_trace_id` so judges can reconstruct Geoff's complete reasoning chain.

| Stage | Role | JSONL record types |
|-------|------|--------------------|
| Manager | Approves/adjusts investigation plan | `case_init`, `investigation_start` |
| Forensicator | Executes playbook steps per device | `hypothesis` (intent), step records in `findings.jsonl` |
| Critic | Validates each finding for forensic validity | embedded in findings as `"critic"` field |
| Correlator | Finds cross-source causal/correlated/identity links | `correlation_event` |
| ClaimVerifier | Checks every final claim against trace_ids | `claim_verification` |
| RevisionLoop | Spawns revised hypotheses when claims are UNSUPPORTED | `hypothesis_revision` |
| Narrative | Generates human-readable IR report | `narrative_report_path` in `find_evil_report.json` |

All six agents run within a single Python process (no external API calls required).
Multi-agent behavior is architectural — each stage has distinct logic and
produces distinct record types that judges can verify independently.

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
- 🔍 **Blue** — Hypothesis (what Geoff planned to investigate before tool dispatch)
- 🔄 **Orange** — Recovery Arc (what Geoff did when a step failed or returned empty output)
- 🔗 **Purple** — Correlation Event (cross-source links Geoff identified)
- ✅ **Green** — Claim Verification VERIFIED (claim backed by a real evidence trace)
- ❌ **Red** — Claim Verification HALLUCINATED (no supporting evidence trace)
- ⚠️ **Yellow** — Claim Verification UNSUPPORTED (trace_id referenced but not found)
- ⚙️ **Gray** — Other tool steps and pipeline events

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

| Rubric Criterion | Record Type(s) | Key Field | How to Verify |
|-----------------|----------------|-----------|---------------|
| C1: Hypothesis-driven | `hypothesis` | `hypothesis`, `selected_tool`, `reasoning` | `grep '"type": "hypothesis"' audit_trail.jsonl \| wc -l` |
| C1: Self-correction | `recovery_arc` | `failure_reason`, `recovery_strategy` | `grep '"type": "recovery_arc"' audit_trail.jsonl` |
| C2: Claim accuracy | `claim_verification` | `verification_status`, `source_trace_ids` | See claim verification commands in Section 2 |
| C3: Cross-source | `correlation_event` | `linked_trace_ids`, `relationship_type` | `grep '"type": "correlation_event"' audit_trail.jsonl` |
| C4: Multi-agent | Architecture | Manager→Forensicator→Critic→Correlator→ClaimVerifier | See Section 0: Cognitive Architecture |
| C5: Trace chain | All records | `trace_id`, `parent_trace_id` | Every record — follow parent_trace_id to root |
| C6: Visualization | HTML output | `render_timeline.py --input ... --output ...` | `python3 src/render_timeline.py --input audit_trail.jsonl --output /tmp/t.html` |

---

## 5. Criterion-by-Criterion Quick Reference

### C1 — Hypothesis-Driven Reasoning
**Look for:** `type: hypothesis` records before each tool call, `type: recovery_arc` after failures.
```bash
grep '"type": "hypothesis"' audit_trail.jsonl | head -3 | python3 -c "import sys,json; [print(json.loads(l)['hypothesis']) for l in sys.stdin]"
```
Each record shows `selected_tool` (what Geoff chose) and `reasoning` (why), logged *before* execution.

### C2 — IR Accuracy / Anti-Hallucination
**Look for:** `type: claim_verification` records with `verification_status` of VERIFIED / HALLUCINATED / UNSUPPORTED.
```bash
grep '"type": "claim_verification"' audit_trail.jsonl | python3 -c "
import sys, json, collections
recs = list(map(json.loads, sys.stdin))
print(collections.Counter(r['verification_status'] for r in recs))
"
```
A VERIFIED result means the claim traces back to a real evidence artifact. HALLUCINATED means no supporting trace was found.

### C3 — Cross-Source Correlation
**Look for:** `type: correlation_event` records with `relationship_type` of CAUSAL, CORRELATED, or IDENTITY.
```bash
grep '"type": "correlation_event"' audit_trail.jsonl | python3 -c "
import sys, json
for r in map(json.loads, sys.stdin):
    print(r['relationship_type'], r['confidence'], r['description'][:60])
"
```

### C4 — Multi-Agent Architecture
**Look for:** The staged pipeline in the source code — not prompt-based, but architectural:
- `geoff_pipeline.py`: `find_evil()` orchestrates the full pipeline
- `geoff_forensicator.py`: per-device specialist agents
- `geoff_critic.py`: validation agents
- `_run_correlator()`: cross-source synthesis
- `_run_claim_verifier()`: accuracy gate
- `narrative_report.py`: final narrative generation

Each stage is a distinct Python module with its own LLM prompt strategy and output schema.

### C5 — Trace Chain (Every Record Has trace_id + parent_trace_id)
**Look for:** Every record in `audit_trail.jsonl` has `trace_id` and most have `parent_trace_id`.
```bash
python3 -c "
import json
recs = [json.loads(l) for l in open('audit_trail.jsonl') if l.strip()]
has_trace = sum(1 for r in recs if r.get('trace_id'))
has_parent = sum(1 for r in recs if r.get('parent_trace_id'))
print(f'{has_trace}/{len(recs)} records have trace_id, {has_parent} have parent_trace_id')
"
```

### C6 — Timeline Visualization
**Run:**
```bash
python3 /home/sansforensics/Geoff/src/render_timeline.py \
  --input /path/to/case_work_dir/audit_trail.jsonl \
  --output /tmp/geoff_timeline.html
```
Open the HTML in any browser. The instruction banner at the top explains how to read it.
The tool uses only the Python standard library (`html`, `json`, `argparse`) — no pip installs needed.

---

*Generated for the Geoff 5-star competition submission.*

## Competition Guardrail Enforcement (C4)

Geoff enforces 5 hard limits per investigation to prevent runaway execution, ensure every claim has evidence, and bound the revision loop. These are hard-coded in `src/geoff_pipeline.py` and visible in every `audit_trail.jsonl`.

| Guardrail | Limit | Enforced Where | How to Verify |
|-----------|-------|---------------|---------------|
| **MAX_TOOL_INVOCATIONS** | 50 per investigation | Before every tool dispatch | `grep '"type": "hypothesis"' audit_trail.jsonl | wc -l` ≤ 50 |
| **MAX_CLAIMS_PER_TRAIL** | 50 per investigation | In `_run_claim_verifier` loop | `grep '"type": "claim_verification"' audit_trail.jsonl | wc -l` ≤ 50 |
| **MAX_CORRELATION_DEPTH** | 3 hops per correlation chain | In `_run_correlator` | `grep '"type": "correlation_event"' audit_trail.jsonl | wc -l` — max 3 per correlation chain |
| **MAX_HYPOTHESIS_REVISIONS** | 3 revisions per verification cycle | In revision loop after C2 | `grep '"type": "hypothesis_revision"' audit_trail.jsonl | wc -l` ≤ 3 |
| **MIN_EVIDENCE_PER_CLAIM** | ≥1 trace_id per claim | Claim record requires `source_trace_ids` | Each `claim_verification` record with VERIFIED status has ≥1 `source_trace_ids` |

When a guardrail fires, it is logged to the job output (visible in the web UI's log view):

```
  ✗ MAX_TOOL_INVOCATIONS (50) reached - skipping volatility.memdump
  [C1] 2 unsupported claims - generating revision hypotheses
```

### Seeing Guardrails in the Audit Trail

Each guardrail event produces a traceable record:

```
# Hypothesis before every tool dispatch:
grep '"type": "hypothesis"' audit_trail.jsonl | python3 -c "import sys,json; recs=[json.loads(l) for l in sys.stdin]; print(len(recs), 'hypotheses logged'); print(json.dumps(recs[0], indent=2))"

# Revision hypothesis triggered by UNSUPPORTED claims:
grep '"type": "hypothesis_revision"' audit_trail.jsonl | python3 -c "import sys,json; recs=[json.loads(l) for l in sys.stdin]; [print(r['hypothesis'][:80], r['revision_number']) for r in recs]"

# Hallucination flags on claims:
grep '"type": "claim_verification"' audit_trail.jsonl | python3 -c "import sys,json; recs=[json.loads(l) for l in sys.stdin]; [print(r.get('hallucination_flags',[])) for r in recs if 'hallucination_flags' in r]"

# Entity alignment per claim:
grep '"type": "claim_verification"' audit_trail.jsonl | python3 -c "import sys,json; recs=[json.loads(l) for l in sys.stdin]; [print(r['claim_text'][:60], r.get('entity_alignment_status',''), r.get('entity_alignment_reason','')) for r in recs if 'entity_alignment_status' in r]"
```

## Concrete 3-Claim Trace Walkthrough

The following walkthrough demonstrates how to trace any finding from the narrative report back to the specific tool execution that produced it — the mandatory 3-claim trace that every judge must perform.

### How the Trace Chain Works

Every finding in the narrative report carries a `trace_id`. Every step in `audit_trail.jsonl` carries both `trace_id` (self) and `parent_trace_id` (link to the hypothesis that spawned it). Together they form a chain:

```
Finding in narrative report
  → trace_id on the claim_verification record
    → parent_trace_id → the hypothesis that drove the investigation
      → trace_id on the tool execution record
        → raw tool output
```

### Walkthrough: 3 Claim Traces

**Claim 1: "Suspicious IP communication detected"**

1. Open `narrative_report.json` and find the finding with `description` containing an IP address
2. Extract its `trace_id` field (present if the narrative was generated with trace chain)
3. If no `trace_id` on the finding directly, search `audit_trail.jsonl` for `type: claim_verification` containing IP text
4. From the `claim_verification` record, get `parent_trace_id` → this is the hypothesis UUID
5. Search `audit_trail.jsonl` for `trace_id: <parent_trace_id>` → this finds the hypothesis
6. From the hypothesis, find its parent's `trace_id` → this is the tool execution record
7. The tool record shows: tool name, parameters, stdout excerpt, timestamp
8. **Verify:** Does the tool output contain the IP and support the claim?

**Claim 2: "File exfiltration via USB"**

1. Search `audit_trail.jsonl` for `type: correlation_event` containing "file" or "USB"
2. Extract the `linked_trace_ids` — these are the tool execution IDs
3. For each linked trace_id, find the corresponding tool record
4. Check: do the tool outputs (e.g., `usbstor` parser, `prefetch` analyzer) both reference the same device?
5. **Verify:** The correlation event linked them — does the evidence support the causal link?

**Claim 3: "Registry persistence mechanism"**

1. Search `audit_trail.jsonl` for `type: claim_verification` with `verification_status: VERIFIED`
2. Extract one `source_trace_ids` entry
3. Find the tool record: `trace_id == source_trace_ids[0]`
4. The tool record contains the exact registry tool output (e.g., `regripper`, `registry.printkey`)
5. **Verify:** The registry key path in the claim matches the tool output

### Using the Timeline Visualizer

```bash
python3 src/render_timeline.py --input /mnt/cases/<case_dir>/audit_trail.jsonl --output timeline.html
# Open timeline.html in any browser
# Color coding: blue=hypothesis, orange=recovery_arc, green/red/yellow=claim_verification, purple=correlation_event
# Each card shows trace_id — click through to follow the chain
```
