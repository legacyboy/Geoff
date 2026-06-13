# Network-Forensics Find Evil: Zero Findings Diagnosis

**Date:** 2026-06-11  
**Case ID:** network-forensics_findevil_ed175f510f5c  
**Job ID:** job-72ff2a1b99cd  

---

## Summary

The fresh Find Evil run on 3 pcap files produced **zero findings** because a **variable-reference bug** in the per-device playbook gating logic causes **every playbook to be silently skipped**. The catch-all aggregator playbooks (PB-SIFT-060–063) run in a separate post-loop phase and always execute, which is why those four JSON files exist in `output/`.

---

## Evidence Chain

### 1. Evidence Ingestion — CORRECT
The 3 pcap files were correctly ingested:
- `/mnt/evidence/network-forensics/botnet-capture.pcap` (928 KB)
- `/mnt/evidence/network-forensics/network-traffic-sample.pcap` (1.6 MB)
- `/mnt/evidence/network-forensics/wireshark-sample.pcap` (1.0 MB)

### 2. Inventory Classification — CORRECT
`checkpoint_inventory.json` correctly classifies all 3 files under `pcaps` with 0.9 confidence:
```json
"pcaps": [
  "/mnt/evidence/network-forensics/network-traffic-sample.pcap",
  "/mnt/evidence/network-forensics/botnet-capture.pcap",
  "/mnt/evidence/network-forensics/wireshark-sample.pcap"
]
```

### 3. Device Discovery — CORRECT
`device_map.json` creates 3 `network_capture` devices with correct `evidence_types: ["pcaps"]` and correct `evidence_files`.

### 4. Execution Plan — CORRECT
`execution_plan.json` correctly includes PB-SIFT-001 as the **first playbook** (pcap analysis for Initial Access):
```json
"execution_plan": [
  "PB-SIFT-001",  // <-- First! Has pcap analysis steps
  "PB-SIFT-002",
  "PB-SIFT-003",
  "PB-SIFT-004",
  "PB-SIFT-005",
  "PB-SIFT-009",
  "PB-SIFT-013",
  "PB-SIFT-022",
  "PB-SIFT-036"
]
```

### 5. PB-SIFT-001 Definition — CORRECT
`geoff_config.py` line 501 defines PB-SIFT-001 with pcap steps:
```python
"PB-SIFT-001": {
    "pcaps": [
        ("network", "analyze_pcap", {"pcap_file": "{pcap}"}),
        ("network", "extract_http", {"pcap_file": "{pcap}"}),
    ],
    ...
}
```

### 6. Device Evidence Construction — CORRECT
`geoff_pipeline.py` lines 5326–5338 correctly build `device_evidence`:
```python
device_evidence[dev_id] = {
    "disk_images": [], "memory_dumps": [], "pcaps": [],
    ...
}
for fpath in dev.get("evidence_files", []):
    for ev_type in inventory:
        if isinstance(inventory[ev_type], list) and fpath in inventory[ev_type]:
            device_evidence[dev_id][ev_type].append(fpath)
```
After this, `device_evidence["pcap_botnet-capture_pcap"]["pcaps"]` contains `["/mnt/evidence/network-forensics/botnet-capture.pcap"]`. **This part is correct.**

---

## ROOT CAUSE: Variable Reference Bug at Line 5462

### The Bug

`geoff_pipeline.py` line 5436:
```python
for dev_id, dev in device_map.items():
    dev_ev = device_evidence[dev_id]    # ← dev_ev = {disk_images: [], ... pcaps: [...]}
```

Then inside the inner playbook loop at lines 5462–5468:
```python
dev_ev_types = set()
for fpath in dev_ev.get('evidence_files', []):   # ← BUG: dev_ev has no 'evidence_files' key!
    for ev_type_key, files in inventory.items():
        if isinstance(files, list) and fpath in files:
            dev_ev_types.add(ev_type_key)
playbook_ev_types = set(pb_steps_def.keys())     # e.g. {"pcaps", "evtx_logs", ...}
if not (dev_ev_types & playbook_ev_types):        # ← Always True → ALWAYS SKIP
    continue                                       # ← Every playbook skipped
```

### Why It Fails

`dev_ev` is `device_evidence[dev_id]` — a dict with keys:
```
disk_images, memory_dumps, pcaps, evtx_logs, evt_logs,
syslogs, registry_hives, mobile_backups, other_files
```

**There is no `evidence_files` key in `device_evidence`.** The `evidence_files` key exists in the **device_map** entries (accessible via `dev`), NOT in the constructed `device_evidence` lookup.

| Variable | Source | Has `evidence_files`? | Has `pcaps`? |
|----------|--------|----------------------|-------------|
| `dev` | `device_map[dev_id]` | ✅ Yes | ❌ No (has `evidence_types` not files) |
| `dev_ev` | `device_evidence[dev_id]` | ❌ **No** | ✅ Yes |

The code at line 5462 uses `dev_ev.get('evidence_files', [])` which **always returns `[]`**, making `dev_ev_types` an empty set. The intersection with `playbook_ev_types` is always empty, so **every playbook is skipped for every device.**

### The Fix

**Line 5462:** Change `dev_ev.get('evidence_files', [])` → `dev.get('evidence_files', [])`

```python
# BEFORE (broken):
for fpath in dev_ev.get('evidence_files', []):

# AFTER (fixed):
for fpath in dev.get('evidence_files', []):
```

This is a **one-word change**: `dev_ev` → `dev`.

---

## Why Catch-All Playbooks (PB-SIFT-060–063) Still Ran

PB-SIFT-060 through PB-SIFT-063 run in **Phase 3c** (lines 6738–6851), which is a **separate post-loop code path** after the per-device playbook execution loop. They have hardcoded `or True` conditions that force execution:

```python
# Line 6748
if _has_comms_artifacts or True:  # always run — stego/encryption scan is always useful
```

These catch-all playbooks don't go through the per-device gating logic and therefore aren't affected by the bug. They produced the only 4 output files (totaling ~1.4 KB).

---

## Audit Trail Confirmation

The audit trail (`audit_trail.jsonl`) contains only a **single event**:
```json
{"ts": "2026-06-11T20:57:28", "event": "case_init", ...}
```

No `pb_step_begin`, `pb_step_end`, `playbook_complete`, or error events exist — confirming that **no playbook steps ever ran** through the main per-device loop.

The checkpoint shows `"playbooks": {"status": "complete"}` because Phase 3c (catch-all playbooks) completed successfully, even though the main playbook loop contributed nothing.

---

## Secondary Observations

### Evidence Quality: VERY LOW
The evidence quality assessment (line 5129) produces "VERY LOW" because there are no disk images, memory dumps, syslogs, or EVTX logs. This is technically correct for a pcaps-only case, but misleading — 3 pcaps should produce findings. The quality label does NOT gate playbook execution (no quality-based skip in the playbook loop), so this is a cosmetic issue, not causal.

### Evidence Quality Fallacy
The quality heuristic at line 5129–5137 is:
```python
if inventory["disk_images"] and inventory["memory_dumps"]:
    evidence_quality = "HIGH"
elif inventory["disk_images"]:
    evidence_quality = "MEDIUM-HIGH"
elif inventory["syslogs"] or ... evtx_logs or ... evt_logs:
    evidence_quality = "LOW"
else:
    evidence_quality = "VERY LOW"
```

Pcaps are **not considered** in the quality heuristic, so any pcaps-only case will always get "VERY LOW" even if it contains rich network evidence. This is a design gap but not the root cause of zero findings.

### Tshark Availability
Tshark is expected to be available on SIFT Workstation by default (it's a core network forensics tool). The `network.analyze_pcap` Geoff function would use it. Even if tshark were missing, the playbook steps would at least *attempt* to run and produce failure output — they would not be silently skipped.

---

## Complete Execution Trace

```
1. Evidence ingestion → 3 pcaps classified correctly
2. Device discovery → 3 network_capture devices, evidence_types=["pcaps"]
3. Execution plan → PB-SIFT-001 through PB-SIFT-036 queued (9 playbooks)
4. Device evidence built → device_evidence[dev]["pcaps"] = [3 paths]
5. Playbook loop begins: for dev_id, dev in device_map.items():
   → dev_ev = device_evidence[dev_id]  // no 'evidence_files' key
6. For each playbook in execution_plan:
   → dev_ev_types = set() from dev_ev.get('evidence_files', []) → EMPTY
   → playbook_ev_types = set(pb_steps_def.keys())
   → dev_ev_types & playbook_ev_types → EMPTY INTERSECTION
   → continue (skip playbook)
   ✗ All 9 playbooks × 3 devices = 27 skip events (silent)
7. Phase 3c: PB-SIFT-060–063 catch-all playbooks run → 4 output files
8. Critic: 0 findings, 0 playbooks run → POOR → reject
9. Manager: reject (no playbooks executed, no findings generated)
```

---

## Impact

Every Find Evil run on **any evidence type** will skip all playbooks in the execution plan and produce zero findings. This bug was likely introduced when the `device_evidence` construction was refactored and the new variable name `dev_ev` was mistakenly used in the gating precheck instead of `dev`.

This affects ALL evidence types (disk images, memory dumps, EVTX logs, etc.), not just pcaps. The only reason any Geoff runs succeed is through the Phase 3c catch-all playbooks and Pass 2 timeline intelligence analysis, which bypass the per-device playbook loop.

## Recommended Actions

1. **Immediate fix**: Change `dev_ev.get('evidence_files', [])` to `dev.get('evidence_files', [])` at line 5462 of `geoff_pipeline.py`
2. **Replay**: The job can be replayed after the fix; the checkpoint has pre-requisite phases complete
3. **Evidence quality**: Consider adding `pcaps` to the quality heuristic so pure-network cases aren't forever "VERY LOW"
4. **Regression test**: Add a unit test with pcaps-only evidence asserting that playbook steps execute
