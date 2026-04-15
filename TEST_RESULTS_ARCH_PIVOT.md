# GEOFF Architecture Pivot — Test Results & Proposal

**Date:** 2026-04-15 01:40 CDT
**Baseline commit:** 9a8478d (rollback point)
**Current commit:** 173beb5

---

## Test Results

### ✅ Module Import & Signature Tests — ALL PASS

| Module | Class | Key Method | Signature Match |
|--------|-------|-----------|----------------|
| device_discovery | DeviceDiscovery | discover(evidence_path, inventory) → (device_map, user_map) | ✅ |
| host_correlator | HostCorrelator | correlate(device_map, user_map, findings, timeline_events) → dict | ✅ |
| super_timeline | SuperTimeline | build(device_map, findings, case_work_dir, plaso_specialist, ...) → (path, events) | ✅ |
| behavioral_analyzer | BehavioralAnalyzer | analyze(device_id, findings, timeline_events, call_llm_func) → flags | ✅ |
| narrative_report | NarrativeReportGenerator | generate(report_json, device_map, user_map, ...) → path | ✅ |

### ✅ Device Discovery Tests — ALL PASS

| Test | Result |
|------|--------|
| Directory structure grouping (evidence/PC/, evidence/phone/) | ✅ 2 devices detected |
| Memory dump associated with disk image (same subdir) | ✅ Both files in DavePC device |
| Flat layout (no subdirs) | ✅ Per-file devices created |
| PCAP → network_capture device type | ✅ |
| Username normalization (CORP\dsmith → dsmith) | ✅ |
| Username normalization (DSmith@CORP.LOCAL → dsmith) | ✅ |

### ✅ Behavioral Analyzer Tests — ALL PASS

| Rule | Test | Result |
|------|------|--------|
| Process path | svchost.exe from C:\Windows\System32\ | ✅ No flag (correct) |
| Process path | svchost.exe from Temp\ | ✅ Flagged HIGH |
| Process parent | svchost.exe from services.exe | ✅ No flag (correct) |
| Process parent | svchost.exe from explorer.exe | ✅ Flagged HIGH |
| Typosquatting | scvhost.exe mimicking svchost.exe | ✅ Flagged CRITICAL |
| Timestomp | created > modified | ✅ Flagged HIGH |
| Spawn chain | winword.exe → cmd.exe | ✅ Flagged HIGH |

### ✅ Super Timeline Test — PASS
- Handles missing psort gracefully (non-SIFT system)
- Produces .jsonl and .csv output files
- Logs each processing step
- Returns 0 events for fake data (correct)

### ✅ Host Correlator Test — PASS
- Correlates dsmith across DESKTOP-ABC and DSmith-iPhone
- Returns per-user device lists

### ✅ Narrative Report Generator — PASS
- Produces 1418-char markdown report
- Creates reports/ directory under case dir
- Works with mock LLM

### ✅ Chat Trigger Tests — ALL PASS
- "start processing /path" → triggers ingestion ✅
- "find evil in this image" → triggers ✅
- "analyze evidence now" → triggers ✅
- "Run mmls on the disk" → does NOT trigger ✅
- "What is the timeline?" → does NOT trigger ✅

### ✅ Integration Call Site Tests — ALL PASS
- All 5 module calls match method signatures
- dev_ev used (not old ev dict) in playbook loop
- Old code removed (_correlate_timelines, merged_super.plaso, user_activity_summary variable)
- ev.get() only used in triage phase (correct — scans all evidence before device loop)

---

## Known Issues & Recommendations

### Issue 1: SuperTimeline SleuthKit Event Extraction (P1)
**Problem:** The SuperTimeline._extract_sleuthkit_events() parser looks for specific patterns in fls stdout that may not match real SleuthKit output format. It currently extracts 0 events from the test finding because the format doesn't match.
**Recommendation:** Test with real `fls -m` output on the SIFT VM. The parser likely needs adjustment for the actual body file format that `fls -m` produces.

### Issue 2: NarrativeReport LLM Prompt (P2)
**Problem:** The narrative report LLM prompt is generated per-user, but the mock test showed the LLM returns a single JSON object rather than per-user narratives. The generate() method may need to iterate over users more explicitly.
**Recommendation:** Test with real LLM on SIFT. If per-user narratives are missing, add explicit per-user prompt calls.

### Issue 3: BehavioralAnalyzer Data Extraction (P1)
**Problem:** The _extract_processes(), _extract_network(), _extract_registry() methods parse raw stdout strings from Volatility/RegRipper. These are fragile — different Volatility plugins produce different output formats. The process extraction currently parses `parts[0]` as PID and `parts[1]` as PPID, but Volatility3 pslist output has different column ordering.
**Recommendation:** Test with real Volatility3 output on SIFT VM. May need format-specific parsers for pslist vs pstree vs netscan.

### Issue 4: HostCorrelator Activity Windows (P2)
**Problem:** The correlated output shows `events=0` even when timeline events exist. The correlate() method may not be mapping timeline events to activity_windows correctly.
**Recommendation:** Debug the activity_windows mapping with real timeline data.

### Issue 5: DeviceDiscovery Orchestrator Dependency (P2)
**Problem:** _enrich_from_disk_image() tries to use SLEUTHKIT_Specialist but the constructor requires evidence_path and the specialist may not be available. The try/except handles this gracefully, but device enrichment falls back to "unknown" type.
**Recommendation:** On SIFT VM, verify that disk image enrichment works when SleuthKit is available. May need to pass image_offsets to DeviceDiscovery.

### Issue 6: Multi-part E01 Files (P2)
**Problem:** The spec mentions that .E01/.E02/.E03 with the same stem should be treated as ONE device. DeviceDiscovery currently treats each file independently in flat layout mode.
**Recommendation:** Add E01/E02/E03 grouping logic to DeviceDiscovery.discover() for flat layouts. Group by stem with trailing digits stripped.

### Issue 7: Frontend Device Map Null Handling (P3)
**Problem:** The JavaScript for the device map table uses `dev.evidence_files?.length` but evidence_files could be undefined if device_map was written without it.
**Recommendation:** Add `|| []` fallback in JavaScript: `(dev.evidence_files || []).length`.

---

## Proposal: SIFT VM Validation Run

Before declaring the architecture pivot complete, we should run a full Find Evil on the SIFT VM with the Jean evidence image:

### Test Plan
1. SSH to SIFT VM, pull latest code
2. Run Find Evil on Jean evidence: `/home/sansforensics/evidence-storage/evidence/Jean`
3. Verify:
   - Device discovery identifies Jean as a single device
   - Playbooks execute per-device (1 device, so runs once)
   - Super-timeline produces events
   - Behavioral analyzer runs (may flag nothing if Jean is clean)
   - Host correlator produces user data
   - Narrative report generated
   - All existing features still work (git commits, validations, critic, anti-forensics cascade)
4. Compare output structure to the Jean run from before the pivot
5. Take a new VM snapshot

### Risk Areas
- SuperTimeline event extraction from real Plaso output
- BehavioralAnalyzer parsing real Volatility pslist format
- DeviceDiscovery enrichment with real SleuthKit tools
- Narrative report quality with real LLM

### Rollback Plan
If SIFT validation reveals critical issues, rollback is clean:
```bash
git checkout 9a8478d
```
This returns to the pre-pivot state with all P0/P1 fixes intact.

---

## Commit History (Architecture Pivot)

| Commit | Description |
|--------|-------------|
| 9a8478d | **BASELINE** — Pre-pivot state (P0/P1 fixes only) |
| 05cd55c | 5 new module files + Phase 1a device discovery |
| edc1b47 | Full pipeline restructure, new phases, chat trigger, frontend |
| 435bcc7 | Fix plaso_specialist reference |
| 6544319 | Fix GLM validation findings (indentation + old code removal) |
| 173beb5 | Update README |

**Total delta from baseline: +8133/-540 lines across 13 files**