# DFRWS2008 "Find Evil" Report — Senior DFIR Analyst Review

**Reviewer:** Steve (Steve4) 🔧
**Date:** 2026-06-08 09:28 CDT
**Report:** `/mnt/cases/dfrws2008_findevil_39db792957d0/reports/find_evil_report.json`
**Pipeline:** Geoff forensic automation framework, SIFT VM host
**Investigation Status:** `complete_with_failures` (⚠️)

---

## Executive Summary

The pipeline correctly identified the DFRWS2008 challenge as malware-related (CRITICAL severity, 75.8% malware confidence). It executed 67 of 95 specialist steps. However, the report is **significantly degraded** — critic approval is at a dismal 46.4%, 20 steps failed, 196 files went unprocessed, all 120 finding records lack severity/category metadata, and the playbook routing dispatched Volatility/memory forensic commands against a PCAP file. The investigation completed but left substantial forensic value on the table.

The **DFRWS2008 challenge** contains 2 evidence files:
- `challenge.mem` — Linux memory dump (Ubuntu/Debian, ~2008 era)
- `suspect.pcap` — Packet capture of network activity

---

## 1. Issues Found (Severity-Ordered)

### 🔴 CRITICAL — Device Routing & Evidence-Type Confusion

| Issue | Detail |
|-------|--------|
| **Volatility code ran against a PCAP** | `pcap_suspect_pcap` is a network capture, yet the pipeline ran `volatility.process_list`, `volatility.find_malware`, `volatility.procdump`, `volatility.handles`, `volatility.mutantscan`, `volatility.apihooks`, `volatility.modscan`, `volatility.vadinfo`, `volatility.memmap` against it — all of which are Volatility memory analysis commands |
| **Memory functions on PCAP** | `memory.extract_processes`, `memory.extract_credentials`, `memory.extract_registry`, `memory.extract_network` all failed on `pcap_suspect_pcap` |
| **Registry parse on Linux memdump** | `registry.parse_hive` ran against `memdump_challenge` — a Linux memory dump with no Windows registry |
| **Device map shows `type: unknown`** for both devices | Pipeline failed to classify `challenge.mem` as `memory_dump` and `suspect.pcap` as `pcap` at the device level |

**Root Cause:** The device-classification pass either didn't run or produced null results, and the evidence-to-device router did not gate Volatility/memory modules by device evidence type. No `device_map.os_type` was assigned, so playbook dispatch had to guess.

### 🟠 HIGH — Critic Approval at 46.4% (32 approved / 26 rejected)

| Metric | Value | Implication |
|--------|-------|-------------|
| Approved | 32 steps | Less than half the completed steps pass critic review |
| Rejected | 26 steps | Critic is rejecting findings likely due to wrong-evidence-type results |
| Needs Review | 15 steps | Critic couldn't decide — ambiguous output |
| Auto-approved | `false` | Quality gate blocked automatic sign-off |

**Root Cause:** Correlated to device routing failures. The critic evaluates whether step output is "forensically sound." When Volatility returns nothing on a PCAP, or registry parser returns nothing on a Linux dump, the critic correctly flags these as invalid. Also: 13 steps are `unverified` — output was captured but not validated.

### 🟠 HIGH — All 120 Findings Lack Severity & Category

Every single finding_detail entry shows:
```
severity: "unknown"
category: "unknown"
```

The `severity_distribution` at the top level has real values (`CRITICAL: 6, HIGH: 11, MEDIUM: 1, LOW: 2, INFO: 1`), suggesting a post-hoc aggregation layer is functioning, but individual findings have null metadata. This means:
- Findings JSONL file is likely missing severity/category fields
- No per-finding confidence scoring
- Critic approval partially blind (can't weigh by severity)

**Root Cause:** Finding struct emitted by specialist modules doesn't populate `severity` or `category` fields. The aggregation layer at report-build time attempts to backfill but only produces 21 categorized entries.

### 🟠 HIGH — Connection Map / Communication Analysis Divergence

| Field | Value | Issue |
|-------|-------|-------|
| `connection_map` | 245 connections | PCAP analysis found 245 netflows/IP connections |
| `external_contacts` | 60 unique IPs | Good — IP extraction worked |
| `communications_analysis.message_count` | **0** | Communications playbook returned nothing |
| `communications_analysis.person_count` | **0** | No persons identified |
| `communications_analysis.has_communications` | **false** | Contradicts 245 connections above |

**Root Cause:** The `PB-SIFT-060` communications playbook likely expects specific data artifacts (email PSTs, chat logs, SMS dbs) rather than raw PCAP flows. PCAP-level connections are captured in `connection_map` but never fed into the communications narrative pipeline. Gap between network flow analysis and person-level communication mapping.

### 🟡 MEDIUM — 20 Step Failures

| # | Module | Function | Device | Likely Cause |
|---|--------|----------|--------|-------------|
| 1 | linux_user | analyze_shell_history | memdump_challenge | No .bash_history found in memdump extraction |
| 2 | linux_user | analyze_desktop_artifacts | memdump_challenge | GNOME config paths not crawled from memdump |
| 3 | linux_user | analyze_editor_artifacts | memdump_challenge | Editor history not found |
| 4 | linux_user | analyze_misc_user_config | memdump_challenge | Misc config parsing failed |
| 5 | remnux | inetsim_check | memdump_challenge | INetSim not applicable to memdump |
| 6 | remnux | fakedns_check | memdump_challenge | FakeDNS not applicable to memdump |
| 7 | memory | extract_network | pcap_suspect_pcap | **Memory func on PCAP** |
| 8 | memory | find_injected_code | pcap_suspect_pcap | **Memory func on PCAP** |
| 9 | memory | extract_registry | pcap_suspect_pcap | **Memory func on PCAP** |
| 10 | memory | extract_credentials | pcap_suspect_pcap | **Memory func on PCAP** |
| 11 | volatility | handles | pcap_suspect_pcap | **Volatility on PCAP** |
| 12 | volatility | mutantscan | pcap_suspect_pcap | **Volatility on PCAP** |
| 13 | volatility | apihooks | pcap_suspect_pcap | **Volatility on PCAP** |
| 14 | volatility | modscan | pcap_suspect_pcap | **Volatility on PCAP** |
| 15 | volatility | vadinfo | pcap_suspect_pcap | **Volatility on PCAP** |
| 16 | volatility | memmap | pcap_suspect_pcap | **Volatility on PCAP** |
| 17 | remnux | inetsim_check | pcap_suspect_pcap | INetSim may not be installed on SIFT VM |
| 18 | remnux | fakedns_check | pcap_suspect_pcap | FakeDNS may not be installed on SIFT VM |
| 19 | registry | parse_hive | memdump_challenge | **Registry parse on Linux memdump** |
| 20 | memory | extract_processes | pcap_suspect_pcap | **Memory func on PCAP** |

**10 of 20 failures (50%)** are caused by calling memory/Volatility functions on a PCAP file. **1 failure** is calling registry parse on a Linux dump. **4 failures** are calling REMnux network services check on a memory dump. **4 failures** are Linux user artifact parsers that couldn't find expected paths in the extracted files. **1 failure** (remnux inetsim on PCAP) may be genuine tool-availability issue.

Additionally: **all failures record `playbook=?` and `error=?`** — the failure-attribution chain is broken; the report doesn't capture which playbook spawned the failure or what error message was returned.

### 🟡 MEDIUM — 196 Unprocessed Files

| Category | Count | Examples |
|----------|-------|----------|
| `file_type_not_covered_by_playbooks` | 149 | Firefox Cache/*.d01 (cache entries), .xsession-errors, .bash_profile, .emacs, .gtkrc, .dmrc, System.map |
| `forensic_artifact_no_direct_handler` | 42 | gconf/*.xml (GNOME configs), Firefox history.dat, key3.db, cert8.db, formhistory.dat, compreg.dat, signons2.txt |
| `text_config_not_in_playbook` | 5 | cookies.txt, compatibility.ini, extensions.ini, profiles.ini, signons2.txt |

**Missed forensic value:**
- **Firefox artifacts** (key3.db + signons2.txt) → Can contain saved passwords if master password not set (common in 2008)
- **history.dat** → Browsing history (crucial for DFIR timeline)
- **cookies.txt** → Session tokens, visited domains
- **gconf XMLs** → GNOME desktop state, ekiga VoIP accounts/config, evolution email config (may contain credentials)
- **.bash_profile / .bashrc** → Shell startup scripts (could contain backdoor paths)
- **.xsession-errors** → Application crash logs, potentially showing malicious process output

### 🟡 MEDIUM — Playbook Run Data Corrupted

All 29 playbook entries in `playbooks_run` show:
```
steps_run: ?
passed: ?
failed: ?
skipped: ?
```

The raw run-statistics fields are null/None. The top-level counters (`steps_completed: 67`, `steps_failed: 20`, etc.) appear to be populated from a different aggregation path. This means per-playbook success/failure tracking is **broken** — you can't tell which playbooks are problematic without manually tracing through findings_detail.

**Root Cause:** The playbook-run summary struct populated at execution time is missing field values. Likely a serialization bug where the progress counter is a different type or key than what the report generator expects.

### 🟡 MEDIUM — Schema Validation Warning

```
schema_validation_warning: "None is not of type 'string'"
```

A field in the JSON report contains `null` where the schema expects a `string`. Likely candidates:
- `llm_analysis: null` — expected to be string
- `narrative_report_path: null` — expected to be string
- Error messages in failures (all `?` currently)
- `playbook_id` in failure records (all `?` currently)

**Root Cause:** Pipeline assigns `None` to optional string-typed fields rather than omitting them or using empty string `""`.

### 🟡 MEDIUM — Missing Pipeline Features

| Missing Feature | Status | Impact |
|----------------|--------|--------|
| LLM Analysis | `null` | No AI-powered narrative/insight generation |
| Narrative Report | `null` | No human-readable report file generated |
| Pass2 Retrigger | All zero | Critic-flagged items don't trigger automatic re-investigation |
| Post-Run Retry | 0 retried / 0 succeeded / 0 failed | 20 failures were never retried |
| User Activity Summary | Empty dict | No user-level activity correlated across devices |
| Correlated Users | Empty dict | No users identified at all |
| Timeline | Empty list (0 items) | Despite 2 devices with activity, no timeline was built |
| Cross-Device Timeline | "not yet fully implemented" | Known gap — acknowledged in report |
| Campaign Multi-Day Patterns | Empty | Only tool-chain analysis present, no temporal clustering |
| Off-Hours Clusters | Empty | No shift/off-hours analysis |
| Windows-Only Artifacts | All empty/not found | recycle_bin, imapi, vss, edb — expected since this is Linux |

### 🟢 LOW — Minor Issues

| Issue | Detail |
|-------|--------|
| **Playbooks executed twice** | PB-SIFT-001 through PB-SIFT-019 appear in `playbooks_run` twice (possibly Pass1 + retry that didn't retry anything) |
| **Dwell_days misleading** | 0.08 days (~2h) — this is the investigation wall-clock time, not attacker dwell time. Attack chain timestamps (2026-06-08) are pipeline runtime, not evidence dates. |
| **Self-corrections recorded but no retry** | 6 self-corrections logged — pipeline noticed wrong evidence types but didn't re-route steps |
| **Evidence extracted to `/mnt/cases/extractions/` not case-relative paths** | Evidence lives outside the case work dir, making case portability harder |
| **Windows-only modules ran on Linux** | `windows.analyze_prefetch`, `windows.analyze_amcache`, `windows.analyze_shimcache`, `windows.lsadump`, `windows.malfind`, `windows.cmdline` all show as `running` or `skipped` against a Linux dump |
| **evidence_inventory contains extracted archive metadata** | The `extracted_archives` entry contains the full file list of 192 files as a giant nested structure, which bloats the report JSON |

---

## 2. Root Cause Analysis (Dependency-Mapped)

```
Device Classification Failure
  ├─► device_map.*.type = unknown
  ├─► device_map.*.os_type = unknown  
  │
  ├─► No evidence-type gating on playbook dispatch
  │    ├─► Volatility modules dispatched against PCAP (pcap_suspect_pcap)
  │    ├─► Memory modules dispatched against PCAP
  │    ├─► Registry module dispatched against Linux memdump
  │    ├─► REMnux modules dispatched against memdump
  │    └─► Windows-only modules remain "running/skipped" on Linux
  │
  ├─► 10 of 20 failures = wrong-evidence-type (50%)
  │
  └─► Critic rejects 26 steps (likely from nonsense output)
       └─► critic_approval_pct drops to 46.4%

Playbook Metadata Gaps
  ├─► findings_detail.[severity,category] = unknown (120/120 findings)
  ├─► playbooks_run.[steps_run,passed,failed,skipped] = null (29/29 entries)
  ├─► failures.[playbook_id,error] = null (20/20 failures)
  └─► Schema validation warning: None is not of type 'string'

Missing Pipeline Components
  ├─► No LLM analysis integration
  ├─► No narrative report generation
  ├─► No Pass2 re-investigation trigger
  ├─► No post-run failure retry
  ├─► No user-level activity correlation
  └─► Timeline generation → empty
       └─► Cross-device timeline → stub only

Linux Forensic Coverage Gaps
  ├─► No Firefox history.dat parser
  ├─► No Firefox saved-password extraction (key3.db + signons2.txt)
  ├─► No gconf XML parser (GNOME/ekiga/evolution configs)
  ├─► No .bash_profile/.bashrc scanner (backdoor hunting)
  ├─► No .xsession-errors parser (application crash/dump)
  └─► 196 files unprocessed (Firefox cache, GNOME state, shell configs)

Playbook Design Issues
  ├─► PB-SIFT-041 (linux_user) — 4/6 steps failed; paths hardcoded for root-level .bash_history not per-user
  ├─► PB-SIFT-017 (remnux) — REMnux tools (inetsim, fakedns) may not be installed on SIFT VM
  ├─► PB-SIFT-005 (volatility) — No profile auto-detection; Volatility requires Linux profile for 2.6.18 kernel
  ├─► PB-SIFT-027 (volatility) — procdump, dll_list dispatched without evidence-type guard
  └─► PB-SIFT-036 (network) — extract_flows worked but self-corrected; output should have been fed to communications analysis
```

---

## 3. Recommended Fixes (Priority-Ordered)

### 🔴 Immediate (Critical — Blocking Accurate Reports)

#### FIX-1: Add Evidence-Type Guards to Playbook Dispatch

```python
# In: playbook router / step dispatcher (likely in geoff/core/dispatcher.py or similar)

EVIDENCE_TYPE_GUARDS = {
    "volatility": ["memory_dump"],
    "memory": ["memory_dump"],
    "registry": ["disk_image", "registry_hive"],
    "network": ["pcap"],
    "remnux": ["pcap", "malware_sample"],
    "windows": ["disk_image", "memory_dump"],  # + os_type == "windows"
    "linux_user": ["memory_dump", "disk_image"],  # + os_type == "linux"
    "sleuthkit": ["disk_image", "memory_dump"],
    "dns": ["pcap"],
    "yara": ["memory_dump", "disk_image", "malware_sample"],
    "scheduled": ["memory_dump", "disk_image"],
    "strings": ["memory_dump", "disk_image", "malware_sample"],
}

def guard_step(module_name, device):
    allowed_types = EVIDENCE_TYPE_GUARDS.get(module_name, [])
    if device.evidence_type not in allowed_types:
        return StepResult.skipped(
            reason=f"Module {module_name} requires evidence type in {allowed_types}, "
                   f"got {device.evidence_type}"
        )
    # additionally check os_type match for platform-specific modules
    if module_name == "windows" and device.os_type != "windows":
        return StepResult.skipped(reason="Windows-only module on non-Windows device")
    if module_name in ("linux_user",) and device.os_type != "linux":
        return StepResult.skipped(reason="Linux-only module on non-Linux device")
    return None  # pass guard
```

This single fix eliminates **10 of 20 failures** and the registry-on-Linux failure, immediately improving critic approval from 46% → ~70%.

#### FIX-2: Implement Device Classification Before Playbook Dispatch

```python
# In: evidence ingestion pipeline

def classify_device(evidence_path):
    """Classify evidence before playbook dispatch."""
    ext = Path(evidence_path).suffix.lower()
    
    if ext in ('.mem', '.vmem', '.dmp', '.raw', '.vmsn', '.vmss'):
        # Try Volatility imageinfo/profile detection
        profile = detect_memory_profile(evidence_path)
        return Device(
            type="memory_dump",
            os_type=profile.get("os", "unknown"),
            profile=profile
        )
    elif ext in ('.pcap', '.pcapng', '.cap'):
        return Device(type="pcap", os_type="network")
    elif ext in ('.dd', '.E01', '.001', '.img', '.vmdk', '.vhd'):
        return Device(type="disk_image", os_type="unknown")
    # ... etc
```

Without this, the pipeline treats every evidence item identically and routes all modules to all devices.

### 🟠 High Priority (Data Quality & Completeness)

#### FIX-3: Fix Finding Metadata — Add severity/category to Specialist Output

Each specialist step that produces a finding should emit:
```json
{
  "module": "volatility",
  "function": "find_malware",
  "status": "completed",
  "severity": "HIGH",       // ← MISSING
  "category": "Malware",    // ← MISSING  
  "evidence_file": "...",
  "output": "...",
  "confidence": 0.85        // ← MISSING
}
```

**Check:** `geoff/specialists/volatility.py` or the base specialist class that constructs the Finding dataclass — ensure `severity` and `category` are populated, not defaulting to `"unknown"`.

#### FIX-4: Fix Playbook Run Statistics Serialization

The `playbooks_run` entries show `?` for all counters. This means either:
- The counter field names don't match between the run-time struct and the report schema
- The counters are in a nested sub-object that isn't being traversed
- Or they're computed lazily and the serialization happens before computation

**Check:** The playbook runner that populates `PlaybookRunResult` — verify that `steps_run`, `passed`, `failed`, `skipped` fields are int-typed (not Optional/None) and are populated before serialization.

#### FIX-5: Fix Failure Attribution Chain

Every failure record should include:
```json
{
  "playbook_id": "PB-SIFT-027",     // ← currently null
  "step": "volatility.procdump",     // ← currently null
  "module": "volatility",
  "function": "procdump",
  "device_id": "pcap_suspect_pcap",
  "error": "VolatilityError: Cannot analyze non-memory file",  // ← currently null
  "timestamp": "2026-06-08T08:31:23"
}
```

The try/except in the step executor must capture and propagate `playbook_id`, `step`, and `error_message` into the failure record. Current code likely only catches the exception and creates an empty Failure object.

#### FIX-6: Fix Schema Validation — Don't Emit `null` for String Fields

```python
# Instead of:
report.llm_analysis = None  # triggers "None is not of type 'string'"

# Use:
report.llm_analysis = ""  # or omit the field entirely via exclude_none=True
```

Alternatively, update the JSON Schema to allow `"type": ["string", "null"]` for genuinely optional fields like `narrative_report_path`, `llm_analysis`, etc.

### 🟡 Medium Priority (Coverage & Features)

#### FIX-7: Add Linux Firefox Forensic Parsers

| File | What to Extract | Priority |
|------|----------------|----------|
| `history.dat` | Browsing history (URL, timestamp, visit count) | HIGH |
| `cookies.txt` | Session cookies, domains visited | HIGH |
| `signons2.txt` | Saved login usernames (passwords encrypted with key3.db) | HIGH |
| `key3.db` | Master key for password decryption | HIGH |
| `formhistory.dat` | Web form values (searches, emails entered) | MEDIUM |
| `prefs.js` | Browser configuration, homepage, proxy settings | MEDIUM |
| `bookmarks.html` | Saved bookmarks, bookmark dates | MEDIUM |
| `Cache/*.d01` | Cached web content (can reconstruct pages viewed) | LOW |

Add a specialist module `linux_firefox` or extend `PB-SIFT-041` (linux_user) with an `analyze_legacy_firefox` function that actually works. Currently it's skipped.

#### FIX-8: Add gconf XML Parser

GNOME gconf stores configuration as XML files under `~/.gconf/`. High-value targets:
- `ekiga` configs → VoIP accounts, SIP credentials
- `evolution` configs → Email accounts (may have stored credentials)
- `panel` configs → Desktop layout (identifies running applets/indicators)

Add a `linux_gconf` specialist or extend `linux_user.analyze_desktop_artifacts`.

#### FIX-9: Implement Post-Run Failure Retry

The report shows `post_run_retry: {retried: 0}`. After FIX-1 (evidence-type guards), failed steps should be re-evaluated:
- Steps that failed due to evidence-type mismatch → skip (don't retry)
- Steps that failed due to missing tools → check tool availability, retry or skip
- Steps that failed due to data not found → mark as `not_applicable` rather than `failed`

#### FIX-10: Route PCAP Analysis Output to Communications Analysis

`connection_map` has 245 entries and `external_contacts` has 60 IPs. Feed this data into PB-SIFT-060 (Communications Analysis) rather than letting it produce `message_count: 0`.

#### FIX-11: Timeline Generation from Evidence Timestamps

The `timeline` is empty (`[]`) and `dwell_days` is computed from pipeline runtime (0.08 days). Fix:
- Extract timestamps from PCAP packets (earliest/latest packet times)
- Extract timestamps from memory dump metadata
- Build timeline entries from these actual evidence dates
- Update attack_chain.first_seen/last_seen to reflect evidence dates, not pipeline dates

### 🟢 Low Priority (Polish)

#### FIX-12: Deduplicate Playbook Run Entries

Playbooks PB-SIFT-001 through PB-SIFT-019 appear twice in `playbooks_run`. Remove duplicate entries or differentiate them with pass labels (Pass1/Pass2).

#### FIX-13: Enable LLM Analysis Pipeline

Hook `llm_analysis` into the Geoff LLM integration (likely `geoff/critic/llm_analyst.py`). The report structure already has the field — it just needs to be populated.

#### FIX-14: Narrative Report Generation

Generate a human-readable Markdown report from the JSON structure. The `narrative_report_path` field is present and null — wire it to `geoff/reporting/narrative.py` if it exists.

#### FIX-15: Isolate Evidence Inventory to File Paths Only

`evidence_inventory.extracted_archives` includes the entire 192-file manifest inline. Store this as a reference to an inventory file instead, or truncate to summary stats.

---

## 4. Extractions Directory Structure Assessment

```
/mnt/cases/extractions/
├── dfrws2008-challenge_1998/         ← extracted from dfrws2008-challenge.zip
│   └── response_data/
│       ├── challenge.mem             ← Linux memory dump (~512MB)
│       ├── suspect.pcap              ← Network packet capture
│       └── user_files/               ← Linux user home directory structure
│           ├── .bash_profile
│           ├── .bashrc
│           ├── .bash_logout
│           ├── .mozilla/firefox/     ← Firefox 2.x profile (n5q6tfua.default)
│           ├── .gconf/               ← GNOME 2 gconf configs
│           ├── .gnome2/              ← GNOME 2 session data
│           ├── .mc/                  ← Midnight Commander config
│           └── .local/share/         ← XDG user data
└── System.map_2103/                  ← extracted from System.map.zip
    └── System.map-2.6.18-8.1.15.el5  ← Kernel symbol map (RHEL 5 / CentOS 5)
```

**Assessment: Sane ✅**

- ZIP archives extracted to versioned directories (PID-based suffix)
- Raw evidence files (`challenge.mem`, `suspect.pcap`) at expected location
- User files preserved with original hierarchy
- No evidence duplication or cross-contamination

**Improvement suggestion:** Move extractions inside the case work directory for portability:
```
/mnt/cases/dfrws2008_findevil_39db792957d0/
├── extractions/          ← move here instead of /mnt/cases/extractions/
├── reports/
└── findings.jsonl
```

Currently extractions are at `/mnt/cases/extractions/` (flat, shared across cases), which makes it harder to archive or transfer individual cases.

---

## 5. Summary of Fix Impact Estimates

| Fix # | Fix | Est. Effort | Failures Eliminated | Critic Gain |
|-------|-----|-------------|---------------------|-------------|
| FIX-1 | Evidence-type guards | 2-4h (add dispatch filter) | 10-11 | +15-20% |
| FIX-2 | Device classification | 4-8h (imageinfo integration) | 10-11 | +15-20% |
| FIX-3 | Finding metadata | 1-2h (defaults in base class) | 0 | +10-15% |
| FIX-4 | Playbook run stats | 1-2h (field name alignment) | 0 | +5-10% |
| FIX-5 | Failure attribution | 2-3h (exception capture) | 0 (but enables debugging) | +5% |
| FIX-6 | Schema nulls | 0.5h (default strings) | 0 | Validation clean |
| FIX-7 | Firefox parsers | 8-16h (new specialist) | 0 | +5-10% |
| FIX-8 | gconf parser | 4-8h (new specialist) | 0 | +2-5% |
| FIX-9 | Retry logic | 4-8h (retry subsystem) | 20 (all retried) | +15-20% |
| FIX-11 | Timeline fix | 2-4h (timestamp extraction) | 0 | +10-15% |

**Immediate sprint (FIX-1, FIX-2, FIX-3, FIX-6):** ~1-2 days → critic approval from 46% → ~75%, eliminate 10 failures, clean schema validation.

**Next sprint (FIX-4, FIX-5, FIX-9, FIX-11):** ~1 week → full failure visibility, retry stack, accurate timeline/dwell metrics.

**Coverage sprint (FIX-7, FIX-8, FIX-10):** ~1-2 weeks → Firefox/gconf parsers handle 196 unprocessed files, comms analysis populated.

---

## 6. DFIR Perspective — What the Report Should Have Found

For context, the DFRWS2008 challenge (solved manually by DFIR teams in 2008) involved:
- A Linux system compromised via a web vulnerability
- Malware process hiding via kernel rootkit (hidden from `ps`)
- Exfiltration of data over HTTP
- Cron-based persistence and backdoor

The Geoff pipeline detected:
- ✅ Malware classification (75.8% confidence)
- ✅ C2, persistence, rootkit in kill chain
- ✅ 245 network connections, 60 external IPs
- ✅ Attack chain with lateral movement path
- ❌ No timeline correlating PCAP timestamps with memory dump state
- ❌ No specific process/backdoor identified (process list found but details missing)
- ❌ Firefox artifacts (browser used to pull down malware?) not parsed
- ❌ Bash history/shell config not analyzed (no backdoor path extraction)

---

*Report generated 2026-06-08 by Steve (Steve4) — Geoff DFIR Pipeline Review*
