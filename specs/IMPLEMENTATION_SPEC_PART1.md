---

## GEOFF Architecture Pivot — Implementation Spec for Developer

### Current State Summary

The codebase lives in `src/geoff_integrated.py` (3594 lines, the monolith), plus `sift_specialists.py`, `sift_specialists_extended.py`, `sift_specialists_remnux.py`, `geoff_critic.py`, and `geoff_forensicator.py`. The main entry points are the `/find-evil` POST endpoint (line 3429) and the `/chat` POST endpoint (line 3183). The core logic is the `find_evil()` function (line 1353) which runs playbooks sequentially. YARA is already removed — no references found anywhere.

---

### CHANGE 1: Evidence Ingestion & Device Discovery

**What exists now:** `_inventory_evidence()` (line 1136) walks a directory and sorts files into flat lists by type (`disk_images`, `memory_dumps`, `pcaps`, etc.). There is zero grouping by host or device. Everything is one big bucket.

**What to build:** A new `DeviceDiscovery` class that wraps `_inventory_evidence` and adds a second pass: **device grouping**.

**File:** Create `src/device_discovery.py`

```python
class DeviceDiscovery:
    """
    Phase 1 of ingestion. Takes an evidence directory and produces
    a DeviceMap — a dict keyed by device_id, where each device has:
      - device_id: str (e.g. "DESKTOP-ABC123" or "DSmith-iPhone")
      - device_type: str ("windows_pc", "linux_server", "ios_mobile", "android_mobile", "network_capture", "unknown")
      - owner: str | None (e.g. "DSmith", "jdoe")
      - evidence_files: list[str] (absolute paths)
      - hostname: str | None
      - os_type: str
      - metadata: dict (partition info, image size, etc.)
    """
```

**Device identification strategy (in priority order):**

1. **Directory structure** — Many forensic collections organize evidence like `evidence/DavePC/`, `evidence/DavePhone/`, `evidence/server01/`. Check if the top-level subdirectories under `evidence_dir` each contain their own evidence files. If so, treat each subdirectory as a separate device. This is the simplest and most reliable signal.

2. **Hostname extraction from disk images** — For each disk image, after running `mmls` and getting the partition offset (this code already exists at line 1411), use SleuthKit to pull hostname artifacts:
   - Windows: Extract `SYSTEM` registry hive → parse `ControlSet001\Control\ComputerName\ComputerName` value. Also check `SOFTWARE\Microsoft\Windows NT\CurrentVersion\RegisteredOwner` for the owner name.
   - Linux: Extract `/etc/hostname` and `/etc/passwd` (for user accounts).
   - macOS: Extract `/Library/Preferences/SystemConfiguration/preferences.plist` for `ComputerName` and `LocalHostName`.
   
   Use `fls` to find the file's inode, then `icat` to extract the content. The specialist code for this already exists in `sift_specialists.py` (SLEUTHKIT_Specialist has `list_files`, `extract_file`, `get_file_info`).

3. **Username extraction** — This is key for cross-device correlation:
   - Windows: Parse `Users/` directory from `fls` output. Each subfolder is a username. Also parse `NTUSER.DAT` paths and `SAM` hive if available.
   - Mobile backups: iOS `Info.plist` contains device name (often "Dave's iPhone"). Android backups have device name in manifest.
   - EVTX logs: Parse the `Computer` field from event log XML headers.
   - PCAPs: Extract hostnames from DHCP, DNS queries, HTTP Host headers, NetBIOS name broadcasts.

4. **Fallback** — If none of the above produce a hostname, use the evidence filename stem (e.g., `workstation.E01` → device_id `workstation`).

**Owner-to-device correlation logic:**
- Build a `UserMap` alongside the `DeviceMap`. The UserMap is `dict[str, list[device_id]]` — mapping a person to all their devices.
- Normalize usernames: strip domain prefixes (`CORP\dsmith` → `dsmith`), lowercase, deduplicate.
- Match across devices: if `dsmith` appears as a Windows user profile on `DESKTOP-ABC` and also as the iOS backup owner on `dsmith_iphone`, link them.
- Store this as `case_work_dir/device_map.json` and `case_work_dir/user_map.json`.

**Integration into existing code:**

In `find_evil()`, after the existing `_inventory_evidence()` call (line 1401), add:

```python
# Phase 1a: Device Discovery
device_discovery = DeviceDiscovery(orchestrator)
device_map, user_map = device_discovery.discover(evidence_path, inventory)
```

The rest of the pipeline then iterates **per-device** instead of per-evidence-type. Change the playbook execution loop (line 1747) to be:

```python
for device_id, device in device_map.items():
    for playbook_id in execution_plan:
        # Run playbook steps only against THIS device's evidence files
        ...
```

**Chat integration:** In the `/chat` endpoint (line 3183), add a new trigger:

```python
# In detect_tool_request() or in chat() directly:
if any(phrase in message_lower for phrase in ['process', 'ingest', 'start processing', 'analyze evidence', 'find evil']):
    # Check if a path is mentioned, or use EVIDENCE_BASE_DIR
    evidence_dir = extract_path_from_message(user_msg) or EVIDENCE_BASE_DIR
    # Trigger find_evil via the existing async job mechanism
    ...
```

This means the user can type "Geoff, start processing /cases/incident42" in the chat window and it kicks off `find_evil`.

---

### CHANGE 2: Multi-Host Device Correlation

**What exists now:** Phase 3b (line 2036) has rudimentary multi-host correlation — it looks for multiple `.plaso` timeline files and merges them. Phase 3c (line 2076) extracts user activity from Plaso events keyed by `username@hostname`. This is on the right track but it's shallow — it only works with Plaso output, not with the actual device grouping.

**What to change:**

Replace the existing Phase 3b/3c with a proper `HostCorrelator` class in a new file `src/host_correlator.py`:

```python
class HostCorrelator:
    """
    Takes a DeviceMap and all findings from playbook execution.
    Produces:
      1. Per-user activity narratives across all their devices
      2. Cross-host event correlation (same user, different hosts, overlapping timeframes)
      3. Lateral movement detection (user appearing on hosts they don't own)
    """
    
    def correlate(self, device_map, user_map, all_findings, timeline_events):
        """
        Returns:
          correlated_users: dict[username] -> {
            devices: [device_ids],
            activity_windows: [(start, end, device_id, event_summary)],
            suspicious_cross_host: [...],  # appeared on device they don't own
            behavioral_flags: [...]  # from behavioral analysis
          }
        """
```

**Key correlation signals to extract per device during playbook execution:**

- **Login events**: Windows 4624/4625/4648 from EVTX → extract username, source IP, logon type, timestamp
- **Process execution**: UserAssist, Prefetch, Amcache, Shimcache → extract executable name, path, execution count, first/last run time
- **Browser history**: Chrome/Firefox/Edge history from disk image → extract URL, visit time, username (from profile path)
- **File access**: Recent files (LNK files), Jump Lists, ShellBags → extract path, access time, username
- **Network connections**: From memory (Volatility netscan) and PCAPs → extract source/dest IP, port, process, timestamp
- **Registry modifications**: From registry hives → extract key, value, timestamp

Each of these already has a specialist function. The change is that the **output of each step must be tagged with `device_id`** from the DeviceMap. Modify `step_record` (line 1807) to include:

```python
step_record = {
    ...existing fields...
    "device_id": device_id,  # NEW
    "owner": device_map[device_id].get("owner"),  # NEW
}
```

---

### CHANGE 3: Super-Timeline

**What exists now:** Timeline creation uses Plaso's `log2timeline` per disk image (in `sift_specialists_extended.py` line 666), and Phase 3b attempts to merge them. The merge is fragile — it re-runs `log2timeline` on already-processed files.

**What to build:** A `SuperTimeline` class in `src/super_timeline.py`:

```python
class SuperTimeline:
    """
    Unified timeline across ALL evidence from ALL devices.
    
    Pipeline:
    1. Run log2timeline on each disk image → individual .plaso files (already exists)
    2. For each memory dump, extract timestamped events (process creation, network connections)
    3. For each PCAP, extract timestamped flows
    4. For each EVTX, extract parsed events
    5. Normalize ALL events into a common schema:
       {
         "timestamp": "ISO-8601",
         "device_id": "DESKTOP-ABC",
         "owner": "dsmith",
         "source_type": "evtx|plaso|pcap|memory|registry",
         "event_type": "process_execution|login|file_access|network_connection|browser_visit|...",
         "summary": "Human-readable one-liner",
         "detail": { ...raw fields... },
         "suspicious": bool,
         "suspicion_reason": str | None
       }
    6. Sort by timestamp
    7. Write to case_work_dir/timeline/super_timeline.jsonl (one event per line)
    8. Also write case_work_dir/timeline/super_timeline.csv for human consumption
    """
    
    def build(self, device_map, findings, case_work_dir, plaso_specialist):
        """
        Orchestrates the full super-timeline build.
        Returns path to the super_timeline.jsonl file.
        """
```

**For the Plaso merge**, don't re-run `log2timeline`. Instead:
1. Run `psort -o json` on each individual `.plaso` file
2. Parse the JSON output line-by-line
3. Tag each event with its `device_id` based on which disk image produced it
4. Append to the unified event list
5. Sort everything by timestamp

**For non-Plaso sources** (memory dumps, PCAPs, EVTX), the playbook steps already extract timestamped data. Rather than re-running the tools, parse the existing findings from the playbook output JSONs in `case_work_dir/output/`. Each finding's `result` dict contains stdout/structured data with timestamps. Write a parser for each source type that extracts `(timestamp, event_type, summary)` tuples.

**Integration:** Call `SuperTimeline.build()` after all playbooks complete but before reporting (between current Phase 3b and Phase 4). Replace the existing Phase 3b/3c code entirely.

---

### CHANGE 4: Human-Readable Report from JSON

**What exists now:** The final output is `find_evil_report.json` (line 2364), a massive JSON blob with `findings_detail` containing every step's raw output. Not human-readable at all.

**What to build:** A `NarrativeReportGenerator` in `src/narrative_report.py`:

```python
class NarrativeReportGenerator:
    """
    Takes the completed investigation data and produces a human-readable report.
    
    The report is structured as:
    1. Executive Summary (2-3 paragraphs)
    2. Per-User Narratives (for each identified user across all their devices)
    3. Timeline of Significant Events (filtered to suspicious + notable)
    4. Findings (grouped by severity)
    5. Conclusion & Recommendations
    
    Uses the LLM (via call_llm) to generate natural language summaries
    from structured data. Does NOT fabricate — only summarizes what's
    actually in the findings.
    """
    
    def generate(self, report_json, device_map, user_map, 
                 super_timeline_path, correlated_users, case_work_dir):
        """
        Returns: path to narrative_report.md (Markdown format)
        Also writes narrative_report.json with structured sections.
        """
```

**Per-user narrative generation:**

For each user in `user_map`, collect:
- All devices they were found on
- Their login patterns (first login, last login, typical hours)
- Programs they executed (from UserAssist, Prefetch)
- Websites they visited (from browser history)
- Files they accessed (from LNK files, Jump Lists)
- Any suspicious activity flagged by behavioral analysis

Then call the LLM with a prompt like:

```
You are a forensic report writer. Given the following structured evidence 
for user "DSmith" across devices [DESKTOP-ABC, DSmith-iPhone], write a 
factual narrative paragraph describing their activity. Only state what 
the evidence shows. Do not speculate.

Evidence:
{json.dumps(user_evidence, indent=2)[:8000]}

Write 2-3 paragraphs describing DSmith's activity as observed in the evidence.
```

The output should read like: *"DSmith logs into DESKTOP-ABC most weekdays between 8:30-9:00 AM. Browser history shows regular visits to msn.com around 11 AM and outlook.office.com throughout the day. No evidence of malware execution was found on this device. Prefetch data shows standard Office applications and Chrome as the primary programs executed..."*

**For the overall executive summary**, feed the LLM the severity distribution, evil_found flag, classification, and a condensed version of the findings, and ask it to write a 2-3 paragraph summary.

**Output format:** Write both `narrative_report.md` (human-readable) and keep the existing `find_evil_report.json` (machine-readable). Add a `"narrative_report_path"` field to the JSON report pointing to the markdown file.

**Integration:** Add as Phase 5b after the existing Phase 5 (schema validation), before the final git commit. Call:

```python
narrative_gen = NarrativeReportGenerator(call_llm_func=call_llm)
narrative_path = narrative_gen.generate(
    report, device_map, user_map, 
    super_timeline_path, correlated_users, case_work_dir
)
report["narrative_report_path"] = str(narrative_path)
```

---

### CHANGE 5: Behavioral Process Analysis (Replaces YARA)

**What exists now:** `TRIAGE_PATTERNS` (line 864) does string matching against filenames and content for known-bad indicators. This is static pattern matching. No behavioral analysis.

**What to build:** A `BehavioralAnalyzer` in `src/behavioral_analyzer.py`:

```python
class BehavioralAnalyzer:
    """
    Replaces YARA rule matching with LLM-driven behavioral analysis.
    
    Instead of "does this file match a signature", we ask:
    "Given what we know about this process/file from the disk image timeline,
     is it doing something it shouldn't be?"
    
    Signals we can extract from existing evidence (no YARA needed):
    
    1. PROCESS ANOMALIES (from Volatility pslist + pstree + netscan):
       - Process running from unusual path (svchost.exe not in System32)
       - Process with unexpected parent (cmd.exe spawned by Word)
       - Process making network connections it shouldn't (notepad.exe → external IP)
       - Process with hidden/unlinked status
       - Process name mimicking system process (scvhost.exe vs svchost.exe)
    
    2. FILE ANOMALIES (from SleuthKit fls + timeline):
       - Executable in temp/user directories
       - File created at unusual time (3 AM on a workstation)
       - File with mismatched extension (document.pdf.exe)
       - File with creation time AFTER last modification (timestomped)
       - DLL in unexpected location
       - Recently created executable not in Prefetch (never legitimately run before)
    
    3. PERSISTENCE ANOMALIES (from Registry):
       - Run key pointing to temp directory
       - Service with unusual binary path
       - Scheduled task created recently pointing to suspicious location
       - COM object hijack (registered CLSID pointing to non-standard DLL)
    
    4. NETWORK ANOMALIES (from PCAP + memory netscan):
       - Beaconing pattern (regular interval connections to same host)
       - DNS to known-bad TLDs or unusually long subdomains (DGA)
       - Large outbound data transfers at unusual hours
       - Connections to IPs in unusual geolocations
       - Process-to-network mismatches (why is calc.exe talking to the internet?)
    
    5. TIMELINE ANOMALIES (from super-timeline):
       - Cluster of file creations in short window (dropper behavior)
       - Gap in logs followed by suspicious activity (log clearing)
       - Activity outside normal user hours
       - Executable appeared on disk with no download/email trail
    """
    
    def analyze(self, device_id, findings_for_device, timeline_events, call_llm_func):
        """
        Run behavioral analysis on one device.
        Returns list of BehavioralFlag objects:
        {
          "flag_type": "process_anomaly|file_anomaly|persistence_anomaly|...",
          "severity": "CRITICAL|HIGH|MEDIUM|LOW",
          "summary": "svchost.exe running from C:\\Users\\DSmith\\AppData\\Local\\Temp",
          "evidence": { ...supporting data... },
          "confidence": "HIGH|MEDIUM|LOW",
          "explanation": "svchost.exe is a Windows system process that should only run from C:\\Windows\\System32. Running from a temp directory is a strong indicator of malware masquerading as a legitimate process."
        }
        """
```

**Implementation approach — rule-based first, LLM second:**

Do the **deterministic checks first** (no LLM needed):

```python
# Process location check
SYSTEM_PROCESSES = {
    "svchost.exe": ["c:\\windows\\system32\\"],
    "lsass.exe": ["c:\\windows\\system32\\"],
    "csrss.exe": ["c:\\windows\\system32\\"],
    "services.exe": ["c:\\windows\\system32\\"],
    "smss.exe": ["c:\\windows\\system32\\"],
    "winlogon.exe": ["c:\\windows\\system32\\"],
    "wininit.exe": ["c:\\windows\\system32\\"],
    "explorer.exe": ["c:\\windows\\"],
    "taskhostw.exe": ["c:\\windows\\system32\\"],
}

# Parent-child check
EXPECTED_PARENTS = {
    "svchost.exe": ["services.exe"],
    "smss.exe": ["system"],
    "csrss.exe": ["smss.exe"],
    "wininit.exe": ["smss.exe"],
    "lsass.exe": ["wininit.exe"],
    "services.exe": ["wininit.exe"],
}

# Timestomp detection
# If MFT $STANDARD_INFORMATION create time > $FILE_NAME create time, it's timestomped
# If creation_time > modification_time on a file, suspicious
```

Then for anything that looks anomalous but needs context, batch the anomalies and send to the LLM:

```
You are a forensic analyst. Review these process/file anomalies from 
device DESKTOP-ABC and rate each as MALICIOUS, SUSPICIOUS, or BENIGN.
Only flag things that a real forensic analyst would flag. 
Do not hallucinate — base your assessment only on the data provided.

Anomalies:
1. Process: notepad.exe (PID 4821) has outbound connection to 185.141.63.120:443
2. File: C:\Users\DSmith\AppData\Local\Temp\update.exe created 2024-03-15T03:22:00
   - Not in Prefetch
   - Creation time is 3:22 AM (outside normal hours for this user)
3. Registry: HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdate 
   → C:\Users\DSmith\AppData\update.exe

Respond in JSON: [{"index": 1, "verdict": "MALICIOUS|SUSPICIOUS|BENIGN", "reason": "..."}]
```

**Integration:** Run `BehavioralAnalyzer.analyze()` per device after the playbooks complete for that device, but before the narrative report generation. The behavioral flags feed into both the super-timeline (tagged events) and the narrative report.

Add to the main pipeline in `find_evil()` after playbook execution:

```python
# Phase 3d: Behavioral Analysis
behavioral_analyzer = BehavioralAnalyzer()
all_behavioral_flags = {}
for device_id, device in device_map.items():
    device_findings = [f for f in findings if f.get("device_id") == device_id]
    device_timeline = [e for e in super_timeline_events if e.get("device_id") == device_id]
    flags = behavioral_analyzer.analyze(device_id, device_findings, device_timeline, call_llm)
    all_behavioral_flags[device_id] = flags
```

---

### Files to Create

| File | Purpose |
|---|---|
| `src/device_discovery.py` | Device grouping, hostname extraction, owner attribution |
| `src/host_correlator.py` | Cross-host user activity correlation |
| `src/super_timeline.py` | Unified timeline across all devices and evidence types |
| `src/narrative_report.py` | LLM-driven human-readable report generation |
| `src/behavioral_analyzer.py` | Process/file/network behavioral anomaly detection |

### Files to Modify

| File | Changes |
|---|---|
| `src/geoff_integrated.py` | Rewrite `find_evil()` pipeline to use new modules. Add device_id to step_records. Replace Phase 3b/3c. Add Phase 3d (behavioral), Phase 5b (narrative). Add chat trigger for "start processing". |
| `src/geoff_integrated.py` | In `detect_tool_request()` (line 609), add trigger for natural language ingestion commands. |
| `src/geoff_integrated.py` | Remove `TRIAGE_PATTERNS` string matching from `_scan_triage_indicators()` — replace with call to `BehavioralAnalyzer` in the pipeline. Keep `_inventory_evidence()` but wrap it with `DeviceDiscovery`. |

### Execution Order in Revised `find_evil()`

1. **Inventory** — `_inventory_evidence()` (keep as-is)
2. **Device Discovery** — `DeviceDiscovery.discover()` → `device_map`, `user_map`
3. **Partition Detection** — existing code (line 1411), now per-device
4. **Case Directory Setup** — existing code, also write `device_map.json` and `user_map.json`
5. **Triage** — PB-SIFT-000, now per-device
6. **Execution Plan** — existing logic, unchanged
7. **Playbook Execution** — existing loop BUT outer loop is now per-device, and every `step_record` gets `device_id` and `owner`
8. **Super-Timeline Build** — `SuperTimeline.build()` (replaces Phase 3b/3c)
9. **Behavioral Analysis** — `BehavioralAnalyzer.analyze()` per device (new)
10. **Host Correlation** — `HostCorrelator.correlate()` (new, replaces Phase 3c)
11. **Findings Aggregation** — existing Phase 4, plus behavioral flags
12. **Schema Validation** — existing Phase 5
13. **Narrative Report** — `NarrativeReportGenerator.generate()` (new)
14. **JSON Report** — existing, augmented with `device_map`, `user_map`, `behavioral_flags`, `narrative_report_path`
15. **Git Commit** — existing

---

### Model Recommendation

You mentioned glm-5.1 for implementation. That should work fine for the deterministic parts (DeviceDiscovery, SuperTimeline, file parsing). For the LLM-calling code (NarrativeReportGenerator, BehavioralAnalyzer), the logic is straightforward — it's just prompt construction and JSON parsing. The harder parts are the forensic domain knowledge in BehavioralAnalyzer (the `SYSTEM_PROCESSES` and `EXPECTED_PARENTS` dicts), which I've included above so the developer doesn't need to know Windows internals.

If glm-5.1 struggles with the SleuthKit/Volatility integration details, I'd recommend implementing one module at a time and testing against a real evidence set between each. Start with `device_discovery.py` since everything else depends on it.
