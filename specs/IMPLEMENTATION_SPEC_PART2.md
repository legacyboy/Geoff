# GEOFF Architecture Pivot — Implementation Spec Part 2
## Data Schemas, Specific Code Changes, Edge Cases, Frontend

---

## 1. JSON SCHEMAS FOR NEW DATA STRUCTURES

### 1.1 DeviceMap (`case_work_dir/device_map.json`)

```json
{
  "devices": {
    "DESKTOP-ABC123": {
      "device_id": "DESKTOP-ABC123",
      "device_type": "windows_pc",
      "hostname": "DESKTOP-ABC123",
      "owner": "dsmith",
      "owner_confidence": "HIGH",
      "os_type": "windows",
      "os_version": "Windows 10 Pro 21H2",
      "evidence_files": [
        "/evidence/dsmith_workstation/workstation.E01",
        "/evidence/dsmith_workstation/NTUSER.DAT",
        "/evidence/dsmith_workstation/SYSTEM"
      ],
      "evidence_types": ["disk_images", "registry_hives"],
      "discovery_method": "registry_hostname",
      "metadata": {
        "partition_offset": 2048,
        "total_size_bytes": 53687091200,
        "filesystem": "NTFS",
        "user_profiles_found": ["dsmith", "Administrator"],
        "timezone": "Eastern Standard Time"
      }
    },
    "DSmith-iPhone": {
      "device_id": "DSmith-iPhone",
      "device_type": "ios_mobile",
      "hostname": "DSmith's iPhone",
      "owner": "dsmith",
      "owner_confidence": "HIGH",
      "os_type": "ios",
      "os_version": "iOS 17.4",
      "evidence_files": [
        "/evidence/dsmith_phone/Info.plist",
        "/evidence/dsmith_phone/Manifest.db"
      ],
      "evidence_types": ["mobile_backups"],
      "discovery_method": "ios_plist_device_name",
      "metadata": {
        "backup_date": "2024-03-15T10:30:00Z"
      }
    },
    "unknown_pcap_001": {
      "device_id": "unknown_pcap_001",
      "device_type": "network_capture",
      "hostname": null,
      "owner": null,
      "owner_confidence": "NONE",
      "os_type": "network",
      "evidence_files": ["/evidence/captures/office_network.pcap"],
      "evidence_types": ["pcaps"],
      "discovery_method": "fallback_filename",
      "metadata": {
        "hosts_observed": ["192.168.1.10", "192.168.1.25", "10.0.0.1"],
        "dns_names_observed": ["DESKTOP-ABC123.local", "fileserver.corp.local"]
      }
    }
  },
  "discovery_log": [
    {"timestamp": "...", "action": "dir_scan", "detail": "Found 3 subdirectories"},
    {"timestamp": "...", "action": "hostname_extract", "detail": "DESKTOP-ABC123 from SYSTEM hive"},
    {"timestamp": "...", "action": "owner_match", "detail": "dsmith matched across PC and iPhone"}
  ]
}
```

### 1.2 UserMap (`case_work_dir/user_map.json`)

```json
{
  "users": {
    "dsmith": {
      "username": "dsmith",
      "display_name": "Dave Smith",
      "aliases": ["CORP\\dsmith", "dsmith@corp.local", "Dave Smith"],
      "devices": ["DESKTOP-ABC123", "DSmith-iPhone"],
      "primary_device": "DESKTOP-ABC123",
      "confidence": "HIGH"
    },
    "admin": {
      "username": "admin",
      "display_name": "Administrator",
      "aliases": ["Administrator", "BUILTIN\\Administrator"],
      "devices": ["DESKTOP-ABC123"],
      "primary_device": "DESKTOP-ABC123",
      "confidence": "MEDIUM"
    }
  },
  "unattributed_devices": ["unknown_pcap_001"],
  "cross_device_users": ["dsmith"]
}
```

### 1.3 Super-Timeline Event Schema (`case_work_dir/timeline/super_timeline.jsonl`)

One JSON object per line:

```json
{
  "timestamp": "2024-03-15T08:45:23.000000Z",
  "device_id": "DESKTOP-ABC123",
  "owner": "dsmith",
  "source_type": "plaso",
  "source_parser": "windows:evtx:4624",
  "event_type": "login",
  "summary": "User dsmith logged in via interactive logon (Type 2)",
  "detail": {
    "event_id": 4624,
    "logon_type": 2,
    "source_ip": "127.0.0.1",
    "workstation": "DESKTOP-ABC123"
  },
  "suspicious": false,
  "suspicion_reason": null,
  "behavioral_flags": []
}
```

```json
{
  "timestamp": "2024-03-15T03:22:14.000000Z",
  "device_id": "DESKTOP-ABC123",
  "owner": "dsmith",
  "source_type": "sleuthkit",
  "source_parser": "fls_timeline",
  "event_type": "file_creation",
  "summary": "File created: C:\\Users\\dsmith\\AppData\\Local\\Temp\\update.exe",
  "detail": {
    "path": "C:\\Users\\dsmith\\AppData\\Local\\Temp\\update.exe",
    "inode": 48291,
    "size_bytes": 245760,
    "timestamps": {
      "created": "2024-03-15T03:22:14Z",
      "modified": "2024-03-14T15:00:00Z",
      "accessed": "2024-03-15T03:22:14Z",
      "mft_modified": "2024-03-15T03:22:14Z"
    }
  },
  "suspicious": true,
  "suspicion_reason": "Executable in temp dir created at 3:22 AM; modification time predates creation (possible timestomp)",
  "behavioral_flags": ["off_hours_creation", "temp_dir_executable", "possible_timestomp"]
}
```

### 1.4 Behavioral Flag Schema

```json
{
  "flag_id": "bf-a1b2c3d4",
  "device_id": "DESKTOP-ABC123",
  "flag_type": "process_anomaly",
  "severity": "HIGH",
  "confidence": "HIGH",
  "summary": "svchost.exe running from C:\\Users\\dsmith\\AppData\\Local\\Temp\\",
  "evidence": {
    "process_name": "svchost.exe",
    "pid": 4128,
    "path": "C:\\Users\\dsmith\\AppData\\Local\\Temp\\svchost.exe",
    "expected_path": "C:\\Windows\\System32\\svchost.exe",
    "parent": "explorer.exe",
    "expected_parent": "services.exe",
    "network_connections": [
      {"dest_ip": "185.141.63.120", "dest_port": 443, "protocol": "TCP"}
    ]
  },
  "explanation": "svchost.exe is a critical Windows system process that should only run from System32 and be spawned by services.exe. This instance is running from a temp directory and was spawned by explorer.exe, which is a strong indicator of malware masquerading as a system process.",
  "mitre_att_ck": ["T1036.005"],
  "related_timeline_events": ["2024-03-15T03:22:14Z", "2024-03-15T03:22:18Z"]
}
```

### 1.5 Narrative Report Structure (`case_work_dir/reports/narrative_report.json`)

```json
{
  "generated_at": "2024-03-16T14:30:00Z",
  "executive_summary": "Investigation of evidence from 2 devices belonging to Dave Smith (dsmith) revealed indicators of compromise on the Windows workstation DESKTOP-ABC123. A suspicious executable was found in a temporary directory...",
  "user_narratives": {
    "dsmith": {
      "summary": "Dave Smith typically logs into DESKTOP-ABC123 between 8:30-9:00 AM on weekdays...",
      "devices_analyzed": ["DESKTOP-ABC123", "DSmith-iPhone"],
      "normal_behavior_profile": {
        "typical_login_hours": "08:30-09:00",
        "common_applications": ["chrome.exe", "outlook.exe", "excel.exe", "teams.exe"],
        "common_websites": ["outlook.office.com", "msn.com", "sharepoint.com"],
        "typical_activity_hours": "08:30-17:30"
      },
      "anomalous_activity": [
        "File update.exe created at 03:22 AM in temp directory",
        "Process svchost.exe spawned from wrong location at 03:22 AM"
      ]
    }
  },
  "significant_events_timeline": [
    {
      "timestamp": "2024-03-15T03:22:14Z",
      "device": "DESKTOP-ABC123",
      "description": "Suspicious executable update.exe created in temp directory",
      "severity": "HIGH"
    }
  ],
  "findings_by_severity": {
    "CRITICAL": [],
    "HIGH": ["Masquerading system process (svchost.exe in temp dir)", "Timestomped executable"],
    "MEDIUM": ["Outbound connection to suspicious IP"],
    "LOW": []
  },
  "conclusion": "Evidence indicates targeted compromise of Dave Smith's workstation. The attack vector appears to be...",
  "recommendations": [
    "Isolate DESKTOP-ABC123 from the network immediately",
    "Reset credentials for dsmith across all systems",
    "Investigate 185.141.63.120 for additional C2 infrastructure"
  ]
}
```

---

## 2. SPECIFIC CODE CHANGES TO `geoff_integrated.py`

### 2.1 New imports (add at top, after existing imports ~line 42)

```python
from device_discovery import DeviceDiscovery
from host_correlator import HostCorrelator
from super_timeline import SuperTimeline
from narrative_report import NarrativeReportGenerator
from behavioral_analyzer import BehavioralAnalyzer
```

### 2.2 Modify `_inventory_evidence()` (line 1136)

Keep this function AS-IS. It stays as the low-level file classifier.
DeviceDiscovery wraps it and adds the grouping layer on top.

### 2.3 Modify `find_evil()` — Phase 1 (line 1398-1404)

**REPLACE:**
```python
    # Phase 1: Evidence Inventory
    inventory = _inventory_evidence(evidence_path)
    os_type = _detect_os(inventory)
    indicator_hits = _scan_triage_indicators(inventory)
```

**WITH:**
```python
    # Phase 1: Evidence Inventory
    inventory = _inventory_evidence(evidence_path)

    # Phase 1a: Device Discovery & User Attribution
    _update_job(3, "discovery", "Identifying devices and users")
    device_disc = DeviceDiscovery(orchestrator)
    device_map, user_map = device_disc.discover(evidence_path, inventory)
    _fe_log(job_id, f"Discovered {len(device_map)} devices, {len(user_map)} users")

    for dev_id, dev in device_map.items():
        _fe_log(job_id, f"  Device: {dev_id} ({dev['device_type']}) "
                        f"owner={dev.get('owner', 'unknown')} "
                        f"files={len(dev['evidence_files'])}")

    # Determine OS from dominant device type (for playbook selection)
    os_type = _detect_os_from_devices(device_map)
    # Triage indicators still useful for initial severity classification
    indicator_hits = _scan_triage_indicators(inventory)
```

### 2.4 Add new helper function `_detect_os_from_devices()`

```python
def _detect_os_from_devices(device_map: dict) -> str:
    """Determine dominant OS from device map for playbook selection."""
    os_counts = {}
    for dev in device_map.values():
        os_t = dev.get("os_type", "unknown")
        os_counts[os_t] = os_counts.get(os_t, 0) + 1
    if not os_counts:
        return "unknown"
    # Return most common OS type, excluding 'network' and 'unknown'
    filtered = {k: v for k, v in os_counts.items() if k not in ("network", "unknown")}
    if filtered:
        return max(filtered, key=filtered.get)
    return "unknown"
```

### 2.5 Modify Phase 1b — Partition Detection (line 1410)

Change from iterating `inventory["disk_images"]` to iterating per-device:

```python
    # Phase 1b: Detect partition offsets per device
    image_offsets = {}
    for dev_id, dev in device_map.items():
        for img in dev["evidence_files"]:
            if img in inventory.get("disk_images", []):
                # ... existing partition detection code unchanged ...
```

### 2.6 Write device_map and user_map to case directory (after line 1464)

```python
    # Write device and user maps
    _atomic_write(
        case_work_dir / "device_map.json",
        json.dumps(device_map, indent=2, default=str)
    )
    _atomic_write(
        case_work_dir / "user_map.json",
        json.dumps(user_map, indent=2, default=str)
    )
```

### 2.7 Modify Playbook Execution Loop (line 1747)

This is the biggest structural change. The current loop is:

```python
for pb_idx, playbook_id in enumerate(execution_plan):
    ...
    for ev_type, step_templates in pb_steps_def.items():
        evidence_items = ev.get(ev_type, [])
        ...
        for item in items:
            ...
```

**CHANGE TO:** Outer loop by device, inner loop by playbook.
Each step_record now carries device_id.

```python
    # Build per-device evidence lookup
    device_evidence = {}  # device_id -> {ev_type: [paths]}
    for dev_id, dev in device_map.items():
        device_evidence[dev_id] = {
            "disk_images": [],
            "memory_dumps": [],
            "pcaps": [],
            "evtx_logs": [],
            "syslogs": [],
            "registry_hives": [],
            "mobile_backups": [],
            "other_files": [],
        }
        for fpath in dev["evidence_files"]:
            for ev_type in inventory:
                if isinstance(inventory[ev_type], list) and fpath in inventory[ev_type]:
                    device_evidence[dev_id][ev_type].append(fpath)

    # Execute playbooks PER DEVICE
    for dev_id, dev in device_map.items():
        dev_ev = device_evidence[dev_id]
        _fe_log(job_id, f"\n{'='*60}")
        _fe_log(job_id, f"Processing device: {dev_id} ({dev['device_type']})")
        _fe_log(job_id, f"Owner: {dev.get('owner', 'unknown')}")
        _fe_log(job_id, f"{'='*60}")

        for pb_idx, playbook_id in enumerate(execution_plan):
            ...  # existing playbook logic, but using dev_ev instead of ev

            # IN EVERY step_record CREATION, add:
            step_record["device_id"] = dev_id
            step_record["owner"] = dev.get("owner")
```

**IMPORTANT:** The `ev` dict (line 1556) that currently holds ALL evidence needs to be replaced with `dev_ev` inside this loop. The per-item iteration stays the same, just scoped to one device's files.

For **network captures** and **EVTX logs** that might not clearly belong to one device, handle them in a final pass after the per-device loop:

```python
    # Process unattributed evidence (PCAPs, logs not tied to a specific device)
    unattributed_ev = {
        ev_type: [f for f in files
                  if not any(f in device_evidence[d].get(ev_type, [])
                             for d in device_evidence)]
        for ev_type, files in inventory.items()
        if isinstance(files, list)
    }
    if any(unattributed_ev.values()):
        _fe_log(job_id, f"\nProcessing unattributed evidence...")
        # Run network/log playbooks against unattributed evidence
        # with device_id = "unattributed"
```

### 2.8 Replace Phase 3b/3c with Super-Timeline + Behavioral + Correlation

**DELETE** the entire Phase 3b (lines 2035-2072) and Phase 3c (lines 2073-2253).

**REPLACE WITH:**

```python
    # ------------------------------------------------------------------
    # Phase 3b: Super-Timeline Build
    # ------------------------------------------------------------------
    _update_job(90, "super-timeline", "Building unified timeline")

    super_tl = SuperTimeline()
    super_timeline_path, super_timeline_events = super_tl.build(
        device_map=device_map,
        findings=findings,
        case_work_dir=case_work_dir,
        plaso_specialist=orchestrator.plaso_specialist,  # or however Plaso is accessed
        job_id=job_id,
        fe_log_func=_fe_log,
    )
    _fe_log(job_id, f"Super-timeline: {len(super_timeline_events)} events across "
                     f"{len(device_map)} devices")

    # ------------------------------------------------------------------
    # Phase 3c: Behavioral Analysis (per device)
    # ------------------------------------------------------------------
    _update_job(93, "behavioral", "Analyzing process and file behavior")

    behavioral = BehavioralAnalyzer()
    all_behavioral_flags = {}
    for dev_id in device_map:
        dev_findings = [f for f in findings if f.get("device_id") == dev_id]
        dev_events = [e for e in super_timeline_events
                      if e.get("device_id") == dev_id]
        flags = behavioral.analyze(
            device_id=dev_id,
            findings=dev_findings,
            timeline_events=dev_events,
            call_llm_func=call_llm,
        )
        all_behavioral_flags[dev_id] = flags
        if flags:
            _fe_log(job_id, f"  {dev_id}: {len(flags)} behavioral flags")

    # Tag super-timeline events with behavioral flags
    super_tl.apply_behavioral_flags(super_timeline_events, all_behavioral_flags)

    # ------------------------------------------------------------------
    # Phase 3d: Cross-Host Correlation
    # ------------------------------------------------------------------
    _update_job(95, "correlation", "Correlating activity across hosts")

    correlator = HostCorrelator()
    correlated_users = correlator.correlate(
        device_map=device_map,
        user_map=user_map,
        findings=findings,
        timeline_events=super_timeline_events,
    )
    _fe_log(job_id, f"Correlated {len(correlated_users)} users across devices")
```

### 2.9 Add Narrative Report Generation (after existing Phase 5, ~line 2376)

```python
    # ------------------------------------------------------------------
    # Phase 5b: Narrative Report
    # ------------------------------------------------------------------
    _update_job(98, "narrative", "Generating human-readable report")

    narrator = NarrativeReportGenerator(call_llm_func=call_llm)
    narrative_path = narrator.generate(
        report_json=report,  # the dict built in Phase 4
        device_map=device_map,
        user_map=user_map,
        super_timeline_path=str(super_timeline_path),
        correlated_users=correlated_users,
        behavioral_flags=all_behavioral_flags,
        case_work_dir=case_work_dir,
    )
    report["narrative_report_path"] = str(narrative_path)
    report["device_map"] = device_map
    report["user_map"] = user_map
    report["behavioral_flags_summary"] = {
        dev_id: len(flags)
        for dev_id, flags in all_behavioral_flags.items()
    }
    _fe_log(job_id, f"Narrative report: {narrative_path}")
```

### 2.10 Chat Trigger for Ingestion (modify `chat()` at line 3183)

Add this block BEFORE the existing `detect_tool_request()` call:

```python
    # Check for ingestion/processing trigger
    ingest_triggers = ['start processing', 'process evidence', 'ingest',
                       'analyze evidence', 'find evil', 'begin investigation',
                       'start analysis', 'run analysis']
    if any(trigger in user_msg.lower() for trigger in ingest_triggers):
        # Extract path if mentioned, otherwise use default
        evidence_dir = _extract_path_from_message(user_msg) or EVIDENCE_BASE_DIR

        if not Path(evidence_dir).exists():
            return jsonify({
                'response': f"Evidence directory not found: {evidence_dir}\n"
                            f"Default: {EVIDENCE_BASE_DIR}",
            })

        # Use the existing async find_evil mechanism
        job_id = f"fe-{uuid.uuid4().hex[:12]}"
        with _state_lock:
            _find_evil_jobs[job_id] = {
                "status": "running",
                "progress_pct": 0.0,
                "current_playbook": "initializing",
                "current_step": "",
                "elapsed_seconds": 0.0,
                "started_at": datetime.now().isoformat(),
                "result": None,
                "error": None,
                "log": [{"time": datetime.now().strftime("%H:%M:%S"),
                         "msg": f"Find Evil started from chat: {evidence_dir}"}],
            }

        def _run():
            try:
                report = find_evil(evidence_dir, job_id=job_id)
                with _state_lock:
                    _find_evil_jobs[job_id]["status"] = "complete"
                    _find_evil_jobs[job_id]["result"] = report
            except Exception as e:
                with _state_lock:
                    _find_evil_jobs[job_id]["status"] = "error"
                    _find_evil_jobs[job_id]["error"] = str(e)

        threading.Thread(target=_run, daemon=True).start()

        return jsonify({
            'response': f"Roger that. Starting investigation on {evidence_dir}.\n"
                        f"Job ID: {job_id}\n"
                        f"I'll process all evidence, identify devices and users, "
                        f"build a unified timeline, and generate a narrative report.\n\n"
                        f"Poll /find-evil/status/{job_id} for progress.",
            'investigation_started': True,
            'job_id': job_id,
        })
```

Add the path extraction helper:

```python
def _extract_path_from_message(msg: str) -> str:
    """Extract a filesystem path from a chat message."""
    # Match absolute paths like /home/... or /evidence/...
    import re
    match = re.search(r'(/[a-zA-Z0-9._/-]+)', msg)
    if match:
        candidate = match.group(1)
        if os.path.exists(candidate):
            return candidate
    return ""
```

---

## 3. NEW FILE: `src/device_discovery.py` — DETAILED IMPLEMENTATION

```python
#!/usr/bin/env python3
"""
Device Discovery — Identifies hosts, devices, and owners from evidence.
"""

import json
import os
import re
import struct
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any
from datetime import datetime


class DeviceDiscovery:
    """
    Takes an evidence directory + inventory and produces:
      - device_map: dict[device_id] -> device info
      - user_map: dict[username] -> user info with device list
    """

    def __init__(self, orchestrator):
        """
        Args:
            orchestrator: The ExtendedOrchestrator from sift_specialists_extended.py
                          Used to call SleuthKit tools for hostname/user extraction.
        """
        self.orchestrator = orchestrator
        self.log = []

    def discover(self, evidence_path: Path, inventory: dict) -> Tuple[dict, dict]:
        """
        Main entry point.

        Returns:
            (device_map, user_map) — both are plain dicts, JSON-serializable.
        """
        evidence_path = Path(evidence_path)
        device_map = {}
        user_map = {}

        # Strategy 1: Check if top-level subdirectories contain evidence
        # (Most common collection layout: evidence/pc1/, evidence/phone/, etc.)
        subdirs = [d for d in evidence_path.iterdir()
                   if d.is_dir() and not d.name.startswith('.')]
        subdir_has_evidence = {}
        for sd in subdirs:
            sd_files = set()
            for ev_type, file_list in inventory.items():
                if not isinstance(file_list, list):
                    continue
                for fpath in file_list:
                    if str(fpath).startswith(str(sd)):
                        sd_files.add(fpath)
            if sd_files:
                subdir_has_evidence[sd.name] = sd_files

        if len(subdir_has_evidence) > 1:
            # Multiple evidence-containing subdirs = multiple devices
            self._log("dir_structure",
                      f"Found {len(subdir_has_evidence)} evidence subdirectories")
            for subdir_name, files in subdir_has_evidence.items():
                dev_id = self._sanitize_device_id(subdir_name)
                device_map[dev_id] = {
                    "device_id": dev_id,
                    "device_type": "unknown",
                    "hostname": None,
                    "owner": None,
                    "owner_confidence": "NONE",
                    "os_type": "unknown",
                    "evidence_files": sorted(files),
                    "evidence_types": self._classify_files(files, inventory),
                    "discovery_method": "directory_structure",
                    "metadata": {},
                }
        elif len(subdir_has_evidence) == 1:
            # Single subdir — treat as one device
            subdir_name = list(subdir_has_evidence.keys())[0]
            files = list(subdir_has_evidence.values())[0]
            dev_id = self._sanitize_device_id(subdir_name)
            device_map[dev_id] = {
                "device_id": dev_id,
                "device_type": "unknown",
                "hostname": None,
                "owner": None,
                "owner_confidence": "NONE",
                "os_type": "unknown",
                "evidence_files": sorted(files),
                "evidence_types": self._classify_files(files, inventory),
                "discovery_method": "directory_structure",
                "metadata": {},
            }
        else:
            # No subdirectory structure — all files are in root
            # Group by evidence file (each disk image = potential device)
            # PCAPs, logs = separate "devices"
            self._log("flat_layout",
                      "No subdirectory structure; grouping by evidence file")
            dev_idx = 0
            for img in inventory.get("disk_images", []):
                dev_id = Path(img).stem
                device_map[dev_id] = {
                    "device_id": dev_id,
                    "device_type": "unknown",
                    "hostname": None,
                    "owner": None,
                    "owner_confidence": "NONE",
                    "os_type": "unknown",
                    "evidence_files": [img],
                    "evidence_types": ["disk_images"],
                    "discovery_method": "disk_image_filename",
                    "metadata": {},
                }
            for mem in inventory.get("memory_dumps", []):
                # Try to associate with a disk image device by name similarity
                mem_stem = Path(mem).stem.lower()
                matched = False
                for dev_id in device_map:
                    if dev_id.lower() in mem_stem or mem_stem in dev_id.lower():
                        device_map[dev_id]["evidence_files"].append(mem)
                        device_map[dev_id]["evidence_types"].append(
                            "memory_dumps")
                        matched = True
                        break
                if not matched:
                    dev_id = f"memdump_{Path(mem).stem}"
                    device_map[dev_id] = {
                        "device_id": dev_id,
                        "device_type": "unknown",
                        "hostname": None,
                        "owner": None,
                        "owner_confidence": "NONE",
                        "os_type": "unknown",
                        "evidence_files": [mem],
                        "evidence_types": ["memory_dumps"],
                        "discovery_method": "memory_dump_filename",
                        "metadata": {},
                    }
            # PCAPs as network capture devices
            for pcap in inventory.get("pcaps", []):
                dev_id = f"pcap_{Path(pcap).stem}"
                device_map[dev_id] = {
                    "device_id": dev_id,
                    "device_type": "network_capture",
                    "hostname": None,
                    "owner": None,
                    "owner_confidence": "NONE",
                    "os_type": "network",
                    "evidence_files": [pcap],
                    "evidence_types": ["pcaps"],
                    "discovery_method": "pcap_filename",
                    "metadata": {},
                }
            # Mobile backups
            for mob in inventory.get("mobile_backups", []):
                mob_dir = str(Path(mob).parent)
                dev_id = f"mobile_{Path(mob_dir).name}"
                if dev_id not in device_map:
                    device_map[dev_id] = {
                        "device_id": dev_id,
                        "device_type": "mobile",
                        "hostname": None,
                        "owner": None,
                        "owner_confidence": "NONE",
                        "os_type": "mobile",
                        "evidence_files": [],
                        "evidence_types": ["mobile_backups"],
                        "discovery_method": "mobile_backup",
                        "metadata": {},
                    }
                device_map[dev_id]["evidence_files"].append(mob)

            # Assign orphaned files (registry, evtx, syslogs) to
            # nearest disk image device or create catchall
            orphans = (
                inventory.get("registry_hives", []) +
                inventory.get("evtx_logs", []) +
                inventory.get("syslogs", []) +
                inventory.get("other_files", [])
            )
            for orphan in orphans:
                assigned = False
                orphan_dir = str(Path(orphan).parent)
                for dev_id, dev in device_map.items():
                    for ef in dev["evidence_files"]:
                        if str(Path(ef).parent) == orphan_dir:
                            dev["evidence_files"].append(orphan)
                            assigned = True
                            break
                    if assigned:
                        break
                # If truly orphaned, add to first device or create catchall
                if not assigned and device_map:
                    first_dev = list(device_map.keys())[0]
                    device_map[first_dev]["evidence_files"].append(orphan)

        # Strategy 2: Enrich each device with hostname/OS/owner
        for dev_id in list(device_map.keys()):
            dev = device_map[dev_id]
            self._enrich_device(dev, inventory)

            # If enrichment found a better hostname, re-key the map
            if (dev["hostname"] and
                    dev["hostname"] != dev_id and
                    dev["discovery_method"] != "registry_hostname"):
                new_id = self._sanitize_device_id(dev["hostname"])
                if new_id != dev_id and new_id not in device_map:
                    dev["device_id"] = new_id
                    device_map[new_id] = dev
                    del device_map[dev_id]

        # Strategy 3: Build user map from discovered owners + user profiles
        all_users = {}  # normalized_username -> {aliases, devices}
        for dev_id, dev in device_map.items():
            owner = dev.get("owner")
            if owner:
                norm = self._normalize_username(owner)
                if norm not in all_users:
                    all_users[norm] = {
                        "username": norm,
                        "display_name": owner,
                        "aliases": set(),
                        "devices": [],
                    }
                all_users[norm]["devices"].append(dev_id)
                all_users[norm]["aliases"].add(owner)

            # Also check user profiles in metadata
            for profile in dev.get("metadata", {}).get(
                    "user_profiles_found", []):
                norm = self._normalize_username(profile)
                if norm not in all_users:
                    all_users[norm] = {
                        "username": norm,
                        "display_name": profile,
                        "aliases": set(),
                        "devices": [],
                    }
                if dev_id not in all_users[norm]["devices"]:
                    all_users[norm]["devices"].append(dev_id)
                all_users[norm]["aliases"].add(profile)

        # Convert sets to lists for JSON
        user_map = {}
        for uname, udata in all_users.items():
            user_map[uname] = {
                "username": uname,
                "display_name": udata["display_name"],
                "aliases": sorted(udata["aliases"]),
                "devices": udata["devices"],
                "primary_device": udata["devices"][0]
                    if udata["devices"] else None,
                "confidence": "HIGH" if len(udata["devices"]) > 1 else "MEDIUM",
            }

        return device_map, user_map

    def _enrich_device(self, dev: dict, inventory: dict):
        """
        Try to extract hostname, OS type, owner, and user profiles
        from the device's evidence files.
        """
        # Check for disk images — extract hostname from filesystem
        for fpath in dev["evidence_files"]:
            if fpath in inventory.get("disk_images", []):
                self._enrich_from_disk_image(dev, fpath)
                break  # One disk image per device is enough

        # Check for mobile backups
        for fpath in dev["evidence_files"]:
            fname = Path(fpath).name.lower()
            if fname == "info.plist":
                self._enrich_from_ios_plist(dev, fpath)
            elif fname == "manifest.db":
                dev["device_type"] = "ios_mobile"
                dev["os_type"] = "ios"

        # Check for registry hives directly
        for fpath in dev["evidence_files"]:
            fname = Path(fpath).name.lower()
            if fname == "system":
                self._enrich_from_system_hive(dev, fpath)
            elif fname in ("ntuser.dat", "usrclass.dat"):
                dev["os_type"] = "windows"
                dev["device_type"] = "windows_pc"

        # Infer device type from OS
        if dev["os_type"] == "windows" and dev["device_type"] == "unknown":
            dev["device_type"] = "windows_pc"
        elif dev["os_type"] == "linux" and dev["device_type"] == "unknown":
            dev["device_type"] = "linux_server"
        elif dev["os_type"] == "macos" and dev["device_type"] == "unknown":
            dev["device_type"] = "macos_workstation"

    def _enrich_from_disk_image(self, dev: dict, image_path: str):
        """
        Use SleuthKit fls to look for hostname/OS indicators in a disk image.

        Developer note: Use the orchestrator's SLEUTHKIT_Specialist to run:
          1. fls -r to get file listing
          2. Look for Windows/System32/config/SYSTEM (→ hostname)
          3. Look for Users/ directory (→ user profiles)
          4. Look for /etc/hostname (→ Linux hostname)
          5. Use icat to extract small files for parsing

        The existing specialist already handles partition offsets.
        """
        try:
            # Get partition offset from existing detection
            # (will be in image_offsets dict in find_evil scope —
            #  pass it through or re-detect here)
            from sift_specialists import SLEUTHKIT_Specialist
            sk = SLEUTHKIT_Specialist(evidence_path=image_path)

            # Quick file listing to find hostname indicators
            # Use a non-recursive listing of key directories first
            fls_result = sk.list_files(image_path, recursive=False)
            if fls_result.get("status") != "success":
                return

            file_listing = fls_result.get("stdout", "")
            file_listing_lower = file_listing.lower()

            # Detect OS from filesystem contents
            if "windows" in file_listing_lower or "system32" in file_listing_lower:
                dev["os_type"] = "windows"
                dev["device_type"] = "windows_pc"
                # Extract user profiles from Users/ directory
                self._extract_windows_users(dev, file_listing)
            elif "etc" in file_listing_lower and "bin" in file_listing_lower:
                dev["os_type"] = "linux"
                dev["device_type"] = "linux_server"
            elif "library" in file_listing_lower and "applications" in file_listing_lower:
                dev["os_type"] = "macos"
                dev["device_type"] = "macos_workstation"

        except Exception as e:
            self._log("enrich_error",
                      f"Failed to enrich {dev['device_id']}: {e}")

    def _extract_windows_users(self, dev: dict, file_listing: str):
        """
        Parse fls output to find user profile directories under Users/.
        Skip: Default, Public, All Users, desktop.ini
        """
        skip_profiles = {"default", "public", "all users", "default user",
                         "desktop.ini", ".", ".."}
        profiles = []
        in_users = False
        for line in file_listing.split("\n"):
            line_lower = line.lower().strip()
            # fls output format: "d/d 12345: Users/username"
            if "/users/" in line_lower or "\\users\\" in line_lower:
                # Extract the username portion
                parts = line.split("/")
                for i, part in enumerate(parts):
                    if part.lower().strip().rstrip(":") == "users" and i + 1 < len(parts):
                        uname = parts[i + 1].strip().rstrip("/")
                        if uname.lower() not in skip_profiles and uname:
                            profiles.append(uname)

        profiles = list(set(profiles))
        dev["metadata"]["user_profiles_found"] = profiles
        if len(profiles) == 1:
            dev["owner"] = profiles[0]
            dev["owner_confidence"] = "MEDIUM"
        elif profiles:
            # Multiple profiles — pick the non-admin one if possible
            non_admin = [p for p in profiles
                         if p.lower() not in ("administrator", "admin",
                                              "defaultuser0")]
            if len(non_admin) == 1:
                dev["owner"] = non_admin[0]
                dev["owner_confidence"] = "MEDIUM"

    def _enrich_from_system_hive(self, dev: dict, hive_path: str):
        """
        Parse SYSTEM registry hive for ComputerName.

        Developer note: Use regripper or the registry specialist to parse:
          ControlSet001\\Control\\ComputerName\\ComputerName
        The orchestrator already has registry.parse_hive().
        """
        try:
            result = self.orchestrator.run_playbook_step(
                "device-discovery",
                {"module": "registry", "function": "parse_hive",
                 "params": {"hive_path": hive_path}}
            )
            if result.get("status") == "success":
                output = json.dumps(result, default=str).lower()
                # Look for computername in the output
                match = re.search(
                    r'computername["\s:=]+([a-zA-Z0-9_-]+)', output,
                    re.IGNORECASE
                )
                if match:
                    hostname = match.group(1).upper()
                    dev["hostname"] = hostname
                    dev["discovery_method"] = "registry_hostname"
                    self._log("hostname_found",
                              f"Hostname from SYSTEM hive: {hostname}")
        except Exception as e:
            self._log("hive_parse_error", f"Failed to parse SYSTEM: {e}")

    def _enrich_from_ios_plist(self, dev: dict, plist_path: str):
        """
        Parse iOS Info.plist for device name and owner.

        The device name is typically "Dave's iPhone" which gives us both
        the owner name and device type.
        """
        try:
            import plistlib
            with open(plist_path, "rb") as f:
                plist = plistlib.load(f)
            device_name = plist.get("Device Name", "")
            if device_name:
                dev["hostname"] = device_name
                dev["device_type"] = "ios_mobile"
                dev["os_type"] = "ios"
                dev["os_version"] = plist.get("Product Version", "")
                # Extract owner from "Dave's iPhone" pattern
                match = re.match(r"^(.+?)['']s\s+(iphone|ipad|ipod)",
                                 device_name, re.IGNORECASE)
                if match:
                    dev["owner"] = match.group(1)
                    dev["owner_confidence"] = "HIGH"
                    dev["discovery_method"] = "ios_plist_device_name"
        except Exception as e:
            self._log("plist_error",
                      f"Failed to parse Info.plist: {e}")

    def _classify_files(self, files, inventory) -> list:
        """Return list of evidence type strings for given files."""
        types = set()
        for fpath in files:
            for ev_type, file_list in inventory.items():
                if isinstance(file_list, list) and fpath in file_list:
                    types.add(ev_type)
        return sorted(types)

    @staticmethod
    def _normalize_username(username: str) -> str:
        """Normalize username: strip domain, lowercase."""
        # CORP\dsmith -> dsmith
        if "\\" in username:
            username = username.split("\\")[-1]
        # dsmith@corp.local -> dsmith
        if "@" in username:
            username = username.split("@")[0]
        return username.lower().strip()

    @staticmethod
    def _sanitize_device_id(name: str) -> str:
        """Create a safe device_id from a name."""
        # Replace spaces and special chars with underscores
        safe = re.sub(r'[^a-zA-Z0-9_-]', '_', name)
        return safe.strip('_') or "unknown_device"

    def _log(self, action: str, detail: str):
        self.log.append({
            "timestamp": datetime.now().isoformat(),
            "action": action,
            "detail": detail,
        })
```

---

## 4. NEW FILE: `src/behavioral_analyzer.py` — KEY DETECTION RULES

```python
#!/usr/bin/env python3
"""
Behavioral Analyzer — Replaces YARA with evidence-based anomaly detection.
Examines processes, files, network, and timeline for things that don't
belong, based on what we extracted from the images.
"""

import json
import re
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Any, Callable, Optional


# ---------------------------------------------------------------
# Known-good baselines for Windows process validation
# ---------------------------------------------------------------

# process_name -> list of expected parent process names
EXPECTED_PARENTS = {
    "smss.exe":       ["system"],
    "csrss.exe":      ["smss.exe"],
    "wininit.exe":    ["smss.exe"],
    "winlogon.exe":   ["smss.exe"],
    "services.exe":   ["wininit.exe"],
    "lsass.exe":      ["wininit.exe"],
    "lsaiso.exe":     ["wininit.exe"],
    "svchost.exe":    ["services.exe"],
    "taskhostw.exe":  ["svchost.exe"],
    "RuntimeBroker.exe": ["svchost.exe"],
    "spoolsv.exe":    ["services.exe"],
    "SearchIndexer.exe": ["services.exe"],
    "dllhost.exe":    ["svchost.exe", "services.exe"],
    "taskhost.exe":   ["svchost.exe", "services.exe"],
    "userinit.exe":   ["winlogon.exe"],
    "explorer.exe":   ["userinit.exe", "winlogon.exe"],
}

# process_name -> list of expected path prefixes (lowercased)
EXPECTED_PATHS = {
    "svchost.exe":    ["c:\\windows\\system32\\"],
    "lsass.exe":      ["c:\\windows\\system32\\"],
    "csrss.exe":      ["c:\\windows\\system32\\"],
    "services.exe":   ["c:\\windows\\system32\\"],
    "smss.exe":       ["c:\\windows\\system32\\"],
    "winlogon.exe":   ["c:\\windows\\system32\\"],
    "wininit.exe":    ["c:\\windows\\system32\\"],
    "explorer.exe":   ["c:\\windows\\"],
    "taskhostw.exe":  ["c:\\windows\\system32\\"],
    "spoolsv.exe":    ["c:\\windows\\system32\\"],
    "conhost.exe":    ["c:\\windows\\system32\\"],
    "dwm.exe":        ["c:\\windows\\system32\\"],
    "dllhost.exe":    ["c:\\windows\\system32\\", "c:\\windows\\syswow64\\"],
    "cmd.exe":        ["c:\\windows\\system32\\", "c:\\windows\\syswow64\\"],
    "powershell.exe": ["c:\\windows\\system32\\windowspowershell\\",
                       "c:\\windows\\syswow64\\windowspowershell\\"],
}

# Processes that should NEVER have outbound network connections
NO_NETWORK_EXPECTED = {
    "notepad.exe", "calc.exe", "mspaint.exe", "write.exe",
    "wordpad.exe", "charmap.exe", "snippingtool.exe",
    "narrator.exe", "magnify.exe",
}

# Suspicious parent → child combinations
SUSPICIOUS_SPAWN_CHAINS = [
    # Office spawning shell
    ("winword.exe", "cmd.exe"),
    ("winword.exe", "powershell.exe"),
    ("winword.exe", "wscript.exe"),
    ("winword.exe", "cscript.exe"),
    ("winword.exe", "mshta.exe"),
    ("excel.exe", "cmd.exe"),
    ("excel.exe", "powershell.exe"),
    ("outlook.exe", "cmd.exe"),
    ("outlook.exe", "powershell.exe"),
    # Browser spawning shell
    ("chrome.exe", "cmd.exe"),
    ("chrome.exe", "powershell.exe"),
    ("iexplore.exe", "cmd.exe"),
    ("msedge.exe", "cmd.exe"),
    # Unusual shell chains
    ("svchost.exe", "cmd.exe"),    # not always bad but worth flagging
    ("wmiprvse.exe", "powershell.exe"),
    ("wmiprvse.exe", "cmd.exe"),
]

# File extensions that are suspicious in temp/user directories
SUSPICIOUS_EXTENSIONS_IN_TEMP = {
    ".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs",
    ".js", ".wsf", ".hta", ".com", ".pif",
}

# File names that mimic system processes (typosquatting)
SYSTEM_PROCESS_NAMES = {
    "svchost.exe", "csrss.exe", "lsass.exe", "services.exe",
    "smss.exe", "winlogon.exe", "explorer.exe", "spoolsv.exe",
    "wininit.exe", "taskhostw.exe", "dwm.exe", "dllhost.exe",
    "conhost.exe", "cmd.exe", "powershell.exe",
}


class BehavioralAnalyzer:
    """
    Analyzes evidence for behavioral anomalies without YARA rules.
    Uses structured data from tool output + timeline to find evil.
    """

    def analyze(self, device_id: str, findings: List[dict],
                timeline_events: List[dict],
                call_llm_func: Callable) -> List[dict]:
        """
        Run all behavioral checks on one device.

        Args:
            device_id: The device being analyzed
            findings: All playbook findings for this device
            timeline_events: Super-timeline events for this device
            call_llm_func: Function to call LLM for ambiguous cases

        Returns:
            List of behavioral flag dicts
        """
        flags = []

        # Extract structured data from findings
        processes = self._extract_processes(findings)
        files = self._extract_files(findings, timeline_events)
        network_conns = self._extract_network(findings)
        registry_entries = self._extract_registry(findings)

        # ---- Deterministic checks (no LLM needed) ----

        # 1. Process path validation
        flags.extend(self._check_process_paths(processes))

        # 2. Process parent-child validation
        flags.extend(self._check_process_parents(processes))

        # 3. Processes with unexpected network activity
        flags.extend(self._check_process_network(processes, network_conns))

        # 4. Suspicious spawn chains
        flags.extend(self._check_spawn_chains(processes))

        # 5. Files in temp directories
        flags.extend(self._check_temp_executables(files))

        # 6. Timestomping detection
        flags.extend(self._check_timestomping(files))

        # 7. Process name typosquatting
        flags.extend(self._check_typosquatting(processes))

        # 8. Off-hours activity
        flags.extend(self._check_off_hours(timeline_events))

        # 9. Persistence pointing to temp/user dirs
        flags.extend(self._check_suspicious_persistence(registry_entries))

        # 10. Beaconing detection in network connections
        flags.extend(self._check_beaconing(network_conns))

        # ---- LLM-assisted analysis for ambiguous flags ----
        # Batch any MEDIUM-confidence flags and ask LLM for assessment
        ambiguous = [f for f in flags if f.get("confidence") == "MEDIUM"]
        if ambiguous and call_llm_func:
            flags = self._llm_assess_ambiguous(
                flags, ambiguous, device_id, call_llm_func)

        # Deduplicate and sort by severity
        flags = self._deduplicate_flags(flags)
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        flags.sort(key=lambda f: severity_order.get(
            f.get("severity", "LOW"), 4))

        return flags

    def _check_process_paths(self, processes: List[dict]) -> List[dict]:
        """Check if system processes are running from expected locations."""
        flags = []
        for proc in processes:
            name = proc.get("name", "").lower()
            path = proc.get("path", "").lower()
            if not path or not name:
                continue

            if name in EXPECTED_PATHS:
                expected = EXPECTED_PATHS[name]
                if not any(path.startswith(exp) for exp in expected):
                    flags.append({
                        "flag_id": f"bf-{uuid.uuid4().hex[:8]}",
                        "flag_type": "process_anomaly",
                        "severity": "HIGH",
                        "confidence": "HIGH",
                        "summary": f"{name} running from unexpected "
                                   f"path: {proc.get('path', '')}",
                        "evidence": {
                            "process_name": name,
                            "pid": proc.get("pid"),
                            "actual_path": proc.get("path"),
                            "expected_paths": expected,
                        },
                        "explanation": (
                            f"{name} is a Windows system process that should "
                            f"only run from {', '.join(expected)}. Running "
                            f"from {proc.get('path', '')} is a strong "
                            f"indicator of malware masquerading as a "
                            f"legitimate process."
                        ),
                        "mitre_att_ck": ["T1036.005"],
                    })
        return flags

    def _check_process_parents(self, processes: List[dict]) -> List[dict]:
        """Check if processes have expected parent processes."""
        flags = []
        pid_to_proc = {p.get("pid"): p for p in processes if p.get("pid")}

        for proc in processes:
            name = proc.get("name", "").lower()
            ppid = proc.get("ppid")
            if not name or not ppid:
                continue

            if name in EXPECTED_PARENTS:
                parent = pid_to_proc.get(ppid, {})
                parent_name = parent.get("name", "unknown").lower()
                expected = [p.lower() for p in EXPECTED_PARENTS[name]]

                if parent_name not in expected and parent_name != "unknown":
                    flags.append({
                        "flag_id": f"bf-{uuid.uuid4().hex[:8]}",
                        "flag_type": "process_anomaly",
                        "severity": "HIGH",
                        "confidence": "HIGH",
                        "summary": (
                            f"{name} (PID {proc.get('pid')}) has unexpected "
                            f"parent: {parent_name} "
                            f"(expected: {', '.join(EXPECTED_PARENTS[name])})"
                        ),
                        "evidence": {
                            "process_name": name,
                            "pid": proc.get("pid"),
                            "parent_name": parent_name,
                            "parent_pid": ppid,
                            "expected_parents": EXPECTED_PARENTS[name],
                        },
                        "explanation": (
                            f"{name} should be spawned by "
                            f"{', '.join(EXPECTED_PARENTS[name])}. "
                            f"Being spawned by {parent_name} suggests "
                            f"process injection or malware execution."
                        ),
                        "mitre_att_ck": ["T1055"],
                    })
        return flags

    def _check_process_network(self, processes: List[dict],
                               network_conns: List[dict]) -> List[dict]:
        """Flag processes that shouldn't have network connections."""
        flags = []
        proc_pids_with_net = set()
        for conn in network_conns:
            pid = conn.get("pid")
            if pid:
                proc_pids_with_net.add(pid)

        pid_to_proc = {p.get("pid"): p for p in processes}

        for pid in proc_pids_with_net:
            proc = pid_to_proc.get(pid, {})
            name = proc.get("name", "").lower()
            if name in NO_NETWORK_EXPECTED:
                # Find the connections for this PID
                pid_conns = [c for c in network_conns if c.get("pid") == pid]
                flags.append({
                    "flag_id": f"bf-{uuid.uuid4().hex[:8]}",
                    "flag_type": "network_anomaly",
                    "severity": "CRITICAL",
                    "confidence": "HIGH",
                    "summary": (
                        f"{name} (PID {pid}) has network connections "
                        f"({len(pid_conns)} connections)"
                    ),
                    "evidence": {
                        "process_name": name,
                        "pid": pid,
                        "connections": pid_conns[:10],
                    },
                    "explanation": (
                        f"{name} should never make network connections. "
                        f"This strongly indicates the process has been "
                        f"hijacked or is malware masquerading as {name}."
                    ),
                    "mitre_att_ck": ["T1071"],
                })
        return flags

    def _check_spawn_chains(self, processes: List[dict]) -> List[dict]:
        """Check for suspicious parent-child process chains."""
        flags = []
        pid_to_proc = {p.get("pid"): p for p in processes if p.get("pid")}

        for proc in processes:
            name = proc.get("name", "").lower()
            ppid = proc.get("ppid")
            parent = pid_to_proc.get(ppid, {})
            parent_name = parent.get("name", "").lower()

            for bad_parent, bad_child in SUSPICIOUS_SPAWN_CHAINS:
                if parent_name == bad_parent and name == bad_child:
                    flags.append({
                        "flag_id": f"bf-{uuid.uuid4().hex[:8]}",
                        "flag_type": "process_anomaly",
                        "severity": "HIGH",
                        "confidence": "MEDIUM",
                        "summary": (
                            f"Suspicious spawn chain: {bad_parent} → "
                            f"{bad_child} (PID {proc.get('pid')})"
                        ),
                        "evidence": {
                            "parent_process": parent_name,
                            "child_process": name,
                            "child_pid": proc.get("pid"),
                            "parent_pid": ppid,
                            "parent_path": parent.get("path"),
                            "child_path": proc.get("path"),
                        },
                        "explanation": (
                            f"{bad_parent} spawning {bad_child} is a common "
                            f"indicator of malicious macro execution or "
                            f"exploit delivery."
                        ),
                        "mitre_att_ck": ["T1059"],
                    })
        return flags

    def _check_temp_executables(self, files: List[dict]) -> List[dict]:
        """Flag executables found in temp/user directories."""
        flags = []
        temp_patterns = [
            "\\temp\\", "\\tmp\\", "/temp/", "/tmp/",
            "\\appdata\\local\\temp\\",
            "\\appdata\\roaming\\",
            "\\programdata\\",
            "\\downloads\\",
            "\\desktop\\",
        ]
        for f in files:
            path = f.get("path", "").lower()
            ext = "." + path.rsplit(".", 1)[-1] if "." in path else ""

            if ext in SUSPICIOUS_EXTENSIONS_IN_TEMP:
                in_temp = any(tp in path for tp in temp_patterns)
                if in_temp:
                    flags.append({
                        "flag_id": f"bf-{uuid.uuid4().hex[:8]}",
                        "flag_type": "file_anomaly",
                        "severity": "MEDIUM",
                        "confidence": "MEDIUM",
                        "summary": f"Executable in temp/user directory: "
                                   f"{f.get('path', '')}",
                        "evidence": {
                            "path": f.get("path"),
                            "size": f.get("size"),
                            "timestamps": f.get("timestamps", {}),
                        },
                        "explanation": (
                            f"Executables in temporary or user-writable "
                            f"directories are a common indicator of "
                            f"malware droppers or downloaded payloads."
                        ),
                        "mitre_att_ck": ["T1204"],
                    })
        return flags

    def _check_timestomping(self, files: List[dict]) -> List[dict]:
        """Detect timestomped files where creation > modification."""
        flags = []
        for f in files:
            ts = f.get("timestamps", {})
            created = ts.get("created", "")
            modified = ts.get("modified", "")
            if created and modified and created > modified:
                flags.append({
                    "flag_id": f"bf-{uuid.uuid4().hex[:8]}",
                    "flag_type": "file_anomaly",
                    "severity": "HIGH",
                    "confidence": "HIGH",
                    "summary": (
                        f"Possible timestomping: {f.get('path', '')} "
                        f"(created {created} > modified {modified})"
                    ),
                    "evidence": {
                        "path": f.get("path"),
                        "created": created,
                        "modified": modified,
                        "mft_modified": ts.get("mft_modified"),
                    },
                    "explanation": (
                        f"A file's creation timestamp is later than its "
                        f"modification timestamp, which is impossible under "
                        f"normal conditions. This is a strong indicator of "
                        f"timestamp manipulation (timestomping) to hide "
                        f"when the file actually appeared on the system."
                    ),
                    "mitre_att_ck": ["T1070.006"],
                })
        return flags

    def _check_typosquatting(self, processes: List[dict]) -> List[dict]:
        """Detect process names that are close to system processes."""
        flags = []
        for proc in processes:
            name = proc.get("name", "").lower()
            path = proc.get("path", "").lower()
            if name in SYSTEM_PROCESS_NAMES:
                # It IS a system process — check path instead
                continue
            # Check for close misspellings
            for sys_name in SYSTEM_PROCESS_NAMES:
                if self._is_typosquat(name, sys_name):
                    flags.append({
                        "flag_id": f"bf-{uuid.uuid4().hex[:8]}",
                        "flag_type": "process_anomaly",
                        "severity": "CRITICAL",
                        "confidence": "HIGH",
                        "summary": (
                            f"Process name typosquatting: '{proc.get('name')}'"
                            f" mimics '{sys_name}'"
                        ),
                        "evidence": {
                            "process_name": proc.get("name"),
                            "mimics": sys_name,
                            "pid": proc.get("pid"),
                            "path": proc.get("path"),
                        },
                        "explanation": (
                            f"Process '{proc.get('name')}' closely resembles "
                            f"the legitimate system process '{sys_name}'. "
                            f"This is a common malware technique to avoid "
                            f"detection by blending in with system processes."
                        ),
                        "mitre_att_ck": ["T1036.005"],
                    })
                    break
        return flags

    @staticmethod
    def _is_typosquat(name: str, system_name: str) -> bool:
        """Check if name is a close misspelling of system_name."""
        if name == system_name:
            return False
        if len(name) != len(system_name):
            # Allow off-by-one length
            if abs(len(name) - len(system_name)) > 1:
                return False
        # Levenshtein distance of 1-2 = likely typosquat
        # Simple implementation:
        diffs = sum(1 for a, b in zip(name, system_name) if a != b)
        len_diff = abs(len(name) - len(system_name))
        return (diffs + len_diff) <= 2 and (diffs + len_diff) >= 1

    def _check_off_hours(self, timeline_events: List[dict]) -> List[dict]:
        """Flag significant activity outside business hours (10PM-5AM)."""
        flags = []
        off_hours_events = []
        for event in timeline_events:
            ts = event.get("timestamp", "")
            if not ts:
                continue
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                hour = dt.hour
                if hour >= 22 or hour < 5:
                    etype = event.get("event_type", "")
                    # Only flag significant events, not routine system events
                    if etype in ("process_execution", "file_creation",
                                 "login", "network_connection"):
                        off_hours_events.append(event)
            except (ValueError, TypeError):
                continue

        if len(off_hours_events) >= 3:
            flags.append({
                "flag_id": f"bf-{uuid.uuid4().hex[:8]}",
                "flag_type": "timeline_anomaly",
                "severity": "MEDIUM",
                "confidence": "MEDIUM",
                "summary": (
                    f"{len(off_hours_events)} significant events "
                    f"outside business hours (10PM-5AM)"
                ),
                "evidence": {
                    "event_count": len(off_hours_events),
                    "sample_events": off_hours_events[:5],
                },
                "explanation": (
                    f"Multiple process executions, file creations, or "
                    f"network connections occurred outside normal hours. "
                    f"This may indicate automated malware activity or "
                    f"unauthorized access."
                ),
                "mitre_att_ck": [],
            })
        return flags

    def _check_suspicious_persistence(self,
                                      registry_entries: List[dict]) -> List[dict]:
        """Flag persistence mechanisms pointing to unusual locations."""
        flags = []
        persistence_keys = [
            "currentversion\\run",
            "currentversion\\runonce",
            "currentversion\\explorer\\shell folders",
        ]
        suspicious_paths = [
            "\\temp\\", "\\tmp\\", "\\appdata\\",
            "\\programdata\\", "\\users\\public\\",
            "\\downloads\\", "\\desktop\\",
        ]
        for entry in registry_entries:
            key = entry.get("key", "").lower()
            value = entry.get("value", "").lower()

            is_persistence = any(pk in key for pk in persistence_keys)
            is_suspicious_target = any(sp in value for sp in suspicious_paths)

            if is_persistence and is_suspicious_target:
                flags.append({
                    "flag_id": f"bf-{uuid.uuid4().hex[:8]}",
                    "flag_type": "persistence_anomaly",
                    "severity": "HIGH",
                    "confidence": "HIGH",
                    "summary": (
                        f"Persistence key points to suspicious location: "
                        f"{entry.get('value', '')}"
                    ),
                    "evidence": {
                        "registry_key": entry.get("key"),
                        "registry_value": entry.get("value"),
                    },
                    "explanation": (
                        f"A Run/RunOnce registry key is configured to "
                        f"execute a binary from a temp or user-writable "
                        f"directory. Legitimate software typically installs "
                        f"to Program Files, not temp directories."
                    ),
                    "mitre_att_ck": ["T1547.001"],
                })
        return flags

    def _check_beaconing(self, network_conns: List[dict]) -> List[dict]:
        """Detect beaconing patterns in network connections."""
        flags = []
        # Group connections by destination
        dest_groups = {}
        for conn in network_conns:
            dest = conn.get("dest_ip", "")
            if not dest or dest.startswith("127.") or dest.startswith("10.") \
               or dest.startswith("192.168.") or dest.startswith("172."):
                continue  # Skip internal/loopback
            if dest not in dest_groups:
                dest_groups[dest] = []
            ts = conn.get("timestamp", "")
            if ts:
                dest_groups[dest].append(ts)

        for dest, timestamps in dest_groups.items():
            if len(timestamps) < 5:
                continue
            # Check for regular intervals
            try:
                sorted_ts = sorted(timestamps)
                intervals = []
                for i in range(1, len(sorted_ts)):
                    t1 = datetime.fromisoformat(
                        sorted_ts[i-1].replace("Z", "+00:00"))
                    t2 = datetime.fromisoformat(
                        sorted_ts[i].replace("Z", "+00:00"))
                    intervals.append((t2 - t1).total_seconds())

                if not intervals:
                    continue

                avg = sum(intervals) / len(intervals)
                # Check if intervals are consistent (std dev < 20% of mean)
                variance = sum((x - avg) ** 2 for x in intervals) / len(intervals)
                std_dev = variance ** 0.5

                if avg > 0 and std_dev / avg < 0.2 and len(intervals) >= 4:
                    flags.append({
                        "flag_id": f"bf-{uuid.uuid4().hex[:8]}",
                        "flag_type": "network_anomaly",
                        "severity": "HIGH",
                        "confidence": "MEDIUM",
                        "summary": (
                            f"Beaconing pattern detected: {dest} "
                            f"({len(timestamps)} connections, "
                            f"~{avg:.0f}s interval)"
                        ),
                        "evidence": {
                            "dest_ip": dest,
                            "connection_count": len(timestamps),
                            "avg_interval_seconds": round(avg, 1),
                            "std_dev_seconds": round(std_dev, 1),
                        },
                        "explanation": (
                            f"Regular-interval connections to {dest} suggest "
                            f"C2 beaconing. Average interval: {avg:.0f}s "
                            f"with low variance ({std_dev:.1f}s)."
                        ),
                        "mitre_att_ck": ["T1071", "T1573"],
                    })
            except (ValueError, TypeError):
                continue

        return flags

    def _llm_assess_ambiguous(self, all_flags: List[dict],
                              ambiguous: List[dict],
                              device_id: str,
                              call_llm_func: Callable) -> List[dict]:
        """Ask LLM to assess MEDIUM-confidence flags."""
        if not ambiguous:
            return all_flags

        prompt = (
            f"You are a forensic analyst. Review these anomalies from "
            f"device {device_id} and rate each as MALICIOUS, SUSPICIOUS, "
            f"or BENIGN. Only base your assessment on the data provided.\n\n"
            f"Anomalies:\n"
        )
        for i, flag in enumerate(ambiguous[:10]):  # Max 10 for context window
            prompt += f"{i+1}. [{flag['flag_type']}] {flag['summary']}\n"
            prompt += f"   Evidence: {json.dumps(flag.get('evidence', {}), default=str)[:300]}\n"

        prompt += (
            f"\nRespond ONLY in JSON array format:\n"
            f'[{{"index": 1, "verdict": "MALICIOUS", "reason": "..."}}, ...]'
        )

        try:
            response = call_llm_func(prompt, agent_type="critic")
            # Parse JSON from response
            match = re.search(r'\[.*\]', response, re.DOTALL)
            if match:
                assessments = json.loads(match.group())
                for assessment in assessments:
                    idx = assessment.get("index", 0) - 1
                    if 0 <= idx < len(ambiguous):
                        verdict = assessment.get("verdict", "").upper()
                        if verdict == "MALICIOUS":
                            ambiguous[idx]["confidence"] = "HIGH"
                            ambiguous[idx]["severity"] = "HIGH"
                        elif verdict == "BENIGN":
                            ambiguous[idx]["confidence"] = "LOW"
                            ambiguous[idx]["severity"] = "LOW"
                        ambiguous[idx]["llm_assessment"] = assessment
        except Exception:
            pass  # LLM assessment is optional; deterministic flags stand

        return all_flags

    # ---- Data extraction helpers ----
    # These parse the findings dicts from playbook execution into
    # structured lists that the check methods can work with.

    def _extract_processes(self, findings: List[dict]) -> List[dict]:
        """Extract process list from Volatility findings."""
        processes = []
        for f in findings:
            if f.get("module") == "volatility" and \
               f.get("function") in ("process_list", "find_malware"):
                result = f.get("result", {})
                stdout = result.get("stdout", "")
                # Parse Volatility pslist output
                # Format: PID  PPID  ImageFileName  Offset  Threads ...
                for line in stdout.split("\n"):
                    parts = line.split()
                    if len(parts) >= 3:
                        try:
                            pid = int(parts[0])
                            ppid = int(parts[1])
                            name = parts[2]
                            processes.append({
                                "pid": pid,
                                "ppid": ppid,
                                "name": name,
                                "path": "",  # May need icat to get full path
                            })
                        except (ValueError, IndexError):
                            continue
        return processes

    def _extract_files(self, findings: List[dict],
                       timeline_events: List[dict]) -> List[dict]:
        """Extract file information from SleuthKit findings and timeline."""
        files = []
        for event in timeline_events:
            if event.get("event_type") in ("file_creation", "file_modification"):
                files.append({
                    "path": event.get("detail", {}).get("path", ""),
                    "size": event.get("detail", {}).get("size_bytes"),
                    "timestamps": event.get("detail", {}).get("timestamps", {}),
                })
        return files

    def _extract_network(self, findings: List[dict]) -> List[dict]:
        """Extract network connections from Volatility and PCAP findings."""
        connections = []
        for f in findings:
            if f.get("module") == "volatility" and \
               f.get("function") == "network_scan":
                result = f.get("result", {})
                stdout = result.get("stdout", "")
                # Parse Volatility netscan output
                for line in stdout.split("\n"):
                    # Format varies but typically:
                    # Offset  Proto  LocalAddr  ForeignAddr  State  PID  Owner
                    parts = line.split()
                    if len(parts) >= 6:
                        try:
                            local = parts[2]
                            foreign = parts[3]
                            pid = int(parts[5]) if parts[5].isdigit() else None
                            dest_ip = foreign.split(":")[0] if ":" in foreign else foreign
                            dest_port = int(foreign.split(":")[1]) if ":" in foreign else None
                            connections.append({
                                "pid": pid,
                                "dest_ip": dest_ip,
                                "dest_port": dest_port,
                                "protocol": parts[1] if len(parts) > 1 else "",
                                "timestamp": f.get("started_at", ""),
                            })
                        except (ValueError, IndexError):
                            continue
        return connections

    def _extract_registry(self, findings: List[dict]) -> List[dict]:
        """Extract registry entries from RegRipper findings."""
        entries = []
        for f in findings:
            if f.get("module") == "registry":
                result = f.get("result", {})
                stdout = result.get("stdout", "")
                # Parse regripper output — varies by plugin
                # Look for key=value patterns
                for line in stdout.split("\n"):
                    if " -> " in line or " = " in line:
                        parts = re.split(r'\s*(?:->|=)\s*', line, 1)
                        if len(parts) == 2:
                            entries.append({
                                "key": parts[0].strip(),
                                "value": parts[1].strip(),
                            })
        return entries

    @staticmethod
    def _deduplicate_flags(flags: List[dict]) -> List[dict]:
        """Remove duplicate flags based on summary text."""
        seen = set()
        deduped = []
        for f in flags:
            key = f.get("summary", "")
            if key not in seen:
                seen.add(key)
                deduped.append(f)
        return deduped
```

---

## 5. EDGE CASES YOUR DEVELOPER MUST HANDLE

### 5.1 Single-device cases
Most common scenario. The device_map has one entry, user_map has 1-2 users.
The per-device loop runs once. Cross-host correlation returns empty.
The narrative report should still work — just skip the "cross-device" section.

### 5.2 No disk images (logs only)
If only EVTX/syslog files are provided, DeviceDiscovery can't extract
hostnames from disk. Fall back to parsing the Computer field from EVTX
XML headers or the hostname in syslog lines.

### 5.3 Multi-part E01 images (.E01, .E02, .E03)
The existing inventory code already picks these up. DeviceDiscovery should
treat .E01/.E02/.E03 with the same stem as ONE device, not three.
Check: group by `Path(img).stem.rstrip('0123456789')` or similar.

### 5.4 Encrypted/damaged images
SleuthKit will return errors. DeviceDiscovery should handle this gracefully
and create the device entry with `"metadata": {"error": "unable to read"}`
but still include it in the device_map.

### 5.5 Memory dump + disk image for same host
Common in IR. If a .vmem and .E01 have similar names or are in the same
subdirectory, they should be grouped as ONE device. DeviceDiscovery already
handles this via the directory-structure strategy.

### 5.6 Very large timelines
A full Plaso timeline can produce millions of events. SuperTimeline.build()
should:
- Stream events (don't load all into memory)
- Write to JSONL (one JSON per line) for streaming reads
- Cap the in-memory super_timeline_events list at ~100K events
- For behavioral analysis, only pass the last 50K events per device
- For the narrative report, summarize rather than enumerate

### 5.7 No Plaso available
SIFT workstations should have Plaso, but if it's missing, SuperTimeline
should fall back to:
- mactime from SleuthKit (bodyfile → sorted timeline)
- Manual timestamp extraction from findings
Log a warning but don't fail the entire pipeline.

### 5.8 LLM unavailable during narrative generation
If call_llm() fails (Ollama down, model not loaded), NarrativeReportGenerator
should fall back to a template-based report that just formats the structured
data as readable text without LLM summarization. Something like:

```
## User: dsmith
- Devices: DESKTOP-ABC123, DSmith-iPhone
- Login times observed: 08:30-09:00 on weekdays
- Programs executed: chrome.exe (47x), outlook.exe (23x), excel.exe (12x)
- Behavioral flags: 2 HIGH, 1 MEDIUM
```

This is less pretty but still useful.

---

## 6. FRONTEND CHANGES TO HTML_TEMPLATE

### 6.1 Show device map in Find Evil results

In `showFindEvilResults()` (line 3116), add after the playbook table:

```javascript
// Device Map
if (report.device_map) {
    html += '<h4 style="color:#58a6ff;margin-top:16px;">Devices Discovered</h4>';
    html += '<table class="fe-pb-table"><tr><th>Device</th><th>Type</th><th>Owner</th><th>OS</th><th>Files</th></tr>';
    for (const [devId, dev] of Object.entries(report.device_map)) {
        html += '<tr>';
        html += '<td>' + devId + '</td>';
        html += '<td>' + (dev.device_type || 'unknown') + '</td>';
        html += '<td>' + (dev.owner || '—') + '</td>';
        html += '<td>' + (dev.os_type || '—') + '</td>';
        html += '<td>' + (dev.evidence_files?.length || 0) + '</td>';
        html += '</tr>';
    }
    html += '</table>';
}

// Behavioral Flags Summary
if (report.behavioral_flags_summary) {
    const total = Object.values(report.behavioral_flags_summary).reduce((a,b) => a+b, 0);
    if (total > 0) {
        html += '<h4 style="color:#f85149;margin-top:16px;">⚠ Behavioral Flags: ' + total + '</h4>';
        for (const [devId, count] of Object.entries(report.behavioral_flags_summary)) {
            if (count > 0) {
                html += '<p style="color:#d29922;">' + devId + ': ' + count + ' flags</p>';
            }
        }
    }
}

// Narrative Report Link
if (report.narrative_report_path) {
    html += '<p style="margin-top:12px;"><strong>📄 Narrative Report:</strong> '
          + report.narrative_report_path + '</p>';
}
```

### 6.2 Add chat trigger hint

In the chat input placeholder, change from a generic hint to:

```html
<input id="chat-input" type="text"
       placeholder="Ask Geoff anything, or say 'start processing /path/to/evidence'..."
       onkeypress="if(event.key==='Enter')sendChat()">
```

---

## 7. TESTING STRATEGY

### Test Case 1: Single Windows image
- One .E01 file
- Expected: 1 device, hostname from registry, 1+ users from Users/ dir
- Super-timeline from Plaso only
- Behavioral analysis runs against Volatility + SleuthKit output

### Test Case 2: Multi-device with shared user
- evidence/workstation/ (has .E01 + .vmem)
- evidence/phone/ (has Info.plist + Manifest.db)
- Same user "dsmith" on both
- Expected: 2 devices, 1 user mapped to both
- Narrative report shows cross-device narrative

### Test Case 3: Just logs (no disk images)
- evidence/ has only .evtx files and syslogs
- Expected: 1 device (or multiple if hostnames differ in EVTX)
- No Plaso timeline; falls back to EVTX timestamps
- Behavioral analysis limited (no process list)

### Test Case 4: Large multi-host enterprise IR
- 5 disk images + 3 memory dumps + 2 PCAPs + 50 EVTX files
- Expected: 5-8 devices, multiple users
- Super-timeline potentially huge → test the 100K cap
- Cross-host correlation finds lateral movement

---

## 8. IMPLEMENTATION ORDER

Recommended build sequence:

1. **`device_discovery.py`** — Everything depends on this. Test with real evidence.
2. **Modify `find_evil()` Phase 1** — Add device discovery, write maps.
3. **Modify playbook execution loop** — Add device_id to step_records, loop per-device.
4. **`super_timeline.py`** — Build unified timeline from findings.
5. **`behavioral_analyzer.py`** — Deterministic checks first, LLM second.
6. **`host_correlator.py`** — Cross-device user correlation.
7. **`narrative_report.py`** — LLM-driven report generation.
8. **Chat trigger** — Add ingestion from chat.
9. **Frontend updates** — Show new data in results.

Each step is independently testable. Don't try to build all 5 new files at once.
