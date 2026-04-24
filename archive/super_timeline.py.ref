#!/usr/bin/env python3
"""
Super-Timeline — Unified timeline across ALL devices and evidence types.

Merges Plaso timelines, Volatility process/network events, EVTX logs,
PCAP flows, and registry timestamps into a single sorted JSONL stream.
"""

import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any


# Maximum events to hold in memory for behavioral analysis
MAX_IN_MEMORY_EVENTS = 100_000

# Standard event schema
EVENT_SCHEMA = {
    "timestamp": "",           # ISO-8601 UTC
    "device_id": "",           # From device_map
    "owner": "",               # From device_map
    "source_type": "",         # plaso, volatility, evtx, pcap, sleuthkit, registry
    "source_parser": "",       # Specific parser (e.g. "windows:evtx:4624")
    "event_type": "",          # Normalized: login, process_execution, file_creation,
                               # file_access, network_connection, browser_visit,
                               # registry_modification, file_deletion, service_change
    "summary": "",             # Human-readable one-liner
    "detail": {},              # Raw structured fields
    "suspicious": False,       # Set by behavioral analyzer later
    "suspicion_reason": None,  # Set by behavioral analyzer later
    "behavioral_flags": [],    # Set by behavioral analyzer later
}


class SuperTimeline:
    """
    Builds a unified timeline across all devices.

    Pipeline:
    1. Collect all Plaso .plaso files from case output
    2. Run psort -o json on each → parse events → tag with device_id
    3. Parse Volatility findings for timestamped process/network events
    4. Parse EVTX findings for login/process creation events
    5. Parse SleuthKit fls output for file timeline events
    6. Parse PCAP findings for network flow events
    7. Parse Registry findings for timestamp-bearing entries
    8. Normalize all into EVENT_SCHEMA
    9. Sort by timestamp
    10. Write to super_timeline.jsonl (streaming) and return in-memory subset
    """

    def __init__(self):
        self.log = []

    def build(self, device_map: dict, findings: List[dict],
              case_work_dir: Path, plaso_specialist: Any,
              job_id: str = None,
              fe_log_func=None) -> Tuple[Path, List[dict]]:
        """
        Build the super-timeline.

        Args:
            device_map: device_id -> device info dict
            findings: All step_records from playbook execution
            case_work_dir: Path to case working directory
            plaso_specialist: The Plaso specialist from sift_specialists_extended
            job_id: Optional job ID for progress logging
            fe_log_func: Optional logging function

        Returns:
            (path_to_jsonl, in_memory_events_list)
            The in-memory list is capped at MAX_IN_MEMORY_EVENTS.
        """
        timeline_dir = case_work_dir / "timeline"
        timeline_dir.mkdir(parents=True, exist_ok=True)
        output_path = timeline_dir / "super_timeline.jsonl"
        csv_path = timeline_dir / "super_timeline.csv"

        all_events = []

        def _log(msg):
            if fe_log_func and job_id:
                fe_log_func(job_id, msg)
            self.log.append(msg)

        # ---- Source 1: Plaso timelines ----
        _log("Super-timeline: Processing Plaso timelines...")
        plaso_events = self._extract_plaso_events(
            case_work_dir, device_map, plaso_specialist, _log)
        all_events.extend(plaso_events)
        _log(f"  Plaso: {len(plaso_events)} events")

        # ---- Source 2: Volatility process/network events ----
        _log("Super-timeline: Processing Volatility findings...")
        vol_events = self._extract_volatility_events(findings, device_map)
        all_events.extend(vol_events)
        _log(f"  Volatility: {len(vol_events)} events")

        # ---- Source 3: EVTX parsed events ----
        _log("Super-timeline: Processing EVTX findings...")
        evtx_events = self._extract_evtx_events(findings, device_map)
        all_events.extend(evtx_events)
        _log(f"  EVTX: {len(evtx_events)} events")

        # ---- Source 4: SleuthKit file events ----
        _log("Super-timeline: Processing SleuthKit findings...")
        sk_events = self._extract_sleuthkit_events(findings, device_map)
        all_events.extend(sk_events)
        _log(f"  SleuthKit: {len(sk_events)} events")

        # ---- Source 5: PCAP network events ----
        _log("Super-timeline: Processing PCAP findings...")
        pcap_events = self._extract_pcap_events(findings, device_map)
        all_events.extend(pcap_events)
        _log(f"  PCAP: {len(pcap_events)} events")

        # ---- Source 6: Registry events ----
        _log("Super-timeline: Processing Registry findings...")
        reg_events = self._extract_registry_events(findings, device_map)
        all_events.extend(reg_events)
        _log(f"  Registry: {len(reg_events)} events")

        # ---- Sort by timestamp ----
        _log(f"Super-timeline: Sorting {len(all_events)} total events...")
        all_events.sort(key=lambda e: e.get("timestamp", ""))

        # ---- Write JSONL (streaming-friendly) ----
        _log(f"Super-timeline: Writing to {output_path}")
        with open(output_path, "w") as f:
            for event in all_events:
                f.write(json.dumps(event, default=str) + "\n")

        # ---- Write CSV for human consumption ----
        self._write_csv(csv_path, all_events)
        _log(f"Super-timeline: CSV written to {csv_path}")

        # ---- Cap in-memory list ----
        in_memory = all_events[:MAX_IN_MEMORY_EVENTS]
        if len(all_events) > MAX_IN_MEMORY_EVENTS:
            _log(f"  Capped in-memory events: {MAX_IN_MEMORY_EVENTS} "
                 f"of {len(all_events)}")

        _log(f"Super-timeline complete: {len(all_events)} events, "
             f"{len(device_map)} devices")

        return output_path, in_memory

    def apply_behavioral_flags(self, events: List[dict],
                                all_flags: Dict[str, List[dict]]):
        """
        Tag timeline events with behavioral flags from the analyzer.

        Matches flags to events by device_id + timestamp proximity.
        """
        for dev_id, flags in all_flags.items():
            dev_events = [e for e in events if e.get("device_id") == dev_id]
            for flag in flags:
                related_ts = flag.get("related_timeline_events", [])
                for event in dev_events:
                    ets = event.get("timestamp", "")
                    if ets in related_ts:
                        event["suspicious"] = True
                        event["suspicion_reason"] = flag.get("summary", "")
                        event["behavioral_flags"].append(
                            flag.get("flag_id", ""))

                # If no specific timestamps, flag events matching the evidence
                if not related_ts:
                    evidence = flag.get("evidence", {})
                    pid = evidence.get("pid")
                    path = evidence.get("path", "").lower()
                    for event in dev_events:
                        detail = event.get("detail", {})
                        if pid and detail.get("pid") == pid:
                            event["suspicious"] = True
                            event["suspicion_reason"] = flag.get("summary")
                            event["behavioral_flags"].append(
                                flag.get("flag_id"))
                        elif path and path in str(detail).lower():
                            event["suspicious"] = True
                            event["suspicion_reason"] = flag.get("summary")
                            event["behavioral_flags"].append(
                                flag.get("flag_id"))

    # ----------------------------------------------------------------
    # Source-specific extraction methods
    # ----------------------------------------------------------------

    def _extract_plaso_events(self, case_work_dir: Path,
                               device_map: dict,
                               plaso_specialist: Any,
                               log_func) -> List[dict]:
        """
        Find .plaso files in case output, run psort -o json, parse output.

        Each event is tagged with the device_id of the disk image that
        produced it (matched by filename).

        Developer notes:
        - Use plaso_specialist.sort_timeline() with output_format='json'
          OR run psort directly via subprocess
        - Parse the JSON output line-by-line (one JSON object per line)
        - Key fields from Plaso JSON: datetime, timestamp_desc, source,
          source_short, message, data_type, hostname, username,
          computer_name, filename
        - Map data_type to our event_type:
            windows:evtx:* → login/process_execution
            filestat → file_creation/file_access
            windows:registry:* → registry_modification
            chrome:history:* → browser_visit
            etc.
        """
        events = []
        output_dir = case_work_dir / "output"
        plaso_files = list(output_dir.glob("*.plaso")) + \
                      list((case_work_dir / "timeline").glob("*.plaso"))

        for plaso_path in plaso_files:
            # Determine which device this plaso file belongs to
            device_id = self._match_plaso_to_device(plaso_path, device_map)

            try:
                # Run psort to get JSON output
                # Developer: use subprocess to call:
                #   python3 /usr/bin/psort.py -o json <plaso_path>
                # Then parse stdout line by line
                import subprocess
                result = subprocess.run(
                    ["python3", "/usr/bin/psort.py", "-o", "json",
                     str(plaso_path)],
                    capture_output=True, text=True, timeout=600
                )

                if result.returncode != 0:
                    log_func(f"  psort failed for {plaso_path.name}: "
                             f"{result.stderr[:200]}")
                    continue

                for line in result.stdout.strip().split("\n"):
                    try:
                        raw = json.loads(line)
                    except (json.JSONDecodeError, ValueError):
                        continue

                    event = self._normalize_plaso_event(raw, device_id,
                                                        device_map)
                    if event:
                        events.append(event)

            except Exception as e:
                log_func(f"  Plaso extraction error for {plaso_path.name}: {e}")

        return events

    def _normalize_plaso_event(self, raw: dict, device_id: str,
                                device_map: dict) -> Optional[dict]:
        """Convert a single Plaso JSON event to our standard schema."""
        timestamp = raw.get("datetime", raw.get("timestamp", ""))
        if not timestamp:
            return None

        data_type = raw.get("data_type", "")
        message = raw.get("message", "")
        username = raw.get("username", "")
        hostname = raw.get("hostname",
                          raw.get("computer_name", ""))

        # Map data_type to our normalized event_type
        event_type = "other"
        if "evtx" in data_type or "evt" in data_type:
            event_id = raw.get("event_identifier", 0)
            if event_id in (4624, 4625, 4648):
                event_type = "login"
            elif event_id == 4688:
                event_type = "process_execution"
            elif event_id in (4720, 4722, 4726):
                event_type = "account_change"
            else:
                event_type = "windows_event"
        elif "filestat" in data_type:
            desc = raw.get("timestamp_desc", "").lower()
            if "creation" in desc:
                event_type = "file_creation"
            elif "modification" in desc:
                event_type = "file_modification"
            elif "access" in desc:
                event_type = "file_access"
            else:
                event_type = "file_activity"
        elif "registry" in data_type:
            event_type = "registry_modification"
        elif "chrome" in data_type or "firefox" in data_type:
            event_type = "browser_visit"
        elif "prefetch" in data_type:
            event_type = "process_execution"
        elif "userassist" in data_type:
            event_type = "process_execution"
        elif "lnk" in data_type:
            event_type = "file_access"

        # Determine owner from device_map
        owner = device_map.get(device_id, {}).get("owner", "")
        if username and not owner:
            owner = username

        return {
            "timestamp": timestamp,
            "device_id": device_id,
            "owner": owner,
            "source_type": "plaso",
            "source_parser": data_type,
            "event_type": event_type,
            "summary": message[:200] if message else f"{data_type} event",
            "detail": {
                k: v for k, v in raw.items()
                if k in ("event_identifier", "source_name", "filename",
                         "username", "hostname", "url", "title",
                         "process_name", "command_line", "logon_type",
                         "source_ip", "source_port")
            },
            "suspicious": False,
            "suspicion_reason": None,
            "behavioral_flags": [],
        }

    def _match_plaso_to_device(self, plaso_path: Path,
                                device_map: dict) -> str:
        """Match a .plaso file to a device_id based on filename."""
        stem = plaso_path.stem.lower()
        for dev_id, dev in device_map.items():
            # Check if plaso filename contains the device_id or
            # the disk image stem
            if dev_id.lower() in stem:
                return dev_id
            for ef in dev.get("evidence_files", []):
                if Path(ef).stem.lower() in stem:
                    return dev_id
        # Fallback: first device
        return list(device_map.keys())[0] if device_map else "unknown"

    def _extract_volatility_events(self, findings: List[dict],
                                    device_map: dict) -> List[dict]:
        """
        Extract timestamped events from Volatility findings.
        Process creation times, network connection timestamps.

        Developer notes:
        - Look for findings where module=="volatility"
        - process_list: extract process name, PID, create time
        - network_scan: extract connection timestamps
        - find_malware: extract injection detection timestamps
        - The step_record has device_id (added in the modified pipeline)
        """
        events = []
        for f in findings:
            if f.get("module") != "volatility":
                continue
            device_id = f.get("device_id", "unknown")
            owner = f.get("owner", "")
            result = f.get("result", {})
            stdout = result.get("stdout", "")
            func = f.get("function", "")

            if func == "process_list":
                # Parse pslist output for process create times
                # Developer: parse the Volatility output format
                # and create process_execution events
                pass  # Implementation depends on Volatility output format

            elif func == "network_scan":
                # Parse netscan output for connection events
                pass

        return events

    def _extract_evtx_events(self, findings: List[dict],
                              device_map: dict) -> List[dict]:
        """
        Extract events from parsed EVTX findings.

        Developer notes:
        - Look for findings where module=="logs" and function=="parse_evtx"
        - The result stdout contains parsed event log entries
        - Key events: 4624 (logon), 4625 (failed logon), 4648 (explicit cred),
          4688 (process creation), 7045 (service installed),
          4720/4722/4726 (account changes)
        - Parse XML or text output depending on the log parser used
        """
        events = []
        for f in findings:
            if f.get("module") != "logs" or f.get("function") != "parse_evtx":
                continue
            device_id = f.get("device_id", "unknown")
            owner = f.get("owner", "")
            # Developer: parse the EVTX output and create events
        return events

    def _extract_sleuthkit_events(self, findings: List[dict],
                                   device_map: dict) -> List[dict]:
        """
        Extract file timeline events from SleuthKit fls output.

        Developer notes:
        - Look for findings where module=="sleuthkit"
        - list_files with mactime format gives MACB timestamps
        - analyze_filesystem gives filesystem timestamps
        - Focus on: file creations, modifications in user directories
        """
        events = []
        return events

    def _extract_pcap_events(self, findings: List[dict],
                              device_map: dict) -> List[dict]:
        """
        Extract network flow events from PCAP findings.

        Developer notes:
        - Look for findings where module=="network"
        - analyze_pcap: extract flow summaries with timestamps
        - extract_http: extract HTTP request timestamps
        - extract_flows: extract TCP flow start/end times
        """
        events = []
        return events

    def _extract_registry_events(self, findings: List[dict],
                                  device_map: dict) -> List[dict]:
        """
        Extract timestamp-bearing registry events.

        Developer notes:
        - Look for findings where module=="registry"
        - UserAssist: program execution counts + timestamps
        - ShellBags: folder access timestamps
        - MRU lists: recent file access timestamps
        - Services: service creation timestamps
        """
        events = []
        return events

    def _write_csv(self, csv_path: Path, events: List[dict]):
        """Write a human-readable CSV version of the timeline."""
        with open(csv_path, "w") as f:
            f.write("timestamp,device_id,owner,event_type,summary,suspicious\n")
            for event in events:
                # Escape CSV fields
                summary = event.get("summary", "").replace('"', '""')
                f.write(
                    f'"{event.get("timestamp", "")}",'
                    f'"{event.get("device_id", "")}",'
                    f'"{event.get("owner", "")}",'
                    f'"{event.get("event_type", "")}",'
                    f'"{summary[:200]}",'
                    f'"{event.get("suspicious", False)}"\n'
                )
