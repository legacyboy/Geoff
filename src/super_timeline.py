#!/usr/bin/env python3
"""
Super-Timeline — Unified timeline across ALL devices and evidence types.

Merges Plaso timelines, Volatility process/network events, EVTX logs,
PCAP flows, and registry timestamps into a single sorted JSONL stream.
"""

import json
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any


# Maximum events to hold in memory for behavioral analysis
MAX_IN_MEMORY_EVENTS = 100_000

# FILETIME epoch offset: 100ns intervals between 1601-01-01 and 1970-01-01
FILETIME_EPOCH = 116444736000000000

# Null timestamp sentinels to skip
NULL_TIMESTAMPS = {0, -9223372036854775808, FILETIME_EPOCH}

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

    @staticmethod
    def _normalize_timestamp(ts: str) -> str:
        """Normalize various timestamp formats to ISO-8601 UTC."""
        if not ts:
            return ""
        ts = ts.strip()
        # Already ISO-like
        if 'T' in ts and len(ts) >= 19:
            return ts.replace(' ', 'T')[:19] + 'Z' if not ts.endswith('Z') else ts
        # Space-separated: 2024-01-01 10:30:00
        if re.match(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}', ts):
            return ts.replace(' ', 'T') + 'Z'
        # Slash-separated: 2024/01/01 10:30:00
        if re.match(r'\d{4}/\d{2}/\d{2}', ts):
            return ts.replace('/', '-')[:10] + 'T' + ts[11:] + 'Z' if len(ts) > 10 else ts
        # FILETIME (100ns intervals since 1601-01-01)
        try:
            ft = int(ts)
            if ft > 1e17:  # Likely FILETIME
                epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
                dt = epoch + timedelta(microseconds=ft // 10)
                return dt.isoformat()[:19] + 'Z'
        except (ValueError, OverflowError):
            pass
        # Unix epoch (seconds or milliseconds)
        try:
            epoch_val = float(ts)
            if epoch_val > 1e12:  # Milliseconds
                epoch_val /= 1000
            if 1e9 < epoch_val < 2e10:  # Reasonable epoch range (2001-2033)
                dt = datetime.fromtimestamp(epoch_val, tz=timezone.utc)
                return dt.isoformat()[:19] + 'Z'
        except (ValueError, OverflowError, OSError):
            pass
        return ts  # Return as-is if we can't parse

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

    @staticmethod
    def _parse_mactime_body(raw: str) -> List[dict]:
        """Parse fls -m mactime body format output.

        Format: md5|path|inode|meta_type|file_type|atime|mtime|ctime|crtime
        or:    md5|name|inode|meta_type|mode|uid|gid|size|atime|mtime|ctime|crtime
        Timestamps are Unix epoch seconds (0 = not set).
        """
        events = []
        for line in raw.splitlines():
            parts = line.split('|')
            if len(parts) < 9:
                continue
            # Determine format by number of fields
            if len(parts) >= 12:
                # 13-field format: md5|name|inode|meta_type|mode|uid|gid|size|atime|mtime|ctime|crtime
                path = parts[1]
                inode = parts[2]
                ts_indices = {8: 'atime', 9: 'mtime', 10: 'ctime', 11: 'crtime'}
            else:
                # 9-field format: md5|path|inode|meta_type|file_type|atime|mtime|ctime|crtime
                path = parts[1]
                inode = parts[2]
                ts_indices = {5: 'atime', 6: 'mtime', 7: 'ctime', 8: 'crtime'}

            timestamps = {}
            for idx, name in ts_indices.items():
                if idx < len(parts):
                    try:
                        ts_val = int(parts[idx])
                        if ts_val > 0:
                            timestamps[name] = ts_val
                    except (ValueError, IndexError):
                        pass

            events.append({
                'path': path,
                'inode': inode,
                'timestamps': timestamps,
            })
        return events

    @staticmethod
    def _is_null_plaso_timestamp(ts_val) -> bool:
        """Check if a Plaso timestamp is null/invalid."""
        if not ts_val or ts_val <= 0:
            return True
        return ts_val in NULL_TIMESTAMPS

    def _extract_plaso_events(self, case_work_dir: Path,
                               device_map: dict,
                               plaso_specialist: Any,  # retained for API compatibility; not used
                               log_func) -> List[dict]:
        """
        Find and parse Plaso timeline events.

        Strategy: read existing .json_line files produced by psort during
        playbook execution. Stream-parse line-by-line to handle multi-GB
        files without OOM. Only fall back to running psort if no
        .json_line files exist but .plaso files do.

        Each event is tagged with the device_id of the disk image that
        produced it (matched by filename).
        """
        events = []
        try:
            MAX_PLASO_EVENTS = int(os.environ.get("GEOFF_MAX_PLASO_EVENTS", "50000"))
        except ValueError:
            MAX_PLASO_EVENTS = 50000
        output_dir = case_work_dir / "output"
        timeline_dir = case_work_dir / "timeline"

        # --- Phase 1: Stream-parse existing .json_line files ---
        json_line_files = []
        for d in [output_dir, timeline_dir]:
            if d.exists():
                json_line_files.extend(d.glob("*.json_line"))

        # Deduplicate by picking newest if multiple match same stem
        seen_stems = {}
        for jlf in json_line_files:
            stem = jlf.stem
            try:
                mtime = jlf.stat().st_mtime
            except OSError:
                continue
            if stem not in seen_stems or mtime > seen_stems[stem][1]:
                seen_stems[stem] = (jlf, mtime)
        json_line_files = sorted([v[0] for v in seen_stems.values()])

        if json_line_files:
            for jlf in json_line_files:
                device_id = self._match_plaso_to_device(jlf, device_map)
                log_func(f"  Plaso: streaming {jlf.name} for device {device_id}")
                count = 0
                skipped = 0
                try:
                    with open(jlf, 'r', encoding='utf-8', errors='replace') as f:
                        for line in f:
                            if len(events) >= MAX_PLASO_EVENTS:
                                log_func(f"  Plaso: capped at {MAX_PLASO_EVENTS} events")
                                break
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                raw = json.loads(line)
                            except (json.JSONDecodeError, ValueError):
                                continue

                            # Skip null-timestamp events
                            ts_val = raw.get("date_time", {}).get("timestamp", 0) if isinstance(raw.get("date_time"), dict) else 0
                            if self._is_null_plaso_timestamp(ts_val):
                                skipped += 1
                                continue

                            event = self._normalize_plaso_event_v2(raw, device_id, device_map)
                            if event:
                                events.append(event)
                                count += 1
                except Exception as e:
                    log_func(f"  Plaso: error reading {jlf.name}: {e}")
                log_func(f"  Plaso: {count} events from {jlf.name} ({skipped} skipped null timestamps)")
            return events

        # --- Phase 2: Safety-net — run psort if .json_line doesn't exist ---
        plaso_files = list(output_dir.glob("*.plaso")) + \
                      list(timeline_dir.glob("*.plaso"))

        if not plaso_files:
            return events

        log_func(f"  Plaso: no .json_line files found; running psort for {len(plaso_files)} .plaso files")
        for plaso_path in plaso_files:
            device_id = self._match_plaso_to_device(plaso_path, device_map)
            json_line_out = plaso_path.with_suffix('.json_line')

            try:
                import subprocess
                import sys as _sys
                # Prefer the psort entry-point that ships with SIFT/REMnux.
                # Fall back to the current interpreter so a virtualenv works too.
                psort_candidates = [
                    "/usr/bin/psort",           # Plaso 20200227+ entry-point
                    "/usr/local/bin/psort",
                    "/usr/bin/psort.py",        # older SIFT layout
                ]
                psort_bin = next((p for p in psort_candidates if Path(p).exists()), None)
                if psort_bin:
                    cmd = [psort_bin, "-o", "json_line", "-w", str(json_line_out), str(plaso_path)]
                else:
                    # Last resort: run psort.py through the current interpreter
                    psort_script = "/usr/bin/psort.py"
                    cmd = [_sys.executable, psort_script, "-o", "json_line", "-w", str(json_line_out), str(plaso_path)]
                    if not Path(psort_script).exists():
                        log_func(f"  psort not found; skipping {plaso_path.name}")
                        continue
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
                if result.returncode != 0:
                    log_func(f"  psort failed for {plaso_path.name}: {result.stderr[:200]}")
                    continue
            except Exception as e:
                log_func(f"  Plaso extraction error for {plaso_path.name}: {e}")
                continue

            # Stream-parse the output file we just wrote
            if json_line_out.exists():
                count = 0
                with open(json_line_out, 'r', encoding='utf-8', errors='replace') as f:
                    for line in f:
                        if len(events) >= MAX_PLASO_EVENTS:
                            break
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            raw = json.loads(line)
                        except (json.JSONDecodeError, ValueError):
                            continue
                        ts_val = raw.get("date_time", {}).get("timestamp", 0) if isinstance(raw.get("date_time"), dict) else 0
                        if self._is_null_plaso_timestamp(ts_val):
                            continue
                        event = self._normalize_plaso_event_v2(raw, device_id, device_map)
                        if event:
                            events.append(event)
                            count += 1
                log_func(f"  Plaso: {count} events from safety-net psort of {plaso_path.name}")
            else:
                log_func(f"  psort succeeded but {json_line_out.name} not found — skipping")

        return events

    def _normalize_plaso_event_v2(self, raw: dict, device_id: str,
                                  device_map: dict) -> Optional[dict]:
        """Convert a psort json_line event to our standard schema.

        psort json_line format has:
        - date_time.timestamp: integer (microseconds or 100ns depending on __class_name)
        - date_time.__class_name: PosixTimeInMicroseconds, Filetime, etc.
        - timestamp_desc: 'Last Visited', 'Content Modification Time', etc.
        - data_type: 'firefox:places:bookmark', 'msiecf:url', etc.
        - display_name: 'NTFS:\\path\\to\\file'
        - message: human-readable summary
        - parser: parser that produced the event
        """
        # Extract timestamp from nested date_time object
        dt_obj = raw.get("date_time", {})
        ts_val = dt_obj.get("timestamp", 0) if isinstance(dt_obj, dict) else 0
        class_name = dt_obj.get("__class_name", "") if isinstance(dt_obj, dict) else ""

        if self._is_null_plaso_timestamp(ts_val):
            return None

        # Convert to ISO timestamp using __class_name when available,
        # otherwise magnitude-based heuristics
        timestamp_str = ""
        try:
            if "Filetime" in class_name:
                # Windows FILETIME: 100-nanosecond intervals since 1601-01-01
                unix_seconds = (ts_val - FILETIME_EPOCH) / 10_000_000
                dt = datetime.fromtimestamp(unix_seconds, tz=timezone.utc)
                timestamp_str = dt.isoformat()[:19] + "Z"
            elif "PosixTime" in class_name or "Microseconds" in class_name:
                # Microseconds since Unix epoch
                dt = datetime.fromtimestamp(ts_val / 1_000_000, tz=timezone.utc)
                timestamp_str = dt.isoformat()[:19] + "Z"
            elif ts_val > 10_000_000_000_000:
                # Magnitude heuristic: > 10 trillion → likely microseconds
                dt = datetime.fromtimestamp(ts_val / 1_000_000, tz=timezone.utc)
                timestamp_str = dt.isoformat()[:19] + "Z"
            elif ts_val > 10_000_000_000:
                # 10 billion → 10 trillion → likely seconds
                dt = datetime.fromtimestamp(ts_val, tz=timezone.utc)
                timestamp_str = dt.isoformat()[:19] + "Z"
            else:
                # Small value — try as seconds
                try:
                    dt = datetime.fromtimestamp(ts_val, tz=timezone.utc)
                    timestamp_str = dt.isoformat()[:19] + "Z"
                except (ValueError, OSError, OverflowError):
                    return None
        except (ValueError, OSError, OverflowError):
            return None

        if not timestamp_str:
            return None

        data_type = raw.get("data_type", "")
        message = raw.get("message", "")
        timestamp_desc = raw.get("timestamp_desc", "")
        username = raw.get("username", "")
        hostname = raw.get("hostname", raw.get("host", ""))
        display_name = raw.get("display_name", "")
        filename = raw.get("filename", "")

        # Clean display_name — strip "NTFS:" prefix
        filepath = display_name
        if filepath.startswith("NTFS:"):
            filepath = filepath[5:]
        if not filepath and filename:
            filepath = filename

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
            desc = timestamp_desc.lower()
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
        elif "msiecf" in data_type:
            event_type = "browser_visit"
        elif "winevt" in data_type:
            event_type = "windows_event"

        # Determine owner from device_map or username
        owner = device_map.get(device_id, {}).get("owner", "")
        if username and not owner:
            owner = username

        # Extract username from filepath if still no owner
        if not owner and filepath:
            user_match = re.search(
                r'(?:Users|Documents and Settings)[/\\\\]([^/\\\\]+)',
                filepath
            )
            if user_match:
                owner = user_match.group(1)

        summary = message[:200] if message else f"{data_type} event"
        if not message and filepath:
            summary = filepath[:200]

        return {
            "timestamp": timestamp_str,
            "device_id": device_id,
            "owner": owner,
            "source_type": "plaso",
            "source_parser": data_type,
            "event_type": event_type,
            "summary": summary,
            "detail": {
                k: v for k, v in raw.items()
                if k in ("event_identifier", "source_name", "filename",
                         "username", "hostname", "url", "title",
                         "process_name", "command_line", "logon_type",
                         "source_ip", "source_port", "parser",
                         "cached_filename", "visit_count",
                         "places_title", "query",
                         "sha256_hash", "inode")
            },
            "suspicious": False,
            "suspicion_reason": None,
            "behavioral_flags": [],
        }

    def _match_plaso_to_device(self, plaso_path: Path,
                                device_map: dict) -> str:
        """Match a .plaso or .json_line file to a device_id based on filename."""
        stem = plaso_path.stem.lower()
        # Strip common prefixes: timeline_ prefix from psort output naming
        if stem.startswith("timeline_"):
            stem = stem[len("timeline_"):]
        for dev_id, dev in device_map.items():
            # Check if plaso filename contains the device_id or
            # the disk image stem
            if dev_id.lower() in stem:
                return dev_id
            for ef in dev.get("evidence_files", []):
                ef_stem = Path(ef).stem.lower()
                # Strip .E01, .E02 segment suffixes
                ef_stem = re.sub(r'\.[eE]\d+$', '', ef_stem)
                if ef_stem in stem:
                    return dev_id
        # Fallback: first device
        return list(device_map.keys())[0] if device_map else "unknown"

    def _extract_volatility_events(self, findings: List[dict],
                                    device_map: dict) -> List[dict]:
        """Extract timestamped events from Volatility findings."""
        events = []
        for f in findings:
            if f.get("module") != "volatility":
                continue
            device_id = f.get("device_id", "unknown")
            owner = f.get("owner", "")
            result = f.get("result", {})
            stdout = result.get("stdout", "")
            raw_output = result.get("raw_output", "")
            func = f.get("function", "")
            text = stdout or raw_output

            if func == "process_list" and text:
                # Volatility3 pslist table format:
                # PID  PPID  ImageFileName  CreateTime  ...
                for line in text.splitlines():
                    parts = line.split()
                    if len(parts) < 4:
                        continue
                    try:
                        pid = int(parts[0])
                    except (ValueError, IndexError):
                        continue
                    # Find a timestamp-like field (contains 'T' or '/' or '-')
                    ts = None
                    for p in parts[3:]:
                        if 'T' in p or re.match(r'\d{4}[/-]\d{2}', p):
                            ts = p
                            # Capture time portion too
                            idx = parts.index(p)
                            if idx + 1 < len(parts) and ':' in parts[idx + 1]:
                                ts = f"{p} {parts[idx + 1]}"
                            break
                    proc_name = parts[2] if len(parts) > 2 else "unknown"
                    events.append({
                        "timestamp": self._normalize_timestamp(ts) if ts else "",
                        "device_id": device_id,
                        "owner": owner,
                        "source_type": "volatility",
                        "source_parser": "pslist",
                        "event_type": "process_execution",
                        "summary": f"Process: {proc_name} (PID {pid})",
                        "detail": {"pid": pid, "ppid": parts[1] if len(parts) > 1 else None, "name": proc_name},
                        "suspicious": False,
                        "suspicion_reason": None,
                        "behavioral_flags": [],
                    })

            elif func == "network_scan" and text:
                # Volatility3 netscan: offset,Proto,LocalAddr,LocalPort,ForeignAddr,ForeignPort,State,PID,CreateTime
                for line in text.splitlines():
                    parts = line.split()
                    if len(parts) < 8:
                        continue
                    # Find timestamp
                    ts = None
                    for p in parts:
                        if 'T' in p or re.match(r'\d{4}[/-]\d{2}', p):
                            ts = p
                            idx = parts.index(p)
                            if idx + 1 < len(parts) and ':' in parts[idx + 1]:
                                ts = f"{p} {parts[idx + 1]}"
                            break
                    proto = parts[1] if len(parts) > 1 else "?"
                    local = parts[2] if len(parts) > 2 else "?"
                    foreign = parts[4] if len(parts) > 4 else "?"
                    events.append({
                        "timestamp": self._normalize_timestamp(ts) if ts else "",
                        "device_id": device_id,
                        "owner": owner,
                        "source_type": "volatility",
                        "source_parser": "netscan",
                        "event_type": "network_connection",
                        "summary": f"{proto} {local} → {foreign}",
                        "detail": {"protocol": proto, "local": local, "foreign": foreign},
                        "suspicious": False,
                        "suspicion_reason": None,
                        "behavioral_flags": [],
                    })

        return events

    def _extract_evtx_events(self, findings: List[dict],
                              device_map: dict) -> List[dict]:
        """Extract events from parsed EVTX findings."""
        events = []
        # Key event IDs and their types
        EVENT_TYPES = {
            "4624": "login", "4625": "failed_login", "4648": "explicit_credential_use",
            "4688": "process_creation", "7045": "service_installed",
            "4720": "account_created", "4722": "account_enabled",
            "4726": "account_deleted", "4697": "service_installed",
            "7036": "service_state_change", "1102": "audit_log_cleared",
        }

        for f in findings:
            if f.get("module") != "logs":
                continue
            device_id = f.get("device_id", "unknown")
            owner = f.get("owner", "")
            result = f.get("result", {})
            stdout = result.get("stdout", "")
            raw_output = result.get("raw_output", "")
            text = stdout or raw_output
            if not text:
                continue

            # Parse EVTX text output — look for Event ID patterns
            # Format varies: could be XML, key=value, or tabular
            event_id_pattern = re.compile(r'Event[ID_\s:]*(\d+)', re.IGNORECASE)
            timestamp_pattern = re.compile(r'(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})')

            for line in text.splitlines():
                eid_match = event_id_pattern.search(line)
                if not eid_match:
                    continue
                eid = eid_match.group(1)
                event_type = EVENT_TYPES.get(eid, f"windows_event_{eid}")
                ts_match = timestamp_pattern.search(line)
                ts = ts_match.group(1) if ts_match else ""

                events.append({
                    "timestamp": self._normalize_timestamp(ts),
                    "device_id": device_id,
                    "owner": owner,
                    "source_type": "evtx",
                    "source_parser": f"windows:evtx:{eid}",
                    "event_type": event_type,
                    "summary": line.strip()[:200],
                    "detail": {"event_id": int(eid), "raw": line.strip()[:500]},
                    "suspicious": eid in ("1102", "4688", "7045"),
                    "suspicion_reason": "Suspicious event ID" if eid in ("1102", "4688", "7045") else None,
                    "behavioral_flags": [],
                })

        return events

    def _extract_sleuthkit_events(self, findings: List[dict],
                                   device_map: dict) -> List[dict]:
        """Extract file timeline events from SleuthKit fls output."""
        events = []
        seen_paths = set()  # Deduplicate across playbooks

        # First pass: process mactime (fls -m) events with real timestamps
        for f in findings:
            if f.get("module") != "sleuthkit" or f.get("function") != "list_files_mactime":
                continue
            device_id = f.get("device_id", "unknown")
            owner = f.get("owner", "")
            result = f.get("result", {})
            mactime_events = result.get("events", [])
            if not mactime_events and result.get("raw_output"):
                # Parse mactime body format from raw_output
                mactime_events = self._parse_mactime_body(result["raw_output"])

            for evt in mactime_events:
                path = evt.get("path", "")
                if path in seen_paths:
                    continue
                seen_paths.add(path)

                timestamps = evt.get("timestamps", {})
                # Use crtime (creation) as primary, fall back to mtime
                ts = ""
                for ts_name in ["crtime", "mtime", "ctime", "atime"]:
                    if timestamps.get(ts_name):
                        try:
                            dt = datetime.fromtimestamp(timestamps[ts_name], tz=timezone.utc)
                            ts = dt.isoformat()[:19] + "Z"
                            break
                        except (ValueError, OSError, OverflowError):
                            pass

                is_dir = path.endswith("/") or evt.get("file_type", "").startswith("d")
                event_type = "directory_listing" if is_dir else "file_creation"

                # Extract owner from path
                path_owner = owner
                if not owner:
                    user_match = re.search(r'(?:Users|Documents and Settings)/([^/\\\\]+)', path)
                    if user_match:
                        path_owner = user_match.group(1)

                events.append({
                    "timestamp": ts,
                    "device_id": device_id,
                    "owner": path_owner,
                    "source_type": "sleuthkit",
                    "source_parser": "fls_mactime",
                    "event_type": event_type,
                    "summary": path[:200],
                    "detail": {
                        "path": path,
                        "inode": evt.get("inode", ""),
                        "timestamps": timestamps,
                    },
                    "suspicious": False,
                    "suspicion_reason": None,
                    "behavioral_flags": [],
                })

        # Second pass: process fls -p events (no timestamps, path-only)
        # Skip if mactime already produced events for same paths
        for f in findings:
            if f.get("module") != "sleuthkit":
                continue
            device_id = f.get("device_id", "unknown")
            owner = f.get("owner", "")
            result = f.get("result", {})
            func = f.get("function", "")

            # Try structured data first, fall back to raw_output
            raw = result.get("raw_output", "")
            if not raw:
                continue

            # Parse fls -p body format:
            #   r/r 12345-144-3:  Documents and Settings/Admin/file.txt
            #   d/d 3519-144-6:   Documents and Settings
            # The meta format is: inode-ntfs_type-alloc_flags
            # NTFS stores timestamps in $STANDARD_INFORMATION and $FILE_NAME
            # but fls -p doesn't include them. We create path-based events.

            for line in raw.splitlines():
                line = line.strip()
                if not line:
                    continue

                # Match fls -p format (handles compound inodes like 3519-144-6)
                match = re.match(r'^([rvmldc]/[rda])\s+(\*?)([\d-]+)[:\t]+(.*)', line)
                if not match:
                    match = re.match(r'^([rvmldc]/[rda])\s+(\*?)(\S+)\s*:\s*(.*)', line)
                if not match:
                    continue

                file_type = match.group(1)
                is_deleted = '*' in match.group(2)
                inode = match.group(3)
                path = match.group(4).strip()

                if path in seen_paths:
                    continue
                seen_paths.add(path)

                is_dir = file_type.startswith('d')
                event_type = "file_creation" if not is_dir else "directory_listing"

                # Flag suspicious paths
                suspicious = False
                suspicion_reason = None
                path_lower = path.lower()
                suspicious_patterns = [
                    ('temp', 'file in temp directory'),
                    ('tmp', 'file in tmp directory'),
                    ('\\software\\', 'software registry path'),
                    ('startup', 'startup folder entry'),
                    ('autorun', 'autorun entry'),
                    ('recycle', 'recycle bin entry'),
                ]
                for pat, reason in suspicious_patterns:
                    if pat in path_lower:
                        suspicious = True
                        suspicion_reason = reason
                        break

                # Extract owner from path if present (e.g., Users/dsmith/)
                path_owner = owner
                if not owner:
                    user_match = re.search(r'(?:Users|Documents and Settings)/([^/\\]+)', path)
                    if user_match:
                        path_owner = user_match.group(1)

                events.append({
                    "timestamp": "",  # fls -p doesn't include timestamps
                    "device_id": device_id,
                    "owner": path_owner,
                    "source_type": "sleuthkit",
                    "source_parser": "fls",
                    "event_type": event_type,
                    "summary": f"{'Deleted: ' if is_deleted else ''}{path}",
                    "detail": {
                        "path": path,
                        "inode": inode,
                        "file_type": file_type,
                        "is_deleted": is_deleted,
                    },
                    "suspicious": suspicious or is_deleted,
                    "suspicion_reason": suspicion_reason or ("Deleted file" if is_deleted else None),
                    "behavioral_flags": [],
                })

        return events

    def _extract_pcap_events(self, findings: List[dict],
                              device_map: dict) -> List[dict]:
        """Extract network flow events from PCAP findings."""
        events = []
        for f in findings:
            if f.get("module") != "network":
                continue
            device_id = f.get("device_id", "unknown")
            owner = f.get("owner", "")
            result = f.get("result", {})
            stdout = result.get("stdout", "")
            raw_output = result.get("raw_output", "")
            func = f.get("function", "")
            text = stdout or raw_output
            if not text:
                continue

            # Parse tshark/tcpflow output for network events
            # Look for IP:port patterns and timestamps
            ts_pattern = re.compile(r'(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})')
            ip_port_pattern = re.compile(r'(\d+\.\d+\.\d+\.\d+):(\d+)')

            for line in text.splitlines():
                ts_match = ts_pattern.search(line)
                if not ts_match:
                    continue
                ts = ts_match.group(1)
                ips = ip_port_pattern.findall(line)
                if not ips:
                    continue

                events.append({
                    "timestamp": self._normalize_timestamp(ts),
                    "device_id": device_id,
                    "owner": owner,
                    "source_type": "pcap",
                    "source_parser": func,
                    "event_type": "network_connection",
                    "summary": line.strip()[:200],
                    "detail": {"endpoints": [f"{ip}:{port}" for ip, port in ips]},
                    "suspicious": False,
                    "suspicion_reason": None,
                    "behavioral_flags": [],
                })

        return events

    def _extract_registry_events(self, findings: List[dict],
                                  device_map: dict) -> List[dict]:
        """Extract timestamp-bearing registry events."""
        events = []
        for f in findings:
            if f.get("module") != "registry":
                continue
            device_id = f.get("device_id", "unknown")
            owner = f.get("owner", "")
            result = f.get("result", {})
            stdout = result.get("stdout", "")
            raw_output = result.get("raw_output", "")
            func = f.get("function", "")
            text = stdout or raw_output
            if not text:
                continue

            # Parse RegRipper output for registry keys with timestamps
            # Common format: Key path\n  Last Write: YYYY-MM-DD HH:MM:SS\n  Value: ...
            ts_pattern = re.compile(r'Last\s+Write[:\s]+(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})', re.IGNORECASE)
            key_pattern = re.compile(r'^\\(.+)', re.MULTILINE)

            current_key = ""
            current_ts = ""
            for line in text.splitlines():
                line_stripped = line.strip()

                # Track registry key path
                if line_stripped.startswith('\\'):
                    current_key = line_stripped
                    continue

                # Look for Last Write timestamp
                ts_match = ts_pattern.search(line_stripped)
                if ts_match and current_key:
                    current_ts = ts_match.group(1)
                    # Determine event type from key
                    key_lower = current_key.lower()
                    event_type = "registry_modification"
                    suspicious = False
                    suspicion_reason = None
                    if 'run' in key_lower or 'runonce' in key_lower:
                        event_type = "persistence_registry"
                        suspicious = True
                        suspicion_reason = "Run/RunOnce key modification"
                    elif 'service' in key_lower:
                        event_type = "service_change"
                        suspicious = True
                        suspicion_reason = "Service registry key"
                    elif 'userassist' in key_lower:
                        event_type = "program_execution"
                    elif 'shellbag' in key_lower or 'shell\\bag' in key_lower:
                        event_type = "folder_access"

                    events.append({
                        "timestamp": self._normalize_timestamp(current_ts),
                        "device_id": device_id,
                        "owner": owner,
                        "source_type": "registry",
                        "source_parser": func,
                        "event_type": event_type,
                        "summary": current_key[:200],
                        "detail": {"key": current_key, "last_write": current_ts},
                        "suspicious": suspicious,
                        "suspicion_reason": suspicion_reason,
                        "behavioral_flags": [],
                    })
                    current_key = ""

        return events

    def _write_csv(self, csv_path: Path, events: List[dict]):
        """Write a human-readable CSV version of the timeline."""
        with open(csv_path, "w") as f:
            f.write("timestamp,device_id,owner,event_type,summary,suspicious\n")
            for event in events:
                # Escape CSV fields, handle None values
                summary = (event.get("summary") or "").replace('"', '""')
                owner = event.get("owner") or ""
                timestamp = event.get("timestamp") or ""
                f.write(
                    f'"{timestamp}",'
                    f'"{event.get("device_id", "")}",'
                    f'"{owner}",'
                    f'"{event.get("event_type", "")}",'
                    f'"{summary[:200]}",'
                    f'"{event.get("suspicious", False)}"\n'
                )
