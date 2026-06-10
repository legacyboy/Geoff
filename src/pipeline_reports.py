#!/usr/bin/env python3
"""Geoff DFIR - Pipeline reporting/intelligence helpers.

Extracted from geoff_pipeline.py to reduce module size. Contains the
Pass 2 timeline intelligence analysis used between Pass 1 execution and
the adaptive Pass 2 playbook selection.
"""

import re
from datetime import datetime

from geoff_config import PASS2_TRIGGER_PLAYBOOK_MAP

# =====================================================================
# Pass 2: Timeline Intelligence Analysis
# =====================================================================

def _timeline_intelligence_analysis(
    super_timeline_events: list,
    device_map: dict,
    indicator_hits: list = None,
    job_id: str = None,
    fe_log_func=None,
) -> dict:
    """Analyse the super timeline for cross-device patterns that warrant
    a second pass of targeted investigation.

    Returns a TimelineIntelligence dict with:
      - cross_device_process_chains
      - usb_lateral_movement
      - off_hours_clusters
      - file_beaconing_patterns
      - ioc_correlations
      - dwell_time_window
      - pass2_playbook_triggers
    """

    def _log(msg):
        if fe_log_func and job_id:
            fe_log_func(job_id, msg)

    intelligence = {
        "cross_device_process_chains": [],
        "usb_lateral_movement": [],
        "off_hours_clusters": [],
        "file_beaconing_patterns": [],
        "ioc_correlations": [],
        "dwell_time_window": {"first_seen": None, "last_seen": None, "dwell_days": 0},
        "pass2_playbook_triggers": [],
    }

    if not super_timeline_events or not device_map:
        return intelligence

    # Index events by device for fast lookup
    dev_events = {}
    for event in super_timeline_events:
        did = event.get("device_id", "")
        if did not in dev_events:
            dev_events[did] = []
        dev_events[did].append(event)

    # ---------------------------------------------------------------
    # 1. Cross-Device Process Chain Detection
    # ---------------------------------------------------------------
    _log("  Timeline Intel: scanning for cross-device process chains...")
    all_process_events = []
    for event in super_timeline_events:
        if event.get("event_type") in ("process_execution", "process_creation"):
            all_process_events.append(event)

    all_process_events.sort(key=lambda e: e.get("timestamp", ""))

    # Look for processes that have the same name appearing on different
    # devices within a short time window (indicating lateral movement)
    # or uncommon child-to-parent chains crossing device boundaries
    chain_keywords = ["psexec", "cmd.exe", "powershell.exe", "wmic.exe",
                      "winrm.exe", "schtasks.exe", "rundll32.exe",
                      "mshta.exe", "regsvr32.exe", "ntdsutil.exe",
                      "vssadmin.exe", "wscript.exe", "cscript.exe"]

    for proc_ev in all_process_events:
        detail = proc_ev.get("detail", {})
        proc_name = detail.get("name", "").lower() or detail.get("process_name", "").lower()
        if not proc_name:
            continue
        match_kw = None
        for kw in chain_keywords:
            if kw in proc_name:
                match_kw = kw
                break
        if not match_kw:
            continue

        # Find same or related process on other devices within 30 minutes
        ts = proc_ev.get("timestamp", "")
        try:
            from datetime import timedelta
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            window_end = dt + timedelta(minutes=30)
        except (ValueError, TypeError):
            continue

        related = []
        for other_ev in all_process_events:
            if other_ev.get("device_id") == proc_ev.get("device_id"):
                continue
            other_ts = other_ev.get("timestamp", "")
            try:
                other_dt = datetime.fromisoformat(other_ts.replace("Z", "+00:00"))
                if dt <= other_dt <= window_end:
                    other_detail = other_ev.get("detail", {})
                    other_name = other_detail.get("name", "").lower() or other_detail.get("process_name", "").lower()
                    if other_name and match_kw in other_name:
                        related.append(other_ev)
            except (ValueError, TypeError):
                continue

        if related and len(related) >= 1:
            devices_involved = list(set([proc_ev.get("device_id")] +
                                        [r.get("device_id") for r in related]))
            chain = {
                "root_process": proc_name,
                "source_device": proc_ev.get("device_id"),
                "source_timestamp": ts,
                "target_devices": list(set(r.get("device_id") for r in related)),
                "related_events": len(related),
                "devices_involved": devices_involved,
                "time_window": {
                    "start": ts,
                    "end": max(r.get("timestamp", ts) for r in related),
                },
            }
            intelligence["cross_device_process_chains"].append(chain)

            # Generate Pass 2 trigger
            trigger = {
                "trigger_id": f"trigger-chain-{proc_name}-{hash(ts) % 10000:04d}",
                "trigger_type": "cross_device_process_chain",
                "playbook_id": PASS2_TRIGGER_PLAYBOOK_MAP.get("cross_device_process_chain", "PB-SIFT-100"),
                "priority": "HIGH",
                "devices_involved": devices_involved,
                "time_window": chain["time_window"],
                "context": {
                    "root_process": proc_name,
                    "source_device": proc_ev.get("device_id"),
                    "chain_length": len(related),
                },
                "investigation_questions": [
                    f"How did {proc_name} execute on {proc_ev.get('device_id')}?",
                    f"What artifacts link {proc_name} across devices?",
                ],
            }
            # Deduplicate - one trigger per matched process keyword
            if not any(t["trigger_type"] == trigger["trigger_type"] and
                       all(d in t["devices_involved"] for d in devices_involved)
                       for t in intelligence["pass2_playbook_triggers"]):
                intelligence["pass2_playbook_triggers"].append(trigger)

    if intelligence["cross_device_process_chains"]:
        _log(f"  ✓ Found {len(intelligence['cross_device_process_chains'])} cross-device process chains")

    # ---------------------------------------------------------------
    # 2. USB Lateral Movement Detection
    # ---------------------------------------------------------------
    _log("  Timeline Intel: scanning for USB serial number correlations...")
    usb_events_by_serial = {}
    for event in super_timeline_events:
        detail = event.get("detail", {})
        key = detail.get("key", "").lower()
        value = detail.get("raw", "").lower() if isinstance(detail.get("raw"), str) else ""
        # Look for USBSTOR or mounted devices entries
        if ("usbstor" in key or "usb" in key or "mounteddevice" in key or
            "usb" in str(detail).lower()):
            # Extract serial numbers using common patterns
            for match in re.finditer(
                r'(?:VEN_[A-Fa-f0-9]{4}&PROD_[A-Fa-f0-9]{4}|[A-Fa-f0-9]{8}&[A-Fa-f0-9]{4}|[0-9A-Z]{10,})',
                str(detail)
            ):
                serial = match.group(0).upper()
                if serial not in usb_events_by_serial:
                    usb_events_by_serial[serial] = []
                usb_events_by_serial[serial].append(event)
        # Also check summary for USB references
        if "usb" in event.get("summary", "").lower():
            summary = event.get("summary", "")
            for match in re.finditer(
                r'(?:VEN_[A-Fa-f0-9]{4}&PROD_[A-Fa-f0-9]{4}|[A-Fa-f0-9]{8}&[A-Fa-f0-9]{4}|[0-9A-Z]{10,})',
                summary
            ):
                serial = match.group(0).upper()
                if serial not in usb_events_by_serial:
                    usb_events_by_serial[serial] = []
                usb_events_by_serial[serial].append(event)

    for serial, events in usb_events_by_serial.items():
        # A USB device seen on multiple hosts = lateral movement candidate
        devices_with_serial = set(e.get("device_id") for e in events)
        if len(devices_with_serial) >= 2:
            timestamps = sorted(e.get("timestamp", "") for e in events if e.get("timestamp"))
            if len(timestamps) >= 2:
                usb_movement = {
                    "serial_number": serial,
                    "devices_involved": sorted(devices_with_serial),
                    "event_count": len(events),
                    "time_window": {
                        "start": timestamps[0],
                        "end": timestamps[-1],
                    },
                }
                intelligence["usb_lateral_movement"].append(usb_movement)

                trigger = {
                    "trigger_id": f"trigger-usb-{serial[:8]}",
                    "trigger_type": "usb_lateral_movement",
                    "playbook_id": PASS2_TRIGGER_PLAYBOOK_MAP.get("usb_lateral_movement", "PB-SIFT-101"),
                    "priority": "HIGH",
                    "devices_involved": sorted(devices_with_serial),
                    "time_window": usb_movement["time_window"],
                    "context": {"serial_number": serial},
                    "investigation_questions": [
                        f"What files were accessed on USB {serial}?",
                        f"Which user performed the USB movement between {list(devices_with_serial)}?",
                    ],
                }
                intelligence["pass2_playbook_triggers"].append(trigger)

    if intelligence["usb_lateral_movement"]:
        _log(f"  ✓ Found {len(intelligence['usb_lateral_movement'])} USB lateral movement patterns")

    # ---------------------------------------------------------------
    # 3. Off-Hours Activity Clusters
    # ---------------------------------------------------------------
    _log("  Timeline Intel: scanning for off-hours activity clusters...")
    off_hours = []
    significant_types = ("process_execution", "process_creation", "file_creation",
                         "login", "network_connection", "service_change")
    for event in super_timeline_events:
        ts = event.get("timestamp", "")
        if not ts:
            continue
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            hour = dt.hour
            if hour >= 22 or hour < 5:
                if event.get("event_type") in significant_types:
                    off_hours.append(event)
        except (ValueError, TypeError):
            continue

    if len(off_hours) >= 3:
        # Cluster by 15-minute windows across devices
        clusters = {}
        for event in off_hours:
            try:
                dt = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
                # Round to 15-min window
                rounded = dt.replace(minute=(dt.minute // 15) * 15, second=0, microsecond=0)
                window_key = rounded.isoformat()[:16]
            except (ValueError, TypeError):
                continue
            if window_key not in clusters:
                clusters[window_key] = []
            clusters[window_key].append(event)

        for window_key, cluster_events in clusters.items():
            devices_in_window = set(e.get("device_id") for e in cluster_events)
            if len(devices_in_window) >= 2:
                timestamps = sorted(e.get("timestamp", "") for e in cluster_events if e.get("timestamp"))
                off_hours_cluster = {
                    "time_window": window_key,
                    "devices_involved": sorted(devices_in_window),
                    "event_count": len(cluster_events),
                    "sample_events": cluster_events[:5],
                    "time_range": {
                        "start": timestamps[0] if timestamps else "",
                        "end": timestamps[-1] if timestamps else "",
                    },
                }
                intelligence["off_hours_clusters"].append(off_hours_cluster)

                trigger = {
                    "trigger_id": f"trigger-offhours-{window_key.replace(':', '').replace('-', '')}",
                    "trigger_type": "off_hours_cluster",
                    "playbook_id": PASS2_TRIGGER_PLAYBOOK_MAP.get("off_hours_cluster", "PB-SIFT-102"),
                    "priority": "MEDIUM",
                    "devices_involved": sorted(devices_in_window),
                    "time_window": {
                        "start": timestamps[0] if timestamps else "",
                        "end": timestamps[-1] if timestamps else "",
                    },
                    "context": {"cluster_window": window_key, "sample_events": len(cluster_events)},
                    "investigation_questions": [
                        f"What triggered activity at {window_key} across {len(devices_in_window)} devices?",
                        "Were scheduled tasks or WMI subscriptions active?",
                    ],
                }
                if not any(t["trigger_type"] == trigger["trigger_type"] and
                           t.get("context", {}).get("cluster_window") == window_key
                           for t in intelligence["pass2_playbook_triggers"]):
                    intelligence["pass2_playbook_triggers"].append(trigger)

    if intelligence["off_hours_clusters"]:
        _log(f"  ✓ Found {len(intelligence['off_hours_clusters'])} off-hours clusters")

    # ---------------------------------------------------------------
    # 4. File Beaconing / Staging Patterns
    # ---------------------------------------------------------------
    _log("  Timeline Intel: scanning for file beaconing/staging patterns...")
    temp_pattern = re.compile(r'(?:\\Temp\\|/tmp/|\.tmp$|\.dat$)', re.IGNORECASE)
    file_events_by_device = {}
    for event in super_timeline_events:
        if event.get("event_type") not in ("file_creation", "file_modification",
                                            "file_deletion"):
            continue
        detail = event.get("detail", {})
        path = detail.get("path", "").lower() or event.get("summary", "").lower()
        if not temp_pattern.search(path):
            continue
        did = event.get("device_id", "")
        if did not in file_events_by_device:
            file_events_by_device[did] = []
        file_events_by_device[did].append(event)

    for did, events in file_events_by_device.items():
        if len(events) < 4:
            continue
        # Sort and look for regular intervals
        try:
            sorted_ts = []
            for e in events:
                ts = e.get("timestamp", "")
                if ts:
                    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                    sorted_ts.append((dt, e))
            sorted_ts.sort(key=lambda x: x[0])
            if len(sorted_ts) < 4:
                continue
            intervals = []
            for i in range(1, len(sorted_ts)):
                intervals.append((sorted_ts[i][0] - sorted_ts[i-1][0]).total_seconds())
            if not intervals:
                continue
            avg_interval = sum(intervals) / len(intervals)
            variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
            if avg_interval > 0 and variance ** 0.5 / avg_interval < 0.3 and len(intervals) >= 3:
                beacon = {
                    "device_id": did,
                    "file_count": len(sorted_ts),
                    "avg_interval_seconds": round(avg_interval, 1),
                    "time_window": {
                        "start": sorted_ts[0][0].isoformat()[:19] + "Z",
                        "end": sorted_ts[-1][0].isoformat()[:19] + "Z",
                    },
                }
                intelligence["file_beaconing_patterns"].append(beacon)
                # Link this to the time window trigger
                if not any(t.get("context", {}).get("device_id") == did and
                           "beacon" in t.get("trigger_id", "")
                           for t in intelligence["pass2_playbook_triggers"]):
                    trigger = {
                        "trigger_id": f"trigger-beacon-{did}",
                        "trigger_type": "file_beaconing",
                        "playbook_id": PASS2_TRIGGER_PLAYBOOK_MAP.get("file_beaconing", "PB-SIFT-103"),
                        "priority": "HIGH",
                        "devices_involved": [did],
                        "time_window": beacon["time_window"],
                        "context": beacon,
                        "investigation_questions": [
                            f"What process created the temp files on {did}?",
                            f"Is the beacon interval {avg_interval:.0f}s associated with known malware families?",
                        ],
                    }
                    intelligence["pass2_playbook_triggers"].append(trigger)
        except (ValueError, TypeError):
            continue

    if intelligence["file_beaconing_patterns"]:
        _log(f"  ✓ Found {len(intelligence['file_beaconing_patterns'])} file beaconing patterns")

    # ---------------------------------------------------------------
    # 5. Cross-Device IOC Correlation
    # ---------------------------------------------------------------
    _log("  Timeline Intel: scanning for cross-device IOC correlations...")
    # Collect IOCs from indicator hits and findings
    known_iocs = set()
    if indicator_hits:
        for hit in indicator_hits:
            if isinstance(hit, dict):
                pattern = hit.get("pattern", "")
                if pattern and len(pattern) > 4:
                    known_iocs.add(pattern.lower())

    # Look for co-occurring suspicious patterns across devices
    dev_ioc_sets = {}
    for event in super_timeline_events:
        if not event.get("suspicious"):
            continue
        did = event.get("device_id", "")
        reason = (event.get("suspicion_reason") or "").lower()
        summary = (event.get("summary") or "").lower()
        detail = event.get("detail", {})
        detail_str = str(detail).lower()

        if did not in dev_ioc_sets:
            dev_ioc_sets[did] = set()

        for ioc in known_iocs:
            if ioc in summary or ioc in detail_str or ioc in reason:
                dev_ioc_sets[did].add(ioc)

    # Find IOCs shared across multiple devices
    for ioc in known_iocs:
        devices_with_ioc = [did for did, iocs in dev_ioc_sets.items() if ioc in iocs]
        if len(devices_with_ioc) >= 2:
            ioc_corr = {
                "ioc": ioc,
                "devices_involved": sorted(devices_with_ioc),
                "device_count": len(devices_with_ioc),
            }
            intelligence["ioc_correlations"].append(ioc_corr)

            trigger = {
                "trigger_id": f"trigger-ioc-{hash(ioc) % 10000:04d}",
                "trigger_type": "ioc_correlation",
                "playbook_id": PASS2_TRIGGER_PLAYBOOK_MAP.get("ioc_correlation", "PB-SIFT-103"),
                "priority": "HIGH",
                "devices_involved": sorted(devices_with_ioc),
                "time_window": {"start": "", "end": ""},  # Full scope
                "context": {"ioc": ioc, "device_count": len(devices_with_ioc)},
                "investigation_questions": [
                    f"How was IOC '{ioc}' deployed across {len(devices_with_ioc)} devices?",
                    f"What is the deployment timeline for '{ioc}'?",
                ],
            }
            intelligence["pass2_playbook_triggers"].append(trigger)

    if intelligence["ioc_correlations"]:
        _log(f"  ✓ Found {len(intelligence['ioc_correlations'])} cross-device IOC correlations")

    # ---------------------------------------------------------------
    # 6. Dwell Time Window Calculation
    # ---------------------------------------------------------------
    _log("  Timeline Intel: calculating dwell time window...")
    all_timestamps = []
    for event in super_timeline_events:
        ts = event.get("timestamp", "")
        if not ts:
            continue
        if event.get("suspicious") or "suspicious" not in event:
            all_timestamps.append(ts)

    if all_timestamps:
        all_timestamps.sort()
        first = all_timestamps[0]
        last = all_timestamps[-1]
        try:
            t0 = datetime.fromisoformat(first.replace("Z", "+00:00")[:19])
            t1 = datetime.fromisoformat(last.replace("Z", "+00:00")[:19])
            dwell_days = round((t1 - t0).total_seconds() / 86400, 2)
        except (ValueError, TypeError):
            dwell_days = 0
        intelligence["dwell_time_window"] = {
            "first_seen": first,
            "last_seen": last,
            "dwell_days": dwell_days,
        }

    # Auto-trigger dwell window deep-dive for multi-day dwells
    if intelligence["dwell_time_window"]["dwell_days"] > 1:
        dw = intelligence["dwell_time_window"]
        trigger = {
            "trigger_id": f"trigger-dwell-{dw['dwell_days']}d",
            "trigger_type": "dwell_window",
            "playbook_id": PASS2_TRIGGER_PLAYBOOK_MAP.get("dwell_window", "PB-SIFT-104"),
            "priority": "MEDIUM",
            "devices_involved": sorted(device_map.keys()),
            "time_window": {"start": dw["first_seen"], "end": dw["last_seen"]},
            "context": {"dwell_days": dw["dwell_days"]},
            "investigation_questions": [
                "What user activity occurred across the full dwell window?",
                "Are there gaps or bursts that align with attacker behavior?",
            ],
        }
        intelligence["pass2_playbook_triggers"].append(trigger)

    _log(f"  Dwell time: {intelligence['dwell_time_window']['dwell_days']} days")
    _log(f"  Pass 2 triggers generated: {len(intelligence['pass2_playbook_triggers'])}")

    return intelligence
