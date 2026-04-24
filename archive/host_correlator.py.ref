#!/usr/bin/env python3
"""
Host Correlator — Cross-device user activity correlation.

Takes the device_map, user_map, all findings, and super-timeline events
to produce per-user activity narratives and detect lateral movement.
"""

import json
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Dict, List, Any, Optional


class HostCorrelator:
    """
    Correlates user activity across multiple devices.

    Produces:
    1. Per-user activity profiles (normal hours, common apps, common sites)
    2. Cross-host event chains (same user acting on different devices)
    3. Lateral movement detection (user appearing on devices they don't own)
    4. Temporal overlap analysis (what was happening on device A while B was active)
    """

    def correlate(self, device_map: dict, user_map: dict,
                  findings: List[dict],
                  timeline_events: List[dict]) -> dict:
        """
        Main correlation entry point.

        Returns:
            dict[username] -> {
                "devices": [device_ids],
                "activity_profile": {
                    "first_seen": "ISO timestamp",
                    "last_seen": "ISO timestamp",
                    "typical_hours": [8, 9, 10, 11, ...],  # hours of day with activity
                    "active_days": ["Mon", "Tue", ...],
                    "common_applications": [("chrome.exe", 47), ...],
                    "common_websites": [("outlook.office.com", 23), ...],
                    "total_events": int,
                },
                "per_device_summary": {
                    "DESKTOP-ABC": {
                        "event_count": int,
                        "first_seen": "ISO",
                        "last_seen": "ISO",
                        "event_types": {"login": 5, "process_execution": 42, ...},
                    },
                    ...
                },
                "cross_host_activity": [
                    {
                        "timestamp_range": ("start", "end"),
                        "devices_active": ["DESKTOP-ABC", "DSmith-iPhone"],
                        "description": "Concurrent activity on PC and phone",
                    },
                    ...
                ],
                "lateral_movement_indicators": [
                    {
                        "timestamp": "ISO",
                        "from_device": "DESKTOP-ABC",
                        "to_device": "SERVER-01",
                        "method": "RDP logon (Event 4624 Type 10)",
                        "severity": "HIGH",
                    },
                    ...
                ],
                "anomalies": [
                    "User appeared on SERVER-01 which is not in their device list",
                    "Activity gap of 6 hours on DESKTOP-ABC followed by burst",
                ],
            }
        """
        correlated = {}

        # Build per-user event collections
        user_events = self._collect_user_events(user_map, timeline_events)

        for username, udata in user_map.get("users", user_map).items():
            if isinstance(udata, str):
                # Handle both user_map formats
                continue

            devices = udata.get("devices", [])
            events = user_events.get(username, [])

            profile = self._build_activity_profile(events)
            per_device = self._build_per_device_summary(events, devices)
            cross_host = self._detect_cross_host_activity(events, devices)
            lateral = self._detect_lateral_movement(
                events, devices, device_map, username)
            anomalies = self._detect_anomalies(events, profile, devices)

            correlated[username] = {
                "devices": devices,
                "activity_profile": profile,
                "per_device_summary": per_device,
                "cross_host_activity": cross_host,
                "lateral_movement_indicators": lateral,
                "anomalies": anomalies,
            }

        return correlated

    def _collect_user_events(self, user_map: dict,
                              timeline_events: List[dict]) -> Dict[str, List]:
        """Group timeline events by normalized username."""
        user_events = defaultdict(list)

        # Build username lookup (including aliases)
        alias_to_user = {}
        users = user_map.get("users", user_map)
        for username, udata in users.items():
            if isinstance(udata, dict):
                for alias in udata.get("aliases", [username]):
                    alias_to_user[alias.lower()] = username
                alias_to_user[username.lower()] = username

        for event in timeline_events:
            owner = event.get("owner", "").lower()
            if owner in alias_to_user:
                user_events[alias_to_user[owner]].append(event)
            elif owner:
                # Try to match by partial username
                for alias, uname in alias_to_user.items():
                    if alias in owner or owner in alias:
                        user_events[uname].append(event)
                        break

        return dict(user_events)

    def _build_activity_profile(self, events: List[dict]) -> dict:
        """Build a behavioral profile from user's events."""
        if not events:
            return {
                "first_seen": None, "last_seen": None,
                "typical_hours": [], "active_days": [],
                "common_applications": [], "common_websites": [],
                "total_events": 0,
            }

        timestamps = []
        hours = defaultdict(int)
        days = defaultdict(int)
        applications = defaultdict(int)
        websites = defaultdict(int)

        for event in events:
            ts = event.get("timestamp", "")
            if ts:
                timestamps.append(ts)
                try:
                    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                    hours[dt.hour] += 1
                    days[dt.strftime("%a")] += 1
                except (ValueError, TypeError):
                    pass

            # Track applications from process execution events
            if event.get("event_type") == "process_execution":
                proc = event.get("detail", {}).get("process_name", "")
                if proc:
                    applications[proc.lower()] += 1

            # Track websites from browser events
            if event.get("event_type") == "browser_visit":
                url = event.get("detail", {}).get("url", "")
                if url:
                    # Extract domain
                    import re
                    domain_match = re.search(
                        r'https?://([^/]+)', url)
                    if domain_match:
                        websites[domain_match.group(1)] += 1

        sorted_ts = sorted(timestamps)
        typical_hours = sorted(
            [h for h, count in hours.items() if count >= 2])
        active_days = sorted(
            days.keys(),
            key=lambda d: ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"].index(d)
            if d in ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"] else 7
        )
        common_apps = sorted(
            applications.items(), key=lambda x: x[1], reverse=True)[:20]
        common_sites = sorted(
            websites.items(), key=lambda x: x[1], reverse=True)[:20]

        return {
            "first_seen": sorted_ts[0] if sorted_ts else None,
            "last_seen": sorted_ts[-1] if sorted_ts else None,
            "typical_hours": typical_hours,
            "active_days": active_days,
            "common_applications": common_apps,
            "common_websites": common_sites,
            "total_events": len(events),
        }

    def _build_per_device_summary(self, events: List[dict],
                                   devices: List[str]) -> dict:
        """Summarize activity per device for this user."""
        per_device = {}
        for dev_id in devices:
            dev_events = [e for e in events
                          if e.get("device_id") == dev_id]
            if not dev_events:
                per_device[dev_id] = {
                    "event_count": 0,
                    "first_seen": None,
                    "last_seen": None,
                    "event_types": {},
                }
                continue

            timestamps = sorted(
                [e.get("timestamp", "") for e in dev_events if e.get("timestamp")])
            event_types = defaultdict(int)
            for e in dev_events:
                event_types[e.get("event_type", "other")] += 1

            per_device[dev_id] = {
                "event_count": len(dev_events),
                "first_seen": timestamps[0] if timestamps else None,
                "last_seen": timestamps[-1] if timestamps else None,
                "event_types": dict(event_types),
            }

        return per_device

    def _detect_cross_host_activity(self, events: List[dict],
                                     devices: List[str]) -> List[dict]:
        """
        Detect time windows where the user was active on multiple devices.
        A 30-minute sliding window is used.
        """
        if len(devices) < 2:
            return []

        cross_host = []

        # Group events by device with parsed timestamps
        device_times = defaultdict(list)
        for event in events:
            dev = event.get("device_id", "")
            ts = event.get("timestamp", "")
            if dev and ts:
                try:
                    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                    device_times[dev].append(dt)
                except (ValueError, TypeError):
                    continue

        # For each pair of devices, find overlapping activity windows
        dev_list = list(device_times.keys())
        for i in range(len(dev_list)):
            for j in range(i + 1, len(dev_list)):
                dev_a = dev_list[i]
                dev_b = dev_list[j]
                times_a = sorted(device_times[dev_a])
                times_b = sorted(device_times[dev_b])

                # Find events within 30 minutes of each other
                window = timedelta(minutes=30)
                for ta in times_a:
                    for tb in times_b:
                        if abs(ta - tb) <= window:
                            cross_host.append({
                                "timestamp_range": (
                                    min(ta, tb).isoformat(),
                                    max(ta, tb).isoformat(),
                                ),
                                "devices_active": [dev_a, dev_b],
                                "description": (
                                    f"Concurrent activity on {dev_a} and "
                                    f"{dev_b} within 30 minutes"
                                ),
                            })
                            break  # One match per time_a is enough

        # Deduplicate by time range
        seen = set()
        deduped = []
        for ch in cross_host:
            key = str(ch["timestamp_range"])
            if key not in seen:
                seen.add(key)
                deduped.append(ch)
        return deduped[:50]  # Cap at 50

    def _detect_lateral_movement(self, events: List[dict],
                                  owned_devices: List[str],
                                  device_map: dict,
                                  username: str) -> List[dict]:
        """
        Detect user appearing on devices they don't own.
        Also detect RDP/network logon events between devices.
        """
        indicators = []
        owned_set = set(owned_devices)

        for event in events:
            dev = event.get("device_id", "")
            if dev and dev not in owned_set:
                indicators.append({
                    "timestamp": event.get("timestamp", ""),
                    "from_device": "unknown",
                    "to_device": dev,
                    "method": f"{event.get('event_type', 'unknown')} on "
                              f"non-owned device",
                    "severity": "HIGH",
                    "event_summary": event.get("summary", "")[:200],
                })

            # Check for network logon types (Type 3, 10 = network/RDP)
            if event.get("event_type") == "login":
                logon_type = event.get("detail", {}).get("logon_type")
                if logon_type in (3, 10):
                    source_ip = event.get("detail", {}).get("source_ip", "")
                    indicators.append({
                        "timestamp": event.get("timestamp", ""),
                        "from_device": f"source_ip:{source_ip}",
                        "to_device": dev,
                        "method": f"Network logon Type {logon_type}"
                                  f" from {source_ip}",
                        "severity": "MEDIUM" if logon_type == 3 else "HIGH",
                        "event_summary": event.get("summary", "")[:200],
                    })

        # Deduplicate
        seen = set()
        deduped = []
        for ind in indicators:
            key = f"{ind['timestamp']}:{ind['to_device']}"
            if key not in seen:
                seen.add(key)
                deduped.append(ind)
        return deduped[:100]

    def _detect_anomalies(self, events: List[dict],
                           profile: dict,
                           devices: List[str]) -> List[str]:
        """Detect general anomalies in user behavior."""
        anomalies = []

        # Check for activity gaps followed by bursts
        if events:
            timestamps = []
            for e in events:
                ts = e.get("timestamp", "")
                try:
                    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                    timestamps.append(dt)
                except (ValueError, TypeError):
                    continue

            if len(timestamps) > 10:
                timestamps.sort()
                for i in range(1, len(timestamps)):
                    gap = (timestamps[i] - timestamps[i-1]).total_seconds()
                    if gap > 6 * 3600:  # 6 hour gap
                        # Check if burst follows
                        burst_count = 0
                        for j in range(i, min(i + 20, len(timestamps))):
                            if j + 1 < len(timestamps):
                                next_gap = (timestamps[j+1] - timestamps[j]).total_seconds()
                                if next_gap < 60:  # Less than 1 minute between events
                                    burst_count += 1
                        if burst_count >= 5:
                            anomalies.append(
                                f"Activity gap of {gap/3600:.1f} hours "
                                f"followed by burst of {burst_count} rapid "
                                f"events at {timestamps[i].isoformat()}"
                            )
                            break  # Report first instance only

        # Check for off-hours patterns
        typical = set(profile.get("typical_hours", []))
        if typical:
            off_hours_events = [
                e for e in events
                if e.get("timestamp") and
                self._get_hour(e["timestamp"]) not in typical
            ]
            if len(off_hours_events) > 10:
                anomalies.append(
                    f"{len(off_hours_events)} events outside typical "
                    f"activity hours ({sorted(typical)})"
                )

        return anomalies

    @staticmethod
    def _get_hour(timestamp: str) -> Optional[int]:
        try:
            dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            return dt.hour
        except (ValueError, TypeError):
            return None
