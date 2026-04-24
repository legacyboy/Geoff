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
