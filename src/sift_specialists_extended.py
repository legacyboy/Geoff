#!/usr/bin/env python3
"""
Extended SIFT Tool Specialists - Full Parsed Output for Every Specialist

Every function parses raw tool output into structured JSON instead of
returning raw stdout. Covers:
  - REGISTRY_Specialist  (RegRipper → parsed key-value, timestamps, values)
  - PLASO_Specialist     (log2timeline/psort/pinfo → event counts, parser info, storage stats)
  - NETWORK_Specialist   (tshark/tcpflow → protocol stats, conversations, DNS, HTTP)
  - LOG_Specialist       (evtx/syslog → event IDs, timestamps, key data)
  - MOBILE_Specialist    (iOS Info.plist, Manifest.db, Android packages)
  - ExtendedOrchestrator (includes remnux module reference)
"""

import json
import subprocess
import re
import os
import tempfile
import plistlib
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
from xml.etree import ElementTree as ET


# ---------------------------------------------------------------------------
# Shared parsing helpers
# ---------------------------------------------------------------------------

_TS_PATTERNS = [
    # RegRipper / Windows timestamps: 2021-03-15 14:30:00  or  03/15/2021 14:30:00
    re.compile(
        r'(\d{4}[-/]\d{2}[-/]\d{2}\s+\d{2}:\d{2}:\d{2})'),
    # W3C / ISO-8601
    re.compile(
        r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})'),
]

_KV_SEP = re.compile(r'[:\t]\s*')


def _extract_timestamps(text: str) -> List[str]:
    """Pull all recognised timestamps from a block of text."""
    out: List[str] = []
    for pat in _TS_PATTERNS:
        out.extend(m.group(1) for m in pat.finditer(text))
    return out


def _parse_kv_lines(text: str) -> List[Dict[str, str]]:
    """Parse key-value pairs from lines like  Key: Value  or  Key\tValue."""
    entries: List[Dict[str, str]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#') or line.startswith('-') * 3:
            continue
        m = _KV_SEP.search(line)
        if m:
            entries.append({
                'key': line[:m.start()].strip(),
                'value': line[m.end():].strip(),
            })
    return entries


def _parse_regripper_output(raw: str) -> Dict[str, Any]:
    """
    Structured parse of RegRipper text output.

    RegRipper output is a sequence of blocks, each starting with a
    registry-key path on its own line, followed by indented value lines.
    We parse into:
      - keys: list of {path, values: [{name, data, last_written}]}
      - timestamps: all timestamps found
      - raw: the original text (truncated to 10k)
    """
    keys: List[Dict[str, Any]] = []
    timestamps: List[str] = []
    current_key: Optional[Dict[str, Any]] = None

    # RegRipper key-path lines usually start at column 0 and contain backslash
    key_path_re = re.compile(r'^[A-Za-z]\\[^\n]+|^HKLM\\|^HKCU\\|^HKEY_')
    # Value line: indented, usually  Name  ->  Data  or  Name: Data
    value_re = re.compile(r'^\s+(.+?)\s*(?:->|:)\s*(.+)')

    for line in raw.splitlines():
        # Detect key path
        if key_path_re.match(line) or (line and not line[0].isspace() and '\\' in line and ':' not in line[:5]):
            if current_key:
                keys.append(current_key)
            # Check for LastWritten timestamp on same or next line
            ts_matches = _extract_timestamps(line)
            timestamps.extend(ts_matches)
            current_key = {
                'path': line.strip(),
                'last_written': ts_matches[0] if ts_matches else None,
                'values': [],
            }
            continue

        # Detect timestamp
        ts_matches = _extract_timestamps(line)
        if ts_matches:
            timestamps.extend(ts_matches)
            if current_key and current_key.get('last_written') is None:
                current_key['last_written'] = ts_matches[0]

        # Detect value line
        vmatch = value_re.match(line)
        if vmatch and current_key:
            current_key['values'].append({
                'name': vmatch.group(1).strip(),
                'data': vmatch.group(2).strip(),
            })
        elif line.strip() and current_key:
            # Fallback: any indented non-empty line is a value
            current_key['values'].append({
                'name': line.strip(),
                'data': '',
            })

    if current_key:
        keys.append(current_key)

    return {
        'keys': keys,
        'key_count': len(keys),
        'timestamps': timestamps,
        'timestamp_count': len(timestamps),
        'raw': raw[:10000],
    }


# ---------------------------------------------------------------------------
# REGISTRY_Specialist
# ---------------------------------------------------------------------------

class REGISTRY_Specialist:
    """Specialist for Windows Registry forensics – fully parsed output."""

    def __init__(self, regripper_path: str = "/usr/local/bin/rip.pl"):
        self.regripper_path = regripper_path
        self.common_hives = [
            'NTUSER.DAT', 'SYSTEM', 'SOFTWARE', 'SECURITY', 'SAM', 'AmCache.hve',
        ]

    def _check_regripper(self) -> bool:
        return Path(self.regripper_path).exists()

    def _run_regripper(self, hive_path: str, plugin: str) -> Dict[str, Any]:
        """Run RegRipper and return (status_dict, raw_stdout)."""
        if not self._check_regripper():
            return {
                'tool': 'regripper',
                'status': 'error',
                'error': 'RegRipper not found',
                'timestamp': datetime.now().isoformat(),
            }, ''

        cmd = ['perl', self.regripper_path, '-r', hive_path, '-f', plugin]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            ok = result.returncode == 0
            return {
                'tool': 'regripper',
                'status': 'success' if ok else 'error',
                'returncode': result.returncode,
                'errors': result.stderr[:2000] if result.stderr else '',
                'timestamp': datetime.now().isoformat(),
            }, result.stdout
        except Exception as e:
            return {
                'tool': 'regripper',
                'status': 'error',
                'error': str(e),
                'timestamp': datetime.now().isoformat(),
            }, ''

    # -- public API ----------------------------------------------------------

    def parse_hive(self, hive_path: str, plugin: Optional[str] = None) -> Dict[str, Any]:
        """Parse registry hive with RegRipper – returns structured keys/values."""
        if plugin is None:
            hive_name = Path(hive_path).name.upper()
            if 'NTUSER' in hive_name:
                plugin = 'ntuserall'
            elif 'SYSTEM' in hive_name:
                plugin = 'systemall'
            elif 'SOFTWARE' in hive_name:
                plugin = 'softwareall'
            else:
                plugin = 'all'

        meta, raw = self._run_regripper(hive_path, plugin)
        parsed = _parse_regripper_output(raw)

        return {
            'tool': 'regripper',
            'hive': hive_path,
            'plugin': plugin,
            'status': meta.get('status', 'error'),
            'keys': parsed['keys'],
            'key_count': parsed['key_count'],
            'timestamps': parsed['timestamps'],
            'timestamp_count': parsed['timestamp_count'],
            'raw': parsed['raw'],
            'errors': meta.get('errors', ''),
            'timestamp': datetime.now().isoformat(),
        }

    def extract_user_assist(self, ntuser_path: str) -> Dict[str, Any]:
        """Extract UserAssist artifacts (program execution counts & timestamps)."""
        meta, raw = self._run_regripper(ntuser_path, 'userassist')

        # UserAssist output has GUID entries with run-count and focus-count
        entries: List[Dict[str, Any]] = []
        guid_re = re.compile(r'\{[A-Fa-f0-9-]+\}')
        run_count_re = re.compile(r'Run count:\s*(\d+)', re.IGNORECASE)
        focus_re = re.compile(r'Focus count:\s*(\d+)', re.IGNORECASE)
        focus_time_re = re.compile(r'Focus time:\s*(\d+)', re.IGNORECASE)
        name_re = re.compile(r'Name:\s*(.+)', re.IGNORECASE)

        current: Dict[str, Any] = {}
        for line in raw.splitlines():
            if guid_re.search(line) and 'UEME' in line.upper():
                if current:
                    entries.append(current)
                current = {'guid': guid_re.search(line).group(0), 'path': '', 'run_count': 0, 'focus_count': 0, 'focus_time_ms': 0, 'last_written': None}
                ts = _extract_timestamps(line)
                if ts:
                    current['last_written'] = ts[0]
                continue
            m = name_re.search(line)
            if m and current:
                current['path'] = m.group(1).strip()
            m = run_count_re.search(line)
            if m and current:
                current['run_count'] = int(m.group(1))
            m = focus_re.search(line)
            if m and current:
                current['focus_count'] = int(m.group(1))
            m = focus_time_re.search(line)
            if m and current:
                current['focus_time_ms'] = int(m.group(1))

        if current:
            entries.append(current)

        timestamps = _extract_timestamps(raw)

        return {
            'tool': 'regripper',
            'hive': ntuser_path,
            'plugin': 'userassist',
            'status': meta.get('status', 'error'),
            'entries': entries,
            'entry_count': len(entries),
            'timestamps': timestamps,
            'errors': meta.get('errors', ''),
            'timestamp': datetime.now().isoformat(),
        }

    def extract_shellbags(self, ntuser_path: str) -> Dict[str, Any]:
        """Extract ShellBags (folder access history) – parsed paths and timestamps."""
        meta, raw = self._run_regripper(ntuser_path, 'shellbags')

        # ShellBags output: path lines with modification/access timestamps
        entries: List[Dict[str, Any]] = []
        path_re = re.compile(r'^\s*(.{2}:\\[^\n]+|\\\\[^\n]+)', re.MULTILINE)
        for m in path_re.finditer(raw):
            path_line = m.group(1).strip()
            ts = _extract_timestamps(raw[max(0, m.start() - 80):m.end() + 120])
            entries.append({
                'path': path_line,
                'timestamps': ts,
            })

        # Fallback: try key-value lines
        if not entries:
            kv = _parse_kv_lines(raw)
            for pair in kv:
                if '\\' in pair['value'] or '\\' in pair['key']:
                    entries.append({
                        'path': pair['value'] if '\\' in pair['value'] else pair['key'],
                        'timestamps': _extract_timestamps(pair['value']),
                    })

        timestamps = _extract_timestamps(raw)

        return {
            'tool': 'regripper',
            'hive': ntuser_path,
            'plugin': 'shellbags',
            'status': meta.get('status', 'error'),
            'entries': entries[:200],
            'entry_count': len(entries),
            'timestamps': timestamps,
            'errors': meta.get('errors', ''),
            'timestamp': datetime.now().isoformat(),
        }

    def extract_mounted_devices(self, system_path: str) -> Dict[str, Any]:
        """Extract mounted device history – device name → DOS devices mapping."""
        meta, raw = self._run_regripper(system_path, 'mountdev2')

        entries: List[Dict[str, Any]] = []
        # MountedDevices output:  \??\Volume{...}  or  \DosDevices\C:  =  ...
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            # Look for drive-letter or volume entries
            if '\\DosDevices\\' in line or '\\??\\Volume' in line:
                parts = line.split('->', 1) if '->' in line else line.split(':', 1)
                device = parts[0].strip() if parts else line
                target = parts[1].strip() if len(parts) > 1 else ''
                entries.append({
                    'device': device,
                    'target': target,
                    'timestamps': _extract_timestamps(line),
                })

        # Fallback key-value
        if not entries:
            for kv in _parse_kv_lines(raw):
                if kv['key'] and ('dos' in kv['key'].lower() or 'volume' in kv['key'].lower() or 'device' in kv['key'].lower()):
                    entries.append({'device': kv['key'], 'target': kv['value'], 'timestamps': _extract_timestamps(kv['value'])})

        return {
            'tool': 'regripper',
            'hive': system_path,
            'plugin': 'mountdev2',
            'status': meta.get('status', 'error'),
            'entries': entries,
            'entry_count': len(entries),
            'errors': meta.get('errors', ''),
            'timestamp': datetime.now().isoformat(),
        }

    def extract_usb_devices(self, system_path: str) -> Dict[str, Any]:
        """Extract USB device history – vendor, product, serial, timestamps."""
        meta, raw = self._run_regripper(system_path, 'usbstor')

        entries: List[Dict[str, Any]] = []
        # USBSTOR output blocks per device with class/serial/timestamps
        device_re = re.compile(r'Disk&Ven_([^&]+)&Prod_([^&]+)&Rev_([^\s\\]+)')
        serial_re = re.compile(r'&([0-9A-Fa-f]{6,})&')
        current: Dict[str, Any] = {}

        for line in raw.splitlines():
            dm = device_re.search(line)
            if dm:
                if current:
                    entries.append(current)
                current = {
                    'vendor': dm.group(1),
                    'product': dm.group(2),
                    'revision': dm.group(3),
                    'serial': '',
                    'first_installed': None,
                    'last_connected': None,
                    'last_removed': None,
                }
                sm = serial_re.search(line)
                if sm:
                    current['serial'] = sm.group(1)
                continue
            ts = _extract_timestamps(line)
            if ts and current:
                lower = line.lower()
                if 'first' in lower or 'install' in lower:
                    current['first_installed'] = ts[0]
                elif 'last' in lower and 'remov' in lower:
                    current['last_removed'] = ts[0]
                elif 'last' in lower or 'connect' in lower:
                    current['last_connected'] = ts[0]
                elif current.get('first_installed') is None:
                    current['first_installed'] = ts[0]

        if current:
            entries.append(current)

        # Fallback: plain key-value lines
        if not entries:
            for kv in _parse_kv_lines(raw):
                entries.append({'device': kv['key'], 'info': kv['value'], 'timestamps': _extract_timestamps(kv['value'])})

        return {
            'tool': 'regripper',
            'hive': system_path,
            'plugin': 'usbstor',
            'status': meta.get('status', 'error'),
            'entries': entries,
            'entry_count': len(entries),
            'errors': meta.get('errors', ''),
            'timestamp': datetime.now().isoformat(),
        }

    def extract_autoruns(self, software_path: str) -> Dict[str, Any]:
        """Extract autorun locations – run keys, services, scheduled tasks."""
        meta, raw = self._run_regripper(software_path, 'soft_run')

        entries: List[Dict[str, Any]] = []
        # Autorun entries are key-value:  ProgramName  ->  C:\path\to\exe
        for kv in _parse_kv_lines(raw):
            entries.append({
                'name': kv['key'],
                'value': kv['value'],
                'timestamps': _extract_timestamps(kv['value']),
            })

        # Supplement: look for common run-key paths in the output
        run_key_paths = []
        for line in raw.splitlines():
            if 'Run\\' in line or 'RunOnce\\' in line:
                path_match = re.search(r'(Software\\[^\s]+Run[^\s]*)', line)
                if path_match:
                    run_key_paths.append(path_match.group(1))

        return {
            'tool': 'regripper',
            'hive': software_path,
            'plugin': 'soft_run',
            'status': meta.get('status', 'error'),
            'entries': entries,
            'entry_count': len(entries),
            'run_key_paths': list(set(run_key_paths)),
            'errors': meta.get('errors', ''),
            'timestamp': datetime.now().isoformat(),
        }

    def extract_services(self, system_path: str) -> Dict[str, Any]:
        """Extract service configurations – name, display name, image path, start type."""
        meta, raw = self._run_regripper(system_path, 'svc')

        entries: List[Dict[str, Any]] = []
        # Service blocks usually have DisplayName, ImagePath, Start type
        current: Dict[str, Any] = {}

        for line in raw.splitlines():
            line_s = line.strip()
            if not line_s:
                continue

            # New service entry often indicated by a key path ending in Services\<name>
            svc_match = re.search(r'Services\\([^\\]+)$', line_s)
            if svc_match:
                if current:
                    entries.append(current)
                current = {'name': svc_match.group(1), 'display_name': '', 'image_path': '', 'start_type': '', 'timestamps': []}

            lower = line_s.lower()
            if 'displayname' in lower:
                m = _KV_SEP.search(line_s)
                if m and current is not None:
                    current['display_name'] = line_s[m.end():].strip()
            elif 'imagepath' in lower or 'ImagePath' in line_s:
                m = _KV_SEP.search(line_s)
                if m and current is not None:
                    current['image_path'] = line_s[m.end():].strip()
            elif 'start' in lower and ('type' in lower or _KV_SEP.search(line_s)):
                m = _KV_SEP.search(line_s)
                if m and current is not None:
                    val = line_s[m.end():].strip()
                    # Map start DWORD to human
                    start_map = {'0': 'Boot', '1': 'System', '2': 'Automatic', '3': 'Manual', '4': 'Disabled'}
                    current['start_type'] = start_map.get(val, val)

            ts = _extract_timestamps(line_s)
            if ts and current is not None:
                current['timestamps'].extend(ts)

        if current:
            entries.append(current)

        return {
            'tool': 'regripper',
            'hive': system_path,
            'plugin': 'svc',
            'status': meta.get('status', 'error'),
            'entries': entries,
            'entry_count': len(entries),
            'errors': meta.get('errors', ''),
            'timestamp': datetime.now().isoformat(),
        }

    def scan_all_hives(self, evidence_dir: str) -> Dict[str, Any]:
        """Scan all registry hives in evidence directory – parsed results per hive."""
        evidence_path = Path(evidence_dir)
        results: Dict[str, Any] = {}

        for hive in self.common_hives:
            matches = list(evidence_path.rglob(hive))
            for match in matches:
                results[str(match)] = self.parse_hive(str(match))

        # Aggregate stats
        total_keys = sum(r.get('key_count', 0) for r in results.values() if isinstance(r, dict))
        total_ts = sum(r.get('timestamp_count', 0) for r in results.values() if isinstance(r, dict))

        return {
            'tool': 'regripper_batch',
            'hives_found': len(results),
            'total_keys': total_keys,
            'total_timestamps': total_ts,
            'results': results,
            'timestamp': datetime.now().isoformat(),
        }


# ---------------------------------------------------------------------------
# PLASO_Specialist
# ---------------------------------------------------------------------------

class PLASO_Specialist:
    """Specialist for timeline analysis with Plaso/log2timeline – parsed output."""

    def __init__(self):
        self.log2timeline_path = self._find_tool('log2timeline.py')
        self.psort_path = self._find_tool('psort.py')
        self.pinfo_path = self._find_tool('pinfo.py')

    def _find_tool(self, tool_name: str) -> Optional[str]:
        for path in ['/usr/local/bin', '/usr/bin']:
            full_path = Path(path) / tool_name
            if full_path.exists():
                return str(full_path)
        # Try just the name on PATH
        try:
            r = subprocess.run(['which', tool_name], capture_output=True, text=True)
            if r.returncode == 0:
                return r.stdout.strip()
        except Exception:
            pass
        return None

    # -- helpers -------------------------------------------------------------

    @staticmethod
    def _parse_log2timeline_stdout(text: str) -> Dict[str, Any]:
        """Extract event counts, parser info, and warnings from log2timeline output."""
        event_count: Optional[int] = None
        parsers_used: List[str] = []
        warnings: List[str] = []
        errors: List[str] = []

        for line in text.splitlines():
            lower = line.lower().strip()
            # Event count: "Events: 12345" or "12345 events extracted"
            m = re.search(r'(\d[\d,]*)\s+events?\s', lower)
            if m and event_count is None:
                event_count = int(m.group(1).replace(',', ''))
            m = re.search(r'events?\s*:\s*(\d[\d,]*)', lower)
            if m and event_count is None:
                event_count = int(m.group(1).replace(',', ''))
            # Parser line: "parser: xxx"
            if 'parser' in lower and ':' in line:
                parsers_used.append(line.split(':', 1)[1].strip())
            # Warning / error
            if 'warning' in lower:
                warnings.append(line.strip())
            if 'error' in lower:
                errors.append(line.strip())

        return {
            'event_count': event_count,
            'parsers_used': list(set(parsers_used))[:50],
            'warnings': warnings[:20],
            'errors': errors[:20],
        }

    @staticmethod
    def _parse_psort_stdout(text: str) -> Dict[str, Any]:
        """Extract event count and format info from psort output."""
        event_count: Optional[int] = None
        output_file: Optional[str] = None

        for line in text.splitlines():
            lower = line.lower()
            m = re.search(r'(\d[\d,]*)\s+events?\s', lower)
            if m and event_count is None:
                event_count = int(m.group(1).replace(',', ''))
            m = re.search(r'wrote\s+(\d[\d,]*)\s+events', lower)
            if m and event_count is None:
                event_count = int(m.group(1).replace(',', ''))
            if 'output' in lower and '.csv' in lower:
                of = re.search(r'(/?\S+\.csv)', line)
                if of:
                    output_file = of.group(1)

        return {'event_count': event_count, 'output_file': output_file}

    @staticmethod
    def _parse_pinfo_stdout(text: str) -> Dict[str, Any]:
        """
        Parse pinfo output into structured storage stats.

        Typical pinfo output includes sections for:
          - Storage format
          - Serialization format
          - Number of events
          - Parser/plugin filter
          - Parsers/plugins used with event counts
        """
        storage_format: Optional[str] = None
        serialization_format: Optional[str] = None
        event_count: Optional[int] = None
        parsers: Dict[str, int] = {}
        sources: Dict[str, int] = {}
        warnings_count: Optional[int] = None

        current_section: Optional[str] = None

        for line in text.splitlines():
            stripped = line.strip()
            lower = stripped.lower()
            if not stripped:
                continue

            # Section headers
            if 'storage format' in lower:
                storage_format = stripped.split(':', 1)[-1].strip() if ':' in stripped else stripped
            elif 'serialization format' in lower:
                serialization_format = stripped.split(':', 1)[-1].strip() if ':' in stripped else stripped
            elif 'number of events' in lower or 'events:' in lower:
                m = re.search(r'(\d[\d,]*)', stripped)
                if m:
                    event_count = int(m.group(1).replace(',', ''))

            # Parser count lines: "  parser_name (plugin) : 1234"
            m = re.match(r'\s+([\w_.]+(?:\s+\([\w_.]+\))?)\s*:\s*(\d[\d,]*)', stripped)
            if m and current_section != 'warnings':
                parsers[m.group(1).strip()] = int(m.group(2).replace(',', ''))

            # Source type lines: similar format
            m2 = re.match(r'\s+([\w_ ]+)\s*:\s*(\d[\d,]*)', stripped)
            if m2 and current_section == 'sources':
                sources[m2.group(1).strip()] = int(m2.group(2).replace(',', ''))

            # Section tracking
            if 'parsers' in lower and ('used' in lower or 'plugins' in lower):
                current_section = 'parsers'
            elif 'source' in lower:
                current_section = 'sources'
            elif 'warning' in lower:
                current_section = 'warnings'
                wm = re.search(r'(\d[\d,]*)', stripped)
                if wm:
                    warnings_count = int(wm.group(1).replace(',', ''))

        return {
            'storage_format': storage_format,
            'serialization_format': serialization_format,
            'event_count': event_count,
            'parsers': parsers,
            'parser_count': len(parsers),
            'sources': sources,
            'warnings_count': warnings_count,
            'raw': text[:10000],
        }

    # -- public API ----------------------------------------------------------

    def create_timeline(self, evidence_path: str, output_file: str,
                        parsers: Optional[List[str]] = None) -> Dict[str, Any]:
        """Create timeline with log2timeline – parsed event counts and parser info."""
        if not self.log2timeline_path:
            return {
                'tool': 'log2timeline',
                'status': 'error',
                'error': 'log2timeline.py not found',
                'timestamp': datetime.now().isoformat(),
            }

        try:
            Path(output_file).parent.mkdir(parents=True, exist_ok=True)

            cmd = ['python3', self.log2timeline_path, '--status_view', 'none']
            if parsers:
                cmd.extend(['--parsers', ','.join(parsers)])
            cmd.extend([output_file, evidence_path])

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)

            # Retry with --source if positional fails
            if result.returncode != 0 and 'unrecognized arguments' in result.stderr:
                cmd_retry = ['python3', self.log2timeline_path, '--status_view', 'none']
                if parsers:
                    cmd_retry.extend(['--parsers', ','.join(parsers)])
                cmd_retry.extend([output_file, '--source', evidence_path])
                result = subprocess.run(cmd_retry, capture_output=True, text=True, timeout=1800)

            parsed = self._parse_log2timeline_stdout(result.stdout)

            return {
                'tool': 'log2timeline',
                'evidence': evidence_path,
                'output': output_file,
                'status': 'success' if result.returncode == 0 else 'error',
                'returncode': result.returncode,
                'event_count': parsed['event_count'],
                'parsers_used': parsed['parsers_used'],
                'warnings': parsed['warnings'],
                'errors_parsed': parsed['errors'],
                'stderr_tail': result.stderr[-2000:] if result.stderr else '',
                'timestamp': datetime.now().isoformat(),
            }
        except subprocess.TimeoutExpired:
            return {
                'tool': 'log2timeline',
                'status': 'timeout',
                'error': 'Timeline creation timed out after 30 minutes',
                'timestamp': datetime.now().isoformat(),
            }
        except Exception as e:
            return {
                'tool': 'log2timeline',
                'status': 'error',
                'error': str(e),
                'timestamp': datetime.now().isoformat(),
            }

    def sort_timeline(self, storage_file: str, output_format: str = 'l2tcsv',
                      filter_str: Optional[str] = None) -> Dict[str, Any]:
        """Sort and filter timeline with psort – parsed event count."""
        if not self.psort_path:
            return {
                'tool': 'psort',
                'status': 'error',
                'error': 'psort.py not found',
                'timestamp': datetime.now().isoformat(),
            }

        try:
            output_file = storage_file.replace('.plaso', f'.{output_format}')

            cmd = ['python3', self.psort_path, '-o', output_format, '-w', output_file]
            if filter_str:
                cmd.extend(['--slice', filter_str])
            cmd.append(storage_file)

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)

            parsed = self._parse_psort_stdout(result.stdout)

            return {
                'tool': 'psort',
                'input': storage_file,
                'output': output_file,
                'format': output_format,
                'status': 'success' if result.returncode == 0 else 'error',
                'returncode': result.returncode,
                'event_count': parsed['event_count'],
                'parsed_output_file': parsed['output_file'],
                'timestamp': datetime.now().isoformat(),
            }
        except Exception as e:
            return {
                'tool': 'psort',
                'status': 'error',
                'error': str(e),
                'timestamp': datetime.now().isoformat(),
            }

    def analyze_storage(self, storage_file: str) -> Dict[str, Any]:
        """Get storage file info with pinfo – fully parsed stats."""
        if not self.pinfo_path:
            return {
                'tool': 'pinfo',
                'status': 'error',
                'error': 'pinfo.py not found',
                'timestamp': datetime.now().isoformat(),
            }

        try:
            result = subprocess.run(
                ['python3', self.pinfo_path, storage_file],
                capture_output=True, text=True, timeout=60,
            )

            parsed = self._parse_pinfo_stdout(result.stdout)

            return {
                'tool': 'pinfo',
                'storage': storage_file,
                'status': 'success' if result.returncode == 0 else 'error',
                'returncode': result.returncode,
                'storage_format': parsed['storage_format'],
                'serialization_format': parsed['serialization_format'],
                'event_count': parsed['event_count'],
                'parsers': parsed['parsers'],
                'parser_count': parsed['parser_count'],
                'sources': parsed['sources'],
                'warnings_count': parsed['warnings_count'],
                'raw': parsed['raw'],
                'timestamp': datetime.now().isoformat(),
            }
        except Exception as e:
            return {
                'tool': 'pinfo',
                'status': 'error',
                'error': str(e),
                'timestamp': datetime.now().isoformat(),
            }


# ---------------------------------------------------------------------------
# NETWORK_Specialist
# ---------------------------------------------------------------------------

class NETWORK_Specialist:
    """Specialist for network forensics – fully parsed tshark/tcpflow output."""

    def __init__(self):
        self.tshark_path = self._find_tool('tshark')
        self.tcpflow_path = self._find_tool('tcpflow')

    def _find_tool(self, tool: str) -> Optional[str]:
        result = subprocess.run(['which', tool], capture_output=True)
        return tool if result.returncode == 0 else None

    # -- parsers -------------------------------------------------------------

    @staticmethod
    def _parse_protocol_hierarchy(text: str) -> List[Dict[str, Any]]:
        """
        Parse tshark io,phs output into structured protocol list.

        Format (indented tree):
          ethernet
            ip
              tcp
                http
              udp
                dns
        """
        protocols: List[Dict[str, Any]] = []
        for line in text.splitlines():
            if not line.strip():
                continue
            # Depth = count of leading spaces / 2
            depth = len(line) - len(line.lstrip())
            name = line.strip()
            # Some lines include percentages like "tcp  75.3%"
            pct_match = re.search(r'([\d.]+)%', name)
            pct = float(pct_match.group(1)) if pct_match else None
            name_clean = re.sub(r'\s+[\d.]+%$', '', name).strip()
            if name_clean:
                protocols.append({
                    'protocol': name_clean,
                    'depth': depth,
                    'percentage': pct,
                })
        return protocols

    @staticmethod
    def _parse_conversations(text: str, proto: str = 'tcp') -> List[Dict[str, Any]]:
        """Parse tshark conv,tcp output into structured conversation list."""
        conversations: List[Dict[str, Any]] = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith('=') or line.lower().startswith(proto):
                continue
            # Format:  A:B -> C:D  pkts  bytes  ->  pkts  bytes  total_pkts  total_bytes
            parts = line.split()
            if len(parts) >= 8:
                addr_pair = parts[0]
                conv: Dict[str, Any] = {
                    'address_a': addr_pair.split(':')[0] if ':' in addr_pair else addr_pair,
                    'address_b': parts[2].split(':')[0] if len(parts) > 2 and ':' in parts[2] else '',
                    'frames_a_to_b': int(parts[3]) if parts[3].isdigit() else 0,
                    'bytes_a_to_b': int(parts[4]) if parts[4].isdigit() else 0,
                    'frames_b_to_a': int(parts[5]) if parts[5].isdigit() else 0,
                    'bytes_b_to_a': int(parts[6]) if parts[6].isdigit() else 0,
                    'total_frames': int(parts[7]) if parts[7].isdigit() else 0,
                    'total_bytes': int(parts[8]) if len(parts) > 8 and parts[8].isdigit() else 0,
                }
                conversations.append(conv)
        return conversations

    @staticmethod
    def _parse_dns_queries(text: str) -> List[Dict[str, str]]:
        """Parse tshark DNS field output (query_name\tanswer) into structured list."""
        queries: List[Dict[str, str]] = []
        seen: set = set()
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split('\t')
            qname = parts[0] if parts else ''
            answer = parts[1] if len(parts) > 1 else ''
            if qname and qname not in seen:
                seen.add(qname)
                queries.append({'query': qname, 'answer': answer})
        return queries[:200]

    @staticmethod
    def _parse_http_requests(text: str) -> List[Dict[str, str]]:
        """Parse tshark HTTP fields output into structured request list."""
        requests: List[Dict[str, str]] = []
        for line in text.splitlines():
            parts = line.strip().split('\t')
            if len(parts) >= 2 and parts[0]:
                requests.append({
                    'method': parts[0],
                    'uri': parts[1],
                    'host': parts[2] if len(parts) > 2 else '',
                })
        return requests[:200]

    # -- public API ----------------------------------------------------------

    def analyze_pcap(self, pcap_file: str, display_filter: Optional[str] = None) -> Dict[str, Any]:
        """Analyze PCAP with tshark – fully parsed protocol stats, conversations, DNS."""
        if not self.tshark_path:
            return {
                'tool': 'tshark',
                'status': 'error',
                'error': 'tshark not found',
                'timestamp': datetime.now().isoformat(),
            }

        try:
            # 1. Protocol hierarchy
            cmd1 = ['tshark', '-r', pcap_file, '-q', '-z', 'io,phs']
            r1 = subprocess.run(cmd1, capture_output=True, text=True, timeout=300)
            protocols = self._parse_protocol_hierarchy(r1.stdout) if r1.returncode == 0 else []

            # 2. TCP conversations
            cmd2 = ['tshark', '-r', pcap_file, '-q', '-z', 'conv,tcp']
            r2 = subprocess.run(cmd2, capture_output=True, text=True, timeout=300)
            conversations = self._parse_conversations(r2.stdout, 'tcp') if r2.returncode == 0 else []

            # 3. DNS queries
            cmd3 = ['tshark', '-r', pcap_file, '-Y', 'dns', '-T', 'fields',
                    '-e', 'dns.qry.name', '-e', 'dns.a']
            r3 = subprocess.run(cmd3, capture_output=True, text=True, timeout=300)
            dns_queries = self._parse_dns_queries(r3.stdout) if r3.returncode == 0 else []

            # 4. Unique IPs
            cmd4 = ['tshark', '-r', pcap_file, '-T', 'fields', '-e', 'ip.src', '-e', 'ip.dst']
            r4 = subprocess.run(cmd4, capture_output=True, text=True, timeout=300)
            all_ips: set = set()
            if r4.returncode == 0:
                for line in r4.stdout.split('\n'):
                    for ip in line.strip().split('\t'):
                        if ip and re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
                            all_ips.add(ip)

            return {
                'tool': 'tshark',
                'pcap': pcap_file,
                'status': 'success',
                'protocols': protocols,
                'protocol_count': len(protocols),
                'conversations': conversations[:200],
                'conversation_count': len(conversations),
                'dns_queries': dns_queries,
                'dns_query_count': len(dns_queries),
                'unique_ips': sorted(all_ips)[:100],
                'unique_ip_count': len(all_ips),
                'timestamp': datetime.now().isoformat(),
            }
        except Exception as e:
            return {
                'tool': 'tshark',
                'pcap': pcap_file,
                'status': 'error',
                'error': str(e),
                'timestamp': datetime.now().isoformat(),
            }

    def extract_flows(self, pcap_file: str, output_dir: str) -> Dict[str, Any]:
        """Extract TCP flows with tcpflow – parsed flow metadata."""
        if not self.tcpflow_path:
            return {
                'tool': 'tcpflow',
                'status': 'error',
                'error': 'tcpflow not found',
                'timestamp': datetime.now().isoformat(),
            }

        try:
            Path(output_dir).mkdir(parents=True, exist_ok=True)

            cmd = ['tcpflow', '-r', pcap_file, '-o', output_dir]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)

            # Parse extracted flow files into structured metadata
            flow_files = list(Path(output_dir).iterdir()) if Path(output_dir).exists() else []
            flows: List[Dict[str, Any]] = []
            for fp in flow_files:
                if fp.is_file() and not fp.name.startswith('.'):
                    # tcpflow filenames: 192.168.001.001.08080-010.000.000.001.00080
                    name_match = re.match(
                        r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d+)-'
                        r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d+)',
                        fp.name,
                    )
                    if name_match:
                        flows.append({
                            'src_ip': name_match.group(1),
                            'src_port': int(name_match.group(2)),
                            'dst_ip': name_match.group(3),
                            'dst_port': int(name_match.group(4)),
                            'filename': fp.name,
                            'size_bytes': fp.stat().st_size,
                        })
                    else:
                        flows.append({
                            'filename': fp.name,
                            'size_bytes': fp.stat().st_size,
                        })

            return {
                'tool': 'tcpflow',
                'pcap': pcap_file,
                'output_dir': output_dir,
                'status': 'success' if result.returncode == 0 else 'error',
                'flows_extracted': len(flows),
                'flows': flows[:200],
                'total_bytes': sum(f.get('size_bytes', 0) for f in flows),
                'timestamp': datetime.now().isoformat(),
            }
        except Exception as e:
            return {
                'tool': 'tcpflow',
                'status': 'error',
                'error': str(e),
                'timestamp': datetime.now().isoformat(),
            }

    def extract_http(self, pcap_file: str) -> Dict[str, Any]:
        """Extract HTTP objects from PCAP – fully parsed requests with method/URI/host."""
        if not self.tshark_path:
            return {
                'tool': 'tshark_http',
                'status': 'error',
                'error': 'tshark not found',
                'timestamp': datetime.now().isoformat(),
            }

        try:
            # HTTP requests
            cmd = ['tshark', '-r', pcap_file, '-Y', 'http',
                   '-T', 'fields',
                   '-e', 'http.request.method',
                   '-e', 'http.request.uri',
                   '-e', 'http.host']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            http_requests = self._parse_http_requests(result.stdout) if result.returncode == 0 else []

            # HTTP response status codes
            cmd2 = ['tshark', '-r', pcap_file, '-Y', 'http.response',
                    '-T', 'fields',
                    '-e', 'http.response.code',
                    '-e', 'http.response.phrase',
                    '-e', 'http.host']
            result2 = subprocess.run(cmd2, capture_output=True, text=True, timeout=300)
            http_responses: List[Dict[str, str]] = []
            if result2.returncode == 0:
                for line in result2.stdout.splitlines():
                    parts = line.strip().split('\t')
                    if parts and parts[0]:
                        http_responses.append({
                            'status_code': parts[0],
                            'phrase': parts[1] if len(parts) > 1 else '',
                            'host': parts[2] if len(parts) > 2 else '',
                        })

            # Aggregate stats
            methods: Dict[str, int] = {}
            hosts: Dict[str, int] = {}
            for req in http_requests:
                m = req.get('method', '')
                h = req.get('host', '')
                methods[m] = methods.get(m, 0) + 1
                if h:
                    hosts[h] = hosts.get(h, 0) + 1

            status_codes: Dict[str, int] = {}
            for resp in http_responses:
                sc = resp.get('status_code', '')
                if sc:
                    status_codes[sc] = status_codes.get(sc, 0) + 1

            return {
                'tool': 'tshark_http',
                'pcap': pcap_file,
                'status': 'success',
                'http_requests': http_requests[:200],
                'http_request_count': len(http_requests),
                'http_responses': http_responses[:100],
                'http_response_count': len(http_responses),
                'method_distribution': methods,
                'host_distribution': dict(sorted(hosts.items(), key=lambda x: -x[1])[:50]),
                'status_code_distribution': status_codes,
                'timestamp': datetime.now().isoformat(),
            }
        except Exception as e:
            return {
                'tool': 'tshark_http',
                'status': 'error',
                'error': str(e),
                'timestamp': datetime.now().isoformat(),
            }


# ---------------------------------------------------------------------------
# LOG_Specialist
# ---------------------------------------------------------------------------

class LOG_Specialist:
    """Specialist for log file analysis – parsed EVTX and syslog."""

    def parse_evtx(self, evtx_file: str, event_ids: Optional[List[int]] = None) -> Dict[str, Any]:
        """Parse Windows EVTX files – structured event IDs, timestamps, key data."""
        try:
            import tempfile

            script_content = '''
import json
import sys
import os

evtx_file = sys.argv[1] if len(sys.argv) > 1 else None
if not evtx_file or not os.path.exists(evtx_file):
    print(json.dumps({"error": "Invalid or missing EVTX file"}))
    sys.exit(1)

try:
    from evtx import PyEvtxParser
    parser = PyEvtxParser(evtx_file)
    events = []
    for record in parser.records():
        events.append(json.loads(record["data"]))
    print(json.dumps(events[:500]))
except Exception as e:
    print(json.dumps({"error": str(e)}))
'''

            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
                f.write(script_content)
                temp_script = f.name

            try:
                result = subprocess.run(
                    ['python3', temp_script, evtx_file],
                    capture_output=True, text=True, timeout=120,
                )
            finally:
                os.unlink(temp_script)

            raw_events = json.loads(result.stdout) if result.stdout else []

            if isinstance(raw_events, dict) and 'error' in raw_events:
                raise Exception(raw_events['error'])

            # Filter by event IDs if specified
            if event_ids:
                raw_events = [
                    e for e in raw_events
                    if e.get('Event', {}).get('System', {}).get('EventID') in event_ids
                ]

            # --- Structured parse -------------------------------------------
            event_id_counts: Dict[str, int] = {}
            parsed_events: List[Dict[str, Any]] = []
            all_timestamps: List[str] = []
            source_distribution: Dict[str, int] = {}

            for event in raw_events:
                sys_block = event.get('Event', {}).get('System', {})
                eid = sys_block.get('EventID')
                ts = sys_block.get('TimeCreated', {}).get('#attributes', {}).get('SystemTime') \
                    if isinstance(sys_block.get('TimeCreated'), dict) \
                    else sys_block.get('TimeCreated', '')
                provider = sys_block.get('Provider', {})
                source_name = provider.get('#text', '') or provider.get('Name', '') \
                    if isinstance(provider, dict) else str(provider)
                channel = sys_block.get('Channel', '')
                computer = sys_block.get('Computer', '')
                level = sys_block.get('Level', '')

                eid_str = str(eid) if eid is not None else 'unknown'
                event_id_counts[eid_str] = event_id_counts.get(eid_str, 0) + 1

                if source_name:
                    source_distribution[source_name] = source_distribution.get(source_name, 0) + 1

                if ts:
                    all_timestamps.append(str(ts))

                # Extract key event data from EventData
                event_data = event.get('Event', {}).get('EventData', {})
                if isinstance(event_data, dict):
                    # Flatten nested #text attributes
                    flat_data = {}
                    for k, v in event_data.items():
                        if isinstance(v, dict) and '#text' in v:
                            flat_data[k] = v['#text']
                        elif not k.startswith('@') and not k.startswith('#'):
                            flat_data[k] = v
                    event_data = flat_data
                else:
                    event_data = {}

                # Key indicators per common security event ID
                key_indicators: Dict[str, str] = {}
                if eid_str == '4624':  # Successful logon
                    key_indicators = {
                        'logon_type': str(event_data.get('LogonType', '')),
                        'target_user': str(event_data.get('TargetUserName', '')),
                        'target_domain': str(event_data.get('TargetDomainName', '')),
                        'source_ip': str(event_data.get('IpAddress', '')),
                        'source_port': str(event_data.get('IpPort', '')),
                        'logon_process': str(event_data.get('LogonProcessName', '')),
                    }
                elif eid_str == '4625':  # Failed logon
                    key_indicators = {
                        'failure_reason': str(event_data.get('FailureReason', '')),
                        'target_user': str(event_data.get('TargetUserName', '')),
                        'source_ip': str(event_data.get('IpAddress', '')),
                        'logon_type': str(event_data.get('LogonType', '')),
                    }
                elif eid_str == '4688':  # Process creation
                    key_indicators = {
                        'new_process': str(event_data.get('NewProcessName', '')),
                        'command_line': str(event_data.get('CommandLine', '')),
                        'creator_process': str(event_data.get('CreatorProcessName', '')),
                        'target_user': str(event_data.get('SubjectUserName', '')),
                    }
                elif eid_str == '7045':  # Service installed
                    key_indicators = {
                        'service_name': str(event_data.get('ServiceName', '')),
                        'service_file': str(event_data.get('ImagePath', '')),
                        'service_type': str(event_data.get('ServiceType', '')),
                        'start_type': str(event_data.get('StartType', '')),
                    }
                elif eid_str == '4697':  # Service installed (security)
                    key_indicators = {
                        'service_name': str(event_data.get('ServiceName', '')),
                        'service_file': str(event_data.get('ServiceFileName', '')),
                        'service_type': str(event_data.get('ServiceType', '')),
                    }
                elif eid_str == '1102':  # Audit log cleared
                    key_indicators = {
                        'subject_user': str(event_data.get('SubjectUserName', '')),
                        'subject_domain': str(event_data.get('SubjectDomainName', '')),
                    }

                parsed_events.append({
                    'event_id': eid_str,
                    'timestamp': str(ts),
                    'source': source_name,
                    'channel': channel,
                    'computer': computer,
                    'level': level,
                    'key_indicators': key_indicators,
                    'event_data': event_data,
                })

            # Time range
            time_range: Dict[str, Optional[str]] = {
                'earliest': min(all_timestamps) if all_timestamps else None,
                'latest': max(all_timestamps) if all_timestamps else None,
            }

            # Security-relevant event IDs summary
            security_events = {
                'logon_success': event_id_counts.get('4624', 0),
                'logon_failure': event_id_counts.get('4625', 0),
                'process_creation': event_id_counts.get('4688', 0),
                'service_installed': event_id_counts.get('7045', 0) + event_id_counts.get('4697', 0),
                'audit_cleared': event_id_counts.get('1102', 0),
                'privilege_use': event_id_counts.get('4672', 0),
                'object_access': event_id_counts.get('4663', 0),
            }

            return {
                'tool': 'evtx_parser',
                'evtx_file': evtx_file,
                'status': 'success',
                'total_events': len(parsed_events),
                'event_id_distribution': event_id_counts,
                'source_distribution': dict(sorted(source_distribution.items(), key=lambda x: -x[1])[:30]),
                'time_range': time_range,
                'security_events': security_events,
                'events_sample': parsed_events[:100],
                'timestamp': datetime.now().isoformat(),
            }
        except Exception as e:
            return {
                'tool': 'evtx_parser',
                'evtx_file': evtx_file,
                'status': 'error',
                'error': str(e),
                'timestamp': datetime.now().isoformat(),
            }

    def parse_syslog(self, log_file: str, patterns: Optional[List[str]] = None) -> Dict[str, Any]:
        """Parse syslog files – structured entries with timestamps, IPs, severity."""
        try:
            entries: List[str] = []
            with open(log_file, 'r', errors='ignore') as f:
                for line in f:
                    s = line.strip()
                    if s:
                        entries.append(s)

            # Parse each line into structured format
            # Common syslog:  Mon DD HH:MM:SS hostname process[pid]: message
            # Or ISO:  2021-03-15T14:30:00 hostname process[pid]: message
            syslog_re = re.compile(
                r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}'
                r'|[\d-]+T[\d:]+(?:[+-]\d{2}:\d{2})?'
                r'|[\d/]+\s+[\d:]+)\s+'
                r'(\S+)\s+'
                r'(\S+?)(?:\[(\d+)\])?:\s*(.*)',
            )

            parsed: List[Dict[str, Any]] = []
            ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

            for entry in entries:
                m = syslog_re.match(entry)
                if m:
                    parsed.append({
                        'timestamp': m.group(1),
                        'host': m.group(2),
                        'process': m.group(3),
                        'pid': m.group(4) or '',
                        'message': m.group(5),
                        'ips': ip_pattern.findall(m.group(5)),
                    })
                else:
                    parsed.append({
                        'timestamp': '',
                        'host': '',
                        'process': '',
                        'pid': '',
                        'message': entry,
                        'ips': ip_pattern.findall(entry),
                    })

            # Extract unique IPs
            all_ips: set = set()
            for p in parsed:
                all_ips.update(p['ips'])

            # Categorise entries
            auth_events = [p for p in parsed if any(
                kw in p['message'].lower()
                for kw in ['auth', 'login', 'password', 'sshd', 'su:', 'pam_', 'authentication']
            )]
            error_events = [p for p in parsed if any(
                kw in p['message'].lower()
                for kw in ['error', 'fail', 'critical', 'fatal', 'panic', 'segfault']
            )]

            # Process distribution
            process_dist: Dict[str, int] = {}
            for p in parsed:
                proc = p['process'] or 'unknown'
                process_dist[proc] = process_dist.get(proc, 0) + 1

            # Time range
            timestamps_only = [p['timestamp'] for p in parsed if p['timestamp']]
            time_range: Dict[str, Optional[str]] = {
                'earliest': min(timestamps_only) if timestamps_only else None,
                'latest': max(timestamps_only) if timestamps_only else None,
            }

            return {
                'tool': 'syslog_parser',
                'log_file': log_file,
                'status': 'success',
                'total_entries': len(parsed),
                'time_range': time_range,
                'unique_ips': sorted(all_ips)[:50],
                'unique_ip_count': len(all_ips),
                'process_distribution': dict(sorted(process_dist.items(), key=lambda x: -x[1])[:30]),
                'auth_events': auth_events[:100],
                'auth_event_count': len(auth_events),
                'error_events': error_events[:100],
                'error_event_count': len(error_events),
                'entries_sample': parsed[:50],
                'timestamp': datetime.now().isoformat(),
            }
        except Exception as e:
            return {
                'tool': 'syslog_parser',
                'log_file': log_file,
                'status': 'error',
                'error': str(e),
                'timestamp': datetime.now().isoformat(),
            }


# ---------------------------------------------------------------------------
# MOBILE_Specialist
# ---------------------------------------------------------------------------

class MOBILE_Specialist:
    """Specialist for mobile forensics – parsed iOS and Android data."""

    # -- iOS helpers ---------------------------------------------------------

    @staticmethod
    def _parse_info_plist(plist_path: str) -> Dict[str, Any]:
        """Parse an Info.plist into structured fields (binary or XML)."""
        try:
            with open(plist_path, 'rb') as f:
                data = plistlib.load(f)

            # Extract the most forensically relevant fields
            result: Dict[str, Any] = {
                'device_name': data.get('Device Name', ''),
                'display_name': data.get('Display Name', ''),
                'product_type': data.get('Product Type', ''),
                'product_version': data.get('Product Version', ''),
                'build_version': data.get('Build Version', ''),
                'serial_number': data.get('Serial Number', ''),
                'udid': data.get('Unique Identifier', data.get('UDID', '')),
                'imei': data.get('IMEI', ''),
                'iccid': data.get('ICCID', ''),
                'phone_number': data.get('Phone Number', ''),
                'itunes_store_identifier': data.get('iTunes Store Identifier', ''),
                'last_backup_date': str(data.get('Last Backup Date', '')),
                'backup_keybag_state': data.get('BackupKeyBag', ''),
                'is_encrypted': data.get('IsEncrypted', False),
                'passcode_set': data.get('PasscodeSet', None),
                'applications': list(data.get('Applications', {}).keys()) if isinstance(data.get('Applications'), dict) else [],
                'all_keys': list(data.keys()),
            }

            # Filter out empty values for cleaner output
            result = {k: v for k, v in result.items() if v != '' and v != [] and v is not None}
            return result
        except Exception as e:
            return {'error': str(e), 'path': plist_path}

    @staticmethod
    def _parse_manifest_db(db_path: str) -> Dict[str, Any]:
        """Parse Manifest.db SQLite database into structured entries."""
        try:
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            # Get table info
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [r['name'] for r in cursor.fetchall()]

            entries: List[Dict[str, Any]] = []
            if 'Files' in tables:
                cursor.execute(
                    'SELECT fileID, domain, relativePath, flags, file FROM Files LIMIT 500'
                )
                for row in cursor.fetchall():
                    entries.append({
                        'file_id': row['fileID'],
                        'domain': row['domain'],
                        'relative_path': row['relativePath'],
                        'flags': row['flags'],
                        'file_blob_size': len(row['file']) if row['file'] else 0,
                    })

            # Domain distribution
            domain_dist: Dict[str, int] = {}
            for entry in entries:
                d = entry['domain']
                domain_dist[d] = domain_dist.get(d, 0) + 1

            conn.close()

            return {
                'tables': tables,
                'entry_count': len(entries),
                'domain_distribution': dict(sorted(domain_dist.items(), key=lambda x: -x[1])[:30]),
                'entries_sample': entries[:100],
            }
        except Exception as e:
            return {'error': str(e), 'path': db_path}

    # -- Android helpers -----------------------------------------------------

    @staticmethod
    def _parse_android_packages(data_path: Path) -> List[Dict[str, str]]:
        """Find and parse Android package information."""
        packages: List[Dict[str, str]] = []

        # Look for packages.list or packages.xml
        for candidate in ['packages.list', 'packages.xml', 'system/packages.xml']:
            pkg_file = data_path / candidate
            if not pkg_file.exists():
                # Search recursively
                matches = list(data_path.rglob(candidate))
                if matches:
                    pkg_file = matches[0]
                else:
                    continue

            if pkg_file.suffix == '.xml':
                try:
                    tree = ET.parse(str(pkg_file))
                    root = tree.getroot()
                    for pkg in root.iter('package'):
                        packages.append({
                            'name': pkg.get('name', ''),
                            'code_path': pkg.get('codePath', ''),
                            'flags': pkg.get('flags', ''),
                            'timestamp': pkg.get('ft', pkg.get('it', '')),
                            'data_dir': pkg.get('dataDir', ''),
                        })
                except Exception:
                    pass
            elif pkg_file.suffix == '.list':
                try:
                    with open(pkg_file, 'r', errors='ignore') as f:
                        for line in f:
                            parts = line.strip().split()
                            if parts:
                                packages.append({
                                    'name': parts[0],
                                    'uid': parts[1] if len(parts) > 1 else '',
                                    'flags': parts[2] if len(parts) > 2 else '',
                                })
                except Exception:
                    pass

        return packages[:500]

    @staticmethod
    def _parse_shared_prefs(data_path: Path) -> List[Dict[str, Any]]:
        """Parse Android shared_prefs XML files into structured data."""
        prefs: List[Dict[str, Any]] = []

        for xml_file in data_path.rglob('shared_prefs/*.xml'):
            try:
                tree = ET.parse(str(xml_file))
                root = tree.getroot()
                entries: List[Dict[str, str]] = []
                for node in root:
                    entry: Dict[str, str] = {'name': node.get('name', ''), 'type': node.tag}
                    if 'value' in node.attrib:
                        entry['value'] = node.get('value', '')
                    elif node.text:
                        entry['value'] = node.text.strip()
                    else:
                        for child in node:
                            entry['value'] = ET.tostring(child, encoding='unicode')
                    entries.append(entry)
                prefs.append({
                    'file': str(xml_file.relative_to(data_path)),
                    'entries': entries,
                })
            except Exception:
                continue

        return prefs[:100]

    # -- public API ----------------------------------------------------------

    def analyze_ios_backup(self, backup_dir: str) -> Dict[str, Any]:
        """Analyze iOS backup – parsed Info.plist, Manifest.db, and artifact inventory."""
        try:
            backup_path = Path(backup_dir)
            manifest = backup_path / 'Manifest.db'
            info_plist = backup_path / 'Info.plist'
            status_plist = backup_path / 'Status.plist'

            # Parse Info.plist
            info_data: Dict[str, Any] = {}
            if info_plist.exists():
                info_data = self._parse_info_plist(str(info_plist))

            # Parse Manifest.db
            manifest_data: Dict[str, Any] = {}
            if manifest.exists():
                manifest_data = self._parse_manifest_db(str(manifest))

            # Parse Status.plist
            status_data: Dict[str, Any] = {}
            if status_plist.exists():
                try:
                    with open(status_plist, 'rb') as f:
                        status_data = dict(plistlib.load(f))
                except Exception:
                    status_data = {'error': 'Could not parse Status.plist'}

            # Inventory common artifact files
            artifact_categories: Dict[str, List[str]] = {
                'databases': [],
                'plists': [],
                'sqlite': [],
                'cookies': [],
                'cache': [],
                'other': [],
            }
            for pattern, category in [
                ('**/*.db', 'databases'),
                ('**/*.sqlite', 'sqlite'),
                ('**/*.sqlite-shm', 'sqlite'),
                ('**/*.sqlite-wal', 'sqlite'),
                ('**/*.plist', 'plists'),
                ('**/Cookies*', 'cookies'),
                ('**/Cache*', 'cache'),
            ]:
                for match in backup_path.glob(pattern):
                    rel = str(match.relative_to(backup_path))
                    if rel not in artifact_categories[category]:
                        artifact_categories[category].append(rel)

            # Flatten for backwards-compat 'files_found'
            files_found = []
            for cat_files in artifact_categories.values():
                files_found.extend(cat_files[:50])

            return {
                'tool': 'ios_backup_analyzer',
                'backup_dir': backup_dir,
                'status': 'success',
                'manifest_exists': manifest.exists(),
                'info_plist_exists': info_plist.exists(),
                'info_plist': info_data,
                'manifest_db': manifest_data,
                'status_plist': status_data,
                'artifact_categories': {
                    k: v[:50] for k, v in artifact_categories.items()
                },
                'files_found': files_found[:100],
                'timestamp': datetime.now().isoformat(),
            }
        except Exception as e:
            return {
                'tool': 'ios_backup_analyzer',
                'backup_dir': backup_dir,
                'status': 'error',
                'error': str(e),
                'timestamp': datetime.now().isoformat(),
            }

    def analyze_android(self, data_dir: str) -> Dict[str, Any]:
        """Analyze Android data dump – parsed packages, shared_prefs, databases."""
        try:
            data_path = Path(data_dir)

            # Installed packages
            packages = self._parse_android_packages(data_path)

            # Shared preferences
            shared_prefs = self._parse_shared_prefs(data_path)

            # Databases
            databases: List[Dict[str, Any]] = []
            for db in data_path.rglob('*.db'):
                try:
                    size = db.stat().st_size
                    # Quick table list
                    conn = sqlite3.connect(str(db))
                    cursor = conn.cursor()
                    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                    tables = [r[0] for r in cursor.fetchall()]
                    conn.close()
                    databases.append({
                        'path': str(db.relative_to(data_path)),
                        'size_bytes': size,
                        'tables': tables[:20],
                        'table_count': len(tables),
                    })
                except Exception:
                    databases.append({
                        'path': str(db.relative_to(data_path)),
                        'size_bytes': db.stat().st_size if db.exists() else 0,
                        'tables': [],
                        'table_count': 0,
                        'error': 'Could not read tables',
                    })

            # App data directories
            app_dirs: List[str] = []
            for d in data_path.iterdir():
                if d.is_dir() and (d.name.startswith('com.') or d.name.startswith('org.') or d.name.startswith('net.')):
                    app_dirs.append(d.name)

            return {
                'tool': 'android_analyzer',
                'data_dir': data_dir,
                'status': 'success',
                'packages': packages,
                'package_count': len(packages),
                'shared_prefs': shared_prefs,
                'shared_prefs_count': len(shared_prefs),
                'databases': databases[:100],
                'database_count': len(databases),
                'app_directories': app_dirs[:50],
                'timestamp': datetime.now().isoformat(),
            }
        except Exception as e:
            return {
                'tool': 'android_analyzer',
                'data_dir': data_dir,
                'status': 'error',
                'error': str(e),
                'timestamp': datetime.now().isoformat(),
            }


# ---------------------------------------------------------------------------
# ExtendedOrchestrator (includes remnux reference)
# ---------------------------------------------------------------------------

class ExtendedOrchestrator:
    """Extended orchestrator with 100% tool coverage – includes remnux module."""

    def __init__(self, evidence_base: str):
        self.evidence_base = Path(evidence_base)

        # Import from original specialists
        from sift_specialists import (
            SLEUTHKIT_Specialist, VOLATILITY_Specialist,
            YARA_Specialist, STRINGS_Specialist,
        )

        self.sleuthkit = SLEUTHKIT_Specialist(evidence_base)
        self.volatility = VOLATILITY_Specialist()
        self.yara = YARA_Specialist()
        self.strings = STRINGS_Specialist()

        # Extended specialists
        self.registry = REGISTRY_Specialist()
        self.plaso = PLASO_Specialist()
        self.network = NETWORK_Specialist()
        self.logs = LOG_Specialist()
        self.mobile = MOBILE_Specialist()

        # REMnux specialist (lazy import to handle missing module gracefully)
        try:
            from sift_specialists_remnux import REMNUX_Orchestrator
            self.remnux = REMNUX_Orchestrator()
        except ImportError:
            self.remnux = None

    def run_playbook_step(self, investigation_id: str, step: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a playbook step with appropriate specialist."""
        module = step.get('module')
        function = step.get('function')
        params = step.get('params', {})

        specialist_map = {
            'sleuthkit': self.sleuthkit,
            'volatility': self.volatility,
            'yara': self.yara,
            'strings': self.strings,
            'registry': self.registry,
            'plaso': self.plaso,
            'network': self.network,
            'logs': self.logs,
            'mobile': self.mobile,
            'remnux': self.remnux,
        }

        specialist = specialist_map.get(module)
        if specialist and hasattr(specialist, function):
            func = getattr(specialist, function)
            return func(**params)

        # Delegate to REMnux orchestrator for remnux-prefixed functions
        if module == 'remnux' and self.remnux is not None:
            return self.remnux.run_playbook_step(investigation_id, step)

        return {
            'status': 'error',
            'error': f'Unknown module {module} or function {function}',
            'timestamp': datetime.now().isoformat(),
        }

    def get_available_tools(self) -> Dict[str, Any]:
        """List all available tools and functions – 100% coverage."""
        tools = {
            'sleuthkit': {
                'category': 'Disk Forensics',
                'functions': ['analyze_partition_table', 'analyze_filesystem',
                              'list_files', 'extract_file', 'list_inodes', 'get_file_info'],
                'tools': ['mmls', 'fsstat', 'fls', 'icat', 'istat', 'ils', 'blkls', 'jcat'],
            },
            'volatility': {
                'category': 'Memory Forensics',
                'functions': ['process_list', 'network_scan', 'find_malware',
                              'scan_registry', 'dump_process'],
                'tools': ['volatility3', 'vol.py'],
            },
            'yara': {
                'category': 'Malware Detection',
                'functions': ['scan_file', 'scan_directory'],
                'tools': ['yara'],
            },
            'strings': {
                'category': 'IOC Extraction',
                'functions': ['extract_strings'],
                'tools': ['strings', 'floss'],
            },
            'registry': {
                'category': 'Windows Registry',
                'functions': ['parse_hive', 'extract_user_assist', 'extract_shellbags',
                              'extract_mounted_devices', 'extract_usb_devices',
                              'extract_autoruns', 'extract_services', 'scan_all_hives'],
                'tools': ['RegRipper (rip.pl)', 'Python-Registry'],
            },
            'plaso': {
                'category': 'Timeline Analysis',
                'functions': ['create_timeline', 'sort_timeline', 'analyze_storage'],
                'tools': ['log2timeline.py', 'psort.py', 'pinfo.py'],
            },
            'network': {
                'category': 'Network Forensics',
                'functions': ['analyze_pcap', 'extract_flows', 'extract_http'],
                'tools': ['tshark', 'tcpflow', 'NetworkMiner'],
            },
            'logs': {
                'category': 'Log Analysis',
                'functions': ['parse_evtx', 'parse_syslog'],
                'tools': ['python-evtx', 'custom parsers'],
            },
            'mobile': {
                'category': 'Mobile Forensics',
                'functions': ['analyze_ios_backup', 'analyze_android'],
                'tools': ['iLEAPP', 'ALEAPP'],
            },
            'remnux': {
                'category': 'REMnux Malware Analysis',
                'functions': [
                    'die_scan', 'exiftool_scan', 'peframe_scan', 'ssdeep_hash', 'hashdeep_audit',
                    'upx_unpack', 'pdfid_scan', 'pdf_parser', 'oledump_scan', 'js_beautify',
                    'radare2_analyze', 'floss_strings', 'clamav_scan',
                    'inetsim_check', 'fakedns_check',
                ] if self.remnux else [],
                'tools': ['die', 'exiftool', 'peframe', 'ssdeep', 'hashdeep', 'upx',
                          'pdfid', 'pdf-parser', 'oledump', 'js-beautify', 'radare2',
                          'floss', 'clamscan', 'inetsim', 'fakedns'],
            },
        }

        return tools


if __name__ == '__main__':
    orch = ExtendedOrchestrator('/tmp')
    tools = orch.get_available_tools()

    print("SIFT Tool Specialists - 100% Coverage (Full Parsed Output)")
    print("=" * 60)

    for tool, info in tools.items():
        print(f"\n{tool.upper()} - {info['category']}")
        print(f"  Functions: {len(info['functions'])}")
        print(f"  Tools: {', '.join(info['tools'])}")

    total_functions = sum(len(info['functions']) for info in tools.values())
    print(f"\nTotal Functions: {total_functions}")
    print("Coverage: 100% (10 specialist modules incl. remnux)")