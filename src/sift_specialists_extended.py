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
import shlex
import shutil
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
        if not line or line.startswith('#') or line.startswith('---'):
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


    def extract_sam_users(self, sam_path: str) -> Dict[str, Any]:
        """Extract user accounts from SAM hive with SIDs, last logon, and account types."""
        meta, raw = self._run_regripper(sam_path, 'sam')
        users = []
        current_user = {}
        for line in raw.split('\n'):
            line = line.strip()
            if line.startswith('Username:') or line.startswith('User Name:'):
                if current_user.get('username'):
                    users.append(current_user)
                current_user = {'username': line.split(':', 1)[1].strip()}
            elif 'SID:' in line and ':' in line:
                current_user['sid'] = line.split(':', 1)[1].strip()
            elif 'Last Logon:' in line and ':' in line:
                current_user['last_logon'] = line.split(':', 1)[1].strip()
            elif 'Account Type:' in line and ':' in line:
                current_user['type'] = line.split(':', 1)[1].strip()
            elif 'Enabled' in line and ':' in line:
                current_user['enabled'] = 'yes' in line.lower() or 'true' in line.lower()
        if current_user.get('username'):
            users.append(current_user)
        return {
            'tool': 'sam_users',
            'sam_path': sam_path,
            'status': 'success' if users else 'error',
            'users': users,
            'user_count': len(users),
            'timestamp': datetime.now().isoformat(),
        }

    def extract_domain_accounts(self, system_path: str, software_path: str = None) -> Dict[str, Any]:
        """Extract domain-joined accounts and cached credentials info from SYSTEM/SECURITY."""
        meta_sys, raw_sys = self._run_regripper(system_path, 'compname')
        computer_name = None
        domain_name = None
        for line in raw_sys.split('\n'):
            if 'ComputerName:' in line:
                computer_name = line.split(':', 1)[1].strip()
            if 'Domain:' in line or 'Workgroup:' in line:
                domain_name = line.split(':', 1)[1].strip()
        return {
            'tool': 'domain_accounts',
            'system_path': system_path,
            'status': 'success',
            'computer_name': computer_name,
            'domain': domain_name,
            'is_domain_joined': domain_name is not None and domain_name.lower() not in ['workgroup', ''],
            'timestamp': datetime.now().isoformat(),
        }

    def extract_sticky_notes(self, user_data_path: str) -> Dict[str, Any]:
        """Extract Sticky Notes content from Windows Plum.sqlite database."""
        plum_path = Path(user_data_path) / 'AppData' / 'Local' / 'Packages' / 'Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe' / 'LocalState' / 'Plum.sqlite'
        if not plum_path.exists():
            return {'tool': 'sticky_notes', 'status': 'error', 'error': 'Plum.sqlite not found', 'timestamp': datetime.now().isoformat()}
        sql = "SELECT Text FROM Note ORDER BY UpdatedAt DESC"
        rows = self._query_sqlite(str(plum_path), sql)
        notes = [r.get('Text', '') for r in rows if r.get('Text')]
        return {
            'tool': 'sticky_notes',
            'db_path': str(plum_path),
            'status': 'success',
            'notes': notes[:50],
            'note_count': len(notes),
            'timestamp': datetime.now().isoformat(),
        }

    def extract_windows_credentials(self, vault_path: str) -> Dict[str, Any]:
        """Extract Windows Credential Manager vault entries (metadata only)."""
        meta, raw = self._run_regripper(vault_path, 'credvault') if Path(self.regripper_path).exists() else ({'status': 'error'}, '')
        credentials = []
        for line in raw.split('\n'):
            if 'Target:' in line or 'User:' in line or 'Server:' in line:
                credentials.append(line.strip())
        return {
            'tool': 'windows_credentials',
            'vault_path': vault_path,
            'status': 'success' if credentials else 'error',
            'credentials_found': len(credentials),
            'sample': credentials[:10],
            'timestamp': datetime.now().isoformat(),
        }
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

            system_python = '/usr/bin/python3'

            # Try multiple command variants for different plaso versions
            # 2024+:  log2timeline.py --storage_file OUTPUT SOURCE
            # 2023:   log2timeline.py --status_view none OUTPUT SOURCE
            # Older:  log2timeline.py OUTPUT SOURCE
            variants = [
                [system_python, self.log2timeline_path, '--storage_file', output_file, evidence_path],
                [system_python, self.log2timeline_path, '--status_view', 'none', output_file, evidence_path],
                [system_python, self.log2timeline_path, output_file, evidence_path],
                [self.log2timeline_path, '--storage_file', output_file, evidence_path],
                [self.log2timeline_path, output_file, evidence_path],
            ]

            result = None
            for cmd in variants:
                try:
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
                    if result.returncode == 0:
                        break
                    # If it's an arg error, try next variant
                    if 'unrecognized arguments' in result.stderr or 'unrecognized option' in result.stderr:
                        continue
                    # If it's a ModuleNotFoundError, try direct script
                    if 'ModuleNotFoundError' in result.stderr and cmd[0] == system_python:
                        continue
                    # Other error — stop trying
                    break
                except Exception:
                    continue

            if result is None:
                return {
                    'tool': 'log2timeline',
                    'status': 'error',
                    'error': 'All log2timeline command variants failed',
                    'timestamp': datetime.now().isoformat(),
                }

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

            cmd = ['/usr/bin/python3', self.psort_path, '-o', output_format, '-w', output_file]
            if filter_str:
                cmd.extend(['--slice', filter_str])
            cmd.append(storage_file)

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)

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
                ['/usr/bin/python3', self.pinfo_path, storage_file],
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


    def extract_linux_users(self, passwd_path: str, shadow_path: str = None) -> Dict[str, Any]:
        """Extract user accounts from /etc/passwd and /etc/shadow files."""
        users = []
        try:
            with open(passwd_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    parts = line.split(':')
                    if len(parts) >= 7:
                        users.append({
                            'username': parts[0],
                            'uid': parts[2],
                            'gid': parts[3],
                            'home_dir': parts[5],
                            'shell': parts[6],
                            'gecos': parts[4] if len(parts) > 4 else '',
                        })
        except Exception as e:
            return {'tool': 'linux_users', 'status': 'error', 'error': str(e), 'timestamp': datetime.now().isoformat()}
        
        # Parse shadow for password status (if available)
        shadow_info = {}
        if shadow_path and Path(shadow_path).exists():
            try:
                with open(shadow_path, 'r') as f:
                    for line in f:
                        parts = line.strip().split(':')
                        if len(parts) >= 2:
                            shadow_info[parts[0]] = {
                                'hash_present': parts[1] not in ['', '*', 'x', '!'],
                                'locked': parts[1].startswith('!') if parts[1] else False,
                            }
            except Exception:
                pass
        
        for u in users:
            u['password_status'] = shadow_info.get(u['username'], {}).get('hash_present', False)
            u['account_locked'] = shadow_info.get(u['username'], {}).get('locked', False)
        
        return {
            'tool': 'linux_users',
            'passwd_path': passwd_path,
            'status': 'success',
            'users': users,
            'user_count': len(users),
            'system_users': [u for u in users if int(u['uid']) < 1000],
            'regular_users': [u for u in users if int(u['uid']) >= 1000],
            'timestamp': datetime.now().isoformat(),
        }

    def extract_wtmp_logins(self, wtmp_path: str) -> Dict[str, Any]:
        """Extract login history from wtmp binary log (last -f style)."""
        try:
            result = subprocess.run(['last', '-f', wtmp_path], capture_output=True, text=True)
            logins = []
            users = set()
            hosts = set()
            for line in result.stdout.split('\n'):
                if 'wtmp begins' in line or not line.strip():
                    continue
                parts = line.split()
                if len(parts) >= 4:
                    username = parts[0]
                    users.add(username)
                    if len(parts) > 2 and parts[2] not in ['tty', ':0']:
                        hosts.add(parts[2])
                    logins.append({
                        'username': username,
                        'tty': parts[1] if len(parts) > 1 else '',
                        'host': parts[2] if len(parts) > 2 and not parts[2].startswith('tty') else 'local',
                        'login_time': ' '.join(parts[3:7]) if len(parts) > 6 else '',
                    })
            return {
                'tool': 'wtmp_logins',
                'wtmp_path': wtmp_path,
                'status': 'success' if logins else 'no_data',
                'login_count': len(logins),
                'unique_users': sorted(users),
                'remote_hosts': sorted(hosts)[:20],
                'recent_logins': logins[:50],
                'timestamp': datetime.now().isoformat(),
            }
        except Exception as e:
            return {'tool': 'wtmp_logins', 'status': 'error', 'error': str(e), 'timestamp': datetime.now().isoformat()}

    def extract_ssh_authorized_keys(self, auth_keys_path: str) -> Dict[str, Any]:
        """Extract SSH authorized keys with key types and fingerprints."""
        keys = []
        try:
            with open(auth_keys_path, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    parts = line.split()
                    if len(parts) >= 2:
                        key_type = parts[0]
                        key_b64 = parts[1]
                        comment = ' '.join(parts[2:]) if len(parts) > 2 else ''
                        keys.append({
                            'line': line_num,
                            'type': key_type,
                            'fingerprint': f"{key_b64[:16]}...{key_b64[-16:]}" if len(key_b64) > 32 else key_b64,
                            'comment': comment,
                        })
            return {
                'tool': 'ssh_authorized_keys',
                'path': auth_keys_path,
                'status': 'success',
                'keys': keys,
                'key_count': len(keys),
                'key_types': list(set(k['type'] for k in keys)),
                'timestamp': datetime.now().isoformat(),
            }
        except Exception as e:
            return {'tool': 'ssh_authorized_keys', 'status': 'error', 'error': str(e), 'timestamp': datetime.now().isoformat()}


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

            # Detect encryption early — check Info.plist IsEncrypted + manifest keys
            is_encrypted = False
            encrypted_msg = ''
            if isinstance(info_data, dict) and info_data.get('is_encrypted') is True:
                is_encrypted = True
                encrypted_msg = 'Backup keybag present in Info.plist — data is encrypted'
            elif manifest.exists():
                # Also check manifest flags: flags & 0x80000000 means encrypted in iOS
                try:
                    conn = sqlite3.connect(str(manifest))
                    cursor = conn.cursor()
                    cursor.execute("SELECT flags FROM Files LIMIT 10")
                    encrypted_count = 0
                    for row in cursor.fetchall():
                        if row['flags'] and (row['flags'] & 0x80000000):
                            encrypted_count += 1
                    if encrypted_count > 0:
                        is_encrypted = True
                        encrypted_msg = f'{encrypted_count} file(s) in manifest have encrypted flags (0x80000000)'
                    conn.close()
                except Exception:
                    pass

            # If encrypted, return early with clear status
            if is_encrypted:
                return {
                    'tool': 'ios_backup_analyzer',
                    'backup_dir': backup_dir,
                    'status': 'encrypted',
                    'is_encrypted': True,
                    'encrypted_message': encrypted_msg,
                    'info_plist': info_data,
                    'manifest_exists': manifest.exists(),
                    'message': 'Encrypted backup detected — extraction skipped. Provide decryption key or backup_password.',
                    'artifact_categories': {
                        k: v[:50] for k, v in artifact_categories.items()
                    },
                    'files_found': files_found[:100],
                    'timestamp': datetime.now().isoformat(),
                }

            return {
                'tool': 'ios_backup_analyzer',
                'backup_dir': backup_dir,
                'status': 'success',
                'is_encrypted': False,
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

    # -- iOS extended extraction ---------------------------------------------

    # Seconds between Unix epoch (1970-01-01) and Mac absolute time (2001-01-01)
    _MAC_EPOCH_OFFSET = 978307200

    @staticmethod
    def _get_ios_file_path(backup_path: Path, domain: str, relative_path: str) -> Optional[Path]:
        """Return the on-disk path for a file stored in an iOS backup via Manifest.db lookup."""
        manifest = backup_path / 'Manifest.db'
        if not manifest.exists():
            return None
        try:
            conn = sqlite3.connect(str(manifest))
            row = conn.execute(
                "SELECT fileID FROM Files WHERE domain=? AND relativePath=?",
                (domain, relative_path),
            ).fetchone()
            conn.close()
            if row:
                file_id = row[0]
                candidate = backup_path / file_id[:2] / file_id
                return candidate if candidate.exists() else None
        except Exception:
            pass
        return None

    def _mac_ts_to_iso(self, ts: Any) -> str:
        """Convert a Mac absolute timestamp (or nanosecond variant) to ISO-8601 string."""
        if not ts or ts <= 0:
            return ''
        try:
            t = float(ts)
            if t > 1e15:          # nanoseconds (iOS 11+)
                t = t / 1e9
            unix_ts = t + self._MAC_EPOCH_OFFSET
            return datetime.utcfromtimestamp(unix_ts).isoformat()
        except Exception:
            return ''

    def extract_ios_sms(self, backup_dir: str) -> Dict[str, Any]:
        """Extract SMS/iMessage conversations from iOS backup (sms.db)."""
        backup_path = Path(backup_dir)
        db_path = self._get_ios_file_path(backup_path, 'HomeDomain', 'Library/SMS/sms.db')
        if db_path is None:
            return {
                'tool': 'ios_sms', 'status': 'not_found',
                'message': 'sms.db not found in backup', 'backup_dir': backup_dir,
            }
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=5)
            conn.row_factory = sqlite3.Row
            messages = []
            try:
                rows = conn.execute("""
                    SELECT m.ROWID, m.text, m.date, m.is_from_me,
                           m.service, h.id AS handle
                    FROM message m
                    LEFT JOIN handle h ON m.handle_id = h.ROWID
                    ORDER BY m.date DESC LIMIT 500
                """).fetchall()
                for r in rows:
                    messages.append({
                        'rowid': r['ROWID'],
                        'text': r['text'] or '',
                        'timestamp': self._mac_ts_to_iso(r['date']),
                        'is_from_me': bool(r['is_from_me']),
                        'service': r['service'] or '',
                        'handle': r['handle'] or '',
                    })
            except Exception as inner:
                conn.close()
                return {'tool': 'ios_sms', 'status': 'error', 'error': str(inner),
                        'backup_dir': backup_dir}
            conn.close()
            return {
                'tool': 'ios_sms', 'status': 'success',
                'backup_dir': backup_dir,
                'message_count': len(messages),
                'messages': messages,
                'timestamp': datetime.now().isoformat(),
            }
        except Exception as e:
            return {'tool': 'ios_sms', 'status': 'error', 'error': str(e),
                    'backup_dir': backup_dir}

    def extract_ios_call_history(self, backup_dir: str) -> Dict[str, Any]:
        """Extract call history from iOS backup (CallHistory.storedata)."""
        backup_path = Path(backup_dir)
        db_path = self._get_ios_file_path(
            backup_path, 'HomeDomain', 'Library/CallHistoryDB/CallHistory.storedata'
        )
        if db_path is None:
            return {
                'tool': 'ios_calls', 'status': 'not_found',
                'message': 'CallHistory.storedata not found', 'backup_dir': backup_dir,
            }
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=5)
            conn.row_factory = sqlite3.Row
            calls = []
            try:
                rows = conn.execute("""
                    SELECT ZADDRESS, ZDURATION, ZDATE, ZCALLTYPE, ZORIGINATED,
                           ZREAD, ZNAME, ZCOUNTRYCODE, ZSERVICE_PROVIDER
                    FROM ZCALLRECORD
                    ORDER BY ZDATE DESC LIMIT 500
                """).fetchall()
                for r in rows:
                    calls.append({
                        'number': r['ZADDRESS'] or '',
                        'name': r['ZNAME'] or '',
                        'duration_sec': r['ZDURATION'] or 0,
                        'timestamp': self._mac_ts_to_iso(r['ZDATE']),
                        'call_type': r['ZCALLTYPE'],
                        'outgoing': bool(r['ZORIGINATED']),
                        'service': r['ZSERVICE_PROVIDER'] or '',
                        'country_code': r['ZCOUNTRYCODE'] or '',
                    })
            except Exception as inner:
                conn.close()
                return {'tool': 'ios_calls', 'status': 'error', 'error': str(inner),
                        'backup_dir': backup_dir}
            conn.close()
            return {
                'tool': 'ios_calls', 'status': 'success',
                'backup_dir': backup_dir,
                'call_count': len(calls),
                'calls': calls,
                'timestamp': datetime.now().isoformat(),
            }
        except Exception as e:
            return {'tool': 'ios_calls', 'status': 'error', 'error': str(e),
                    'backup_dir': backup_dir}

    def extract_ios_safari_history(self, backup_dir: str) -> Dict[str, Any]:
        """Extract Safari browsing history from iOS backup."""
        backup_path = Path(backup_dir)
        db_path = self._get_ios_file_path(
            backup_path, 'HomeDomain', 'Library/Safari/History.db'
        )
        if db_path is None:
            return {
                'tool': 'ios_safari', 'status': 'not_found',
                'message': 'Safari History.db not found', 'backup_dir': backup_dir,
            }
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=5)
            conn.row_factory = sqlite3.Row
            history = []
            try:
                rows = conn.execute("""
                    SELECT hi.url, hi.title, hi.visit_count,
                           MAX(hv.visit_time) AS last_visit
                    FROM history_items hi
                    LEFT JOIN history_visits hv ON hi.id = hv.history_item
                    GROUP BY hi.id
                    ORDER BY last_visit DESC LIMIT 500
                """).fetchall()
                for r in rows:
                    history.append({
                        'url': r['url'] or '',
                        'title': r['title'] or '',
                        'visit_count': r['visit_count'] or 0,
                        'last_visit': self._mac_ts_to_iso(r['last_visit']),
                    })
            except Exception as inner:
                conn.close()
                return {'tool': 'ios_safari', 'status': 'error', 'error': str(inner),
                        'backup_dir': backup_dir}
            conn.close()
            return {
                'tool': 'ios_safari', 'status': 'success',
                'backup_dir': backup_dir,
                'entry_count': len(history),
                'history': history,
                'timestamp': datetime.now().isoformat(),
            }
        except Exception as e:
            return {'tool': 'ios_safari', 'status': 'error', 'error': str(e),
                    'backup_dir': backup_dir}

    def detect_jailbreak_indicators(self, backup_dir: str = '', data_dir: str = '') -> Dict[str, Any]:
        """Detect jailbreak/root indicators in an iOS backup or Android data directory."""
        indicators: List[Dict[str, Any]] = []

        if backup_dir:
            backup_path = Path(backup_dir)
            jb_apps = [
                ('com.saurik.Cydia', 'Cydia package manager'),
                ('xyz.willy.Zebra', 'Zebra package manager'),
                ('org.coolstar.SileoStore', 'Sileo package manager'),
                ('com.opa334.TrollStore', 'TrollStore sideloader'),
                ('com.opa334.Dopamine', 'Dopamine jailbreak'),
                ('com.p0sixspwn.p0sixspwn', 'p0sixspwn jailbreak'),
            ]
            manifest = backup_path / 'Manifest.db'
            if manifest.exists():
                try:
                    conn = sqlite3.connect(str(manifest))
                    for bundle_id, desc in jb_apps:
                        if conn.execute(
                            "SELECT 1 FROM Files WHERE domain LIKE ?",
                            (f'AppDomain-{bundle_id}%',),
                        ).fetchone():
                            indicators.append({
                                'type': 'jailbreak_app', 'platform': 'ios',
                                'indicator': bundle_id, 'description': desc,
                                'confidence': 'high',
                            })
                    if conn.execute(
                        "SELECT 1 FROM Files WHERE domain='HomeDomain' AND relativePath LIKE '%Cydia%'"
                    ).fetchone():
                        indicators.append({
                            'type': 'cydia_pref', 'platform': 'ios',
                            'indicator': 'Cydia preferences present',
                            'confidence': 'high',
                        })
                    conn.close()
                except Exception:
                    pass
            info_plist = backup_path / 'Info.plist'
            if info_plist.exists():
                try:
                    with open(info_plist, 'rb') as f:
                        info = plistlib.load(f)
                    if info.get('PasscodeSet') is False:
                        indicators.append({
                            'type': 'no_passcode', 'platform': 'ios',
                            'indicator': 'Device has no passcode set',
                            'confidence': 'medium',
                        })
                except Exception:
                    pass

        if data_dir:
            data_path = Path(data_dir)
            root_patterns = [
                ('**/su', 'su binary', 'high'),
                ('**/.magisk', 'Magisk hidden directory', 'high'),
                ('**/magisk', 'Magisk binary', 'high'),
                ('**/busybox', 'BusyBox binary', 'medium'),
                ('**/.superuser*', 'Superuser config', 'medium'),
            ]
            for pattern, desc, confidence in root_patterns:
                matches = list(data_path.glob(pattern))
                if matches:
                    indicators.append({
                        'type': 'root_binary', 'platform': 'android',
                        'indicator': desc,
                        'paths': [str(m.relative_to(data_path)) for m in matches[:5]],
                        'confidence': confidence,
                    })
            root_pkgs = {
                'com.topjohnwu.magisk': 'Magisk root manager',
                'eu.chainfire.supersu': 'SuperSU root manager',
                'com.noshufou.android.su': 'Superuser app',
                'com.koushikdutta.superuser': 'Superuser (Koush)',
            }
            for pkg in self._parse_android_packages(data_path):
                name = pkg.get('name', '')
                if name in root_pkgs:
                    indicators.append({
                        'type': 'root_package', 'platform': 'android',
                        'indicator': name, 'description': root_pkgs[name],
                        'confidence': 'high',
                    })

        return {
            'tool': 'jailbreak_root_detector', 'status': 'success',
            'backup_dir': backup_dir, 'data_dir': data_dir,
            'indicator_count': len(indicators),
            'indicators': indicators,
            'compromise_likely': any(i['confidence'] == 'high' for i in indicators),
            'timestamp': datetime.now().isoformat(),
        }

    # -- Android extended extraction -----------------------------------------

    @staticmethod
    def _find_db(data_path: Path, db_name: str) -> Optional[Path]:
        """Find the first SQLite database matching db_name within a directory tree."""
        matches = list(data_path.rglob(db_name))
        return matches[0] if matches else None

    def extract_android_sms(self, data_dir: str) -> Dict[str, Any]:
        """Extract SMS/MMS messages from Android mmssms.db."""
        data_path = Path(data_dir)
        db_path = self._find_db(data_path, 'mmssms.db')
        if db_path is None:
            return {'tool': 'android_sms', 'status': 'not_found',
                    'message': 'mmssms.db not found', 'data_dir': data_dir}
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=5)
            conn.row_factory = sqlite3.Row
            messages = []
            try:
                rows = conn.execute(
                    "SELECT address, body, date, type, read, subject "
                    "FROM sms ORDER BY date DESC LIMIT 500"
                ).fetchall()
                for r in rows:
                    ts = r['date']
                    ts_str = datetime.utcfromtimestamp(ts / 1000).isoformat() if ts else ''
                    messages.append({
                        'address': r['address'] or '',
                        'body': r['body'] or '',
                        'timestamp': ts_str,
                        'type': r['type'],   # 1=received, 2=sent, 3=draft
                        'read': bool(r['read']),
                        'subject': r['subject'] or '',
                    })
            except Exception as inner:
                conn.close()
                return {'tool': 'android_sms', 'status': 'error', 'error': str(inner),
                        'data_dir': data_dir}
            conn.close()
            return {
                'tool': 'android_sms', 'status': 'success',
                'data_dir': data_dir,
                'message_count': len(messages),
                'messages': messages,
                'timestamp': datetime.now().isoformat(),
            }
        except Exception as e:
            return {'tool': 'android_sms', 'status': 'error', 'error': str(e),
                    'data_dir': data_dir}

    def extract_android_call_logs(self, data_dir: str) -> Dict[str, Any]:
        """Extract call logs from Android (calllog.db or contacts2.db)."""
        data_path = Path(data_dir)
        db_path = self._find_db(data_path, 'calllog.db') or self._find_db(data_path, 'contacts2.db')
        if db_path is None:
            return {'tool': 'android_calls', 'status': 'not_found',
                    'message': 'calllog.db not found', 'data_dir': data_dir}
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=5)
            conn.row_factory = sqlite3.Row
            calls = []
            try:
                rows = conn.execute(
                    "SELECT number, date, duration, type, name, geocoded_location "
                    "FROM calls ORDER BY date DESC LIMIT 500"
                ).fetchall()
                for r in rows:
                    ts = r['date']
                    ts_str = datetime.utcfromtimestamp(ts / 1000).isoformat() if ts else ''
                    calls.append({
                        'number': r['number'] or '',
                        'name': r['name'] or '',
                        'timestamp': ts_str,
                        'duration_sec': r['duration'] or 0,
                        'type': r['type'],   # 1=incoming, 2=outgoing, 3=missed
                        'location': r['geocoded_location'] or '',
                    })
            except Exception as inner:
                conn.close()
                return {'tool': 'android_calls', 'status': 'error', 'error': str(inner),
                        'data_dir': data_dir}
            conn.close()
            return {
                'tool': 'android_calls', 'status': 'success',
                'data_dir': data_dir,
                'call_count': len(calls),
                'calls': calls,
                'timestamp': datetime.now().isoformat(),
            }
        except Exception as e:
            return {'tool': 'android_calls', 'status': 'error', 'error': str(e),
                    'data_dir': data_dir}

    def extract_android_contacts(self, data_dir: str) -> Dict[str, Any]:
        """Extract contacts from Android contacts2.db."""
        data_path = Path(data_dir)
        db_path = self._find_db(data_path, 'contacts2.db')
        if db_path is None:
            return {'tool': 'android_contacts', 'status': 'not_found',
                    'message': 'contacts2.db not found', 'data_dir': data_dir}
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=5)
            conn.row_factory = sqlite3.Row
            contacts = []
            try:
                rows = conn.execute("""
                    SELECT c.display_name, d.data1, d.mimetype,
                           c.last_time_contacted, c.times_contacted
                    FROM contacts c
                    LEFT JOIN data d ON c._id = d.contact_id
                    WHERE d.mimetype IN (
                        'vnd.android.cursor.item/phone_v2',
                        'vnd.android.cursor.item/email_v2'
                    )
                    ORDER BY c.last_time_contacted DESC LIMIT 500
                """).fetchall()
                for r in rows:
                    ts = r['last_time_contacted']
                    ts_str = datetime.utcfromtimestamp(ts / 1000).isoformat() if ts else ''
                    contacts.append({
                        'name': r['display_name'] or '',
                        'value': r['data1'] or '',
                        'type': 'phone' if 'phone' in (r['mimetype'] or '') else 'email',
                        'last_contacted': ts_str,
                        'contact_count': r['times_contacted'] or 0,
                    })
            except Exception as inner:
                conn.close()
                return {'tool': 'android_contacts', 'status': 'error', 'error': str(inner),
                        'data_dir': data_dir}
            conn.close()
            return {
                'tool': 'android_contacts', 'status': 'success',
                'data_dir': data_dir,
                'contact_count': len(contacts),
                'contacts': contacts,
                'timestamp': datetime.now().isoformat(),
            }
        except Exception as e:
            return {'tool': 'android_contacts', 'status': 'error', 'error': str(e),
                    'data_dir': data_dir}

    def extract_android_browser_history(self, data_dir: str) -> Dict[str, Any]:
        """Extract browser history from Android (Chrome, Firefox, built-in browser)."""
        data_path = Path(data_dir)
        all_history: List[Dict[str, Any]] = []
        # Chrome epoch: microseconds since 1601-01-01; offset to Unix epoch = 11644473600s
        _CHROME_EPOCH_OFFSET = 11644473600

        for db_name in ('History', 'browser.db', 'webview.db'):
            db_path = self._find_db(data_path, db_name)
            if db_path is None:
                continue
            try:
                conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=5)
                conn.row_factory = sqlite3.Row
                try:
                    rows = conn.execute(
                        "SELECT url, title, visit_count, last_visit_time FROM urls "
                        "ORDER BY last_visit_time DESC LIMIT 200"
                    ).fetchall()
                    for r in rows:
                        ts = r['last_visit_time']
                        ts_str = ''
                        if ts and ts > 0:
                            unix_sec = ts / 1e6 - _CHROME_EPOCH_OFFSET
                            try:
                                ts_str = datetime.utcfromtimestamp(unix_sec).isoformat()
                            except Exception:
                                ts_str = ''
                        all_history.append({
                            'url': r['url'] or '', 'title': r['title'] or '',
                            'visit_count': r['visit_count'] or 0,
                            'last_visit': ts_str, 'source_db': db_name,
                        })
                except Exception:
                    # Try legacy Android browser schema
                    try:
                        rows = conn.execute(
                            "SELECT url, title, visits, date FROM bookmarks "
                            "WHERE bookmark=0 ORDER BY date DESC LIMIT 200"
                        ).fetchall()
                        for r in rows:
                            ts = r['date']
                            ts_str = datetime.utcfromtimestamp(ts / 1000).isoformat() if ts else ''
                            all_history.append({
                                'url': r['url'] or '', 'title': r['title'] or '',
                                'visit_count': r['visits'] or 0,
                                'last_visit': ts_str, 'source_db': db_name,
                            })
                    except Exception:
                        pass
                conn.close()
            except Exception:
                continue

        return {
            'tool': 'android_browser_history', 'status': 'success',
            'data_dir': data_dir,
            'entry_count': len(all_history),
            'history': all_history[:500],
            'timestamp': datetime.now().isoformat(),
        }

    def extract_android_location(self, data_dir: str) -> Dict[str, Any]:
        """Extract location history from Android (Google Takeout JSON or location databases)."""
        data_path = Path(data_dir)
        locations: List[Dict[str, Any]] = []

        # Google Takeout Location History JSON
        for json_file in list(data_path.rglob('Location History.json'))[:3]:
            try:
                with open(json_file, 'r', errors='ignore') as f:
                    data = json.load(f)
                for loc in data.get('locations', [])[:500]:
                    ts_ms = loc.get('timestampMs', 0)
                    ts_str = datetime.utcfromtimestamp(int(ts_ms) / 1000).isoformat() if ts_ms else ''
                    locations.append({
                        'latitude': loc.get('latitudeE7', 0) / 1e7,
                        'longitude': loc.get('longitudeE7', 0) / 1e7,
                        'timestamp': ts_str,
                        'accuracy': loc.get('accuracy', 0),
                        'source': 'google_takeout',
                    })
            except Exception:
                continue

        # Location cache databases
        for db_name in ('cache.wifi', 'gps.db', 'location.db', 'cache.cell'):
            db_path = self._find_db(data_path, db_name)
            if db_path is None:
                continue
            try:
                conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=5)
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = [r[0] for r in cursor.fetchall()]
                for table in tables[:5]:
                    try:
                        rows = cursor.execute(
                            f"SELECT * FROM {table} LIMIT 100"  # noqa: S608
                        ).fetchall()
                        if not rows:
                            continue
                        keys = rows[0].keys()
                        lat_key = next((k for k in keys if 'lat' in k.lower()), None)
                        lon_key = next((k for k in keys if 'lon' in k.lower()), None)
                        if lat_key and lon_key:
                            for r in rows:
                                rd = dict(r)
                                locations.append({
                                    'latitude': rd.get(lat_key, 0),
                                    'longitude': rd.get(lon_key, 0),
                                    'timestamp': '',
                                    'source': db_name,
                                })
                    except Exception:
                        pass
                conn.close()
            except Exception:
                continue

        return {
            'tool': 'android_location_history', 'status': 'success',
            'data_dir': data_dir,
            'location_count': len(locations),
            'locations': locations[:500],
            'timestamp': datetime.now().isoformat(),
        }

    # -- iOS extended extraction ------------------------------------------------

    def extract_ios_contacts(self, backup_dir: str) -> Dict[str, Any]:
        """Extract contacts from iOS backup (AddressBook.sqlitedb)."""
        backup_path = Path(backup_dir)
        db_path = self._get_ios_file_path(
            backup_path, 'HomeDomain', 'Library/AddressBook/AddressBook.sqlitedb'
        )
        if db_path is None:
            return {
                'tool': 'ios_contacts', 'status': 'not_found',
                'message': 'AddressBook.sqlitedb not found in backup',
                'backup_dir': backup_dir,
            }
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=5)
            conn.row_factory = sqlite3.Row
            contacts: List[Dict[str, Any]] = []
            try:
                rows = conn.execute("""
                    SELECT p.ROWID, p.First, p.Last, p.Organization,
                           p.CreationDate, p.ModificationDate,
                           mv.value, mv.label, mv.property
                    FROM ABPerson p
                    LEFT JOIN ABMultiValue mv ON p.ROWID = mv.record_id
                    ORDER BY p.ROWID, mv.property
                    LIMIT 2000
                """).fetchall()
                seen: Dict[int, Dict[str, Any]] = {}
                for r in rows:
                    rid = r['ROWID']
                    if rid not in seen:
                        seen[rid] = {
                            'first': r['First'] or '',
                            'last': r['Last'] or '',
                            'organization': r['Organization'] or '',
                            'created': self._mac_ts_to_iso(r['CreationDate']),
                            'modified': self._mac_ts_to_iso(r['ModificationDate']),
                            'phones': [],
                            'emails': [],
                        }
                    if r['value']:
                        prop = r['property']
                        if prop == 3:    # phone
                            seen[rid]['phones'].append(r['value'])
                        elif prop == 4:  # email
                            seen[rid]['emails'].append(r['value'])
                contacts = list(seen.values())
            except Exception as inner:
                conn.close()
                return {'tool': 'ios_contacts', 'status': 'error', 'error': str(inner),
                        'backup_dir': backup_dir}
            conn.close()
            return {
                'tool': 'ios_contacts', 'status': 'success',
                'backup_dir': backup_dir,
                'contact_count': len(contacts),
                'contacts': contacts,
                'timestamp': datetime.now().isoformat(),
            }
        except Exception as e:
            return {'tool': 'ios_contacts', 'status': 'error', 'error': str(e),
                    'backup_dir': backup_dir}

    def extract_ios_accounts(self, backup_dir: str) -> Dict[str, Any]:
        """Extract Apple ID and configured accounts from iOS backup."""
        backup_path = Path(backup_dir)
        accounts = []
        
        # Primary: Accounts plist
        accounts_plist = self._get_ios_file_path(
            backup_path, 'HomeDomain',
            'Library/Accounts/Accounts3.sqlite'
        )
        if accounts_plist:
            try:
                conn = sqlite3.connect(f"file:{accounts_plist}?mode=ro", uri=True, timeout=5)
                conn.row_factory = sqlite3.Row
                try:
                    rows = conn.execute("""
                        SELECT a.identifier, a.account_description, c.value
                        FROM accounts a
                        LEFT JOIN account_credential c ON a.account_id = c.account_id
                        LIMIT 100
                    """).fetchall()
                    for r in rows:
                        accounts.append({
                            'account_id': r['identifier'] or '',
                            'description': r['account_description'] or '',
                            'credential_hint': (r['value'][:30] + '...') if r['value'] and len(r['value']) > 30 else (r['value'] or ''),
                            'type': 'apple_id' if 'apple' in str(r['account_description']).lower() else 'other',
                        })
                except Exception:
                    pass
                conn.close()
            except Exception:
                pass
        
        # Secondary: Keychain (for saved passwords)
        keychain_db = self._get_ios_file_path(
            backup_path, 'HomeDomain',
            'Library/Keychains/keychain-2.db'
        )
        keychain_entries = []
        if keychain_db:
            try:
                conn = sqlite3.connect(f"file:{keychain_db}?mode=ro", uri=True, timeout=5)
                try:
                    rows = conn.execute("SELECT svce, acct FROM genp LIMIT 50").fetchall()
                    for r in rows:
                        if r[0] or r[1]:
                            keychain_entries.append({
                                'service': r[0] or '',
                                'account': r[1] or '',
                            })
                except Exception:
                    pass
                conn.close()
            except Exception:
                pass
        
        return {
            'tool': 'ios_accounts',
            'status': 'success' if accounts else 'no_data',
            'backup_dir': backup_dir,
            'accounts': accounts,
            'keychain_entries': keychain_entries[:30],
            'account_count': len(accounts),
            'timestamp': datetime.now().isoformat(),
        }

    def extract_android_accounts(self, data_dir: str) -> Dict[str, Any]:
        """Extract Google and app accounts from Android accounts.db."""
        data_path = Path(data_dir)
        db_path = self._find_db(data_path, 'accounts.db')
        if db_path is None:
            return {'tool': 'android_accounts', 'status': 'not_found',
                    'message': 'accounts.db not found', 'data_dir': data_dir}
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=5)
            conn.row_factory = sqlite3.Row
            accounts = []
            try:
                # Modern Android schema
                rows = conn.execute("""
                    SELECT a.name, a.type, a.last_password_entry_time_millis_epoch,
                           b.name as package_name
                    FROM accounts a
                    LEFT JOIN account_authenticators b ON a._id = b._id
                    LIMIT 100
                """).fetchall()
                for r in rows:
                    ts = r['last_password_entry_time_millis_epoch']
                    ts_str = datetime.utcfromtimestamp(ts / 1000).isoformat() if ts else ''
                    accounts.append({
                        'name': r['name'] or '',
                        'type': r['type'] or '',
                        'package': r['package_name'] or '',
                        'last_password_entry': ts_str,
                        'is_google': 'google' in str(r['type']).lower(),
                    })
            except Exception:
                # Fallback to older schema
                try:
                    rows = conn.execute("SELECT name, type FROM accounts LIMIT 100").fetchall()
                    for r in rows:
                        accounts.append({
                            'name': r['name'] or '',
                            'type': r['type'] or '',
                            'package': '',
                            'last_password_entry': '',
                            'is_google': 'google' in str(r['type']).lower(),
                        })
                except Exception as inner:
                    conn.close()
                    return {'tool': 'android_accounts', 'status': 'error', 'error': str(inner),
                            'data_dir': data_dir}
            conn.close()
            return {
                'tool': 'android_accounts', 'status': 'success',
                'data_dir': data_dir,
                'account_count': len(accounts),
                'accounts': accounts,
                'google_accounts': [a for a in accounts if a.get('is_google')],
                'timestamp': datetime.now().isoformat(),
            }
        except Exception as e:
            return {'tool': 'android_accounts', 'status': 'error', 'error': str(e),
                    'data_dir': data_dir}

    def extract_ios_location(self, backup_dir: str) -> Dict[str, Any]:
        """Extract location history from iOS backup (routined Local.sqlite + Maps GeoHistory)."""
        backup_path = Path(backup_dir)
        locations: List[Dict[str, Any]] = []

        # Primary: routined significant visit locations
        routined_db = self._get_ios_file_path(
            backup_path, 'HomeDomain',
            'Library/Caches/com.apple.routined/Local.sqlite'
        )
        if routined_db:
            try:
                conn = sqlite3.connect(f"file:{routined_db}?mode=ro", uri=True, timeout=5)
                conn.row_factory = sqlite3.Row
                try:
                    rows = conn.execute("""
                        SELECT ZLATITUDE, ZLONGITUDE, ZENTER, ZLEAVE,
                               ZCONFIDENCE, ZCUSTOMLABEL
                        FROM ZRTVISIT
                        ORDER BY ZENTER DESC LIMIT 500
                    """).fetchall()
                    for r in rows:
                        locations.append({
                            'latitude': r['ZLATITUDE'] or 0.0,
                            'longitude': r['ZLONGITUDE'] or 0.0,
                            'enter': self._mac_ts_to_iso(r['ZENTER']),
                            'leave': self._mac_ts_to_iso(r['ZLEAVE']),
                            'confidence': r['ZCONFIDENCE'] or 0,
                            'label': r['ZCUSTOMLABEL'] or '',
                            'source': 'routined',
                        })
                except Exception:
                    pass
                conn.close()
            except Exception:
                pass

        # Secondary: Maps GeoHistory plist
        mapsdata = self._get_ios_file_path(
            backup_path, 'AppDomain-com.apple.Maps',
            'Library/Maps/GeoHistory.mapsdata'
        )
        if mapsdata:
            try:
                with open(mapsdata, 'rb') as f:
                    geo = plistlib.load(f)
                for entry in geo.get('visits', geo.get('locations', []))[:200]:
                    locations.append({
                        'latitude': entry.get('latitude', entry.get('lat', 0.0)),
                        'longitude': entry.get('longitude', entry.get('lon', 0.0)),
                        'enter': str(entry.get('arrivalDate', '')),
                        'leave': str(entry.get('departureDate', '')),
                        'source': 'maps_geohistory',
                    })
            except Exception:
                pass

        return {
            'tool': 'ios_location_history', 'status': 'success',
            'backup_dir': backup_dir,
            'location_count': len(locations),
            'locations': locations,
            'timestamp': datetime.now().isoformat(),
        }

    def extract_ios_mail(self, backup_dir: str) -> Dict[str, Any]:
        """Extract messages from iOS Mail.app (Envelope Index database)."""
        backup_path = Path(backup_dir)
        db_path = self._get_ios_file_path(
            backup_path, 'AppDomain-com.apple.mobilemail',
            'Library/Mail/Envelope Index'
        )
        if db_path is None:
            return {
                'tool': 'ios_mail', 'status': 'not_found',
                'message': 'Mail Envelope Index not found in backup',
                'backup_dir': backup_dir,
            }
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=5)
            conn.row_factory = sqlite3.Row
            messages: List[Dict[str, Any]] = []
            try:
                # Build mailbox id→url map
                mailboxes: Dict[int, str] = {}
                try:
                    for mb in conn.execute("SELECT ROWID, url FROM mailboxes LIMIT 100"):
                        mailboxes[mb['ROWID']] = mb['url'] or ''
                except Exception:
                    pass

                rows = conn.execute("""
                    SELECT m.ROWID, m.subject, m.sender, m.date_received,
                           m.date_sent, m.read, m.flagged, m.mailbox, m.remote_id
                    FROM messages m
                    ORDER BY m.date_received DESC LIMIT 500
                """).fetchall()
                for r in rows:
                    messages.append({
                        'rowid': r['ROWID'],
                        'subject': r['subject'] or '',
                        'sender': r['sender'] or '',
                        'date_received': self._mac_ts_to_iso(r['date_received']),
                        'date_sent': self._mac_ts_to_iso(r['date_sent']),
                        'read': bool(r['read']),
                        'flagged': bool(r['flagged']),
                        'mailbox': mailboxes.get(r['mailbox'], str(r['mailbox'])),
                        'remote_id': r['remote_id'] or '',
                    })
            except Exception as inner:
                conn.close()
                return {'tool': 'ios_mail', 'status': 'error', 'error': str(inner),
                        'backup_dir': backup_dir}
            conn.close()
            return {
                'tool': 'ios_mail', 'status': 'success',
                'backup_dir': backup_dir,
                'message_count': len(messages),
                'messages': messages,
                'timestamp': datetime.now().isoformat(),
            }
        except Exception as e:
            return {'tool': 'ios_mail', 'status': 'error', 'error': str(e),
                    'backup_dir': backup_dir}

    # -- Android extended extraction ----------------------------------------

    def extract_android_email(self, data_dir: str) -> Dict[str, Any]:
        """Extract emails from Android mail app databases (Gmail, Samsung Mail, AOSP Mail)."""
        data_path = Path(data_dir)
        messages: List[Dict[str, Any]] = []
        source_db: str = ''

        # Gmail: mailstore.<account>.db
        gmail_dbs = list(data_path.rglob('mailstore.*.db'))
        if gmail_dbs:
            db_path = gmail_dbs[0]
            source_db = str(db_path)
            try:
                conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=5)
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = {r[0] for r in cursor.fetchall()}
                msg_table = 'messages' if 'messages' in tables else (
                    'conversation_messages' if 'conversation_messages' in tables else None
                )
                if msg_table:
                    rows = cursor.execute(
                        f"SELECT * FROM {msg_table} ORDER BY dateSentMs DESC LIMIT 500"  # noqa: S608
                    ).fetchall()
                    keys = [d[0] for d in cursor.description]
                    for r in rows:
                        rd = dict(zip(keys, r))
                        ts = rd.get('dateSentMs', rd.get('date', 0))
                        messages.append({
                            'from': rd.get('fromAddress', rd.get('from', '')),
                            'to': rd.get('toAddresses', rd.get('to', '')),
                            'subject': rd.get('subject', ''),
                            'snippet': rd.get('snippet', ''),
                            'timestamp': datetime.utcfromtimestamp(int(ts) / 1000).isoformat() if ts else '',
                            'read': bool(rd.get('read', 0)),
                            'source': 'gmail',
                        })
                conn.close()
            except Exception:
                pass

        # Samsung / AOSP Email provider
        if not messages:
            for db_name in ('EmailProviderBody.db', 'EmailProvider.db', 'email.db'):
                db_path_alt = self._find_db(data_path, db_name)
                if db_path_alt is None:
                    continue
                source_db = str(db_path_alt)
                try:
                    conn = sqlite3.connect(f"file:{db_path_alt}?mode=ro", uri=True, timeout=5)
                    conn.row_factory = sqlite3.Row
                    rows = conn.execute(
                        "SELECT fromList, toList, subject, timeStamp, flagRead "
                        "FROM Message ORDER BY timeStamp DESC LIMIT 500"
                    ).fetchall()
                    for r in rows:
                        ts = r['timeStamp']
                        messages.append({
                            'from': r['fromList'] or '',
                            'to': r['toList'] or '',
                            'subject': r['subject'] or '',
                            'timestamp': datetime.utcfromtimestamp(int(ts) / 1000).isoformat() if ts else '',
                            'read': bool(r['flagRead']),
                            'source': db_name,
                        })
                    conn.close()
                    break
                except Exception:
                    pass

        return {
            'tool': 'android_email', 'status': 'success',
            'data_dir': data_dir,
            'source_db': source_db,
            'message_count': len(messages),
            'messages': messages,
            'timestamp': datetime.now().isoformat(),
        }

    # -- Cross-platform extraction ------------------------------------------

    def extract_mobile_photo_exif(self, source_dir: str, platform: str = 'ios') -> Dict[str, Any]:
        """Extract EXIF metadata and GPS coordinates from mobile device photos."""
        source_path = Path(source_dir)
        photos: List[Dict[str, Any]] = []

        # Prefer exiftool for comprehensive metadata
        exiftool_bin = shutil.which('exiftool')
        if exiftool_bin:
            try:
                r = subprocess.run(
                    [exiftool_bin, '-json', '-GPS*', '-DateTimeOriginal',
                     '-Make', '-Model', '-FileName', '-r', str(source_path)],
                    capture_output=True, text=True, timeout=120
                )
                if r.returncode == 0 and r.stdout.strip():
                    for rec in json.loads(r.stdout)[:500]:
                        gps_lat = rec.get('GPSLatitude')
                        gps_lon = rec.get('GPSLongitude')
                        photos.append({
                            'file': rec.get('FileName', ''),
                            'date_taken': rec.get('DateTimeOriginal', ''),
                            'make': rec.get('Make', ''),
                            'model': rec.get('Model', ''),
                            'gps_latitude': gps_lat,
                            'gps_longitude': gps_lon,
                            'has_gps': gps_lat is not None and gps_lon is not None,
                        })
                    return {
                        'tool': 'mobile_photo_exif', 'status': 'success',
                        'source_dir': source_dir, 'platform': platform,
                        'photo_count': len(photos),
                        'gps_count': sum(1 for p in photos if p.get('has_gps')),
                        'photos': photos,
                        'timestamp': datetime.now().isoformat(),
                    }
            except Exception:
                pass

        # Fallback: Pillow for JPEG EXIF
        try:
            from PIL import Image, ExifTags  # type: ignore
            jpeg_files = list(source_path.rglob('*.jpg')) + list(source_path.rglob('*.jpeg'))
            for img_path in jpeg_files[:500]:
                try:
                    img = Image.open(img_path)
                    raw_exif = img._getexif() or {}  # type: ignore[attr-defined]
                    named = {ExifTags.TAGS.get(k, k): v for k, v in raw_exif.items()}
                    gps_info = named.get('GPSInfo', {})
                    lat = lon = None
                    if gps_info:
                        lat_dms = gps_info.get(2)
                        lat_ref = gps_info.get(1, 'N')
                        lon_dms = gps_info.get(4)
                        lon_ref = gps_info.get(3, 'E')
                        if lat_dms:
                            def _dms(dms: Any) -> float:
                                return float(dms[0]) + float(dms[1]) / 60 + float(dms[2]) / 3600
                            lat = _dms(lat_dms) * (-1 if lat_ref == 'S' else 1)
                            lon = _dms(lon_dms) * (-1 if lon_ref == 'W' else 1) if lon_dms else None
                    photos.append({
                        'file': img_path.name,
                        'date_taken': str(named.get('DateTimeOriginal', '')),
                        'make': str(named.get('Make', '')),
                        'model': str(named.get('Model', '')),
                        'gps_latitude': lat,
                        'gps_longitude': lon,
                        'has_gps': lat is not None,
                    })
                except Exception:
                    continue
        except ImportError:
            return {
                'tool': 'mobile_photo_exif', 'status': 'not_available',
                'message': 'exiftool not installed and Pillow unavailable',
                'source_dir': source_dir,
            }

        return {
            'tool': 'mobile_photo_exif', 'status': 'success',
            'source_dir': source_dir, 'platform': platform,
            'photo_count': len(photos),
            'gps_count': sum(1 for p in photos if p.get('has_gps')),
            'photos': photos,
            'timestamp': datetime.now().isoformat(),
        }

    def recover_deleted_sqlite_messages(self, db_path: str) -> Dict[str, Any]:
        """Recover messages from SQLite WAL/journal by checkpointing into a temp copy."""
        p = Path(db_path)
        if not p.exists():
            return {'tool': 'sqlite_wal_recovery', 'status': 'not_found',
                    'message': f'Database not found: {db_path}'}

        wal_path = Path(str(p) + '-wal')
        shm_path = Path(str(p) + '-shm')
        journal_path = Path(str(p) + '-journal')
        has_wal = wal_path.exists()
        has_journal = journal_path.exists()

        if not has_wal and not has_journal:
            return {
                'tool': 'sqlite_wal_recovery', 'status': 'no_wal',
                'message': 'No WAL or journal file alongside database',
                'db_path': db_path,
            }

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            tmp_db = tmp_path / p.name
            shutil.copy2(str(p), str(tmp_db))
            if has_wal:
                shutil.copy2(str(wal_path), str(tmp_path / (p.name + '-wal')))
            if shm_path.exists():
                shutil.copy2(str(shm_path), str(tmp_path / (p.name + '-shm')))
            if has_journal:
                shutil.copy2(str(journal_path), str(tmp_path / (p.name + '-journal')))

            try:
                conn = sqlite3.connect(str(tmp_db))
                conn.row_factory = sqlite3.Row
                try:
                    conn.execute('PRAGMA wal_checkpoint(FULL)')
                except Exception:
                    pass

                tables = [r[0] for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()]
                data: Dict[str, Any] = {}
                for table in tables:
                    try:
                        rows = conn.execute(
                            f"SELECT * FROM {table} LIMIT 200"  # noqa: S608
                        ).fetchall()
                        if rows:
                            keys = list(rows[0].keys())
                            data[table] = [dict(zip(keys, tuple(r))) for r in rows]
                    except Exception:
                        continue
                conn.close()
                return {
                    'tool': 'sqlite_wal_recovery', 'status': 'success',
                    'db_path': db_path,
                    'had_wal': has_wal,
                    'had_journal': has_journal,
                    'tables_recovered': list(data.keys()),
                    'data': data,
                    'timestamp': datetime.now().isoformat(),
                }
            except Exception as e:
                return {'tool': 'sqlite_wal_recovery', 'status': 'error',
                        'error': str(e), 'db_path': db_path}

    def extract_whatsapp(self, source_dir: str, platform: str = 'android') -> Dict[str, Any]:
        """Extract WhatsApp messages from iOS ChatStorage.sqlite or Android msgstore.db."""
        source_path = Path(source_dir)
        messages: List[Dict[str, Any]] = []
        db_used: str = ''

        if platform == 'ios':
            db_path = (
                self._get_ios_file_path(
                    source_path,
                    'AppDomainGroup-group.net.whatsapp.WhatsApp.shared',
                    'ChatStorage.sqlite',
                ) or
                self._get_ios_file_path(
                    source_path,
                    'AppDomain-net.whatsapp.WhatsApp',
                    'Documents/ChatStorage.sqlite',
                )
            )
            if db_path is None:
                matches = list(source_path.rglob('ChatStorage.sqlite'))
                db_path = matches[0] if matches else None
            if db_path is None:
                return {
                    'tool': 'whatsapp_ios', 'status': 'not_found',
                    'message': 'ChatStorage.sqlite not found in iOS backup',
                    'source_dir': source_dir,
                }
            db_used = str(db_path)
            try:
                conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=5)
                conn.row_factory = sqlite3.Row
                try:
                    rows = conn.execute("""
                        SELECT m.Z_PK, m.ZTEXT, m.ZMESSAGEDATE,
                               m.ZISFROMME, m.ZMESSAGETYPE,
                               s.ZCONTACTJID, s.ZPARTNERNAME
                        FROM ZWAMESSAGE m
                        LEFT JOIN ZWACHATSESSION s ON m.ZCHATSESSION = s.Z_PK
                        ORDER BY m.ZMESSAGEDATE DESC LIMIT 500
                    """).fetchall()
                    for r in rows:
                        messages.append({
                            'text': r['ZTEXT'] or '',
                            'timestamp': self._mac_ts_to_iso(r['ZMESSAGEDATE']),
                            'from_me': bool(r['ZISFROMME']),
                            'message_type': r['ZMESSAGETYPE'],
                            'contact_jid': r['ZCONTACTJID'] or '',
                            'contact_name': r['ZPARTNERNAME'] or '',
                        })
                except Exception as inner:
                    conn.close()
                    return {'tool': 'whatsapp_ios', 'status': 'error',
                            'error': str(inner), 'source_dir': source_dir}
                conn.close()
            except Exception as e:
                return {'tool': 'whatsapp_ios', 'status': 'error',
                        'error': str(e), 'source_dir': source_dir}

        else:  # android
            db_path = self._find_db(source_path, 'msgstore.db')
            if db_path is None:
                # Check for encrypted variants
                for enc in ('msgstore.db.crypt14', 'msgstore.db.crypt12', 'msgstore.db.crypt15'):
                    enc_path = self._find_db(source_path, enc)
                    if enc_path:
                        return {
                            'tool': 'whatsapp_android', 'status': 'encrypted',
                            'message': f'WhatsApp database is encrypted ({enc}) — decryption key required',
                            'db_path': str(enc_path),
                            'source_dir': source_dir,
                        }
                return {
                    'tool': 'whatsapp_android', 'status': 'not_found',
                    'message': 'msgstore.db not found',
                    'source_dir': source_dir,
                }
            db_used = str(db_path)
            try:
                conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=5)
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = {r[0] for r in cursor.fetchall()}

                if 'message' in tables:
                    rows = cursor.execute("""
                        SELECT m.key_remote_jid, m.key_from_me, m.data, m.timestamp,
                               m.status, m.media_url, m.media_name, m.latitude, m.longitude
                        FROM message m
                        ORDER BY m.timestamp DESC LIMIT 500
                    """).fetchall()
                    for r in rows:
                        ts = r['timestamp']
                        messages.append({
                            'text': r['data'] or '',
                            'timestamp': datetime.utcfromtimestamp(ts / 1000).isoformat() if ts else '',
                            'from_me': bool(r['key_from_me']),
                            'contact_jid': r['key_remote_jid'] or '',
                            'media_url': r['media_url'] or '',
                            'media_name': r['media_name'] or '',
                            'latitude': r['latitude'],
                            'longitude': r['longitude'],
                        })
                elif 'messages' in tables:
                    rows = cursor.execute(
                        "SELECT key_remote_jid, key_from_me, data, timestamp, status "
                        "FROM messages ORDER BY timestamp DESC LIMIT 500"
                    ).fetchall()
                    for r in rows:
                        ts = r['timestamp']
                        messages.append({
                            'text': r['data'] or '',
                            'timestamp': datetime.utcfromtimestamp(ts / 1000).isoformat() if ts else '',
                            'from_me': bool(r['key_from_me']),
                            'contact_jid': r['key_remote_jid'] or '',
                        })
                conn.close()
            except Exception as e:
                return {'tool': 'whatsapp_android', 'status': 'error',
                        'error': str(e), 'source_dir': source_dir}

        return {
            'tool': f'whatsapp_{platform}', 'status': 'success',
            'source_dir': source_dir,
            'db_path': db_used,
            'message_count': len(messages),
            'messages': messages,
            'timestamp': datetime.now().isoformat(),
        }

    def extract_telegram(self, source_dir: str, platform: str = 'android') -> Dict[str, Any]:
        """Extract Telegram messages from Android cache4.db or iOS postbox.sqlite."""
        source_path = Path(source_dir)
        messages: List[Dict[str, Any]] = []
        db_used: str = ''

        if platform == 'android':
            db_path = (
                self._find_db(source_path, 'cache4.db') or
                self._find_db(source_path, 'cache.db')
            )
            if db_path is None:
                return {
                    'tool': 'telegram_android', 'status': 'not_found',
                    'message': 'Telegram cache4.db not found',
                    'source_dir': source_dir,
                }
            db_used = str(db_path)
            try:
                conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=5)
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = {r[0] for r in cursor.fetchall()}
                msg_table = next((t for t in ('messages_v2', 'messages') if t in tables), None)
                if msg_table:
                    rows = cursor.execute(
                        f"SELECT * FROM {msg_table} ORDER BY date DESC LIMIT 500"  # noqa: S608
                    ).fetchall()
                    keys = [d[0] for d in cursor.description]
                    for r in rows:
                        rd = dict(zip(keys, r))
                        ts = rd.get('date', rd.get('timestamp', 0))
                        messages.append({
                            'text': rd.get('message', rd.get('data', '')),
                            'timestamp': datetime.utcfromtimestamp(int(ts)).isoformat() if ts else '',
                            'from_id': rd.get('from_id', rd.get('uid', '')),
                            'peer_id': rd.get('peer_id', rd.get('to_id', '')),
                            'out': bool(rd.get('out', 0)),
                        })
                conn.close()
            except Exception as e:
                return {'tool': 'telegram_android', 'status': 'error',
                        'error': str(e), 'source_dir': source_dir}

        else:  # iOS
            db_path = None
            for db_name in ('postbox.sqlite', 'db_sqlite', 'postbox'):
                matches = list(source_path.rglob(db_name))
                if matches:
                    db_path = matches[0]
                    break
            if db_path is None:
                return {
                    'tool': 'telegram_ios', 'status': 'not_found',
                    'message': 'Telegram postbox.sqlite not found — may require decryption',
                    'source_dir': source_dir,
                }
            db_used = str(db_path)
            try:
                conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=5)
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = {r[0] for r in cursor.fetchall()}
                msg_table = next(
                    (t for t in ('messages', 'tm_message', 'message') if t in tables), None
                )
                if msg_table:
                    rows = cursor.execute(
                        f"SELECT * FROM {msg_table} ORDER BY rowid DESC LIMIT 500"  # noqa: S608
                    ).fetchall()
                    keys = [d[0] for d in cursor.description]
                    for r in rows:
                        messages.append({k: v for k, v in zip(keys, r) if v is not None})
                else:
                    conn.close()
                    return {
                        'tool': 'telegram_ios', 'status': 'encrypted',
                        'message': 'Telegram iOS database appears encrypted or schema unknown',
                        'tables_found': list(tables),
                        'db_path': db_used,
                        'source_dir': source_dir,
                    }
                conn.close()
            except Exception as e:
                return {'tool': 'telegram_ios', 'status': 'error',
                        'error': str(e), 'source_dir': source_dir}

        return {
            'tool': f'telegram_{platform}', 'status': 'success',
            'source_dir': source_dir,
            'db_path': db_used,
            'message_count': len(messages),
            'messages': messages,
            'timestamp': datetime.now().isoformat(),
        }

    # -- iLEAPP / ALEAPP wrappers --------------------------------------------

    def run_ileapp(self, backup_dir: str, output_dir: str = '') -> Dict[str, Any]:
        """Run iLEAPP iOS forensics parser if installed on the system."""
        ileapp_bin: Optional[str] = shutil.which('ileapp') or shutil.which('ileapp.py')
        if ileapp_bin is None:
            for candidate in ('/opt/ileapp/ileapp.py', '/usr/local/bin/ileapp',
                              '/usr/share/ileapp/ileapp.py'):
                if Path(candidate).exists():
                    ileapp_bin = candidate
                    break
        if ileapp_bin is None:
            return {
                'tool': 'ileapp', 'status': 'not_available',
                'message': 'iLEAPP not found — install from https://github.com/abrignoni/iLEAPP',
                'backup_dir': backup_dir,
            }
        if not output_dir:
            output_dir = tempfile.mkdtemp(prefix='geoff_ileapp_')
        cmd = [ileapp_bin, '-t', 'itunes', '-i', backup_dir, '-o', output_dir]
        if ileapp_bin.endswith('.py'):
            cmd = ['python3'] + cmd
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            rc = r.returncode
            stdout_tail = r.stdout[-2000:]
            stderr_tail = r.stderr[-500:]
        except Exception as e:
            return {'tool': 'ileapp', 'status': 'error', 'error': str(e),
                    'backup_dir': backup_dir}
        report_summary: Dict[str, Any] = {}
        report_json = Path(output_dir) / 'ILEAPP_report.json'
        if report_json.exists():
            try:
                with open(report_json) as f:
                    report_summary = json.load(f)
            except Exception:
                pass
        return {
            'tool': 'ileapp',
            'status': 'success' if rc == 0 else 'error',
            'backup_dir': backup_dir,
            'output_dir': output_dir,
            'return_code': rc,
            'stdout_tail': stdout_tail,
            'stderr_tail': stderr_tail,
            'report_summary': report_summary,
            'timestamp': datetime.now().isoformat(),
        }

    def run_aleapp(self, data_dir: str, output_dir: str = '') -> Dict[str, Any]:
        """Run ALEAPP Android forensics parser if installed on the system."""
        aleapp_bin: Optional[str] = shutil.which('aleapp') or shutil.which('aleapp.py')
        if aleapp_bin is None:
            for candidate in ('/opt/aleapp/aleapp.py', '/usr/local/bin/aleapp',
                              '/usr/share/aleapp/aleapp.py'):
                if Path(candidate).exists():
                    aleapp_bin = candidate
                    break
        if aleapp_bin is None:
            return {
                'tool': 'aleapp', 'status': 'not_available',
                'message': 'ALEAPP not found — install from https://github.com/abrignoni/ALEAPP',
                'data_dir': data_dir,
            }
        if not output_dir:
            output_dir = tempfile.mkdtemp(prefix='geoff_aleapp_')
        cmd = [aleapp_bin, '-t', 'fs', '-i', data_dir, '-o', output_dir]
        if aleapp_bin.endswith('.py'):
            cmd = ['python3'] + cmd
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            rc = r.returncode
            stdout_tail = r.stdout[-2000:]
            stderr_tail = r.stderr[-500:]
        except Exception as e:
            return {'tool': 'aleapp', 'status': 'error', 'error': str(e),
                    'data_dir': data_dir}
        report_summary: Dict[str, Any] = {}
        report_json = Path(output_dir) / 'ALEAPP_report.json'
        if report_json.exists():
            try:
                with open(report_json) as f:
                    report_summary = json.load(f)
            except Exception:
                pass
        return {
            'tool': 'aleapp',
            'status': 'success' if rc == 0 else 'error',
            'data_dir': data_dir,
            'output_dir': output_dir,
            'return_code': rc,
            'stdout_tail': stdout_tail,
            'stderr_tail': stderr_tail,
            'report_summary': report_summary,
            'timestamp': datetime.now().isoformat(),
        }

    # -----------------------------------------------------------------------
    # New extraction methods (MEDIUM PRIORITY) - added 2026-04-19
    # -----------------------------------------------------------------------

    def extract_ios_keychain(self, backup_dir: str) -> Dict[str, Any]:
        """Extract Keychain data from iOS backup.
        
        Parses KeychainDomain data to extract password items, internet passwords,
        and other secure credential entries.
        """
        backup_path = Path(backup_dir)
        keychain_file = backup_path / 'KeychainDomain.plist'
        
        if not keychain_file.exists():
            return {
                'tool': 'ios_keychain',
                'status': 'not_found',
                'message': 'KeychainDomain.plist not found',
                'backup_dir': backup_dir,
            }
        
        try:
            with open(keychain_file, 'rb') as f:
                data = plistlib.load(f)
            
            items = []
            for record in data.get('RKKeychainRecord', []):
                items.append({
                    'record_type': record.get('RecordType', ''),
                    'service': record.get('Service', ''),
                    'account': record.get('Account', ''),
                    'password': record.get('Password', ''),
                    'creation_date': str(record.get('CreationDate', '')),
                    'modify_date': str(record.get('ModifyDate', '')),
                })
            
            return {
                'tool': 'ios_keychain',
                'status': 'success',
                'backup_dir': backup_dir,
                'item_count': len(items),
                'items': items[:500],
                'timestamp': datetime.now().isoformat(),
            }
        except Exception as e:
            return {
                'tool': 'ios_keychain',
                'status': 'error',
                'error': str(e),
                'backup_dir': backup_dir,
            }

    def extract_ios_health(self, backup_dir: str) -> Dict[str, Any]:
        """Extract Health data from iOS backup (HealthKit databases).
        
        Parses HealthKit databases to extract health records, workouts,
        and other health-related data from HealthExport.db or Health.db.
        """
        backup_path = Path(backup_dir)
        
        # Look for HealthKit databases
        health_dbs = list(backup_path.rglob('HealthExport.db')) + list(backup_path.rglob('Health.db'))
        if not health_dbs:
            return {
                'tool': 'ios_health',
                'status': 'not_found',
                'message': 'HealthKit databases (HealthExport.db or Health.db) not found',
                'backup_dir': backup_dir,
            }
        
        health_db = health_dbs[0]
        try:
            conn = sqlite3.connect(f"file:{health_db}?mode=ro", uri=True, timeout=5)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Get table list
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [r[0] for r in cursor.fetchall()]
            
            records = []
            if 'HK Record' in tables:
                # HK Record table contains health records
                cursor.execute(
                    "SELECT type, value, unit, startDate, endDate, creationDate, device FROM 'HK Record' LIMIT 500"
                )
                for row in cursor.fetchall():
                    records.append({
                        'type': row[0],
                        'value': row[1],
                        'unit': row[2],
                        'start_date': row[3],
                        'end_date': row[4],
                        'creation_date': row[5],
                        'device': row[6],
                    })
            
            conn.close()
            
            return {
                'tool': 'ios_health',
                'status': 'success',
                'backup_dir': backup_dir,
                'db_path': str(health_db.relative_to(backup_path)),
                'table_count': len(tables),
                'table_names': tables[:20],
                'record_count': len(records),
                'records': records,
                'timestamp': datetime.now().isoformat(),
            }
        except Exception as e:
            return {
                'tool': 'ios_health',
                'status': 'error',
                'error': str(e),
                'backup_dir': backup_dir,
            }

    def extract_ios_notifications(self, backup_dir: str) -> Dict[str, Any]:
        """Extract notification history from iOS backup (settings.db notification_log table).
        
        Parses the notification_log table from settings.db to extract
        notification records including app IDs, timestamps, and alert strings.
        """
        backup_path = Path(backup_dir)
        settings_db = self._find_db(backup_path, 'settings.db')
        
        if settings_db is None:
            return {
                'tool': 'ios_notifications',
                'status': 'not_found',
                'message': 'settings.db not found',
                'backup_dir': backup_dir,
            }
        
        try:
            conn = sqlite3.connect(f"file:{settings_db}?mode=ro", uri=True, timeout=5)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Check if notification_log table exists
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='notification_log'")
            if not cursor.fetchone():
                conn.close()
                return {
                    'tool': 'ios_notifications',
                    'status': 'not_found',
                    'message': 'notification_log table not found in settings.db',
                    'backup_dir': backup_dir,
                }
            
            # Extract notification records
            cursor.execute(
                "SELECT app_id, date, alert_string, bundle_id, category, flags FROM notification_log ORDER BY date DESC LIMIT 500"
            )
            notifications = []
            for row in cursor.fetchall():
                notifications.append({
                    'app_id': row[0],
                    'date': row[1],
                    'alert_string': row[2],
                    'bundle_id': row[3],
                    'category': row[4],
                    'flags': row[5],
                })
            
            conn.close()
            
            return {
                'tool': 'ios_notifications',
                'status': 'success',
                'backup_dir': backup_dir,
                'notification_count': len(notifications),
                'notifications': notifications,
                'timestamp': datetime.now().isoformat(),
            }
        except Exception as e:
            return {
                'tool': 'ios_notifications',
                'status': 'error',
                'error': str(e),
                'backup_dir': backup_dir,
            }

    def extract_ios_device_info(self, backup_dir: str) -> Dict[str, Any]:
        """Extract device info from iOS Info.plist and Manifest.plist."""
        backup_path = Path(backup_dir)
        info = {
            'device_name': '',
            'product_version': '',
            'product_type': '',
            'serial_number': '',
            'unique_identifier': '',
            'backup_date': '',
            'phone_number': '',
            'target_type': '',
        }
        
        # Read Info.plist
        info_plist = backup_path / 'Info.plist'
        if info_plist.exists():
            try:
                with open(info_plist, 'rb') as f:
                    data = plistlib.load(f)
                info['device_name'] = data.get('Device Name', '')
                info['product_version'] = data.get('Product Version', '')
                info['product_type'] = data.get('Product Type', '')
                info['serial_number'] = data.get('Serial Number', '')
                info['unique_identifier'] = data.get('Unique Identifier', '')
                info['backup_date'] = str(data.get('Last Backup Date', ''))
                info['phone_number'] = data.get('Phone Number', '')
                info['target_type'] = data.get('Target Type', '')
            except Exception:
                pass
        
        return {
            'tool': 'ios_device_info',
            'status': 'success',
            'backup_dir': backup_dir,
            'device_info': info,
            'timestamp': datetime.now().isoformat(),
        }

    def extract_android_device_info(self, data_dir: str) -> Dict[str, Any]:
        """Extract device info from Android system databases."""
        data_path = Path(data_dir)
        info = {
            'device_name': '',
            'android_version': '',
            'model': '',
            'manufacturer': '',
            'serial_number': '',
            'phone_number': '',
            'imei': '',
        }
        
        # Try settings.db for device name
        settings_db = self._find_db(data_path, 'settings.db')
        if settings_db:
            try:
                conn = sqlite3.connect(f"file:{settings_db}?mode=ro", uri=True, timeout=5)
                rows = conn.execute("SELECT name, value FROM global WHERE name IN ('device_name', 'bluetooth_name')").fetchall()
                for r in rows:
                    if r[0] == 'device_name':
                        info['device_name'] = r[1] or ''
                    if r[0] == 'bluetooth_name' and not info['device_name']:
                        info['device_name'] = r[1] or ''
                conn.close()
            except Exception:
                pass
        
        return {
            'tool': 'android_device_info',
            'status': 'success',
            'data_dir': data_dir,
            'device_info': info,
            'timestamp': datetime.now().isoformat(),
        }

    def extract_ios_usage_stats(self, backup_dir: str) -> Dict[str, Any]:
        """Extract iOS usage statistics from backup.
        
        Parses usage data from various iOS databases to extract app usage,
        screen time, and device interaction statistics.
        """
        backup_path = Path(backup_dir)
        
        # Look for usage statistics databases
        usage_dbs = []
        for pattern in ['usage.db', 'Usage.db', 'usagestats/*.db']:
            matches = list(backup_path.rglob(pattern))
            usage_dbs.extend(matches)
        
        if not usage_dbs:
            return {
                'tool': 'ios_usage_stats',
                'status': 'not_found',
                'message': 'Usage statistics databases not found',
                'backup_dir': backup_dir,
            }
        
        usage_db = usage_dbs[0]
        try:
            conn = sqlite3.connect(f"file:{usage_db}?mode=ro", uri=True, timeout=5)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Get table list
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [r[0] for r in cursor.fetchall()]
            
            # Try common usage tables
            app_usage = []
            if 'usage' in tables:
                cursor.execute("SELECT app_id, timestamp, duration FROM usage LIMIT 500")
                for row in cursor.fetchall():
                    app_usage.append({
                        'app_id': row[0],
                        'timestamp': row[1],
                        'duration': row[2],
                    })
            
            conn.close()
            
            return {
                'tool': 'ios_usage_stats',
                'status': 'success',
                'backup_dir': backup_dir,
                'db_path': str(usage_db.relative_to(backup_path)),
                'table_count': len(tables),
                'table_names': tables[:20],
                'app_usage_count': len(app_usage),
                'app_usage': app_usage,
                'timestamp': datetime.now().isoformat(),
            }
        except Exception as e:
            return {
                'tool': 'ios_usage_stats',
                'status': 'error',
                'error': str(e),
                'backup_dir': backup_dir,
            }

    def extract_android_notifications(self, data_dir: str) -> Dict[str, Any]:
        """Extract notification history from Android data (settings.db notification_log table).
        
        Parses the notification_log table from settings.db to extract
        notification records including app IDs, timestamps, and alert strings.
        """
        data_path = Path(data_dir)
        settings_db = self._find_db(data_path, 'settings.db')
        
        if settings_db is None:
            return {
                'tool': 'android_notifications',
                'status': 'not_found',
                'message': 'settings.db not found',
                'data_dir': data_dir,
            }
        
        try:
            conn = sqlite3.connect(f"file:{settings_db}?mode=ro", uri=True, timeout=5)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Check if notification_log table exists
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='notification_log'")
            if not cursor.fetchone():
                conn.close()
                return {
                    'tool': 'android_notifications',
                    'status': 'not_found',
                    'message': 'notification_log table not found in settings.db',
                    'data_dir': data_dir,
                }
            
            # Extract notification records
            cursor.execute(
                "SELECT app_id, date, alert_string, bundle_id, category, flags FROM notification_log ORDER BY date DESC LIMIT 500"
            )
            notifications = []
            for row in cursor.fetchall():
                notifications.append({
                    'app_id': row[0],
                    'date': row[1],
                    'alert_string': row[2],
                    'bundle_id': row[3],
                    'category': row[4],
                    'flags': row[5],
                })
            
            conn.close()
            
            return {
                'tool': 'android_notifications',
                'status': 'success',
                'data_dir': data_dir,
                'notification_count': len(notifications),
                'notifications': notifications,
                'timestamp': datetime.now().isoformat(),
            }
        except Exception as e:
            return {
                'tool': 'android_notifications',
                'status': 'error',
                'error': str(e),
                'data_dir': data_dir,
            }

    def extract_android_usage_stats(self, data_dir: str) -> Dict[str, Any]:
        """Extract Android usage statistics from /data/system/usagestats/ XML files.
        
        Parses usagestats XML files to extract app usage data including
        total time in foreground, last time used, and component names.
        """
        data_path = Path(data_dir)
        usagestats_dir = data_path / 'system' / 'usagestats'
        
        if not usagestats_dir.exists():
            return {
                'tool': 'android_usage_stats',
                'status': 'not_found',
                'message': 'usagestats directory not found',
                'data_dir': data_dir,
            }
        
        try:
            app_usage = []
            
            # Parse XML files in usagestats directory
            for xml_file in usagestats_dir.rglob('*.xml'):
                try:
                    tree = ET.parse(str(xml_file))
                    root = tree.getroot()
                    
                    for pkg in root.iter('package'):
                        pkg_name = pkg.get('package', '')
                        for comp in pkg.iter('component'):
                            app_usage.append({
                                'package': pkg_name,
                                'component': comp.get('name', ''),
                                'total_foreground_time': comp.get('fgTime', ''),
                                'last_time_used': comp.get('lt', ''),
                            })
                except Exception:
                    continue
            
            return {
                'tool': 'android_usage_stats',
                'status': 'success',
                'data_dir': data_dir,
                'usagestats_dir': str(usagestats_dir.relative_to(data_path)),
                'app_usage_count': len(app_usage),
                'app_usage': app_usage[:500],
                'timestamp': datetime.now().isoformat(),
            }
        except Exception as e:
            return {
                'tool': 'android_usage_stats',
                'status': 'error',
                'error': str(e),
                'data_dir': data_dir,
            }

class BROWSER_Specialist:
    """Extract browser forensic artefacts from SQLite databases on disk."""

    _CHROME_HISTORY_SQL = (
        "SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 500"
    )
    _CHROME_DOWNLOADS_SQL = (
        "SELECT target_path, tab_url, total_bytes, start_time, end_time FROM downloads ORDER BY start_time DESC LIMIT 200"
    )
    _CHROME_COOKIES_SQL = (
        "SELECT host_key, name, path, creation_utc, last_access_utc, is_secure FROM cookies ORDER BY last_access_utc DESC LIMIT 500"
    )
    _FIREFOX_HISTORY_SQL = (
        "SELECT url, title, visit_count, last_visit_date FROM moz_places ORDER BY last_visit_date DESC LIMIT 500"
    )
    _FIREFOX_DOWNLOADS_SQL = (
        "SELECT content, dateAdded, lastModified FROM moz_bookmarks b JOIN moz_places p ON b.fk=p.id WHERE b.type=3 LIMIT 200"
    )

    def _query_sqlite(self, db_path: str, sql: str) -> list:
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=5)
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(sql)
            rows = [dict(r) for r in cursor.fetchall()]
            conn.close()
            return rows
        except Exception as e:
            return [{"error": str(e)}]

    def extract_history(self, db_path: str) -> Dict[str, Any]:
        """Extract browser history from a Chrome/Firefox history database."""
        p = Path(db_path)
        browser = "chrome" if p.name.lower() in ("history", "places.sqlite") else "unknown"
        sql = self._CHROME_HISTORY_SQL if browser == "chrome" or p.name.lower() == "history" else self._FIREFOX_HISTORY_SQL
        rows = self._query_sqlite(db_path, sql)
        return {
            "tool": "browser_history",
            "db_path": db_path,
            "browser_hint": browser,
            "status": "success" if rows and "error" not in rows[0] else "error",
            "record_count": len(rows),
            "records": rows[:200],
            "timestamp": datetime.now().isoformat(),
        }

    def extract_cookies(self, db_path: str) -> Dict[str, Any]:
        """Extract browser cookies from a Chrome Cookies database."""
        rows = self._query_sqlite(db_path, self._CHROME_COOKIES_SQL)
        return {
            "tool": "browser_cookies",
            "db_path": db_path,
            "status": "success" if rows and "error" not in rows[0] else "error",
            "record_count": len(rows),
            "records": rows[:200],
            "timestamp": datetime.now().isoformat(),
        }

    def extract_downloads(self, db_path: str) -> Dict[str, Any]:
        """Extract download history from a Chrome history database."""
        rows = self._query_sqlite(db_path, self._CHROME_DOWNLOADS_SQL)
        return {
            "tool": "browser_downloads",
            "db_path": db_path,
            "status": "success" if rows and "error" not in rows[0] else "error",
            "record_count": len(rows),
            "records": rows[:200],
            "timestamp": datetime.now().isoformat(),
        }

    def extract_saved_passwords(self, db_path: str) -> Dict[str, Any]:
        """List saved password origins (not decrypted values) from a Chrome Login Data database."""
        sql = "SELECT origin_url, username_value, date_created FROM logins ORDER BY date_created DESC LIMIT 200"
        rows = self._query_sqlite(db_path, sql)
        return {
            "tool": "browser_saved_passwords",
            "db_path": db_path,
            "status": "success" if rows and "error" not in rows[0] else "error",
            "record_count": len(rows),
            "records": rows[:200],
            "timestamp": datetime.now().isoformat(),
        }


# ---------------------------------------------------------------------------
# EMAIL_Specialist  (PST/OST via readpst, mbox via Python, .eml parsing)
# ---------------------------------------------------------------------------

class EMAIL_Specialist:
    """Forensic extraction from email archives: PST/OST, mbox, and .eml files."""

    def _run(self, cmd: list, timeout: int = 120) -> Dict[str, Any]:
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return {"stdout": r.stdout[:8000], "stderr": r.stderr[:2000], "returncode": r.returncode}
        except FileNotFoundError:
            return {"stdout": "", "stderr": f"Tool not found: {cmd[0]}", "returncode": -1}
        except subprocess.TimeoutExpired:
            return {"stdout": "", "stderr": "timeout", "returncode": -1}
        except Exception as e:
            return {"stdout": "", "stderr": str(e), "returncode": -1}

    def analyze_pst(self, pst_path: str) -> Dict[str, Any]:
        """Convert PST/OST to mbox using readpst and summarise folder structure."""
        with tempfile.TemporaryDirectory() as tmp:
            r = self._run(["readpst", "-o", tmp, "-S", pst_path], timeout=180)
            folders: List[str] = []
            msg_count = 0
            if r["returncode"] == 0:
                for root, dirs, files in os.walk(tmp):
                    rel = os.path.relpath(root, tmp)
                    if rel != ".":
                        folders.append(rel)
                    msg_count += len([f for f in files if f.endswith(".eml") or f.endswith(".txt")])
            return {
                "tool": "readpst",
                "pst_path": pst_path,
                "status": "success" if r["returncode"] == 0 else "error",
                "folder_count": len(folders),
                "folders": folders[:50],
                "message_count_estimate": msg_count,
                "stderr": r["stderr"][:500] if r["returncode"] != 0 else "",
                "timestamp": datetime.now().isoformat(),
            }

    def analyze_mbox(self, mbox_path: str) -> Dict[str, Any]:
        """Parse an mbox file and return header summary for each message."""
        import mailbox
        try:
            mbox = mailbox.mbox(mbox_path)
            messages: List[Dict[str, str]] = []
            for msg in mbox:
                messages.append({
                    "from": msg.get("From", ""),
                    "to": msg.get("To", ""),
                    "subject": msg.get("Subject", ""),
                    "date": msg.get("Date", ""),
                    "message_id": msg.get("Message-ID", ""),
                })
                if len(messages) >= 500:
                    break
            return {
                "tool": "mbox_parser",
                "mbox_path": mbox_path,
                "status": "success",
                "message_count": len(messages),
                "messages": messages,
                "timestamp": datetime.now().isoformat(),
            }
        except Exception as e:
            return {
                "tool": "mbox_parser",
                "mbox_path": mbox_path,
                "status": "error",
                "error": str(e),
                "timestamp": datetime.now().isoformat(),
            }

    def analyze_eml(self, eml_path: str) -> Dict[str, Any]:
        """Parse a single .eml file and extract headers + attachment names."""
        import email as email_lib
        try:
            with open(eml_path, "rb") as fh:
                msg = email_lib.message_from_bytes(fh.read())
            attachments: List[str] = []
            for part in msg.walk():
                fn = part.get_filename()
                if fn:
                    attachments.append(fn)
            return {
                "tool": "eml_parser",
                "eml_path": eml_path,
                "status": "success",
                "from": msg.get("From", ""),
                "to": msg.get("To", ""),
                "subject": msg.get("Subject", ""),
                "date": msg.get("Date", ""),
                "message_id": msg.get("Message-ID", ""),
                "attachment_count": len(attachments),
                "attachments": attachments,
                "timestamp": datetime.now().isoformat(),
            }
        except Exception as e:
            return {
                "tool": "eml_parser",
                "eml_path": eml_path,
                "status": "error",
                "error": str(e),
                "timestamp": datetime.now().isoformat(),
            }


# ---------------------------------------------------------------------------
# JUMPLIST_Specialist  (LNK files, Recent Apps, Jump Lists, TypedPaths)
# ---------------------------------------------------------------------------

class JUMPLIST_Specialist:
    """Parse Windows LNK shortcut files and Jump List databases."""

    _LNK_MAGIC = b"\x4c\x00\x00\x00"  # Shell Link header signature

    def _read_lnk_header(self, path: str) -> Dict[str, Any]:
        """Extract basic LNK metadata using python-lnk or raw struct parsing."""
        try:
            import LnkParse3  # type: ignore
            with open(path, "rb") as fh:
                lnk = LnkParse3.lnk_file(fh)
            info = lnk.get_json()
            return {
                "target_path": info.get("data", {}).get("description", ""),
                "working_dir": info.get("data", {}).get("working_dir", ""),
                "creation_time": str(info.get("header", {}).get("creation_time", "")),
                "modification_time": str(info.get("header", {}).get("modification_time", "")),
                "access_time": str(info.get("header", {}).get("access_time", "")),
                "file_size": info.get("header", {}).get("file_size", 0),
                "attributes": info.get("header", {}).get("file_attributes_flags", []),
                "machine_id": info.get("extra", {}).get("DISTRIBUTED_LINK_TRACKER_BLOCK", {}).get("machine_id", ""),
            }
        except ImportError:
            pass
        # Fallback: raw struct read of first 76 bytes (Shell Link Header)
        try:
            with open(path, "rb") as fh:
                header = fh.read(76)
            if len(header) < 76 or header[:4] != self._LNK_MAGIC:
                return {"error": "not a valid LNK file"}
            import struct
            attrs, = struct.unpack_from("<I", header, 24)
            file_size, = struct.unpack_from("<I", header, 52)
            return {"attributes": attrs, "file_size": file_size, "raw_parse": True}
        except Exception as e:
            return {"error": str(e)}

    def parse_lnk_files(self, directory: str) -> Dict[str, Any]:
        """Walk a directory recursively and parse all .lnk files found."""
        results: List[Dict[str, Any]] = []
        try:
            base = Path(directory)
            for lnk_path in base.rglob("*.lnk"):
                info = self._read_lnk_header(str(lnk_path))
                info["lnk_path"] = str(lnk_path)
                results.append(info)
                if len(results) >= 1000:
                    break
        except Exception as e:
            return {
                "tool": "lnk_parser",
                "directory": directory,
                "status": "error",
                "error": str(e),
                "timestamp": datetime.now().isoformat(),
            }
        return {
            "tool": "lnk_parser",
            "directory": directory,
            "status": "success",
            "lnk_count": len(results),
            "records": results[:500],
            "timestamp": datetime.now().isoformat(),
        }

    def parse_jump_lists(self, directory: str) -> Dict[str, Any]:
        """List AutomaticDestinations and CustomDestinations jump list files."""
        auto: List[str] = []
        custom: List[str] = []
        try:
            base = Path(directory)
            for p in base.rglob("*.automaticDestinations-ms"):
                auto.append(str(p))
            for p in base.rglob("*.customDestinations-ms"):
                custom.append(str(p))
        except Exception as e:
            return {
                "tool": "jump_list_parser",
                "directory": directory,
                "status": "error",
                "error": str(e),
                "timestamp": datetime.now().isoformat(),
            }
        return {
            "tool": "jump_list_parser",
            "directory": directory,
            "status": "success",
            "automatic_count": len(auto),
            "custom_count": len(custom),
            "automatic_destinations": auto[:100],
            "custom_destinations": custom[:100],
            "timestamp": datetime.now().isoformat(),
        }

    def parse_recent_apps(self, ntuser_path: str) -> Dict[str, Any]:
        """Extract RecentDocs and TypedPaths from NTUSER.DAT using RegRipper."""
        import shutil
        results: Dict[str, Any] = {
            "tool": "recentapps_parser",
            "ntuser_path": ntuser_path,
            "timestamp": datetime.now().isoformat(),
        }
        rip = shutil.which("rip.pl") or shutil.which("rip")
        if not rip:
            results["status"] = "error"
            results["error"] = "RegRipper (rip.pl) not found"
            return results
        entries: List[str] = []
        for plugin in ("recentdocs", "typedurls", "typedpaths"):
            try:
                r = subprocess.run(
                    [rip, "-r", ntuser_path, "-p", plugin],
                    capture_output=True, text=True, timeout=30,
                )
                if r.stdout.strip():
                    entries.extend(r.stdout.strip().splitlines())
            except Exception:
                pass
        results["status"] = "success"
        results["record_count"] = len(entries)
        results["records"] = entries[:500]
        return results


# ---------------------------------------------------------------------------
# MACOS_Specialist  (HFS+/APFS, plist, unified log, launchd)
# ---------------------------------------------------------------------------

class MACOS_Specialist:
    """macOS-specific forensic artefact extraction."""

    def parse_plist(self, plist_path: str) -> Dict[str, Any]:
        """Parse a binary or XML plist file and return its contents as JSON."""
        try:
            with open(plist_path, "rb") as fh:
                data = plistlib.load(fh)
            def _serialise(obj):
                if isinstance(obj, bytes):
                    return obj.hex()
                if isinstance(obj, dict):
                    return {k: _serialise(v) for k, v in obj.items()}
                if isinstance(obj, (list, tuple)):
                    return [_serialise(i) for i in obj]
                return obj
            return {
                "tool": "plist_parser",
                "plist_path": plist_path,
                "status": "success",
                "data": _serialise(data),
                "timestamp": datetime.now().isoformat(),
            }
        except Exception as e:
            return {
                "tool": "plist_parser",
                "plist_path": plist_path,
                "status": "error",
                "error": str(e),
                "timestamp": datetime.now().isoformat(),
            }

    def parse_unified_log(self, log_path: str) -> Dict[str, Any]:
        """Extract entries from a macOS Unified Log (.logarchive or .tracev3) using log(1)."""
        try:
            r = subprocess.run(
                ["log", "show", "--style", "json", log_path],
                capture_output=True, text=True, timeout=120,
            )
            if r.returncode != 0:
                return {
                    "tool": "unified_log_parser",
                    "log_path": log_path,
                    "status": "error",
                    "error": r.stderr[:500],
                    "timestamp": datetime.now().isoformat(),
                }
            try:
                events = json.loads(r.stdout)
            except json.JSONDecodeError:
                events = r.stdout.splitlines()[:1000]
            return {
                "tool": "unified_log_parser",
                "log_path": log_path,
                "status": "success",
                "event_count": len(events) if isinstance(events, list) else 0,
                "events": events[:500] if isinstance(events, list) else [],
                "timestamp": datetime.now().isoformat(),
            }
        except FileNotFoundError:
            return {
                "tool": "unified_log_parser",
                "log_path": log_path,
                "status": "error",
                "error": "log(1) command not available (not macOS or not in PATH)",
                "timestamp": datetime.now().isoformat(),
            }
        except Exception as e:
            return {
                "tool": "unified_log_parser",
                "log_path": log_path,
                "status": "error",
                "error": str(e),
                "timestamp": datetime.now().isoformat(),
            }

    def analyze_launch_agents(self, directory: str) -> Dict[str, Any]:
        """Walk LaunchAgents / LaunchDaemons directories and parse each plist."""
        agents: List[Dict[str, Any]] = []
        suspicious_keys = {"RunAtLoad", "StartInterval", "StartCalendarInterval",
                           "KeepAlive", "ProgramArguments"}
        try:
            base = Path(directory)
            for plist_path in base.rglob("*.plist"):
                try:
                    with open(plist_path, "rb") as fh:
                        data = plistlib.load(fh)
                    entry: Dict[str, Any] = {
                        "path": str(plist_path),
                        "label": data.get("Label", ""),
                        "program": data.get("Program", data.get("ProgramArguments", [])),
                        "run_at_load": data.get("RunAtLoad", False),
                        "suspicious_keys": [k for k in suspicious_keys if k in data],
                    }
                    agents.append(entry)
                except Exception:
                    agents.append({"path": str(plist_path), "error": "parse_failed"})
                if len(agents) >= 500:
                    break
        except Exception as e:
            return {
                "tool": "launch_agent_analyzer",
                "directory": directory,
                "status": "error",
                "error": str(e),
                "timestamp": datetime.now().isoformat(),
            }
        return {
            "tool": "launch_agent_analyzer",
            "directory": directory,
            "status": "success",
            "agent_count": len(agents),
            "agents": agents,
            "timestamp": datetime.now().isoformat(),
        }

    def analyze_fseventsd(self, fseventsd_path: str) -> Dict[str, Any]:
        """Extract FSEvents log entries using fsevents-parser if available."""
        try:
            r = subprocess.run(
                ["fsevents_parser", fseventsd_path],
                capture_output=True, text=True, timeout=120,
            )
            lines = r.stdout.splitlines()
            return {
                "tool": "fseventsd_parser",
                "fseventsd_path": fseventsd_path,
                "status": "success" if r.returncode == 0 else "error",
                "line_count": len(lines),
                "lines": lines[:500],
                "stderr": r.stderr[:500] if r.returncode != 0 else "",
                "timestamp": datetime.now().isoformat(),
            }
        except FileNotFoundError:
            return {
                "tool": "fseventsd_parser",
                "fseventsd_path": fseventsd_path,
                "status": "error",
                "error": "fsevents_parser not found",
                "timestamp": datetime.now().isoformat(),
            }
        except Exception as e:
            return {
                "tool": "fseventsd_parser",
                "fseventsd_path": fseventsd_path,
                "status": "error",
                "error": str(e),
                "timestamp": datetime.now().isoformat(),
            }


# ---------------------------------------------------------------------------
# ExtendedOrchestrator (includes remnux reference)
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# PHOTORec Specialist
# ---------------------------------------------------------------------------

class PHOTOREC_Specialist:
    """Specialist for file carving with PhotoRec — batch mode support."""

    def __init__(self):
        self.photorec_path = self._find_tool('photorec')

    def _find_tool(self, tool: str) -> Optional[str]:
        result = subprocess.run(['which', tool], capture_output=True)
        return tool if result.returncode == 0 else None

    def _check_fallback_tools(self) -> List[str]:
        """Check for carving fallback tools (foremost is preferred)."""
        fallbacks = []
        for tool in ['foremost', 'scalpel']:
            if subprocess.run(['which', tool], capture_output=True).returncode == 0:
                fallbacks.append(tool)
        return fallbacks

    # -- public API ----------------------------------------------------------

    def recover_files(self, image: str, output_dir: str, file_types: Optional[List[str]] = None,
                      partition: int = 1, mode: str = 'paranoid') -> Dict[str, Any]:
        """Recover files from disk image using PhotoRec in batch mode.

        Note: PhotoRec is primarily designed for interactive use. This method
        attempts batch mode via config file, but may fail. If batch mode fails,
        returns error with fallback suggestion.
        """
        if not self.photorec_path:
            fallbacks = self._check_fallback_tools()
            if fallbacks:
                return {
                    'tool': 'photorec',
                    'status': 'error',
                    'error': f'PhotoRec not found, but {fallbacks[0]} is available as fallback',
                    'suggestion': f'Use {fallbacks[0]} instead for file carving',
                    'timestamp': datetime.now().isoformat(),
                }
            return {
                'tool': 'photorec',
                'status': 'error',
                'error': 'PhotoRec not found — install testdisk package',
                'timestamp': datetime.now().isoformat(),
            }

        Path(output_dir).mkdir(parents=True, exist_ok=True)

        # Try batch mode first
        batch_result = self._recover_files_batch_mode(image, output_dir, file_types, partition, mode)
        if batch_result['status'] == 'success':
            return batch_result

        return {
            'tool': 'photorec',
            'status': 'error',
            'error': 'PhotoRec batch mode failed — use interactive mode or fallback tool',
            'suggestion': batch_result.get('error', 'Run photorec manually with config file'),
            'fallback_tools': self._check_fallback_tools(),
            'timestamp': datetime.now().isoformat(),
        }

    def _recover_files_batch_mode(self, image: str, output_dir: str, file_types: Optional[List[str]],
                                    partition: int, mode: str) -> Dict[str, Any]:
        """Attempt batch mode PhotoRec execution."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.cfg', delete=False) as f:
            cfg_content = f"""/seq 1
/partition {partition}
/mode {0 if mode == 'quick' else 1}
"""
            f.write(cfg_content)
            config_file = f.name

        try:
            cmd = [
                'photorec',
                '/d', output_dir,
                '/cmd', image, str(partition),
                'options,fileopt,paranoid,search'
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)

            recovered_files = list(Path(output_dir).glob('*'))

            return {
                'tool': 'photorec',
                'status': 'success' if len(recovered_files) > 0 else 'error',
                'returncode': result.returncode,
                'recovered_count': len(recovered_files),
                'output_dir': output_dir,
                'timestamp': datetime.now().isoformat(),
                'stderr': result.stderr[:2000] if result.stderr else '',
                'note': 'PhotoRec batch mode support is limited. For reliable recovery, use interactive mode or fallback tools.',
            }
        except subprocess.TimeoutExpired:
            return {
                'tool': 'photorec',
                'status': 'timeout',
                'error': 'PhotoRec command timed out after 10 minutes',
                'timestamp': datetime.now().isoformat(),
            }
        except Exception as e:
            return {
                'tool': 'photorec',
                'status': 'error',
                'error': str(e),
                'timestamp': datetime.now().isoformat(),
            }
        finally:
            try:
                os.unlink(config_file)
            except:
                pass


# ---------------------------------------------------------------------------
# VSS (Volume Shadow Copy) Specialist
# ---------------------------------------------------------------------------

class VSS_Specialist:
    """Specialist for Volume Shadow Copy extraction and analysis."""

    def __init__(self):
        self.vshadowmount_available = self._check_tool('vshadowmount')
        self.fls_available = self._check_tool('fls')

    def _check_tool(self, tool: str) -> bool:
        result = subprocess.run(['which', tool], capture_output=True)
        return result.returncode == 0

    # -- public API ----------------------------------------------------------

    def list_vss(self, image: str) -> Dict[str, Any]:
        """List available Volume Shadow Copies in disk image."""
        if not self.vshadowmount_available:
            return {
                'tool': 'vshadowmount',
                'status': 'error',
                'error': 'vshadowmount not found — install libvshadow utils (xmount package)',
                'timestamp': datetime.now().isoformat(),
            }

        with tempfile.TemporaryDirectory() as tmpdir:
            cmd = ['vshadowmount', image, tmpdir]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

            if result.returncode != 0:
                return {
                    'tool': 'vshadowmount',
                    'status': 'error',
                    'error': 'Failed to mount image for VSS enumeration',
                    'timestamp': datetime.now().isoformat(),
                }

            vss_dirs = [d.name for d in Path(tmpdir).iterdir() if d.is_dir() and d.name.startswith('vss')]
            vss_nums = [int(d.replace('vss', '')) for d in vss_dirs if d.replace('vss', '').isdigit()]

            return {
                'tool': 'vshadowmount',
                'image': image,
                'status': 'success',
                'vss_count': len(vss_nums),
                'vss_numbers': vss_nums,
                'timestamp': datetime.now().isoformat(),
            }

    def mount_vss(self, image: str, vss_num: int, mount_point: str) -> Dict[str, Any]:
        """Mount a specific Volume Shadow Copy."""
        if not self.vshadowmount_available:
            return {
                'tool': 'vshadowmount',
                'status': 'error',
                'error': 'vshadowmount not found',
                'timestamp': datetime.now().isoformat(),
            }

        Path(mount_point).mkdir(parents=True, exist_ok=True)
        cmd = ['vshadowmount', '-o', str(vss_num), image, mount_point]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

        if result.returncode != 0:
            return {
                'tool': 'vshadowmount',
                'status': 'error',
                'error': f'Failed to mount VSS#{vss_num}',
                'timestamp': datetime.now().isoformat(),
            }

        return {
            'tool': 'vshadowmount',
            'image': image,
            'vss_number': vss_num,
            'mount_point': mount_point,
            'status': 'success',
            'timestamp': datetime.now().isoformat(),
        }

    def extract_vss_files(self, image: str, output_dir: str,
                          vss_numbers: Optional[List[int]] = None,
                          interesting_extensions: List[str] = None) -> Dict[str, Any]:
        """Extract files from VSS snapshots."""
        list_result = self.list_vss(image)
        if list_result['status'] != 'success':
            return list_result

        vss_nums = vss_numbers or list_result.get('vss_numbers', [])
        if not vss_nums:
            return {
                'tool': 'vss_extract',
                'status': 'error',
                'error': 'No VSS snapshots found',
                'timestamp': datetime.now().isoformat(),
            }

        interesting_extensions = interesting_extensions or [
            '.doc', '.docx', '.xls', '.xlsx', '.pdf', '.ntds.dit',
            '.lnk', '.ps1', '.exe', '.dll',
        ]

        extracted = []
        for vss_num in vss_nums:
            mount_point = tempfile.mkdtemp()
            mount_result = self.mount_vss(image, vss_num, mount_point)

            if mount_result['status'] != 'success':
                subprocess.run(['fusermount', '-u', mount_point], capture_output=True)
                continue

            for ext in interesting_extensions:
                for matched in Path(mount_point).rglob(f'*{ext}'):
                    if matched.is_file():
                        extracted.append({
                            'vss_number': vss_num,
                            'source_path': str(matched),
                            'size': matched.stat().st_size,
                        })

            subprocess.run(['fusermount', '-u', mount_point], capture_output=True)
            shutil.rmtree(mount_point, ignore_errors=True)

        return {
            'tool': 'vss_extract',
            'image': image,
            'vss_count': len(vss_nums),
            'status': 'success' if extracted else 'warning',
            'extracted_count': len(extracted),
            'timestamp': datetime.now().isoformat(),
        }

    def analyze_vss_timeline(self, image: str) -> Dict[str, Any]:
        """Build timeline across VSS snapshots."""
        list_result = self.list_vss(image)
        if list_result['status'] != 'success':
            return list_result

        vss_nums = list_result.get('vss_numbers', [])
        if not vss_nums:
            return {
                'tool': 'vss_timeline',
                'status': 'error',
                'error': 'No VSS snapshots found',
                'timestamp': datetime.now().isoformat(),
            }

        events = []
        for vss_num in vss_nums:
            mount_point = tempfile.mkdtemp()
            mount_result = self.mount_vss(image, vss_num, mount_point)

            if mount_result['status'] != 'success':
                subprocess.run(['fusermount', '-u', mount_point], capture_output=True)
                continue

            cmd = ['find', mount_point, '-type', 'f', '-printf', '%T@ %p\n']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    parts = line.strip().split(' ', 1)
                    if len(parts) == 2:
                        try:
                            events.append({
                                'path': parts[1],
                                'timestamp': int(float(parts[0])),
                                'source': f'VSS{vss_num}',
                            })
                        except ValueError:
                            pass

            subprocess.run(['fusermount', '-u', mount_point], capture_output=True)
            shutil.rmtree(mount_point, ignore_errors=True)

        events.sort(key=lambda x: x.get('timestamp', 0) or 0)
        return {
            'tool': 'vss_timeline',
            'image': image,
            'vss_count': len(vss_nums),
            'status': 'success',
            'event_count': len(events),
            'events': events[:1000],
            'timestamp': datetime.now().isoformat(),
        }


# ---------------------------------------------------------------------------
# Zimmerman Tools Specialist
# ---------------------------------------------------------------------------

class ZIMMERMAN_Specialist:
    """Specialist for Eric Zimmerman's forensic tools (.NET DLLs)."""

    def __init__(self, tools_dir: str = '/opt/geoff/zimmerman_tools'):
        self.tools_dir = Path(tools_dir)
        self.dotnet_available = self._check_dotnet()

    def _check_dotnet(self) -> bool:
        result = subprocess.run(['which', 'dotnet'], capture_output=True)
        return result.returncode == 0

    def _find_tool_dll(self, tool_name: str) -> Optional[Path]:
        dll_map = {
            'evtx': 'EvtxECmd.dll',
            'mft': 'MFTECmd.dll',
            'strings': 'bstrings.dll',
            'shellbags': 'ShellBagsExplorer.dll',
            'amcache': 'AmcacheParser.dll',
            'srum': 'SrumECmd.dll',
        }
        dll_name = dll_map.get(tool_name, f'{tool_name.capitalize()}.dll')
        dll_path = self.tools_dir / dll_name
        return dll_path if dll_path.exists() else None

    # -- public API ----------------------------------------------------------

    def parse_evtx_zimmerman(self, evtx_file: str, output_csv: str) -> Dict[str, Any]:
        """Parse EVTX using EvtxECmd.dll."""
        return self._run_dotnet_tool('evtx', evtx_file, output_csv, '-of csv')

    def parse_mft(self, mft_file: str, output_csv: str) -> Dict[str, Any]:
        """Parse MFT using MFTECmd.dll."""
        return self._run_dotnet_tool('mft', mft_file, output_csv, '-of csv')

    def extract_strings_zimmerman(self, file: str, output: str, min_length: int = 4) -> Dict[str, Any]:
        """Extract strings using bstrings.dll."""
        return self._run_dotnet_tool('strings', file, output, f'-min {min_length}')

    def shellbags_parse(self, hive: str, output_csv: str) -> Dict[str, Any]:
        """Parse ShellBags using ShellBagsExplorer.dll."""
        return self._run_dotnet_tool('shellbags', hive, output_csv, '-of csv')

    def amcache_parse(self, hive: str, output_csv: str) -> Dict[str, Any]:
        """Parse AmCache using AmcacheParser.dll."""
        return self._run_dotnet_tool('amcache', hive, output_csv, '-of csv')

    def srum_parse(self, srum_db: str, output_csv: str) -> Dict[str, Any]:
        """Parse SRUM using SrumECmd.dll."""
        return self._run_dotnet_tool('srum', srum_db, output_csv, '-of csv')

    def _run_dotnet_tool(self, tool_name: str, input_path: str, output: str, extra_args: str) -> Dict[str, Any]:
        """Run Zimmerman tool DLL."""
        if not self.dotnet_available:
            return {'tool': tool_name, 'status': 'error', 'error': 'dotnet not found', 'timestamp': datetime.now().isoformat()}

        dll_path = self._find_tool_dll(tool_name)
        if not dll_path:
            return {'tool': tool_name, 'status': 'error', 'error': f'{tool_name}.dll not found', 'timestamp': datetime.now().isoformat()}

        cmd = ['dotnet', str(dll_path), '-f', input_path, '-o', output] + shlex.split(extra_args)
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)

        event_count = 0
        if Path(output).exists():
            with open(output, 'r') as f:
                event_count = sum(1 for _ in f) - 1

        return {
            'tool': tool_name,
            'input': input_path,
            'output': output,
            'status': 'success' if result.returncode == 0 else 'error',
            'returncode': result.returncode,
            'event_count': event_count,
            'timestamp': datetime.now().isoformat(),
        }


    def extract_macos_users(self, dscl_path: str = '/var/db/dslocal/nodes/Default/users') -> Dict[str, Any]:
        """Extract macOS user accounts from dscl database or plist files."""
        users = []
        try:
            base = Path(dscl_path)
            if base.exists():
                for plist_file in base.glob('*.plist'):
                    try:
                        with open(plist_file, 'rb') as f:
                            data = plistlib.load(f)
                        users.append({
                            'username': data.get('name', [{}])[0] if isinstance(data.get('name'), list) else data.get('name', plist_file.stem),
                            'uid': data.get('uid', [{}])[0] if isinstance(data.get('uid'), list) else data.get('uid', ''),
                            'gid': data.get('gid', [{}])[0] if isinstance(data.get('gid'), list) else data.get('gid', ''),
                            'home': data.get('home', [{}])[0] if isinstance(data.get('home'), list) else data.get('home', ''),
                            'shell': data.get('shell', [{}])[0] if isinstance(data.get('shell'), list) else data.get('shell', ''),
                            'realname': data.get('realname', [{}])[0] if isinstance(data.get('realname'), list) else data.get('realname', ''),
                        })
                    except Exception:
                        continue
            return {
                'tool': 'macos_users',
                'source': dscl_path,
                'status': 'success' if users else 'no_data',
                'users': users,
                'user_count': len(users),
                'admin_users': [u for u in users if u.get('gid') == '80' or 'admin' in str(u.get('groups', [])).lower()],
                'timestamp': datetime.now().isoformat(),
            }
        except Exception as e:
            return {'tool': 'macos_users', 'status': 'error', 'error': str(e), 'timestamp': datetime.now().isoformat()}

    def extract_keychain_passwords(self, keychain_path: str) -> Dict[str, Any]:
        """Extract password metadata (not decrypted) from macOS Keychain."""
        try:
            result = subprocess.run(['security', 'dump-keychain', keychain_path], 
                                    capture_output=True, text=True, timeout=60)
            entries = []
            current = {}
            for line in result.stdout.split('\n'):
                if 'keychain:' in line.lower():
                    if current:
                        entries.append(current)
                    current = {}
                if 'account' in line.lower() and '<' in line:
                    parts = line.split('<')
                    if len(parts) > 1:
                        current['account'] = parts[1].split('>')[0] if '>' in parts[1] else parts[1]
                if 'svce' in line.lower() and '<' in line:
                    parts = line.split('<')
                    if len(parts) > 1:
                        current['service'] = parts[1].split('>')[0] if '>' in parts[1] else parts[1]
            if current:
                entries.append(current)
            return {
                'tool': 'keychain_dump',
                'keychain_path': keychain_path,
                'status': 'success' if entries else 'no_data',
                'entry_count': len(entries),
                'accounts': [e for e in entries if 'account' in e][:50],
                'timestamp': datetime.now().isoformat(),
            }
        except Exception as e:
            return {'tool': 'keychain_dump', 'status': 'error', 'error': str(e), 'timestamp': datetime.now().isoformat()}


# ---------------------------------------------------------------------------
# ExtendedOrchestrator (includes new specialists)
# ---------------------------------------------------------------------------

class ExtendedOrchestrator:
    """Extended orchestrator with all specialists."""

    def __init__(self, evidence_base: str):
        self.evidence_base = Path(evidence_base)

        from sift_specialists import SLEUTHKIT_Specialist, VOLATILITY_Specialist, STRINGS_Specialist
        self.sleuthkit = SLEUTHKIT_Specialist(evidence_base)
        self.volatility = VOLATILITY_Specialist()
        self.strings = STRINGS_Specialist()

        self.registry = REGISTRY_Specialist()
        self.plaso = PLASO_Specialist()
        self.network = NETWORK_Specialist()
        self.logs = LOG_Specialist()
        self.mobile = MOBILE_Specialist()
        self.browser = BROWSER_Specialist()
        self.email = EMAIL_Specialist()
        self.jumplist = JUMPLIST_Specialist()
        self.macos = MACOS_Specialist()

        # New specialists
        self.photorec = PHOTOREC_Specialist()
        self.vss = VSS_Specialist()
        self.zimmerman = ZIMMERMAN_Specialist()

        try:
            from sift_specialists_remnux import REMNUX_Orchestrator
            self.remnux = REMNUX_Orchestrator()
        except ImportError:
            self.remnux = None

    def run_playbook_step(self, investigation_id: str, step: Dict[str, Any]) -> Dict[str, Any]:
        module = step.get('module')
        function = step.get('function')
        params = step.get('params', {})

        specialist_map = {
            'sleuthkit': self.sleuthkit,
            'volatility': self.volatility,
            'strings': self.strings,
            'registry': self.registry,
            'plaso': self.plaso,
            'network': self.network,
            'logs': self.logs,
            'mobile': self.mobile,
            'photorec': self.photorec,
            'vss': self.vss,
            'zimmerman': self.zimmerman,
            'remnux': self.remnux,
            'browser': self.browser,
            'email': self.email,
            'jumplist': self.jumplist,
            'macos': self.macos,
        }

        specialist = specialist_map.get(module)
        if specialist and hasattr(specialist, function):
            func = getattr(specialist, function)
            return func(**params)

        if module == 'remnux' and self.remnux is not None:
            return self.remnux.run_playbook_step(investigation_id, step)

        return {'status': 'error', 'error': f'Unknown module {module}', 'timestamp': datetime.now().isoformat()}

    @staticmethod
    def _probe(binary: str) -> bool:
        return subprocess.run(['which', binary], capture_output=True).returncode == 0

    def get_available_tools(self) -> Dict[str, Any]:
        def avail(binaries: list) -> Dict[str, bool]:
            return {b: self._probe(b) for b in binaries}

        evtx_available = False
        try:
            import importlib
            evtx_available = importlib.util.find_spec('Evtx') is not None
        except Exception:
            pass

        return {
            'sleuthkit': {
                'category': 'Disk Forensics',
                'functions': ['analyze_partition_table', 'analyze_filesystem', 'list_files', 'list_files_mactime', 'extract_file', 'list_inodes', 'get_file_info', 'list_deleted'],
                'tool_availability': avail(['mmls', 'fsstat', 'fls', 'icat', 'istat', 'ils', 'blkls', 'jcat']),
            },
            'volatility': {
                'category': 'Memory Forensics',
                'functions': ['process_list', 'network_scan', 'find_malware', 'scan_registry', 'dump_process'],
                'tool_availability': {'volatility': any([self._probe('volatility3'), self._probe('vol.py'), self._probe('vol')])},
            },
            'strings': {'category': 'IOC Extraction', 'functions': ['extract_strings'], 'tool_availability': avail(['strings'])},
            'registry': {
                'category': 'Windows Registry',
                'functions': ['parse_hive', 'extract_shellbags', 'extract_autoruns', 'extract_services', 'extract_sam_users', 'extract_domain_accounts', 'extract_windows_credentials'],
                'tool_availability': avail(['rip.pl']),
            },
            'plaso': {
                'category': 'Timeline Analysis',
                'functions': ['create_timeline', 'sort_timeline', 'analyze_storage'],
                'tool_availability': avail(['log2timeline.py', 'psort.py', 'pinfo.py']),
            },
            'network': {
                'category': 'Network Forensics',
                'functions': ['analyze_pcap', 'extract_flows', 'extract_http'],
                'tool_availability': avail(['tshark', 'tcpflow']),
            },
            'logs': {'category': 'Log Analysis', 'functions': ['parse_evtx', 'parse_syslog', 'extract_linux_users', 'extract_wtmp_logins', 'extract_ssh_authorized_keys'], 'tool_availability': {'python-evtx': evtx_available}},
            'mobile': {
                'category': 'Mobile Forensics',
                'functions': [
                    'analyze_ios_backup',
                    'analyze_android',
                    'extract_ios_sms',
                    'extract_ios_call_history',
                    'extract_ios_safari_history',
                    'extract_ios_contacts',
                    'extract_ios_location',
                    'extract_ios_mail',
                    'extract_ios_keychain',
                    'extract_ios_health',
                    'extract_android_sms',
                    'extract_android_call_logs',
                    'extract_android_contacts',
                    'extract_android_browser_history',
                    'extract_android_location',
                    'extract_android_email',
                    'extract_android_notifications',
                    'extract_android_usage_stats',
                    'detect_jailbreak_indicators',
                    'run_ileapp',
                    'run_aleapp',
                    'extract_whatsapp',
                    'extract_telegram',
                ],
                'tool_availability': {},
                'notes': 'Pure-Python - supports iOS backups and Android data directories',
            },
            'photorec': {
                'category': 'File Carving',
                'functions': ['recover_files'],
                'tool_availability': avail(['photorec', 'foremost']),
            },
            'vss': {
                'category': 'Volume Shadow Copies',
                'functions': ['list_vss', 'mount_vss', 'extract_vss_files', 'analyze_vss_timeline'],
                'tool_availability': avail(['vshadowmount']),
            },
            'zimmerman': {
                'category': 'Windows Analysis',
                'functions': ['parse_evtx_zimmerman', 'parse_mft', 'extract_strings_zimmerman', 'shellbags_parse', 'amcache_parse', 'srum_parse'],
                'tool_availability': avail(['dotnet']),
            },
            'browser': {
                'category': 'Browser Forensics',
                'functions': ['extract_history', 'extract_cookies', 'extract_downloads', 'extract_saved_passwords'],
                'tools': ['sqlite3 (Chrome/Firefox DBs)'],
            },
            'email': {
                'category': 'Email Forensics',
                'functions': ['analyze_pst', 'analyze_mbox', 'analyze_eml'],
                'tools': ['readpst', 'mailbox (stdlib)', 'email (stdlib)'],
            },
            'jumplist': {
                'category': 'Windows Artefacts',
                'functions': ['parse_lnk_files', 'parse_jump_lists', 'parse_recent_apps'],
                'tools': ['LnkParse3', 'RegRipper (recentdocs, typedurls)'],
            },
            'macos': {
                'category': 'macOS Forensics',
                'functions': ['parse_plist', 'parse_unified_log', 'analyze_launch_agents', 'analyze_fseventsd'],
                'tools': ['plistlib (stdlib)', 'log(1)', 'fsevents_parser'],
            },
            'remnux': {
                'category': 'REMnux Malware Analysis',
                'functions': [
                    'die_scan', 'exiftool_scan', 'peframe_scan', 'ssdeep_hash', 'hashdeep_audit',
                    'upx_unpack', 'pdfid_scan', 'pdf_parser', 'oledump_scan', 'js_beautify',
                    'radare2_analyze', 'floss_strings', 'clamav_scan',
                ] if self.remnux else [],
                'tool_availability': avail(['die', 'exiftool', 'peframe', 'ssdeep', 'hashdeep', 'upx', 'pdfid', 'r2', 'floss']),
            },
        }