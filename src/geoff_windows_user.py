#!/usr/bin/env python3
"""Geoff DFIR - PB-SIFT-042 Stray Windows User Artifact Analysis.

Processes Windows user profile files extracted outside a disk image:
  - NTUSER.DAT registry hive (Run keys, RecentDocs, TypedURLs, UserAssist)
  - Prefetch files (.pf)
  - LNK / Recent shortcut files
  - Jump lists (.automaticDestinations-ms, .customDestinations-ms)
  - AppData artifacts (Roaming/Local application data)
  - Browser profiles (Chrome/Edge/Firefox SQLite databases)
"""

import json
import os
import re
import sqlite3
import struct
import subprocess
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Tool / library availability probes
# ---------------------------------------------------------------------------

def _which(cmd: str) -> bool:
    try:
        return subprocess.run(
            ["which", cmd], capture_output=True, timeout=5
        ).returncode == 0
    except Exception:
        return False


def _python_registry_available() -> bool:
    try:
        import importlib.util
        return importlib.util.find_spec("Registry") is not None
    except Exception:
        return False


_HAVE_HIVEXSH = _which("hivexsh")
_HAVE_HIVEXGET = _which("hivexget")
_HAVE_HIVEXREGEDIT = _which("hivexregedit")
_HAVE_PYTHON_REGISTRY = _python_registry_available()

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_NTUSER_NAMES = frozenset({"ntuser.dat", "usrclass.dat"})
_PREFETCH_EXT = frozenset({".pf"})
_LNK_EXT = frozenset({".lnk"})
_JUMPLIST_EXT = frozenset({".automaticDestinations-ms", ".customDestinations-ms"})
_APPDATA_MARKERS = ("appdata", "roaming", "local\\", "localappdata")
_BROWSER_PROFILE_NAMES = frozenset({
    # Chrome / Edge (Chromium)
    "history", "login data", "cookies", "web data", "bookmarks", "top sites",
    "shortcuts", "visited links",
    # Firefox
    "places.sqlite", "logins.json", "cookies.sqlite", "formhistory.sqlite",
    "signons.sqlite", "favicons.sqlite",
    # IE / Edge Legacy
    "webcachev01.dat",
})

# FILETIME epoch (100-ns intervals since 1601-01-01)
_FILETIME_EPOCH = datetime(1601, 1, 1)

# Well-known Run key paths
_RUN_KEYS = [
    "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx",
    "Software\\Microsoft\\Windows NT\\CurrentVersion\\Run",
]

# Suspicious AppData binary extensions
_SUSP_APPDATA_EXTS = frozenset({
    ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse",
    ".wsf", ".hta", ".scr", ".pif",
})


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class WindowsUserSpecialist:
    """PB-SIFT-042 — Stray Windows User Artifact Analysis."""

    def __init__(self):
        self._session_findings: list = []

    # ------------------------------------------------------------------
    # NTUSER.DAT
    # ------------------------------------------------------------------

    def analyze_ntuser_dat(self, hive_path: str) -> dict:
        p = Path(hive_path)
        if p.name.lower() not in _NTUSER_NAMES:
            return {"status": "skipped", "reason": "not an NTUSER.DAT or USRCLASS.DAT hive", "file": hive_path}

        findings = []
        if _HAVE_PYTHON_REGISTRY:
            findings = _parse_ntuser_python_registry(hive_path)
        elif _HAVE_HIVEXREGEDIT:
            findings = _parse_ntuser_hivexregedit(hive_path)
        elif _HAVE_HIVEXSH:
            findings = _parse_ntuser_hivexsh(hive_path)
        else:
            findings = _parse_ntuser_strings(hive_path)

        method = ("python-registry" if _HAVE_PYTHON_REGISTRY
                  else "hivexregedit" if _HAVE_HIVEXREGEDIT
                  else "hivexsh" if _HAVE_HIVEXSH
                  else "strings-fallback")
        run_entries = [f for f in findings if f.get("type") == "run_key"]
        summary = (f"NTUSER.DAT: {len(findings)} findings via {method}, "
                   f"{len(run_entries)} Run key entries")

        result = {"status": "success", "findings": findings, "summary": summary, "file": hive_path}
        self._session_findings.extend(findings)
        return result

    # ------------------------------------------------------------------
    # Prefetch files
    # ------------------------------------------------------------------

    def analyze_prefetch(self, prefetch_file: str) -> dict:
        p = Path(prefetch_file)
        if p.suffix.lower() not in _PREFETCH_EXT:
            return {"status": "skipped", "reason": "not a .pf prefetch file", "file": prefetch_file}

        parsed = _parse_prefetch_binary(prefetch_file)
        findings = [{
            "type": "prefetch",
            "file": prefetch_file,
            **parsed,
        }]
        exe = parsed.get("exe_name", p.stem.split("-")[0] if "-" in p.stem else p.stem)
        run_count = parsed.get("run_count", "?")
        last_run = parsed.get("last_run_time", "")
        summary = f"Prefetch {p.name}: exe={exe}, runs={run_count}" + (f", last={last_run[:19]}" if last_run else "")

        result = {"status": "success", "findings": findings, "summary": summary, "file": prefetch_file}
        self._session_findings.extend(findings)
        return result

    # ------------------------------------------------------------------
    # LNK files
    # ------------------------------------------------------------------

    def analyze_lnk_files(self, lnk_path: str) -> dict:
        p = Path(lnk_path)
        if p.suffix.lower() not in _LNK_EXT:
            return {"status": "skipped", "reason": "not a .lnk shortcut file", "file": lnk_path}

        parsed = _parse_lnk_binary(lnk_path)
        findings = [{
            "type": "lnk_file",
            "file": lnk_path,
            **parsed,
        }]
        target = parsed.get("target_path", "")
        summary = f"LNK {p.name} → {target}" if target else f"LNK {p.name}: parse result={parsed.get('note', 'ok')}"

        result = {"status": "success", "findings": findings, "summary": summary, "file": lnk_path}
        self._session_findings.extend(findings)
        return result

    # ------------------------------------------------------------------
    # Jump lists
    # ------------------------------------------------------------------

    def analyze_jump_lists(self, jump_list_path: str) -> dict:
        p = Path(jump_list_path)
        is_jumplist = (
            p.suffix.lower() in {".automaticDestinations-ms".lower(), ".customDestinations-ms".lower()}
            or p.name.lower().endswith(".automaticdestinations-ms")
            or p.name.lower().endswith(".customdestinations-ms")
        )
        if not is_jumplist:
            return {"status": "skipped", "reason": "not a jump list file", "file": jump_list_path}

        # Jump lists are OLE Compound Files (complex) — extract strings as fallback
        items = _extract_jumplist_items(jump_list_path)
        findings = [{
            "type": "jump_list",
            "file": jump_list_path,
            "app_id": p.stem,
            "list_type": "automatic" if "automatic" in p.name.lower() else "custom",
            "items": items[:50],
            "item_count": len(items),
        }]
        summary = f"Jump list {p.name}: {len(items)} path/URL items found"

        result = {"status": "success", "findings": findings, "summary": summary, "file": jump_list_path}
        self._session_findings.extend(findings)
        return result

    # ------------------------------------------------------------------
    # AppData artifacts
    # ------------------------------------------------------------------

    def analyze_appdata(self, artifact_path: str) -> dict:
        path_lower = str(artifact_path).lower().replace("\\", "/")
        if not any(m in path_lower for m in _APPDATA_MARKERS):
            return {"status": "skipped", "reason": "not an AppData path", "file": artifact_path}

        p = Path(artifact_path)
        indicators = []

        # Flag executable extensions directly in AppData
        if p.suffix.lower() in _SUSP_APPDATA_EXTS:
            indicators.append({
                "type": "suspicious_executable",
                "file": artifact_path,
                "extension": p.suffix.lower(),
                "significance": "HIGH",
                "reason": f"Executable {p.suffix} in AppData location",
            })

        try:
            raw = p.read_bytes()
        except OSError as e:
            return {"status": "error", "error": str(e), "file": artifact_path}

        # Try to extract strings from binary or read as text
        if b'\x00' in raw[:256]:
            strings = _extract_strings_from_bytes(raw)
            urls = [s for s in strings if s.startswith(('http://', 'https://', 'ftp://'))]
            findings = [{
                "type": "appdata_binary",
                "file": artifact_path,
                "size_bytes": len(raw),
                "urls_found": urls[:20],
                "indicators": indicators,
            }]
            summary = f"AppData binary {p.name}: {len(raw)} bytes, {len(urls)} URLs, {len(indicators)} indicators"
        else:
            try:
                text = raw.decode("utf-8", errors="replace")
            except Exception:
                text = raw.decode("latin-1", errors="replace")
            urls = re.findall(r'https?://[^\s"\'<>]{10,300}', text)
            # Check for persistence patterns in text files
            for line in text.splitlines()[:200]:
                if re.search(r'(?:HKCU|HKLM|Software\\Microsoft\\Windows\\CurrentVersion\\Run)', line, re.IGNORECASE):
                    indicators.append({"type": "registry_run_reference", "line": line.strip()[:200]})
            findings = [{
                "type": "appdata_text",
                "file": artifact_path,
                "size_bytes": len(raw),
                "urls_found": urls[:20],
                "indicators": indicators,
            }]
            summary = f"AppData {p.name}: {len(text.splitlines())} lines, {len(urls)} URLs, {len(indicators)} indicators"

        result = {"status": "success", "findings": findings, "summary": summary, "file": artifact_path}
        self._session_findings.extend(findings)
        return result

    # ------------------------------------------------------------------
    # Browser profiles
    # ------------------------------------------------------------------

    def analyze_browser_profile(self, profile_path: str) -> dict:
        p = Path(profile_path)
        name_lower = p.name.lower()
        if name_lower not in _BROWSER_PROFILE_NAMES:
            return {"status": "skipped", "reason": "not a recognized browser profile file", "file": profile_path}

        findings = []

        # SQLite-based browser files
        if p.suffix.lower() in (".sqlite", ".db") or name_lower in (
            "history", "login data", "cookies", "web data",
        ):
            findings = _parse_browser_sqlite(profile_path)

        # Firefox logins.json
        elif name_lower == "logins.json":
            findings = _parse_logins_json(profile_path)

        # Chrome bookmarks JSON
        elif name_lower == "bookmarks":
            findings = _parse_chrome_bookmarks(profile_path)

        else:
            findings = [{"type": "browser_artifact", "file": profile_path, "name": p.name}]

        browser = _detect_browser(profile_path)
        summary = f"Browser profile ({browser}) {p.name}: {len(findings)} items"

        result = {"status": "success", "findings": findings, "summary": summary, "file": profile_path}
        self._session_findings.extend(findings)
        return result

    # ------------------------------------------------------------------
    # Aggregate
    # ------------------------------------------------------------------

    def aggregate_findings(self, output_path: str) -> dict:
        """Aggregate all session findings into a structured JSON report."""
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)

        by_type: dict = {}
        for f in self._session_findings:
            ftype = f.get("type", "unknown")
            by_type.setdefault(ftype, []).append(f)

        # Count high-significance items
        high_sig = sum(
            1 for f in self._session_findings
            if "HIGH" in str(f.get("significance", ""))
               or any("HIGH" in str(i.get("significance", "")) for i in f.get("indicators", []))
        )

        report = {
            "playbook": "PB-SIFT-042",
            "playbook_name": "Stray Windows User Artifact Analysis",
            "generated_at": datetime.now().isoformat(),
            "total_findings": len(self._session_findings),
            "high_significance_items": high_sig,
            "findings_by_type": {k: len(v) for k, v in by_type.items()},
            "findings": self._session_findings,
        }

        try:
            out.write_text(json.dumps(report, default=str, indent=2))
        except OSError as e:
            return {"status": "error", "error": f"write failed: {e}"}

        return {
            "status": "success",
            "output_path": output_path,
            "total_findings": len(self._session_findings),
            "high_significance_items": high_sig,
            "summary": (f"PB-SIFT-042: {len(self._session_findings)} findings, "
                        f"{high_sig} high-significance → {output_path}"),
        }


# ---------------------------------------------------------------------------
# NTUSER.DAT parsers
# ---------------------------------------------------------------------------

def _parse_ntuser_python_registry(hive_path: str) -> list:
    """Parse NTUSER.DAT using python-registry."""
    try:
        from Registry import Registry
    except ImportError:
        return _parse_ntuser_strings(hive_path)

    findings = []
    try:
        reg = Registry.Registry(hive_path)

        # Run keys
        for key_path in _RUN_KEYS:
            try:
                key = reg.open(key_path)
                for val in key.values():
                    findings.append({
                        "type": "run_key",
                        "key": key_path,
                        "name": val.name(),
                        "value": str(val.value())[:500],
                        "significance": "HIGH",
                    })
            except Exception:
                pass

        # RecentDocs
        try:
            recent = reg.open("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs")
            for val in recent.values():
                try:
                    raw = val.value()
                    if isinstance(raw, bytes):
                        # RecentDocs values are binary with embedded filename
                        text = raw.decode("utf-16-le", errors="replace").split("\x00")[0]
                        findings.append({
                            "type": "recent_doc",
                            "name": val.name(),
                            "filename": text[:200],
                        })
                except Exception:
                    pass
        except Exception:
            pass

        # TypedURLs
        try:
            typed = reg.open("Software\\Microsoft\\Internet Explorer\\TypedURLs")
            for val in typed.values():
                findings.append({
                    "type": "typed_url",
                    "name": val.name(),
                    "url": str(val.value())[:500],
                })
        except Exception:
            pass

        # MRU lists (ComDlg32 OpenSaveMRU)
        try:
            mru = reg.open("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSaveMRU")
            for sub in mru.subkeys():
                for val in sub.values():
                    if val.name() != "MRUList":
                        findings.append({
                            "type": "open_save_mru",
                            "extension": sub.name(),
                            "path": str(val.value())[:300],
                        })
        except Exception:
            pass

    except Exception as e:
        findings.append({"type": "parse_error", "error": str(e), "file": hive_path})

    return findings


def _parse_ntuser_hivexregedit(hive_path: str) -> list:
    """Parse NTUSER.DAT using hivexregedit --export."""
    findings = []
    try:
        result = subprocess.run(
            ["hivexregedit", "--export", hive_path,
             "HKEY_USERS\\ROOT\\Software\\Microsoft\\Windows\\CurrentVersion"],
            capture_output=True, text=True, timeout=30, errors="replace"
        )
        text = result.stdout

        # Parse .reg format: "Name"="Value" or "Name"=dword:XXXXXXXX
        current_key = ""
        for line in text.splitlines():
            if line.startswith("["):
                current_key = line.strip("[]")
            elif "=" in line and not line.startswith(";"):
                m = re.match(r'"([^"]+)"\s*=\s*"([^"]*)"', line)
                if m:
                    if "Run" in current_key:
                        findings.append({
                            "type": "run_key",
                            "key": current_key,
                            "name": m.group(1),
                            "value": m.group(2)[:400],
                            "significance": "HIGH",
                        })
                    elif "TypedURL" in current_key:
                        findings.append({
                            "type": "typed_url",
                            "name": m.group(1),
                            "url": m.group(2)[:400],
                        })
    except Exception as e:
        findings.append({"type": "parse_error", "error": f"hivexregedit: {e}", "file": hive_path})
    return findings


def _parse_ntuser_hivexsh(hive_path: str) -> list:
    """Parse NTUSER.DAT using hivexsh with a script."""
    findings = []
    script = "ls\n"
    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.hivexsh', delete=False) as f:
            f.write(script)
            script_path = f.name
        result = subprocess.run(
            ["hivexsh", hive_path],
            input=script, capture_output=True, text=True, timeout=30
        )
        os.unlink(script_path)
        if result.stdout:
            findings.append({"type": "hive_listing", "output": result.stdout[:2000]})
    except Exception as e:
        findings.append({"type": "parse_error", "error": f"hivexsh: {e}", "file": hive_path})
    return findings


def _parse_ntuser_strings(hive_path: str) -> list:
    """Fallback: extract readable strings from NTUSER.DAT binary."""
    findings = []
    try:
        raw = Path(hive_path).read_bytes()
        strings = _extract_strings_from_bytes(raw, min_len=8)

        # Look for run key values, URLs, paths
        for s in strings:
            if re.search(r'(?:\.exe|\.bat|\.cmd|\.ps1|\.vbs)\b', s, re.IGNORECASE):
                findings.append({
                    "type": "executable_string",
                    "value": s[:300],
                    "note": "extracted from hive binary via strings",
                })
            elif s.startswith(('http://', 'https://', 'ftp://')):
                findings.append({
                    "type": "url_string",
                    "value": s[:300],
                })
            elif re.search(r'^[A-Za-z]:\\', s):
                findings.append({
                    "type": "windows_path",
                    "value": s[:300],
                })

        findings.append({
            "type": "parse_note",
            "note": "No registry parsing tools available (python-registry, hivexregedit, hivexsh). "
                    "Install with: pip install python-registry or apt install hivex-tools",
        })
    except Exception as e:
        findings.append({"type": "parse_error", "error": str(e)})
    return findings


# ---------------------------------------------------------------------------
# Prefetch parser
# ---------------------------------------------------------------------------

def _filetime_to_iso(data: bytes, offset: int) -> str:
    """Convert 8-byte FILETIME at offset to ISO datetime string."""
    if offset + 8 > len(data):
        return ""
    try:
        ft = struct.unpack_from("<Q", data, offset)[0]
        if ft == 0:
            return ""
        dt = _FILETIME_EPOCH + timedelta(microseconds=ft // 10)
        return dt.isoformat()
    except Exception:
        return ""


def _parse_prefetch_binary(path: str) -> dict:
    """Parse a Windows Prefetch .pf file."""
    try:
        data = Path(path).read_bytes()
    except OSError as e:
        return {"error": str(e)}

    if len(data) < 84:
        return {"note": "file too small to parse", "raw_strings": _extract_strings_from_bytes(data)}

    # Win10+ MAM compressed
    if data[:4] == b'MAM\x04':
        strings = _extract_strings_from_bytes(data)
        # Extract exe name from filename stem: NOTEPAD.EXE-AB12CD34.pf
        p = Path(path)
        exe_name = p.stem.split('-')[0] if '-' in p.stem else p.stem
        return {
            "format": "win10_mam_compressed",
            "exe_name_from_filename": exe_name,
            "note": "MAM-compressed format; decompression not implemented — extracted strings below",
            "strings_sample": strings[:20],
        }

    version = struct.unpack_from("<I", data, 0)[0]
    sig = data[4:8]
    if sig != b'SCCA':
        strings = _extract_strings_from_bytes(data)
        return {"note": "unrecognised prefetch format", "strings_sample": strings[:20]}

    # Executable name at offset 16 (60 bytes, UTF-16-LE)
    try:
        exe_raw = data[16:76]
        exe_name = exe_raw.decode("utf-16-le", errors="replace").split("\x00")[0]
    except Exception:
        exe_name = ""

    # Run count and last run time offsets differ by version
    if version == 17:    # WinXP
        run_count_off, lrt_off = 0x90, 0x78
    elif version == 23:  # Vista/7
        run_count_off, lrt_off = 0x98, 0x80
    elif version == 26:  # Win8.1
        run_count_off, lrt_off = 0x98, 0x80
    else:                # Unknown/Win8
        run_count_off, lrt_off = 0x98, 0x80

    try:
        run_count = struct.unpack_from("<I", data, run_count_off)[0] if run_count_off + 4 <= len(data) else 0
    except Exception:
        run_count = 0

    last_run = _filetime_to_iso(data, lrt_off)

    # Collect referenced files (file strings section)
    file_refs = []
    try:
        # File strings section offset and length at 0x64/0x68 (version 17) or 0x6C/0x70
        str_off_off = 0x64 if version == 17 else 0x6C
        str_len_off = str_off_off + 4
        if str_off_off + 8 <= len(data):
            str_section_off = struct.unpack_from("<I", data, str_off_off)[0]
            str_section_len = struct.unpack_from("<I", data, str_len_off)[0]
            if str_section_off and str_section_len and str_section_off + str_section_len <= len(data):
                raw_str = data[str_section_off:str_section_off + str_section_len]
                decoded = raw_str.decode("utf-16-le", errors="replace")
                file_refs = [s for s in decoded.split("\x00") if s and len(s) > 3][:40]
    except Exception:
        pass

    return {
        "version": version,
        "exe_name": exe_name,
        "run_count": run_count,
        "last_run_time": last_run,
        "file_references": file_refs,
    }


# ---------------------------------------------------------------------------
# LNK parser
# ---------------------------------------------------------------------------

_LNK_MAGIC = b'\x4C\x00\x00\x00'
_LNK_CLSID = b'\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46'


def _parse_lnk_binary(path: str) -> dict:
    """Parse a Windows LNK shell link file (Shell Link Binary File Format)."""
    try:
        data = Path(path).read_bytes()
    except OSError as e:
        return {"error": str(e)}

    if len(data) < 76 or data[:4] != _LNK_MAGIC:
        strings = _extract_strings_from_bytes(data, min_len=6)
        # Extract paths from strings
        paths = [s for s in strings if re.search(r'^[A-Za-z]:\\|^\\\\', s)]
        return {"note": "not a standard LNK or truncated", "paths_from_strings": paths[:10]}

    try:
        # Header fields
        link_flags = struct.unpack_from("<I", data, 20)[0]
        file_attrs = struct.unpack_from("<I", data, 24)[0]
        ctime = _filetime_to_iso(data, 28)
        atime = _filetime_to_iso(data, 36)
        mtime = _filetime_to_iso(data, 44)
        file_size_target = struct.unpack_from("<I", data, 52)[0]
        show_cmd = struct.unpack_from("<I", data, 60)[0]

        offset = 76  # after header

        # HasLinkTargetIDList flag (bit 0)
        if link_flags & 0x01:
            id_list_size = struct.unpack_from("<H", data, offset)[0]
            offset += 2 + id_list_size

        # HasLinkInfo flag (bit 1)
        local_base_path = ""
        net_name = ""
        if (link_flags & 0x02) and offset + 4 <= len(data):
            li_size = struct.unpack_from("<I", data, offset)[0]
            li_flags = struct.unpack_from("<I", data, offset + 4)[0]
            volume_id_off = struct.unpack_from("<I", data, offset + 8)[0]
            local_base_off = struct.unpack_from("<I", data, offset + 12)[0]
            net_share_off = struct.unpack_from("<I", data, offset + 16)[0]
            common_path_suffix_off = struct.unpack_from("<I", data, offset + 20)[0]

            if li_flags & 0x01 and offset + local_base_off < len(data):
                # VolumeIDAndLocalBasePath
                end = data.find(b'\x00', offset + local_base_off)
                local_base_path = data[offset + local_base_off:end].decode("latin-1", errors="replace")

            if li_flags & 0x02 and offset + net_share_off < len(data):
                # CommonNetworkRelativeLinkAndPathSuffix
                nrl_header_size = struct.unpack_from("<I", data, offset + net_share_off)[0]
                net_name_off = struct.unpack_from("<I", data, offset + net_share_off + 8)[0]
                end = data.find(b'\x00', offset + net_share_off + net_name_off)
                net_name = data[offset + net_share_off + net_name_off:end].decode("latin-1", errors="replace")

            offset += li_size

        target_path = local_base_path or net_name or ""

        # StringData: relative path, working dir, command line args, icon path
        relative_path = ""
        working_dir = ""
        cmd_args = ""
        if offset < len(data):
            try:
                for flag_bit, field_name in [
                    (0x04, "relative_path"), (0x08, "working_dir"),
                    (0x10, "cmd_args"), (0x20, "icon_location"),
                ]:
                    if (link_flags & flag_bit) and offset + 2 <= len(data):
                        count_chars = struct.unpack_from("<H", data, offset)[0]
                        offset += 2
                        if offset + count_chars * 2 <= len(data):
                            s = data[offset:offset + count_chars * 2].decode("utf-16-le", errors="replace")
                            if field_name == "relative_path":
                                relative_path = s
                            elif field_name == "working_dir":
                                working_dir = s
                            elif field_name == "cmd_args":
                                cmd_args = s
                            offset += count_chars * 2
            except Exception:
                pass

        if not target_path and relative_path:
            target_path = relative_path

        return {
            "target_path": target_path[:400],
            "relative_path": relative_path[:300],
            "working_directory": working_dir[:300],
            "command_arguments": cmd_args[:300],
            "target_size_bytes": file_size_target,
            "creation_time": ctime,
            "access_time": atime,
            "write_time": mtime,
            "show_command": show_cmd,
            "is_directory": bool(file_attrs & 0x10),
        }

    except Exception as e:
        strings = _extract_strings_from_bytes(data, min_len=6)
        return {"note": f"parse error: {e}", "paths_from_strings": [s for s in strings if '\\' in s][:10]}


# ---------------------------------------------------------------------------
# Jump list extractor
# ---------------------------------------------------------------------------

def _extract_jumplist_items(path: str) -> list:
    """Extract path/URL items from a jump list using string extraction.

    Jump lists are OLE Compound Files containing embedded LNK entries.
    Full CFBF parsing is complex; we use string extraction as a pragmatic fallback.
    """
    try:
        data = Path(path).read_bytes()
    except OSError:
        return []

    items = []
    strings = _extract_strings_from_bytes(data, min_len=8)
    seen: set = set()
    for s in strings:
        if s in seen:
            continue
        seen.add(s)
        if re.search(r'^[A-Za-z]:\\|^\\\\[A-Za-z]', s):
            items.append({"type": "windows_path", "path": s[:400]})
        elif re.search(r'^https?://', s, re.IGNORECASE):
            items.append({"type": "url", "url": s[:400]})
        elif re.search(r'^[A-Za-z]:[/\\]|^/[A-Za-z]', s):
            items.append({"type": "path", "path": s[:400]})
    return items


# ---------------------------------------------------------------------------
# Browser profile parsers
# ---------------------------------------------------------------------------

def _parse_browser_sqlite(path: str) -> list:
    """Parse a Chrome/Edge/Firefox browser SQLite database."""
    p = Path(path)
    name_lower = p.name.lower()
    findings = []

    # Make a temp copy to avoid WAL lock issues
    try:
        tmp = tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False)
        tmp.write(p.read_bytes())
        tmp.close()
        db_path = tmp.name
    except OSError as e:
        return [{"type": "browser_error", "error": str(e)}]

    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=5)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        # Discover available tables
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row[0].lower(): row[0] for row in cur.fetchall()}

        if "urls" in tables:  # Chrome/Edge history
            cur.execute(f"SELECT url, title, visit_count, last_visit_time FROM {tables['urls']} ORDER BY last_visit_time DESC LIMIT 200")
            for row in cur.fetchall():
                findings.append({
                    "type": "browser_history_url",
                    "file": path,
                    "url": row[0][:400] if row[0] else "",
                    "title": row[1][:200] if row[1] else "",
                    "visit_count": row[2],
                    "last_visit": _chrome_time_to_iso(row[3]) if row[3] else "",
                })

        if "logins" in tables:  # Chrome Login Data
            cur.execute(f"SELECT origin_url, username_value, date_created, blacklisted_by_user FROM {tables['logins']} LIMIT 200")
            for row in cur.fetchall():
                findings.append({
                    "type": "browser_saved_login",
                    "file": path,
                    "url": row[0][:300] if row[0] else "",
                    "username": row[1][:200] if row[1] else "",
                    "blacklisted": bool(row[3]),
                    "note": "password encrypted by OS credential store",
                })

        if "cookies" in tables:  # Chrome/Edge cookies
            cur.execute(f"SELECT host_key, name, path, expires_utc FROM {tables['cookies']} LIMIT 500")
            for row in cur.fetchall():
                findings.append({
                    "type": "browser_cookie",
                    "file": path,
                    "host": row[0][:200] if row[0] else "",
                    "name": row[1][:100] if row[1] else "",
                    "path": row[2][:100] if row[2] else "",
                })

        if "moz_places" in tables:  # Firefox history
            cur.execute(f"SELECT url, title, visit_count, last_visit_date FROM {tables['moz_places']} ORDER BY last_visit_date DESC LIMIT 200")
            for row in cur.fetchall():
                findings.append({
                    "type": "firefox_history_url",
                    "file": path,
                    "url": row[0][:400] if row[0] else "",
                    "title": row[1][:200] if row[1] else "",
                    "visit_count": row[2],
                    "last_visit": _moz_time_to_iso(row[3]) if row[3] else "",
                })

        conn.close()
    except Exception as e:
        findings.append({"type": "sqlite_error", "error": str(e), "file": path})
    finally:
        try:
            os.unlink(db_path)
        except Exception:
            pass

    return findings


def _parse_logins_json(path: str) -> list:
    """Parse Firefox logins.json saved credentials."""
    try:
        data = json.loads(Path(path).read_bytes())
    except Exception as e:
        return [{"type": "parse_error", "error": str(e), "file": path}]
    findings = []
    for login in data.get("logins", []):
        findings.append({
            "type": "firefox_saved_login",
            "file": path,
            "hostname": login.get("hostname", "")[:300],
            "username_field": login.get("usernameField", ""),
            "username_encrypted": str(login.get("encryptedUsername", ""))[:80],
            "time_created": _moz_time_to_iso(login.get("timeCreated", 0) * 1000),
            "time_last_used": _moz_time_to_iso(login.get("timeLastUsed", 0) * 1000),
        })
    return findings


def _parse_chrome_bookmarks(path: str) -> list:
    """Parse Chrome/Edge bookmarks JSON."""
    try:
        data = json.loads(Path(path).read_bytes())
    except Exception as e:
        return [{"type": "parse_error", "error": str(e), "file": path}]
    findings = []

    def _walk(node):
        if not isinstance(node, dict):
            return
        if node.get("type") == "url":
            findings.append({
                "type": "chrome_bookmark",
                "file": path,
                "url": node.get("url", "")[:400],
                "name": node.get("name", "")[:200],
            })
        for child in node.get("children", []):
            _walk(child)

    for root in data.get("roots", {}).values():
        _walk(root)
    return findings


# ---------------------------------------------------------------------------
# Time helpers
# ---------------------------------------------------------------------------

def _chrome_time_to_iso(chrome_time: int) -> str:
    """Convert Chrome's microseconds-since-1601 to ISO string."""
    if not chrome_time:
        return ""
    try:
        dt = _FILETIME_EPOCH + timedelta(microseconds=chrome_time)
        return dt.isoformat()
    except Exception:
        return ""


def _moz_time_to_iso(moz_time) -> str:
    """Convert Mozilla's microseconds-since-Unix-epoch to ISO string."""
    if not moz_time:
        return ""
    try:
        dt = datetime.utcfromtimestamp(int(moz_time) / 1_000_000)
        return dt.isoformat()
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------

def _extract_strings_from_bytes(data: bytes, min_len: int = 6) -> list:
    """Extract printable ASCII strings from binary data."""
    pattern = re.compile(rb'[ -~]{' + str(min_len).encode() + rb',}')
    return [m.group(0).decode("ascii", errors="replace") for m in pattern.finditer(data)]


def _detect_browser(profile_path: str) -> str:
    """Heuristically detect browser from path."""
    path_lower = profile_path.lower().replace("\\", "/")
    if "firefox" in path_lower or "mozilla" in path_lower:
        return "Firefox"
    if "chrome" in path_lower:
        return "Chrome"
    if "edge" in path_lower or "microsoftedge" in path_lower:
        return "Edge"
    if "opera" in path_lower:
        return "Opera"
    return "unknown"
