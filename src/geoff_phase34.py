#!/usr/bin/env python3
"""Geoff DFIR — Phase 3+4 analysis module.

Extracted from geoff_discovery.py to reduce monolith size.

Contains:
  Phase 3+4 correlation functions (A013-A020):
    detect_campaign_patterns, analyze_negative_space, parse_recycle_bin,
    find_imapi_burn_logs, check_vss_auto_mount, find_windows_edb_paths,
    handle_unprocessed_files, cross_device_timeline_stub

  New extended analysis functions:
    parse_windows_event_logs  — EVTX / Event Log parsing (A021)
    analyze_registry_persistence — Registry persistence analysis (A022)
    generate_body_file        — Sleuth Kit MAC body file + CSV output (A023)
"""

import csv
import json
import os
import shutil
import struct
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from geoff_utils import (
    _fe_log,
    _ckpt_phase_done,
    _ckpt_mark_phase,
    _ckpt_save,
)


# ---------------------------------------------------------------------------
# A013 — Campaign temporal correlation
# ---------------------------------------------------------------------------

def detect_campaign_patterns(
    findings: list,
    indicator_hits: list,
    device_map: dict = None,
    job_id: str = None,
    case_work_dir: str = None,
    ckpt: dict = None,
) -> dict:
    """A013 — Campaign temporal correlation."""
    result = {
        "campaign_detected": False,
        "multi_day_patterns": [],
        "off_hours_clusters": [],
        "tool_chains": [],
        "campaign_summary": "",
    }

    if ckpt and _ckpt_phase_done(ckpt, "campaign_patterns"):
        _fe_log(job_id, "  [CKPT] Skipping campaign pattern detection — loaded from checkpoint")
        saved_path = Path(case_work_dir) / "checkpoint_campaign.json" if case_work_dir else None
        if saved_path and saved_path.exists():
            try:
                return json.loads(saved_path.read_text())
            except Exception:
                pass
        return result

    try:
        all_timestamps = []

        for hit in indicator_hits or []:
            if isinstance(hit, dict):
                ts = hit.get("timestamp", "") or hit.get("matched_in", "")
                if ts:
                    all_timestamps.append(ts)

        for f in findings or []:
            if not isinstance(f, dict):
                continue
            if f.get("status") in ("completed", "passed"):
                ts = f.get("completed_at") or f.get("started_at", "")
                if ts:
                    all_timestamps.append(ts)
                result_data = f.get("result", {})
                if isinstance(result_data, dict):
                    for ts_key in ("timestamp", "event_time", "created_time", "modified_time", "access_time"):
                        sub_ts = result_data.get(ts_key, "")
                        if sub_ts and isinstance(sub_ts, str):
                            all_timestamps.append(sub_ts)

        if not all_timestamps:
            _fe_log(job_id, "  [CAMPAIGN] No timestamps available for correlation")
            if ckpt and case_work_dir:
                _ckpt_mark_phase(ckpt, "campaign_patterns", "complete")
                _ckpt_save(Path(case_work_dir), ckpt)
            return result

        parsed_dates = []
        for ts in all_timestamps:
            for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d",
                        "%m/%d/%Y %H:%M:%S", "%m/%d/%Y", "%Y/%m/%d %H:%M:%S"):
                try:
                    parsed_dates.append(datetime.strptime(ts[:19], fmt))
                    break
                except (ValueError, IndexError):
                    continue

        if not parsed_dates:
            _fe_log(job_id, "  [CAMPAIGN] Could not parse any timestamps")
            if ckpt and case_work_dir:
                _ckpt_mark_phase(ckpt, "campaign_patterns", "complete")
                _ckpt_save(Path(case_work_dir), ckpt)
            return result

        parsed_dates.sort()

        unique_days = sorted(set(d.date() for d in parsed_dates))
        if len(unique_days) >= 2:
            day_spans = []
            for i in range(len(unique_days) - 1):
                span = (unique_days[i + 1] - unique_days[i]).days
                if span <= 2:
                    day_spans.append({
                        "start": unique_days[i].isoformat(),
                        "end": unique_days[i + 1].isoformat(),
                        "gap_days": span,
                    })
            if day_spans:
                merged = [day_spans[0]]
                for span in day_spans[1:]:
                    last = merged[-1]
                    if (datetime.fromisoformat(span["start"]) -
                            datetime.fromisoformat(last["end"])).days <= 2:
                        last["end"] = span["end"]
                    else:
                        merged.append(span)
                result["multi_day_patterns"] = merged
                result["campaign_detected"] = True
                _fe_log(job_id, f"  [CAMPAIGN] Multi-day activity: {len(merged)} window(s) across {len(unique_days)} unique days")

        off_hours = []
        for d in parsed_dates:
            hour = d.hour
            if hour < 6 or hour >= 22:
                off_hours.append(d.isoformat())
        if off_hours:
            result["off_hours_clusters"] = [{
                "count": len(off_hours),
                "first": off_hours[0],
                "last": off_hours[-1],
                "ratio": round(len(off_hours) / len(parsed_dates), 3),
            }]
            result["campaign_detected"] = True
            _fe_log(job_id, f"  [CAMPAIGN] Off-hours activity: {len(off_hours)}/{len(parsed_dates)} events outside 06:00-22:00")

        tool_chain_modules = ["volatility", "registry", "scheduled", "network", "sleuthkit", "email", "jumplist"]
        seen_chains = []
        for f in findings or []:
            if not isinstance(f, dict):
                continue
            mod = f.get("module", "").lower().strip()
            func = f.get("function", "").lower().strip()
            if mod in tool_chain_modules and f.get("status") == "completed":
                seen_chains.append(f"{mod}.{func}")
        if seen_chains:
            result["tool_chains"] = [{
                "modules_used": list(dict.fromkeys(seen_chains)),
                "chain_count": len(seen_chains),
            }]
            result["campaign_detected"] = True
            _fe_log(job_id, f"  [CAMPAIGN] Tool chain: {len(dict.fromkeys(seen_chains))} distinct module/function types used")

        parts = []
        if result["multi_day_patterns"]:
            parts.append(f"{len(result['multi_day_patterns'])} multi-day window(s)")
        if result["off_hours_clusters"]:
            parts.append(f"{result['off_hours_clusters'][0]['count']} off-hours events")
        if result["tool_chains"]:
            parts.append(f"{result['tool_chains'][0]['chain_count']} tool-chain steps")
        result["campaign_summary"] = "; ".join(parts) if parts else "No campaign patterns detected"

        _fe_log(job_id, f"  [CAMPAIGN] Summary: {result['campaign_summary']}")

    except Exception as e:
        _fe_log(job_id, f"  [CAMPAIGN] Error during detection (non-fatal): {e}")
        result["campaign_summary"] = f"Error: {e}"

    if ckpt and case_work_dir:
        saved_path = Path(case_work_dir) / "checkpoint_campaign.json"
        try:
            saved_path.write_text(json.dumps(result, default=str))
            _ckpt_mark_phase(ckpt, "campaign_patterns", "complete")
            _ckpt_save(Path(case_work_dir), ckpt)
        except Exception:
            pass

    return result


# ---------------------------------------------------------------------------
# A014 — Negative space analysis
# ---------------------------------------------------------------------------

def analyze_negative_space(
    device_map: dict,
    mount_points: list = None,
    job_id: str = None,
    case_work_dir: str = None,
    ckpt: dict = None,
) -> dict:
    """A014 — Negative space analysis."""
    result = {
        "negative_space_detected": False,
        "missing_vss": [],
        "cleared_logs": [],
        "missing_artifacts": [],
        "timeline_gaps": [],
        "negative_space_summary": "",
    }

    if ckpt and _ckpt_phase_done(ckpt, "negative_space"):
        _fe_log(job_id, "  [CKPT] Skipping negative space analysis — loaded from checkpoint")
        saved_path = Path(case_work_dir) / "checkpoint_negative_space.json" if case_work_dir else None
        if saved_path and saved_path.exists():
            try:
                return json.loads(saved_path.read_text())
            except Exception:
                pass
        return result

    if ckpt and case_work_dir:
        _ckpt_mark_phase(ckpt, "negative_space", "running")
        _ckpt_save(Path(case_work_dir), ckpt)

    try:
        mounts = mount_points or []

        for mp in mounts:
            mp = str(mp)
            system32 = None
            for root_dir in ["Windows", "WINNT", "winnt"]:
                candidate = os.path.join(mp, root_dir, "System32")
                if os.path.isdir(candidate):
                    system32 = candidate
                    break

            if system32 and os.path.isdir(system32):
                vss_tools = False
                for vss_exe in ["vssadmin.exe", "diskshadow.exe", "vssvc.exe"]:
                    if os.path.isfile(os.path.join(system32, vss_exe)):
                        vss_tools = True
                        break
                if not vss_tools:
                    result["missing_vss"].append({
                        "mount_point": mp,
                        "reason": "VSS management tools not found (vssadmin/diskshadow missing)",
                        "severity": "HIGH",
                    })
                    result["negative_space_detected"] = True

            vss_dir = os.path.join(mp, "System Volume Information")
            if os.path.isdir(vss_dir):
                try:
                    vss_contents = os.listdir(vss_dir)
                    vss_files = [f for f in vss_contents if f.startswith("{") or f.endswith(".vss")]
                    if not vss_files:
                        result["missing_vss"].append({
                            "mount_point": mp,
                            "reason": "System Volume Information exists but no VSS snapshots present",
                            "severity": "MEDIUM",
                        })
                        result["negative_space_detected"] = True
                except (PermissionError, OSError):
                    pass

        for mp in mounts:
            mp = str(mp)
            for evtx_dir in ["Windows/System32/winevt/Logs", "Windows/System32/config"]:
                log_path = os.path.join(mp, evtx_dir)
                if not os.path.isdir(log_path):
                    continue

                try:
                    evtx_files = [f for f in os.listdir(log_path) if f.endswith(".evtx") or f.endswith(".evt")]
                except (PermissionError, OSError):
                    continue
                if len(evtx_files) == 0:
                    result["cleared_logs"].append({
                        "path": log_path,
                        "reason": "No event log files found (possible wevtutil cl)",
                        "severity": "CRITICAL",
                        "file_count": 0,
                    })
                    result["negative_space_detected"] = True
                elif len(evtx_files) <= 3:
                    result["cleared_logs"].append({
                        "path": log_path,
                        "reason": f"Only {len(evtx_files)} event log files — abnormally low count",
                        "severity": "HIGH",
                        "file_count": len(evtx_files),
                    })
                    result["negative_space_detected"] = True

                sec_paths = [f for f in evtx_files if "security" in f.lower() or "secevent" in f.lower()]
                for sf in sec_paths:
                    full_path = os.path.join(log_path, sf)
                    try:
                        size_kb = os.path.getsize(full_path) / 1024
                        if size_kb < 64:
                            result["cleared_logs"].append({
                                "path": full_path,
                                "reason": f"Security log only {size_kb:.0f}KB — likely cleared",
                                "severity": "HIGH",
                                "size_kb": round(size_kb, 1),
                            })
                            result["negative_space_detected"] = True
                    except OSError:
                        pass

        expected_artifact_patterns = {
            "Prefetch": ["Windows/Prefetch/*.pf", "Windows/Prefetch"],
            "Amcache": ["Windows/appcompat/Programs/Amcache.hve", "Windows/appcompat/Programs"],
            "SRUM": ["Windows/System32/sru/SRUDB.dat", "Windows/System32/sru"],
            "RecentFileCache": ["Windows/System32/RecentFileCache.bcf"],
            "Jumplist": ["Users/*/AppData/Roaming/Microsoft/Windows/Recent/*.automaticDestinations-ms"],
        }

        for art_name, art_patterns in expected_artifact_patterns.items():
            for mp in mounts:
                mp = str(mp)
                found = False
                for pattern in art_patterns:
                    if "*" in pattern or "?" in pattern:
                        try:
                            matches = list(Path(mp).glob(pattern))
                            if matches:
                                found = True
                                break
                        except (PermissionError, OSError):
                            continue
                    else:
                        dir_path = Path(mp) / pattern
                        if dir_path.is_dir():
                            try:
                                contents = list(dir_path.iterdir())
                                if len(contents) >= 2:
                                    found = True
                                    break
                            except (PermissionError, OSError):
                                continue
                        elif dir_path.exists():
                            found = True
                            break
                if not found:
                    result["missing_artifacts"].append({
                        "artifact": art_name,
                        "mount_point": mp,
                        "reason": f"{art_name} not found — possible anti-forensics",
                        "severity": "MEDIUM",
                    })
                    result["negative_space_detected"] = True

        for mp in mounts:
            mp = str(mp)
            evtx_path = os.path.join(mp, "Windows/System32/winevt/Logs")
            if not os.path.isdir(evtx_path):
                continue
            try:
                evtx_files = [f for f in os.listdir(evtx_path) if f.endswith(".evtx")]
            except (PermissionError, OSError):
                continue
            if len(evtx_files) >= 5:
                result["timeline_gaps"].append({
                    "mount_point": mp,
                    "event_log_count": len(evtx_files),
                    "note": "Timeline gap analysis limited — full timeline evidence review recommended",
                    "severity": "INFO",
                })

        parts = []
        if result["missing_vss"]:
            parts.append(f"{len(result['missing_vss'])} VSS anomalies")
        if result["cleared_logs"]:
            parts.append(f"{len(result['cleared_logs'])} log anomalies")
        if result["missing_artifacts"]:
            parts.append(f"{len(result['missing_artifacts'])} missing artifacts")
        result["negative_space_summary"] = "; ".join(parts) if parts else "No negative space anomalies detected"

        _fe_log(job_id, f"  [NEG-SPACE] {result['negative_space_summary']}")

    except Exception as e:
        _fe_log(job_id, f"  [NEG-SPACE] Error during analysis (non-fatal): {e}")
        result["negative_space_summary"] = f"Error: {e}"

    if ckpt and case_work_dir:
        saved_path = Path(case_work_dir) / "checkpoint_negative_space.json"
        try:
            saved_path.write_text(json.dumps(result, default=str))
            _ckpt_mark_phase(ckpt, "negative_space", "complete")
            _ckpt_save(Path(case_work_dir), ckpt)
        except Exception:
            pass

    return result


# ---------------------------------------------------------------------------
# A015 — Recycle Bin $I/$R parser
# ---------------------------------------------------------------------------

def parse_recycle_bin(
    mount_points: list,
    job_id: str = None,
    case_work_dir: str = None,
    ckpt: dict = None,
) -> dict:
    """A015 — Recycle Bin $I / $R parser."""
    result = {
        "recycle_bin_found": False,
        "deleted_files": [],
        "total_deleted": 0,
        "suspicious_deletions": [],
    }

    if ckpt and _ckpt_phase_done(ckpt, "recycle_bin"):
        _fe_log(job_id, "  [CKPT] Skipping recycle bin parsing — loaded from checkpoint")
        saved_path = Path(case_work_dir) / "checkpoint_recycle_bin.json" if case_work_dir else None
        if saved_path and saved_path.exists():
            try:
                return json.loads(saved_path.read_text())
            except Exception:
                pass
        return result

    if ckpt and case_work_dir:
        _ckpt_mark_phase(ckpt, "recycle_bin", "running")
        _ckpt_save(Path(case_work_dir), ckpt)

    try:
        suspicious_extensions = frozenset({".exe", ".dll", ".ps1", ".vbs", ".js", ".bat",
                                           ".scr", ".pif", ".hta", ".jar", ".docm", ".xlsm"})
        recycle_dirs_found = []

        for mp in mount_points:
            mp = str(mp)
            for rb_name in ("$Recycle.Bin", "$RECYCLE.BIN"):
                candidate = os.path.join(mp, rb_name)
                if os.path.isdir(candidate):
                    recycle_dirs_found.append(candidate)

        for recycle_dir in recycle_dirs_found:
            result["recycle_bin_found"] = True
            try:
                for sid_dir in os.listdir(recycle_dir):
                    sid_path = os.path.join(recycle_dir, sid_dir)
                    if not os.path.isdir(sid_path):
                        continue
                    for entry in os.listdir(sid_path):
                        if not entry.startswith("$I"):
                            continue
                        i_path = os.path.join(sid_path, entry)
                        r_path = os.path.join(sid_path, "$R" + entry[2:])
                        entry_info = {
                            "sid": sid_dir,
                            "i_file": i_path,
                            "r_file": r_path if os.path.exists(r_path) else None,
                            "i_file_size": 0,
                            "deleted_path": "",
                            "deleted_when": "",
                            "suspicious": False,
                        }
                        try:
                            entry_info["i_file_size"] = os.path.getsize(i_path)
                        except OSError:
                            pass

                        # $I binary format:
                        #   0-7:   version (uint64 LE)
                        #   8-15:  original file size (uint64 LE)
                        #   16-23: deletion FILETIME (uint64 LE)
                        #   24+:   v1 = null-terminated UTF-16LE; v2 = uint32 count + UTF-16LE
                        try:
                            with open(i_path, "rb") as fh:
                                data = fh.read()
                            if len(data) >= 24:
                                version = struct.unpack("<Q", data[0:8])[0]
                                ft = struct.unpack("<Q", data[16:24])[0]
                                if ft > 0:
                                    try:
                                        dt = datetime(1601, 1, 1) + timedelta(microseconds=ft // 10)
                                        entry_info["deleted_when"] = dt.isoformat()
                                    except (OverflowError, ValueError):
                                        pass
                                if version == 2 and len(data) >= 28:
                                    path_chars = struct.unpack("<I", data[24:28])[0]
                                    raw = data[28:28 + path_chars * 2]
                                    entry_info["deleted_path"] = raw.decode("utf-16-le", errors="replace").rstrip("\x00")
                                elif len(data) > 24:
                                    end = data.find(b"\x00\x00", 24)
                                    if end != -1 and (end - 24) % 2 != 0:
                                        end += 1
                                    raw = data[24:end] if end != -1 else data[24:]
                                    entry_info["deleted_path"] = raw.decode("utf-16-le", errors="replace").rstrip("\x00")
                        except (OSError, struct.error):
                            pass

                        ext = os.path.splitext(entry_info.get("deleted_path", entry))[1].lower()
                        if ext in suspicious_extensions:
                            entry_info["suspicious"] = True
                            result["suspicious_deletions"].append(entry_info)

                        result["deleted_files"].append(entry_info)

            except (PermissionError, OSError):
                continue

        result["total_deleted"] = len(result["deleted_files"])

        if result["total_deleted"] > 0:
            _fe_log(job_id, f"  [RECYCLE-BIN] Found {result['total_deleted']} deleted files across {len(recycle_dirs_found)} Recycle Bin dirs")
            if result["suspicious_deletions"]:
                _fe_log(job_id, f"  [RECYCLE-BIN] {len(result['suspicious_deletions'])} suspicious deletions (executables/scripts)")

    except Exception as e:
        _fe_log(job_id, f"  [RECYCLE-BIN] Error during parsing (non-fatal): {e}")

    if ckpt and case_work_dir:
        saved_path = Path(case_work_dir) / "checkpoint_recycle_bin.json"
        try:
            saved_path.write_text(json.dumps(result, default=str))
            _ckpt_mark_phase(ckpt, "recycle_bin", "complete")
            _ckpt_save(Path(case_work_dir), ckpt)
        except Exception:
            pass

    return result


# ---------------------------------------------------------------------------
# A016 — IMAPI burn log finder
# ---------------------------------------------------------------------------

def find_imapi_burn_logs(
    mount_points: list,
    job_id: str = None,
    case_work_dir: str = None,
    ckpt: dict = None,
) -> dict:
    """A016 — CD-R IMAPI burn log finder."""
    result = {
        "imapi_logs_found": False,
        "log_files": [],
        "total_burn_events": 0,
    }

    if ckpt and _ckpt_phase_done(ckpt, "imapi_burn_logs"):
        _fe_log(job_id, "  [CKPT] Skipping IMAPI burn log scan — loaded from checkpoint")
        saved_path = Path(case_work_dir) / "checkpoint_imapi.json" if case_work_dir else None
        if saved_path and saved_path.exists():
            try:
                return json.loads(saved_path.read_text())
            except Exception:
                pass
        return result

    if ckpt and case_work_dir:
        _ckpt_mark_phase(ckpt, "imapi_burn_logs", "running")
        _ckpt_save(Path(case_work_dir), ckpt)

    try:
        imapi_candidates = [
            "Windows/System32/imapi.log",
            "Windows/System32/imapiburn.log",
            "Windows/System32/IMAPI/imapi.log",
        ]

        for mp in mount_points:
            mp = str(mp)
            for rel_path in imapi_candidates:
                full_path = os.path.join(mp, rel_path)
                if not os.path.isfile(full_path):
                    continue
                result["imapi_logs_found"] = True
                log_info = {
                    "path": full_path,
                    "size": 0,
                    "line_count": 0,
                    "burn_events": [],
                }
                try:
                    log_info["size"] = os.path.getsize(full_path)
                    with open(full_path, "r", errors="replace") as fh:
                        lines = fh.readlines()
                    log_info["line_count"] = len(lines)
                    burn_keywords = ["burn", "write", "disc", "cd-r", "dvd", "recorder", "finalize"]
                    for line in lines:
                        if any(kw in line.lower() for kw in burn_keywords):
                            log_info["burn_events"].append(line.strip()[:200])
                except (PermissionError, OSError) as e:
                    log_info["error"] = str(e)

                result["log_files"].append(log_info)

            users_dir = os.path.join(mp, "Users")
            if os.path.isdir(users_dir):
                try:
                    for user_entry in os.listdir(users_dir):
                        burn_dir = os.path.join(users_dir, user_entry,
                                                "AppData", "Local", "Microsoft", "Windows", "Burn")
                        if os.path.isdir(burn_dir):
                            for _ in os.listdir(burn_dir):
                                result["total_burn_events"] += 1
                except (PermissionError, OSError):
                    pass

        if result["imapi_logs_found"]:
            total_events = sum(len(lf.get("burn_events", [])) for lf in result["log_files"])
            result["total_burn_events"] += total_events
            _fe_log(job_id, f"  [IMAPI] Found {len(result['log_files'])} burn log(s) with ~{result['total_burn_events']} events")

    except Exception as e:
        _fe_log(job_id, f"  [IMAPI] Error during scan (non-fatal): {e}")

    if ckpt and case_work_dir:
        saved_path = Path(case_work_dir) / "checkpoint_imapi.json"
        try:
            saved_path.write_text(json.dumps(result, default=str))
            _ckpt_mark_phase(ckpt, "imapi_burn_logs", "complete")
            _ckpt_save(Path(case_work_dir), ckpt)
        except Exception:
            pass

    return result


# ---------------------------------------------------------------------------
# A017 — VSS auto-mount checker
# ---------------------------------------------------------------------------

def check_vss_auto_mount(
    mount_points: list,
    job_id: str = None,
    case_work_dir: str = None,
    ckpt: dict = None,
) -> dict:
    """A017 — VSS auto-mount checker."""
    result = {
        "vss_available": False,
        "vss_snapshots_found": 0,
        "vss_mountable": False,
        "vss_scan_result": "",
    }

    if ckpt and _ckpt_phase_done(ckpt, "vss_auto_mount"):
        _fe_log(job_id, "  [CKPT] Skipping VSS auto-mount check — loaded from checkpoint")
        saved_path = Path(case_work_dir) / "checkpoint_vss_auto.json" if case_work_dir else None
        if saved_path and saved_path.exists():
            try:
                return json.loads(saved_path.read_text())
            except Exception:
                pass
        return result

    if ckpt and case_work_dir:
        _ckpt_mark_phase(ckpt, "vss_auto_mount", "running")
        _ckpt_save(Path(case_work_dir), ckpt)

    try:
        for mp in mount_points:
            mp = str(mp)
            svi_path = os.path.join(mp, "System Volume Information")
            if os.path.isdir(svi_path):
                result["vss_available"] = True
                try:
                    vss_entries = os.listdir(svi_path)
                    vss_snaps = [e for e in vss_entries
                                 if (e.startswith("{") and e.endswith("}")) or e.endswith(".vss")]
                    result["vss_snapshots_found"] = len(vss_snaps)
                except (PermissionError, OSError):
                    result["vss_snapshots_found"] = -1

            vshadow_path = shutil.which("vshadow") or shutil.which("vshadowmount")
            if vshadow_path:
                result["vss_mountable"] = True
                result["vss_scan_result"] = f"VSS tools available ({os.path.basename(vshadow_path)})"
            else:
                result["vss_scan_result"] = "VSS tools not available on analysis host"

        if result["vss_available"]:
            _fe_log(job_id, f"  [VSS-CHK] Shadow copies found: {result['vss_snapshots_found']}, mountable: {result['vss_mountable']}")
        else:
            _fe_log(job_id, "  [VSS-CHK] No VSS shadow copies detected")

    except Exception as e:
        _fe_log(job_id, f"  [VSS-CHK] Error during scan (non-fatal): {e}")

    if ckpt and case_work_dir:
        saved_path = Path(case_work_dir) / "checkpoint_vss_auto.json"
        try:
            saved_path.write_text(json.dumps(result, default=str))
            _ckpt_mark_phase(ckpt, "vss_auto_mount", "complete")
            _ckpt_save(Path(case_work_dir), ckpt)
        except Exception:
            pass

    return result


# ---------------------------------------------------------------------------
# A018 — Windows.edb path finder
# ---------------------------------------------------------------------------

def find_windows_edb_paths(
    mount_points: list,
    job_id: str = None,
    case_work_dir: str = None,
    ckpt: dict = None,
) -> dict:
    """A018 — Windows.edb search index path finder."""
    result = {
        "edb_found": False,
        "edb_paths": [],
        "edb_sizes": [],
    }

    if ckpt and _ckpt_phase_done(ckpt, "windows_edb"):
        _fe_log(job_id, "  [CKPT] Skipping Windows.edb scan — loaded from checkpoint")
        saved_path = Path(case_work_dir) / "checkpoint_edb.json" if case_work_dir else None
        if saved_path and saved_path.exists():
            try:
                return json.loads(saved_path.read_text())
            except Exception:
                pass
        return result

    if ckpt and case_work_dir:
        _ckpt_mark_phase(ckpt, "windows_edb", "running")
        _ckpt_save(Path(case_work_dir), ckpt)

    try:
        edb_patterns = [
            "ProgramData/Microsoft/Search/Data/Applications/Windows/Windows.edb",
            "ProgramData/Microsoft/Search/Data/Applications/Windows/windows.edb",
            "Users/*/AppData/Roaming/Microsoft/Search/Data/Applications/Windows/Windows.edb",
            "Windows/System32/config/Windows.edb",
        ]

        for mp in mount_points:
            mp = str(mp)
            for pattern in edb_patterns:
                if "*" in pattern:
                    try:
                        for match in Path(mp).glob(pattern):
                            edb_path = str(match)
                            result["edb_paths"].append(edb_path)
                            try:
                                size_mb = os.path.getsize(edb_path) / (1024 * 1024)
                            except OSError:
                                size_mb = 0
                            result["edb_sizes"].append({"path": edb_path, "size_mb": round(size_mb, 1)})
                    except (PermissionError, OSError):
                        continue
                else:
                    full_path = os.path.join(mp, pattern)
                    if os.path.isfile(full_path):
                        result["edb_paths"].append(full_path)
                        try:
                            size_mb = os.path.getsize(full_path) / (1024 * 1024)
                        except OSError:
                            size_mb = 0
                        result["edb_sizes"].append({"path": full_path, "size_mb": round(size_mb, 1)})

        if result["edb_paths"]:
            result["edb_found"] = True
            total_size = sum(s.get("size_mb", 0) for s in result["edb_sizes"])
            _fe_log(job_id, f"  [EDB] Found {len(result['edb_paths'])} Windows.edb file(s), ~{total_size:.0f}MB total")

    except Exception as e:
        _fe_log(job_id, f"  [EDB] Error during scan (non-fatal): {e}")

    if ckpt and case_work_dir:
        saved_path = Path(case_work_dir) / "checkpoint_edb.json"
        try:
            saved_path.write_text(json.dumps(result, default=str))
            _ckpt_mark_phase(ckpt, "windows_edb", "complete")
            _ckpt_save(Path(case_work_dir), ckpt)
        except Exception:
            pass

    return result


# ---------------------------------------------------------------------------
# A019 — Unprocessed files handler
# ---------------------------------------------------------------------------

def handle_unprocessed_files(
    inventory: dict,
    processed_paths: set,
    execution_plan: dict = None,
    job_id: str = None,
    case_work_dir: str = None,
    ckpt: dict = None,
) -> dict:
    """A019 — Unprocessed files handler."""
    result = {
        "total_unprocessed": 0,
        "unprocessed_by_category": {},
        "unprocessed_list": [],
        "summary": "",
    }

    if ckpt and _ckpt_phase_done(ckpt, "unprocessed_files"):
        _fe_log(job_id, "  [CKPT] Skipping unprocessed files handler — loaded from checkpoint")
        saved_path = Path(case_work_dir) / "checkpoint_unprocessed.json" if case_work_dir else None
        if saved_path and saved_path.exists():
            try:
                return json.loads(saved_path.read_text())
            except Exception:
                pass
        return result

    if ckpt and case_work_dir:
        _ckpt_mark_phase(ckpt, "unprocessed_files", "running")
        _ckpt_save(Path(case_work_dir), ckpt)

    try:
        from geoff_discovery import _all_inventory_paths
        all_inventory_paths = _all_inventory_paths(inventory)
        unprocessed = [p for p in all_inventory_paths if p not in processed_paths]

        result["total_unprocessed"] = len(unprocessed)

        for path in unprocessed:
            ext = os.path.splitext(path)[1].lower()
            if ext in (".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff"):
                reason = "media_file_not_dispatchable"
            elif ext in (".txt", ".log", ".cfg", ".ini", ".inf"):
                reason = "text_config_not_in_playbook"
            elif ext in (".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx"):
                reason = "office_document_not_in_playbook"
            elif ext in (".zip", ".rar", ".7z", ".tar", ".gz"):
                reason = "archive_not_extracted"
            elif ext in (".pf", ".db", ".dat", ".xml"):
                reason = "forensic_artifact_no_direct_handler"
            else:
                reason = "file_type_not_covered_by_playbooks"

            result["unprocessed_list"].append({"path": path, "reason": reason, "extension": ext})
            result["unprocessed_by_category"].setdefault(reason, []).append(path)

        parts = [f"{reason}: {len(paths)}" for reason, paths in result["unprocessed_by_category"].items()]
        result["summary"] = (
            f"{result['total_unprocessed']} unprocessed files ({'; '.join(parts)})"
            if parts else "All files processed"
        )
        _fe_log(job_id, f"  [UNPROC] {result['summary']}")

    except Exception as e:
        _fe_log(job_id, f"  [UNPROC] Error during analysis (non-fatal): {e}")
        result["summary"] = f"Error: {e}"

    if ckpt and case_work_dir:
        saved_path = Path(case_work_dir) / "checkpoint_unprocessed.json"
        try:
            saved_path.write_text(json.dumps(result, default=str))
            _ckpt_mark_phase(ckpt, "unprocessed_files", "complete")
            _ckpt_save(Path(case_work_dir), ckpt)
        except Exception:
            pass

    return result


# ---------------------------------------------------------------------------
# A020 — Cross-device timeline stub
# ---------------------------------------------------------------------------

def cross_device_timeline_stub(
    device_map: dict,
    findings: list,
    job_id: str = None,
    case_work_dir: str = None,
    ckpt: dict = None,
) -> dict:
    """A020 — Cross-device timeline stub."""
    result = {
        "devices_with_activity": 0,
        "device_time_ranges": [],
        "cross_device_events": [],
        "timeline_stub_note": "Cross-device timeline correlation not yet fully implemented",
    }

    if ckpt and _ckpt_phase_done(ckpt, "cross_device_timeline"):
        _fe_log(job_id, "  [CKPT] Skipping cross-device timeline — loaded from checkpoint")
        saved_path = Path(case_work_dir) / "checkpoint_xdevice_timeline.json" if case_work_dir else None
        if saved_path and saved_path.exists():
            try:
                return json.loads(saved_path.read_text())
            except Exception:
                pass
        return result

    if ckpt and case_work_dir:
        _ckpt_mark_phase(ckpt, "cross_device_timeline", "running")
        _ckpt_save(Path(case_work_dir), ckpt)

    try:
        if not device_map:
            _fe_log(job_id, "  [XDEV-TL] No device map available, skipping")
            if ckpt and case_work_dir:
                _ckpt_mark_phase(ckpt, "cross_device_timeline", "complete")
                _ckpt_save(Path(case_work_dir), ckpt)
            return result

        per_device_times = {}
        for f in findings or []:
            if not isinstance(f, dict):
                continue
            if f.get("status") not in ("completed", "passed"):
                continue
            dev = f.get("device_id", "unknown")
            ts = f.get("completed_at") or f.get("started_at", "")
            if ts:
                entry = per_device_times.setdefault(dev, {"timestamps": [], "count": 0})
                entry["timestamps"].append(ts)
                entry["count"] += 1

        result["devices_with_activity"] = len(per_device_times)

        for dev_id, data in per_device_times.items():
            parsed = []
            for ts in data["timestamps"]:
                for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
                    try:
                        parsed.append(datetime.strptime(ts[:19], fmt))
                        break
                    except (ValueError, IndexError):
                        continue
            if parsed:
                parsed.sort()
                result["device_time_ranges"].append({
                    "device_id": dev_id,
                    "first_event": parsed[0].isoformat(),
                    "last_event": parsed[-1].isoformat(),
                    "total_events": data["count"],
                    "span_hours": round((parsed[-1] - parsed[0]).total_seconds() / 3600, 1),
                })

        if len(per_device_times) >= 2:
            result["cross_device_events"] = [{
                "note": f"Activity detected across {len(per_device_times)} devices",
                "devices": list(per_device_times.keys()),
                "devices_with_findings": {d: f"{t['count']} findings" for d, t in per_device_times.items()},
            }]

        _fe_log(job_id, f"  [XDEV-TL] Activity across {result['devices_with_activity']} device(s)")
        for dr in result["device_time_ranges"]:
            _fe_log(job_id,
                    f"    {dr['device_id']}: {dr['first_event']} -> {dr['last_event']} "
                    f"({dr['span_hours']}h, {dr['total_events']} events)")

    except Exception as e:
        _fe_log(job_id, f"  [XDEV-TL] Error (non-fatal): {e}")

    if ckpt and case_work_dir:
        saved_path = Path(case_work_dir) / "checkpoint_xdevice_timeline.json"
        try:
            saved_path.write_text(json.dumps(result, default=str))
            _ckpt_mark_phase(ckpt, "cross_device_timeline", "complete")
            _ckpt_save(Path(case_work_dir), ckpt)
        except Exception:
            pass

    return result


# ---------------------------------------------------------------------------
# A021 — EVTX / Windows Event Log parsing
# ---------------------------------------------------------------------------

# Key EventIDs of interest per channel
_EVTX_INTERESTING = {
    # Security
    4624: ("LOGON", "HIGH"),
    4625: ("LOGON_FAIL", "HIGH"),
    4648: ("EXPLICIT_CREDS", "CRITICAL"),
    4672: ("SPECIAL_PRIV", "HIGH"),
    4720: ("ACCOUNT_CREATE", "HIGH"),
    4728: ("GROUP_MEMBER_ADD", "HIGH"),
    4732: ("GROUP_MEMBER_ADD", "HIGH"),
    4756: ("GROUP_MEMBER_ADD", "HIGH"),
    4776: ("NTLM_AUTH", "MEDIUM"),
    4798: ("USER_ENUM", "MEDIUM"),
    4799: ("GROUP_ENUM", "MEDIUM"),
    # System
    7001: ("SERVICE_START", "LOW"),
    7002: ("SERVICE_STOP", "LOW"),
    7045: ("SERVICE_INSTALL", "HIGH"),
    1001: ("APP_CRASH", "LOW"),
    # PowerShell (Microsoft-Windows-PowerShell/Operational)
    4103: ("PS_PIPE_MSG", "HIGH"),
    4104: ("PS_SCRIPT_BLOCK", "CRITICAL"),
}

_EVTX_MAGIC = b"ElfFile\x00"  # EVTX file header magic


def _parse_evtx_fallback(path: str) -> list:
    """Binary header inspection when python-evtx is unavailable.

    Returns minimal metadata: file_path, record_count_estimate, oldest_record,
    newest_record derived from the EVTX chunk header statistics.
    """
    records = []
    try:
        with open(path, "rb") as fh:
            header = fh.read(4096)

        if not header.startswith(_EVTX_MAGIC):
            return records

        # EVTX file header layout (128 bytes):
        #   0x00-0x07  signature "ElfFile\x00"
        #   0x08-0x0F  oldest_chunk (uint64 LE)
        #   0x10-0x17  current_chunk_num (uint64 LE)
        #   0x18-0x1F  next_record_id (uint64 LE)
        #   0x20-0x23  header_size (uint32 LE)
        #   0x24-0x25  minor_version (uint16 LE)
        #   0x26-0x27  major_version (uint16 LE)
        #   0x28-0x29  header_block_size (uint16 LE)
        #   0x2A-0x2B  chunk_count (uint16 LE)
        if len(header) >= 0x30:
            next_record_id = struct.unpack("<Q", header[0x18:0x20])[0]
            oldest_chunk = struct.unpack("<Q", header[0x08:0x10])[0]
            records.append({
                "source": path,
                "event_id": 0,
                "timestamp": "",
                "provider": "",
                "summary": (
                    f"EVTX binary header: next_record_id={next_record_id}, "
                    f"oldest_chunk={oldest_chunk}"
                ),
                "severity": "INFO",
                "tag": "EVTX_METADATA",
            })
    except (OSError, struct.error):
        pass
    return records


def _parse_evtx_with_library(path: str) -> list:
    """Parse EVTX with python-evtx (Evtx.Evtx) if available."""
    import Evtx.Evtx as evtx
    import Evtx.Views as evtxv

    records = []
    with evtx.Evtx(path) as log:
        for record in log.records():
            try:
                xml_str = record.xml()
                root = ET.fromstring(xml_str)
                ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

                system = root.find("e:System", ns)
                if system is None:
                    continue

                event_id_elem = system.find("e:EventID", ns)
                event_id = int(event_id_elem.text) if event_id_elem is not None else 0

                ts_elem = system.find("e:TimeCreated", ns)
                timestamp = ts_elem.get("SystemTime", "") if ts_elem is not None else ""

                provider_elem = system.find("e:Provider", ns)
                provider = provider_elem.get("Name", "") if provider_elem is not None else ""

                # Collect EventData key=value pairs
                event_data = root.find("e:EventData", ns)
                data_pairs = {}
                if event_data is not None:
                    for data_elem in event_data.findall("e:Data", ns):
                        name = data_elem.get("Name", "")
                        value = data_elem.text or ""
                        if name:
                            data_pairs[name] = value[:256]
                summary = "; ".join(f"{k}={v}" for k, v in list(data_pairs.items())[:6])

                tag, severity = _EVTX_INTERESTING.get(event_id, ("OTHER", "INFO"))
                if tag != "OTHER" or event_id in _EVTX_INTERESTING:
                    records.append({
                        "source": path,
                        "event_id": event_id,
                        "timestamp": timestamp,
                        "provider": provider,
                        "summary": summary[:512],
                        "severity": severity,
                        "tag": tag,
                    })
            except ET.ParseError:
                continue
    return records


def parse_windows_event_logs(
    mount_points: list,
    job_id: str = None,
    case_work_dir: str = None,
    ckpt: dict = None,
) -> dict:
    """A021 — Parse Windows EVTX event logs.

    Searches mounted partitions for Windows/System32/winevt/Logs/*.evtx,
    uses python-evtx if available or falls back to binary header extraction.
    Catches Security (4624/4625/4648/4672), System (7001/7002/7045/1001),
    and PowerShell (4103/4104) events of interest.

    Returns
    -------
    dict with keys:
        evtx_files_found : int
        events_of_interest : list of dict
        event_summary : str
        by_severity : dict (CRITICAL/HIGH/MEDIUM/LOW counts)
    """
    result = {
        "evtx_files_found": 0,
        "events_of_interest": [],
        "event_summary": "",
        "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
    }

    if ckpt and _ckpt_phase_done(ckpt, "event_logs"):
        _fe_log(job_id, "  [CKPT] Skipping event log parsing — loaded from checkpoint")
        saved_path = Path(case_work_dir) / "checkpoint_event_logs.json" if case_work_dir else None
        if saved_path and saved_path.exists():
            try:
                return json.loads(saved_path.read_text())
            except Exception:
                pass
        return result

    if ckpt and case_work_dir:
        _ckpt_mark_phase(ckpt, "event_logs", "running")
        _ckpt_save(Path(case_work_dir), ckpt)

    try_library = True
    try:
        import Evtx.Evtx  # noqa: F401
    except ImportError:
        try_library = False

    evtx_paths = []
    for mp in (mount_points or []):
        mp = str(mp)
        log_dir = os.path.join(mp, "Windows", "System32", "winevt", "Logs")
        if not os.path.isdir(log_dir):
            continue
        try:
            for fname in os.listdir(log_dir):
                if fname.lower().endswith(".evtx"):
                    evtx_paths.append(os.path.join(log_dir, fname))
        except (PermissionError, OSError):
            pass

    result["evtx_files_found"] = len(evtx_paths)

    for evtx_path in evtx_paths:
        try:
            if try_library:
                recs = _parse_evtx_with_library(evtx_path)
            else:
                recs = _parse_evtx_fallback(evtx_path)
            result["events_of_interest"].extend(recs)
        except Exception as e:
            _fe_log(job_id, f"  [EVTX] Error parsing {evtx_path} (non-fatal): {e}")

    for ev in result["events_of_interest"]:
        sev = ev.get("severity", "INFO")
        result["by_severity"][sev] = result["by_severity"].get(sev, 0) + 1

    total = len(result["events_of_interest"])
    crit = result["by_severity"]["CRITICAL"]
    high = result["by_severity"]["HIGH"]
    result["event_summary"] = (
        f"{result['evtx_files_found']} EVTX files, {total} events of interest "
        f"({crit} CRITICAL, {high} HIGH)"
    )
    _fe_log(job_id, f"  [EVTX] {result['event_summary']}")

    if ckpt and case_work_dir:
        saved_path = Path(case_work_dir) / "checkpoint_event_logs.json"
        try:
            saved_path.write_text(json.dumps(result, default=str))
            _ckpt_mark_phase(ckpt, "event_logs", "complete")
            _ckpt_save(Path(case_work_dir), ckpt)
        except Exception:
            pass

    return result


# ---------------------------------------------------------------------------
# A022 — Registry persistence analysis
# ---------------------------------------------------------------------------

# Common persistence key paths (relative to hive root)
_RUN_KEYS = [
    r"Software\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"Software\Microsoft\Windows\CurrentVersion\RunServices",
    r"Software\Microsoft\Windows\CurrentVersion\RunServicesOnce",
    r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
]

_SERVICES_KEY = r"SYSTEM\CurrentControlSet\Services"

# REGF hive magic
_REGF_MAGIC = b"regf"

# Known-good Microsoft service description prefixes (simple heuristic)
_MS_SERVICE_PREFIXES = (
    "Windows ", "Microsoft ", "DCOM ", "COM+ ", "Network ", "Remote ",
    "Background ", "Security ", "Cryptographic ", "Print ", "Windows Audio",
    "Distributed ", "Event ", "Plug and Play", "Power", "Shell Hardware",
    "Task Scheduler", "Themes", "Volume Shadow", "Windows Defender",
    "Windows Firewall", "Windows Management", "Windows Search",
    "Windows Time", "Windows Update",
)


def _read_hive_regipy(hive_path: str, key_path: str) -> list:
    """Read values under key_path using regipy."""
    import regipy.registry as rr

    results = []
    reg = rr.RegistryHive(hive_path)
    try:
        key = reg.get_key(key_path)
        for value in key.get_values():
            results.append({
                "name": value.name,
                "value_type": str(value.value_type),
                "data": str(value.value)[:512],
            })
    except Exception:
        pass
    return results


def _read_hive_fallback(hive_path: str, key_path: str) -> list:
    """Minimal REGF binary parser — reads value names from leaf nk records.

    This is a best-effort heuristic, not a full registry parser.
    Returns value names with truncated data where detectable.
    """
    results = []
    try:
        with open(hive_path, "rb") as fh:
            data = fh.read(16 * 1024 * 1024)  # cap at 16 MB

        if not data.startswith(_REGF_MAGIC):
            return results

        # Scan for "vk" (value key) records — each is a value entry
        # vk record: signature "vk" + uint16 name_length + uint32 data_length
        #            + uint32 data_offset + uint32 type + uint16 flags + 2 bytes
        #            + name (ASCII or Unicode)
        offset = 0
        while True:
            idx = data.find(b"vk", offset)
            if idx == -1:
                break
            offset = idx + 2
            if idx + 22 > len(data):
                continue
            try:
                name_len = struct.unpack("<H", data[idx + 2:idx + 4])[0]
                data_len_raw = struct.unpack("<I", data[idx + 4:idx + 8])[0]
                val_type = struct.unpack("<I", data[idx + 12:idx + 16])[0]
                flags = struct.unpack("<H", data[idx + 16:idx + 18])[0]
                if name_len == 0 or name_len > 512:
                    continue
                name_bytes = data[idx + 22:idx + 22 + name_len]
                # Bit 0 of flags: 1 = ASCII, 0 = UTF-16LE
                if flags & 1:
                    name = name_bytes.decode("ascii", errors="replace")
                else:
                    name = name_bytes.decode("utf-16-le", errors="replace")
                # Data length > 0x80000000 means inline data (small value)
                inline = bool(data_len_raw & 0x80000000)
                data_len = data_len_raw & 0x7FFFFFFF
                if inline:
                    raw_val = data[idx + 8:idx + 12]
                    val_str = raw_val[:data_len].decode("utf-16-le", errors="replace").rstrip("\x00")
                else:
                    val_str = f"<type={val_type} len={data_len}>"
                results.append({
                    "name": name,
                    "value_type": str(val_type),
                    "data": val_str[:512],
                })
            except (struct.error, UnicodeDecodeError):
                continue
    except OSError:
        pass
    return results


def _score_persistence_risk(key_path: str, name: str, data: str) -> str:
    """Return HIGH/MEDIUM/LOW risk level for a persistence entry."""
    data_lower = data.lower()
    suspicious_exts = (".exe", ".dll", ".ps1", ".vbs", ".js", ".bat", ".scr", ".hta", ".cmd")
    if any(data_lower.endswith(ext) for ext in suspicious_exts):
        if "system32" not in data_lower and "program files" not in data_lower:
            return "HIGH"
    if "powershell" in data_lower and ("-enc" in data_lower or "-exec" in data_lower or "bypass" in data_lower):
        return "CRITICAL"
    if any(x in data_lower for x in ("wscript", "cscript", "mshta", "regsvr32", "rundll32")):
        return "HIGH"
    if any(x in data_lower for x in ("temp", "appdata\\local\\temp", "programdata")):
        return "HIGH"
    return "MEDIUM"


def _scan_scheduled_tasks_xml(mount_point: str, job_id: str = None) -> list:
    """Parse XML scheduled task files under Windows/System32/Tasks/."""
    tasks = []
    tasks_dir = os.path.join(mount_point, "Windows", "System32", "Tasks")
    if not os.path.isdir(tasks_dir):
        return tasks

    for root_dir, _dirs, files in os.walk(tasks_dir):
        for fname in files:
            task_path = os.path.join(root_dir, fname)
            try:
                tree = ET.parse(task_path)
                root_elem = tree.getroot()
                # Strip namespace for simpler access
                ns_strip = lambda tag: tag.split("}")[-1] if "}" in tag else tag  # noqa: E731

                exec_elem = None
                for elem in root_elem.iter():
                    if ns_strip(elem.tag) == "Exec":
                        exec_elem = elem
                        break

                command, args = "", ""
                if exec_elem is not None:
                    for child in exec_elem:
                        tag = ns_strip(child.tag)
                        if tag == "Command":
                            command = (child.text or "").strip()
                        elif tag == "Arguments":
                            args = (child.text or "").strip()

                if not command:
                    continue

                risk = _score_persistence_risk(task_path, fname, f"{command} {args}")
                tasks.append({
                    "type": "scheduled_task",
                    "key_path": task_path,
                    "name": fname,
                    "data": f"{command} {args}".strip()[:512],
                    "risk": risk,
                })
            except (ET.ParseError, OSError):
                continue
    return tasks


def analyze_registry_persistence(
    mount_points: list,
    job_id: str = None,
    case_work_dir: str = None,
    ckpt: dict = None,
) -> dict:
    """A022 — Registry persistence analysis.

    Checks mounted SYSTEM/SOFTWARE/NTUSER.DAT hives for common persistence
    locations. Uses regipy if available, otherwise falls back to binary vk
    record scanning. Also parses Windows/System32/Tasks/*.xml for scheduled
    task persistence.

    Returns
    -------
    dict with keys:
        hives_found : list of str
        persistence_entries : list of dict
        high_risk_count : int
        summary : str
    """
    result = {
        "hives_found": [],
        "persistence_entries": [],
        "high_risk_count": 0,
        "summary": "",
    }

    if ckpt and _ckpt_phase_done(ckpt, "registry_persistence"):
        _fe_log(job_id, "  [CKPT] Skipping registry persistence analysis — loaded from checkpoint")
        saved_path = Path(case_work_dir) / "checkpoint_registry.json" if case_work_dir else None
        if saved_path and saved_path.exists():
            try:
                return json.loads(saved_path.read_text())
            except Exception:
                pass
        return result

    if ckpt and case_work_dir:
        _ckpt_mark_phase(ckpt, "registry_persistence", "running")
        _ckpt_save(Path(case_work_dir), ckpt)

    try_regipy = True
    try:
        import regipy.registry  # noqa: F401
    except ImportError:
        try_regipy = False

    def read_hive(hive_path: str, key_path: str) -> list:
        if try_regipy:
            try:
                return _read_hive_regipy(hive_path, key_path)
            except Exception:
                pass
        return _read_hive_fallback(hive_path, key_path)

    for mp in (mount_points or []):
        mp = str(mp)
        config_dir = os.path.join(mp, "Windows", "System32", "config")

        # SOFTWARE hive — HKLM Run keys
        software_hive = os.path.join(config_dir, "SOFTWARE")
        if os.path.isfile(software_hive):
            result["hives_found"].append(software_hive)
            for key_path in _RUN_KEYS:
                values = read_hive(software_hive, key_path)
                for val in values:
                    risk = _score_persistence_risk(key_path, val["name"], val["data"])
                    result["persistence_entries"].append({
                        "hive": "SOFTWARE",
                        "type": "run_key",
                        "key_path": key_path,
                        "name": val["name"],
                        "data": val["data"],
                        "risk": risk,
                    })

        # SYSTEM hive — non-Microsoft services
        system_hive = os.path.join(config_dir, "SYSTEM")
        if os.path.isfile(system_hive):
            result["hives_found"].append(system_hive)
            svc_values = read_hive(system_hive, _SERVICES_KEY)
            for val in svc_values:
                name = val.get("name", "")
                data = val.get("data", "")
                # Skip obvious Microsoft services
                if any(data.startswith(pfx) for pfx in _MS_SERVICE_PREFIXES):
                    continue
                if name in ("DisplayName", "Description", "ImagePath", "ObjectName"):
                    continue
                risk = _score_persistence_risk(_SERVICES_KEY, name, data)
                if risk in ("HIGH", "CRITICAL"):
                    result["persistence_entries"].append({
                        "hive": "SYSTEM",
                        "type": "service",
                        "key_path": _SERVICES_KEY,
                        "name": name,
                        "data": data,
                        "risk": risk,
                    })

        # NTUSER.DAT hives — per-user Run keys
        users_dir = os.path.join(mp, "Users")
        if os.path.isdir(users_dir):
            try:
                for user_entry in os.listdir(users_dir):
                    ntuser = os.path.join(users_dir, user_entry, "NTUSER.DAT")
                    if not os.path.isfile(ntuser):
                        continue
                    result["hives_found"].append(ntuser)
                    for key_path in _RUN_KEYS:
                        values = read_hive(ntuser, key_path)
                        for val in values:
                            risk = _score_persistence_risk(key_path, val["name"], val["data"])
                            result["persistence_entries"].append({
                                "hive": f"NTUSER.DAT ({user_entry})",
                                "type": "run_key",
                                "key_path": key_path,
                                "name": val["name"],
                                "data": val["data"],
                                "risk": risk,
                            })
            except (PermissionError, OSError):
                pass

        # Scheduled task XML files
        sched_tasks = _scan_scheduled_tasks_xml(mp, job_id=job_id)
        result["persistence_entries"].extend(sched_tasks)

    result["high_risk_count"] = sum(
        1 for e in result["persistence_entries"] if e.get("risk") in ("HIGH", "CRITICAL")
    )
    total = len(result["persistence_entries"])
    result["summary"] = (
        f"{len(result['hives_found'])} hives, {total} persistence entries, "
        f"{result['high_risk_count']} high-risk"
    )
    _fe_log(job_id, f"  [REG-PERSIST] {result['summary']}")

    if ckpt and case_work_dir:
        saved_path = Path(case_work_dir) / "checkpoint_registry.json"
        try:
            saved_path.write_text(json.dumps(result, default=str))
            _ckpt_mark_phase(ckpt, "registry_persistence", "complete")
            _ckpt_save(Path(case_work_dir), ckpt)
        except Exception:
            pass

    return result


# ---------------------------------------------------------------------------
# A023 — Unified timeline / Sleuth Kit MAC body file
# ---------------------------------------------------------------------------

def _ts_to_epoch(ts_str: str) -> int:
    """Convert ISO timestamp string to Unix epoch seconds; returns 0 on failure."""
    if not ts_str:
        return 0
    for fmt in (
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
    ):
        try:
            dt = datetime.strptime(ts_str[:26], fmt)
            epoch = int((dt - datetime(1970, 1, 1)).total_seconds())
            return epoch
        except (ValueError, IndexError):
            continue
    return 0


def generate_body_file(
    findings_writer,
    report_dir: str,
    job_id: str = None,
    case_work_dir: str = None,
    ckpt: dict = None,
) -> dict:
    """A023 — Generate Sleuth Kit MAC body file and CSV timeline.

    Takes all timestamped findings from findings_writer and outputs:
      - {report_dir}/timeline.body  (mactime -b compatible)
      - {report_dir}/timeline.csv   (human-readable)

    Body file format:
      MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime

    Returns
    -------
    dict with keys:
        body_file : str (path to .body file, or empty on failure)
        csv_file  : str (path to .csv file, or empty on failure)
        entry_count : int
        summary : str
    """
    result = {
        "body_file": "",
        "csv_file": "",
        "entry_count": 0,
        "summary": "",
    }

    if ckpt and _ckpt_phase_done(ckpt, "generate_timeline"):
        _fe_log(job_id, "  [CKPT] Skipping timeline generation — loaded from checkpoint")
        saved_path = Path(case_work_dir) / "checkpoint_timeline.json" if case_work_dir else None
        if saved_path and saved_path.exists():
            try:
                return json.loads(saved_path.read_text())
            except Exception:
                pass
        return result

    if ckpt and case_work_dir:
        _ckpt_mark_phase(ckpt, "generate_timeline", "running")
        _ckpt_save(Path(case_work_dir), ckpt)

    try:
        report_path = Path(report_dir)
        report_path.mkdir(parents=True, exist_ok=True)

        records = []
        if hasattr(findings_writer, "all_records"):
            records = findings_writer.all_records()

        body_rows = []
        csv_rows = []

        for rec in records:
            if not isinstance(rec, dict):
                continue

            name = (
                rec.get("evidence_file")
                or rec.get("file_path")
                or rec.get("path")
                or rec.get("description", "unknown")
            )
            name = str(name).replace("|", "_")  # body format uses | as delimiter

            md5 = rec.get("md5", "0") or "0"
            inode = 0
            mode = "----------"
            uid = 0
            gid = 0
            size = rec.get("size", 0) or 0

            # Extract timestamps — prefer result sub-dict, fall back to top-level
            result_data = rec.get("result", {}) if isinstance(rec.get("result"), dict) else {}
            atime = _ts_to_epoch(
                result_data.get("access_time") or rec.get("access_time") or rec.get("completed_at") or ""
            )
            mtime = _ts_to_epoch(
                result_data.get("modified_time") or rec.get("modified_time") or rec.get("started_at") or ""
            )
            ctime = _ts_to_epoch(
                result_data.get("created_time") or rec.get("created_time") or ""
            )
            crtime = _ts_to_epoch(
                result_data.get("timestamp") or rec.get("timestamp") or ""
            )

            # Only include entries that have at least one meaningful timestamp
            if not any([atime, mtime, ctime, crtime]):
                best_ts = rec.get("completed_at") or rec.get("started_at", "")
                epoch = _ts_to_epoch(best_ts)
                if not epoch:
                    continue
                mtime = epoch

            body_rows.append(
                f"{md5}|{name}|{inode}|{mode}|{uid}|{gid}|{size}|{atime}|{mtime}|{ctime}|{crtime}"
            )
            csv_rows.append({
                "timestamp": datetime.utcfromtimestamp(mtime or atime or ctime or crtime).isoformat() if any([mtime, atime, ctime, crtime]) else "",
                "name": name,
                "md5": md5,
                "size": size,
                "atime": atime,
                "mtime": mtime,
                "ctime": ctime,
                "crtime": crtime,
                "severity": rec.get("severity", ""),
                "module": rec.get("module", ""),
                "function": rec.get("function", ""),
            })

        # Sort by mtime then atime
        body_rows.sort(key=lambda r: int(r.split("|")[8] or "0"))
        csv_rows.sort(key=lambda r: r.get("mtime") or r.get("atime") or 0)

        body_path = report_path / "timeline.body"
        csv_path = report_path / "timeline.csv"

        body_path.write_text("\n".join(body_rows) + "\n" if body_rows else "")
        result["body_file"] = str(body_path)

        with open(csv_path, "w", newline="", encoding="utf-8") as fh:
            if csv_rows:
                writer = csv.DictWriter(fh, fieldnames=list(csv_rows[0].keys()))
                writer.writeheader()
                writer.writerows(csv_rows)
        result["csv_file"] = str(csv_path)

        result["entry_count"] = len(body_rows)
        result["summary"] = f"{result['entry_count']} timeline entries -> {body_path.name}, {csv_path.name}"
        _fe_log(job_id, f"  [TIMELINE] {result['summary']}")

    except Exception as e:
        _fe_log(job_id, f"  [TIMELINE] Error generating body file (non-fatal): {e}")
        result["summary"] = f"Error: {e}"

    if ckpt and case_work_dir:
        saved_path = Path(case_work_dir) / "checkpoint_timeline.json"
        try:
            saved_path.write_text(json.dumps(result, default=str))
            _ckpt_mark_phase(ckpt, "generate_timeline", "complete")
            _ckpt_save(Path(case_work_dir), ckpt)
        except Exception:
            pass

    return result
