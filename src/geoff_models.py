#!/usr/bin/env python3
"""Geoff DFIR - Data models, action logging, and classification functions.

Extracted from geoff_integrated.py monolith.

Dependencies: geoff_config (constants), geoff_utils (helpers, logging, locks)
"""

import os
import json
import tempfile
from pathlib import Path
from datetime import datetime
from typing import Optional

# ---------------------------------------------------------------------------
# Imports from sibling modules
# ---------------------------------------------------------------------------

from geoff_config import CASES_WORK_DIR

from geoff_utils import (
    _log_lock,
    _atomic_append,
    _log_error,
    _log_info,
    git_commit_action,
    _fe_log,
    orchestrator,
)

__all__ = ["ActionLogger", "_detect_file_type_from_header", "_re_evaluate_playbooks", "action_logger", "get_all_cases", "get_available_tools_status", "get_evidence_recursive"]







# ---------------------------------------------------------------------------
# _re_evaluate_playbooks — post-playbook artifact-driven re-queuing
# ---------------------------------------------------------------------------

def _re_evaluate_playbooks(completed_playbook, pb_findings, execution_plan, skipped_playbooks,
                              inventory, os_type, has_disk_images, disk_artifacts,
                              indicator_hits, job_id):
    """After each playbook completes, check if new artifacts were discovered
    that warrant additional playbooks. Pull every thread.

    Returns list of newly-queued playbook IDs (empty if nothing new).
    """
    newly_queued = []
    already_queued = set(execution_plan)

    _new_artifacts = {
        "email": False, "browser": False, "registry": False, "evtx": False, "evt": False,
        "memory": False, "pcap": False, "mobile": False, "encrypted": False,
        "cloud_sync": False, "collaboration": False, "vm": False, "container": False,
    }

    _sigs = {
        "email":       [".pst", ".ost", ".dbx", ".eml", ".mbox", "outlook",
                        "thunderbird", "evolution", "mailbox", "maildir", "sent items"],
        "browser":     ["places.sqlite", "history", "cookies.db", "chrome/user data",
                        "firefox/profiles", "sessionstore"],
        "registry":    ["ntuser.dat", "software", "system", "sam", "security",
                        "system32/config"],
        "evtx":        [".evtx", "winevt/logs"],
        "evt":         [".evt"],
        "memory":      ["hiberfil", "pagefile", ".dmp", "memory dump", "vmem"],
        "pcap":        [".pcap", ".pcapng", "packet capture", "network capture"],
        "mobile":      ["backup/", "iphone", "android", "manifest.plist", "info.plist",
                        "build.prop"],
        "encrypted":   ["bitlocker", "filevault", "veracrypt", "truecrypt", "luks",
                        "encrypted"],
        "cloud_sync":  ["onedrive", "skydrive", "dropbox", "filecache.db", "googledrive"],
        "collaboration":["teams", "slack", "discord", "skype", "zoom"],
        "vm":          [".vmss", ".vmsn", ".vmem", ".vhdx", ".vmdk", "vmware"],
        "container":   ["docker", "containerd", "overlay2", "kubernetes"],
    }

    for step in pb_findings:
        result = step.get("result", {})
        if not isinstance(result, dict):
            continue
        result_str = json.dumps(result, default=str).lower()
        for artifact_type, patterns in _sigs.items():
            if not _new_artifacts[artifact_type]:
                for pat in patterns:
                    if pat in result_str:
                        _new_artifacts[artifact_type] = True
                        break

    for hit in indicator_hits:
        if isinstance(hit, dict):
            cat = hit.get("category", "").lower()
            if cat in ("phishing", "email", "credential_theft"):
                _new_artifacts["email"] = True
            if cat in ("c2", "beaconing"):
                _new_artifacts["browser"] = True

    _artifact_to_playbook = {
        "email":         ["PB-SIFT-023"],
        "browser":       ["PB-SIFT-022"],
        "registry":      ["PB-SIFT-009"] + (["PB-SIFT-028"] if os_type == "windows" else []),
        "evtx":          ["PB-SIFT-028"] if os_type == "windows" else [],
        "evt":           ["PB-SIFT-028"] if os_type == "windows" else [],
        "memory":        ["PB-SIFT-027"],
        "pcap":          ["PB-SIFT-011"],
        "mobile":        ["PB-SIFT-021"],
        "encrypted":     ["PB-SIFT-029"],
        "cloud_sync":    ["PB-SIFT-030"],
        "collaboration": ["PB-SIFT-031"],
        "vm":            ["PB-SIFT-032"],
        "container":     ["PB-SIFT-033"],
    }

    for artifact_type, is_new in _new_artifacts.items():
        if is_new:
            if artifact_type in disk_artifacts:
                disk_artifacts[artifact_type] = True
            playbooks = _artifact_to_playbook.get(artifact_type, [])
            for pb in playbooks:
                if pb not in already_queued:
                    execution_plan.append(pb)
                    already_queued.add(pb)
                    newly_queued.append(pb)
                    _fe_log(job_id, f"  \u21b3 {pb} queued after {completed_playbook} discovered {artifact_type} artifacts")
                    skipped_playbooks[:] = [s for s in skipped_playbooks if s.get("id") != pb]

    return newly_queued


# ---------------------------------------------------------------------------
# ActionLogger — Git-backed forensic action audit trail
# ---------------------------------------------------------------------------

class ActionLogger:
    """Logger for all Geoff actions with git integration"""

    def __init__(self, log_dir: str = None):
        if log_dir is None:
            log_dir = os.environ.get('GEOFF_LOGS_DIR', CASES_WORK_DIR + '/logs')
        self.log_dir = Path(log_dir)
        try:
            self.log_dir.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            _log_error("ActionLogger init mkdir", e)
            self.log_dir = Path(tempfile.gettempdir()) / 'geoff-logs'
            self.log_dir.mkdir(exist_ok=True)

        self.action_log = self.log_dir / f"actions_{datetime.now().strftime('%Y%m')}.jsonl"

    def log(self, action_type: str, details: dict, commit: bool = True):
        """Log an action with optional git commit"""
        entry = {
            'timestamp': datetime.now().isoformat(),
            'action_type': action_type,
            'details': details
        }

        # Atomic write for action log (with lock)
        try:
            log_content = json.dumps(entry) + '\n'
            with _log_lock:
                _atomic_append(self.action_log, log_content)
                # Log rotation: if file > 10MB, rotate
                try:
                    if os.path.exists(self.action_log) and os.path.getsize(self.action_log) > 10 * 1024 * 1024:
                        rotated = f"{self.action_log}.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                        os.rename(self.action_log, rotated)
                        _log_info(f"Log rotated: {rotated}")
                except Exception as rot_exc:
                    _log_info(f"action log rotation skipped: {rot_exc}")
        except Exception as e:
            _log_error(f"ActionLogger log write {self.action_log}", e)
            # Fallback to regular write
            try:
                with open(self.action_log, 'a') as f:
                    f.write(log_content)
            except Exception as e2:
                _log_error(f"ActionLogger fallback log write", e2)

        if commit:
            git_commit_action(f"{action_type}: {details.get('description', 'action')}")

        return entry


# Initialize global action logger
action_logger = ActionLogger()


# ---------------------------------------------------------------------------
# Evidence directory helpers
# ---------------------------------------------------------------------------

def get_evidence_recursive(path, prefix=""):
    """Recursively get all files and folders"""
    items = []
    try:
        for item in sorted(os.listdir(path)):
            item_path = os.path.join(path, item)
            display_name = f"{prefix}{item}"
            if os.path.isdir(item_path):
                items.append(f"[DIR] {display_name}/")
                items.extend(get_evidence_recursive(item_path, f"{display_name}/"))
            else:
                size = os.path.getsize(item_path)
                items.append(f"{display_name} ({size} bytes)")
    except Exception as e:
        print(f"[GEOFF] Error reading evidence directory: {e}", file=sys.stderr)
    return items


def get_all_cases():
    """Get ALL cases with ALL contents"""
    evidence_path = "/mnt/evidence-storage/evidence"
    cases = {}
    if not os.path.exists(evidence_path):
        return cases
    try:
        for case_name in sorted(os.listdir(evidence_path)):
            case_path = os.path.join(evidence_path, case_name)
            if os.path.isdir(case_path):
                cases[case_name] = get_evidence_recursive(case_path)
    except Exception as e:
        print(f"Error reading cases: {e}")
    return cases


def get_available_tools_status():
    """Get status of all forensic tools"""
    return orchestrator.get_available_tools()


# ---------------------------------------------------------------------------
# _detect_file_type_from_header — magic-byte file type detection
# ---------------------------------------------------------------------------

def _detect_file_type_from_header(path: str) -> str | None:
    """Detect file type from magic bytes (fast, no external tools needed)."""
    try:
        with open(path, "rb") as f:
            header = f.read(8)

        if not header:
            return None

        # Windows crash dump / kernel dump
        if header[:8] in (b'PAGEDUMP', b'PAGEDU64'):
            return "memory_dump"
        # Windows hibernation file
        if header[:4] == b'HIBR':
            return "memory_dump"

        # ZIP archives (iOS backups, Cellebrite extractions)
        if header[:2] == b'PK':
            return "zip_archive"

        # GZIP compressed files (tar.gz backups)
        if header[:2] == b'\x1f\x8b':
            return "gzip_archive"

        # TAR archives
        if len(header) >= 8 and header[257:262] == b'ustar':
            return "tar_archive"

        # 7-Zip
        if header[:6] == b'7z\xbc\xaf\x27\x1c':
            return "7zip_archive"

        # SQLite databases (mobile artifacts)
        if header[:16] == b'SQLite format 3\x00':
            return "sqlite_db"

        # Windows registry
        if header[:4] == b'regf':
            return "registry_hive"

        # EWF disk image (EnCase)
        if header[:3] == b'EVF':
            return "ewf_disk_image"

        # PCAP
        if header[:4] in (b'\xa1\xb2\xc3\xd4', b'\xd4\xc3\xb2\xa1', b'\x0a\x0d\x0d\x0a'):
            return "pcap"

        # ELF binary (Linux)
        if header[:4] == b'\x7fELF':
            return "elf_binary"

        # Mach-O binary (macOS/iOS)
        if header[:4] in (b'\xcf\xfa\xed\xfe', b'\xfe\xed\xfa\xcf'):
            return "macho_binary"

        # Windows PE
        if header[:2] == b'MZ':
            return "pe_binary"

        # DMG (Apple disk image) — koly signature
        if b'koly' in header:
            return "dmg_image"

        # VMDK (VMware disk) — sparse or descriptor
        if header[:4] == b'KDMV' or b'Disk DescriptorFile' in header[:32]:
            return "vmdk_image"

        # ISO 9660 / UDF
        if header[:5] == b'CD001' or header[:4] in (b'NSR0', b'NSR02', b'NSR03'):
            return "iso_image"

        # VHD/VHDX (Microsoft virtual disk)
        if header[:4] == b'vhdx' or header[:8] == b'conectix':
            return "vhd_image"

        # QCOW2 (QEMU disk)
        if header[:4] == b'QFI\xfb':
            return "qcow2_image"

        # OVA — XML with OVF namespace
        if b'<?xml' in header[:8] and b'ovf' in header[:64].lower():
            return "ova_archive"

        # JPEG/PNG images (mobile photo evidence)
        if header[:4] == b'\xff\xd8\xff\xe0' or header[:4] == b'\xff\xd8\xff\xe1':
            return "jpeg_image"
        if header[:8] == b'\x89PNG\r\n\x1a\n':
            return "png_image"

        return None
    except:
        return None
