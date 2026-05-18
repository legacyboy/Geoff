#!/usr/bin/env python3
"""Geoff DFIR - Evidence inventory, device discovery, partition detection,
and evidence scanning/classification.

Auto-extracted from geoff_integrated.py monolith.

Dependencies: geoff_config (constants), geoff_utils (helpers, logging),
              geoff_models (_detect_file_type_from_header).
"""

import os
import json
import re
import shlex
import subprocess
import struct
import hashlib
import shutil
import tempfile
import time
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Imports from sibling modules
# ---------------------------------------------------------------------------

from geoff_config import (
    AI_EVIDENCE_CLASSIFICATION,
    _EVIDENCE_TYPE_MAP,
    _EMAIL_EXTENSIONS,
    EVIDENCE_BASE_DIR,
    CASES_WORK_DIR,
    COMMON_LEGACY_OFFSETS,
    MITRE_TAGS,
)

from sift_specialists import SLEUTHKIT_Specialist
from sift_specialists_extended import VSS_Specialist

from geoff_utils import (
    _fe_log,
    _fe_log_with_exception,
    safe_run,
    _hash_file,
    _atomic_write,
    _log_error,
    _log_info,
    _state_lock,
    _active_mounts,
    _ckpt_phase_done,
    _ckpt_mark_phase,
    _ckpt_save,
    _ckpt_load,
    _ckpt_archive_registered,
    _ckpt_register_archive,
    _ckpt_disk_walked,
    _ckpt_mark_disk_walked,
    _detect_os,
    _detect_os_from_devices,
)

from geoff_models import _detect_file_type_from_header

# Self-healing (may not be wired yet at import time)
try:
    from geoff_self_heal import _attempt_heal
except ImportError:
    _attempt_heal = None


# ---------------------------------------------------------------------------
# Classification constants
# ---------------------------------------------------------------------------

_HEADER_TYPE_MAP = {
    "ewf_disk_image": "disk_images",
    "pcap": "pcaps",
    "registry_hive": "registry_hives",
    "sqlite_db": "other_files",  # May be mobile — validated by name
    "zip_archive": "other_files",  # May be mobile — validated by name
    "gzip_archive": "other_files",  # May be mobile — validated by name
    "tar_archive": "other_files",
    "7zip_archive": "other_files",
    "elf_binary": "other_files",
    "macho_binary": "other_files",
    "pe_binary": "other_files",
    "dmg_image": "disk_images",
    "vmdk_image": "disk_images",
    "vhd_image": "disk_images",
    "qcow2_image": "disk_images",
    "iso_image": "disk_images",
    "ova_archive": "other_files",
    "jpeg_image": "other_files",
    "png_image": "other_files",
}


# ---------------------------------------------------------------------------
# Triage indicator patterns (used by _scan_triage_indicators)
# ---------------------------------------------------------------------------

TRIAGE_PATTERNS = {
    "ransomware": [".locked", ".encrypted", ".crypt", "readme_decrypt", "how_to_decrypt",
                   "recover_files", ".locky", ".cerber", ".sage", ".globe",
                   "your_files_are", "ransom_note", "decrypt_instructions",
                   "vssadmin delete", "wbadmin delete", "bcdedit /set",
                   "wipe_mbr", "destroy_vss", "epmntdrv", "hermetic"],
    "credential_theft": ["mimikatz", "lsass", "ntds.dit", "procdump", "hashdump",
                         "creddump", "cachedump", "secretsdump", "dcsync",
                         "kerberoast", "asrep_roast", "golden ticket", "rubeus",
                         "invoke-kerberoast"],
    "lateral_movement": ["psexec", "wmic", "winrm", "sharpexec", "remcom",
                         "paexec", "cmbexec", "dcom", "atexec",
                         "nsenter", "container_escape", "docker.sock",
                         "chroot /host", "privileged_container", "pivot_root"],
    "persistence": ["autorun", "run_once", "scheduled_task", "startup",
                    "wmi_subscription", "com_hijack", "shell:",
                    "uefi", "bootkit", "flashrom", "spi_flash",
                    "survive_reinstall", "uefi_dxe", "dxe_driver"],
    "exfiltration": ["megasync", "dropbox", "onedrive", "googledrive",
                    "rsync", "scp", "sftp", "ftp_upload", "exfil",
                    "inbox_rule", "forward_to", "forwardingrule", "mailforward",
                    "s3 sync", "attacker-exfil"],
    "anti_forensics": ["eventlog_clear", "wevtutil cl", "log clear",
                      "timestomp", "timemodify", "ccleaner", "bleachbit",
                      "shred", "history -c", "drop table", "drop database",
                      "dd if=/dev/urandom", "wipe_free_space"],
    "web_shell": ["c99", "r57", "wso", "b374k", "alfa", "cmd=", "exec=",
                  "shell=", "eval(", "base64_decode", "webshell",
                  "xp_cmdshell", "sqlmap", "union select", "proxylogon"],
    "lolbin": ["certutil", "bitsadmin", "mshta", "rundll32", "regsvr32",
               "wmic", "msbuild", "installutil", "msiexec"],
    "c2": ["cobalt strike", "beacon", "covenant", "sliver", "poshc2", "empire",
            "cobaltstrike", "teamserver", "metasploit", "reverse_shell",
            ".onion", "stratum+tcp://"],
    "cryptominer": ["xmrig", "minexmr", "xmrpool", "moneroocean", "supportxmr",
                    "stratum+tcp", "cryptonight", "randomx", "monero", "coinhive",
                    "minergate", "nicehash", "pool.minexmr"],
    "rootkit": ["rootkit", "sys_call_table", "syscall_hook", "hooking",
                "hide_pid", "hide_port", "process_hide", "module_hide",
                "lkm", "kthreadd_helper", "insmod", "kernel_module",
                "LD_PRELOAD", "__intercepted_"],
    "ot_attack": ["modbus", "scada", "plc_attack", "safety_bypass", "sis_bypass",
                  "setpoint_override", "industroyer", "ot_sabotage",
                  "scada_exploit", "industrial_control", "dnp3", "iec-61850"],
    "phishing": ["phishing", "credential_harvesting", "spoofed_sender", "urgent_action_required",
                 "verify_your_account", "suspended_account", "click_here_to_verify",
                 "password_expire", "unauthorized_access", "secure_your_account",
                 "bit.ly/", "tinyurl.com/", "goo.gl/", "t.co/",
                 ".scr", ".pif", ".vbs",
                 "verify_identity", "account_compromised", "bank_notification",
                 "invoice_attachment", "shipping_notification", "fedex_tracking",
                 "ups_delivery", "dhl_shipment", "password_reset_required"],
}

SEVERITY_MAP = {
    "ransomware": "CRITICAL",
    "credential_theft": "HIGH",
    "lateral_movement": "HIGH",
    "persistence": "HIGH",
    "exfiltration": "HIGH",
    "anti_forensics": "HIGH",
    "web_shell": "HIGH",
    "lolbin": "MEDIUM",
    "c2": "CRITICAL",
    "cryptominer": "HIGH",
    "rootkit": "CRITICAL",
    "ot_attack": "CRITICAL",
    "phishing": "HIGH",
}


# ===========================================================================
# Partition Detection
# ===========================================================================

__all__ = [
    "SEVERITY_MAP", "TRIAGE_PATTERNS", "_all_inventory_paths",
    "_classify_unprocessed", "_compute_indicator_confidence",
    "_content_scan", "_detect_partition_offsets", "_extract_archive",
    "extract_local_users", "_extract_match_context", "_inventory_evidence",
    "_inventory_evidence_with_ai", "_is_indicator_match",
    "_list_extracted_files", "_mount_and_discover", "_mount_vss_snapshots",
    "_resolve_e01_path", "_run_device_discovery",
    "_scan_filenames_for_indicators", "_scan_triage_indicators",
    "_strings_scan", "_tool_available",
    "_validate_inventory_classification", "detect_anti_forensics",
    "parse_usnjrnl", "scan_file_signatures", "search_email_artifacts",
    "parse_ie_webcache", "parse_browser_search_terms", "parse_google_drive",
    "check_google_drive_registry", "analyze_network_shares",
    "find_network_drive_files", "recover_formatted_fat", "detect_usb_format",
    "post_mount_inventory_sweep",
    # Phase 3+4 — re-exported from geoff_phase34
    "detect_campaign_patterns",
    "analyze_negative_space",
    "parse_recycle_bin",
    "find_imapi_burn_logs",
    "check_vss_auto_mount",
    "find_windows_edb_paths",
    "handle_unprocessed_files",
    "cross_device_timeline_stub",
]

# ---------------------------------------------------------------------------
# Phase 3+4 re-exports — implementations live in geoff_phase34
# ---------------------------------------------------------------------------
from geoff_phase34 import (  # noqa: E402
    detect_campaign_patterns,
    analyze_negative_space,
    parse_recycle_bin,
    find_imapi_burn_logs,
    check_vss_auto_mount,
    find_windows_edb_paths,
    handle_unprocessed_files,
    cross_device_timeline_stub,
)


def post_mount_inventory_sweep(inventory: dict, case_work_dir: str, job_id: str = None) -> dict:
    """Second-pass inventory sweep after partition mounting.

    Walks every active mount point searching for known forensic artifact
    paths that the initial extension-based inventory cannot discover
    (artifacts that only exist *inside* mounted disk images).

    Artifact categories scanned:
      - email_files: OST, PST, Windows.edb, WebCache *.db
      - browser_files: Chrome History, Firefox places.sqlite, WebCacheV01.dat
      - cloud_files: Google Drive snapshot.db, sync_config.db
      - recycle_bin_files: $Recycle.Bin $I* metadata files
      - prefetch_files: Windows/Prefetch *.pf
      - anti_forensics_files: Eraser logs, CCleaner config

    Each newly discovered path is added to both its category-specific list
    and the ``other_files`` list in the inventory so that downstream
    playbook dispatching can find them.

    Returns:
        dict mapping each category name to the list of newly discovered
        absolute paths (empty list if none found).
    """
    from pathlib import Path as _Path

    # ------------------------------------------------------------------
    # Artifact path patterns (relative to mount point root).
    # Uses glob syntax compatible with Path.glob().
    # ------------------------------------------------------------------
    _artifact_patterns = {
        "email_files": [
            "Users/*/AppData/Local/Microsoft/Outlook/*.ost",
            "Users/*/Documents/Outlook Files/*.pst",
            "Users/*/AppData/Local/Microsoft/Windows/Search/Windows.edb",
            "Users/*/AppData/Local/Microsoft/Windows/WebCache/*.db",
        ],
        "browser_files": [
            "Users/*/AppData/Local/Google/Chrome/User Data/Default/History",
            "Users/*/AppData/Roaming/Mozilla/Firefox/Profiles/*/places.sqlite",
            "Users/*/AppData/Local/Microsoft/Windows/WebCache/WebCacheV01.dat",
        ],
        "cloud_files": [
            "Users/*/AppData/Local/Google/DriveFS/*/snapshot.db",
            "Users/*/AppData/Local/Google/Drive/snapshot.db",
            "Users/*/AppData/Local/Google/Drive/sync_config.db",
        ],
        "recycle_bin_files": [
            "$Recycle.Bin/*/$I*",
        ],
        "prefetch_files": [
            "Windows/Prefetch/*.pf",
        ],
        "anti_forensics_files": [
            "Users/*/AppData/Local/Eraser/*.log",
            "Program Files/CCleaner/CCleaner.ini",
        ],
    }

    newly_discovered = {cat: [] for cat in _artifact_patterns}

    # Snapshot active mounts under lock
    with _state_lock:
        mount_points = list(_active_mounts)

    if not mount_points:
        _fe_log(job_id, "  [POST-MOUNT-SWEEP] No active mounts — skipping")
        return newly_discovered

    _fe_log(job_id, f"  [POST-MOUNT-SWEEP] Scanning {len(mount_points)} mount point(s) "
                     f"for embedded forensic artifacts")

    for mp in mount_points:
        if not os.path.isdir(mp):
            continue
        mp_path = _Path(mp)
        for category, patterns in _artifact_patterns.items():
            for pattern in patterns:
                try:
                    matches = list(mp_path.glob(pattern))
                except Exception:
                    continue  # Bad pattern or permission error — skip
                for match_path in matches:
                    if not match_path.is_file():
                        continue
                    resolved = str(match_path.resolve())
                    if resolved not in newly_discovered[category]:
                        newly_discovered[category].append(resolved)

    # Merge newly discovered artifacts into the inventory
    # Each artifact is added to both its dedicated category and to
    # other_files so that playbook dispatching (which drives from
    # PLAYBOOK_STEPS evidence-type keys) can pick them up.
    total_new = 0
    for category, paths in newly_discovered.items():
        if not paths:
            continue
        inventory.setdefault(category, [])
        for p in paths:
            if p not in inventory[category]:
                inventory[category].append(p)
                total_new += 1
            if p not in inventory.setdefault("other_files", []):
                inventory["other_files"].append(p)

    # Log per-category summary
    for category, paths in newly_discovered.items():
        if paths:
            _fe_log(job_id, f"  [POST-MOUNT-SWEEP] {category}: {len(paths)} new artifact(s)")

    _fe_log(job_id, f"  [POST-MOUNT-SWEEP] Total: {total_new} new artifact(s) "
                     f"merged into inventory across {sum(1 for v in newly_discovered.values() if v)} category(ies)")

    return newly_discovered


def search_email_artifacts(inventory: dict, job_id: str = None) -> list:
    """Walk mounted filesystems looking for email-related artifacts.

    Searches all active mount points (*_active_mounts*) for files matching
    email-forensic extensions (.pst, .ost, .eml, .msg, .edb, .mbox, .dbx).
    Found paths are recorded in the inventory under ``other_files``.

    Returns:
        list[str]: Full paths to all email artifacts discovered.
    """
    import fnmatch

    _email_patterns = frozenset({
        "*.pst", "*.ost", "*.eml", "*.msg", "*.edb",
        "*.mbox", "*.dbx", "*.emlx",
    })

    found: list[str] = []

    # Snapshot active mounts under lock
    with _state_lock:
        mount_points = list(_active_mounts)

    if not mount_points:
        _fe_log(job_id, "  [EMAIL-SEARCH] No active mounts — skipping email artifact search")
        return found

    _fe_log(job_id, f"  [EMAIL-SEARCH] Scanning {len(mount_points)} mount point(s) for email artifacts")

    for mp in mount_points:
        if not os.path.isdir(mp):
            continue
        mp_path = Path(mp)
        _fe_log(job_id, f"    Walking {mp} …")
        walked = 0
        try:
            for fpath in mp_path.rglob("*"):
                # rglob yields dirs too — only act on files
                if not fpath.is_file():
                    continue
                walked += 1
                name = fpath.name
                # Quick extension check before fnmatch
                ext = fpath.suffix.lower()
                if ext in _EMAIL_EXTENSIONS:
                    full = str(fpath.resolve())
                    if full not in found:
                        found.append(full)
                elif any(fnmatch.fnmatch(name, pat) for pat in _email_patterns):
                    full = str(fpath.resolve())
                    if full not in found:
                        found.append(full)
        except Exception as walk_e:
            _fe_log(job_id, f"    ⚠ Walk error in {mp}: {walk_e}")

    # Deduplicate and register in inventory
    if found:
        _fe_log(job_id, f"  [EMAIL-SEARCH] Found {len(found)} email artifact(s)")
        for fp in found:
            if fp not in inventory.setdefault("other_files", []):
                inventory["other_files"].append(fp)
    else:
        _fe_log(job_id, "  [EMAIL-SEARCH] No email artifacts found on mounted partitions")

    return found


def _detect_partition_offsets(disk_images: list, device_map: dict,
                               ckpt: dict, ckpt_offsets_file: Path,
                               job_id: str = None) -> dict:
    """Detect partition offsets for each disk image using mmls.

    Tries SLEUTHKIT_Specialist, direct mmls invocation, and fallback offsets.
    Uses self-healing for hard failures.  Checkpoint-aware: skips when
    partition_offsets phase is already complete.

    Returns dict: image_path → start_sector.
    """
    image_offsets = {}

    if _ckpt_phase_done(ckpt, "partition_offsets"):
        try:
            image_offsets = json.loads(ckpt_offsets_file.read_text())
        except (IOError, json.JSONDecodeError):
            image_offsets = {}
        _fe_log(job_id, "  [CKPT] Skipping partition scan — loaded from checkpoint")
        return image_offsets

    _ckpt_mark_phase(ckpt, "partition_offsets", "running")
    _ckpt_save(Path(ckpt.get("_case_dir", "/tmp")), ckpt)

    # -----------------------------------------------------------------------
    # qemu-img conversion for virtual disk formats not natively supported by
    # SleuthKit (.vhdx, .qcow2, .vdi). Convert to raw image alongside the
    # original, then use the raw copy for SleuthKit operations.
    # -----------------------------------------------------------------------
    _QEMU_CONVERT_EXTS = {".vhdx", ".qcow2", ".vdi"}
    _qemu_img = shutil.which("qemu-img")

    for dev_id, dev in device_map.items():
        for i, img in enumerate(dev.get("evidence_files", [])):
            if img not in disk_images:
                continue
            ext = Path(img).suffix.lower()
            if ext in _QEMU_CONVERT_EXTS and _qemu_img:
                raw_img = str(Path(img).parent / f"{Path(img).stem}.raw")
                if not Path(raw_img).exists():
                    _fe_log(job_id, f"  Converting {Path(img).name} to raw for SleuthKit compatibility...")
                    conv_cmd = [_qemu_img, "convert", "-O", "raw", img, raw_img]
                    conv_result = subprocess.run(conv_cmd, capture_output=True, text=True, timeout=600)
                    if conv_result.returncode == 0:
                        dev["evidence_files"][i] = raw_img
                        _fe_log(job_id, f"  qemu-img: {Path(img).name} → {Path(raw_img).name}")
                        # Also register the raw image as a disk image if not already
                        if raw_img not in disk_images:
                            disk_images.append(raw_img)
                    else:
                        _fe_log(job_id, f"  ⚠ qemu-img conversion failed for {Path(img).name}: {conv_result.stderr[:200]}")

    for dev_id, dev in device_map.items():
        for img in dev.get("evidence_files", []):
            if img not in disk_images:
                continue
            try:
                # Try SLEUTHKIT specialist first
                try:
                    from sift_specialists import SLEUTHKIT_Specialist
                    specialist = SLEUTHKIT_Specialist(evidence_path=img)
                    mmls_result = specialist.analyze_partition_table(img)
                except Exception:
                    mmls_result = {"status": "error", "stderr": "SLEUTHKIT_Specialist unavailable"}

                if mmls_result.get("status") == "success" and mmls_result.get("partitions"):
                    # Find first NTFS/ext4/HFS+ partition
                    for part in mmls_result["partitions"]:
                        desc = part.get("description", "").lower()
                        start = part.get("start_sector", 0)
                        if any(fs in desc for fs in ["ntfs", "ext", "hfs", "fat", "linux", "windows"]):
                            image_offsets[img] = start
                            _fe_log(job_id, f"Partition offset for {Path(img).name}: sector {start}")
                            break
                    if img not in image_offsets and mmls_result["partitions"]:
                        for part in mmls_result["partitions"]:
                            start = part.get("start_sector", 0)
                            if start > 0:
                                image_offsets[img] = start
                                _fe_log(job_id, f"Partition offset for {Path(img).name}: sector {start} (first partition)")
                                break

                if img not in image_offsets:
                    # Try direct mmls invocation as a last-resort fallback
                    try:
                        raw_mmls = subprocess.run(
                            ['mmls', img], capture_output=True, text=True, timeout=30
                        )
                        if raw_mmls.returncode == 0:
                            for line in raw_mmls.stdout.splitlines():
                                line = line.strip()
                                m = re.match(r'^\d+:\s+(\d+)\s+(\d+)\s+(\d+)\s+(.*)', line)
                                if m:
                                    desc = m.group(4).lower()
                                    start = int(m.group(1))
                                    if any(fs in desc for fs in ['ntfs', 'ext', 'fat', 'hfs']) and start > 0:
                                        image_offsets[img] = start
                                        _fe_log(job_id, f"Partition offset for {Path(img).name}: sector {start} (direct mmls fallback)")
                                        break
                    except Exception:
                        pass

                if img not in image_offsets:
                    # LLM-powered self-healing
                    _pd_err = f"mmls failed to identify partitions for {Path(img).name}"
                    if mmls_result and mmls_result.get("stderr"):
                        _pd_err += f": {str(mmls_result['stderr'])[:200]}"
                    if _attempt_heal is not None:
                        healed = _attempt_heal(
                            module="system",
                            function="detect_partitions",
                            params={"evidence_path": img},
                            error_result={"status": "error", "stderr": _pd_err},
                            job_id=job_id,
                            evidence_file=img,
                            evidence_type="disk_image",
                        )
                        if healed and (healed.get("status") in ("skipped",) or healed.get("_heal_skipped")):
                            _fe_log(job_id, f"  ⎘ [HEAL] Partition detection skipped for {Path(img).name}: {healed.get('_skip_reason', 'LLM skip')}")
                            continue
                    # Fallback: common legacy offset
                    image_offsets[img] = 63
                    _fe_log(job_id, f"Partition detection failed for {Path(img).name}, using legacy offset 63 (DOS partition table)")

            except Exception as e:
                _fe_log(job_id, f"Partition detection crashed for {Path(img).name}: {e}")
                if _attempt_heal is not None:
                    healed = _attempt_heal(
                        module="system",
                        function="detect_partitions",
                        params={"evidence_path": img},
                        error_result={"status": "error", "stderr": str(e)[:300]},
                        job_id=job_id,
                        evidence_file=img,
                        evidence_type="disk_image",
                    )
                    if healed and (healed.get("status") in ("skipped",) or healed.get("_heal_skipped")):
                        _fe_log(job_id, f"  ⎘ [HEAL] Partition detection skipped after crash for {Path(img).name}")
                        continue
                image_offsets[img] = 63
                _fe_log(job_id, f"  using legacy offset 63 as fallback")

    # Save checkpoint
    if image_offsets:
        _atomic_write(ckpt_offsets_file, json.dumps(image_offsets, default=str))
        _ckpt_mark_phase(ckpt, "partition_offsets", "complete",
                         str(ckpt_offsets_file.name))
        _ckpt_save(Path(ckpt.get("_case_dir", "/tmp")), ckpt)

    return image_offsets


# ===========================================================================
# Device Discovery
# ===========================================================================

def _run_device_discovery(evidence_path: Path, inventory: dict,
                           orchestrator, job_id: str = None) -> tuple:
    """Run DeviceDiscovery and return (device_map, user_map).

    If no devices are resolved, synthesises a single host-unknown device
    so the per-device playbook loop always runs.
    """
    from device_discovery import DeviceDiscovery
    device_disc = DeviceDiscovery(orchestrator)
    device_map, user_map = device_disc.discover(evidence_path, inventory)
    _fe_log(job_id, f"Discovered {len(device_map)} devices, {len(user_map)} users")

    if not device_map:
        all_evidence = (
            inventory["disk_images"] + inventory["memory_dumps"] + inventory["pcaps"]
            + inventory.get("evtx_logs", []) + inventory.get("evt_logs", [])
            + inventory["syslogs"] + inventory["registry_hives"]
            + inventory["mobile_backups"] + inventory["other_files"]
        )
        device_map = {
            "host-unknown": {
                "device_id": "host-unknown",
                "device_type": "unknown",
                "owner": "unknown",
                "os_type": "unknown",
                "evidence_files": all_evidence,
            }
        }
        _fe_log(job_id, "  No devices resolved — created synthetic host-unknown device")

    return device_map, user_map


# ===========================================================================
# Mount & Discover (filesystem walk inside disk images)
# ===========================================================================


def _resolve_e01_path(img_path: str) -> str:
    """If img_path is an E02/E03 segment, return the base E01 path."""
    for seg in [".E02", ".E03", ".E04", ".E05", ".e02", ".e03", ".e04", ".e05"]:
        if img_path.endswith(seg):
            base = img_path[:-4]
            e01 = base + ".E01"
            if os.path.isfile(e01):
                return e01
    return img_path



def _mount_and_discover(inventory: dict, image_offsets: dict,
                         case_name: str, job_id: str = None) -> dict:
    """Mount disk image partitions and classify all files inside via real filesystem walk.

    Replaces the old fls-based _nuclear_deep_classify with actual partition mounting +
    os.walk(). This gives REAL filesystem paths like
        /mnt/<case>/<image>_p2048/WINDOWS/system32/config/SOFTWARE
    that tools can process natively (no image::virtual::path hacks).

    Classification uses the same extension/header logic as _inventory_evidence,
    adapted for files found inside mounted images.
    """
    _fe_log(job_id, "\U0001F4C2 Mount & Discover: mounting partitions and walking filesystems")

    disk_images = inventory.get("disk_images", [])
    if not disk_images:
        _fe_log(job_id, "  No disk images — mount discovery skipped")
        return {"nuclear_evidence": {}, "nuclear_findings": [], "nuclear_images_processed": 0}

    # Evidence type buckets for newly discovered artifacts
    new_evidence = {
        "nested_disk_images": [],   # E01/DD/VMDK/VHDX/QCOW2 found inside image
        "email_files": [],           # PST/OST/DBX/EML/MBOX
        "sqlite_dbs": [],            # SQLite databases
        "browser_artifacts": [],     # Chrome/Firefox/Edge/Safari data
        "archives_inside": [],       # ZIP/7z/tar.gz found inside image
        "registry_hives": [],        # Registry files found inside image
        "evtx_logs": [],             # Event logs found inside image
        "evt_logs": [],              # Legacy event logs inside image
        "documents": [],             # Office/PDF docs
        "memory_dumps_inside": [],   # hiberfil.sys, pagefile.sys
    }
    nuclear_findings = []

    # --- Classification pattern sets (same as _inventory_evidence + nuclear patterns) ---
    disk_ext = frozenset({'.e01', '.ee01', '.e02', '.e03', '.e04',
                           '.dd', '.raw', '.img', '.001', '.002',
                           '.aff', '.aff4', '.ex01',
                           '.vmdk', '.vhd', '.vhdx', '.qcow2', '.qcow',
                           '.iso', '.dmg'})
    mem_ext  = frozenset({'.vmem', '.mem', '.dmp', '.core', '.lime', '.mdmp', '.hdmp'})
    email_ext = frozenset({'.pst', '.ost', '.dbx', '.eml', '.mbox', '.msg', '.emlx',
                            '.msf', '.oab', '.olk14', '.olk15', '.pab', '.nst'})
    archive_ext = frozenset({'.zip', '.7z', '.rar', '.tar', '.gz', '.bz2', '.xz', '.lz',
                              '.cab', '.arj', '.lzh', '.ace'})
    registry_names = frozenset({
        'ntuser.dat', 'system', 'software', 'security', 'sam', 'amcache.hve',
        'usrclass.dat', 'default', 'system.sav', 'software.sav',
        'components', 'bcd-template', 'drivers',
    })
    evtx_ext = frozenset({'.evtx'})
    evt_ext  = frozenset({'.evt'})
    doc_ext  = frozenset({
        '.docx', '.doc', '.docm', '.dotx', '.dotm',
        '.xlsx', '.xls', '.xlsm', '.xltx', '.xltm',
        '.pptx', '.ppt', '.pptm', '.potx', '.potm',
        '.pdf', '.odt', '.ods', '.odp', '.rtf',
        '.one', '.onetoc2',
    })

    # Memory dump filenames (exact)
    _memory_file_names = frozenset({
        'hiberfil.sys', 'pagefile.sys', 'swapfile.sys',
        'memory.dmp', 'kernel.dmp',
    })
    # Browser artifact filenames
    _browser_filenames = frozenset({
        'places.sqlite', 'cookies.sqlite', 'cookies.db',
        'bookmarks', 'downloads.sqlite', 'formhistory.sqlite',
        'permissions.sqlite', 'sessionstore.js', 'sessionstore.jsonlz4',
        'sessionstore-backups', 'login data', 'web data', 'favicons',
        'top sites', 'shortcuts',
    })

    # --- Build mount base directory ---
    mount_base = f"{CASES_WORK_DIR}/mounts/{case_name}"
    os.makedirs(mount_base, exist_ok=True)

    images_processed = 0
    _MAX_FILES_PER_IMAGE = 50000  # Safety cap

    for img_path in disk_images:
        offset = image_offsets.get(img_path)
        if offset is None:
            _fe_log(job_id, f"  ⚠ No partition offset for {Path(img_path).name} — skipping")
            continue

        # Compute byte offset: start_sector * 512
        byte_offset = offset * 512
        img_stem = Path(img_path).stem
        mount_point = f"{mount_base}/{img_stem}_p{offset}"

        # --- Multi-partition enumeration via mmls ---
        # Enumerate ALL partitions so dual-boot/GPT disks don't miss partitions
        all_partitions = []  # list of (start_sector, description, fs_type)
        try:
            mmls_r = subprocess.run(
                ["mmls", img_path], capture_output=True, text=True, timeout=30,
            )
            if mmls_r.returncode == 0:
                for mmls_line in mmls_r.stdout.splitlines():
                    mmls_line = mmls_line.strip()
                    if not mmls_line or mmls_line.startswith("Slot") or mmls_line.startswith("---") or mmls_line.startswith("Offset") or mmls_line.startswith("Units"):
                        continue
                    parts = mmls_line.split()
                    # mmls format:  slot: start end length desc
                    # Or:  start end length desc
                    start_sector = None
                    desc_parts = []
                    # Try format with slot prefix
                    m1 = re.match(r'^\d+:\s+\d+:\d+\s+(\d+)\s+(\d+)\s+(\d+)\s+(.*)', mmls_line)
                    if m1:
                        start_sector = int(m1.group(1))
                        desc = m1.group(4).strip()
                    else:
                        m2 = re.match(r'^\d+:\s+(\d+)\s+(\d+)\s+(\d+)\s+(.*)', mmls_line)
                        if m2:
                            start_sector = int(m2.group(1))
                            desc = m2.group(4).strip()
                    if start_sector is not None and start_sector > 0:
                        desc_lower = desc.lower()
                        fs_type = ""
                        for fs_name in ["ntfs", "ext", "fat", "hfs", "hfs+", "linux", "windows"]:
                            if fs_name in desc_lower:
                                fs_type = fs_name
                                break
                        all_partitions.append((start_sector, desc, fs_type))
                if all_partitions:
                    _fe_log(job_id, f"  📋 mmls: {len(all_partitions)} partition(s) found for {Path(img_path).name}")
                    for ps, pd, pf in all_partitions:
                        _fe_log(job_id, f"      Sector {ps}: {pd}")
                    # Use first filesystem partition if the existing offset is the same
                    # but also collect all others
        except Exception as mmls_e:
            _fe_log(job_id, f"  ⚠ mmls enumeration failed for {Path(img_path).name}: {mmls_e}")

        # Build list of (offset, description) tuples to mount
        mount_offsets = []
        if all_partitions:
            for ps, pd, pf in all_partitions:
                if pf:  # Only mount partitions with recognized filesystems
                    mount_offsets.append((ps * 512, pd))
        if not mount_offsets:
            # Fallback: just the original offset
            mount_offsets.append((byte_offset, "primary"))

        _fe_log(job_id, f"  📋 Will mount {len(mount_offsets)} partition(s) for {Path(img_path).name}")
        _partition_offsets_tracked = {}  # partition_mount_point -> sector_offset

        # --- BitLocker detection ---
        # Check for BitLocker header signature ("bdmv" at offset 3) on the raw volume
        _is_bitlocker = False
        try:
            with open(img_path, "rb") as _bf:
                _bf.seek(3)
                _bheader = _bf.read(4)
                if _bheader == b"bdmv":
                    _is_bitlocker = True
                    _fe_log(job_id, f"  🔒 BitLocker detected on {Path(img_path).name} (bdmv signature)")
        except Exception:
            pass

        if _is_bitlocker:
            _blk_mount_point = f"{mount_base}/{img_stem}_blk_{offset}"
            os.makedirs(_blk_mount_point, exist_ok=True)
            _dislocker = shutil.which("dislocker")
            if _dislocker:
                _fe_log(job_id, f"  🔓 Attempting dislocker mount...")
                try:
                    # dislocker-file to get a decrypted volume
                    _dl_result = subprocess.run(
                        [_dislocker, "-v", "-V", img_path, "-f", _blk_mount_point],
                        capture_output=True, text=True, timeout=120,
                    )
                    _dl_file = os.path.join(_blk_mount_point, "dislocker-file")
                    if _dl_result.returncode == 0 and os.path.exists(_dl_file):
                        _fe_log(job_id, f"  🔓 BitLocker decrypted via dislocker: {_dl_file}")
                        # Mount the decrypted volume
                        _dl_mount = f"{_blk_mount_point}/mnt"
                        os.makedirs(_dl_mount, exist_ok=True)
                        _dm_r = subprocess.run(
                            ["sudo", "mount", "-o", "ro,loop", _dl_file, _dl_mount],
                            capture_output=True, text=True, timeout=30,
                        )
                        if _dm_r.returncode == 0:
                            _active_mounts.append(_dl_mount)
                            _fe_log(job_id, f"  📌 Mounted decrypted BitLocker volume @ {_dl_mount}")
                            # Override mount_point to the decrypted mount
                            mount_point = _dl_mount
                            mounted = True
                        else:
                            _fe_log(job_id, f"  ⚠ dislocker: could not mount decrypted volume: {_dm_r.stderr.strip()[:200]}")
                    else:
                        _fe_log(job_id, f"  ⚠ dislocker mount failed (no key available): {_dl_result.stderr.strip()[:200]}")
                        # Flag as encrypted in findings (even without key, record it)
                        nuclear_findings.append({
                            "image": img_path,
                            "note": "ENCRYPTED — BitLocker volume requires key",
                            "evidence_type": "bitlocker_encrypted",
                        })
                except Exception as _bl_e:
                    _fe_log(job_id, f"  ⚠ dislocker error: {_bl_e}")
                    nuclear_findings.append({
                        "image": img_path,
                        "note": f"ENCRYPTED — BitLocker volume requires key (dislocker error: {str(_bl_e)[:100]})",
                        "evidence_type": "bitlocker_encrypted",
                    })
            else:
                _fe_log(job_id, f"  ⚠ dislocker not installed — BitLocker volume cannot be decrypted")
                nuclear_findings.append({
                    "image": img_path,
                    "note": "ENCRYPTED — BitLocker volume requires dislocker tool",
                    "evidence_type": "bitlocker_encrypted",
                })
            # If BitLocker was detected and decryption failed, still try standard mount as fallback
            if not mounted:
                _fe_log(job_id, f"  ⚠ Continuing with standard mount attempt as fallback for {Path(img_path).name}")

        # --- APFS volume enumeration ---
        # After mounting an APFS image, enumerate all APFS volumes
        _is_apfs = False
        _apfs_volumes = []
        try:
            # Check for APFS magic (NXSB) at offset 0 of container
            with open(img_path, "rb") as _af:
                _aheader = _af.read(4)
                if _aheader == b"NXSB" or _aheader == b"BSXN":
                    _is_apfs = True
                    _fe_log(job_id, f"  🍎 APFS container detected on {Path(img_path).name}")
        except Exception:
            pass

        if _is_apfs:
            _fsapfsinfo = shutil.which("fsapfsinfo")
            if _fsapfsinfo:
                try:
                    _apfs_result = subprocess.run(
                        [_fsapfsinfo, img_path],
                        capture_output=True, text=True, timeout=60,
                    )
                    if _apfs_result.returncode == 0:
                        # Parse output for volume names
                        _vol_re = re.compile(r'Name:\s+(.+)')
                        _vol_offset_re = re.compile(r'Volume\s+(\d+)\s+\(offset\s+(\d+)\)')
                        for _apline in _apfs_result.stdout.splitlines():
                            _vm = _vol_re.search(_apline)
                            if _vm:
                                _vol_name = _vm.group(1).strip()
                                _apfs_volumes.append({"name": _vol_name, "offset": None})
                            _vom = _vol_offset_re.search(_apline)
                            if _vom:
                                _vidx = int(_vom.group(1))
                                _voff = int(_vom.group(2))
                                if _vidx < len(_apfs_volumes):
                                    _apfs_volumes[_vidx]["offset"] = _voff
                        _fe_log(job_id, f"  🍎 APFS volumes found: {[v['name'] for v in _apfs_volumes]}")
                except Exception as _apfs_e:
                    _fe_log(job_id, f"  ⚠ fsapfsinfo error: {_apfs_e}")
            else:
                # Fallback: try apfs-fuse directly
                _apfs_fuse = shutil.which("apfs-fuse")
                if _apfs_fuse:
                    _fe_log(job_id, f"  🍎 Using apfs-fuse for APFS mounting")
                    _apfs_mount = f"{mount_base}/{img_stem}_apfs"
                    os.makedirs(_apfs_mount, exist_ok=True)
                    try:
                        _afuse_r = subprocess.run(
                            [_apfs_fuse, img_path, _apfs_mount],
                            capture_output=True, text=True, timeout=60,
                        )
                        if _afuse_r.returncode == 0:
                            _active_mounts.append(_apfs_mount)
                            _fe_log(job_id, f"  📌 apfs-fuse mounted @ {_apfs_mount}")
                            # List sub-volumes
                            for _d in Path(_apfs_mount).iterdir():
                                if _d.is_dir():
                                    _apfs_volumes.append({"name": _d.name, "offset": None,
                                                         "mount": str(_d), "fuse": True})
                    except Exception as _afuse_e:
                        _fe_log(job_id, f"  ⚠ apfs-fuse error: {_afuse_e}")

        for pidx, (part_byte_offset, part_desc) in enumerate(mount_offsets):
            part_mount_point = f"{mount_base}/{img_stem}_p{part_byte_offset // 512}"

        # Try common fallback if first mount attempt fails
        offsets_to_try = [byte_offset]
        if offset == 63:
            offsets_to_try.append(2048 * 512)  # Try GPT offset as fallback
        elif offset == 2048:
            offsets_to_try.append(63 * 512)    # Try legacy MBR offset as fallback

        mounted = False
        fls_image_processed = False  # Set when sleuthkit fallback found+classified items
        _mount_err_msg = ""
        for try_offset in offsets_to_try:
            if mounted:
                break
            try:
                os.makedirs(mount_point, exist_ok=True)
                # For EWF (E01): ewfmount then mount partition
                ewf_raw_dir = f"/tmp/geoff_ewf_{os.getpid()}"
                os.makedirs(ewf_raw_dir, exist_ok=True)
                ewf_result = subprocess.run(
                    ["ewfmount", img_path, ewf_raw_dir],
                    capture_output=True, text=True, timeout=60,
                )
                if ewf_result.returncode == 0:
                    ewf_device = f"{ewf_raw_dir}/ewf1"
                    raw_mount = ["sudo", "mount", "-o", f"ro,loop,offset={try_offset}", ewf_device, mount_point]
                    raw_r = subprocess.run(raw_mount, capture_output=True, text=True, timeout=30)
                    chk = subprocess.run(["mount"], capture_output=True, text=True, timeout=10)
                    if mount_point in chk.stdout:
                        _active_mounts.append(mount_point)
                        _fe_log(job_id, f"  📌 Mounted {Path(img_path).name} @ {mount_point} (ewf+offset={try_offset})")
                        mounted = True
                    elif try_offset == offsets_to_try[-1]:
                        _mount_err_msg = raw_r.stderr.strip()[:300]
                if not mounted:
                    # Fallback: direct mount for raw DD images
                    direct_cmd = [
                        "sudo", "mount", "-o", f"ro,loop,offset={try_offset}",
                        img_path, mount_point,
                    ]
                    direct_r = subprocess.run(direct_cmd, capture_output=True, text=True, timeout=30)
                    if direct_r.returncode == 0:
                        _active_mounts.append(mount_point)
                        _fe_log(job_id, f"  📌 Mounted {Path(img_path).name} @ {mount_point} (direct, offset={try_offset})")
                        mounted = True
                    else:
                        err = direct_r.stderr.strip()[:300]
                        _mount_err_msg = err
                        if try_offset == offsets_to_try[-1]:
                            _fe_log(job_id, f"  ✗ Mount failed for {Path(img_path).name}: {err}")

                        # Sleuthkit fallback for corrupted NTFS (e.g. 'Record 0 has no FILE magic').
                        # Run fls on ewf1 raw device (not the E01 directly) — avoids redundant
                        # EWF decompression and is significantly faster for large images.
                        _fe_log(job_id, f"  🔍 Falling back to sleuthkit walk for {Path(img_path).name}")
                        try:
                            ewf1_path = f"{ewf_raw_dir}/ewf1"
                            # Resolve E02/E03 segments to E01
                            base_img = img_path
                            for seg in [".E02", ".E03", ".E04", ".E05", ".e02", ".e03", ".e04", ".e05"]:
                                if base_img.endswith(seg):
                                    e01 = base_img[:-4] + ".E01"
                                    if os.path.isfile(e01):
                                        base_img = e01
                                    break
                            sk_device = ewf1_path if os.path.exists(ewf1_path) else base_img
                            sk_label = "ewf1-raw" if sk_device == ewf1_path else "E01-direct"
                            _fe_log(job_id, f"  🔍 Sleuthkit device: {sk_label}")

                            # Use mmls on ewf1 to discover the actual partition start sector
                            fls_offset = offset
                            if sk_device == ewf1_path:
                                mmls_r = subprocess.run(
                                    ["mmls", sk_device],
                                    capture_output=True, text=True, timeout=30,
                                )
                                if mmls_r.returncode == 0:
                                    for mmls_line in mmls_r.stdout.splitlines():
                                        parts = mmls_line.split()
                                        if len(parts) >= 5 and parts[0].rstrip(":").isdigit():
                                            try:
                                                start = int(parts[2])
                                                if start > 0:
                                                    fls_offset = start
                                                    _fe_log(job_id, f"  🔍 mmls partition offset: {fls_offset}")
                                                    break
                                            except (ValueError, IndexError):
                                                continue

                            # Case-specific extraction dir for icat output
                            extract_dir = f"/tmp/geoff_extract_{case_name}_{img_stem}"
                            os.makedirs(extract_dir, exist_ok=True)

                            # Resolve E02/E03 segments to E01 for fls (handles multi-part)
                            fls_target = sk_device
                            for seg in [".E02", ".E03", ".E04", ".E05", ".e02", ".e03", ".e04", ".e05"]:
                                if fls_target.endswith(seg):
                                    base = fls_target[:-4]
                                    e01 = base + ".E01"
                                    if os.path.isfile(e01):
                                        fls_target = e01
                                    break
                            fls_result = subprocess.run(
                                ["fls", "-o", str(fls_offset), "-r", fls_target],
                                capture_output=True, text=True, timeout=600,
                            )
                            if fls_result.returncode == 0:
                                found = 0
                                _reg_basenames = frozenset([
                                    "software", "system", "sam", "security", "default",
                                    "ntuser.dat", "usrclass.dat", "amcache.hve",
                                ])
                                for fls_line in fls_result.stdout.splitlines():
                                    if not fls_line.strip() or fls_line.strip().startswith("|"):
                                        continue
                                    tab_idx = fls_line.find("\t")
                                    if tab_idx < 0:
                                        continue
                                    meta_part = fls_line[:tab_idx].strip()
                                    name = fls_line[tab_idx + 1:].strip().replace('"', '')
                                    if not name:
                                        continue
                                    # inode addr like "25184-128-1" from "r/r 25184-128-1:"
                                    inode = meta_part.split()[-1].rstrip(":") if " " in meta_part else ""
                                    ext = Path(name).suffix.lower()
                                    basename_lower = Path(name).name.lower()
                                    internal_ref = f"{img_path}::{name}"

                                    ev_type = None
                                    if ext == ".evtx":
                                        ev_type = "evtx_logs"
                                    elif ext == ".evt":
                                        ev_type = "evt_logs"
                                    elif basename_lower in _reg_basenames:
                                        ev_type = "registry_hives"
                                    elif ext in (".e01", ".dd", ".raw", ".vmdk", ".vhdx", ".qcow2"):
                                        ev_type = "nested_disk_images"
                                    elif ext in (".pst", ".ost", ".dbx", ".eml", ".mbox"):
                                        ev_type = "email_files"
                                    elif basename_lower in _browser_filenames:
                                        ev_type = "browser_artifacts"
                                    elif ext in (".sqlite", ".sqlite3", ".db", ".db3") and basename_lower not in _reg_basenames:
                                        ev_type = "sqlite_dbs"

                                    if ev_type is None:
                                        continue

                                    # Extract registry hives, event logs, and PST/OST via icat so downstream
                                    # tools receive real files, not virtual image::path references
                                    extracted_path = internal_ref
                                    if ev_type in ("registry_hives", "evtx_logs") and inode:
                                        inode_num = inode.split("-")[0]
                                        safe_name = f"{Path(name).stem.lower()}_{inode_num}{ext}"
                                        out_path = os.path.join(extract_dir, safe_name)
                                        try:
                                            icat_r = subprocess.run(
                                                ["icat", "-o", str(fls_offset), sk_device, inode],
                                                capture_output=True, timeout=60,
                                            )
                                            if icat_r.returncode == 0 and icat_r.stdout:
                                                with open(out_path, "wb") as fout:
                                                    fout.write(icat_r.stdout)
                                                extracted_path = out_path
                                                _fe_log(job_id, f"  📥 icat: {basename_lower} → {out_path}")
                                        except Exception as icat_e:
                                            _fe_log(job_id, f"  ⚠ icat failed for {basename_lower}: {icat_e}")
                                    elif ext in (".pst", ".ost") and inode:
                                        # Extract PST/OST for email analysis.
                                        # Simple shell redirect (avoids OOM from capture_output).
                                        # If icat fails on the sleuthkit device, retry on the raw E01
                                        # path — sleuthkit handles EWF natively and this is often more
                                        # reliable for multi-part images.
                                        inode_num = inode.split("-")[0]
                                        safe_name = f"{Path(name).stem.lower()}_{inode_num}{ext}"
                                        out_path = os.path.join(extract_dir, safe_name)
                                        _extracted_ok = False

                                        # Method 1: icat via shell redirect on sleuthkit device
                                        icat_cmd = f"icat -o {fls_offset} {shlex.quote(str(sk_device))} {shlex.quote(inode)} > {shlex.quote(out_path)}"
                                        try:
                                            icat_shell = subprocess.run(
                                                ["bash", "-c", icat_cmd],
                                                capture_output=True, text=True, timeout=600,
                                            )
                                            if (icat_shell.returncode == 0 and os.path.isfile(out_path)
                                                    and os.path.getsize(out_path) > 0):
                                                extracted_path = out_path
                                                _extracted_ok = True
                                                _fe_log(job_id, f"  📥 icat pst: {name} → {out_path} "
                                                         f"({os.path.getsize(out_path)} bytes)")
                                            elif icat_shell.returncode != 0 and icat_shell.stderr:
                                                _fe_log(job_id, f"  ⚠ icat pst err: {icat_shell.stderr.strip()[:200]}")
                                        except subprocess.TimeoutExpired:
                                            _fe_log(job_id, f"  ⚠ icat pst timeout ({name})")
                                        except Exception as icat_e:
                                            _fe_log(job_id, f"  ⚠ icat pst failed ({name}): {icat_e}")

                                        # Method 2: icat directly on the raw E01 image path
                                        # (sleuthkit natively handles EWF, often more reliable)
                                        if not _extracted_ok:
                                            base_img_str = str(base_img)
                                            icat_cmd2 = (
                                                f"icat -o {fls_offset} {shlex.quote(base_img_str)} "
                                                f"{shlex.quote(inode)} > {shlex.quote(out_path)}"
                                            )
                                            try:
                                                icat_shell2 = subprocess.run(
                                                    ["bash", "-c", icat_cmd2],
                                                    capture_output=True, text=True, timeout=600,
                                                )
                                                if (icat_shell2.returncode == 0 and os.path.isfile(out_path)
                                                        and os.path.getsize(out_path) > 0):
                                                    extracted_path = out_path
                                                    _extracted_ok = True
                                                    _fe_log(job_id, f"  📥 icat pst (E01-dir): {name} → {out_path} "
                                                             f"({os.path.getsize(out_path)} bytes)")
                                                elif icat_shell2.returncode != 0 and icat_shell2.stderr:
                                                    _fe_log(job_id, f"  ⚠ icat pst E01 err: {icat_shell2.stderr.strip()[:200]}")
                                            except subprocess.TimeoutExpired:
                                                _fe_log(job_id, f"  ⚠ icat pst E01 timeout ({name})")
                                            except Exception as icat_e:
                                                _fe_log(job_id, f"  ⚠ icat pst E01 failed ({name}): {icat_e}")

                                        if not _extracted_ok:
                                            _fe_log(job_id, f"  ✗ icat pst FAILED for {name} — will try ewfmount fallback")
                                    elif ev_type in ("browser_artifacts", "sqlite_dbs") and inode:
                                        # Extract browser SQLite DBs for history/cookie analysis
                                        inode_num = inode.split("-")[0]
                                        safe_name = f"{Path(name).stem.lower()}_{inode_num}{ext}"
                                        out_path = os.path.join(extract_dir, safe_name)
                                        try:
                                            icat_r = subprocess.run(
                                                ["icat", "-o", str(fls_offset), sk_device, inode],
                                                capture_output=True, timeout=60,
                                            )
                                            if icat_r.returncode == 0 and icat_r.stdout:
                                                with open(out_path, "wb") as fout:
                                                    fout.write(icat_r.stdout)
                                                extracted_path = out_path
                                                _fe_log(job_id, f"  📥 icat db: {basename_lower} → {out_path}")
                                        except Exception as icat_e:
                                            _fe_log(job_id, f"  ⚠ icat failed for {basename_lower}: {icat_e}")

                                    new_evidence[ev_type].append(extracted_path)
                                    nuclear_findings.append({
                                        "image": img_path,
                                        "mount_point": None,
                                        "internal_path": name,
                                        "full_path": extracted_path,
                                        "filename": Path(name).name,
                                        "evidence_type": ev_type,
                                        "via": f"sleuthkit_{sk_label}",
                                    })
                                    found += 1

                                if found > 0:
                                    fls_image_processed = True
                                    _fe_log(job_id, f"  🔍 Sleuthkit found {found} items in "
                                            f"{Path(img_path).name} via {sk_label}")
                        except Exception as fls_e:
                            _fe_log(job_id, f"  ✗ Sleuthkit walk also failed: {fls_e}")

            except Exception as mount_exc:
                _mount_err_msg = str(mount_exc)[:300]
                _fe_log(job_id, f"  ✗ Mount error for {Path(img_path).name}: {mount_exc}")

        if not mounted and not fls_image_processed:
            # LLM-powered self-healing for pipeline infrastructure failures
            # (Skip self-heal when fls successfully found & classified items)
            if _attempt_heal is not None:
                healed = _attempt_heal(
                    module="system",
                    function="mount_disk",
                    params={
                        "img_path": img_path,
                        "offset": offset,
                        "mount_point": mount_point,
                    },
                    error_result={"status": "error", "stderr": _mount_err_msg or "Unknown mount error"},
                    job_id=job_id,
                    evidence_file=img_path,
                    evidence_type="disk_image",
                )
                if healed:
                    if healed.get("status") in ("skipped",) or healed.get("_heal_skipped"):
                        _fe_log(job_id, f"  ⎘ [HEAL] Skipped {Path(img_path).name}: {healed.get('_skip_reason', 'LLM skip')}")
                    elif healed.get("status") == "success" and healed.get("_self_healed"):
                        _fe_log(job_id, f"  ✓ [HEAL] {Path(img_path).name} mount healed: {healed.get('_heal_fix_type', 'unknown')}")
            continue

        # When mount failed but fls found items, extract via icat instead of os.walk
        if not mounted and fls_image_processed:
            _fe_log(job_id, f"  \U0001f50d Fls found items - extracting via icat for {Path(img_path).name}")
            ewf_raw_dir = f"/tmp/geoff_ewf_{os.getpid()}"
            os.makedirs(ewf_raw_dir, exist_ok=True)
            # E02/E03 segments need the base E01 file for ewfmount
            mount_img = img_path
            for seg in [".E02", ".E03", ".E04", ".E05", ".e02", ".e03", ".e04", ".e05"]:
                if mount_img.endswith(seg):
                    base = mount_img[:-4]
                    e01_path = base + ".E01"
                    if os.path.isfile(e01_path):
                        mount_img = e01_path
                    break
            ewf_sub = subprocess.run(["ewfmount", mount_img, ewf_raw_dir], capture_output=True, text=True, timeout=60)
            if ewf_sub.returncode == 0 and os.path.isfile(f"{ewf_raw_dir}/ewf1"):
                sk_dev = f"{ewf_raw_dir}/ewf1"
                extract_dir = Path(CASES_WORK_DIR) / "extractions" / f"geoff_extract_{case_name}_{Path(img_path).stem}"
                os.makedirs(str(extract_dir), exist_ok=True)
                for ev_type, paths in new_evidence.items():
                    if not isinstance(paths, (list, set)):
                        continue
                    for ref in list(paths):
                        if "::" not in str(ref):
                            continue
                        fname = str(ref).rsplit("::", 1)[-1]
                        ext = Path(fname).suffix.lower()
                        if ext not in (".pst", ".ost", ".dbx", ".eml", ".mbox", ".msg", ".evtx", ".evt", ".sqlite", ".db"):
                            if not any(x in fname.lower() for x in ["places", "cookies", "history", "bookmark", "favicon"]):
                                continue
                        fls_find = subprocess.run(["fls", "-o", str(offset), sk_dev, "/"], capture_output=True, text=True, timeout=60)
                        for fl in fls_find.stdout.split("\n"):
                            if Path(fname).name in fl:
                                fl_parts = fl.split()
                                if len(fl_parts) >= 2:
                                    inode = fl_parts[0].strip("*+-$").split("-")[0]
                                    if inode.lstrip("0123456789") == "":
                                        out_name = Path(fname).name
                                        # readpst outputs files without .eml extension - add it
                                        if ext in (".pst", ".ost") and not out_name.lower().endswith(".eml"):
                                            out_name = Path(fname).stem + ".eml"
                                        out_path = os.path.join(str(extract_dir), out_name)
                                        with open(out_path, "wb") as fh:
                                            subprocess.run(["icat", "-o", str(offset), sk_dev, inode], stdout=fh, stderr=subprocess.DEVNULL, timeout=600)
                                        if os.path.getsize(out_path) > 100:
                                            _fe_log(job_id, f"  \U0001f4e5 Extracted {Path(fname).name} ({os.path.getsize(out_path)} bytes)")
                                            if out_path not in inventory.get("other_files", []):
                                                inventory.setdefault("other_files", []).append(out_path)
                                        break
            images_processed += 1
            continue

        # --- Walk the mounted filesystem ---
        # --- Walk the mounted filesystem ---
        file_count = 0
        classified_count = 0

        try:
            for root, dirs, files in os.walk(mount_point):
                # Skip very deep recursion
                for f in files:
                    full_path = os.path.join(root, f)
                    if not os.path.isfile(full_path):
                        continue

                    file_count += 1
                    if file_count > _MAX_FILES_PER_IMAGE:
                        break

                    # --- Classify this file ---
                    name = os.path.basename(full_path)
                    name_lower = name.lower()
                    ext_lower = os.path.splitext(name_lower)[1]
                    path_lower = full_path.lower()

                    # Use content-type detection for known files
                    header_type = _detect_file_type_from_header(full_path)

                    matched_ev_type = None
                    matched_filename = name

                    # Primary: content-based detection
                    if header_type == "ewf_disk_image" or header_type in ("vmdk_image", "vhd_image", "qcow2_image", "iso_image", "dmg_image"):
                        matched_ev_type = "nested_disk_images"
                    elif header_type == "registry_hive":
                        matched_ev_type = "registry_hives"
                    elif header_type == "pcap":
                        matched_ev_type = "archives_inside"  # unexpected inside image, treat as archive
                    elif header_type == "memory_dump":
                        matched_ev_type = "memory_dumps_inside"

                    # Secondary: extension-based
                    if matched_ev_type is None:
                        if ext_lower in disk_ext:
                            matched_ev_type = "nested_disk_images"
                        elif ext_lower in mem_ext:
                            matched_ev_type = "memory_dumps_inside"
                        elif ext_lower in email_ext:
                            matched_ev_type = "email_files"
                        elif ext_lower in archive_ext:
                            matched_ev_type = "archives_inside"
                        elif ext_lower in evtx_ext:
                            matched_ev_type = "evtx_logs"
                        elif ext_lower in evt_ext:
                            matched_ev_type = "evt_logs"
                        elif ext_lower in doc_ext:
                            matched_ev_type = "documents"

                    # Tertiary: filename patterns
                    if matched_ev_type is None:
                        if name_lower in _memory_file_names:
                            matched_ev_type = "memory_dumps_inside"
                        elif name_lower in registry_names:
                            matched_ev_type = "registry_hives"
                        elif name_lower in _browser_filenames:
                            matched_ev_type = "browser_artifacts"
                        elif (ext_lower in ('.sqlite', '.sqlite3', '.db', '.db3')
                              and name_lower not in registry_names):
                            matched_ev_type = "sqlite_dbs"

                    # Quaternary: path-context patterns for browser artifacts,
                    # registry hives, and event logs
                    if matched_ev_type is None:
                        if any(pat in path_lower for pat in (
                            '/chrome/user data/', '/google/chrome/', '/chromium/',
                            '/firefox/profiles/', '/mozilla/firefox/',
                            '/microsoft/edge/', '/microsoftedge/',
                            '/brave/', '/opera/', '/vivaldi/',
                            '/safari/', '/library/safari/',
                            '/appdata/local/google/chrome/',
                            '/appdata/roaming/mozilla/firefox/',
                            '/.config/google-chrome/', '/.config/chromium/',
                            '/.mozilla/firefox/', '/.config/brave/',
                        )):
                            matched_ev_type = "browser_artifacts"
                        elif any(pat in path_lower for pat in (
                            '/system32/config/software',
                            '/system32/config/system',
                            '/system32/config/sam',
                            '/system32/config/security',
                            '/system32/config/default',
                            '/system32/config/components',
                            '/system32/config/bcd-template',
                            '/system32/config/drivers',
                            '/users/', '/documents and settings/',
                        )) and name_lower in registry_names:
                            matched_ev_type = "registry_hives"
                        elif any(pat in path_lower for pat in (
                            '/winevt/logs/', '/system32/config/appevent',
                            '/system32/config/secevent', '/system32/config/sysevent',
                        )):
                            matched_ev_type = "evtx_logs" if '/winevt/logs/' in path_lower else "evt_logs"
                        elif any(pat in path_lower for pat in (
                            'outlook', 'thunderbird', 'evolution', 'kmail',
                            'mutt', 'maildir', 'windows mail', 'outlook express',
                            '/mail/', '/imapmail/', '/maildir/',
                            '/appdata/local/microsoft/outlook/',
                            '/appdata/roaming/thunderbird/',
                            '/.thunderbird/', '/.local/share/evolution/',
                            '/library/mail/',
                        )):
                            matched_ev_type = "email_files"

                    if matched_ev_type and matched_ev_type in new_evidence:
                        # Use real path: fill_path for inventory
                        if full_path not in new_evidence[matched_ev_type]:
                            new_evidence[matched_ev_type].append(full_path)
                        nuclear_findings.append({
                            "image": img_path,
                            "mount_point": mount_point,
                            "internal_path": os.path.relpath(full_path, mount_point),
                            "full_path": full_path,
                            "filename": matched_filename,
                            "evidence_type": matched_ev_type,
                        })
                        classified_count += 1

                if file_count > _MAX_FILES_PER_IMAGE:
                    _fe_log(job_id, f"  ⚠ Capped at {_MAX_FILES_PER_IMAGE} files for {Path(img_path).name}")
                    break

        except Exception as walk_exc:
            _fe_log(job_id, f"  ✗ Walk error for {mount_point}: {walk_exc}")

        images_processed += 1
        _fe_log(job_id, f"    Classified {classified_count} interesting files out of {file_count} entries")

        # --- Ewfmount fallback: extract un-extracted email files (PST/OST) ---
        # When the fls walk found email files but icat failed (silently or with
        # errors), do a fresh ewfmount + fls + icat to extract the real file.
        _img_str = str(img_path)
        _email_virtuals = [
            nf for nf in nuclear_findings
            if nf.get("evidence_type") == "email_files"
            and "::" in str(nf.get("full_path", ""))
            and str(nf.get("image", "")) == _img_str
        ]
        if _email_virtuals:
            _fe_log(job_id, f"  🔄 Ewfmount fallback: {len(_email_virtuals)} email file(s) need extraction")
            _efb_dir = tempfile.mkdtemp(prefix="geoff_efb_")
            try:
                # Resolve E02/E03 to E01 for ewfmount
                _efb_img = _img_str
                for seg in [".E02", ".E03", ".E04", ".E05", ".e02", ".e03", ".e04", ".e05"]:
                    if _efb_img.endswith(seg):
                        _base = _efb_img[:-4]
                        _e01 = _base + ".E01"
                        if os.path.isfile(_e01):
                            _efb_img = _e01
                        break
                _ewf_ok = False
                try:
                    ewf_r = subprocess.run(
                        ["ewfmount", _efb_img, _efb_dir],
                        capture_output=True, text=True, timeout=60,
                    )
                    if ewf_r.returncode == 0 and os.path.isfile(f"{_efb_dir}/ewf1"):
                        _ewf_ok = True
                        _fe_log(job_id, f"  🔄 ewfmount OK: {_efb_dir}/ewf1")
                    else:
                        _fe_log(job_id, f"  ⚠ ewfmount fallback failed: {ewf_r.stderr.strip()[:200]}")
                except Exception as e:
                    _fe_log(job_id, f"  ⚠ ewfmount fallback error: {e}")

                if _ewf_ok:
                    _efb_dev = f"{_efb_dir}/ewf1"
                    # Discover partition offset via mmls
                    _efb_off = offset
                    mmls_r = subprocess.run(
                        ["mmls", _efb_dev], capture_output=True, text=True, timeout=30,
                    )
                    if mmls_r.returncode == 0:
                        for mline in mmls_r.stdout.splitlines():
                            mparts = mline.split()
                            if len(mparts) >= 5 and mparts[0].rstrip(":").isdigit():
                                try:
                                    s = int(mparts[2])
                                    if s > 0:
                                        _efb_off = s
                                        break
                                except (ValueError, IndexError):
                                    continue

                    _efb_extract = (Path(CASES_WORK_DIR) / "extractions" /
                                    f"geoff_efb_{case_name}_{Path(img_path).stem}")
                    os.makedirs(str(_efb_extract), exist_ok=True)

                    for nf in _email_virtuals:
                        _vref = str(nf["full_path"])
                        _vname = _vref.rsplit("::", 1)[-1]
                        _vpath = Path(_vname)
                        _vext = _vpath.suffix.lower()
                        if _vext not in (".pst", ".ost"):
                            continue

                        # Find full inode via fls -r (recursive)
                        _ff = subprocess.run(
                            ["fls", "-o", str(_efb_off), "-r", _efb_dev],
                            capture_output=True, text=True, timeout=120,
                        )
                        _found_inode = None
                        for _fl in _ff.stdout.splitlines():
                            # fls lines: "r/r 24012-128-3:    outlook.pst"
                            if _vname in _fl:
                                _tab = _fl.find("\t")
                                _meta = _fl[:_tab].strip() if _tab >= 0 else _fl.strip()
                                _inode_raw = _meta.split()[-1].rstrip(":")
                                if "-" in _inode_raw and _inode_raw.split("-")[0].isdigit():
                                    _found_inode = _inode_raw
                                    break

                        if not _found_inode:
                            _fe_log(job_id, f"  ⚠ fls fallback: could not find inode for {_vname}")
                            continue

                        _safe = f"{_vpath.stem.lower()}_{_found_inode.split('-')[0]}{_vext}"
                        _op = os.path.join(str(_efb_extract), _safe)
                        _icat_sh = (f"icat -o {_efb_off} {shlex.quote(_efb_dev)} "
                                    f"{shlex.quote(_found_inode)} > {shlex.quote(_op)}")
                        _icat_r = subprocess.run(
                            ["bash", "-c", _icat_sh],
                            capture_output=True, text=True, timeout=600,
                        )
                        if (_icat_r.returncode == 0 and os.path.isfile(_op)
                                and os.path.getsize(_op) > 0):
                            nf["full_path"] = _op
                            nf["via"] = "ewfmount_fallback"
                            # Update new_evidence in-place (replace virtual ref with real path)
                            for _et, _paths in new_evidence.items():
                                if _et == "email_files" and isinstance(_paths, list):
                                    for _i, _p in enumerate(_paths):
                                        if "::" in str(_p) and str(_p).endswith(f"::{_vname}"):
                                            _paths[_i] = _op
                                            break
                            _fe_log(job_id, f"  📥 efb fallback pst: {_vname} → {_op} "
                                     f"({os.path.getsize(_op)} bytes)")
                        else:
                            _fe_log(job_id, f"  ✗ efb fallback icat failed for {_vname}")
            finally:
                subprocess.run(["umount", _efb_dir], capture_output=True, timeout=10)
                shutil.rmtree(_efb_dir, ignore_errors=True)

        # --- Multi-partition: mount and walk remaining partitions ---
        # After the primary partition is processed, mount any additional partitions
        # found by mmls enumeration (dual-boot/GPT disks)
        if len(mount_offsets) > 1:
            _fe_log(job_id, f"  📋 Processing {len(mount_offsets)-1} additional partition(s)...")
            for pidx2, (part_byte_offset2, part_desc2) in enumerate(mount_offsets):
                if pidx2 == 0 and mounted:
                    # Primary partition already processed above
                    continue
                part_sector = part_byte_offset2 // 512
                part_mount_point2 = f"{mount_base}/{img_stem}_p{part_sector}"
                _fe_log(job_id, f"  📋 Additional partition #{pidx2}: sector {part_sector} ({part_desc2})")
                os.makedirs(part_mount_point2, exist_ok=True)
                try:
                    # Try direct mount for raw DD images
                    direct_r2 = subprocess.run(
                        ["sudo", "mount", "-o", f"ro,loop,offset={part_byte_offset2}",
                         img_path, part_mount_point2],
                        capture_output=True, text=True, timeout=30,
                    )
                    if direct_r2.returncode == 0:
                        chk2 = subprocess.run(["mount"], capture_output=True, text=True, timeout=10)
                        if part_mount_point2 in chk2.stdout:
                            _active_mounts.append(part_mount_point2)
                            _fe_log(job_id, f"  📌 Mounted additional partition @ {part_mount_point2}")
                            # Track partition offset
                            _partition_offsets_tracked[part_mount_point2] = part_sector
                            # Walk this partition for evidence files
                            try:
                                for root2, dirs2, files2 in os.walk(part_mount_point2):
                                    for f2 in files2:
                                        full_path2 = os.path.join(root2, f2)
                                        if not os.path.isfile(full_path2):
                                            continue
                                        name2 = os.path.basename(full_path2)
                                        name2_lower = name2.lower()
                                        ext2 = os.path.splitext(name2_lower)[1]
                                        path2_lower = full_path2.lower()
                                        header_type2 = _detect_file_type_from_header(full_path2)
                                        matched_ev_type2 = None
                                        if header_type2 in ("ewf_disk_image", "vmdk_image", "vhd_image", "qcow2_image", "iso_image", "dmg_image"):
                                            matched_ev_type2 = "nested_disk_images"
                                        elif header_type2 == "registry_hive":
                                            matched_ev_type2 = "registry_hives"
                                        elif header_type2 == "pcap":
                                            matched_ev_type2 = "archives_inside"
                                        elif header_type2 == "memory_dump":
                                            matched_ev_type2 = "memory_dumps_inside"
                                        if matched_ev_type2 is None:
                                            if ext2 in disk_ext:
                                                matched_ev_type2 = "nested_disk_images"
                                            elif ext2 in mem_ext:
                                                matched_ev_type2 = "memory_dumps_inside"
                                            elif ext2 in email_ext:
                                                matched_ev_type2 = "email_files"
                                            elif ext2 in archive_ext:
                                                matched_ev_type2 = "archives_inside"
                                            elif ext2 in evtx_ext:
                                                matched_ev_type2 = "evtx_logs"
                                            elif ext2 in evt_ext:
                                                matched_ev_type2 = "evt_logs"
                                            elif ext2 in doc_ext:
                                                matched_ev_type2 = "documents"
                                            elif name2_lower in _memory_file_names:
                                                matched_ev_type2 = "memory_dumps_inside"
                                            elif name2_lower in registry_names:
                                                matched_ev_type2 = "registry_hives"
                                            elif name2_lower in _browser_filenames:
                                                matched_ev_type2 = "browser_artifacts"
                                            elif ext2 in ('.sqlite', '.sqlite3', '.db', '.db3') and name2_lower not in registry_names:
                                                matched_ev_type2 = "sqlite_dbs"
                                            elif any(pat in path2_lower for pat in ('/chrome/user data/', '/firefox/profiles/', '/microsoft/edge/', '/safari/', '/appdata/local/google/chrome/', '/.mozilla/firefox/', '/library/safari/')):
                                                matched_ev_type2 = "browser_artifacts"
                                        if matched_ev_type2 and matched_ev_type2 in new_evidence:
                                            if full_path2 not in new_evidence[matched_ev_type2]:
                                                new_evidence[matched_ev_type2].append(full_path2)
                                            nuclear_findings.append({
                                                "image": img_path,
                                                "mount_point": part_mount_point2,
                                                "internal_path": os.path.relpath(full_path2, part_mount_point2),
                                                "full_path": full_path2,
                                                "filename": name2,
                                                "evidence_type": matched_ev_type2,
                                                "partition": part_sector,
                                            })
                            except Exception as walk_e2:
                                _fe_log(job_id, f"  ⚠ Walk error on additional partition {part_mount_point2}: {walk_e2}")
                    else:
                        err2 = direct_r2.stderr.strip()[:200]
                        _fe_log(job_id, f"  ⚠ Could not mount additional partition {part_sector}: {err2}")
                except Exception as mount_e2:
                    _fe_log(job_id, f"  ⚠ Additional partition mount error {part_sector}: {mount_e2}")

    # ------------------------------------------------------------------
    # Merge discovered evidence into inventory (real filesystem paths)
    # ------------------------------------------------------------------
    _merge_count = 0
    for ev_type, paths in new_evidence.items():
        if not paths:
            continue

        if ev_type == "nested_disk_images":
            for p in paths:
                if p not in inventory["disk_images"]:
                    inventory["disk_images"].append(p)
                    _merge_count += 1
        elif ev_type == "email_files":
            for p in paths:
                if p not in inventory["other_files"]:
                    inventory["other_files"].append(p)
                    _merge_count += 1
        elif ev_type == "sqlite_dbs":
            for p in paths:
                if p not in inventory["other_files"]:
                    inventory["other_files"].append(p)
                    _merge_count += 1
        elif ev_type == "browser_artifacts":
            for p in paths:
                if p not in inventory["other_files"]:
                    inventory["other_files"].append(p)
                    _merge_count += 1
        elif ev_type == "archives_inside":
            for p in paths:
                if p not in inventory["other_files"]:
                    inventory["other_files"].append(p)
                    _merge_count += 1
        elif ev_type == "registry_hives":
            for p in paths:
                if p not in inventory["registry_hives"]:
                    inventory["registry_hives"].append(p)
                    _merge_count += 1
        elif ev_type == "evtx_logs":
            for p in paths:
                if p not in inventory.get("evtx_logs", []):
                    inventory.get("evtx_logs", []).append(p)
                    _merge_count += 1
        elif ev_type == "evt_logs":
            for p in paths:
                if p not in inventory.get("evt_logs", []):
                    inventory.get("evt_logs", []).append(p)
                    _merge_count += 1
        elif ev_type == "documents":
            for p in paths:
                if p not in inventory["other_files"]:
                    inventory["other_files"].append(p)
                    _merge_count += 1
        elif ev_type == "memory_dumps_inside":
            for p in paths:
                if p not in inventory["memory_dumps"]:
                    inventory["memory_dumps"].append(p)
                    _merge_count += 1

    # Store nuclear findings in inventory for downstream reference
    inventory["nuclear_findings"] = nuclear_findings

    _fe_log(job_id, f"  ☢ Mount & Discover complete: {images_processed} images, "
             f"{_merge_count} new evidence items in inventory")
    for ev_type, paths in new_evidence.items():
        if paths:
            _fe_log(job_id, f"    {ev_type}: {len(paths)} found")

    # Post-processing: scan extract dirs for PST/OST files and convert to .eml via readpst
    # This handles cases where the sleuthkit walk found the file but icat extraction was skipped
    pst_scan = list(Path("/tmp").glob(f"geoff_extract_{case_name}*/**/*.pst"))
    pst_scan += list(Path("/tmp").glob(f"geoff_extract_{case_name}*/**/*.ost"))
    for pst_file in pst_scan:
        pst_path = str(pst_file)
        _fe_log(job_id, f"  \U0001f4e5 Post-scan discovered PST: {pst_path}")
        eml_dir = tempfile.mkdtemp(prefix="pst_post_extract_")
        try:
            rp = subprocess.run(["readpst", "-M", "-o", eml_dir, pst_path], capture_output=True, text=True, timeout=600)
            if rp.returncode == 0:
                for root, dirs, files in os.walk(eml_dir):
                    for fn in files:
                        fp = os.path.join(root, fn)
                        if os.path.getsize(fp) > 50:
                            # Rename to .eml if needed
                            if not fn.lower().endswith(".eml"):
                                new_fp = fp + ".eml"
                                shutil.copy2(fp, new_fp)
                                inventory.setdefault("other_files", []).append(new_fp)
                            else:
                                inventory.setdefault("other_files", []).append(fp)
                            _fe_log(job_id, f"    \U0001f4e5 Added email: {fp} from PST")
        except Exception as pst_e:
            _fe_log(job_id, f"    \u26a0 PST post-extraction failed: {pst_e}")
        finally:
            shutil.rmtree(eml_dir, ignore_errors=True)

    return {
        "nuclear_evidence": new_evidence,
        "nuclear_findings": nuclear_findings,
        "nuclear_images_processed": images_processed,
    }


# ===========================================================================
# Evidence Inventory (filesystem walk + classification)
# ===========================================================================

def _inventory_evidence(evidence_path: Path) -> dict:
    """Walk the evidence directory and categorise every file."""
    inventory = {
        "disk_images": [],
        "memory_dumps": [],
        "pcaps": [],
        "evtx_logs": [],
        "evt_logs": [],
        "syslogs": [],
        "registry_hives": [],
        "mobile_backups": [],
        "other_files": [],
        "total_size_bytes": 0,
        "file_hashes": {},  # path -> sha256
    }

    disk_ext = {'.e01', '.ee01', '.e02', '.e03', '.e04', '.dd', '.raw', '.img', '.001', '.002', '.aff', '.aff4', '.ex01'}
    mem_ext  = {'.vmem', '.mem', '.dmp', '.core', '.lin'}
    pcap_ext = {'.pcap', '.pcapng', '.cap'}
    registry_names = {'ntuser.dat', 'system', 'software', 'security', 'sam', 'amcache.hve',
                      'usrclass.dat', 'default', 'system.sav', 'software.sav'}
    mobile_indicators = {'info.plist', 'manifest.db', 'manifest.plist'}
    syslog_names = {'syslog', 'auth.log', 'kern.log', 'messages', 'secure', 'auth.log.1', 'daemon.log'}

    for item in evidence_path.rglob('*'):
        if not item.is_file():
            continue
        try:
            size = item.stat().st_size
        except OSError as e:
            print(f"[GEOFF] Cannot stat {item}: {e}", file=__import__('sys').stderr)
            size = 0
        inventory["total_size_bytes"] += size

        # Hash evidence files for chain of custody (skip very large files to prevent hangs)
        if size < 1_000_000_000:  # Skip hashing files over 1GB
            file_hash = _hash_file(str(item))
            inventory["file_hashes"][str(item)] = file_hash
            if file_hash == "hash_failed":
                inventory["integrity_failures"] = inventory.get("integrity_failures", []) + [str(item)]
        else:
            inventory["file_hashes"][str(item)] = "skipped_too_large"
            inventory["total_size_bytes"] += size

        ext = item.suffix.lower()
        name_lower = item.name.lower()

        # PRIMARY: Content-based detection from file header (magic bytes)
        header_type = _detect_file_type_from_header(str(item))

        # SECONDARY: Filename-based detection
        if header_type == "zip_archive" or header_type == "gzip_archive" or header_type == "tar_archive" or header_type == "7zip_archive":
            # Archive detected from header — check if it's mobile-related by name
            if any(ind in name_lower for ind in ('android', 'ios', 'iphone', 'ipad', 'pixel', 'galaxy', 'samsung', 'mobile', 'backup', 'cellebrite', 'extractions')):
                inventory["mobile_backups"].append(str(item))
            else:
                # Could be any archive — let AI decide later
                inventory["other_files"].append(str(item))
            continue
        elif header_type == "sqlite_db":
            # SQLite DBs are often mobile artifacts (contacts, messages, etc.)
            if any(ind in name_lower for ind in ('contacts', 'messages', 'sms', 'accounts', 'call', 'mail', 'chat', 'whatsapp', 'signal', 'telegram')):
                inventory["mobile_backups"].append(str(item))
            else:
                inventory["other_files"].append(str(item))
            continue
        elif header_type == "registry_hive":
            inventory["registry_hives"].append(str(item))
            continue
        elif header_type == "ewf_disk_image":
            inventory["disk_images"].append(str(item))
            continue
        elif header_type == "pcap":
            inventory["pcaps"].append(str(item))
            continue
        elif header_type == "memory_dump":
            inventory["memory_dumps"].append(str(item))
            continue

        # FALLBACK: Extension-based classification for known types
        # But first, use `file -b --mime-type` to verify the MIME type matches
        mime_type = ""
        try:
            mime_result = subprocess.run(
                ["file", "-b", "--mime-type", str(item)],
                capture_output=True, text=True, timeout=10
            )
            if mime_result.returncode == 0:
                mime_type = mime_result.stdout.strip()
        except Exception:
            pass

        # Map MIME types to evidence categories
        _mime_to_ev_type = {
            "application/x-ms-dos-executable": "other_files",
            "application/vnd.microsoft.portable-executable": "other_files",
            "application/x-executable": "other_files",
            "application/x-sharedlib": "other_files",
            "application/x-object": "other_files",
            "application/x-dosexec": "other_files",
            "text/plain": "other_files",
            "image/": "other_files",
            "video/": "other_files",
            "audio/": "other_files",
        }

        if mime_type:
            # Detect conflicting classifications — spoofed extension
            if ext in disk_ext and "disk" not in mime_type and "filesystem" not in mime_type and "application/octet-stream" not in mime_type:
                _fe_log(job_id, f"  ⚠ Extension spoof detected: {item.name} has .{ext} extension but MIME is {mime_type}")
            if ext in mem_ext and "core" not in mime_type and "octet-stream" not in mime_type and "application/x" not in mime_type:
                _fe_log(job_id, f"  ⚠ Extension spoof detected: {item.name} has .{ext} extension but MIME is {mime_type}")
            if ext == ".evtx" and "xml" not in mime_type and "octet-stream" not in mime_type:
                _fe_log(job_id, f"  ⚠ Extension spoof detected: {item.name} has .evtx extension but MIME is {mime_type}")
            if ext == ".evt" and "octet-stream" in mime_type and header_type != "unknown":
                _fe_log(job_id, f"  ⚠ Extension spoof detected: {item.name} has .evt extension but MIME is {mime_type}")

        if ext in disk_ext:
            inventory["disk_images"].append(str(item))
        elif ext in mem_ext:
            inventory["memory_dumps"].append(str(item))
        elif ext in pcap_ext:
            inventory["pcaps"].append(str(item))
        elif ext == '.evtx':
            inventory.get("evtx_logs", []).append(str(item))
        elif ext == '.evt':
            inventory.get("evt_logs", []).append(str(item))
        elif name_lower in registry_names:
            inventory["registry_hives"].append(str(item))
        elif name_lower in syslog_names or name_lower.startswith('syslog'):
            inventory["syslogs"].append(str(item))
        elif name_lower in mobile_indicators:
            inventory["mobile_backups"].append(str(item))
        else:
            inventory["other_files"].append(str(item))

    # --- AI-based classification for ambiguous files ---
    if AI_EVIDENCE_CLASSIFICATION and inventory["other_files"]:
        try:
            pass
        except Exception:
            pass

    return inventory


def _inventory_evidence_with_ai(evidence_path: Path, orchestrator, call_llm_func) -> dict:
    """Enhanced evidence inventory using AI-based classification.

    First runs fast extension-based classification, then uses:
    1. File header analysis (python-magic / file command)
    2. LLM reasoning for ambiguous files
    3. Critic validation for accuracy

    Returns inventory with 'ai_classified' metadata and confidence scores.
    """
    from evidence_classifier import AIEvidenceClassifier
    classifier = AIEvidenceClassifier(orchestrator, call_llm_func)
    return classifier.classify_evidence(evidence_path)


# ===========================================================================
# Inventory Validation (re-classify mis-categorized files)
# ===========================================================================

def _validate_inventory_classification(inventory: dict, job_id: str = None) -> dict:
    """Validate and re-classify files that may have been mis-categorized.

    Geoff should NEVER leave files unprocessed in evidence. This function:
      1. Re-scans every file in 'other_files' using content-based detection
      2. Moves files with detectable headers to the correct bucket
      3. Warns about files that appear misclassified
      4. Returns the corrected inventory with a 'validation_log'

    Files that cannot be positively identified remain in 'other_files'
    for the catch-all PB-SIFT-025 (Generic File Analysis).
    """
    validation_log = []
    moved = {k: [] for k in inventory if k != "other_files" and isinstance(inventory[k], list)}

    # Files to re-check: everything currently in 'other_files'
    to_check = list(inventory.get("other_files", []))

    # Guard against runaway validation on huge extractions (e.g. 500K+ iOS files)
    VALIDATION_LIMIT = 5000
    if len(to_check) > VALIDATION_LIMIT:
        _fe_log(job_id, f"  ⚠ {len(to_check)} files in other_files — validating first {VALIDATION_LIMIT} (rest to PB-SIFT-025)")
        to_check = to_check[:VALIDATION_LIMIT]

    still_other = []
    for fpath in to_check:
        # Skip directories, symlinks, etc.
        p = Path(fpath)
        if not p.is_file():
            still_other.append(fpath)
            continue

        # Fast header-based re-detection
        header_type = _detect_file_type_from_header(fpath)
        target_bucket = _HEADER_TYPE_MAP.get(header_type)

        if target_bucket and target_bucket in inventory and target_bucket != "other_files":
            # Move to correct bucket (only if it's a different bucket)
            if fpath not in inventory[target_bucket]:
                inventory[target_bucket].append(fpath)
            moved[target_bucket].append(fpath)
            msg = f"VALIDATION: {p.name} -> {target_bucket} (header: {header_type})"
            validation_log.append(msg)
            if job_id:
                _fe_log(job_id, f"  ⚠ {msg}")
        else:
            # Remains in other_files for generic analysis
            still_other.append(fpath)
            # Log detected type even if staying in other_files (audit trail)
            if header_type and job_id:
                _fe_log(job_id, f"  ✓ {p.name}: detected as {header_type} -> other_files (generic analysis)")

    # Update other_files to only contain unclassified files
    if len(inventory.get("other_files", [])) > VALIDATION_LIMIT:
        unvalidated = inventory["other_files"][VALIDATION_LIMIT:]
        inventory["other_files"] = still_other + unvalidated
    else:
        inventory["other_files"] = still_other

    # Log summary
    total_moved = sum(len(v) for v in moved.values())
    if total_moved > 0:
        summary = f"VALIDATION: {total_moved} file(s) reclassified from other_files"
        for bucket, files in moved.items():
            if files:
                summary += f" | {bucket}: {len(files)}"
        if job_id:
            _fe_log(job_id, f"  ⚠ {summary}")
        validation_log.insert(0, summary)
    else:
        validation_log.append("VALIDATION: No misclassifications detected")

    inventory["validation_log"] = validation_log
    return inventory


# ===========================================================================
# Archive Extraction
# ===========================================================================

def _extract_archive(archive_path: str, extract_dir: str | None = None,
                      job_id: str = None) -> dict:
    """Extract compressed archive (.tar.gz, .zip, .tar, .7z) for forensic analysis.

    Disk space is expected in DFIR. Extracts all contents so mobile and file
    analysis tools can process them natively.

    Returns {"status": "extracted", "extracted_dir": str, "files": list}
            or {"status": "error", "error": str}
    """
    import tarfile
    import zipfile
    import gzip
    import shutil

    archive = Path(archive_path)
    if not archive.exists():
        return {"status": "error", "error": f"Archive not found: {archive_path}"}

    # Use provided dir or create extraction dir in cases work dir (writable)
    if extract_dir is None:
        base_name = archive.name.replace('.tar.gz', '').replace('.tgz', '').replace('.zip', '').replace('.tar', '').replace('.7z', '').replace('.gz', '')
        extract_dir = os.path.join(CASES_WORK_DIR, "extractions", f"{base_name}_{hash(archive_path) % 10000:04d}")
    extract_path = Path(extract_dir)

    # If already extracted, return existing
    if extract_path.exists() and any(extract_path.iterdir()):
        existing_files = _list_extracted_files(extract_dir)
        return {
            "status": "already_extracted",
            "extracted_dir": str(extract_path),
            "files": existing_files,
            "file_count": len(existing_files),
        }

    try:
        extract_path.mkdir(parents=True, exist_ok=True)
        _fe_log(job_id, f"  📦 Extracting {archive.name} → {extract_dir}")
        start = time.time()

        # Detect archive type from header and extract
        with open(archive_path, "rb") as f:
            header = f.read(8)

        extracted_files = []

        if header[:2] == b'PK':
            # ZIP archive — may be password protected
            try:
                with zipfile.ZipFile(archive_path, 'r') as zf:
                    zf.extractall(extract_dir)
                extracted_files = _list_extracted_files(extract_dir)
            except (RuntimeError, zipfile.BadZipFile) as zip_err:
                err_str = str(zip_err).lower()
                if "password" in err_str or "encrypted" in err_str:
                    # Try common forensic passwords
                    _fe_log(job_id, f"  🔐 ZIP is password protected — trying common passwords...")
                    _passwords = ["infected", "malware", "virus", "password", "123456", ""]
                    _unlocked = False
                    for pw in _passwords:
                        try:
                            with zipfile.ZipFile(archive_path, 'r') as zf:
                                zf.extractall(extract_dir, pwd=pw.encode() if pw else None)
                            _fe_log(job_id, f"  🔓 ZIP unlocked with password: '{pw or '(empty)'}'")
                            _unlocked = True
                            break
                        except (RuntimeError, zipfile.BadZipFile):
                            continue
                    if _unlocked:
                        extracted_files = _list_extracted_files(extract_dir)
                    else:
                        return {"status": "error", "error": f"PASSWORD PROTECTED — archive requires password: {archive.name}"}
                else:
                    return {"status": "error", "error": f"ZIP extraction failed: {zip_err}"}

        elif header[:2] == b'\x1f\x8b':
            # GZIP compressed (tar.gz or single .gz file)
            if str(archive).endswith('.tar.gz') or str(archive).endswith('.tgz'):
                with tarfile.open(archive_path, 'r:gz') as tf:
                    tf.extractall(extract_dir)
            else:
                # Single .gz file
                out_path = extract_path / archive.stem
                with gzip.open(archive_path, 'rb') as gz:
                    with open(out_path, 'wb') as out:
                        shutil.copyfileobj(gz, out)
            extracted_files = _list_extracted_files(extract_dir)

        elif header[257:262] == b'ustar':
            # Plain TAR
            with tarfile.open(archive_path, 'r') as tf:
                tf.extractall(extract_dir)
            extracted_files = _list_extracted_files(extract_dir)

        elif header[:6] == b'7z\xbc\xaf\x27\x1c':
            # 7-Zip — requires p7zip-full
            result = safe_run(
                ["7z", "x", "-y", f"-o{extract_dir}", archive_path],
                timeout=3600
            )
            if result["code"] != 0:
                # Check if password is required
                stderr_lower = (result.get('stderr', '') or '').lower()
                stdout_lower = (result.get('stdout', '') or '').lower()
                if 'password' in stderr_lower or 'wrong password' in stdout_lower or 'can not open encrypted' in stderr_lower:
                    _fe_log(job_id, f"  🔐 7z is password protected — trying common passwords...")
                    _passwords = ["infected", "malware", "virus", "password", "123456", ""]
                    _unlocked = False
                    for pw in _passwords:
                        pw_result = safe_run(
                            ["7z", "x", "-y", f"-p{pw}", f"-o{extract_dir}", archive_path],
                            timeout=3600
                        )
                        if pw_result["code"] == 0:
                            _fe_log(job_id, f"  🔓 7z unlocked with password: '{pw or '(empty)'}'")
                            _unlocked = True
                            break
                    if _unlocked:
                        extracted_files = _list_extracted_files(extract_dir)
                    else:
                        return {"status": "error", "error": f"PASSWORD PROTECTED — 7z archive requires password: {archive.name}"}
                else:
                    return {"status": "error", "error": f"7z extraction failed: {result['stderr'][:200]}"}
            else:
                extracted_files = _list_extracted_files(extract_dir)

        else:
            return {"status": "error", "error": f"Unknown archive format: {archive.name}"}

        elapsed = time.time() - start
        _fe_log(job_id, f"  ✅ Extracted {len(extracted_files)} files ({elapsed:.1f}s)")

        return {
            "status": "extracted",
            "extracted_dir": str(extract_path),
            "files": extracted_files,
            "file_count": len(extracted_files),
            "elapsed_seconds": round(elapsed, 1),
        }

    except Exception as e:
        _fe_log(job_id, f"  ✗ Extraction failed: {e}")
        return {"status": "error", "error": str(e)}


def _list_extracted_files(extract_dir: str, max_files: int = 100000):
    """Recursively list all files in an extracted archive directory."""
    files = []
    for root, dirs, fnames in os.walk(extract_dir):
        for fname in fnames:
            files.append(os.path.join(root, fname))
        if len(files) > max_files:
            break
    return files


# ===========================================================================
# Indicator Scanning (filename scan, strings scan, content scan)
# ===========================================================================

def _is_indicator_match(haystack: str, needle: str) -> bool:
    """Match indicator patterns with word-boundary awareness.

    For patterns >= 5 chars: use word-boundary regex (\\b).
    For patterns < 5 chars: require exact word match (delimited by non-alphanumeric).
    This prevents 'scp' matching inside 'descriptor', 'c99' matching C99 standard refs, etc.
    """
    needle_lower = needle.lower()
    haystack_lower = haystack.lower()

    if len(needle_lower) >= 5:
        # Word-boundary regex for longer patterns
        try:
            return bool(re.search(r'\b' + re.escape(needle_lower) + r'\b', haystack_lower))
        except re.error:
            return needle_lower in haystack_lower
    else:
        # Short patterns: require non-alphanumeric delimiter on both sides
        # or match at start/end of string
        pattern = re.escape(needle_lower)
        try:
            return bool(re.search(r'(?<![a-zA-Z0-9])' + pattern + r'(?![a-zA-Z0-9])', haystack_lower))
        except re.error:
            return False


def _extract_match_context(haystack: str, needle: str, context_chars: int = 60) -> str:
    """Extract surrounding text where needle matched in haystack.

    Returns up to context_chars chars before and after the match,
    with the match position marked.
    """
    try:
        haystack_lower = haystack.lower()
        needle_lower = needle.lower()
        idx = haystack_lower.find(needle_lower)
        if idx == -1:
            import re as _re_ctx
            pattern = _re_ctx.escape(needle_lower)
            m = _re_ctx.search(r'(?<![a-zA-Z0-9])' + pattern + r'(?![a-zA-Z0-9])', haystack_lower)
            if m:
                idx = m.start()
            else:
                return "(no match context)"
        start = max(0, idx - context_chars)
        end = min(len(haystack), idx + len(needle) + context_chars)
        before = haystack[start:idx].replace(chr(10), ' ').replace(chr(13), ' ').replace(chr(9), ' ')
        match_text = haystack[idx:idx + len(needle)]
        after = haystack[idx + len(needle):end].replace(chr(10), ' ').replace(chr(13), ' ').replace(chr(9), ' ')
        prefix = "..." if start > 0 else ""
        suffix = "..." if end < len(haystack) else ""
        return f"{prefix}{before}>>>{match_text}<<<{after}{suffix}"
    except Exception:
        return "(context extraction error)"


def _compute_indicator_confidence(category: str, pattern: str, source_type: str) -> int:
    """Compute a 0-100 confidence score for an indicator hit.

    Scoring factors:
      - Source type reliability (filename_scan < strings_scan < content_scan)
      - Pattern length (longer = less likely false positive)
      - Category severity weight
    """
    source_weights = {
        "filename_scan": 25,
        "strings_scan": 35,
        "strings_scan_other": 30,
        "content_scan": 40,
        "direct_match": 45,
    }
    source_score = source_weights.get(source_type, 20)

    plen = len(pattern)
    if plen >= 16:
        length_bonus = 25
    elif plen >= 12:
        length_bonus = 20
    elif plen >= 8:
        length_bonus = 12
    elif plen >= 6:
        length_bonus = 6
    else:
        length_bonus = 0

    severity = SEVERITY_MAP.get(category, "MEDIUM")
    severity_weights = {"CRITICAL": 30, "HIGH": 20, "MEDIUM": 10, "LOW": 0, "INFO": 0}
    cat_score = severity_weights.get(severity, 10)

    total = source_score + length_bonus + cat_score
    return min(100, total)


def _scan_filenames_for_indicators(all_paths: list,
                                    triage_patterns: dict = None,
                                    severity_map: dict = None,
                                    mitre_tags: dict = None) -> list:
    """Phase 1: Scan file names for indicator patterns (word-boundary matching)."""
    if triage_patterns is None:
        triage_patterns = TRIAGE_PATTERNS
    if severity_map is None:
        severity_map = SEVERITY_MAP
    if mitre_tags is None:
        mitre_tags = MITRE_TAGS

    hits = []
    MIN_PATTERN_LENGTH = 5

    for category, patterns in triage_patterns.items():
        for pattern in patterns:
            if len(pattern) < MIN_PATTERN_LENGTH:
                continue
            for fpath in all_paths:
                if _is_indicator_match(fpath, pattern):
                    hits.append({
                        "category": category,
                        "pattern": pattern,
                        "file": fpath,
                        "severity": severity_map.get(category, "MEDIUM"),
                        "confidence": _compute_indicator_confidence(category, pattern, "filename_scan"),
                        "source": "filename_scan",
                        "context": _extract_match_context(str(fpath), pattern),
                        "mitre_techniques": mitre_tags.get(category, []),
                    })
                    break  # one hit per pattern is enough
    return hits


def _strings_scan(binary_evidence: list,
                   other_files: list = None,
                   triage_patterns: dict = None,
                   severity_map: dict = None,
                   mitre_tags: dict = None,
                   max_size: int = 2 * 1024**3) -> list:
    """Phase 2: Run strings against binary evidence files for keyword hits.

    Skip files > max_size (default 2GB) for triage — the full malware
    hunting playbook runs strings properly on large files.

    Args:
        binary_evidence: List of file paths for disk images and memory dumps.
        other_files: List of other binary files to scan (skip text files).
        triage_patterns: Indicator patterns map.
        severity_map: Severity level map.
        mitre_tags: MITRE ATT&CK tags map.
        max_size: Max file size in bytes for triage strings scan.
    """
    if triage_patterns is None:
        triage_patterns = TRIAGE_PATTERNS
    if severity_map is None:
        severity_map = SEVERITY_MAP
    if mitre_tags is None:
        mitre_tags = MITRE_TAGS

    hits = []
    MIN_PATTERN_LENGTH = 5

    # Phase 2a: strings on disk images and memory dumps
    for fpath in binary_evidence:
        try:
            file_size = Path(str(fpath)).stat().st_size if Path(str(fpath)).exists() else 0
            if file_size > max_size:
                continue
            result = safe_run(
                ["bash", "-c", f"strings -n 8 {shlex.quote(str(fpath))} | head -c 500000"],
                timeout=60
            )
            if result["code"] != 0:
                continue
            content_lower = result["stdout"].lower()
            for category, keywords in triage_patterns.items():
                for kw in keywords:
                    if len(kw) < MIN_PATTERN_LENGTH:
                        continue
                    if _is_indicator_match(content_lower, kw):
                        hits.append({
                            "category": category,
                            "pattern": kw,
                            "file": str(fpath),
                            "severity": severity_map.get(category, "MEDIUM"),
                            "confidence": _compute_indicator_confidence(category, kw, "strings_scan"),
                            "source": "strings_scan",
                            "context": _extract_match_context(content_lower, kw),
                            "mitre_techniques": mitre_tags.get(category, []),
                        })
                        break
        except (subprocess.TimeoutExpired, OSError, IOError):
            continue

    # Phase 2b: strings on binary other_files (skip text files)
    if other_files:
        _phase3_exts = {".evtx", ".log", ".txt", ".xml", ".json", ".csv",
                        ".sys", ".reg", ".ini", ".cfg", ".conf", ".bat",
                        ".ps1", ".vbs", ".js", ".html", ".php", ""}
        for fpath in other_files:
            if Path(str(fpath)).suffix.lower() in _phase3_exts:
                continue
            try:
                file_size = Path(str(fpath)).stat().st_size if Path(str(fpath)).exists() else 0
                if file_size > max_size:
                    continue
                result = safe_run(
                    ["bash", "-c", f"strings -n 8 {shlex.quote(str(fpath))} | head -c 500000"],
                    timeout=60,
                )
                if result["code"] != 0:
                    continue
                content_lower = result["stdout"].lower()
                for category, keywords in triage_patterns.items():
                    for kw in keywords:
                        if len(kw) < MIN_PATTERN_LENGTH:
                            continue
                        if _is_indicator_match(content_lower, kw):
                            hits.append({
                                "category": category,
                                "pattern": kw,
                                "file": str(fpath),
                                "severity": severity_map.get(category, "MEDIUM"),
                                "confidence": _compute_indicator_confidence(category, kw, "strings_scan_other"),
                                "source": "strings_scan_other",
                                "context": _extract_match_context(content_lower, kw),
                                "mitre_techniques": mitre_tags.get(category, []),
                            })
                            break
            except (subprocess.TimeoutExpired, OSError, IOError):
                continue

    return hits


def _content_scan(text_evidence: list,
                   triage_patterns: dict = None,
                   severity_map: dict = None,
                   mitre_tags: dict = None) -> list:
    """Phase 3: Direct content scan for text-accessible evidence files.

    Reads up to 512KB per file. Includes files with no extension
    (e.g. 'syslog', 'messages', 'secure').
    """
    if triage_patterns is None:
        triage_patterns = TRIAGE_PATTERNS
    if severity_map is None:
        severity_map = SEVERITY_MAP
    if mitre_tags is None:
        mitre_tags = MITRE_TAGS

    hits = []
    MIN_PATTERN_LENGTH = 5
    max_read_bytes = 512 * 1024  # 512KB per file

    for fpath_str in text_evidence:
        try:
            p = Path(fpath_str)
            if not p.exists() or not p.is_file():
                continue
            file_size = p.stat().st_size
            if file_size > 5 * 1024 * 1024:  # Skip files > 5MB
                continue
            with open(fpath_str, "rb") as f:
                content = f.read(max_read_bytes)
            content_lower = content.lower().decode("utf-8", errors="ignore")
            for category, keywords in triage_patterns.items():
                for kw in keywords:
                    if len(kw) < MIN_PATTERN_LENGTH:
                        continue
                    if _is_indicator_match(content_lower, kw):
                        hits.append({
                            "category": category,
                            "pattern": kw,
                            "file": fpath_str,
                            "severity": severity_map.get(category, "MEDIUM"),
                            "confidence": _compute_indicator_confidence(category, kw, "content_scan"),
                            "source": "content_scan",
                            "context": _extract_match_context(content_lower, kw),
                            "mitre_techniques": mitre_tags.get(category, []),
                        })
                        break  # one hit per category per file
        except (OSError, IOError, PermissionError):
            continue

    return hits


def _scan_triage_indicators(inventory: dict,
                             triage_patterns: dict = None,
                             severity_map: dict = None,
                             mitre_tags: dict = None) -> list:
    """Scan for high-signal triage patterns using filenames AND content.

    Phase 1: Scan file names for indicator patterns (word-boundary matching).
    Phase 2: Run strings against evidence files for keyword hits.
    Phase 3: For text-accessible evidence (logs, registry), scan directly.

    All hits include a 'confidence' field:
      - 'POSSIBLE': string/filename match only, not yet playbook-confirmed
      - 'CONFIRMED': would be set by playbook findings (not this function)
    """
    if triage_patterns is None:
        triage_patterns = TRIAGE_PATTERNS
    if severity_map is None:
        severity_map = SEVERITY_MAP
    if mitre_tags is None:
        mitre_tags = MITRE_TAGS

    all_paths = inventory["other_files"] + inventory["disk_images"]
    all_hits = []

    # Phase 1: Filename-based scanning
    all_hits.extend(_scan_filenames_for_indicators(all_paths, triage_patterns, severity_map, mitre_tags))

    # Phase 2: Strings scan on binary evidence
    binary_evidence = inventory.get("disk_images", []) + inventory.get("memory_dumps", [])
    all_hits.extend(_strings_scan(binary_evidence, inventory.get("other_files", []),
                                   triage_patterns, severity_map, mitre_tags))

    # Phase 3: Direct content scan for text-accessible evidence
    text_extensions = {".evtx", ".log", ".txt", ".xml", ".json", ".csv",
                       ".sys", ".reg", ".ini", ".cfg", ".conf", ".bat",
                       ".ps1", ".vbs", ".js", ".html", ".php", ""}
    text_evidence = []
    for fpath_str in (inventory.get("evtx_logs", []) + inventory.get("syslogs", []) +
                      inventory.get("other_files", [])):
        ext = Path(str(fpath_str)).suffix.lower()
        if ext in text_extensions:
            text_evidence.append(fpath_str)

    all_hits.extend(_content_scan(text_evidence, triage_patterns, severity_map, mitre_tags))

    # Deduplicate: keep first hit per (category, file) pair across all phases
    seen = set()
    deduped = []
    for h in all_hits:
        key = (h["category"], h["file"])
        if key not in seen:
            seen.add(key)
            deduped.append(h)

    return deduped


# ===========================================================================
# Tool availability check
# ===========================================================================

def _tool_available(module: str, function: str) -> bool:
    """Quick check whether the specialist function can actually run.

    For now we assume the specialist exists and will fail gracefully if the
    underlying CLI tool is missing.  The orchestrator returns an error dict
    with status='error' in that case, which we handle as a skip.
    """
    # We always attempt the call and handle errors; this function exists so
    # callers can do an optimistic check if they want.
    return True


# ===========================================================================
# Inventory path helpers and unprocessed-file classification
# ===========================================================================

def _all_inventory_paths(inventory: dict) -> set:
    """Flat set of every evidence file path across all evidence types."""
    skip_keys = {"total_size_bytes", "file_hashes", "integrity_failures"}
    paths = set()
    for key, value in inventory.items():
        if key not in skip_keys and isinstance(value, list):
            paths.update(str(p) for p in value)
    return paths


def _classify_unprocessed(
    all_paths: set,
    processed_paths: set,
    inventory: dict,
    execution_plan: list,
    playbook_steps: dict = None,
) -> list:
    """Return a list of dicts describing each unprocessed file and the reason.

    If playbook_steps is not provided, uses an empty dict (no playbook coverage).
    """
    if playbook_steps is None:
        playbook_steps = {}

    # Determine which evidence types have at least one step in the execution plan
    covered_ev_types = set()
    for pb_id in execution_plan:
        pb_def = playbook_steps.get(pb_id, {})
        covered_ev_types.update(pb_def.keys())

    # Item cap applies to types other than disk_images and memory_dumps
    UNCAPPED_TYPES = {"disk_images", "memory_dumps"}

    # Build reverse map: path -> ev_type
    skip_keys = {"total_size_bytes", "file_hashes", "integrity_failures"}
    path_to_evtype = {}
    for ev_type, items in inventory.items():
        if ev_type not in skip_keys and isinstance(items, list):
            for idx, p in enumerate(items):
                path_to_evtype[str(p)] = (ev_type, idx)

    unprocessed = []
    for path in sorted(all_paths - processed_paths):
        ev_type, item_idx = path_to_evtype.get(path, (None, None))

        if ev_type is None:
            reason = "not_in_inventory"
            detail = "File appears in evidence dir but was not classified by inventory."
        elif ev_type not in covered_ev_types:
            reason = "no_playbook_coverage"
            detail = (
                f"Evidence type '{ev_type}' has no steps in any loaded playbook "
                f"({', '.join(execution_plan) or 'none'})."
            )
        elif ev_type not in UNCAPPED_TYPES and item_idx is not None and item_idx >= 3:
            reason = "item_cap_exceeded"
            detail = (
                f"Evidence type '{ev_type}' caps processing at 3 items per run. "
                f"This file was item #{item_idx + 1}."
            )
        else:
            reason = "step_skipped_or_failed"
            detail = (
                "File's evidence type is covered and within item cap, but no step "
                "recorded it as evidence_file. It may have been skipped (idempotency) "
                "or the step failed before recording."
            )

        unprocessed.append({
            "path": path,
            "evidence_type": ev_type,
            "reason": reason,
            "detail": detail,
        })

    return unprocessed


# ===========================================================================
# VSS (Volume Shadow Copy) mount and discover
# ===========================================================================

def _mount_vss_snapshots(inventory: dict, image_offsets: dict,
                          case_name: str, job_id: str = None) -> dict:
    """Mount VSS (Volume Shadow Copy) snapshots for each disk image and
    classify files found inside.

    Returns a dict with:
      vss_evidence:  dict of evidence_type -> [paths found inside VSS mounts]
      vss_findings:  list of finding dicts with _source_vss tag
      vss_images_processed: int count of images with VSS snapshots found
      vss_snapshot_count: int total number of VSS snapshots processed
    """
    _fe_log(job_id, "📸 VSS: Scanning disk images for Volume Shadow Copies")

    disk_images = inventory.get("disk_images", [])
    if not disk_images:
        _fe_log(job_id, "  No disk images — VSS scan skipped")
        return {
            "vss_evidence": {}, "vss_findings": [],
            "vss_images_processed": 0, "vss_snapshot_count": 0,
        }

    # Evidence type buckets for VSS-discovered artifacts
    vss_evidence = {
        "nested_disk_images": [],
        "email_files": [],
        "sqlite_dbs": [],
        "browser_artifacts": [],
        "archives_inside": [],
        "registry_hives": [],
        "evtx_logs": [],
        "evt_logs": [],
        "documents": [],
        "memory_dumps_inside": [],
    }
    vss_findings = []

    # Classification pattern sets (same as _mount_and_discover)
    disk_ext = frozenset({'.e01', '.ee01', '.e02', '.e03', '.e04',
                           '.dd', '.raw', '.img', '.001', '.002',
                           '.aff', '.aff4', '.ex01',
                           '.vmdk', '.vhd', '.vhdx', '.qcow2', '.qcow',
                           '.iso', '.dmg'})
    mem_ext  = frozenset({'.vmem', '.mem', '.dmp', '.core', '.lime', '.mdmp', '.hdmp'})
    email_ext = frozenset({'.pst', '.ost', '.dbx', '.eml', '.mbox', '.msg', '.emlx',
                            '.msf', '.oab', '.olk14', '.olk15', '.pab', '.nst'})
    archive_ext = frozenset({'.zip', '.7z', '.rar', '.tar', '.gz', '.bz2', '.xz', '.lz',
                              '.cab', '.arj', '.lzh', '.ace'})
    registry_names = frozenset({
        'ntuser.dat', 'system', 'software', 'security', 'sam', 'amcache.hve',
        'usrclass.dat', 'default', 'system.sav', 'software.sav',
        'components', 'bcd-template', 'drivers',
    })
    evtx_ext = frozenset({'.evtx'})
    evt_ext  = frozenset({'.evt'})
    doc_ext  = frozenset({
        '.docx', '.doc', '.docm', '.dotx', '.dotm',
        '.xlsx', '.xls', '.xlsm', '.xltx', '.xltm',
        '.pptx', '.ppt', '.pptm', '.potx', '.potm',
        '.pdf', '.odt', '.ods', '.odp', '.rtf',
        '.one', '.onetoc2',
    })

    # Browser artifact filenames
    _browser_filenames = frozenset({
        'places.sqlite', 'cookies.sqlite', 'cookies.db',
        'bookmarks', 'downloads.sqlite', 'formhistory.sqlite',
        'permissions.sqlite', 'sessionstore.js', 'sessionstore.jsonlz4',
        'sessionstore-backups', 'login data', 'web data', 'favicons',
        'top sites', 'shortcuts',
    })

    # Memory dump filenames (exact)
    _memory_file_names = frozenset({
        'hiberfil.sys', 'pagefile.sys', 'swapfile.sys',
        'memory.dmp', 'kernel.dmp',
    })

    mount_base = f"/home/sansforensics/cases/mounts/{case_name}"
    os.makedirs(mount_base, exist_ok=True)

    vss_spec = VSS_Specialist()
    images_processed = 0
    total_snapshots = 0
    _MAX_FILES_PER_VSS = 20000  # Safety cap per snapshot

    for img_path in disk_images:
        offset = image_offsets.get(img_path)
        if offset is None:
            _fe_log(job_id, f"  ⚠ No partition offset for {Path(img_path).name} — skipping VSS")
            continue

        img_stem = Path(img_path).stem
        _fe_log(job_id, f"  📸 VSS: Checking {Path(img_path).name} for shadow copies...")

        # Step 1: List VSS snapshots
        list_result = vss_spec.list_vss(img_path)
        if list_result.get('status') != 'success':
            _fe_log(job_id, f"    No VSS snapshots or vshadowmount unavailable for {Path(img_path).name}")
            continue

        vss_nums = list_result.get('vss_numbers', [])
        if not vss_nums:
            _fe_log(job_id, f"    No VSS snapshots found in {Path(img_path).name}")
            continue

        _fe_log(job_id, f"    Found {len(vss_nums)} VSS snapshot(s): {vss_nums}")
        images_processed += 1

        # Step 2: Mount and walk each VSS snapshot
        for vss_num in vss_nums:
            mount_point = f"{mount_base}/{img_stem}_vss{vss_num}"
            os.makedirs(mount_point, exist_ok=True)

            mount_result = vss_spec.mount_vss(img_path, vss_num, mount_point)
            if mount_result.get('status') != 'success':
                _fe_log(job_id, f"    ✗ Failed to mount VSS#{vss_num} for {Path(img_path).name}")
                continue

            total_snapshots += 1
            _active_mounts.append(mount_point)
            _fe_log(job_id, f"    📌 VSS#{vss_num} mounted @ {mount_point}")

            # Step 3: Walk the VSS filesystem and classify files
            file_count = 0
            classified_count = 0
            try:
                for root, dirs, files in os.walk(mount_point):
                    for f in files:
                        full_path = os.path.join(root, f)
                        if not os.path.isfile(full_path):
                            continue

                        file_count += 1
                        if file_count > _MAX_FILES_PER_VSS:
                            break

                        name = os.path.basename(full_path)
                        name_lower = name.lower()
                        ext_lower = os.path.splitext(name_lower)[1]
                        path_lower = full_path.lower()

                        header_type = _detect_file_type_from_header(full_path)

                        matched_ev_type = None
                        matched_filename = name

                        # Primary: content-based detection
                        if header_type in ("ewf_disk_image", "vmdk_image", "vhd_image",
                                           "qcow2_image", "iso_image", "dmg_image"):
                            matched_ev_type = "nested_disk_images"
                        elif header_type == "registry_hive":
                            matched_ev_type = "registry_hives"
                        elif header_type == "memory_dump":
                            matched_ev_type = "memory_dumps_inside"

                        # Secondary: extension-based
                        if matched_ev_type is None:
                            if ext_lower in disk_ext:
                                matched_ev_type = "nested_disk_images"
                            elif ext_lower in mem_ext:
                                matched_ev_type = "memory_dumps_inside"
                            elif ext_lower in email_ext:
                                matched_ev_type = "email_files"
                            elif ext_lower in archive_ext:
                                matched_ev_type = "archives_inside"
                            elif ext_lower in evtx_ext:
                                matched_ev_type = "evtx_logs"
                            elif ext_lower in evt_ext:
                                matched_ev_type = "evt_logs"
                            elif ext_lower in doc_ext:
                                matched_ev_type = "documents"

                        # Tertiary: filename patterns
                        if matched_ev_type is None:
                            if name_lower in _memory_file_names:
                                matched_ev_type = "memory_dumps_inside"
                            elif name_lower in registry_names:
                                matched_ev_type = "registry_hives"
                            elif name_lower in _browser_filenames:
                                matched_ev_type = "browser_artifacts"
                            elif (ext_lower in ('.sqlite', '.sqlite3', '.db', '.db3')
                                  and name_lower not in registry_names):
                                matched_ev_type = "sqlite_dbs"

                        # Quaternary: path-context patterns
                        if matched_ev_type is None:
                            if any(pat in path_lower for pat in (
                                '/chrome/user data/', '/google/chrome/', '/chromium/',
                                '/firefox/profiles/', '/mozilla/firefox/',
                                '/microsoft/edge/', '/microsoftedge/',
                                '/brave/', '/opera/', '/vivaldi/',
                                '/safari/', '/library/safari/',
                                '/appdata/local/google/chrome/',
                                '/appdata/roaming/mozilla/firefox/',
                                '/.config/google-chrome/', '/.config/chromium/',
                                '/.mozilla/firefox/', '/.config/brave/',
                            )):
                                matched_ev_type = "browser_artifacts"
                            elif any(pat in path_lower for pat in (
                                '/system32/config/software',
                                '/system32/config/system',
                                '/system32/config/sam',
                                '/system32/config/security',
                                '/system32/config/default',
                                '/system32/config/components',
                                '/system32/config/bcd-template',
                                '/system32/config/drivers',
                                '/users/', '/documents and settings/',
                            )) and name_lower in registry_names:
                                matched_ev_type = "registry_hives"
                            elif any(pat in path_lower for pat in (
                                '/winevt/logs/', '/system32/config/appevent',
                                '/system32/config/secevent', '/system32/config/sysevent',
                            )):
                                matched_ev_type = "evtx_logs" if '/winevt/logs/' in path_lower else "evt_logs"
                            elif any(pat in path_lower for pat in (
                                'outlook', 'thunderbird', 'evolution', 'kmail',
                                'mutt', 'maildir', 'windows mail', 'outlook express',
                                '/mail/', '/imapmail/', '/maildir/',
                                '/appdata/local/microsoft/outlook/',
                                '/appdata/roaming/thunderbird/',
                                '/.thunderbird/', '/.local/share/evolution/',
                                '/library/mail/',
                            )):
                                matched_ev_type = "email_files"

                        if matched_ev_type and matched_ev_type in vss_evidence:
                            if full_path not in vss_evidence[matched_ev_type]:
                                vss_evidence[matched_ev_type].append(full_path)
                            vss_findings.append({
                                "image": img_path,
                                "vss_number": vss_num,
                                "mount_point": mount_point,
                                "internal_path": os.path.relpath(full_path, mount_point),
                                "full_path": full_path,
                                "filename": matched_filename,
                                "evidence_type": matched_ev_type,
                                "_source_vss": True,
                                "_source_label": f"VSS#{vss_num}",
                            })
                            classified_count += 1

                    if file_count > _MAX_FILES_PER_VSS:
                        break

            except Exception as walk_exc:
                _fe_log(job_id, f"    ✗ VSS walk error for VSS#{vss_num} @ {mount_point}: {walk_exc}")

            _fe_log(job_id, f"    VSS#{vss_num}: classified {classified_count} files out of {file_count} entries")

    # Step 4: Merge VSS-discovered evidence into inventory
    _merge_count = 0
    for ev_type, paths in vss_evidence.items():
        if not paths:
            continue

        if ev_type == "nested_disk_images":
            for p in paths:
                if p not in inventory["disk_images"]:
                    inventory["disk_images"].append(p)
                    _merge_count += 1
        elif ev_type == "email_files":
            for p in paths:
                if p not in inventory["other_files"]:
                    inventory["other_files"].append(p)
                    _merge_count += 1
        elif ev_type == "sqlite_dbs":
            for p in paths:
                if p not in inventory["other_files"]:
                    inventory["other_files"].append(p)
                    _merge_count += 1
        elif ev_type == "browser_artifacts":
            for p in paths:
                if p not in inventory["other_files"]:
                    inventory["other_files"].append(p)
                    _merge_count += 1
        elif ev_type == "archives_inside":
            for p in paths:
                if p not in inventory["other_files"]:
                    inventory["other_files"].append(p)
                    _merge_count += 1
        elif ev_type == "registry_hives":
            for p in paths:
                if p not in inventory["registry_hives"]:
                    inventory["registry_hives"].append(p)
                    _merge_count += 1
        elif ev_type == "evtx_logs":
            for p in paths:
                if p not in inventory.get("evtx_logs", []):
                    inventory.setdefault("evtx_logs", []).append(p)
                    _merge_count += 1
        elif ev_type == "evt_logs":
            for p in paths:
                if p not in inventory.get("evt_logs", []):
                    inventory.setdefault("evt_logs", []).append(p)
                    _merge_count += 1
        elif ev_type == "documents":
            for p in paths:
                if p not in inventory["other_files"]:
                    inventory["other_files"].append(p)
                    _merge_count += 1
        elif ev_type == "memory_dumps_inside":
            for p in paths:
                if p not in inventory["memory_dumps"]:
                    inventory["memory_dumps"].append(p)
                    _merge_count += 1

    # Store VSS findings in inventory for downstream reference
    inventory["vss_findings"] = vss_findings

    _fe_log(job_id, f"  📸 VSS Mount & Discover complete: {images_processed} images, "
             f"{total_snapshots} snapshots, {_merge_count} new evidence items in inventory")
    for ev_type, paths in vss_evidence.items():
        if paths:
            _fe_log(job_id, f"    {ev_type}: {len(paths)} found in VSS")

    return {
        "vss_evidence": vss_evidence,
        "vss_findings": vss_findings,
        "vss_images_processed": images_processed,
        "vss_snapshot_count": total_snapshots,
    }


# ===========================================================================
# A001 — User Identification from SAM + NTUSER.DAT
# ===========================================================================


def extract_local_users(inventory: dict, image_offsets: dict,
                        case_name: str, case_work_dir: str,
                        job_id: str = None) -> dict:
    """Extract local user accounts from SAM hives and profile directories.

    Walks the mount points of each disk image to enumerate \\Users\\*
    profile directories, then uses icat + reglookup on the SAM hive to
    resolve usernames to SIDs.  Writes user_map.json to the case work
    directory and returns a dict that subsequent specialists can use to
    tag findings with a username.

    Args:
        inventory:  Evidence inventory dict (must have "disk_images" key).
        image_offsets:  Dict mapping image paths to partition start sectors.
        case_name:  Evidence-path name used to locate mount points under
                    CASES_WORK_DIR/mounts/<case_name>/.
        case_work_dir:  Path to the case work directory (for output).
        job_id:  Optional async job ID for logging.

    Returns:
        dict:  {username: {sid, profile_path, last_login, created}}
    """
    import datetime
    import tempfile

    user_map: dict = {}
    mount_base = f"{CASES_WORK_DIR}/mounts/{case_name}"
    disk_images = inventory.get("disk_images", [])

    if not disk_images:
        _fe_log(job_id, "  [USERS] No disk images — user extraction skipped")
        _atomic_write(
            Path(case_work_dir) / "user_map.json",
            json.dumps(user_map, indent=2, default=str),
        )
        return user_map

    _fe_log(job_id, f"  [USERS] Extracting local users from {len(disk_images)} disk image(s)")

    # ------------------------------------------------------------------
    # Phase A: Walk mounted Users/* directories for profile enumeration
    # ------------------------------------------------------------------
    profile_meta: dict = {}   # mount_point / "Users" / <dirname> → metadata

    for img_path in disk_images:
        offset = image_offsets.get(img_path)
        if offset is None:
            _fe_log(job_id, f"  [USERS] ⚠ No partition offset for {Path(img_path).name} — skipping mount walk")
            continue

        img_stem = Path(img_path).stem
        mount_point = Path(f"{mount_base}/{img_stem}_p{offset}")

        if not mount_point.exists():
            _fe_log(job_id, f"  [USERS] Mount point not found: {mount_point}")
            continue

        # Try common Windows profile-root paths
        user_roots = [
            mount_point / "Users",
            mount_point / "users",
            mount_point / "Documents and Settings",
            mount_point / "documents and settings",
        ]
        users_dir = None
        for ur in user_roots:
            if ur.is_dir():
                users_dir = ur
                break

        if users_dir is None:
            _fe_log(job_id, f"  [USERS] No Users/Profiles directory found at {mount_point}")
            continue

        _fe_log(job_id, f"  [USERS] Scanning {users_dir} …")
        for entry in sorted(users_dir.iterdir(), key=lambda x: x.name):
            if not entry.is_dir():
                continue
            dirname = entry.name
            # Skip system folders
            if dirname.startswith(".") or dirname.lower() in (
                "all users", "default user", "default", "public",
                "administrator", "guest", "defaultaccount",
            ):
                continue

            # Collect directory-level metadata
            try:
                mtime = datetime.datetime.fromtimestamp(
                    entry.stat().st_mtime
                ).isoformat()
            except (OSError, ValueError):
                mtime = ""
            try:
                ctime = datetime.datetime.fromtimestamp(
                    entry.stat().st_ctime
                ).isoformat()
            except (OSError, ValueError):
                ctime = ""

            profile_meta.setdefault(mount_point, {})[dirname] = {
                "profile_path": str(entry),
                "last_login": mtime,
                "created": ctime,
            }

    _fe_log(job_id, f"  [USERS] Found {sum(len(v) for v in profile_meta.values())} profile dir(s) across {len(profile_meta)} mount(s)")

    # ------------------------------------------------------------------
    # Phase B: Extract SAM hive via icat and parse with reglookup
    # ------------------------------------------------------------------
    for img_path in disk_images:
        offset = image_offsets.get(img_path)
        if offset is None:
            continue

        _fe_log(job_id, f"  [USERS] Looking for SAM in {Path(img_path).name} (offset {offset}) …")

        try:
            # Use fls to find the SAM hive inode in System32/config
            fls_cmd = ["fls", "-o", str(offset), "-r", img_path]
            fls_result = subprocess.run(
                fls_cmd, capture_output=True, text=True, timeout=90,
            )

            sam_inode = None
            if fls_result.returncode == 0:
                for line in fls_result.stdout.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    # Skip fls metadata lines
                    if line.startswith("|") or "class" in line or "Slot" in line:
                        continue
                    # fls format: r/r 1234-128-3:  filename
                    # or: d/d 5678:  dirname
                    m = re.match(r'[d\-]/[r\-]\s+(\d+)[-:\s]', line)
                    if not m:
                        continue
                    # Extract filename from end of line (after last space)
                    name = line.split()[-1].strip('"\'') if line.split() else ""
                    path_lower = line.lower()
                    if name.lower() == "sam" and "config" in path_lower:
                        sam_inode = m.group(1)
                        _fe_log(job_id, f"  [USERS] SAM inode {sam_inode} found in {Path(img_path).name}")
                        break

            if sam_inode is None:
                _fe_log(job_id, f"  [USERS] SAM not found via fls in {Path(img_path).name}")
                continue

            # Extract SAM binary via icat
            icat_result = subprocess.run(
                ["icat", "-o", str(offset), img_path, sam_inode],
                capture_output=True, timeout=30,
            )
            if icat_result.returncode != 0 or len(icat_result.stdout) == 0:
                _fe_log(job_id, f"  [USERS] icat extraction of SAM failed for {Path(img_path).name}")
                continue

            sam_raw = icat_result.stdout
            _fe_log(job_id, f"  [USERS] Extracted SAM ({len(sam_raw)} bytes) from {Path(img_path).name}")

            # Write SAM to temp file for reglookup
            tmp_sam = tempfile.NamedTemporaryFile(suffix=".sam", delete=False)
            try:
                tmp_sam.write(sam_raw)
                tmp_sam.close()

                # reglookup — parse SAM registry hive
                reg_cmd = ["reglookup", tmp_sam.name]
                reg_result = subprocess.run(
                    reg_cmd, capture_output=True, text=True, timeout=60,
                )

                if reg_result.returncode != 0:
                    _fe_log(job_id, f"  [USERS] reglookup failed for SAM: {reg_result.stderr[:200]}")
                    continue

                # Parse reglookup output
                username_rids: dict = {}  # username → hex RID string
                domain_part = ""          # e.g., "3623811015-3361044348-30300820"
                for reg_line in reg_result.stdout.splitlines():
                    if reg_line.startswith("#") or not reg_line.strip():
                        continue
                    parts = reg_line.split("|")
                    if len(parts) < 3:
                        continue
                    key_path = parts[0].strip()
                    value_name = parts[1].strip()
                    value_data = parts[2].strip() if len(parts) > 2 else ""

                    # Match: SAM\SAM\Domains\Account\Users\Names\<username>
                    # The (default) value contains the RID as a hex string
                    uname_match = re.match(
                        r'SAM\\\\SAM\\\\Domains\\\\Account\\\\Users\\\\Names\\\\(.+)',
                        key_path,
                    )
                    if uname_match and value_name in ("(default)", ""):
                        try:
                            rid_int = int(value_data, 16) if value_data else 0
                            if rid_int > 0:
                                username_rids[uname_match.group(1)] = f"{rid_int:08x}"
                        except (ValueError, TypeError):
                            pass

                    # Extract domain identifier from SAM\SAM\Domains\Account\F key
                    # The F value contains binary data; domain subauthorities are at offset 0x30
                    if not domain_part and re.match(
                        r'SAM\\\\SAM\\\\Domains\\\\Account\\\\F',
                        key_path,
                    ):
                        if value_name in ("(default)", ""):
                            try:
                                raw_bytes = bytes.fromhex(value_data)
                                if len(raw_bytes) >= 0x3C:
                                    sub1 = int.from_bytes(raw_bytes[0x30:0x34], 'little')
                                    sub2 = int.from_bytes(raw_bytes[0x34:0x38], 'little')
                                    sub3 = int.from_bytes(raw_bytes[0x38:0x3C], 'little')
                                    domain_part = f"{sub1}-{sub2}-{sub3}"
                            except (ValueError, TypeError, IndexError):
                                pass

                # Build user_map entries from SAM data
                img_stem = Path(img_path).stem
                mp = Path(f"{mount_base}/{img_stem}_p{offset}")
                mount_profiles = profile_meta.get(mp, {})

                for username, rid_hex in username_rids.items():
                    # Skip built-in accounts
                    if username.lower() in (
                        "administrator", "guest", "defaultaccount",
                        "defaultuser0", "homegroupuser",
                    ):
                        continue

                    # Fetch profile metadata if available
                    pmeta = mount_profiles.get(username, {})
                    user_map[username] = {
                        "sid": f"S-1-5-21-{domain_part}-{rid_hex}" if domain_part else f"S-1-5-21-{rid_hex}",
                        "profile_path": pmeta.get("profile_path", ""),
                        "last_login": pmeta.get("last_login", ""),
                        "created": pmeta.get("created", ""),
                    }

                _fe_log(job_id, f"  [USERS] Parsed {len(username_rids)} user(s) from SAM in {Path(img_path).name}")

            finally:
                # Always clean up temp SAM file
                try:
                    os.unlink(tmp_sam.name)
                except OSError:
                    pass

        except Exception as e:
            _fe_log(job_id, f"  [USERS] Error processing SAM in {Path(img_path).name}: {e}")

    # Add any profile directories that didn't have SAM entries (orphaned profiles)
    for mp, profiles in profile_meta.items():
        for dirname, pmeta in profiles.items():
            if dirname not in user_map:
                user_map[dirname] = {
                    "sid": "",
                    "profile_path": pmeta.get("profile_path", ""),
                    "last_login": pmeta.get("last_login", ""),
                    "created": pmeta.get("created", ""),
                }

    # Write user_map.json to case work directory
    _atomic_write(
        Path(case_work_dir) / "user_map.json",
        json.dumps(user_map, indent=2, default=str),
    )

    _fe_log(job_id, f"  [USERS] ✓ user_map.json written with {len(user_map)} user(s)")
    return user_map


# ===========================================================================
# A006 — File Signature vs Extension Mismatch Detection
# ===========================================================================

# Mapping: extension → expected magic type patterns (substrings or whole strings)
# These are compared against the output of `file -b` to detect mismatches.
_EXPECTED_SIGNATURE_MAP = {
    # Office documents (all start with PK or OLE2)
    ".docx": ["Microsoft Word", "Word", "PK", "OLE2", "Composite Document File"],
    ".doc": ["Composite Document File", "OLE2", "Microsoft Word"],
    ".xlsx": ["Microsoft Excel", "Excel", "PK", "OLE2", "Composite Document File"],
    ".xls": ["Composite Document File", "OLE2", "Microsoft Excel"],
    ".pptx": ["Microsoft PowerPoint", "PowerPoint", "PK", "OLE2", "Composite Document File"],
    ".ppt": ["Composite Document File", "OLE2", "Microsoft PowerPoint"],
    ".pdf": ["PDF document", "PDF"],
    ".jpg": ["JPEG image", "JPEG", "JFIF", "EXIF"],
    ".jpeg": ["JPEG image", "JPEG", "JFIF", "EXIF"],
    ".png": ["PNG image", "PNG"],
    ".gif": ["GIF image", "GIF"],
    ".mp3": ["MPEG ADTS", "MP3", "MPEG layer 3", "Audio file with ID3"],
    ".mp4": ["ISO Media", "MP4", "MPEG-4", "QuickTime"],
    ".avi": ["AVI", "Microsoft AVI"],
    ".zip": ["Zip archive", "PK"],
    ".rar": ["RAR archive", "RAR"],
    ".7z": ["7-zip Archive", "7z"],
    ".tar": ["tar archive"],
    ".gz": ["gzip compressed", "gzip"],
    ".exe": ["PE32", "PE32+", "MS-DOS executable", "PE"],
    ".dll": ["PE32", "PE32+", "MS-DOS executable", "PE"],
    ".ps1": ["PowerShell", "ASCII text", "Unicode text", "UTF-8"],
    ".bat": ["ASCII text", "batch", "command"],
    ".vbs": ["ASCII text", "VBScript", "Unicode text"],
    ".py": ["ASCII text", "Python script", "Unicode text", "UTF-8"],
    ".js": ["ASCII text", "JavaScript", "Unicode text"],
}

# Mismatch patterns that are especially suspicious (commonly used for malware delivery)
_HIGH_VALUE_MISMATCHES = {
    "docx as media":  (".docx", ".mp3", ".mp4", ".avi"),
    "xlsx as image":  (".xlsx", ".jpg", ".png", ".gif"),
    "ppt as media":   (".ppt", ".pptx", ".mp4", ".mp3", ".avi"),
    "archive as image": (".zip", ".rar", ".7z", ".jpg", ".png"),
    "executable hidden": (".exe", ".dll", ".jpg", ".png", ".mp3", ".docx"),
}

_SUSPICIOUS_MEDIA_EXTENSIONS = frozenset({".mp3", ".mp4", ".avi", ".wmv", ".mov", ".flv", ".mkv"})
_SUSPICIOUS_IMAGE_EXTENSIONS = frozenset({".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp"})
_DOCUMENT_EXTENSIONS = frozenset({
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf",
    ".rtf", ".txt", ".csv", ".odt", ".ods", ".odp",
})


def _get_expected_signature(filename: str) -> str:
    """Return the canonical expected magic type label for a file extension."""
    ext = Path(filename).suffix.lower()
    sig_patterns = _EXPECTED_SIGNATURE_MAP.get(ext, [])
    if sig_patterns:
        return sig_patterns[0]  # Most specific/representative type
    return "unknown"


def _get_file_magic(path: str) -> str:
    """Run `file -b` on a path and return the (truncated) magic type string."""
    try:
        result = subprocess.run(
            ["file", "-b", path],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            # Take the primary file type (before any comma or semicolon)
            magic = result.stdout.strip().split(",")[0].split(";")[0].strip()
            return magic
        return "error"
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        return f"error: {e}"


def _classify_mismatch_severity(magic: str, ext: str, filename: str) -> str:
    """Classify severity of a signature/extension mismatch."""
    fname_lower = filename.lower()

    # CRITICAL: executable magic with document/media extension
    if any(kw in magic.lower() for kw in ["pe32", "ms-dos executable", "elf"]):
        if ext in _DOCUMENT_EXTENSIONS or ext in _SUSPICIOUS_MEDIA_EXTENSIONS or ext in _SUSPICIOUS_IMAGE_EXTENSIONS:
            return "CRITICAL"

    # HIGH: document magic (Office/Zip) with media/image extension (classic malware delivery)
    if "pk" in magic.lower() or "ole2" in magic.lower() or "composite document" in magic.lower():
        if ext in _SUSPICIOUS_MEDIA_EXTENSIONS:
            return "HIGH"
        if ext in _SUSPICIOUS_IMAGE_EXTENSIONS:
            return "HIGH"

    # HIGH: media magic with document extension (data exfil / covert channel)
    if any(kw in magic.lower() for kw in ["iso media", "mpeg", "quicktime", "avi"]):
        if ext in _DOCUMENT_EXTENSIONS:
            return "HIGH"

    # MEDIUM: any other unexpected combination
    if ext in _DOCUMENT_EXTENSIONS or ext in _SUSPICIOUS_MEDIA_EXTENSIONS or ext in _SUSPICIOUS_IMAGE_EXTENSIONS:
        return "MEDIUM"

    return "LOW"


def scan_file_signatures(
    user_map: dict = None,
    inventory: dict = None,
    case_name: str = None,
    job_id: str = None,
    max_files: int = 5000,
) -> list:
    """Walk user profile directories, run `file` on documents, detect mismatches.

    Compares magic-header type against file extension.  Flags mismatches
    that may indicate anti-forensics / malware delivery through disguised
    files (e.g. PE binary with .jpg extension, docx with .mp3, etc.).

    Args:
        user_map:  Dict of {username: {profile_path, ...}} from A001 extraction.
        inventory: Evidence inventory dict (may have mount paths in other_files).
        case_name: Case name used to locate mount points under CASES_WORK_DIR/mounts/.
        job_id: Optional async job ID for logging.
        max_files: Maximum files to scan (truncated to avoid runaway scans).

    Returns:
        List of dicts with keys:
            path, expected_type, actual_type, extension, severity, username
    """
    import datetime

    mismatches: list = []
    scanned_dirs: list = []
    start_ts = datetime.datetime.now().isoformat()

    # --- Source 1: Walk user profile directories from user_map ---
    if user_map:
        for username, udata in user_map.items():
            profile_path = udata.get("profile_path", "")
            if not profile_path or not os.path.isdir(profile_path):
                continue
            scanned_dirs.append(profile_path)
            _walk_profile_for_mismatches(profile_path, username, mismatches, max_files)

    # --- Source 2: Scan mount points for user directories ---
    if case_name:
        mount_base = Path(f"{CASES_WORK_DIR}/mounts/{case_name}")
        if mount_base.is_dir():
            for mount_point in mount_base.iterdir():
                if not mount_point.is_dir():
                    continue
                # Look for Users, users, home (Linux), or root-level profiles
                for user_root in [mount_point / "Users", mount_point / "users",
                                  mount_point / "home", mount_point / "export/home",
                                  mount_point / "Documents and Settings"]:
                    if user_root.is_dir():
                        scanned_dirs.append(str(user_root))
                        for entry in sorted(user_root.iterdir()):
                            if not entry.is_dir():
                                continue
                            dirname = entry.name
                            if dirname.lower() in (".", "..", "all users", "default user",
                                                   "default", "public", "administrator"):
                                continue
                            _walk_profile_for_mismatches(
                                str(entry), dirname, mismatches, max_files
                            )

    # --- Source 3: Fallback — walk other_files from inventory (standalone docs) ---
    if inventory:
        other_files = inventory.get("other_files", [])
        doc_count = 0
        for fpath in other_files:
            if doc_count >= max_files:
                break
            ext = Path(fpath).suffix.lower()
            if ext in _EXPECTED_SIGNATURE_MAP:
                _check_single_file(fpath, mismatches)
                doc_count += 1

    _fe_log(job_id, f"  [SIG-SCAN] Scanned {len(scanned_dirs)} profile dir(s), "
                     f"found {len(mismatches)} signature mismatches")
    return mismatches


def _walk_profile_for_mismatches(
    profile_path: str,
    username: str,
    mismatches: list,
    max_files: int,
) -> None:
    """Walk a single profile directory and check each document file."""
    checked = 0
    try:
        for root, dirs, files in os.walk(profile_path):
            if checked >= max_files:
                break
            # Skip common non-evidence subdirectories to stay fast
            dirs[:] = [d for d in dirs if not d.startswith(".") and d.lower() not in (
                "appdata/local/temp", "appdata/local/microsoft/windows/caches",
                "cache", "tmp",
            )]
            for fname in files:
                if checked >= max_files:
                    break
                ext = Path(fname).suffix.lower()
                if ext not in _EXPECTED_SIGNATURE_MAP:
                    continue
                fpath = os.path.join(root, fname)
                _check_single_file(fpath, mismatches, username)
                checked += 1
    except (PermissionError, OSError) as e:
        pass  # Skip inaccessible directories silently


def _check_single_file(
    fpath: str,
    mismatches: list,
    username: str = None,
) -> None:
    """Check a single file for signature/extension mismatch and append if found."""
    if not os.path.isfile(fpath):
        return

    magic = _get_file_magic(fpath)
    if not magic or magic == "error":
        return

    ext = Path(fpath).suffix.lower()
    expected = _get_expected_signature(fpath)

    # Check if magic contradicts the expected type
    is_mismatch = False
    if ext in _EXPECTED_SIGNATURE_MAP:
        expected_patterns = _EXPECTED_SIGNATURE_MAP[ext]
        # A mismatch occurs when NONE of the expected patterns appear in the magic output
        if not any(p.lower() in magic.lower() for p in expected_patterns):
            is_mismatch = True

    if is_mismatch:
        severity = _classify_mismatch_severity(magic, ext, fpath)
        mismatches.append({
            "path": fpath,
            "expected_type": expected,
            "actual_type": magic,
            "extension": ext,
            "severity": severity,
            "username": username or "unknown",
        })


# ===========================================================================
# A009 — Anti-Forensics Tool Signature Detection
# ===========================================================================

# Anti-forensics tool definitions: Prefetch globs, file path patterns,
# UserAssist search terms, and associated Windows registry key fragments.
_ANTI_FORENSICS_TOOLS = {
    "eraser": {
        "prefetch_patterns": ["ERASER.EXE-*.pf", "ERASER*.pf"],
        "file_patterns": [
            "**/Eraser/*.log",
            "**/Eraser/Eraser*.exe",
            "**/Eraser/**",
        ],
        "userassist_patterns": ["eraser"],
        "uninstall_keys": [],
    },
    "ccleaner": {
        "prefetch_patterns": [
            "CCLEANER*.EXE-*.pf", "CCLEANER64*.EXE-*.pf",
            "CCLEANER*.pf",
        ],
        "file_patterns": [
            "**/CCleaner/CCleaner.ini",
            "**/CCleaner/CCleaner*.exe",
            "**/CCleaner/**",
        ],
        "userassist_patterns": ["ccleaner"],
        "uninstall_keys": [
            r"Microsoft\Windows\CurrentVersion\Uninstall\CCleaner",
            r"Microsoft\Windows\CurrentVersion\Uninstall\{CCleaner}",
        ],
    },
    "sdelete": {
        "prefetch_patterns": ["SDELETE.EXE-*.pf", "SDELETE*.pf"],
        "file_patterns": [
            "**/Sysinternals/SDelete*",
            "**/Sysinternals/sdelete*",
            "**/sdelete*",
        ],
        "userassist_patterns": ["sdelete"],
        "uninstall_keys": [],
    },
    "bleachbit": {
        "prefetch_patterns": ["BLEACHBIT*.EXE-*.pf", "BLEACHBIT*.pf"],
        "file_patterns": ["**/BleachBit/**", "**/bleachbit*"],
        "userassist_patterns": ["bleachbit"],
        "uninstall_keys": [
            r"Microsoft\Windows\CurrentVersion\Uninstall\BleachBit",
        ],
    },
    "wevtutil": {
        "prefetch_patterns": [],
        "file_patterns": [],
        "userassist_patterns": [],
        "uninstall_keys": [],
    },
    "cipher_w": {
        "prefetch_patterns": [],
        "file_patterns": ["**/cipher.exe"],
        "userassist_patterns": ["cipher"],
        "uninstall_keys": [],
    },
}

# Common mount-point subdirectories to search for anti-forensics artifacts
_AF_SEARCH_DIRS = [
    "Windows/Prefetch",
    "WINDOWS/Prefetch",
    "windows/prefetch",
    "Program Files",
    "Program Files (x86)",
    "ProgramData",
    "Users",
    "Documents and Settings",
    "Windows/System32/winevt/Logs",
    "Windows/System32/config",
    "$Extend",
    "System Volume Information",
]


def detect_anti_forensics(
    inventory: dict = None,
    mount_points: list = None,
    device_map: dict = None,
    job_id: str = None,
) -> dict:
    """Detect anti-forensics tool artifacts across mounted evidence partitions.

    Scans mounted filesystem paths for known anti-forensic tool evidence:
    - Prefetch directory entries (.pf files) for tool execution
    - Tool-specific file paths (CCleaner.ini, Eraser logs, etc.)
    - UserAssist entries in NTUSER.DAT hives for execution counts
    - General patterns: large $UsnJrnl delta, VSS snapshot deletion

    Args:
        inventory: Case evidence inventory dict (from _inventory_evidence).
        mount_points: Optional list of active mount paths to scan.
                      Falls back to _active_mounts if not provided.
        device_map: Per-device evidence mapping for attribution.
        job_id: Optional job ID for logging.

    Returns:
        dict: {tool_name: {
            detected: bool,
            evidence: [path_strings],
            confidence: str ("HIGH"|"MEDIUM"|"LOW"),
            execution_count: int,
        }}
    """
    import fnmatch

    results: dict = {}

    # Resolve mount points to scan
    active_mounts: list = []
    if mount_points:
        active_mounts = list(mount_points)
    else:
        from geoff_utils import _active_mounts as _am
        with _state_lock:
            active_mounts = list(_am)

    if not active_mounts:
        _fe_log(job_id, "  [AF-DETECT] No active mounts — scanning inventory paths only")

    # Collect candidate paths from inventory and mount points
    search_paths: list = []

    # Add inventory evidence files
    if inventory:
        for ev_type in ("disk_images", "other_files", "registry_hives", "evtx_logs"):
            for fp in inventory.get(ev_type, []):
                if isinstance(fp, str) and os.path.exists(fp):
                    search_paths.append(fp)

    # Add mount point root directories
    for mp in active_mounts:
        if os.path.isdir(mp):
            search_paths.append(mp)
            # Add well-known subdirectories
            for sub in _AF_SEARCH_DIRS:
                candidate = os.path.join(mp, sub)
                if os.path.isdir(candidate):
                    search_paths.append(candidate)

    # Avoid duplicates
    search_paths = list(dict.fromkeys(search_paths))
    _fe_log(job_id, f"  [AF-DETECT] Scanning {len(search_paths)} path(s) for anti-forensics artifacts")

    # --- Scan each tool ---
    import glob as _glob

    for tool_name, tool_def in _ANTI_FORENSICS_TOOLS.items():
        evidence_paths: list = []
        execution_count: int = 0
        confidence_signals: int = 0

        # Check Prefetch directory
        for sp in search_paths:
            sp_lower = sp.lower()
            if "prefetch" in sp_lower and os.path.isdir(sp):
                for pattern in tool_def.get("prefetch_patterns", []):
                    try:
                        matches = _glob.glob(os.path.join(sp, pattern))
                        for m in matches:
                            if m not in evidence_paths:
                                evidence_paths.append(m)
                                confidence_signals += 1
                                # Extract execution count from prefetch filename
                                import re as _re
                                pf_count = _re.search(r'-([A-F0-9]+)\.pf$', os.path.basename(m), _re.I)
                                if pf_count:
                                    execution_count += 1
                    except Exception:
                        pass
                break  # Only check the first prefetch directory found

        # Check tool-specific file paths
        for sp in search_paths:
            for pattern in tool_def.get("file_patterns", []):
                try:
                    matches = _glob.glob(os.path.join(sp, pattern))
                    for m in matches:
                        if m not in evidence_paths:
                            evidence_paths.append(m)
                            confidence_signals += 1
                except Exception:
                    pass

        # Check UserAssist in NTUSER.DAT hives
        userassist_patterns = tool_def.get("userassist_patterns", [])
        if userassist_patterns and inventory:
            for hive_path in inventory.get("registry_hives", []):
                hive_lower = os.path.basename(hive_path).lower()
                if "ntuser.dat" in hive_lower:
                    try:
                        import subprocess as _sp
                        # Try to extract UserAssist via python-registry or regripper
                        # Use simple string scan as fallback
                        if os.path.isfile(hive_path):
                            # Try strings-based detection on the hive
                            _sr = _sp.run(
                                ["strings", "-n", "8", hive_path],
                                capture_output=True, text=True, timeout=30,
                            )
                            if _sr.returncode == 0:
                                output_lower = _sr.stdout.lower()
                                for up in userassist_patterns:
                                    if up in output_lower:
                                        if hive_path not in evidence_paths:
                                            evidence_paths.append(
                                                f"{hive_path}::UserAssist:{up}"
                                            )
                                            confidence_signals += 2  # stronger signal
                                    # Count occurrences as proxy for execution count
                                    execution_count += output_lower.count(up)
                    except Exception:
                        pass

        # Determine confidence
        confidence = "LOW"
        if confidence_signals >= 3:
            confidence = "HIGH"
        elif confidence_signals >= 1:
            confidence = "MEDIUM"

        results[tool_name] = {
            "detected": len(evidence_paths) > 0,
            "evidence": evidence_paths,
            "confidence": confidence,
            "execution_count": execution_count,
        }

        if evidence_paths:
            _fe_log(job_id,
                f"  [AF-DETECT] {tool_name}: detected={len(evidence_paths)} "
                f"evidence={confidence} count={execution_count}"
            )

    return results


# ===========================================================================
# A007 — $UsnJrnl Change Journal Forensics
# ===========================================================================

# USN_RECORD_V3 struct format (little-endian):
#   I=uint32 H=uint16 Q=uint64
#   RecordLength(I) + MajorVersion(H) + MinorVersion(H) +
#   FileReferenceNumber(Q) + ParentFileReferenceNumber(Q) +
#   Usn(Q) + Timestamp(Q) +
#   Reason(I) + SourceInfo(I) + SecurityId(I) + FileAttributes(I) +
#   FileNameLength(H) + FileNameOffset(H)
_USN_V3_HEADER_FMT = '<IHHQQQQIIIIHH'
_USN_V3_HEADER_SIZE = 60

# USN_RECORD_V4 same as V3 + MajorInfoOffsetInFile(I) at end
_USN_V4_HEADER_FMT = '<IHHQQQQIIIIIHH'
_USN_V4_HEADER_SIZE = 64

# USN reason flags (Microsoft NTFS)
_USN_REASON_DATA_OVERWRITE     = 0x00000001
_USN_REASON_DATA_EXTEND        = 0x00000002
_USN_REASON_DATA_TRUNCATION    = 0x00000004
_USN_REASON_FILE_CREATE        = 0x00000100
_USN_REASON_FILE_DELETE        = 0x00000200
_USN_REASON_RENAME_OLD_NAME    = 0x00001000
_USN_REASON_RENAME_NEW_NAME    = 0x00002000
_USN_REASON_CLOSE              = 0x80000000

_REASON_LABELS = {
    0x00000001: 'DATA_OVERWRITE',
    0x00000002: 'DATA_EXTEND',
    0x00000004: 'DATA_TRUNCATION',
    0x00000100: 'FILE_CREATE',
    0x00000200: 'FILE_DELETE',
    0x00001000: 'RENAME_OLD_NAME',
    0x00002000: 'RENAME_NEW_NAME',
    0x80000000: 'CLOSE',
}


def _decode_reasons(reason_mask: int) -> str:
    """Decode a USN reason bitmask into comma-separated label string."""
    parts = []
    for bitmask, label in sorted(_REASON_LABELS.items()):
        if reason_mask & bitmask:
            parts.append(label)
    return '|'.join(parts) if parts else hex(reason_mask)


def parse_usnjrnl(journal_path: str = None,
                  image_path: str = None,
                  partition_offset: int = None,
                  mft_inode: int = None,
                  max_records: int = 10_000_000,
                  job_id: str = None) -> list:
    """Parse $UsnJrnl:$J change journal records from a Windows NTFS volume.

    Supports two input modes:
      1. **Mounted filesystem** — pass *journal_path* pointing to the
         ``\$Extend\$UsnJrnl:\$J`` file on a mounted partition.
      2. **Raw image + icat** — pass *image_path*, *partition_offset* (in
         512-byte sectors), and *mft_inode* of the ``\$Extend\$UsnJrnl``
         directory entry to extract the ``$J`` stream via ``icat``.

    Returns a list of dicts, each containing:
        ``timestamp`` (ISO), ``filename`` (str), ``parent_path`` (str or None),
        ``reason`` (int), ``reason_label`` (str), ``usn`` (int),
        ``file_reference_number`` (hex str).

    Only records matching one of the *target_reasons* are retained:
        DATA_OVERWRITE, FILE_DELETE, RENAME_OLD_NAME, RENAME_NEW_NAME.
    """
    # --- Target reasons (forensically interesting) ---
    target_reasons = (
        _USN_REASON_DATA_OVERWRITE |
        _USN_REASON_FILE_DELETE |
        _USN_REASON_RENAME_OLD_NAME |
        _USN_REASON_RENAME_NEW_NAME
    )

    # Approach 1: mounted filesystem path
    raw_data = b''
    if journal_path and os.path.isfile(journal_path):
        _fe_log(job_id, f"  [USNJRNL] Reading mounted journal: {journal_path}")
        try:
            with open(journal_path, 'rb') as fh:
                raw_data = fh.read()
        except (IOError, OSError) as e:
            _fe_log(job_id, f"  [USNJRNL] Failed to read mounted journal: {e}")
            return []
    elif image_path and partition_offset is not None and mft_inode is not None:
        # Approach 2: icat extraction from raw image
        _fe_log(job_id,
                f"  [USNJRNL] Extracting via icat: offset={partition_offset} "
                f"inode={mft_inode} image={image_path}")
        try:
            icat_cmd = [
                'icat', '-o', str(partition_offset),
                image_path, str(mft_inode)
            ]
            result = subprocess.run(icat_cmd, capture_output=True, timeout=120)
            if result.returncode != 0:
                _fe_log(job_id,
                        f"  [USNJRNL] icat failed (rc={result.returncode}): "
                        f"{result.stderr[:200]}")
                return []
            raw_data = result.stdout
        except (subprocess.TimeoutExpired, OSError) as e:
            _fe_log(job_id, f"  [USNJRNL] icat exception: {e}")
            return []
    else:
        _fe_log(job_id,
                "  [USNJRNL] No journal path or image+offset+inode provided — "
                "skipping")
        return []

    if not raw_data:
        _fe_log(job_id, "  [USNJRNL] Empty journal data — nothing to parse")
        return []

    # --- Parse USN records ---
    records: list = []
    offset = 0
    data_len = len(raw_data)
    parsed = 0
    skipped_version = 0
    skipped_reason = 0

    while offset + 4 <= data_len and parsed < max_records:
        # Read the first 4 bytes (RecordLength) to know how far to advance next
        rec_len = struct.unpack_from('<I', raw_data, offset)[0]

        # Sanity check — record must be at least V3 header size
        if rec_len < _USN_V3_HEADER_SIZE or rec_len > 10 * 1024 * 1024:
            break  # corrupt or end of journal padding

        if offset + rec_len > data_len:
            break

        try:
            # Determine version from MajorVersion (bytes 4-5)
            major_ver = struct.unpack_from('<H', raw_data, offset + 4)[0]

            if major_ver == 4:
                fmt = _USN_V4_HEADER_FMT
                hdr_size = _USN_V4_HEADER_SIZE
            elif major_ver == 3:
                fmt = _USN_V3_HEADER_FMT
                hdr_size = _USN_V3_HEADER_SIZE
            elif major_ver == 2:
                # V2 is same header layout as V3 for our purposes
                fmt = _USN_V3_HEADER_FMT
                hdr_size = _USN_V3_HEADER_SIZE
            else:
                skipped_version += 1
                offset += rec_len
                continue

            fields = struct.unpack_from(fmt, raw_data, offset)
            (_rec_len, _major_ver, _minor_ver,
             file_ref_num, parent_ref_num,
             usn, filetime_raw,
             reason, _source_info, _security_id, _file_attrs,
             fn_len, fn_offset) = fields[:14]

            # Decode reason — keep only target records
            if not (reason & target_reasons):
                skipped_reason += 1
                offset += rec_len
                continue

            # Decode filename (UTF-16LE, at fn_offset from start of record)
            fn_start = offset + fn_offset
            if fn_len > 0 and fn_start + fn_len <= offset + rec_len:
                filename = raw_data[fn_start:fn_start + fn_len].decode(
                    'utf-16-le', errors='replace'
                )
            else:
                filename = ''

            # Convert FILETIME (100-ns intervals since 1601-01-01) to ISO
            if filetime_raw:
                try:
                    from datetime import datetime, timezone
                    epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
                    ts = epoch.timestamp() + filetime_raw / 10_000_000.0
                    timestamp = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
                except (OSError, ValueError, OverflowError):
                    timestamp = str(filetime_raw)
            else:
                timestamp = ''

            records.append({
                'timestamp': timestamp,
                'filename': filename,
                'parent_path': None,  # would require extra lookup
                'reason': reason,
                'reason_label': _decode_reasons(reason),
                'usn': usn,
                'file_reference_number': hex(file_ref_num),
            })
            parsed += 1

        except (struct.error, UnicodeDecodeError) as e:
            _fe_log(job_id, f"  [USNJRNL] Parse error at offset {offset}: {e}")
            offset += rec_len
            continue

        offset += rec_len

    _fe_log(job_id,
            f"  [USNJRNL] Parsed {parsed} target record(s) "
            f"(skipped {skipped_version} version, "
            f"{skipped_reason} non-target reason)")

    return records


# ===========================================================================
# A008 — Browser History Enhancement (IE/Edge)
# ===========================================================================


def parse_ie_webcache(inventory: dict = None, active_mounts: list = None,
                       job_id: str = None, **kwargs) -> list:
    """Locate and parse IE/Edge WebCacheV01.dat (ESE DB) and legacy index.dat.

    Searches every active mount point for:
      a) WebCacheV01.dat (ESE DB — shared by IE and Edge Chromium)
      b) index.dat (legacy IE history)

    Uses ``esedbexport`` (if available) or ``strings`` to extract content from
    the ESE database, then parses the Content table for URLs, timestamps,
    visit counts.  Legacy index.dat is parsed via ``strings`` for URL content.

    Returns:
        list[dict]: Each entry has keys:
            url, timestamp, title, visit_count, source
    """
    results: list[dict] = []

    # Resolve mount points
    from geoff_utils import _active_mounts as _am, _state_lock as _sl
    mounts = []
    if active_mounts:
        mounts = active_mounts
    else:
        with _sl:
            mounts = list(_am) if _am else []

    if not mounts:
        _fe_log(job_id, "  [IE/EDGE] No active mounts — skipping WebCache/History parse")
        return results

    # Known search locations (relative to mount point)
    search_candidates = [
        # Windows 10/11 — Edge (Chromium) + IE share the same ESE database
        "Users/*/AppData/Local/Microsoft/Windows/WebCache/WebCacheV01.dat",
        # Windows 8.1 and earlier IE history
        "Users/*/AppData/Local/Microsoft/Windows/History/index.dat",
        # All Users / System32 variant
        "Windows/System32/config/systemprofile/AppData/Local/Microsoft/Windows/WebCache/WebCacheV01.dat",
    ]

    _fe_log(job_id, "  [IE/EDGE] Searching mounted partitions for IE/Edge history files …")

    import fnmatch
    found_files: list[str] = []

    for mp in mounts:
        mp_path = Path(mp)
        if not mp_path.is_dir():
            continue
        for candidate in search_candidates:
            # Split the pattern into mount-relative components
            parts = candidate.split("/")
            # Walk up to first wildcard
            prefix_parts = []
            wild_idx = None
            for i, p in enumerate(parts):
                if "*" in p:
                    wild_idx = i
                    break
                prefix_parts.append(p)
            prefix = mp_path / "/".join(prefix_parts)
            suffix_pattern = "/".join(parts[wild_idx:]) if wild_idx is not None else ""

            if not prefix.exists():
                continue

            if wild_idx is not None:
                # Simpler: just use rglob with the known filename
                fname = parts[-1]
                for hit in mp_path.rglob(fname):
                    if hit.is_file() and hit not in found_files:
                        found_files.append(str(hit))
        # Also do a wider search for the exact filenames
        for fname in ("WebCacheV01.dat", "index.dat"):
            for hit in mp_path.rglob(fname):
                if hit.is_file() and str(hit) not in found_files:
                    found_files.append(str(hit))

    if not found_files:
        _fe_log(job_id, "  [IE/EDGE] No IE/Edge history files found")
        return results

    _fe_log(job_id, f"  [IE/EDGE] Found {len(found_files)} IE/Edge history file(s)")

    # Check for esedbexport tool
    esedbexport_path = shutil.which("esedbexport")

    for fpath in found_files:
        fname = Path(fpath).name.lower()
        entries: list[dict] = []

        if fname == "webcachev01.dat" and esedbexport_path:
            # ESE database approach
            try:
                out_dir = tempfile.mkdtemp(prefix="geoff_webcache_")
                _fe_log(job_id, f"  [IE/EDGE] Exporting ESE DB: {fpath}")
                cmd = [esedbexport_path, "-t", str(out_dir), fpath]
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                if proc.returncode != 0:
                    _fe_log(job_id, f"  [IE/EDGE] esedbexport failed for {fpath}: {proc.stderr[:200]}")
                    # Fall back to strings
                    raise RuntimeError("esedbexport failed")
                # Look for exported CSV tables
                for csv_file in Path(out_dir).rglob("*.csv"):
                    if "Content" in csv_file.name or "History" in csv_file.name:
                        import csv
                        with open(csv_file, "r", errors="replace") as cf:
                            reader = csv.DictReader(cf)
                            for row in reader:
                                url = row.get("url", row.get("URL", row.get("Url", "")))
                                ts = row.get("timestamp", row.get("access_time", row.get("modified_time", "")))
                                title = row.get("title", row.get("Title", ""))
                                visit_count = row.get("visit_count", row.get("count", row.get("access_count", "1")))
                                entries.append({
                                    "url": url,
                                    "timestamp": ts,
                                    "title": title,
                                    "visit_count": int(visit_count) if visit_count.isdigit() else 1,
                                    "source": fpath,
                                })
                # Cleanup
                shutil.rmtree(out_dir, ignore_errors=True)
            except Exception as e:
                _fe_log(job_id, f"  [IE/EDGE] ESE parse fell back to strings: {e}")
                # Fallback: use strings extraction
                try:
                    strings_out = subprocess.run(
                        ["strings", fpath], capture_output=True, text=True, timeout=30
                    )
                    if strings_out.returncode == 0:
                        for line in strings_out.stdout.splitlines():
                            line = line.strip()
                            if line.startswith("http://") or line.startswith("https://"):
                                entries.append({
                                    "url": line,
                                    "timestamp": "",
                                    "title": "",
                                    "visit_count": 1,
                                    "source": fpath,
                                })
                except Exception as s_e:
                    _fe_log(job_id, f"  [IE/EDGE] strings fallback failed for {fpath}: {s_e}")

        elif fname == "webcachev01.dat":
            # No esedbexport — fallback to strings
            _fe_log(job_id, f"  [IE/EDGE] esedbexport not available — using strings on {fpath}")
            try:
                strings_out = subprocess.run(
                    ["strings", fpath], capture_output=True, text=True, timeout=30
                )
                if strings_out.returncode == 0:
                    for line in strings_out.stdout.splitlines():
                        line = line.strip()
                        if line.startswith("http://") or line.startswith("https://"):
                            entries.append({
                                "url": line,
                                "timestamp": "",
                                "title": "",
                                "visit_count": 1,
                                "source": fpath,
                            })
            except Exception as e:
                _fe_log(job_id, f"  [IE/EDGE] strings failed for {fpath}: {e}")

        elif fname == "index.dat":
            # Legacy IE index.dat — use strings to extract URLs
            _fe_log(job_id, f"  [IE/EDGE] Parsing legacy index.dat: {fpath}")
            try:
                strings_out = subprocess.run(
                    ["strings", fpath], capture_output=True, text=True, timeout=30
                )
                if strings_out.returncode == 0:
                    for line in strings_out.stdout.splitlines():
                        line = line.strip()
                        if line.startswith("http://") or line.startswith("https://") or line.startswith("ftp://"):
                            entries.append({
                                "url": line,
                                "timestamp": "",
                                "title": "",
                                "visit_count": 1,
                                "source": fpath,
                            })
            except Exception as e:
                _fe_log(job_id, f"  [IE/EDGE] strings failed for {fpath}: {e}")

        if entries:
            _fe_log(job_id, f"  [IE/EDGE] Extracted {len(entries)} entries from {Path(fpath).name}")
            results.extend(entries)

    _fe_log(job_id, f"  [IE/EDGE] Total entries extracted: {len(results)}")
    return results


# Exfiltration / anti-forensics keyword list for browser search-term matching
_BROWSER_SEARCH_KEYWORDS = frozenset({
    "leak", "exfil", "exfiltrate", "exfiltration",
    "anti-forensic", "anti_forensic", "antiforensic",
    "wipe", "delete", "eraser", "ccleaner", "bleachbit",
    "shred", "timestomp", "log clear", "wevtutil",
    "drop table", "drop database", "secure delete",
    "overwrite", "evidence wipe", "clear history",
    "delete history", "remove evidence", "cover tracks",
    "hide activity", "clear logs", "remove logs",
})


def parse_browser_search_terms(history_entries: list = None,
                                  active_mounts: list = None,
                                  job_id: str = None,
                                  **kwargs) -> list:
    """Cross-reference browser history entries against keyword list.

    Takes a list of browser history entries (from Chrome/Firefox SQLite parsing
    or ``parse_ie_webcache``) and checks each entry's URL and title against a
    keyword list targeting exfiltration and anti-forensics activity.

    Entries matching one or more keywords are flagged with **HIGH** confidence.

    Args:
        history_entries: List of dicts with keys ``url``, ``title``, etc.
        active_mounts: Optional list of mount point paths to search for
                       browser history SQLite databases directly.
        job_id: Optional async job ID for logging.

    Returns:
        list[dict]: Flagged entries with keys:
            url, timestamp, title, visit_count, source, matched_keywords,
            confidence, category
    """
    flagged: list[dict] = []

    # If no history entries provided, try to find browser databases on mounts
    if not history_entries and active_mounts:
        _fe_log(job_id, "  [BROWSER-KEYWORDS] No history entries provided — scanning mounts for browser DBs")
        history_entries = []
        from geoff_utils import _state_lock as _sl, _active_mounts as _am
        mounts = active_mounts or []
        if not mounts:
            with _sl:
                mounts = list(_am) if _am else []
        for mp in mounts:
            mp_path = Path(mp)
            if not mp_path.is_dir():
                continue
            for db_name in ("WebCacheV01.dat", "index.dat"):
                for hit in mp_path.rglob(db_name):
                    if hit.is_file():
                        history_entries.append({"url": "", "title": "", "source": str(hit)})

    if not history_entries:
        _fe_log(job_id, "  [BROWSER-KEYWORDS] No browser history to scan")
        return flagged

    _fe_log(job_id, f"  [BROWSER-KEYWORDS] Scanning {len(history_entries)} history entries …")

    compiled_patterns = {kw: re.compile(re.escape(kw), re.IGNORECASE) for kw in _BROWSER_SEARCH_KEYWORDS}

    for entry in history_entries:
        if not isinstance(entry, dict):
            continue
        url = entry.get("url", "")
        title = entry.get("title", "")
        search_text = f"{url} {title}"

        matched_kws: list[str] = []
        for kw, pattern in compiled_patterns.items():
            if pattern.search(search_text):
                matched_kws.append(kw)

        if matched_kws:
            flagged.append({
                "url": url,
                "timestamp": entry.get("timestamp", ""),
                "title": title,
                "visit_count": entry.get("visit_count", 1),
                "source": entry.get("source", ""),
                "matched_keywords": matched_kws,
                "confidence": "HIGH",
                "category": "exfiltration" if any(
                    k in ("leak", "exfil", "exfiltrate", "exfiltration") for k in matched_kws
                ) else "anti_forensics",
            })

    if flagged:
        _fe_log(job_id, f"  [BROWSER-KEYWORDS] Flagged {len(flagged)} search term(s) with HIGH confidence")
        for f in flagged[:10]:
            _fe_log(job_id, f"    🔍 [{f['category']}] URL={f['url'][:80]} keywords={f['matched_keywords']}")
        if len(flagged) > 10:
            _fe_log(job_id, f"    ... and {len(flagged) - 10} more")
    else:
        _fe_log(job_id, "  [BROWSER-KEYWORDS] No suspicious search terms found")


# ===========================================================================
# A010 — Google Drive Cloud Sync Forensics
# ===========================================================================

def parse_google_drive(job_id: str = None) -> dict:
    """Walk mounted partitions looking for Google Drive sync artifacts.

    Searches all active mount points for:
      - Drive for Desktop snapshot.db (modern)
      - Legacy Drive snapshot.db
      - sync_config.db
      - sync_log.log
      - Google Drive sync folder

    Opens SQLite databases (snapshot.db, sync_config.db) and queries the
    cloud_entry table.  Parses sync_log.log for upload/download events and
    account email.

    Returns:
        dict with keys:
          artifacts_found (bool)
          drive_version (str)
          account_email (str)
          files (list[dict]) — each with filename, size, modified, shared, doc_id
          sync_log_entries (list[dict]) — each with timestamp, event, details
    """
    result = {
        "artifacts_found": False,
        "drive_version": "",
        "account_email": "",
        "files": [],
        "sync_log_entries": [],
    }

    # Snapshot active mounts under lock
    with _state_lock:
        mount_points = list(_active_mounts)

    if not mount_points:
        _fe_log(job_id, "  [GDRIVE] No active mounts — skipping Google Drive scan")
        return result

    _fe_log(job_id, f"  [GDRIVE] Scanning {len(mount_points)} mount point(s) for Google Drive artifacts")

    # Windows LocalAppData paths (also check Documents and Settings for XP)
    drive_glob_paths = [
        "Users/*/AppData/Local/Google/DriveFS/*/snapshot.db",
        "Users/*/AppData/Local/Google/Drive/snapshot.db",
        "Users/*/AppData/Local/Google/Drive/sync_config.db",
        "Users/*/AppData/Local/Google/Drive/sync_log.log",
        "Users/*/Google Drive",
        "Documents and Settings/*/Local Settings/Application Data/Google/DriveFS/*/snapshot.db",
        "Documents and Settings/*/Local Settings/Application Data/Google/Drive/snapshot.db",
    ]

    found_snapshots = []
    found_sync_configs = []
    found_sync_logs = []
    found_drive_folders = []

    for mp in mount_points:
        if not os.path.isdir(mp):
            continue
        mp_path = Path(mp)
        _fe_log(job_id, f"    Scanning {mp} for Google Drive artifacts …")

        for pattern in drive_glob_paths:
            try:
                matches = list(Path(mp_path).glob(pattern))
            except (PermissionError, OSError):
                continue

            for m in matches:
                m_str = str(m.resolve())
                if pattern.endswith("snapshot.db"):
                    if m_str not in found_snapshots:
                        found_snapshots.append(m_str)
                        _fe_log(job_id, f"      Found Drive snapshot DB: {m_str}")
                elif pattern.endswith("sync_config.db"):
                    if m_str not in found_sync_configs:
                        found_sync_configs.append(m_str)
                        _fe_log(job_id, f"      Found Drive sync config DB: {m_str}")
                elif pattern.endswith("sync_log.log"):
                    if m_str not in found_sync_logs:
                        found_sync_logs.append(m_str)
                        _fe_log(job_id, f"      Found Drive sync log: {m_str}")
                elif pattern.endswith("Google Drive"):
                    if m_str not in found_drive_folders:
                        found_drive_folders.append(m_str)
                        _fe_log(job_id, f"      Found Google Drive folder: {m_str}")

    if not (found_snapshots or found_sync_configs or found_sync_logs or found_drive_folders):
        _fe_log(job_id, "  [GDRIVE] No Google Drive artifacts found on mounted partitions")
        return result

    result["artifacts_found"] = True

    # --- Parse snapshot.db(s) for cloud_entry table ---
    for snap_path in found_snapshots:
        try:
            import sqlite3
            conn = sqlite3.connect(snap_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            # Detect Drive version from path
            if "DriveFS" in snap_path:
                result["drive_version"] = "Drive for Desktop"
            else:
                result["drive_version"] = "Legacy Drive"

            # Query cloud_entry table
            try:
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='cloud_entry'")
                if cursor.fetchone():
                    cursor.execute("""
                        SELECT doc_id, filename, modified, created, size,
                               checksum, shared, removed
                        FROM cloud_entry
                        ORDER BY modified DESC
                        LIMIT 5000
                    """)
                    rows = cursor.fetchall()
                    for row in rows:
                        entry = {
                            "doc_id": row["doc_id"] if row["doc_id"] else "",
                            "filename": row["filename"] if row["filename"] else "",
                            "size": row["size"] if row["size"] else 0,
                            "modified": row["modified"] if row["modified"] else "",
                            "shared": bool(row["shared"]) if row["shared"] is not None else False,
                        }
                        if entry["filename"] and entry["filename"] not in [f["filename"] for f in result["files"]]:
                            result["files"].append(entry)

                    _fe_log(job_id, f"      cloud_entry: {len(rows)} entries from {Path(snap_path).name}")
                else:
                    _fe_log(job_id, f"      No cloud_entry table in {Path(snap_path).name}")
            except sqlite3.Error as sqe:
                _fe_log(job_id, f"      SQLite query error on {Path(snap_path).name}: {sqe}")

            conn.close()
        except Exception as e:
            _fe_log(job_id, f"      Error opening snapshot DB {snap_path}: {e}")

    # --- Parse sync_config.db for account email ---
    for cfg_path in found_sync_configs:
        try:
            import sqlite3
            conn = sqlite3.connect(cfg_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            # Try various tables that may hold account info
            for tbl in ["config", "sync_config", "accounts", "settings"]:
                try:
                    cursor.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name='{tbl}'")
                    if cursor.fetchone():
                        cursor.execute(f"SELECT * FROM \"{tbl}\" LIMIT 200")
                        rows = cursor.fetchall()
                        for row in rows:
                            row_dict = dict(row)
                            # Look for email-like values in any column
                            for col in row_dict:
                                val = str(row_dict[col])
                                if "@" in val and "." in val and not val.startswith("http"):
                                    result["account_email"] = val
                                    _fe_log(job_id, f"      Found account email: {val}")
                                    break
                            if result["account_email"]:
                                break
                except sqlite3.Error:
                    continue
                if result["account_email"]:
                    break

            conn.close()
        except Exception as e:
            _fe_log(job_id, f"      Error opening sync config DB {cfg_path}: {e}")

    # --- Parse sync_log.log for upload/download events ---
    for log_path in found_sync_logs:
        try:
            with open(log_path, "r", errors="replace") as lf:
                for line in lf:
                    line = line.strip()
                    if not line:
                        continue
                    # Try to extract timestamp and event
                    # Common format: [YYYY-MM-DD HH:MM:SS] EVENT_TYPE: details
                    ts_match = re.match(r'\[(\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2}(?:\.\d+)?)\]', line)
                    if ts_match:
                        ts = ts_match.group(1)
                        rest = line[ts_match.end():].strip()
                    else:
                        ts = ""
                        rest = line

                    # Classify the event
                    event_type = "unknown"
                    details = rest

                    rest_lower = rest.lower()
                    if "upload" in rest_lower or "up_sync" in rest_lower or "up sync" in rest_lower:
                        event_type = "upload"
                    elif "download" in rest_lower or "down_sync" in rest_lower or "down sync" in rest_lower:
                        event_type = "download"
                    elif "error" in rest_lower or "fail" in rest_lower:
                        event_type = "error"
                    elif "delete" in rest_lower:
                        event_type = "delete"
                    elif "email" in rest_lower or "account" in rest_lower or "@" in rest:
                        event_type = "account"
                        # Extract email if present
                        email_m = re.search(r'[\w.+-]+@[\w-]+\.[\w.]+', rest)
                        if email_m:
                            result["account_email"] = email_m.group(0)
                    elif "sync" in rest_lower:
                        event_type = "sync"

                    result["sync_log_entries"].append({
                        "timestamp": ts,
                        "event": event_type,
                        "details": details[:500],
                    })

            _fe_log(job_id, f"      sync_log: {len(result['sync_log_entries'])} entries from {Path(log_path).name}")

        except Exception as e:
            _fe_log(job_id, f"      Error parsing sync log {log_path}: {e}")

    _fe_log(job_id, f"  [GDRIVE] Results: {len(result['files'])} file(s), "
                     f"{len(result['sync_log_entries'])} log entry(ies), "
                     f"email={result['account_email'] or 'not found'}")

    return result


def check_google_drive_registry(inventory: dict, job_id: str = None) -> dict:
    """Extract Google Drive configuration from NTUSER.DAT registry hives.

    Searches mounted partitions for NTUSER.DAT files and extracts
    HKCU\\Software\\Google\\Drive key to recover account email,
    install time, and cache path.

    Args:
        inventory: Evidence inventory dict (to find registry hives)
        job_id: Optional job ID for logging

    Returns:
        dict with keys: account_email, install_time, cache_path, hives_checked
    """
    result = {
        "account_email": "",
        "install_time": "",
        "cache_path": "",
        "hives_checked": 0,
    }

    # Collect NTUSER.DAT paths from inventory and mounted partitions
    ntuser_paths = []

    # Check in registry_hives from inventory
    for hive in inventory.get("registry_hives", []):
        name = Path(hive).name.lower()
        if "ntuser" in name or "usrclass" in name:
            ntuser_paths.append(hive)

    # Also search mounted partitions for NTUSER.DAT
    with _state_lock:
        mount_points = list(_active_mounts)

    for mp in mount_points or []:
        if not os.path.isdir(mp):
            continue
        try:
            for ntuser in Path(mp).rglob("NTUSER.DAT"):
                p = str(ntuser.resolve())
                if p not in ntuser_paths:
                    ntuser_paths.append(p)
        except (PermissionError, OSError):
            pass

    if not ntuser_paths:
        _fe_log(job_id, "  [GDRIVE-REG] No NTUSER.DAT files found — skipping registry check")
        return result

    _fe_log(job_id, f"  [GDRIVE-REG] Scanning {len(ntuser_paths)} NTUSER.DAT hive(s) for Google Drive config")

    for hive_path in ntuser_paths:
        result["hives_checked"] += 1
        try:
            # Try using regripper or registry module if available
            # Fallback: try strings-based extraction for Google Drive keys
            from geoff_utils import safe_run

            # Attempt to use registry parsing tools
            reg_cmd = ["strings", hive_path]
            r = safe_run(reg_cmd, timeout=30)
            if r["code"] == 0:
                output = r["stdout"]
                # Look for Google Drive registry artifacts in strings output
                # HKCU\\Software\\Google\\Drive keys are stored as registry paths
                for line in output.splitlines():
                    line_lower = line.lower()
                    if "google" in line_lower and "drive" in line_lower:
                        # Extract email
                        email_m = re.search(r'[\w.+-]+@[\w-]+\.[\w.]+', line)
                        if email_m and not result["account_email"]:
                            result["account_email"] = email_m.group(0)
                        # Extract timestamps (Windows FILETIME can appear nearby)
                        # Extract cache paths
                        if "cache" in line_lower and ("path" in line_lower or "dir" in line_lower):
                            # Try to extract the path value after key= or : separator
                            parts = re.split(r'[=:]', line, maxsplit=1)
                            if len(parts) > 1:
                                candidate = parts[1].strip().strip('"').strip("'")
                                if candidate and not result["cache_path"]:
                                    result["cache_path"] = candidate

            # Also try direct regf support if available
            # For the evidence context, strings extraction is sufficient
            _fe_log(job_id, f"    Registry strings scan: {Path(hive_path).name} checked")

        except Exception as e:
            _fe_log(job_id, f"    Error scanning {Path(hive_path).name}: {e}")

    if result["account_email"] or result["install_time"] or result["cache_path"]:
        _fe_log(job_id, f"  [GDRIVE-REG] Found: email={result['account_email'] or 'N/A'}, "
                         f"cache={result['cache_path'] or 'N/A'}")
    else:
        _fe_log(job_id, "  [GDRIVE-REG] No Google Drive registry artifacts found")

    return result


# ===========================================================================
# A011 — Network Share Forensics
# ===========================================================================


def _find_ntuser_files(inventory: dict) -> list:
    """Collect NTUSER.DAT paths from inventory and mounted partitions."""
    ntuser_paths = []

    # Check in registry_hives from inventory
    for hive in inventory.get("registry_hives", []):
        name = Path(hive).name.lower()
        if "ntuser" in name:
            ntuser_paths.append(hive)

    # Also search mounted partitions for NTUSER.DAT
    with _state_lock:
        mount_points = list(_active_mounts)

    for mp in mount_points or []:
        if not os.path.isdir(mp):
            continue
        try:
            for ntuser in Path(mp).rglob("NTUSER.DAT"):
                p = str(ntuser.resolve())
                if p not in ntuser_paths:
                    ntuser_paths.append(p)
        except (PermissionError, OSError):
            pass

    return ntuser_paths


def _parse_reglookup_csv(output: str) -> list:
    """Parse reglookup CSV output into a list of dicts with path, value, data columns."""
    records = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(",")
        if len(parts) >= 3:
            path = parts[0].strip().strip('"')
            value = parts[1].strip().strip('"')
            data = parts[2].strip().strip('"')
            records.append({"path": path, "value": value, "data": data})
    return records


def analyze_network_shares(inventory: dict, job_id: str = None) -> dict:
    """Analyze network share artifacts from registry, prefetch, and PowerShell history.

    Extracts:
      a. HKCU\\Network\\* from NTUSER.DAT — mapped drive letters & remote paths
      b. HKCU\\...\\MountPoints2\\* from NTUSER.DAT — MRU network locations
      c. Prefetch for NET.EXE-*.pf — net use command execution
      d. PowerShell history for net use commands
      e. Registry for mapped drive persistence

    Args:
        inventory: Evidence inventory dict (to find registry hives)
        job_id: Optional job ID for logging

    Returns:
        dict with keys:
            mapped_drives: [{letter, remote_path, provider_name, last_connected}]
            mru_connections: [{path, last_accessed}]
            net_commands: [{timestamp, command}]
            powershell_commands: [{timestamp, command}]
    """
    result = {
        "mapped_drives": [],
        "mru_connections": [],
        "net_commands": [],
        "powershell_commands": [],
    }

    _fe_log(job_id, "  [NET-SHARE] Beginning network share forensics …")

    # --- a. Extract HKCU\\Network\\* from NTUSER.DAT via reglookup ---
    ntuser_paths = _find_ntuser_files(inventory)
    if not ntuser_paths:
        _fe_log(job_id, "  [NET-SHARE] No NTUSER.DAT files found — registry analysis skipped")
    else:
        _fe_log(job_id, f"  [NET-SHARE] Found {len(ntuser_paths)} NTUSER.DAT hive(s) for registry analysis")
        for hive_path in ntuser_paths:
            try:
                # Query HKCU\\Network for mapped drive letters
                hive_label = Path(hive_path).name
                reg_cmd = [
                    "reglookup", "-p",
                    "/Microsoft/Windows/CurrentVersion/Explorer/MountPoints2",
                    hive_path,
                ]
                r = safe_run(reg_cmd, timeout=60)
                if r["code"] == 0 and r["stdout"].strip():
                    records = _parse_reglookup_csv(r["stdout"])
                    # Filter for MRU network locations (subkeys under MountPoints2)
                    for rec in records:
                        rpath = rec.get("path", "")
                        rval = rec.get("value", "")
                        rdata = rec.get("data", "")
                        if "MountPoints2" in rpath and rval:
                            # Extract network path from the subkey name
                            # MountPoints2 subkeys contain UNC paths encoded with #
                            path_parts = rpath.split("\\")
                            # The last meaningful segment is the network path encoding
                            for part in path_parts:
                                if "#" in part and "\\" not in part:
                                    # Decode # to \\ for UNC paths
                                    decoded = part.replace("#", "\\")
                                    result["mru_connections"].append({
                                        "path": decoded,
                                        "last_accessed": rdata if rdata else "",
                                        "source_hive": hive_label,
                                    })
                                    break

                    _fe_log(job_id, f"  [NET-SHARE] {hive_label}: found {len(result['mru_connections'])} MountPoints2 MRU connection(s)")

                # Query HKCU\\Network for mapped drive letters
                reg_cmd2 = [
                    "reglookup", "-p",
                    "/Network",
                    hive_path,
                ]
                r2 = safe_run(reg_cmd2, timeout=60)
                if r2["code"] == 0 and r2["stdout"].strip():
                    records2 = _parse_reglookup_csv(r2["stdout"])
                    mapped = {}
                    for rec in records2:
                        rpath = rec.get("path", "")
                        rval = rec.get("value", "")
                        rdata = rec.get("data", "")
                        if rval and rdata:
                            # Extract drive letter from path: /Network/<letter>
                            parts = rpath.split("/")
                            for i, p in enumerate(parts):
                                if p == "Network" and i + 1 < len(parts):
                                    letter = parts[i + 1]
                                    if letter not in mapped:
                                        mapped[letter] = {
                                            "letter": letter,
                                            "remote_path": "",
                                            "provider_name": "",
                                            "last_connected": "",
                                        }
                                    if rval.lower() == "remotepath":
                                        mapped[letter]["remote_path"] = rdata
                                    elif rval.lower() == "providername":
                                        mapped[letter]["provider_name"] = rdata
                                    elif rval.lower() in ("connectiontype", "connectflags"):
                                        mapped[letter]["last_connected"] = rdata
                                    break

                    for drive_info in mapped.values():
                        result["mapped_drives"].append(drive_info)

                    if mapped:
                        _fe_log(job_id, f"  [NET-SHARE] {hive_label}: found {len(mapped)} mapped drive(s) in registry")

                # --- e. Check registry for mapped drive persistence ---
                # Persistent mapped drives are indicated by the presence of
                # HKCU\\Network\\<letter>\\ConnectionType = 1 (persistent)
                for drive in result["mapped_drives"]:
                    if drive.get("last_connected") in ("1", "0x1"):
                        drive["persistent"] = True
                    else:
                        drive["persistent"] = False

            except Exception as e:
                _fe_log(job_id, f"  [NET-SHARE] Registry analysis error for {Path(hive_path).name}: {e}")

    # --- c. Check Prefetch for NET.EXE-*.pf ---
    with _state_lock:
        mount_points = list(_active_mounts)
    for mp in mount_points or []:
        if not os.path.isdir(mp):
            continue
        try:
            # Common Windows Prefetch locations
            prefetch_dirs = [
                Path(mp) / "Windows" / "Prefetch",
                Path(mp) / "WINDOWS" / "Prefetch",
                Path(mp) / "WINNT" / "Prefetch",
            ]
            for pf_dir in prefetch_dirs:
                if pf_dir.is_dir():
                    for pf_file in pf_dir.glob("NET.EXE-*.pf"):
                        ts = ""
                        try:
                            ts = datetime.fromtimestamp(pf_file.stat().st_mtime).isoformat()
                        except Exception:
                            pass
                        result["net_commands"].append({
                            "timestamp": ts,
                            "command": f"net use (via {pf_file.name})",
                            "prefetch_file": str(pf_file),
                        })
                    for pf_file in pf_dir.glob("NET1.EXE-*.pf"):
                        ts = ""
                        try:
                            ts = datetime.fromtimestamp(pf_file.stat().st_mtime).isoformat()
                        except Exception:
                            pass
                        result["net_commands"].append({
                            "timestamp": ts,
                            "command": f"net use (via {pf_file.name})",
                            "prefetch_file": str(pf_file),
                        })
        except (PermissionError, OSError):
            pass

    # Log prefetch results
    if result["net_commands"]:
        _fe_log(job_id, f"  [NET-SHARE] Found {len(result['net_commands'])} NET.EXE prefetch file(s)")

    # --- d. Search PowerShell history for net use commands ---
    for mp in mount_points or []:
        if not os.path.isdir(mp):
            continue
        try:
            # PowerShell history paths for different Windows versions
            ps_history_paths = [
                Path(mp) / "Users" / "*" / "AppData" / "Roaming" / "Microsoft" / "Windows" / "PowerShell" / "PSReadLine" / "ConsoleHost_history.txt",
                Path(mp) / "Documents and Settings" / "*" / "Application Data" / "Microsoft" / "Windows" / "PowerShell" / "PSReadLine" / "ConsoleHost_history.txt",
            ]
            for ps_glob in ps_history_paths:
                for hist_file in Path(mp).glob(str(ps_glob.relative_to(mp))):
                    try:
                        lines = hist_file.read_text(encoding="utf-8", errors="replace").splitlines()
                        for line in lines:
                            line_stripped = line.strip()
                            # Match net use and related network commands
                            if re.search(r'\bnet\s+use\b', line_stripped, re.IGNORECASE):
                                result["powershell_commands"].append({
                                    "timestamp": "",
                                    "command": line_stripped,
                                    "history_file": str(hist_file),
                                })
                            elif re.search(r'\bnet\s+(view|share|file)\b', line_stripped, re.IGNORECASE):
                                result["powershell_commands"].append({
                                    "timestamp": "",
                                    "command": line_stripped,
                                    "history_file": str(hist_file),
                                })
                    except (PermissionError, OSError, UnicodeDecodeError):
                        pass
        except (PermissionError, OSError):
            pass

    if result["powershell_commands"]:
        _fe_log(job_id, f"  [NET-SHARE] Found {len(result['powershell_commands'])} net use command(s) in PowerShell history")

    # --- Summary ---
    total_findings = (
        len(result["mapped_drives"])
        + len(result["mru_connections"])
        + len(result["net_commands"])
        + len(result["powershell_commands"])
    )
    _fe_log(job_id, f"  [NET-SHARE] Complete — found {total_findings} network share artifact(s) "
                     f"({len(result['mapped_drives'])} drive(s), "
                     f"{len(result['mru_connections'])} MRU connection(s), "
                     f"{len(result['net_commands'])} prefetch(es), "
                     f"{len(result['powershell_commands'])} PowerShell command(s))")

    return result


def find_network_drive_files(inventory: dict,
                              network_shares: dict,
                              mount_points: list = None,
                              job_id: str = None) -> list:
    """Scan findings for files accessed via UNC paths or network share patterns.

    Cross-references file paths discovered in mounted partitions with known
    network share paths from MountPoints2 history.

    Args:
        inventory: Evidence inventory dict
        network_shares: Output of analyze_network_shares()
        mount_points: Optional list of active mount points
        job_id: Optional job ID for logging

    Returns:
        list of dicts: [{path, share_path, source, confidence}]
    """
    network_files = []
    _fe_log(job_id, "  [NET-SHARE-FILES] Beginning network-accessed file scan …")

    if mount_points is None:
        with _state_lock:
            mount_points = list(_active_mounts)

    # Collect all known remote paths from mapped drives and MRU connections
    known_remote_paths = set()
    for drive in network_shares.get("mapped_drives", []):
        rp = drive.get("remote_path", "")
        if rp:
            known_remote_paths.add(rp.rstrip("\\").lower())
    for conn in network_shares.get("mru_connections", []):
        cp = conn.get("path", "")
        if cp:
            known_remote_paths.add(cp.rstrip("\\").lower())

    if not known_remote_paths:
        _fe_log(job_id, "  [NET-SHARE-FILES] No known remote paths to cross-reference")
        return network_files

    _fe_log(job_id, f"  [NET-SHARE-FILES] Cross-referencing with {len(known_remote_paths)} known remote path(s)")

    # Build a set of mount point paths for quick path resolution
    mount_prefixes = []
    for mp in mount_points or []:
        if os.path.isdir(mp):
            mount_prefixes.append(str(Path(mp).resolve()).lower())

    # Walk all inventory evidence files looking for UNC patterns
    all_evidence = (
        inventory.get("disk_images", [])
        + inventory.get("memory_dumps", [])
        + inventory.get("other_files", [])
        + inventory.get("registry_hives", [])
    )

    for ev_path in all_evidence:
        ev_path_lower = ev_path.lower()
        # Check if this path references a known remote/share
        for known in known_remote_paths:
            known_lower = known.lower()
            if known_lower and known_lower in ev_path_lower:
                network_files.append({
                    "path": ev_path,
                    "share_path": known,
                    "source": "inventory_path_match",
                    "confidence": "MEDIUM",
                })
                break

    # Also scan MountPoints2 connections for recently accessed network paths
    # that might appear as LNK files or file references in the filesystem
    for mp in mount_points or []:
        if not os.path.isdir(mp):
            continue
        try:
            # Look for LNK files referencing network paths
            for lnk_file in Path(mp).rglob("*.lnk"):
                if lnk_file.is_file():
                    lnk_name = lnk_file.name.lower()
                    for known in known_remote_paths:
                        to_match = known.lower()
                        # Extract share name from UNC path (last component)
                        share_name = to_match.rstrip("\\").split("\\")[-1] if "\\" in to_match else ""
                        if share_name and share_name in lnk_name:
                            network_files.append({
                                "path": str(lnk_file),
                                "share_path": known,
                                "source": "lnk_to_share",
                                "confidence": "LOW",
                            })
                            break
        except (PermissionError, OSError):
            pass

    # Deduplicate
    seen = set()
    deduped = []
    for nf in network_files:
        key = nf["path"]
        if key not in seen:
            seen.add(key)
            deduped.append(nf)

    _fe_log(job_id, f"  [NET-SHARE-FILES] Found {len(deduped)} network-accessed file(s)")
    return deduped


# ===========================================================================
# A012 — FAT/exFAT Formatted Media Recovery
# ===========================================================================


def recover_formatted_fat(
    disk_images: list,
    device_map: dict,
    image_offsets: dict,
    output_dir: str = None,
    job_id: str = None,
) -> dict:
    """Recover files from FAT12/16/32 and exFAT formatted partitions.

    Examines disk images for FAT filesystems that have been quick-formatted
    (preserving directory entries in unallocated space).  Uses The Sleuth Kit
    (mmls, fsstat, fls -rd, icat) to recover deleted directory entries and
    photorec for signature-based carving as a fallback.

    Returns:
        dict with keys:
          - formatted (bool): whether quick-format was detected
          - fs_type (str): detected FAT variant or 'exFAT'
          - recovered_entries (list[dict]): each entry has name, size,
            timestamps, deleted_flag, recovered_path
          - carving_results (dict): total_carved and file_types {ext: count}
    """
    result: dict = {
        "formatted": False,
        "fs_type": "",
        "recovered_entries": [],
        "carving_results": {"total_carved": 0, "file_types": {}},
    }

    if not disk_images:
        _fe_log(job_id, "  [FAT-RECOV] No disk images to scan")
        return result

    _fe_log(job_id, f"  [FAT-RECOV] Scanning {len(disk_images)} disk image(s) for FAT/exFAT")

    # Check that required tools are available
    _mmls = shutil.which("mmls")
    _fsstat = shutil.which("fsstat")
    _fls = shutil.which("fls")
    _icat = shutil.which("icat")
    _photorec = shutil.which("photorec")
    _recovery_dir = output_dir or tempfile.gettempdir()
    _carve_dir = os.path.join(_recovery_dir, "photorec_carved")

    FAT_SIGNATURES = frozenset({"FAT12", "FAT16", "FAT32", "exFAT"})

    for img in disk_images:
        if not os.path.isfile(img):
            _fe_log(job_id, f"  [FAT-RECOV] Skipping non-file: {img}")
            continue

        _fe_log(job_id, f"  [FAT-RECOV] Processing {Path(img).name}")

        # (a) Identify partition layout with mmls
        partitions = []
        if _mmls:
            try:
                mmls_proc = subprocess.run(
                    [_mmls, img],
                    capture_output=True, text=True, timeout=30,
                )
                if mmls_proc.returncode == 0:
                    for line in mmls_proc.stdout.splitlines():
                        line = line.strip()
                        m = re.match(
                            r"^\d+:\s+(\d+)\s+(\d+)\s+(\d+)\s+(.*)",
                            line,
                        )
                        if m:
                            start = int(m.group(1))
                            desc = m.group(4).lower()
                            partitions.append({
                                "start_sector": start,
                                "description": desc,
                            })
            except Exception as exc:
                _fe_log(job_id, f"  [FAT-RECOV] mmls failed for {Path(img).name}: {exc}")

        # Also check device_map for any pre-computed partitions
        for dev_id, dev in device_map.items():
            for ef in dev.get("evidence_files", []):
                if ef == img:
                    part_info = dev.get("partitions", [])
                    if part_info:
                        partitions = part_info
                        break

        if not partitions:
            _fe_log(job_id, f"  [FAT-RECOV] No partitions found for {Path(img).name}, skipping")
            continue

        # (b) Check each partition for FAT/exFAT
        for part in partitions:
            offset = part.get("start_sector", 0)
            desc = part.get("description", "")

            # (c) Run fsstat to get filesystem info
            fs_type = ""
            fs_creation = ""
            backup_boot = False
            if _fsstat and offset > 0:
                try:
                    fs_proc = subprocess.run(
                        [_fsstat, "-o", str(offset), img],
                        capture_output=True, text=True, timeout=30,
                    )
                    if fs_proc.returncode == 0:
                        out = fs_proc.stdout
                        # Detect FAT variant
                        for sig in FAT_SIGNATURES:
                            if sig in out:
                                fs_type = sig
                                break
                        if not fs_type:
                            # Broader pattern
                            if re.search(r"File\s+System\s+Type:\s+FAT", out, re.IGNORECASE):
                                fs_type = "FAT"
                            elif "exFAT" in out:
                                fs_type = "exFAT"
                        # Backup boot sector indicates format vs natural FS
                        if "Backup Boot Sector" in out:
                            backup_boot = True
                        # Creation time
                        cm = re.search(
                            r"Creation\s+(time|date).*?:\s*(.+)",
                            out,
                            re.IGNORECASE,
                        )
                        if cm:
                            fs_creation = cm.group(2).strip()
                        elif any(sig in out for sig in FAT_SIGNATURES):
                            # Fallback: look for "Volume Creation" in fsstat output
                            vc = re.search(
                                r"Volume\s+Creation.*?:\s*(.+)",
                                out,
                                re.IGNORECASE,
                            )
                            if vc:
                                fs_creation = vc.group(1).strip()
                except Exception as exc:
                    _fe_log(job_id, f"  [FAT-RECOV] fsstat failed at offset {offset}: {exc}")

            # Also check the device_map offset if we already have it
            if not fs_type and img in image_offsets and image_offsets[img] > 0:
                offset = image_offsets[img]
                if _fsstat:
                    try:
                        fs_proc = subprocess.run(
                            [_fsstat, "-o", str(offset), img],
                            capture_output=True, text=True, timeout=30,
                        )
                        if fs_proc.returncode == 0:
                            out = fs_proc.stdout
                            for sig in FAT_SIGNATURES:
                                if sig in out:
                                    fs_type = sig
                                    break
                            if not fs_type and re.search(r"File\s+System\s+Type:\s+FAT", out, re.IGNORECASE):
                                fs_type = "FAT"
                            if "Backup Boot Sector" in out:
                                backup_boot = True
                    except Exception:
                        pass

            if not fs_type:
                continue  # Not a FAT filesystem — skip this partition

            _fe_log(job_id, f"  [FAT-RECOV] Detected {fs_type} at offset {offset} (backup_boot={backup_boot})")

            # (d) Recover deleted directory entries with fls -rd
            recovered_entries = []
            if _fls:
                try:
                    fls_proc = subprocess.run(
                        [_fls, "-o", str(offset), "-rd", img],
                        capture_output=True, text=True, timeout=60,
                    )
                    if fls_proc.returncode == 0:
                        for line in fls_proc.stdout.splitlines():
                            line = line.strip()
                            if not line:
                                continue
                            # Parse fls -rd output: flags inode | name [metadata]
                            # Format: r/r 12345-128-1: filename.txt
                            # Deleted entries show as * and have r/r or d/d flags
                            m = re.match(
                                r"([dDrR/-])\s*/\s*([dDrR/-])\s+(\S+)\s+(.+)$",
                                line,
                            )
                            if m:
                                flags = m.group(1) + "/" + m.group(2)
                                inode_str = m.group(3)
                                name = m.group(4).strip()
                                deleted_flag = "*" in line[:25] or line.startswith("*")
                                # Strip size metadata from name
                                name_clean = name.split("\t")[0].split("  ")[0].strip()
                                entry = {
                                    "name": name_clean,
                                    "size": 0,
                                    "timestamps": {},
                                    "deleted_flag": deleted_flag or ("*" in line),
                                    "recovered_path": "",
                                    "inode": inode_str,
                                    "flags": flags,
                                }
                                recovered_entries.append(entry)
                except Exception as exc:
                    _fe_log(job_id, f"  [FAT-RECOV] fls -rd failed at offset {offset}: {exc}")

            # (e) Try icat for each recovered entry where possible
            recovered_count = 0
            img_basename = Path(img).stem
            for entry in recovered_entries:
                inode_str = entry.get("inode", "")
                if not inode_str or not _icat:
                    continue
                # Strip metadata suffix (e.g., "12345-128-1" → "12345")
                inode_clean = inode_str.split("-")[0]
                if not inode_clean.isdigit():
                    continue
                out_path = os.path.join(
                    _recovery_dir,
                    f"{img_basename}_o{offset}_ino{inode_clean}_{entry['name']}",
                )
                try:
                    icat_proc = subprocess.run(
                        [_icat, "-o", str(offset), img, inode_clean],
                        capture_output=True, timeout=30,
                    )
                    if icat_proc.returncode == 0 and icat_proc.stdout:
                        with open(out_path, "wb") as f:
                            f.write(icat_proc.stdout)
                        entry["recovered_path"] = out_path
                        entry["size"] = len(icat_proc.stdout)
                        recovered_count += 1
                except Exception as exc:
                    _fe_log(job_id, f"  [FAT-RECOV] icat failed for inode {inode_clean}: {exc}")

            if recovered_entries:
                _fe_log(job_id, f"  [FAT-RECOV] Recovered {recovered_count}/{len(recovered_entries)} entries via icat")

            # (f) photorec as fallback carving
            carving_results = {"total_carved": 0, "file_types": {}}
            if _photorec and not recovered_entries:
                # Only run photorec if we didn't get good icat results
                try:
                    os.makedirs(_carve_dir, exist_ok=True)
                    _fe_log(job_id, f"  [FAT-RECOV] Running photorec on {Path(img).name} …")
                    photo_proc = subprocess.run(
                        [_photorec, "/d", _carve_dir, "/cmd", img, "fat,whole"],
                        capture_output=True, text=True, timeout=600,
                    )
                    # photorec exits 0 on success, but also on some errors
                    if photo_proc.returncode == 0 or os.path.isdir(_carve_dir):
                        carved_files = list(Path(_carve_dir).rglob("*"))
                        for cf in carved_files:
                            if cf.is_file():
                                ext = cf.suffix.lower() or ".bin"
                                carving_results["file_types"][ext] = (
                                    carving_results["file_types"].get(ext, 0) + 1
                                )
                                carving_results["total_carved"] += 1
                        _fe_log(
                            job_id,
                            f"  [FAT-RECOV] photorec carved {carving_results['total_carved']} file(s) "
                            f"({len(carving_results['file_types'])} types)",
                        )
                except Exception as exc:
                    _fe_log(job_id, f"  [FAT-RECOV] photorec failed: {exc}")

            # (g) Determine if quick-formatted
            # Quick-format indicators:
            #   1. Backup Boot Sector present (FAT32-specific)
            #   2. Directory entries found in unallocated space (fls -rd returned data)
            #   3. Filesystem creation time is recent relative to evidence
            formatted = backup_boot and len(recovered_entries) > 0

            result["formatted"] = formatted
            result["fs_type"] = fs_type
            result["recovered_entries"].extend(recovered_entries)
            result["carving_results"]["total_carved"] += carving_results["total_carved"]
            for ext, count in carving_results["file_types"].items():
                result["carving_results"]["file_types"][ext] = (
                    result["carving_results"]["file_types"].get(ext, 0) + count
                )

            if formatted:
                _fe_log(
                    job_id,
                    f"  [FAT-RECOV] ⚠ QUICK-FORMAT DETECTED on {fs_type} partition at offset {offset} "
                    f"({len(recovered_entries)} entries recovered)",
                )

    return result


def detect_usb_format(
    device_map: dict,
    job_id: str = None,
) -> dict:
    """Detect whether a USB drive was intentionally formatted.

    Checks for FAT backup boot sector presence and compares filesystem
    creation time to USB first-connect time when available.

    Returns:
        dict with keys:
          - format_detected (bool)
          - format_time (str): ISO timestamp or empty string
          - tool_used (str): tool that provided the evidence
    """
    result: dict = {
        "format_detected": False,
        "format_time": "",
        "tool_used": "",
    }

    for dev_id, dev in device_map.items():
        dev_type = dev.get("device_type", "").lower()
        # Only check USB / removable devices
        if "usb" not in dev_type and "removable" not in dev_type:
            continue

        _fe_log(job_id, f"  [USB-FMT] Checking device {dev_id} for format evidence")

        # Check for FAT backup boot sector — this is the strongest indicator
        # of a format (as opposed to natural filesystem creation)
        for img in dev.get("evidence_files", []):
            if not os.path.isfile(img):
                continue

            # Use fsstat to check for Backup Boot Sector
            _fsstat = shutil.which("fsstat")
            if _fsstat:
                # Try common FAT offsets
                img_offsets = dev.get("image_offsets", {})
                test_offsets = [img_offsets.get(img, 0), 0, 63, 2048, 32256]
                for offset in test_offsets:
                    if offset <= 0:
                        continue
                    try:
                        fs_proc = subprocess.run(
                            [_fsstat, "-o", str(offset), img],
                            capture_output=True, text=True, timeout=30,
                        )
                        if fs_proc.returncode == 0:
                            out = fs_proc.stdout
                            if "Backup Boot Sector" in out:
                                # Extract creation time
                                cm = re.search(
                                    r"Creation\s+(time|date).*?:\s*(.+)",
                                    out,
                                    re.IGNORECASE,
                                )
                                if cm:
                                    result["format_time"] = cm.group(2).strip()
                                result["format_detected"] = True
                                result["tool_used"] = "fsstat"
                                _fe_log(
                                    job_id,
                                    f"  [USB-FMT] ⚠ Format detected on {Path(img).name} "
                                    f"(Backup Boot Sector present, offset {offset})",
                                )
                                break
                    except Exception:
                        continue
                if result["format_detected"]:
                    break

            # Also check via mmls partition description
            if not result["format_detected"]:
                _mmls = shutil.which("mmls")
                if _mmls:
                    try:
                        mm_proc = subprocess.run(
                            [_mmls, img],
                            capture_output=True, text=True, timeout=30,
                        )
                        if mm_proc.returncode == 0:
                            for line in mm_proc.stdout.splitlines():
                                if "FAT" in line and ("backup" in line.lower() or "format" in line.lower()):
                                    result["format_detected"] = True
                                    result["tool_used"] = "mmls"
                                    _fe_log(job_id, f"  [USB-FMT] Format indicator in mmls: {line.strip()}")
                                    break
                    except Exception:
                        pass

    return result

