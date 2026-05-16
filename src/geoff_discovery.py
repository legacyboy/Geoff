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
    EVIDENCE_BASE_DIR,
    CASES_WORK_DIR,
    COMMON_LEGACY_OFFSETS,
    MITRE_TAGS,
)

from sift_specialists import SLEUTHKIT_Specialist

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


__all__ = ["SEVERITY_MAP", "TRIAGE_PATTERNS", "_all_inventory_paths", "_classify_unprocessed", "_compute_indicator_confidence", "_content_scan", "_detect_partition_offsets", "_extract_archive", "_extract_match_context", "_inventory_evidence", "_inventory_evidence_with_ai", "_is_indicator_match", "_list_extracted_files", "_mount_and_discover", "_resolve_e01_path", "_run_device_discovery", "_scan_filenames_for_indicators", "_scan_triage_indicators", "_strings_scan", "_tool_available", "_validate_inventory_classification"]

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
    mount_base = f"/home/sansforensics/cases/mounts/{case_name}"
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
                                                capture_output=True, text=True, timeout=300,
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
                                                    capture_output=True, text=True, timeout=300,
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
                                            subprocess.run(["icat", "-o", str(offset), sk_dev, inode], stdout=fh, stderr=subprocess.DEVNULL, timeout=300)
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
                            capture_output=True, text=True, timeout=300,
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
            rp = subprocess.run(["readpst", "-M", "-o", eml_dir, pst_path], capture_output=True, text=True, timeout=300)
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
            # ZIP archive
            with zipfile.ZipFile(archive_path, 'r') as zf:
                zf.extractall(extract_dir)
            extracted_files = _list_extracted_files(extract_dir)

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
                return {"status": "error", "error": f"7z extraction failed: {result['stderr'][:200]}"}
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
