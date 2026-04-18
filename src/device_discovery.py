#!/usr/bin/env python3
"""
Device Discovery — Identifies hosts, devices, and owners from evidence.
"""

import json
import os
import re
import struct
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any
from datetime import datetime


class DeviceDiscovery:
    """
    Takes an evidence directory + inventory and produces:
      - device_map: dict[device_id] -> device info
      - user_map: dict[username] -> user info with device list
    """

    def __init__(self, orchestrator):
        """
        Args:
            orchestrator: The ExtendedOrchestrator from sift_specialists_extended.py
                          Used to call SleuthKit tools for hostname/user extraction.
        """
        self.orchestrator = orchestrator
        self.log = []

    def discover(self, evidence_path: Path, inventory: dict) -> Tuple[dict, dict]:
        """
        Main entry point.

        Returns:
            (device_map, user_map) — both are plain dicts, JSON-serializable.
        """
        evidence_path = Path(evidence_path)
        device_map = {}
        user_map = {}

        # Strategy 1: Check if top-level subdirectories contain evidence
        # (Most common collection layout: evidence/pc1/, evidence/phone/, etc.)
        subdirs = [d for d in evidence_path.iterdir()
                   if d.is_dir() and not d.name.startswith('.')]
        subdir_has_evidence = {}
        for sd in subdirs:
            sd_files = set()
            for ev_type, file_list in inventory.items():
                if not isinstance(file_list, list):
                    continue
                for fpath in file_list:
                    if str(fpath).startswith(str(sd)):
                        sd_files.add(fpath)
            if sd_files:
                subdir_has_evidence[sd.name] = sd_files

        if len(subdir_has_evidence) > 1:
            # Multiple evidence-containing subdirs = multiple devices
            self._log("dir_structure",
                      f"Found {len(subdir_has_evidence)} evidence subdirectories")
            for subdir_name, files in subdir_has_evidence.items():
                dev_id = self._sanitize_device_id(subdir_name)
                device_map[dev_id] = {
                    "device_id": dev_id,
                    "device_type": "unknown",
                    "hostname": None,
                    "owner": None,
                    "owner_confidence": "NONE",
                    "os_type": "unknown",
                    "evidence_files": sorted(files),
                    "evidence_types": self._classify_files(files, inventory),
                    "discovery_method": "directory_structure",
                    "metadata": {},
                }
        elif len(subdir_has_evidence) == 1:
            # Single subdir — treat as one device
            subdir_name = list(subdir_has_evidence.keys())[0]
            files = list(subdir_has_evidence.values())[0]
            dev_id = self._sanitize_device_id(subdir_name)
            device_map[dev_id] = {
                "device_id": dev_id,
                "device_type": "unknown",
                "hostname": None,
                "owner": None,
                "owner_confidence": "NONE",
                "os_type": "unknown",
                "evidence_files": sorted(files),
                "evidence_types": self._classify_files(files, inventory),
                "discovery_method": "directory_structure",
                "metadata": {},
            }
        else:
            # No subdirectory structure — all files are in root
            # Group by evidence file (each disk image = potential device)
            # PCAPs, logs = separate "devices"
            self._log("flat_layout",
                      "No subdirectory structure; grouping by evidence file")
            dev_idx = 0
            # Group disk images by stem (e.g., image.E01, image.E02 → one device)
            grouped_disks = {}
            for img in inventory.get("disk_images", []):
                stem = Path(img).stem
                # Strip trailing segment number for EnCase/VHD: image.E01 → image
                group_stem = re.sub(r'\.(E|e)\d+$', '', stem)
                # Also handle .vhd, .vmdk, etc.
                if group_stem == stem:
                    group_stem = re.sub(r'\.(vhd|vmdk|vdi|raw|dd|img)$', '', stem, flags=re.IGNORECASE)
                if group_stem not in grouped_disks:
                    grouped_disks[group_stem] = []
                grouped_disks[group_stem].append(img)

            for group_stem, images in grouped_disks.items():
                dev_id = group_stem
                device_map[dev_id] = {
                    "device_id": dev_id,
                    "device_type": "unknown",
                    "hostname": None,
                    "owner": None,
                    "owner_confidence": "NONE",
                    "os_type": "unknown",
                    "evidence_files": images,
                    "evidence_types": ["disk_images"],
                    "discovery_method": "disk_image_filename",
                    "metadata": {},
                }
            for mem in inventory.get("memory_dumps", []):
                # Try to associate with a disk image device by name similarity
                mem_stem = Path(mem).stem.lower()
                matched = False
                for dev_id in device_map:
                    if dev_id.lower() in mem_stem or mem_stem in dev_id.lower():
                        device_map[dev_id]["evidence_files"].append(mem)
                        device_map[dev_id]["evidence_types"].append(
                            "memory_dumps")
                        matched = True
                        break
                if not matched:
                    dev_id = f"memdump_{Path(mem).stem}"
                    device_map[dev_id] = {
                        "device_id": dev_id,
                        "device_type": "unknown",
                        "hostname": None,
                        "owner": None,
                        "owner_confidence": "NONE",
                        "os_type": "unknown",
                        "evidence_files": [mem],
                        "evidence_types": ["memory_dumps"],
                        "discovery_method": "memory_dump_filename",
                        "metadata": {},
                    }
            # PCAPs as network capture devices
            for pcap in inventory.get("pcaps", []):
                dev_id = f"pcap_{Path(pcap).stem}"
                device_map[dev_id] = {
                    "device_id": dev_id,
                    "device_type": "network_capture",
                    "hostname": None,
                    "owner": None,
                    "owner_confidence": "NONE",
                    "os_type": "network",
                    "evidence_files": [pcap],
                    "evidence_types": ["pcaps"],
                    "discovery_method": "pcap_filename",
                    "metadata": {},
                }
            # Mobile backups
            for mob in inventory.get("mobile_backups", []):
                mob_dir = str(Path(mob).parent)
                dev_id = f"mobile_{Path(mob_dir).name}"
                if dev_id not in device_map:
                    device_map[dev_id] = {
                        "device_id": dev_id,
                        "device_type": "mobile",
                        "hostname": None,
                        "owner": None,
                        "owner_confidence": "NONE",
                        "os_type": "mobile",
                        "evidence_files": [],
                        "evidence_types": ["mobile_backups"],
                        "discovery_method": "mobile_backup",
                        "metadata": {},
                    }
                device_map[dev_id]["evidence_files"].append(mob)

            # Assign orphaned files (registry, evtx, syslogs) to
            # nearest disk image device or create catchall
            orphans = (
                inventory.get("registry_hives", []) +
                inventory.get("evtx_logs", []) +
                inventory.get("syslogs", []) +
                inventory.get("other_files", [])
            )
            for orphan in orphans:
                assigned = False
                orphan_dir = str(Path(orphan).parent)
                for dev_id, dev in device_map.items():
                    for ef in dev["evidence_files"]:
                        if str(Path(ef).parent) == orphan_dir:
                            dev["evidence_files"].append(orphan)
                            assigned = True
                            break
                    if assigned:
                        break
                # If truly orphaned, add to first device or create catchall
                if not assigned and device_map:
                    first_dev = list(device_map.keys())[0]
                    device_map[first_dev]["evidence_files"].append(orphan)

        # Strategy 2: Enrich each device with hostname/OS/owner
        for dev_id in list(device_map.keys()):
            dev = device_map[dev_id]
            self._enrich_device(dev, inventory)

            # If enrichment found a better hostname, re-key the map
            if (dev["hostname"] and
                    dev["hostname"] != dev_id and
                    dev["discovery_method"] != "registry_hostname"):
                new_id = self._sanitize_device_id(dev["hostname"])
                if new_id != dev_id and new_id not in device_map:
                    dev["device_id"] = new_id
                    device_map[new_id] = dev
                    del device_map[dev_id]

        # Strategy 3: Build user map from discovered owners + user profiles
        all_users = {}  # normalized_username -> {aliases, devices}
        for dev_id, dev in device_map.items():
            owner = dev.get("owner")
            if owner:
                norm = self._normalize_username(owner)
                if norm not in all_users:
                    all_users[norm] = {
                        "username": norm,
                        "display_name": owner,
                        "aliases": set(),
                        "devices": [],
                    }
                all_users[norm]["devices"].append(dev_id)
                all_users[norm]["aliases"].add(owner)

            # Also check user profiles in metadata
            for profile in dev.get("metadata", {}).get(
                    "user_profiles_found", []):
                norm = self._normalize_username(profile)
                if norm not in all_users:
                    all_users[norm] = {
                        "username": norm,
                        "display_name": profile,
                        "aliases": set(),
                        "devices": [],
                    }
                if dev_id not in all_users[norm]["devices"]:
                    all_users[norm]["devices"].append(dev_id)
                all_users[norm]["aliases"].add(profile)

        # Convert sets to lists for JSON
        user_map = {}
        for uname, udata in all_users.items():
            user_map[uname] = {
                "username": uname,
                "display_name": udata["display_name"],
                "aliases": sorted(udata["aliases"]),
                "devices": udata["devices"],
                "primary_device": udata["devices"][0]
                    if udata["devices"] else None,
                "role": "user",
                "confidence": "HIGH" if len(udata["devices"]) > 1 else "MEDIUM",
            }

        return device_map, user_map

    def _enrich_device(self, dev: dict, inventory: dict):
        """
        Try to extract hostname, OS type, owner, and user profiles
        from the device's evidence files.
        """
        # Check for disk images — extract hostname from filesystem
        for fpath in dev["evidence_files"]:
            if fpath in inventory.get("disk_images", []):
                self._enrich_from_disk_image(dev, fpath)
                break  # One disk image per device is enough

        # Check for mobile backups
        for fpath in dev["evidence_files"]:
            fname = Path(fpath).name.lower()
            if fname == "info.plist":
                self._enrich_from_ios_plist(dev, fpath)
            elif fname == "manifest.db":
                dev["device_type"] = "ios_mobile"
                dev["os_type"] = "ios"

        # Check for registry hives directly
        for fpath in dev["evidence_files"]:
            fname = Path(fpath).name.lower()
            if fname == "system":
                self._enrich_from_system_hive(dev, fpath)
            elif fname in ("ntuser.dat", "usrclass.dat"):
                dev["os_type"] = "windows"
                dev["device_type"] = "windows_pc"

        # Infer device type from OS
        if dev["os_type"] == "windows" and dev["device_type"] == "unknown":
            dev["device_type"] = "windows_pc"
        elif dev["os_type"] == "linux" and dev["device_type"] == "unknown":
            dev["device_type"] = "linux_server"
        elif dev["os_type"] == "macos" and dev["device_type"] == "unknown":
            dev["device_type"] = "macos_workstation"

    def _enrich_from_disk_image(self, dev: dict, image_path: str):
        """
        Use SleuthKit fls to look for hostname/OS indicators in a disk image.

        Developer note: Use the orchestrator's SLEUTHKIT_Specialist to run:
          1. fls -r to get file listing
          2. Look for Windows/System32/config/SYSTEM (→ hostname)
          3. Look for Users/ directory (→ user profiles)
          4. Look for /etc/hostname (→ Linux hostname)
          5. Use icat to extract small files for parsing

        The existing specialist already handles partition offsets.
        """
        try:
            # Get partition offset from existing detection
            # (will be in image_offsets dict in find_evil scope —
            #  pass it through or re-detect here)
            from sift_specialists import SLEUTHKIT_Specialist
            sk = SLEUTHKIT_Specialist(evidence_path=image_path)

            # Quick file listing to find hostname indicators
            # Use a non-recursive listing of key directories first
            fls_result = sk.list_files(image_path, recursive=False)
            if fls_result.get("status") != "success":
                return

            file_listing = fls_result.get("stdout", "")
            file_listing_lower = file_listing.lower()

            # Detect OS from filesystem contents
            if "windows" in file_listing_lower or "system32" in file_listing_lower:
                dev["os_type"] = "windows"
                dev["device_type"] = "windows_pc"
                # Extract user profiles from Users/ directory
                self._extract_windows_users(dev, file_listing)
            elif "etc" in file_listing_lower and "bin" in file_listing_lower:
                dev["os_type"] = "linux"
                dev["device_type"] = "linux_server"
            elif "library" in file_listing_lower and "applications" in file_listing_lower:
                dev["os_type"] = "macos"
                dev["device_type"] = "macos_workstation"

        except Exception as e:
            self._log("enrich_error",
                      f"Failed to enrich {dev['device_id']}: {e}")

    def _extract_windows_users(self, dev: dict, file_listing: str):
        """
        Parse fls output to find user profile directories under Users/.
        Skip: Default, Public, All Users, desktop.ini
        """
        skip_profiles = {"default", "public", "all users", "default user",
                         "desktop.ini", ".", ".."}
        profiles = []
        in_users = False
        for line in file_listing.split("\n"):
            line_lower = line.lower().strip()
            # fls output format: "d/d 12345: Users/username"
            if "/users/" in line_lower or "\\users\\" in line_lower:
                # Extract the username portion
                parts = line.split("/")
                for i, part in enumerate(parts):
                    if part.lower().strip().rstrip(":") == "users" and i + 1 < len(parts):
                        uname = parts[i + 1].strip().rstrip("/")
                        if uname.lower() not in skip_profiles and uname:
                            profiles.append(uname)

        profiles = list(set(profiles))
        dev["metadata"]["user_profiles_found"] = profiles
        if len(profiles) == 1:
            dev["owner"] = profiles[0]
            dev["owner_confidence"] = "MEDIUM"
        elif profiles:
            # Multiple profiles — pick the non-admin one if possible
            non_admin = [p for p in profiles
                         if p.lower() not in ("administrator", "admin",
                                              "defaultuser0")]
            if len(non_admin) == 1:
                dev["owner"] = non_admin[0]
                dev["owner_confidence"] = "MEDIUM"

    def _enrich_from_system_hive(self, dev: dict, hive_path: str):
        """
        Parse SYSTEM registry hive for ComputerName.

        Developer note: Use regripper or the registry specialist to parse:
          ControlSet001\\Control\\ComputerName\\ComputerName
        The orchestrator already has registry.parse_hive().
        """
        try:
            result = self.orchestrator.run_playbook_step(
                "device-discovery",
                {"module": "registry", "function": "parse_hive",
                 "params": {"hive_path": hive_path}}
            )
            if result.get("status") == "success":
                output = json.dumps(result, default=str).lower()
                # Look for computername in the output
                match = re.search(
                    r'computername["\s:=]+([a-zA-Z0-9_-]+)', output,
                    re.IGNORECASE
                )
                if match:
                    hostname = match.group(1).upper()
                    dev["hostname"] = hostname
                    dev["discovery_method"] = "registry_hostname"
                    self._log("hostname_found",
                              f"Hostname from SYSTEM hive: {hostname}")
        except Exception as e:
            self._log("hive_parse_error", f"Failed to parse SYSTEM: {e}")

    def _enrich_from_ios_plist(self, dev: dict, plist_path: str):
        """
        Parse iOS Info.plist for device name and owner.

        The device name is typically "Dave's iPhone" which gives us both
        the owner name and device type.
        """
        try:
            import plistlib
            with open(plist_path, "rb") as f:
                plist = plistlib.load(f)
            device_name = plist.get("Device Name", "")
            if device_name:
                dev["hostname"] = device_name
                dev["device_type"] = "ios_mobile"
                dev["os_type"] = "ios"
                dev["os_version"] = plist.get("Product Version", "")
                # Extract owner from "Dave's iPhone" pattern
                match = re.match(r"^(.+?)['']s\s+(iphone|ipad|ipod)",
                                 device_name, re.IGNORECASE)
                if match:
                    dev["owner"] = match.group(1)
                    dev["owner_confidence"] = "HIGH"
                    dev["discovery_method"] = "ios_plist_device_name"
        except Exception as e:
            self._log("plist_error",
                      f"Failed to parse Info.plist: {e}")

    def _classify_files(self, files, inventory) -> list:
        """Return list of evidence type strings for given files."""
        types = set()
        for fpath in files:
            for ev_type, file_list in inventory.items():
                if isinstance(file_list, list) and fpath in file_list:
                    types.add(ev_type)
        return sorted(types)

    @staticmethod
    def _normalize_username(username: str) -> str:
        """Normalize username: strip domain, lowercase."""
        # CORP\dsmith -> dsmith
        if "\\" in username:
            username = username.split("\\")[-1]
        # dsmith@corp.local -> dsmith
        if "@" in username:
            username = username.split("@")[0]
        return username.lower().strip()

    @staticmethod
    def _sanitize_device_id(name: str) -> str:
        """Create a safe device_id from a name."""
        # Replace spaces and special chars with underscores
        safe = re.sub(r'[^a-zA-Z0-9_-]', '_', name)
        return safe.strip('_') or "unknown_device"

    def _log(self, action: str, detail: str):
        self.log.append({
            "timestamp": datetime.now().isoformat(),
            "action": action,
            "detail": detail,
        })
