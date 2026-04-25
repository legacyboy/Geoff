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
                    "evidence_types": self._get_evidence_types(files, inventory),
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
                "evidence_types": self._get_evidence_types(files, inventory),
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
                mob_path = Path(mob)
                # If mob is a directory (extracted archive), use it directly
                if mob_path.is_dir():
                    mob_dir = str(mob_path)
                    dev_id = f"mobile_{mob_path.name}"
                else:
                    mob_dir = str(mob_path.parent)
                    dev_id = f"mobile_{mob_path.parent.name}"
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
        # Merge directory-based profiles with SAM registry accounts
        all_users = {}  # normalized_username -> {aliases, devices, metadata}
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

            # Add directory-based user profiles (includes system accounts)
            for profile in dev.get("metadata", {}).get(
                    "user_profiles_found", []):
                norm = self._normalize_username(profile)
                if norm not in all_users:
                    all_users[norm] = {
                        "username": norm,
                        "display_name": profile,
                        "aliases": set(),
                        "devices": [],
                        "metadata": {"source": "directory"}
                    }
                    # Mark system accounts
                    system_accounts = {"administrator", "localservice", "networkservice", 
                                       "system", "default", "public", "all users", "default user",
                                       "admin", "defaultuser0", "defaultuser1"}
                    if profile.lower() in system_accounts:
                        all_users[norm]["metadata"]["system_account"] = True
                if dev_id not in all_users[norm]["devices"]:
                    all_users[norm]["devices"].append(dev_id)
                all_users[norm]["aliases"].add(profile)

            # Add SAM registry users (prefer SAM data for duplicates)
            for sam_user in dev.get("metadata", {}).get("sam_users", []):
                username = sam_user.get("username")
                if not username:
                    continue
                norm = self._normalize_username(username)
                if norm not in all_users:
                    # New user from SAM
                    all_users[norm] = {
                        "username": norm,
                        "display_name": username,
                        "aliases": set(),
                        "devices": [],
                        "metadata": {
                            "source": "sam",
                            "sid": sam_user.get("sid"),
                            "last_login": sam_user.get("last_login"),
                            "account_type": sam_user.get("account_type", "user"),
                            "enabled": sam_user.get("enabled", True),
                            "system_account": sam_user.get("type", "user").lower() in ("system", "builtin")
                        }
                    }
                else:
                    # Duplicate: prefer SAM data (has SID, last_login, account_type)
                    existing = all_users[norm]
                    if existing.get("metadata", {}).get("source") != "sam":
                        # Upgrade with SAM data
                        existing["metadata"] = existing.get("metadata", {})
                        existing["metadata"]["source"] = "sam"
                        existing["metadata"]["sid"] = sam_user.get("sid")
                        existing["metadata"]["last_login"] = sam_user.get("last_login")
                        existing["metadata"]["account_type"] = sam_user.get("account_type", "user")
                        existing["metadata"]["enabled"] = sam_user.get("enabled", True)
                
                if dev_id not in all_users[norm]["devices"]:
                    all_users[norm]["devices"].append(dev_id)
                all_users[norm]["aliases"].add(username)

        # Convert sets to lists for JSON and build final user_map
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
                "metadata": udata.get("metadata", {}),
                "system_account": udata.get("metadata", {}).get("system_account", False),
            }
            # Include SAM-specific fields at top level if present
            if "sid" in udata.get("metadata", {}):
                user_map[uname]["sid"] = udata["metadata"]["sid"]
            if "last_login" in udata.get("metadata", {}):
                user_map[uname]["last_login"] = udata["metadata"]["last_login"]
            if "account_type" in udata.get("metadata", {}):
                user_map[uname]["account_type"] = udata["metadata"]["account_type"]
            if "enabled" in udata.get("metadata", {}):
                user_map[uname]["enabled"] = udata["metadata"]["enabled"]

        return device_map, user_map

    def _get_evidence_types(self, files, inventory: dict):
        """Return list of evidence type strings for given files."""
        types = set()
        for fpath in files:
            for ev_type, file_list in inventory.items():
                if isinstance(file_list, list) and fpath in file_list:
                    types.add(ev_type)
        return sorted(types)

    def _enrich_device(self, dev: dict, inventory: dict):
        """
        Try to extract hostname, OS type, owner, and user profiles
        from the device's evidence files.
        Cross-platform support: Windows, Linux, macOS, iOS, Android, Memory, Network.
        """
        # Check for disk images — extract hostname from filesystem
        for fpath in dev["evidence_files"]:
            if fpath in inventory.get("disk_images", []):
                self._enrich_from_disk_image(dev, fpath)
                break  # One disk image per device is enough

        # Check for memory dumps — extract users via Volatility
        for fpath in dev["evidence_files"]:
            if fpath in inventory.get("memory_dumps", []):
                self._enrich_from_memory_dump(dev, fpath, inventory)

        # Check for mobile backups
        for fpath in dev["evidence_files"]:
            fname = Path(fpath).name.lower()
            if fname == "info.plist":
                self._enrich_from_ios_plist(dev, fpath)
                # Also extract Apple ID from the plist
                self._extract_ios_plist_accounts(dev, fpath)
            elif fname == "manifest.db":
                dev["device_type"] = "ios_mobile"
                dev["os_type"] = "ios"
            elif fname == "deviceinfo.txt":
                self._enrich_from_deviceinfo(dev, fpath)
            elif fname == "build.prop":
                self._extract_build_prop(dev, fpath)
            elif fname.endswith(".ab") or "android" in fname.lower():
                self._enrich_from_android_backup(dev, fpath)
                self._extract_android_users(dev, fpath)
                # Also extract contacts from Android backup
                self._extract_android_contacts(dev, fpath)
            elif fname.endswith(".zip"):
                # Try to extract accounts/keychain from any iOS or Android zip
                if "ios" in fpath.lower() or "backup" in fpath.lower() or "iphone" in fpath.lower():
                    self._extract_ios_accounts(dev, fpath)
                    self._extract_ios_keychain(dev, fpath)
                if "android" in fpath.lower():
                    self._extract_android_contacts(dev, fpath)
                    self._extract_android_users(dev, fpath)

        # Also search ALL zip files in inventory (they may be assigned to other devices)
        all_zips = inventory.get("mobile_backups", []) + inventory.get("disk_images", [])
        for fpath in all_zips:
            if not fpath.endswith(".zip"):
                continue
            if "ios" in fpath.lower() or "backup" in fpath.lower() or "iphone" in fpath.lower():
                self._extract_ios_keychain(dev, fpath)
            if "android" in fpath.lower():
                self._extract_android_contacts(dev, fpath)

        # Check for registry hives directly
        for fpath in dev["evidence_files"]:
            fname = Path(fpath).name.lower()
            if fname == "system":
                self._enrich_from_system_hive(dev, fpath)
            elif fname == "sam":
                self._enrich_from_sam_hive(dev, fpath)
            elif fname in ("ntuser.dat", "usrclass.dat"):
                dev["os_type"] = "windows"
                dev["device_type"] = "windows_pc"

        # Check for Linux/MacOS hostname files
        for fpath in dev["evidence_files"]:
            fname = Path(fpath).name.lower()
            if fname == "hostname":  # /etc/hostname
                self._enrich_from_linux_hostname(dev, fpath)
            elif fname.endswith(".plist") and "preferences" in str(fpath).lower():
                self._enrich_from_macos_plist(dev, fpath)

        # Check for PCAP network captures
        for fpath in dev["evidence_files"]:
            if fpath in inventory.get("pcaps", []):
                self._enrich_from_pcap(dev, fpath)

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
            from sift_specialists import SLEUTHKIT_Specialist
            sk = SLEUTHKIT_Specialist(evidence_path=image_path)

            # Quick file listing to find hostname indicators
            fls_result = sk.list_files(image_path)
            if fls_result.get("status") != "success":
                return

            file_listing = fls_result.get("stdout", "") or fls_result.get("raw_output", "")
            file_listing_lower = file_listing.lower()

            # Detect OS from filesystem contents
            if "windows" in file_listing_lower or "system32" in file_listing_lower:
                dev["os_type"] = "windows"
                dev["device_type"] = "windows_pc"
                # Extract hostname from SYSTEM hive
                self._extract_hostname_from_windows_image(dev, sk, image_path, file_listing)
                # Extract user profiles
                self._extract_windows_users(dev, sk, image_path, file_listing)
            elif "etc/hostname" in file_listing_lower or ("etc" in file_listing_lower and "bin" in file_listing_lower):
                dev["os_type"] = "linux"
                dev["device_type"] = "linux_server"
                # Extract hostname from /etc/hostname
                self._extract_hostname_from_linux_image(dev, sk, image_path, file_listing)
            elif "library" in file_listing_lower and "applications" in file_listing_lower:
                dev["os_type"] = "macos"
                dev["device_type"] = "macos_workstation"
                # Extract hostname from macOS preferences
                self._extract_hostname_from_macos_image(dev, sk, image_path, file_listing)

        except Exception as e:
            self._log("enrich_error",
                      f"Failed to enrich {dev['device_id']}: {e}")

    def _extract_windows_users(self, dev: dict, sk: 'SLEUTHKIT_Specialist', image_path: str, file_listing: str):
        """
        Parse fls output to find user profile directories AND SAM registry accounts.
        Supports both WinXP (Documents and Settings/) and Win7+ (Users/).
        Uses targeted directory listing if recursive listing is too large.
        Merges directory-based profiles with SAM registry accounts.
        
        Priority:
        1. Targeted listing of Documents and Settings/ or Users/ directories (most accurate)
        2. Fallback to pattern matching in recursive listing (less accurate)
        """
        skip_profiles = {"default", "public", "all users", "default user",
                         "desktop.ini", ".", "..", "local settings", "application data",
                         "temp", "templates", "start menu", "favorites", "history",
                         "cookies", "recent", "sendto", "my documents", "nethood",
                         "printhood", "user account pictures", "default pictures"}
        profiles = []

        # FIRST: Try to find the Documents and Settings or Users directory inodes
        # and do targeted listing (most accurate method)
        doc_settings_inode = None
        users_inode = None
        
        for line in file_listing.split("\n"):
            stripped = line.strip()
            if not stripped:
                continue
            # Look for TOP-LEVEL Documents and Settings or Users directories only
            # These appear as "d/d inode:\tDocuments and Settings" or "d/d inode:\tUsers"
            # NOT as paths containing /Documents and Settings/ or /Users/
            if stripped.endswith("\tDocuments and Settings") or stripped == "Documents and Settings":
                match = re.search(r'([\d-]+):\s*Documents and Settings$', stripped)
                if match:
                    doc_settings_inode = match.group(1)
            elif "\tUsers" in stripped or stripped.endswith("\tUsers"):
                # Must be a top-level directory, not nested (e.g., not /some/path/Users)
                # Check that there's no slash before "Users" in the path part
                if re.search(r':\s*Users$', stripped):
                    match = re.search(r'([\d-]+):\s*Users$', stripped)
                    if match:
                        users_inode = match.group(1)

        # List Documents and Settings directory to find users (WinXP)
        if doc_settings_inode:
            try:
                sub_result = sk.list_files(image_path, inode=doc_settings_inode, recursive=False)
                sub_stdout = sub_result.get("stdout", "") or sub_result.get("raw_output", "")
                for line in sub_stdout.split("\n"):
                    stripped = line.strip()
                    if not stripped:
                        continue
                    # Parse child entry: "type inode:\tname" e.g., "d/d 10222-144-6:\tAdministrator"
                    # Split on tab or colon+whitespace
                    parts = re.split(r'[:\t]+\s*', stripped, maxsplit=2)
                    if len(parts) >= 2:
                        name = parts[-1].strip()
                        if name.lower() not in skip_profiles and len(name) > 1:
                            profiles.append(name)
            except Exception as e:
                self._log("user_extract_error", f"Failed to list Documents and Settings: {e}")

        # List Users directory to find users (Win7+) - only if no profiles found yet
        if users_inode and not profiles:
            try:
                sub_result = sk.list_files(image_path, inode=users_inode, recursive=False)
                sub_stdout = sub_result.get("stdout", "") or sub_result.get("raw_output", "")
                for line in sub_stdout.split("\n"):
                    stripped = line.strip()
                    if not stripped:
                        continue
                    parts = re.split(r'[:\t]+\s*', stripped, maxsplit=2)
                    if len(parts) >= 2:
                        name = parts[-1].strip()
                        if name.lower() not in skip_profiles and len(name) > 1:
                            profiles.append(name)
            except Exception as e:
                self._log("user_extract_error", f"Failed to list Users: {e}")

        # SECOND: If still no profiles found, fall back to pattern matching in recursive listing
        # This is less accurate but catches edge cases
        if not profiles:
            for line in file_listing.split("\n"):
                line_lower = line.lower().strip()
                # Only match direct children of /Users/ or /Documents and Settings/
                # Pattern: /Users/username/ or /Documents and Settings/username/
                # where username is followed by / (not more path components we care about)
                if "/users/" in line_lower:
                    # Extract username from path like /Users/username/something
                    match = re.search(r'/users/([^/]+)', line_lower)
                    if match:
                        uname = match.group(1).strip()
                        # Only accept if it looks like a top-level profile (not nested like /caches/users/xxx)
                        if '/users/' + uname + '/' in line_lower and '/application data/' not in line_lower and '/caches/' not in line_lower:
                            if uname not in skip_profiles and uname and len(uname) > 1:
                                profiles.append(uname)
                elif "/documents and settings/" in line_lower:
                    match = re.search(r'/documents and settings/([^/]+)', line_lower)
                    if match:
                        uname = match.group(1).strip()
                        if uname not in skip_profiles and uname and len(uname) > 1:
                            profiles.append(uname)

        # Deduplicate directory profiles
        profiles = list(set(profiles))
        
        # Extract SAM users from registry if SAM hive is available
        sam_users = []
        sam_hive_path = None
        
        # Look for SAM hive in the file listing
        for line in file_listing.split("\n"):
            line_lower = line.lower()
            if "config/sam" in line_lower or "config\\sam" in line_lower:
                # Parse fls output format: type inode: path
                match = re.search(r'([\d-]+):\s*.*sam$', line, re.IGNORECASE)
                if match:
                    sam_inode = match.group(1)
                    # Extract SAM hive using icat
                    import subprocess
                    
                    # Detect partition offset
                    offset = None
                    try:
                        mmls_result = subprocess.run(["mmls", image_path], capture_output=True, text=True, timeout=30)
                        for mmls_line in mmls_result.stdout.split("\n"):
                            if "NTFS" in mmls_line or "exFAT" in mmls_line or "0x07" in mmls_line:
                                mmls_parts = mmls_line.split()
                                if len(mmls_parts) >= 5:
                                    try:
                                        offset = int(mmls_parts[2])
                                        break
                                    except ValueError:
                                        continue
                    except Exception:
                        pass
                    
                    # Extract SAM hive
                    cmd = ["icat"]
                    if offset is not None:
                        cmd.extend(["-o", str(offset)])
                    cmd.extend([image_path, sam_inode])
                    
                    sam_hive_path = None
                    try:
                        result = subprocess.run(cmd, capture_output=True, timeout=120)
                        if result.returncode == 0 and result.stdout:
                            # Write to temp file for RegRipper
                            import tempfile
                            with tempfile.NamedTemporaryFile(delete=False, suffix=".sam") as tmp:
                                tmp.write(result.stdout)
                                sam_hive_path = tmp.name

                            # Use REGISTRY_Specialist to parse SAM
                            from sift_specialists_extended import REGISTRY_Specialist
                            reg_spec = REGISTRY_Specialist()
                            sam_result = reg_spec.extract_sam_users(sam_hive_path)

                            if sam_result.get("status") == "success":
                                sam_users = sam_result.get("users", [])
                    except subprocess.TimeoutExpired:
                        self._log("sam_extract_error", "icat timed out for SAM hive")
                    except Exception as e:
                        self._log("sam_extract_error", f"Failed to extract SAM hive: {e}")
                    finally:
                        if sam_hive_path:
                            try:
                                os.unlink(sam_hive_path)
                            except OSError:
                                pass
                    break
        
        # Store directory profiles in metadata
        dev["metadata"]["user_profiles_found"] = profiles
        
        # Store SAM users in metadata with source marking
        if sam_users:
            dev["metadata"]["sam_users"] = [
                {
                    "username": u.get("username"),
                    "sid": u.get("sid"),
                    "last_login": u.get("last_logon"),
                    "account_type": u.get("type", "user"),
                    "enabled": u.get("enabled", True),
                    "source": "sam"
                }
                for u in sam_users
            ]
            self._log("sam_users_found", 
                      f"Found {len(sam_users)} accounts in SAM: " + 
                      ", ".join([u.get("username", "unknown") for u in sam_users]))
        
        # Build combined user list for owner detection
        # Directory profiles include system accounts; SAM has actual Windows accounts
        all_usernames = set(profiles)  # Start with directory profiles
        
        # Add SAM usernames
        for sam_user in sam_users:
            username = sam_user.get("username")
            if username:
                all_usernames.add(username)
        
        # System accounts to skip when determining owner
        skip_accounts = {
            "administrator", "admin", "defaultuser0", "defaultuser1",
            "localservice", "networkservice", "system", "default",
            "public", "all users", "default user"
        }
        
        # Filter out system accounts for owner detection
        non_system = [p for p in all_usernames if p.lower() not in skip_accounts]
        
        if len(non_system) == 1:
            # Single non-system user = owner
            dev["owner"] = non_system[0]
            dev["owner_confidence"] = "MEDIUM"
        elif len(non_system) > 1:
            # Multiple non-system users: pick shortest name or first alphabetically
            non_system_sorted = sorted(non_system, key=lambda x: (len(x), x.lower()))
            dev["owner"] = non_system_sorted[0]
            dev["owner_confidence"] = "MEDIUM"
        elif len(all_usernames) == 1:
            # Only one profile found (even if it's a system account)
            dev["owner"] = list(all_usernames)[0]
            dev["owner_confidence"] = "LOW"
        else:
            # Only system accounts found
            dev["owner"] = None
            dev["owner_confidence"] = "NONE"

    def _enrich_from_system_hive(self, dev: dict, hive_path: str):
        """
        Parse SYSTEM registry hive for ComputerName from a disk image.
        Uses icat to extract the hive and parses the binary for ComputerName.
        SYSTEM hive is typically at Windows/System32/config/SYSTEM (Win7+)
        or WINDOWS/system32/config/SYSTEM (WinXP).
        """
        try:
            from sift_specialists import SLEUTHKIT_Specialist
            
            # Find the disk image this hive belongs to
            image_path = None
            for ef in dev["evidence_files"]:
                if ef in self.orchestrator.inventory.get("disk_images", []):
                    image_path = ef
                    break
            
            if not image_path:
                # Try to find any disk image in the evidence
                for ef in dev["evidence_files"]:
                    if Path(ef).suffix.lower() in ['.e01', '.e02', '.vhd', '.vmdk', '.vdi', '.raw', '.dd', '.img']:
                        image_path = ef
                        break
            
            if not image_path:
                self._log("hive_parse_error", f"No disk image found for {hive_path}")
                return
            
            sk = SLEUTHKIT_Specialist(evidence_path=image_path)
            
            # Find SYSTEM hive inode using list_files
            result = sk.list_files(image_path)
            stdout = result.get("stdout", "") or result.get("raw_output", "")
            
            system_inode = None
            # Look for SYSTEM hive at common paths
            for line in stdout.split("\n"):
                line_lower = line.lower()
                if "config/system" in line_lower or "config\\system" in line_lower:
                    # Parse fls output format: type inode: path
                    match = re.search(r'\s([\d-]+):\s*.*system$', line, re.IGNORECASE)
                    if match:
                        system_inode = match.group(1)
                        break
            
            if not system_inode:
                self._log("hive_parse_error", "SYSTEM hive inode not found")
                return
            
            # Extract SYSTEM hive using icat
            extract_result = sk.extract_file(image_path, system_inode)
            if extract_result.get("status") != "success":
                self._log("hive_parse_error", f"Failed to extract SYSTEM hive: {extract_result}")
                return
            
            # The extracted file path should be in the result
            extracted_path = extract_result.get("extracted_path")
            if not extracted_path or not Path(extracted_path).exists():
                self._log("hive_parse_error", "Extracted SYSTEM hive not found")
                return
            
            # Parse the binary SYSTEM hive for ComputerName
            # The ComputerName value is stored as a UTF-16LE string in the registry binary
            with open(extracted_path, 'rb') as f:
                system_data = f.read()
            
            # Look for ComputerName key path and value
            # Registry stores paths as UTF-16LE with null separators
            search_path = b"ControlSet001\\Control\\ComputerName\\ComputerName"
            search_path_utf16 = search_path.decode('ascii').encode('utf-16le')
            
            # Find the path in the binary
            path_pos = system_data.find(search_path_utf16)
            if path_pos == -1:
                # Try ControlSet002 or CurrentControlSet
                for cs in [b"ControlSet002", b"CurrentControlSet"]:
                    alt_path = cs + b"\\Control\\ComputerName\\ComputerName"
                    alt_path_utf16 = alt_path.decode('ascii').encode('utf-16le')
                    path_pos = system_data.find(alt_path_utf16)
                    if path_pos != -1:
                        break
            
            if path_pos == -1:
                self._log("hive_parse_error", "ComputerName registry path not found")
                return
            
            # The value data follows the key path - look for the hostname string
            # Registry values are typically stored after the key path
            # Look for UTF-16LE alphanumeric string after the path
            after_path = system_data[path_pos + len(search_path_utf16):path_pos + len(search_path_utf16) + 200]
            
            # Find UTF-16LE null terminator sequence and extract string between
            # Hostname is typically 2-32 chars of alphanumeric + hyphens
            hostname_match = re.search(b'([A-Za-z0-9-]{2,32})(?:\x00\x00)+', after_path)
            if hostname_match:
                hostname = hostname_match.group(1).decode('utf-16le', errors='ignore').strip()
                if hostname and len(hostname) <= 15:  # NetBIOS name limit
                    dev["hostname"] = hostname.upper()
                    dev["discovery_method"] = "registry_hostname"
                    self._log("hostname_found", f"Hostname from SYSTEM hive: {hostname}")
                    return
            
            # Fallback: search for common hostname patterns in the entire file
            # Windows hostnames are typically alphanumeric with hyphens, 2-15 chars
            for match in re.finditer(b'([A-Za-z0-9][A-Za-z0-9-]{0,13}[A-Za-z0-9])(?:\x00\x00)', system_data):
                candidate = match.group(1).decode('ascii', errors='ignore')
                if candidate and len(candidate) >= 2:
                    # Validate it looks like a hostname (not a path or random string)
                    if re.match(r'^[A-Za-z][A-Za-z0-9-]*[A-Za-z0-9]$', candidate):
                        dev["hostname"] = candidate.upper()
                        dev["discovery_method"] = "registry_hostname"
                        self._log("hostname_found", f"Hostname from SYSTEM hive (fallback): {candidate}")
                        return
            
            self._log("hive_parse_error", "Could not extract ComputerName from SYSTEM hive")
            
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

    def _enrich_from_deviceinfo(self, dev: dict, info_path: str):
        """
        Parse Cellebrite DeviceInfo.txt for device name, owner, and metadata.
        
        File format:
            Device Model:iPhone 11 (N104AP)
            OS Version:iOS None
            Device owner:This Is's iPhone
            Vendor:Apple
        """
        try:
            with open(info_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            
            # Extract device model
            model_match = re.search(r'Device Model:(.+)', content)
            if model_match:
                dev["device_type"] = model_match.group(1).strip()
                dev["metadata"]["device_model"] = model_match.group(1).strip()
            
            # Extract OS version
            os_match = re.search(r'OS Version:(.+)', content)
            if os_match:
                dev["os_version"] = os_match.group(1).strip()
                if "ios" in dev["os_version"].lower():
                    dev["os_type"] = "ios"
                    dev["device_type"] = "ios_mobile"
                elif "android" in dev["os_version"].lower():
                    dev["os_type"] = "android"
                    dev["device_type"] = "android_mobile"
            
            # Extract device owner
            owner_match = re.search(r'Device owner:(.+)', content)
            if owner_match:
                owner_raw = owner_match.group(1).strip()
                # Parse "This Is's iPhone" → owner "This Is"
                # Handle both ASCII apostrophe and Unicode right single quotation mark
                name_match = re.match(r"^(.+?)[\u0027\u2019]s\s+(iphone|ipad|ipod|android|samsung|pixel|device)",
                                     owner_raw, re.IGNORECASE)
                if name_match:
                    dev["owner"] = name_match.group(1).strip()
                    dev["owner_confidence"] = "HIGH"
                else:
                    # Just use the raw owner string if no pattern match
                    dev["owner"] = owner_raw
                    dev["owner_confidence"] = "MEDIUM"
                dev["discovery_method"] = "cellebrite_deviceinfo"
            
            # Extract vendor
            vendor_match = re.search(r'Vendor:(.+)', content)
            if vendor_match:
                dev["metadata"]["vendor"] = vendor_match.group(1).strip()
            
            self._log("deviceinfo_parsed",
                      f"DeviceInfo: owner={dev.get('owner')}, model={dev.get('device_type')}")
        except Exception as e:
            self._log("deviceinfo_error",
                      f"Failed to parse DeviceInfo.txt: {e}")

    def _extract_build_prop(self, dev: dict, prop_path: str):
        """Parse Android build.prop for device model, version, and user."""
        try:
            with open(prop_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            
            model = re.search(r'ro\.product\.model=(.+)', content)
            if model:
                dev["device_type"] = model.group(1).strip()
                dev["metadata"]["model"] = model.group(1).strip()
            
            version = re.search(r'ro\.build\.version\.release=(.+)', content)
            if version:
                dev["os_version"] = version.group(1).strip()
                dev["os_type"] = "android"
            
            user = re.search(r'ro\.build\.user=(.+)', content)
            if user:
                dev["owner"] = user.group(1).strip()
                dev["owner_confidence"] = "MEDIUM"
                dev["discovery_method"] = "build_prop"
            
            self._log("build_prop_parsed", f"build.prop: model={dev.get('device_type')}, user={dev.get('owner')}")
        except Exception as e:
            self._log("build_prop_error", f"Failed to parse build.prop: {e}")

    def _extract_ios_accounts(self, dev: dict, backup_dir: str):
        """Extract Apple ID / iCloud accounts from iOS backup."""
        try:
            backup_path = Path(backup_dir)
            accounts = []
            
            # Check for Accounts3.sqlite
            accounts_db = list(backup_path.rglob("Accounts3.sqlite"))
            if accounts_db:
                import sqlite3
                conn = sqlite3.connect(f"file:{accounts_db[0]}?mode=ro", uri=True, timeout=5)
                rows = conn.execute("SELECT identifier, account_description FROM accounts LIMIT 20").fetchall()
                for r in rows:
                    accounts.append({"id": r[0], "desc": r[1]})
                conn.close()
            
            if accounts:
                dev["metadata"]["ios_accounts"] = accounts
                dev["user_accounts"] = [a["id"] for a in accounts if a["id"]]
                self._log("ios_accounts_found", f"Found {len(accounts)} iOS accounts")
        except Exception as e:
            self._log("ios_accounts_error", f"Failed to extract iOS accounts: {e}")

    def _extract_android_users(self, dev: dict, backup_path: str):
        """Extract Google accounts from Android backup."""
        try:
            backup = Path(backup_path)
            accounts = []
            
            # Look for accounts.db in backup
            db_files = list(backup.rglob("accounts.db"))
            if db_files:
                import sqlite3
                conn = sqlite3.connect(f"file:{db_files[0]}?mode=ro", uri=True, timeout=5)
                rows = conn.execute("SELECT name, type FROM accounts LIMIT 20").fetchall()
                for r in rows:
                    accounts.append({"name": r[0], "type": r[1]})
                conn.close()
            
            # Also check for Google account in backup metadata
            google_account = list(backup.rglob("*/com.google.android.gm/databases/*"))
            if google_account:
                dev["metadata"]["gmail_databases"] = len(google_account)
            
            if accounts:
                dev["metadata"]["android_accounts"] = accounts
                dev["user_accounts"] = [a["name"] for a in accounts if a["name"]]
                self._log("android_accounts_found", f"Found {len(accounts)} Android accounts")
        except Exception as e:
            self._log("android_accounts_error", f"Failed to extract Android users: {e}")

    def _extract_ios_keychain(self, dev, backup_path):
        """Extract iOS keychain entries from keychain-2.db."""
        try:
            backup_path = Path(backup_path)
            keychain_db = list(backup_path.rglob("keychain-2.db"))
            
            # Also search inside zip archives
            if not keychain_db:
                zip_files = list(backup_path.rglob("*.zip")) if backup_path.is_dir() else [backup_path] if backup_path.suffix == '.zip' else []
                for zip_file in zip_files:
                    try:
                        import zipfile
                        with zipfile.ZipFile(zip_file, 'r') as zf:
                            for name in zf.namelist():
                                if 'keychain-2.db' in name or 'KeychainDump' in name:
                                    self._log("ios_keychain_found", f"Found keychain in zip: {zip_file.name}/{name}")
                                    dev["metadata"]["keychain_in_zip"] = f"{zip_file.name}/{name}"
                                    break
                    except:
                        pass
            
            if not keychain_db:
                return
            
            import sqlite3
            conn = sqlite3.connect(f"file:{keychain_db[0]}?mode=ro", uri=True, timeout=5)
            rows = conn.execute(
                "SELECT service, account FROM genp WHERE service IS NOT NULL LIMIT 100"
            ).fetchall()
            conn.close()
            
            entries = [{"service": r[0], "account": r[1]} for r in rows if r[0]]
            if entries:
                dev["metadata"]["keychain_entries"] = entries
                self._log("ios_keychain_found", f"Found {len(entries)} keychain entries")
        except Exception as e:
            self._log("ios_keychain_error", f"Failed to extract iOS keychain: {e}")

    def _extract_ios_plist_accounts(self, dev, plist_path):
        """Extract Apple ID from Info.plist."""
        try:
            import plistlib
            with open(plist_path, "rb") as f:
                plist = plistlib.load(f)
            
            apple_id = plist.get("AppleID") or plist.get("iTunesAppleID")
            if apple_id:
                dev["metadata"]["apple_id"] = apple_id
                self._log("ios_apple_id_found", f"Found Apple ID: {apple_id}")
        except Exception as e:
            self._log("ios_plist_accounts_error", f"Failed to extract Apple ID from plist: {e}")

    def _extract_android_contacts(self, dev, backup_path):
        """Extract contacts from Android contacts2.db."""
        try:
            backup = Path(backup_path)
            contacts_db = list(backup.rglob("contacts2.db"))
            
            # Also search inside zip archives
            if not contacts_db:
                for zip_file in backup.rglob("*.zip"):
                    try:
                        import zipfile
                        with zipfile.ZipFile(zip_file, 'r') as zf:
                            for name in zf.namelist():
                                if 'contacts2.db' in name or 'contacts' in name.lower():
                                    self._log("android_contacts_found", f"Found contacts DB in zip: {name}")
                                    dev["metadata"]["contacts_in_zip"] = str(zip_file)
                                    break
                    except:
                        pass
            
            if not contacts_db:
                return
            
            import sqlite3
            conn = sqlite3.connect(f"file:{contacts_db[0]}?mode=ro", uri=True, timeout=5)
            rows = conn.execute(
                "SELECT display_name, phone_number FROM data WHERE display_name IS NOT NULL LIMIT 50"
            ).fetchall()
            conn.close()
            
            contacts = [{"name": r[0], "phone": r[1]} for r in rows if r[0]]
            if contacts:
                dev["metadata"]["contacts"] = contacts
                self._log("android_contacts_found", f"Found {len(contacts)} contacts")
        except Exception as e:
            self._log("android_contacts_error", f"Failed to extract Android contacts: {e}")

    def _enrich_from_sam_hive(self, dev: dict, hive_path: str):
        """
        Parse SAM registry hive to extract actual user accounts.
        
        Uses the registry specialist to dump user SIDs, usernames, and
        last login timestamps from the SAM database.
        """
        try:
            result = self.orchestrator.run_playbook_step(
                "device-discovery",
                {"module": "registry", "function": "parse_hive",
                 "params": {"hive_path": hive_path}}
            )
            if result.get("status") == "success":
                # Extract user accounts from parsed SAM
                parsed = result.get("parsed", {})
                users = parsed.get("users", [])
                
                if users:
                    user_list = []
                    for user in users:
                        user_list.append({
                            "username": user.get("username"),
                            "sid": user.get("sid"),
                            "last_login": user.get("last_logon"),
                            "account_type": user.get("type", "user"),
                            "enabled": user.get("enabled", True)
                        })
                    dev["metadata"]["sam_users"] = user_list
                    self._log("sam_users_found", 
                              f"Found {len(user_list)} accounts in SAM: " + 
                              ", ".join([u.get("username", "unknown") for u in user_list]))
        except Exception as e:
            self._log("sam_parse_error", f"Failed to parse SAM: {e}")

    def _enrich_from_linux_hostname(self, dev: dict, hostname_path: str):
        """
        Read /etc/hostname file for Linux hostname.
        """
        try:
            with open(hostname_path, "r") as f:
                hostname = f.read().strip()
            if hostname:
                dev["hostname"] = hostname
                dev["os_type"] = "linux"
                dev["device_type"] = "linux_server"
                dev["discovery_method"] = "linux_hostname_file"
                self._log("hostname_found", f"Hostname from /etc/hostname: {hostname}")
        except Exception as e:
            self._log("hostname_read_error", f"Failed to read hostname: {e}")

    def _enrich_from_macos_plist(self, dev: dict, plist_path: str):
        """
        Parse macOS preferences plist for ComputerName.
        """
        try:
            import plistlib
            with open(plist_path, "rb") as f:
                plist = plistlib.load(f)
            computer_name = plist.get("ComputerName", "")
            if computer_name:
                dev["hostname"] = computer_name
                dev["os_type"] = "macos"
                dev["device_type"] = "macos_workstation"
                dev["discovery_method"] = "macos_plist_computer_name"
                self._log("hostname_found", f"Hostname from macOS plist: {computer_name}")
        except Exception as e:
            self._log("macos_plist_error", f"Failed to parse macOS plist: {e}")

    def _enrich_from_android_backup(self, dev: dict, backup_path: str):
        """
        Parse Android backup for device info and Google accounts.
        Android backups (.ab files) contain account information.
        """
        try:
            # For .ab files, we'd need to use adb backup extraction
            # For now, extract from filename or directory structure
            fname = Path(backup_path).name
            # Look for patterns like "com.google.android.gm" or account files
            dev["os_type"] = "android"
            dev["device_type"] = "android_mobile"
            
            # Try to read accounts from backup if it's extracted
            if Path(backup_path).is_dir():
                accounts_file = Path(backup_path) / "accounts.db"
                if accounts_file.exists():
                    # Would need SQLite parsing - mark for now
                    dev["metadata"]["android_accounts_found"] = True
            
            dev["discovery_method"] = "android_backup"
            self._log("android_backup_found", f"Android backup: {fname}")
        except Exception as e:
            self._log("android_backup_error", f"Failed to process Android backup: {e}")

    def _enrich_from_memory_dump(self, dev: dict, mem_path: str, inventory: dict):
        """
        Extract system info from memory dump using Volatility.
        Looks for: computer name, users from hashdump/lsadump.
        """
        try:
            # Volatility would be called here - for now, use filename hints
            # and mark for Volatility analysis
            dev["metadata"]["memory_dump_path"] = mem_path
            dev["metadata"]["requires_volatility"] = True
            
            # If volatility results are available in inventory
            if "volatility_results" in inventory:
                vol_results = inventory["volatility_results"]
                if isinstance(vol_results, dict):
                    if "hostname" in vol_results:
                        dev["hostname"] = vol_results["hostname"]
                    if "users" in vol_results:
                        dev["metadata"]["volatility_users"] = vol_results["users"]
            
            dev["discovery_method"] = "memory_dump_volatility"
            self._log("memory_dump_found", f"Memory dump for analysis: {Path(mem_path).name}")
        except Exception as e:
            self._log("memory_dump_error", f"Failed to process memory dump: {e}")

    def _enrich_from_pcap(self, dev: dict, pcap_path: str):
        """
        Extract network info from PCAP: IPs, domains, potential exfil targets.
        """
        try:
            dev["device_type"] = "network_capture"
            dev["os_type"] = "network"
            dev["metadata"]["pcap_path"] = pcap_path
            dev["metadata"]["requires_pcap_analysis"] = True
            
            # Basic metadata from filename
            fname = Path(pcap_path).name
            dev["hostname"] = f"pcap_{fname}"
            
            # If tshark/tcpflow results available
            if "pcap_analysis" in dev.get("metadata", {}):
                analysis = dev["metadata"]["pcap_analysis"]
                if "external_hosts" in analysis:
                    dev["metadata"]["external_connections"] = analysis["external_hosts"]
            
            dev["discovery_method"] = "pcap_network_capture"
            self._log("pcap_found", f"PCAP for analysis: {fname}")
        except Exception as e:
            self._log("pcap_error", f"Failed to process PCAP: {e}")

    def _extract_hostname_from_windows_image(self, dev: dict, sk: 'SLEUTHKIT_Specialist', image_path: str, file_listing: str):
        """
        Extract hostname from Windows disk image by finding and parsing SYSTEM hive.
        SYSTEM hive is at Windows/System32/config/SYSTEM (Win7+) or WINDOWS/system32/config/SYSTEM (WinXP).
        Uses mmls to detect partition offset, then icat to extract the hive.
        """
        # Find SYSTEM hive inode
        system_inode = None
        for line in file_listing.split("\n"):
            line_stripped = line.strip()
            if not line_stripped:
                continue
            # Look for config/SYSTEM or config\\SYSTEM in path
            if "config/system" in line.lower() or "config\\system" in line.lower():
                # Parse fls output: type inode: path
                match = re.search(r'\s([\d-]+):\s*.*system$', line, re.IGNORECASE)
                if match:
                    system_inode = match.group(1)
                    break
        
        if not system_inode:
            self._log("hostname_search", "SYSTEM hive inode not found in file listing")
            return
        
        # Extract SYSTEM hive using icat directly (binary-safe)
        import subprocess
        
        # Detect partition offset using mmls
        offset = None
        try:
            mmls_result = subprocess.run(["mmls", image_path], capture_output=True, text=True, timeout=30)
            for line in mmls_result.stdout.split("\n"):
                # Look for lines with partition info: "000:000   0000000063   ...   NTFS"
                # Format: Slot Start End Length Description
                # Example: "002:  000:000   0000000063   0020948759   0020948697   NTFS / exFAT (0x07)"
                if "NTFS" in line or "exFAT" in line or "0x07" in line:
                    parts = line.split()
                    if len(parts) >= 5:
                        # parts[0] = "002:", parts[1] = "000:000", parts[2] = Start sector
                        try:
                            offset = int(parts[2])
                            break
                        except ValueError:
                            continue
        except Exception as e:
            self._log("hostname_error", f"mmls failed: {e}")
        
        # Build icat command with partition offset
        cmd = ["icat"]
        if offset is not None:
            cmd.extend(["-o", str(offset)])
        cmd.extend([image_path, system_inode])
        
        try:
            # Run icat and capture binary output
            result = subprocess.run(cmd, capture_output=True, timeout=120)
            if result.returncode != 0:
                self._log("hostname_error", f"icat failed (offset={offset}): {result.stderr.decode('utf-8', errors='replace')[:200]}")
                return
            
            system_data = result.stdout
            if not system_data:
                self._log("hostname_error", "icat returned empty data")
                return
            
            # Parse binary for ComputerName
            # Registry value data follows the key name
            # Pattern: ComputerName\x00\x00\x00\x00 + metadata (4-20 bytes) + UTF-16LE hostname + \x00\x00
            # Example: ComputerName nulls + d8ffffff + J\x00E\x00A\x00N\x00-\x001\x003\x00F\x00B\x00F\x000\x003\x008\x00A\x003\x00\x00\x00
            hostname_found = None
            
            # Search for ComputerName followed by UTF-16LE hostname
            for m in re.finditer(b'ComputerName\x00\x00\x00\x00.{4,20}?(([A-Z]\x00[A-Z0-9\x00-]{10,40}\x00\x00))', system_data, re.IGNORECASE | re.DOTALL):
                try:
                    raw_hostname = m.group(1)
                    # Decode UTF-16LE (remove null bytes between chars)
                    hostname = raw_hostname.decode('utf-16le', errors='ignore').rstrip('\x00')
                    # Validate: must start with letter, alphanumeric with hyphens, reasonable length
                    # Filter out registry key names like "System", "Control", etc.
                    skip_names = {'system', 'control', 'select', 'setup', 'services', 'currentcontrolset'}
                    if hostname and 10 <= len(hostname) <= 30:
                        if re.match(r'^[A-Za-z][A-Za-z0-9-]*[A-Za-z0-9]?$', hostname) and hostname.lower() not in skip_names:
                            hostname_found = hostname.upper()
                            break
                except:
                    continue
            
            if hostname_found:
                dev["hostname"] = hostname_found
                dev["discovery_method"] = "registry_hostname"
                self._log("hostname_found", f"Hostname from SYSTEM hive: {hostname_found}")
                return
        except subprocess.TimeoutExpired:
            self._log("hostname_error", "icat timed out")
        except Exception as e:
            self._log("hostname_error", f"Failed to extract/parse SYSTEM hive: {e}")
    
    def _extract_hostname_from_linux_image(self, dev: dict, sk: 'SLEUTHKIT_Specialist', image_path: str, file_listing: str):
        """
        Extract hostname from Linux disk image by reading /etc/hostname.
        """
        # Find /etc/hostname inode
        hostname_inode = None
        for line in file_listing.split("\n"):
            if "etc/hostname" in line.lower() or "etc\\hostname" in line.lower():
                match = re.search(r'\s([\d-]+):\s*.*hostname$', line, re.IGNORECASE)
                if match:
                    hostname_inode = match.group(1)
                    break
        
        if not hostname_inode:
            self._log("hostname_search", "/etc/hostname inode not found")
            return
        
        # Extract using icat directly
        import subprocess
        
        cmd = ["icat"]
        clean_image_path = image_path
        if ":" in image_path:
            parts = image_path.rsplit(":", 1)
            if len(parts) == 2 and parts[1].isdigit():
                cmd.extend(["-o", parts[1]])
                clean_image_path = parts[0]
        
        cmd.extend([clean_image_path, hostname_inode])
        
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=30)
            if result.returncode != 0:
                self._log("hostname_error", f"icat failed: {result.stderr.decode('utf-8', errors='replace')[:200]}")
                return
            
            hostname = result.stdout.decode('utf-8', errors='replace').strip()
            if hostname:
                dev["hostname"] = hostname
                dev["discovery_method"] = "linux_hostname_file"
                self._log("hostname_found", f"Hostname from /etc/hostname: {hostname}")
        except subprocess.TimeoutExpired:
            self._log("hostname_error", "icat timed out")
        except Exception as e:
            self._log("hostname_error", f"Failed to extract /etc/hostname: {e}")
    
    def _extract_hostname_from_macos_image(self, dev: dict, sk: 'SLEUTHKIT_Specialist', image_path: str, file_listing: str):
        """
        Extract hostname from macOS disk image by reading preferences plist.
        Looks for ComputerName in /Library/Preferences/SystemConfiguration/preferences.plist
        or similar locations.
        """
        # Find preferences plist inode
        plist_inode = None
        for line in file_listing.split("\n"):
            line_lower = line.lower()
            if ("preferences.plist" in line_lower or "systemconfiguration" in line_lower) and "plist" in line_lower:
                match = re.search(r'\s([\d-]+):\s*(.*)$', line)
                if match:
                    plist_inode = match.group(1)
                    break
        
        if not plist_inode:
            self._log("hostname_search", "macOS preferences plist not found")
            return
        
        # Extract using icat directly
        import subprocess
        import tempfile
        
        with tempfile.NamedTemporaryFile(delete=False, suffix=".plist") as tmp:
            tmp_path = tmp.name
        
        cmd = ["icat"]
        clean_image_path = image_path
        if ":" in image_path:
            parts = image_path.rsplit(":", 1)
            if len(parts) == 2 and parts[1].isdigit():
                cmd.extend(["-o", parts[1]])
                clean_image_path = parts[0]
        
        cmd.extend([clean_image_path, plist_inode])
        
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=60)
            if result.returncode != 0:
                self._log("hostname_error", f"icat failed: {result.stderr.decode('utf-8', errors='replace')[:200]}")
                return
            
            # Write binary output to temp file
            Path(tmp_path).write_bytes(result.stdout)
            
            # Parse plist
            import plistlib
            with open(tmp_path, 'rb') as f:
                plist = plistlib.load(f)
            
            # Navigate to ComputerName - structure varies by macOS version
            computer_name = None
            if isinstance(plist, dict):
                # Try direct ComputerName
                computer_name = plist.get("ComputerName")
                # Try nested structure
                if not computer_name and "System" in plist:
                    computer_name = plist["System"].get("ComputerName")
                if not computer_name and "HostNames" in plist:
                    computer_name = plist["HostNames"].get("ComputerName")
            
            if computer_name:
                dev["hostname"] = str(computer_name)
                dev["discovery_method"] = "macos_plist_computer_name"
                self._log("hostname_found", f"Hostname from macOS plist: {computer_name}")
        except subprocess.TimeoutExpired:
            self._log("hostname_error", "icat timed out")
        except Exception as e:
            self._log("hostname_error", f"Failed to extract/parse macOS plist: {e}")
        finally:
            if Path(tmp_path).exists():
                Path(tmp_path).unlink()

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
