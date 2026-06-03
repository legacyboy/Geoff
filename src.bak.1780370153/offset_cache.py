#!/usr/bin/env python3
"""Geoff DFIR - Persistent, validated filesystem offset cache.

Solves the critical problem of wrong partition offsets causing cascading
failures across ALL playbook steps that use {offset} substitution.

Key design decisions:
  - mmls discovers ALL partition offsets for an image
  - Each offset is validated with fsstat before being committed
  - Cache persists to offset_cache.json in the case work directory
  - Pipeline step executor can request next offset when one fails
  - Checkpoint resumes load the cache without re-detection

Exports:
  OffsetCache, OffsetEntry
"""

import json
import os
import re
import subprocess
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, List, Optional, Any


# ---------------------------------------------------------------------------
# OffsetEntry — per-image offset data
# ---------------------------------------------------------------------------

@dataclass
class OffsetEntry:
    """Per-image partition offset data with validation state."""
    image_path: str
    all_offsets: List[int]                        # All partition offsets from mmls
    primary_offset: Optional[int] = None          # Currently validated best offset
    partition_descriptions: Dict[int, str] = field(default_factory=dict)  # offset -> desc
    validated: bool = False
    tried_offsets: List[int] = field(default_factory=list)  # offsets already tried (failed)
    exhausted: bool = False
    fs_type: str = ""                              # filesystem type of validated offset

    def to_dict(self) -> dict:
        return {
            "image_path": self.image_path,
            "all_offsets": self.all_offsets,
            "primary_offset": self.primary_offset,
            "partition_descriptions": self.partition_descriptions,
            "validated": self.validated,
            "tried_offsets": self.tried_offsets,
            "exhausted": self.exhausted,
            "fs_type": self.fs_type,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "OffsetEntry":
        return cls(
            image_path=d["image_path"],
            all_offsets=d.get("all_offsets", []),
            primary_offset=d.get("primary_offset"),
            partition_descriptions=d.get("partition_descriptions", {}),
            validated=d.get("validated", False),
            tried_offsets=d.get("tried_offsets", []),
            exhausted=d.get("exhausted", False),
            fs_type=d.get("fs_type", ""),
        )


# ---------------------------------------------------------------------------
# OffsetCache
# ---------------------------------------------------------------------------

class OffsetCache:
    """Persistent, validated filesystem offset cache.

    Stores per-image partition offsets validated by fsstat.
    Persists to <case_work_dir>/offset_cache.json for checkpoint resume.

    Usage:
        cache = OffsetCache(Path("/mnt/cases/2018_findevil_xxx/offset_cache.json"))
        offset = cache.detect_and_cache("/mnt/evidence/disk.E01", job_id="fe-xxx")
        # offset is now validated — all subsequent calls use it:
        offset = cache.get_validated_offset("/mnt/evidence/disk.E01")  # returns int

        # If a step fails with this offset:
        next_offset = cache.mark_offset_failed("/mnt/evidence/disk.E01", bad_offset)
        # Returns next valid offset or None if all exhausted
    """

    def __init__(self, cache_path: Path, fe_log_func=None):
        self._cache_path = Path(cache_path)
        self._entries: Dict[str, OffsetEntry] = {}
        self._fe_log = fe_log_func or self._default_log
        self._load()

    @staticmethod
    def _default_log(job_id: str, msg: str):
        print(f"[OFFSET-CACHE] {msg}")

    # -- Persistence --------------------------------------------------------

    def _load(self):
        """Load cache from JSON on init."""
        if self._cache_path.exists():
            try:
                data = json.loads(self._cache_path.read_text())
                for img_path, entry_data in data.get("entries", {}).items():
                    self._entries[img_path] = OffsetEntry.from_dict(entry_data)
            except Exception:
                self._entries = {}

    def _save(self):
        """Persist cache to JSON."""
        try:
            self._cache_path.parent.mkdir(parents=True, exist_ok=True)
            data = {
                "version": 1,
                "entries": {img: entry.to_dict() for img, entry in self._entries.items()},
            }
            self._cache_path.write_text(json.dumps(data, default=str, indent=2))
        except Exception:
            pass

    # -- Public API ---------------------------------------------------------

    def get_validated_offset(self, image_path: str) -> Optional[int]:
        """Return the validated offset for an image, or None."""
        entry = self._entries.get(image_path)
        if entry and entry.validated and entry.primary_offset is not None:
            return entry.primary_offset
        return None

    def get_all_offsets(self, image_path: str) -> List[int]:
        """Return all partition offsets from mmls, in priority order."""
        entry = self._entries.get(image_path)
        return list(entry.all_offsets) if entry else []

    def get_fs_type(self, image_path: str) -> str:
        """Return the filesystem type of the validated offset."""
        entry = self._entries.get(image_path)
        return entry.fs_type if entry else ""

    def is_exhausted(self, image_path: str) -> bool:
        """Return True if all offsets have been tried and failed."""
        entry = self._entries.get(image_path)
        return entry.exhausted if entry else False

    def to_dict(self) -> Dict[str, int]:
        """Return simple image_path -> offset dict for backward compatibility."""
        result = {}
        for img, entry in self._entries.items():
            if entry.validated and entry.primary_offset is not None:
                result[img] = entry.primary_offset
            elif entry.all_offsets:
                result[img] = entry.all_offsets[0]
        return result

    def mark_offset_failed(self, image_path: str, failed_offset: int,
                           job_id: str = "") -> Optional[int]:
        """Mark an offset as failed, try next, validate it, return it.

        Returns the next validated offset, or None if all exhausted.
        """
        entry = self._entries.get(image_path)
        if not entry:
            return None

        if failed_offset not in entry.tried_offsets:
            entry.tried_offsets.append(failed_offset)

        # Try remaining offsets
        for candidate in entry.all_offsets:
            if candidate in entry.tried_offsets:
                continue
            self._fe_log(job_id, f"  [OFFSET] Trying next partition offset {candidate} "
                         f"for {Path(image_path).name} (previous {failed_offset} failed)")
            if self._validate_offset(image_path, candidate):
                entry.primary_offset = candidate
                entry.validated = True
                entry.fs_type = self._detect_fs_type(image_path, candidate)
                self._save()
                self._fe_log(job_id, f"  [OFFSET] ✓ Offset {candidate} validated "
                             f"for {Path(image_path).name} ({entry.fs_type})")
                return candidate
            else:
                entry.tried_offsets.append(candidate)

        # All offsets exhausted
        entry.exhausted = True
        entry.validated = False
        self._save()
        self._fe_log(job_id, f"  [OFFSET] ✗ All {len(entry.all_offsets)} partition offsets "
                     f"exhausted for {Path(image_path).name}")
        return None

    def detect_and_cache(self, image_path: str, job_id: str = "") -> Optional[int]:
        """Run mmls, parse partitions, validate with fsstat, cache result.

        Returns the validated offset or None.
        """
        # Check cache first
        cached = self.get_validated_offset(image_path)
        if cached is not None:
            self._fe_log(job_id, f"  [OFFSET] Cache hit: {Path(image_path).name} → "
                         f"sector {cached} ({self.get_fs_type(image_path)})")
            return cached

        # Also skip if already exhausted
        if self.is_exhausted(image_path):
            self._fe_log(job_id, f"  [OFFSET] {Path(image_path).name} previously exhausted, skipping")
            return None

        # Run mmls to discover partitions
        partitions = self._run_mmls(image_path, job_id)
        if not partitions:
            # Try whole-disk mode (no partition table)
            if self._validate_offset(image_path, 0):
                entry = OffsetEntry(
                    image_path=image_path,
                    all_offsets=[0],
                    primary_offset=0,
                    validated=True,
                    fs_type=self._detect_fs_type(image_path, 0) or "raw",
                )
                self._entries[image_path] = entry
                self._save()
                self._fe_log(job_id, f"  [OFFSET] {Path(image_path).name}: no partition table, "
                             f"whole-disk mode validated (offset 0)")
                return 0

            self._fe_log(job_id, f"  [OFFSET] {Path(image_path).name}: no partitions found "
                         f"and whole-disk mode failed")
            entry = OffsetEntry(
                image_path=image_path,
                all_offsets=[],
                exhausted=True,
            )
            self._entries[image_path] = entry
            self._save()
            return None

        # Build entry with all offsets
        all_offsets = [p["offset"] for p in partitions]
        descriptions = {p["offset"]: p.get("description", "") for p in partitions}

        entry = OffsetEntry(
            image_path=image_path,
            all_offsets=all_offsets,
            partition_descriptions=descriptions,
        )

        # Validate each offset with fsstat — first success wins
        for part in partitions:
            offset = part["offset"]
            fs_type = part.get("fs_type", "")
            desc = part.get("description", "").lower()

            # Skip meta/unallocated partitions (no real filesystem)
            if any(skip in desc for skip in ["metadata", "unallocated", "free",
                                             "primary table", "gpt header",
                                             "protective mbr", "unused"]):
                continue

            if self._validate_offset(image_path, offset):
                entry.primary_offset = offset
                entry.validated = True
                entry.fs_type = self._detect_fs_type(image_path, offset) or fs_type
                self._fe_log(job_id, f"  [OFFSET] ✓ {Path(image_path).name}: "
                             f"sector {offset} validated ({entry.fs_type}) — "
                             f"{descriptions.get(offset, '')}")
                break
            else:
                entry.tried_offsets.append(offset)

        if not entry.validated and entry.all_offsets:
            # None validated — mark which ones we tried but don't mark exhausted yet
            # (pipeline may want to try more via mark_offset_failed)
            self._fe_log(job_id, f"  [OFFSET] ⚠ {Path(image_path).name}: "
                         f"no offset validated from {len(all_offsets)} partitions")

        self._entries[image_path] = entry
        self._save()
        return entry.primary_offset if entry.validated else None

    # -- Internal: mmls ----------------------------------------------------

    def _run_mmls(self, image_path: str, job_id: str = "") -> List[Dict[str, Any]]:
        """Run mmls and return parsed partition list with priority ordering.

        Tries multiple strategies for EWF images and different partition
        table types. Returns ALL partitions (not just the first match).

        Priority ordering: NTFS/ext > FAT/exFAT > HFS > other > meta/unallocated
        """
        # Resolve E01 path if given an E02+ segment
        resolved_path = self._resolve_e01_path(image_path)

        # For E01 images, try ewfmount first (most reliable)
        ext = Path(resolved_path).suffix.lower()
        is_ewf = ext in ('.e01', '.e02', '.e03', '.e04', '.e05', '.ee01', '.ex01')

        if is_ewf:
            ewf_result = self._try_ewfmount_mmls(resolved_path, job_id)
            if ewf_result:
                return self._prioritize_partitions(ewf_result)

        # Direct mmls (works for raw images and E01 with TSK EWF support)
        partitions = self._parse_mmls_output(resolved_path, job_id)
        if partitions:
            return self._prioritize_partitions(partitions)

        # Try mmls with explicit partition table types
        for pt_type in ["gpt", "dos", "mac", "bsd"]:
            partitions = self._parse_mmls_output(resolved_path, job_id, pt_type=pt_type)
            if partitions:
                self._fe_log(job_id, f"  [OFFSET] mmls -t {pt_type} found "
                             f"{len(partitions)} partitions for {Path(image_path).name}")
                return self._prioritize_partitions(partitions)

        return []

    def _try_ewfmount_mmls(self, e01_path: str, job_id: str) -> List[Dict[str, Any]]:
        """Try ewfmount + mmls on ewf1 for EWF images."""
        ewf_raw_dir = f"/tmp/geoff_ewf_offset_{os.getpid()}_{hash(e01_path) % 100000}"
        try:
            os.makedirs(ewf_raw_dir, exist_ok=True)
            ewf_result = subprocess.run(
                ["ewfmount", e01_path, ewf_raw_dir],
                capture_output=True, text=True, timeout=60,
            )
            if ewf_result.returncode != 0:
                self._fe_log(job_id, f"  [OFFSET] ewfmount failed: "
                             f"{ewf_result.stderr.strip()[:200]}")
                try: os.rmdir(ewf_raw_dir)
                except: pass
                return []

            ewf1_path = f"{ewf_raw_dir}/ewf1"
            if not os.path.exists(ewf1_path):
                self._fe_log(job_id, f"  [OFFSET] ewfmount OK but ewf1 not found")
                self._cleanup_ewfmount(ewf_raw_dir, job_id)
                return []

            partitions = self._parse_mmls_output(ewf1_path, job_id)
            self._cleanup_ewfmount(ewf_raw_dir, job_id)
            return partitions

        except subprocess.TimeoutExpired:
            self._fe_log(job_id, f"  [OFFSET] ewfmount timed out")
            self._cleanup_ewfmount(ewf_raw_dir, job_id)
            return []
        except Exception as e:
            self._fe_log(job_id, f"  [OFFSET] ewfmount error: {e}")
            self._cleanup_ewfmount(ewf_raw_dir, job_id)
            return []

    def _cleanup_ewfmount(self, mount_dir: str, job_id: str):
        """Unmount and clean up ewfmount directory."""
        try:
            subprocess.run(["fusermount", "-u", mount_dir],
                          capture_output=True, timeout=10)
        except Exception:
            pass
        try:
            os.rmdir(mount_dir)
        except Exception:
            pass

    def _parse_mmls_output(self, image_path: str, job_id: str = "",
                           pt_type: str = None) -> List[Dict[str, Any]]:
        """Run mmls and parse output into partition list."""
        cmd = ["mmls"]
        if pt_type:
            cmd.extend(["-t", pt_type])
        cmd.append(image_path)

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if result.returncode != 0:
                return []
        except (subprocess.TimeoutExpired, Exception):
            return []

        partitions = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("DOS") or line.startswith("Slot") \
               or line.startswith("---") or line.startswith("Offset") \
               or line.startswith("Units") or line.startswith("Mac") \
               or line.startswith("BSD"):
                continue
            if line.startswith("0") and "-------" in line:
                continue
            if line.startswith("0") and "Meta" in line[:20]:
                continue

            # Format: 002:  000:000   0000000063   0009510479   0009510417   NTFS / exFAT (0x07)
            match = re.match(r'^\d+:\s+\d+:\d+\s+(\d+)\s+(\d+)\s+(\d+)\s+(.*)', line)
            if not match:
                # Format: 000: 0000063 020948759 020948697 NTFS (0x07)
                match = re.match(r'^\d+:\s+(\d+)\s+(\d+)\s+(\d+)\s+(.*)', line)
            if not match:
                # Simple format: start end length description
                parts = line.split()
                if len(parts) >= 4:
                    try:
                        match_type = "simple"
                        start = int(parts[0])
                        desc = ' '.join(parts[3:])
                    except ValueError:
                        continue
                else:
                    continue

            if match:
                start = int(match.group(1))
                desc = match.group(4).strip()
                fs_type = self._extract_fs_type(desc)
                partitions.append({
                    "offset": start,
                    "fs_type": fs_type,
                    "description": desc,
                })

        return partitions

    @staticmethod
    def _extract_fs_type(description: str) -> str:
        """Extract filesystem type from mmls description string."""
        lower = description.lower()
        hex_map = {
            '0x07': 'ntfs', '0x0b': 'fat32', '0x0c': 'fat32',
            '0x06': 'fat', '0x83': 'ext', '0x82': 'swap',
            '0xaf': 'hfs', '0xab': 'hfs',
        }
        fs_map = {
            'ntfs': 'ntfs', 'exfat': 'exfat', 'fat32': 'fat32',
            'fat16': 'fat16', 'fat12': 'fat12',
            'ext4': 'ext4', 'ext3': 'ext3', 'ext2': 'ext2',
            'hfs+': 'hfsplus', 'hfsx': 'hfsx', 'hfs': 'hfs',
            'ufs': 'ufs', 'ufs2': 'ufs2',
            'swap': 'swap', 'linux': 'ext',
        }
        for code, fs in hex_map.items():
            if code in lower:
                return fs
        for key, fs in fs_map.items():
            if key in lower:
                return fs
        return ""

    @staticmethod
    def _prioritize_partitions(partitions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Sort partitions: real filesystems first, then by priority.

        Priority: NTFS/ext > FAT > HFS > other > meta
        """
        def _priority(p: dict) -> int:
            desc = p.get("description", "").lower()
            fs = p.get("fs_type", "").lower()

            # Meta/unallocated — lowest priority
            if any(skip in desc for skip in ["metadata", "unallocated", "free",
                                             "primary table", "gpt header",
                                             "protective mbr", "unused", "gap"]):
                return 100

            # High priority filesystems
            if fs in ("ntfs", "ext4", "ext3", "ext2") or "ntfs" in desc or "ext" in desc:
                return 1
            if fs in ("fat32", "exfat", "fat16", "fat12") or "fat" in desc or "exfat" in desc:
                return 2
            if fs in ("hfs", "hfsplus", "hfsx") or "hfs" in desc:
                return 3
            if "windows" in desc or "linux" in desc:
                return 2
            # Unknown but has a filesystem type
            if fs:
                return 5
            # Everything else
            return 10

        return sorted(partitions, key=_priority)

    # -- Internal: validation -----------------------------------------------

    def _validate_offset(self, image_path: str, offset: int) -> bool:
        """Validate that fsstat succeeds with this offset."""
        try:
            result = subprocess.run(
                ['fsstat', '-o', str(offset), image_path],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                stdout = result.stdout or ""
                # fsstat returns 0 even on some "partial" reads — check for real output
                if 'File System Type' in stdout or 'File System' in stdout:
                    return True
                # Some fsstat outputs don't have that exact string but still work
                if len(stdout) > 100 and not any(err in stdout.lower()
                    for err in ['cannot determine', 'invalid', 'error', 'not a']):
                    return True
            return False
        except (subprocess.TimeoutExpired, Exception):
            return False

    def _detect_fs_type(self, image_path: str, offset: int) -> str:
        """Detect filesystem type via fsstat output."""
        try:
            result = subprocess.run(
                ['fsstat', '-o', str(offset), image_path],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0 and result.stdout:
                for line in result.stdout.splitlines():
                    if 'File System Type:' in line:
                        return line.split(':', 1)[1].strip()
            return ""
        except Exception:
            return ""

    @staticmethod
    def _resolve_e01_path(image_path: str) -> str:
        """If image_path is an E02+ segment, return the E01 path."""
        p = Path(image_path)
        for seg in ('.E02', '.E03', '.E04', '.E05', '.e02', '.e03', '.e04', '.e05'):
            if image_path.endswith(seg):
                e01 = image_path[:-4] + '.E01'
                if os.path.isfile(e01):
                    return e01
                e01_lower = image_path[:-4] + '.e01'
                if os.path.isfile(e01_lower):
                    return e01_lower
                break
        return image_path

    def get_entry(self, image_path: str) -> Optional[OffsetEntry]:
        """Return the raw OffsetEntry for an image (for advanced use)."""
        return self._entries.get(image_path)

    def __contains__(self, image_path: str) -> bool:
        return image_path in self._entries

    def __len__(self) -> int:
        return len(self._entries)