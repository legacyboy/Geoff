#!/usr/bin/env python3
"""
SIFT Tool Specialists - Full Parsers
Each specialist handles a specific forensic domain with structured output parsing
"""

import json
import subprocess
import re
import os
import shutil
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Union


class SLEUTHKIT_Specialist:
    """Specialist for SleuthKit disk analysis tools with full output parsing"""

    def __init__(self, evidence_path: str):
        self.evidence_path = Path(evidence_path)
        self.tools_available = self._check_tools()

    def _check_tools(self) -> Dict[str, bool]:
        tools = ['mmls', 'fsstat', 'fls', 'icat', 'istat', 'ils', 'blkls', 'jcat']
        available = {}
        for tool in tools:
            result = subprocess.run(['which', tool], capture_output=True)
            available[tool] = result.returncode == 0
        return available

    def analyze_partition_table(self, disk_image: str) -> Dict[str, Any]:
        """mmls - Display partition layout with parsed partition entries"""
        segments = self._find_image_segments(disk_image)
        raw = self.run('mmls', segments)
        if raw['status'] != 'success':
            return raw

        partitions = []
        # mmls output format (typical):
        #   Slot      Start        End          Length       Description
        #   002:  000:000   0000000063   0009510479   0009510417   NTFS / exFAT (0x07)
        # Also handles simpler formats without slot prefixes
        for line in raw['stdout'].splitlines():
            line = line.strip()
            if not line or line.startswith('DOS') or line.startswith('Slot') or line.startswith('---') or line.startswith('Offset') or line.startswith('Units') or line == '':
                continue
            # Skip unallocated/meta entries with -------
            if line.startswith('0') and '-------' in line:
                continue
            if line.startswith('0') and 'Meta' in line[:20]:
                continue
            # Try format with slot prefix: 002:  000:000   0000000063   0009510479   0009510417   NTFS...
            match = re.match(r'^\d+:\s+\d+:\d+\s+(\d+)\s+(\d+)\s+(\d+)\s+(.*)', line)
            if match:
                partitions.append({
                    'start_sector': int(match.group(1)),
                    'end_sector': int(match.group(2)),
                    'length_sectors': int(match.group(3)),
                    'description': match.group(4).strip()
                })
                continue
            # Try older format: slot:start  slot:end  slot:length  desc
            match = re.match(r'^(\d+):(\d+)\s+(\d+):(\d+)\s+(\d+):(\d+)\s+(.*)', line)
            if match:
                partitions.append({
                    'slot': int(match.group(1)),
                    'start_sector': int(match.group(2)),
                    'end_sector': int(match.group(4)),
                    'length_sectors': int(match.group(6)),
                    'description': match.group(7).strip()
                })
                continue
            # Try DOS/MBR format: slot: start end length desc
            # e.g. "000: 0000063 020948759 020948697 NTFS (0x07)"
            match = re.match(r'^\d+:\s+(\d+)\s+(\d+)\s+(\d+)\s+(.*)', line)
            if match:
                partitions.append({
                    'start_sector': int(match.group(1)),
                    'end_sector': int(match.group(2)),
                    'length_sectors': int(match.group(3)),
                    'description': match.group(4).strip()
                })
                continue
            # Try simpler format: start end length description
            parts = line.split()
            if len(parts) >= 4:
                try:
                    partitions.append({
                        'start_sector': int(parts[0]),
                        'end_sector': int(parts[1]),
                        'length_sectors': int(parts[2]),
                        'description': ' '.join(parts[3:])
                    })
                except ValueError:
                    pass

        return {
            'tool': 'mmls',
            'disk_image': disk_image,
            'status': 'success',
            'partition_count': len(partitions),
            'partitions': partitions,
            'raw_output': raw['stdout'],
            'timestamp': datetime.now().isoformat()
        }

    @staticmethod
    def _resolve_e01_path(image_path: str) -> str:
        """If image_path is an E02/E03/... segment, return the corresponding E01 path.

        SleuthKit tools (mmls, fls, icat, etc.) require the E01 file as the
        primary reference for EnCase images — passing an E02 directly will fail.
        """
        p = Path(image_path)
        # Match .E02, .E03, .E04, .E05 (case-insensitive)
        for seg in ('.E02', '.E03', '.E04', '.E05', '.e02', '.e03', '.e04', '.e05'):
            if image_path.endswith(seg):
                e01 = image_path[:-4] + '.E01'
                if os.path.isfile(e01):
                    return e01
                # Try lowercase
                e01_lower = image_path[:-4] + '.e01'
                if os.path.isfile(e01_lower):
                    return e01_lower
                break
        return image_path

    def _find_image_segments(self, image_path: str) -> List[str]:
        """Find all segments of a split or EnCase disk image.

        For EnCase images (.E01/.E02/...), resolves E02+ back to E01 first,
        then collects all segments (.E01, .E02, ...) so SleuthKit can find
        the complete image set.

        For split DD images (.001, .002, ...), finds all sibling segments.
        For single files (.img, .dd, .raw, etc.), returns [image_path].
        """
        # --- EnCase segment resolution ---
        # If we were given an E02/E03/... file, we MUST resolve to E01 first
        # because mmls/fls/icat require the E01 as the primary reference.
        image_path = self._resolve_e01_path(image_path)
        p = Path(image_path)
        if not p.exists():
            return [image_path]

        # EnCase images: collect all .E01/.E02/... segments in order
        if p.suffix.lower() in ('.e01', '.e02', '.e03', '.e04', '.e05',
                                 '.ee01', '.ex01'):
            base = p.stem  # e.g. "nps-2009-domexusers.redacted" from "nps-2009-domexusers.redacted.E01"
            dir_path = p.parent
            segments = []
            for f in sorted(dir_path.iterdir()):
                if (f.is_file() and f.stem == base
                        and f.suffix.lower() in ('.e01', '.e02', '.e03', '.e04', '.e05',
                                                  '.ee01', '.ex01')):
                    segments.append(str(f))
            if segments:
                return segments
            return [image_path]

        # --- Split DD images (.001, .002, ...) ---
        if p.suffix.lower() in ('.img', '.dd', '.bin', '.raw'):
            segment_suffix = p.suffix
            if segment_suffix and re.match(r'^\d+$', segment_suffix.lstrip('.')):
                base_name = p.stem
                dir_path = p.parent
                segments = []
                for f in sorted(dir_path.iterdir()):
                    if f.is_file() and f.stem == base_name:
                        ext = f.suffix.lstrip('.')
                        if ext.isdigit():
                            segments.append(str(f))
                if segments:
                    return segments
                return [image_path]
            return [image_path]

        # Non-standard extensions: try segment detection anyway
        stem = p.stem
        segment_suffix = p.suffix
        if segment_suffix and re.match(r'^\d+$', segment_suffix.lstrip('.')):
            dir_path = p.parent
            segments = []
            for f in sorted(dir_path.iterdir()):
                if f.is_file() and f.stem == stem:
                    ext = f.suffix.lstrip('.')
                    if ext.isdigit():
                        segments.append(str(f))
            if segments:
                return segments

        return [image_path]

    def _detect_partition(self, image_path: str) -> List[Dict[str, Any]]:
        """Run mmls to find partition offsets and filesystem types.

        Returns a list of partitions with keys:
          - offset: sector number (start_sector)
          - fs_type: filesystem type string (ntfs, ext4, fat32, etc.)
          - description: full description string from mmls output
        """
        segments = self._find_image_segments(image_path)
        raw = self.run('mmls', segments)
        if raw['status'] != 'success':
            return []

        partitions = []
        for line in raw['stdout'].splitlines():
            line = line.strip()
            if not line or line.startswith('DOS') or line.startswith('Slot') or line.startswith('---') or line.startswith('Offset') or line.startswith('Units') or line == '':
                continue
            if line.startswith('0') and '-------' in line:
                continue
            if line.startswith('0') and 'Meta' in line[:20]:
                continue
            # Try format with slot prefix: 002:  000:000   0000000063   0009510479   0009510417   NTFS...
            match = re.match(r'^\d+:\s+\d+:\d+\s+(\d+)\s+(\d+)\s+(\d+)\s+(.*)', line)
            if match:
                desc = match.group(4).strip()
                # Extract fs_type from description (e.g. "NTFS / exFAT (0x07)" -> "ntfs")
                fs_type = self._extract_fs_type(desc)
                partitions.append({
                    'offset': int(match.group(1)),
                    'fs_type': fs_type,
                    'description': desc
                })
                continue
            # Try DOS/MBR format: slot: start end length desc
            # e.g. "000: 0000063 020948759 020948697 NTFS (0x07)"
            match = re.match(r'^\d+:\s+(\d+)\s+(\d+)\s+(\d+)\s+(.*)', line)
            if match:
                desc = match.group(4).strip()
                fs_type = self._extract_fs_type(desc)
                partitions.append({
                    'offset': int(match.group(1)),
                    'fs_type': fs_type,
                    'description': desc
                })
                continue
            # Try simpler format: start end length description
            parts = line.split()
            if len(parts) >= 4:
                try:
                    desc = ' '.join(parts[3:])
                    fs_type = self._extract_fs_type(desc)
                    partitions.append({
                        'offset': int(parts[0]),
                        'fs_type': fs_type,
                        'description': desc
                    })
                except ValueError:
                    pass

        return partitions

    @staticmethod
    def _extract_fs_type(description: str) -> str:
        """Extract filesystem type from mmls description string."""
        lower = description.lower()
        # Map TSK hex codes and common names to canonical type strings
        fs_map = {
            'ntfs': 'ntfs',
            'ntfs/': 'ntfs',
            'fat': 'fat',
            'fat32': 'fat32',
            'exfat': 'exfat',
            'ext': 'ext',
            'ext2': 'ext2',
            'ext3': 'ext3',
            'ext4': 'ext4',
            'ufs': 'ufs',
            'ufs2': 'ufs2',
            'hfs': 'hfs',
            'hfsx': 'hfsx',
            'udf': 'udf',
            'ffs': 'ffs',
            'swap': 'swap',
            'none': 'none',
        }
        # Also map hex codes like 0x07 -> ntfs, 0x0b -> fat32, etc.
        hex_map = {
            '0x07': 'ntfs',
            '0x0b': 'fat32',
            '0x0c': 'fat32',
            '0x06': 'fat',
            '0x00': 'none',
            '0x83': 'ext',
            '0x82': 'swap',
        }
        for code, fs in hex_map.items():
            if code in lower:
                return fs
        for key, fs in fs_map.items():
            if key in lower:
                return fs
        return ''

    def run(self, tool: str, args: List[str]) -> Dict[str, Any]:
        if not self.tools_available.get(tool, False):
            return {
                'tool': tool,
                'status': 'error',
                'error': f'{tool} not found in PATH',
                'timestamp': datetime.now().isoformat()
            }
        try:
            result = subprocess.run([tool] + args, capture_output=True, text=True, timeout=600)
            return {
                'tool': tool,
                'status': 'success' if result.returncode == 0 else 'error',
                'returncode': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'timestamp': datetime.now().isoformat()
            }
        except subprocess.TimeoutExpired:
            return {'tool': tool, 'status': 'timeout', 'error': 'Command timed out after 5 minutes', 'timestamp': datetime.now().isoformat()}
        except Exception as e:
            return {'tool': tool, 'status': 'error', 'error': str(e), 'timestamp': datetime.now().isoformat()}

    def _run_with_segments(self, tool: str, base_image: str,
                           base_args: Optional[List[str]] = None,
                           extra_partitions: Optional[List[str]] = None,
                           graceful: bool = True) -> Dict[str, Any]:
        """Run a sleuthkit tool with auto-detected image segments and partitions.

        Args:
            tool: sleuthkit tool name (fls, fsstat, icat, etc.)
            base_image: the image path to analyze
            base_args: extra arguments to pass to the tool
            extra_partitions: pre-detected partitions (offset/fs_type) to use
            graceful: if True, handle truncated/partial image errors gracefully
        """
        # Auto-detect partitions if not provided
        partitions = extra_partitions if extra_partitions else self._detect_partition(base_image)

        # Auto-detect image segments
        segments = self._find_image_segments(base_image)

        # Build the argument list
        cmd_args = list(base_args) if base_args else []

        # Check if inode is in args (last positional arg after image)
        # Must check BEFORE removing image path
        has_inode = False
        inode_value = None
        for i, a in enumerate(cmd_args):
            if a == base_image:
                # Check if next arg exists and is not a flag (inode)
                if i + 1 < len(cmd_args) and not cmd_args[i + 1].startswith('-'):
                    has_inode = True
                    inode_value = cmd_args[i + 1]

        # Remove duplicate image paths if segments will be added
        # _find_image_segments handles image path resolution
        for i, a in enumerate(cmd_args):
            if a == base_image:
                cmd_args[i] = None
        cmd_args = [a for a in cmd_args if a is not None]

        # If inode was present, remove it temporarily and add at end
        if has_inode:
            cmd_args = [a for a in cmd_args if a != inode_value]

        # If partitions were detected and no offset is already specified, use first partition offset
        offset_provided = False
        for i, a in enumerate(cmd_args):
            if a == '-o' and i + 1 < len(cmd_args):
                offset_provided = True
                break

        if not offset_provided and partitions:
            # Try to find a filesystem partition (skip unused/meta)
            target_partition = None
            for p in partitions:
                if p.get('fs_type') and p['fs_type'] != 'none':
                    target_partition = p
                    break
            if target_partition is None and partitions:
                target_partition = partitions[0]
            if target_partition and target_partition.get('offset') is not None:
                cmd_args.extend(['-o', str(target_partition['offset'])])
                # Add -f flag with detected filesystem type
                if target_partition.get('fs_type'):
                    cmd_args.extend(['-f', target_partition['fs_type']])

        # Pass all image segments as arguments
        for seg in segments:
            cmd_args.append(seg)

        # Add inode at the very end (required by TSK syntax)
        if has_inode and inode_value:
            cmd_args.append(inode_value)

        raw = self.run(tool, cmd_args)

        # Handle partial/truncated image errors gracefully
        if not offset_provided and partitions and raw['status'] == 'error':
            stderr_lower = raw.get('stderr', '').lower()
            # Check for common truncated/partial image errors
            if any(kw in stderr_lower for kw in ['bitmap', 'block', 'unallocated', 'cannot determine',
                                                   'truncat', 'partial', 'corrupt', 'bad magic',
                                                   'invalid superblock', 'bad superblock',
                                                   'dinode_lookup', 'update sequence', 'metadata structure',
                                                   'mft size', 'mft entry']):
                # If the error is about metadata/bitmap/read failure, try with raw mode or skip partition
                if any(p.get('fs_type') for p in partitions):
                    # Try with offset but without -f fs type (let TSK auto-detect)
                    alt_args = list(base_args) if base_args else []
                    best = None
                    for p in partitions:
                        if p.get('fs_type') and p['fs_type'] != 'none':
                            best = p
                            break
                    if best is None and partitions:
                        best = partitions[0]
                    if best and best.get('offset') is not None:
                        alt_args.extend(['-o', str(best['offset'])])
                    for seg in segments:
                        alt_args.append(seg)
                    alt_raw = self.run(tool, alt_args)
                    if alt_raw['status'] == 'success':
                        return {
                            'tool': tool,
                            'status': 'success_with_partial',
                            'returncode': 0,
                            'stdout': alt_raw['stdout'],
                            'stderr': raw.get('stderr', ''),
                            'note': 'Recovered via partition auto-detection with auto fs-type; original metadata error',
                            'timestamp': datetime.now().isoformat()
                        }
                    # If still failing, try direct disk access without partition offset
                    # (treat whole image as filesystem)
                    alt_args2 = list(base_args) if base_args else []
                    for seg in segments:
                        alt_args2.append(seg)
                    alt_raw2 = self.run(tool, alt_args2)
                    if alt_raw2['status'] == 'success':
                        return {
                            'tool': tool,
                            'status': 'success_with_partial',
                            'returncode': 0,
                            'stdout': alt_raw2['stdout'],
                            'stderr': raw.get('stderr', ''),
                            'note': 'Recovered via direct disk access (no partition offset); original metadata error',
                            'timestamp': datetime.now().isoformat()
                        }

        return raw

    def analyze_filesystem(self, image: str, offset: Optional[int] = None) -> Dict[str, Any]:
        """fsstat - Display filesystem statistics with parsed structure"""
        args = []
        if offset is not None:
            args = ['-o', str(offset)]
        args.append(image)  # will be replaced by _run_with_segments segments
        raw = self._run_with_segments('fsstat', image, base_args=args)
        if raw['status'] in ('error', 'timeout'):
            # Return as-is for timeout, but mark success_with_partial gracefully
            if raw['status'] == 'success_with_partial':
                pass  # fall through to parsing below
            else:
                return raw

        fs_info = {
            'file_system_type': '',
            'volume_serial': '',
            'oem_name': '',
            'cluster_size': 0,
            'total_clusters': 0,
            'free_clusters': 0,
            'metadata': {}
        }

        for line in raw['stdout'].splitlines():
            stripped = line.strip()
            if 'File System Type:' in stripped:
                fs_info['file_system_type'] = stripped.split(':', 1)[1].strip()
            elif 'Volume Serial Number:' in stripped:
                fs_info['volume_serial'] = stripped.split(':', 1)[1].strip()
            elif 'OEM Name:' in stripped:
                fs_info['oem_name'] = stripped.split(':', 1)[1].strip()
            elif 'Cluster Size:' in stripped:
                try:
                    fs_info['cluster_size'] = int(re.search(r'\d+', stripped.split(':')[1]).group())
                except (ValueError, AttributeError):
                    pass
            elif 'Total Cluster Range:' in stripped:
                try:
                    nums = re.findall(r'\d+', stripped)
                    fs_info['total_clusters'] = int(nums[-1]) if nums else 0
                except ValueError:
                    pass
            # Catch any key: value pairs as metadata
            elif ':' in stripped and not stripped.startswith('-') and not stripped.startswith('/'):
                key, _, val = stripped.partition(':')
                if key.strip() and val.strip() and len(key.strip()) < 50:
                    fs_info['metadata'][key.strip()] = val.strip()

        return {
            'tool': 'fsstat',
            'image': image,
            'offset': offset,
            'status': 'success',
            'filesystem_info': fs_info,
            'raw_output': raw['stdout'],
            'timestamp': datetime.now().isoformat()
        }

    def list_files(self, image: str, offset: Optional[int] = None, inode: Optional[Union[int, str]] = None, recursive: bool = True, filter_path: Optional[str] = None, time_window_start: Optional[str] = None, time_window_end: Optional[str] = None) -> Dict[str, Any]:
        """fls - List files and directories with parsed file entries.

        *filter_path* (str, optional): substring match against file/dir full_path.
            Only entries whose path contains this string are returned.
        *time_window_start* / *time_window_end* (str, optional): accepted for
            playbook compat; fls does not do inline time-filtering.  Use
            list_files_mactime for time-constrained file enumeration.
        """
        args = []
        if recursive:
            args.append('-r')
        args.append('-p')  # Prepend path
        if offset is not None:
            args.extend(['-o', str(offset)])
        args.append(image)  # will be replaced by _run_with_segments
        if inode is not None:
            # inode is passed as a positional argument (not -f flag)
            args.append(str(inode))
        raw = self._run_with_segments('fls', image, base_args=args)
        if raw['status'] == 'success_with_partial':
            # Normalize the status for downstream parsing
            raw = dict(raw)
            raw['status'] = 'success'
        elif raw['status'] != 'success':
            return raw

        files = []
        dirs = []
        deleted = []

        for line in raw['stdout'].splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            # fls -p output format: r/r *inode-meta: name or d/d *inode-meta: name
            # inode can be composite like 3519-144-6 (meta_addr-attr_type-attr_id)
            match = re.match(r'^([rvmldc]/[rda])\s+(\*?)([\d-]+)\s*:\s+(.*)', stripped)
            if not match:
                # Alternate format: type meta_inode name
                match2 = re.match(r'^([rvmldc]/[rda])\s+(\*?)([\d-]+)\s+(.*)', stripped)
                if match2:
                    file_type = match2.group(1)
                    is_deleted = '*' in match2.group(2)
                    meta_inode_raw = match2.group(3)
                    meta_inode = int(meta_inode_raw.split('-')[0]) if '-' in meta_inode_raw else int(meta_inode_raw)
                    name = match2.group(4).strip()
                else:
                    continue
            else:
                file_type = match.group(1)
                is_deleted = '*' in match.group(2)
                meta_inode_raw = match.group(3)
                meta_inode = int(meta_inode_raw.split('-')[0]) if '-' in meta_inode_raw else int(meta_inode_raw)
                name = match.group(4).strip()

            entry = {
                'type': file_type,
                'inode': meta_inode,
                'name': name,
                'is_deleted': is_deleted,
                'full_path': name
            }

            if file_type.startswith('d'):
                dirs.append(entry)
            else:
                files.append(entry)

            if is_deleted:
                deleted.append(entry)

        # Apply path-based filtering when filter_path is set
        if filter_path:
            filter_lower = filter_path.lower()
            files = [f for f in files if filter_lower in f.get('full_path', '').lower()]
            dirs = [d for d in dirs if filter_lower in d.get('full_path', '').lower()]
            deleted = [e for e in deleted if filter_lower in e.get('full_path', '').lower()]

        # Time-window filtering note: fls output does not include timestamps in
        # standard format.  list_files_mactime is the correct tool for
        # time-constrained enumeration from a disk image.
        time_window_applied = False
        if time_window_start or time_window_end:
            time_window_applied = False  # not actionable in std fls output

        return {
            'tool': 'fls',
            'image': image,
            'offset': offset,
            'status': 'success',
            'total_files': len(files),
            'total_dirs': len(dirs),
            'deleted_count': len(deleted),
            'files': files[:500],
            'directories': dirs[:200],
            'deleted_files': deleted[:200],
            'stdout': raw['stdout'],  # For backward compatibility with enrichment code
            'raw_output': raw['stdout'][:50000],
            'timestamp': datetime.now().isoformat()
        }

    def extract_file(self, image: str, inode: int, output_path: str, offset: Optional[int] = None) -> Dict[str, Any]:
        """icat - Extract file by inode"""
        args = []
        if offset is not None:
            args = ['-o', str(offset)]
        args.extend([image, str(inode)])
        raw = self._run_with_segments('icat', image, base_args=args)
        if raw['status'] == 'success_with_partial':
            raw = dict(raw)
            raw['status'] = 'success'
        if raw['status'] == 'success':
            try:
                out = Path(output_path).resolve()
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_bytes(raw['stdout'].encode('latin-1') if isinstance(raw['stdout'], str) else raw['stdout'])
                size = out.stat().st_size
                return {
                    'tool': 'icat',
                    'status': 'success',
                    'output_file': str(out),
                    'bytes_extracted': size,
                    'inode': inode,
                    'timestamp': datetime.now().isoformat()
                }
            except Exception as e:
                return {'tool': 'icat', 'status': 'error', 'error': str(e), 'timestamp': datetime.now().isoformat()}
        return raw

    def list_deleted(self, image: str, offset: Optional[int] = None, time_window_start: Optional[str] = None, time_window_end: Optional[str] = None) -> Dict[str, Any]:
        """List deleted files using fls — filters for entries marked as deleted."""
        result = self.list_files(image, offset, recursive=True, time_window_start=time_window_start, time_window_end=time_window_end)
        if result['status'] != 'success':
            return result
        deleted_files = result.get('deleted_files', [])
        deleted_entries = [e for e in result.get('files', []) + result.get('directories', []) if e.get('is_deleted')]
        return {
            'tool': 'fls (deleted)',
            'image': image,
            'offset': offset,
            'status': 'success',
            'total_deleted': len(deleted_entries),
            'deleted_files': deleted_entries if deleted_entries else deleted_files,
            'raw_output': result.get('raw_output', ''),
        }

    def extract_browser_artifacts(self, image: str, offset: Optional[int] = None) -> Dict[str, Any]:
        """Find and extract browser-related files from inside a disk image.

        Scans the fls listing for browser history, cookies, and cache databases,
        then extracts them via icat to a temp directory for analysis by the
        browser specialist.
        """
        listing = self.list_files(image, offset, recursive=True)
        if listing.get('status') not in ('success', 'success_with_partial'):
            return {'tool': 'extract_browser_artifacts', 'status': 'error',
                    'error': f'fls failed: {listing.get("status")}',
                    'timestamp': datetime.now().isoformat()}

        browser_files = (
            'history', 'places.sqlite', 'cookies.sqlite', 'cookies.db',
            'login data', 'web data', 'favicons.db', 'bookmarks.html',
            'sessionstore.js', 'formhistory.sqlite',
            'downloads.sqlite', 'signons.sqlite', 'key4.db', 'key3.db',
            'cert9.db', 'permissions.sqlite',
        )
        browser_dirs = (
            'google/chrome', 'mozilla/firefox', 'microsoft/edge',
            'appdata/local/google/chrome', 'appdata/roaming/mozilla/firefox',
            'appdata/local/microsoft/edge',
            'local settings/application data/google/chrome',
            'local settings/application data/mozilla/firefox',
        )

        candidates = []
        all_files = listing.get('files', [])
        for f in all_files:
            name = f.get('name', '').lower()
            full_path = f.get('full_path', '').lower()
            inode = f.get('inode')
            if inode is None:
                continue
            # Match by filename
            if name in browser_files or name.endswith(('.sqlite', '.db')):
                if any(d in full_path for d in browser_dirs):
                    candidates.append(f)
                    continue
            # Match by directory
            if any(d in full_path for d in browser_dirs):
                if name in browser_files:
                    candidates.append(f)

        if not candidates:
            return {
                'tool': 'extract_browser_artifacts',
                'image': image,
                'offset': offset,
                'status': 'success',
                'extracted_files': [],
                'message': 'No browser artifacts found inside disk image',
                'timestamp': datetime.now().isoformat(),
            }

        import tempfile
        output_dir = Path(tempfile.mkdtemp(prefix='geoff_browser_'))
        extracted = []
        for f in candidates[:50]:
            name = f.get('name', f'inode_{f["inode"]}')
            inode = f['inode']
            out_path = output_dir / name.replace('\\', '_').replace('/', '_').replace(' ', '_')
            result = self.extract_file(image, inode, str(out_path), offset)
            if result.get('status') == 'success':
                extracted.append({
                    'path': result['output_file'],
                    'original_path': f.get('full_path', name),
                    'inode': inode,
                    'size': result.get('bytes_extracted', 0),
                })

        return {
            'tool': 'extract_browser_artifacts',
            'image': image,
            'offset': offset,
            'status': 'success',
            'extracted_files': extracted,
            'candidates_found': len(candidates),
            'candidates_extracted': len(extracted),
            'output_dir': str(output_dir),
            'timestamp': datetime.now().isoformat(),
        }

    def extract_email_artifacts(self, image: str, offset: Optional[int] = None) -> Dict[str, Any]:
        """Find and extract email-related files from inside a disk image.

        Scans the fls listing for PST, OST, DBX, EML, MSG, and mbox files,
        then extracts them via icat to a temp directory for analysis by the
        email specialist.
        """
        # Get full file listing first
        listing = self.list_files(image, offset, recursive=True)
        if listing.get('status') not in ('success', 'success_with_partial'):
            return {'tool': 'extract_email_artifacts', 'status': 'error',
                    'error': f'fls failed: {listing.get("status")}',
                    'timestamp': datetime.now().isoformat()}

        email_extensions = {'.pst', '.ost', '.dbx', '.mbox', '.eml', '.msg', '.nk2'}
        email_dirs = ('outlook', 'thunderbird', 'windows mail', 'outlook express',
                      'windows live mail', 'identities', 'local settings/application data/microsoft/outlook',
                      'appdata/local/microsoft/outlook', 'appdata/roaming/microsoft/outlook')

        candidates = []
        all_files = listing.get('files', [])
        for f in all_files:
            name = f.get('name', '').lower()
            full_path = f.get('full_path', '').lower()
            inode = f.get('inode')
            if inode is None:
                continue
            # Match by extension
            if any(name.endswith(ext) for ext in email_extensions):
                candidates.append(f)
                continue
            # Match by directory path
            if any(d in full_path for d in email_dirs):
                if any(name.endswith(ext) for ext in ('.pst', '.ost', '.dbx', '.eml', '.msg', '.msf', '.nk2')):
                    candidates.append(f)

        if not candidates:
            return {
                'tool': 'extract_email_artifacts',
                'image': image,
                'offset': offset,
                'status': 'success',
                'extracted_files': [],
                'message': 'No email artifacts found inside disk image',
                'timestamp': datetime.now().isoformat(),
            }

        # Extract each candidate via icat
        import tempfile
        output_dir = Path(tempfile.mkdtemp(prefix='geoff_email_'))
        extracted = []
        for f in candidates[:50]:  # Limit to 50 files max
            name = f.get('name', f'inode_{f["inode"]}')
            inode = f['inode']
            out_path = output_dir / name.replace('\\', '_').replace('/', '_').replace(' ', '_')
            result = self.extract_file(image, inode, str(out_path), offset)
            if result.get('status') == 'success':
                extracted.append({
                    'path': result['output_file'],
                    'original_path': f.get('full_path', name),
                    'inode': inode,
                    'size': result.get('bytes_extracted', 0),
                })

        return {
            'tool': 'extract_email_artifacts',
            'image': image,
            'offset': offset,
            'status': 'success',
            'extracted_files': extracted,
            'candidates_found': len(candidates),
            'candidates_extracted': len(extracted),
            'output_dir': str(output_dir),
            'timestamp': datetime.now().isoformat(),
        }

    def list_files_mactime(self, image: str, offset: Optional[int] = None) -> Dict[str, Any]:
        """fls -m — List files in mactime body format with MACB timestamps."""
        args = ['-m', '/']  # mactime body format, root hostname prefix
        if offset is not None:
            args.extend(['-o', str(offset)])
        args.append(image)  # replaced by _run_with_segments
        raw = self._run_with_segments('fls', image, base_args=args)
        if raw['status'] == 'success_with_partial':
            raw = dict(raw)
            raw['status'] = 'success'
        elif raw['status'] != 'success':
            return raw

        # mactime body format: md5|path|inode|meta_type|file_type|mtime|atime|ctime|crtime
        # or: md5|name|inode|meta_type|mode|uid|gid|size|atime|mtime|ctime|crtime
        events = []
        for line in raw['stdout'].splitlines():
            parts = line.split('|')
            if len(parts) < 9:
                continue
            path = parts[1] if len(parts) > 1 else ''
            inode = parts[2] if len(parts) > 2 else ''
            # Timestamps are Unix epoch (seconds)
            timestamps = {}
            ts_names = ['mtime', 'atime', 'ctime', 'crtime']
            # In 13-field format: atime=8, mtime=9, ctime=10, crtime=11
            # In 9-field format: mtime=5, atime=6, ctime=7, crtime=8
            if len(parts) >= 12:
                ts_indices = {8: 'atime', 9: 'mtime', 10: 'ctime', 11: 'crtime'}
            else:
                ts_indices = {5: 'mtime', 6: 'atime', 7: 'ctime', 8: 'crtime'}

            for idx, name in ts_indices.items():
                if idx < len(parts):
                    try:
                        ts_val = int(parts[idx])
                        if ts_val > 0:
                            timestamps[name] = ts_val
                    except (ValueError, IndexError):
                        pass

            events.append({
                'path': path,
                'inode': inode,
                'timestamps': timestamps,
            })

        return {
            'tool': 'fls_mactime',
            'image': image,
            'offset': offset,
            'status': 'success',
            'total_events': len(events),
            'events': events[:5000],
            'raw_output': raw['stdout'][:50000],
            'timestamp': datetime.now().isoformat()
        }

    def list_inodes(self, image: str, offset: Optional[int] = None) -> Dict[str, Any]:
        """ils - List inode information with parsed entries"""
        args = []
        if offset is not None:
            args = ['-o', str(offset)]
        args.append(image)  # replaced by _run_with_segments
        raw = self._run_with_segments('ils', image, base_args=args)
        if raw['status'] == 'success_with_partial':
            raw = dict(raw)
            raw['status'] = 'success'
        elif raw['status'] != 'success':
            return raw

        inodes = []
        for line in raw['stdout'].splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith('class') or stripped.startswith('---'):
                continue
            parts = stripped.split('|')
            if len(parts) >= 6:
                try:
                    inodes.append({
                        'inode': parts[0].strip(),
                        'type': parts[1].strip(),
                        'mode': parts[2].strip(),
                        'uid': parts[3].strip(),
                        'gid': parts[4].strip(),
                        'size': parts[5].strip(),
                    })
                except (IndexError, ValueError):
                    pass

        return {
            'tool': 'ils',
            'image': image,
            'offset': offset,
            'status': 'success',
            'inode_count': len(inodes),
            'inodes': inodes[:500],
            'raw_output': raw['stdout'][:50000],
            'timestamp': datetime.now().isoformat()
        }

    def get_file_info(self, image: str, inode: int, offset: Optional[int] = None) -> Dict[str, Any]:
        """istat - Display inode details with parsed structure"""
        args = []
        if offset is not None:
            args = ['-o', str(offset)]
        args.extend([image, str(inode)])  # image replaced by _run_with_segments
        raw = self._run_with_segments('istat', image, base_args=args)
        if raw['status'] == 'success_with_partial':
            raw = dict(raw)
            raw['status'] = 'success'
        elif raw['status'] != 'success':
            return raw

        info = {
            'inode': inode,
            'type': '',
            'mode': '',
            'uid': 0,
            'gid': 0,
            'size': 0,
            'access_time': '',
            'modify_time': '',
            'change_time': '',
            'create_time': '',
            'block_count': 0,
            'blocks': [],
            'metadata': {}
        }

        for line in raw['stdout'].splitlines():
            stripped = line.strip()
            if 'Type:' in stripped:
                info['type'] = stripped.split(':', 1)[1].strip()
            elif 'Mode:' in stripped and '/' in stripped:
                info['mode'] = stripped.split(':', 1)[1].strip()
            elif 'UID:' in stripped:
                try:
                    info['uid'] = int(re.search(r'\d+', stripped).group())
                except (ValueError, AttributeError):
                    pass
            elif 'GID:' in stripped:
                try:
                    info['gid'] = int(re.search(r'\d+', stripped).group())
                except (ValueError, AttributeError):
                    pass
            elif 'Size:' in stripped:
                try:
                    info['size'] = int(re.search(r'\d+', stripped).group())
                except (ValueError, AttributeError):
                    pass
            elif 'Accessed:' in stripped or 'Access:' in stripped:
                info['access_time'] = stripped.split(':', 1)[1].strip()
            elif 'Modified:' in stripped or 'File Modified:' in stripped:
                info['modify_time'] = stripped.split(':', 1)[1].strip()
            elif 'Changed:' in stripped or 'Inode Modified:' in stripped:
                info['change_time'] = stripped.split(':', 1)[1].strip()
            elif 'Created:' in stripped or 'File Created:' in stripped:
                info['create_time'] = stripped.split(':', 1)[1].strip()
            elif 'Block Count:' in stripped:
                try:
                    info['block_count'] = int(re.search(r'\d+', stripped).group())
                except (ValueError, AttributeError):
                    pass
            # Direct blocks line
            elif stripped and re.match(r'^\d+\s', stripped) and '  ' in stripped:
                blocks = re.findall(r'\d+', stripped)
                info['blocks'].extend([int(b) for b in blocks])

        return {
            'tool': 'istat',
            'image': image,
            'inode': inode,
            'offset': offset,
            'status': 'success',
            'file_info': info,
            'raw_output': raw['stdout'],
            'timestamp': datetime.now().isoformat()
        }


class VOLATILITY_Specialist:
    """Specialist for memory forensics with Volatility3 and full output parsing"""

    def __init__(self, profile: str = "Win10x64"):
        self.profile = profile
        self.volatility_path = self._find_volatility()

    def _find_volatility(self) -> Optional[str]:
        for path in ['/usr/local/bin/volatility3', '/usr/bin/volatility3',
                     '/usr/local/bin/vol.py', '/usr/bin/vol.py',
                     '/usr/local/bin/vol', '/usr/bin/vol']:
            if Path(path).exists():
                return path
        # Try which (check vol first, then vol.py)
        for cmd in ['vol', 'vol.py', 'volatility3']:
            result = subprocess.run(['which', cmd], capture_output=True)
            if result.returncode == 0:
                return result.stdout.strip().decode() if isinstance(result.stdout, bytes) else result.stdout.strip()
        return None

    def run(self, plugin: str, memory_dump: str, **kwargs) -> Dict[str, Any]:
        if not self.volatility_path:
            return {'tool': 'volatility', 'plugin': plugin, 'status': 'error', 'error': 'Volatility not found', 'timestamp': datetime.now().isoformat()}

        cmd = [self.volatility_path, '-f', memory_dump, '-q', plugin]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            # Check if volatility returned any useful output
            stdout = result.stdout
            stderr = result.stderr

            # Detect failure conditions: no output, or error messages about profile/symbols
            no_output = not stdout.strip()
            profile_error = any(pat in stderr.lower() for pat in [
                'symbol', 'profile', 'not found', 'no suitable', 'error',
                'failed to find', 'unsupported', 'unknown', 'could not',
                'no mapping', 'no config', 'invalid',
            ])

            if result.returncode != 0 or no_output or profile_error:
                # Volatility failed — fall back to strings and bulk_extractor
                _fe_log(f"[VOLATILITY] {plugin} failed for {Path(memory_dump).name} — falling back to strings/bulk_extractor")
                fallback_result = self._fallback_analysis(memory_dump, plugin)
                fallback_result['volatility_error'] = stderr[:500] if stderr else 'No output from volatility'
                fallback_result['volatility_returncode'] = result.returncode
                return fallback_result

            return {
                'tool': 'volatility',
                'plugin': plugin,
                'status': 'success' if result.returncode == 0 else 'error',
                'returncode': result.returncode,
                'stdout': stdout,
                'stderr': stderr,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {'tool': 'volatility', 'plugin': plugin, 'status': 'error', 'error': str(e), 'timestamp': datetime.now().isoformat()}

    def _fallback_analysis(self, memory_dump: str, plugin: str) -> Dict[str, Any]:
        """Fallback when Volatility fails: use strings and bulk_extractor on raw memory."""
        results = {
            'tool': 'volatility_fallback',
            'plugin': plugin,
            'status': 'success',
            'memory_dump': memory_dump,
            'timestamp': datetime.now().isoformat(),
        }

        # Run strings to extract IPs, URLs, and process names
        try:
            strings_r = subprocess.run(
                ['strings', '-a', '-n', '8', memory_dump],
                capture_output=True, text=True, timeout=120,
            )
            if strings_r.returncode == 0:
                text = strings_r.stdout
                # Extract IP addresses
                ip_pattern = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b')
                ips = list(set(ip_pattern.findall(text)))[:100]
                # Extract URLs
                url_pattern = re.compile(r'https?://[^\s<>"\')\]]+', re.IGNORECASE)
                urls = list(set(url_pattern.findall(text)))[:100]
                # Extract process names (common patterns)
                proc_pattern = re.compile(r'([a-zA-Z0-9_]+\.(?:exe|dll|sys|com|bat|ps1))', re.IGNORECASE)
                procs = list(set(proc_pattern.findall(text)))[:200]
                results['strings_ips'] = ips
                results['strings_urls'] = urls
                results['strings_processes'] = procs
                results['strings_length'] = len(text)
        except Exception as e:
            results['strings_error'] = str(e)

        # Run bulk_extractor for more thorough carving
        try:
            be = shutil.which('bulk_extractor')
            if be:
                be_dir = tempfile.mkdtemp(prefix='geoff_be_')
                be_r = subprocess.run(
                    [be, '-o', be_dir, memory_dump],
                    capture_output=True, text=True, timeout=600,
                )
                if be_r.returncode == 0:
                    be_results = {}
                    for be_file in ['url.txt', 'email.txt', 'ip.txt', 'domain.txt', 'telephone.txt']:
                        be_path = os.path.join(be_dir, be_file)
                        if os.path.isfile(be_path):
                            with open(be_path) as f:
                                be_results[be_file.replace('.txt', '')] = [l.strip() for l in f.readlines() if l.strip()][:100]
                    results['bulk_extractor'] = be_results
                shutil.rmtree(be_dir, ignore_errors=True)
        except Exception as e:
            results['bulk_extractor_error'] = str(e)

        return results

    def _parse_table_output(self, stdout: str) -> List[Dict[str, str]]:
        """Parse Volatility's tabular output into structured records"""
        records = []
        lines = stdout.splitlines()
        if not lines:
            return records

        # Find header line
        header_line = None
        header_idx = 0
        for i, line in enumerate(lines):
            if '---' in line and i > 0:
                header_line = lines[i - 1].strip()
                header_idx = i + 1
                break
            elif line.strip() and not line.startswith(' ') and not line.startswith('Volatility'):
                # Might be the header itself
                parts = line.split()
                if len(parts) >= 3:
                    header_line = line.strip()
                    header_idx = i + 1
                    # Skip separator line if present
                    if header_idx < len(lines) and '---' in lines[header_idx]:
                        header_idx += 1
                    break

        if not header_line:
            return records

        headers = [h.strip() for h in header_line.split() if h.strip()]
        if not headers:
            return records

        # Calculate column positions from header
        col_positions = []
        for h in headers:
            idx = header_line.find(h)
            if idx >= 0:
                col_positions.append((h, idx))

        for line in lines[header_idx:]:
            stripped = line.strip()
            if not stripped or stripped.startswith('---') or 'Volatility' in stripped:
                continue
            record = {}
            for i, (col_name, col_start) in enumerate(col_positions):
                if i + 1 < len(col_positions):
                    end = col_positions[i + 1][1]
                    value = line[col_start:end].strip()
                else:
                    value = line[col_start:].strip()
                record[col_name] = value
            if record:
                records.append(record)

        return records

    def process_list(self, memory_dump: str) -> Dict[str, Any]:
        """List running processes with parsed table"""
        raw = self.run('windows.pslist.PsList', memory_dump)
        if raw['status'] != 'success':
            return raw

        processes = self._parse_table_output(raw['stdout'])

        return {
            'tool': 'volatility',
            'plugin': 'pslist',
            'status': 'success',
            'process_count': len(processes),
            'processes': processes,
            'raw_output': raw['stdout'],
            'timestamp': datetime.now().isoformat()
        }

    def network_scan(self, memory_dump: str) -> Dict[str, Any]:
        """Scan for network connections with parsed table"""
        raw = self.run('windows.netscan.NetScan', memory_dump)
        if raw['status'] != 'success':
            return raw

        connections = self._parse_table_output(raw['stdout'])

        # Extract unique IPs and ports
        unique_ips = set()
        unique_ports = set()
        for conn in connections:
            for key in ['Foreign Addr', 'Local Addr', 'Address']:
                addr = conn.get(key, '')
                if addr:
                    # Split off port
                    parts = addr.rsplit(':', 1)
                    if len(parts) == 2:
                        unique_ips.add(parts[0])
                        try:
                            unique_ports.add(int(parts[1]))
                        except ValueError:
                            pass
                    else:
                        unique_ips.add(addr)

        return {
            'tool': 'volatility',
            'plugin': 'netscan',
            'status': 'success',
            'connection_count': len(connections),
            'connections': connections,
            'unique_ips': list(unique_ips)[:100],
            'unique_ports': sorted(list(unique_ports))[:50],
            'raw_output': raw['stdout'],
            'timestamp': datetime.now().isoformat()
        }

    def find_malware(self, memory_dump: str) -> Dict[str, Any]:
        """Find injected code/malware with parsed results"""
        raw = self.run('windows.malfind.Malfind', memory_dump)
        if raw['status'] != 'success':
            return raw

        injections = self._parse_table_output(raw['stdout'])

        return {
            'tool': 'volatility',
            'plugin': 'malfind',
            'status': 'success',
            'injection_count': len(injections),
            'injections': injections,
            'malware_detected': len(injections) > 0,
            'raw_output': raw['stdout'],
            'timestamp': datetime.now().isoformat()
        }

    def scan_registry(self, memory_dump: str) -> Dict[str, Any]:
        """Scan registry hives with parsed results"""
        raw = self.run('windows.registry.hivelist.HiveList', memory_dump)
        if raw['status'] != 'success':
            return raw

        hives = self._parse_table_output(raw['stdout'])

        return {
            'tool': 'volatility',
            'plugin': 'hivelist',
            'status': 'success',
            'hive_count': len(hives),
            'hives': hives,
            'raw_output': raw['stdout'],
            'timestamp': datetime.now().isoformat()
        }

    def dump_process(self, memory_dump: str, pid: Optional[int] = None, target_pids: Optional[List[int]] = None, output_dir: str = '/tmp/geoff_memdumps') -> Dict[str, Any]:
        """Dump process memory for one or more PIDs.

        Pass a single *pid* (int) for backward compat, or *target_pids*
        (list of int) to dump multiple processes in one call.
        """
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        if not self.volatility_path:
            return {'tool': 'volatility', 'plugin': 'memmap', 'status': 'error', 'error': 'Volatility not found', 'timestamp': datetime.now().isoformat()}

        # Normalise pids list from either pid or target_pids (target_pids takes
        # precedence when both are supplied).
        pids: List[int] = []
        if target_pids:
            pids = target_pids if isinstance(target_pids, list) else [target_pids]
        elif pid is not None:
            pids = [pid]
        else:
            return {'tool': 'volatility', 'plugin': 'memmap', 'status': 'error', 'error': 'No pid or target_pids provided', 'timestamp': datetime.now().isoformat()}

        results: List[Dict[str, Any]] = []
        for _pid in pids:
            cmd = [self.volatility_path, '-f', memory_dump, '-q', 'windows.memmap.Memmap', '--pid', str(_pid), '--dump', '-D', output_dir]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
                results.append({
                    'pid': _pid,
                    'status': 'success' if result.returncode == 0 else 'error',
                    'returncode': result.returncode,
                    'raw_output': result.stdout,
                })
            except Exception as e:
                results.append({'pid': _pid, 'status': 'error', 'error': str(e)})

        success_count = sum(1 for r in results if r.get('status') == 'success')
        return {
            'tool': 'volatility',
            'plugin': 'memmap',
            'output_dir': output_dir,
            'pids_requested': pids,
            'pids_dumped': success_count,
            'status': 'success' if success_count > 0 else 'error',
            'results': results,
            'timestamp': datetime.now().isoformat()
        }



# Keywords that indicate forensic acquisition metadata bleed-through.
# When found inside a purported file path, the "path" is spurious.
_FORENSIC_METADATA_KEYWORDS = [
    'Image Verification',
    'Acquisition started',
    'Acquisition finished',
    '[Device Info]',
    'Source Type',
    'Drive Geometry',
    'Cylinders:',
    'Tracks per Cylinder',
    'Sectors per Track',
    'Physical Evidentiary',
    'MD5 checksum',
    'SHA1 checksum',
    'SHA256 checksum',
    'Image Information:',
]

def _is_valid_file_path(path: str) -> bool:
    """Reject paths that contain forensic acquisition metadata bleed-through."""
    if len(path) < 3:
        return False
    for kw in _FORENSIC_METADATA_KEYWORDS:
        if kw in path:
            return False
    return True


class STRINGS_Specialist:
    """Specialist for string extraction and IOC analysis with full parsing"""

    def __init__(self):
        result = subprocess.run(['which', 'strings'], capture_output=True)
        self.strings_available = result.returncode == 0

    def extract_strings(self, file_path: str, min_length: int = 4, encoding: str = 'ascii') -> Dict[str, Any]:
        """Extract strings from binary with IOC categorization"""
        if not self.strings_available:
            return {
                'tool': 'strings',
                'file': file_path,
                'status': 'error',
                'error': 'strings binary not found in PATH — install binutils',
                'timestamp': datetime.now().isoformat(),
            }
        cmd = ['strings', '-n', str(min_length)]
        if encoding == 'unicode':
            cmd.extend(['-e', 'l'])
        elif encoding == 'wide':
            cmd.extend(['-e', 'b'])
        cmd.append(file_path)

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            all_strings = result.stdout.strip().splitlines() if result.stdout else []

            # Categorized IOCs
            iocs = {
                'urls': [],
                'ips': [],
                'emails': [],
                'registry_keys': [],
                'file_paths': [],
                'domains': [],
                'suspicious_strings': []
            }

            # Regex patterns
            url_re = re.compile(r'https?://[^\s"\'\)\]]+')
            ip_re = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b')
            # Email: min 3-char local part, letter-digit domain labels, validated TLDs
            email_re = re.compile(
                r'\b[a-zA-Z0-9][a-zA-Z0-9._%+-]{2,}@'
                r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'
                r'(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*'
                r'\.(?:com|org|net|edu|gov|[a-zA-Z]{2,3})\b'
            )
            registry_re = re.compile(r'(HKLM|HKCU|HKEY_[A-Z_]+)\\[A-Za-z0-9_\\]+')
            win_path_re = re.compile(r'[A-Za-z]:\\[^\s"\'\)\]>]+')
            unix_path_re = re.compile(r'/(?:etc|tmp|var|usr|home|bin|opt|root)/[^\s"\'\)\]>]+')
            domain_re = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b')

            # Suspicious string patterns (word-boundary matched)
            suspicious_keywords = [
                'passwd', 'cmd.exe', 'powershell', 'wscript',
                'cscript', 'mimikatz', 'lsass', 'ntds.dit',
                'inject', 'shellcode', 'keylog', 'rootkit', 'backdoor',
                'beacon', 'exfil', 'encrypt', 'decrypt', 'ransom'
            ]

            seen = set()
            for s in all_strings:
                # URLs
                for url in url_re.findall(s):
                    if url not in seen:
                        iocs['urls'].append(url)
                        seen.add(url)

                # IPs (filter loopback, RFC1918, link-local, broadcast, version strings)
                for ip in ip_re.findall(s):
                    octets = ip.split('.')
                    second = int(octets[1]) if len(octets) > 1 and octets[1].isdigit() else 0
                    # Reject version strings like 7.0.2.7 where all 4 octets are single digits
                    # Exception for well-known public DNS servers
                    all_single = all(len(o) == 1 for o in octets)
                    if all_single and ip not in {'8.8.8.8', '1.1.1.1', '8.8.4.4', '1.0.0.1'}:
                        continue
                    is_private = (
                        ip.startswith(('0.', '127.', '169.254.', '255.'))
                        or ip.startswith('10.')
                        or ip.startswith('192.168.')
                        or (ip.startswith('172.') and 16 <= second <= 31)
                    )
                    if not is_private and ip not in seen:
                        iocs['ips'].append(ip)
                        seen.add(ip)

                # Emails
                for email in email_re.findall(s):
                    if email not in seen:
                        iocs['emails'].append(email)
                        seen.add(email)

                # Registry
                for reg in registry_re.findall(s):
                    if reg not in seen:
                        iocs['registry_keys'].append(reg)
                        seen.add(reg)

                # Windows paths
                for path in win_path_re.findall(s):
                    if path not in seen and _is_valid_file_path(path):
                        iocs['file_paths'].append(path)
                        seen.add(path)

                # Unix paths
                for path in unix_path_re.findall(s):
                    if path not in seen and _is_valid_file_path(path):
                        iocs['file_paths'].append(path)
                        seen.add(path)

                # Suspicious keywords (word-boundary matched, min length 6)
                if len(s) >= 6:
                    s_lower = s.lower()
                    for kw in suspicious_keywords:
                        if re.search(r'\b' + re.escape(kw) + r'\b', s_lower) and s not in seen:
                            iocs['suspicious_strings'].append(s)
                            seen.add(s)
                            break

            return {
                'tool': 'strings',
                'file': file_path,
                'status': 'success',
                'total_strings': len(all_strings),
                'strings_sample': all_strings[:200],
                'iocs': iocs,
                'ioc_counts': {k: len(v) for k, v in iocs.items()},
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {'tool': 'strings', 'file': file_path, 'status': 'error', 'error': str(e), 'timestamp': datetime.now().isoformat()}


class SpecialistOrchestrator:
    """Orchestrates multiple specialists for complex investigations"""

    def __init__(self, evidence_base: str):
        self.evidence_base = Path(evidence_base)
        self.sleuthkit = SLEUTHKIT_Specialist(evidence_base)
        self.volatility = VOLATILITY_Specialist()
        self.strings = STRINGS_Specialist()

    def run_playbook_step(self, playbook_id: str, step: Dict[str, Any]) -> Dict[str, Any]:
        module = step.get('module')
        function = step.get('function')
        params = step.get('params', {})

        specialist_map = {
            'sleuthkit': self.sleuthkit,
            'volatility': self.volatility,
            'strings': self.strings,
        }

        specialist = specialist_map.get(module)
        if specialist and hasattr(specialist, function):
            func = getattr(specialist, function)
            return func(**params)

        return {'status': 'error', 'error': f'Unknown module {module} or function {function}', 'timestamp': datetime.now().isoformat()}

    def get_available_tools(self) -> Dict[str, List[str]]:
        return {
            'sleuthkit': {
                'available': self.sleuthkit.tools_available,
                'functions': ['analyze_partition_table', 'analyze_filesystem',
                             'list_files', 'extract_file', 'list_inodes', 'get_file_info', 'list_deleted']
            },
            'volatility': {
                'available': self.volatility.volatility_path is not None,
                'functions': ['process_list', 'network_scan', 'find_malware',
                             'scan_registry', 'dump_process']
            },
            'strings': {
                'available': True,
                'functions': ['extract_strings']
            }
        }


if __name__ == '__main__':
    orch = SpecialistOrchestrator('/home/sansforensics/evidence-storage')
    tools = orch.get_available_tools()
    for tool, info in tools.items():
        print(f"\n{tool.upper()}:")
        print(f"  Available: {info['available']}")
        print(f"  Functions: {', '.join(info['functions'])}")