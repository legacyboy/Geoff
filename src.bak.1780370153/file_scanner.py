#!/usr/bin/env python3
"""
File Scanner — magic-byte signature matching for forensic file identification.

Provides:
  - FileScanner: orchestrator class (registered in ExtendedOrchestrator)
  - signature_mismatch_scan(): compare file magic vs extension, flag mismatches

Magic signatures are stored inline (no external dependencies beyond what
Python provides + python-magic if available).
"""

import os
import re
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple

# ---------------------------------------------------------------------------
# Magic byte signatures (header bytes) for common file types
# Format: extension -> [(offset, b"magic_bytes", description), ...]
# ---------------------------------------------------------------------------

_FILE_SIGNATURES: Dict[str, List[Tuple[int, bytes, str]]] = {
    ".exe":    [(0, b"MZ", "MS-DOS executable")],
    ".dll":    [(0, b"MZ", "Portable Executable DLL")],
    ".sys":    [(0, b"MZ", "Windows system driver")],
    ".scr":    [(0, b"MZ", "Windows screensaver")],
    ".com":    [(0, b"MZ", "MS-DOS COM")],
    # PE header at offset 0x3C points to "PE\\0\\0"
    # (checked separately via _check_pe_signature)

    ".pdf":    [(0, b"%PDF", "PDF document")],
    ".zip":    [(0, b"PK\x03\x04", "ZIP archive"),
                (0, b"PK\x05\x06", "ZIP archive (empty)"),
                (0, b"PK\x07\x08", "ZIP archive (spanned)")],
    ".jar":    [(0, b"PK\x03\x04", "JAR archive (ZIP)")],
    ".docx":   [(0, b"PK\x03\x04", "Office Open XML")],
    ".xlsx":   [(0, b"PK\x03\x04", "Office Open XML")],
    ".pptx":   [(0, b"PK\x03\x04", "Office Open XML")],
    ".odt":    [(0, b"PK\x03\x04", "OpenDocument")],
    ".ods":    [(0, b"PK\x03\x04", "OpenDocument")],
    ".odp":    [(0, b"PK\x03\x04", "OpenDocument")],

    ".doc":    [(0, b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", "OLE2 Compound Document (Legacy Word)")],
    ".xls":    [(0, b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", "OLE2 Compound Document (Legacy Excel)")],
    ".ppt":    [(0, b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", "OLE2 Compound Document (Legacy PowerPoint)")],
    ".msg":    [(0, b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", "Outlook MSG")],
    ".mdb":    [(0, b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", "Access MDB")],
    ".pst":    [(0, b"!BDN", "Outlook PST"),
                (0, b"\x21\x42\x44\x4E", "Outlook PST")],

    ".jpg":    [(0, b"\xFF\xD8\xFF", "JPEG image")],
    ".jpeg":   [(0, b"\xFF\xD8\xFF", "JPEG image")],
    ".png":    [(0, b"\x89PNG\r\n\x1a\n", "PNG image")],
    ".gif":    [(0, b"GIF8", "GIF image")],
    ".bmp":    [(0, b"BM", "BMP image")],
    ".tiff":   [(0, b"MM\x00\x2A", "TIFF (big-endian)"),
                (0, b"II\x2A\x00", "TIFF (little-endian)")],

    ".mp3":    [(0, b"ID3", "MP3 audio"),
                (0, b"\xFF\xFB", "MP3 audio"),
                (0, b"\xFF\xF3", "MP3 audio"),
                (0, b"\xFF\xE3", "MP3 audio")],
    ".mp4":    [(4, b"ftyp", "MP4 video"),
                (4, b"ftypmp4", "MP4 video"),
                (0, b"\x00\x00\x00\x1Cftyp", "MP4 video")],
    ".avi":    [(0, b"RIFF", "AVI video")],
    ".mov":    [(4, b"moov", "QuickTime MOV"),
                (4, b"mdat", "QuickTime MOV")],
    ".flv":    [(0, b"FLV\x01", "Flash video")],
    ".wmv":    [(0, b"\x30\x26\xB2\x75\x8E\x66\xCF\x11", "WMV/ASF")],

    ".html":   [(0, b"<html", "HTML"),
                (0, b"<!DOCTYPE html", "HTML"),
                (0, b"<HTML", "HTML"),
                (0, b"\xEF\xBB\xBF<html", "HTML (UTF-8 BOM)")],
    ".htm":    [(0, b"<html", "HTML"),
                (0, b"<HTML", "HTML")],
    ".xml":    [(0, b"<?xml", "XML"),
                (0, b"\xEF\xBB\xBF<?xml", "XML (UTF-8 BOM)")],

    ".ps1":    [(0, b"<#", "PowerShell comment start"),
                (0, b"#Requires", "PowerShell"),
                (0, b"function ", "PowerShell"),
                (0, b"param(", "PowerShell"),
                (0, b"$", "PowerShell variable start")],
    ".bat":    [(0, b"@echo", "Batch file"),
                (0, b"echo ", "Batch file"),
                (0, b"REM ", "Batch file")],
    ".sh":     [(0, b"#!/bin/", "Shell script"),
                (0, b"#!/usr/bin/", "Shell script"),
                (0, b"#!/bash", "Shell script")],

    ".elf":    [(0, b"\x7FELF", "ELF binary")],
    ".dmg":    [(0, b"koly", "Apple DMG")],
    ".iso":    [(0, b"\x01CD001", "ISO 9660"),
                (0, b"\x01CDROM", "ISO 9660")],
    ".vhd":    [(0, b"conectix", "Virtual PC VHD")],
    ".vmdk":   [(0, b"KDMV", "VMware VMDK"),
                (0, b"# Disk DescriptorFile", "VMware VMDK")],
    ".vdi":    [(0, b"\x7F\x10\xDA\xBE", "VirtualBox VDI")],
    ".qcow2":  [(0, b"QFI\xFB", "QEMU QCOW2")],

    ".evtx":   [(0, b"ElfFile\x00", "Windows EVTX log")],
    ".evt":    [(0, b"LfLe", "Windows EVT log (old)")],

    ".lnk":    [(0, b"\x4C\x00\x00\x00\x01\x14\x02\x00", "Windows LNK shortcut")],
    ".prefetch":   [(0, b"SCCA", "Windows Prefetch (Win10)"),
                    (0, b"MAM\x04", "Windows Prefetch (Win8)")],

    ".pf":     [(0, b"SCCA", "Windows Prefetch")],
    ".reg":    [(0, b"Windows Registry Editor Version", "Registry export"),
                (0, b"REGEDIT", "Registry export")],
    ".manifest":  [(0, b"<?xml", "XML manifest")],
}

# Additional magic checks for embedded signatures
_PE_CHECK_OFFSET_OFFSET = 0x3C  # Location of PE signature pointer in MZ header
_PE_SIGNATURE = b"PE\x00\x00"


def _get_file_magic(path: str, max_bytes: int = 512) -> str:
    """Read first *max_bytes* of a file and return a hex+text magic summary.

    Falls back to reading file bytes directly.  Returns empty string on error.
    """
    try:
        with open(path, "rb") as f:
            header = f.read(max_bytes)
    except (IOError, OSError):
        return ""

    if not header:
        return ""

    # Try python-magic first (if available)
    try:
        import magic
        return magic.from_file(str(path), mime=True)
    except (ImportError, Exception):
        pass

    # Fallback: check for known signatures
    result = _check_known_signatures(header)
    return result


def _check_known_signatures(header: bytes) -> str:
    """Match file header bytes against known signatures."""
    # MZ/PE detection
    if len(header) >= 2 and header[:2] == b"MZ":
        if len(header) > 64:
            pe_offset = header[0x3C]
            if len(header) > pe_offset + 4 and header[pe_offset:pe_offset+4] == b"PE\x00\x00":
                return "application/x-msdownload"  # PE executable
        return "application/x-dosexec"  # DOS executable

    # ZIP-based
    if len(header) >= 4 and header[:4] == b"PK\x03\x04":
        return "application/zip"

    # OLE2
    if len(header) >= 8 and header[:8] == b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1":
        return "application/x-ole-storage"

    # PDF
    if len(header) >= 4 and header[:4] == b"%PDF":
        return "application/pdf"

    # Images
    if len(header) >= 3 and header[:3] == b"\xFF\xD8\xFF":
        return "image/jpeg"
    if len(header) >= 8 and header[:8] == b"\x89PNG\r\n\x1a\n":
        return "image/png"
    if len(header) >= 4 and header[:4] == b"GIF8":
        return "image/gif"

    # ELF
    if len(header) >= 4 and header[:4] == b"\x7FELF":
        return "application/x-elf"

    # HTML/XML
    if any(header[:len(b)] == b for b in [b"<html", b"<HTML", b"<!DOCTYPE", b"<?xml"]):
        if header[:4] == b"<?xml":
            return "text/xml"
        return "text/html"

    # Windows SCCA Prefetch
    if len(header) >= 4 and header[:4] == b"SCCA":
        return "application/x-windows-prefetch"

    return "application/octet-stream"


def _expected_mime_for_extension(ext: str) -> Optional[str]:
    """Return expected MIME type for a given file extension."""
    ext_to_mime = {
        ".exe": "application/x-msdownload",
        ".dll": "application/x-msdownload",
        ".sys": "application/x-msdownload",
        ".scr": "application/x-msdownload",
        ".pdf": "application/pdf",
        ".zip": "application/zip",
        ".jar": "application/java-archive",
        ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        ".doc": "application/msword",
        ".xls": "application/vnd.ms-excel",
        ".ppt": "application/vnd.ms-powerpoint",
        ".msg": "application/vnd.ms-outlook",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".png": "image/png",
        ".gif": "image/gif",
        ".bmp": "image/bmp",
        ".tiff": "image/tiff",
        ".mp3": "audio/mpeg",
        ".mp4": "video/mp4",
        ".avi": "video/x-msvideo",
        ".html": "text/html",
        ".htm": "text/html",
        ".xml": "text/xml",
        ".elf": "application/x-elf",
        ".lnk": "application/x-windows-shortcut",
        ".prefetch": "application/x-windows-prefetch",
        ".pf": "application/x-windows-prefetch",
        ".evtx": "application/x-windows-evtx",
        ".reg": "text/plain",
        ".ps1": "text/plain",
        ".bat": "text/plain",
        ".sh": "text/x-shellscript",
    }
    return ext_to_mime.get(ext.lower())


def _classify_mismatch_severity(actual_magic: str, ext: str, filename: str) -> str:
    """Classify signature/extension mismatch severity.

    Returns one of: 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', or 'INFO'.
    """
    actual_lower = actual_magic.lower()
    ext_lower = ext.lower()

    # CRITICAL: EXE/DLL/SYS disguised as document/media (classic malware hiding)
    executable_exts = {".exe", ".dll", ".sys", ".scr", ".com"}
    document_exts = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx"}
    media_exts = {".jpg", ".jpeg", ".png", ".gif", ".mp3", ".mp4", ".avi"}

    if ext_lower in document_exts or ext_lower in media_exts:
        if actual_lower in ("application/x-msdownload", "application/x-dosexec",
                            "application/x-elf", "application/zip"):
            return "CRITICAL"

    if ext_lower in document_exts:
        if "image/" in actual_lower or "video/" in actual_lower:
            return "HIGH"

    if ext_lower in executable_exts:
        if "image/" in actual_lower or "video/" in actual_lower or "audio/" in actual_lower:
            return "CRITICAL"

    # HIGH: ZIP/OLE2 renamed to non-archive extension
    if ext_lower not in {".zip", ".jar", ".docx", ".xlsx", ".pptx", ".doc", ".xls", ".ppt", ".msg"}:
        if actual_lower in ("application/zip", "application/x-ole-storage"):
            return "HIGH"

    # MEDIUM: Common mismatch (e.g., JPG saved as .png, text as .doc)
    if ext_lower == ".png" and actual_lower == "image/jpeg":
        return "MEDIUM"
    if ext_lower == ".jpg" and actual_lower == "image/png":
        return "MEDIUM"
    if ext_lower in {".html", ".htm"} and actual_lower == "text/xml":
        return "MEDIUM"

    # LOW: Text/plain classification but extension is text-ish
    if ext_lower in {".txt", ".log", ".md", ".ini", ".cfg"}:
        if actual_lower != "application/octet-stream":
            return "LOW"

    return "INFO"


def _check_single_file(file_path: str, output_dir: str) -> Optional[Dict[str, Any]]:
    """Check a single file for signature/extension mismatch.

    Returns dict with mismatch info, or None if no mismatch detected.
    """
    path = Path(file_path)
    if not path.is_file() or path.stat().st_size == 0:
        return None

    ext = path.suffix.lower()
    # Only check files with known extension mappings
    if ext not in _FILE_SIGNATURES:
        return None

    magic_type = _get_file_magic(str(path))
    expected = _expected_mime_for_extension(ext)

    if expected is None:
        return None

    # Check if magic matches any expected signature for this extension
    signatures = _FILE_SIGNATURES.get(ext, [])
    matches_expected = False

    try:
        with open(str(path), "rb") as f:
            header = f.read(512)
    except (IOError, OSError):
        return None

    for offset, magic_bytes, _ in signatures:
        if len(header) > offset + len(magic_bytes):
            if header[offset:offset + len(magic_bytes)] == magic_bytes:
                matches_expected = True
                break

    # For exe/dll, also check PE signature at offset pointed to by 0x3C
    if not matches_expected and ext in (".exe", ".dll", ".sys", ".scr"):
        pe_check = _check_pe_signature(header)
        if pe_check:
            matches_expected = pe_check

    if matches_expected:
        return None

    # Mismatch detected
    severity = _classify_mismatch_severity(magic_type, ext, path.name)
    if severity == "INFO" and magic_type == "application/octet-stream":
        return None  # Truly unknown magic = can't classify

    return {
        "file": str(path),
        "filename": path.name,
        "extension": ext,
        "detected_magic": magic_type,
        "expected_type": expected,
        "severity": severity,
        "size": path.stat().st_size,
    }


def _check_pe_signature(header: bytes) -> bool:
    """Check if header has valid PE signature at the offset pointed to by MZ header."""
    if len(header) < 2 or header[:2] != b"MZ":
        return False
    if len(header) < 0x40:
        return False
    pe_offset = header[_PE_CHECK_OFFSET_OFFSET]
    pe_offset_int = pe_offset if isinstance(pe_offset, int) else pe_offset[0]
    if len(header) > pe_offset_int + 4:
        return header[pe_offset_int:pe_offset_int + 4] == _PE_SIGNATURE
    return False


class FileScanner:
    """Scanner that verifies file magic-byte signatures match their extensions."""

    def __init__(self, evidence_base: str):
        self.evidence_base = evidence_base
        # Paths to scan
        self.scan_paths: List[str] = []

    def signature_mismatch_scan(self, output_dir: str) -> Dict[str, Any]:
        """Scan extracted files for signature/extension mismatches.

        Walks *output_dir* recursively, reading file headers and comparing
        magic bytes against the expected file-extension signature table.

        Returns a dict with findings grouped by severity.
        """
        scan_root = Path(output_dir)
        if not scan_root.exists() or not scan_root.is_dir():
            return {
                "tool": "signature_mismatch_scan",
                "status": "error",
                "error": f"Output directory does not exist: {output_dir}",
                "timestamp": datetime.now().isoformat(),
            }

        # Collect candidate files (up to 10,000 to prevent runaway)
        candidates = []
        for f in scan_root.rglob("*"):
            if not f.is_file() or f.stat().st_size == 0:
                continue
            ext = f.suffix.lower()
            if ext in _FILE_SIGNATURES:
                candidates.append(str(f))
            if len(candidates) >= 10000:
                break

        if not candidates:
            return {
                "tool": "signature_mismatch_scan",
                "status": "success",
                "total_checked": 0,
                "mismatches": [],
                "message": "No files with known extensions found in output_dir",
                "timestamp": datetime.now().isoformat(),
            }

        mismatches: List[Dict[str, Any]] = []
        for fp in candidates:
            result = _check_single_file(fp, output_dir)
            if result is not None:
                mismatches.append(result)

        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for m in mismatches:
            sev = m.get("severity", "INFO")
            if sev in severity_counts:
                severity_counts[sev] += 1

        return {
            "tool": "signature_mismatch_scan",
            "status": "success",
            "total_checked": len(candidates),
            "total_mismatches": len(mismatches),
            "severity_counts": severity_counts,
            "critical_mismatches": [m for m in mismatches if m.get("severity") == "CRITICAL"],
            "high_mismatches": [m for m in mismatches if m.get("severity") == "HIGH"],
            "medium_mismatches": [m for m in mismatches if m.get("severity") == "MEDIUM"],
            "all_mismatches": mismatches,
            "timestamp": datetime.now().isoformat(),
        }

    def scan_single_file(self, file_path: str) -> Dict[str, Any]:
        """Check a single file for signature mismatch."""
        result = _check_single_file(file_path, str(Path(file_path).parent))
        if result is None:
            return {
                "tool": "signature_mismatch_scan",
                "file": file_path,
                "status": "success",
                "mismatch": False,
                "timestamp": datetime.now().isoformat(),
            }
        return {
            "tool": "signature_mismatch_scan",
            "file": file_path,
            "status": "success",
            "mismatch": True,
            "detail": result,
            "timestamp": datetime.now().isoformat(),
        }
