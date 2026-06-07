#!/usr/bin/env python3
"""Geoff DFIR - PB-SIFT-061 Steganography Detection.

Scans image/audio files for steganography indicators using:
  - Entropy analysis (enhanced from CommunicationsAnalyzer)
  - LSB analysis on BMP/PNG files
  - Palette analysis on GIF files
  - File size anomaly detection
  - Known stego tool binary/registry/prefetch artifacts
  - YARA-based stego tool detection
"""

import json
import math
import os
import re
import shutil
import struct
import subprocess
import tempfile
from collections import Counter
from pathlib import Path
from typing import Callable, Optional

# ---------------------------------------------------------------------------
# Entropy helpers
# ---------------------------------------------------------------------------

def _byte_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _file_entropy(path: Path, sample_bytes: int = 65536) -> float:
    try:
        with open(path, "rb") as fh:
            data = fh.read(sample_bytes)
        return _byte_entropy(data)
    except OSError:
        return 0.0


# ---------------------------------------------------------------------------
# File-type constants
# ---------------------------------------------------------------------------

_IMAGE_EXTS = frozenset({".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".tif", ".webp"})
_AUDIO_EXTS = frozenset({".mp3", ".wav", ".flac", ".ogg", ".aac", ".wma", ".m4a"})

# Known stego tool binaries (lowercase)
_STEGO_TOOL_BINS = frozenset({
    "steghide", "outguess", "jphide", "jpseek", "silenteye", "openstego",
    "stegosuite", "stegdetect", "stegbreak", "stegcracker", "stegsnow",
    "f5", "jsteg", "cloak", "camouflage", "invisible_secrets",
    "hide4pgp", "hydan", "mp3stego", "deepsound", "xiao_steganography",
    "our_secret", "steganography_studio",
})

# Registry key fragments associated with stego tools
_STEGO_REGISTRY_PATTERNS = [
    r"steghide", r"openstego", r"silenteye", r"stegosuite",
    r"invisible.secrets", r"our.secret", r"deepsound",
]

# Prefetch name fragments (Windows prefetch files are APPNAME-HASH.pf)
_STEGO_PREFETCH_PATTERNS = [
    "STEGHIDE", "OPENSTEGO", "SILENTEYE", "STEGOSUITE", "OUTGUESS",
    "JPHIDE", "JPSEEK", "STEGSNOW", "STEGDETECT", "DEEPSOUND",
]

# ---------------------------------------------------------------------------
# YARA rules for stego tool artifacts
# ---------------------------------------------------------------------------

_STEGO_YARA_RULES = r"""
rule StegTool_Steghide {
    meta:
        description = "Steghide steganography tool strings"
    strings:
        $a = "steghide" nocase
        $b = "steghide embed" nocase
        $c = "steghide extract" nocase
    condition:
        any of them
}

rule StegTool_OpenStego {
    meta:
        description = "OpenStego tool strings"
    strings:
        $a = "OpenStego" nocase
        $b = "openstego" nocase
        $c = "com.openstego" nocase
    condition:
        any of them
}

rule StegTool_OutGuess {
    meta:
        description = "OutGuess steganography tool"
    strings:
        $a = "outguess" nocase
        $b = "OutGuess" fullword
    condition:
        any of them
}

rule StegTool_SilentEye {
    meta:
        description = "SilentEye steganography tool"
    strings:
        $a = "SilentEye" fullword
        $b = "silenteye" nocase
    condition:
        any of them
}

rule StegTool_JPHide {
    meta:
        description = "JPHide/JPSeek tool strings"
    strings:
        $a = "jphide" nocase
        $b = "jpseek" nocase
    condition:
        any of them
}

rule StegTool_DeepSound {
    meta:
        description = "DeepSound audio steganography"
    strings:
        $a = "DeepSound" nocase
        $b = "deepsound" nocase
    condition:
        any of them
}

rule StegTool_MP3Stego {
    meta:
        description = "MP3Stego audio steganography"
    strings:
        $a = "MP3Stego" fullword
        $b = "mp3stego" nocase
    condition:
        any of them
}
"""

# ---------------------------------------------------------------------------
# LSB analysis helpers
# ---------------------------------------------------------------------------

def _analyze_png_lsb(path: Path) -> Optional[dict]:
    """Check PNG IDAT chunks for LSB anomalies via entropy of low-bits plane."""
    try:
        with open(path, "rb") as fh:
            data = fh.read()
        if data[:8] != b"\x89PNG\r\n\x1a\n":
            return None
        # Extract raw IDAT payload (concatenated)
        idat_raw = b""
        pos = 8
        while pos + 12 <= len(data):
            length = struct.unpack(">I", data[pos:pos+4])[0]
            chunk_type = data[pos+4:pos+8]
            if chunk_type == b"IDAT":
                idat_raw += data[pos+8:pos+8+length]
            pos += 12 + length
        if len(idat_raw) < 256:
            return None
        # Take LSBs of first 4KB of compressed IDAT — high entropy suggests LSB stego
        lsb_bytes = bytes(b & 1 for b in idat_raw[:4096])
        lsb_entropy = _byte_entropy(lsb_bytes)
        # Pure random LSBs → entropy near 1.0; natural images → lower
        if lsb_entropy >= 0.98:
            return {
                "method": "png_lsb",
                "lsb_entropy": round(lsb_entropy, 4),
                "reason": "PNG IDAT LSB plane shows near-maximum entropy — possible LSB steganography",
                "confidence": "MEDIUM",
            }
    except Exception:
        pass
    return None


def _analyze_bmp_lsb(path: Path) -> Optional[dict]:
    """Check BMP file for LSB anomalies in pixel data."""
    try:
        with open(path, "rb") as fh:
            header = fh.read(54)
        if len(header) < 54 or header[:2] != b"BM":
            return None
        pixel_offset = struct.unpack("<I", header[10:14])[0]
        width = struct.unpack("<I", header[18:22])[0]
        height = abs(struct.unpack("<i", header[22:26])[0])
        bpp = struct.unpack("<H", header[28:30])[0]
        if bpp < 24:
            return None  # palette-indexed, different analysis
        with open(path, "rb") as fh:
            fh.seek(pixel_offset)
            pixel_data = fh.read(min(width * height * (bpp // 8), 65536))
        if len(pixel_data) < 256:
            return None
        lsb_bytes = bytes(b & 1 for b in pixel_data)
        lsb_entropy = _byte_entropy(lsb_bytes)
        if lsb_entropy >= 0.98:
            return {
                "method": "bmp_lsb",
                "lsb_entropy": round(lsb_entropy, 4),
                "reason": "BMP pixel LSB plane shows near-maximum entropy — possible LSB steganography",
                "confidence": "MEDIUM",
            }
    except Exception:
        pass
    return None


def _analyze_gif_palette(path: Path) -> Optional[dict]:
    """Check GIF palette for anomalies that indicate data hiding."""
    try:
        with open(path, "rb") as fh:
            header = fh.read(13)
        if len(header) < 13 or header[:6] not in (b"GIF87a", b"GIF89a"):
            return None
        packed = header[10]
        has_gct = bool(packed & 0x80)
        if not has_gct:
            return None
        gct_size = 3 * (2 ** ((packed & 0x07) + 1))
        with open(path, "rb") as fh:
            fh.seek(13)
            palette = fh.read(gct_size)
        # Check for non-monotonic or random palette ordering (stego hides in palette order)
        palette_triples = [palette[i:i+3] for i in range(0, len(palette), 3)]
        sorted_triples = sorted(palette_triples)
        if palette_triples != sorted_triples and len(set(palette_triples)) == len(palette_triples):
            return {
                "method": "gif_palette",
                "palette_size": len(palette_triples),
                "reason": "GIF palette appears randomized — palette-based steganography indicator",
                "confidence": "LOW",
            }
    except Exception:
        pass
    return None


def _check_size_anomaly(path: Path, ext: str) -> Optional[dict]:
    """Flag images with file sizes suspiciously large for their type."""
    try:
        size = path.stat().st_size
    except OSError:
        return None
    # Typical uncompressed 1080p image ~6MB; flag anything over 20MB for image types
    thresholds = {
        ".gif": 5 * 1024 * 1024,
        ".png": 30 * 1024 * 1024,
        ".bmp": 50 * 1024 * 1024,
        ".jpg": 15 * 1024 * 1024,
        ".jpeg": 15 * 1024 * 1024,
        ".wav": 100 * 1024 * 1024,
    }
    threshold = thresholds.get(ext)
    if threshold and size > threshold:
        return {
            "method": "size_anomaly",
            "size_bytes": size,
            "threshold_bytes": threshold,
            "reason": f"Unusually large {ext.upper()} file ({size // (1024*1024)}MB) — may contain embedded payload",
            "confidence": "LOW",
        }
    return None


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class StegoAnalyzer:
    """PB-SIFT-061 — Steganography Detection."""

    def __init__(self):
        self._yara_available = shutil.which("yara") is not None
        self._rules_file: Optional[str] = self._write_yara_rules()

    def _write_yara_rules(self) -> Optional[str]:
        try:
            rules_dir = Path("/tmp/geoff_stego_rules")
            rules_dir.mkdir(exist_ok=True)
            rules_path = rules_dir / "stego.yar"
            rules_path.write_text(_STEGO_YARA_RULES)
            return str(rules_path)
        except Exception:
            return None

    def _run_yara(self, target: str) -> list:
        if not self._yara_available or not self._rules_file:
            return []
        try:
            result = subprocess.run(
                ["yara", "-f", self._rules_file, target],
                capture_output=True, text=True, timeout=120,
            )
            matches = []
            for line in result.stdout.splitlines():
                parts = line.strip().split(" ", 1)
                if len(parts) == 2:
                    matches.append({"rule": parts[0], "file": parts[1]})
            return matches
        except Exception:
            return []

    # ------------------------------------------------------------------
    # File scanning
    # ------------------------------------------------------------------

    def scan_files(self, evidence_dir: str) -> list:
        """Scan image/audio files for steganography indicators."""
        suspects = []
        ev_path = Path(evidence_dir)
        if not ev_path.exists():
            return suspects

        for root, _, files in os.walk(ev_path):
            for fname in files:
                fp = Path(root) / fname
                ext = fp.suffix.lower()
                if ext not in (_IMAGE_EXTS | _AUDIO_EXTS):
                    continue
                try:
                    size = fp.stat().st_size
                except OSError:
                    continue
                if size < 1024:
                    continue

                indicators = []

                # Entropy analysis
                entropy = _file_entropy(fp)
                if ext in _IMAGE_EXTS and entropy >= 7.95:
                    indicators.append({
                        "method": "entropy",
                        "entropy": round(entropy, 4),
                        "reason": "Near-maximum entropy for image file",
                        "confidence": "MEDIUM",
                    })
                elif ext in _AUDIO_EXTS and entropy >= 7.90:
                    indicators.append({
                        "method": "entropy",
                        "entropy": round(entropy, 4),
                        "reason": "High entropy audio file",
                        "confidence": "LOW",
                    })

                # LSB analysis
                if ext == ".png":
                    lsb = _analyze_png_lsb(fp)
                    if lsb:
                        indicators.append(lsb)
                elif ext == ".bmp":
                    lsb = _analyze_bmp_lsb(fp)
                    if lsb:
                        indicators.append(lsb)
                elif ext == ".gif":
                    pal = _analyze_gif_palette(fp)
                    if pal:
                        indicators.append(pal)

                # Size anomaly
                size_flag = _check_size_anomaly(fp, ext)
                if size_flag:
                    indicators.append(size_flag)

                if indicators:
                    confidence_order = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
                    best_confidence = max(
                        indicators, key=lambda x: confidence_order.get(x.get("confidence", "LOW"), 0)
                    )["confidence"]
                    suspects.append({
                        "path": str(fp),
                        "size_bytes": size,
                        "ext": ext,
                        "indicators": indicators,
                        "confidence": best_confidence,
                    })

        return suspects

    # ------------------------------------------------------------------
    # Artifact scanning (tool binaries/registry/prefetch in findings)
    # ------------------------------------------------------------------

    def scan_tool_artifacts(self, findings: list) -> list:
        """Detect stego tool artifacts in existing findings."""
        artifacts = []
        seen: set = set()

        for rec in findings:
            function = str(rec.get("function", "")).lower()
            output = str(rec.get("output", ""))
            output_lower = output.lower()

            # Binary/file listing hits
            if any(kw in function for kw in ("list_files", "list_deleted", "filesystem", "process_list")):
                for tool in _STEGO_TOOL_BINS:
                    if tool in output_lower:
                        key = f"binary:{tool}"
                        if key not in seen:
                            seen.add(key)
                            artifacts.append({
                                "artifact_type": "binary",
                                "tool_name": tool,
                                "source_function": function,
                                "context": _excerpt(output, tool, 100),
                                "confidence": "HIGH",
                            })

            # Registry hits
            if "registry" in function or "hive" in function:
                for pattern in _STEGO_REGISTRY_PATTERNS:
                    if re.search(pattern, output_lower):
                        key = f"registry:{pattern}"
                        if key not in seen:
                            seen.add(key)
                            artifacts.append({
                                "artifact_type": "registry",
                                "pattern": pattern,
                                "source_function": function,
                                "context": _excerpt(output, pattern, 100),
                                "confidence": "MEDIUM",
                            })

            # Prefetch hits
            if "prefetch" in function or "prefetch" in output_lower:
                for pf in _STEGO_PREFETCH_PATTERNS:
                    if pf in output.upper():
                        key = f"prefetch:{pf}"
                        if key not in seen:
                            seen.add(key)
                            artifacts.append({
                                "artifact_type": "prefetch",
                                "tool_name": pf,
                                "source_function": function,
                                "context": _excerpt(output, pf, 100),
                                "confidence": "HIGH",
                            })

        return artifacts

    def scan_yara_directory(self, evidence_dir: str) -> list:
        """Run YARA stego rules against evidence directory."""
        if not self._yara_available or not self._rules_file:
            return []
        ev_path = Path(evidence_dir)
        if not ev_path.exists():
            return []
        return self._run_yara(str(ev_path))

    # ------------------------------------------------------------------
    # Confidence scoring
    # ------------------------------------------------------------------

    def _score_suspect(self, suspect: dict) -> dict:
        """Enrich a suspect with an overall confidence score."""
        indicators = suspect.get("indicators", [])
        order = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
        scores = [order.get(i.get("confidence", "LOW"), 1) for i in indicators]
        combined = min(3, sum(scores))  # cap at HIGH
        suspect["overall_score"] = combined
        suspect["confidence"] = {3: "HIGH", 2: "MEDIUM"}.get(combined, "LOW")
        return suspect

    # ------------------------------------------------------------------
    # Report generation
    # ------------------------------------------------------------------

    def generate_report(self, suspects: list, artifacts: list, yara_hits: list) -> dict:
        scored = [self._score_suspect(s) for s in suspects]
        scored.sort(key=lambda x: -x.get("overall_score", 0))
        return {
            "playbook": "PB-SIFT-061",
            "playbook_name": "Steganography Detection",
            "suspect_count": len(scored),
            "artifact_count": len(artifacts),
            "yara_hit_count": len(yara_hits),
            "high_confidence_suspects": [s for s in scored if s.get("confidence") == "HIGH"],
            "all_suspects": scored[:100],
            "tool_artifacts": artifacts,
            "yara_hits": yara_hits,
        }

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def analyze(
        self,
        case_dir: str,
        evidence_dir: str,
        findings: list,
        call_llm_func: Optional[Callable] = None,
    ) -> dict:
        suspects = self.scan_files(evidence_dir)
        artifacts = self.scan_tool_artifacts(findings)
        yara_hits = self.scan_yara_directory(evidence_dir)

        report = self.generate_report(suspects, artifacts, yara_hits)

        narrative = ""
        if call_llm_func and (suspects or artifacts or yara_hits):
            narrative = self._generate_narrative(report, call_llm_func)
        report["narrative"] = narrative

        if case_dir:
            out_path = Path(case_dir) / "output" / "PB-SIFT-061_stego.json"
            try:
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_text(json.dumps(report, default=str, indent=2))
            except OSError:
                pass

        return report

    def _generate_narrative(self, report: dict, call_llm_func: Callable) -> str:
        suspects = report.get("high_confidence_suspects", report.get("all_suspects", []))[:5]
        artifacts = report.get("tool_artifacts", [])[:5]
        parts = [
            "You are a digital forensics analyst. Summarize the steganography findings.",
            f"Total suspects: {report['suspect_count']}, tool artifacts: {report['artifact_count']}, YARA hits: {report['yara_hit_count']}",
        ]
        if suspects:
            parts.append("Top suspects:")
            for s in suspects:
                inds = "; ".join(i.get("reason", "") for i in s.get("indicators", []))
                parts.append(f"  - {s['path']}: {inds}")
        if artifacts:
            parts.append("Tool artifacts found:")
            for a in artifacts:
                parts.append(f"  - {a['artifact_type']}: {a.get('tool_name', a.get('pattern', ''))} ({a['confidence']})")
        parts.append(
            "\nWrite a concise forensic narrative (2-3 paragraphs) covering: "
            "(1) whether steganography was likely used, "
            "(2) specific files or artifacts of concern, "
            "(3) recommended next steps for extraction."
        )
        try:
            return call_llm_func("\n".join(parts), agent_type="manager") or ""
        except Exception:
            return ""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _excerpt(text: str, keyword: str, context_chars: int = 100) -> str:
    idx = text.lower().find(keyword.lower())
    if idx < 0:
        return text[:context_chars]
    start = max(0, idx - context_chars // 2)
    end = min(len(text), idx + len(keyword) + context_chars // 2)
    return text[start:end]
