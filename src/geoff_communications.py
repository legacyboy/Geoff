#!/usr/bin/env python3
"""Geoff DFIR - PB-SIFT-060 Communications Analysis.

Reads from findings already produced by existing playbooks (especially
PB-SIFT-023 Email Forensics) and produces:
  - Structured message list
  - Person-to-person communication graph
  - Steganography suspects (high-entropy images/audio)
  - Encrypted / password-protected file flags
  - LLM-powered narrative summary
  - Key relationship map
"""

import json
import math
import os
import re
import struct
import zipfile
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

# ---------------------------------------------------------------------------
# Entropy helpers
# ---------------------------------------------------------------------------

def _byte_entropy(data: bytes) -> float:
    """Shannon entropy in bits-per-byte (0–8)."""
    if not data:
        return 0.0
    freq = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _file_entropy(path: Path, sample_bytes: int = 65536) -> float:
    """Read up to *sample_bytes* from a file and return its entropy."""
    try:
        with open(path, "rb") as fh:
            data = fh.read(sample_bytes)
        return _byte_entropy(data)
    except OSError:
        return 0.0


# ---------------------------------------------------------------------------
# File-type helpers
# ---------------------------------------------------------------------------

_IMAGE_EXTS = frozenset({".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".tif", ".webp"})
_AUDIO_EXTS = frozenset({".mp3", ".wav", ".flac", ".ogg", ".aac", ".wma", ".m4a"})
_ARCHIVE_EXTS = frozenset({".zip", ".7z", ".rar", ".tar", ".gz", ".bz2", ".xz", ".iso"})
_ENCRYPTED_CONTAINER_EXTS = frozenset({".tc", ".vc", ".luks", ".dmg", ".aes"})

# Magic bytes → label
_MAGIC_MAP = [
    (b"PK\x03\x04", "zip"),
    (b"7z\xbc\xaf\x27\x1c", "7zip"),
    (b"Rar!\x1a\x07", "rar"),
    (b"\x1f\x8b", "gzip"),
    (b"BZh", "bzip2"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"TRUECRYPT", "truecrypt"),
    (b"VERA", "veracrypt"),
]


def _read_magic(path: Path, n: int = 16) -> bytes:
    try:
        with open(path, "rb") as fh:
            return fh.read(n)
    except OSError:
        return b""


def _is_zip_encrypted(path: Path) -> bool:
    """Return True if any entry in a ZIP file has the encrypted flag set."""
    try:
        with zipfile.ZipFile(path, "r") as zf:
            return any(bool(info.flag_bits & 0x1) for info in zf.infolist())
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Message parsing
# ---------------------------------------------------------------------------

_FROM_RE = re.compile(r"(?:^|\n)\s*From\s*:\s*(.+?)(?=\n|$)", re.IGNORECASE)
_TO_RE   = re.compile(r"(?:^|\n)\s*To\s*:\s*(.+?)(?=\n|$)", re.IGNORECASE)
_SUBJ_RE = re.compile(r"(?:^|\n)\s*Subject\s*:\s*(.+?)(?=\n|$)", re.IGNORECASE)
_DATE_RE = re.compile(r"(?:^|\n)\s*Date\s*:\s*(.+?)(?=\n|$)", re.IGNORECASE)
_EMAIL_ADDR_RE = re.compile(r"[\w.+\-]+@[\w.\-]+\.\w+")


def _extract_addr(raw: str) -> str:
    """Extract the first bare e-mail address from a header value."""
    m = _EMAIL_ADDR_RE.search(raw)
    if m:
        return m.group(0).lower().strip()
    return raw.strip().lower()[:120]


def _parse_message_block(text: str) -> Optional[dict]:
    """Parse From/To/Subject/Date from a block of text."""
    fm = _FROM_RE.search(text)
    tm = _TO_RE.search(text)
    sm = _SUBJ_RE.search(text)
    dm = _DATE_RE.search(text)
    if not fm and not tm:
        return None
    return {
        "from": _extract_addr(fm.group(1)) if fm else "",
        "to": [_extract_addr(a) for a in (tm.group(1).split(",") if tm else [])],
        "subject": sm.group(1).strip()[:200] if sm else "",
        "date": dm.group(1).strip()[:50] if dm else "",
        "raw_snippet": text[:300],
    }


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class CommunicationsAnalyzer:
    """PB-SIFT-060 — Communications Analysis."""

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def extract_communications(self, findings: list) -> list:
        """Extract structured messages from email/chat findings."""
        messages = []
        seen: set = set()

        for rec in findings:
            module = str(rec.get("module", "")).lower()
            function = str(rec.get("function", "")).lower()
            output = str(rec.get("output", ""))
            playbook = str(rec.get("playbook", ""))

            _CHAT_FUNC_KWS = (
                "sms", "whatsapp", "telegram", "imessage", "signal",
                "teams", "slack", "discord",
            )
            _CHAT_OUTPUT_KWS = ("sender:", "message:", "timestamp:")

            is_email = (
                module == "email"
                or "email" in playbook.lower()
                or any(kw in function for kw in ("pst", "mbox", "eml", "msg", "dbx"))
                or any(kw in output[:200].lower() for kw in ("from:", "subject:", "received:"))
            )
            is_chat = (
                module in ("mobile", "collaboration")
                or any(kw in function for kw in _CHAT_FUNC_KWS)
                or any(kw in output[:200].lower() for kw in _CHAT_OUTPUT_KWS)
            )
            if not is_email and not is_chat:
                continue

            if is_chat and not is_email:
                # Parse chat messages into the same structured format
                blocks = re.split(r"\n(?=(?:sender|from|author)\s*[:\-])", output, flags=re.IGNORECASE)
                for block in blocks:
                    sm = re.search(r"(?:sender|from|author)\s*[:\-]\s*(.+?)(?=\n|$)", block, re.IGNORECASE)
                    rm = re.search(r"(?:recipient|to|receiver)\s*[:\-]\s*(.+?)(?=\n|$)", block, re.IGNORECASE)
                    mm = re.search(r"(?:message|body|content|text)\s*[:\-]\s*(.+?)(?=\n|$)", block, re.IGNORECASE)
                    tm = re.search(r"(?:timestamp|date|time|sent_at)\s*[:\-]\s*(.+?)(?=\n|$)", block, re.IGNORECASE)
                    if not sm and not rm:
                        continue
                    sender_raw = sm.group(1).strip()[:120] if sm else ""
                    recipients_raw = [r.strip()[:120] for r in (rm.group(1).split(",") if rm else [])]
                    msg = {
                        "from": sender_raw,
                        "to": recipients_raw,
                        "subject": mm.group(1).strip()[:200] if mm else "",
                        "date": tm.group(1).strip()[:50] if tm else "",
                        "raw_snippet": block[:300],
                        "platform": "chat",
                    }
                    key = f"{msg['from']}|{','.join(msg['to'])}|{msg['subject']}"
                    if key not in seen:
                        seen.add(key)
                        msg["source_playbook"] = playbook
                        msg["source_function"] = function
                        messages.append(msg)
                continue

            # Split output into potential email message blocks
            blocks = re.split(r"\n(?=From:)", output, flags=re.IGNORECASE)
            for block in blocks:
                msg = _parse_message_block(block)
                if msg:
                    key = f"{msg['from']}|{','.join(msg['to'])}|{msg['subject']}"
                    if key not in seen:
                        seen.add(key)
                        msg["source_playbook"] = playbook
                        msg["source_function"] = function
                        messages.append(msg)

        return messages

    def build_communication_graph(self, messages: list) -> dict:
        """Build person-to-person graph: {person: {sent_to, received_from, subjects, dates}}."""
        graph: dict = defaultdict(lambda: {
            "sent_to": Counter(),
            "received_from": Counter(),
            "subjects": [],
            "dates": [],
            "message_count": 0,
        })

        for msg in messages:
            sender = msg.get("from", "")
            recipients = msg.get("to", [])
            subject = msg.get("subject", "")
            date = msg.get("date", "")

            if not sender and not recipients:
                continue

            if sender:
                node = graph[sender]
                node["message_count"] += 1
                if subject:
                    node["subjects"].append(subject)
                if date:
                    node["dates"].append(date)
                for r in recipients:
                    if r and r != sender:
                        node["sent_to"][r] += 1
                        graph[r]["received_from"][sender] += 1

        # Convert Counters to dicts for JSON serialisation
        result = {}
        for person, data in graph.items():
            result[person] = {
                "sent_to": dict(data["sent_to"].most_common()),
                "received_from": dict(data["received_from"].most_common()),
                "subjects": data["subjects"][:20],
                "dates": data["dates"][:20],
                "message_count": data["message_count"],
                "total_contacts": len(data["sent_to"]),
            }
        return result

    def detect_steganography(self, evidence_dir: str) -> list:
        """Scan image/audio files for anomalously high entropy (stego suspect)."""
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

                entropy = _file_entropy(fp)
                # Normal JPEG/PNG are already compressed (~7.5–8.0 bits/byte).
                # We flag images that are near-maximum entropy AND suspiciously
                # large relative to their dimensions (can't check dims without PIL,
                # so use size as rough proxy).
                if ext in _IMAGE_EXTS and entropy >= 7.95:
                    suspects.append({
                        "path": str(fp),
                        "entropy": round(entropy, 4),
                        "size_bytes": size,
                        "reason": "Near-maximum entropy for image file — possible embedded payload",
                        "confidence": "MEDIUM",
                    })
                elif ext in _AUDIO_EXTS and entropy >= 7.90:
                    suspects.append({
                        "path": str(fp),
                        "entropy": round(entropy, 4),
                        "size_bytes": size,
                        "reason": "High entropy audio file — possible LSB steganography",
                        "confidence": "LOW",
                    })

        return suspects

    def detect_encrypted_files(self, evidence_dir: str) -> list:
        """Flag password-protected archives and encrypted containers."""
        flagged = []
        ev_path = Path(evidence_dir)
        if not ev_path.exists():
            return flagged

        for root, _, files in os.walk(ev_path):
            for fname in files:
                fp = Path(root) / fname
                ext = fp.suffix.lower()

                # Encrypted containers by extension
                if ext in _ENCRYPTED_CONTAINER_EXTS:
                    flagged.append({
                        "path": str(fp),
                        "type": "encrypted_container",
                        "extension": ext,
                        "reason": f"Encrypted container extension ({ext})",
                        "confidence": "HIGH",
                    })
                    continue

                # ZIP with encrypted entries
                if ext == ".zip":
                    magic = _read_magic(fp)
                    if magic[:4] == b"PK\x03\x04" and _is_zip_encrypted(fp):
                        flagged.append({
                            "path": str(fp),
                            "type": "password_protected_zip",
                            "extension": ext,
                            "reason": "ZIP archive with encrypted entries (password required)",
                            "confidence": "HIGH",
                        })
                    continue

                # Other archives: flag if magic is known + high entropy (can't open)
                magic = _read_magic(fp)
                for magic_bytes, label in _MAGIC_MAP:
                    if magic[:len(magic_bytes)] == magic_bytes and label in ("7zip", "rar"):
                        entropy = _file_entropy(fp, 4096)
                        if entropy >= 7.8:
                            flagged.append({
                                "path": str(fp),
                                "type": f"high_entropy_{label}",
                                "extension": ext,
                                "reason": f"{label.upper()} archive with high entropy (possibly encrypted)",
                                "confidence": "MEDIUM",
                            })
                        break

        return flagged

    def identify_relationships(self, messages: list) -> list:
        """Extract top relationships with frequency and subject clustering."""
        pair_data: dict = defaultdict(lambda: {"count": 0, "subjects": []})

        for msg in messages:
            sender = msg.get("from", "")
            for recipient in msg.get("to", []):
                if sender and recipient and sender != recipient:
                    pair = tuple(sorted([sender, recipient]))
                    pair_data[pair]["count"] += 1
                    subject = msg.get("subject", "")
                    if subject and subject not in pair_data[pair]["subjects"]:
                        pair_data[pair]["subjects"].append(subject)

        relationships = []
        for (a, b), data in sorted(pair_data.items(), key=lambda x: -x[1]["count"]):
            relationships.append({
                "person_a": a,
                "person_b": b,
                "message_count": data["count"],
                "subject_samples": data["subjects"][:5],
                "confidence": "HIGH" if data["count"] >= 5 else "MEDIUM" if data["count"] >= 2 else "LOW",
            })

        return relationships[:50]  # top 50 pairs

    def generate_narrative(
        self,
        messages: list,
        graph: dict,
        relationships: list,
        call_llm_func: Callable,
    ) -> str:
        """LLM-powered narrative summary of communications."""
        if not call_llm_func or not messages:
            return ""

        # Build a concise summary for the LLM prompt
        top_pairs = relationships[:10]
        people = list(graph.keys())[:20]

        prompt_parts = [
            f"You are a digital forensics analyst. Summarize the communications found in this case.",
            f"\nTotal messages analysed: {len(messages)}",
            f"People identified: {', '.join(people[:10])}",
        ]

        if top_pairs:
            prompt_parts.append("\nTop communication pairs:")
            for rel in top_pairs[:5]:
                prompt_parts.append(
                    f"  - {rel['person_a']} ↔ {rel['person_b']}: "
                    f"{rel['message_count']} messages, "
                    f"subjects: {'; '.join(rel['subject_samples'][:3])}"
                )

        sample_subjects = list({m.get("subject", "") for m in messages if m.get("subject")})[:15]
        if sample_subjects:
            prompt_parts.append(f"\nEmail subjects (sample): {'; '.join(sample_subjects)}")

        prompt = "\n".join(prompt_parts)
        prompt += (
            "\n\nWrite a concise forensic narrative (3–5 paragraphs) that: "
            "(1) identifies the key actors and their roles, "
            "(2) describes what the communications reveal about their activities, "
            "(3) highlights any suspicious patterns (covert channels, coded language, "
            "deletions, or timing anomalies), and "
            "(4) cites specific evidence (sender, subject, date) where possible."
        )

        try:
            result = call_llm_func(prompt, agent_type="manager")
            return result or ""
        except Exception:
            return ""

    def analyze(
        self,
        case_dir: str,
        evidence_dir: str,
        findings: list,
        call_llm_func: Optional[Callable] = None,
    ) -> dict:
        """Main entry point. Returns full PB-SIFT-060 result dict."""
        messages = self.extract_communications(findings)
        graph = self.build_communication_graph(messages)
        stego = self.detect_steganography(evidence_dir)
        encrypted = self.detect_encrypted_files(evidence_dir)
        relationships = self.identify_relationships(messages)
        narrative = ""
        if call_llm_func and (messages or stego or encrypted):
            narrative = self.generate_narrative(messages, graph, relationships, call_llm_func)

        result = {
            "playbook": "PB-SIFT-060",
            "playbook_name": "Communications Analysis",
            "message_count": len(messages),
            "person_count": len(graph),
            "messages": messages[:200],  # cap for large cases
            "communication_graph": graph,
            "steganography_suspects": stego,
            "encrypted_files": encrypted,
            "relationships": relationships,
            "narrative": narrative,
            "has_communications": len(messages) > 0,
            "has_stego_suspects": len(stego) > 0,
            "has_encrypted_files": len(encrypted) > 0,
        }

        # Persist to case_dir if provided
        if case_dir:
            out_path = Path(case_dir) / "output" / "PB-SIFT-060_communications.json"
            try:
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_text(json.dumps(result, default=str, indent=2))
            except OSError:
                pass

        return result
