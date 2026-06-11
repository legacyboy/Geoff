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

import email as _email_lib
from email import policy as _email_policy
import json
import math
import os
import re
import shutil
import struct
import subprocess
import tempfile
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
# PCAP helpers
# ---------------------------------------------------------------------------

_PCAP_MAGIC = frozenset({
    b'\xd4\xc3\xb2\xa1',  # libpcap LE
    b'\xa1\xb2\xc3\xd4',  # libpcap BE
    b'\x0a\x0d\x0d\x0a',  # pcapng
    b'\x4d\x3c\xb2\xa1',  # libpcap LE nanosecond
    b'\xa1\xb2\x3c\x4d',  # libpcap BE nanosecond
})


def _is_pcap_file(path: Path) -> bool:
    return _read_magic(path, 4) in _PCAP_MAGIC


def _parse_smtp_stream(stream_text: str) -> Optional[dict]:
    """Parse email metadata from a tshark ASCII follow of an SMTP TCP stream."""
    mail_from = ''
    rcpt_to: list = []
    subject = ''
    date = ''
    body_lines: list = []
    in_data = False
    in_headers = False

    for line in stream_text.splitlines():
        stripped = line.strip()
        upper = stripped.upper()

        if not in_data:
            mf = re.match(r'MAIL FROM:\s*<([^>]+)>', stripped, re.IGNORECASE)
            if mf:
                mail_from = mf.group(1).lower()
                continue
            rt = re.match(r'RCPT TO:\s*<([^>]+)>', stripped, re.IGNORECASE)
            if rt:
                rcpt_to.append(rt.group(1).lower())
                continue
            if upper.startswith('DATA'):
                in_data = True
                in_headers = True
                continue
        else:
            if stripped == '.':
                break
            if in_headers:
                if not stripped:
                    in_headers = False
                    continue
                sm = re.match(r'Subject:\s*(.*)', stripped, re.IGNORECASE)
                if sm:
                    subject = sm.group(1).strip()
                dm = re.match(r'Date:\s*(.*)', stripped, re.IGNORECASE)
                if dm:
                    date = dm.group(1).strip()
                if not mail_from:
                    fm = re.match(r'From:\s*(.*)', stripped, re.IGNORECASE)
                    if fm:
                        mail_from = _extract_addr(fm.group(1))
                if not rcpt_to:
                    tm = re.match(r'To:\s*(.*)', stripped, re.IGNORECASE)
                    if tm:
                        rcpt_to = [_extract_addr(a.strip()) for a in tm.group(1).split(',') if a.strip()]
            else:
                body_lines.append(stripped)

    if not mail_from and not rcpt_to:
        return None
    body = '\n'.join(body_lines)
    return {
        'from': mail_from,
        'to': rcpt_to,
        'subject': subject[:200],
        'date': date[:50],
        'body': body,
        'raw_snippet': f"From: {mail_from}\nTo: {', '.join(rcpt_to)}\nSubject: {subject}\n\n{body}",
    }


def _extract_pcap_smtp(pcap_path: Path) -> list:
    """Extract SMTP email messages from a PCAP via tshark (IMF export + stream fallback)."""
    messages: list = []
    tmpdir = None

    # Primary: tshark --export-objects imf exports RFC-822 email files directly
    try:
        tmpdir = tempfile.mkdtemp(prefix='geoff_imf_')
        subprocess.run(
            ['tshark', '-r', str(pcap_path), '--export-objects', f'imf,{tmpdir}'],
            capture_output=True, timeout=60,
        )
        for eml_path in sorted(Path(tmpdir).iterdir()):
            try:
                raw = eml_path.read_bytes()
                if not raw:
                    continue
                msg = _email_lib.message_from_bytes(raw, policy=_email_policy.compat32)
                from_hdr = str(msg.get('From', ''))
                to_hdr = str(msg.get('To', ''))
                subject = str(msg.get('Subject', ''))
                date = str(msg.get('Date', ''))
                msg_id = str(msg.get('Message-ID', ''))

                body = ''
                if msg.is_multipart():
                    for part in msg.walk():
                        if part.get_content_type() == 'text/plain':
                            payload = part.get_payload(decode=True)
                            body = (payload or b'').decode('utf-8', errors='replace')[:800]
                            break
                else:
                    payload = msg.get_payload(decode=True)
                    if payload:
                        body = payload.decode('utf-8', errors='replace')[:800]

                from_clean = _extract_addr(from_hdr)
                to_list = [_extract_addr(a.strip()) for a in to_hdr.split(',') if a.strip()]
                if not from_clean and not to_list:
                    continue

                messages.append({
                    'from': from_clean,
                    'to': to_list,
                    'subject': subject[:200],
                    'date': date[:50],
                    'body': body,
                    'message_id': msg_id[:100],
                    'raw_snippet': f"From: {from_hdr}\nTo: {to_hdr}\nSubject: {subject}\n\n{body}",
                    'source_playbook': 'PCAP_SMTP',
                    'source_function': f'pcap:{pcap_path.name}',
                    'protocol': 'smtp',
                })
            except Exception:
                continue
    except FileNotFoundError:
        pass
    except Exception:
        pass
    finally:
        if tmpdir:
            shutil.rmtree(tmpdir, ignore_errors=True)

    # Fallback: follow each SMTP TCP stream and parse the conversation manually
    if not messages:
        try:
            res = subprocess.run(
                ['tshark', '-r', str(pcap_path), '-Y', 'smtp', '-T', 'fields', '-e', 'tcp.stream'],
                capture_output=True, text=True, timeout=30,
            )
            stream_ids = sorted({ln.strip() for ln in res.stdout.splitlines() if ln.strip().isdigit()})
            for sid in stream_ids:
                try:
                    fr = subprocess.run(
                        ['tshark', '-r', str(pcap_path), '-qz', f'follow,tcp,ascii,{sid}'],
                        capture_output=True, text=True, timeout=30,
                    )
                    parsed = _parse_smtp_stream(fr.stdout)
                    if parsed:
                        parsed.update({
                            'source_playbook': 'PCAP_SMTP',
                            'source_function': f'pcap:{pcap_path.name}',
                            'protocol': 'smtp',
                        })
                        messages.append(parsed)
                except Exception:
                    continue
        except (FileNotFoundError, Exception):
            pass

    return messages


def _extract_pcap_imap(pcap_path: Path) -> list:
    """Extract IMAP session info: credentials, mailbox access, and envelope data."""
    results: list = []
    try:
        stream_res = subprocess.run(
            ['tshark', '-r', str(pcap_path), '-Y', 'imap', '-T', 'fields', '-e', 'tcp.stream'],
            capture_output=True, text=True, timeout=30,
        )
        stream_ids = sorted({ln.strip() for ln in stream_res.stdout.splitlines() if ln.strip().isdigit()})

        for sid in stream_ids:
            try:
                fr = subprocess.run(
                    ['tshark', '-r', str(pcap_path), '-qz', f'follow,tcp,ascii,{sid}'],
                    capture_output=True, text=True, timeout=30,
                )
                content = fr.stdout
                # Extract credentials from AUTH=LOGIN (base64-encoded)
                username = ''
                password = ''
                mailbox = ''
                msg_count = ''
                lines = content.splitlines()
                waiting_user = False
                waiting_pass = False
                for line in lines:
                    stripped = line.strip()
                    if re.match(r'\d+\s+authenticate\s+login', stripped, re.IGNORECASE):
                        waiting_user = True
                        continue
                    # Skip size markers (pure digits) and server prompts
                    if stripped.isdigit() or stripped.startswith('+') or stripped.startswith('*'):
                        continue
                    if waiting_user and stripped:
                        try:
                            import base64 as _b64
                            decoded = _b64.b64decode(stripped + '==').decode('utf-8', errors='replace').strip('\x00')
                            if decoded and all(32 <= ord(c) < 127 for c in decoded) and not username:
                                username = decoded
                                waiting_user = False
                                waiting_pass = True
                                continue
                        except Exception:
                            pass
                    if waiting_pass and stripped:
                        try:
                            import base64 as _b64
                            decoded = _b64.b64decode(stripped + '==').decode('utf-8', errors='replace').strip('\x00')
                            if decoded and all(32 <= ord(c) < 127 for c in decoded) and not password:
                                password = decoded
                                waiting_pass = False
                                continue
                        except Exception:
                            pass
                    mb_m = re.match(r'\d+\s+select\s+"?([^"]+)"?', stripped, re.IGNORECASE)
                    if mb_m:
                        mailbox = mb_m.group(1)
                    cnt_m = re.match(r'\*\s+(\d+)\s+EXISTS', stripped)
                    if cnt_m:
                        msg_count = cnt_m.group(1)

                if username:
                    body_parts = [f'IMAP session: user={username}']
                    if password:
                        body_parts.append(f'password={password}')
                    if mailbox:
                        body_parts.append(f'mailbox={mailbox}')
                    if msg_count:
                        body_parts.append(f'{msg_count} messages in mailbox')
                    results.append({
                        'from': username,
                        'to': [],
                        'subject': f'IMAP session: {username} on {pcap_path.name}',
                        'date': '',
                        'body': '; '.join(body_parts),
                        'raw_snippet': '; '.join(body_parts),
                        'source_playbook': 'PCAP_IMAP',
                        'source_function': f'pcap:{pcap_path.name}',
                        'protocol': 'imap',
                    })
            except Exception:
                continue
    except (FileNotFoundError, Exception):
        pass
    return results


def _extract_pcap_ftp(pcap_path: Path) -> list:
    """Extract FTP sessions: credentials and file transfers."""
    results: list = []
    try:
        res = subprocess.run(
            [
                'tshark', '-r', str(pcap_path),
                '-Y', 'ftp',
                '-T', 'fields',
                '-e', 'tcp.stream',
                '-e', 'ftp.request.command',
                '-e', 'ftp.request.arg',
            ],
            capture_output=True, text=True, timeout=30,
        )

        sessions: dict = {}
        for line in res.stdout.splitlines():
            parts = line.split('\t', 2)
            if len(parts) < 3:
                continue
            sid, cmd, arg = parts[0].strip(), parts[1].strip().upper(), parts[2].strip()
            if not sid or not cmd:
                continue
            sess = sessions.setdefault(sid, {'user': '', 'pass': '', 'files': []})
            if cmd == 'USER':
                sess['user'] = arg
            elif cmd == 'PASS':
                sess['pass'] = arg
            elif cmd in ('STOR', 'RETR', 'MKD', 'CWD'):
                if arg and arg not in sess['files']:
                    sess['files'].append(f'{cmd}:{arg}')

        for sid, sess in sessions.items():
            if sess['user'] or sess['files']:
                file_list = ', '.join(sess['files'][:20])
                body = f"FTP user={sess['user'] or '?'}"
                if sess['pass']:
                    body += f" pass={sess['pass']}"
                if file_list:
                    body += f"; transfers: {file_list}"
                results.append({
                    'from': sess['user'] or 'ftp_user',
                    'to': [],
                    'subject': f"FTP session: {sess['user']} transferred {len(sess['files'])} file(s)",
                    'date': '',
                    'body': body,
                    'raw_snippet': body,
                    'source_playbook': 'PCAP_FTP',
                    'source_function': f'pcap:{pcap_path.name}',
                    'protocol': 'ftp',
                    'ftp_files': sess['files'],
                })
    except (FileNotFoundError, Exception):
        pass
    return results


def _looks_like_real_email(email: str) -> bool:
    """Return True only if email passes basic structural validity checks."""
    if not email or email.count('@') != 1:
        return False
    local, domain = email.split('@', 1)
    if not local or not domain:
        return False
    if local.startswith('.') or local.endswith('.') or '..' in local:
        return False
    parts = domain.split('.')
    if len(parts) < 2:
        return False
    if '..' in domain or domain.startswith('-') or domain.endswith('-'):
        return False
    tld = parts[-1]
    if not tld.isalpha() or len(tld) < 2 or len(tld) > 6:
        return False
    # Domain parts (excluding TLD) must be alphanumeric + hyphens, min 1 char
    if not all(p and re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?$', p) for p in parts[:-1]):
        return False
    return True


def _extract_pcap_http_webmail(pcap_path: Path) -> list:
    """Extract webmail account identifiers from HTTP traffic (Hotmail, Gmail, Yahoo)."""
    results: list = []
    seen_accounts: set = set()

    # ASCII-only strict patterns to avoid matching binary garbage
    _WEBMAIL_PATTERNS = [
        # Hotmail cookie with email address embedded (HMSC... cookie)
        (re.compile(r'HMSC\w+=\d{0,3}([a-zA-Z0-9][a-zA-Z0-9.+\-]+@hotmail\.[a-z]{2,6})', re.ASCII), 'Hotmail'),
        # HTML display of Hotmail email (shown in inbox)
        (re.compile(r'>([a-zA-Z0-9][a-zA-Z0-9.+\-]+@hotmail\.[a-z]{2,6})<', re.ASCII), 'Hotmail'),
        # Gmail (ASCII only, word boundary)
        (re.compile(r'\b([a-zA-Z0-9][a-zA-Z0-9.+\-]{2,}@gmail\.com)\b', re.ASCII), 'Gmail'),
        # Yahoo Mail (ASCII only, word boundary)
        (re.compile(r'\b([a-zA-Z0-9][a-zA-Z0-9.+\-]{2,}@yahoo\.[a-z]{2,6})\b', re.ASCII), 'Yahoo Mail'),
        # Generic: strict ASCII word-char email, min 3-char local part, 2-6 char TLD
        (re.compile(r'\b([a-zA-Z0-9][a-zA-Z0-9.+\-]{2,63}@[a-zA-Z0-9][a-zA-Z0-9.\-]{1,100}\.[a-zA-Z]{2,6})\b', re.ASCII), 'webmail'),
    ]

    try:
        stream_res = subprocess.run(
            ['tshark', '-r', str(pcap_path), '-Y', 'http', '-T', 'fields', '-e', 'tcp.stream'],
            capture_output=True, text=True, timeout=30,
        )
        stream_ids = sorted({ln.strip() for ln in stream_res.stdout.splitlines() if ln.strip().isdigit()})

        for sid in list(stream_ids)[:40]:
            try:
                fr = subprocess.run(
                    ['tshark', '-r', str(pcap_path), '-qz', f'follow,tcp,ascii,{sid}'],
                    capture_output=True, text=True, timeout=20,
                )
                content = fr.stdout  # limit per stream

                for pattern, service in _WEBMAIL_PATTERNS:
                    for m in pattern.finditer(content):
                        # Extract the email address group (last non-empty group)
                        email = next((g for g in reversed(m.groups()) if g and '@' in g), None)
                        if not email or email in seen_accounts:
                            continue
                        if not _looks_like_real_email(email):
                            continue
                        if any(x in email.lower() for x in ('noreply', 'no-reply', 'mailer-daemon', 'postmaster')):
                            continue
                        seen_accounts.add(email)
                        results.append({
                            'from': email,
                            'to': [],
                            'subject': f'{service} account: {email}',
                            'date': '',
                            'body': f'Webmail account {email} identified in {service} HTTP session',
                            'raw_snippet': f'{service} webmail: {email}',
                            'source_playbook': 'PCAP_HTTP',
                            'source_function': f'pcap:{pcap_path.name}',
                            'protocol': 'http_webmail',
                        })
                        break  # one hit per stream per pattern type is enough
            except Exception:
                continue
    except (FileNotFoundError, Exception):
        pass
    return results


def _extract_pcap_irc(pcap_path: Path) -> list:
    """Extract IRC PRIVMSG messages from a PCAP via tshark."""
    messages: list = []
    seen: set = set()

    try:
        result = subprocess.run(
            [
                'tshark', '-r', str(pcap_path),
                '-Y', 'irc',
                '-T', 'fields',
                '-e', 'frame.time_epoch',
                '-e', 'ip.src',
                '-e', 'ip.dst',
                '-e', 'irc.request',
                '-e', 'irc.response',
            ],
            capture_output=True, text=True, timeout=60,
        )

        ip_to_nick: dict = {}

        for line in result.stdout.splitlines():
            parts = line.split('\t', 4)
            if len(parts) < 5:
                continue
            ts = parts[0].strip()
            src_ip = parts[1].strip()
            request = parts[3].strip()
            response = parts[4].strip()

            # Track IP → nickname from NICK commands
            if request:
                nm = re.match(r'NICK\s+(\S+)', request, re.IGNORECASE)
                if nm:
                    ip_to_nick[src_ip] = nm.group(1)

            # Client PRIVMSG (no prefix — look up nick from NICK tracking)
            if request:
                pm = re.match(r'PRIVMSG\s+(\S+)\s+:(.*)', request, re.IGNORECASE)
                if pm:
                    nick = ip_to_nick.get(src_ip, src_ip)
                    channel, text = pm.group(1), pm.group(2)
                    key = f"{nick}|{channel}|{text[:80]}"
                    if key not in seen:
                        seen.add(key)
                        messages.append({
                            'from': nick,
                            'to': [channel],
                            'subject': f'IRC:{channel}',
                            'date': ts,
                            'body': text[:500],
                            'raw_snippet': f'{nick} → {channel}: {text[:200]}',
                            'source_playbook': 'PCAP_IRC',
                            'source_function': f'pcap:{pcap_path.name}',
                            'protocol': 'irc',
                        })

            # Server relay: :nick!user@host PRIVMSG #chan :text
            if response:
                rm = re.match(
                    r':(\w[\w\-\[\]\\`^{}|]*)(?:!\S+)?\s+PRIVMSG\s+(\S+)\s+:(.*)',
                    response, re.IGNORECASE,
                )
                if rm:
                    nick, channel, text = rm.group(1), rm.group(2), rm.group(3)
                    key = f"{nick}|{channel}|{text[:80]}"
                    if key not in seen:
                        seen.add(key)
                        messages.append({
                            'from': nick,
                            'to': [channel],
                            'subject': f'IRC:{channel}',
                            'date': ts,
                            'body': text[:500],
                            'raw_snippet': f'{nick} → {channel}: {text[:200]}',
                            'source_playbook': 'PCAP_IRC',
                            'source_function': f'pcap:{pcap_path.name}',
                            'protocol': 'irc',
                        })

    except FileNotFoundError:
        pass
    except Exception:
        pass

    return messages


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
        """Extract structured messages from email/chat findings.

        Handles:
          - Plain-text email/chat findings (From/To/Subject parsing)
          - Structured chat blocks (sender:/message:/timestamp:)
          - Structured messages from specialist extractors (structured_messages field)
          - Direct chat extraction from evidence (geoff_chat_extractor)
        """
        messages = []
        seen: set = set()

        for rec in findings:
            module = str(rec.get("module", "")).lower()
            function = str(rec.get("function", "")).lower()
            output = str(rec.get("output", ""))
            playbook = str(rec.get("playbook", ""))
            result = rec.get("result", {})

            # ---- Structured messages from specialist extractors ----
            structured = result.get("structured_messages", []) if isinstance(result, dict) else []
            if structured:
                for msg in structured:
                    if not isinstance(msg, dict):
                        continue
                    msg_from = str(msg.get("from", ""))
                    msg_to = msg.get("to", [])
                    if isinstance(msg_to, str):
                        msg_to = [msg_to]
                    msg_body = str(msg.get("body", "") or msg.get("text", ""))
                    msg_ts = str(msg.get("timestamp", "") or msg.get("date", ""))
                    platform = str(msg.get("platform", function))
                    key = f"{msg_from}|{','.join(msg_to)}|{msg_body[:50]}|{platform}"
                    if key not in seen and (msg_from or msg_to):
                        seen.add(key)
                        messages.append({
                            "from": msg_from,
                            "to": msg_to,
                            "subject": msg_body,
                            "date": msg_ts,
                            "raw_snippet": f"[{platform}] {msg_from} → {', '.join(msg_to)}: {msg_body}",
                            "platform": platform,
                            "source_playbook": playbook,
                            "source_function": function,
                            "_structured": True,
                        })
                continue  # Already processed structured messages, skip text parsing

            # ---- Raw result from extractors (e.g., SkypeExtractor returns list of messages) ----
            raw = result.get("raw_result", {}) if isinstance(result, dict) else {}
            if isinstance(raw, dict) and raw.get("messages"):
                for msg in raw["messages"]:
                    if not isinstance(msg, dict):
                        continue
                    msg_from = str(msg.get("from", ""))
                    msg_to = msg.get("to", [])
                    if isinstance(msg_to, str):
                        msg_to = [msg_to]
                    msg_body = str(msg.get("body", "") or msg.get("text", ""))
                    msg_ts = str(msg.get("timestamp", "") or msg.get("date", ""))
                    platform = str(msg.get("platform", function))
                    key = f"{msg_from}|{','.join(msg_to)}|{msg_body[:50]}|{platform}"
                    if key not in seen and (msg_from or msg_to):
                        seen.add(key)
                        messages.append({
                            "from": msg_from,
                            "to": msg_to,
                            "subject": msg_body,
                            "date": msg_ts,
                            "raw_snippet": f"[{platform}] {msg_from} → {', '.join(msg_to)}: {msg_body}",
                            "platform": platform,
                            "source_playbook": playbook,
                            "source_function": function,
                            "_structured": True,
                        })
                continue

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

    def extract_chat_from_evidence(self, evidence_dir: str) -> list:
        """Directly extract chat messages from evidence directory.

        Calls the geoff_chat_extractor module to find and parse:
          - WhatsApp (msgstore.db, ChatStorage.sqlite)
          - Signal (signal.db, JSON backups)
          - Slack (LevelDB stores)
          - Teams (LevelDB, SQLite)
          - Skype (main.db)

        Returns list of structured messages in the standard format.
        """
        messages = []
        try:
            from geoff_chat_extractor import extract_all_from_evidence
            results = extract_all_from_evidence(evidence_dir)

            for platform, result in results.items():
                if not result.get("messages"):
                    continue
                for msg in result["messages"]:
                    msg_from = str(msg.get("from", ""))
                    msg_to = msg.get("to", [])
                    if isinstance(msg_to, str):
                        msg_to = [msg_to]
                    msg_body = str(msg.get("body", ""))
                    msg_ts = str(msg.get("timestamp", ""))
                    messages.append({
                        "from": msg_from,
                        "to": msg_to,
                        "subject": msg_body,
                        "date": msg_ts,
                        "raw_snippet": f"[{platform}] {msg_from} → {', '.join(msg_to)}: {msg_body}",
                        "platform": platform,
                        "source_playbook": "PB-SIFT-031",
                        "source_function": f"extract_{platform}_from_evidence",
                        "_direct_extraction": True,
                    })
        except ImportError:
            pass
        except Exception:
            pass

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

    def extract_pcap_communications(self, evidence_dir: str) -> list:
        """Find PCAP/capture files in evidence_dir and extract SMTP/IRC messages."""
        all_messages: list = []
        ev_path = Path(evidence_dir)
        if not ev_path.exists():
            return all_messages

        pcap_files: list = []
        for root, _, files in os.walk(ev_path):
            for fname in files:
                fp = Path(root) / fname
                ext = fp.suffix.lower()
                if ext in ('.pcap', '.pcapng', '.cap'):
                    pcap_files.append(fp)
                elif ext in ('.log', '') and _is_pcap_file(fp):
                    pcap_files.append(fp)

        for pcap_path in pcap_files[:10]:
            all_messages.extend(_extract_pcap_smtp(pcap_path))
            all_messages.extend(_extract_pcap_irc(pcap_path))
            all_messages.extend(_extract_pcap_imap(pcap_path))
            all_messages.extend(_extract_pcap_ftp(pcap_path))
            all_messages.extend(_extract_pcap_http_webmail(pcap_path))

        return all_messages

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

        # Extract directly from PCAP files (SMTP + IRC)
        pcap_msgs = self.extract_pcap_communications(evidence_dir)
        if pcap_msgs:
            seen_keys = {
                f"{m.get('from')}|{','.join(m.get('to', []))}|{m.get('subject', '')}"
                for m in messages
            }
            for pm in pcap_msgs:
                key = f"{pm.get('from')}|{','.join(pm.get('to', []))}|{pm.get('subject', '')}"
                if key not in seen_keys:
                    seen_keys.add(key)
                    messages.append(pm)

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
            "email_count": sum(1 for m in messages if m.get("protocol") in ("smtp", "imap")),
            "irc_messages": sum(1 for m in messages if m.get("protocol") == "irc"),
            "ftp_sessions": sum(1 for m in messages if m.get("protocol") == "ftp"),
            "webmail_accounts": sum(1 for m in messages if m.get("protocol") == "http_webmail"),
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
