#!/usr/bin/env python3
"""Geoff DFIR - PB-SIFT-041 Orphan Linux/Unix User Artifact Analysis.

Processes stray Linux/Unix home-directory files extracted outside a disk image:
  - Shell history (.bash_history, .zsh_history, etc.)
  - Shell config (.bashrc, .bash_profile, .profile, .zshrc, etc.)
  - SSH artifacts (authorized_keys, known_hosts, config, private keys)
  - Legacy Firefox 2 flat-file profile (history.dat, cookies.txt, signons2.txt, etc.)
  - Desktop environment artifacts (.gnome2/, .gconf/, .mc/, etc.)
  - Editor artifacts (.emacs, .viminfo, .vimrc, .nano_history)
  - Misc user config (.dmrc, .lesshst, .xsession-errors, .gtkrc*)
"""

import json
import re
import struct
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Suspicious shell command patterns
# ---------------------------------------------------------------------------
_SUSPICIOUS_CMDS = [
    (r'\bwget\s+.*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', "wget to IP address"),
    (r'\bcurl\s+.*https?://\S+', "curl to external URL"),
    (r'\bnc\b.*\s+-[lezLEZ]', "netcat with flags"),
    (r'\bncat\b', "ncat"),
    (r'\bbase64\s+(-d|--decode)', "base64 decode"),
    (r'\bchmod\s+(777|a\+x)', "chmod 777 or a+x"),
    (r'\bdd\s+if=\S+\s+of=', "dd raw copy"),
    (r'(?:python|perl|ruby|php)\s+-[ce]\s+["\'].*eval', "eval in interpreter"),
    (r'\bsudo\s+(?:-s\b|su\b)', "sudo shell escalation"),
    (r'(?:^|[;&|])\s*/tmp/\S+', "executing from /tmp"),
    (r'\brm\s+-[rf]{1,2}\s+/', "rm -rf on root path"),
    (r'\biptables\s+.*-[jJ]\s+ACCEPT', "iptables ACCEPT rule"),
    (r'\bssh\s+.*StrictHostKeyChecking=no', "SSH no host key check"),
    (r'\b(?:scp|rsync)\s+.*(?:@\S+|:\S+)', "remote file transfer"),
    (r'>\s*/dev/(?:tcp|udp)/\S+/\d+', "bash /dev/tcp redirect"),
]

# ---------------------------------------------------------------------------
# File name sets for filter routing
# ---------------------------------------------------------------------------
_SHELL_HISTORY_NAMES = frozenset({
    ".bash_history", ".zsh_history", ".sh_history", ".ash_history",
    ".history", "bash_history", "zsh_history", ".fish_history",
})
_SHELL_CONFIG_NAMES = frozenset({
    ".bashrc", ".bash_profile", ".bash_login", ".bash_logout",
    ".profile", ".zshrc", ".zprofile", ".zsh_profile", ".zlogin", ".zlogout",
    ".kshrc", ".tcshrc", ".cshrc", ".bash_aliases",
})
_SSH_NAMES = frozenset({
    "authorized_keys", "authorized_keys2", "known_hosts", "config",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    "id_rsa.pub", "id_dsa.pub", "id_ecdsa.pub", "id_ed25519.pub",
    "identity", "identity.pub",
})
_FIREFOX_LEGACY_NAMES = frozenset({
    "history.dat", "cookies.txt", "signons2.txt", "formhistory.dat",
    "bookmarks.html",
})
_BOOKMARKS_BACKUP_RE = re.compile(r'^bookmarks.*\.html$', re.IGNORECASE)
_DESKTOP_PATHS = (".gnome2", ".gnome", ".gconf", ".gconfd", ".mc",
                   ".local/share/applications", ".local/share")
_EDITOR_NAMES = frozenset({
    ".emacs", ".viminfo", ".vimrc", ".vimrc.local", ".nano_history", ".nanorc",
})
_MISC_CONFIG_NAMES = frozenset({".dmrc", ".lesshst", ".xsession-errors"})
_GTKRC_RE = re.compile(r'^\.gtkrc', re.IGNORECASE)


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class LinuxUserSpecialist:
    """PB-SIFT-041 — Orphan Linux/Unix User Artifact Analysis."""

    def __init__(self):
        self._session_findings: list = []

    # ------------------------------------------------------------------
    # Shell history
    # ------------------------------------------------------------------

    def analyze_shell_history(self, history_file: str) -> dict:
        p = Path(history_file)
        if p.name not in _SHELL_HISTORY_NAMES:
            return {"status": "skipped", "reason": "not a shell history file", "file": history_file}

        try:
            text = _read_text(history_file)
        except OSError as e:
            return {"status": "error", "error": str(e), "file": history_file}

        commands = [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.startswith("#")]
        suspicious = []
        for cmd in commands:
            for pattern, label in _SUSPICIOUS_CMDS:
                if re.search(pattern, cmd, re.IGNORECASE):
                    suspicious.append({"command": cmd[:300], "reason": label})
                    break

        findings = [{
            "type": "shell_history",
            "file": history_file,
            "command_count": len(commands),
            "suspicious": suspicious,
            "commands_sample": commands[:20],
        }]
        summary = f"Shell history {p.name}: {len(commands)} commands, {len(suspicious)} suspicious"
        result = {"status": "success", "findings": findings, "summary": summary, "file": history_file}
        self._session_findings.extend(findings)
        return result

    # ------------------------------------------------------------------
    # Shell config
    # ------------------------------------------------------------------

    def analyze_shell_config(self, config_file: str) -> dict:
        p = Path(config_file)
        if p.name not in _SHELL_CONFIG_NAMES:
            return {"status": "skipped", "reason": "not a shell config file", "file": config_file}

        try:
            text = _read_text(config_file)
        except OSError as e:
            return {"status": "error", "error": str(e), "file": config_file}

        indicators = []
        for i, line in enumerate(text.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith('#'):
                continue
            if re.search(r'\balias\s+\w+\s*=.*(?:\bnc\b|bash.*\|)', stripped):
                indicators.append({"line": i, "content": stripped[:200], "reason": "suspicious alias"})
            if re.search(r'\bLD_PRELOAD\b', stripped):
                indicators.append({"line": i, "content": stripped[:200], "reason": "LD_PRELOAD set"})
            if re.search(r'\bPATH=.*(?:/tmp|/var/tmp|\.\b)', stripped):
                indicators.append({"line": i, "content": stripped[:200], "reason": "suspicious PATH entry"})
            if re.search(r'\bexport\s+HIST(?:FILE|SIZE|FILESIZE)\s*=\s*(?:/dev/null|0\b)', stripped):
                indicators.append({"line": i, "content": stripped[:200], "reason": "history suppression"})
            if re.search(r'(?:curl|wget|nc\b|ncat)\s+.*&\s*$', stripped):
                indicators.append({"line": i, "content": stripped[:200], "reason": "background network command in rc"})

        aliases = re.findall(r'^\s*alias\s+(\w+)\s*=(.+)', text, re.MULTILINE)
        exports = re.findall(r'^\s*export\s+(\w+)=(.+)', text, re.MULTILINE)

        findings = [{
            "type": "shell_config",
            "file": config_file,
            "alias_count": len(aliases),
            "export_count": len(exports),
            "indicators": indicators,
            "aliases": [{"name": a[0], "value": a[1].strip()[:100]} for a in aliases[:20]],
        }]
        summary = (f"Shell config {p.name}: {len(aliases)} aliases, "
                   f"{len(exports)} exports, {len(indicators)} suspicious indicators")
        result = {"status": "success", "findings": findings, "summary": summary, "file": config_file}
        self._session_findings.extend(findings)
        return result

    # ------------------------------------------------------------------
    # SSH artifacts
    # ------------------------------------------------------------------

    def analyze_ssh_artifacts(self, ssh_file: str) -> dict:
        p = Path(ssh_file)
        in_ssh_dir = ".ssh" in str(ssh_file).replace("\\", "/")
        if p.name not in _SSH_NAMES and not in_ssh_dir:
            return {"status": "skipped", "reason": "not an SSH artifact", "file": ssh_file}

        try:
            text = _read_text(ssh_file)
        except OSError as e:
            return {"status": "error", "error": str(e), "file": ssh_file}

        findings = []
        if p.name in ("authorized_keys", "authorized_keys2"):
            entries = [ln.strip() for ln in text.splitlines()
                       if ln.strip() and not ln.startswith('#')]
            indicators = []
            for entry in entries:
                if 'command=' in entry:
                    indicators.append({"type": "forced_command", "entry": entry[:250]})
                elif not re.search(r'no-pty|no-agent|no-port', entry):
                    indicators.append({"type": "unrestricted_key", "entry": entry[:250]})
            findings = [{
                "type": "ssh_authorized_keys",
                "file": ssh_file,
                "key_count": len(entries),
                "forced_commands": [i for i in indicators if i["type"] == "forced_command"],
                "all_entries": indicators,
            }]
            summary = f"authorized_keys: {len(entries)} keys, {sum(1 for i in indicators if i['type'] == 'forced_command')} with forced command"

        elif p.name == "known_hosts":
            hosts = []
            for line in text.splitlines():
                ln = line.strip()
                if ln and not ln.startswith('#'):
                    host_field = ln.split()[0] if ln.split() else ''
                    if host_field:
                        # Hashed entries start with |1|
                        hosts.append({"host": host_field, "hashed": host_field.startswith("|1|")})
            findings = [{
                "type": "ssh_known_hosts",
                "file": ssh_file,
                "host_count": len(hosts),
                "hashed_count": sum(1 for h in hosts if h["hashed"]),
                "hosts": hosts[:50],
            }]
            summary = f"known_hosts: {len(hosts)} entries ({sum(1 for h in hosts if h['hashed'])} hashed)"

        elif p.name == "config":
            host_blocks = re.findall(r'^\s*Host\s+(.+)', text, re.MULTILINE | re.IGNORECASE)
            hostnames = re.findall(r'^\s*HostName\s+(.+)', text, re.MULTILINE | re.IGNORECASE)
            proxy_cmds = re.findall(r'^\s*ProxyCommand\s+(.+)', text, re.MULTILINE | re.IGNORECASE)
            findings = [{
                "type": "ssh_config",
                "file": ssh_file,
                "host_aliases": [h.strip() for h in host_blocks],
                "hostnames": [h.strip() for h in hostnames],
                "proxy_commands": [p.strip() for p in proxy_cmds],
            }]
            summary = (f"SSH config: {len(host_blocks)} host aliases, "
                       f"{len(hostnames)} HostName entries, {len(proxy_cmds)} ProxyCommand entries")

        elif p.name.startswith("id_") and not p.name.endswith(".pub"):
            encrypted = "ENCRYPTED" in text or "Proc-Type: 4,ENCRYPTED" in text
            findings = [{
                "type": "ssh_private_key",
                "file": ssh_file,
                "key_type": p.name,
                "encrypted": encrypted,
                "significance": "HIGH — unencrypted private key" if not encrypted else "MEDIUM",
            }]
            summary = f"SSH private key: {p.name} ({'unencrypted' if not encrypted else 'encrypted'})"

        else:
            findings = [{"type": "ssh_artifact", "file": ssh_file, "name": p.name}]
            summary = f"SSH artifact: {p.name}"

        result = {"status": "success", "findings": findings, "summary": summary, "file": ssh_file}
        self._session_findings.extend(findings)
        return result

    # ------------------------------------------------------------------
    # Legacy Firefox 2 artifacts
    # ------------------------------------------------------------------

    def analyze_legacy_firefox(self, profile_file: str) -> dict:
        p = Path(profile_file)
        is_legacy = (
            p.name in _FIREFOX_LEGACY_NAMES
            or _BOOKMARKS_BACKUP_RE.match(p.name)
        )
        if not is_legacy:
            return {"status": "skipped", "reason": "not a legacy Firefox profile file", "file": profile_file}

        # Skip NSS binary databases
        if p.suffix.lower() == ".db" and p.name not in _FIREFOX_LEGACY_NAMES:
            return {"status": "skipped", "reason": "binary NSS database", "file": profile_file}

        try:
            text = _read_text(profile_file)
        except OSError as e:
            return {"status": "error", "error": str(e), "file": profile_file}

        if p.name == "history.dat":
            findings = _parse_mork_history(profile_file, text)
            summary = f"Firefox 2 history.dat: {len(findings)} URL records extracted"
        elif p.name == "cookies.txt":
            findings = _parse_cookies_txt(profile_file, text)
            summary = f"Firefox cookies.txt: {len(findings)} cookies parsed"
        elif p.name == "signons2.txt":
            findings = _parse_signons2(profile_file, text)
            summary = f"Firefox signons2.txt: {len(findings)} saved credential sites"
        elif p.name == "formhistory.dat":
            findings = _parse_formhistory(profile_file, text)
            summary = f"Firefox formhistory.dat: {len(findings)} form field values"
        elif "bookmarks" in p.name.lower() and p.suffix.lower() == ".html":
            findings = _parse_bookmarks_html(profile_file, text)
            summary = f"Firefox bookmarks HTML: {len(findings)} bookmark entries"
        else:
            findings = [{"type": "firefox_misc", "file": profile_file, "name": p.name}]
            summary = f"Firefox artifact: {p.name}"

        result = {"status": "success", "findings": findings, "summary": summary, "file": profile_file}
        self._session_findings.extend(findings)
        return result

    # ------------------------------------------------------------------
    # Desktop environment artifacts
    # ------------------------------------------------------------------

    def analyze_desktop_artifacts(self, artifact_file: str) -> dict:
        path_str = str(artifact_file)
        in_desktop = any(d in path_str for d in _DESKTOP_PATHS)
        if not in_desktop:
            return {"status": "skipped", "reason": "not a desktop environment artifact", "file": artifact_file}

        p = Path(artifact_file)

        try:
            raw = p.read_bytes()
            if b'\x00' in raw[:256] and not raw[:4] in (b'\xce\xfa\xed\xfe', b'\xfe\xed\xfa\xce'):
                return {"status": "skipped", "reason": "binary file skipped", "file": artifact_file}
            text = raw.decode("utf-8", errors="replace")
        except OSError as e:
            return {"status": "error", "error": str(e), "file": artifact_file}

        findings = []
        path_lower = path_str.lower()

        if ".mc/history" in path_lower or (p.name == "history" and ".mc" in path_lower):
            cmds = [ln.strip() for ln in text.splitlines() if ln.strip()]
            suspicious = []
            for cmd in cmds:
                for pattern, label in _SUSPICIOUS_CMDS:
                    if re.search(pattern, cmd, re.IGNORECASE):
                        suspicious.append({"command": cmd[:200], "reason": label})
                        break
            findings = [{
                "type": "mc_history",
                "file": artifact_file,
                "command_count": len(cmds),
                "commands": cmds[:50],
                "suspicious": suspicious,
            }]
            summary = f"Midnight Commander history: {len(cmds)} commands, {len(suspicious)} suspicious"

        elif ".mc/" in path_lower:
            findings = [{"type": "mc_config", "file": artifact_file, "content_preview": text[:500]}]
            summary = f"MC config {p.name}: {len(text.splitlines())} lines"

        elif ".gconf" in path_lower or ".gconfd" in path_lower:
            keys = re.findall(r'<entry\s+name="([^"]+)"', text)
            str_vals = re.findall(r'<stringvalue>([^<]{1,200})</stringvalue>', text)
            findings = [{
                "type": "gconf_data",
                "file": artifact_file,
                "keys": keys[:30],
                "string_values": str_vals[:30],
            }]
            summary = f"GConf {p.name}: {len(keys)} keys, {len(str_vals)} string values"

        elif ".gnome2" in path_lower or ".gnome" in path_lower:
            findings = [{"type": "gnome_config", "file": artifact_file, "size_bytes": len(raw)}]
            summary = f"GNOME config: {p.name} ({len(raw)} bytes)"

        elif ".local/share/applications" in path_lower and p.suffix == ".desktop":
            exec_m = re.search(r'^Exec\s*=\s*(.+)', text, re.MULTILINE)
            name_m = re.search(r'^Name\s*=\s*(.+)', text, re.MULTILINE)
            findings = [{
                "type": "desktop_entry",
                "file": artifact_file,
                "name": name_m.group(1).strip() if name_m else "",
                "exec": exec_m.group(1).strip() if exec_m else "",
            }]
            summary = f"Desktop entry: {findings[0]['name']} → {findings[0]['exec']}"

        else:
            findings = [{"type": "desktop_artifact", "file": artifact_file, "size_bytes": len(raw)}]
            summary = f"Desktop artifact: {p.name} ({len(raw)} bytes)"

        result = {"status": "success", "findings": findings, "summary": summary, "file": artifact_file}
        self._session_findings.extend(findings)
        return result

    # ------------------------------------------------------------------
    # Editor artifacts
    # ------------------------------------------------------------------

    def analyze_editor_artifacts(self, artifact_file: str) -> dict:
        p = Path(artifact_file)
        if p.name not in _EDITOR_NAMES:
            return {"status": "skipped", "reason": "not an editor artifact", "file": artifact_file}

        try:
            text = _read_text(artifact_file)
        except OSError as e:
            return {"status": "error", "error": str(e), "file": artifact_file}

        findings = []
        if p.name == ".viminfo":
            marks = re.findall(r"^'\d+\s+\d+\s+\d+\s+(.+)", text, re.MULTILINE)
            searches = re.findall(r'^/(.+)', text, re.MULTILINE)
            cmd_hist = re.findall(r'^:(.+)', text, re.MULTILINE)
            susp_marks = [m for m in marks
                          if any(d in m for d in ('/etc/', '/tmp/', '/root/', 'pass', 'shadow', 'key'))]
            findings = [{
                "type": "viminfo",
                "file": artifact_file,
                "file_marks": marks[:30],
                "suspicious_paths": susp_marks,
                "search_history": searches[:20],
                "command_history": cmd_hist[:20],
            }]
            summary = (f".viminfo: {len(marks)} file marks, {len(susp_marks)} suspicious, "
                       f"{len(searches)} searches")

        elif p.name in (".vimrc", ".vimrc.local"):
            indicators = []
            for i, line in enumerate(text.splitlines(), 1):
                if re.search(r'^\s*!(?:curl|wget|nc\b|bash|python|perl)', line):
                    indicators.append({"line": i, "content": line.strip()[:200], "reason": "shell exec in vimrc"})
                if re.search(r'autocmd.*VimEnter.*!', line, re.IGNORECASE):
                    indicators.append({"line": i, "content": line.strip()[:200], "reason": "startup autocmd with shell exec"})
            findings = [{
                "type": "vimrc",
                "file": artifact_file,
                "line_count": len(text.splitlines()),
                "indicators": indicators,
            }]
            summary = f".vimrc: {len(text.splitlines())} lines, {len(indicators)} suspicious"

        elif p.name == ".emacs":
            indicators = []
            for i, line in enumerate(text.splitlines(), 1):
                if re.search(r'shell-command|call-process|start-process', line):
                    indicators.append({"line": i, "content": line.strip()[:200], "reason": "shell/process execution"})
            findings = [{
                "type": "emacs_config",
                "file": artifact_file,
                "line_count": len(text.splitlines()),
                "indicators": indicators,
            }]
            summary = f".emacs: {len(text.splitlines())} lines, {len(indicators)} shell-exec references"

        elif p.name == ".nano_history":
            entries = [ln.strip() for ln in text.splitlines() if ln.strip()]
            findings = [{"type": "nano_history", "file": artifact_file, "entries": entries[:50]}]
            summary = f"nano history: {len(entries)} search patterns"

        else:
            findings = [{"type": "editor_artifact", "file": artifact_file, "name": p.name}]
            summary = f"Editor artifact: {p.name}"

        result = {"status": "success", "findings": findings, "summary": summary, "file": artifact_file}
        self._session_findings.extend(findings)
        return result

    # ------------------------------------------------------------------
    # Misc user config
    # ------------------------------------------------------------------

    def analyze_misc_user_config(self, config_file: str) -> dict:
        p = Path(config_file)
        is_match = p.name in _MISC_CONFIG_NAMES or _GTKRC_RE.match(p.name)
        if not is_match:
            return {"status": "skipped", "reason": "not a misc user config file", "file": config_file}

        try:
            text = _read_text(config_file)
        except OSError as e:
            return {"status": "error", "error": str(e), "file": config_file}

        findings = []
        if p.name == ".dmrc":
            session_m = re.search(r'^Session\s*=\s*(.+)', text, re.MULTILINE)
            lang_m = re.search(r'^Language\s*=\s*(.+)', text, re.MULTILINE)
            findings = [{
                "type": "dmrc",
                "file": config_file,
                "session": session_m.group(1).strip() if session_m else "",
                "language": lang_m.group(1).strip() if lang_m else "",
            }]
            summary = f".dmrc: session={findings[0]['session']}, language={findings[0]['language']}"

        elif p.name == ".lesshst":
            entries = [ln.strip() for ln in text.splitlines()
                       if ln.strip() and not ln.startswith('.')]
            findings = [{"type": "less_history", "file": config_file, "searches": entries[:50]}]
            summary = f"less history: {len(entries)} search patterns"

        elif p.name == ".xsession-errors":
            errors = [ln.strip() for ln in text.splitlines()
                      if re.search(r'(?:Error|WARNING|CRITICAL|Segfault|failed|denied)',
                                   ln, re.IGNORECASE)]
            username_m = re.search(r'localuser:(\w+)', text)
            findings = [{
                "type": "xsession_errors",
                "file": config_file,
                "username": username_m.group(1) if username_m else "",
                "error_count": len(errors),
                "errors": errors[:20],
            }]
            summary = (f".xsession-errors: {len(errors)} error/warning lines"
                       + (f", user={findings[0]['username']}" if findings[0]['username'] else ""))

        elif _GTKRC_RE.match(p.name):
            include_m = re.search(r'^include\s+"([^"]+)"', text, re.MULTILINE)
            findings = [{
                "type": "gtkrc",
                "file": config_file,
                "size_bytes": len(text),
                "include": include_m.group(1) if include_m else "",
            }]
            summary = f"GTK config {p.name}: {len(text)} bytes"

        else:
            findings = [{"type": "misc_config", "file": config_file}]
            summary = f"Misc config: {p.name}"

        result = {"status": "success", "findings": findings, "summary": summary, "file": config_file}
        self._session_findings.extend(findings)
        return result

    # ------------------------------------------------------------------
    # Aggregate
    # ------------------------------------------------------------------

    def aggregate_findings(self, output_path: str) -> dict:
        """Aggregate all session findings into a structured JSON report."""
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)

        by_type: dict = {}
        for f in self._session_findings:
            ftype = f.get("type", "unknown")
            by_type.setdefault(ftype, []).append(f)

        suspicious_count = sum(
            len(f.get("suspicious", [])) + len(f.get("indicators", []))
            for f in self._session_findings
        )

        report = {
            "playbook": "PB-SIFT-041",
            "playbook_name": "Orphan Linux/Unix User Artifact Analysis",
            "generated_at": datetime.now().isoformat(),
            "total_findings": len(self._session_findings),
            "suspicious_items": suspicious_count,
            "findings_by_type": {k: len(v) for k, v in by_type.items()},
            "findings": self._session_findings,
        }

        try:
            out.write_text(json.dumps(report, default=str, indent=2))
        except OSError as e:
            return {"status": "error", "error": f"write failed: {e}"}

        return {
            "status": "success",
            "output_path": output_path,
            "total_findings": len(self._session_findings),
            "suspicious_items": suspicious_count,
            "summary": (f"PB-SIFT-041: {len(self._session_findings)} findings, "
                        f"{suspicious_count} suspicious items → {output_path}"),
        }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _read_text(path: str) -> str:
    """Read a text file with UTF-8 first, latin-1 fallback."""
    p = Path(path)
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return p.read_text(encoding="latin-1", errors="replace")


def _parse_mork_history(file_path: str, text: str) -> list:
    """Extract URLs from Firefox 2 Mork-format history.dat via regex."""
    findings = []
    seen: set = set()

    # Mork uses $XX hex escapes for non-ASCII chars in strings
    # URLs appear as values for various keys; extract all http/https URLs
    url_re = re.compile(r'https?://[^\s\)\]>\'\"\\$]{5,500}', re.IGNORECASE)
    for raw_url in url_re.findall(text):
        # Clean trailing punctuation
        url = raw_url.rstrip('.,;)')
        if url not in seen:
            seen.add(url)
            findings.append({
                "type": "firefox_history_url",
                "file": file_path,
                "url": url,
                "domain": _extract_domain(url),
            })

    # Also extract page titles from Mork unicode-escaped strings (W$00X$00...)
    title_re = re.compile(r'\((?:87|8D|8C|8E|8F|90|91|92|8B)=([^\)]+)\)')
    for m in title_re.finditer(text):
        raw = m.group(1)
        # Attempt naive Mork unicode decode: W$00e$00l$00 → "Wel"
        decoded = re.sub(r'\$00', '', raw)
        decoded = re.sub(r'\$[0-9A-Fa-f]{2}', '', decoded).strip()
        if decoded and len(decoded) > 3:
            findings.append({
                "type": "firefox_history_title",
                "file": file_path,
                "title": decoded[:200],
            })

    return findings


def _parse_cookies_txt(file_path: str, text: str) -> list:
    """Parse Netscape-format cookies.txt (tab-delimited)."""
    findings = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split('\t')
        if len(parts) >= 7:
            findings.append({
                "type": "firefox_cookie",
                "file": file_path,
                "domain": parts[0],
                "path": parts[2],
                "secure": parts[3].upper() == "TRUE",
                "expires": parts[4],
                "name": parts[5],
                "value_len": len(parts[6]),
            })
    return findings


def _parse_signons2(file_path: str, text: str) -> list:
    """Parse Firefox 2 signons2.txt saved credentials."""
    findings = []
    lines = text.splitlines()
    i = 0
    current_url = None
    while i < len(lines):
        line = lines[i].strip()
        if line.startswith('http://') or line.startswith('https://'):
            current_url = line
        elif line.startswith('.') and current_url:
            # End of URL block - '.' separates blocks
            pass
        elif current_url and line and not line.startswith('#') and not line.startswith('*'):
            username_field = line
            encrypted_user = lines[i + 1].strip() if i + 1 < len(lines) else ""
            password_field = lines[i + 2].strip() if i + 2 < len(lines) else ""
            encrypted_pass = lines[i + 3].strip() if i + 3 < len(lines) else ""
            if password_field.startswith('*'):
                findings.append({
                    "type": "firefox_saved_credential",
                    "file": file_path,
                    "url": current_url,
                    "username_field": username_field,
                    "password_field": password_field.lstrip('*'),
                    "username_encrypted": encrypted_user[:60],
                    "note": "credentials encrypted with NSS key3.db",
                })
                i += 3
        i += 1
    return findings


def _parse_formhistory(file_path: str, text: str) -> list:
    """Extract form field values from Firefox 2 Mork-format formhistory.dat."""
    findings = []
    # Form data stored with key=value pairs in Mork format
    # Look for field name=value patterns
    entry_re = re.compile(r'\((?:80|81|82|83)=([^\)]{1,200})\)')
    seen: set = set()
    for m in entry_re.finditer(text):
        val = m.group(1).strip()
        if val and val not in seen:
            seen.add(val)
            findings.append({
                "type": "firefox_form_value",
                "file": file_path,
                "value": val[:200],
            })
    return findings


def _parse_bookmarks_html(file_path: str, text: str) -> list:
    """Extract bookmarks from Firefox HTML bookmark export."""
    findings = []
    # Match <A HREF="url">title</A>
    bookmark_re = re.compile(
        r'<A\s+[^>]*HREF="([^"]+)"[^>]*>([^<]*)</A>',
        re.IGNORECASE,
    )
    for m in bookmark_re.finditer(text):
        url = m.group(1).strip()
        title = m.group(2).strip()
        findings.append({
            "type": "firefox_bookmark",
            "file": file_path,
            "url": url,
            "title": title[:200],
            "domain": _extract_domain(url),
        })
    return findings


def _extract_domain(url: str) -> str:
    """Extract just the domain from a URL."""
    m = re.match(r'https?://([^/?\s]+)', url, re.IGNORECASE)
    return m.group(1).lower() if m else ""
