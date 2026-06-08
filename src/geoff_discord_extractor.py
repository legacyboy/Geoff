#!/usr/bin/env python3
"""Geoff DFIR — Discord Chat & Messaging Extractor.

Targets the Narcos 2019 scenario: John Fredricksen ↔ Steve Kowhai communications
via Discord on Windows 10 laptops.

Extraction sources (from disk images):
  1.  %APPDATA%/discord/Local Storage/leveldb/  — LevelDB key-value store
      containing cached messages, channel metadata, and user state
  2.  %APPDATA%/discord/Cache/  — Chromium-style disk cache (also LevelDB)
  3.  %APPDATA%/discord/Local State  — JSON config with user identity
  4.  %APPDATA%/discord/settings.json  — User settings

Extraction sources (from memory dumps):
  1.  strings + regex search for Discord usernames, channel names,
      message fragments, and timestamps

Output format (feeds into CommunicationsAnalyzer and report_json):
  {
      "platform": "discord",
      "users": [{"username": "John#1234", "user_id": "...", "source": "..."}],
      "channels": [{"name": "general", "channel_id": "...", "type": "DM|guild_text"}],
      "servers": [{"name": "...", "server_id": "..."}],
      "messages": [{"from": "...", "to": "...", "content": "...", "timestamp": "..."}],
      "attachments": [{"filename": "...", "url": "...", "channel": "..."}],
      "extraction_sources": ["leveldb", "memory_strings", ...],
  }
"""

import json
import os
import re
import struct
import sqlite3
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Optional, Callable


# ---------------------------------------------------------------------------
# Constants — Discord data paths and patterns
# ---------------------------------------------------------------------------

# Windows AppData paths relative to user profile root
_DISCORD_PATHS = [
    "AppData/Roaming/discord/Local Storage/leveldb",
    "AppData/Roaming/discord/Cache",
    "AppData/Roaming/discord/Cache/Cache_Data",
    "AppData/Roaming/discord/Local State",
    "AppData/Roaming/discord/settings.json",
    "AppData/Roaming/discord/Cookies",
    "AppData/Local/discord",
    # Alternate paths (older Discord versions)
    "AppData/Roaming/discordptb/Local Storage/leveldb",
    "AppData/Roaming/discordcanary/Local Storage/leveldb",
    "AppData/Roaming/discorddevelopment/Local Storage/leveldb",
]

# Discord-specific file patterns to look for in disk image walks
_DISCORD_FILE_PATTERNS = [
    re.compile(r"discord[/\\]Local\s+Storage[/\\]leveldb[/\\]\d+\.ldb", re.I),
    re.compile(r"discord[/\\]Local\s+Storage[/\\]leveldb[/\\]MANIFEST-\d+", re.I),
    re.compile(r"discord[/\\]Local\s+Storage[/\\]leveldb[/\\]LOG", re.I),
    re.compile(r"discord[/\\]Local\s+Storage[/\\]leveldb[/\\]CURRENT", re.I),
    re.compile(r"discord[/\\]Cache[/\\]data_\d+", re.I),
    re.compile(r"discord[/\\]Cache[/\\]index", re.I),
    re.compile(r"discord[/\\]Cache[/\\]f_\d+", re.I),
    re.compile(r"discord[/\\]Local\s+State", re.I),
    re.compile(r"discord[/\\]settings\.json", re.I),
    re.compile(r"discord[/\\]Cookies", re.I),
    re.compile(r"discord[/\\]session[/\\].+\.json", re.I),
]

# ---------------------------------------------------------------------------
# Memory dump string search patterns
# ---------------------------------------------------------------------------

# Discord username pattern: username#discriminator or @username
_DISCORD_USERNAME_RE = re.compile(
    r'(?:@|username[:\s]*)?([A-Za-z0-9_\.]{2,32}#\d{4})'
)

# Discord message content fragments (JSON-like in memory)
_DISCORD_MESSAGE_FRAGMENT_RE = re.compile(
    r'"content"\s*:\s*"([^"]{2,500})"',
)

# Discord channel name patterns
_DISCORD_CHANNEL_RE = re.compile(
    r'(?:"name"\s*:\s*"([^"]{2,100})"\s*,\s*"(?:id|guild_id|channel_id|type)")|'
    r'(?:channel[_\s]?name[:\s]*([A-Za-z0-9_\-]{2,32}))',
    re.I,
)

# Discord server/guild name
_DISCORD_GUILD_RE = re.compile(
    r'(?:"name"\s*:\s*"([^"]{2,100})"\s*,\s*"(?:id|guild\.id|owner)")|'
    r'(?:guild[_\s]?name[:\s]*([A-Za-z0-9_\- ]{2,50}))',
    re.I,
)

# Discord IDs (snowflakes — 17-19 digit numbers)
_DISCORD_SNOWFLAKE_RE = re.compile(r'\b(\d{17,20})\b')

# Discord token pattern (base64-like, ~60 chars, starts with 'm' or common prefixes)
_DISCORD_TOKEN_RE = re.compile(r'([A-Za-z0-9_\-\.]{20,80})')

# Timestamps in Discord message JSON
_DISCORD_TIMESTAMP_RE = re.compile(
    r'"timestamp"\s*:\s*"([^"]{10,30})"',
)

# ---------------------------------------------------------------------------
# LevelDB parsing (minimal — enough to extract Discord cached data)
# ---------------------------------------------------------------------------

def _parse_leveldb_log(path: Path) -> Optional[dict]:
    """Extract key-value data from a LevelDB .log file.

    LevelDB log format: each record is a 32-bit CRC + 16-bit length + 8-bit type,
    prefixed by a block marker. We scan for readable JSON substrings since
    Discord stores messages/channel data as JSON values.
    """
    results: dict = defaultdict(list)
    try:
        raw = path.read_bytes()
    except (OSError, PermissionError):
        return None

    # Discord stores data in LevelDB with JSON values
    # Scan for JSON-like objects and arrays
    _JSON_OBJ_RE = re.compile(rb'\{[^{}]*?(?:(?:\{[^{}]*?\})[^{}]*?)*\}')
    _JSON_ARR_RE = re.compile(rb'\[[^\[\]]*?(?:(?:\[[^\[\]]*?\])[^\[\]]*?)*\]')

    for match in _JSON_OBJ_RE.finditer(raw):
        try:
            obj = json.loads(match.group().decode("utf-8", errors="replace"))
            if isinstance(obj, dict):
                _classify_json_obj(obj, results, path)
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass

    for match in _JSON_ARR_RE.finditer(raw):
        try:
            arr = json.loads(match.group().decode("utf-8", errors="replace"))
            if isinstance(arr, list):
                for item in arr:
                    if isinstance(item, dict):
                        _classify_json_obj(item, results, path)
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass

    return dict(results) if results else None


def _classify_json_obj(obj: dict, results: defaultdict, source: Path):
    """Classify a parsed JSON object into Discord categories."""
    # Channel/message data — has 'content', 'author', 'channel_id'
    if "content" in obj and ("author" in obj or "channel_id" in obj):
        results["messages"].append(obj)
    # User/author data — has 'username' and 'discriminator' or 'id'
    elif "username" in obj and ("discriminator" in obj or "id" in obj):
        results["users"].append(obj)
    # Channel metadata
    elif "name" in obj and ("type" in obj or "guild_id" in obj):
        if obj.get("type") in (0, 1, 2, 3, 4, 5, 6):
            results["channels"].append(obj)
    # Guild/server data
    elif "name" in obj and "id" in obj and "owner_id" in obj:
        results["servers"].append(obj)
    # Generic JSON with possible Discord data
    elif any(k in obj for k in ("token", "email", "phone", "discord")):
        results["metadata"].append(obj)


def _parse_leveldb_ldb(path: Path) -> Optional[dict]:
    """Extract key-value data from a LevelDB .ldb (SSTable) file.

    SSTable format: data blocks with restart points. We scan for
    Discord-relevant JSON substrings.
    """
    return _parse_leveldb_log(path)  # Same approach — scan for JSON


def _scan_leveldb_directory(dir_path: Path) -> dict:
    """Scan an entire LevelDB directory for Discord data."""
    results: dict = defaultdict(list)
    if not dir_path.is_dir():
        return {}

    for entry in sorted(dir_path.iterdir()):
        name = entry.name.lower()
        if entry.is_file():
            if name.endswith(".ldb") or name.endswith(".sst"):
                parsed = _parse_leveldb_ldb(entry)
                if parsed:
                    for k, v in parsed.items():
                        results[k].extend(v)
            elif name.endswith((".log", ".old")):
                parsed = _parse_leveldb_log(entry)
                if parsed:
                    for k, v in parsed.items():
                        results[k].extend(v)
            elif name == "current" or name.startswith("manifest"):
                # CURRENT and MANIFEST contain LevelDB metadata — skip
                pass
            else:
                # Try parsing any remaining files as they may contain JSON data
                parsed = _parse_leveldb_log(entry)
                if parsed:
                    for k, v in parsed.items():
                        results[k].extend(v)

    return dict(results)


# ---------------------------------------------------------------------------
# Local State / settings.json parsing
# ---------------------------------------------------------------------------

def _parse_local_state(path: Path) -> Optional[dict]:
    """Parse Discord's Local State JSON file for user identity."""
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (json.JSONDecodeError, UnicodeDecodeError, OSError):
        return None

    result = {}
    # OS-level crypto keys (encrypted Discord token storage)
    if "os_crypt" in data:
        result["has_encrypted_storage"] = True
        result["os_crypt_keys"] = list(data["os_crypt"].keys())[:5] if isinstance(data["os_crypt"], dict) else []

    # User identity
    for key in ("email", "username", "user_id", "token"):
        if key in data:
            result[key] = str(data[key])[:200]
        elif "profile" in data and isinstance(data["profile"], dict) and key in data["profile"]:
            result[key] = str(data["profile"][key])[:200]

    return result if result else None


def _parse_settings(path: Path) -> Optional[dict]:
    """Parse Discord's settings.json."""
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (json.JSONDecodeError, UnicodeDecodeError, OSError):
        return None

    result = {}
    for key in ("account", "channel", "guilds", "currentGuildId", "recentEmojis"):
        if key in data:
            val = data[key]
            if isinstance(val, (dict, list)):
                result[key] = val if isinstance(val, list) and len(str(val)) < 2000 else str(val)[:500]
            else:
                result[key] = str(val)[:200]

    return result if result else None


# ---------------------------------------------------------------------------
# Cookie extraction (session/identity data)
# ---------------------------------------------------------------------------

def _parse_discord_cookies(path: Path) -> Optional[list]:
    """Parse Discord's Cookies SQLite database for session tokens."""
    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        cur = conn.cursor()
        cur.execute(
            "SELECT host_key, name, value, expires_utc, last_access_utc "
            "FROM cookies WHERE host_key LIKE '%discord%'"
        )
        rows = cur.fetchall()
        conn.close()
        cookies = []
        for host, name, value, expires, last_access in rows:
            cookies.append({
                "host": host,
                "name": name,
                "value": value[:100] if value else "",
                "value_length": len(value) if value else 0,
            })
        return cookies if cookies else None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Memory dump string analysis
# ---------------------------------------------------------------------------

def _extract_discord_from_strings(strings_text: str) -> dict:
    """Extract Discord data from a strings dump of a memory image.

    Args:
        strings_text: Raw strings output from a memory dump (lines of text)

    Returns:
        dict with keys: users, messages, channels, servers, tokens, metadata
    """
    results: dict = defaultdict(list)
    seen_usernames: set = set()
    seen_channels: set = set()
    seen_tokens: set = set()

    for line in strings_text.splitlines():
        line = line.strip()
        if len(line) < 4:
            continue

        # Username pattern: user#1234 or @user
        for match in _DISCORD_USERNAME_RE.finditer(line):
            uname = match.group(1)
            if uname not in seen_usernames:
                seen_usernames.add(uname)
                # Find context around the username
                ctx_start = max(0, match.start() - 40)
                ctx_end = min(len(line), match.end() + 200)
                results["users"].append({
                    "username": uname,
                    "source": "memory_strings",
                    "context": line[ctx_start:ctx_end],
                })

        # Message content fragments
        for match in _DISCORD_MESSAGE_FRAGMENT_RE.finditer(line):
            content = match.group(1)
            if len(content) > 3:
                # Look for nearby sender/timestamp
                sender = ""
                ts = ""
                sender_match = re.search(
                    r'"username"\s*:\s*"([^"]{2,32})"',
                    line[max(0, match.start() - 200):match.start()],
                )
                if sender_match:
                    sender = sender_match.group(1)
                results["messages"].append({
                    "content": content,
                    "from": sender,
                    "source": "memory_strings",
                })

        # Guild/server names
        for match in _DISCORD_GUILD_RE.finditer(line):
            name = match.group(1) or match.group(2)
            if name and len(name) > 1:
                results["servers"].append({
                    "name": name,
                    "source": "memory_strings",
                })

        # Channel names
        for match in _DISCORD_CHANNEL_RE.finditer(line):
            name = match.group(1) or match.group(2)
            if name and len(name) > 1 and name not in seen_channels:
                seen_channels.add(name)
                results["channels"].append({
                    "name": name,
                    "source": "memory_strings",
                })

        # Discord tokens (base64-like after "token")
        if "token" in line.lower() and "discord" in line.lower():
            for match in _DISCORD_TOKEN_RE.finditer(line):
                token = match.group(1)
                if len(token) >= 24 and token not in seen_tokens:
                    seen_tokens.add(token)
                    results["tokens"].append({
                        "token_fragment": token[:20] + "...",
                        "source": "memory_strings",
                    })

        # Snowflake IDs near "discord"
        if "discord" in line.lower():
            for match in _DISCORD_SNOWFLAKE_RE.finditer(line):
                sid = match.group(1)
                results["ids"].append(sid)

    return dict(results)


# ---------------------------------------------------------------------------
# Structured output builder
# ---------------------------------------------------------------------------

def _build_structured_output(
    leveldb_results: Optional[dict],
    local_state: Optional[dict],
    settings: Optional[dict],
    cookies: Optional[list],
    memory_results: Optional[dict],
    source_path: str = "",
) -> dict:
    """Build the standardised Discord extraction output dict."""

    output: dict = {
        "platform": "discord",
        "users": [],
        "channels": [],
        "servers": [],
        "messages": [],
        "attachments": [],
        "extraction_sources": [],
        "metadata": {},
    }

    seen_users: set = set()
    seen_channels: set = set()
    seen_messages: set = set()

    # --- Process LevelDB results ---
    if leveldb_results:
        output["extraction_sources"].append("leveldb")

        for user in leveldb_results.get("users", []):
            username = user.get("username", "")
            discrim = user.get("discriminator", "")
            uid = str(user.get("id", ""))
            if username and discrim:
                full = f"{username}#{discrim}"
            else:
                full = username or uid or "unknown"
            if full not in seen_users:
                seen_users.add(full)
                output["users"].append({
                    "username": full,
                    "user_id": uid,
                    "source": "leveldb",
                    "raw": user if len(str(user)) < 500 else str(user)[:500],
                })

        for channel in leveldb_results.get("channels", []):
            name = channel.get("name", "")
            cid = str(channel.get("id", ""))
            ctype = channel.get("type", "unknown")
            if name and name not in seen_channels:
                seen_channels.add(name)
                output["channels"].append({
                    "name": name,
                    "channel_id": cid,
                    "type": _discord_channel_type(ctype),
                    "source": "leveldb",
                })

        for server in leveldb_results.get("servers", []):
            output["servers"].append({
                "name": server.get("name", ""),
                "server_id": str(server.get("id", "")),
                "source": "leveldb",
            })

        for msg in leveldb_results.get("messages", []):
            content = msg.get("content", "")
            author = msg.get("author", {})
            if isinstance(author, dict):
                sender = author.get("username", "")
            else:
                sender = str(author) if author else ""
            msg_key = f"{sender}:{content[:80]}"
            if msg_key not in seen_messages:
                seen_messages.add(msg_key)
                # Parse Discord snowflake ID → timestamp
                sid = str(msg.get("id", ""))
                ts = _snowflake_to_iso(sid) if sid.isdigit() and len(sid) >= 17 else ""
                output["messages"].append({
                    "from": sender,
                    "to": "",  # Infer from channel context
                    "content": content[:1000],
                    "timestamp": ts,
                    "message_id": sid,
                    "source": "leveldb",
                })
                # Check for attachments
                for att in msg.get("attachments", []):
                    if isinstance(att, dict):
                        output["attachments"].append({
                            "filename": att.get("filename", ""),
                            "url": att.get("url", ""),
                            "message_id": sid,
                            "source": "leveldb",
                        })

    # --- Process Local State ---
    if local_state:
        output["extraction_sources"].append("local_state")
        output["metadata"]["local_state"] = local_state

    # --- Process Settings ---
    if settings:
        output["extraction_sources"].append("settings_json")

    # --- Process Cookies ---
    if cookies:
        output["extraction_sources"].append("cookies")
        output["metadata"]["cookies"] = cookies

    # --- Process Memory Strings ---
    if memory_results:
        output["extraction_sources"].append("memory_strings")

        for user in memory_results.get("users", []):
            uname = user.get("username", "")
            if uname not in seen_users:
                seen_users.add(uname)
                output["users"].append(user)

        for channel in memory_results.get("channels", []):
            name = channel.get("name", "")
            if name not in seen_channels:
                seen_channels.add(name)
                output["channels"].append(channel)

        for server in memory_results.get("servers", []):
            output["servers"].append(server)

        for msg in memory_results.get("messages", []):
            msg_key = f"{msg.get('from', '')}:{msg.get('content', '')[:80]}"
            if msg_key not in seen_messages:
                seen_messages.add(msg_key)
                output["messages"].append(msg)

        if memory_results.get("tokens"):
            output["metadata"]["token_fragments"] = memory_results["tokens"]

        if memory_results.get("ids"):
            id_set = set(memory_results["ids"])
            output["metadata"]["discord_snowflake_ids"] = sorted(id_set)[:50]

    # --- Source path ---
    output["metadata"]["source_path"] = source_path
    output["metadata"]["total_findings"] = (
        len(output["users"])
        + len(output["channels"])
        + len(output["messages"])
        + len(output["servers"])
        + len(output["attachments"])
    )

    return output


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _discord_channel_type(type_val) -> str:
    """Convert Discord channel type integer to string."""
    mapping = {
        0: "guild_text",
        1: "dm",
        2: "guild_voice",
        3: "group_dm",
        4: "guild_category",
        5: "guild_news",
        6: "guild_store",
    }
    if isinstance(type_val, int):
        return mapping.get(type_val, f"unknown_{type_val}")
    return str(type_val)


def _snowflake_to_iso(snowflake_str: str) -> str:
    """Convert Discord snowflake ID to ISO 8601 timestamp.

    Discord epoch = 2015-01-01T00:00:00.000Z (milliseconds since Unix epoch).
    Snowflake = (timestamp_ms - DISCORD_EPOCH) << 22 + internal_worker_id << 17 + internal_process_id << 12 + increment.
    """
    try:
        snowflake = int(snowflake_str)
        timestamp_ms = (snowflake >> 22) + 1420070400000
        dt = datetime.utcfromtimestamp(timestamp_ms / 1000.0)
        return dt.isoformat() + "Z"
    except (ValueError, OSError, OverflowError):
        return ""


# ---------------------------------------------------------------------------
# Disk image scanning (works on mounted filesystem or extracted files)
# ---------------------------------------------------------------------------

def _find_discord_paths_from_walk(disk_walk_output: str) -> list:
    """Parse a disk walk / fls output to find Discord-related file paths.

    Args:
        disk_walk_output: Output of fls or similar tool listing files

    Returns:
        List of Discord-related paths found
    """
    found = []
    for line in disk_walk_output.splitlines():
        line_lower = line.lower()
        if "discord" in line_lower:
            # Extract the path portion
            for pattern in _DISCORD_FILE_PATTERNS:
                if pattern.search(line):
                    found.append(line.strip())
                    break
            else:
                # Generic discord hit
                found.append(line.strip())
    return found


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class DiscordExtractor:
    """Discord chat and message extraction for DFIR investigations.

    Handles both disk-image extraction (LevelDB, JSON files) and
    memory dump analysis (string-based regex scanning).

    Usage:
        extractor = DiscordExtractor()
        # From mounted disk image
        result = extractor.extract_from_filesystem("/mnt/evidence/user/AppData/Roaming/discord")
        # From memory dump strings
        result = extractor.extract_from_memory_strings(strings_output)
        # Analyze findings for Discord artifacts
        matches = extractor.find_discord_artifacts_in_findings(findings_list)
    """

    def __init__(self):
        pass

    # ------------------------------------------------------------------
    # Filesystem extraction
    # ------------------------------------------------------------------

    def extract_from_filesystem(self, base_path: str) -> dict:
        """Extract Discord data from a filesystem path.

        Args:
            base_path: Path to discord AppData directory (e.g.,
                       .../AppData/Roaming/discord/) or parent directory

        Returns:
            Structured output dict
        """
        base = Path(base_path)
        if not base.exists():
            return _build_structured_output(None, None, None, None, None, base_path)

        leveldb_results = None
        local_state = None
        settings = None
        cookies = None

        # Find LevelDB directories
        leveldb_dir = None
        for candidate in [
            base / "Local Storage" / "leveldb",
            base / "Local Storage",
            base / "Cache" / "Cache_Data",
            base / "Cache",
        ]:
            if candidate.is_dir():
                # Check if it contains .ldb or .log files
                has_ldb = any(f.suffix.lower() in (".ldb", ".log", ".sst")
                              for f in candidate.iterdir() if f.is_file())
                if has_ldb:
                    leveldb_dir = candidate
                    break
            elif base.name.lower() == "leveldb" and base.is_dir():
                leveldb_dir = base
                break

        if leveldb_dir:
            leveldb_results = _scan_leveldb_directory(leveldb_dir)

        # Parse Local State
        for candidate in [base / "Local State", base.parent / "Local State"
                          if base.name.lower() in ("leveldb", "cache", "local storage")
                          else Path("/dev/null")]:
            if candidate.exists():
                local_state = _parse_local_state(candidate)
                break

        # Parse settings.json
        for candidate in [base / "settings.json", base.parent / "settings.json"]:
            if candidate.exists():
                settings = _parse_settings(candidate)
                break

        # Parse Cookies
        for candidate in [base / "Cookies", base.parent / "Cookies"]:
            if candidate.exists():
                cookies = _parse_discord_cookies(candidate)
                break

        return _build_structured_output(
            leveldb_results, local_state, settings, cookies, None, base_path
        )

    def extract_from_findings_walk(self, disk_walk_output: str,
                                     extraction_func: Optional[Callable] = None) -> dict:
        """Find Discord paths in a disk walk output, then extract.

        Args:
            disk_walk_output: Output from fls or similar walk tool
            extraction_func: Optional function(path) -> bytes to extract file contents
                             from a disk image (e.g., icat-based extraction)

        Returns:
            Structured output dict
        """
        paths = _find_discord_paths_from_walk(disk_walk_output)
        if not paths:
            return _build_structured_output(None, None, None, None, None, "")

        # Note: actual file extraction from disk images requires icat or
        # similar tool. The extraction_func callback handles this.
        # For now, return the paths found.
        result = _build_structured_output(None, None, None, None, None, "")
        result["metadata"]["discord_paths_found"] = paths
        result["extraction_sources"] = ["disk_walk"]
        return result

    # ------------------------------------------------------------------
    # Memory dump extraction
    # ------------------------------------------------------------------

    def extract_from_memory_strings(self, strings_output: str) -> dict:
        """Extract Discord data from a strings dump of a memory image.

        Args:
            strings_output: Output of `strings` or similar tool on a memory dump

        Returns:
            Structured output dict
        """
        memory_results = _extract_discord_from_strings(strings_output)
        return _build_structured_output(
            None, None, None, None, memory_results, "memory_dump"
        )

    def extract_from_memory_file(self, memory_path: str,
                                   min_length: int = 8) -> dict:
        """Run strings on a memory dump file and extract Discord data.

        Args:
            memory_path: Path to memory dump file (.vmem, .dmp, .raw, etc.)
            min_length: Minimum string length for `strings` command

        Returns:
            Structured output dict
        """
        import subprocess
        import tempfile

        try:
            result = subprocess.run(
                ["strings", "-n", str(min_length), memory_path],
                capture_output=True,
                text=True,
                timeout=300,
            )
            strings_output = result.stdout
            if result.stderr and len(strings_output) < 100:
                strings_output = result.stderr
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            strings_output = ""

        return self.extract_from_memory_strings(strings_output)

    # ------------------------------------------------------------------
    # Findings analysis
    # ------------------------------------------------------------------

    def find_discord_artifacts_in_findings(self, findings: list) -> list:
        """Scan existing findings for Discord-related artifacts.

        Args:
            findings: List of finding dicts from Geoff pipeline

        Returns:
            List of findings that reference Discord
        """
        discord_findings = []
        _DISCORD_KW = [
            "discord", "discordapp", "discord.com",
        ]

        for rec in findings:
            output = str(rec.get("output", "")).lower()
            function = str(rec.get("function", "")).lower()
            module = str(rec.get("module", "")).lower()
            text = f"{output} {function} {module}"

            if any(kw in text for kw in _DISCORD_KW):
                discord_findings.append({
                    "finding_id": rec.get("step_key", ""),
                    "module": module,
                    "function": function,
                    "evidence_file": str(rec.get("evidence_file", "")),
                    "context": output[:500] if len(output) > 500 else output,
                })

        return discord_findings

    # ------------------------------------------------------------------
    # Main entry point — integration with Geoff pipeline
    # ------------------------------------------------------------------

    def analyze(
        self,
        evidence_dir: str = "",
        findings: list = None,
        disk_walk_output: str = "",
        memory_strings_output: str = "",
        call_llm_func: Optional[Callable] = None,
    ) -> dict:
        """Main entry point for Discord extraction.

        Args:
            evidence_dir: Path to evidence directory (filesystem extraction)
            findings: Existing Geoff findings list (artifact scanning)
            disk_walk_output: Output of fls/filesystem walk
            memory_strings_output: Output of strings on memory dump

        Returns:
            Complete Discord extraction report dict
        """
        results = []

        # Filesystem extraction
        if evidence_dir:
            fs_result = self.extract_from_filesystem(evidence_dir)
            if fs_result.get("metadata", {}).get("total_findings", 0) > 0:
                results.append(fs_result)

        # Disk walk (find paths, don't extract — caller handles extraction)
        if disk_walk_output:
            walk_result = self.extract_from_findings_walk(disk_walk_output)
            results.append(walk_result)

        # Memory strings extraction
        if memory_strings_output:
            mem_result = self.extract_from_memory_strings(memory_strings_output)
            if mem_result.get("metadata", {}).get("total_findings", 0) > 0:
                results.append(mem_result)

        # Merge results
        merged = self._merge_results(results)

        # Scan findings for Discord artifacts
        if findings:
            discord_hits = self.find_discord_artifacts_in_findings(findings)
            if discord_hits:
                merged["metadata"]["findings_referencing_discord"] = discord_hits

        # Generate narrative
        narrative = ""
        if call_llm_func and merged["messages"]:
            narrative = self._generate_narrative(merged, call_llm_func)
        merged["narrative"] = narrative

        return merged

    def _merge_results(self, results: list) -> dict:
        """Merge multiple extraction results (e.g., from different sources)."""
        if not results:
            return _build_structured_output(None, None, None, None, None, "")

        if len(results) == 1:
            return results[0]

        merged = results[0].copy()
        seen_users = {u["username"] for u in merged["users"]}
        seen_channels = {c["name"] for c in merged["channels"]}
        seen_messages = set(
            f"{m.get('from', '')}|{m.get('content', '')[:60]}" for m in merged["messages"]
        )

        for r in results[1:]:
            for user in r.get("users", []):
                if user.get("username", "") not in seen_users:
                    seen_users.add(user["username"])
                    merged["users"].append(user)

            for channel in r.get("channels", []):
                if channel.get("name", "") not in seen_channels:
                    seen_channels.add(channel["name"])
                    merged["channels"].append(channel)

            for msg in r.get("messages", []):
                key = f"{msg.get('from', '')}|{msg.get('content', '')[:60]}"
                if key not in seen_messages:
                    seen_messages.add(key)
                    merged["messages"].append(msg)

            for server in r.get("servers", []):
                merged["servers"].append(server)

            for att in r.get("attachments", []):
                merged["attachments"].append(att)

            merged["extraction_sources"] = list(set(
                merged.get("extraction_sources", []) +
                r.get("extraction_sources", [])
            ))

            # Merge metadata
            for mk, mv in r.get("metadata", {}).items():
                if mk in merged.get("metadata", {}):
                    if isinstance(merged["metadata"][mk], list) and isinstance(mv, list):
                        merged["metadata"][mk].extend(mv)
                    elif isinstance(merged["metadata"][mk], dict) and isinstance(mv, dict):
                        merged["metadata"][mk].update(mv)
                else:
                    merged["metadata"][mk] = mv

        merged["metadata"]["total_findings"] = (
            len(merged["users"])
            + len(merged["channels"])
            + len(merged["messages"])
            + len(merged["servers"])
            + len(merged["attachments"])
        )

        return merged

    def _generate_narrative(self, result: dict, call_llm_func: Callable) -> str:
        """LLM-powered narrative summary of Discord communications."""
        users = result.get("users", [])[:10]
        messages = result.get("messages", [])[:20]
        channels = result.get("channels", [])[:5]
        sources = result.get("extraction_sources", [])

        parts = [
            "You are a digital forensics analyst. Summarize the Discord communications found.",
            f"Extraction sources: {', '.join(sources)}",
            f"Users found: {len(result.get('users', []))}",
            f"Messages extracted: {len(messages)}",
            f"Channels: {len(channels)}",
        ]

        if users:
            parts.append("Users identified:")
            for u in users:
                parts.append(f"  - {u.get('username', 'unknown')} (source: {u.get('source', '')})")

        if messages:
            parts.append("\nSample messages:")
            for m in messages[:10]:
                sender = m.get("from", "unknown")
                content = m.get("content", "")[:200]
                ts = m.get("timestamp", "")
                parts.append(f"  [{ts}] {sender}: {content}")

        parts.append(
            "\nWrite a concise forensic narrative (2-3 paragraphs) covering: "
            "(1) who the Discord users are and their relationships, "
            "(2) what the communications reveal about their activities, "
            "(3) whether Discord was used to coordinate illegal activities, "
            "(4) recommended next investigative steps."
        )
        try:
            return call_llm_func("\n".join(parts), agent_type="manager") or ""
        except Exception:
            return ""


# ---------------------------------------------------------------------------
# Convenience function for pipeline integration
# ---------------------------------------------------------------------------

def extract_discord_from_evidence(
    evidence_dir: str = "",
    findings: list = None,
    disk_walk_output: str = "",
    memory_strings_outputs: list = None,
) -> dict:
    """Convenience function: extract Discord data from multiple evidence sources.

    Args:
        evidence_dir: Path to extracted/mounted filesystem
        findings: List of Geoff findings
        disk_walk_output: Output of fls/disk walk
        memory_strings_outputs: List of strings outputs from multiple memory dumps

    Returns:
        Structured Discord extraction report
    """
    extractor = DiscordExtractor()

    if memory_strings_outputs:
        mem_combined = "\n".join(memory_strings_outputs)
    else:
        mem_combined = ""

    return extractor.analyze(
        evidence_dir=evidence_dir,
        findings=findings,
        disk_walk_output=disk_walk_output,
        memory_strings_output=mem_combined,
    )
