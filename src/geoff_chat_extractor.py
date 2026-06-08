#!/usr/bin/env python3
"""Geoff DFIR - Chat & Messaging Content Extractors.

Dedicated extraction for communication app databases:
  - WhatsApp  (msgstore.db / ChatStorage.sqlite)
  - Signal    (signal.db / backup)
  - Slack     (leveldb)
  - Teams     (leveldb / PWA SQLite)
  - Skype     (main.db SQLite)

Each extractor returns a list of structured message dicts:
    {from, to, body, timestamp, platform, media_attachments, ...}

All extractors handle missing/encrypted/stale databases gracefully.
"""

import json
import os
import re
import sqlite3
import struct
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SQLITE_MAGIC = b"SQLite format 3\x00"
_LEVELDB_LOG_MAGIC = b"\x00\x00\x00\x00"  # LevelDB log files often start with zero block

# WhatsApp iOS table names
_WA_IOS_TABLES = [
    "ZWAMESSAGE",       # Core Data entity
    "ZWA_MESSAGE",      # alternative naming
    "ZWAMEDIAITEM",     # media attachments
    "ZWACHATSESSION",
]

# WhatsApp Android table names
_WA_ANDROID_TABLES = [
    "messages",
    "message",
    "chat",
    "chat_list",
    "jid",
    "messages_fts_content",
    "message_media",
    "message_thumbnails",
]

# Signal table names (unencrypted or partially accessible)
_SIGNAL_TABLES = [
    "mms",
    "sms",
    "thread",
    "part",
    "identities",
    "recipient_preferences",
    "groups",
    "group_membership",
]

# Slack leveldb key patterns
_SLACK_KEY_PATTERNS = [
    rb"messages", rb"channel", rb"user", rb"team",
    rb"msg",     rb"dm",      rb"mpim", rb"workspace",
]

# Skype main.db tables
_SKYPE_TABLES = [
    "Messages",
    "Conversations",
    "Contacts",
    "Transfers",
    "Calls",
    "Participants",
]

# Teams storage patterns
_TEAMS_PATTERNS = [
    "teams",
    "microsoft teams",
    "msteams",
    "teams.localstorage",
    "IndexedDB",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_sqlite(path: Path) -> bool:
    """Check if file is a valid SQLite database."""
    try:
        header = path.read_bytes()[:16]
        return header == _SQLITE_MAGIC
    except (OSError, PermissionError):
        return False


def _safe_db_connect(path: Path, readonly: bool = True) -> Optional[sqlite3.Connection]:
    """Open SQLite connection safely, with readonly mode."""
    uri = f"file:{path}?mode=ro" if readonly else str(path)
    try:
        conn = sqlite3.connect(uri, uri=readonly)
        conn.row_factory = sqlite3.Row
        return conn
    except sqlite3.DatabaseError:
        return None
    except sqlite3.OperationalError:
        return None
    except Exception:
        return None


def _sqlite_table_exists(conn: sqlite3.Connection, table: str) -> bool:
    """Check if a table exists in the database."""
    try:
        cur = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
            (table,),
        )
        return cur.fetchone() is not None
    except Exception:
        return False


def _sqlite_table_columns(conn: sqlite3.Connection, table: str) -> List[str]:
    """Return column names for a table."""
    try:
        cur = conn.execute(f"PRAGMA table_info({table})")
        return [row[1] for row in cur.fetchall()]
    except Exception:
        return []


def _safe_column_lookup(columns: List[str], candidates: List[str]) -> Optional[str]:
    """Find the first column that exists in the list (case-insensitive)."""
    cols_lower = {c.lower(): c for c in columns}
    for cand in candidates:
        if cand.lower() in cols_lower:
            return cols_lower[cand.lower()]
    return None


def _unix_epoch_to_iso(ts: Any) -> str:
    """Convert Unix timestamp (seconds or millis) to ISO string."""
    if ts is None:
        return ""
    try:
        ts_float = float(ts)
        if ts_float > 1e12:  # milliseconds
            ts_float /= 1000.0
        if ts_float < 0 or ts_float > 4e10:  # unreasonable
            return str(ts)
        return datetime.fromtimestamp(ts_float, tz=timezone.utc).isoformat()
    except (ValueError, TypeError, OSError, OverflowError):
        return str(ts) if ts else ""


def _apple_cocoa_ts_to_iso(cocoa_ts: Any) -> str:
    """Convert Apple Cocoa timestamp (seconds since 2001-01-01) to ISO."""
    if cocoa_ts is None:
        return ""
    try:
        ts_float = float(cocoa_ts)
        # Cocoa epoch: 2001-01-01, Unix epoch: 1970-01-01, offset = 978307200
        adjusted = 978307200.0 + ts_float
        if adjusted < 0 or adjusted > 4e10:
            return str(cocoa_ts)
        return datetime.fromtimestamp(adjusted, tz=timezone.utc).isoformat()
    except (ValueError, TypeError, OSError, OverflowError):
        return str(cocoa_ts) if cocoa_ts else ""


def _find_files(root: Path, patterns: List[str], max_depth: int = 5) -> List[Path]:
    """Find files matching patterns under root directory."""
    results: List[Path] = []
    if not root.exists():
        return results
    try:
        for path in root.rglob("*"):
            if path.is_file():
                name = path.name.lower()
                for pat in patterns:
                    if pat.lower() in name:
                        results.append(path)
                        break
    except PermissionError:
        pass
    return results


# ---------------------------------------------------------------------------
# WhatsApp Extractor
# ---------------------------------------------------------------------------

class WhatsAppExtractor:
    """Extract messages from WhatsApp databases.

    Android: msgstore.db (SQLite) from /data/data/com.whatsapp/databases/
    iOS:     ChatStorage.sqlite from iOS backups (Core Data)
    """

    PLATFORM = "whatsapp"

    def extract(self, db_path: str) -> Dict[str, Any]:
        """Main entry point. Returns structured messages."""
        path = Path(db_path)
        if not path.exists():
            return {"status": "skipped", "error": "Database not found", "messages": []}

        # Try Android format first (direct SQLite)
        if path.is_file() and _is_sqlite(path):
            result = self._extract_android(path)
            if result.get("messages"):
                return result
            # Fall through to try iOS format
            result_ios = self._extract_ios(path)
            if result_ios.get("messages"):
                return result_ios
            # Return whatever we got, preferring the one with more info
            if result.get("error") and not result_ios.get("error"):
                return result_ios
            return result

        # Directory: search for SQLite files
        if path.is_dir():
            return self._extract_from_directory(path)

        return {"status": "skipped", "error": "Not a database file", "messages": []}

    def _extract_from_directory(self, root: Path) -> Dict[str, Any]:
        """Search directory for WhatsApp databases and extract from all."""
        all_msgs: List[Dict[str, Any]] = []
        errors: List[str] = []
        db_files = _find_files(root, ["msgstore.db", "wa.db", "chatsettings.db", "chatstorage.sqlite"])

        for db_path in db_files:
            try:
                result = self._extract_android(db_path)
                if result.get("status") == "success":
                    all_msgs.extend(result.get("messages", []))
                elif result.get("error"):
                    errors.append(f"{db_path.name}: {result['error']}")
            except Exception as e:
                errors.append(f"{db_path.name}: {e}")

        # Try iOS backup paths
        ios_dbs = list(root.rglob("ChatStorage.sqlite"))
        for db_path in ios_dbs:
            try:
                result = self._extract_ios(db_path)
                if result.get("status") == "success":
                    all_msgs.extend(result.get("messages", []))
            except Exception as e:
                errors.append(f"{db_path.name}: {e}")

        return {
            "status": "success" if all_msgs else "empty",
            "messages": all_msgs,
            "message_count": len(all_msgs),
            "databases_scanned": len(db_files) + len(ios_dbs),
            "errors": errors[:5],
            "platform": self.PLATFORM,
        }

    def _extract_android(self, path: Path) -> Dict[str, Any]:
        """Parse msgstore.db (Android WhatsApp).

        Schema varies by version. Common tables:
        - messages: _id, key_remote_jid, key_from_me, data, timestamp, media_url, media_name, ...
        - message_media: message_id, media_path, ...
        """
        conn = _safe_db_connect(path)
        if not conn:
            return {"status": "error", "error": "Cannot open database (possibly encrypted crypt12/crypt14)", "messages": []}

        messages: List[Dict[str, Any]] = []
        try:
            # Probe for message table
            msg_table = None
            for tname in ["messages", "message"]:
                if _sqlite_table_exists(conn, tname):
                    msg_table = tname
                    break

            if not msg_table:
                conn.close()
                return {"status": "empty", "error": "No messages table found", "messages": []}

            cols = _sqlite_table_columns(conn, msg_table)

            # Map known columns
            id_col   = _safe_column_lookup(cols, ["_id", "id", "msg_id"])
            jid_col  = _safe_column_lookup(cols, ["key_remote_jid", "remote_jid", "jid", "chat_jid", "recipient_jid"])
            from_me_col = _safe_column_lookup(cols, ["key_from_me", "from_me", "is_from_me", "sent"])
            body_col = _safe_column_lookup(cols, ["data", "text_data", "message", "body", "content", "text"])
            ts_col   = _safe_column_lookup(cols, ["timestamp", "received_timestamp", "sent_timestamp", "sort_timestamp", "date"])
            media_col = _safe_column_lookup(cols, ["media_url", "media_name", "media_caption", "media_wa_type"])
            status_col = _safe_column_lookup(cols, ["status", "message_status"])

            if not body_col:
                conn.close()
                return {"status": "empty", "error": "No message body column found", "messages": []}

            # Build query from available columns
            select_cols = []
            for c in [id_col, jid_col, from_me_col, body_col, ts_col, media_col, status_col]:
                if c:
                    select_cols.append(c)
            query = f"SELECT {', '.join(select_cols)} FROM {msg_table} ORDER BY {ts_col or id_col or 'rowid'} DESC LIMIT 5000"

            cur = conn.execute(query)
            for row in cur.fetchall():
                rowd = dict(row)
                body = str(rowd.get(body_col, "")) if body_col else ""
                if not body or not body.strip():
                    continue  # skip empty/system messages

                jid = str(rowd.get(jid_col, "")) if jid_col else ""
                from_me = bool(rowd.get(from_me_col, 0)) if from_me_col else None
                ts_raw = rowd.get(ts_col) if ts_col else None
                ts = _unix_epoch_to_iso(ts_raw)
                media = str(rowd.get(media_col, "")) if media_col else ""

                # Determine sender/recipient from JID
                if jid:
                    # JID format: 1234567890@s.whatsapp.net or 1234567890-1234567890@g.us
                    if "@g.us" in jid or "@broadcast" in jid:
                        chat_type = "group"
                    else:
                        chat_type = "direct"
                else:
                    chat_type = "unknown"

                sender = "self" if from_me else jid.split("@")[0] if jid else "unknown"
                recipient = jid.split("@")[0] if jid and from_me else "self"

                messages.append({
                    "from": sender,
                    "to": [recipient],
                    "body": body[:1000],
                    "timestamp": ts,
                    "platform": self.PLATFORM,
                    "chat_type": chat_type,
                    "media": media[:200] if media else "",
                    "raw_jid": jid,
                })

            conn.close()
            return {
                "status": "success",
                "messages": messages,
                "message_count": len(messages),
                "source": f"android:{msg_table}",
                "platform": self.PLATFORM,
            }
        except Exception as e:
            conn.close()
            return {"status": "error", "error": str(e), "messages": []}

    def _extract_ios(self, path: Path) -> Dict[str, Any]:
        """Parse ChatStorage.sqlite (iOS WhatsApp - Core Data).

        Apple's Core Data stores entities with Z-prefixed tables.
        The entity tables vary by iOS version.
        """
        conn = _safe_db_connect(path)
        if not conn:
            return {"status": "error", "error": "Cannot open iOS WhatsApp database", "messages": []}

        messages: List[Dict[str, Any]] = []
        try:
            # Find the message entity table
            msg_table = None
            for tname in _WA_IOS_TABLES:
                if _sqlite_table_exists(conn, tname):
                    msg_table = tname
                    break

            # Fallback: query sqlite_master for tables matching ZWA* pattern
            if not msg_table:
                cur = conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'ZWAMESSAGE%'"
                )
                row = cur.fetchone()
                if row:
                    msg_table = row[0]

            if not msg_table:
                conn.close()
                return {"status": "empty", "error": "No message table found in iOS WhatsApp DB", "messages": []}

            cols = _sqlite_table_columns(conn, msg_table)

            # Core Data entity columns typically include:
            # ZTEXT, ZFROMJID, ZTOJID, ZMESSAGEDATE, ZISFROMME, ZMEDIAITEM, ZCHATSESSION
            body_col = _safe_column_lookup(cols, ["ZTEXT", "ZTEXTSTORAGE", "ZMESSAGETEXT", "ZBODY", "ZTEXTBLOB"])
            from_jid_col = _safe_column_lookup(cols, ["ZFROMJID", "ZSENDERJID", "ZFROM", "ZAUTHORJID"])
            to_jid_col = _safe_column_lookup(cols, ["ZTOJID", "ZRECIPIENTJID", "ZTO"])
            ts_col = _safe_column_lookup(cols, ["ZMESSAGEDATE", "ZDATE", "ZTIMESTAMP", "ZSORTDATE"])
            from_me_col = _safe_column_lookup(cols, ["ZISFROMME", "ZFROMME"])
            media_col = _safe_column_lookup(cols, ["ZMEDIAITEM", "ZMEDIAURL", "ZMEDIANAME"])

            if not body_col:
                conn.close()
                return {"status": "empty", "error": "No message body column found in iOS WhatsApp DB", "messages": []}

            select_cols = []
            for c in [body_col, from_jid_col, to_jid_col, ts_col, from_me_col, media_col]:
                if c:
                    select_cols.append(c)
            query = f"SELECT {', '.join(select_cols)} FROM {msg_table} WHERE {body_col} IS NOT NULL ORDER BY {ts_col or 'rowid'} DESC LIMIT 5000"

            cur = conn.execute(query)
            for row in cur.fetchall():
                rowd = dict(row)
                body = str(rowd.get(body_col, ""))
                if not body or not body.strip():
                    continue

                from_me = bool(rowd.get(from_me_col, 0)) if from_me_col else None
                ts_raw = rowd.get(ts_col) if ts_col else None
                ts = _apple_cocoa_ts_to_iso(ts_raw)
                from_jid = str(rowd.get(from_jid_col, "")) if from_jid_col else ""
                to_jid = str(rowd.get(to_jid_col, "")) if to_jid_col else ""
                media = str(rowd.get(media_col, "")) if media_col else ""

                sender = from_jid if from_jid else ("self" if from_me else "unknown")
                recipient = to_jid if to_jid else ("self" if not from_me and from_me is not None else "unknown")

                messages.append({
                    "from": sender,
                    "to": [recipient],
                    "body": body[:1000],
                    "timestamp": ts,
                    "platform": self.PLATFORM,
                    "os": "ios",
                    "media": media[:200] if media else "",
                })

            conn.close()
            return {
                "status": "success" if messages else "empty",
                "messages": messages,
                "message_count": len(messages),
                "source": f"ios:{msg_table}",
                "platform": self.PLATFORM,
            }
        except Exception as e:
            conn.close()
            return {"status": "error", "error": str(e), "messages": []}


# ---------------------------------------------------------------------------
# Signal Extractor
# ---------------------------------------------------------------------------

class SignalExtractor:
    """Extract messages from Signal databases.

    Signal uses SQLCipher-encrypted databases. Without the decryption key,
    we can only:
      - Detect that the database is encrypted
      - Parse any unencrypted backups or plaintext JSON exports
      - Extract metadata from file timestamps and paths

    Full extraction requires key material from the device.
    """

    PLATFORM = "signal"

    def extract(self, db_path: str) -> Dict[str, Any]:
        """Main entry point. Returns whatever is extractable."""
        path = Path(db_path)
        if not path.exists():
            return {"status": "skipped", "error": "Database not found", "messages": []}

        if path.is_file():
            if _is_sqlite(path):
                return self._extract_sqlite(path)
            elif path.suffix.lower() == ".json":
                return self._extract_json_backup(path)
            else:
                return self._extract_plaintext_backup(path)

        if path.is_dir():
            return self._extract_from_directory(path)

        return {"status": "skipped", "error": "Cannot process", "messages": []}

    def _extract_sqlite(self, path: Path) -> Dict[str, Any]:
        """Attempt to open the Signal SQLite database."""
        conn = _safe_db_connect(path)
        if not conn:
            # Very likely SQLCipher encrypted
            return {
                "status": "skipped",
                "error": "Signal database appears encrypted (SQLCipher). Decryption key required.",
                "messages": [],
                "encrypted": True,
                "platform": self.PLATFORM,
            }

        messages: List[Dict[str, Any]] = []
        try:
            # Signal plaintext databases may contain mms/sms tables (SMS fallback)
            # or thread/part tables from unencrypted backups
            for table in ["mms", "sms"]:
                if not _sqlite_table_exists(conn, table):
                    continue
                cols = _sqlite_table_columns(conn, table)

                body_col = _safe_column_lookup(cols, ["body", "message", "text", "content", "subject"])
                addr_col = _safe_column_lookup(cols, ["address", "sender", "from_address", "recipient"])
                ts_col = _safe_column_lookup(cols, ["date", "date_sent", "timestamp", "received_at"])
                type_col = _safe_column_lookup(cols, ["type", "msg_type", "message_type"])

                if not body_col:
                    continue

                select_cols = [c for c in [body_col, addr_col, ts_col, type_col] if c]
                try:
                    cur = conn.execute(
                        f"SELECT {', '.join(select_cols)} FROM {table} "
                        f"WHERE {body_col} IS NOT NULL AND {body_col} != '' "
                        f"ORDER BY {ts_col or 'rowid'} DESC LIMIT 5000"
                    )
                except sqlite3.OperationalError:
                    continue

                for row in cur.fetchall():
                    rowd = dict(row)
                    body = str(rowd.get(body_col, ""))
                    if not body.strip():
                        continue

                    addr = str(rowd.get(addr_col, "")) if addr_col else ""
                    ts_raw = rowd.get(ts_col) if ts_col else None
                    ts = _unix_epoch_to_iso(ts_raw)
                    msg_type = str(rowd.get(type_col, "")) if type_col else ""

                    # Signal type codes: 1=received, 2=sent, etc.
                    is_sent = "sent" in msg_type.lower() or msg_type == "2"

                    messages.append({
                        "from": "self" if is_sent else addr,
                        "to": [addr] if is_sent else ["self"],
                        "body": body[:1000],
                        "timestamp": ts,
                        "platform": self.PLATFORM,
                        "table_source": table,
                    })

            conn.close()
            return {
                "status": "success" if messages else "empty",
                "messages": messages,
                "message_count": len(messages),
                "platform": self.PLATFORM,
            }
        except Exception as e:
            conn.close()
            return {"status": "error", "error": str(e), "messages": []}

    def _extract_json_backup(self, path: Path) -> Dict[str, Any]:
        """Parse a Signal JSON backup/export file."""
        messages: List[Dict[str, Any]] = []
        try:
            data = json.loads(path.read_text())
            conversations = data if isinstance(data, list) else data.get("conversations", [data])

            for conv in conversations:
                if isinstance(conv, dict):
                    msgs = conv.get("messages", [conv])
                elif isinstance(conv, list):
                    msgs = conv
                else:
                    continue

                for msg in msgs:
                    if not isinstance(msg, dict):
                        continue
                    body = msg.get("body") or msg.get("text") or msg.get("message", "")
                    if not body:
                        continue
                    sender = msg.get("source") or msg.get("sender") or msg.get("from", "")
                    ts_raw = msg.get("timestamp") or msg.get("date") or msg.get("sent_at")
                    ts = _unix_epoch_to_iso(ts_raw)
                    recipient = msg.get("destination") or msg.get("to") or msg.get("recipient", "")
                    messages.append({
                        "from": sender,
                        "to": [recipient] if recipient else [],
                        "body": str(body)[:1000],
                        "timestamp": ts,
                        "platform": self.PLATFORM,
                    })
        except (json.JSONDecodeError, UnicodeDecodeError, OSError) as e:
            return {"status": "error", "error": str(e), "messages": []}

        return {
            "status": "success" if messages else "empty",
            "messages": messages,
            "message_count": len(messages),
            "platform": self.PLATFORM,
        }

    def _extract_plaintext_backup(self, path: Path) -> Dict[str, Any]:
        """Extract strings from a Signal backup file and look for message patterns."""
        messages: List[Dict[str, Any]] = []
        try:
            result = subprocess.run(
                ["strings", "-n", "10", str(path)],
                capture_output=True, text=True, timeout=30,
            )
            # Look for message-like patterns: timestamp followed by text
            for line in result.stdout.splitlines():
                line = line.strip()
                if len(line) < 20:
                    continue
                # Simple heuristic: lines with a date-like prefix
                match = re.match(r"(\d{4}[-/]\d{2}[-/]\d{2}[T\s]\d{2}:\d{2})[:\s]+(.+)", line)
                if match:
                    messages.append({
                        "from": "unknown",
                        "to": [],
                        "body": match.group(2)[:500],
                        "timestamp": match.group(1),
                        "platform": self.PLATFORM,
                        "source": "strings_extraction",
                    })
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass

        return {
            "status": "success" if messages else "empty",
            "messages": messages,
            "message_count": len(messages),
            "platform": self.PLATFORM,
        }

    def _extract_from_directory(self, root: Path) -> Dict[str, Any]:
        """Search directory for Signal artifacts."""
        all_msgs: List[Dict[str, Any]] = []
        encrypted_dbs: List[str] = []

        for db_name in ["signal.db", "signaldb", "messages.db", "backup.db"]:
            for found in root.rglob(db_name):
                try:
                    result = self._extract_sqlite(found)
                    if result.get("status") == "success":
                        all_msgs.extend(result.get("messages", []))
                    if result.get("encrypted"):
                        encrypted_dbs.append(str(found))
                except Exception:
                    pass

        # Also check for JSON exports
        for json_file in root.rglob("*.json"):
            if "signal" in json_file.name.lower():
                try:
                    result = self._extract_json_backup(json_file)
                    if result.get("status") == "success":
                        all_msgs.extend(result.get("messages", []))
                except Exception:
                    pass

        return {
            "status": "success" if all_msgs else "empty",
            "messages": all_msgs,
            "message_count": len(all_msgs),
            "encrypted_databases": encrypted_dbs,
            "platform": self.PLATFORM,
        }


# ---------------------------------------------------------------------------
# Slack Extractor
# ---------------------------------------------------------------------------

class SlackExtractor:
    """Extract messages from Slack LevelDB stores.

    Slack desktop app uses LevelDB for local caching:
      Windows: %APPDATA%/Slack/Local Storage/leveldb/
      macOS:   ~/Library/Application Support/Slack/Local Storage/leveldb/
      Linux:   ~/.config/Slack/Local Storage/leveldb/

    The LevelDB stores JSON blobs with channel, message, and user data.
    """

    PLATFORM = "slack"

    def extract(self, db_path: str) -> Dict[str, Any]:
        """Main entry point. Accepts a directory (leveldb) or single file."""
        path = Path(db_path)
        if not path.exists():
            return {"status": "skipped", "error": "Path not found", "messages": []}

        if path.is_dir():
            return self._extract_leveldb(path)

        return self._extract_single_file(path)

    def _extract_leveldb(self, leveldb_dir: Path) -> Dict[str, Any]:
        """Extract JSON blobs from a LevelDB directory using strings + parsing."""
        messages: List[Dict[str, Any]] = []
        workspaces: List[str] = []
        channels: List[str] = []

        # Collect all .ldb and .log files
        db_files = list(leveldb_dir.glob("*.ldb")) + list(leveldb_dir.glob("*.log"))
        if not db_files:
            db_files = [f for f in leveldb_dir.iterdir() if f.is_file()]

        # Extract strings from each file
        for dbf in db_files[:20]:
            try:
                result = subprocess.run(
                    ["strings", "-n", "20", str(dbf)],
                    capture_output=True, text=True, timeout=15,
                )
                for line in result.stdout.splitlines():
                    line = line.strip()
                    if not line:
                        continue

                    # Try to parse as JSON
                    parsed = self._try_parse_slack_json(line)
                    if parsed:
                        if parsed.get("type") == "workspace":
                            workspaces.append(parsed.get("name", ""))
                        elif parsed.get("type") == "channel":
                            channels.append(parsed.get("name", ""))
                        elif parsed.get("type") in ("message", "text"):
                            messages.append(parsed)
                        elif parsed.get("text") or parsed.get("body"):
                            messages.append(parsed)

                    # Slack-specific patterns in non-JSON strings
                    if "slack.com" in line.lower() or "workspace" in line.lower():
                        ws_match = re.search(r"([\w\-]+)\.slack\.com", line)
                        if ws_match:
                            workspaces.append(ws_match.group(1))
            except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
                continue

        return {
            "status": "success" if messages else "empty",
            "messages": messages,
            "message_count": len(messages),
            "workspaces": list(set(workspaces))[:20],
            "channels": list(set(channels))[:50],
            "files_scanned": len(db_files),
            "platform": self.PLATFORM,
        }

    def _try_parse_slack_json(self, text: str) -> Optional[Dict[str, Any]]:
        """Attempt to parse a line as Slack JSON data."""
        # Find JSON boundaries in the string
        json_start = text.find("{")
        json_end = text.rfind("}") + 1
        if json_start < 0 or json_end <= json_start:
            return None

        json_str = text[json_start:json_end]
        try:
            data = json.loads(json_str)
        except json.JSONDecodeError:
            return None

        if not isinstance(data, dict):
            return None

        # Extract message fields from various Slack JSON formats
        msg: Dict[str, Any] = {
            "platform": self.PLATFORM,
        }

        # User
        user = (
            data.get("user")
            or data.get("username")
            or data.get("author")
            or data.get("sender")
            or (data.get("message", {}).get("user") if isinstance(data.get("message"), dict) else None)
            or ""
        )
        msg["from"] = str(user) if user else "unknown"

        # Text
        text = (
            data.get("text")
            or data.get("body")
            or data.get("message")
            or data.get("content")
            or (data.get("message", {}).get("text") if isinstance(data.get("message"), dict) else None)
        )
        if not text:
            return None
        msg["body"] = str(text)[:1000]

        # Timestamp
        ts = (
            data.get("ts")
            or data.get("timestamp")
            or data.get("time")
            or data.get("created")
        )
        if ts:
            try:
                ts_float = float(ts)
                if ts_float > 1e12:
                    ts_float /= 1000.0
                msg["timestamp"] = datetime.fromtimestamp(ts_float, tz=timezone.utc).isoformat()
            except (ValueError, TypeError, OSError, OverflowError):
                msg["timestamp"] = str(ts)

        # Channel
        channel = (
            data.get("channel")
            or data.get("channel_name")
            or data.get("name")
            or data.get("conversation")
        )
        if channel:
            msg["channel"] = str(channel)

        # Type indicator
        msg["type"] = (
            data.get("type")
            or data.get("subtype")
            or "message"
        )

        # Team/workspace
        team = data.get("team") or data.get("team_id") or data.get("workspace")
        if team:
            msg["workspace"] = str(team)

        # Recipient (DM channel)
        if data.get("channel_type") == "im" or "dm" in str(data.get("channel", "")).lower():
            msg["to"] = [str(data.get("user", ""))] if data.get("user") else []

        return msg

    def _extract_single_file(self, path: Path) -> Dict[str, Any]:
        """Fallback: extract strings from a single file."""
        return self._extract_leveldb(path.parent)


# ---------------------------------------------------------------------------
# Teams Extractor
# ---------------------------------------------------------------------------

class TeamsExtractor:
    """Extract messages from Microsoft Teams local storage.

    Teams (PWA/Electron) stores data in:
      Windows: %APPDATA%/Microsoft/Teams/
      macOS:   ~/Library/Application Support/Microsoft/Teams/

    Storage options include LevelDB (older electron), IndexedDB,
    and SQLite (newer PWA versions).
    """

    PLATFORM = "teams"

    def extract(self, db_path: str) -> Dict[str, Any]:
        """Main entry point."""
        path = Path(db_path)
        if not path.exists():
            return {"status": "skipped", "error": "Path not found", "messages": []}

        if path.is_dir():
            return self._extract_from_directory(path)

        if path.is_file():
            if path.name.endswith(".sqlite") or path.name.endswith(".db"):
                return self._extract_sqlite(path)
            return self._extract_leveldb_file(path)

        return {"status": "skipped", "error": "Cannot process", "messages": []}

    def _extract_from_directory(self, root: Path) -> Dict[str, Any]:
        """Search Teams data directory for all storage types."""
        all_msgs: List[Dict[str, Any]] = []
        workspaces: List[str] = []
        errors: List[str] = []

        # 1. Look for LevelDB storage
        leveldb_dirs = []
        for name in ["leveldb", "Local Storage"]:
            for found in root.rglob(name):
                if found.is_dir():
                    leveldb_dirs.append(found)

        for ldb_dir in leveldb_dirs:
            try:
                result = self._extract_leveldb_dir(ldb_dir)
                if result.get("status") == "success":
                    all_msgs.extend(result.get("messages", []))
            except Exception as e:
                errors.append(f"leveldb {ldb_dir}: {e}")

        # 2. Look for SQLite databases
        for sqlite_file in _find_files(root, ["teams.sqlite", "skype.db", "s4l.db", "teams_local.sqlite"]):
            try:
                result = self._extract_sqlite(sqlite_file)
                if result.get("status") == "success":
                    all_msgs.extend(result.get("messages", []))
            except Exception as e:
                errors.append(f"sqlite {sqlite_file.name}: {e}")

        # 3. Look for IndexedDB (.leveldb)
        for idb in root.rglob("*.leveldb"):
            if idb.is_dir():
                try:
                    result = self._extract_leveldb_dir(idb)
                    if result.get("status") == "success":
                        all_msgs.extend(result.get("messages", []))
                except Exception as e:
                    errors.append(f"indexeddb {idb}: {e}")

        # 4. Extract JSON from storage files (cookies, localstorage, sessionstorage)
        for storage_dir in root.rglob("*"):
            if not storage_dir.is_dir():
                continue
            dirname = storage_dir.name.lower()
            if any(kw in dirname for kw in ["storage", "cache", "data"]):
                for f in storage_dir.iterdir():
                    if f.is_file() and f.suffix.lower() in (".json", ".log", ".txt"):
                        try:
                            data = json.loads(f.read_text(errors="replace"))
                            extracted = self._parse_teams_json(data)
                            all_msgs.extend(extracted)
                        except (json.JSONDecodeError, UnicodeDecodeError, OSError):
                            pass

        return {
            "status": "success" if all_msgs else "empty",
            "messages": all_msgs,
            "message_count": len(all_msgs),
            "workspaces": workspaces,
            "errors": errors[:5],
            "platform": self.PLATFORM,
        }

    def _extract_leveldb_dir(self, leveldb_dir: Path) -> Dict[str, Any]:
        """Extract strings from a LevelDB directory and parse for Teams data."""
        messages: List[Dict[str, Any]] = []
        db_files = list(leveldb_dir.glob("*.ldb")) + list(leveldb_dir.glob("*.log"))
        if not db_files:
            db_files = [f for f in leveldb_dir.iterdir() if f.is_file()]

        for dbf in db_files[:20]:
            try:
                result = subprocess.run(
                    ["strings", "-n", "30", str(dbf)],
                    capture_output=True, text=True, timeout=15,
                )
                for line in result.stdout.splitlines():
                    line = line.strip()
                    if not line:
                        continue

                    # Try JSON parsing
                    msg = self._try_parse_teams_json(line)
                    if msg:
                        messages.append(msg)

                    # Teams-specific patterns in raw strings
                    if "teams.microsoft.com" in line or "microsoftteams" in line.lower():
                        # Extract user/tenant info from URLs
                        pass

            except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
                continue

        return {
            "status": "success" if messages else "empty",
            "messages": messages,
            "message_count": len(messages),
            "platform": self.PLATFORM,
        }

    def _extract_leveldb_file(self, path: Path) -> Dict[str, Any]:
        """Single leveldb file extraction."""
        messages: List[Dict[str, Any]] = []
        try:
            result = subprocess.run(
                ["strings", "-n", "30", str(path)],
                capture_output=True, text=True, timeout=15,
            )
            for line in result.stdout.splitlines():
                line = line.strip()
                if line:
                    msg = self._try_parse_teams_json(line)
                    if msg:
                        messages.append(msg)
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass

        return {
            "status": "success" if messages else "empty",
            "messages": messages,
            "message_count": len(messages),
            "platform": self.PLATFORM,
        }

    def _extract_sqlite(self, path: Path) -> Dict[str, Any]:
        """Extract from Teams SQLite database."""
        conn = _safe_db_connect(path)
        if not conn:
            return {"status": "error", "error": "Cannot open Teams SQLite", "messages": []}

        messages: List[Dict[str, Any]] = []
        try:
            # Probe for message-like tables
            cur = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND (name LIKE '%message%' OR name LIKE '%conversation%' OR name LIKE '%chat%')"
            )
            msg_tables = [row[0] for row in cur.fetchall()]

            for table in msg_tables:
                cols = _sqlite_table_columns(conn, table)
                body_col = _safe_column_lookup(cols, [
                    "content", "body", "text", "message", "message_content",
                    "composemessagecontent", "implicitcontent",
                ])
                sender_col = _safe_column_lookup(cols, [
                    "sender", "from", "author", "from_id", "sender_id",
                    "userid", "user_id", "participantid",
                ])
                ts_col = _safe_column_lookup(cols, [
                    "timestamp", "created", "created_at", "arrivaltime",
                    "messagetime", "composetime", "date",
                ])

                if not body_col:
                    continue

                select_cols = [c for c in [body_col, sender_col, ts_col] if c]
                try:
                    cur2 = conn.execute(
                        f"SELECT {', '.join(select_cols)} FROM {table} "
                        f"WHERE {body_col} IS NOT NULL AND {body_col} != '' "
                        f"ORDER BY {ts_col or 'rowid'} DESC LIMIT 5000"
                    )
                except sqlite3.OperationalError:
                    continue

                for row in cur2.fetchall():
                    rowd = dict(row)
                    body = str(rowd.get(body_col, ""))
                    if not body.strip():
                        continue

                    sender = str(rowd.get(sender_col, "")) if sender_col else "unknown"
                    ts_raw = rowd.get(ts_col) if ts_col else None
                    ts = _unix_epoch_to_iso(ts_raw)

                    messages.append({
                        "from": sender,
                        "to": [],
                        "body": body[:1000],
                        "timestamp": ts,
                        "platform": self.PLATFORM,
                        "table_source": table,
                    })

            conn.close()
        except Exception as e:
            conn.close()
            return {"status": "error", "error": str(e), "messages": []}

        return {
            "status": "success" if messages else "empty",
            "messages": messages,
            "message_count": len(messages),
            "platform": self.PLATFORM,
        }

    def _try_parse_teams_json(self, text: str) -> Optional[Dict[str, Any]]:
        """Try to parse a line as a Teams JSON message."""
        json_start = text.find("{")
        json_end = text.rfind("}") + 1
        if json_start < 0 or json_end <= json_start:
            return None

        json_str = text[json_start:json_end]
        try:
            data = json.loads(json_str)
        except json.JSONDecodeError:
            return None

        if not isinstance(data, dict):
            return None

        # Teams message fields
        text_content = (
            data.get("content")
            or data.get("body")
            or data.get("text")
            or data.get("message")
        )
        if not text_content:
            return None

        msg: Dict[str, Any] = {
            "from": str(data.get("from") or data.get("sender") or data.get("author") or data.get("user") or "unknown"),
            "body": str(text_content)[:1000],
            "platform": self.PLATFORM,
        }

        ts_raw = (
            data.get("timestamp")
            or data.get("createdDateTime")
            or data.get("created")
            or data.get("time")
        )
        if ts_raw:
            try:
                msg["timestamp"] = _unix_epoch_to_iso(ts_raw)
            except Exception:
                msg["timestamp"] = str(ts_raw)

        channel = data.get("channelIdentity") or data.get("channel") or data.get("chatId") or data.get("conversationId")
        if channel:
            msg["channel"] = str(channel)

        return msg

    def _parse_teams_json(self, data: Any) -> List[Dict[str, Any]]:
        """Recursively extract messages from parsed JSON structures."""
        messages: List[Dict[str, Any]] = []

        if isinstance(data, list):
            for item in data:
                messages.extend(self._parse_teams_json(item))
        elif isinstance(data, dict):
            # Direct message
            content = data.get("content") or data.get("body") or data.get("text")
            if content and isinstance(content, str) and len(content) >= 2:
                msg = self._try_parse_teams_json(json.dumps(data))
                if msg:
                    messages.append(msg)

            # Recurse into nested structures
            for key in ("messages", "events", "items", "data", "payload", "body"):
                val = data.get(key)
                if isinstance(val, (list, dict)):
                    messages.extend(self._parse_teams_json(val))

        return messages


# ---------------------------------------------------------------------------
# Skype Extractor
# ---------------------------------------------------------------------------

class SkypeExtractor:
    """Extract messages from Skype main.db (SQLite).

    Classic/desktop Skype stores data in:
      Windows: %APPDATA%/Skype/<username>/main.db
      macOS:   ~/Library/Application Support/Skype/<username>/main.db
      Linux:   ~/.Skype/<username>/main.db

    Schema (classic Skype):
      Messages:      id, chatname, author, from_dispname, body_xml, timestamp, ...
      Conversations: id, identity, displayname, ...
      Contacts:      id, skypename, fullname, ...
      Calls:         id, host_identity, current_video_audience, begin_timestamp, ...
      Transfers:     id, chatname, filename, filesize, partner_handle, ...
    """

    PLATFORM = "skype"

    def extract(self, db_path: str) -> Dict[str, Any]:
        """Main entry point."""
        path = Path(db_path)
        if not path.exists():
            return {"status": "skipped", "error": "Database not found", "messages": []}

        if path.is_file() and _is_sqlite(path):
            return self._extract_main_db(path)

        if path.is_dir():
            return self._extract_from_directory(path)

        return {"status": "skipped", "error": "Not a valid Skype database", "messages": []}

    def _extract_main_db(self, path: Path) -> Dict[str, Any]:
        """Full extraction from main.db."""
        conn = _safe_db_connect(path)
        if not conn:
            return {"status": "error", "error": "Cannot open Skype main.db", "messages": []}

        result: Dict[str, Any] = {
            "status": "empty",
            "messages": [],
            "contacts": [],
            "calls": [],
            "transfers": [],
            "message_count": 0,
            "contact_count": 0,
            "call_count": 0,
            "platform": self.PLATFORM,
        }

        try:
            # Extract contacts
            if _sqlite_table_exists(conn, "Contacts"):
                cols = _sqlite_table_columns(conn, "Contacts")
                name_col = _safe_column_lookup(cols, ["skypename", "displayname", "fullname", "given_displayname"])
                if name_col:
                    # Build dynamic column list from available columns only
                    _extra_cols = []
                    for _ec in ["skypename", "fullname", "birthday", "phone_mobile",
                                 "phone_office", "emails", "country", "city"]:
                        if _ec in cols:
                            _extra_cols.append(_ec)
                    _col_list = ", ".join([name_col] + _extra_cols) if _extra_cols else name_col
                    cur = conn.execute(f"SELECT {_col_list} FROM Contacts LIMIT 10000")
                    for row in cur.fetchall():
                        rd = dict(row)
                        result["contacts"].append({
                            "skypename": str(rd.get("skypename", "")),
                            "display_name": str(rd.get(name_col, "")) if name_col else "",
                            "fullname": str(rd.get("fullname", "")),
                            "emails": str(rd.get("emails", "")),
                        })

            result["contact_count"] = len(result["contacts"])

            # Extract messages
            if _sqlite_table_exists(conn, "Messages"):
                cols = _sqlite_table_columns(conn, "Messages")
                body_col = _safe_column_lookup(cols, ["body_xml", "body", "message", "content", "text"])
                author_col = _safe_column_lookup(cols, ["author", "from_dispname", "sender", "creator"])
                chat_col = _safe_column_lookup(cols, ["chatname", "conversation", "chat"])
                ts_col = _safe_column_lookup(cols, ["timestamp", "time", "created", "sent"])

                if body_col:
                    select_cols = [c for c in [body_col, author_col, chat_col, ts_col] if c]
                    cur = conn.execute(
                        f"SELECT {', '.join(select_cols)} FROM Messages "
                        f"WHERE {body_col} IS NOT NULL AND {body_col} != '' "
                        f"ORDER BY {ts_col or 'id'} DESC LIMIT 10000"
                    )

                    for row in cur.fetchall():
                        rd = dict(row)
                        body = str(rd.get(body_col, ""))
                        if not body.strip():
                            continue

                        # Strip XML/HTML from body_xml
                        body_clean = _strip_skype_xml(body)

                        author = str(rd.get(author_col, "")) if author_col else "unknown"
                        chat = str(rd.get(chat_col, "")) if chat_col else ""
                        ts_raw = rd.get(ts_col) if ts_col else None
                        ts = _unix_epoch_to_iso(ts_raw)

                        result["messages"].append({
                            "from": author,
                            "to": [chat] if chat else [],
                            "body": body_clean[:1000],
                            "timestamp": ts,
                            "platform": self.PLATFORM,
                            "chat_name": chat,
                        })

            result["message_count"] = len(result["messages"])

            # Extract calls
            if _sqlite_table_exists(conn, "Calls"):
                cols = _sqlite_table_columns(conn, "Calls")
                host_col = _safe_column_lookup(cols, ["host_identity", "host", "caller"])
                ts_col = _safe_column_lookup(cols, ["begin_timestamp", "start_timestamp", "timestamp"])
                dur_col = _safe_column_lookup(cols, ["duration", "call_duration"])

                if host_col:
                    select_cols = [c for c in [host_col, ts_col, dur_col] if c]
                    cur = conn.execute(
                        f"SELECT {', '.join(select_cols)} FROM Calls ORDER BY {ts_col or 'id'} DESC LIMIT 5000"
                    )
                    for row in cur.fetchall():
                        rd = dict(row)
                        ts_raw = rd.get(ts_col) if ts_col else None
                        result["calls"].append({
                            "host": str(rd.get(host_col, "")),
                            "timestamp": _unix_epoch_to_iso(ts_raw),
                            "duration": str(rd.get(dur_col, "")) if dur_col else "",
                        })

            result["call_count"] = len(result["calls"])

            # Extract file transfers
            if _sqlite_table_exists(conn, "Transfers"):
                cols = _sqlite_table_columns(conn, "Transfers")
                file_col = _safe_column_lookup(cols, ["filename", "file_name", "name"])
                partner_col = _safe_column_lookup(cols, ["partner_handle", "partner", "sender_handle"])
                size_col = _safe_column_lookup(cols, ["filesize", "size", "file_size"])

                if file_col:
                    select_cols = [c for c in [file_col, partner_col, size_col] if c]
                    cur = conn.execute(
                        f"SELECT {', '.join(select_cols)} FROM Transfers LIMIT 5000"
                    )
                    for row in cur.fetchall():
                        rd = dict(row)
                        result["transfers"].append({
                            "filename": str(rd.get(file_col, "")),
                            "partner": str(rd.get(partner_col, "")) if partner_col else "",
                            "size": str(rd.get(size_col, "")) if size_col else "",
                        })

            result["status"] = "success" if result["messages"] else "partial"
            conn.close()
        except Exception as e:
            conn.close()
            return {"status": "error", "error": str(e), "messages": []}

        return result

    def _extract_from_directory(self, root: Path) -> Dict[str, Any]:
        """Search directory for Skype main.db files."""
        all_msgs: List[Dict[str, Any]] = []
        all_contacts: List[Dict[str, Any]] = []
        all_calls: List[Dict[str, Any]] = []

        for db_name in ["main.db", "skype.db"]:
            for found in root.rglob(db_name):
                try:
                    result = self._extract_main_db(found)
                    if result.get("status") in ("success", "partial"):
                        all_msgs.extend(result.get("messages", []))
                        all_contacts.extend(result.get("contacts", []))
                        all_calls.extend(result.get("calls", []))
                except Exception:
                    pass

        return {
            "status": "success" if all_msgs else "empty",
            "messages": all_msgs,
            "contacts": all_contacts,
            "calls": all_calls,
            "message_count": len(all_msgs),
            "contact_count": len(all_contacts),
            "platform": self.PLATFORM,
        }


def _strip_skype_xml(text: str) -> str:
    """Strip Skype XML markup from message bodies."""
    # Remove XML tags: <bRaw>...</bRaw>, <files>, <ss>, etc.
    text = re.sub(r"<[^>]+>", "", text)
    # Common entities
    text = text.replace("&amp;", "&")
    text = text.replace("&lt;", "<")
    text = text.replace("&gt;", ">")
    text = text.replace("&quot;", '"')
    text = text.replace("&apos;", "'")
    return text.strip()


# ---------------------------------------------------------------------------
# Unified factory
# ---------------------------------------------------------------------------

def get_extractor(platform: str):
    """Return the appropriate extractor instance for a platform."""
    extractors = {
        "whatsapp": WhatsAppExtractor,
        "signal": SignalExtractor,
        "slack": SlackExtractor,
        "teams": TeamsExtractor,
        "skype": SkypeExtractor,
    }
    cls = extractors.get(platform.lower())
    if cls:
        return cls()
    return None


def extract_all_from_evidence(evidence_dir: str) -> Dict[str, Any]:
    """Scan an evidence directory and extract from all supported platforms.

    Returns a dict mapping platform → extraction result.
    """
    ev_path = Path(evidence_dir)
    results: Dict[str, Any] = {}

    # WhatsApp
    wa = WhatsAppExtractor()
    results["whatsapp"] = wa.extract(str(ev_path))

    # Signal
    sig = SignalExtractor()
    results["signal"] = sig.extract(str(ev_path))

    # Slack - look for LevelDB directories
    slack = SlackExtractor()
    for ldb in ev_path.rglob("leveldb"):
        if ldb.is_dir():
            slack_result = slack.extract(str(ldb))
            if slack_result.get("status") == "success":
                results.setdefault("slack", slack_result)
                if not results["slack"].get("messages"):
                    results["slack"] = slack_result
                else:
                    results["slack"]["messages"].extend(slack_result.get("messages", []))
                    results["slack"]["message_count"] = len(results["slack"]["messages"])

    if "slack" not in results:
        results["slack"] = {"status": "not_found", "messages": [], "platform": "slack"}

    # Teams
    teams = TeamsExtractor()
    teams_dirs = list(ev_path.rglob("Teams")) + list(ev_path.rglob("Microsoft/Teams"))
    if teams_dirs:
        team_msgs: List[Dict[str, Any]] = []
        for td in teams_dirs[:3]:
            tr = teams.extract(str(td))
            if tr.get("status") == "success":
                team_msgs.extend(tr.get("messages", []))
        results["teams"] = {
            "status": "success" if team_msgs else "empty",
            "messages": team_msgs,
            "message_count": len(team_msgs),
            "platform": "teams",
        }
    else:
        # Fallback: scan full evidence for Teams DBs
        teams_result = teams.extract(str(ev_path))
        results["teams"] = teams_result

    # Skype
    skype = SkypeExtractor()
    skype_dbs = list(ev_path.rglob("main.db"))
    if skype_dbs:
        all_skype: Dict[str, Any] = {"status": "empty", "messages": [], "contacts": [], "calls": [], "platform": "skype"}
        for db in skype_dbs[:10]:
            sr = skype.extract(str(db))
            if sr.get("status") in ("success", "partial"):
                all_skype["messages"].extend(sr.get("messages", []))
                all_skype["contacts"].extend(sr.get("contacts", []))
                all_skype["calls"].extend(sr.get("calls", []))
                all_skype["status"] = "success"
        all_skype["message_count"] = len(all_skype["messages"])
        all_skype["contact_count"] = len(all_skype["contacts"])
        results["skype"] = all_skype

    if "skype" not in results:
        results["skype"] = {"status": "not_found", "messages": [], "platform": "skype"}

    return results


def extract_to_findings_format(extraction_result: Dict[str, Any], platform: str) -> List[Dict[str, Any]]:
    """Convert extraction results into findings-compatible format.

    Each finding record has: playbook, module, function, output (text),
    so CommunicationsAnalyzer can parse them.
    """
    findings: List[Dict[str, Any]] = []
    messages = extraction_result.get("messages", [])
    if not messages:
        return findings

    # Batch messages into chunks to keep output manageable
    chunk_size = 50
    for i in range(0, len(messages), chunk_size):
        chunk = messages[i:i + chunk_size]
        output_lines = []
        for msg in chunk:
            sender = msg.get("from", "unknown")
            recipients = msg.get("to", [])
            body = msg.get("body", "")
            ts = msg.get("timestamp", "")

            output_lines.append(f"sender: {sender}")
            if recipients:
                output_lines.append(f"recipient: {', '.join(recipients)}")
            output_lines.append(f"message: {body[:300]}")
            if ts:
                output_lines.append(f"timestamp: {ts}")
            output_lines.append("")  # blank separator

        findings.append({
            "playbook": "PB-SIFT-031",
            "module": "collaboration",
            "function": f"extract_{platform}",
            "output": "\n".join(output_lines),
            "platform": platform,
            "message_count": len(chunk),
            "total_messages": len(messages),
        })

    return findings
