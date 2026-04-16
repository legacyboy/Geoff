"""
Tests for SuperTimeline static helper methods.

SuperTimeline only uses stdlib — no mocking needed.
"""

import pytest
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from super_timeline import SuperTimeline


# ---------------------------------------------------------------------------
# _normalize_timestamp
# ---------------------------------------------------------------------------

class TestNormalizeTimestamp:

    def test_empty_string_returns_empty(self):
        assert SuperTimeline._normalize_timestamp("") == ""

    def test_iso_with_t_already_correct(self):
        ts = "2024-03-15T10:30:00Z"
        assert SuperTimeline._normalize_timestamp(ts) == ts

    def test_iso_without_z_gets_z_appended(self):
        result = SuperTimeline._normalize_timestamp("2024-03-15T10:30:00")
        assert result.endswith("Z")

    def test_space_separated_converted_to_t(self):
        result = SuperTimeline._normalize_timestamp("2024-03-15 10:30:00")
        assert "T" in result
        assert result.endswith("Z")

    def test_slash_separated_date_normalized(self):
        result = SuperTimeline._normalize_timestamp("2024/03/15 10:30:00")
        assert "-" in result
        assert "/" not in result

    def test_unix_epoch_seconds_converted(self):
        # 2024-01-01 00:00:00 UTC = 1704067200
        result = SuperTimeline._normalize_timestamp("1704067200")
        assert "2024" in result
        assert result.endswith("Z")

    def test_unix_epoch_milliseconds_converted(self):
        # Same date in milliseconds
        result = SuperTimeline._normalize_timestamp("1704067200000")
        assert "2024" in result
        assert result.endswith("Z")

    def test_windows_filetime_converted(self):
        # Windows FILETIME for 2024-06-01 00:00:00 UTC
        # = 133616736000000000 (verified: (2024-06-01 - 1601-01-01) * 1e7)
        result = SuperTimeline._normalize_timestamp("133616736000000000")
        assert result.endswith("Z")
        assert "2024" in result

    def test_unparseable_returned_as_is(self):
        weird = "not-a-timestamp"
        result = SuperTimeline._normalize_timestamp(weird)
        assert result == weird

    def test_whitespace_stripped(self):
        result = SuperTimeline._normalize_timestamp("  2024-03-15T10:30:00Z  ")
        assert result == "2024-03-15T10:30:00Z"


# ---------------------------------------------------------------------------
# _parse_mactime_body
# ---------------------------------------------------------------------------

class TestParseMactimeBody:

    def test_empty_string_returns_empty_list(self):
        assert SuperTimeline._parse_mactime_body("") == []

    def test_short_lines_skipped(self):
        # Fewer than 9 fields
        raw = "only|four|fields|here"
        assert SuperTimeline._parse_mactime_body(raw) == []

    def test_nine_field_format_parsed(self):
        # md5|path|inode|meta_type|file_type|atime|mtime|ctime|crtime
        raw = "abc123|/etc/passwd|12345|r/rrwxrwxrwx|-|1704067200|1704067100|1704067000|1704066900"
        result = SuperTimeline._parse_mactime_body(raw)
        assert len(result) == 1
        ev = result[0]
        assert ev["path"] == "/etc/passwd"
        assert ev["inode"] == "12345"
        assert ev["timestamps"]["atime"] == 1704067200
        assert ev["timestamps"]["mtime"] == 1704067100

    def test_zero_timestamps_excluded(self):
        # epoch 0 means "not set" — should be excluded from timestamps dict
        raw = "abc|/etc/shadow|99|r/r----|0|0|0|0|0"
        result = SuperTimeline._parse_mactime_body(raw)
        assert len(result) == 1
        assert result[0]["timestamps"] == {}

    def test_thirteen_field_format_parsed(self):
        # md5|name|inode|meta_type|mode|uid|gid|size|atime|mtime|ctime|crtime
        raw = "abc|/home/user/evil.exe|555|r/r----|0755|1000|1000|4096|1704067200|1704067100|1704067000|1704066900"
        result = SuperTimeline._parse_mactime_body(raw)
        assert len(result) == 1
        ev = result[0]
        assert ev["path"] == "/home/user/evil.exe"
        assert ev["timestamps"]["atime"] == 1704067200

    def test_multiple_lines_all_parsed(self):
        lines = [
            "abc|/file1|1|r/r----|0|1000|1000|0|0",
            "def|/file2|2|r/r----|0|2000|2000|0|0",
            "ghi|/file3|3|r/r----|0|3000|3000|0|0",
        ]
        result = SuperTimeline._parse_mactime_body("\n".join(lines))
        assert len(result) == 3
        paths = [e["path"] for e in result]
        assert "/file1" in paths
        assert "/file3" in paths

    def test_non_integer_timestamp_gracefully_skipped(self):
        raw = "abc|/file|1|r/r----|0|not_a_number|1000|0|0"
        result = SuperTimeline._parse_mactime_body(raw)
        assert len(result) == 1
        # atime was bad, mtime was ok
        assert "atime" not in result[0]["timestamps"]
        assert result[0]["timestamps"].get("mtime") == 1000
