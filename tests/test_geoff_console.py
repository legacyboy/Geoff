"""
Tests for pure helper functions in scripts/geoff_console.py.

geoff_console imports `requests` at module level with a graceful sys.exit on
import failure, so we stub it before importing.
"""

import pytest
import sys, os
from pathlib import Path
from unittest.mock import MagicMock

# Stub requests before the module is loaded
if "requests" not in sys.modules:
    sys.modules["requests"] = MagicMock()

SCRIPTS_DIR = os.path.join(os.path.dirname(__file__), "..", "scripts")
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

import geoff_console
from geoff_console import (
    _load_dotenv,
    _progress_bar,
    _render_log_line,
    _BAR_WIDTH,
    GeoffClient,
)

# Force NO_COLOR mode so tests don't need to strip ANSI codes
geoff_console._NO_COLOR = True


# ---------------------------------------------------------------------------
# _load_dotenv
# ---------------------------------------------------------------------------

class TestLoadDotenv:

    def test_returns_dict_for_missing_file(self, tmp_path):
        result = _load_dotenv(tmp_path / "nonexistent.env")
        assert result == {}

    def test_simple_key_value(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text("GEOFF_PORT=9090\n")
        result = _load_dotenv(env_file)
        assert result["GEOFF_PORT"] == "9090"

    def test_comments_ignored(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text("# This is a comment\nGEOFF_PORT=8080\n")
        result = _load_dotenv(env_file)
        assert "GEOFF_PORT" in result
        assert len(result) == 1

    def test_blank_lines_ignored(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text("\n\nKEY=value\n\n")
        result = _load_dotenv(env_file)
        assert result == {"KEY": "value"}

    def test_double_quoted_value_stripped(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text('GEOFF_API_KEY="my-secret-key"\n')
        result = _load_dotenv(env_file)
        assert result["GEOFF_API_KEY"] == "my-secret-key"

    def test_single_quoted_value_stripped(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text("GEOFF_API_KEY='my-secret-key'\n")
        result = _load_dotenv(env_file)
        assert result["GEOFF_API_KEY"] == "my-secret-key"

    def test_value_with_equals_sign(self, tmp_path):
        """Values may contain = signs — only the first = is the delimiter."""
        env_file = tmp_path / ".env"
        env_file.write_text("TOKEN=abc=def=ghi\n")
        result = _load_dotenv(env_file)
        assert result["TOKEN"] == "abc=def=ghi"

    def test_multiple_keys(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text("KEY1=val1\nKEY2=val2\nKEY3=val3\n")
        result = _load_dotenv(env_file)
        assert len(result) == 3
        assert result["KEY3"] == "val3"


# ---------------------------------------------------------------------------
# _progress_bar
# ---------------------------------------------------------------------------

class TestProgressBar:

    def test_zero_percent(self):
        result = _progress_bar(0)
        assert "0%" in result
        assert "░" * _BAR_WIDTH in result

    def test_hundred_percent(self):
        result = _progress_bar(100)
        assert "100%" in result
        assert "█" * _BAR_WIDTH in result

    def test_fifty_percent_balanced(self):
        result = _progress_bar(50)
        filled = _BAR_WIDTH // 2
        assert "█" * filled in result

    def test_result_is_string(self):
        assert isinstance(_progress_bar(42), str)

    def test_total_bar_width_consistent(self):
        # Strip surrounding brackets and percentage — count █+░
        raw = _progress_bar(33)
        bar_chars = raw[1:1 + _BAR_WIDTH]
        assert len(bar_chars) == _BAR_WIDTH
        assert all(c in ("█", "░") for c in bar_chars)

    def test_boundary_value_99(self):
        result = _progress_bar(99)
        assert "99%" in result


# ---------------------------------------------------------------------------
# _render_log_line  (NO_COLOR mode — no ANSI codes)
# ---------------------------------------------------------------------------

class TestRenderLogLine:

    def test_empty_entry_returns_string(self):
        result = _render_log_line({})
        assert isinstance(result, str)

    def test_complete_message_contains_text(self):
        result = _render_log_line({"msg": "✓ step complete"})
        assert "step complete" in result

    def test_fail_message_contains_text(self):
        result = _render_log_line({"msg": "✗ step failed"})
        assert "step failed" in result

    def test_error_message_contains_text(self):
        result = _render_log_line({"msg": "error running tool"})
        assert "error running tool" in result

    def test_timestamp_included_in_output(self):
        result = _render_log_line({"time": "10:30:01", "msg": "doing thing"})
        assert "10:30:01" in result

    def test_skip_message_contains_text(self):
        result = _render_log_line({"msg": "⎘ skipped already-complete step"})
        assert "skipped" in result

    def test_needs_review_message(self):
        result = _render_log_line({"msg": "⚠ needs_review: low confidence"})
        assert "needs_review" in result

    def test_plain_message_passes_through(self):
        result = _render_log_line({"msg": "running pslist"})
        assert "running pslist" in result


# ---------------------------------------------------------------------------
# GeoffClient
# ---------------------------------------------------------------------------

class TestGeoffClient:

    def test_api_key_added_to_headers(self):
        client = GeoffClient("http://localhost:8080", api_key="test-key")
        assert client._headers.get("X-API-Key") == "test-key"

    def test_no_api_key_no_header(self):
        client = GeoffClient("http://localhost:8080", api_key="")
        assert "X-API-Key" not in client._headers

    def test_url_construction(self):
        client = GeoffClient("http://localhost:9999", api_key="")
        assert client._url("/cases") == "http://localhost:9999/cases"

    def test_trailing_slash_stripped_by_config(self):
        """build_config strips trailing slash — verify manually here."""
        server = "http://localhost:8080/"
        client = GeoffClient(server.rstrip("/"), api_key="")
        assert client._url("/cases") == "http://localhost:8080/cases"
