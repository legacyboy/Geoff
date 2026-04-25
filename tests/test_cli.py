#!/usr/bin/env python3
"""
Tests for Geoff CLI (bin/geoff-find-evil) argument parsing and basic behavior.

These tests focus on argument parsing validation rather than full integration,
which would require running the actual find_evil pipeline.
"""

import pytest
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def geoff_cli_path():
    """Return the path to the geoff-find-evil CLI."""
    here = Path(__file__).resolve()
    geoff_root = here.parent.parent
    cli_path = geoff_root / "bin" / "geoff-find-evil"
    return str(cli_path)


# =============================================================================
# Argument Parsing Tests
# =============================================================================

class TestArgumentParsing:
    """Tests for CLI argument parsing."""

    def test_help_flag_shows_usage(self, geoff_cli_path):
        """--help flag should show usage and exit 0."""
        result = subprocess.run(
            [sys.executable, geoff_cli_path, "--help"],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        assert result.returncode == 0
        assert "Usage:" in result.stderr or "geoff-find-evil" in result.stderr

    def test_no_args_shows_usage(self, geoff_cli_path):
        """Running without arguments should show usage."""
        result = subprocess.run(
            [sys.executable, geoff_cli_path],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        assert result.returncode == 0
        assert "Usage:" in result.stderr or "geoff-find-evil" in result.stderr

    def test_help_shows_json_option(self, geoff_cli_path):
        """Help should mention -j/--json option."""
        result = subprocess.run(
            [sys.executable, geoff_cli_path, "--help"],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        assert "-j" in result.stderr or "--json" in result.stderr

    def test_help_shows_output_option(self, geoff_cli_path):
        """Help should mention -o/--output option."""
        result = subprocess.run(
            [sys.executable, geoff_cli_path, "--help"],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        assert "-o" in result.stderr or "--output" in result.stderr

    def test_help_shows_strict_option(self, geoff_cli_path):
        """Help should mention --strict option."""
        result = subprocess.run(
            [sys.executable, geoff_cli_path, "--help"],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        assert "--strict" in result.stderr

    def test_help_shows_no_color_option(self, geoff_cli_path):
        """Help should mention --no-color option."""
        result = subprocess.run(
            [sys.executable, geoff_cli_path, "--help"],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        assert "--no-color" in result.stderr


# =============================================================================
# Exit Code Tests (Basic)
# =============================================================================

class TestExitCodes:
    """Tests for CLI exit codes."""

    def test_help_exits_0(self, geoff_cli_path):
        """--help should exit with code 0."""
        result = subprocess.run(
            [sys.executable, geoff_cli_path, "--help"],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        assert result.returncode == 0

    def test_no_args_exits_0(self, geoff_cli_path):
        """No arguments should exit with code 0 (shows help)."""
        result = subprocess.run(
            [sys.executable, geoff_cli_path],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        assert result.returncode == 0

    def test_missing_path_exits_2(self, geoff_cli_path):
        """Non-existent path should exit with code 2."""
        result = subprocess.run(
            [sys.executable, geoff_cli_path, "/nonexistent/path/xyz123"],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        assert result.returncode == 2
        assert "error" in result.stderr.lower() or "not found" in result.stderr.lower()


# =============================================================================
# Module Import Tests
# =============================================================================

class TestModuleStructure:
    """Tests for CLI module structure."""

    def test_cli_file_exists(self, geoff_cli_path):
        """CLI file should exist."""
        assert Path(geoff_cli_path).exists()

    def test_cli_file_is_executable(self, geoff_cli_path):
        """CLI file should be executable or have shebang."""
        cli_path = Path(geoff_cli_path)
        # Either executable bit or shebang
        is_exec = cli_path.stat().st_mode & 0o111
        has_shebang = cli_path.read_text().startswith('#!')
        assert is_exec or has_shebang

    def test_cli_has_shebang(self, geoff_cli_path):
        """CLI should have python3 shebang."""
        cli_path = Path(geoff_cli_path)
        content = cli_path.read_text()
        assert content.startswith('#!/usr/bin/env python3') or content.startswith('#!python3')


# =============================================================================
# Documentation Tests
# =============================================================================

class TestDocumentation:
    """Tests for CLI documentation."""

    def test_help_mentions_exit_codes(self, geoff_cli_path):
        """Help should document exit codes."""
        result = subprocess.run(
            [sys.executable, geoff_cli_path, "--help"],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        assert "Exit" in result.stderr or "exit" in result.stderr

    def test_help_mentions_evidence_dir(self, geoff_cli_path):
        """Help should mention evidence_dir argument."""
        result = subprocess.run(
            [sys.executable, geoff_cli_path, "--help"],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        assert "evidence" in result.stderr.lower()


# =============================================================================
# Flag Validation Tests
# =============================================================================

class TestFlagValidation:
    """Tests for CLI flag behavior."""

    def test_json_flag_recognized(self, geoff_cli_path):
        """-j flag should be recognized (not cause parse error)."""
        # Just test that it doesn't fail on argument parsing
        # (will fail on missing path, but that's expected)
        result = subprocess.run(
            [sys.executable, geoff_cli_path, "-j", "/nonexistent"],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        # Should fail with path error, not argument parse error
        assert result.returncode == 2
        assert "usage:" not in result.stderr.lower() or "error:" in result.stderr.lower()

    def test_output_flag_recognized(self, geoff_cli_path):
        """-o flag should be recognized."""
        result = subprocess.run(
            [sys.executable, geoff_cli_path, "-o", "/tmp/test.json", "/nonexistent"],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        assert result.returncode == 2

    def test_strict_flag_recognized(self, geoff_cli_path):
        """--strict flag should be recognized."""
        result = subprocess.run(
            [sys.executable, geoff_cli_path, "--strict", "/nonexistent"],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        assert result.returncode == 2

    def test_no_color_flag_recognized(self, geoff_cli_path):
        """--no-color flag should be recognized."""
        result = subprocess.run(
            [sys.executable, geoff_cli_path, "--no-color", "/nonexistent"],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        assert result.returncode == 2

    def test_combined_flags(self, geoff_cli_path):
        """Multiple flags should work together."""
        result = subprocess.run(
            [sys.executable, geoff_cli_path, "-j", "--no-color", "--strict", "/nonexistent"],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        assert result.returncode == 2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
