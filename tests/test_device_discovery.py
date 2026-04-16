"""
Tests for DeviceDiscovery static helper methods.

DeviceDiscovery.__init__ requires an orchestrator; we pass a MagicMock for
tests that only call static methods.
"""

import pytest
import sys, os
from unittest.mock import MagicMock
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from device_discovery import DeviceDiscovery

# Instance with mock orchestrator for static method testing
_dd = DeviceDiscovery(MagicMock())


# ---------------------------------------------------------------------------
# _normalize_username
# ---------------------------------------------------------------------------

class TestNormalizeUsername:

    def test_plain_username_lowercased(self):
        assert DeviceDiscovery._normalize_username("JohnDoe") == "johndoe"

    def test_domain_prefix_stripped(self):
        assert DeviceDiscovery._normalize_username("CORP\\dsmith") == "dsmith"

    def test_upn_suffix_stripped(self):
        assert DeviceDiscovery._normalize_username("dsmith@corp.local") == "dsmith"

    def test_leading_trailing_whitespace_stripped(self):
        assert DeviceDiscovery._normalize_username("  alice  ") == "alice"

    def test_domain_and_mixed_case(self):
        assert DeviceDiscovery._normalize_username("DOMAIN\\Alice") == "alice"

    def test_empty_string(self):
        assert DeviceDiscovery._normalize_username("") == ""

    def test_only_domain_backslash(self):
        # "CORP\" with nothing after — split gives ["CORP", ""], last part is ""
        assert DeviceDiscovery._normalize_username("CORP\\") == ""

    def test_multiple_backslashes_takes_last_segment(self):
        assert DeviceDiscovery._normalize_username("A\\B\\carol") == "carol"

    def test_upn_with_subdomain(self):
        assert DeviceDiscovery._normalize_username("bob@sub.corp.example.com") == "bob"


# ---------------------------------------------------------------------------
# _sanitize_device_id
# ---------------------------------------------------------------------------

class TestSanitizeDeviceId:

    def test_simple_name_unchanged(self):
        assert DeviceDiscovery._sanitize_device_id("laptop1") == "laptop1"

    def test_spaces_replaced_with_underscore(self):
        result = DeviceDiscovery._sanitize_device_id("suspect pc")
        assert " " not in result
        assert "_" in result

    def test_dots_replaced(self):
        result = DeviceDiscovery._sanitize_device_id("pc.corp.local")
        assert "." not in result

    def test_leading_underscores_stripped(self):
        result = DeviceDiscovery._sanitize_device_id("___name")
        assert not result.startswith("_")

    def test_empty_string_returns_unknown_device(self):
        assert DeviceDiscovery._sanitize_device_id("") == "unknown_device"

    def test_only_special_chars_returns_unknown_device(self):
        assert DeviceDiscovery._sanitize_device_id("...") == "unknown_device"

    def test_alphanumeric_dashes_underscores_preserved(self):
        name = "PC-001_lab"
        assert DeviceDiscovery._sanitize_device_id(name) == name

    def test_slashes_replaced(self):
        result = DeviceDiscovery._sanitize_device_id("/evidence/pc1")
        assert "/" not in result

    def test_unicode_chars_replaced(self):
        result = DeviceDiscovery._sanitize_device_id("pc-ñ1")
        # ñ is not in [a-zA-Z0-9_-], should be replaced
        assert "ñ" not in result
