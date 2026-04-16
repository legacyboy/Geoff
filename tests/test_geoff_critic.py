"""
Tests for GeoffCritic static/pure methods in src/geoff_critic.py.

GeoffCritic imports `requests` (used only in _call_critic_llm).
We stub out requests via sys.modules — conftest.py does NOT stub it,
so we mock it here.
"""

import pytest
import sys, os
from unittest.mock import MagicMock, patch

# Stub 'requests' before importing geoff_critic
if "requests" not in sys.modules:
    sys.modules["requests"] = MagicMock()

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from geoff_critic import GeoffCritic

critic = GeoffCritic()


# ---------------------------------------------------------------------------
# _is_valid_ip
# ---------------------------------------------------------------------------

class TestIsValidIP:

    def test_valid_loopback(self):
        assert GeoffCritic._is_valid_ip("127.0.0.1") is True

    def test_valid_private(self):
        assert GeoffCritic._is_valid_ip("192.168.1.100") is True

    def test_valid_broadcast(self):
        assert GeoffCritic._is_valid_ip("255.255.255.255") is True

    def test_zero_address(self):
        assert GeoffCritic._is_valid_ip("0.0.0.0") is True

    def test_invalid_octet_too_large(self):
        assert GeoffCritic._is_valid_ip("256.0.0.1") is False

    def test_invalid_negative_octet(self):
        assert GeoffCritic._is_valid_ip("-1.0.0.1") is False

    def test_only_three_octets(self):
        assert GeoffCritic._is_valid_ip("192.168.1") is False

    def test_five_octets(self):
        assert GeoffCritic._is_valid_ip("1.2.3.4.5") is False

    def test_non_numeric_octet(self):
        assert GeoffCritic._is_valid_ip("192.168.abc.1") is False

    def test_empty_string(self):
        assert GeoffCritic._is_valid_ip("") is False

    def test_ipv6_not_valid(self):
        assert GeoffCritic._is_valid_ip("::1") is False


# ---------------------------------------------------------------------------
# _is_valid_hash
# ---------------------------------------------------------------------------

class TestIsValidHash:

    def test_valid_md5(self):
        assert GeoffCritic._is_valid_hash("d41d8cd98f00b204e9800998ecf8427e") is True

    def test_valid_sha1(self):
        assert GeoffCritic._is_valid_hash("da39a3ee5e6b4b0d3255bfef95601890afd80709") is True

    def test_valid_sha256(self):
        assert GeoffCritic._is_valid_hash(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ) is True

    def test_uppercase_accepted(self):
        assert GeoffCritic._is_valid_hash("D41D8CD98F00B204E9800998ECF8427E") is True

    def test_too_short(self):
        assert GeoffCritic._is_valid_hash("deadbeef") is False

    def test_too_long(self):
        assert GeoffCritic._is_valid_hash("a" * 65) is False

    def test_non_hex_chars(self):
        assert GeoffCritic._is_valid_hash("d41d8cd98f00b204e9800998ecf8427g") is False

    def test_empty_string(self):
        assert GeoffCritic._is_valid_hash("") is False

    def test_hash_with_spaces_invalid(self):
        assert GeoffCritic._is_valid_hash("d41d8cd9 8f00b204e9800998ecf8427e") is False


# ---------------------------------------------------------------------------
# _is_valid_url
# ---------------------------------------------------------------------------

class TestIsValidURL:

    def test_http_url(self):
        assert GeoffCritic._is_valid_url("http://example.com") is True

    def test_https_url(self):
        assert GeoffCritic._is_valid_url("https://malware.example.com/payload.exe") is True

    def test_https_uppercase(self):
        assert GeoffCritic._is_valid_url("HTTPS://example.com") is True

    def test_ftp_invalid(self):
        assert GeoffCritic._is_valid_url("ftp://example.com") is False

    def test_bare_domain_invalid(self):
        assert GeoffCritic._is_valid_url("example.com") is False

    def test_empty_string_invalid(self):
        assert GeoffCritic._is_valid_url("") is False


# ---------------------------------------------------------------------------
# validate_ioc_extraction
# ---------------------------------------------------------------------------

class TestValidateIOCExtraction:

    def test_present_ioc_validated(self):
        source = "Connection to 192.168.1.1 detected"
        iocs = {"ips": ["192.168.1.1"]}
        result = critic.validate_ioc_extraction(iocs, source)
        assert result["false_positive_count"] == 0
        assert "192.168.1.1" in result["validated_iocs"]["ips"]

    def test_absent_ioc_is_false_positive(self):
        source = "Nothing suspicious here"
        iocs = {"ips": ["10.0.0.1"]}
        result = critic.validate_ioc_extraction(iocs, source)
        assert result["false_positive_count"] == 1
        assert result["validated_iocs"]["ips"] == []

    def test_mixed_iocs(self):
        source = "Hash: deadbeefdeadbeefdeadbeefdeadbeef seen at 10.0.0.5"
        iocs = {
            "hashes": ["deadbeefdeadbeefdeadbeefdeadbeef"],
            "ips": ["10.0.0.5", "172.16.0.1"],  # second IP not in source
        }
        result = critic.validate_ioc_extraction(iocs, source)
        assert result["false_positive_count"] == 1
        assert len(result["validated_iocs"]["hashes"]) == 1
        assert len(result["validated_iocs"]["ips"]) == 1

    def test_result_has_required_keys(self):
        result = critic.validate_ioc_extraction({}, "")
        for key in ("validation_type", "original_ioc_count",
                    "validated_ioc_count", "false_positives",
                    "false_positive_count", "validated_iocs", "timestamp"):
            assert key in result


# ---------------------------------------------------------------------------
# validate_ioc_formats
# ---------------------------------------------------------------------------

class TestValidateIOCFormats:

    def test_valid_ip_passes_format_check(self):
        iocs = {"ips": ["192.168.1.1", "8.8.8.8"]}
        result = critic.validate_ioc_formats(iocs)
        assert result["format_valid_count"] == 2
        assert result["format_issue_count"] == 0

    def test_invalid_ip_caught(self):
        iocs = {"ips": ["999.999.999.999"]}
        result = critic.validate_ioc_formats(iocs)
        assert result["format_issue_count"] >= 1

    def test_valid_hash_passes(self):
        iocs = {"hashes": ["d41d8cd98f00b204e9800998ecf8427e"]}
        result = critic.validate_ioc_formats(iocs)
        assert result["format_valid_count"] == 1

    def test_invalid_hash_caught(self):
        iocs = {"hashes": ["not-a-hash"]}
        result = critic.validate_ioc_formats(iocs)
        assert result["format_issue_count"] >= 1

    def test_valid_url_passes(self):
        iocs = {"urls": ["https://example.com/payload"]}
        result = critic.validate_ioc_formats(iocs)
        assert result["format_valid_count"] == 1

    def test_empty_iocs_no_issues(self):
        result = critic.validate_ioc_formats({})
        assert result["format_issue_count"] == 0
        assert result["format_valid_count"] == 0
