#!/usr/bin/env python3
"""
Tests for AI Evidence Classifier with Self-Healing

Covers:
1. Fast classification (extension-based)
2. Header analysis (file command / python-magic)
3. LLM reasoning (mocked)
4. Critic validation (mocked)
5. Self-healing (error recovery)
6. Fallback classification (minimal)
"""

import json
import os
import pytest
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock, call
from datetime import datetime

from evidence_classifier import AIEvidenceClassifier, classify_with_ai


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def mock_orchestrator():
    """Mock ExtendedOrchestrator."""
    return Mock()


@pytest.fixture
def mock_llm():
    """Mock LLM call function that returns JSON responses."""
    def _call_llm(agent_type, prompt, **kwargs):
        # Return a simple classification for testing
        return json.dumps([
            {
                "path": "/tmp/evidence/unknown_file.bin",
                "evidence_type": "memory_dumps",
                "confidence": 0.85,
                "reasoning": "VMware header detected",
                "os_hint": "windows"
            }
        ])
    return _call_llm


@pytest.fixture
def classifier(mock_orchestrator, mock_llm):
    """Create classifier with mocked dependencies."""
    return AIEvidenceClassifier(mock_orchestrator, mock_llm, healing_attempts=2)


@pytest.fixture
def evidence_dir():
    """Create temporary evidence directory with test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)

        # Create test files with various extensions
        (tmpdir / "disk.E01").write_text("test")
        (tmpdir / "memory.vmem").write_text("test")
        (tmpdir / "capture.pcap").write_text("test")
        (tmpdir / "events.evtx").write_text("test")
        (tmpdir / "unknown.bin").write_text("test")
        (tmpdir / "syslog").write_text("test log entry")

        yield tmpdir


# =============================================================================
# Stage 1: Fast Classification Tests
# =============================================================================

class TestFastClassification:
    """Test extension-based fast classification."""

    def test_classifies_disk_images(self, classifier, evidence_dir):
        inventory = classifier._fast_classify(evidence_dir)
        assert any("disk.E01" in p for p in inventory["disk_images"])
        assert inventory["classification_confidence"][str(evidence_dir / "disk.E01")] == 0.9

    def test_classifies_memory_dumps(self, classifier, evidence_dir):
        inventory = classifier._fast_classify(evidence_dir)
        assert any("memory.vmem" in p for p in inventory["memory_dumps"])
        assert inventory["classification_confidence"][str(evidence_dir / "memory.vmem")] == 0.9

    def test_classifies_pcaps(self, classifier, evidence_dir):
        inventory = classifier._fast_classify(evidence_dir)
        assert any("capture.pcap" in p for p in inventory["pcaps"])

    def test_classifies_evtx(self, classifier, evidence_dir):
        inventory = classifier._fast_classify(evidence_dir)
        assert any("events.evtx" in p for p in inventory["evtx_logs"])

    def test_ambiguous_files_low_confidence(self, classifier, evidence_dir):
        inventory = classifier._fast_classify(evidence_dir)
        assert any("unknown.bin" in p for p in inventory["other_files"])
        assert inventory["classification_confidence"][str(evidence_dir / "unknown.bin")] == 0.3

    def test_totals_size(self, classifier, evidence_dir):
        inventory = classifier._fast_classify(evidence_dir)
        assert inventory["total_size_bytes"] > 0


# =============================================================================
# Stage 2: Header Analysis Tests
# =============================================================================

class TestHeaderAnalysis:
    """Test file header-based classification."""

    def test_header_classifies_ewf(self, classifier, evidence_dir):
        # Create a file with EWF header
        ewf_file = evidence_dir / "disk_no_ext"
        ewf_file.write_bytes(b"EVF\x09\x0d\x0a\xff\x00")

        inventory = classifier._fast_classify(evidence_dir)
        inventory["other_files"] = [str(ewf_file)]  # Force into other_files

        with patch('subprocess.run') as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = "EWF/Expert Witness Compression Format"

            classifier._header_classify(inventory)

        assert any("disk_no_ext" in p for p in inventory["disk_images"])

    def test_header_classifies_pcap(self, classifier, evidence_dir):
        pcap_file = evidence_dir / "capture_no_ext"
        pcap_file.write_bytes(b"\xd4\xc3\xb2\xa1")  # PCAP magic number

        inventory = classifier._fast_classify(evidence_dir)
        inventory["other_files"] = [str(pcap_file)]

        with patch('subprocess.run') as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = "tcpdump capture file - version 2.4"

            classifier._header_classify(inventory)

        assert any("capture_no_ext" in p for p in inventory["pcaps"])

    def test_header_skip_text_files(self, classifier, evidence_dir):
        """Text files should remain ambiguous for LLM."""
        inventory = classifier._fast_classify(evidence_dir)
        initial_other = len(inventory["other_files"])

        with patch('subprocess.run') as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = "ASCII text"

            classifier._header_classify(inventory)

        # Text files stay ambiguous (return None from _map_header_to_type)
        # They remain in other_files
        assert len(inventory["other_files"]) >= initial_other

    def test_header_handles_subprocess_error(self, classifier, evidence_dir):
        """Gracefully handle missing 'file' command."""
        inventory = classifier._fast_classify(evidence_dir)

        with patch('subprocess.run', side_effect=FileNotFoundError("file not found")):
            # Should not crash, just skip header analysis
            classifier._header_classify(inventory)

        # No crash means success


# =============================================================================
# Stage 3: LLM Classification Tests
# =============================================================================

class TestLLMClassification:
    """Test LLM-based reasoning for ambiguous files."""

    def test_llm_classifies_remaining_files(self, classifier, evidence_dir):
        inventory = classifier._fast_classify(evidence_dir)

        # Force a file into other_files
        test_file = str(evidence_dir / "unknown.bin")
        inventory["other_files"] = [test_file]

        # Patch LLM to return correct path
        def mock_llm_local(*args, **kwargs):
            return json.dumps([{
                "path": test_file,
                "evidence_type": "memory_dumps",
                "confidence": 0.85,
                "reasoning": "VMware header detected",
                "os_hint": "windows"
            }])

        classifier_local = AIEvidenceClassifier(Mock(), mock_llm_local, healing_attempts=2)
        classifier_local._llm_classify(inventory)

        assert any("unknown.bin" in p for p in inventory["memory_dumps"])
        assert inventory["classification_confidence"][test_file] == 0.85

    def test_llm_tracks_ai_classified(self, classifier, evidence_dir):
        inventory = classifier._fast_classify(evidence_dir)
        test_file = str(evidence_dir / "unknown.bin")
        inventory["other_files"] = [test_file]

        def mock_llm_local(*args, **kwargs):
            return json.dumps([{
                "path": test_file,
                "evidence_type": "memory_dumps",
                "confidence": 0.85,
                "reasoning": "VMware header detected",
                "os_hint": "windows"
            }])

        classifier_local = AIEvidenceClassifier(Mock(), mock_llm_local, healing_attempts=2)
        classifier_local._llm_classify(inventory)

        assert len(inventory["ai_classified"]) > 0
        assert inventory["ai_classified"][0]["method"] == "llm_reasoning"

    def test_llm_handles_empty_batch(self, classifier):
        inventory = {
            "other_files": [],
            "disk_images": [],
            "memory_dumps": [],
            "ai_classified": [],
            "classification_confidence": {}
        }

        classifier._llm_classify(inventory)  # Should not crash
        assert inventory["ai_classified"] == []

    def test_llm_handles_json_parse_error(self, classifier, evidence_dir):
        """Test recovery from invalid JSON response."""
        def bad_llm(*args, **kwargs):
            return "not valid json"

        classifier_bad = AIEvidenceClassifier(Mock(), bad_llm, healing_attempts=2)
        inventory = classifier_bad._fast_classify(evidence_dir)
        inventory["other_files"] = [str(evidence_dir / "unknown.bin")]

        classifier_bad._llm_classify(inventory)
        # Should not crash, just skip LLM classification


# =============================================================================
# Stage 4: Critic Validation Tests
# =============================================================================

class TestCriticValidation:
    """Test Critic review and correction of classifications."""

    def test_critic_corrects_wrong_type(self, classifier, evidence_dir):
        inventory = classifier._fast_classify(evidence_dir)
        test_file = str(evidence_dir / "disk.E01")

        # Simulate AI misclassification
        inventory["ai_classified"] = [{
            "path": test_file,
            "evidence_type": "memory_dumps",  # Wrong!
            "confidence": 0.85,
            "method": "llm_reasoning"
        }]

        # Mock Critic returning correction
        def critic_llm(*args, **kwargs):
            return json.dumps([
                {
                    "path": test_file,
                    "issue": "wrong_type",
                    "corrected_type": "disk_images",
                    "reasoning": "EWF header indicates disk image, not memory dump"
                }
            ])

        classifier_critic = AIEvidenceClassifier(Mock(), critic_llm)
        classifier_critic._critic_validate(inventory)

        # Should move from wherever it was to disk_images
        assert any(test_file in p for p in inventory["disk_images"])

    def test_critic_accepts_correct_classifications(self, classifier, evidence_dir):
        inventory = classifier._fast_classify(evidence_dir)

        # Correct classification
        inventory["ai_classified"] = [{
            "path": str(evidence_dir / "memory.vmem"),
            "evidence_type": "memory_dumps",
            "confidence": 0.9,
            "method": "header_analysis"
        }]

        def accepting_llm(*args, **kwargs):
            return json.dumps([])  # No corrections

        classifier_critic = AIEvidenceClassifier(Mock(), accepting_llm)
        classifier_critic._critic_validate(inventory)

        # Classification should remain unchanged
        assert any("memory.vmem" in p for p in inventory["memory_dumps"])


# =============================================================================
# Stage 5: Self-Healing Tests
# =============================================================================

class TestSelfHealing:
    """Test error recovery and self-healing capabilities."""

    def test_attempt_heal_success(self, classifier):
        """Normal operation without errors."""
        result = classifier._attempt_heal(
            "test_op",
            lambda: {"status": "ok"}
        )
        assert result == {"status": "ok"}
        assert classifier.healing_count == 0

    def test_attempt_heal_retry(self, classifier):
        """Retry after first failure."""
        call_count = 0

        def flaky_operation():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise RuntimeError("First attempt fails")
            return {"status": "recovered"}

        result = classifier._attempt_heal("test_op", flaky_operation)
        assert result == {"status": "recovered"}
        assert call_count == 2
        assert classifier.healing_count == 1

    def test_attempt_heal_fallback(self, classifier):
        """Use fallback after all retries exhausted."""
        def always_fails():
            raise RuntimeError("Persistent error")

        def fallback():
            return {"status": "fallback"}

        result = classifier._attempt_heal("test_op", always_fails, fallback)
        assert result == {"status": "fallback"}
        assert classifier.error_count > 0

    def test_diagnose_missing_dependency(self, classifier):
        """Detect and attempt to heal missing Python module."""
        error = ImportError("No module named 'magic'")
        with patch('subprocess.run') as mock_run:
            mock_run.return_value.returncode = 0
            result = classifier._diagnose_and_heal("header_analysis", error)
            mock_run.assert_called()

    def test_diagnose_permission_error(self, classifier):
        """Handle permission errors gracefully."""
        error = PermissionError("Permission denied: /root/secret")
        result = classifier._diagnose_and_heal("fast_classify", error)
        assert result is True  # Continue without those files

    def test_diagnose_timeout(self, classifier):
        """Handle timeout errors."""
        error = TimeoutError("Command timed out")
        result = classifier._diagnose_and_heal("llm_classify", error)
        assert result is True

    def test_diagnose_llm_rate_limit(self, classifier):
        """Handle LLM rate limiting with backoff."""
        error = Exception("429 Too Many Requests")
        with patch('time.sleep') as mock_sleep:
            result = classifier._diagnose_and_heal("llm_classify", error)
            mock_sleep.assert_called_once()
            assert result is True

    def test_diagnose_json_error(self, classifier):
        """Handle JSON parsing errors."""
        error = json.JSONDecodeError("Invalid JSON", "", 0)
        result = classifier._diagnose_and_heal("llm_classify", error)
        assert result is True

    def test_diagnose_unknown_error(self, classifier):
        """Unknown errors allow retry."""
        error = ValueError("Something completely unexpected")
        result = classifier._diagnose_and_heal("test_op", error)
        assert result is True  # Allows retry for unknown errors


# =============================================================================
# Minimal Fallback Tests
# =============================================================================

class TestMinimalFallback:
    """Test ultimate fallback classification (no external deps)."""

    def test_minimal_classifies_extensions(self, classifier, evidence_dir):
        inventory = classifier._minimal_fast_classify(evidence_dir)
        assert any("disk.E01" in p for p in inventory["disk_images"])
        assert any("memory.vmem" in p for p in inventory["memory_dumps"])

    def test_minimal_marks_healing_applied(self, classifier, evidence_dir):
        inventory = classifier._minimal_fast_classify(evidence_dir)
        assert inventory.get("healing_applied") is True

    def test_minimal_low_confidence(self, classifier, evidence_dir):
        inventory = classifier._minimal_fast_classify(evidence_dir)
        assert inventory["classification_confidence"][str(evidence_dir / "disk.E01")] == 0.5

    def test_minimal_skips_permission_errors(self, classifier):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            # Create unreadable file
            secret = tmpdir / "secret.E01"
            secret.write_text("test")
            os.chmod(str(secret), 0o000)

            inventory = classifier._minimal_fast_classify(tmpdir)
            # Should not crash
            assert "healing_applied" in inventory

            os.chmod(str(secret), 0o644)  # Cleanup


# =============================================================================
# Integration Tests
# =============================================================================

class TestIntegration:
    """End-to-end integration tests."""

    def test_classify_evidence_full_pipeline(self, classifier, evidence_dir):
        """Test complete classification pipeline."""
        inventory = classifier.classify_evidence(evidence_dir)

        # All expected files should be classified
        assert len(inventory["disk_images"]) >= 1
        assert len(inventory["memory_dumps"]) >= 1
        assert len(inventory["pcaps"]) >= 1

        # Confidence scores present
        for cat in ["disk_images", "memory_dumps", "pcaps", "evtx_logs"]:
            for fpath in inventory[cat]:
                assert fpath in inventory["classification_confidence"]

    def test_classify_with_ai_function(self, mock_orchestrator, mock_llm, evidence_dir):
        """Test convenience function classify_with_ai."""
        inventory = classify_with_ai(evidence_dir, mock_orchestrator, mock_llm)
        assert len(inventory["disk_images"]) >= 1

    def test_healing_log_populated(self, classifier, evidence_dir):
        """Test that healing log captures errors."""
        # Force an error by making header analysis fail permanently
        def always_fails():
            raise RuntimeError("Permanent failure")
        
        classifier._attempt_heal("header_test", always_fails)
        
        log = classifier.get_healing_log()
        assert len(log) > 0
        assert any("Permanent failure" in entry.get("error", "") for entry in log)

    def test_classification_log_populated(self, classifier, evidence_dir):
        """Test that classification log captures decisions."""
        # Trigger some logging
        classifier._log("test_event", "Test message")
        
        log = classifier.get_classification_log()
        assert len(log) > 0
        assert any("test_event" in str(entry) for entry in log)


# =============================================================================
# Edge Cases
# =============================================================================

class TestEdgeCases:
    """Test edge cases and error conditions."""

    def test_empty_directory(self, classifier):
        """Handle empty evidence directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            inventory = classifier.classify_evidence(Path(tmpdir))
            assert inventory["total_size_bytes"] == 0
            assert all(len(inventory[k]) == 0 for k in ["disk_images", "memory_dumps", "pcaps"])

    def test_directory_with_subdirectories(self, classifier, evidence_dir):
        """Handle nested directory structure."""
        # Create subdirectory
        subdir = evidence_dir / "nested"
        subdir.mkdir()
        (subdir / "nested_disk.E01").write_text("test")

        inventory = classifier.classify_evidence(evidence_dir)
        assert any("nested_disk.E01" in p for p in inventory["disk_images"])

    def test_special_characters_in_filenames(self, classifier):
        """Handle filenames with special characters."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            (tmpdir / "file with spaces.E01").write_text("test")
            (tmpdir / "file-with-dashes.raw").write_text("test")

            inventory = classifier.classify_evidence(tmpdir)
            assert any("spaces" in p for p in inventory["disk_images"])
            assert any("dashes" in p for p in inventory["disk_images"])

    def test_very_large_file(self, classifier, evidence_dir):
        """Handle very large files (size tracking)."""
        large_file = evidence_dir / "large.E01"
        large_file.write_text("x" * 1000000)

        inventory = classifier.classify_evidence(evidence_dir)
        assert inventory["total_size_bytes"] >= 1000000

    def test_broken_symlinks(self, classifier, evidence_dir):
        """Handle broken symlinks gracefully."""
        target = evidence_dir / "nonexistent"
        link = evidence_dir / "broken_link.E01"
        try:
            link.symlink_to(target)
        except OSError:
            pytest.skip("Symlinks not supported on this platform")

        inventory = classifier.classify_evidence(evidence_dir)
        # Should not crash
        assert "total_size_bytes" in inventory
