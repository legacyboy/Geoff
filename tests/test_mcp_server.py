#!/usr/bin/env python3
"""
Comprehensive tests for Geoff MCP Server tools.

Tests all 17 MCP tools with mocked forensic calls, LLM calls, and file system operations.
"""

import pytest
import json
import uuid
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock, PropertyMock
from datetime import datetime

# Import MCP server tools
from geoff_mcp_server import (
    start_find_evil,
    get_job_status,
    list_cases,
    list_evidence,
    get_case_report,
    get_findings,
    list_playbooks,
    chat,
    disk_analyze,
    memory_analyze,
    registry_analyze,
    network_analyze,
    log_analyze,
    malware_analyze,
    timeline_analyze,
    browser_analyze,
    run_specialist,
    _safe_evidence_path,
    _find_case_dir,
)


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def mock_evidence_dir():
    """Create a temporary evidence directory with mock files."""
    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        # Create mock evidence files
        (td_path / "disk.E01").touch()
        (td_path / "memory.vmem").touch()
        (td_path / "capture.pcap").touch()
        (td_path / "system.evtx").touch()
        (td_path / "SOFTWARE").touch()
        yield td_path


@pytest.fixture
def mock_cases_dir():
    """Create a temporary cases directory with a mock case."""
    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        # Use exact naming pattern that _find_case_dir expects: {case_name}_findevil_{timestamp}
        case_dir = td_path / "IR-001-Test_findevil_20240101_120000"
        case_dir.mkdir(parents=True)
        reports_dir = case_dir / "reports"
        reports_dir.mkdir()
        (reports_dir / "narrative_report.md").write_text("# Investigation Report\n\n## Findings\n\nEvil was found.")
        (reports_dir / "find_evil_report.json").write_text(json.dumps({
            "case_id": "IR-001-Test",
            "evil_found": True,
            "severity": "HIGH",
            "findings": [{"type": "suspicious_process", "details": "mimikatz.exe"}]
        }))
        # Also create a secondary case for prefix matching tests
        secondary_dir = td_path / "IR-001-Test-Secondary_findevil_20240102_120000"
        secondary_dir.mkdir(parents=True)
        (secondary_dir / "reports").mkdir()
        (secondary_dir / "reports" / "narrative_report.md").write_text("# Secondary Report")
        yield td_path, case_dir


@pytest.fixture
def mock_find_evil_job():
    """Mock a find_evil job in the job tracker."""
    job_id = f"fe-{uuid.uuid4().hex[:12]}"
    with patch('geoff_mcp_server._find_evil_jobs') as mock_jobs:
        mock_jobs.__getitem__ = MagicMock()
        mock_jobs.__contains__ = MagicMock()
        mock_jobs.__setitem__ = MagicMock()
        mock_jobs.get = MagicMock()
        
        job_data = {
            "status": "running",
            "progress_pct": 45.0,
            "current_playbook": "PB-SIFT-003",
            "current_step": "registry.parse_hive",
            "elapsed_seconds": 120.5,
            "started_at": datetime.now().isoformat(),
            "result": None,
            "error": None,
            "log": [{"time": "12:00:00", "msg": "Investigation started"}],
        }
        
        def get_item(key):
            if key == job_id:
                return job_data
            raise KeyError(key)
        
        def contains(key):
            return key == job_id
        
        def get_item_method(key, default=None):
            if key == job_id:
                return job_data
            return default
        
        mock_jobs.__getitem__.side_effect = get_item
        mock_jobs.__contains__.side_effect = contains
        mock_jobs.get.side_effect = get_item_method
        mock_jobs.__iter__ = MagicMock(return_value=iter([job_id]))
        
        yield job_id, mock_jobs, job_data


# =============================================================================
# Helper Function Tests
# =============================================================================

class TestSafeEvidencePath:
    """Tests for _safe_evidence_path helper."""

    @patch('geoff_mcp_server.EVIDENCE_BASE_DIR', '/base/evidence')
    def test_absolute_path_returns_as_is(self):
        """Absolute paths should be returned unchanged."""
        result = _safe_evidence_path("/custom/path/evidence")
        assert result == "/custom/path/evidence"

    @patch('geoff_mcp_server.EVIDENCE_BASE_DIR', '/base/evidence')
    def test_relative_path_joins_base(self):
        """Relative paths should be joined to EVIDENCE_BASE_DIR."""
        result = _safe_evidence_path("case-001")
        assert result == "/base/evidence/case-001"

    @patch('geoff_mcp_server.EVIDENCE_BASE_DIR', '/base/evidence')
    def test_nested_relative_path(self):
        """Nested relative paths should work correctly."""
        result = _safe_evidence_path("cases/2024/IR-001")
        assert result == "/base/evidence/cases/2024/IR-001"


class TestFindCaseDir:
    """Tests for _find_case_dir helper."""

    def test_finds_exact_match(self, mock_cases_dir):
        """Should find case directory with exact name match."""
        td_path, case_dir = mock_cases_dir
        # Function looks for report at reports/narrative_report.md inside case dir
        result = _find_case_dir(td_path, "IR-001-Test", "reports/narrative_report.md")
        assert result is not None
        assert "IR-001-Test_findevil_" in result.name

    def test_returns_none_for_missing_case(self, mock_cases_dir):
        """Should return None when case doesn't exist."""
        td_path, _ = mock_cases_dir
        result = _find_case_dir(td_path, "NONEXISTENT", "reports/narrative_report.md")
        assert result is None

    def test_returns_none_for_missing_report(self, mock_cases_dir):
        """Should return None when report file doesn't exist."""
        td_path, _ = mock_cases_dir
        result = _find_case_dir(td_path, "IR-001-Test", "reports/nonexistent.md")
        assert result is None

    def test_prefix_match_with_findevil_separator(self, mock_cases_dir):
        """Should match case name prefix followed by _findevil_ (exact prefix only)."""
        td_path, case_dir = mock_cases_dir
        # The pattern requires exact prefix match: "IR-001-Test" matches "IR-001-Test_findevil_*"
        # but NOT "IR-001-Test-Secondary_findevil_*" (to prevent IR-01 matching IR-016)
        result = _find_case_dir(td_path, "IR-001-Test", "reports/narrative_report.md")
        assert result is not None
        assert result.name == "IR-001-Test_findevil_20240101_120000"


# =============================================================================
# Investigation Tool Tests
# =============================================================================

class TestStartFindEvil:
    """Tests for start_find_evil MCP tool."""

    @patch('geoff_mcp_server._spawn_find_evil')
    @patch('geoff_mcp_server.threading.Thread')
    @patch('geoff_mcp_server._find_evil_jobs', {})
    @patch('geoff_mcp_server.EVIDENCE_BASE_DIR', '/base/evidence')
    def test_starts_investigation_success(self, mock_thread_cls, mock_spawn, mock_evidence_dir):
        """Should start investigation and return job_id."""
        with patch('geoff_mcp_server.Path.exists', return_value=True):
            result = start_find_evil(str(mock_evidence_dir))
        
        assert result["status"] == "running"
        assert "job_id" in result
        assert result["job_id"].startswith("fe-")
        assert "evidence_dir" in result
        mock_thread_cls.assert_called_once()
        mock_spawn.assert_not_called()  # Runs in background thread

    def test_returns_error_for_missing_directory(self):
        """Should return error when evidence directory doesn't exist."""
        with patch('geoff_mcp_server.Path.exists', return_value=False):
            result = start_find_evil("/nonexistent/path")
        
        assert result["status"] == "error"
        assert "error" in result
        assert "not found" in result["error"].lower()

    @patch('geoff_mcp_server._spawn_find_evil')
    @patch('geoff_mcp_server.threading.Thread')
    @patch('geoff_mcp_server._find_evil_jobs', {})
    def test_relative_path_resolves(self, mock_thread_cls, mock_spawn):
        """Should resolve relative paths against EVIDENCE_BASE_DIR."""
        with patch('geoff_mcp_server.Path.exists', return_value=True):
            with patch('geoff_mcp_server.EVIDENCE_BASE_DIR', '/base/evidence'):
                result = start_find_evil("case-001")
        
        assert result["status"] == "running"
        assert result["evidence_dir"] == "/base/evidence/case-001"


class TestGetJobStatus:
    """Tests for get_job_status MCP tool."""

    def test_returns_job_status(self, mock_find_evil_job):
        """Should return current job status."""
        job_id, mock_jobs, job_data = mock_find_evil_job
        
        result = get_job_status(job_id)
        
        assert result["job_id"] == job_id
        assert result["status"] == "running"
        assert result["progress_pct"] == 45.0
        assert result["current_playbook"] == "PB-SIFT-003"
        assert "log" in result

    def test_returns_not_found_for_invalid_job(self):
        """Should return not_found for invalid job_id."""
        with patch('geoff_mcp_server._find_evil_jobs', {}):
            result = get_job_status("nonexistent-job")
        
        assert result["status"] == "not_found"
        assert "error" in result

    def test_includes_result_for_complete_job(self, mock_find_evil_job):
        """Should include result when job is complete."""
        job_id, mock_jobs, job_data = mock_find_evil_job
        job_data["status"] = "complete"
        job_data["result"] = {"evil_found": True, "severity": "HIGH"}
        
        result = get_job_status(job_id)
        
        assert result["status"] == "complete"
        assert result["result"] == {"evil_found": True, "severity": "HIGH"}

    def test_includes_error_for_failed_job(self, mock_find_evil_job):
        """Should include error when job failed."""
        job_id, mock_jobs, job_data = mock_find_evil_job
        job_data["status"] = "error"
        job_data["error"] = "Evidence directory not accessible"
        
        result = get_job_status(job_id)
        
        assert result["status"] == "error"
        assert result["error"] == "Evidence directory not accessible"


class TestListCases:
    """Tests for list_cases MCP tool."""

    @patch('geoff_mcp_server.get_all_cases')
    def test_returns_cases_dict(self, mock_get_all_cases):
        """Should return dict of cases with file trees."""
        mock_get_all_cases.return_value = {
            "IR-001": {"files": ["disk.E01", "memory.vmem"]},
            "IR-002": {"files": ["capture.pcap"]},
        }
        
        result = list_cases()
        
        assert "cases" in result
        assert result["cases"] == mock_get_all_cases.return_value
        mock_get_all_cases.assert_called_once()


class TestListEvidence:
    """Tests for list_evidence MCP tool."""

    @patch('geoff_mcp_server.get_evidence_recursive')
    @patch('geoff_mcp_server.EVIDENCE_BASE_DIR', '/base/evidence')
    def test_lists_all_evidence(self, mock_get_recursive, mock_evidence_dir):
        """Should list all evidence when no case_name provided."""
        mock_get_recursive.return_value = {"disk.E01": {"size": 1024}}
        
        with patch('geoff_mcp_server.Path.exists', return_value=True):
            result = list_evidence()
        
        assert "evidence" in result
        mock_get_recursive.assert_called_once_with("/base/evidence")

    @patch('geoff_mcp_server.get_evidence_recursive')
    @patch('geoff_mcp_server.EVIDENCE_BASE_DIR', '/base/evidence')
    def test_lists_case_scoped_evidence(self, mock_get_recursive, mock_evidence_dir):
        """Should list evidence for specific case."""
        mock_get_recursive.return_value = {"disk.E01": {"size": 1024}}
        
        with patch('geoff_mcp_server.Path.exists', return_value=True):
            result = list_evidence(case_name="IR-001")
        
        assert "evidence" in result
        mock_get_recursive.assert_called_once_with("/base/evidence/IR-001")

    def test_returns_error_for_invalid_case_name(self):
        """Should return error for invalid case_name with special chars."""
        result = list_evidence(case_name="../../../etc/passwd")
        
        assert "error" in result
        assert result["evidence"] == {}

    def test_returns_error_for_missing_path(self):
        """Should return error when evidence path doesn't exist."""
        with patch('geoff_mcp_server.Path.exists', return_value=False):
            result = list_evidence()
        
        assert "error" in result
        assert result["evidence"] == {}


class TestGetCaseReport:
    """Tests for get_case_report MCP tool."""

    def test_returns_report_for_valid_case(self, mock_cases_dir):
        """Should return narrative report for valid case."""
        td_path, case_dir = mock_cases_dir
        with patch('geoff_mcp_server.CASES_WORK_DIR', str(td_path)):
            with patch('geoff_mcp_server.Path.exists', return_value=True):
                result = get_case_report("IR-001-Test")
        
        assert "report" in result
        assert "# Investigation Report" in result["report"]

    def test_returns_error_for_missing_case(self):
        """Should return error when case doesn't exist."""
        with patch('geoff_mcp_server._find_case_dir', return_value=None):
            with patch('geoff_mcp_server.CASES_WORK_DIR', '/tmp/cases'):
                with patch('geoff_mcp_server.Path.exists', return_value=True):
                    result = get_case_report("NONEXISTENT")
        
        assert "error" in result

    def test_returns_error_for_invalid_case_name(self):
        """Should return error for invalid case_name."""
        # Path traversal chars are sanitized but still result in "not found"
        with patch('geoff_mcp_server.CASES_WORK_DIR', '/tmp'):
            with patch('geoff_mcp_server.Path.exists', return_value=True):
                result = get_case_report("nonexistent-case-xyz")
        
        assert "error" in result


class TestGetFindings:
    """Tests for get_findings MCP tool."""

    def test_returns_findings_json(self, mock_cases_dir):
        """Should return findings JSON for valid case."""
        td_path, case_dir = mock_cases_dir
        with patch('geoff_mcp_server.CASES_WORK_DIR', str(td_path)):
            with patch('geoff_mcp_server.Path.exists', return_value=True):
                result = get_findings("IR-001-Test")
        
        assert "findings" in result
        assert result["findings"]["evil_found"] is True
        assert result["findings"]["severity"] == "HIGH"

    def test_returns_error_for_missing_case(self):
        """Should return error when case doesn't exist."""
        with patch('geoff_mcp_server._find_case_dir', return_value=None):
            with patch('geoff_mcp_server.CASES_WORK_DIR', '/tmp/cases'):
                with patch('geoff_mcp_server.Path.exists', return_value=True):
                    result = get_findings("NONEXISTENT")
        
        assert "error" in result


class TestListPlaybooks:
    """Tests for list_playbooks MCP tool."""

    @patch('geoff_mcp_server.PLAYBOOK_NAMES', {
        "PB-SIFT-000": "Triage & Execution Planning",
        "PB-SIFT-001": "Initial Access",
        "PB-SIFT-002": "Execution",
    })
    def test_returns_playbook_list(self):
        """Should return list of available playbooks."""
        result = list_playbooks()
        
        assert "playbooks" in result
        assert len(result["playbooks"]) == 3
        assert result["playbooks"][0]["id"] == "PB-SIFT-000"
        assert result["playbooks"][0]["name"] == "Triage & Execution Planning"


# =============================================================================
# Chat Tool Tests
# =============================================================================

class TestChat:
    """Tests for chat MCP tool."""

    @patch('geoff_mcp_server.call_llm')
    def test_chat_with_message_only(self, mock_call_llm):
        """Should call LLM with message and return response."""
        mock_call_llm.return_value = "The evidence shows signs of credential theft."
        
        result = chat("What does the evidence show?")
        
        assert "response" in result
        assert result["response"] == "The evidence shows signs of credential theft."
        assert result["agent_type"] == "manager"
        mock_call_llm.assert_called_once_with("What does the evidence show?", context="", agent_type="manager")

    @patch('geoff_mcp_server.call_llm')
    def test_chat_with_context(self, mock_call_llm):
        """Should call LLM with message and context."""
        mock_call_llm.return_value = "Based on the context, mimikatz was executed."
        
        context = json.dumps({"findings": ["mimikatz.exe found"]})
        result = chat("What malware was found?", context=context)
        
        mock_call_llm.assert_called_once()
        call_args = mock_call_llm.call_args
        assert call_args[1]["context"] == context

    @patch('geoff_mcp_server.call_llm')
    def test_chat_with_agent_type(self, mock_call_llm):
        """Should support different agent types."""
        mock_call_llm.return_value = "Critical analysis complete."
        
        result = chat("Analyze this", agent_type="critic")
        
        assert result["agent_type"] == "critic"
        mock_call_llm.assert_called_once_with("Analyze this", context="", agent_type="critic")


# =============================================================================
# Specialist Tool Tests
# =============================================================================

class TestDiskAnalyze:
    """Tests for disk_analyze MCP tool."""

    @patch('geoff_mcp_server.ExtendedOrchestrator')
    def test_calls_sleuthkit_specialist(self, mock_orch_cls, mock_evidence_dir):
        """Should call sleuthkit specialist with correct params."""
        mock_orch = MagicMock()
        mock_orch.run_playbook_step.return_value = {"status": "success", "partitions": 2}
        mock_orch_cls.return_value = mock_orch
        
        result = disk_analyze(
            function="list_partitions",
            evidence_dir=str(mock_evidence_dir),
            params={"recursive": True}
        )
        
        assert result["status"] == "success"
        mock_orch.run_playbook_step.assert_called_once()


class TestMemoryAnalyze:
    """Tests for memory_analyze MCP tool."""

    @patch('geoff_mcp_server.ExtendedOrchestrator')
    def test_calls_volatility_specialist(self, mock_orch_cls, mock_evidence_dir):
        """Should call volatility specialist with correct params."""
        mock_orch = MagicMock()
        mock_orch.run_playbook_step.return_value = {"status": "success", "processes": 45}
        mock_orch_cls.return_value = mock_orch
        
        result = memory_analyze(
            function="process_list",
            evidence_dir=str(mock_evidence_dir),
            params={"memory_dump": "dump.vmem"}
        )
        
        assert result["status"] == "success"


class TestRegistryAnalyze:
    """Tests for registry_analyze MCP tool."""

    @patch('geoff_mcp_server.ExtendedOrchestrator')
    def test_calls_registry_specialist(self, mock_orch_cls, mock_evidence_dir):
        """Should call registry specialist with correct params."""
        mock_orch = MagicMock()
        mock_orch.run_playbook_step.return_value = {"status": "success", "keys": ["Run", "RunOnce"]}
        mock_orch_cls.return_value = mock_orch
        
        result = registry_analyze(
            function="extract_run_keys",
            evidence_dir=str(mock_evidence_dir),
            params={"hive_path": "SOFTWARE"}
        )
        
        assert result["status"] == "success"


class TestNetworkAnalyze:
    """Tests for network_analyze MCP tool."""

    @patch('geoff_mcp_server.ExtendedOrchestrator')
    def test_calls_network_specialist(self, mock_orch_cls, mock_evidence_dir):
        """Should call network specialist with correct params."""
        mock_orch = MagicMock()
        mock_orch.run_playbook_step.return_value = {"status": "success", "connections": 120}
        mock_orch_cls.return_value = mock_orch
        
        result = network_analyze(
            function="parse_pcap",
            evidence_dir=str(mock_evidence_dir),
            params={"pcap_file": "capture.pcap"}
        )
        
        assert result["status"] == "success"


class TestLogAnalyze:
    """Tests for log_analyze MCP tool."""

    @patch('geoff_mcp_server.ExtendedOrchestrator')
    def test_calls_log_specialist(self, mock_orch_cls, mock_evidence_dir):
        """Should call log specialist with correct params."""
        mock_orch = MagicMock()
        mock_orch.run_playbook_step.return_value = {"status": "success", "events": 5000}
        mock_orch_cls.return_value = mock_orch
        
        result = log_analyze(
            function="parse_evtx",
            evidence_dir=str(mock_evidence_dir),
            params={"evtx_file": "system.evtx"}
        )
        
        assert result["status"] == "success"


class TestMalwareAnalyze:
    """Tests for malware_analyze MCP tool."""

    @patch('geoff_mcp_server.ExtendedOrchestrator')
    def test_calls_remnux_specialist(self, mock_orch_cls, mock_evidence_dir):
        """Should call REMnux specialist with correct params."""
        mock_orch = MagicMock()
        mock_orch.run_playbook_step.return_value = {"status": "success", "malware_detected": True}
        mock_orch_cls.return_value = mock_orch
        
        result = malware_analyze(
            function="yara_scan",
            evidence_dir=str(mock_evidence_dir),
            params={"target_file": "suspicious.exe"}
        )
        
        assert result["status"] == "success"


class TestTimelineAnalyze:
    """Tests for timeline_analyze MCP tool."""

    @patch('geoff_mcp_server.ExtendedOrchestrator')
    def test_calls_plaso_specialist(self, mock_orch_cls, mock_evidence_dir):
        """Should call Plaso specialist with correct params."""
        mock_orch = MagicMock()
        mock_orch.run_playbook_step.return_value = {"status": "success", "events": 100000}
        mock_orch_cls.return_value = mock_orch
        
        result = timeline_analyze(
            function="create_timeline",
            evidence_dir=str(mock_evidence_dir),
            params={"evidence_path": "disk.E01"}
        )
        
        assert result["status"] == "success"


class TestBrowserAnalyze:
    """Tests for browser_analyze MCP tool."""

    @patch('geoff_mcp_server.ExtendedOrchestrator')
    def test_calls_browser_specialist(self, mock_orch_cls, mock_evidence_dir):
        """Should call browser specialist with correct params."""
        mock_orch = MagicMock()
        mock_orch.run_playbook_step.return_value = {"status": "success", "history_entries": 500}
        mock_orch_cls.return_value = mock_orch
        
        result = browser_analyze(
            function="extract_history",
            evidence_dir=str(mock_evidence_dir),
            params={"db_path": "History"}
        )
        
        assert result["status"] == "success"


class TestRunSpecialist:
    """Tests for run_specialist generic dispatcher."""

    @patch('geoff_mcp_server.ExtendedOrchestrator')
    def test_dispatches_to_correct_module(self, mock_orch_cls, mock_evidence_dir):
        """Should dispatch to correct specialist module."""
        mock_orch = MagicMock()
        mock_orch.run_playbook_step.return_value = {"status": "success", "result": "custom"}
        mock_orch_cls.return_value = mock_orch
        
        result = run_specialist(
            module="mobile",
            function="analyze_ios_backup",
            evidence_dir=str(mock_evidence_dir),
            params={"backup_path": "/backup"}
        )
        
        assert result["status"] == "success"
        mock_orch.run_playbook_step.assert_called_once()

    @patch('geoff_mcp_server.ExtendedOrchestrator')
    def test_handles_specialist_error(self, mock_orch_cls, mock_evidence_dir):
        """Should handle specialist errors gracefully."""
        mock_orch = MagicMock()
        mock_orch.run_playbook_step.side_effect = Exception("Specialist failed")
        mock_orch_cls.return_value = mock_orch
        
        result = run_specialist(
            module="sleuthkit",
            function="list_files",
            evidence_dir=str(mock_evidence_dir)
        )
        
        assert result["status"] == "error"
        assert "Specialist failed" in result["error"]


# =============================================================================
# Error Handling Tests
# =============================================================================

class TestErrorHandling:
    """Tests for error handling across MCP tools."""

    def test_specialist_tools_handle_missing_evidence(self):
        """Specialist tools should handle missing evidence directories."""
        with patch('geoff_mcp_server.ExtendedOrchestrator') as mock_orch_cls:
            mock_orch = MagicMock()
            mock_orch.run_playbook_step.side_effect = FileNotFoundError("Evidence not found")
            mock_orch_cls.return_value = mock_orch
            
            result = disk_analyze(
                function="list_partitions",
                evidence_dir="/nonexistent"
            )
            
            assert result["status"] == "error"

    @patch('geoff_mcp_server.call_llm')
    def test_chat_handles_llm_error(self, mock_call_llm):
        """Chat should handle LLM errors gracefully."""
        mock_call_llm.side_effect = Exception("LLM connection failed")
        
        with pytest.raises(Exception):
            chat("Test message")

    def test_get_job_status_handles_corrupted_job(self):
        """Should handle corrupted job state gracefully."""
        with patch('geoff_mcp_server._find_evil_jobs') as mock_jobs:
            mock_jobs.get.return_value = None
            
            result = get_job_status("corrupted-job")
            
            assert result["status"] == "not_found"


# =============================================================================
# Integration-style Tests
# =============================================================================

class TestMCPToolIntegration:
    """Integration-style tests for MCP tool workflows."""

    @patch('geoff_mcp_server._spawn_find_evil')
    @patch('geoff_mcp_server.threading.Thread')
    @patch('geoff_mcp_server._find_evil_jobs', {})
    def test_full_investigation_workflow(self, mock_thread_cls, mock_spawn, mock_evidence_dir):
        """Test complete investigation workflow: start -> poll -> get report."""
        job_id = None
        
        # Start investigation
        with patch('geoff_mcp_server.Path.exists', return_value=True):
            start_result = start_find_evil(str(mock_evidence_dir))
            job_id = start_result["job_id"]
        
        assert job_id is not None
        assert start_result["status"] == "running"
        
        # Mock job completion
        with patch('geoff_mcp_server._find_evil_jobs') as mock_jobs:
            mock_jobs.get.return_value = {
                "status": "complete",
                "progress_pct": 100.0,
                "current_playbook": "complete",
                "current_step": "",
                "elapsed_seconds": 300.0,
                "result": {"evil_found": True, "case_work_dir": "/cases/IR-001"},
                "log": [],
            }
            mock_jobs.__contains__ = lambda _, x: x == job_id
            
            # Poll status
            status_result = get_job_status(job_id)
            
            assert status_result["status"] == "complete"
            assert status_result["progress_pct"] == 100.0
            assert status_result["result"]["evil_found"] is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
