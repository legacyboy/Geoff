"""
Tests for BehavioralAnalyzer in src/behavioral_analyzer.py.

Only stdlib imports — no mocking needed.
"""

import pytest
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from behavioral_analyzer import BehavioralAnalyzer


ba = BehavioralAnalyzer()


# ---------------------------------------------------------------------------
# _is_typosquat
# ---------------------------------------------------------------------------

class TestIsTyposquat:

    def test_exact_match_not_typosquat(self):
        assert BehavioralAnalyzer._is_typosquat("svchost.exe", "svchost.exe") is False

    def test_one_char_substitution(self):
        # svch0st.exe vs svchost.exe — 1 substitution
        assert BehavioralAnalyzer._is_typosquat("svch0st.exe", "svchost.exe") is True

    def test_transposition_is_typosquat(self):
        # scvhost.exe — first two chars transposed, same length, diffs=1
        assert BehavioralAnalyzer._is_typosquat("scvhost.exe", "svchost.exe") is True

    def test_completely_different_name_not_typosquat(self):
        assert BehavioralAnalyzer._is_typosquat("notepad.exe", "svchost.exe") is False

    def test_two_char_swap_within_name(self):
        # svchsot.exe — two chars swapped inside, same length, diffs=2 ≤ 2
        assert BehavioralAnalyzer._is_typosquat("svchsot.exe", "svchost.exe") is True

    def test_three_char_difference_not_typosquat(self):
        # svcXXX.exe vs svchost.exe — too different
        assert BehavioralAnalyzer._is_typosquat("svcXXX.exe", "svchost.exe") is False

    def test_empty_name_not_typosquat(self):
        assert BehavioralAnalyzer._is_typosquat("", "svchost.exe") is False

    def test_case_sensitivity(self):
        # _is_typosquat is byte-level; "Svchost.exe" differs by 1 char from "svchost.exe"
        assert BehavioralAnalyzer._is_typosquat("Svchost.exe", "svchost.exe") is True


# ---------------------------------------------------------------------------
# _check_process_paths
# ---------------------------------------------------------------------------

class TestCheckProcessPaths:

    def test_legit_svchost_path_no_flag(self):
        processes = [{"name": "svchost.exe", "path": "C:\\Windows\\System32\\svchost.exe", "pid": 1}]
        flags = ba._check_process_paths(processes)
        assert flags == []

    def test_svchost_from_temp_flagged(self):
        processes = [{"name": "svchost.exe", "path": "C:\\Users\\user\\AppData\\Local\\Temp\\svchost.exe", "pid": 999}]
        flags = ba._check_process_paths(processes)
        assert len(flags) == 1
        assert flags[0]["severity"] == "HIGH"
        assert "svchost.exe" in flags[0]["summary"]

    def test_unknown_process_not_flagged(self):
        # Process not in EXPECTED_PATHS — no flag
        processes = [{"name": "chrome.exe", "path": "C:\\Program Files\\Google\\Chrome\\chrome.exe", "pid": 42}]
        flags = ba._check_process_paths(processes)
        assert flags == []

    def test_missing_path_skipped(self):
        processes = [{"name": "svchost.exe", "pid": 1}]  # no path key
        flags = ba._check_process_paths(processes)
        assert flags == []

    def test_powershell_from_syswow64_ok(self):
        processes = [{
            "name": "powershell.exe",
            "path": "C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe",
            "pid": 111
        }]
        flags = ba._check_process_paths(processes)
        assert flags == []

    def test_powershell_from_downloads_flagged(self):
        processes = [{
            "name": "powershell.exe",
            "path": "C:\\Users\\user\\Downloads\\powershell.exe",
            "pid": 222
        }]
        flags = ba._check_process_paths(processes)
        assert len(flags) == 1
        assert "T1036.005" in flags[0]["mitre_att_ck"]

    def test_mitre_tag_present(self):
        processes = [{"name": "lsass.exe", "path": "C:\\Temp\\lsass.exe", "pid": 4}]
        flags = ba._check_process_paths(processes)
        assert any("T1036.005" in f.get("mitre_att_ck", []) for f in flags)


# ---------------------------------------------------------------------------
# _check_timestomping
# ---------------------------------------------------------------------------

class TestCheckTimestomping:

    def test_normal_timestamps_no_flag(self):
        files = [{"path": "/etc/passwd", "timestamps": {"created": "2024-01-01", "modified": "2024-06-01"}}]
        flags = ba._check_timestomping(files)
        assert flags == []

    def test_created_after_modified_flagged(self):
        files = [{"path": "/tmp/evil.exe", "timestamps": {"created": "2024-06-01", "modified": "2024-01-01"}}]
        flags = ba._check_timestomping(files)
        assert len(flags) == 1
        assert flags[0]["severity"] == "HIGH"
        assert "T1070.006" in flags[0]["mitre_att_ck"]

    def test_equal_timestamps_no_flag(self):
        files = [{"path": "/tmp/file", "timestamps": {"created": "2024-01-01", "modified": "2024-01-01"}}]
        flags = ba._check_timestomping(files)
        assert flags == []

    def test_missing_created_no_flag(self):
        files = [{"path": "/tmp/file", "timestamps": {"modified": "2024-01-01"}}]
        flags = ba._check_timestomping(files)
        assert flags == []

    def test_missing_timestamps_key_no_flag(self):
        files = [{"path": "/tmp/file"}]
        flags = ba._check_timestomping(files)
        assert flags == []

    def test_flag_contains_path(self):
        files = [{"path": "/tmp/payload.exe", "timestamps": {"created": "2024-12-01", "modified": "2024-01-01"}}]
        flags = ba._check_timestomping(files)
        assert "/tmp/payload.exe" in flags[0]["summary"]


# ---------------------------------------------------------------------------
# _check_temp_executables
# ---------------------------------------------------------------------------

class TestCheckTempExecutables:

    def test_exe_in_temp_flagged(self):
        files = [{"path": "C:\\Users\\bob\\AppData\\Local\\Temp\\dropper.exe"}]
        flags = ba._check_temp_executables(files)
        assert len(flags) == 1
        assert flags[0]["severity"] == "MEDIUM"
        assert "T1204" in flags[0]["mitre_att_ck"]

    def test_ps1_in_temp_flagged(self):
        files = [{"path": "C:\\Temp\\stage2.ps1"}]
        flags = ba._check_temp_executables(files)
        assert len(flags) == 1

    def test_txt_in_temp_not_flagged(self):
        files = [{"path": "C:\\Temp\\readme.txt"}]
        flags = ba._check_temp_executables(files)
        assert flags == []

    def test_exe_in_system32_not_flagged(self):
        files = [{"path": "C:\\Windows\\System32\\notepad.exe"}]
        flags = ba._check_temp_executables(files)
        assert flags == []

    def test_dll_in_downloads_flagged(self):
        files = [{"path": "C:\\Users\\alice\\Downloads\\inject.dll"}]
        flags = ba._check_temp_executables(files)
        assert len(flags) == 1

    def test_vbs_in_appdata_roaming_flagged(self):
        files = [{"path": "C:\\Users\\bob\\AppData\\Roaming\\launch.vbs"}]
        flags = ba._check_temp_executables(files)
        assert len(flags) == 1

    def test_desktop_exe_flagged(self):
        files = [{"path": "C:\\Users\\bob\\Desktop\\tool.exe"}]
        flags = ba._check_temp_executables(files)
        assert len(flags) == 1

    def test_multiple_files_mixed_results(self):
        files = [
            {"path": "C:\\Temp\\evil.exe"},
            {"path": "C:\\Windows\\explorer.exe"},
            {"path": "C:\\Temp\\readme.txt"},
        ]
        flags = ba._check_temp_executables(files)
        assert len(flags) == 1
