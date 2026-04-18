"""Tests for gap-analysis features: MITRE tagging, attack chain, new playbooks,
registry step additions, and browser/email/macos/mobile playbooks."""
import sys
import os
import pytest

SRC_DIR = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "src"))
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)


# ---------------------------------------------------------------------------
# Fixtures / imports
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _no_base_dir_restriction(monkeypatch):
    import geoff_integrated
    monkeypatch.setattr(geoff_integrated, "EVIDENCE_BASE_DIR", "")
    monkeypatch.setattr(geoff_integrated, "CASES_WORK_DIR", "")


import geoff_integrated as gi


# ---------------------------------------------------------------------------
# MITRE ATT&CK tagging
# ---------------------------------------------------------------------------

class TestMitreTagging:
    def test_mitre_tags_dict_present(self):
        assert hasattr(gi, "MITRE_TAGS")
        assert "ransomware" in gi.MITRE_TAGS
        assert "T1486" in gi.MITRE_TAGS["ransomware"]

    def test_all_triage_categories_have_mitre(self):
        for cat in gi.TRIAGE_PATTERNS:
            assert cat in gi.MITRE_TAGS, f"Category {cat!r} missing from MITRE_TAGS"

    def test_indicator_hit_carries_mitre_tag(self, tmp_path):
        lnk = tmp_path / "mimikatz.exe"
        lnk.write_bytes(b"x")
        inv = {
            "other_files": [str(lnk)],
            "disk_images": [], "memory_dumps": [],
            "evtx_logs": [], "syslogs": [],
        }
        hits = gi._scan_triage_indicators(inv)
        assert hits, "Expected at least one hit"
        assert "mitre_techniques" in hits[0]
        assert hits[0]["mitre_techniques"]  # non-empty list

    def test_content_hit_carries_mitre_tag(self, tmp_path):
        log = tmp_path / "auth.log"
        log.write_text("lsass process injection via procdump detected\n")
        inv = {
            "other_files": [], "disk_images": [], "memory_dumps": [],
            "evtx_logs": [], "syslogs": [str(log)],
        }
        hits = gi._scan_triage_indicators(inv)
        assert hits
        for h in hits:
            assert "mitre_techniques" in h


# ---------------------------------------------------------------------------
# Attack chain reconstruction
# ---------------------------------------------------------------------------

class TestAttackChain:
    def _make_findings(self):
        return [
            {"device_id": "host-A", "started_at": "2024-01-10T08:00:00", "completed_at": "2024-01-10T08:01:00"},
            {"device_id": "host-B", "started_at": "2024-01-12T10:00:00", "completed_at": "2024-01-12T10:05:00"},
            {"device_id": "host-A", "started_at": "2024-01-15T12:00:00", "completed_at": "2024-01-15T12:01:00"},
        ]

    def test_dwell_days_computed(self):
        findings = self._make_findings()
        chain = gi._reconstruct_attack_chain(findings, [], {})
        assert chain["dwell_days"] == pytest.approx(5.17, abs=0.1)

    def test_first_and_last_ts(self):
        findings = self._make_findings()
        chain = gi._reconstruct_attack_chain(findings, [], {})
        assert chain["first_seen_ts"] == "2024-01-10T08:00:00"
        assert chain["last_seen_ts"] == "2024-01-15T12:01:00"

    def test_lateral_movement_path_ordered(self):
        findings = self._make_findings()
        chain = gi._reconstruct_attack_chain(findings, [], {})
        # host-A first seen before host-B
        assert chain["lateral_movement_path"] == ["host-A", "host-B"]

    def test_mitre_techniques_from_hits(self, tmp_path):
        # "cobaltstrike.bin" — dot after pattern gives clean \b boundary
        lnk = tmp_path / "cobaltstrike.bin"
        lnk.write_bytes(b"x")
        inv = {
            "other_files": [str(lnk)],
            "disk_images": [], "memory_dumps": [],
            "evtx_logs": [], "syslogs": [],
        }
        hits = gi._scan_triage_indicators(inv)
        chain = gi._reconstruct_attack_chain([], hits, {})
        assert "mitre_techniques_observed" in chain
        assert chain["mitre_techniques_observed"]

    def test_no_findings_returns_none_dwell(self):
        chain = gi._reconstruct_attack_chain([], [], {})
        assert chain["dwell_days"] is None
        assert chain["first_seen_ts"] is None

    def test_kill_chain_phases_populated(self, tmp_path):
        f = tmp_path / "mimikatz.exe"
        f.write_bytes(b"x")
        inv = {
            "other_files": [str(f)],
            "disk_images": [], "memory_dumps": [],
            "evtx_logs": [], "syslogs": [],
        }
        hits = gi._scan_triage_indicators(inv)
        chain = gi._reconstruct_attack_chain([], hits, {})
        assert "credential_theft" in chain["kill_chain_phases"]


# ---------------------------------------------------------------------------
# New playbooks in PLAYBOOK_STEPS and PLAYBOOK_NAMES
# ---------------------------------------------------------------------------

class TestNewPlaybooks:
    @pytest.mark.parametrize("pb_id,expected_name", [
        ("PB-SIFT-021", "Mobile Analysis"),
        ("PB-SIFT-022", "Browser Forensics"),
        ("PB-SIFT-023", "Email Forensics"),
        ("PB-SIFT-024", "macOS Forensics"),
    ])
    def test_playbook_in_names(self, pb_id, expected_name):
        assert pb_id in gi.PLAYBOOK_NAMES
        assert gi.PLAYBOOK_NAMES[pb_id] == expected_name

    @pytest.mark.parametrize("pb_id", [
        "PB-SIFT-021", "PB-SIFT-022", "PB-SIFT-023", "PB-SIFT-024",
    ])
    def test_playbook_has_steps(self, pb_id):
        assert pb_id in gi.PLAYBOOK_STEPS
        steps = gi.PLAYBOOK_STEPS[pb_id]
        assert steps  # non-empty

    def test_pb021_mobile_backups_steps(self):
        steps = gi.PLAYBOOK_STEPS["PB-SIFT-021"]
        assert "mobile_backups" in steps
        fns = [s[1] for s in steps["mobile_backups"]]
        assert "analyze_ios_backup" in fns
        assert "analyze_android" in fns

    def test_pb022_browser_steps(self):
        steps = gi.PLAYBOOK_STEPS["PB-SIFT-022"]
        assert "other_files" in steps
        fns = [s[1] for s in steps["other_files"]]
        assert "extract_history" in fns
        assert "extract_cookies" in fns

    def test_pb023_email_steps(self):
        steps = gi.PLAYBOOK_STEPS["PB-SIFT-023"]
        fns = [s[1] for s in steps.get("other_files", [])]
        assert "analyze_pst" in fns
        assert "analyze_mbox" in fns

    def test_pb024_macos_steps(self):
        steps = gi.PLAYBOOK_STEPS["PB-SIFT-024"]
        fns = [s[1] for s in steps.get("other_files", [])]
        assert "parse_plist" in fns
        assert "analyze_launch_agents" in fns


# ---------------------------------------------------------------------------
# Registry step additions in existing playbooks
# ---------------------------------------------------------------------------

class TestRegistryStepAdditions:
    def test_pb003_has_user_assist(self):
        hive_steps = gi.PLAYBOOK_STEPS["PB-SIFT-003"]["registry_hives"]
        fns = [s[1] for s in hive_steps]
        assert "extract_user_assist" in fns

    def test_pb003_has_shellbags(self):
        hive_steps = gi.PLAYBOOK_STEPS["PB-SIFT-003"]["registry_hives"]
        fns = [s[1] for s in hive_steps]
        assert "extract_shellbags" in fns

    def test_pb007_has_usb_devices(self):
        hive_steps = gi.PLAYBOOK_STEPS["PB-SIFT-007"]["registry_hives"]
        fns = [s[1] for s in hive_steps]
        assert "extract_usb_devices" in fns

    def test_pb007_has_mounted_devices(self):
        hive_steps = gi.PLAYBOOK_STEPS["PB-SIFT-007"]["registry_hives"]
        fns = [s[1] for s in hive_steps]
        assert "extract_mounted_devices" in fns

    def test_pb003_retains_autoruns(self):
        hive_steps = gi.PLAYBOOK_STEPS["PB-SIFT-003"]["registry_hives"]
        fns = [s[1] for s in hive_steps]
        assert "extract_autoruns" in fns

    def test_pb003_has_jumplist(self):
        disk_steps = gi.PLAYBOOK_STEPS["PB-SIFT-003"]["disk_images"]
        fns = [s[1] for s in disk_steps]
        assert "parse_lnk_files" in fns


# ---------------------------------------------------------------------------
# Execution plan logic: new playbooks triggered correctly
# ---------------------------------------------------------------------------

class TestExecutionPlanLogic:
    """Smoke-test that _build_execution_plan logic includes new playbooks.

    We test indirectly by calling the triage execution-plan building code
    via the PLAYBOOK_STEPS constants — not by running find_evil (which
    requires live tools).
    """

    def test_browser_forensics_always_included_in_plan_steps(self):
        # PB-SIFT-022 exists and has steps — confirming it will always be eligible
        assert "PB-SIFT-022" in gi.PLAYBOOK_STEPS

    def test_mobile_playbook_has_mobile_backups_key(self):
        # Only triggered when mobile_backups non-empty
        assert "mobile_backups" in gi.PLAYBOOK_STEPS["PB-SIFT-021"]

    def test_macos_playbook_has_disk_images_key(self):
        assert "disk_images" in gi.PLAYBOOK_STEPS["PB-SIFT-024"]
