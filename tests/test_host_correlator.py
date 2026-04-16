"""
Tests for HostCorrelator in src/host_correlator.py.

Only stdlib imports — no mocking needed.
"""

import pytest
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from host_correlator import HostCorrelator


hc = HostCorrelator()


# ---------------------------------------------------------------------------
# _get_hour (static)
# ---------------------------------------------------------------------------

class TestGetHour:

    def test_iso_timestamp_with_z(self):
        assert HostCorrelator._get_hour("2024-03-15T14:30:00Z") == 14

    def test_midnight(self):
        assert HostCorrelator._get_hour("2024-01-01T00:00:00Z") == 0

    def test_noon(self):
        assert HostCorrelator._get_hour("2024-06-15T12:00:00Z") == 12

    def test_invalid_string_returns_none(self):
        assert HostCorrelator._get_hour("not-a-timestamp") is None

    def test_none_raises_attribute_error(self):
        # _get_hour expects a str; None.replace() raises AttributeError
        with pytest.raises(AttributeError):
            HostCorrelator._get_hour(None)

    def test_empty_string_returns_none(self):
        assert HostCorrelator._get_hour("") is None

    def test_end_of_day(self):
        assert HostCorrelator._get_hour("2024-12-31T23:59:59Z") == 23


# ---------------------------------------------------------------------------
# correlate() — integration-style with fixture data
# ---------------------------------------------------------------------------

def _make_event(owner, timestamp, device_id="DESKTOP-1", event_type="process_execution"):
    return {
        "owner": owner,
        "timestamp": timestamp,
        "device_id": device_id,
        "event_type": event_type,
        "summary": f"{event_type} by {owner}",
    }


class TestCorrelate:

    def _simple_user_map(self):
        return {
            "alice": {
                "devices": ["DESKTOP-1"],
                "aliases": ["alice"],
            }
        }

    def _simple_device_map(self):
        return {
            "DESKTOP-1": {
                "device_id": "DESKTOP-1",
                "owner": "alice",
                "hostname": "DESKTOP-1",
            }
        }

    def test_returns_dict(self):
        result = hc.correlate({}, {}, [], [])
        assert isinstance(result, dict)

    def test_empty_inputs_no_crash(self):
        result = hc.correlate({}, {}, [], [])
        assert result == {}

    def test_user_in_result(self):
        user_map = self._simple_user_map()
        device_map = self._simple_device_map()
        events = [_make_event("alice", "2024-03-15T09:00:00Z")]
        result = hc.correlate(device_map, user_map, [], events)
        assert "alice" in result

    def test_activity_profile_has_required_keys(self):
        user_map = self._simple_user_map()
        device_map = self._simple_device_map()
        events = [
            _make_event("alice", "2024-03-15T09:00:00Z"),
            _make_event("alice", "2024-03-15T10:00:00Z"),
        ]
        result = hc.correlate(device_map, user_map, [], events)
        profile = result["alice"]["activity_profile"]
        assert "first_seen" in profile
        assert "last_seen" in profile
        assert "total_events" in profile

    def test_total_events_count(self):
        user_map = self._simple_user_map()
        device_map = self._simple_device_map()
        events = [_make_event("alice", f"2024-03-15T{h:02d}:00:00Z") for h in range(5)]
        result = hc.correlate(device_map, user_map, [], events)
        assert result["alice"]["activity_profile"]["total_events"] == 5

    def test_result_has_lateral_movement_key(self):
        user_map = self._simple_user_map()
        device_map = self._simple_device_map()
        result = hc.correlate(device_map, user_map, [], [])
        assert "lateral_movement_indicators" in result["alice"]

    def test_result_has_anomalies_key(self):
        user_map = self._simple_user_map()
        device_map = self._simple_device_map()
        result = hc.correlate(device_map, user_map, [], [])
        assert "anomalies" in result["alice"]

    def test_multiple_users_all_in_result(self):
        user_map = {
            "alice": {"devices": ["DESKTOP-1"], "aliases": ["alice"]},
            "bob":   {"devices": ["DESKTOP-2"], "aliases": ["bob"]},
        }
        device_map = {
            "DESKTOP-1": {"device_id": "DESKTOP-1", "owner": "alice"},
            "DESKTOP-2": {"device_id": "DESKTOP-2", "owner": "bob"},
        }
        events = [
            _make_event("alice", "2024-01-01T08:00:00Z", "DESKTOP-1"),
            _make_event("bob",   "2024-01-01T09:00:00Z", "DESKTOP-2"),
        ]
        result = hc.correlate(device_map, user_map, [], events)
        assert "alice" in result
        assert "bob" in result
