"""
Tests for _require_auth decorator in geoff_integrated.py.

Uses the Flask test client to hit the /cases endpoint (simplest protected
route that doesn't need a running Ollama or evidence directory).

Scenarios:
  1. Auth disabled (GEOFF_API_KEY="") — all requests allowed
  2. Auth enabled — missing key → 401
  3. Auth enabled — wrong key → 401
  4. Auth enabled — correct key via X-API-Key → 200
  5. Auth enabled — correct key via Authorization: Bearer → 200
  6. / (index) is never protected — always 200
"""

import os
import importlib
import pytest
import sys


# ---------------------------------------------------------------------------
# Fixture: create a fresh Flask test client with the given API key
# ---------------------------------------------------------------------------

def _make_client(api_key: str):
    """
    Re-import geoff_integrated with the given GEOFF_API_KEY env var so the
    module-level constant picks it up, then return a Flask test client.

    Because geoff_integrated is a module singleton we patch the module-level
    GEOFF_API_KEY variable directly after import.
    """
    import geoff_integrated
    # Patch the module-level constant without re-importing
    geoff_integrated.GEOFF_API_KEY = api_key
    return geoff_integrated.app.test_client()


# ---------------------------------------------------------------------------
# Auth disabled (empty key)
# ---------------------------------------------------------------------------

class TestAuthDisabled:
    def test_cases_no_key_header_returns_not_401(self):
        client = _make_client("")
        resp = client.get("/cases")
        assert resp.status_code != 401

    def test_index_always_accessible(self):
        client = _make_client("")
        resp = client.get("/")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Auth enabled
# ---------------------------------------------------------------------------

class TestAuthEnabled:
    KEY = "supersecret-test-key"

    def setup_method(self):
        self.client = _make_client(self.KEY)

    def test_missing_key_returns_401(self):
        resp = self.client.get("/cases")
        assert resp.status_code == 401

    def test_wrong_key_returns_401(self):
        resp = self.client.get("/cases", headers={"X-API-Key": "wrongkey"})
        assert resp.status_code == 401

    def test_correct_key_via_x_api_key_allowed(self):
        resp = self.client.get("/cases", headers={"X-API-Key": self.KEY})
        assert resp.status_code != 401

    def test_correct_key_via_bearer_token_allowed(self):
        resp = self.client.get(
            "/cases",
            headers={"Authorization": f"Bearer {self.KEY}"}
        )
        assert resp.status_code != 401

    def test_bearer_with_extra_spaces_stripped(self):
        # removeprefix('Bearer ') leaves leading space; .strip() removes it —
        # so the key still matches and auth passes.
        resp = self.client.get(
            "/cases",
            headers={"Authorization": f"Bearer  {self.KEY}"}
        )
        assert resp.status_code != 401

    def test_401_body_contains_error_message(self):
        resp = self.client.get("/cases")
        data = resp.get_json()
        assert "error" in data
        assert "Unauthorized" in data["error"] or "unauthorized" in data["error"].lower()

    def test_index_bypasses_auth(self):
        """/ is not decorated with _require_auth — must always return 200."""
        resp = self.client.get("/")
        assert resp.status_code == 200

    def test_post_chat_with_correct_key(self):
        resp = self.client.post(
            "/chat",
            json={"message": "hello"},
            headers={"X-API-Key": self.KEY},
        )
        assert resp.status_code != 401

    def test_post_chat_without_key_returns_401(self):
        resp = self.client.post("/chat", json={"message": "hello"})
        assert resp.status_code == 401
