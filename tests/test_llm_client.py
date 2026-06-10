"""Tests for geoff_llm_client.generate_with_retry — the shared retry/rate-limit
layer used by the Manager, Forensicator, Critic and Healer LLM callers."""

import sys
import os
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "src")))

import geoff_llm_client
from geoff_llm_client import generate_with_retry, parse_retry_after, TokenBucket


def _response(status=200, body=None, headers=None):
    resp = MagicMock()
    resp.status_code = status
    resp.json.return_value = body if body is not None else {"response": "ok"}
    resp.headers = headers or {}
    return resp


_ARGS = dict(
    base_url="http://test:11434",
    headers={"Content-Type": "application/json"},
    model="test-model",
)


class TestSuccess:
    def test_returns_response_text(self):
        with patch.object(geoff_llm_client.requests, "post",
                          return_value=_response(body={"response": "hello"})):
            assert generate_with_retry("hi", **_ARGS) == "hello"

    def test_callable_params_resolved(self):
        calls = {}
        def url():
            calls["url"] = True
            return "http://test:11434"
        with patch.object(geoff_llm_client.requests, "post",
                          return_value=_response()) as mock_post:
            generate_with_retry("hi", base_url=url,
                                headers=lambda: {"X": "1"},
                                model=lambda: "m1")
        assert calls["url"]
        assert mock_post.call_args.kwargs["json"]["model"] == "m1"

    def test_temperature_passed(self):
        with patch.object(geoff_llm_client.requests, "post",
                          return_value=_response()) as mock_post:
            generate_with_retry("hi", temperature=0.3, **_ARGS)
        assert mock_post.call_args.kwargs["json"]["options"]["temperature"] == 0.3


class TestAuthErrors:
    def test_401_fails_immediately(self):
        with patch.object(geoff_llm_client.requests, "post",
                          return_value=_response(status=401)) as mock_post:
            assert generate_with_retry("hi", failure_value=None, **_ARGS) is None
        assert mock_post.call_count == 1

    def test_403_fails_immediately_with_failure_value(self):
        with patch.object(geoff_llm_client.requests, "post",
                          return_value=_response(status=403)):
            assert generate_with_retry("hi", failure_value="", **_ARGS) == ""

    def test_auth_retries_once_then_fails(self):
        with patch.object(geoff_llm_client.requests, "post",
                          return_value=_response(status=401)) as mock_post, \
             patch.object(geoff_llm_client.time, "sleep"):
            assert generate_with_retry("hi", auth_retries=1,
                                       failure_value="", **_ARGS) == ""
        assert mock_post.call_count == 2

    def test_auth_retry_can_succeed(self):
        responses = [_response(status=401), _response(body={"response": "ok now"})]
        with patch.object(geoff_llm_client.requests, "post",
                          side_effect=responses), \
             patch.object(geoff_llm_client.time, "sleep"):
            assert generate_with_retry("hi", auth_retries=1, **_ARGS) == "ok now"


class TestRateLimit429:
    def test_429_respects_retry_after_then_succeeds(self):
        responses = [
            _response(status=429, headers={"Retry-After": "5"}),
            _response(body={"response": "after wait"}),
        ]
        sleeps = []
        with patch.object(geoff_llm_client.requests, "post", side_effect=responses), \
             patch.object(geoff_llm_client.time, "sleep", side_effect=sleeps.append):
            assert generate_with_retry("hi", **_ARGS) == "after wait"
        # waits max(Retry-After, backoff[0]=30)
        assert sleeps and sleeps[0] == 30

    def test_parse_retry_after(self):
        assert parse_retry_after(_response(headers={"Retry-After": "12"})) == 12.0
        assert parse_retry_after(_response(headers={"Retry-After": "garbage"})) == 60
        assert parse_retry_after(_response()) == 0


class TestServerErrors:
    def test_5xx_quick_retries_then_succeeds(self):
        responses = [_response(status=503), _response(status=503),
                     _response(body={"response": "recovered"})]
        sleeps = []
        with patch.object(geoff_llm_client.requests, "post", side_effect=responses), \
             patch.object(geoff_llm_client.time, "sleep", side_effect=sleeps.append):
            assert generate_with_retry("hi", **_ARGS) == "recovered"
        assert sleeps == [10, 10]  # quick 10s retries for the first 3 attempts


class TestErrorBodyAndEmpty:
    def test_ollama_error_in_body_retried(self):
        responses = [
            _response(body={"response": "[ERROR] Ollama returned 502"}),
            _response(body={"response": "clean answer"}),
        ]
        with patch.object(geoff_llm_client.requests, "post", side_effect=responses), \
             patch.object(geoff_llm_client.time, "sleep"):
            assert generate_with_retry("hi", **_ARGS) == "clean answer"

    def test_empty_response_retried_when_enabled(self):
        responses = [
            _response(body={"response": "   "}),
            _response(body={"response": "real answer"}),
        ]
        with patch.object(geoff_llm_client.requests, "post", side_effect=responses), \
             patch.object(geoff_llm_client.time, "sleep"):
            assert generate_with_retry("hi", retry_on_empty=True, **_ARGS) == "real answer"

    def test_empty_response_returned_when_disabled(self):
        with patch.object(geoff_llm_client.requests, "post",
                          return_value=_response(body={"response": ""})):
            assert generate_with_retry("hi", **_ARGS) == ""

    def test_thinking_field_extracted(self):
        body = {"response": "", "thinking": 'reasoning... {"verdict": "ok"} done'}
        with patch.object(geoff_llm_client.requests, "post",
                          return_value=_response(body=body)):
            result = generate_with_retry("hi", extract_thinking=True, **_ARGS)
        assert result == '{"verdict": "ok"}'


class TestRetryWindow:
    def test_returns_failure_value_when_window_exhausted(self):
        timeout_exc = geoff_llm_client.requests.exceptions.ConnectionError("down")
        clock = {"t": 0}

        def fake_time():
            return clock["t"]

        def fake_sleep(s):
            clock["t"] += s

        with patch.object(geoff_llm_client.requests, "post", side_effect=timeout_exc), \
             patch.object(geoff_llm_client.time, "time", side_effect=fake_time), \
             patch.object(geoff_llm_client.time, "sleep", side_effect=fake_sleep):
            result = generate_with_retry("hi", max_retry_time=60,
                                         failure_value="FAILED", **_ARGS)
        assert result == "FAILED"


class TestTokenBucket:
    def test_burst_does_not_sleep(self):
        bucket = TokenBucket(max_tokens=3, refill_rate=1000)
        with patch.object(geoff_llm_client.time, "sleep") as mock_sleep:
            for _ in range(3):
                bucket.acquire()
        mock_sleep.assert_not_called()

    def test_exhausted_bucket_waits(self):
        bucket = TokenBucket(max_tokens=1, refill_rate=0.5)
        with patch.object(geoff_llm_client.time, "sleep") as mock_sleep:
            bucket.acquire()
            bucket.acquire()
        assert mock_sleep.called

    def test_rate_limiter_invoked_per_attempt(self):
        bucket = MagicMock()
        with patch.object(geoff_llm_client.requests, "post",
                          return_value=_response()):
            generate_with_retry("hi", rate_limiter=bucket, **_ARGS)
        bucket.acquire.assert_called_once()
