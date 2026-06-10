#!/usr/bin/env python3
"""Geoff DFIR — shared Ollama LLM client: rate limiting and retry policy.

Single implementation of the retry/backoff/rate-limit logic that was
previously copy-pasted across geoff_self_heal.call_llm,
geoff_self_heal._call_manager_llm, geoff_forensicator._call_ollama_with_retry
and geoff_critic._call_critic_llm. The per-agent differences (model,
temperature, retry window, failure value, auth policy, empty-response
handling) are parameters.

This module deliberately has no geoff_config import: callers pass callables
for URL/headers/model so each agent keeps its own resolution rules and no
circular-import risk is introduced.
"""

import threading
import time
import re
import sys
from typing import Callable, Optional, Union

import requests

# Error strings that indicate an Ollama-side failure leaked into an otherwise
# successful (HTTP 200) response body.
OLLAMA_ERROR_PATTERNS = (
    "Having trouble connecting to Ollama",
    "Check OLLAMA_URL",
    "[ERROR] Ollama returned",
)

# Exponential backoff schedule in seconds; the last value repeats.
BACKOFF_TIMES = [30, 60, 120, 240, 300]

# Effectively unlimited attempts — the retry *time window* is the real bound.
MAX_RETRIES = 99


class TokenBucket:
    """Token-bucket rate limiter shared by the agents that call Ollama."""

    def __init__(self, max_tokens: int = 10, refill_rate: float = 0.5,
                 label: str = "GEOFF"):
        self.max_tokens = max_tokens
        self.refill_rate = refill_rate  # tokens per second
        self.tokens = float(max_tokens)
        self.last_refill = time.time()
        self.label = label
        self._lock = threading.Lock()

    def acquire(self):
        """Wait (if needed) until a token is available, then consume it."""
        with self._lock:
            now = time.time()
            elapsed = now - self.last_refill
            self.tokens = min(self.max_tokens,
                              self.tokens + elapsed * self.refill_rate)
            self.last_refill = now
            if self.tokens < 1:
                wait_time = (1 - self.tokens) / self.refill_rate
                self.tokens = 0
                self.last_refill = now + wait_time
            else:
                wait_time = 0
                self.tokens -= 1
        if wait_time > 0:
            print(f"[{self.label}] Rate limited — waiting {wait_time:.1f}s for token bucket")
            time.sleep(wait_time)


def parse_retry_after(response) -> float:
    """Parse a Retry-After header; returns seconds to wait (0 if absent)."""
    retry_after = response.headers.get("Retry-After")
    if retry_after:
        try:
            return float(retry_after)
        except ValueError:
            # HTTP-date format — fall back to a default
            return 60
    return 0


def _resolve(value):
    """Allow str-or-callable parameters: call it if callable."""
    return value() if callable(value) else value


def generate_with_retry(
    prompt: str,
    *,
    base_url: Union[str, Callable[[], str]],
    headers: Union[dict, Callable[[], dict]],
    model: Union[str, Callable[[], str]],
    temperature: float = 0.1,
    request_timeout: int = 180,
    max_retry_time: int = 600,
    tag: str = "GEOFF",
    failure_value=None,
    rate_limiter: Optional[TokenBucket] = None,
    auth_retries: int = 0,
    retry_on_empty: bool = False,
    extract_thinking: bool = False,
    log_file=None,
) -> Optional[str]:
    """POST /api/generate with the standard Geoff retry policy.

    Policy (identical to the four previous copies):
      HTTP 200 with an Ollama error string in the body → backoff and retry.
      HTTP 401/403 → fail immediately (or retry `auth_retries` times after 10s).
      HTTP 429 → wait max(Retry-After, backoff).
      HTTP 5xx → 3 quick retries at 10s, then the normal backoff schedule.
      Timeout / connection error / anything else → backoff schedule.
      Total time bounded by `max_retry_time`; returns `failure_value` when
      exhausted.

    `base_url`, `headers` and `model` may be callables — they are re-resolved
    on every attempt so runtime config changes take effect mid-retry.
    `retry_on_empty` / `extract_thinking` implement the critic's handling of
    thinking models that return blank `response` fields.
    """
    start = time.time()

    def _log(msg):
        if log_file is not None:
            print(msg, file=log_file)
        else:
            print(msg)

    def _backoff(attempt):
        return BACKOFF_TIMES[min(attempt, len(BACKOFF_TIMES) - 1)]

    for attempt in range(MAX_RETRIES):
        elapsed = time.time() - start
        if elapsed > max_retry_time:
            _log(f"[{tag}] LLM retry timeout after {elapsed:.0f}s/{max_retry_time}s")
            return failure_value

        if rate_limiter is not None:
            rate_limiter.acquire()

        def _sleep_or_fail(wait, cap=None):
            """Sleep min(wait, remaining[, cap]); False when out of budget."""
            remaining = max_retry_time - (time.time() - start)
            actual = min(wait, remaining) if cap is None else min(wait, cap, remaining)
            if actual <= 0:
                return False
            time.sleep(actual)
            return True

        try:
            response = requests.post(
                f"{_resolve(base_url)}/api/generate",
                headers=_resolve(headers),
                json={
                    "model": _resolve(model),
                    "prompt": prompt,
                    "stream": False,
                    "options": {"temperature": temperature},
                },
                timeout=request_timeout,
            )
            if response.status_code == 200:
                resp_json = response.json()
                result_text = resp_json.get('response', '')
                if extract_thinking and not result_text.strip():
                    # Thinking models (qwen3.5, deepseek-r1) sometimes leave
                    # response empty and put the answer in `thinking`.
                    thinking = resp_json.get('thinking', '')
                    if thinking:
                        m = re.search(r'\{.*\}', thinking, re.DOTALL)
                        if m:
                            result_text = m.group()
                if retry_on_empty and not result_text.strip():
                    # Cloud proxy may return blank under load — short retry.
                    wait = _backoff(attempt)
                    _log(f"[{tag}] Empty response, retry {attempt+1} (elapsed {elapsed:.0f}s/{max_retry_time}s)")
                    if not _sleep_or_fail(wait, cap=30):
                        return failure_value
                    continue
                if any(pat in result_text for pat in OLLAMA_ERROR_PATTERNS):
                    wait = _backoff(attempt)
                    _log(f"[{tag}] Ollama error in response, retry {attempt+1} after {wait}s (elapsed {elapsed:.0f}s/{max_retry_time}s)")
                    if not _sleep_or_fail(wait):
                        return failure_value
                    continue
                return result_text
            elif response.status_code in (401, 403):
                if attempt < auth_retries:
                    _log(f"[{tag}] LLM HTTP {response.status_code} — auth error, retry {attempt+1} after 10s")
                    time.sleep(10)
                    continue
                _log(f"[{tag}] LLM HTTP {response.status_code} — bad auth, giving up immediately")
                return failure_value
            elif response.status_code == 429:
                retry_after = parse_retry_after(response)
                wait = max(retry_after, _backoff(attempt))
                _log(f"[{tag}] HTTP 429 rate limited, retry {attempt+1} after {wait:.0f}s (Retry-After: {retry_after})")
                if not _sleep_or_fail(wait):
                    return failure_value
                continue
            elif 500 <= response.status_code < 600:
                # Server errors: brief retry (3 attempts at 10s), then the
                # normal backoff schedule.
                wait = 10 if attempt < 3 else _backoff(attempt)
                _log(f"[{tag}] LLM HTTP {response.status_code} (server error), retry {attempt+1} after {wait}s")
                if not _sleep_or_fail(wait):
                    return failure_value
                continue
            else:
                wait = _backoff(attempt)
                _log(f"[{tag}] Ollama HTTP {response.status_code}, retry {attempt+1} after {wait}s (elapsed {elapsed:.0f}s/{max_retry_time}s)")
                if not _sleep_or_fail(wait):
                    return failure_value
                continue
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
            wait = _backoff(attempt)
            _log(f"[{tag}] LLM {type(e).__name__} retry {attempt+1} after {wait}s (elapsed {elapsed:.0f}s/{max_retry_time}s)")
            if not _sleep_or_fail(wait):
                return failure_value
            continue
        except Exception as e:
            _log(f"[{tag}] LLM Error (attempt {attempt+1}): {e}")
            wait = _backoff(attempt)
            if not _sleep_or_fail(wait):
                return failure_value
            continue
    return failure_value  # all retries exhausted
