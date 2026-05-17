#!/usr/bin/env python3
"""Geoff DFIR - LLM-powered self-healing, LLM invocation, and manager agents.

Auto-extracted from geoff_integrated.py monolith.

Exports:
  Self-healing:   _attempt_heal, _execute_heal, classify_error_fast,
                  _audit_heal, _heal_cache, _wire_attempt_heal
  LLM invocation: call_llm, _call_manager_llm
  Manager agents: _manager_review_execution_plan,
                  _manager_generate_correction, _self_check_chat_response
  Constants:      GEOFF_PROMPT
"""

import os
import json
import re
import sys
import time
import tempfile
import shutil
from pathlib import Path
from typing import Optional

import requests

from geoff_config import (
    AGENT_MODELS, ollama_base_url, ollama_headers, STRICT_MODE, CASES_WORK_DIR,
)
from geoff_utils import (
    _fe_log, _log_info, _log_error, _run_step_via_orchestrator, _build_error_context,
)
from geoff_critic import HealCache, ErrorContext, HealDecision

# ---------------------------------------------------------------------------
# Token-bucket rate limiter (shared with geoff_forensicator.py pattern)
# ---------------------------------------------------------------------------
_sh_rate_limiter = {
    "tokens": 10,
    "max_tokens": 10,
    "refill_rate": 0.5,
    "last_refill": time.time(),
    "lock": __import__("threading").Lock(),
}

def _sh_rate_limit():
    """Token-bucket rate limiter: waits if needed before allowing a call."""
    with _sh_rate_limiter["lock"]:
        now = time.time()
        elapsed = now - _sh_rate_limiter["last_refill"]
        _sh_rate_limiter["tokens"] = min(
            _sh_rate_limiter["max_tokens"],
            _sh_rate_limiter["tokens"] + elapsed * _sh_rate_limiter["refill_rate"]
        )
        _sh_rate_limiter["last_refill"] = now
        if _sh_rate_limiter["tokens"] < 1:
            wait_time = (1 - _sh_rate_limiter["tokens"]) / _sh_rate_limiter["refill_rate"]
            _sh_rate_limiter["tokens"] = 0
            _sh_rate_limiter["last_refill"] = now + wait_time
        else:
            wait_time = 0
            _sh_rate_limiter["tokens"] -= 1
    if wait_time > 0:
        print(f"[GEOFF] Rate limited — waiting {wait_time:.1f}s for token bucket")
        time.sleep(wait_time)

def _parse_retry_after(response) -> float:
    """Parse Retry-After header from HTTP response."""
    retry_after = response.headers.get("Retry-After")
    if retry_after:
        try:
            return float(retry_after)
        except ValueError:
            return 60
    return 0

# ---------------------------------------------------------------------------
# Module-level references set by importing module
# ---------------------------------------------------------------------------

geoff_critic = None          # GeoffCritic singleton
action_logger = None         # ActionLogger singleton
PLAYBOOK_STEPS: dict = {}    # Playbook steps dict (filled by importer)

# ---------------------------------------------------------------------------
# Heal cache singleton
# ---------------------------------------------------------------------------

_heal_cache = HealCache(
    os.environ.get("GEOFF_GIT_DIR", CASES_WORK_DIR + "/git") + "/heal_cache.json"
)

# ---------------------------------------------------------------------------
# classify_error_fast
# ---------------------------------------------------------------------------


__all__ = ["GEOFF_PROMPT", "_attempt_heal", "_audit_heal", "_call_manager_llm", "_execute_heal", "_manager_generate_correction", "_manager_review_execution_plan", "_self_check_chat_response", "_wire_attempt_heal", "call_llm", "classify_error_fast"]
def classify_error_fast(ctx: ErrorContext) -> Optional[str]:
    """Pre-classify errors for deterministic cases, avoiding LLM calls.
    Returns error_class string if deterministic, None if LLM is needed."""
    stderr = (ctx.stderr or "").lower()
    if "permission denied" in stderr or "operation not permitted" in stderr:
        return "permission_error"
    if "command not found" in stderr or ("no such file" in stderr and ctx.tool_command):
        return "tool_missing"
    if "sqlite_busy" in stderr or "database is locked" in stderr:
        return "lock_error.sqlite_busy"
    if "hive locked" in stderr or "file is locked" in stderr:
        return "lock_error.file_locked"
    # Mount error classifications (self-healing coverage for pipeline infra)
    if "wrong fs type" in stderr or "unknown filesystem type" in stderr:
        return "mount_error.wrong_fs_type"
    if "no such device" in stderr or "no such file or directory" in stderr:
        if ctx.function in ("mount_disk", "detect_partitions"):
            return "mount_error.no_such_device"
    if "loop device" in stderr:
        return "mount_error.loop_device"
    return None


# ---------------------------------------------------------------------------
# _execute_heal
# ---------------------------------------------------------------------------

def _execute_heal(module: str, function: str, params: dict,
                   decision: HealDecision, job_id: str) -> Optional[dict]:
    """Dispatch a HealDecision into concrete tool execution.

    Returns the healed result dict, or None if healing failed.
    """
    fix_type = decision.fix_type

    # --- Param-based retries ---
    if fix_type in ("retry_params", "retry_with_offset", "retry_without_offset",
                    "retry_with_profile"):
        new_params = dict(params)
        new_params.update(decision.new_params)
        new_params["_heal_attempt"] = True
        return _run_step_via_orchestrator(module, function, new_params, job_id=job_id)

    elif fix_type == "retry_with_backoff":
        new_params = dict(params)
        new_params.update(decision.new_params)
        new_params["_heal_attempt"] = True
        for delay in [0.5, 1.0, 2.0]:
            time.sleep(delay)
            r = _run_step_via_orchestrator(module, function, new_params, job_id=job_id)
            if r.get("status") == "success":
                return r
        return None

    elif fix_type == "copy_then_retry":
        src = (decision.new_params.get("source_path")
               or params.get("hive_path")
               or params.get("ntuser_path")
               or params.get("system_path"))
        if not src or not Path(src).exists():
            return None
        tmp_name = None
        try:
            with tempfile.NamedTemporaryFile(suffix=Path(src).suffix, delete=False) as tmp:
                shutil.copy2(src, tmp.name)
                tmp_name = tmp.name
            new_params = dict(params)
            new_params.update(decision.new_params)
            for key in ("hive_path", "ntuser_path", "system_path"):
                if key in new_params:
                    new_params[key] = tmp_name
            new_params["_heal_attempt"] = True
            r = _run_step_via_orchestrator(module, function, new_params, job_id=job_id)
            return r if r.get("status") == "success" else None
        finally:
            if tmp_name:
                try:
                    os.unlink(tmp_name)
                except OSError:
                    pass

    elif fix_type == "fallback_tool":
        if not decision.fallback_module or not decision.fallback_function:
            return None
        new_params = dict(params)
        new_params.update(decision.new_params)
        new_params["_heal_attempt"] = True
        _fe_log(job_id, f"  [HEAL] Fallback: {decision.fallback_module}.{decision.fallback_function}")
        return _run_step_via_orchestrator(
            decision.fallback_module, decision.fallback_function,
            new_params, job_id=job_id,
        )

    elif fix_type == "adjust_command":
        if not decision.adjusted_command:
            return None
        new_params = dict(params)
        new_params["raw_command"] = decision.adjusted_command
        new_params["_heal_attempt"] = True
        return _run_step_via_orchestrator(module, function, new_params, job_id=job_id)

    elif fix_type in ("skip_file", "skip_step"):
        return {
            "status": "skipped",
            "_heal_skipped": True,
            "_skip_reason": decision.skip_reason,
        }

    return None


# ---------------------------------------------------------------------------
# _attempt_heal
# ---------------------------------------------------------------------------

def _attempt_heal(module: str, function: str, params: dict,
                   error_result: dict, job_id: str,
                   prior_attempts: list = None,
                   evidence_file: str = None,
                   evidence_type: str = None,
                   os_type: str = "") -> Optional[dict]:
    """Ask Critic to diagnose and fix a failed step.

    Returns healed result dict, or None if healing failed / not applicable.
    """
    ctx = _build_error_context(
        module, function, params, error_result, job_id,
        prior_attempts or [],
        evidence_file=evidence_file,
        evidence_type=evidence_type,
        os_type=os_type,
    )

    # Fast-path: non-healable error classes skip the LLM entirely
    fast_class = classify_error_fast(ctx)
    if fast_class == "permission_error":
        return None

    # Check local cache first
    cache_key = ctx.cache_key()
    decision = _heal_cache.get(cache_key)
    if decision:
        decision.from_cache = True
        _fe_log(job_id, f"  [HEAL] Cache hit for {cache_key[:8]} → {decision.fix_type}")
    else:
        decision = geoff_critic.analyze_execution_error_v2(ctx)
        if decision.fixable and decision.confidence >= 5:
            _heal_cache.store(cache_key, decision)
            _fe_log(job_id, f"  [HEAL] LLM diagnosed → {decision.fix_type} (confidence: {decision.confidence})")

    if not decision.fixable or decision.fix_type == "fail":
        _fe_log(job_id, f"  [HEAL] Not fixable: {decision.root_cause or decision.fix_detail}")
        return None

    healed_result = _execute_heal(module, function, params, decision, job_id)

    # Audit trail
    outcome = "healed" if (healed_result and healed_result.get("status") == "success") else ("skipped" if (healed_result and healed_result.get("status") == "skipped") else "failed")
    _audit_heal(job_id, module, function, ctx, decision, outcome)

    if healed_result and healed_result.get("status") == "success":
        healed_result["_self_healed"] = True
        healed_result["_heal_fix_type"] = decision.fix_type
        healed_result["_heal_confidence"] = decision.confidence
        healed_result["_heal_from_cache"] = decision.from_cache
        _heal_cache.record_outcome(cache_key, success=True)
        _fe_log(job_id, f"  ✓ [HEAL] {module}.{function} healed: {decision.fix_type}")
    elif healed_result and healed_result.get("status") == "skipped":
        _fe_log(job_id, f"  ⎘ [HEAL] {module}.{function} skipped: {decision.skip_reason}")
    else:
        _heal_cache.record_outcome(cache_key, success=False)
        _fe_log(job_id, f"  ✗ [HEAL] {module}.{function} healing failed")

    return healed_result


# ---------------------------------------------------------------------------
# _audit_heal
# ---------------------------------------------------------------------------

def _audit_heal(job_id: str, module: str, function: str,
                 ctx: ErrorContext, decision: HealDecision, outcome: str):
    """Log a self-heal event to the action audit trail."""
    try:
        action_logger.log('SELF_HEAL', {
            'job_id': job_id,
            'module': module,
            'function': function,
            'evidence_file': ctx.evidence_file,
            'error_class': ctx.exception_type,
            'error_summary': (ctx.stderr or "")[:150],
            'fix_type': decision.fix_type,
            'fix_detail': decision.fix_detail,
            'confidence': decision.confidence,
            'from_cache': decision.from_cache,
            'outcome': outcome,
            'heal_latency_ms': decision.latency_ms,
            'llm_model': decision.llm_model,
            'description': f"SELF_HEAL: {module}.{function} → {decision.fix_type} ({outcome})",
        }, commit=False)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# GEOFF_PROMPT — system prompt for the main LLM
# ---------------------------------------------------------------------------

GEOFF_PROMPT = """You are G.E.O.F.F. (Git-backed Evidence Operations Forensic Framework), a professional digital forensics investigation system.

Your role is to conduct thorough, systematic forensic analysis using established methodologies and the complete SIFT toolkit.

**Available Forensic Capabilities:**

*Disk Forensics (SleuthKit):* Partition analysis, filesystem statistics, file listing/extraction, inode analysis

*Memory Forensics (Volatility):* Process enumeration, network connections, malware detection, registry analysis, memory dumping

*IOC Extraction:* String analysis, URL/IP/email extraction, registry artifact identification

*Windows Registry Analysis (RegRipper):* Hive parsing, execution history, folder access, USB device tracking, persistence mechanisms, service enumeration

*Timeline Analysis (Plaso):* Temporal event reconstruction, super timeline generation

*Network Forensics:* PCAP analysis, flow reconstruction, protocol extraction

*Log Analysis:* Windows Event Log parsing, authentication analysis, syslog examination

*Mobile Forensics:* iOS backup analysis, Android data extraction

*REMnux Malware Analysis:* Static/dynamic analysis, binary identification, unpacking, disassembly, AV scanning

**Analytical Reasoning Protocol:**
When answering a forensic question, structure your reasoning as:
1. **Hypothesis** — State what you are testing (e.g., "Testing whether persistence was established via registry Run key")
2. **Evidence** — Cite the specific artifact, tool result, file path, offset, or log entry that supports or refutes the hypothesis
3. **Assessment** — State your conclusion with confidence level ("confirmed", "likely", "possible", "no evidence")
Do not provide a raw data dump. Every claim must be traceable to a named artifact.

**Accuracy Requirements:**
- Only assert findings that are directly evidenced by a specific artifact you can name
- When citing a finding, always include: source file, tool used, and the specific field/value observed
- Use "appears to", "consistent with", or "no evidence of" for inferences vs. confirmed facts
- If the available context does not contain the answer, say explicitly: "The current evidence does not support a conclusion on this"

**Operational Protocol:**
- Respond with clear, technical accuracy
- When instructed to investigate, execute systematically without unnecessary clarification
- Report findings with supporting evidence
- Maintain chain of custody through git-backed validation
- Cite specific tools and artifacts examined

**Response Standards:**
- Professional, objective tone
- Evidence-based conclusions with explicit artifact citations
- Clear identification of IOCs and suspicious activity with source references
- Structured investigative narrative suitable for legal documentation (not a raw execution log)"""


# ---------------------------------------------------------------------------
# call_llm
# ---------------------------------------------------------------------------

def call_llm(user_message, context="", agent_type="manager"):
    """Call LLM via Ollama (local or remote)

    agent_type: "manager", "forensicator", or "critic" - determines which model to use

    HTTP 401/403 = immediate fail (bad auth). HTTP 5xx = brief retry (3x with 10s backoff).
    Connection/network errors = full retry window (30 min with exponential backoff).
    """
    _ollama_error_patterns = (
        "Having trouble connecting to Ollama",
        "Check OLLAMA_URL",
        "[ERROR] Ollama returned",
    )
    _MAX_RETRY_TIME = 1800  # 30 minutes total retry window
    _BACKOFF_TIMES = [30, 60, 120, 240, 300]  # seconds, last value repeats
    _max_retries = 99  # effectively unlimited within time window
    _start = time.time()

    for attempt in range(_max_retries):
        elapsed = time.time() - _start
        if elapsed > _MAX_RETRY_TIME:
            print(f"[GEOFF] LLM retry timeout after {elapsed:.0f}s/{_MAX_RETRY_TIME}s", file=sys.stderr)
            return None

        _sh_rate_limit()  # Rate limit before API call

        try:
            model = AGENT_MODELS.get(agent_type, AGENT_MODELS["manager"])

            full_prompt = f"{GEOFF_PROMPT}\n\n{context}\n\nUser: {user_message}\n\nGeoff:"
            response = requests.post(
                f"{ollama_base_url()}/generate",
                headers=ollama_headers(),
                json={
                    "model": model,
                    "prompt": full_prompt,
                    "stream": False,
                    "options": {"temperature": 0.3}
                },
                timeout=300  # 5 min — cloud models can be slow
            )
            if response.status_code == 200:
                result_text = response.json().get('response', 'Hmm, let me check that again.')
                # Reject error messages that leaked into the response
                if any(pat in result_text for pat in _ollama_error_patterns):
                    wait = _BACKOFF_TIMES[min(attempt, len(_BACKOFF_TIMES) - 1)]
                    remaining = _MAX_RETRY_TIME - elapsed
                    actual_wait = min(wait, remaining)
                    if actual_wait <= 0:
                        return None
                    print(f"[GEOFF] Ollama error in response, retry {attempt+1} after {wait}s (elapsed {elapsed:.0f}s/{_MAX_RETRY_TIME}s)", file=sys.stderr)
                    time.sleep(actual_wait)
                    continue
                return result_text
            elif response.status_code in (401, 403):
                print(f"[GEOFF] LLM HTTP {response.status_code} — bad auth, giving up immediately", file=sys.stderr)
                return None
            elif response.status_code == 429:
                retry_after = _parse_retry_after(response)
                wait_time = max(retry_after, _BACKOFF_TIMES[min(attempt, len(_BACKOFF_TIMES) - 1)])
                remaining = _MAX_RETRY_TIME - elapsed
                actual_wait = min(wait_time, remaining)
                if actual_wait <= 0:
                    return None
                print(f"[GEOFF] HTTP 429 rate limited, retry {attempt+1} after {actual_wait:.0f}s (Retry-After: {retry_after})", file=sys.stderr)
                time.sleep(actual_wait)
                continue
            elif 500 <= response.status_code < 600:
                # Server errors: brief retry (3 attempts with 10s backoff)
                if attempt < 3:
                    wait = 10
                    remaining = _MAX_RETRY_TIME - elapsed
                    actual_wait = min(wait, remaining)
                    if actual_wait <= 0:
                        return None
                    print(f"[GEOFF] LLM HTTP {response.status_code} (server error), retry {attempt+1} after {wait}s", file=sys.stderr)
                    time.sleep(actual_wait)
                    continue
                # After 3 attempts, fall through to full retry window
                wait = _BACKOFF_TIMES[min(attempt, len(_BACKOFF_TIMES) - 1)]
                remaining = _MAX_RETRY_TIME - elapsed
                actual_wait = min(wait, remaining)
                if actual_wait <= 0:
                    return None
                print(f"[GEOFF] LLM HTTP {response.status_code}, retry {attempt+1} after {wait}s (elapsed {elapsed:.0f}s/{_MAX_RETRY_TIME}s)", file=sys.stderr)
                time.sleep(actual_wait)
                continue
            else:
                wait = _BACKOFF_TIMES[min(attempt, len(_BACKOFF_TIMES) - 1)]
                remaining = _MAX_RETRY_TIME - elapsed
                actual_wait = min(wait, remaining)
                if actual_wait <= 0:
                    return None
                print(f"[GEOFF] Ollama HTTP {response.status_code}, retry {attempt+1} after {wait}s (elapsed {elapsed:.0f}s/{_MAX_RETRY_TIME}s)", file=sys.stderr)
                time.sleep(actual_wait)
                continue
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
            wait = _BACKOFF_TIMES[min(attempt, len(_BACKOFF_TIMES) - 1)]
            remaining = _MAX_RETRY_TIME - elapsed
            actual_wait = min(wait, remaining)
            if actual_wait <= 0:
                return None
            print(f"[GEOFF] LLM {type(e).__name__} retry {attempt+1} after {wait}s (elapsed {elapsed:.0f}s/{_MAX_RETRY_TIME}s)", file=sys.stderr)
            time.sleep(actual_wait)
            continue
        except Exception as e:
            print(f"[GEOFF] LLM Error (attempt {attempt+1}): {e}", file=sys.stderr)
            wait = _BACKOFF_TIMES[min(attempt, len(_BACKOFF_TIMES) - 1)]
            remaining = _MAX_RETRY_TIME - elapsed
            actual_wait = min(wait, remaining)
            if actual_wait <= 0:
                return None
            time.sleep(actual_wait)
            continue
    return None  # All retries exhausted


# ---------------------------------------------------------------------------
# _call_manager_llm
# ---------------------------------------------------------------------------

def _call_manager_llm(prompt: str, timeout: int = 180) -> str:
    """Raw LLM call using Manager model — no GEOFF_PROMPT wrapping.

    Returns empty string on failure. Caller should handle None/empty gracefully.

    HTTP 401/403 = immediate fail (bad auth). HTTP 5xx = brief retry (3x with 10s backoff).
    Connection/network errors = full retry window (30 min with exponential backoff).
    """
    _error_patterns = (
        "Having trouble connecting to Ollama",
        "Check OLLAMA_URL",
        "[ERROR] Ollama returned",
    )
    _MAX_RETRY_TIME = 1800  # 30 minutes total retry window
    _BACKOFF_TIMES = [30, 60, 120, 240, 300]  # seconds, last value repeats
    _max_retries = 99  # effectively unlimited within time window
    _start = time.time()

    for attempt in range(_max_retries):
        elapsed = time.time() - _start
        if elapsed > _MAX_RETRY_TIME:
            print(f"[MANAGER] LLM retry timeout after {elapsed:.0f}s/{_MAX_RETRY_TIME}s")
            return ""

        _sh_rate_limit()

        try:
            model = AGENT_MODELS.get("manager", AGENT_MODELS.get("default", ""))
            response = requests.post(
                f"{ollama_base_url()}/generate",
                headers=ollama_headers(),
                json={"model": model, "prompt": prompt, "stream": False,
                      "options": {"temperature": 0.1}},
                timeout=timeout,
            )
            if response.status_code == 200:
                result_text = response.json().get("response", "")
                if any(pat in result_text for pat in _error_patterns):
                    wait = _BACKOFF_TIMES[min(attempt, len(_BACKOFF_TIMES) - 1)]
                    remaining = _MAX_RETRY_TIME - elapsed
                    actual_wait = min(wait, remaining)
                    if actual_wait <= 0:
                        return ""
                    print(f"[MANAGER] Ollama error in response, retry {attempt+1} after {wait}s (elapsed {elapsed:.0f}s/{_MAX_RETRY_TIME}s)")
                    time.sleep(actual_wait)
                    continue
                return result_text
            elif response.status_code in (401, 403):
                print(f"[MANAGER] LLM HTTP {response.status_code} — bad auth, giving up immediately")
                return ""
            elif response.status_code == 429:
                retry_after = _parse_retry_after(response)
                wait_time = max(retry_after, _BACKOFF_TIMES[min(attempt, len(_BACKOFF_TIMES) - 1)])
                remaining = _MAX_RETRY_TIME - elapsed
                actual_wait = min(wait_time, remaining)
                if actual_wait <= 0:
                    return ""
                print(f"[MANAGER] HTTP 429 rate limited, retry {attempt+1} after {actual_wait:.0f}s (Retry-After: {retry_after})")
                time.sleep(actual_wait)
                continue
            elif 500 <= response.status_code < 600:
                if attempt < 3:
                    wait = 10
                    remaining = _MAX_RETRY_TIME - elapsed
                    actual_wait = min(wait, remaining)
                    if actual_wait <= 0:
                        return ""
                    print(f"[MANAGER] LLM HTTP {response.status_code} (server error), retry {attempt+1} after {wait}s")
                    time.sleep(actual_wait)
                    continue
                wait = _BACKOFF_TIMES[min(attempt, len(_BACKOFF_TIMES) - 1)]
                remaining = _MAX_RETRY_TIME - elapsed
                actual_wait = min(wait, remaining)
                if actual_wait <= 0:
                    return ""
                print(f"[MANAGER] Ollama HTTP {response.status_code}, retry {attempt+1} after {wait}s (elapsed {elapsed:.0f}s/{_MAX_RETRY_TIME}s)")
                time.sleep(actual_wait)
                continue
            else:
                wait = _BACKOFF_TIMES[min(attempt, len(_BACKOFF_TIMES) - 1)]
                remaining = _MAX_RETRY_TIME - elapsed
                actual_wait = min(wait, remaining)
                if actual_wait <= 0:
                    return ""
                print(f"[MANAGER] Ollama HTTP {response.status_code}, retry {attempt+1} after {wait}s (elapsed {elapsed:.0f}s/{_MAX_RETRY_TIME}s)")
                time.sleep(actual_wait)
                continue
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
            wait = _BACKOFF_TIMES[min(attempt, len(_BACKOFF_TIMES) - 1)]
            remaining = _MAX_RETRY_TIME - elapsed
            actual_wait = min(wait, remaining)
            if actual_wait <= 0:
                return ""
            print(f"[MANAGER] LLM {type(e).__name__} retry {attempt+1} after {wait}s (elapsed {elapsed:.0f}s/{_MAX_RETRY_TIME}s)")
            time.sleep(actual_wait)
            continue
        except Exception as e:
            print(f"[MANAGER] LLM error (attempt {attempt+1}): {e}")
            wait = _BACKOFF_TIMES[min(attempt, len(_BACKOFF_TIMES) - 1)]
            remaining = _MAX_RETRY_TIME - elapsed
            actual_wait = min(wait, remaining)
            if actual_wait <= 0:
                return ""
            time.sleep(actual_wait)
            continue
    return ""


# ---------------------------------------------------------------------------
# _manager_review_execution_plan
# ---------------------------------------------------------------------------

def _manager_review_execution_plan(
    proposed_plan: list, skipped: list, inventory: dict,
    triage_findings: list, indicator_hits: list, os_type: str,
    classification: str, severity: str, job_id: str,
) -> list:
    """
    Manager LLM reviews the proposed execution plan and may reorder or amend it.
    Falls back to the proposed plan if the LLM is unavailable or returns garbage.
    """
    valid_ids = set(PLAYBOOK_STEPS.keys())
    mandatory = ["PB-SIFT-001", "PB-SIFT-002", "PB-SIFT-003", "PB-SIFT-004", "PB-SIFT-005"]

    ev_summary = {k: len(v) if isinstance(v, list) else v for k, v in inventory.items()}
    raw_categories = sorted({h.get("category", "") for h in indicator_hits if isinstance(h, dict)})[:10]

    # Sanitize values interpolated into the LLM prompt
    safe_os = str(os_type).replace("\n", " ").replace("\r", " ")[:100]
    safe_classification = str(classification).replace("\n", " ").replace("\r", " ")[:100]
    safe_severity = str(severity).replace("\n", " ").replace("\r", " ")[:50]
    hit_categories = [str(c).replace("\n", " ").replace("\r", " ")[:100] for c in raw_categories]

    prompt = f"""You are the Manager agent for a DFIR investigation. Review and optimise the execution plan.

CASE CONTEXT:
- OS: {safe_os}
- Initial classification: {safe_classification}
- Severity: {safe_severity}
- Evidence counts: {json.dumps(ev_summary)}
- Indicator categories from triage: {hit_categories}

PROPOSED EXECUTION PLAN (in order):
{json.dumps(proposed_plan)}

AVAILABLE PLAYBOOK IDs:
{json.dumps(sorted(valid_ids))}

SKIPPED (with reasons):
{json.dumps([s['id'] for s in skipped])}

Your task: return an optimised execution plan. You may reorder playbooks to address the most critical threat vectors first, remove clearly irrelevant ones, or re-include skipped ones if warranted.
Rules: {', '.join(mandatory)} are mandatory and must be present.

Respond ONLY in valid JSON (no extra text):
{{
    "approved_execution_plan": ["PB-SIFT-001", "PB-SIFT-002"],
    "reasoning": "one sentence explaining the key prioritisation decision"
}}"""

    _fe_log(job_id, "▶ Manager: reviewing execution plan…")
    raw = _call_manager_llm(prompt)
    try:
        m = re.search(r'\{.*\}', raw, re.DOTALL)
        if m:
            parsed = json.loads(m.group())
            candidate = parsed.get("approved_execution_plan", [])
            reasoning = parsed.get("reasoning", "")
            validated = [pb for pb in candidate if pb in valid_ids]
            # Guarantee mandatory playbooks are present in order
            for pb in mandatory:
                if pb in valid_ids and pb not in validated:
                    validated.insert(mandatory.index(pb), pb)
            if validated:
                _fe_log(job_id, f"  ✓ Manager approved {len(validated)}-playbook plan: {reasoning}")
                return validated
    except Exception as e:
        _fe_log(job_id, f"  ⚠ Manager plan parse error ({e}) — using proposed plan")

    _fe_log(job_id, f"  ⚠ Manager LLM unavailable — using proposed plan ({len(proposed_plan)} playbooks)")
    return proposed_plan


# ---------------------------------------------------------------------------
# _manager_generate_correction
# ---------------------------------------------------------------------------

def _manager_generate_correction(
    module: str, function: str, result: dict,
    forensicator_notes: dict, critic_issues: list,
) -> dict:
    """
    Self-correction: Manager generates a revised analysis when Critic rejects the original.
    Returns dict with corrected analyst_note, threat_indicators, and correction_reasoning.
    Returns {} if LLM is unavailable.
    """
    result_summary = json.dumps(result, default=str)[:2000]
    issues_text = "; ".join(str(i) for i in critic_issues[:5]) if critic_issues else "sanity check failed"
    original_note = forensicator_notes.get("analyst_note") or "(none)"
    indicators = forensicator_notes.get("threat_indicators") or []

    prompt = f"""You are the Manager agent in a DFIR investigation. The Critic rejected a forensic analysis step.

STEP: {module}.{function}
TOOL RESULT (excerpt):
{result_summary}

ORIGINAL ANALYSIS: {original_note}
ORIGINAL INDICATORS: {indicators}

CRITIC ISSUES: {issues_text}

Generate a corrected analysis that:
1. Only claims what is directly supported by the tool result excerpt above
2. Does not invent file names, offsets, paths, or timestamps not present in the output
3. Uses precise language: "output contains X" not "likely Y"
4. Cites the specific artifact or field in the tool output for each claim

Respond ONLY in valid JSON (no extra text):
{{
    "analyst_note": "one precise sentence citing what the tool output actually shows",
    "threat_indicators": ["indicators directly evidenced in the output, or empty list"],
    "correction_reasoning": "brief explanation of what was wrong and what was corrected"
}}"""

    try:
        response = _call_manager_llm(prompt, timeout=180)
        m = re.search(r'\{.*\}', response, re.DOTALL)
        if m:
            return json.loads(m.group())
    except Exception as e:
        print(f"[MANAGER] Correction generation failed for {module}.{function}: {e}")
    return {}


# ---------------------------------------------------------------------------
# _self_check_chat_response
# ---------------------------------------------------------------------------

def _self_check_chat_response(user_msg: str, context: str, response: str) -> str:
    """
    Self-correction for chat: verifies the response is grounded in available context.
    If unsupported claims are detected, regenerates once with an explicit correction prompt.
    Returns the original response if the LLM is unavailable or the response is short.
    """
    if len(response) < 80 or len(context) < 30:
        return response

    check_prompt = f"""You are a forensic accuracy reviewer. Determine whether this response makes claims NOT supported by the context.

CONTEXT:
{context[:3000]}

USER QUESTION: {user_msg[:500]}

RESPONSE TO CHECK:
{response[:2000]}

Does the response invent file names, tool outputs, findings, paths, or timestamps that are NOT present in the context above?

Respond ONLY in valid JSON:
{{"grounded": true, "issues": []}}
or
{{"grounded": false, "issues": ["list specific unsupported claims"]}}"""

    try:
        # Cloud models need longer timeout
        is_cloud = ":cloud" in AGENT_MODELS.get("manager", "") or ollama_base_url().startswith("https://")
        check_timeout = 90 if is_cloud else 30
        check_raw = _call_manager_llm(check_prompt, timeout=check_timeout)
        m = re.search(r'\{.*\}', check_raw, re.DOTALL)
        if not m:
            return response
        check_result = json.loads(m.group())
        if check_result.get("grounded", True):
            return response
        issues = check_result.get("issues") or []
        if not issues:
            return response

        # Regenerate with correction prompt
        correction_prompt = (
            f"{GEOFF_PROMPT}\n\n{context}\n\n"
            f"User: {user_msg}\n\n"
            f"Note: A prior draft response contained these accuracy issues: "
            f"{'; '.join(str(i) for i in issues[:3])}. "
            f"Provide a corrected response that only references evidence present in the context above. "
            f"If the context does not contain sufficient information, say so explicitly.\n\nGeoff:"
        )
        corrected = _call_manager_llm(correction_prompt, timeout=180)
        return corrected if corrected.strip() else response
    except Exception as corr_exc:
        _log_info(f"chat self-correction skipped: {corr_exc}")
        return response


# ---------------------------------------------------------------------------
# _wire_attempt_heal
# ---------------------------------------------------------------------------

def _wire_attempt_heal():
    """Wire _attempt_heal into geoff_utils after the function is defined.
    Called at the end of the module."""
    import geoff_utils as _gu
    _gu._attempt_heal = _attempt_heal
