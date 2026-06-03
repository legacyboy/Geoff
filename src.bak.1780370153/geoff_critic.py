#!/usr/bin/env python3
"""
Geoff Critic - Sanity Check Agent for DFIR Analysis
Reviews Geoff's tool outputs and conclusions for obvious hallucinations.
Two checks: 1) Are claimed findings actually in the raw output? 2) Any obvious nonsense?
"""

import json
import subprocess
import re
import os
import hashlib
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Literal

import sys

# Add src directory to path (works for both local and deployed)
SRC_DIR = os.path.dirname(os.path.abspath(__file__))
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

import requests
import time

# ---------------------------------------------------------------------------
# Self-Healing Data Structures
# ---------------------------------------------------------------------------

@dataclass
class ErrorContext:
    """Structured error context passed to the Critic LLM for diagnosis."""
    job_id: str
    step_index: int
    module: str
    function: str
    exception_type: str
    exception_message: str
    traceback: str
    tool_command: str
    params: dict
    stdout: str
    stderr: str
    exit_code: Optional[int]
    evidence_file: str
    evidence_type: str
    os_type: str
    prior_heal_attempts: list = field(default_factory=list)

    def to_prompt_block(self) -> str:
        """Render a human-readable prompt block for the Critic LLM."""
        tb = (self.traceback or "")[:2048]
        block = f"""Module:   {self.module}
Function: {self.function}
Evidence: {self.evidence_file} ({self.evidence_type}, {self.os_type})

=== INVOCATION ===
Parameters:
{json.dumps(self.params, default=str, indent=2)}

Shell command (if applicable):
{self.tool_command or '(none)'}

=== ERROR ===
Exception: {self.exception_type}: {self.exception_message}

stderr:
{(self.stderr or '')[:1024]}

stdout:
{(self.stdout or '')[:1024]}

Exit code: {self.exit_code}

Traceback (last frames):
{tb}

=== PRIOR ATTEMPTS ===
{json.dumps(self.prior_heal_attempts, default=str, indent=2)}"""
        return block

    def cache_key(self) -> str:
        """Deterministic key for caching error→fix mappings."""
        raw = f"{self.module}.{self.function}|{self.exception_type}|{(self.stderr or '')[:200]}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]


@dataclass
class HealDecision:
    """Parsed healing decision returned by the Critic LLM."""
    fixable: bool = False
    fix_type: str = "fail"
    fix_detail: str = ""
    root_cause: str = ""
    new_params: dict = field(default_factory=dict)
    fallback_module: Optional[str] = None
    fallback_function: Optional[str] = None
    adjusted_command: Optional[str] = None
    skip_reason: Optional[str] = None
    confidence: int = 0
    llm_model: str = ""
    latency_ms: int = 0
    from_cache: bool = False


@dataclass
class HealCacheEntry:
    """Persisted cache entry for error→fix mappings."""
    cache_key: str
    error_fingerprint: str
    decision: HealDecision
    success_count: int = 0
    failure_count: int = 0
    last_seen: str = ""
    created: str = ""


class HealCache:
    """Local file-based cache for error→fix mappings to avoid repeat LLM calls."""

    def __init__(self, path: str):
        self._path = Path(path)
        self._store: dict = {}
        self._load()

    def _load(self):
        if self._path.exists():
            try:
                data = json.loads(self._path.read_text())
                for k, v in data.items():
                    decision_data = v.pop('decision', {})
                    decision = HealDecision(**decision_data) if decision_data else HealDecision()
                    entry = HealCacheEntry(decision=decision, **{kvk: v[kvk] for kvk in v if kvk != 'decision'})
                    self._store[k] = entry
            except Exception:
                pass

    def get(self, key: str) -> Optional[HealDecision]:
        entry = self._store.get(key)
        if entry and entry.success_count > 0:
            return entry.decision
        return None

    def store(self, key: str, decision: HealDecision):
        entry = HealCacheEntry(
            cache_key=key,
            error_fingerprint="",
            decision=decision,
            success_count=0,
            failure_count=0,
            last_seen=datetime.now().isoformat(),
            created=datetime.now().isoformat(),
        )
        self._store[key] = entry
        self._flush()

    def record_outcome(self, key: str, success: bool):
        if key in self._store:
            if success:
                self._store[key].success_count += 1
            else:
                self._store[key].failure_count += 1
            self._store[key].last_seen = datetime.now().isoformat()
            self._flush()

    def _flush(self):
        try:
            serializable = {}
            for k, entry in self._store.items():
                d = asdict(entry)
                d['decision'] = asdict(entry.decision)
                serializable[k] = d
            self._path.write_text(json.dumps(serializable, default=str, indent=2))
        except Exception:
            pass


class GeoffCritic:
    """
    Critic agent that sanity-checks Geoff's forensic analysis.
    - Checks for obvious hallucinations (claims not in raw output)
    - Validates IOC extraction against source text
    - Commits validation results to git for reproducibility
    """

    def __init__(self, ollama_url: str = None,
                 model: str = os.environ.get("GEOFF_CRITIC_MODEL", "qwen3.5:cloud")):
        self.ollama_url = ollama_url or os.environ.get('OLLAMA_URL', 'http://localhost:11434')
        self.model = model
        self._api_key = os.environ.get('OLLAMA_API_KEY', '')
        self.validation_log = []

    def _base_url(self):
        if self._api_key:
            return 'https://ollama.com/api'
        return self.ollama_url

    def _ollama_headers(self):
        h = {'Content-Type': 'application/json'}
        if self._api_key:
            h['Authorization'] = f'Bearer {self._api_key}'
        return h

    def _call_critic_llm(self, prompt: str) -> str:
        """Call LLM for sanity check review

        Returns the LLM response, or empty string on failure.
        On Ollama timeout after retries, returns empty string so the caller
        can mark the step needs_review instead of producing a finding.
        """
        _MAX_RETRY_TIME = 1800  # 30 minutes total retry window
        _BACKOFF_TIMES = [30, 60, 120, 240, 300]  # seconds, last value repeats
        _max_retries = 99  # effectively unlimited within time window
        _error_patterns = (
            "Having trouble connecting to Ollama",
            "Check OLLAMA_URL",
            "[ERROR] Ollama returned",
        )
        _start = time.time()

        for attempt in range(_max_retries):
            elapsed = time.time() - _start
            if elapsed > _MAX_RETRY_TIME:
                print(f"[CRITIC] LLM retry timeout after {elapsed:.0f}s/{_MAX_RETRY_TIME}s")
                return ""

            try:
                response = requests.post(
                    f"{self._base_url()}/generate",
                    headers=self._ollama_headers(),
                    json={
                        "model": self.model,
                        "prompt": prompt,
                        "stream": False,
                        "options": {"temperature": 0.2}
                    },
                    timeout=600
                )
                if response.status_code == 200:
                    result_text = response.json().get('response', '')
                    # Reject error messages that leaked into the response
                    if any(pat in result_text for pat in _error_patterns):
                        wait = _BACKOFF_TIMES[min(attempt, len(_BACKOFF_TIMES) - 1)]
                        remaining = _MAX_RETRY_TIME - elapsed
                        actual_wait = min(wait, remaining)
                        if actual_wait <= 0:
                            return ""
                        print(f"[CRITIC] Ollama error in response, retry {attempt+1} after {wait}s (elapsed {elapsed:.0f}s/{_MAX_RETRY_TIME}s)")
                        time.sleep(actual_wait)
                        continue
                    return result_text
                elif response.status_code in (401, 403):
                    print(f"[CRITIC] LLM HTTP {response.status_code} — bad auth, giving up immediately")
                    return ""
                elif 500 <= response.status_code < 600:
                    # Server errors: brief retry (3 attempts with 10s backoff)
                    if attempt < 3:
                        wait = 10
                        remaining = _MAX_RETRY_TIME - elapsed
                        actual_wait = min(wait, remaining)
                        if actual_wait <= 0:
                            return ""
                        print(f"[CRITIC] LLM HTTP {response.status_code} (server error), retry {attempt+1} after {wait}s")
                        time.sleep(actual_wait)
                        continue
                    # After 3 attempts, fall through to full retry window
                    wait = _BACKOFF_TIMES[min(attempt, len(_BACKOFF_TIMES) - 1)]
                    remaining = _MAX_RETRY_TIME - elapsed
                    actual_wait = min(wait, remaining)
                    if actual_wait <= 0:
                        return ""
                    print(f"[CRITIC] Ollama HTTP {response.status_code}, retry {attempt+1} after {wait}s (elapsed {elapsed:.0f}s/{_MAX_RETRY_TIME}s)")
                    time.sleep(actual_wait)
                    continue
            except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
                wait = _BACKOFF_TIMES[min(attempt, len(_BACKOFF_TIMES) - 1)]
                remaining = _MAX_RETRY_TIME - elapsed
                actual_wait = min(wait, remaining)
                if actual_wait <= 0:
                    return ""
                print(f"[CRITIC] LLM {type(e).__name__} retry {attempt+1} after {wait}s (elapsed {elapsed:.0f}s/{_MAX_RETRY_TIME}s)")
                time.sleep(actual_wait)
                continue
            except Exception as e:
                print(f"[CRITIC] LLM Error (attempt {attempt+1}): {e}")
                wait = _BACKOFF_TIMES[min(attempt, len(_BACKOFF_TIMES) - 1)]
                remaining = _MAX_RETRY_TIME - elapsed
                actual_wait = min(wait, remaining)
                if actual_wait <= 0:
                    return ""
                time.sleep(actual_wait)
                continue
        return ""  # All retries exceeded (should not normally reach here)

    # Forensic metadata keywords that indicate IOC bleed-through
    # (same list used in narrative_report._FORENSIC_METADATA_KEYWORDS)
    _FORENSIC_NOISE_KEYWORDS = frozenset([
        'Image Verification', 'Acquisition started', 'Acquisition finished',
        '[Device Info]', 'Source Type', 'Drive Geometry',
        'Cylinders:', 'Tracks per Cylinder', 'Sectors per Track',
        'Physical Evidentiary', 'MD5 checksum', 'SHA1 checksum', 'SHA256 checksum',
        'Image Information:',
    ])

    # Well-known infrastructure IPs that should not be treated as IOCs
    _INFRASTRUCTURE_IPS = frozenset([
        '8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1',
        '208.67.222.222', '208.67.220.220',  # OpenDNS
        '9.9.9.9',  # Quad9
        '0.0.0.0', '127.0.0.1', '255.255.255.255',
    ])

    # Noise URL domains (same as narrative_report._NOISE_URL_DOMAINS)
    _NOISE_URL_DOMAINS = frozenset([
        'doubleclick.net', 'atwola.com', 'googlesyndication.com',
        'googleadservices.com', 'quantserve.com', 'scorecardresearch.com',
        'googletagmanager.com', 'google-analytics.com', 'moatads.com',
        'outbrain.com', 'taboola.com', 'criteo.com', 'rubiconproject.com',
        'pubmatic.com', 'openx.net', 'casalemedia.com', 'agkn.com',
        'adsrvr.org', 'adsymptotic.com', 'exponential.com', 'burstnet.com',
        'contextweb.com', 'bluekai.com', 'demdex.net', 'rlcdn.com',
        'adsafeprotected.com', '2mdn.net', 'adform.net', 'adnxs.com',
        'adzerk.net', 'tribalfusion.com', 'turn.com', 'invitemedia.com',
        'media6degrees.com', 'specificmedia.com', 'tidaltv.com',
    ])

    # System email local parts that should not be treated as IOCs
    _SYSTEM_EMAIL_LOCALPARTS = frozenset({
        'mailer-daemon', 'postmaster', 'root',
        'administrator', 'noreply', 'no-reply',
    })

    def validate_tool_output(self, tool_name: str, tool_params: Dict,
                            raw_output: str, geoff_analysis: str) -> Dict[str, Any]:
        """
        Validate tool output: check for hallucinations, nonsense, empty output,
        IOC presence in raw data, and produce an explicit verdict.

        Returns:
            Dict with verdict (APPROVED/REQUIRES_REVIEW/REJECTED), hallucinations,
            nonsense, invalid_iocs, passes_sanity, and metadata.
        """
        safe_tool_name = str(tool_name).replace("\n", " ").replace("\r", " ")[:100]
        safe_raw = str(raw_output)[:3000]
        safe_analysis = str(geoff_analysis).replace("\n", "\n  ")[:5000]

        # ---- Pre-check: empty or near-empty output ----
        raw_stripped = str(raw_output).strip()
        too_short = len(raw_stripped) < 15  # less than 15 chars of output

        # ---- Pre-check: forensic metadata bleed-through ----
        # If the raw output is primarily forensic acquisition metadata,
        # it's not meaningful forensic data
        forensic_metadata_lines = 0
        total_lines = raw_stripped.count('\n') + 1
        for kw in self._FORENSIC_NOISE_KEYWORDS:
            forensic_metadata_lines += raw_stripped.lower().count(kw.lower())
        forensic_noise_ratio = forensic_metadata_lines / max(total_lines, 1)
        is_forensic_metadata = forensic_noise_ratio > 0.5  # >50% metadata lines

        # Extract claimed IOCs from analysis for cross-check against raw output
        claimed_iocs = []
        if geoff_analysis:
            claimed_iocs.extend(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', geoff_analysis))
            claimed_iocs.extend(re.findall(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b', geoff_analysis))
            claimed_iocs.extend(re.findall(r'\b[0-9a-f]{32}\b', geoff_analysis, re.I))
            claimed_iocs.extend(re.findall(r'\b[0-9a-f]{40}\b', geoff_analysis, re.I))
            claimed_iocs.extend(re.findall(r'\b[0-9a-f]{64}\b', geoff_analysis, re.I))
        # Filter out non-IOC domain-like strings (e.g. common tool names)
        claimed_iocs = [i for i in claimed_iocs if i not in (
            'localhost', 'local', 'domain', 'timeout', 'error',
            'stdout', 'stderr', 'bytes', 'sectors', 'partitions',
        )]
        # Additional noise filtering: reject well-known infrastructure IPs
        claimed_iocs = [i for i in claimed_iocs if i not in self._INFRASTRUCTURE_IPS]
        # Reject noise URL domains
        claimed_iocs = [i for i in claimed_iocs
                       if not any(nd in i.lower() for nd in self._NOISE_URL_DOMAINS)]
        # Reject system email local parts
        claimed_iocs = [i for i in claimed_iocs
                       if not (i.split('@')[0].lower() in self._SYSTEM_EMAIL_LOCALPARTS if '@' in i else False)]

        # Check which claimed IOCs actually appear in raw output
        missing_iocs = []
        for ioc in claimed_iocs:
            if ioc not in raw_stripped:
                missing_iocs.append(ioc)

        # ---- LLM call for detailed sanity check ----
        sanity_prompt = f"""You are a forensic validation critic. Your job is to issue an explicit verdict on whether this tool output and analysis are trustworthy.

TOOL: {safe_tool_name}
RAW OUTPUT (excerpt):
{safe_raw}

ANALYSIS:
{safe_analysis}

IMPORTANT CONTEXT:
- If the raw output contains E01/E02 acquisition metadata (drive geometry, checksums, image verification, sector counts, partition tables without file content), the "findings" are forensic artifacts, NOT indicators of compromise. Flag these as nonsense.
- Private IP addresses (10.x.x.x, 172.16-31.x.x, 192.168.x.x, 127.x.x.x) are NOT actionable IOCs.
- Well-known infrastructure IPs (8.8.8.8, 1.1.1.1, etc.) are NOT actionable IOCs.
- Version strings like "7.0.2.7" that look like IPs are NOT IOCs.
- Paths shorter than 15 characters or containing binary/control characters are likely noise, not real file paths.

Answer these questions:
1. Does the analysis claim something NOT present in the raw output? (hallucination)
2. Is there any obvious nonsense? (impossible values, contradictory claims, forensic metadata presented as IOCs)
3. Are any claimed IOCs (IPs, hashes, timestamps, URLs) invalid format?
4. Does the raw output contain meaningful data (non-empty, no only-error messages)?
5. **What is your overall verdict?** Choose one:
   - APPROVED: analysis is correct, output is meaningful, no issues found
   - REQUIRES_REVIEW: minor issues (some missing context, ambiguous data, or minor hallucinations that don't affect overall conclusion)
   - REJECTED: major issues (critical hallucinations, empty output, nonsense claims)

Respond in JSON:
{{
    "hallucinations": ["list claims not in raw output, or empty list"],
    "nonsense": ["list obvious nonsense, or empty list"],
    "invalid_iocs": ["list IOCs with invalid format, or empty list"],
    "passes_sanity": true/false,
    "verdict": "APPROVED" or "REQUIRES_REVIEW" or "REJECTED",
    "verdict_reason": "Brief explanation of why this verdict was chosen"
}}"""

        critic_response = self._call_critic_llm(sanity_prompt)

        # If critic LLM was unavailable after retries, mark as needs_review
        if not critic_response or not critic_response.strip():
            result = {
                "hallucinations": [],
                "nonsense": [],
                "invalid_iocs": [],
                "passes_sanity": None,
                "needs_review": True,
                "unverified_reason": "Ollama timeout - critic validation failed",
                "verdict": "REQUIRES_REVIEW",
                "verdict_reason": "Ollama unavailable after retries",
                "parse_error": True,
                "raw_critic_response": "Ollama unavailable after retries",
            }
        else:
            try:
                json_match = re.search(r'\{.*\}', critic_response, re.DOTALL)
                if json_match:
                    result = json.loads(json_match.group())
                else:
                    result = json.loads(critic_response)
            except Exception:
                result = {
                    "hallucinations": [],
                    "nonsense": [],
                    "passes_sanity": None,
                    "verdict": "REQUIRES_REVIEW",
                    "verdict_reason": "Failed to parse LLM response",
                    "parse_error": True,
                    "raw_critic_response": critic_response[:500]
                }

        # ---- Post-processing: logic-based checks that override the LLM if needed ----

        # 1. Empty output detection (if output is too short, that's always a problem)
        if too_short:
            result["empty_output"] = True
            # Downgrade verdict if LLM missed this
            if result.get("verdict") == "APPROVED":
                result["verdict"] = "REJECTED"
                result["verdict_reason"] = f"Output is too short ({len(raw_stripped)} chars) — no meaningful data produced"
                result["passes_sanity"] = False
                if "Empty/insufficient output" not in result.get("nonsense", []):
                    result.setdefault("nonsense", []).append("Empty/insufficient output")

        # 1b. Forensic metadata bleed-through detection
        # If the raw output is dominated by E01 acquisition metadata (drive geometry,
        # checksums, image verification), the "findings" are forensic artifacts, not IOCs
        if is_forensic_metadata:
            result["forensic_metadata_bleedthrough"] = True
            if result.get("verdict") == "APPROVED":
                result["verdict"] = "REQUIRES_REVIEW"
                result["verdict_reason"] = ("Raw output is dominated by forensic acquisition metadata "
                                               "(drive geometry, checksums, image verification) — "
                                               "findings may be forensic artifacts, not IOCs")
                result["passes_sanity"] = False
            if "Forensic metadata bleed-through" not in result.get("nonsense", []):
                result.setdefault("nonsense", []).append("Forensic metadata bleed-through")

        # 2. IOC presence verification
        if missing_iocs:
            result["claimed_iocs_missing_from_raw"] = missing_iocs
            # Downgrade verdict if analysis claims IOCs not in raw output
            if result.get("verdict") == "APPROVED" and missing_iocs:
                result["verdict"] = "REQUIRES_REVIEW"
                result["verdict_reason"] = f"Analysis claims {len(missing_iocs)} IOC(s) not found in raw output"
                result["passes_sanity"] = False

        # 2b. Private IP and infrastructure IOC filtering
        # Even if IOCs are present in raw output, private IPs and well-known
        # infrastructure IPs are not actionable IOCs and should be flagged
        _priv_ip_re = re.compile(
            r'^(10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.|127\\.|0\\.0\\.0\\.0|255\\.)')
        infra_in_analysis = []
        if geoff_analysis:
            # Check for private/well-known IPs in analysis output
            for ip_match in re.finditer(r'\b(\d{1,3}\.){3}\d{1,3}\b', geoff_analysis):
                ip = ip_match.group(0)
                if ip in self._INFRASTRUCTURE_IPS or _priv_ip_re.match(ip):
                    infra_in_analysis.append(ip)
        if infra_in_analysis:
            result["infrastructure_ips_in_analysis"] = infra_in_analysis
            # Don't downgrade verdict for this, but flag it for human review
            if result.get("verdict") == "APPROVED":
                result.setdefault("nonsense", []).append(
                    f"Private/infrastructure IPs treated as IOCs: {', '.join(infra_in_analysis[:5])}"
                )

        # 3. Derive verdict from passes_sanity if LLM didn't provide one
        if "verdict" not in result or result.get("verdict") not in ("APPROVED", "REQUIRES_REVIEW", "REJECTED"):
            ps = result.get("passes_sanity")
            if ps is True:
                result["verdict"] = "APPROVED"
                result["verdict_reason"] = "Sanity check passed"
            elif ps is False:
                result["verdict"] = "REJECTED"
                result["verdict_reason"] = "Sanity check failed"
            else:
                result["verdict"] = "REQUIRES_REVIEW"
                result["verdict_reason"] = "Sanity check inconclusive"

        # 4. Default passes_sanity if missing
        if "passes_sanity" not in result:
            result["passes_sanity"] = True if result.get("verdict") == "APPROVED" else (
                False if result.get("verdict") == "REJECTED" else None
            )

        # Add metadata
        result.update({
            "tool_name": tool_name,
            "timestamp": datetime.now().isoformat(),
            "raw_output_length": len(raw_output),
            "analysis_length": len(geoff_analysis),
        })

        return result

    def validate_ioc_extraction(self, iocs: Dict[str, List],
                               source_text: str) -> Dict[str, Any]:
        """Validate extracted IOCs are actually present in source"""
        false_positives = []
        validated_iocs = {}

        for ioc_type, ioc_list in iocs.items():
            validated_iocs[ioc_type] = []
            for ioc in ioc_list:
                if ioc in source_text:
                    validated_iocs[ioc_type].append(ioc)
                else:
                    false_positives.append({
                        "type": ioc_type,
                        "value": ioc,
                        "reason": "Not found in source text"
                    })

        return {
            "validation_type": "iocs",
            "original_ioc_count": sum(len(v) for v in iocs.values()),
            "validated_ioc_count": sum(len(v) for v in validated_iocs.values()),
            "false_positives": false_positives,
            "false_positive_count": len(false_positives),
            "validated_iocs": validated_iocs,
            "timestamp": datetime.now().isoformat()
        }

    # --- IOC Format Validation Helpers ---

    @staticmethod
    def _is_valid_ip(value: str) -> bool:
        """Check if value looks like a valid IPv4 address."""
        parts = value.split('.')
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False

    @staticmethod
    def _is_valid_hash(value: str) -> bool:
        """Check if value looks like a valid MD5/SHA1/SHA256 hash."""
        hex_chars = set("0123456789abcdef")
        value_lower = value.lower()
        if not all(c in hex_chars for c in value_lower):
            return False
        return len(value_lower) in (32, 40, 64)  # MD5, SHA1, SHA256

    @staticmethod
    def _is_valid_timestamp(value) -> bool:
        """Check if value is a plausible forensic timestamp.
        Accepts: epoch seconds (0-2B range), Windows FILETIME, ISO 8601 strings.
        Does NOT reject nanosecond epochs — those are common in forensic data."""
        if isinstance(value, (int, float)):
            # Epoch seconds or epoch millis
            return 0 <= value <= 4_000_000_000 or 0 <= value / 1000 <= 4_000_000_000
        if isinstance(value, str):
            # ISO 8601 format
            if re.match(r'\d{4}-\d{2}-\d{2}', value):
                return True
            # Epoch as string
            try:
                v = float(value)
                return 0 <= v <= 4_000_000_000 or 0 <= v / 1000 <= 4_000_000_000
            except ValueError:
                pass
        return True  # Don't reject timestamps we can't parse — they might be valid forensic formats

    @staticmethod
    def _is_valid_url(value: str) -> bool:
        """Basic URL format check."""
        return bool(re.match(r'https?://', value, re.IGNORECASE))

    def validate_ioc_formats(self, iocs: Dict[str, List]) -> Dict[str, Any]:
        """Validate that extracted IOCs have valid format (not presence in source).
        This is complementary to validate_ioc_extraction() which checks source text presence.

        Checks: IP format, hash format, timestamp plausibility, URL format.
        Returns format validation results without modifying the IOCs.
        """
        format_issues = []
        format_valid = []

        validators = {
            'ips': self._is_valid_ip,
            'ip_addresses': self._is_valid_ip,
            'domains': lambda v: bool(re.match(r'[\w.-]+\.[a-z]{2,}$', v, re.IGNORECASE)),
            'hashes': self._is_valid_hash,
            'md5': self._is_valid_hash,
            'sha1': self._is_valid_hash,
            'sha256': self._is_valid_hash,
            'urls': self._is_valid_url,
            'emails': lambda v: bool(re.match(r'^[\w.+-]+@[\w.-]+$', v)),
            'timestamps': self._is_valid_timestamp,
        }

        for ioc_type, ioc_list in iocs.items():
            validator = validators.get(ioc_type)
            if validator is None:
                # Unknown type — can't validate format, assume OK
                format_valid.extend(ioc_list)
                continue
            for ioc in ioc_list:
                if isinstance(ioc, str) and validator(ioc):
                    format_valid.append(ioc)
                else:
                    format_issues.append({
                        "type": ioc_type,
                        "value": str(ioc)[:100],
                        "reason": f"Invalid {ioc_type} format"
                    })

        return {
            "validation_type": "ioc_formats",
            "total_iocs": len(format_valid) + len(format_issues),
            "format_valid_count": len(format_valid),
            "format_issues": format_issues,
            "format_issue_count": len(format_issues),
            "timestamp": datetime.now().isoformat()
        }

    def commit_validation(self, investigation_id: str, validation_result: Dict,
                         base_path: str = os.environ.get("GEOFF_GIT_DIR", "/tmp/geoff-validations")):
        """Commit validation result to git for reproducibility"""

        validation_dir = Path(base_path) / "validations"
        validation_dir.mkdir(exist_ok=True)

        validation_file = validation_dir / f"{investigation_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        with open(validation_file, 'w') as f:
            json.dump(validation_result, f, indent=2)

        # Git commit
        try:
            subprocess.run(['git', 'config', 'user.email'], cwd=base_path,
                         capture_output=True, check=True)
        except Exception:
            subprocess.run(['git', 'config', 'user.email', 'critic@geoff.local'],
                         cwd=base_path, capture_output=True)
            subprocess.run(['git', 'config', 'user.name', 'Geoff Critic'],
                         cwd=base_path, capture_output=True)

        try:
            subprocess.run(['git', 'add', str(validation_file)],
                         cwd=base_path, check=True, capture_output=True)

            passes = validation_result.get('passes_sanity', False)
            label = "PASS" if passes else "FAIL"
            commit_msg = f"[CRITIC-{label}] {investigation_id}: sanity check"

            subprocess.run(['git', 'commit', '-m', commit_msg],
                         cwd=base_path, capture_output=True)

            print(f"[CRITIC] Committed validation: {validation_file.name}")
            return True
        except Exception as e:
            print(f"[CRITIC] Git error: {e}")
            return False

    # --- Self-Healing (Execution Error Analysis) ---

    def analyze_execution_error(self, tool_name: str, tool_params: Dict,
                                 error_result: Dict, context: Dict = None) -> Dict[str, Any]:
        """
        Critic-based self-healing: analyze tool execution errors and recommend fixes.
        
        This is the central healing authority. When a tool fails, the Critic:
        1. Classifies the error type
        2. Determines if it's healable
        3. Returns a healing strategy for the orchestrator to execute
        
        Returns:
            Dict with keys:
            - healable: bool - whether this error can be healed
            - error_type: str - classification (partition_offset, invalid_profile, etc.)
            - healing_strategy: str - description of the fix
            - action: str - what the orchestrator should do
            - new_params: Dict - modified parameters for retry
            - confidence: float - how confident the Critic is (0.0-1.0)
            - explanation: str - why this fix should work
        """
        stderr = error_result.get("stderr", "").lower()
        stdout = error_result.get("stdout", "")
        error_msg = error_result.get("error", "")
        ctx = context or {}
        
        # Quick rejection: non-healable errors
        non_healable = [
            "not found", "no such file", "permission denied",
            "unauthorized", "authentication failed", "ssl error",
            "network unreachable", "connection refused"
        ]
        if any(pat in stderr for pat in non_healable):
            return {
                "healable": False,
                "error_type": "non_healable",
                "reason": "Error pattern indicates non-recoverable failure",
                "confidence": 0.9
            }
        
        # Healable error patterns
        healable_patterns = [
            "cannot determine file system type",
            "dinode_lookup", "update sequence", "metadata structure",
            "mft size", "mft entry", "bad magic", "invalid superblock",
            "invalid profile", "unrecognized windows version",
            "database is locked", "sqlite_busy",
            "hive locked", "file is locked"
        ]
        
        if not any(pat in stderr for pat in healable_patterns):
            # Not obviously healable, but ask LLM for analysis
            pass  # Fall through to LLM analysis
        
        # Build healing analysis prompt
        safe_tool = str(tool_name).replace("\n", " ")[:100]
        safe_params = json.dumps(tool_params, default=str)[:800]
        safe_stderr = stderr[:500]
        safe_stdout = stdout[:300]
        safe_context = json.dumps(ctx, default=str)[:500]
        
        healing_prompt = f"""You are the Geoff Critic, an expert DFIR system analyzer. A forensic tool failed with an error.

TOOL: {safe_tool}
PARAMETERS: {safe_params}

ERROR OUTPUT:
stderr: {safe_stderr}
stdout: {safe_stdout}
error: {error_msg}

CONTEXT:
{safe_context}

Analyze this error and determine if it can be healed. Consider:
1. Is this a known recoverable error (partition offset, profile mismatch, locked file, etc.)?
2. What is the root cause?
3. What is the best healing strategy?

Healing actions available:
- retry_with_offset: Retry with auto-detected partition offset
- retry_without_offset: Retry treating entire image as filesystem
- retry_with_profile: Retry with different Volatility/TSK profile
- retry_with_backoff: Retry SQLite operations with delays (0.5s, 1s, 2s)
- copy_then_retry: Copy locked file to temp location first
- skip: Skip this step, mark as failed but non-critical
- fail: Cannot heal, mark as failed

Respond ONLY in valid JSON:
{{
    "healable": true/false,
    "error_type": "partition_offset|invalid_profile|locked_file|sqlite_busy|metadata_corrupt|other|none",
    "root_cause": "brief technical explanation",
    "healing_strategy": "description of proposed fix",
    "action": "retry_with_offset|retry_without_offset|retry_with_profile|retry_with_backoff|copy_then_retry|skip|fail",
    "new_params": {{"key": "value"}},
    "confidence": 0.0-1.0,
    "explanation": "why this fix should work"
}}"""

        critic_response = self._call_critic_llm(healing_prompt)
        
        try:
            json_match = re.search(r'\{.*\}', critic_response, re.DOTALL)
            if json_match:
                result = json.loads(json_match.group())
            else:
                result = json.loads(critic_response)
                
            # Ensure required fields
            if "healable" not in result:
                result["healable"] = False
            if "action" not in result:
                result["action"] = "fail"
            if "new_params" not in result:
                result["new_params"] = {}
            if "confidence" not in result:
                result["confidence"] = 0.5
                
            # Add metadata
            result["tool_name"] = tool_name
            result["timestamp"] = datetime.now().isoformat()
            result["original_error"] = stderr[:200]
            
            return result
            
        except Exception as e:
            # LLM failed to return valid JSON - conservative fallback
            return {
                "healable": False,
                "error_type": "parse_error",
                "reason": f"Could not parse Critic healing response: {e}",
                "action": "fail",
                "confidence": 0.0,
                "llm_response": critic_response[:500]
            }

    # --- Self-Healing v2 (ErrorContext-driven) ---

    def analyze_execution_error_v2(self, ctx: ErrorContext) -> HealDecision:
        """LLM-powered error diagnosis using structured ErrorContext.

        Sends the full error context to the Critic LLM and parses the
        structured JSON response into a HealDecision.
        """
        prompt = self._build_heal_prompt(ctx)
        t0 = time.time()
        raw = self._call_critic_llm(prompt)
        latency_ms = int((time.time() - t0) * 1000)

        try:
            m = re.search(r'\{.*\}', raw, re.DOTALL)
            data = json.loads(m.group() if m else raw)
        except Exception:
            return HealDecision(
                fixable=False, fix_type="fail", confidence=0,
                root_cause="parse_error", llm_model=self.model,
                latency_ms=latency_ms, from_cache=False,
            )

        return HealDecision(
            fixable=data.get("fixable", False),
            fix_type=data.get("fix_type", "fail"),
            fix_detail=data.get("fix_detail", ""),
            root_cause=data.get("root_cause", ""),
            new_params=data.get("new_params") or {},
            fallback_module=data.get("fallback_module"),
            fallback_function=data.get("fallback_function"),
            adjusted_command=data.get("adjusted_command"),
            skip_reason=data.get("skip_reason"),
            confidence=int(data.get("confidence", 5)),
            llm_model=self.model,
            latency_ms=latency_ms,
            from_cache=False,
        )

    def _build_heal_prompt(self, ctx: ErrorContext) -> str:
        """Build the Critic LLM prompt for error diagnosis."""
        return f"""You are the Geoff Critic, an expert DFIR forensic analyst. A forensic pipeline step has failed.
Your task: diagnose the error and prescribe a fix.

=== FAILED STEP ===
{ctx.to_prompt_block()}

=== AVAILABLE FIX TYPES ===
- retry_params         Modify params dict and retry the same tool
- retry_with_offset    Change the partition offset (sleuthkit only)
- retry_without_offset Remove offset param (sleuthkit only)
- retry_with_profile   Change Volatility profile or TSK filesystem type
- retry_with_backoff   Retry with 0.5s/1s/2s delays (SQLite busy errors)
- copy_then_retry      Copy locked file to temp, retry on copy
- fallback_tool        Use a different specialist or function entirely
- adjust_command       Modify the raw shell command string
- skip_file            Mark this evidence file as unprocessable and continue
- skip_step            Mark this step as non-critical and skip it
- fail                 Cannot heal; propagate failure

=== INSTRUCTIONS ===
1. Identify the root cause precisely.
2. If fixable, choose the most targeted fix type.
3. For retry_params: provide the complete new_params dict (merge with existing).
4. For fallback_tool: specify module and function from the Geoff specialist registry.
5. For adjust_command: provide the complete corrected shell command.
6. Set confidence 1-10 (10 = certain this works).
7. Only choose skip_file if the artifact is genuinely corrupt/unreadable.
8. Only choose fail if the error is environmental (missing tool, permission denied, no such file).

Respond ONLY in valid JSON — no explanation outside the JSON block:
{{
    "fixable": true,
    "fix_type": "retry_params",
    "fix_detail": "human-readable description of what's being changed and why",
    "root_cause": "precise technical diagnosis",
    "new_params": {{}},
    "fallback_module": null,
    "fallback_function": null,
    "adjusted_command": null,
    "skip_reason": null,
    "confidence": 8
}}"""

    def analyze_chat_request(self, user_message: str, chat_history: List[Dict],
                              current_context: Dict = None) -> Dict[str, Any]:
        """
        Chat-based healing: analyze user questions about tool failures.
        
        When user asks in chat about errors, the Critic:
        1. Detects if user is asking about a failed tool/execution
        2. Provides healing advice or executes healing
        3. Returns natural language response + structured healing plan
        """
        ctx = current_context or {}
        
        # Check if this is a healing-related query
        healing_keywords = [
            "failed", "error", "not working", "cannot", "unable",
            "fix", "repair", "retry", "heal", "recover",
            "sleuthkit", "volatility", "fls", "mmls", "partition"
        ]
        
        is_healing_query = any(kw in user_message.lower() for kw in healing_keywords)
        
        if not is_healing_query:
            return {"is_healing_request": False}
        
        # Build chat healing prompt
        history_str = "\n".join([
            f"{'User' if h.get('role') == 'user' else 'Assistant'}: {h.get('content', '')[:200]}"
            for h in chat_history[-5:]  # Last 5 messages
        ])
        
        chat_prompt = f"""You are Geoff Critic in chat mode. A user is asking about a forensic tool or execution issue.

USER MESSAGE: {user_message}

CHAT HISTORY:
{history_str}

CURRENT CONTEXT:
{json.dumps(ctx, default=str)[:500]}

Analyze the user's request:
1. Are they asking about a specific tool failure?
2. What tool and parameters were involved (if known from context)?
3. What healing advice or action should be taken?

If they want to retry/fix a failed operation, provide healing guidance.

Respond in JSON:
{{
    "is_healing_request": true,
    "detected_tool": "tool.name or null",
    "detected_issue": "description of the problem",
    "healing_advice": "natural language response for user",
    "can_auto_heal": true/false,
    "healing_action": "action if auto-heal possible, else null",
    "healing_params": {{}} 
}}"""

        response = self._call_critic_llm(chat_prompt)
        
        try:
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                result = json.loads(json_match.group())
            else:
                result = json.loads(response)
            result["timestamp"] = datetime.now().isoformat()
            return result
        except Exception:
            return {
                "is_healing_request": True,
                "detected_tool": None,
                "detected_issue": "Could not parse request",
                "healing_advice": "I see you're asking about an error. Could you specify which tool or evidence file had the issue?",
                "can_auto_heal": False,
                "healing_action": None,
                "healing_params": {}
            }

    def get_validation_summary(self, investigation_id: str,
                              base_path: str = os.environ.get("GEOFF_GIT_DIR", "/tmp/geoff-validations")) -> Dict:
        """Get summary of all validations for an investigation"""

        validation_dir = Path(base_path) / "validations"
        if not validation_dir.exists():
            return {"validations": [], "total": 0, "passed": 0, "failed": 0}

        validations = []
        passed = 0
        failed = 0

        for val_file in sorted(validation_dir.glob(f"{investigation_id}_*.json")):
            try:
                with open(val_file) as f:
                    val = json.load(f)
                    validations.append(val)
                    if val.get('passes_sanity', False):
                        passed += 1
                    else:
                        failed += 1
            except Exception:
                pass

        return {
            "investigation_id": investigation_id,
            "validations": validations,
            "total": len(validations),
            "passed": passed,
            "failed": failed,
            "pass_rate": passed / len(validations) if validations else 0
        }


class ValidationPipeline:
    """
    Pipeline that wraps Geoff's operations with a sanity check.
    Execute tool -> sanity check results. No double validation.
    """

    def __init__(self, geoff_orchestrator, critic: Optional[GeoffCritic] = None):
        self.orchestrator = geoff_orchestrator
        self.critic = critic or GeoffCritic()
        self.investigation_id = None

    def start_investigation(self, case_name: str) -> str:
        """Start new investigation with validation tracking"""
        self.investigation_id = f"{case_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        return self.investigation_id

    def execute_and_validate(self, step: Dict[str, Any], geoff_analysis: str = "") -> Dict[str, Any]:
        """
        Execute tool step, then sanity check results.
        """
        module = step.get('module')
        function = step.get('function')
        params = step.get('params', {})

        # Execute tool
        print(f"[PIPELINE] Executing {module}.{function}...")
        tool_result = self.orchestrator.run_playbook_step(
            self.investigation_id or "unknown", step
        )

        # Get raw output
        raw_output = tool_result.get('stdout', '') or json.dumps(tool_result)

        # Sanity check the analysis if provided
        if geoff_analysis:
            print(f"[PIPELINE] Sanity checking analysis...")
            validation = self.critic.validate_tool_output(
                f"{module}.{function}",
                params,
                raw_output,
                geoff_analysis
            )

            # Commit validation
            self.critic.commit_validation(
                self.investigation_id or "unknown",
                validation
            )

            tool_result['critic_validation'] = validation
            tool_result['passes_sanity'] = validation.get('passes_sanity', False)

        return tool_result

    def get_reproducibility_package(self) -> Dict:
        """Generate package for another investigator to reproduce"""
        if not self.investigation_id:
            return {"error": "No active investigation"}

        summary = self.critic.get_validation_summary(self.investigation_id)

        return {
            "investigation_id": self.investigation_id,
            "reproducibility": {
                "all_steps_passed_sanity": summary['failed'] == 0,
                "sanity_check_pass_rate": summary['pass_rate'],
                "validation_count": summary['total']
            },
            "validation_summary": summary,
            "reproduction_instructions": [
                "1. Clone this git repository",
                "2. Checkout commit with investigation ID",
                "3. Review validations/ directory for step-by-step sanity checks",
                "4. Run same tool commands as logged",
                "5. Compare results against critic validations"
            ]
        }


# For direct testing
if __name__ == "__main__":
    critic = GeoffCritic()

    test_output = """
    r/r 1234:    /Users/admin/Desktop/evidence.doc
    r/r 1235:    /Users/admin/Desktop/normal.txt
    d/d 1236:    /Users/admin/Documents
    """

    test_analysis = "Found 3 files including evidence.doc and 2 deleted files."

    result = critic.validate_tool_output(
        "sleuthkit.fls",
        {"partition": "/dev/sda1"},
        test_output,
        test_analysis
    )

    print("Sanity Check Result:")
    print(json.dumps(result, indent=2))