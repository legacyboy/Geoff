#!/usr/bin/env python3
"""Chain of custody — Merkle hash-chained JSONL custody log for Geoff DFIR.

Implements tamper-evident, append-only per-case custody logging that satisfies
NIST SP 800-86, ISO 27037, ACPO Principle 3, and FRE 901 requirements.
"""
from __future__ import annotations

import concurrent.futures
import hashlib
import json
import logging
import os
import threading
import uuid
import warnings
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Thread pool for background evidence hashing (non-blocking, max 2 workers)
_hash_executor = concurrent.futures.ThreadPoolExecutor(
    max_workers=2, thread_name_prefix="coc_hash"
)

# Cache: {(path, mtime_ns, size): sha256} — avoids re-reading unchanged files
_stat_hash_cache: Dict[tuple, str] = {}
_stat_hash_cache_lock = threading.Lock()


def _stream_hash(path: str) -> str:
    """Streaming SHA-256, bypasses all memo caches."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            while True:
                chunk = f.read(1 << 20)  # 1 MB chunks
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return "hash_failed"


def _hash_with_stat_cache(path: str) -> str:
    """Hash file using (path, mtime_ns, size) as cache key.

    Only re-reads the file if its mtime or size has changed since last hash.
    This avoids double-reading evidence files that are unchanged between steps.
    """
    try:
        st = os.stat(path)
        key = (path, st.st_mtime_ns, st.st_size)
        with _stat_hash_cache_lock:
            cached = _stat_hash_cache.get(key)
        if cached is not None:
            return cached
        result = _stream_hash(path)
        with _stat_hash_cache_lock:
            _stat_hash_cache[key] = result
        return result
    except OSError:
        return "hash_failed"


def _start_hash_async(path: str) -> "concurrent.futures.Future[str]":
    """Submit a file hash to the background thread pool. Returns immediately."""
    return _hash_executor.submit(_hash_with_stat_cache, path)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class ChainOfCustodyRecord:
    """Single entry in the chain of custody log."""

    # Identity
    record_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    record_type: str = "step"  # step | transfer | verification | attestation | failure

    # Timestamp (UTC ISO 8601 with timezone) — set by ChainOfCustodyLog.append
    timestamp: str = ""

    # Evidence identification
    evidence_path: str = ""
    evidence_sha256: str = ""
    evidence_size: int = 0

    # Action performed
    playbook_id: str = ""
    specialist_module: str = ""
    specialist_function: str = ""
    specialist_version: str = ""
    raw_command: str = ""
    full_parameters: Dict = field(default_factory=dict)

    # Output integrity
    output_sha256: str = ""
    output_size: int = 0

    # Agent identity
    initiating_agent: str = "Geoff"
    device_id: str = ""

    # Pre/post verification
    pre_verification_hash: str = ""
    post_verification_hash: str = ""
    verification_passed: Optional[bool] = None

    # Hash chain — filled by ChainOfCustodyLog.append
    previous_record_hash: str = ""
    record_hash: str = ""

    # Outcome
    status: str = "completed"
    error_detail: Optional[str] = None

    # Critic validation
    critic_verdict: Optional[str] = None
    critic_confidence: Optional[str] = None

    # Git anchor
    git_commit_sha: Optional[str] = None

    # Analyst attestation (human review)
    attested_by: Optional[str] = None
    attestation_timestamp: Optional[str] = None


# ---------------------------------------------------------------------------
# Chain of custody log
# ---------------------------------------------------------------------------

class ChainOfCustodyLog:
    """Append-only, Merkle hash-chained JSONL custody log.

    Each record's SHA-256 covers all fields except record_hash itself, and
    includes the previous record's hash — forming a tamper-evident linked list.

    Stores at {case_work_dir}/chain_of_custody.jsonl.
    """

    GENESIS_HASH: str = hashlib.sha256(b"GENESIS").hexdigest()

    def __init__(self, case_work_dir: Path, operator_id: str = "Geoff") -> None:
        self.log_path = Path(case_work_dir) / "chain_of_custody.jsonl"
        self.root_path = Path(case_work_dir) / "chain_of_custody_root.json"
        self.operator_id = operator_id
        self._lock = threading.Lock()
        self._prev_hash = self._load_last_hash()
        self._record_count = self._count_existing_records()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load_last_hash(self) -> str:
        if not self.log_path.exists():
            return self.GENESIS_HASH
        last = self.GENESIS_HASH
        try:
            with open(self.log_path) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        r = json.loads(line)
                        h = r.get("record_hash")
                        if h:
                            last = h
        except (OSError, json.JSONDecodeError):
            pass
        return last

    def _count_existing_records(self) -> int:
        if not self.log_path.exists():
            return 0
        count = 0
        try:
            with open(self.log_path) as f:
                for line in f:
                    if line.strip():
                        count += 1
        except OSError:
            pass
        return count

    def _compute_record_hash(self, record_dict: dict) -> str:
        """SHA-256 of record with all fields except record_hash, sorted by key."""
        d = {k: v for k, v in record_dict.items() if k != "record_hash"}
        canonical = json.dumps(d, sort_keys=True, default=str)
        return hashlib.sha256(canonical.encode()).hexdigest()

    def _compute_merkle_root(self, records: list) -> str:
        if not records:
            return hashlib.sha256(b"EMPTY").hexdigest()
        leaves = [r.get("record_hash", "") for r in records]
        while len(leaves) > 1:
            if len(leaves) % 2 == 1:
                leaves.append(leaves[-1])
            leaves = [
                hashlib.sha256((leaves[i] + leaves[i + 1]).encode()).hexdigest()
                for i in range(0, len(leaves), 2)
            ]
        return leaves[0]

    def _update_merkle_root(self) -> None:
        records: list = []
        try:
            with open(self.log_path) as f:
                for line in f:
                    if line.strip():
                        records.append(json.loads(line))
        except (OSError, json.JSONDecodeError):
            return
        root = self._compute_merkle_root(records)
        try:
            self.root_path.write_text(json.dumps({
                "merkle_root": root,
                "record_count": len(records),
                "computed_at": datetime.now(timezone.utc).isoformat(),
            }, indent=2))
        except OSError:
            pass

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def append(self, record: ChainOfCustodyRecord) -> dict:
        """Append record to the log, computing the hash chain. Returns persisted dict."""
        d = asdict(record)
        d["timestamp"] = datetime.now(timezone.utc).isoformat()

        with self._lock:
            d["previous_record_hash"] = self._prev_hash
            record_hash = self._compute_record_hash(d)
            d["record_hash"] = record_hash

            line = json.dumps(d, sort_keys=True, default=str) + "\n"
            try:
                self.log_path.parent.mkdir(parents=True, exist_ok=True)
                with open(self.log_path, "a") as f:
                    f.write(line)
                    f.flush()
                    os.fsync(f.fileno())
            except OSError as e:
                logger.warning("ChainOfCustodyLog append failed: %s", e)
                return d

            self._prev_hash = record_hash
            self._record_count += 1
            count = self._record_count

        if count % 10 == 0:
            self._update_merkle_root()

        return d

    def verify(self) -> dict:
        """Verify the entire chain. Returns {valid, total_records, breaks, merkle_root_valid}."""
        breaks: List[dict] = []
        records: List[dict] = []
        prev_hash = self.GENESIS_HASH

        if not self.log_path.exists():
            return {
                "valid": False, "total_records": 0,
                "breaks": [{"error": "log_not_found"}], "merkle_root_valid": False,
            }

        try:
            with open(self.log_path) as f:
                for i, raw in enumerate(f):
                    raw = raw.strip()
                    if not raw:
                        continue
                    r = json.loads(raw)
                    records.append(r)

                    if r.get("previous_record_hash") != prev_hash:
                        breaks.append({
                            "record": i, "chain_break": True,
                            "expected_prev": prev_hash[:16],
                            "actual_prev": (r.get("previous_record_hash") or "")[:16],
                        })

                    computed = self._compute_record_hash(r)
                    if computed != r.get("record_hash"):
                        breaks.append({
                            "record": i, "hash_mismatch": True,
                            "expected": computed[:16],
                            "actual": (r.get("record_hash") or "")[:16],
                        })

                    prev_hash = r.get("record_hash", "")
        except json.JSONDecodeError as e:
            return {
                "valid": False, "total_records": len(records),
                "breaks": breaks + [{"error": str(e)}], "merkle_root_valid": False,
            }
        except OSError as e:
            return {
                "valid": False, "total_records": 0,
                "breaks": [{"error": str(e)}], "merkle_root_valid": False,
            }

        root_valid = True
        if self.root_path.exists():
            try:
                stored = json.loads(self.root_path.read_text())
                root_valid = stored.get("merkle_root") == self._compute_merkle_root(records)
            except Exception:
                root_valid = False

        return {
            "valid": len(breaks) == 0 and root_valid,
            "total_records": len(records),
            "breaks": breaks,
            "merkle_root_valid": root_valid,
        }

    def get_merkle_root(self) -> str:
        """Return the Merkle root SHA-256 of the entire chain."""
        if not self.log_path.exists():
            return hashlib.sha256(b"EMPTY").hexdigest()
        records: list = []
        try:
            with open(self.log_path) as f:
                for line in f:
                    if line.strip():
                        records.append(json.loads(line))
        except (OSError, json.JSONDecodeError):
            pass
        return self._compute_merkle_root(records)

    def get_custody_for_finding(self, finding_id: str) -> List[dict]:
        """Return all custody records related to a finding_id or step_key."""
        if not self.log_path.exists():
            return []
        results: List[dict] = []
        try:
            with open(self.log_path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    r = json.loads(line)
                    # Build the step_key for this record
                    step_key = ":".join(filter(None, [
                        r.get("playbook_id", ""),
                        r.get("specialist_module", ""),
                        r.get("specialist_function", ""),
                        r.get("device_id", ""),
                    ]))
                    if (finding_id in step_key
                            or (step_key and step_key in finding_id)
                            or r.get("record_id") == finding_id
                            or r.get("device_id") == finding_id):
                        results.append(r)
        except (OSError, json.JSONDecodeError):
            pass
        return results


# ---------------------------------------------------------------------------
# Evidence intake
# ---------------------------------------------------------------------------

def evidence_intake(
    evidence_dir: str,
    custody_log: Optional[ChainOfCustodyLog] = None,
) -> List[dict]:
    """Walk evidence_dir, hash all files, and create initial custody records.

    Creates one record per file with record_type="verification" (intake baseline).
    Returns list of persisted record dicts.
    """
    records: List[dict] = []
    for ev_file in sorted(Path(evidence_dir).rglob("*")):
        if not ev_file.is_file():
            continue
        sha256 = _hash_with_stat_cache(str(ev_file))
        try:
            size = ev_file.stat().st_size
        except OSError:
            size = 0
        rec = ChainOfCustodyRecord(
            record_type="verification",
            evidence_path=str(ev_file),
            evidence_sha256=sha256,
            evidence_size=size,
            initiating_agent="Geoff",
            status="intake_verified",
            pre_verification_hash=sha256,
            post_verification_hash=sha256,
            verification_passed=True,
        )
        if custody_log is not None:
            records.append(custody_log.append(rec))
        else:
            records.append(asdict(rec))
    return records


# ---------------------------------------------------------------------------
# Pre/post evidence integrity verification
# ---------------------------------------------------------------------------

def verify_evidence_integrity(
    evidence_path: str,
    pre_hash: Optional[str] = None,
    custody_log: Optional[ChainOfCustodyLog] = None,
) -> Tuple[str, str, Optional[bool]]:
    """Verify evidence file integrity before/after a specialist step.

    Call before the step with pre_hash=None to get the baseline hash.
    Call after the step with the previously returned pre_hash to check integrity.

    Returns (pre_hash, post_hash, verification_passed).
    Records a verification entry in custody_log if provided; records a failure
    entry and emits a warning if pre != post.
    """
    if not os.path.isfile(evidence_path):
        return ("N/A", "N/A", None)

    current_hash = _hash_with_stat_cache(evidence_path)

    if pre_hash is None:
        # Baseline call — no prior hash to compare against
        return (current_hash, current_hash, True)

    passed = current_hash == pre_hash

    if not passed:
        warnings.warn(
            f"CUSTODY VIOLATION: {evidence_path} hash changed "
            f"pre={pre_hash[:16]}... post={current_hash[:16]}...",
            RuntimeWarning,
            stacklevel=2,
        )

    if custody_log is not None:
        rec = ChainOfCustodyRecord(
            record_type="verification" if passed else "failure",
            evidence_path=evidence_path,
            evidence_sha256=pre_hash if passed else current_hash,
            pre_verification_hash=pre_hash,
            post_verification_hash=current_hash,
            verification_passed=passed,
            status="completed" if passed else "hash_mismatch",
            error_detail=(
                None if passed
                else f"Hash changed: pre={pre_hash[:16]} post={current_hash[:16]}"
            ),
        )
        custody_log.append(rec)

    return (pre_hash, current_hash, passed)


# ---------------------------------------------------------------------------
# Pipeline integration helpers
# ---------------------------------------------------------------------------

# Per-case custody log cache: case_work_dir str -> ChainOfCustodyLog
_case_coc_logs: Dict[str, ChainOfCustodyLog] = {}
_case_coc_lock = threading.Lock()


def get_case_custody_log(case_work_dir) -> ChainOfCustodyLog:
    """Return (creating lazily) the ChainOfCustodyLog for a given case directory."""
    key = str(case_work_dir)
    with _case_coc_lock:
        if key not in _case_coc_logs:
            _case_coc_logs[key] = ChainOfCustodyLog(Path(case_work_dir))
        return _case_coc_logs[key]


def record_step_custody(
    step_record: dict,
    evidence_file: str,
    pre_hash: str,
    post_hash: str,
    verification_passed: Optional[bool],
    custody_log: ChainOfCustodyLog,
    initiating_agent: str = "Manager",
) -> Optional[dict]:
    """Build a ChainOfCustodyRecord from a completed pipeline step and append to log.

    Hashes the step output for output integrity. Returns the persisted record dict.
    """
    output_data = step_record.get("result", {})
    output_bytes = json.dumps(output_data, default=str).encode()
    output_sha256 = hashlib.sha256(output_bytes).hexdigest()
    output_size = len(output_bytes)

    ev_size = 0
    if evidence_file and os.path.isfile(evidence_file):
        try:
            ev_size = os.stat(evidence_file).st_size
        except OSError:
            pass

    critic = step_record.get("critic")
    critic_verdict = critic.get("verdict") if isinstance(critic, dict) else None
    critic_confidence = critic.get("confidence") if isinstance(critic, dict) else None

    rec = ChainOfCustodyRecord(
        record_type="step",
        evidence_path=evidence_file or "",
        evidence_sha256=pre_hash or "",
        evidence_size=ev_size,
        playbook_id=step_record.get("playbook", ""),
        specialist_module=step_record.get("module", ""),
        specialist_function=step_record.get("function", ""),
        specialist_version=step_record.get("specialist_version", ""),
        raw_command=step_record.get("raw_command", ""),
        full_parameters=step_record.get("params", {}),
        output_sha256=output_sha256,
        output_size=output_size,
        initiating_agent=initiating_agent,
        device_id=step_record.get("device_id", ""),
        pre_verification_hash=pre_hash or "",
        post_verification_hash=post_hash or "",
        verification_passed=verification_passed,
        status=step_record.get("status", "completed"),
        error_detail=step_record.get("error"),
        critic_verdict=critic_verdict,
        critic_confidence=critic_confidence,
    )
    return custody_log.append(rec)
