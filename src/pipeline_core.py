#!/usr/bin/env python3
"""Geoff DFIR - Pipeline core helpers (step-level execution machinery).

Extracted from geoff_pipeline.py to reduce module size. Contains the
step-level helpers shared by find_evil() and replay:

  - _MODULE_EVIDENCE_GUARDS / _evidence_type_mismatch: evidence-type guards
  - execute_step_parallel(): evidence-level parallel step execution
  - _cleanup_ewf_early_mounts(): FUSE ewfmount cleanup
  - _reconstruct_attack_chain(): dwell time + lateral movement path
  - _preflight_validation(): pre-run environment checks
  - _reconstruct_raw_command(): copy-pasteable CLI string for the audit log
  - _commit_step_with_custody(): per-step git commit with custody sidecar
  - _run_forensicator_batch(): batch manifest for the Forensicator
  - _retry_unprocessed(): fallback-chain retry of unprocessed evidence

These helpers deliberately do not touch the wired singletons
(orchestrator / geoff_critic / geoff_forensicator), so this module needs
no post-init wiring from geoff_integrated.py.
"""

import os
import json
import hashlib
import subprocess
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

from geoff_config import PLAYBOOK_STEPS, _atomic_write, _hash_file
from geoff_utils import (
    _fe_log, _log_error, _log_info, _make_exec_key,
    safe_run, safe_git_commit,
)
from geoff_fallback_chains import _execute_fallback_chain
import command_logger
import geoff_discovery
from geoff_discovery import _classify_unprocessed

try:
    from geoff_chain_of_custody import (
        get_case_custody_log, record_step_custody,
        _start_hash_async, _hash_with_stat_cache,
    )
    _COC_AVAILABLE = True
except ImportError:
    _COC_AVAILABLE = False

# ---------------------------------------------------------------------------
# Evidence-type guards: prevent modules running against incompatible evidence
# ---------------------------------------------------------------------------

_MODULE_EVIDENCE_GUARDS: dict = {
    "volatility": {"memory_dumps"},
    "memory":     {"memory_dumps"},
    "registry":   {"disk_images", "registry_hives"},
    "windows":    {"disk_images", "registry_hives", "memory_dumps"},
    "sleuthkit":  {"disk_images", "memory_dumps"},
    "network":    {"pcaps"},
    "dns":        {"pcaps"},
    "remnux":     {"pcaps", "memory_dumps", "disk_images"},
    "linux_user": {"disk_images", "memory_dumps", "other_files"},
    "yara":       {"memory_dumps", "disk_images"},
    "scheduled":  {"memory_dumps", "disk_images"},
    "strings":    {"memory_dumps", "disk_images"},
}


def _evidence_type_mismatch(module: str, ev_type: str, dev: dict) -> tuple:
    """Return (should_skip, reason). Skip when module is incompatible with ev_type or device OS."""
    allowed = _MODULE_EVIDENCE_GUARDS.get(module)
    if allowed is not None and ev_type not in allowed:
        return True, f"module {module} requires evidence in {sorted(allowed)}, got {ev_type}"
    dev_os = (dev.get("os_type") or "").lower()
    if module in ("registry", "windows") and dev_os == "linux":
        return True, f"module {module} requires Windows; device os_type={dev_os}"
    if module == "linux_user" and dev_os not in ("", "unknown", "linux"):
        return True, f"module {module} requires Linux; device os_type={dev_os}"
    return False, ""

# ---------------------------------------------------------------------------
# Parallel execution helpers for evidence-level concurrency
# ---------------------------------------------------------------------------

def execute_step_parallel(module, function, params_list, playbook_id,
                           job_id, dev_id, dev, output_dir, image_offsets,
                           findings_writer, pb_findings, exec_cache):
    """Execute a step across multiple evidence items in parallel.

    Batches same (module, function) across items using ThreadPoolExecutor.
    Each worker gets independent copies of all inputs.
    Dedup is checked per-item; cache-hit items aren't double-appended.

    Args:
        params_list: List of (item, params_dict) tuples, one per evidence item
        exec_cache: _ExecResultCache instance for dedup

    Returns:
        (completed_delta, failed_delta, skipped_delta)
    """
    if not params_list:
        return (0, 0, 0)

    max_workers = int(os.environ.get("GEOFF_MAX_WORKERS", "3"))
    results = []
    step_locks: dict = {}
    step_locks_meta = threading.Lock()

    def _run_single(item, item_params):
        """Run one step on one evidence item and return a result tuple."""
        step_key = f"{playbook_id}:{module}:{function}:{Path(item).name}"

        # Idempotency check
        if findings_writer.is_completed(step_key):
            _fe_log(job_id, f"  ⎘ {module}.{function} already completed for {Path(item).name}")
            return ("skipped", None, 0, 0, 1)

        exec_key_inner = _make_exec_key(module, function, item, item_params)
        with step_locks_meta:
            if exec_key_inner not in step_locks:
                step_locks[exec_key_inner] = threading.Lock()
            step_lock = step_locks[exec_key_inner]

        with step_lock:
            _cached = exec_cache.get(exec_key_inner)
            if _cached is not None:
                _fe_log(job_id, f"  deduped {module}.{function} ({Path(item).name})")
                deduped_rec = {
                    "playbook": playbook_id, "module": module, "function": function,
                    "evidence_file": item, "device_id": dev_id,
                    "status": "completed", "result": _cached, "_deduped": True,
                }
                findings_writer.append(deduped_rec)
                pb_findings.append(deduped_rec)
                return ("deduped", deduped_rec, 1, 0, 0)

            raw_cmd = _reconstruct_raw_command(module, function, item_params)
            exec_hash = hashlib.md5(
                f"{step_key}:{json.dumps(item_params, sort_keys=True, default=str)}".encode()
            ).hexdigest()[:12]

            try:
                command_logger.set_step(step_key, playbook_id)
            except Exception:
                pass  # worker threads don't inherit command_logger context

            step_record = {
                "playbook": playbook_id,
                "step_key": step_key,
                "execution_hash": exec_hash,
                "module": module,
                "function": function,
                "params": item_params,
                "raw_command": raw_cmd,
                "evidence_file": item,
                "device_id": dev_id,
                "owner": dev.get("owner") if dev else None,
                "status": "running",
                "started_at": datetime.now().isoformat(),
                "result": {},
            }

            result = _execute_fallback_chain(
                module, function, item_params, evidence_path=item, job_id=job_id
            )
            exec_cache.set(exec_key_inner, result)

        c = f = s = 0
        if isinstance(result, dict) and result.get("code") is not None:
            code = result["code"]
            if code == -1:
                step_record["status"] = "failed"
                step_record["error"] = f"Timeout: {result.get('stderr', '')} (CIFS network latency may cause slow reads on compressed E01 images)"
                step_record["result"] = {"status": "failed", "stdout": "", "stderr": result.get('stderr', ''), "artifacts": [], "error": "timeout"}
                _fe_log(job_id, f"  ✗ {module}.{function} → timeout (CIFS network latency may cause slow reads on compressed E01 images)")
                f = 1
            elif code < 0:
                step_record["status"] = "failed"
                step_record["error"] = f"Execution error: {result.get('stderr', '')}"
                step_record["result"] = {"status": "failed", "stdout": "", "stderr": result.get('stderr', ''), "artifacts": [], "error": "execution_error"}
                f = 1
            else:
                step_status = result.get("status", "error")
                if step_status == "error" and "not found" in str(result.get("error", "")).lower():
                    step_record["status"] = "skipped"
                    step_record["result"] = {"status": "skipped", "stdout": "", "stderr": "", "artifacts": [], "error": "tool not found"}
                    s = 1
                elif step_status in ("success", "success_partial"):
                    stdout = result.get("stdout", "")
                    if step_status == "success" and (not stdout or len(stdout.strip()) < 10):
                        step_record["status"] = "failed"
                        step_record["error"] = f"Empty or invalid output from {module}.{function}"
                        step_record["result"] = {"status": "failed", "stdout": stdout or "", "stderr": result.get('stderr', ''), "artifacts": [], "error": "empty output"}
                        f = 1
                    else:
                        step_record["status"] = "completed"
                        step_record["result"] = result
                        if step_status == "success_partial":
                            step_record["_fallback_primary_failed"] = result.get("_fallback_primary_failed", True)
                            step_record["_fallback_final_method"] = result.get("_fallback_final_method", "")
                        c = 1

        findings_writer.append(step_record)
        pb_findings.append(step_record)

        return (step_record["status"], step_record, c, f, s)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(_run_single, item, params): (item, params)
            for item, params in params_list
        }

        item_order = {item: idx for idx, (item, _) in enumerate(params_list)}
        temp = {}

        for future in as_completed(futures):
            item, params = futures[future]
            try:
                temp[item] = future.result()
            except Exception as exc:
                _log_error(f"Parallel step {module}.{function} on {item} failed: {exc}")
                temp[item] = ("error", {"status": "error", "evidence_file": item, "error": str(exc)}, 0, 1, 0)

        results = sorted(temp.items(), key=lambda x: item_order.get(x[0], 0))

    delta_c = delta_f = delta_s = 0
    for item, (status, step_record, c, f, s) in results:
        # Bug 2 fix: step_record is None for idempotency-skipped items
        if step_record is None:
            delta_s += s
            continue
        delta_c += c
        delta_f += f
        delta_s += s

    return (delta_c, delta_f, delta_s)

def _cleanup_ewf_early_mounts(ewf_mounts: dict) -> None:
    """Unmount FUSE ewfmount directories created during the Phase 2.5 pre-mount.

    Filesystem mounts (mount_dir) are tracked via _active_mounts and cleaned
    up by _cleanup_mounts(). Only the FUSE ewfmount dirs need fusermount here.
    """
    import shutil as _shutil
    for _img, _mnt in ewf_mounts.items():
        _ewf_dir = _mnt.get("ewf_dir")
        if _ewf_dir and os.path.exists(_ewf_dir):
            for _fuse_cmd in (["fusermount", "-u", _ewf_dir], ["fusermount3", "-u", _ewf_dir]):
                try:
                    subprocess.run(_fuse_cmd, capture_output=True, timeout=15)
                    break
                except Exception:
                    continue
            try:
                _shutil.rmtree(_ewf_dir, ignore_errors=True)
            except Exception:
                pass
        _mnt_dir = _mnt.get("mount_dir")
        if _mnt_dir and os.path.exists(_mnt_dir):
            try:
                _shutil.rmtree(_mnt_dir, ignore_errors=True)
            except Exception:
                pass

def _reconstruct_attack_chain(findings: list, indicator_hits: list, device_map: dict) -> dict:
    """Compute dwell time and reconstruct lateral movement path from findings.

    Returns a dict with:
      - first_seen_ts: ISO timestamp of earliest artefact
      - last_seen_ts: ISO timestamp of most recent artefact
      - dwell_days: float (None if timestamps unavailable)
      - lateral_movement_path: list of device IDs in order of first activity
      - mitre_techniques_observed: deduplicated list of all ATT&CK IDs seen
      - kill_chain_phases: set of categories observed (triage + findings)
    """
    timestamps: list = []
    device_first_seen: dict = {}  # device_id -> earliest ISO ts

    for f in findings:
        for ts_key in ("started_at", "completed_at"):
            ts = f.get(ts_key)
            if ts:
                timestamps.append(ts)
        dev = f.get("device_id")
        ts = f.get("started_at") or f.get("completed_at")
        if dev and ts:
            if dev not in device_first_seen or ts < device_first_seen[dev]:
                device_first_seen[dev] = ts

    first_ts = min(timestamps) if timestamps else None
    last_ts = max(timestamps) if timestamps else None

    dwell_days = None
    if first_ts and last_ts:
        try:
            from datetime import datetime as _dt
            fmt = "%Y-%m-%dT%H:%M:%S"
            # Strip sub-second and TZ offset for simple comparison
            t0 = _dt.fromisoformat(first_ts[:19])
            t1 = _dt.fromisoformat(last_ts[:19])
            dwell_days = round((t1 - t0).total_seconds() / 86400, 2)
        except Exception as dwell_exc:
            _log_info(f"dwell calculation skipped: {dwell_exc}")

    # Lateral movement path: devices sorted by first activity
    lateral_path = sorted(device_first_seen.keys(),
                          key=lambda d: device_first_seen[d])

    # Collect all ATT&CK techniques from indicator hits
    mitre_seen: list = []
    kill_chain_phases: set = set()
    for hit in indicator_hits:
        kill_chain_phases.add(hit.get("category", ""))
        for t in hit.get("mitre_techniques", []):
            if t not in mitre_seen:
                mitre_seen.append(t)

    return {
        "first_seen_ts": first_ts,
        "last_seen_ts": last_ts,
        "dwell_days": dwell_days,
        "lateral_movement_path": lateral_path,
        "mitre_techniques_observed": mitre_seen,
        "kill_chain_phases": sorted(kill_chain_phases - {""}),
    }

# ---------------------------------------------------------------------------
# Batch Mode Helpers
# ---------------------------------------------------------------------------

def _preflight_validation(evidence_path: Path, case_work_dir: Path, job_id: str) -> list:
    """
    Preflight checks before starting a Find Evil run.
    Returns a list of warning strings (empty list = all clear).
    Raises ValueError for fatal conditions (missing evidence dir is handled by
    the caller; this function focuses on softer warnings).
    """
    warnings = []

    # Evidence directory must contain at least one file
    evidence_files = [f for f in evidence_path.rglob("*") if f.is_file()]
    if not evidence_files:
        warnings.append(f"Evidence directory {evidence_path} contains no files - inventory will be empty")

    # Verify git is available (needed for custody commits)
    git_check = safe_run(['git', '--version'], timeout=5)
    if git_check["code"] != 0:
        warnings.append("git not found in PATH - per-step custody commits will be skipped")

    # Verify case_work_dir parent is writable
    try:
        case_work_dir.parent.mkdir(parents=True, exist_ok=True)
        test_file = case_work_dir.parent / f".geoff_preflight_{uuid.uuid4().hex[:8]}"
        test_file.touch()
        test_file.unlink()
    except OSError as e:
        warnings.append(f"Case work dir parent not writable: {e}")

    if warnings:
        for w in warnings:
            _fe_log(job_id, f"  ⚠ Preflight: {w}")
    else:
        _fe_log(job_id, "  ✓ Preflight: all checks passed")
    return warnings

def _reconstruct_raw_command(module: str, function: str, params: dict) -> str:
    """
    Reconstruct a copy-pasteable CLI command string from module, function, and params.
    Handles the most common forensic tools used across all playbook steps.
    Falls back to a descriptive string for unknown param patterns.
    """
    if not params:
        return f"{module}.{function}"

    # ---- SleuthKit tools ----
    if module == "sleuthkit":
        # Extract image path from any of the common keys
        image = params.get("disk_image") or params.get("image") or ""
        offset = params.get("offset")
        inode = params.get("inode")
        # Determine the tool from the function
        tool_map = {
            "analyze_partition_table": "mmls",
            "analyze_filesystem": "fsstat",
            "list_files": "fls",
            "list_files_mactime": "fls",
            "list_inodes": "ils",
            "get_file_info": "istat",
            "list_deleted": "fls",
            "extract_file": "icat",
        }
        tool = tool_map.get(function, function)
        args = []
        if offset is not None:
            args.append(f"-o {offset}")
        if function == "list_files" and params.get("recursive"):
            args.append("-r")
        if function == "list_deleted":
            args.append("-d")
        if function == "list_files_mactime":
            args.append("-m")
        args.append(image)
        if inode is not None:
            args.append(str(inode))
        cmd = f"{tool} {' '.join(a for a in args if a)}"
        return cmd.strip()

    # ---- Strings tool ----
    if module == "strings":
        file_path = params.get("file_path", "")
        min_len = params.get("min_length")
        encoding = params.get("encoding")
        args = []
        if min_len:
            args.append(f"-n {min_len}")
        if encoding:
            enc_map = {"ascii": "a", "unicode": "l", "wide": "l"}
            args.append(f"-e {enc_map.get(encoding, encoding)}")
        args.append(file_path)
        return f"strings {' '.join(a for a in args if a)}"

    # ---- Volatility tool ----
    if module == "volatility":
        mem = params.get("memory_dump", "")
        plugin_map = {
            "process_list": "windows.pslist",
            "network_scan": "windows.netscan",
            "find_malware": "windows.malfind",
            "scan_registry": "windows.registry.printkey",
            "dump_process": "windows.dumpfiles",
        }
        plugin = plugin_map.get(function, function)
        # Check if volatility3 or vol.py
        return f"vol -f {mem} {plugin}"

    # ---- Memory module ----
    if module == "memory":
        mem = params.get("memory_dump", "")
        func_name = function.replace("_", ".")
        return f"memory.{func_name} --memory-dump {mem}"

    # ---- Network tools ----
    if module == "network":
        pcap = params.get("pcap_file", "")
        if function == "analyze_pcap":
            return f"tshark -r {pcap}"
        elif function == "extract_http":
            return f"tshark -r {pcap} -Y http"
        elif function == "extract_flows":
            return f"tshark -r {pcap} -T fields -e ip.src -e ip.dst -e ip.proto"
        return f"network.{function} {pcap}"

    # ---- Logs module ----
    if module == "logs":
        log_file = params.get("evtx_file") or params.get("evt_file") or params.get("log_file") or params.get("syslog_file", "")
        if function == "parse_evtx":
            return f"python3 -m evtx_dump {log_file}"
        elif function == "parse_evt":
            return f"python3 -m python-evt {log_file}"
        elif function == "parse_syslog":
            return f"cat {log_file}"
        return f"logs.{function} {log_file}"

    # ---- Registry module ----
    if module == "registry":
        hive = params.get("software_path") or params.get("system_path") or params.get("ntuser_path") or params.get("sam_path") or params.get("hive_path", "")
        if function == "extract_autoruns":
            return f"regripper -r {hive} -a autoruns"
        elif function == "extract_services":
            return f"regripper -r {hive} -a services"
        elif function == "parse_hive":
            return f"regripper -r {hive}"
        return f"registry.{function} {hive}"

    # ---- Bulk Extractor ----
    if module == "bulk_extractor":
        image = params.get("image", "")
        outdir = params.get("output_dir", "/tmp/bulk_extractor_out")
        return f"bulk_extractor -o {outdir} {image}"

    # ---- dc3dd ----
    if module == "dc3dd":
        image = params.get("image", "")
        return f"dc3dd if={image}"

    # ---- VSS module ----
    if module == "vss":
        image = params.get("image", "")
        return f"vshadowinfo {image}"

    # ---- Browser module ----
    if module == "browser":
        profile_path = params.get("profile_path") or params.get("directory") or params.get("evidence_dir", "")
        return f"browser.{function} {profile_path}"

    # ---- SQLite module ----
    if module == "sqlite":
        db_path = params.get("db_path") or params.get("database") or params.get("file_path", "")
        return f"sqlite3 {db_path} .dump"

    # ---- Email module ----
    if module == "email":
        mbox = params.get("mbox") or params.get("email_file") or params.get("file_path", "")
        return f"email.{function} {mbox}"

    # ---- JumpList ----
    if module == "jumplist":
        directory = params.get("directory", "")
        return f"jumplist.{function} {directory}"

    # ---- Scheduled tasks ----
    if module == "scheduled":
        evidence_dir = params.get("evidence_dir", "")
        return f"scheduled.{function} {evidence_dir}"

    # ---- Plaso ----
    if module == "plaso":
        image = params.get("image") or params.get("source", "")
        return f"log2timeline.py --storage-file {params.get('storage_file', 'plaso.dump')} {image}"

    # ---- Mobile ----
    if module == "mobile":
        mobile_dir = params.get("mobile", "") or params.get("backup_dir", "") or params.get("directory", "")
        return f"mobile.{function} {mobile_dir}"

    # ---- Photorec ----
    if module == "photorec":
        image = params.get("disk_image") or params.get("image", "")
        return f"photorec /d {params.get('output_dir', '/tmp/photorec')} {image}"

    # ---- Zeek ----
    if module == "zeek":
        pcap = params.get("pcap_file") or params.get("pcap", "")
        return f"zeek -r {pcap}"

    # ---- Generic fallback ----
    # Build a descriptive string from params
    param_str = " ".join(f"{k}={v}" for k, v in sorted(params.items()) if not k.startswith("_"))
    return f"{module}.{function} {param_str}"

def _commit_step_with_custody(
    step_record: dict,
    evidence_file: str,
    case_work_dir: Path,
    job_id: str,
) -> dict:
    """
    Commit a single completed step result to git with chain-of-custody metadata.

    Writes a custody record alongside the step output, then commits.
    Returns the git commit result dict (same shape as safe_git_commit).
    Called for each completed step (~10s overhead per step for git commit).
    """
    step_key = step_record.get("step_key", "unknown")
    module = step_record.get("module", "unknown")
    function = step_record.get("function", "unknown")
    playbook_id = step_record.get("playbook", "unknown")

    # Chain-of-custody: hash evidence file + hash params
    evidence_sha256 = (
        _hash_file(evidence_file)
        if evidence_file and os.path.isfile(evidence_file)
        else "N/A"
    )
    params_hash = hashlib.sha256(
        json.dumps(step_record.get("params", {}), sort_keys=True, default=str).encode()
    ).hexdigest()[:16]

    raw_command = step_record.get("raw_command", "")

    # Real versions of the tool binaries that actually executed during this
    # step, captured by the command logger (empty if logging was unavailable).
    try:
        tool_versions = command_logger.get_step_tool_versions()
    except Exception:
        tool_versions = {}

    custody = {
        "step_key": step_key,
        "playbook": playbook_id,
        "module": module,
        "function": function,
        "evidence_file": evidence_file,
        "evidence_sha256": evidence_sha256,
        "params_hash": params_hash,
        "raw_command": raw_command,
        "tool_versions": tool_versions,
        "status": step_record.get("status", "unknown"),
        "committed_at": datetime.now().isoformat(),
        "execution_hash": step_record.get("execution_hash", ""),
    }

    # Write custody sidecar to disk
    custody_dir = case_work_dir / "custody"
    custody_dir.mkdir(exist_ok=True)
    safe_key = step_key.replace(":", "_").replace("/", "_")[:120]
    custody_file = custody_dir / f"{safe_key}.json"
    try:
        _atomic_write(custody_file, json.dumps(custody, indent=2, default=str))
    except Exception as e:
        _fe_log(job_id, f"  ⚠ Custody write failed for {step_key}: {e}")

    # Append to the Merkle hash-chained chain-of-custody log
    if _COC_AVAILABLE:
        try:
            coc_log = get_case_custody_log(case_work_dir)
            pre_hash_future = step_record.get("_coc_pre_hash_future")
            if pre_hash_future is not None:
                try:
                    pre_hash = pre_hash_future.result(timeout=60)
                except Exception:
                    pre_hash = evidence_sha256
            else:
                pre_hash = evidence_sha256
            post_hash = (
                _hash_with_stat_cache(evidence_file)
                if evidence_file and os.path.isfile(evidence_file)
                else "N/A"
            )
            verification_passed = (
                pre_hash == post_hash
                if pre_hash not in ("N/A", "hash_failed") and post_hash not in ("N/A", "hash_failed")
                else None
            )
            if verification_passed is False:
                _fe_log(job_id, (
                    f"  ⚠ CUSTODY VIOLATION: {evidence_file} hash changed during "
                    f"{module}.{function} (pre={pre_hash[:12]} post={post_hash[:12]})"
                ))
            record_step_custody(
                step_record=step_record,
                evidence_file=evidence_file or "",
                pre_hash=pre_hash,
                post_hash=post_hash,
                verification_passed=verification_passed,
                custody_log=coc_log,
                initiating_agent="Manager",
            )
        except Exception as coc_err:
            _fe_log(job_id, f"  ⚠ Chain-of-custody record failed for {step_key}: {coc_err}")

    ev_name = Path(evidence_file).name if evidence_file else "N/A"
    commit_msg = (
        f"step: {playbook_id}:{module}.{function} "
        f"[{step_record.get('status', 'unknown')}] "
        f"ev={ev_name} sha256={evidence_sha256[:12]}"
    )
    if raw_command:
        commit_msg += f"\ncmd: {raw_command[:200]}"
    return safe_git_commit(commit_msg, base_path=str(case_work_dir))

def _run_forensicator_batch(
    execution_plan: list,
    device_map: dict,
    case_work_dir: Path,
    job_id: str,
) -> dict:
    """
    Batch mode orchestrator: logs the start of autonomous execution and returns
    metadata used by _manager_post_critic_decision.

    Actual step execution runs inside find_evil's existing per-device/playbook
    loop - per-step custody commits happen inside that loop.
    """
    total_templates = sum(
        sum(len(steps) for steps in PLAYBOOK_STEPS.get(pb, {}).values())
        for pb in execution_plan
        if pb in PLAYBOOK_STEPS
    )
    _fe_log(job_id, (
        f"  [BATCH] Autonomous execution: {len(execution_plan)} playbooks, "
        f"~{total_templates} step templates, {len(device_map)} device(s)"
    ), agent="Forensicator")
    return {
        "mode": "batch",
        "playbooks_queued": len(execution_plan),
        "devices": list(device_map.keys()),
        "started_at": datetime.now().isoformat(),
    }

def _retry_unprocessed(
    findings_writer,
    inventory: dict,
    image_offsets: dict,
    case_work_dir: Path,
    evidence_path: Path,
    execution_plan: list,
    job_id: str = None,
    fe_log_func=None,
) -> dict:
    """Post-run retry phase for unprocessed evidence files.

    Called after the main find_evil() pipeline completes and before
    report generation.  Attempts to reprocess files that were:
      - skipped/failed with "step_skipped_or_failed"
      - capped with "item_cap_exceeded"

    Re-runs the relevant discovery/playbook steps with relaxed limits
    and logs retry attempts and results.  Updated findings are appended
    to the findings_writer so that severity counting and report
    generation include the retry results.

    Returns a summary dict: {"retried": N, "succeeded": N, "failed": N}.
    """

    def _log(msg):
        if fe_log_func and job_id:
            fe_log_func(job_id, msg)

    _log("\n\U0001F501 Post-Run Retry: reprocessing unprocessed evidence files")

    # Build the current processed-paths set from findings_writer
    processed_paths = set()
    for rec in findings_writer.all_records():
        ef = rec.get("evidence_file")
        if ef:
            processed_paths.add(str(ef))

    all_paths = geoff_discovery._all_inventory_paths(inventory)
    unprocessed = _classify_unprocessed(
        all_paths, processed_paths, inventory, execution_plan
    )

    retryable = [
        u for u in unprocessed
        if u["reason"] in ("step_skipped_or_failed", "item_cap_exceeded")
    ]

    if not retryable:
        _log("  No retryable unprocessed files")
        return {"retried": 0, "succeeded": 0, "failed": 0}

    _log(f"  {len(retryable)} retryable files ({len(unprocessed)} total unprocessed)")

    retried = 0
    succeeded = 0
    failed = 0
    output_dir = str(case_work_dir / "output")

    for entry in retryable:
        path = entry["path"]
        ev_type = entry.get("evidence_type")
        reason = entry["reason"]

        if not Path(path).exists():
            _log(f"  \u23D8 {Path(path).name}: file gone \u2014 skip")
            continue

        # Find a playbook that covers this evidence type
        for pb_id in execution_plan:
            if pb_id not in PLAYBOOK_STEPS:
                continue
            pb_steps = PLAYBOOK_STEPS[pb_id]
            if ev_type not in pb_steps:
                continue

            step_templates = pb_steps[ev_type]
            item_stem = Path(path).stem

            # Run the first applicable step template for this evidence type
            for module, function, raw_params in step_templates[:1]:
                params = {}
                for k, v in raw_params.items():
                    if isinstance(v, str):
                        v = (
                            v.replace("{image}", path)
                             .replace("{mem}", path)
                             .replace("{pcap}", path)
                             .replace("{evtx}", path)
                             .replace("{evt}", path)
                             .replace("{syslog}", path)
                             .replace("{hive}", path)
                             .replace("{mobile}", str(Path(path).parent))
                             .replace("{file}", path)
                             .replace("{output_dir}", output_dir)
                             .replace("{image_stem}", item_stem)
                             .replace("{offset}", str(image_offsets.get(path, [2048])[0] if isinstance(image_offsets.get(path), list) else image_offsets.get(path, 2048)))
                        )
                    params[k] = v

                for k, v_conv in list(params.items()):
                    if isinstance(v_conv, str) and v_conv.isdigit():
                        params[k] = int(v_conv)
                    elif isinstance(v_conv, str) and v_conv.lower() in ("true", "false"):
                        params[k] = v_conv.lower() == "true"

                step_key = f"retry:{pb_id}:{module}:{function}:{Path(path).name}"

                try:
                    result = _execute_fallback_chain(module, function, params,
                                                     evidence_path=path, job_id=job_id)
                    step_status = (
                        "completed" if result.get("status") in ("success", "success_partial") else "failed"
                    )
                    if result.get("status") == "unprocessable":
                        step_status = "unprocessable"

                    record = {
                        "playbook": pb_id,
                        "step_key": step_key,
                        "module": module,
                        "function": function,
                        "params": params,
                        "evidence_file": path,
                        "status": step_status,
                        "result": result,
                        "_retry": True,
                        "_retry_reason": reason,
                        "started_at": datetime.now().isoformat(),
                        "completed_at": datetime.now().isoformat(),
                    }
                    findings_writer.append(record)
                    retried += 1

                    if step_status == "completed":
                        succeeded += 1
                        _log(
                            f"  \u2713 Retry ok: {module}.{function} \u2192 "
                            f"{Path(path).name}"
                        )
                    else:
                        failed += 1
                        _log(
                            f"  \u2717 Retry fail: {module}.{function} \u2192 "
                            f"{Path(path).name}"
                        )
                except Exception as exc:
                    failed += 1
                    retried += 1
                    _log(f"  \u2717 Retry error: {Path(path).name}: {exc}")
                break  # one step per file is enough
            break  # one playbook per file is enough

    _log(
        f"  Retry phase done: {retried} attempted, "
        f"{succeeded} ok, {failed} failed"
    )
    return {"retried": retried, "succeeded": succeeded, "failed": failed}
