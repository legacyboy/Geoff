"""Deterministic fallback chains for specialist functions.

When a specialist's primary tool fails, the pipeline calls
_execute_fallback_chain() to try progressively simpler methods
before declaring evidence unprocessable.

No LLM healing happens here — that remains the pipeline's
responsibility after this function returns "unprocessable".
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

# geoff_utils does not import geoff_fallback_chains, so there is
# no circular dependency.
from geoff_utils import _run_step_via_orchestrator, _fe_log


# ---------------------------------------------------------------------------
# Evidence path parameter names per (module, function)
# ---------------------------------------------------------------------------

_EVIDENCE_PARAM = {
    ("sleuthkit", "list_files"):              "image",
    ("sleuthkit", "analyze_partition_table"): "disk_image",
    ("sleuthkit", "analyze_filesystem"):      "image",
    ("sleuthkit", "list_deleted"):            "image",
    ("sleuthkit", "extract_file"):            "image",
    ("sleuthkit", "list_files_mactime"):      "image",
    ("volatility", "process_list"):           "memory_dump",
    ("volatility", "network_scan"):           "memory_dump",
    ("volatility", "find_malware"):           "memory_dump",
    ("memory", "analyze_memory"):             "memory_dump",
    ("memory", "extract_processes"):          "memory_dump",
    ("memory", "find_injected_code"):         "memory_dump",
    ("memory", "raw"):                        "memory_dump",
    ("photorec", "recover_files"):            "image",
    ("bulk_extractor", "scan_image"):         "image",
    ("strings", "extract_strings"):           "file_path",
    ("registry", "parse_hive"):               "hive_path",
    ("registry", "extract_keys"):             "hive_path",
    ("network", "analyze_pcap"):              "pcap_file",
    ("network", "extract_flows"):             "pcap_file",
    ("plaso", "create_timeline"):             "evidence_path",
    ("vss", "list_vss"):                      "image",
    ("vss", "extract_vss_files"):             "image",
    ("logs", "parse_evtx"):                   "evtx_file",
    ("logs", "parse_syslog"):                 "syslog_file",
    ("windows", "extract_prefetch"):          "image",
    ("mobile", "analyze_ios_backup"):         "backup_path",
    ("mobile", "analyze_android"):            "image",
}


def _remap_evidence_params(module: str, function: str,
                            params: dict, evidence_path: str) -> dict:
    """Return a copy of params with evidence_path set under the right key."""
    p = dict(params)
    param_name = _EVIDENCE_PARAM.get((module, function), "image")
    p[param_name] = evidence_path
    if module in ("photorec", "bulk_extractor") and "output_dir" not in p:
        stem = Path(evidence_path).stem
        p["output_dir"] = f"/tmp/geoff_carving_{stem}"
    return p


# ---------------------------------------------------------------------------
# Fallback chain registry
# Each key is "module.function". Each value is an ordered list of attempts.
# Entries are tried in order; first success wins.
# The primary (index 0) always matches the key's module.function.
# "strings.extract_strings" is the terminal fallback — it always yields
# *something* (ASCII/Unicode strings) even from corrupt or raw blobs.
# ---------------------------------------------------------------------------

FALLBACK_CHAINS: dict[str, list[dict[str, Any]]] = {

    # ── Disk Image Analysis ──────────────────────────────────────────────────
    "sleuthkit.list_files": [
        {"module": "sleuthkit",      "function": "list_files",             "params_mod": None,                               "label": "fls_auto"},
        {"module": "sleuthkit",      "function": "list_files",             "params_mod": {"offset": 0},                      "label": "fls_offset0"},
        {"module": "sleuthkit",      "function": "analyze_partition_table", "params_mod": None,                              "label": "mmls_probe"},
        {"module": "photorec",       "function": "recover_files",         "params_mod": None,                               "label": "photorec_carve"},
        {"module": "bulk_extractor", "function": "scan_image",            "params_mod": None,                               "label": "bulk_extractor"},
        {"module": "strings",        "function": "extract_strings",        "params_mod": None,                               "label": "strings_terminal"},
    ],
    "sleuthkit.analyze_partition_table": [
        {"module": "sleuthkit",      "function": "analyze_partition_table", "params_mod": None,                              "label": "mmls_standard"},
        {"module": "sleuthkit",      "function": "analyze_partition_table", "params_mod": {"offset": 0},                    "label": "mmls_offset0"},
        {"module": "sleuthkit",      "function": "analyze_filesystem",     "params_mod": None,                               "label": "fsstat_fallback"},
        {"module": "photorec",       "function": "recover_files",         "params_mod": None,                               "label": "photorec_carve"},
        {"module": "bulk_extractor", "function": "scan_image",            "params_mod": None,                               "label": "bulk_extractor"},
        {"module": "strings",        "function": "extract_strings",       "params_mod": None,                               "label": "strings_terminal"},
    ],
    "sleuthkit.analyze_filesystem": [
        {"module": "sleuthkit",      "function": "analyze_filesystem",     "params_mod": None,                               "label": "fsstat_auto"},
        {"module": "sleuthkit",      "function": "analyze_filesystem",     "params_mod": {"offset": 0},                      "label": "fsstat_offset0"},
        {"module": "sleuthkit",      "function": "list_files",            "params_mod": None,                               "label": "fls_fallback"},
        {"module": "photorec",       "function": "recover_files",         "params_mod": None,                               "label": "photorec_carve"},
        {"module": "strings",        "function": "extract_strings",       "params_mod": None,                               "label": "strings_terminal"},
    ],
    "sleuthkit.list_deleted": [
        {"module": "sleuthkit",      "function": "list_deleted",           "params_mod": None,                               "label": "ils_standard"},
        {"module": "sleuthkit",      "function": "list_files",            "params_mod": None,                               "label": "fls_with_deleted_flag"},
        {"module": "photorec",       "function": "recover_files",         "params_mod": None,                               "label": "photorec_carve"},
        {"module": "bulk_extractor", "function": "scan_image",            "params_mod": None,                               "label": "bulk_extractor"},
    ],

    # ── Memory Forensics ─────────────────────────────────────────────────────
    "volatility.process_list": [
        {"module": "volatility",     "function": "process_list",          "params_mod": None,                               "label": "vol_pslist"},
        {"module": "memory",         "function": "extract_processes",     "params_mod": None,                               "label": "vol3_pslist"},
        {"module": "bulk_extractor", "function": "scan_image",            "params_mod": None,                               "label": "bulk_extractor"},
        {"module": "strings",        "function": "extract_strings",       "params_mod": None,                               "label": "strings_terminal"},
    ],
    "volatility.network_scan": [
        {"module": "volatility",     "function": "network_scan",          "params_mod": None,                               "label": "vol_netscan"},
        {"module": "strings",        "function": "extract_strings",       "params_mod": None,                               "label": "strings_ips_urls"},
    ],
    "volatility.find_malware": [
        {"module": "volatility",     "function": "find_malware",          "params_mod": None,                               "label": "vol_malfind"},
        {"module": "memory",         "function": "find_injected_code",    "params_mod": None,                               "label": "vol3_malfind"},
        {"module": "strings",        "function": "extract_strings",       "params_mod": None,                               "label": "strings_suspicious"},
    ],
    "memory.analyze_memory": [
        {"module": "memory",         "function": "analyze_memory",        "params_mod": None,                               "label": "vol3_detect"},
        {"module": "memory",         "function": "raw",                   "params_mod": None,                               "label": "memory_raw_metadata"},
        {"module": "bulk_extractor", "function": "scan_image",            "params_mod": None,                               "label": "bulk_extractor"},
        {"module": "strings",        "function": "extract_strings",       "params_mod": None,                               "label": "strings_terminal"},
    ],
    "memory.extract_processes": [
        {"module": "memory",         "function": "extract_processes",     "params_mod": None,                               "label": "vol3_pslist"},
        {"module": "bulk_extractor", "function": "scan_image",            "params_mod": None,                               "label": "bulk_extractor"},
        {"module": "strings",        "function": "extract_strings",       "params_mod": None,                               "label": "strings_terminal"},
    ],

    # ── Timeline Analysis ────────────────────────────────────────────────────
    "plaso.create_timeline": [
        {"module": "plaso",          "function": "create_timeline",        "params_mod": None,                               "label": "log2timeline_full"},
        {"module": "plaso",          "function": "create_timeline",        "params_mod": {"parsers": ["filestat", "pe"]},    "label": "log2timeline_minimal"},
        {"module": "sleuthkit",      "function": "list_files_mactime",     "params_mod": None,                               "label": "fls_mactime"},
        {"module": "strings",        "function": "extract_strings",        "params_mod": None,                               "label": "strings_terminal"},
    ],

    # ── Registry ─────────────────────────────────────────────────────────────
    "registry.parse_hive": [
        {"module": "registry",       "function": "parse_hive",            "params_mod": None,                               "label": "regripper_full"},
        {"module": "strings",        "function": "extract_strings",        "params_mod": None,                               "label": "strings_registry"},
    ],
    "registry.extract_keys": [
        {"module": "registry",       "function": "extract_keys",          "params_mod": None,                               "label": "regripper_targeted"},
        {"module": "registry",       "function": "parse_hive",            "params_mod": None,                               "label": "regripper_full"},
        {"module": "strings",        "function": "extract_strings",        "params_mod": None,                               "label": "strings_registry"},
    ],

    # ── Network ──────────────────────────────────────────────────────────────
    "network.analyze_pcap": [
        {"module": "network",        "function": "analyze_pcap",          "params_mod": None,                               "label": "tshark_standard"},
        {"module": "network",        "function": "extract_flows",         "params_mod": None,                               "label": "tcpflow_fallback"},
        {"module": "strings",        "function": "extract_strings",        "params_mod": None,                               "label": "strings_terminal"},
    ],

    # ── VSS ──────────────────────────────────────────────────────────────────
    "vss.extract_vss_files": [
        {"module": "vss",            "function": "extract_vss_files",     "params_mod": None,                               "label": "vss_extract"},
        {"module": "photorec",       "function": "recover_files",         "params_mod": None,                               "label": "photorec_carve"},
        {"module": "bulk_extractor", "function": "scan_image",            "params_mod": None,                               "label": "bulk_extractor"},
    ],

    # ── Carving (these are already fallbacks; give them minimal chains) ──────
    "photorec.recover_files": [
        {"module": "photorec",       "function": "recover_files",         "params_mod": None,                               "label": "photorec_chain"},
        # PHOTOREC_Specialist internally chains photorec -> foremost -> scalpel
        {"module": "bulk_extractor", "function": "scan_image",            "params_mod": None,                               "label": "bulk_extractor"},
        {"module": "strings",        "function": "extract_strings",       "params_mod": None,                               "label": "strings_terminal"},
    ],

    # ── Windows Artifacts ────────────────────────────────────────────────────
    "windows.extract_prefetch": [
        {"module": "windows",        "function": "extract_prefetch",      "params_mod": None,                               "label": "prefetch_standard"},
        {"module": "strings",        "function": "extract_strings",        "params_mod": None,                               "label": "strings_prefetch"},
    ],

    # ── Logs ─────────────────────────────────────────────────────────────────
    "logs.parse_evtx": [
        {"module": "logs",           "function": "parse_evtx",            "params_mod": None,                               "label": "evtx_standard"},
        {"module": "strings",        "function": "extract_strings",        "params_mod": None,                               "label": "strings_evtx"},
    ],
    "logs.parse_syslog": [
        {"module": "logs",           "function": "parse_syslog",          "params_mod": None,                               "label": "syslog_standard"},
        {"module": "strings",        "function": "extract_strings",        "params_mod": None,                               "label": "strings_syslog"},
    ],

    # ── Mobile ───────────────────────────────────────────────────────────────
    "mobile.analyze_ios_backup": [
        {"module": "mobile",         "function": "analyze_ios_backup",    "params_mod": None,                               "label": "ios_standard"},
        {"module": "strings",        "function": "extract_strings",        "params_mod": None,                               "label": "strings_ios"},
    ],
    "mobile.analyze_android": [
        {"module": "mobile",         "function": "analyze_android",       "params_mod": None,                               "label": "android_standard"},
        {"module": "strings",        "function": "extract_strings",        "params_mod": None,                               "label": "strings_android"},
    ],
}


# ---------------------------------------------------------------------------
# Fallback chain executor
# ---------------------------------------------------------------------------

_MAX_TRANSIENT_RETRIES = 2  # per-step exception retries within the chain


def _execute_fallback_chain(module: str, function: str, params: dict,
                             evidence_path: str, job_id: str = "") -> dict:
    """Try every method in the fallback chain for this specialist function.

    Returns on the first success. If all methods fail, returns a dict with
    status="unprocessable" that documents every attempt.

    Does NOT call the LLM healer — that remains the pipeline's responsibility
    after this function returns "unprocessable".
    """
    chain_key = f"{module}.{function}"
    chain = FALLBACK_CHAINS.get(chain_key)

    if not chain:
        # No chain defined — single attempt, return as-is
        result = _try_step(module, function, params, evidence_path, job_id)
        result.setdefault("_fallback_chain", [chain_key])
        result.setdefault("_fallback_final_method", chain_key)
        return result

    attempts: list[dict] = []

    for i, entry in enumerate(chain):
        m = entry["module"]
        f = entry["function"]
        label = entry.get("label", f"{m}.{f}")

        step_params = _remap_evidence_params(m, f, params, evidence_path)
        if entry.get("params_mod"):
            step_params.update(entry["params_mod"])

        result = _try_step(m, f, step_params, evidence_path, job_id)

        attempt_record = {
            "method": label,
            "module": m,
            "function": f,
            "status": result.get("status", "unknown"),
            "error": str(result.get("error", ""))[:200],
        }
        attempts.append(attempt_record)

        if result.get("status") == "success":
            result["_fallback_chain"]         = [a["method"] for a in attempts]
            result["_fallback_attempt_count"] = len(attempts)
            result["_fallback_final_method"]  = label
            result["_fallback_primary_failed"] = i > 0
            if i > 0:
                _fe_log(job_id, f"  ✓ Fail-forward: {chain_key} succeeded via {label} (attempt {i+1})")
            return result

        _fe_log(job_id, f"  ↻ Fail-forward: {label} failed ({attempt_record['error'][:80]}), trying next…")

    # All methods exhausted
    _fe_log(job_id, f"  ✗ Fail-forward exhausted: all {len(attempts)} methods failed for {chain_key}")
    last_error = attempts[-1]["error"] if attempts else "no attempts made"
    return {
        "status": "unprocessable",
        "evidence": evidence_path,
        "original_module": module,
        "original_function": function,
        "attempted_methods": [a["method"] for a in attempts],
        "attempt_details": attempts,
        "reason": f"All {len(attempts)} methods failed. Last error: {last_error}",
        "_fallback_chain": [a["method"] for a in attempts],
        "_fallback_exhausted": True,
        "timestamp": datetime.now().isoformat(),
    }


def _try_step(module: str, function: str, params: dict,
              evidence_path: str, job_id: str) -> dict:
    """Run one step, retrying on transient exceptions only."""
    last_exc = None
    for attempt in range(_MAX_TRANSIENT_RETRIES):
        try:
            return _run_step_via_orchestrator(module, function, params, job_id=job_id)
        except Exception as exc:
            last_exc = exc
            if attempt < _MAX_TRANSIENT_RETRIES - 1:
                _fe_log(job_id, f"  ↻ Transient exception in {module}.{function} (retry {attempt+1}): {exc}")
            continue
    # Exhausted exception retries — return as error
    return {"status": "error", "error": f"Exception: {last_exc}"}