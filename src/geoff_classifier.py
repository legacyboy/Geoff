#!/usr/bin/env python3
"""
Geoff DFIR — Multi-Label Case Classification Engine (A004)

Maps forensic findings, triage indicator hits, and behavioral flags onto a
THREAT_TAXONOMY (defined in geoff_config.py) using weighted scoring. Produces
a ranked list of threat categories with confidence scores and matching indicators.

Primary use: classify_case() called from geoff_pipeline.py after triage and
again after all findings are collected.
"""

import json
from collections import Counter
from typing import Dict, List, Any, Optional

from geoff_config import THREAT_TAXONOMY

# ---------------------------------------------------------------------------
# Indicator signal extraction helpers
# ---------------------------------------------------------------------------

# Map triage-indicator categories (from TRIAGE_PATTERNS/SEVERITY_MAP) to
# THREAT_TAXONOMY indicator names.
_INDICATOR_CATEGORY_MAP: Dict[str, List[str]] = {
    "ransomware":         ["encryption", "ransom_note", "mass_rename"],
    "credential_theft":   ["credentials_harvesting"],
    "lateral_movement":   ["lateral_movement"],
    "persistence":        ["persistence"],
    "exfiltration":       ["data_exfil", "cloud_sync"],
    "anti_forensics":     ["anti_forensics"],
    "web_shell":          ["downloaded_executable", "c2"],
    "c2":                 ["c2"],
    "phishing":           ["email_suspicious", "downloaded_executable"],
    "cryptominer":        ["executable"],
    "rootkit":            ["persistence", "executable"],
    "ot_attack":          ["executable"],
    "lolbin":             ["executable"],
}

# Map behavioral flag types to THREAT_TAXONOMY indicator names.
_BEHAVIORAL_FLAG_MAP: Dict[str, List[str]] = {
    "timeline_anomaly":   ["off_hours"],
    "no_recovery":        ["anti_forensics"],
    "off_hours":          ["off_hours"],
    "usb_copy":           ["usb_copy"],
    "mass_rename":        ["mass_rename", "renamed_files"],
    "cloud_sync":         ["cloud_sync"],
    "anti_forensics":     ["anti_forensics"],
    "lateral_movement":   ["lateral_movement"],
    "network_scan":       ["network_scan"],
}

# Map finding module/function pairs to THREAT_TAXONOMY indicator names.
_FINDING_MODULE_MAP: Dict[str, List[str]] = {
    "volatility.network_scan":        ["network_scan"],
    "volatility.find_malware":        ["executable"],
    "volatility.malfind":             ["executable"],
    "registry.extract_autoruns":      ["persistence"],
    "registry.extract_services":      ["persistence"],
    "scheduled.parse_windows_scheduled_tasks": ["persistence"],
    "scheduled.parse_linux_crontabs":  ["persistence"],
    "network.analyze_pcap":           ["c2", "network_scan"],
    "network.extract_http":           ["c2"],
    "email.detect_phishing":          ["email_suspicious", "phishing"],
    "email.detect_spoofing":          ["email_suspicious"],
    "email.IOC_extraction":           ["email_exfil"],
    "email.direct_pst":               ["email_exfil"],
    "sleuthkit.list_files":            [],
}

# Evidence types that map to indicators
_EVIDENCE_TYPE_INDICATORS: Dict[str, List[str]] = {
    "pcap":              ["network_scan", "c2"],
    "memory_dump":       ["executable"],
    "email":             ["email_suspicious", "email_exfil"],
    "disk_image":        [],
}


def _extract_indicators_from_indicator_hits(indicator_hits: List[Dict]) -> Dict[str, int]:
    """Scan triage indicator_hits and return {indicator_name: hit_count}."""
    signals: Dict[str, int] = {}

    for hit in indicator_hits:
        if not isinstance(hit, dict):
            continue
        category = hit.get("category", "").lower().strip()
        confidence = hit.get("confidence", "POSSIBLE")
        weight = 2 if confidence == "CONFIRMED" else 1

        mapped = _INDICATOR_CATEGORY_MAP.get(category, [])
        for ind in mapped:
            signals[ind] = signals.get(ind, 0) + weight

    return signals


def _extract_indicators_from_behavioral_flags(behavioral_flags: Dict[str, List[Dict]]) -> Dict[str, int]:
    """Scan behavioral flags and return {indicator_name: hit_count}."""
    signals: Dict[str, int] = {}

    if not behavioral_flags:
        return signals

    for dev_id, flags in behavioral_flags.items():
        for flag in flags:
            if not isinstance(flag, dict):
                continue
            flag_type = flag.get("flag_type", "").lower().strip()
            mapped = _BEHAVIORAL_FLAG_MAP.get(flag_type, [])
            for ind in mapped:
                signals[ind] = signals.get(ind, 0) + 1

    return signals


def _extract_indicators_from_findings(findings: List[Dict]) -> Dict[str, int]:
    """Scan completed findings for module/function patterns and evidence types."""
    signals: Dict[str, int] = {}

    if not findings:
        return signals

    for f in findings:
        if not isinstance(f, dict):
            continue
        module = f.get("module", "").lower().strip()
        func = f.get("function", "").lower().strip()
        ev_type = f.get("evidence_type", "").lower().strip()
        status = f.get("status", "")

        # Skip failed/unrelated findings
        if status in ("failed", "skipped", "pending"):
            continue

        # Map from module.function key
        key = f"{module}.{func}"
        mapped = _FINDING_MODULE_MAP.get(key, [])
        for ind in mapped:
            signals[ind] = signals.get(ind, 0) + 1

        # Map from evidence type
        ev_mapped = _EVIDENCE_TYPE_INDICATORS.get(ev_type, [])
        for ind in ev_mapped:
            signals[ind] = signals.get(ind, 0) + 1

        # Check result content for additional signals
        result = f.get("result", {})
        if isinstance(result, dict):
            result_str = json.dumps(result, default=str).lower()

            # USB / removable media activity
            if any(kw in result_str for kw in ["usb", "removable", "mount point", "drive letter", "flash"]):
                signals["usb_copy"] = signals.get("usb_copy", 0) + 1

            # Network share access
            if any(kw in result_str for kw in ["network share", "smb", "cifs", "\\\\", "mounted drive"]):
                signals["network_share_access"] = signals.get("network_share_access", 0) + 1

            # Personal software / unauthorized hardware
            if any(kw in result_str for kw in ["teamviewer", "anydesk", "logmein", "vnc", "remote desktop"]):
                signals["personal_software"] = signals.get("personal_software", 0) + 1

            # Encryption
            if any(kw in result_str for kw in ["encrypt", "bitlocker", "veracrypt", "truecrypt"]):
                signals["encryption"] = signals.get("encryption", 0) + 1

            # Multi-stage compromise
            if any(kw in result_str for kw in ["stage", "dropper", "downloader", "stager"]):
                signals["multi_stage"] = signals.get("multi_stage", 0) + 1

            # Credentials harvesting
            if any(kw in result_str for kw in ["password", "hash", "credential", "token"]):
                signals["credentials_harvesting"] = signals.get("credentials_harvesting", 0) + 1

            # Renamed files
            if any(kw in result_str for kw in ["renamed", "moved", "copy to", "backup"]):
                signals["renamed_files"] = signals.get("renamed_files", 0) + 1

    return signals


# ---------------------------------------------------------------------------
# Scoring engine
# ---------------------------------------------------------------------------


def classify_case(
    findings: Optional[List[Dict]] = None,
    indicator_hits: Optional[List[Dict]] = None,
    behavioral_flags: Optional[Dict[str, List[Dict]]] = None,
) -> List[Dict[str, Any]]:
    """Multi-label case classification engine.

    Scans evidence findings, triage indicator hits, and behavioral flags, then
    scores each category in THREAT_TAXONOMY based on how many of its required
    indicators were triggered.

    Parameters
    ----------
    findings : list of dict, optional
        Completed finding records from findings_writer.all_records().
    indicator_hits : list of dict, optional
        Triage indicator hits from _scan_triage_indicators().
    behavioral_flags : dict of str -> list, optional
        Per-device behavioral flags {device_id: [{flag_type, ...}, ...]}.

    Returns
    -------
    list of dict
        Results sorted by confidence (descending). Each entry::

            {
                "category": str,         # Threat category name
                "confidence": float,     # 0.0 – 1.0
                "matching_indicators": [str]   # Which indicators were triggered
            }

        Categories with confidence > 0 are included. The top entry is the
        primary classification; entries with confidence > 0.3 are secondary.
    """
    # 1. Aggregate indicators from all three sources
    signals: Dict[str, int] = {}
    for source_fn, source_data in [
        (_extract_indicators_from_indicator_hits, indicator_hits or []),
        (_extract_indicators_from_behavioral_flags, behavioral_flags or {}),
        (_extract_indicators_from_findings, findings or []),
    ]:
        try:
            for k, v in source_fn(source_data).items():
                signals[k] = signals.get(k, 0) + v
        except Exception:
            continue

    if not signals:
        return []

    # 2. Score each threat category
    results: List[Dict[str, Any]] = []
    total_signal_count = sum(signals.values())

    for category_name, taxonomy in THREAT_TAXONOMY.items():
        required_indicators = taxonomy.get("indicators", [])
        score_weight = taxonomy.get("score_weight", 1.0)

        if not required_indicators:
            continue

        # Find which required indicators are present in our signals
        matched_indicators = [
            ind for ind in required_indicators if ind in signals
        ]
        num_matched = len(matched_indicators)
        num_required = len(required_indicators)

        if num_matched == 0:
            continue

        # Raw score: proportion of required indicators matched
        raw_score = num_matched / num_required

        # Signal-bonus: how strongly did the matched indicators fire?
        matched_signal_sum = sum(signals[ind] for ind in matched_indicators)
        if total_signal_count > 0:
            signal_fraction = matched_signal_sum / total_signal_count
        else:
            signal_fraction = 0.0

        # Combined confidence: blend coverage + signal strength, apply weight
        confidence = min(1.0, (raw_score * 0.6 + signal_fraction * 0.4) * score_weight)

        results.append({
            "category": category_name,
            "confidence": round(confidence, 4),
            "matching_indicators": matched_indicators,
        })

    # 3. Sort by descending confidence
    results.sort(key=lambda r: r["confidence"], reverse=True)

    return results


def summarize_classification(
    classification_results: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Build a backward-compatible classification summary dict.

    Parameters
    ----------
    classification_results : list of dict
        Output from classify_case().

    Returns
    -------
    dict with keys:
        primary : str                  — top category name
        secondary : list[str]          — categories with confidence > 0.3
        confidence : float             — confidence of primary
        all : list[dict]               — full classification results
    """
    if not classification_results:
        return {
            "primary": "Unknown",
            "secondary": [],
            "confidence": 0.0,
            "all": [],
        }

    top = classification_results[0]
    return {
        "primary": top["category"],
        "secondary": [
            r["category"]
            for r in classification_results
            if r["confidence"] > 0.3 and r["category"] != top["category"]
        ],
        "confidence": top["confidence"],
        "all": classification_results,
    }
