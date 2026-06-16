#!/usr/bin/env python3
"""
Geoff DFIR — MITRE ATT&CK Binding Layer.

Maps forensic findings from the find_evil() pipeline to specific MITRE ATT&CK
techniques by pattern-matching on module names, function names, result content,
and parameter values.
"""

import re

# ---------------------------------------------------------------------------
# MITRE ATT&CK Technique Map
# ---------------------------------------------------------------------------
# Each entry has:
#   technique_id     — MITRE ATT&CK ID (e.g. T1052.001)
#   technique_name   — Human-readable label
#   patterns         — list of dicts with keys searched across finding records
#
# Pattern matching strategy: all patterns are evaluated as regex against
# stringified versions of finding fields.  A technique matches if ANY one
# of its patterns fires on a finding.

MITRE_MAP = [
    # ---- Exfiltration over USB ----
    {
        "technique_id": "T1052.001",
        "technique_name": "Exfiltration over USB",
        "description": "USB activity combined with file copy to removable media",
        "confidence_weight": 0.8,
        "patterns": [
            # USB device enumeration / removable storage activity
            {"fields": ["module", "function", "result", "params"],
             "regex": r"(?i)(USB|removable\s*media|\\Device\\HarddiskVolume)",
             "reason": "USB storage device detected"},
            # File copy to removable paths
            {"fields": ["result", "params", "evidence_file"],
             "regex": r"(?i)(copy.*(?:USB|F:|E:|removable)|(?:USB|removable).*copy)",
             "reason": "File copy to removable storage"},
        ],
    },

    # ---- Exfiltration to Cloud Storage ----
    {
        "technique_id": "T1567.002",
        "technique_name": "Exfiltration to Cloud Storage",
        "description": "Google Drive, OneDrive, Dropbox, or other cloud-storage artifacts",
        "confidence_weight": 0.7,
        "patterns": [
            {"fields": ["module", "function", "result", "params"],
             "regex": r"(?i)(google\s*drive|onedrive|dropbox|cloud\s*storage|box\.com|icloud)",
             "reason": "Cloud storage artifact detected"},
            {"fields": ["result", "description", "params"],
             "regex": r"(?i)(cloud.*exfil|exfil.*cloud|upload.*cloud|sync.*cloud)",
             "reason": "Cloud exfiltration pattern"},
        ],
    },

    # ---- Data Staged from Local System ----
    {
        "technique_id": "T1074.001",
        "technique_name": "Data Staged from Local System",
        "description": "Files collected or copied into a staging directory before exfiltration",
        "confidence_weight": 0.7,
        "patterns": [
            {"fields": ["module", "function", "result", "description", "params"],
             "regex": r"(?i)(staging|stage\s*dir|collect.*file|bulk.*copy|mass.*copy|data.*stage)",
             "reason": "Data staging activity detected"},
            {"fields": ["result", "params"],
             "regex": r"(?i)(temp.*copy|copy.*temp|consolidat|aggregat)",
             "reason": "File consolidation pattern"},
        ],
    },

    # ---- Archive Collected Data ----
    {
        "technique_id": "T1560.001",
        "technique_name": "Archive Collected Data",
        "description": "Multiple files compressed or archived (zip, rar, 7z, tar) before exfiltration",
        "confidence_weight": 0.75,
        "patterns": [
            {"fields": ["module", "function", "result", "params", "description"],
             "regex": r"(?i)(\bzip\b|\.zip\b|\.rar\b|\.7z\b|\.tar\b|\.gz\b|compress|archive|packer|winrar|7zip)",
             "reason": "Archive/compression tool detected"},
            {"fields": ["result", "params", "evidence_file"],
             "regex": r"(?i)(multiple.*file|batch.*compress|bulk.*archive|file.*collect)",
             "reason": "Batch archiving pattern"},
        ],
    },

    # ---- Indicator Removal — File Deletion ----
    {
        "technique_id": "T1070.004",
        "technique_name": "Indicator Removal — File Deletion",
        "description": "Shift+Delete, USN journal clearing, sdelete, or bulk file deletion",
        "confidence_weight": 0.8,
        "patterns": [
            {"fields": ["module", "function", "result", "description"],
             "regex": r"(?i)(shift.*delete|permanent.*delete|secure.*delete|sdelete|wipe.*file|delete.*file|USN|UsnJrnl|journal.*clear)",
             "reason": "Secure/bulk file deletion detected"},
            {"fields": ["module", "function", "result", "params"],
             "regex": r"(?i)(delete|removal|erase).{0,30}(file|data|journal|log)",
             "reason": "Indicator removal via deletion"},
        ],
    },

    # ---- Indicator Removal — Clear Logs (wevtutil, CCleaner) ----
    {
        "technique_id": "T1070.001",
        "technique_name": "Indicator Removal — Clear Logs",
        "description": "Event log clearing via wevtutil, CCleaner, or similar tools",
        "confidence_weight": 0.85,
        "patterns": [
            {"fields": ["module", "function", "result", "params", "description"],
             "regex": r"(?i)(wevtutil|clear.*log|log.*clear|event.*clear|clear.*event)",
             "reason": "Event log clearing tool detected"},
            {"fields": ["module", "function", "result", "params", "description"],
             "regex": r"(?i)(ccleaner.*log|log.*wipe|evtx.*clear|\.evtx.*delet|log.*delet)",
             "reason": "Log wiping behavior"},
        ],
    },

    # ---- Data Destruction ----
    {
        "technique_id": "T1485",
        "technique_name": "Data Destruction",
        "description": "Eraser, DoD 7-pass wipe, or other data-destruction tools",
        "confidence_weight": 0.85,
        "patterns": [
            {"fields": ["module", "function", "result", "params", "description"],
             "regex": r"(?i)(eraser|dod.*wipe|7.?pass|dod.*pass|guttmann|data.*destruct|disk.*wipe|secure.*erase)",
             "reason": "Data destruction tool detected"},
            {"fields": ["module", "function", "result", "params"],
             "regex": r"(?i)(wipe|shred|overwrite).{0,20}(disk|drive|partition|free.?space)",
             "reason": "Disk wiping activity"},
        ],
    },

    # ---- Email Collection (Outlook OST/PST access) ----
    {
        "technique_id": "T1114.002",
        "technique_name": "Email Collection",
        "description": "Outlook OST/PST file access or extraction",
        "confidence_weight": 0.8,
        "patterns": [
            {"fields": ["module", "function", "result", "params", "description"],
             "regex": r"(?i)(\.pst\b|\.ost\b|outlook|email.*collect|mail.*extract|pst.*extract|ost.*extract)",
             "reason": "PST/OST email file access detected"},
            {"fields": ["module", "function", "result", "params", "evidence_file"],
             "regex": r"(?i)(pst|ost).{0,10}(file|extract|access|copy|readpst)",
             "reason": "Email database extraction"},
        ],
    },

    # ---- Exfiltration via Email ----
    {
        "technique_id": "T1048.001",
        "technique_name": "Exfiltration via Email",
        "description": "Sending data via email attachments",
        "confidence_weight": 0.75,
        "patterns": [
            {"fields": ["module", "function", "result", "description"],
             "regex": r"(?i)(email.*attach|attach.*email|exfil.*email|email.*exfil|mail.*send|smtp.*data)",
             "reason": "Email exfiltration pattern"},
            {"fields": ["result", "params", "description"],
             "regex": r"(?i)(send.*(?:attach|file|data)|(?:attach|file|data).*send).{0,20}(?:mail|email)",
             "reason": "Data sent via email"},
        ],
    },

    # ---- Obfuscated Files or Information ----
    {
        "technique_id": "T1027",
        "technique_name": "Obfuscated Files or Information",
        "description": "File rename with extension change, encoding, or other obfuscation",
        "confidence_weight": 0.65,
        "patterns": [
            {"fields": ["module", "function", "result", "params", "description"],
             "regex": r"(?i)(rename|obfuscat|extension.*change|file.*rename|double.?ext|hidden.*ext)",
             "reason": "File renaming / obfuscation detected"},
            {"fields": ["module", "function", "result", "description"],
             "regex": r"(?i)(encoded|base64|cipher|encrypt|xor|packed|embedded.*file)",
             "reason": "Obfuscation/encoding technique"},
        ],
    },

    # ---- Clear Windows Event Logs (CCleaner) ----
    {
        "technique_id": "T1070.008",
        "technique_name": "Clear Windows Event Logs",
        "description": "CCleaner or similar utility used to clear Windows event logs",
        "confidence_weight": 0.8,
        "patterns": [
            {"fields": ["module", "function", "result", "params", "description"],
             "regex": r"(?i)(ccleaner.*event|ccleaner.*log|ccleaner.*evtx|clear.*windows.*event|windows.*event.*clear)",
             "reason": "CCleaner event log clearing"},
            {"fields": ["module", "function", "result", "description"],
             "regex": r"(?i)(event.*log.*clear|clear.*event.*log|evtx.*remov|log.*purg)",
             "reason": "Windows event log clearing"},
        ],
    },
]


def map_findings_to_mitre(findings: list) -> list:
    """Evaluate all findings and return matched MITRE ATT&CK techniques.

    Args:
        findings: List of finding dicts from findings_writer.all_records().
                  Each finding typically has keys like:
                    module, function, result, params, description,
                    evidence_file, playbook, step_key, status

    Returns:
        List of dicts, each with:
            technique_id     — MITRE ATT&CK ID (str)
            technique_name   — Human-readable label (str)
            confidence       — Float 0.0–1.0 (derived from highest match quality)
            evidence_paths   — List of evidence file paths that triggered the match
            matched_reasons  — List of human-readable reasons for the match
    """
    matched = {}

    for finding in findings:
        # Build a searchable text corpus from the relevant fields
        corpus_parts = []
        for key in ("module", "function", "description", "playbook"):
            val = finding.get(key)
            if val:
                corpus_parts.append(str(val))

        # Flatten nested dicts (result, params) into the search corpus
        for nested_key in ("result", "params"):
            val = finding.get(nested_key)
            if val and isinstance(val, dict):
                corpus_parts.append(_flatten_dict(val))
            elif val:
                corpus_parts.append(str(val))

        # Also include evidence_file path
        ef = finding.get("evidence_file")
        if ef:
            corpus_parts.append(str(ef))

        corpus = " ".join(corpus_parts)
        evidence_file = str(ef) if ef else ""

        for technique in MITRE_MAP:
            tid = technique["technique_id"]
            for pattern in technique["patterns"]:
                matched_fields_match = False
                # Check if the finding has any of the specified fields
                for field in pattern["fields"]:
                    val = finding.get(field)
                    if val:
                        matched_fields_match = True
                        break

                if not matched_fields_match:
                    continue

                # Apply the regex
                if re.search(pattern["regex"], corpus):
                    if tid not in matched:
                        matched[tid] = {
                            "technique_id": tid,
                            "technique_name": technique["technique_name"],
                            "confidence": technique["confidence_weight"],
                            "evidence_paths": [],
                            "matched_reasons": [],
                        }
                    if evidence_file and evidence_file not in matched[tid]["evidence_paths"]:
                        matched[tid]["evidence_paths"].append(evidence_file)
                    reason = pattern.get("reason", "Pattern matched")
                    if reason not in matched[tid]["matched_reasons"]:
                        matched[tid]["matched_reasons"].append(reason)
                    break  # One pattern match per technique per finding is enough

    # Build final list sorted by technique_id
    result = sorted(matched.values(), key=lambda x: x["technique_id"])

    # Apply dedup for evidence paths
    for entry in result:
        entry["evidence_paths"] = list(dict.fromkeys(entry["evidence_paths"]))

    return result


def _flatten_dict(d: dict, max_depth: int = 3) -> str:
    """Recursively flatten a nested dict into a space-separated string of values."""
    parts = []
    stack = [d]
    depth = 0
    while stack and depth < max_depth:
        current = stack.pop()
        if isinstance(current, dict):
            for v in current.values():
                if isinstance(v, dict):
                    stack.append(v)
                elif isinstance(v, list):
                    for item in v[:10]:
                        if isinstance(item, dict):
                            stack.append(item)
                        else:
                            parts.append(str(item))
                else:
                    parts.append(str(v))
        depth += 1
    return " ".join(p for p in parts if p)
