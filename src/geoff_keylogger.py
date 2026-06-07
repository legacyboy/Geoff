#!/usr/bin/env python3
"""Geoff DFIR - PB-SIFT-062 Keylogger/Spyware Detection.

Detects keylogger and spyware artifacts including:
  - Known keylogger binaries in file listings
  - Keyboard hook DLLs in process listings
  - Windows accessibility service abuse (sticky keys, magnifier, etc.)
  - Android accessibility service overlay attacks
  - Keylogger output log files (keystroke patterns)
  - Correlation with email findings (keyloggers that email output)
"""

import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Callable, Optional

# ---------------------------------------------------------------------------
# Known keylogger binary names (lowercase)
# ---------------------------------------------------------------------------

_KEYLOGGER_BINS = frozenset({
    # Commercial keyloggers
    "refog", "refog_keylogger", "refog_personal_monitor",
    "actual_keylogger", "ardamax", "ardamax_keylogger",
    "elite_keylogger", "spyrix", "spyrix_keylogger",
    "golden_keylogger", "best_keylogger", "revealer_keylogger",
    "all_in_one_keylogger", "easykeylogger",
    "family_keylogger", "perfect_keylogger", "keylogger_pro",
    "micro_keylogger", "home_keylogger", "kidlogger",
    "ispy", "spyrix_personal_monitor",
    # RATs with keylogging
    "darkcomet", "njrat", "pandabat", "blackshades",
    "quasar", "nanocore", "remcos", "asyncrat",
    # Generic / open source
    "logkeys", "pykeylogger", "xinput_keylogger",
    "klog", "keylogger",
})

# Hook DLL names associated with keyboard hooking (lowercase fragments)
_HOOK_DLL_PATTERNS = [
    r"kbdhook",
    r"keyboard.hook",
    r"keyhook",
    r"llkeyboard",
    r"wh_keyboard",
    r"setwindowshookex",
    r"getkeyboardstate",
    r"keylogger\.dll",
    r"klogger\.dll",
]

# Windows accessibility binary abuse (image file execution options hijack)
_ACCESSIBILITY_BINS = frozenset({
    "sethc.exe",       # Sticky Keys
    "magnify.exe",     # Magnifier
    "osk.exe",         # On-Screen Keyboard
    "utilman.exe",     # Utility Manager
    "narrator.exe",    # Narrator
    "displayswitch.exe",
    "atbroker.exe",
})

# Android accessibility service abuse indicators
_ANDROID_OVERLAY_PATTERNS = [
    r"AccessibilityService",
    r"BIND_ACCESSIBILITY_SERVICE",
    r"android\.permission\.BIND_ACCESSIBILITY_SERVICE",
    r"overlayService",
    r"TYPE_APPLICATION_OVERLAY",
    r"SYSTEM_ALERT_WINDOW",
]

# Log file patterns that suggest keystroke capture
_LOG_FILE_PATTERNS = [
    r"keylog",
    r"keystroke",
    r"keycapture",
    r"input_log",
    r"klog\d*\.txt",
    r"keys\d*\.log",
    r"typed\d*\.txt",
    r"capture\d*\.log",
]

# Email delivery patterns for keylogger output
_EMAIL_DELIVERY_PATTERNS = [
    r"smtp.*keylog",
    r"keylog.*smtp",
    r"send.*log.*email",
    r"email.*keystroke",
    r"mail.*capture",
]

# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class KeyloggerAnalyzer:
    """PB-SIFT-062 — Keylogger/Spyware Detection."""

    def scan_binaries(self, findings: list) -> list:
        """Detect known keylogger binaries in file listings and process lists."""
        hits = []
        seen: set = set()

        for rec in findings:
            function = str(rec.get("function", "")).lower()
            output = str(rec.get("output", ""))
            output_lower = output.lower()
            playbook = str(rec.get("playbook", ""))

            is_file_or_proc = any(kw in function for kw in (
                "list_files", "list_deleted", "process_list", "find_malware",
                "filesystem", "strings",
            ))
            if not is_file_or_proc:
                continue

            for bin_name in _KEYLOGGER_BINS:
                if bin_name in output_lower:
                    key = f"binary:{bin_name}"
                    if key not in seen:
                        seen.add(key)
                        hits.append({
                            "detection_type": "binary",
                            "name": bin_name,
                            "source_function": function,
                            "source_playbook": playbook,
                            "context": _excerpt(output, bin_name, 150),
                            "confidence": "HIGH",
                        })

        return hits

    def scan_hook_dlls(self, findings: list) -> list:
        """Detect keyboard hook DLLs in process/module listings."""
        hits = []
        seen: set = set()

        for rec in findings:
            function = str(rec.get("function", "")).lower()
            output = str(rec.get("output", ""))
            playbook = str(rec.get("playbook", ""))

            is_relevant = any(kw in function for kw in (
                "process_list", "find_malware", "malfind", "cmdline",
                "network_scan", "list_files", "strings",
            ))
            if not is_relevant:
                continue

            for pattern in _HOOK_DLL_PATTERNS:
                if re.search(pattern, output, re.IGNORECASE):
                    key = f"hook:{pattern}"
                    if key not in seen:
                        seen.add(key)
                        m = re.search(pattern, output, re.IGNORECASE)
                        hits.append({
                            "detection_type": "hook_dll",
                            "pattern": pattern,
                            "source_function": function,
                            "source_playbook": playbook,
                            "context": _excerpt(output, m.group(0), 150) if m else output[:200],
                            "confidence": "MEDIUM",
                        })

        return hits

    def scan_accessibility_abuse(self, findings: list) -> list:
        """Detect Windows accessibility binary hijacking (IFEO, debugger key)."""
        hits = []
        seen: set = set()

        for rec in findings:
            function = str(rec.get("function", "")).lower()
            output = str(rec.get("output", ""))
            output_lower = output.lower()
            playbook = str(rec.get("playbook", ""))

            is_relevant = any(kw in function for kw in (
                "registry", "autoruns", "hive", "list_files",
            ))
            if not is_relevant:
                continue

            for bin_name in _ACCESSIBILITY_BINS:
                if bin_name.lower() in output_lower:
                    # More suspicious if paired with "debugger" or "ImageFileExecutionOptions"
                    is_hijack = bool(re.search(
                        r"(debugger|ImageFileExecutionOptions|IFEO|cmd\.exe|powershell|wscript)",
                        output, re.IGNORECASE,
                    ))
                    key = f"accessibility:{bin_name}"
                    if key not in seen:
                        seen.add(key)
                        hits.append({
                            "detection_type": "accessibility_abuse",
                            "binary": bin_name,
                            "suspected_hijack": is_hijack,
                            "source_function": function,
                            "source_playbook": playbook,
                            "context": _excerpt(output, bin_name, 200),
                            "confidence": "HIGH" if is_hijack else "MEDIUM",
                        })

        return hits

    def scan_android_overlay(self, findings: list) -> list:
        """Detect Android accessibility service overlay attacks."""
        hits = []
        seen: set = set()

        for rec in findings:
            function = str(rec.get("function", "")).lower()
            output = str(rec.get("output", ""))
            playbook = str(rec.get("playbook", ""))
            module = str(rec.get("module", "")).lower()

            if module not in ("mobile", "android") and "android" not in function:
                continue

            for pattern in _ANDROID_OVERLAY_PATTERNS:
                if re.search(pattern, output, re.IGNORECASE):
                    key = f"android:{pattern}"
                    if key not in seen:
                        seen.add(key)
                        m = re.search(pattern, output, re.IGNORECASE)
                        hits.append({
                            "detection_type": "android_overlay",
                            "pattern": pattern,
                            "source_function": function,
                            "source_playbook": playbook,
                            "context": _excerpt(output, m.group(0), 150) if m else output[:200],
                            "confidence": "MEDIUM",
                        })

        return hits

    def scan_log_files(self, findings: list) -> list:
        """Detect keylogger output files by filename and content patterns."""
        hits = []
        seen: set = set()

        for rec in findings:
            function = str(rec.get("function", "")).lower()
            output = str(rec.get("output", ""))
            playbook = str(rec.get("playbook", ""))

            if "list_files" not in function and "list_deleted" not in function:
                continue

            for pattern in _LOG_FILE_PATTERNS:
                for m in re.finditer(pattern, output, re.IGNORECASE):
                    filename = m.group(0)
                    key = f"logfile:{filename.lower()}"
                    if key not in seen:
                        seen.add(key)
                        hits.append({
                            "detection_type": "log_file",
                            "filename_pattern": pattern,
                            "matched": filename,
                            "source_function": function,
                            "source_playbook": playbook,
                            "context": _excerpt(output, filename, 150),
                            "confidence": "MEDIUM",
                        })

        return hits

    def correlate_with_email(self, keylogger_hits: list, email_findings: list) -> list:
        """Correlate keylogger findings with email delivery (keyloggers that email output)."""
        if not keylogger_hits or not email_findings:
            return []

        correlations = []
        for rec in email_findings:
            output = str(rec.get("output", ""))
            for pattern in _EMAIL_DELIVERY_PATTERNS:
                if re.search(pattern, output, re.IGNORECASE):
                    correlations.append({
                        "correlation_type": "email_delivery",
                        "source_function": rec.get("function", ""),
                        "pattern": pattern,
                        "context": output[:200],
                        "confidence": "HIGH",
                        "note": "Keylogger appears to deliver captured data via email",
                    })

        return correlations

    def generate_report(
        self,
        binaries: list,
        hook_dlls: list,
        accessibility: list,
        android_overlay: list,
        log_files: list,
        email_correlations: list,
    ) -> dict:
        all_hits = binaries + hook_dlls + accessibility + android_overlay + log_files + email_correlations
        high = [h for h in all_hits if h.get("confidence") == "HIGH"]
        return {
            "playbook": "PB-SIFT-062",
            "playbook_name": "Keylogger/Spyware Analysis",
            "total_hits": len(all_hits),
            "high_confidence_hits": len(high),
            "binary_detections": binaries,
            "hook_dll_detections": hook_dlls,
            "accessibility_abuse": accessibility,
            "android_overlay_attacks": android_overlay,
            "log_file_detections": log_files,
            "email_delivery_correlations": email_correlations,
            "summary_hits": (high or all_hits)[:20],
        }

    def analyze(
        self,
        case_dir: str,
        findings: list,
        call_llm_func: Optional[Callable] = None,
    ) -> dict:
        email_findings = [f for f in findings if "email" in str(f.get("module", "")).lower()]

        binaries = self.scan_binaries(findings)
        hook_dlls = self.scan_hook_dlls(findings)
        accessibility = self.scan_accessibility_abuse(findings)
        android_overlay = self.scan_android_overlay(findings)
        log_files = self.scan_log_files(findings)
        email_correlations = self.correlate_with_email(
            binaries + hook_dlls, email_findings
        )

        report = self.generate_report(
            binaries, hook_dlls, accessibility, android_overlay,
            log_files, email_correlations,
        )

        narrative = ""
        if call_llm_func and report["total_hits"] > 0:
            narrative = self._generate_narrative(report, call_llm_func)
        report["narrative"] = narrative

        if case_dir:
            out_path = Path(case_dir) / "output" / "PB-SIFT-062_keylogger.json"
            try:
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_text(json.dumps(report, default=str, indent=2))
            except OSError:
                pass

        return report

    def _generate_narrative(self, report: dict, call_llm_func: Callable) -> str:
        parts = [
            "You are a digital forensics analyst. Summarize the keylogger/spyware findings.",
            f"Total hits: {report['total_hits']}, high confidence: {report['high_confidence_hits']}",
        ]
        for hit in report["summary_hits"][:8]:
            dtype = hit.get("detection_type", "")
            name = hit.get("name") or hit.get("binary") or hit.get("pattern", "")
            parts.append(f"  - [{dtype}] {name} ({hit.get('confidence', '')}): {hit.get('context', '')[:80]}")
        parts.append(
            "\nWrite a concise forensic narrative (2-3 paragraphs) covering: "
            "(1) what keylogger/spyware was found and its likely purpose, "
            "(2) what data may have been captured, "
            "(3) whether it communicates findings externally, "
            "(4) recommended containment steps."
        )
        try:
            return call_llm_func("\n".join(parts), agent_type="manager") or ""
        except Exception:
            return ""


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _excerpt(text: str, keyword: str, context_chars: int = 100) -> str:
    idx = text.lower().find(keyword.lower())
    if idx < 0:
        return text[:context_chars]
    start = max(0, idx - context_chars // 2)
    end = min(len(text), idx + len(keyword) + context_chars // 2)
    return text[start:end]
