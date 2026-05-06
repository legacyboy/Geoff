#!/usr/bin/env python3
"""
Narrative Report Generator — Converts JSON findings into human-readable reports.

Uses LLM to generate natural language summaries, with a template-based
fallback if the LLM is unavailable.
"""

import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Callable, Optional


def _safe_prompt_str(value: Any, max_len: int = 500) -> str:
    """Sanitize a value before embedding it in an LLM prompt.

    Strips newlines and carriage returns (prevent prompt structure breaks),
    escapes backslashes and double-quotes (prevent injection via IOC values
    such as URLs containing quote chars), and truncates to avoid context bloat.
    """
    s = str(value) if value is not None else ""
    s = s.replace("\n", " ").replace("\r", " ")
    s = s.replace("\\", "\\\\").replace('"', '\\"')
    return s[:max_len]


def osLabel(d):
    """Generate OS label for a device from device_type and os_type fields."""
    # Collect ALL OS indicators from device_type and os_type fields
    indicators = set()
    # Support both object attribute access and dict access
    if isinstance(d, dict):
        t = (d.get('device_type') or "").lower()
        os_t = (d.get('os_type') or "").lower()
        os_v = d.get('os_version') or ''
    else:
        t = (getattr(d, 'device_type', None) or "").lower()
        os_t = (getattr(d, 'os_type', None) or "").lower()
        os_v = getattr(d, 'os_version', None) or ''
    
    if "ios" in t: indicators.add(f"iOS {os_v}".strip())
    if "android" in t: indicators.add(f"Android {os_v}".strip())
    if "mobile" in t: indicators.add(f"Mobile/Portable {os_v}".strip())
    if "server" in t or "server" in os_t: indicators.add(f"Server {os_v}".strip())
    if "network" in t or "network" in os_t: indicators.add(f"Network Capture {os_v}".strip())
    if "pcap" in t: indicators.add(f"PCAP {os_v}".strip())
    if os_t == "windows": indicators.add(f"Windows {os_v}".strip())
    if os_t == "linux": indicators.add(f"Linux {os_v}".strip())
    if os_t == "macos": indicators.add(f"macOS {os_v}".strip())
    if not indicators and os_t and os_t != "unknown": indicators.add(os_t.title())
    
    return ", ".join(sorted(indicators)) if indicators else "unknown"


# Behavior flag explanations mapping
_FLAG_EXPLANATIONS = {
    "no_recovery": "No user accounts recovered from registry hives - may indicate account deletion, use of non-standard authentication, or corrupted registry data",
    "lateral_movement": "Evidence of lateral movement detected - attacker moved between systems using stolen credentials or remote access tools. Check for Remote Desktop, PsExec, WMI, or SMB-based movement artifacts.",
    "credential_theft": "Credential harvesting detected - passwords, hashes, or tokens were extracted from memory or registry. Tools like Mimikatz, Lazagne, or ProcDump may have been used.",
    "exfiltration": "Data exfiltration detected - large outbound data transfers to external hosts. Check for FTP, HTTP POST, DNS tunneling, or cloud storage uploads.",
    "c2_traffic": "Command & Control communications detected - regular beaconing to external infrastructure. Common C2 channels include HTTPS, DNS, and custom protocols.",
    "persistence": "Persistence mechanism detected - the attacker has established a way to maintain access. Common methods: scheduled tasks, registry Run keys, services, or WMI event subscriptions.",
    "lolbin": "Living-off-the-land binary (LOLBin) usage detected - legitimate system tools used maliciously. Examples: PowerShell, certutil, mshta, regsvr32, or wmic used for code execution or download.",
    "web_shell": "Web shell detected - attacker-placed script providing remote access via HTTP/HTTPS. Often found as .asp, .aspx, .php, or .jsp files in web directories.",
    "cryptominer": "Cryptocurrency mining activity detected - unauthorized use of system resources. Look for high CPU usage, mining pool connections, and coin miner executables.",
    "phishing": "Phishing indicators detected - suspicious emails, attachments, or links. Check email headers, attachment hashes, and URL reputation.",
    "privilege_escalation": "Privilege escalation activity detected - user obtained higher-level permissions. Check for UAC bypass, token manipulation, or exploitation of vulnerable services.",
    "defense_evasion": "Defense evasion techniques detected - attacker avoiding detection. Common methods: disabling security tools, clearing logs, timestomping, or process injection.",
    "discovery": "System discovery activity detected - attacker mapping the environment. Look for net commands, network scanning, and directory enumeration.",
    "collection": "Data collection activity detected - attacker gathering sensitive information. Check for file access patterns, clipboard capture, and screen captures.",
    "network_traffic": "Suspicious network traffic detected - unusual connections. Check for unusual ports, protocols, or connection patterns.",
}


class NarrativeReportGenerator:
    """
    Generates human-readable investigation reports from structured findings.

    Output structure:
    1. Executive Summary (2-3 paragraphs)
    2. Devices & Users Overview
    3. Per-User Activity Narratives
    4. Timeline of Significant Events
    5. Behavioral Findings (grouped by severity)
    6. Conclusion & Recommendations
    """

    def __init__(self, call_llm_func: Callable = None):
        """
        Args:
            call_llm_func: Function matching the signature of call_llm()
                           in geoff_integrated.py. Takes (message, context, agent_type).
                           If None, falls back to template-based output.
        """
        self.call_llm = call_llm_func

    # Ollama error patterns — text that should NEVER appear in narrative output
    _OLLAMA_ERROR_PATTERNS = (
        "Having trouble connecting to Ollama",
        "Check OLLAMA_URL",
        "[ERROR] Ollama returned",
    )

    def _call_llm_with_retry(self, prompt: str, context: str = "", agent_type: str = "manager",
                              max_retries: int = 3, backoff: list = None) -> str | None:
        """Call LLM with retry and error detection.

        Returns the LLM response text, or None if all retries fail or the
        response contains Ollama error messages. On failure, the caller
        should use template fallback and mark the section needs_review.
        """
        if not self.call_llm:
            return None

        if backoff is None:
            backoff = [30, 60, 120]

        import time as _time
        for attempt in range(max_retries + 1):
            try:
                result = self.call_llm(prompt, context, agent_type=agent_type)
                # Detect leaked error messages
                if result is None or any(pat in str(result) for pat in self._OLLAMA_ERROR_PATTERNS):
                    if attempt < max_retries:
                        print(f"[NARRATIVE] Ollama error in response, retrying ({attempt+1}/{max_retries})...")
                        _time.sleep(backoff[attempt] if attempt < len(backoff) else backoff[-1])
                        continue
                    return None  # All retries exhausted
                return result
            except Exception as e:
                print(f"[NARRATIVE] LLM call failed (attempt {attempt+1}): {e}")
                if attempt < max_retries:
                    _time.sleep(backoff[attempt] if attempt < len(backoff) else backoff[-1])
                    continue
                return None
        return None

    def generate(self, report_json: dict, device_map: dict,
                 user_map: dict, super_timeline_path: str,
                 correlated_users: dict, behavioral_flags: dict,
                 case_work_dir: Path,
                 step_evidence_anchors: Optional[List[dict]] = None) -> Path:
        """
        Generate the full narrative report.

        Args:
            step_evidence_anchors: Optional list of evidence_chain dicts from
                completed find_evil steps (CRITICAL/HIGH significance), used to
                anchor the attack chain narrative to specific artifacts.

        Returns:
            Path to narrative_report.md
        """
        case_work_dir = Path(case_work_dir)
        report_dir = case_work_dir / "reports"
        report_dir.mkdir(parents=True, exist_ok=True)

        md_path = report_dir / "narrative_report.md"
        json_path = report_dir / "narrative_report.json"

        sections = {}
        needs_review_sections = []  # Track sections where LLM failed

        # 1. Executive Summary
        exec_result = self._generate_executive_summary(
            report_json, device_map, user_map, behavioral_flags)
        sections["executive_summary"] = exec_result
        # Template fallbacks contain specific phrasing — check for it
        if exec_result and self._is_template_fallback(exec_result):
            needs_review_sections.append("executive_summary")

        # 2. Devices & Users Overview
        sections["devices_and_users"] = self._generate_devices_overview(
            device_map, user_map)

        # 3. Per-User Narratives
        sections["user_narratives"] = {}
        users = user_map.get("users", user_map)
        for username, udata in users.items():
            if isinstance(udata, dict):
                narrative = self._generate_user_narrative(
                    username, udata, correlated_users.get(username, {}),
                    device_map, behavioral_flags)
                sections["user_narratives"][username] = narrative
                if narrative and self._is_template_fallback(narrative):
                    needs_review_sections.append(f"user_narratives.{username}")

        # 4. Timeline of Significant Events
        sections["significant_events"] = \
            self._generate_significant_timeline(
                super_timeline_path, behavioral_flags)

        # 5. Behavioral Findings
        # 5b. Failed steps analysis
        sections["failed_steps"] = self._render_failed_steps(report_json)

        # 5c. Behavioral Findings
        sections["findings"] = self._generate_findings_section(
            behavioral_flags, report_json)

        # 6. IOC Extraction
        iocs = self._extract_iocs(report_json, behavioral_flags)
        sections["iocs"] = iocs

        # 7. Attack Chain Synthesis (the interpretation layer)
        sections["attack_chain"] = self._synthesize_attack_chain(
            report_json, behavioral_flags, correlated_users, iocs,
            step_evidence_anchors=step_evidence_anchors or [])
        if sections["attack_chain"] and self._is_template_fallback(sections["attack_chain"]):
            needs_review_sections.append("attack_chain")

        # 8. Conclusion & Recommendations
        sections["conclusion"] = self._generate_conclusion(
            report_json, behavioral_flags, correlated_users)
        if sections["conclusion"] and self._is_template_fallback(sections["conclusion"]):
            needs_review_sections.append("conclusion")

        # Track needs_review flag in output
        if needs_review_sections:
            sections["needs_review"] = True
            sections["needs_review_sections"] = needs_review_sections
            sections["needs_review_reason"] = "Ollama timeout - narrative generation failed, template fallback used"

        # Write markdown report — include needs_review banner if applicable
        md_content = self._render_markdown(sections, report_json)
        if needs_review_sections:
            banner = ("\n> ⚠️ **Needs Review**: The following sections used template fallback "
                      "due to Ollama timeout: " + ", ".join(needs_review_sections) + "\n\n")
            md_content = banner + md_content
        with open(md_path, "w") as f:
            f.write(md_content)

        # Write structured JSON version
        with open(json_path, "w") as f:
            json.dump(sections, f, indent=2, default=str)

        return md_path

    def _is_template_fallback(self, text: str) -> bool:
        """Detect if text was generated by template fallback rather than LLM.

        Template fallbacks start with predictable patterns like
        'This investigation analyzed evidence from' or
        '{username} was observed on'.
        """
        if not text:
            return False
        # Common template fallback prefixes
        template_prefixes = (
            "This investigation analyzed evidence from",
            "was observed on",
            "## Attack Chain",
            "# Conclusion",
        )
        # Only flag as template if we see multiple template markers
        marker_count = sum(1 for pfx in template_prefixes if pfx in (text[:200] if text else ""))
        # Single marker is fine (LLM might start similarly), but if the text
        # is very short for an LLM-quality section, it's likely template
        return len(text) < 150 and marker_count >= 1

    # ----------------------------------------------------------------
    # Section generators
    # ----------------------------------------------------------------

    def _generate_executive_summary(self, report_json: dict,
                                     device_map: dict,
                                     user_map: dict,
                                     behavioral_flags: dict) -> str:
        """Generate 2-3 paragraph executive summary."""

        # Count key metrics
        num_devices = len(device_map)
        num_users = len(user_map.get("users", user_map))
        total_flags = sum(len(f) for f in behavioral_flags.values())
        high_flags = sum(
            1 for flags in behavioral_flags.values()
            for f in flags if f.get("severity") in ("CRITICAL", "HIGH"))
        evil_found = report_json.get("evil_found", False)
        severity = report_json.get("severity", "INFO")
        elapsed = report_json.get("elapsed_seconds", 0)

        context = {
            "num_devices": num_devices,
            "num_users": num_users,
            "total_behavioral_flags": total_flags,
            "high_severity_flags": high_flags,
            "evil_found": evil_found,
            "overall_severity": severity,
            "os_types": list(set(
                d.get("os_type", "unknown") for d in device_map.values())),
            "device_types": list(set(
                d.get("device_type", "unknown") for d in device_map.values())),
            "elapsed_minutes": round(elapsed / 60, 1),
            "steps_completed": report_json.get("steps_completed", 0),
            "steps_failed": report_json.get("steps_failed", 0),
            "classification": report_json.get("classification", ""),
            "kill_chain_phases": (report_json.get("attack_chain", {}) or {}).get("kill_chain_phases", []),
            "mitre_techniques_observed": (report_json.get("attack_chain", {}) or {}).get("mitre_techniques_observed", []),
        }

        if self.call_llm:
            prompt = (
                f"You are a forensic report writer. Write a 2-3 paragraph "
                f"executive summary for a digital forensics investigation.\n\n"
                f"Investigation facts:\n"
                f"{json.dumps(context, indent=2)}\n\n"
                f"Top behavioral flags:\n"
            )
            # Add top 5 flags
            top_flags = []
            for flags in behavioral_flags.values():
                top_flags.extend(flags)
            top_flags.sort(
                key=lambda f: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2,
                               "LOW": 3}.get(f.get("severity", "LOW"), 4))
            for flag in top_flags[:5]:
                prompt += f"- [{_safe_prompt_str(flag.get('severity'), 20)}] {_safe_prompt_str(flag.get('summary'))}\n"

            prompt += (
                f"\nWrite a factual executive summary. Do not speculate "
                f"beyond what the evidence shows. Use professional tone "
                f"suitable for legal documentation."
            )

            try:
                result = self._call_llm_with_retry(prompt, "", agent_type="manager")
                if result is not None:
                    return result
                # LLM failed — mark section for review and fall through to template
            except Exception:
                pass  # Fall through to template

        # Template fallback
        return self._template_executive_summary(context, behavioral_flags)

    def _template_executive_summary(self, context: dict,
                                     behavioral_flags: dict) -> str:
        """Template-based executive summary when LLM is unavailable.

        Produces a narrative story, not a data dump. Weaves together the
        investigation timeline, key findings, and overall impact.
        """
        evil = context["evil_found"]
        severity = context["overall_severity"]

        # Build a narrative opening paragraph
        lines = []
        lines.append(
            f"A comprehensive digital forensic investigation was conducted across "
            f"{context['num_devices']} devices, analyzing {context['num_users']} "
            f"user account(s). The investigation spanned "
            f"{context['elapsed_minutes']} minutes, executing "
            f"{context['steps_completed']} analysis steps with "
            f"{context['steps_failed']} steps encountering errors."
        )

        if evil:
            lines.append("")
            lines.append(
                f"**The investigation confirmed a security compromise of "
                f"{severity} severity.** Multiple indicators of malicious "
                f"activity were identified across the examined evidence, "
                f"consistent with a coordinated intrusion."
            )

            # Collect all flags for the narrative
            all_flags = []
            for flags in behavioral_flags.values():
                all_flags.extend(flags)
            all_flags.sort(
                key=lambda f: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2,
                               "LOW": 3}.get(f.get("severity", "LOW"), 4))

            high_flags = [f for f in all_flags
                        if f.get("severity") in ("CRITICAL", "HIGH")]
            mid_flags = [f for f in all_flags
                        if f.get("severity") == "MEDIUM"]

            # Build the "what happened" narrative from flag types
            flag_types_seen = set()
            for f in all_flags:
                ft = f.get("flag_type", "")
                if ft:
                    flag_types_seen.add(ft)

            # Narrative arc based on evidence - combine flag types with classification
            # Also derive narrative from kill_chain_phases and classification when behavioral flags sparse
            categories_seen = set()
            # Check kill_chain_phases from attack_chain
            for phase in context.get("kill_chain_phases", []):
                categories_seen.add(phase.lower())
            # Also check classification string
            cls_lower = context.get("classification", "").lower()
            cat_map = {
                "phishing": ["phishing", "initial access"],
                "credential_theft": ["credential theft", "credential access", "credential_theft"],
                "persistence": ["persistence"],
                "lateral_movement": ["lateral movement", "lateral_movement"],
                "cryptominer": ["cryptominer"],
                "exfiltration": ["exfiltration"],
                "c2": ["c2", "command and control", "command & control"],
                "web_shell": ["web shell", "web_shell"],
                "lolbin": ["lolbin", "living off the land"],
                "privilege_escalation": ["privilege escalation", "privilege_escalation"],
                "defense_evasion": ["defense evasion", "defense_evasion"],
            }
            for cat, keywords in cat_map.items():
                for kw in keywords:
                    if kw in cls_lower:
                        categories_seen.add(cat)
            # Merge with flag_types
            all_cats = flag_types_seen | categories_seen

            lines.append("")
            lines.append("### Incident Narrative")
            lines.append("")

            narrative_parts = []
            if "phishing" in all_cats or "initial_access" in all_cats:
                narrative_parts.append(
                    "**Possible phishing** activity was detected (T1566) based on "
                    "classification metadata — analyst review of specific artifacts recommended."
                )
            if "credential_theft" in all_cats or "credential_access" in all_cats:
                narrative_parts.append(
                    "**Possible credential theft** activity was detected (T1003) based on "
                    "classification metadata — analyst review of specific artifacts recommended."
                )
            if "persistence" in all_cats:
                narrative_parts.append(
                    "**Possible persistence** activity was detected (T1053) based on "
                    "classification metadata — analyst review of specific artifacts recommended."
                )
            if "lateral_movement" in all_cats:
                narrative_parts.append(
                    "**Possible lateral movement** was detected based on "
                    "classification metadata — analyst review of specific artifacts recommended."
                )
            if "cryptominer" in all_cats:
                narrative_parts.append(
                    "**Possible cryptocurrency mining** activity was detected (T1496) based on "
                    "classification metadata — analyst review of specific artifacts recommended."
                )
            if "exfiltration" in all_cats:
                narrative_parts.append(
                    "**Possible data exfiltration** activity was detected (T1048) based on "
                    "classification metadata — analyst review of specific artifacts recommended."
                )
            if "c2" in all_cats or "command_and_control" in all_cats:
                narrative_parts.append(
                    "**Possible command and control** (C2) communications were detected based on "
                    "classification metadata — analyst review of specific artifacts recommended."
                )
            if "web_shell" in all_cats:
                narrative_parts.append(
                    "**Possible web shell** activity was detected based on "
                    "classification metadata — analyst review of specific artifacts recommended."
                )
            if "lolbin" in all_cats:
                narrative_parts.append(
                    "**Possible living-off-the-land binary** (LOLBin) usage was detected based on "
                    "classification metadata — analyst review of specific artifacts recommended."
                )
            if "privilege_escalation" in all_cats:
                narrative_parts.append(
                    "**Possible privilege escalation** activity was detected based on "
                    "classification metadata — analyst review of specific artifacts recommended."
                )
            if "defense_evasion" in all_cats:
                narrative_parts.append(
                    "**Possible defense evasion** activity was detected based on "
                    "classification metadata — analyst review of specific artifacts recommended."
                )

            if narrative_parts:
                for i, part in enumerate(narrative_parts, 1):
                    lines.append(f"{i}. {part}")
            elif high_flags:
                lines.append("The following high-severity findings trace the attack path:")
                for flag in high_flags[:8]:
                    lines.append(f"- **[{flag.get('severity')}]** {flag.get('summary', 'Unknown flag')}")

            lines.append("")
            lines.append(
                f"Behavioral analysis identified **{context['total_behavioral_flags']}** "
                f"anomalies across the evidence set, with **{context['high_severity_flags']}** "
                f"rated HIGH or CRITICAL. These findings collectively paint a picture of "
                f"a deliberate, multi-stage intrusion requiring immediate containment "
                f"and remediation."
            )

            if mid_flags:
                lines.append("")
                lines.append(
                    f"Additionally, {len(mid_flags)} MEDIUM-severity observations were "
                    f"noted that may represent secondary indicators or benign anomalies "
                    f"requiring analyst review."
                )
        else:
            # Clean investigation
            lines.append("")
            lines.append(
                f"No confirmed indicators of compromise were identified. "
                f"Overall severity assessment: {severity}. "
                f"Behavioral analysis identified {context['total_behavioral_flags']} "
                f"anomalies, of which {context['high_severity_flags']} were rated "
                f"HIGH or CRITICAL - these should be reviewed manually to rule out "
                f"false positives."
            )

        return "\n".join(lines)

    def _render_playbook_summary(self, report_json: dict) -> str:
        """Render condensed playbook execution summary."""
        pbs = report_json.get("playbooks_run", [])
        if not pbs:
            return "No playbook execution data available."

        condensed = {}
        for pr in pbs:
            pid = pr.get("playbook_id", "Unknown")
            name = pr.get("name", pid)
            if pid not in condensed:
                condensed[pid] = {"name": name, "runs": 0, "completed": 0, "failed": 0, "skipped": 0}
            condensed[pid]["runs"] += 1
            condensed[pid]["completed"] += pr.get("steps_completed", 0)
            condensed[pid]["failed"] += pr.get("steps_failed", 0)
            condensed[pid]["skipped"] += pr.get("steps_skipped", 0)

        lines = []
        lines.append("| Playbook | Runs | Completed | Failed | Skipped | Total Steps |")
        lines.append("|----------|------|-----------|--------|---------|-------------|")
        for pid in sorted(condensed.keys()):
            c = condensed[pid]
            total = c["completed"] + c["failed"] + c["skipped"]
            lines.append(f"| {c['name']} ({pid}) | {c['runs']} | {c['completed']} | {c['failed']} | {c['skipped']} | {total} |")

        return "\n".join(lines)

    def _generate_devices_overview(self, device_map: dict,
                                    user_map: dict) -> str:
        """Generate devices and users overview section."""
        lines = []
        for dev_id, dev in device_map.items():
            owner = dev.get("owner", "unattributed")
            os_label = osLabel(dev)
            lines.append(
                f"- **{dev_id}** ({dev.get('device_type', 'unknown')}): "
                f"{os_label}, "
                f"owner: {owner}, "
                f"{len(dev.get('evidence_files', []))} evidence file(s)")

        lines.append("")
        users = user_map.get("users", user_map)
        for username, udata in users.items():
            if isinstance(udata, dict):
                devices = udata.get("devices", [])
                lines.append(
                    f"- **{username}**: "
                    f"{len(devices)} device(s) "
                    f"({', '.join(devices)})")

        return "\n".join(lines)

    def _generate_user_narrative(self, username: str, udata: dict,
                                  correlation: dict,
                                  device_map: dict,
                                  behavioral_flags: dict) -> str:
        """Generate activity narrative for one user."""
        devices = udata.get("devices", [])
        profile = correlation.get("activity_profile", {})
        anomalies = correlation.get("anomalies", [])
        lateral = correlation.get("lateral_movement_indicators", [])

        # Collect user's behavioral flags across their devices
        user_flags = []
        for dev_id in devices:
            user_flags.extend(behavioral_flags.get(dev_id, []))

        if self.call_llm:
            prompt = (
                f"You are a forensic report writer. Write 2-3 paragraphs "
                f"describing the observed activity of user '{username}' "
                f"across their device(s).\n\n"
                f"User info:\n"
                f"- Devices: {', '.join(devices)}\n"
                f"- Activity profile: {json.dumps(profile, default=str)[:2000]}\n"
                f"- Anomalies detected: {anomalies}\n"
                f"- Lateral movement indicators: {len(lateral)}\n"
                f"- Behavioral flags on their devices: {len(user_flags)}\n"
            )

            if profile.get("common_applications"):
                prompt += f"- Top applications: {profile['common_applications'][:10]}\n"
            if profile.get("common_websites"):
                prompt += f"- Top websites: {profile['common_websites'][:10]}\n"
            if profile.get("typical_hours"):
                prompt += f"- Active hours: {profile['typical_hours']}\n"

            if user_flags:
                prompt += "\nBehavioral flags:\n"
                for flag in user_flags[:5]:
                    prompt += (
                        f"- [{_safe_prompt_str(flag.get('severity'), 20)}] "
                        f"{_safe_prompt_str(flag.get('summary'))}\n")

            prompt += (
                f"\nWrite a factual narrative. State only what the evidence "
                f"shows. Example good output: '{username} typically logs in "
                f"between 8:30-9:00 AM. Browser history shows regular "
                f"visits to office365.com. No suspicious process execution "
                f"was detected on the workstation.'"
            )

            try:
                result = self._call_llm_with_retry(prompt, "", agent_type="manager")
                if result is not None:
                    return result
            except Exception:
                pass

        # Template fallback
        return self._template_user_narrative(
            username, devices, profile, user_flags, anomalies, lateral)

    def _template_user_narrative(self, username: str,
                                  devices: List[str],
                                  profile: dict,
                                  flags: List[dict],
                                  anomalies: List[str],
                                  lateral: List[dict]) -> str:
        """Template user narrative when LLM unavailable."""
        lines = []

        lines.append(
            f"{username} was observed on "
            f"{len(devices)} device(s): {', '.join(devices)}.")

        if profile.get("first_seen") and profile.get("last_seen"):
            lines.append(
                f"Activity observed from {profile['first_seen']} "
                f"to {profile['last_seen']}.")

        if profile.get("typical_hours"):
            hours = profile["typical_hours"]
            if hours:
                lines.append(
                    f"Typical active hours: "
                    f"{min(hours):02d}:00 - {max(hours):02d}:59.")

        if profile.get("common_applications"):
            apps = [name for name, count
                    in profile["common_applications"][:5]]
            lines.append(
                f"Most frequently executed applications: "
                f"{', '.join(apps)}.")

        if profile.get("common_websites"):
            sites = [name for name, count
                     in profile["common_websites"][:5]]
            lines.append(
                f"Most visited websites: {', '.join(sites)}.")

        if profile.get("total_events"):
            lines.append(
                f"Total events attributed: "
                f"{profile['total_events']}.")

        high_flags = [f for f in flags
                      if f.get("severity") in ("CRITICAL", "HIGH")]
        if high_flags:
            lines.append("")
            lines.append(
                f"**{len(high_flags)} high-severity behavioral flags "
                f"were identified:**")
            for flag in high_flags[:5]:
                lines.append(f"- {flag.get('summary', 'Unknown')}")

        if anomalies:
            lines.append("")
            lines.append("Anomalies detected:")
            for a in anomalies[:5]:
                lines.append(f"- {a}")

        if lateral:
            lines.append("")
            lines.append(
                f"**{len(lateral)} lateral movement indicator(s) detected.**")

        if not high_flags and not anomalies and not lateral:
            lines.append(
                "No suspicious activity was detected for this user.")

        return "\n".join(lines)

    def _generate_significant_timeline(self, super_timeline_path: str,
                                        behavioral_flags: dict) -> str:
        """
        Extract significant (suspicious) events from super-timeline.

        Reads the JSONL file and filters for suspicious events.
        """
        significant = []
        try:
            with open(super_timeline_path, "r") as f:
                for line in f:
                    try:
                        event = json.loads(line)
                        if event.get("suspicious"):
                            significant.append(event)
                    except (json.JSONDecodeError, ValueError):
                        continue
        except (FileNotFoundError, IOError):
            # If super-timeline doesn't exist, extract from flags
            for dev_id, flags in behavioral_flags.items():
                for flag in flags:
                    significant.append({
                        "timestamp": "",
                        "device_id": dev_id,
                        "summary": flag.get("summary", ""),
                        "severity": flag.get("severity", ""),
                    })

        # Sort by timestamp
        significant.sort(key=lambda e: e.get("timestamp", ""))

        # Format as readable timeline
        lines = []
        for event in significant[:50]:  # Cap at 50 events
            ts = event.get("timestamp", "N/A")
            dev = event.get("device_id", "")
            summary = event.get("summary", "Unknown event")
            lines.append(f"- **{ts}** [{dev}] {summary}")

        return "\n".join(lines) if lines else \
            "No suspicious events were identified in the timeline."

    def _generate_findings_section(self, behavioral_flags: dict,
                                    report_json: dict) -> str:
        """Generate findings grouped by severity, with behavioral explanations."""
        all_flags = []
        for dev_id, flags in behavioral_flags.items():
            for flag in flags:
                flag_copy = dict(flag)
                flag_copy["device_id"] = dev_id
                all_flags.append(flag_copy)

        # Group by severity
        by_severity = {
            "CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []
        }
        for flag in all_flags:
            sev = flag.get("severity", "LOW")
            if sev in by_severity:
                by_severity[sev].append(flag)

        lines = []
        for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            flags = by_severity[severity]
            if not flags:
                continue
            lines.append(f"\n### {severity} Severity ({len(flags)} findings)")
            for flag in flags[:20]:
                ft = flag.get("flag_type", flag.get("summary", "Unknown"))
                dev = flag.get("device_id", "")
                summary = flag.get("summary", "")

                # Get MITRE techniques if available
                mitres = flag.get("mitre_att_ck", [])
                mitre_links = ""
                if mitres:
                    mitre_links = " (" + ", ".join(
                        f"[{t}](https://attack.mitre.org/techniques/{t}/)"
                        for t in mitres[:5]
                    ) + ")"

                lines.append(
                    f"- **{ft}** [{dev}]: {summary}{mitre_links}")

                # Use _FLAG_EXPLANATIONS for contextual explanation
                if ft in _FLAG_EXPLANATIONS:
                    lines.append(f"  > {_FLAG_EXPLANATIONS[ft]}")
                elif flag.get("explanation"):
                    expl = flag.get("explanation", "")
                    lines.append(f"  *{expl[:200]}*")

        if not any(by_severity.values()):
            lines.append(
                "No behavioral anomalies were detected across any device. "
                "This may indicate a clean environment or that investigative "
                "tooling did not trigger behavioral rules.")

        return "\n".join(lines)

    def _generate_conclusion(self, report_json: dict,
                              behavioral_flags: dict,
                              correlated_users: dict) -> str:
        """Generate conclusion and recommendations."""
        total_flags = sum(len(f) for f in behavioral_flags.values())
        critical = sum(
            1 for flags in behavioral_flags.values()
            for f in flags if f.get("severity") == "CRITICAL")
        evil = report_json.get("evil_found", False)

        if self.call_llm:
            prompt = (
                f"You are a forensic report writer. Write a brief conclusion "
                f"and 3-5 actionable recommendations based on:\n\n"
                f"- Evil found: {evil}\n"
                f"- Overall severity: {report_json.get('severity', 'INFO')}\n"
                f"- Total behavioral flags: {total_flags}\n"
                f"- Critical flags: {critical}\n"
                f"- Users with lateral movement: "
                f"{sum(1 for u in correlated_users.values() if u.get('lateral_movement_indicators'))}\n"
            )

            # Add top critical/high flags
            for flags in behavioral_flags.values():
                for flag in flags:
                    if flag.get("severity") in ("CRITICAL", "HIGH"):
                        prompt += f"- {_safe_prompt_str(flag.get('summary'))}\n"

            prompt += (
                f"\nBe specific and actionable. Example: "
                f"'Isolate DESKTOP-ABC from the network', "
                f"'Reset credentials for user dsmith'."
            )

            try:
                result = self._call_llm_with_retry(prompt, "", agent_type="manager")
                if result is not None:
                    return result
            except Exception:
                pass

        # Template fallback
        lines = []
        if evil:
            lines.append(
                "Evidence of compromise was identified during this "
                "investigation. Immediate containment actions are recommended.")
        else:
            lines.append(
                "No confirmed indicators of compromise were found. "
                "However, the following recommendations should be considered:")

        lines.append("\n**Recommendations:**")

        if critical > 0:
            lines.append(
                "1. Immediately isolate affected device(s) from the network")
            lines.append(
                "2. Preserve all evidence in current state for legal proceedings")
        if total_flags > 0:
            lines.append(
                f"3. Review the {total_flags} behavioral flags in detail")
            lines.append(
                "4. Reset credentials for affected user accounts")
        lines.append(
            "5. Conduct a follow-up investigation with expanded scope "
            "if warranted")

        return "\n".join(lines)

    # ----------------------------------------------------------------
    # IOC Extraction
    # ----------------------------------------------------------------

    # Private IP ranges — excluded from extracted IOCs
    _PRIV_IP = re.compile(
        r'^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|0\.0\.0\.0|255\.)')

    def _extract_iocs(self, report_json: dict,
                      behavioral_flags: dict) -> Dict[str, List[str]]:
        """Extract and deduplicate IOCs from all evidence sources.

        Scans indicator_hits, behavioral flag evidence dicts, and tool stdout
        for IPs (public only), file hashes, URLs, registry keys, Windows file
        paths, and email addresses. Returns dict of sorted lists.
        """
        buckets: Dict[str, set] = {
            "ip_addresses":  set(),
            "file_hashes":   set(),
            "urls":          set(),
            "registry_keys": set(),
            "file_paths":    set(),
            "email_addresses": set(),
        }

        def _scan(text: str) -> None:
            if not text or not isinstance(text, str):
                return
            # Public IPv4
            for m in re.finditer(r'\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b', text):
                ip = m.group(0)
                if all(0 <= int(x) <= 255 for x in ip.split('.')):
                    if not self._PRIV_IP.match(ip):
                        buckets["ip_addresses"].add(ip)
            # MD5 / SHA1 / SHA256 hashes
            for m in re.finditer(r'\b[0-9a-fA-F]{32,64}\b', text):
                h = m.group(0).lower()
                if len(h) in (32, 40, 64):
                    buckets["file_hashes"].add(h)
            # URLs
            for m in re.finditer(r'https?://[^\s"\'<>\r\n]{4,}', text):
                buckets["urls"].add(m.group(0).rstrip('.,)'))
            # Windows registry keys
            for m in re.finditer(
                    r'(?:HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)'
                    r'[\\\/][^\s"\'<>\r\n]+',
                    text, re.IGNORECASE):
                buckets["registry_keys"].add(m.group(0))
            # Windows file paths (min 10 chars to reduce noise)
            for m in re.finditer(
                    r'[A-Za-z]:\\(?:[^\\\/:*?"<>|\r\n]+\\)*[^\\\/:*?"<>|\r\n]{2,}',
                    text):
                p = m.group(0).rstrip('.,)')
                if len(p) >= 10:
                    buckets["file_paths"].add(p)
            # Email addresses
            for m in re.finditer(
                    r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b', text):
                buckets["email_addresses"].add(m.group(0).lower())

        # Source 1: triage indicator hits
        for hit in report_json.get("indicator_hits", []):
            _scan(hit.get("file", ""))
            _scan(hit.get("pattern", ""))
            _scan(hit.get("raw_match", ""))

        # Source 2: behavioral flag evidence dicts
        for dev_flags in behavioral_flags.values():
            for flag in dev_flags:
                ev = flag.get("evidence", {})
                if isinstance(ev, dict):
                    for v in ev.values():
                        _scan(str(v) if v is not None else "")

        # Source 3: tool stdout (capped to first 100KB to avoid scanning huge outputs)
        for finding in report_json.get("findings_detail", []):
            result = finding.get("result", {})
            if isinstance(result, dict):
                _scan((result.get("stdout", "") or "")[:102400])
                _scan((result.get("raw_output", "") or "")[:102400])

        # Source 4: raw text evidence files (syslogs, evtx_logs, other_files)
        # Capped at 512KB per file to limit memory use
        inv = report_json.get("evidence_inventory", {})
        text_ev = (
            inv.get("syslogs", [])
            + inv.get("evtx_logs", [])
            + inv.get("other_files", [])
        )
        for fpath in text_ev:
            try:
                size = os.path.getsize(fpath)
                if size > 5 * 1024 * 1024:
                    continue
                with open(fpath, "rb") as fh:
                    raw = fh.read(524288)
                # Replace null bytes with newlines so adjacent embedded strings
                # don't merge when decoded (e.g. strings extracted from binaries)
                _scan(raw.replace(b'\x00', b'\n').decode("utf-8", errors="ignore"))
            except OSError:
                continue

        return {k: sorted(v) for k, v in buckets.items() if v}

    # ----------------------------------------------------------------
    # Attack Chain Synthesis
    # ----------------------------------------------------------------

    # Maps MITRE ATT&CK technique IDs to kill-chain phase names
    _MITRE_PHASES = {
        "T1566": "Initial Access", "T1190": "Initial Access",
        "T1133": "Initial Access", "T1078": "Initial Access",
        "T1059": "Execution", "T1204": "Execution",
        "T1053": "Execution/Persistence", "T1047": "Execution",
        "T1547": "Persistence", "T1060": "Persistence",
        "T1112": "Persistence", "T1543": "Persistence",
        "T1036": "Defense Evasion", "T1070": "Defense Evasion",
        "T1027": "Defense Evasion", "T1140": "Defense Evasion",
        "T1003": "Credential Access", "T1110": "Credential Access",
        "T1555": "Credential Access",
        "T1046": "Discovery", "T1083": "Discovery", "T1082": "Discovery",
        "T1021": "Lateral Movement", "T1076": "Lateral Movement",
        "T1041": "Exfiltration", "T1048": "Exfiltration",
        "T1071": "Command & Control", "T1105": "Command & Control",
    }

    def _synthesize_attack_chain(self, report_json: dict,
                                  behavioral_flags: dict,
                                  correlated_users: dict,
                                  iocs: dict,
                                  step_evidence_anchors: Optional[List[dict]] = None) -> str:
        """Produce a holistic attack narrative using the LLM (or template fallback).

        This is the key interpretation layer — it takes all the evidence and
        produces a coherent 'what happened' story with MITRE ATT&CK mapping,
        attribution assessment, key evidence anchors, and specific recommended
        actions. Each claim in the narrative must be traceable to a specific
        artifact in step_evidence_anchors.
        """
        evil = report_json.get("evil_found", False)
        severity = report_json.get("severity", "INFO")
        devices = list(report_json.get("device_map", {}).keys())
        users = list(report_json.get("user_map", {}).keys()) if isinstance(
            report_json.get("user_map"), dict) else []

        # Collect all behavioral flags sorted by severity
        all_flags: List[dict] = []
        for dev_id, flags in behavioral_flags.items():
            for f in flags:
                fc = dict(f)
                fc["_device"] = dev_id
                all_flags.append(fc)
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        all_flags.sort(key=lambda f: sev_order.get(f.get("severity", "LOW"), 4))

        # Collect lateral movement indicators across all users
        lateral_indicators = []
        for udata in correlated_users.values():
            lateral_indicators.extend(udata.get("lateral_movement_indicators", []))

        # Indicator hit categories
        hit_categories = sorted(set(
            h.get("category", "") for h in report_json.get("indicator_hits", [])
            if h.get("category")))

        if self.call_llm:
            # Build a concise evidence summary for the prompt
            flags_text = ""
            for f in all_flags[:15]:
                flags_text += (
                    f"  [{f.get('severity')}] [{f.get('_device')}] "
                    f"{f.get('summary', '')} "
                    f"(MITRE: {', '.join(f.get('mitre_att_ck', []))})\n"
                )

            lateral_text = ""
            for li in lateral_indicators[:5]:
                lateral_text += (
                    f"  {li.get('timestamp','')} — {li.get('from_device','')} → "
                    f"{li.get('to_device','')} via {li.get('method','')}\n"
                )

            ioc_summary = ", ".join([
                f"{len(v)} {k.replace('_',' ')}"
                for k, v in iocs.items() if v
            ]) or "none extracted"

            # Build evidence anchor text — each item is traceable to a specific
            # artifact, tool, and observation from the execution pipeline.
            anchors = step_evidence_anchors or []
            anchor_text = ""
            for a in anchors[:20]:
                note = _safe_prompt_str(a.get("analyst_note") or "")
                tool = _safe_prompt_str(a.get("tool") or "", max_len=100)
                evidence_file = _safe_prompt_str(a.get("evidence_file") or "?", max_len=200)
                significance = _safe_prompt_str(a.get("significance") or "?", max_len=20)
                raw_indicators = a.get("threat_indicators") or []
                indicators = ", ".join(
                    _safe_prompt_str(i, max_len=100) for i in raw_indicators[:10]
                )
                anchor_text += (
                    f"  [{significance}] {tool} on {evidence_file}: {note}"
                    + (f" | indicators: {indicators}" if indicators else "")
                    + "\n"
                )

            prompt = f"""You are a senior DFIR analyst writing the interpretation section of a forensic report.

INVESTIGATION VERDICT: {'COMPROMISE CONFIRMED' if evil else 'NO CONFIRMED COMPROMISE'}
OVERALL SEVERITY: {severity}
DEVICES EXAMINED: {', '.join(devices) or 'unknown'}
USERS INVOLVED: {', '.join(users) or 'unknown'}
TRIAGE CATEGORIES HIT: {', '.join(hit_categories) or 'none'}
IOCs EXTRACTED: {ioc_summary}

TOP BEHAVIORAL FLAGS:
{flags_text or '  None detected.'}
LATERAL MOVEMENT:
{lateral_text or '  None detected.'}
VERIFIED EVIDENCE ANCHORS (tool → artifact → finding):
{anchor_text or '  No high-significance anchors available.'}

Write the following sections. ACCURACY RULES:
- Every factual claim in Attack Narrative and Key Evidence MUST cite a specific artifact from the VERIFIED EVIDENCE ANCHORS above (tool name + file name)
- Use format: "... (source: <tool> on <file>)" when citing an anchor
- Use "appears to", "likely", "consistent with" for inferences — never present inferences as facts
- Do NOT invent file names, timestamps, offsets, or tool outputs not present in the anchors or flags above
- If evidence is insufficient for a section, write "Insufficient evidence to assess" rather than speculating

## Attack Narrative
[3-5 paragraphs. Chronological account of what happened, citing specific evidence anchors. How did the attacker get in? What did they do? How was it detected?]

## MITRE ATT\u0026CK Techniques Observed
[Bullet list: Txxxx — Technique Name — specific supporting evidence anchor]

## Attribution Assessment
[Insider threat, external attacker, or undetermined? Confidence level and reasoning. Cite specific evidence.]

## Key Evidence
[5-8 bullet points: the most significant individual findings, each with: artifact path, tool used, and specific observation]

## Recommended Actions
[5-7 specific, prioritised containment and remediation steps for THIS investigation based on the evidence above]"""

            try:
                result = self._call_llm_with_retry(prompt, "", agent_type="manager")
                if result is not None:
                    return result
            except Exception:
                pass  # fall through to template

        # ---- Template fallback ----
        mitres_observed = (report_json.get("attack_chain", {}) or {}).get("mitre_techniques_observed", [])
        return self._template_attack_chain(
            evil, severity, all_flags, lateral_indicators,
            hit_categories, devices, users, mitres_observed=mitres_observed)

    def _template_attack_chain(self, evil: bool, severity: str,
                                all_flags: List[dict],
                                lateral_indicators: List[dict],
                                hit_categories: List[str],
                                devices: List[str],
                                users: List[str],
                                mitres_observed: list = None) -> str:
        """Template-based attack chain when LLM is unavailable."""
        lines = []

        # Narrative
        lines.append("## Attack Narrative\n")
        if not evil:
            lines.append(
                "No confirmed compromise was identified during this investigation. "
                "The evidence examined did not reveal definitive indicators of "
                "malicious activity, though the following anomalies were noted for "
                "awareness.")
        else:
            lines.append(
                f"This investigation identified indicators of compromise on "
                f"{len(devices)} device(s) involving {len(users)} user account(s). "
                f"Overall severity was assessed as **{severity}**.")
            if hit_categories:
                lines.append(
                    f"\nTriage scanning identified hits in the following categories: "
                    f"{', '.join(hit_categories)}.")
            if lateral_indicators:
                lines.append(
                    f"\nLateral movement was detected: "
                    f"{len(lateral_indicators)} cross-device event(s) observed.")

        # MITRE phases observed from behavioral flags AND attack_chain
        lines.append("\n## MITRE ATT&CK Techniques Observed\n")

        # First, try behavioral flags for technique mappings
        phase_map: Dict[str, List[str]] = {}
        for flag in all_flags:
            for tid in flag.get("mitre_att_ck", []):
                phase = self._MITRE_PHASES.get(tid.split('.')[0], "Other")
                phase_map.setdefault(phase, [])
                entry = f"[{tid}](https://attack.mitre.org/techniques/{tid}/) — {flag.get('summary', '')[:80]}"
                if entry not in phase_map[phase]:
                    phase_map[phase].append(entry)

        # If no techniques from flags, use attack_chain MITRE techniques
        if not phase_map:
            ac_mitres = mitres_observed if mitres_observed else []
            for tid in (ac_mitres or []):
                phase = self._MITRE_PHASES.get(tid.split('.')[0], "Other")
                phase_map.setdefault(phase, [])
                link = f"[{tid}](https://attack.mitre.org/techniques/{tid}/)"
                if link not in phase_map[phase]:
                    phase_map[phase].append(link)

        if phase_map:
            for phase in ["Initial Access", "Execution", "Persistence",
                          "Defense Evasion", "Credential Access", "Discovery",
                          "Lateral Movement", "Exfiltration",
                          "Command & Control", "Other",
                          "Execution/Persistence"]:
                if phase in phase_map:
                    lines.append(f"**{phase}:**")
                    for entry in phase_map[phase][:5]:
                        lines.append(f"- {entry}")
        else:
            lines.append("No MITRE ATT&CK techniques were identified by behavioral analysis. See the MITRE ATT&CK Matrix above for techniques identified from the attack chain analysis.")

        # Attribution
        lines.append("\n## Attribution Assessment\n")
        if lateral_indicators:
            lines.append(
                "Lateral movement between internal devices suggests a targeted "
                "intrusion rather than opportunistic malware. Confidence: **MEDIUM**.")
        elif any(f.get("severity") == "CRITICAL" for f in all_flags):
            lines.append(
                "CRITICAL severity findings indicate deliberate action. "
                "Attribution requires further investigation. Confidence: **LOW**.")
        else:
            lines.append(
                "Insufficient evidence to determine attribution. "
                "Manual review of flagged items is recommended.")

        # Key evidence
        lines.append("\n## Key Evidence\n")
        for flag in all_flags[:8]:
            lines.append(
                f"- **[{flag.get('severity')}]** [{flag.get('_device', '')}] "
                f"{flag.get('summary', '')}")

        # Recommended actions
        lines.append("\n## Recommended Actions\n")
        if evil:
            lines.append("1. Isolate affected device(s) from the network immediately")
            lines.append("2. Preserve all evidence — do not reboot or modify systems")
            lines.append("3. Reset credentials for all users active on affected devices")
            if lateral_indicators:
                lines.append("4. Audit all systems the compromised account(s) accessed")
            lines.append("5. Engage IR team for full forensic acquisition if not done")
            lines.append("6. Review and harden authentication (MFA, privileged access)")
            lines.append("7. File incident report with relevant compliance / legal teams")
        else:
            lines.append("1. Review all flagged behavioral anomalies manually")
            lines.append("2. Verify that flagged processes and file paths are legitimate")
            lines.append("3. Consider expanding evidence scope if anomalies are unexplained")
            lines.append("4. Ensure endpoint security tooling is current on all devices")

        return "\n".join(lines)

    # ----------------------------------------------------------------
    # Markdown rendering
    # ----------------------------------------------------------------

    def _render_mitre_matrix(self, mitres: list, kill_phases: list) -> str:
        """Generate a text-based MITRE ATT&CK matrix showing lit-up cells."""
        if not mitres and not kill_phases:
            return "No MITRE ATT&CK techniques were identified."

        tactic_order = [
            "Initial Access", "Execution", "Persistence", "Privilege Escalation",
            "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
            "Collection", "Exfiltration", "Command & Control"
        ]

        phase_map = {
            "initial_access": "Initial Access", "execution": "Execution",
            "persistence": "Persistence", "privilege_escalation": "Privilege Escalation",
            "defense_evasion": "Defense Evasion", "credential_access": "Credential Access",
            "credential_theft": "Credential Access", "discovery": "Discovery",
            "lateral_movement": "Lateral Movement", "collection": "Collection",
            "exfiltration": "Exfiltration", "command_and_control": "Command & Control",
            "c2": "Command & Control", "phishing": "Initial Access",
            "lolbin": "Execution", "web_shell": "Persistence", "cryptominer": "Command & Control",
        }

        active_tactics = set()
        for phase in kill_phases:
            mapped = phase_map.get(phase.lower(), None)
            if mapped:
                active_tactics.add(mapped)

        lines = []
        lines.append("| Tactic | Active | Techniques |")
        lines.append("|--------|--------|------------|")
        for tactic in tactic_order:
            active = tactic in active_tactics
            status = "YES" if active else "no"
            techniques_for_tactic = []
            for tid in mitres:
                phase = self._MITRE_PHASES.get(tid.split(".")[0], "Other")
                if phase == tactic or (phase == "Execution/Persistence" and tactic in ("Execution", "Persistence")):
                    techniques_for_tactic.append(f"[{tid}](https://attack.mitre.org/techniques/{tid}/)")

            tech_str = ", ".join(techniques_for_tactic) if techniques_for_tactic else "-"
            lines.append(f"| {tactic} | {status} | {tech_str} |")

        return "\n".join(lines)

    def _render_markdown(self, sections: dict,
                          report_json: dict) -> str:
        """Render all sections into a Markdown document."""
        title = report_json.get("title", "Forensic Investigation Report")
        generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")

            # Build classification from attack_chain
        ac = report_json.get("attack_chain", {})
        kill_phases = ac.get("kill_chain_phases", [])
        mitres = ac.get("mitre_techniques_observed", [])
        class_str = ", ".join(kp.replace("_", " ").title() for kp in kill_phases[:6]) if kill_phases else report_json.get("classification", "Unknown")

        md = f"""# {title}

**Generated:** {generated}
**Evidence Directory:** {report_json.get("evidence_dir", "N/A")}
**Analysis:** {report_json.get("steps_completed", 0)} steps completed, {report_json.get("steps_failed", 0)} failed, {report_json.get("steps_skipped", 0)} skipped
**Playbooks:** {report_json.get("playbooks_total", 0)} unique, {report_json.get("specialist_steps_executed", 0)} specialist steps

---

## Playbook Execution Summary

{self._render_playbook_summary(report_json)}

---
**Overall Severity:** {report_json.get("severity", "INFO")}
**Classification:** {class_str}
**MITRE Techniques Observed:** {", ".join(mitres[:20]) if mitres else "None"}
**Evil Found:** {"YES" if report_json.get("evil_found") else "NO"}

---

## MITRE ATT&CK Matrix

{self._render_mitre_matrix(mitres, kill_phases)}

---

## Executive Summary

{sections.get('executive_summary', 'No summary generated.')}

---

## Devices & Users

{sections.get('devices_and_users', 'No devices identified.')}

---

## User Activity Narratives

"""
        for username, narrative in sections.get('user_narratives', {}).items():
            md += f"### {username}\n\n{narrative}\n\n"

        md += f"""---

## Significant Events Timeline

{sections.get('significant_events', 'No significant events.')}

---

## Findings

{sections.get('findings', 'No findings.')}

---

## Failed Steps

{sections.get("failed_steps", "No failed steps data.")}

---

## Indicators of Compromise

{self._render_ioc_table(sections.get('iocs', {}))}

---

## Investigation Synthesis

{sections.get('attack_chain', 'No synthesis generated.')}

---

## Conclusion & Recommendations

{sections.get('conclusion', 'No conclusion generated.')}

---

*Report generated by G.E.O.F.F. (Git-backed Evidence Operations Forensic Framework)*
*This report summarises automated analysis. All findings should be verified by a qualified examiner.*
"""

        return md

    def _render_failed_steps(self, report_json: dict) -> str:
        """Render failed steps with explanations."""
        failures = report_json.get("failures", [])
        if not failures:
            return "No steps failed during this investigation."

        lines = []
        lines.append(f"| # | Playbook | Module | Function | Reason |")
        lines.append(f"|---|----------|--------|----------|--------|")
        for i, f_info in enumerate(failures[:50], 1):
            pb = f_info.get("playbook", "?")
            module = f_info.get("module", "?")
            func = f_info.get("function", "?")
            error = f_info.get("result", {}).get("error", "")
            stderr = f_info.get("result", {}).get("stderr", "")
            status = f_info.get("status", "")
            if error:
                reason = error[:100]
            elif stderr:
                reason = stderr[:100]
            elif status == "skipped":
                reason = "Skipped (tool not available or dependency missing)"
            elif status == "failed":
                reason = "Failed (tool execution error or invalid parameters)"
            else:
                reason = f"Status: {status}"
            reason = str(reason).replace("|", "/").replace("\n", " ")
            lines.append(f"| {i} | {pb} | {module} | {func} | {reason} |")

        if len(failures) > 50:
            lines.append(f"| | | | | *(+{len(failures)-50} more)* |")

        return "\n".join(lines)

    def _render_ioc_table(self, iocs: dict) -> str:
        """Render extracted IOCs as markdown tables grouped by type."""
        if not iocs:
            return "No indicators of compromise were extracted from this investigation."

        labels = {
            "ip_addresses":    "IP Addresses",
            "file_hashes":     "File Hashes",
            "urls":            "URLs",
            "registry_keys":   "Registry Keys",
            "file_paths":      "File Paths",
            "email_addresses": "Email Addresses",
        }
        lines = []
        for key, label in labels.items():
            values = iocs.get(key, [])
            if not values:
                continue
            lines.append(f"**{label}** ({len(values)})\n")
            lines.append("| Value |")
            lines.append("|-------|")
            for v in values[:50]:  # cap at 50 per category
                lines.append(f"| `{v}` |")
            if len(values) > 50:
                lines.append(f"| *(+{len(values)-50} more — see findings_jsonl)* |")
            lines.append("")
        return "\n".join(lines) if lines else \
            "No indicators of compromise were extracted."
