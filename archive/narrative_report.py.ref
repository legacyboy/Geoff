#!/usr/bin/env python3
"""
Narrative Report Generator — Converts JSON findings into human-readable reports.

Uses LLM to generate natural language summaries, with a template-based
fallback if the LLM is unavailable.
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Callable, Optional


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

    def generate(self, report_json: dict, device_map: dict,
                 user_map: dict, super_timeline_path: str,
                 correlated_users: dict, behavioral_flags: dict,
                 case_work_dir: Path) -> Path:
        """
        Generate the full narrative report.

        Returns:
            Path to narrative_report.md
        """
        case_work_dir = Path(case_work_dir)
        report_dir = case_work_dir / "reports"
        report_dir.mkdir(parents=True, exist_ok=True)

        md_path = report_dir / "narrative_report.md"
        json_path = report_dir / "narrative_report.json"

        sections = {}

        # 1. Executive Summary
        sections["executive_summary"] = self._generate_executive_summary(
            report_json, device_map, user_map, behavioral_flags)

        # 2. Devices & Users Overview
        sections["devices_and_users"] = self._generate_devices_overview(
            device_map, user_map)

        # 3. Per-User Narratives
        sections["user_narratives"] = {}
        users = user_map.get("users", user_map)
        for username, udata in users.items():
            if isinstance(udata, dict):
                sections["user_narratives"][username] = \
                    self._generate_user_narrative(
                        username, udata, correlated_users.get(username, {}),
                        device_map, behavioral_flags)

        # 4. Timeline of Significant Events
        sections["significant_events"] = \
            self._generate_significant_timeline(
                super_timeline_path, behavioral_flags)

        # 5. Behavioral Findings
        sections["findings"] = self._generate_findings_section(
            behavioral_flags, report_json)

        # 6. Conclusion & Recommendations
        sections["conclusion"] = self._generate_conclusion(
            report_json, behavioral_flags, correlated_users)

        # Write markdown report
        md_content = self._render_markdown(sections, report_json)
        with open(md_path, "w") as f:
            f.write(md_content)

        # Write structured JSON version
        with open(json_path, "w") as f:
            json.dump(sections, f, indent=2, default=str)

        return md_path

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
                prompt += f"- [{flag.get('severity')}] {flag.get('summary')}\n"

            prompt += (
                f"\nWrite a factual executive summary. Do not speculate "
                f"beyond what the evidence shows. Use professional tone "
                f"suitable for legal documentation."
            )

            try:
                return self.call_llm(prompt, "", agent_type="manager")
            except Exception:
                pass  # Fall through to template

        # Template fallback
        return self._template_executive_summary(context, behavioral_flags)

    def _template_executive_summary(self, context: dict,
                                     behavioral_flags: dict) -> str:
        """Template-based executive summary when LLM is unavailable."""
        evil = "Indicators of compromise were identified" if \
            context["evil_found"] else \
            "No confirmed indicators of compromise were found"

        summary = (
            f"This investigation analyzed evidence from "
            f"{context['num_devices']} device(s) involving "
            f"{context['num_users']} user account(s). "
            f"Device types examined: {', '.join(context['device_types'])}. "
            f"The investigation completed {context['steps_completed']} "
            f"analysis steps in {context['elapsed_minutes']} minutes"
        )

        if context["steps_failed"]:
            summary += f" ({context['steps_failed']} steps failed)"
        summary += ".\n\n"

        summary += (
            f"{evil}. Overall severity assessment: "
            f"{context['overall_severity']}. "
            f"Behavioral analysis identified {context['total_behavioral_flags']}"
            f" anomalies, of which {context['high_severity_flags']} were "
            f"rated HIGH or CRITICAL severity."
        )

        if context["high_severity_flags"] > 0:
            summary += "\n\nKey findings requiring immediate attention:\n"
            all_flags = []
            for flags in behavioral_flags.values():
                all_flags.extend(flags)
            all_flags.sort(
                key=lambda f: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2,
                               "LOW": 3}.get(f.get("severity", "LOW"), 4))
            for flag in all_flags[:5]:
                if flag.get("severity") in ("CRITICAL", "HIGH"):
                    summary += f"- {flag.get('summary', 'Unknown flag')}\n"

        return summary

    def _generate_devices_overview(self, device_map: dict,
                                    user_map: dict) -> str:
        """Generate devices and users overview section."""
        lines = []
        for dev_id, dev in device_map.items():
            owner = dev.get("owner", "unattributed")
            lines.append(
                f"- **{dev_id}** ({dev.get('device_type', 'unknown')}): "
                f"{dev.get('os_type', 'unknown')}, "
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
                        f"- [{flag.get('severity')}] "
                        f"{flag.get('summary')}\n")

            prompt += (
                f"\nWrite a factual narrative. State only what the evidence "
                f"shows. Example good output: '{username} typically logs in "
                f"between 8:30-9:00 AM. Browser history shows regular "
                f"visits to office365.com. No suspicious process execution "
                f"was detected on the workstation.'"
            )

            try:
                return self.call_llm(prompt, "", agent_type="manager")
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
        """Generate findings grouped by severity."""
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
            lines.append(f"\n### {severity} ({len(flags)})")
            for flag in flags[:20]:
                lines.append(
                    f"- **{flag.get('flag_type', '')}** "
                    f"[{flag.get('device_id', '')}]: "
                    f"{flag.get('summary', '')}")
                if flag.get("explanation"):
                    lines.append(
                        f"  *{flag['explanation'][:200]}*")

        if not any(by_severity.values()):
            lines.append(
                "No behavioral anomalies were detected across any device.")

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
                        prompt += f"- {flag.get('summary')}\n"

            prompt += (
                f"\nBe specific and actionable. Example: "
                f"'Isolate DESKTOP-ABC from the network', "
                f"'Reset credentials for user dsmith'."
            )

            try:
                return self.call_llm(prompt, "", agent_type="manager")
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
    # Markdown rendering
    # ----------------------------------------------------------------

    def _render_markdown(self, sections: dict,
                          report_json: dict) -> str:
        """Render all sections into a Markdown document."""
        title = report_json.get("title", "Forensic Investigation Report")
        generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")

        md = f"""# {title}

**Generated:** {generated}
**Evidence Directory:** {report_json.get('evidence_dir', 'N/A')}
**Overall Severity:** {report_json.get('severity', 'INFO')}
**Evil Found:** {'YES' if report_json.get('evil_found') else 'NO'}

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

## Conclusion & Recommendations

{sections.get('conclusion', 'No conclusion generated.')}

---

*Report generated by G.E.O.F.F. (Git-backed Evidence Operations Forensic Framework)*
*This report summarizes automated analysis. All findings should be verified by a qualified examiner.*
"""

        return md
