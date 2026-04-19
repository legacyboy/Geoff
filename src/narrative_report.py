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

    Strips newlines (prevent prompt structure breaks) and truncates to avoid
    context bloat.  Returns a plain string safe for f-string interpolation.
    """
    s = str(value) if value is not None else ""
    s = s.replace("\n", " ").replace("\r", " ")
    return s[:max_len]


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

        # 6. IOC Extraction
        iocs = self._extract_iocs(report_json, behavioral_flags)
        sections["iocs"] = iocs

        # 7. Attack Chain Synthesis (the interpretation layer)
        sections["attack_chain"] = self._synthesize_attack_chain(
            report_json, behavioral_flags, correlated_users, iocs,
            step_evidence_anchors=step_evidence_anchors or [])

        # 8. Conclusion & Recommendations
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
                prompt += f"- [{_safe_prompt_str(flag.get('severity'), 20)}] {_safe_prompt_str(flag.get('summary'))}\n"

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
                        prompt += f"- {_safe_prompt_str(flag.get('summary'))}\n"

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
                note = a.get("analyst_note") or ""
                indicators = ", ".join(a.get("threat_indicators") or [])
                anchor_text += (
                    f"  [{a.get('significance','?')}] {a.get('tool','')} "
                    f"on {a.get('evidence_file','?')}: {note}"
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
                return self.call_llm(prompt, "", agent_type="manager")
            except Exception:
                pass  # fall through to template

        # ---- Template fallback ----
        return self._template_attack_chain(
            evil, severity, all_flags, lateral_indicators,
            hit_categories, devices, users)

    def _template_attack_chain(self, evil: bool, severity: str,
                                all_flags: List[dict],
                                lateral_indicators: List[dict],
                                hit_categories: List[str],
                                devices: List[str],
                                users: List[str]) -> str:
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

        # MITRE phases observed from flag technique tags
        lines.append("\n## MITRE ATT&CK Techniques Observed\n")
        phase_map: Dict[str, List[str]] = {}
        for flag in all_flags:
            for tid in flag.get("mitre_att_ck", []):
                # Strip sub-technique suffix for phase lookup
                phase = self._MITRE_PHASES.get(tid.split('.')[0], "Other")
                phase_map.setdefault(phase, [])
                entry = f"{tid} — {flag.get('summary', '')[:80]}"
                if entry not in phase_map[phase]:
                    phase_map[phase].append(entry)
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
            lines.append("No MITRE ATT&CK techniques mapped from behavioral flags.")

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
