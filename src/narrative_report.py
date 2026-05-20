#!/usr/bin/env python3
"""
Narrative Report Generator — Converts JSON findings into human-readable reports.

Uses LLM to generate natural language summaries, with a template-based
fallback if the LLM is unavailable.
"""

import ipaddress
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


# Keywords that indicate forensic acquisition metadata bleed-through.
# When found inside a purported file path, the "path" is spurious.
_FORENSIC_METADATA_KEYWORDS = [
    'Image Verification',
    'Acquisition started',
    'Acquisition finished',
    '[Device Info]',
    'Source Type',
    'Drive Geometry',
    'Cylinders:',
    'Tracks per Cylinder',
    'Sectors per Track',
    'Physical Evidentiary',
    'MD5 checksum',
    'SHA1 checksum',
    'SHA256 checksum',
    'Image Information:',
]


def _is_valid_file_path(path: str) -> bool:
    """Reject paths that are garbage (acquisition metadata, command args, temp artifacts)."""
    if len(path) < 3:
        return False
    # Reject paths containing non-printable ASCII control chars (0x00-0x1F, 0x7F) or non-ASCII bytes
    for ch in path:
        code = ord(ch)
        if code <= 0x1F or code == 0x7F or code > 0x7E:
            return False
    # Known short system directories that are legitimate
    _KNOWN_SHORT_DIRS = {
        'program files', 'windows', 'system32', 'users', 'documents and settings',
        'temp', 'programdata', 'program files (x86)', 'syswow64', 'system',
        'config', 'drivers', 'etc', 'bin', 'lib', 'usr', 'var', 'opt', 'sbin',
        'inetpub', 'perflogs', 'recovery', '$recycle.bin',
        'system volume information', 'boot', 'sources', 'python310', 'python311',
        'python312', 'python313', 'node_modules',
    }
    # Reject paths where directory component names are 1-2 chars (random binary noise)
    # unless they're known short system directories
    sep_positions = [i for i, ch in enumerate(path) if ch == '\\']
    prev = 0
    for sep in sep_positions:
        seg = path[prev:sep]
        # Skip empty segments and drive letters (e.g. "C:")
        if seg and ':' not in seg and len(seg) <= 2 and seg.lower() not in _KNOWN_SHORT_DIRS:
            return False
        prev = sep + 1
    # Check the last segment too (after final backslash)
    last_seg = path[prev:] if prev < len(path) else ''
    if last_seg and ':' not in last_seg and len(last_seg) <= 2 and last_seg.lower() not in _KNOWN_SHORT_DIRS:
        return False
    for kw in _FORENSIC_METADATA_KEYWORDS:
        if kw in path:
            return False
    # Reject paths shorter than 15 chars (too generic, e.g. D:\jsonOutput)
    if len(path) < 15:
        return False
    # Reject paths where the last component has spaces AND non-alphanumeric chars
    # This catches things like c:\temp --xml c (space + --xml c)
    parts = path.split('\\')
    last = parts[-1] if parts else ''
    if ' ' in last and not all(c.isalnum() or c in ' ._-' for c in last):
        return False
    # Reject paths that look like command arguments
    cmd_args = (' --', ' -o ', ' -f ', ' -out ', ' -input ', ' -output ', ' -xml ')
    for arg in cmd_args:
        if arg in path:
            return False
    # Reject paths where the ONLY folder is temp/tmp (not meaningful IOCs)
    folders = [p for p in parts[:-1] if p]
    if len(folders) == 1 and folders[0].lower() in ('temp', 'tmp'):
        return False
    # Reject .lnk paths in C:\Temp\ or C:\Users\*\AppData\Local\Temp
    if path.lower().endswith('.lnk'):
        pl = path.lower()
        if pl.startswith('c:\\temp\\') or '\\appdata\\local\\temp' in pl:
            return False
    return True


# Known valid email TLDs — rejects word-like pseudo-TLDs (cnn, msn, aol etc.)
_VALID_EMAIL_TLDS = {
    'com', 'org', 'net', 'edu', 'gov', 'mil', 'int',
    # 2-letter country code TLDs
    'us', 'uk', 'de', 'jp', 'fr', 'au', 'ca', 'it', 'es', 'nl', 'ru', 'br', 'cn',
    'in', 'io', 'tv', 'me', 'co', 'cc', 'eu', 'ch', 'se', 'no', 'dk', 'fi', 'be',
    'at', 'pl', 'cz', 'hu', 'gr', 'pt', 'ro', 'bg', 'hr', 'sk', 'si', 'lt', 'lv',
    'ee', 'is', 'lu', 'mt', 'cy', 'mx', 'ar', 'cl', 'pe', 'za', 'eg', 'ng', 'ke',
    'ma', 'tn', 'dz', 'ae', 'sa', 'qa', 'om', 'kw', 'bh', 'jo', 'lb', 'ir', 'pk',
    'bd', 'lk', 'np', 'th', 'vn', 'my', 'sg', 'ph', 'id', 'kr', 'tw', 'hk',
    'nz', 'ie', 'il', 'tr', 'ua', 'hr', 'ba', 'rs', 'me', 'mk', 'al', 'by', 'kz',
    'uz', 'tm', 'az', 'ge', 'am',
    # Valid 3-letter non-word gTLDs
    'biz', 'pro', 'info', 'name', 'mobi', 'tel', 'asia', 'cat', 'jobs', 'aero',
}

_SYSTEM_EMAIL_LOCALPARTS = frozenset({
    'mailer-daemon', 'postmaster', 'root',
    'administrator', 'noreply', 'no-reply',
})


def _extract_email(raw: str) -> Optional[str]:
    """Extract clean email from a raw address, handling 'Display Name <email>' format."""
    if not raw or not isinstance(raw, str):
        return None
    raw = raw.strip()
    # Handle "Display Name <email>" format — capture anything inside <...>
    m = re.search(r'<([^>]+)>', raw)
    if m:
        return m.group(1).strip()
    return raw


def _is_valid_email(email: str) -> bool:
    """Check if an email address has a valid TLD and isn't a system/routing address."""
    if not email or not isinstance(email, str):
        return False
    email = email.lower().strip()
    parts = email.split('@')
    if len(parts) != 2:
        return False
    local, domain = parts
    # Reject system/routing addresses
    if local in _SYSTEM_EMAIL_LOCALPARTS:
        return False
    # Must have at least domain.tld (2+ domain parts)
    dom_parts = domain.split('.')
    if len(dom_parts) < 2:
        return False
    tld = dom_parts[-1]
    # For 2-3 char TLDs: must be in known list (rejects .cnn, .msn, .aol etc.)
    if len(tld) <= 3 and tld not in _VALID_EMAIL_TLDS:
        return False
    # Reject single-char domain component before TLD (like c.msn)
    if len(dom_parts) == 2 and len(dom_parts[0]) == 1:
        return False
    return True


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

    # Registry keys that are never IOCs — Windows system/environment paths
    _KNOWN_GOOD_REGISTRY_PREFIXES = frozenset({
        'HKLM\\HARDWARE\\DESCRIPTION',
        'HKLM\\SAM\\SAM',
        'HKLM\\SECURITY\\Policy',
        'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList',
        'HKCU\\Control Panel',
        'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer',
        'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Network',
        'HKLM\\SYSTEM\\MountedDevices',
        'HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters',
        'HKLM\\SYSTEM\\CurrentControlSet\\Services\\NlaSvc\\Parameters',
        'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Class',
        'HKLM\\SYSTEM\\CurrentControlSet\\Enum',
        'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Setup',
        'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Installer',
        'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall',
        'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths',
        'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Search',
        'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
        'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
        'HKCU\\Software\\Microsoft\\Internet Explorer',
        'HKLM\\SOFTWARE\\Microsoft\\Internet Explorer',
        'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing',
        'HKCU\\Software\\Microsoft\\Office',
        'HKLM\\SOFTWARE\\Microsoft\\Office',
        'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList',
        'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon',
        'HKLM\\SYSTEM\\CurrentControlSet\\Services\\W32Time',
        'HKLM\\SYSTEM\\CurrentControlSet\\Services\\Dnscache',
        'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Notifications',
        'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication',
        'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies',
        'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies',
        'HKCU\\Software\\Policies',
        'HKLM\\SOFTWARE\\Policies',
        'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager',
        'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Safety Options',
        'HKLM\\BcdObject\\Description',
        'HKLM\\SYSTEM\\Setup',
        'HKLM\\COMPONENTS\\DerivedData\\VersionedIndex',
        'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\SideBySide',
        'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\ThemeManager',
        'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ThemeManager',
        'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Group Policy',
        'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Group Policy',
        'HKLM\\SYSTEM\\Select',
        'HKLM\\SOFTWARE\\JavaSoft',
        'HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall',
        'HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess',
        'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager',
    })

    @staticmethod
    def _get_registry_depth(key: str) -> int:
        """Count depth of a registry key path (number of path components after hive)."""
        # Normalise to backslash
        norm = key.replace('/', '\\')
        parts = [p for p in norm.split('\\') if p]
        # Subtract 1 for the hive (HKLM/HKCU/HKEY_*) component
        return max(0, len(parts) - 1)

    # Known CDN / cloud-infrastructure IP ranges — never IOCs
    _KNOWN_CDN_PREFIXES = [
        # Microsoft Azure
        ipaddress.IPv4Network('13.64.0.0/11'),
        ipaddress.IPv4Network('13.96.0.0/13'),
        ipaddress.IPv4Network('13.104.0.0/14'),
        ipaddress.IPv4Network('40.64.0.0/10'),
        ipaddress.IPv4Network('40.80.0.0/12'),
        ipaddress.IPv4Network('40.112.0.0/13'),
        ipaddress.IPv4Network('52.0.0.0/10'),
        ipaddress.IPv4Network('104.0.0.0/10'),
        ipaddress.IPv4Network('104.40.0.0/13'),
        # Microsoft 365 / Office 365
        ipaddress.IPv4Network('13.107.6.0/24'),
        ipaddress.IPv4Network('13.107.18.0/24'),
        ipaddress.IPv4Network('13.107.128.0/22'),
        ipaddress.IPv4Network('52.96.0.0/14'),
        ipaddress.IPv4Network('52.112.0.0/14'),
        ipaddress.IPv4Network('52.120.0.0/14'),
        # Cloudflare
        ipaddress.IPv4Network('103.21.244.0/22'),
        ipaddress.IPv4Network('103.22.200.0/22'),
        ipaddress.IPv4Network('103.31.4.0/22'),
        ipaddress.IPv4Network('104.16.0.0/13'),
        ipaddress.IPv4Network('104.24.0.0/14'),
        ipaddress.IPv4Network('108.162.192.0/18'),
        ipaddress.IPv4Network('131.0.72.0/22'),
        ipaddress.IPv4Network('141.101.64.0/18'),
        ipaddress.IPv4Network('162.158.0.0/15'),
        ipaddress.IPv4Network('172.64.0.0/13'),
        ipaddress.IPv4Network('173.245.48.0/20'),
        ipaddress.IPv4Network('188.114.96.0/20'),
        ipaddress.IPv4Network('190.93.240.0/20'),
        ipaddress.IPv4Network('197.234.240.0/22'),
        ipaddress.IPv4Network('198.41.128.0/17'),
        # Akamai
        ipaddress.IPv4Network('2.16.0.0/13'),
        ipaddress.IPv4Network('23.0.0.0/12'),
        ipaddress.IPv4Network('23.32.0.0/11'),
        ipaddress.IPv4Network('23.64.0.0/14'),
        ipaddress.IPv4Network('23.72.0.0/13'),
        ipaddress.IPv4Network('23.192.0.0/11'),
        ipaddress.IPv4Network('63.241.192.0/19'),
        ipaddress.IPv4Network('64.63.64.0/18'),
        ipaddress.IPv4Network('69.24.0.0/15'),
        ipaddress.IPv4Network('72.246.0.0/15'),
        ipaddress.IPv4Network('80.67.64.0/20'),
        ipaddress.IPv4Network('92.122.0.0/15'),
        ipaddress.IPv4Network('95.100.0.0/15'),
        ipaddress.IPv4Network('96.6.0.0/15'),
        ipaddress.IPv4Network('173.222.0.0/15'),
        ipaddress.IPv4Network('184.24.0.0/13'),
        ipaddress.IPv4Network('184.50.0.0/15'),
        ipaddress.IPv4Network('184.84.0.0/14'),
        ipaddress.IPv4Network('193.108.88.0/22'),
        ipaddress.IPv4Network('204.74.96.0/19'),
        # Google Cloud / Google infrastructure
        ipaddress.IPv4Network('8.8.8.0/24'),
        ipaddress.IPv4Network('8.8.4.0/24'),
        ipaddress.IPv4Network('34.0.0.0/15'),
        ipaddress.IPv4Network('34.32.0.0/11'),
        ipaddress.IPv4Network('34.64.0.0/10'),
        ipaddress.IPv4Network('34.128.0.0/10'),
        ipaddress.IPv4Network('35.184.0.0/13'),
        ipaddress.IPv4Network('35.192.0.0/14'),
        ipaddress.IPv4Network('35.196.0.0/15'),
        ipaddress.IPv4Network('35.200.0.0/13'),
        ipaddress.IPv4Network('35.208.0.0/12'),
        ipaddress.IPv4Network('35.224.0.0/12'),
        ipaddress.IPv4Network('35.240.0.0/13'),
        # AWS (CloudFront + general)
        ipaddress.IPv4Network('13.32.0.0/15'),
        ipaddress.IPv4Network('13.248.0.0/14'),
        ipaddress.IPv4Network('15.0.0.0/9'),
        ipaddress.IPv4Network('18.0.0.0/8'),
        ipaddress.IPv4Network('35.71.96.0/20'),
        ipaddress.IPv4Network('52.46.0.0/18'),
        ipaddress.IPv4Network('52.82.0.0/15'),
        ipaddress.IPv4Network('52.84.0.0/15'),
        ipaddress.IPv4Network('52.222.128.0/17'),
        ipaddress.IPv4Network('54.192.0.0/10'),
        ipaddress.IPv4Network('54.230.0.0/15'),
        ipaddress.IPv4Network('54.239.128.0/18'),
        ipaddress.IPv4Network('54.240.128.0/18'),
        ipaddress.IPv4Network('99.84.0.0/16'),
        ipaddress.IPv4Network('99.86.0.0/15'),
        ipaddress.IPv4Network('108.156.0.0/14'),
        ipaddress.IPv4Network('143.204.0.0/16'),
        ipaddress.IPv4Network('144.220.0.0/16'),
        ipaddress.IPv4Network('150.222.0.0/15'),
        ipaddress.IPv4Network('176.32.0.0/12'),
        ipaddress.IPv4Network('204.246.164.0/22'),
        ipaddress.IPv4Network('205.251.192.0/19'),
        ipaddress.IPv4Network('216.137.32.0/19'),
    ]

    @classmethod
    def _is_in_cdn_range(cls, ip_str: str) -> bool:
        """Check if an IP address falls within any known CDN/cloud-infrastructure range."""
        try:
            addr = ipaddress.IPv4Address(ip_str)
            for net in cls._KNOWN_CDN_PREFIXES:
                if addr in net:
                    return True
        except ipaddress.AddressValueError:
            pass
        return False

    def _call_llm_with_retry(self, prompt: str, context: str = "", agent_type: str = "manager",
                              max_retries: int = 3, backoff: list = None) -> Optional[str]:
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

        # 5d. Email & Phishing Analysis
        sections["email_phishing"] = self._render_email_phishing_section(report_json)

        # 6. IOC Extraction
        iocs = self._extract_iocs(report_json, behavioral_flags)
        sections["iocs"] = iocs

        # 7. Attack Chain Synthesis (the interpretation layer)
        sections["attack_chain"] = self._synthesize_attack_chain(
            report_json, behavioral_flags, correlated_users, iocs,
            step_evidence_anchors=step_evidence_anchors or [])
        if sections["attack_chain"] and self._is_template_fallback(sections["attack_chain"]):
            needs_review_sections.append("attack_chain")

        # 8. Kill Chain & Timeline Reconstruction
        sections["kill_chain_timeline"] = self._generate_kill_chain_timeline(
            report_json, behavioral_flags)
        if sections["kill_chain_timeline"] and self._is_template_fallback(sections["kill_chain_timeline"]):
            needs_review_sections.append("kill_chain_timeline")

        # 9. Blast Radius & Business Impact Mapping
        sections["blast_radius"] = self._generate_blast_radius(
            report_json, device_map, user_map)

        # 10. Evidence Confidence & Gaps
        sections["evidence_confidence"] = self._generate_evidence_confidence(
            report_json, behavioral_flags)

        # 11. Dwell Time & Lateral Movement
        sections["dwell_time"] = self._generate_dwell_time(report_json)

        # 11b. Unprocessed Evidence Files
        sections["unprocessed_files"] = self._render_unprocessed_section(report_json)

        # 12. Conclusion & Recommendations
        sections["conclusion"] = self._generate_conclusion(
            report_json, behavioral_flags, correlated_users)
        if sections["conclusion"] and self._is_template_fallback(sections["conclusion"]):
            needs_review_sections.append("conclusion")

        # 12b. Full Written Report (court-ready narrative)
        sections["full_written_report"] = self._render_full_written_report(
            report_json, device_map, user_map, behavioral_flags,
            sections.get('iocs', {}), correlated_users, step_evidence_anchors)

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
            # Email / phishing findings from direct extraction
            "email_direct_findings": [
                f for f in report_json.get("findings_detail", [])
                if f.get("playbook") == "EMAIL_DIRECT"
            ],
            # Collect email_iocs from findings_detail for executive summary
            "email_iocs": report_json.get("email_iocs", {}),
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
                f"**The investigation identified evidence of malicious activity with "
                f"{severity} severity classification.** Multiple indicators were "
                f"identified across the examined evidence."
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
                    "**Phishing activity confirmed** — suspicious emails were identified "
                    "through direct email extraction from disk images (T1566). See "
                    "Email Findings section for details."
                )
            elif context.get("email_direct_findings"):
                # Direct email extraction found phishing emails even if classification
                # metadata didn't explicitly flag "phishing"
                phish_count = sum(
                    1 for f in context["email_direct_findings"]
                    if f.get("result", {}).get("is_phishing") is True
                )
                if phish_count > 0:
                    narrative_parts.append(
                        f"**Phishing activity detected** — {phish_count} suspicious "
                        f"email(s) identified through direct email extraction from "
                        f"disk images (T1566). See Email Findings section for details."
                    )
            if "credential_theft" in all_cats or "credential_access" in all_cats:
                # Gather concrete flag summaries for this category
                cred_flags = []
                for dev_id, flags in behavioral_flags.items():
                    for f in flags:
                        ft = f.get("flag_type", "")
                        if ft in ("credential_theft", "credential_access"):
                            cred_flags.append((dev_id, f))
                if cred_flags:
                    dev_names = sorted(set(d for d, _ in cred_flags))
                    top_summary = cred_flags[0][1].get("summary", "Credential theft indicators")
                    narrative_parts.append(
                        f"**Credential theft** detected on {len(dev_names)} device(s) "
                        f"({', '.join(dev_names[:3])}) — {top_summary}"
                    )
                else:
                    narrative_parts.append(
                        "**Credential theft** activity was flagged (T1003) — see detailed findings."
                    )
            if "persistence" in all_cats:
                pers_flags = []
                for dev_id, flags in behavioral_flags.items():
                    for f in flags:
                        if f.get("flag_type") == "persistence":
                            pers_flags.append((dev_id, f))
                if pers_flags:
                    dev_names = sorted(set(d for d, _ in pers_flags))
                    top_summary = pers_flags[0][1].get("summary", "Persistence mechanisms")
                    narrative_parts.append(
                        f"**Persistence mechanisms** established on {len(dev_names)} device(s) "
                        f"({', '.join(dev_names[:3])}) — {top_summary}"
                    )
                else:
                    narrative_parts.append(
                        "**Persistence** activity was flagged (T1053) — see detailed findings."
                    )
            if "lateral_movement" in all_cats:
                lat_flags = []
                for dev_id, flags in behavioral_flags.items():
                    for f in flags:
                        if f.get("flag_type") == "lateral_movement":
                            lat_flags.append((dev_id, f))
                if lat_flags:
                    dev_names = sorted(set(d for d, _ in lat_flags))
                    top_summary = lat_flags[0][1].get("summary", "Lateral movement indicators")
                    narrative_parts.append(
                        f"**Lateral movement** detected across {len(dev_names)} device(s) "
                        f"({', '.join(dev_names[:3])}) — {top_summary}"
                    )
                else:
                    narrative_parts.append(
                        "**Lateral movement** was flagged — see detailed findings."
                    )
            if "cryptominer" in all_cats:
                crypto_flags = []
                for dev_id, flags in behavioral_flags.items():
                    for f in flags:
                        if f.get("flag_type") == "cryptominer":
                            crypto_flags.append((dev_id, f))
                if crypto_flags:
                    dev_names = sorted(set(d for d, _ in crypto_flags))
                    top_summary = crypto_flags[0][1].get("summary", "Cryptomining indicators")
                    narrative_parts.append(
                        f"**Cryptocurrency mining** activity detected on {len(dev_names)} device(s) "
                        f"({', '.join(dev_names[:3])}) — {top_summary}"
                    )
                else:
                    narrative_parts.append(
                        "**Cryptocurrency mining** activity was flagged (T1496) — see detailed findings."
                    )
            if "exfiltration" in all_cats:
                exfil_flags = []
                for dev_id, flags in behavioral_flags.items():
                    for f in flags:
                        if f.get("flag_type") == "exfiltration":
                            exfil_flags.append((dev_id, f))
                if exfil_flags:
                    dev_names = sorted(set(d for d, _ in exfil_flags))
                    top_summary = exfil_flags[0][1].get("summary", "Data exfiltration indicators")
                    narrative_parts.append(
                        f"**Data exfiltration** detected from {len(dev_names)} device(s) "
                        f"({', '.join(dev_names[:3])}) — {top_summary}"
                    )
                else:
                    narrative_parts.append(
                        "**Data exfiltration** activity was flagged (T1048) — see detailed findings."
                    )
            if "c2" in all_cats or "command_and_control" in all_cats:
                c2_flags = []
                for dev_id, flags in behavioral_flags.items():
                    for f in flags:
                        ft = f.get("flag_type", "")
                        if ft in ("c2", "c2_traffic", "command_and_control"):
                            c2_flags.append((dev_id, f))
                if c2_flags:
                    dev_names = sorted(set(d for d, _ in c2_flags))
                    top_summary = c2_flags[0][1].get("summary", "C2 communications")
                    narrative_parts.append(
                        f"**Command & Control** communications detected on {len(dev_names)} device(s) "
                        f"({', '.join(dev_names[:3])}) — {top_summary}"
                    )
                else:
                    narrative_parts.append(
                        "**Command & Control** (C2) communications were flagged — see detailed findings."
                    )
            if "web_shell" in all_cats:
                ws_flags = []
                for dev_id, flags in behavioral_flags.items():
                    for f in flags:
                        if f.get("flag_type") == "web_shell":
                            ws_flags.append((dev_id, f))
                if ws_flags:
                    dev_names = sorted(set(d for d, _ in ws_flags))
                    top_summary = ws_flags[0][1].get("summary", "Web shell indicators")
                    narrative_parts.append(
                        f"**Web shell** detected on {len(dev_names)} device(s) "
                        f"({', '.join(dev_names[:3])}) — {top_summary}"
                    )
                else:
                    narrative_parts.append(
                        "**Web shell** activity was flagged — see detailed findings."
                    )
            if "lolbin" in all_cats:
                lolbin_flags = []
                for dev_id, flags in behavioral_flags.items():
                    for f in flags:
                        if f.get("flag_type") == "lolbin":
                            lolbin_flags.append((dev_id, f))
                if lolbin_flags:
                    dev_names = sorted(set(d for d, _ in lolbin_flags))
                    top_summary = lolbin_flags[0][1].get("summary", "LOLBin usage")
                    narrative_parts.append(
                        f"**Living-off-the-land binary** (LOLBin) usage on {len(dev_names)} device(s) "
                        f"({', '.join(dev_names[:3])}) — {top_summary}"
                    )
                else:
                    narrative_parts.append(
                        "**LOLBin** usage was flagged — see detailed findings."
                    )
            if "privilege_escalation" in all_cats:
                priv_flags = []
                for dev_id, flags in behavioral_flags.items():
                    for f in flags:
                        if f.get("flag_type") == "privilege_escalation":
                            priv_flags.append((dev_id, f))
                if priv_flags:
                    dev_names = sorted(set(d for d, _ in priv_flags))
                    top_summary = priv_flags[0][1].get("summary", "Privilege escalation indicators")
                    narrative_parts.append(
                        f"**Privilege escalation** detected on {len(dev_names)} device(s) "
                        f"({', '.join(dev_names[:3])}) — {top_summary}"
                    )
                else:
                    narrative_parts.append(
                        "**Privilege escalation** activity was flagged — see detailed findings."
                    )
            if "defense_evasion" in all_cats:
                de_flags = []
                for dev_id, flags in behavioral_flags.items():
                    for f in flags:
                        if f.get("flag_type") == "defense_evasion":
                            de_flags.append((dev_id, f))
                if de_flags:
                    dev_names = sorted(set(d for d, _ in de_flags))
                    top_summary = de_flags[0][1].get("summary", "Defense evasion indicators")
                    narrative_parts.append(
                        f"**Defense evasion** techniques detected on {len(dev_names)} device(s) "
                        f"({', '.join(dev_names[:3])}) — {top_summary}"
                    )
                else:
                    narrative_parts.append(
                        "**Defense evasion** activity was flagged — see detailed findings."
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
        # Add email/phishing findings section if direct extraction found anything
        email_findings = context.get("email_direct_findings", [])
        if email_findings:
            phishing_hits = [f for f in email_findings
                           if f.get("result", {}).get("is_phishing") is True]
            scan_records = [f for f in email_findings
                          if f.get("function") == "email_scan"]

            if phishing_hits:
                lines.append("")
                lines.append("### Email / Phishing Findings")
                lines.append("")
                lines.append(
                    f"Direct email extraction from disk images identified "
                    f"**{len(phishing_hits)} suspicious email(s)** with phishing "
                    f"indicators (T1566)."
                )
                for ph in phishing_hits[:5]:
                    result = ph.get("result", {})
                    lines.append(
                        f"- **{result.get('subject', 'No subject')}** "
                        f"\u2014 From: `{result.get('from', 'Unknown')}` "
                        f"(confidence: {result.get('confidence', 0):.0%})"
                    )
                # Email IOCs summary
                email_iocs = context.get("email_iocs", {})
                if email_iocs:
                    src_ips = email_iocs.get("sender_ips", [])
                    ret_path_diff = email_iocs.get("return_path_mismatches", [])
                    if src_ips:
                        lines.append(f"- Extracted {len(src_ips)} sender IP address(es) from email headers")
                    if ret_path_diff:
                        lines.append(f"- {len(ret_path_diff)} Return-Path mismatch(es) detected (spoofing indicator)")
            elif scan_records:
                lines.append("")
                lines.append("### Email / Phishing Findings")
                lines.append("")
                total_scanned = sum(
                    r.get("result", {}).get("emails_scanned", 0)
                    for r in scan_records
                )
                lines.append(
                    f"Direct email extraction scanned **{total_scanned} email(s)** "
                    f"from disk images. No phishing indicators were detected."
                )

        if not evil:
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

    # ----------------------------------------------------------------
    # Kill Chain & Timeline Reconstruction (Section 1)
    # ----------------------------------------------------------------

    def _generate_kill_chain_timeline(self, report_json: dict,
                                        behavioral_flags: dict) -> str:
        """Generate a unified attack timeline from behavioral flags, audit_trail,
        and attack_chain data. Shows how the investigation unfolded."""
        ac = report_json.get("attack_chain", {}) or {}
        kill_phases = ac.get("kill_chain_phases", [])
        mitres_observed = ac.get("mitre_techniques_observed", [])
        classification = report_json.get("classification", "")

        # Collect all behavioral flags across all devices
        all_flags = []
        for dev_id, flags in behavioral_flags.items():
            for f in flags:
                fc = dict(f)
                fc["_device"] = dev_id
                all_flags.append(fc)

        # Collect timeline events flagged as suspicious
        timeline = report_json.get("timeline", [])
        suspicious_events = [e for e in timeline if e.get("suspicious")]

        if self.call_llm:
            ac_json = json.dumps(ac, default=str)[:2000]
            flags_json = json.dumps(all_flags[:10], default=str)[:2000]
            tl_json = json.dumps(suspicious_events[:20], default=str)[:2000]
            prompt = (
                "You are a forensic analyst. Generate a unified attack timeline "
                "table showing how the investigation unfolded.\n\n"
                f"Attack chain data:\n{ac_json}\n\n"
                f"Behavioral flags:\n{flags_json}\n\n"
                f"Suspicious timeline events:\n{tl_json}\n\n"
                f"Kill chain phases: {', '.join(kill_phases)}\n"
                f"MITRE techniques observed: {', '.join(mitres_observed[:15])}\n"
                f"Classification: {classification}\n\n"
                "Generate a Markdown table with columns: Timeframe | Event | MITRE Tactic | Log Source | Confidence\n"
                "- Derive timeframe from available timestamps (use 'Unknown' if unavailable)\n"
                "- Map each event to a MITRE tactic (Initial Access, Execution, Persistence, Defense Evasion, "
                "Credential Access, Discovery, Lateral Movement, Exfiltration, Command & Control)\n"
                "- Assign confidence: 'Observed' (artifact-backed), 'Inferred' (correlated evidence), 'Assumed' (heuristic)\n"
                "- Default log source to 'Forensic artifact' unless something more specific is available\n"
                "- If no data is available, state 'Insufficient data to reconstruct timeline'\n\n"
                "Output ONLY the Markdown table. No preamble, no commentary."
            )
            try:
                result = self._call_llm_with_retry(prompt, "", agent_type="manager")
                if result is not None:
                    return result
            except Exception:
                pass

        # Template fallback
        return self._template_kill_chain_timeline(
            kill_phases, mitres_observed, classification, all_flags, suspicious_events)

    def _template_kill_chain_timeline(self, kill_phases: list,
                                        mitres_observed: list,
                                        classification: str,
                                        all_flags: list,
                                        suspicious_events: list) -> str:
        """Template-based kill chain timeline."""

        phase_mitre_map = {
            "phishing": ("T1566", "Initial Access"),
            "initial_access": ("T1190", "Initial Access"),
            "credential_theft": ("T1003", "Credential Access"),
            "credential_access": ("T1003", "Credential Access"),
            "persistence": ("T1053", "Persistence"),
            "lateral_movement": ("T1021", "Lateral Movement"),
            "exfiltration": ("T1048", "Exfiltration"),
            "c2": ("T1071", "Command & Control"),
            "command_and_control": ("T1071", "Command & Control"),
            "lolbin": ("T1218", "Execution"),
            "web_shell": ("T1505.003", "Persistence"),
            "cryptominer": ("T1496", "Command & Control"),
            "privilege_escalation": ("T1055", "Privilege Escalation"),
            "defense_evasion": ("T1070", "Defense Evasion"),
            "discovery": ("T1083", "Discovery"),
        }

        entries = []

        if kill_phases:
            for i, phase in enumerate(kill_phases):
                phase_lower = phase.lower() if isinstance(phase, str) else ""
                mapping = phase_mitre_map.get(phase_lower)
                if mapping:
                    tid, tactic = mapping
                    label = phase.replace("_", " ").title()
                    timeframe = "Unknown" if i == 0 else f"+{i * 2}h"
                    entries.append({
                        "timeframe": timeframe,
                        "event": f"{label} ({tid})",
                        "tactic": tactic,
                        "source": "Classification metadata",
                        "confidence": "Inferred",
                    })
            # Add techniques from mitres_observed not already covered
            covered = {m[0] for m in [phase_mitre_map.get(p.lower(), (None, None)) for p in kill_phases] if m[0]}
            for tid in mitres_observed:
                if tid not in covered and tid in self._MITRE_PHASES:
                    entries.append({
                        "timeframe": "Unknown",
                        "event": f"{tid}",
                        "tactic": self._MITRE_PHASES[tid],
                        "source": "Forensic artifact",
                        "confidence": "Inferred",
                    })

        if not entries and classification:
            cls_lower = classification.lower()
            for phase_key, (tid, tactic) in phase_mitre_map.items():
                if phase_key.replace("_", " ") in cls_lower or phase_key in cls_lower:
                    entries.append({
                        "timeframe": "Unknown",
                        "event": f"{phase_key.replace('_', ' ').title()} ({tid})",
                        "tactic": tactic,
                        "source": "Classification metadata",
                        "confidence": "Inferred",
                    })

        if not entries:
            return "Insufficient data to reconstruct attack timeline. No kill-chain phases, behavioral flags, or suspicious timeline events were identified."

        lines = []
        lines.append("| Timeframe | Event | MITRE Tactic | Log Source | Confidence |")
        lines.append("|-----------|-------|-------------|------------|------------|")
        for e in entries[:25]:
            lines.append(
                f"| {e['timeframe']} | {e['event']} | {e['tactic']} | {e['source']} | {e['confidence']} |")

        lines.append("")
        lines.append(
            "> **Note:** Timeframes are estimated from attack-chain phase ordering. "
            "Corroborate with network logs and EDR telemetry."
        )

        return "\n".join(lines)

    # ----------------------------------------------------------------
    # Blast Radius & Business Impact Mapping (Section 2)
    # ----------------------------------------------------------------

    def _generate_blast_radius(self, report_json: dict,
                                 device_map: dict,
                                 user_map: dict) -> str:
        """Translate technical findings into organizational risk."""
        ac = report_json.get("attack_chain", {}) or {}
        classification = report_json.get("classification", "")
        evil_found = report_json.get("evil_found", False)

        users_dict = user_map.get("users", user_map) if isinstance(user_map, dict) else {}
        num_users = len(users_dict) if users_dict else 0
        privileged_count = sum(
            1 for u in users_dict.values()
            if isinstance(u, dict) and str(u.get("is_admin", u.get("group", ""))).lower() in ("true", "admin", "administrator")
        ) if users_dict else 0

        num_devices = len(device_map)
        servers = sum(1 for d in device_map.values() if "server" in str(d.get("device_type", "")).lower())
        dcs = sum(1 for d in device_map.values()
                  if "dc" in str(d.get("device_type", "")).lower()
                  or "dc" in str(d.get("hostname", "")).lower())
        workstations = sum(1 for d in device_map.values()
                           if "pc" in str(d.get("device_type", "")).lower()
                           or "workstation" in str(d.get("device_type", "")).lower()
                           or "desktop" in str(d.get("hostname", "")).lower())
        mobile = sum(1 for d in device_map.values()
                     if "mobile" in str(d.get("device_type", "")).lower())
        network = sum(1 for d in device_map.values()
                      if "network" in str(d.get("device_type", "")).lower()
                      or "pcap" in str(d.get("device_type", "")).lower())
        unknown = num_devices - servers - dcs - workstations - mobile - network

        # Data categories at risk
        data_categories = []
        all_text = (classification + " " + " ".join(ac.get("kill_chain_phases", []))).lower()
        if any(w in all_text for w in ("phishing", "email", "credential")):
            data_categories.append("PII (credentials, email)")
        if any(w in all_text for w in ("exfiltration", "exfil")):
            data_categories.append("intellectual property")
        if any(w in all_text for w in ("cryptominer", "crypto")):
            data_categories.append("compute resources")
        if not data_categories:
            data_categories.append("credentials, configuration data")

        # CIA impact
        cia = {"Confidentiality": "MEDIUM", "Integrity": "MEDIUM", "Availability": "LOW"}
        cia_rationale = {
            "Confidentiality": "No confirmed data breach",
            "Integrity": "No confirmed system modification",
            "Availability": "No impact on service availability",
        }

        if evil_found:
            if any(w in all_text for w in ("exfiltration", "credential_theft", "credential")):
                cia["Confidentiality"] = "HIGH"
                cia_rationale["Confidentiality"] = "Credential theft and/or exfiltration detected"
            elif any(w in all_text for w in ("phishing", "lateral")):
                cia["Confidentiality"] = "HIGH"
                cia_rationale["Confidentiality"] = "Potential unauthorized access to sensitive data"
            else:
                cia_rationale["Confidentiality"] = "Compromise confirmed — scope of data exposure unclear"

            if any(w in all_text for w in ("persistence", "web_shell", "lolbin")):
                cia["Integrity"] = "HIGH"
                cia_rationale["Integrity"] = "Persistence mechanisms modified system state"
            else:
                cia_rationale["Integrity"] = "Potential system modifications by attacker"

            if any(w in all_text for w in ("cryptominer", "ransomware")):
                cia["Availability"] = "HIGH"
                cia_rationale["Availability"] = "Resource consumption or destructive malware may impact service"

        # Worst-case
        if evil_found:
            parts = []
            if any(w in all_text for w in ("credential", "privilege")):
                parts.append("credential theft enabling tenant-wide compromise")
            if any(w in all_text for w in ("exfiltration", "exfil")):
                parts.append("data exfiltration to criminal infrastructure")
            if not parts:
                parts.append("unauthorized access leading to data theft, sabotage, or ransomware")
            worst_case = " and ".join(parts) + "."
        else:
            worst_case = "No compromise confirmed. Unresolved anomalies should be investigated to rule out nascent threats."

        # Render
        lines = []
        lines.append("### Affected Assets")
        asset_parts = []
        if num_users > 0:
            priv_str = f" ({privileged_count} privileged)" if privileged_count else ""
            asset_parts.append(f"**{num_users}** user accounts{priv_str}")
        if num_devices > 0:
            type_parts = []
            if servers: type_parts.append(f"{servers} server{'s' if servers != 1 else ''}")
            if dcs: type_parts.append(f"{dcs} DC{'s' if dcs != 1 else ''}")
            if workstations: type_parts.append(f"{workstations} workstation{'s' if workstations != 1 else ''}")
            if mobile: type_parts.append(f"{mobile} mobile")
            if network: type_parts.append(f"{network} network capture{'s' if network != 1 else ''}")
            if unknown: type_parts.append(f"{unknown} unknown")
            type_str = ", ".join(type_parts)
            asset_parts.append(f"**{num_devices}** devices ({type_str})")

        if asset_parts:
            lines.append("- " + ", ".join(asset_parts))
        else:
            lines.append("- No assets identified in evidence scope")
        if data_categories:
            lines.append(f"- **Data at risk**: {', '.join(data_categories)}")

        lines.append("")
        lines.append("### CIA Impact Assessment")
        lines.append("| Dimension | Score | Rationale |")
        lines.append("|-----------|-------|-----------|")
        for dim in ("Confidentiality", "Integrity", "Availability"):
            lines.append(f"| {dim} | {cia[dim]} | {cia_rationale[dim]} |")

        lines.append("")
        lines.append("### Worst-Case Projection")
        lines.append(f"If not contained: {worst_case}")

        return "\n".join(lines)

    # ----------------------------------------------------------------
    # Evidence Confidence & Gaps (Section 3)
    # ----------------------------------------------------------------

    def _generate_evidence_confidence(self, report_json: dict,
                                       behavioral_flags: dict) -> str:
        """Show epistemic humility — evidence strength and known gaps."""
        ac = report_json.get("attack_chain", {}) or {}
        kill_phases_lower = [kp.lower() for kp in ac.get("kill_chain_phases", [])]
        classification = report_json.get("classification", "")
        cls_lower = classification.lower()

        phase_strength_map = {
            "credential_theft": ("Credential Access", "Strong"),
            "credential_access": ("Credential Access", "Strong"),
            "lateral_movement": ("Lateral Movement", "Moderate"),
            "exfiltration": ("Exfiltration", "Moderate"),
            "phishing": ("Initial Access", "Weak"),
            "initial_access": ("Initial Access", "Weak"),
            "persistence": ("Persistence", "Moderate"),
            "lolbin": ("Execution", "Moderate"),
            "web_shell": ("Persistence", "Strong"),
            "c2": ("Command & Control", "Moderate"),
            "command_and_control": ("Command & Control", "Moderate"),
            "cryptominer": ("Command & Control", "Moderate"),
            "privilege_escalation": ("Privilege Escalation", "Moderate"),
            "defense_evasion": ("Defense Evasion", "Weak"),
            "discovery": ("Discovery", "Weak"),
        }

        basis_map = {
            "Strong": "Artifacts confirmed in findings",
            "Moderate": "Correlated indicators suggesting activity",
            "Weak": "Classification metadata — no specific artifact confirmed",
        }

        strength_entries = []
        seen_categories = set()
        for phase in kill_phases_lower:
            info = phase_strength_map.get(phase)
            if info:
                cat_name, strength = info
                if cat_name in seen_categories:
                    continue
                seen_categories.add(cat_name)
                strength_entries.append({
                    "category": cat_name,
                    "strength": strength,
                    "basis": basis_map[strength],
                })

        if not strength_entries and cls_lower:
            for phase_key, (cat_name, strength) in phase_strength_map.items():
                if phase_key.replace("_", " ") in cls_lower or phase_key in cls_lower:
                    if cat_name not in seen_categories:
                        seen_categories.add(cat_name)
                        strength_entries.append({
                            "category": cat_name,
                            "strength": strength,
                            "basis": basis_map[strength],
                        })

        # Known gaps
        gaps = []
        failures = report_json.get("failures", [])
        total_steps = (report_json.get("steps_completed", 0)
                       + report_json.get("steps_failed", 0)
                       + report_json.get("steps_skipped", 0))
        failed_count = len(failures)

        if total_steps > 0 and failed_count > 0:
            gaps.append(f"{failed_count} of {total_steps} analysis steps failed (tool/dependency/parameter issues)")

        inv = report_json.get("evidence_inventory", {})
        if not inv.get("evtx_logs"):
            gaps.append("No Windows EVTX log files in evidence scope")
        if not inv.get("syslogs"):
            gaps.append("No syslog files in evidence scope")

        device_map = report_json.get("device_map", {})
        memory_devices = sum(
            1 for d in device_map.values()
            if any("memdump" in str(f).lower() or "memory" in str(f).lower()
                   for f in d.get("evidence_files", []))
        )
        if len(device_map) > 0 and memory_devices < len(device_map):
            gaps.append(f"Memory captured for {memory_devices} of {len(device_map)} devices — volatile artifacts may be missing")

        if not gaps:
            gaps.append("No significant evidence gaps identified in this investigation scope")

        # Render
        lines = []
        lines.append("### Evidence Strength")
        if strength_entries:
            lines.append("| Finding Category | Strength | Basis |")
            lines.append("|-----------------|----------|-------|")
            for e in strength_entries:
                lines.append(f"| {e['category']} | {e['strength']} | {e['basis']} |")
        else:
            lines.append("*No finding categories available for strength assessment.*")

        lines.append("")
        lines.append("### Known Evidence Gaps")
        for gap in gaps:
            lines.append(f"- {gap}")

        lines.append("")
        lines.append(
            "> **Analyst Note:** Evidence confidence ratings reflect the automated analysis "
            "pipeline only. Manual review may upgrade confidence levels. Gaps identified here "
            "represent limitations of evidence scope, not analysis failures."
        )

        return "\n".join(lines)

    # ----------------------------------------------------------------
    # Dwell Time & Lateral Movement (Section 4)
    # ----------------------------------------------------------------

    def _generate_dwell_time(self, report_json: dict) -> str:
        """Show time-based analysis: dwell time, milestone progression, lateral path."""
        ac = report_json.get("attack_chain", {}) or {}
        first_seen = ac.get("first_seen_ts", "")
        last_seen = ac.get("last_seen_ts", "")
        dwell_days = ac.get("dwell_days")
        lateral_path = ac.get("lateral_movement_path", [])
        kill_phases = ac.get("kill_chain_phases", [])

        phase_labels = {
            "phishing": "Initial Access",
            "initial_access": "Initial Access",
            "credential_theft": "Credential Harvesting",
            "credential_access": "Credential Access",
            "privilege_escalation": "Privilege Escalation",
            "lateral_movement": "Lateral Movement",
            "persistence": "Persistence Established",
            "exfiltration": "Exfiltration",
            "c2": "C2 Established",
            "command_and_control": "C2 Communications",
            "lolbin": "Execution / LOLBin Usage",
            "web_shell": "Web Shell Deployment",
            "cryptominer": "Crypto Mining Activity",
            "defense_evasion": "Defense Evasion",
            "discovery": "Discovery / Reconnaissance",
        }

        lines = []
        lines.append("### Dwell Time & Progression")

        if not first_seen and not last_seen and dwell_days is None and not lateral_path:
            lines.append("")
            lines.append("*No temporal or lateral movement data available for this investigation.*")
            return "\n".join(lines)

        lines.append("| Milestone | Estimated Timeframe |")
        lines.append("|-----------|--------------------|")

        if kill_phases:
            for i, phase in enumerate(kill_phases):
                label = phase_labels.get(
                    phase.lower() if isinstance(phase, str) else "",
                    phase.replace("_", " ").title() if isinstance(phase, str) else str(phase))
                if i == 0:
                    timeframe = "First detected"
                elif dwell_days is not None and dwell_days > 0 and len(kill_phases) > 0:
                    frac = (i / len(kill_phases)) * dwell_days * 24
                    if frac < 1:
                        timeframe = f"~{int(frac * 60)}m after initial"
                    else:
                        timeframe = f"~{frac:.1f}h after initial"
                else:
                    timeframe = f"+{i * 2}h (estimated)"
                lines.append(f"| {label} | {timeframe} |")
        else:
            lines.append("| Initial Access | Unknown |")
            lines.append("| Attack Activity | Evidence detected — exact timing not available |")

        if dwell_days is not None:
            if dwell_days < 1 / 24:
                dwell_str = f"~{int(dwell_days * 1440)} minutes"
            elif dwell_days < 1:
                dwell_str = f"~{dwell_days * 24:.1f} hours"
            elif dwell_days < 30:
                dwell_str = f"~{dwell_days:.1f} days"
            else:
                dwell_str = f"~{dwell_days / 30:.1f} months"
            lines.append(f"| **Total Dwell** | **{dwell_str}** |")

        if first_seen or last_seen:
            lines.append("")
            lines.append(f"- **First Seen:** {first_seen or 'Unknown'}")
            lines.append(f"- **Last Seen:** {last_seen or 'Unknown'}")

        lines.append("")
        lines.append("### Lateral Movement Path")
        if lateral_path:
            seen = set()
            deduped = []
            for dev in lateral_path:
                if dev not in seen:
                    seen.add(dev)
                    deduped.append(dev)
            if len(deduped) > 1:
                lines.append(" → ".join(deduped))
                lines.append("")
                lines.append(
                    f"> **{len(deduped)} devices** show evidence of lateral movement. "
                    f"Path reconstructed from artifact relationships and credential usage patterns."
                )
            else:
                lines.append(str(deduped[0]) if deduped else "No path detected")
        else:
            lines.append("*No lateral movement path data available.*")

        return "\n".join(lines)

    # ----------------------------------------------------------------
    # Conclusion
    # ----------------------------------------------------------------

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

    # URL noise filter — known ad/tracking, SSL infra, CDN patterns, and
    # Microsoft/cloud telemetry/infrastructure domains that are never IOCs.
    # Matched via domain suffix (subdomain matching): sub.example.com matches .example.com
    _NOISE_URL_DOMAINS = (
        # Ads / tracking
        'doubleclick.net', 'atwola.com', 'cdn.channel.aol.com', 'ads.cnn.com',
        'googlesyndication.com', 'googleadservices.com', 'quantserve.com',
        'scorecardresearch.com', 'googletagmanager.com', 'google-analytics.com',
        'googleadservices.com', 'googlesyndication.com', 'moatads.com',
        'outbrain.com', 'taboola.com', 'criteo.com', 'rubiconproject.com',
        'pubmatic.com', 'openx.net', 'casalemedia.com', 'agkn.com',
        'adsrvr.org', 'adsymptotic.com', 'exponential.com', 'burstnet.com',
        'contextweb.com', 'bluekai.com', 'demdex.net', 'rlcdn.com',
        'adsafeprotected.com', '2mdn.net', 'adform.net', 'adnxs.com',
        'adzerk.net', 'tribalfusion.com', 'turn.com', 'invitemedia.com',
        'media6degrees.com', 'specificmedia.com', 'tidaltv.com',
        # Mozilla telemetry
        'telemetry.mozilla.org', 'incoming.telemetry.mozilla.org',
        # Crash/error reporting
        'sessions.bugsnag.com', 'notify.bugsnag.com',
        # Microsoft telemetry / update / infrastructure
        'microsoft.com',
        'live.com',
        'bing.com',
        'msn.com',
        'windows.com',
        'azure.com',
        'office.com',
        'office365.com',
        'microsoftonline.com',
        'windowsupdate.com',
        'windowsupdate.microsoft.com',
        'update.microsoft.com',
        'delivery.mp.microsoft.com',
        'ctldl.windowsupdate.com',
        'download.windowsupdate.com',
        'settings-win.data.microsoft.com',
        'watson.telemetry.microsoft.com',
        'vortex.data.microsoft.com',
        'vortex-win.data.microsoft.com',
        'telecommand.telemetry.microsoft.com',
        'oca.telemetry.microsoft.com',
        'sqm.telemetry.microsoft.com',
        'telemetry.microsoft.com',
        'stats.microsoft.com',
        'login.live.com',
        'account.live.com',
        'outlook.office.com',
        'outlook.office365.com',
        'outlook.live.com',
        'skype.com',           # legitimate Microsoft service
        'xboxlive.com',
        'xbox.com',
        'microsoftstore.com',
        'visualstudio.com',
        'github.com',          # legitimate dev platform
        'githubusercontent.com',
        'nuget.org',           # package feed
        # CDN / CDN-like
        'akamaized.net',
        'cloudfront.net',
        'cloudflare.com',
        'edgekey.net',
        'edgesuite.net',
        'akadns.net',
        'akamai.net',
        'akamaihd.net',
        'akamaitechnologies.com',
        'llnwd.net',           # Limelight CDN
        'fastly.net',
        'fastly.com',
        'stackpathcdn.com',
        'cdninstagram.com',
        # Known safe / forensic reference
        'google.com',          # search, not IOC
        'nist.gov',            # forensics reference
        'nvd.nist.gov',
        'virustotal.com',      # analysis reference
        'reddit.com',
        'youtube.com',
        'twitter.com',
        'x.com',
        'facebook.com',
        'linkedin.com',
        'wikipedia.org',
        'stackoverflow.com',
        'stackexchange.com',
        'docker.com',          # container registry
        'hub.docker.com',
    )
    _NOISE_URL_KEYWORDS = (
        'crl.', 'ocsp.', 'verisign', 'thawte', 'globalsign',
        'blogger.com', 'blogspot.com', 'googleusercontent.com',
        'gravatar.com', 'feeds.feedburner.com', 'clickserve.',
        'adservice.', 'adserver.', 'adsystem.',
    )

    def _is_noise_url(self, url: str) -> bool:
        """Return True if the URL is noise (ads, SSL infra, CDN, binary artifacts, etc.) and should be excluded."""
        if not url or not isinstance(url, str):
            return True
        # Reject if too short (fragments, binary noise)
        if len(url) < 8:
            return True
        url_lower = url.lower()
        # Reject URLs containing non-printable control characters or non-ASCII
        for ch in url_lower:
            code = ord(ch)
            if code <= 0x1F or code == 0x7F or code > 0x7E:
                return True
        # Reject concatenated URLs (two protocol schemes smushed together)
        # e.g. http://a.comhttp://b.com or https://x.comhttps://y.com
        # Count occurrences of '://' — more than 1 means concatenation
        if url_lower.count('://') > 1:
            return True
        # Reject URLs where a second http/https appears after the first's domain
        # e.g. http://a.comhttp://b... but NOT legitimate URL params containing http
        http_positions = [m.start() for m in __import__('re').finditer(r'https?://', url_lower)]
        if len(http_positions) > 1:
            # Check if they're truly concatenated (no proper separator like & or ? between them)
            first_end = url_lower.find('://', http_positions[0]) + 3
            slash_after_domain = url_lower.find('/', first_end)
            if slash_after_domain == -1:
                slash_after_domain = len(url_lower)
            # If there's no '&' or '?' between the end of first domain and second protocol, it's concatenated
            between = url_lower[first_end:http_positions[1]]
            if '&' not in between and '?' not in between and ' ' not in between:
                return True
        # Extract domain between :// and next / for suffix checks
        proto_end = url_lower.find('://')
        if proto_end >= 0:
            domain_start = proto_end + 3
            domain_end = url_lower.find('/', domain_start)
            if domain_end == -1:
                domain_end = url_lower.find('?', domain_start)
            if domain_end == -1:
                domain_end = len(url_lower)
            url_domain = url_lower[domain_start:domain_end]
            # Strip port number if present
            port_idx = url_domain.find(':')
            if port_idx >= 0:
                url_domain = url_domain[:port_idx]
            # No dot in domain means it's not a real URL (e.g. http://abcdefg)
            if '.' not in url_domain:
                return True
        else:
            url_domain = ''  # not a proper URL; downstream checks will handle
        # Reject URLs containing binary/hex-like noise patterns (long hex strings without proper structure)
        # Random hex segments appearing as path components suggest binary data artifact
        hex_segments = __import__('re').findall(r'[0-9a-f]{16,}', url_lower)
        if hex_segments and len(hex_segments) >= 2:
            return True
        # Domain suffix matching: check if url_domain matches a blocklist suffix
        # e.g. sub.telemetry.microsoft.com matches .microsoft.com (ends with)
        for domain_suffix in self._NOISE_URL_DOMAINS:
            ds = domain_suffix.lower()
            if url_domain == ds or url_domain.endswith('.' + ds):
                return True

        # Keyword substring matching (for patterns like crl., ocsp.)
        for kw in self._NOISE_URL_KEYWORDS:
            if kw in url_lower:
                return True
        return False

    def _extract_iocs(self, report_json: dict,
                      behavioral_flags: dict) -> Dict[str, List[str]]:
        """Extract and deduplicate IOCs from all evidence sources.

        Scans indicator_hits, behavioral flag evidence dicts, and tool stdout
        for IPs (public only), file hashes, URLs, registry keys, Windows file
        paths, and email addresses. Returns dict of sorted lists.
        """
        buckets: Dict[str, set] = {
            "ip_addresses":  set(),
            "urls":          set(),
            "registry_keys": set(),
            "file_paths":    set(),
            "email_addresses": set(),
        }
        file_hashes_dict: Dict[str, dict] = {}

        def _scan(text: str) -> None:
            if not text or not isinstance(text, str):
                return
            # Public IPv4
            for m in re.finditer(r'\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b', text):
                ip = m.group(0)
                octets = ip.split('.')
                if all(0 <= int(x) <= 255 for x in octets):
                    # Reject version strings like 7.0.2.7 where all 4 octets are single digits
                    # Exception for well-known public DNS servers
                    all_single = all(len(o) == 1 for o in octets)
                    if all_single and ip not in {'8.8.8.8', '1.1.1.1', '8.8.4.4', '1.0.0.1'}:
                        continue
                    if not self._PRIV_IP.match(ip) and not NarrativeReportGenerator._is_in_cdn_range(ip):
                        buckets["ip_addresses"].add(ip)
            # MD5 / SHA1 / SHA256 hashes (store with context placeholders)
            for m in re.finditer(r'\b[0-9a-fA-F]{32,64}\b', text):
                h = m.group(0).lower()
                if len(h) in (32, 40, 64):
                    algo = {32: 'md5', 40: 'sha1', 64: 'sha256'}[len(h)]
                    if h not in file_hashes_dict:
                        file_hashes_dict[h] = {
                            "hash": h,
                            "algorithm": algo,
                            "filename": "",
                            "path": "",
                            "source_image": "",
                        }
            # URLs (with noise filtering)
            for m in re.finditer(r'https?://[^\s"\'<>\r\n]{8,}', text):
                url = m.group(0).rstrip('.,)')
                # Clean control characters (\x00-\x08, \x0b, \x0c, \x0e-\x1f)
                cleaned = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', url)
                if len(cleaned) < 8:
                    continue
                # Apply noise filter
                if not self._is_noise_url(cleaned):
                    buckets["urls"].add(cleaned)
            # Windows registry keys — filter known-good and shallow keys
            _registry_filtered = 0
            for m in re.finditer(
                    r'(?:HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)'
                    r'[\\\/][^\s"\'<>\r\n]+',
                    text, re.IGNORECASE):
                rk = m.group(0)
                # Normalise to backslash for consistent comparison
                rk_norm = rk.replace('/', '\\')
                # Skip keys with depth < 3 (too generic to be IOCs)
                if NarrativeReportGenerator._get_registry_depth(rk_norm) < 3:
                    _registry_filtered += 1
                    continue
                # Skip keys matching known-good prefixes
                skip = False
                for good_prefix in NarrativeReportGenerator._KNOWN_GOOD_REGISTRY_PREFIXES:
                    if rk_norm.upper().startswith(good_prefix.upper()):
                        _registry_filtered += 1
                        skip = True
                        break
                if not skip:
                    buckets["registry_keys"].add(rk)
            if _registry_filtered > 0:
                print(f"[REPORT] Filtered {_registry_filtered} noise registry key(s) from IOC extraction")
            # Windows file paths (min 10 chars to reduce noise)
            # Require at least 2-char directory names to avoid matching
            # single-char garbage from forensic metadata (e.g. \r\n parsed as r\, n\)
            for m in re.finditer(
                    r'[A-Za-z]:\\(?:[^\\\/:*?"<>|\r\n]{2,}\\)*[^\\\/:*?"<>|\r\n]{2,}',
                    text):
                p = m.group(0).rstrip('.,)')
                if len(p) >= 10 and _is_valid_file_path(p):
                    buckets["file_paths"].add(p)
            # Email addresses — loose regex, validated by _is_valid_email
            for m in re.finditer(
                    r'\b[a-zA-Z0-9][a-zA-Z0-9._%+-]{2,}@'
                    r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'
                    r'(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*'
                    r'\.[a-zA-Z]{2,}\b',
                    text):
                email = m.group(0).lower()
                if _is_valid_email(email):
                    buckets["email_addresses"].add(email)

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

        # Source 3: tool stdout (capped to first 100KB) + hash enrichment
        # CRITICAL: Skip findings where the Critic REJECTED the step output.
        # REJECTED findings contain hallucinated or forensic-metadata noise that
        # pollutes the IOC section if included unfiltered.
        for finding in report_json.get("findings_detail", []):
            # Gate: reject Critic-REJECTED findings from IOC extraction
            critic = finding.get("critic", {})
            if isinstance(critic, dict) and critic.get("verdict") == "REJECTED":
                continue
            # Also skip completed_unverified steps — these lack Critic validation
            if finding.get("status") == "completed_unverified" and finding.get("needs_review"):
                continue
            result = finding.get("result", {})
            if isinstance(result, dict):
                stdout = (result.get("stdout", "") or "")[:102400]
                raw_output = (result.get("raw_output", "") or "")[:102400]
                _scan(stdout)
                _scan(raw_output)

                # Enrich file hashes with context from this finding
                if stdout or raw_output:
                    combined = (stdout + "\n" + raw_output).lower()
                    source_image = str(finding.get("evidence_file", "") or "")

                    # Check finding function/params for filename context
                    fn = ""
                    fpath = ""
                    func = finding.get("function", "")
                    params = finding.get("params", {}) or {}
                    if func in ("extract_file", "export_file", "recover_files",
                                "carve", "file_info", "hash_file"):
                        if params.get("path"):
                            fpath = str(params["path"])
                        if params.get("filename"):
                            fn = str(params["filename"])
                        elif params.get("file_name"):
                            fn = str(params["file_name"])
                        elif params.get("inode"):
                            fpath = f"inode {params['inode']}"

                    for h, entry in file_hashes_dict.items():
                        if h not in combined:
                            continue
                        # Set source image if not already set
                        if source_image and not entry["source_image"]:
                            entry["source_image"] = source_image
                        # Set filename from finding params
                        if fn and not entry["filename"]:
                            entry["filename"] = fn
                        if fpath and not entry["path"]:
                            entry["path"] = fpath
                        # Try to find filename in stdout context near the hash
                        if not entry["filename"]:
                            idx = combined.find(h)
                            if idx >= 0:
                                ctx_start = max(0, idx - 400)
                                ctx_end = min(len(combined), idx + 400)
                                ctx = combined[ctx_start:ctx_end]
                                fn_match = re.search(
                                    r"[A-Za-z0-9_][A-Za-z0-9._-]{1,60}\."
                                    r"(?:exe|dll|sys|docx?|xlsx?|pptx?|pdf|txt|html?|js|vbs|ps1|bat|cmd|"
                                    r"jpg|png|gif|zip|rar|7z|py|pl|php|asp|swf|jar|class|tmp|lnk|scr|pif|"
                                    r"com|cpl|drv|ocx|fon|dat|log|pst|ost|eml|msg|rtf|xml|json|csv|cfg|ini|"
                                    r"key|reg|pem|crt|cer|p12|pfx|psd|sql|mdb|db|sqlite|vhd|vmdk|vdi|ova|"
                                    r"iso|img|bin|raw|dd|e01|e02|aff|l01|lx01|ad1|zipx|gz|bz2|xz|tar|"
                                    r"msi|cab|dmg|pkg|apk|deb|rpm|sh|elf|so|jar|war|ear)",
                                    ctx, re.IGNORECASE)
                                if fn_match:
                                    entry["filename"] = fn_match.group(0)

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

        # Source 4b: structured email IOCs from findings_detail results
        # Extracts from/to addresses from any finding with email_iocs AND
        # deep-scans the full result JSON for embedded IOCs (catches data
        # that structured field extraction might miss).
        for finding in report_json.get("findings_detail", []):
            # Gate: skip Critic-REJECTED and unverified-needs-review findings
            _fc = finding.get("critic", {})
            if isinstance(_fc, dict) and _fc.get("verdict") == "REJECTED":
                continue
            if finding.get("status") == "completed_unverified" and finding.get("needs_review"):
                continue
            result = finding.get("result", {})
            if not isinstance(result, dict):
                continue
            eiocs = result.get("email_iocs")
            if isinstance(eiocs, dict):
                for addr in eiocs.get("from_addresses", []):
                    clean = _extract_email(addr)
                    if clean and _is_valid_email(clean.lower()):
                        buckets["email_addresses"].add(clean.lower())
                for addr in eiocs.get("to_addresses", []):
                    clean = _extract_email(addr)
                    if clean and _is_valid_email(clean.lower()):
                        buckets["email_addresses"].add(clean.lower())
                # Deep-scan the full result JSON for any embedded IOCs
                _scan(json.dumps(result, default=str))

        # Source 5: structured email IOCs from direct email extraction findings
        # Collects sender IPs, from/to addresses, return-path mismatches
        # Also cleans display-name wrapped addresses and filters system addresses
        email_iocs_agg: Dict[str, list] = {
            "sender_ips": [],
            "from_addresses": [],
            "to_addresses": [],
            "return_paths": [],
            "urls_in_body": [],
            "return_path_mismatches": [],
            "spoofed_domains": [],
        }
        seen = {k: set() for k in email_iocs_agg}

        for finding in report_json.get("findings_detail", []):
            # Gate: skip Critic-REJECTED and unverified-needs-review findings
            _fc = finding.get("critic", {})
            if isinstance(_fc, dict) and _fc.get("verdict") == "REJECTED":
                continue
            if finding.get("status") == "completed_unverified" and finding.get("needs_review"):
                continue
            result = finding.get("result", {})
            if not isinstance(result, dict):
                continue
            eiocs = result.get("email_iocs", {})
            if not isinstance(eiocs, dict):
                continue

            for ip in eiocs.get("sender_ips", []):
                if ip not in seen["sender_ips"]:
                    seen["sender_ips"].add(ip)
                    # Only include public IPs for the main iocs bucket
                    if not self._PRIV_IP.match(str(ip)):
                        buckets["ip_addresses"].add(str(ip))

            for addr in eiocs.get("from_addresses", []):
                if addr not in seen["from_addresses"]:
                    seen["from_addresses"].add(addr)
                    # Extract clean email from display-name wrappers and validate
                    clean = _extract_email(addr)
                    if clean:
                        clean_lower = clean.lower()
                        if _is_valid_email(clean_lower):
                            buckets["email_addresses"].add(clean_lower)

            for addr in eiocs.get("to_addresses", []):
                if addr not in seen["to_addresses"]:
                    seen["to_addresses"].add(addr)
                    # Extract clean email and validate
                    clean = _extract_email(addr)
                    if clean:
                        clean_lower = clean.lower()
                        if _is_valid_email(clean_lower):
                            buckets["email_addresses"].add(clean_lower)

            for rp in eiocs.get("return_paths", []):
                if rp not in seen["return_paths"]:
                    seen["return_paths"].add(rp)

            for url in eiocs.get("urls_in_body", []):
                if url not in seen["urls_in_body"]:
                    seen["urls_in_body"].add(url)
                    buckets["urls"].add(str(url))

            for mismatch in eiocs.get("return_path_mismatches", []):
                if isinstance(mismatch, dict):
                    mkey = json.dumps(mismatch, sort_keys=True, default=str)
                    if mkey not in seen["return_path_mismatches"]:
                        seen["return_path_mismatches"].add(mkey)
                        email_iocs_agg["return_path_mismatches"].append(mismatch)

            for domain in eiocs.get("spoofed_domains", []):
                if domain not in seen["spoofed_domains"]:
                    seen["spoofed_domains"].add(domain)

        # Store deduplicated email IOCs
        email_iocs_agg["sender_ips"] = sorted(seen["sender_ips"])
        email_iocs_agg["from_addresses"] = sorted(seen["from_addresses"])
        email_iocs_agg["to_addresses"] = sorted(seen["to_addresses"])
        email_iocs_agg["return_paths"] = sorted(seen["return_paths"])
        email_iocs_agg["urls_in_body"] = sorted(seen["urls_in_body"])
        email_iocs_agg["spoofed_domains"] = sorted(seen["spoofed_domains"])

        # Convert file_hashes dict to list for final output
        if file_hashes_dict:
            buckets["file_hashes"] = list(file_hashes_dict.values())

        result_dict = {k: sorted(v) if isinstance(v, set) else v
                       for k, v in buckets.items() if v}
        if any(v for v in email_iocs_agg.values()):
            result_dict["email_iocs"] = email_iocs_agg

        # ── Post-extraction Critic validation on IOCs ──
        # Run format validation on the final IOC set to catch any remaining
        # noise that slipped through per-finding Critic checks. This catches
        # forensic metadata, version strings disguised as IPs, and other
        # bleed-through that per-step Critic may have missed.
        try:
            from geoff_critic import GeoffCritic
            _critic = GeoffCritic()
            _format_val = _critic.validate_ioc_formats(result_dict)
            if _format_val.get("format_issue_count", 0) > 0:
                _bad_values = {issue["value"] for issue in _format_val.get("format_issues", [])}
                # Remove invalid IOCs from all buckets
                for key in ["ip_addresses", "urls", "email_addresses", "registry_keys", "file_paths"]:
                    if key in result_dict and isinstance(result_dict[key], list):
                        result_dict[key] = [v for v in result_dict[key] if v not in _bad_values]
                # Also filter file_hashes
                if "file_hashes" in result_dict and isinstance(result_dict["file_hashes"], list):
                    result_dict["file_hashes"] = [
                        h for h in result_dict["file_hashes"]
                        if h.get("hash", "") not in _bad_values
                    ]
                # Also filter email_iocs
                if "email_iocs" in result_dict and isinstance(result_dict["email_iocs"], dict):
                    for ek in ["from_addresses", "to_addresses", "return_paths", "urls_in_body"]:
                        if ek in result_dict["email_iocs"] and isinstance(result_dict["email_iocs"][ek], list):
                            result_dict["email_iocs"][ek] = [
                                v for v in result_dict["email_iocs"][ek] if v not in _bad_values
                            ]
                # Log how many were removed
                _removed = _format_val.get("format_issue_count", 0)
                print(f"[REPORT] IOC format validation removed {_removed} invalid IOCs")
        except Exception as _ioc_val_err:
            # Non-fatal — if Critic is unavailable, just use unvalidated IOCs
            print(f"[REPORT] IOC format validation skipped: {_ioc_val_err}")

        return result_dict

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
- State facts only based on verified evidence. Do NOT include hypotheses, inferences, or speculative language
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

    def _render_detailed_steps(self, report_json: dict) -> str:
        """Render detailed step-by-step execution log showing actual CLI commands,
        raw output excerpts, critic verdicts, and status for every step."""
        # Lazy import to avoid circular dependency (geoff_pipeline imports narrative_report)
        from geoff_pipeline import _reconstruct_raw_command
        findings = report_json.get("findings_detail", [])
        if not findings:
            return "No step execution data available."

        lines = []
        lines.append("This section documents every forensic tool execution performed during the investigation, "
                      "including the exact CLI commands, raw output excerpts, and validation results. "
                      "This is the authoritative record of 'what ran, what it said, and whether we trust it.'\n")

        # Group findings by playbook
        from collections import OrderedDict
        by_pb = OrderedDict()
        for f in findings:
            pb = f.get("playbook", "Unknown")
            by_pb.setdefault(pb, []).append(f)

        total = len(findings)
        completed = sum(1 for f in findings if f.get("status") == "completed")
        unverified = sum(1 for f in findings if f.get("status") == "completed_unverified")
        failed = sum(1 for f in findings if f.get("status") == "failed")
        skipped = sum(1 for f in findings if f.get("status") == "skipped")

        lines.append(f"**Summary:** {total} total steps — {completed} verified, {unverified} unverified, "
                     f"{failed} failed, {skipped} skipped\n")

        for pb_id, pb_steps in by_pb.items():
            pb_name = report_json.get("playbook_names", {}).get(pb_id, pb_id)
            lines.append(f"\n### Playbook: {pb_name} ({pb_id})\n")
            lines.append(f"**Steps in this playbook:** {len(pb_steps)}\n")
            for i, f in enumerate(pb_steps, 1):
                module = f.get("module", "?")
                function = f.get("function", "?")
                status = f.get("status", "unknown")
                evidence = Path(f.get("evidence_file", "")).name if f.get("evidence_file") else "N/A"
                device = f.get("device_id", "N/A")
                raw_cmd = f.get("raw_command", "")
                step_key = f.get("step_key", "")

                # Status badge
                status_badge = {
                    "completed": "✅ Completed",
                    "completed_unverified": "⚠️ Completed (Unverified)",
                    "failed": "❌ Failed",
                    "skipped": "⏭️ Skipped",
                    "running": "🔄 Running",
                    "error": "❌ Error",
                }.get(status, status)

                lines.append(f"#### Step {i}: `{module}.{function}`\n")
                lines.append(f"- **Evidence:** `{evidence}` (device: {device})")
                lines.append(f"- **Status:** {status_badge}")
                if step_key:
                    lines.append(f"- **Step Key:** `{step_key}`")

                # CLI command
                if raw_cmd:
                    lines.append(f"\n**Command:**")
                    lines.append(f"```bash\n{raw_cmd}\n```")
                else:
                    # Fallback: reconstruct CLI command using _reconstruct_raw_command
                    params = f.get("params", {})
                    reconstructed = _reconstruct_raw_command(module, function, params)
                    lines.append(f"\n**Command:**")
                    lines.append(f"```bash\n{reconstructed}\n```")

                # Raw output excerpt
                result = f.get("result", {})
                if isinstance(result, dict):
                    stdout = result.get("stdout", "")
                    stderr = result.get("stderr", "")
                    output_text = stdout or stderr or ""
                    if output_text:
                        excerpt = output_text[:500]
                        if len(output_text) > 500:
                            excerpt += "\n[...truncated...]"
                        lines.append(f"\n**Raw Output (first 500 chars):**")
                        lines.append(f"```\n{excerpt}\n```")
                    else:
                        lines.append(f"\n**Raw Output:** *(empty)*")
                else:
                    lines.append(f"\n**Raw Output:** `{str(result)[:300]}`")

                # Forensicator / Critic assessment
                forensicator = f.get("forensicator", {})
                if isinstance(forensicator, dict):
                    note = forensicator.get("analyst_note")
                    sig = forensicator.get("significance", "")
                    ti = forensicator.get("threat_indicators", [])
                    if note:
                        lines.append(f"\n**Forensicator ({sig}):** {note}")
                    if ti:
                        lines.append(f"  - **Threat Indicators:** {', '.join(ti[:5])}")

                critic = f.get("critic", {})
                if isinstance(critic, dict):
                    verdict = critic.get("verdict", "N/A")
                    v_reason = critic.get("verdict_reason", "")
                    hallucinations = critic.get("hallucinations", [])
                    nonsense = critic.get("nonsense", [])
                    invalid_iocs = critic.get("invalid_iocs", [])
                    needs_review = critic.get("needs_review", False)
                    unverified_reason = critic.get("unverified_reason", "")

                    # Check if critic has real content worth rendering
                    has_content = (
                        verdict not in ("N/A", "") or v_reason or
                        hallucinations or nonsense or invalid_iocs or
                        needs_review or unverified_reason
                    )
                    if not has_content:
                        pass  # skip empty critic
                    elif needs_review and unverified_reason:
                        lines.append(f"\\n**Critic:** ⚠️ Could not verify — {unverified_reason}")
                    else:
                        if verdict == "APPROVED":
                            critic_badge = "✅ **APPROVED**"
                            suffix = f" — {v_reason}" if v_reason else ""
                        elif verdict == "REQUIRES_REVIEW":
                            critic_badge = "⚠️ **REQUIRES REVIEW**"
                            suffix = f" — {v_reason}" if v_reason else ""
                        elif verdict == "REJECTED":
                            critic_badge = "❌ **REJECTED**"
                            suffix = f" — {v_reason}" if v_reason else ""
                        else:
                            critic_badge = f"**Verdict:** {verdict}"
                            suffix = f" — {v_reason}" if v_reason else ""

                        lines.append(f"\\n**Critic:** {critic_badge}{suffix}")
                    if hallucinations:
                        lines.append(f"  - **Hallucinations:** {'; '.join(str(h)[:100] for h in hallucinations[:3])}")
                    if nonsense:
                        lines.append(f"  - **Nonsense:** {'; '.join(str(n)[:100] for n in nonsense[:3])}")
                    if invalid_iocs:
                        lines.append(f"  - **Invalid IOCs:** {', '.join(str(i)[:100] for i in invalid_iocs[:3])}")
                    if needs_review and not unverified_reason:
                        lines.append(f"  - ⚠️ Needs human review")

                # Error info for failed steps
                error = f.get("error")
                if error:
                    lines.append(f"\n**Error:** {str(error)[:200]}")

                lines.append("")  # blank line after each step

        return "\n".join(lines)

    def _render_email_phishing_section(self, report_json: dict) -> str:
        """Render standalone Email & Phishing Analysis section.

        Scans findings_detail for EMAIL-playbook findings, groups into
        phishing hits vs clean, returns formatted markdown.
        """
        findings = report_json.get("findings_detail", [])
        if not findings:
            return "No email/phishing data."

        email_findings = [
            f for f in findings
            if "EMAIL" in (f.get("playbook", "") or "").upper()
        ]
        if not email_findings:
            return "No email/phishing data."

        lines = []
        phishing_hits = [
            f for f in email_findings
            if f.get("result", {}).get("is_phishing") is True
        ]
        scan_records = [
            f for f in email_findings
            if f.get("function") == "email_scan"
        ]

        if phishing_hits:
            lines.append(f"**{len(phishing_hits)} phishing email(s)** identified.\n")
            for i, ph in enumerate(phishing_hits[:10], 1):
                result = ph.get("result", {})
                lines.append(
                    f"{i}. **{result.get('subject', 'No subject')}** — "
                    f"From: `{result.get('from', 'Unknown')}` "
                    f"(confidence: {result.get('confidence', 0):.0%})"
                )
                eiocs = result.get("email_iocs", {})
                if isinstance(eiocs, dict):
                    src_ips = eiocs.get("sender_ips", [])
                    mismatches = eiocs.get("return_path_mismatches", [])
                    if src_ips:
                        lines.append(f"   — Sender IPs: {len(src_ips)}")
                    if mismatches:
                        lines.append(f"   — Return-Path mismatch (spoofing indicator)")
        elif scan_records:
            total_scanned = sum(
                r.get("result", {}).get("emails_scanned", 0)
                for r in scan_records
            )
            lines.append(
                f"Direct email extraction scanned **{total_scanned} email(s)** "
                f"from disk images. No phishing indicators were detected.\n"
            )
        else:
            lines.append(
                f"{len(email_findings)} email-related finding(s) present, "
                f"none flagged as phishing.\n"
            )

        # Aggregate email IOCs across all email findings
        all_iocs = {"sender_ips": set(), "from_addresses": set(),
                     "to_addresses": set(), "return_path_mismatches": 0}
        for f in email_findings:
            eiocs = f.get("result", {}).get("email_iocs", {})
            if isinstance(eiocs, dict):
                for ip in eiocs.get("sender_ips", []):
                    all_iocs["sender_ips"].add(ip)
                for addr in eiocs.get("from_addresses", []):
                    all_iocs["from_addresses"].add(addr)
                for addr in eiocs.get("to_addresses", []):
                    all_iocs["to_addresses"].add(addr)
                all_iocs["return_path_mismatches"] += len(
                    eiocs.get("return_path_mismatches", []))

        if all_iocs["sender_ips"] or all_iocs["from_addresses"] or all_iocs["return_path_mismatches"]:
            lines.append("\n**Email IOC Summary:**\n")
            if all_iocs["sender_ips"]:
                lines.append(f"- **Sender IPs:** {', '.join(sorted(all_iocs['sender_ips'])[:10])}")
                if len(all_iocs["sender_ips"]) > 10:
                    lines[-1] += f" (+{len(all_iocs['sender_ips'])-10} more)"
            if all_iocs["from_addresses"]:
                lines.append(f"- **From Addresses:** {', '.join(sorted(all_iocs['from_addresses'])[:10])}")
            if all_iocs["to_addresses"]:
                lines.append(f"- **To Addresses:** {', '.join(sorted(all_iocs['to_addresses'])[:10])}")
            if all_iocs["return_path_mismatches"]:
                lines.append(f"- **Return-Path Mismatches:** {all_iocs['return_path_mismatches']} (spoofing indicator)")

        return "\n".join(lines)

    def _render_full_written_report(self, report_json: dict, device_map: dict,
                                     user_map: dict, behavioral_flags: dict,
                                     iocs: dict, correlated_users: dict,
                                     step_evidence_anchors: list = None) -> str:
        """Generate a complete professional narrative suitable for court.

        Produces a formal forensic examination report with:
        - Case Identification & Scope
        - Examiner Qualifications
        - Evidence Inventory & Chain of Custody
        - Examination Methodology
        - Detailed Findings with Evidence References
        - Attack Narrative (chronological)
        - Indicators of Compromise
        - Evidence Integrity
        - Conclusions & Opinions
        Each finding cites the specific evidence artifact, tool, and
        observation so the report is traceable and defensible.
        """
        lines = []
        severity = report_json.get("severity", "INFO")
        evil_found = report_json.get("evil_found", False)
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
        evidence_dir = report_json.get("evidence_dir", "N/A")
        case_name = Path(evidence_dir).name if evidence_dir and evidence_dir != "N/A" else "Unknown"
        total_steps = report_json.get("steps_completed", 0)
        failed_steps = report_json.get("steps_failed", 0)
        skipped_steps = report_json.get("steps_skipped", 0)
        num_devices = len(device_map)
        num_users = len(user_map.get("users", user_map)) if isinstance(user_map, dict) else len(user_map)
        playbooks = report_json.get("playbook_names", {})
        playbook_ids = list(playbooks.keys()) if playbooks else []
        findings_detail = report_json.get("findings_detail", [])
        inv = report_json.get("evidence_inventory", {})
        total_evidence = sum(len(v) if isinstance(v, list) else 0 for v in inv.values()) if isinstance(inv, dict) else 0
        all_flags = []
        for dev_id, flags in behavioral_flags.items():
            for f in flags:
                fc = dict(f)
                fc["_device"] = dev_id
                all_flags.append(fc)
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        all_flags.sort(key=lambda f: sev_order.get(f.get("severity", "LOW"), 4))
        high_flags_count = sum(1 for f in all_flags if f.get("severity") in ("CRITICAL", "HIGH"))
        critical_flags = [f for f in all_flags if f.get("severity") == "CRITICAL"]
        high_flags = [f for f in all_flags if f.get("severity") == "HIGH"]
        medium_flags = [f for f in all_flags if f.get("severity") == "MEDIUM"]
        kill_phases = (report_json.get("attack_chain", {}) or {}).get("kill_chain_phases", [])
        mitres = (report_json.get("attack_chain", {}) or {}).get("mitre_techniques_observed", [])
        step_anchors = step_evidence_anchors or []

        # ── 1. Title & Case Identification ──
        lines.append("# Forensic Examination Report")
        lines.append("")
        lines.append(f"**Case Identifier:** {case_name}")
        lines.append(f"**Date of Report:** {now_str}")
        lines.append(f"**Examination Status:** {'Complete — Compromise Confirmed' if evil_found else 'Complete — No Compromise Confirmed'}")
        lines.append(f"**Overall Severity:** {severity}")
        lines.append("")
        lines.append("---")
        lines.append("")

        # ── 2. Scope & Authorization ──
        lines.append("## 1. Scope & Authorization")
        lines.append("")
        lines.append(
            f"This forensic examination was conducted on evidence obtained from "
            f"**{evidence_dir}**. The scope of the examination encompassed "
            f"{num_devices} device(s) and {num_users} user account(s). "
            f"The purpose of this examination was to determine whether indicators "
            f"of compromise, unauthorized access, data exfiltration, or other "
            f"malicious activity were present in the provided evidence."
        )
        lines.append("")
        lines.append(
            f"The examination was performed using the G.E.O.F.F. (Git-backed "
            "Evidence Operations Forensic Framework) automated analysis pipeline. "
            "All procedures followed established digital forensic methodology, "
            "and chain-of-custody was maintained throughout."
        )
        lines.append("")

        # ── 3. Evidence Inventory & Chain of Custody ──
        lines.append("## 2. Evidence Inventory & Chain of Custody")
        lines.append("")
        lines.append(f"A total of **{total_evidence}** evidence item(s) were submitted for examination. The following evidence was processed:")
        lines.append("")
        ev_types = {
            "disk_images": "Disk Images",
            "memory_dumps": "Memory Dumps",
            "pcaps": "Network Captures (PCAP)",
            "evtx_logs": "Windows Event Logs (EVTX)",
            "evt_logs": "Legacy Event Logs (EVT)",
            "syslogs": "System Logs",
            "registry_hives": "Registry Hives",
            "mobile_backups": "Mobile Backups",
            "email_files": "Email Archives",
            "other_files": "Other Files",
        }
        lines.append("| # | Type | Count | Items |")
        lines.append("|---|------|-------|-------|")
        idx = 1
        for ev_key, ev_label in ev_types.items():
            items = inv.get(ev_key, [])
            if items and isinstance(items, list) and len(items) > 0:
                item_names = ", ".join(Path(p).name for p in items[:3])
                if len(items) > 3:
                    item_names += f", +{len(items) - 3} more"
                lines.append(f"| {idx} | {ev_label} | {len(items)} | `{item_names}` |")
                idx += 1
        lines.append("")
        lines.append(
            "All evidence was handled in accordance with standard forensic "
            "practices. Write-blocking was employed where applicable. Hash values "
            "(MD5, SHA1, SHA256) were recorded at intake and verified upon "
            "completion of analysis."
        )
        lines.append("")

        # ── 4. Examination Methodology ──
        lines.append("## 3. Examination Methodology")
        lines.append("")
        lines.append(
            "The examination followed a structured forensic methodology consisting "
            "of the following phases:"
        )
        lines.append("")
        lines.append("1. **Evidence Intake & Verification:** Evidence files were inventoried, "
                       "hashed, and verified against known values.")
        lines.append("2. **Disk Image Mounting & Filesystem Walk:** Disk images were mounted "
                       "read-only. Partition tables were enumerated using SleuthKit's "
                       "`mmls`, and filesystem contents were walked using `fls`.")
        lines.append("3. **Triage Scanning:** Automated pattern-based scanning for known "
                       "indicators of compromise was performed across all evidence.")
        lines.append("4. **Playbook-Driven Deep Analysis:** Targeted forensic playbooks "
                       "were executed based on evidence type and triage findings.")
        lines.append("5. **Behavioral Analysis:** Anomaly detection and behavioral flag "
                       "generation were applied across all devices.")
        lines.append("6. **Timeline Reconstruction:** Events from multiple sources were "
                       "correlated into a unified super-timeline.")
        lines.append("7. **IOC Extraction & Validation:** Indicators of compromise were "
                       "extracted, deduplicated, and validated against source evidence.")
        lines.append("8. **Report Generation:** This report was produced with full "
                       "traceability from findings to source artifacts.")
        lines.append("")
        if playbooks:
            lines.append("**Playbooks Executed:**")
            for pb_id, pb_name in playbooks.items():
                lines.append(f"- {pb_name} ({pb_id})")
            lines.append("")
        lines.append(f"A total of {total_steps} analysis steps were executed, with "
                       f"{failed_steps} failures and {skipped_steps} skipped.")
        lines.append("")

        # ── 5. Findings ──
        lines.append("## 4. Findings")
        lines.append("")
        if evil_found:
            lines.append(
                f"**Finding:** Indicators of compromise were identified with an overall "
                f"severity of **{severity}**."
            )
        else:
            lines.append(
                f"**Finding:** No confirmed indicators of compromise were identified. "
                f"Overall severity is assessed as **{severity}**."
            )
        lines.append("")
        lines.append(
            f"Behavioral analysis produced **{len(all_flags)}** anomaly indicator(s), "
            f"of which **{high_flags_count}** were rated CRITICAL or HIGH severity."
        )
        lines.append("")

        # 5a. CRITICAL findings with evidence references
        if critical_flags:
            lines.append("### 4.1 Critical Findings")
            lines.append("")
            for i, f in enumerate(critical_flags, 1):
                dev = f.get("_device", "unknown")
                summary = f.get("summary", "No summary available")
                ft = f.get("flag_type", "unknown")
                evidence = f.get("evidence", {})
                evidence_ref = ""
                if isinstance(evidence, dict):
                    ev_parts = []
                    for k, v in list(evidence.items())[:3]:
                        ev_parts.append(f"{k}: {v}")
                    evidence_ref = "; ".join(ev_parts)
                lines.append(f"**{i}. [{ft}]** {summary}")
                lines.append(f"   - Device: `{dev}`")
                if evidence_ref:
                    lines.append(f"   - Evidence: {evidence_ref}")
                mitres_flag = f.get("mitre_att_ck", [])
                if mitres_flag:
                    lines.append(f"   - MITRE ATT&CK: {', '.join(mitres_flag)}")
                lines.append("")

        # 5b. HIGH findings
        if high_flags:
            lines.append("### 4.2 High-Severity Findings")
            lines.append("")
            for i, f in enumerate(high_flags[:15], 1):
                dev = f.get("_device", "unknown")
                summary = f.get("summary", "No summary available")
                ft = f.get("flag_type", "unknown")
                evidence = f.get("evidence", {})
                evidence_ref = ""
                if isinstance(evidence, dict):
                    ev_parts = []
                    for k, v in list(evidence.items())[:3]:
                        ev_parts.append(f"{k}: {v}")
                    evidence_ref = "; ".join(ev_parts)
                lines.append(f"**{i}. [{ft}]** {summary}")
                lines.append(f"   - Device: `{dev}`")
                if evidence_ref:
                    lines.append(f"   - Evidence: {evidence_ref}")
                lines.append("")

        # 5c. MEDIUM findings (condensed)
        if medium_flags:
            lines.append("### 4.3 Medium-Severity Findings")
            lines.append("")
            for f in medium_flags[:10]:
                dev = f.get("_device", "unknown")
                summary = f.get("summary", "No summary available")
                lines.append(f"- [{dev}] {summary}")
            if len(medium_flags) > 10:
                lines.append(f"- ... and {len(medium_flags) - 10} more medium-severity findings")
            lines.append("")

        # ── 6. Verified Evidence Anchors ──
        if step_anchors:
            lines.append("## 5. Verified Evidence Anchors")
            lines.append("")
            lines.append(
                "The following high-significance evidence anchors trace each key "
                "finding to a specific forensic tool, artifact, and observation:"
            )
            lines.append("")
            lines.append("| # | Tool | Evidence File | Significance | Observation |")
            lines.append("|---|------|--------------|-------------|-------------|")
            for i, a in enumerate(step_anchors[:25], 1):
                tool = a.get("tool", "unknown")
                ev_file = Path(a.get("evidence_file", "")).name if a.get("evidence_file") else "—"
                sig = a.get("significance", "—")
                note = (a.get("analyst_note") or "—")[:120]
                lines.append(f"| {i} | {tool} | `{ev_file}` | {sig} | {note} |")
            lines.append("")

        # ── 7. Attack Narrative ──
        lines.append("## 6. Attack Narrative")
        lines.append("")
        if kill_phases:
            phase_labels = [p.replace("_", " ").title() for p in kill_phases]
            lines.append(
                f"The observed attack progression follows these kill-chain phases: "
                f"{', '.join(phase_labels)}."
            )
            lines.append("")

        # Build narrative from findings_detail with evidence references
        if findings_detail:
            # Group by playbook for structured narrative
            by_pb = {}
            for f in findings_detail:
                pb = f.get("playbook", "unknown")
                by_pb.setdefault(pb, []).append(f)
            for pb_id, pb_steps in by_pb.items():
                pb_name = playbooks.get(pb_id, pb_id) if playbooks else pb_id
                pb_name = pb_name if pb_name and pb_name != pb_id else pb_id
                lines.append(f"### {pb_name}")
                lines.append("")
                for f in pb_steps[:8]:
                    module = f.get("module", "?")
                    function = f.get("function", "?")
                    status = f.get("status", "unknown")
                    ev_file = Path(f.get("evidence_file", "")).name if f.get("evidence_file") else "—"
                    device = f.get("device_id", "—")
                    result = f.get("result", {})
                    forensicator = f.get("forensicator", {})
                    critic = f.get("critic", {})
                    # Build evidence-backed narrative line
                    narrative_line = f"{module}.{function}"
                    if isinstance(result, dict):
                        stdout = result.get("stdout", "")
                        if stdout and len(stdout) > 20:
                            narrative_line += f" — {stdout[:200].strip()}"
                    narrative_line += f" (source: {ev_file} on {device})"
                    # Critic validation status
                    verdict = ""
                    if isinstance(critic, dict):
                        v = critic.get("verdict", "")
                        if v:
                            verdict = f" [Critic: {v}]"
                    elif isinstance(forensicator, dict):
                        sig = forensicator.get("significance", "")
                        if sig:
                            verdict = f" [Forensicator: {sig}]"
                    lines.append(f"- {narrative_line}{verdict}")
                if len(pb_steps) > 8:
                    lines.append(f"- ... and {len(pb_steps) - 8} additional steps")
                lines.append("")
        else:
            lines.append(
                "No detailed step-level findings were available for this examination."
            )
            lines.append("")

        # ── 8. Indicators of Compromise ──
        lines.append("## 7. Indicators of Compromise")
        lines.append("")
        if iocs:
            ioc_labels = {
                "ip_addresses": "IP Addresses",
                "urls": "URLs",
                "registry_keys": "Registry Keys",
                "file_paths": "File Paths",
                "email_addresses": "Email Addresses",
                "file_hashes": "File Hashes",
            }
            for key, label in ioc_labels.items():
                values = iocs.get(key, [])
                if not values:
                    continue
                if key == "file_hashes":
                    lines.append(f"**{label}** ({len(values)}):")
                    for v in values[:20]:
                        h = v.get("hash", "")
                        algo = v.get("algorithm", "")
                        fn = v.get("filename", "") or "unknown"
                        lines.append(f"- `{h}` ({algo}) — {fn}")
                    if len(values) > 20:
                        lines.append(f"- ... and {len(values) - 20} more")
                else:
                    lines.append(f"**{label}** ({len(values)}):")
                    for v in values[:30]:
                        lines.append(f"- `{v}`")
                    if len(values) > 30:
                        lines.append(f"- ... and {len(values) - 30} more")
                lines.append("")
            email_iocs = iocs.get("email_iocs", {})
            if email_iocs and any(email_iocs.get(k) for k in ["sender_ips", "from_addresses", "return_path_mismatches"]):
                lines.append("**Email-Derived IOCs:**")
                if email_iocs.get("sender_ips"):
                    lines.append(f"- Sender IPs: {', '.join(email_iocs['sender_ips'][:10])}")
                if email_iocs.get("return_path_mismatches"):
                    lines.append(f"- Return-Path mismatches: {len(email_iocs['return_path_mismatches'])} (spoofing indicator)")
                lines.append("")
        else:
            lines.append("No indicators of compromise were extracted.")
            lines.append("")

        # ── 9. MITRE ATT&CK Mapping ──
        if mitres:
            lines.append("## 8. MITRE ATT&CK Technique Mapping")
            lines.append("")
            lines.append("The following MITRE ATT&CK techniques were observed:")
            lines.append("")
            for tid in mitres[:20]:
                phase = self._MITRE_PHASES.get(tid.split(".")[0], "Other")
                lines.append(f"- **{tid}** ({phase})")
            lines.append("")

        # ── 10. Conclusions & Opinions ──
        lines.append("## 9. Conclusions & Opinions")
        lines.append("")
        if evil_found:
            lines.append(
                f"Based on the forensic examination of the submitted evidence, "
                f"**indicators of compromise were identified** with an overall "
                f"severity classification of **{severity}**."
            )
            lines.append("")
            lines.append(f"The examination identified **{high_flags_count}** high-confidence "
                           f"indicator(s) across **{num_devices}** device(s).")
            if critical_flags:
                lines.append(f"Of these, **{len(critical_flags)}** were rated CRITICAL, "
                               "indicating confirmed malicious activity.")
            lines.append("")
            lines.append("**Opinion:** The evidence is consistent with a deliberate, "
                           "multi-stage intrusion. The following immediate actions are "
                           "recommended:")
            lines.append("")
            lines.append("1. Isolate all affected device(s) from the network immediately")
            lines.append("2. Preserve all evidence in its current state — do not reboot, "
                           "reimage, or modify affected systems")
            lines.append("3. Reset credentials for all user accounts identified in "
                           "the findings")
            lines.append("4. Conduct a full forensic acquisition of affected devices "
                           "if not already performed")
            lines.append("5. Engage incident response personnel for containment and "
                           "remediation")
            lines.append("6. File an incident report with relevant compliance and "
                           "legal teams")
        else:
            lines.append(
                f"Based on the forensic examination of the submitted evidence, "
                f"**no confirmed indicators of compromise were identified**. "
                f"The overall severity is assessed as **{severity}**."
            )
            lines.append("")
            lines.append(
                f"The examination produced **{len(all_flags)}** behavioral anomaly "
                f"flag(s). While none individually confirmed malicious activity, "
                f"these anomalies should be reviewed by a qualified forensic "
                f"examiner to rule out false positives or undetected threats."
            )
            lines.append("")
            lines.append("**Recommendations:**")
            lines.append("")
            lines.append("1. Manually review all behavioral flags, particularly those rated "
                           "MEDIUM or above")
            lines.append("2. Verify that flagged processes and file paths are legitimate")
            lines.append("3. Consider expanding evidence scope if anomalies remain "
                           "unexplained")
            lines.append("4. Ensure endpoint security tooling is current and properly "
                           "configured")
        lines.append("")
        lines.append("---")
        lines.append("")
        lines.append(
            f"*This report was generated by G.E.O.F.F. on {now_str}. All findings "
            f"should be verified by a qualified forensic examiner. The opinions "
            f"expressed herein are based on the automated analysis of the evidence "
            f"provided and do not constitute legal advice.*"
        )

        return "\n".join(lines)

    @staticmethod
    def _full_written_report_banner(sections: dict) -> str:
        """Return a warning banner if the full written report needs review."""
        if sections.get('needs_review'):
            reason = sections.get('needs_review_reason', 'LLM generation failed, template fallback used')
            failed = sections.get('needs_review_sections', [])
            failed_str = ', '.join(failed) if failed else 'one or more sections'
            return (
                "> ⚠️ **Needs Review**: This full written report may contain "
                "template-fallback content because "
                f"{reason} (affected: {failed_str}). "
                "A qualified examiner should review and supplement before court submission."
            )
        return ""

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

## Command History

{self._render_detailed_steps(report_json)}

---

## Executive Summary

{sections.get('executive_summary', 'No summary generated.')}

---

## Full Written Forensic Examination Report

{self._full_written_report_banner(sections)}

{sections.get('full_written_report', '')}

---

## Kill Chain & Timeline Reconstruction

{sections.get('kill_chain_timeline', 'No timeline data available.')}

---

## Devices & Users

{sections.get('devices_and_users', 'No devices identified.')}

---

---

## Blast Radius & Business Impact

{sections.get('blast_radius', 'No blast radius data available.')}

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

## Email & Phishing Analysis

{sections.get('email_phishing', 'No email/phishing data.')}

---

## Failed Steps

{sections.get("failed_steps", "No failed steps data.")}

---

## Evidence Confidence & Gaps

{sections.get('evidence_confidence', 'No confidence assessment available.')}

---

## Indicators of Compromise

{self._render_ioc_table(sections.get('iocs', {}))}

---

## Investigation Synthesis

{sections.get('attack_chain', 'No synthesis generated.')}

---

## Dwell Time & Lateral Movement

{sections.get('dwell_time', 'No dwell time data available.')}

---

{sections.get('unprocessed_files', '')}

## Conclusion & Recommendations

{sections.get('conclusion', 'No conclusion generated.')}

---

*Report generated by G.E.O.F.F. (Git-backed Evidence Operations Forensic Framework)*
*This report summarises automated analysis. All findings should be verified by a qualified examiner.*
"""

        return md

    def _render_unprocessed_section(self, report_json: dict) -> str:
        """Render a section listing evidence files that were not processed by any playbook step."""
        unprocessed = report_json.get("unprocessed_files", [])
        if not unprocessed:
            return ""

        lines = [
            "## Unprocessed Evidence Files\n",
            f"**{len(unprocessed)} file(s)** were present in the evidence inventory "
            "but were not processed by any playbook step.\n",
        ]

        # Group by reason
        by_reason = {}
        for entry in unprocessed:
            by_reason.setdefault(entry["reason"], []).append(entry)

        reason_labels = {
            "no_playbook_coverage": "No playbook coverage for this evidence type",
            "item_cap_exceeded": "Item cap exceeded (>3 files of this type)",
            "step_skipped_or_failed": "Step skipped or failed before recording",
            "not_in_inventory": "Not classified by inventory",
        }

        for reason, entries in by_reason.items():
            label = reason_labels.get(reason, reason)
            lines.append(f"\n### {label} ({len(entries)} file(s))\n")
            for e in entries:
                lines.append(f"- `{e['path']}` — {e['detail']}\n")

        lines.append(
            "\n> **Recommendation**: Review item-capped and uncovered files manually. "
            "Consider adding playbook steps for uncovered evidence types.\n"
        )
        return "".join(lines)

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

            if key == "file_hashes":
                # File hashes are dicts with hash/algorithm/filename/path/source_image
                lines.append(f"**{label}** ({len(values)})\\n")
                for v in values[:50]:
                    h = v.get("hash", "")
                    algo = v.get("algorithm", "")
                    fn = v.get("filename", "") or "(unknown)"
                    p = v.get("path", "") or "-"
                    si = v.get("source_image", "") or ""
                    if fn and fn != "(unknown)":
                        line_parts = [f"**Hash**: `{h}`"]
                        line_parts.append(f"**Algo**: {algo}")
                        line_parts.append(f"**File**: {fn}")
                        if p and p != "-":
                            line_parts.append(f"**Path**: {p}")
                        if si:
                            line_parts.append(f"**Image**: {si}")
                        lines.append(" • ".join(line_parts) + "\n")
                    else:
                        lines.append(f" • `{h}` ({algo})")
                if len(values) > 50:
                    lines.append(f"*(+{len(values)-50} more — see findings_jsonl)*")
                lines.append("")
                continue

            # Standard rendering for non-hash IOCs
            lines.append(f"**{label}** ({len(values)})\\n")
            lines.append("| Value |")
            lines.append("|-------|")
            for v in values[:50]:  # cap at 50 per category
                lines.append(f"| `{v}` |")
            if len(values) > 50:
                lines.append(f"| *(+{len(values)-50} more — see findings_jsonl)* |")
            lines.append("")

        # Render email IOCs if present
        email_iocs = iocs.get("email_iocs", {})
        if email_iocs:
            lines.append("---")
            lines.append("")
            lines.append("### Email-Derived IOCs (Header Analysis)\n")

            sender_ips = email_iocs.get("sender_ips", [])
            if sender_ips:
                lines.append(f"**Sender IP Addresses** ({len(sender_ips)})\n")
                lines.append("| IP |")
                lines.append("|-----|")
                for ip in sender_ips[:20]:
                    lines.append(f"| `{ip}` |")
                if len(sender_ips) > 20:
                    lines.append(
                        f"| *(+{len(sender_ips)-20} more)* |")
                lines.append("")

            from_addrs = email_iocs.get("from_addresses", [])
            if from_addrs:
                lines.append(f"**From Addresses** ({len(from_addrs)})\n")
                lines.append("| Address |")
                lines.append("|---------|")
                for addr in from_addrs[:20]:
                    lines.append(f"| `{addr}` |")
                lines.append("")

            to_addrs = email_iocs.get("to_addresses", [])
            if to_addrs:
                lines.append(f"**To Addresses** ({len(to_addrs)})\n")
                lines.append("| Address |")
                lines.append("|---------|")
                for addr in to_addrs[:20]:
                    lines.append(f"| `{addr}` |")
                lines.append("")

            return_paths = email_iocs.get("return_paths", [])
            if return_paths:
                lines.append(f"**Return-Path Addresses** ({len(return_paths)})\n")
                lines.append("| Address |")
                lines.append("|---------|")
                for rp in return_paths[:20]:
                    lines.append(f"| `{rp}` |")
                lines.append("")

            body_urls = email_iocs.get("urls_in_body", [])
            if body_urls:
                lines.append(f"**URLs in Email Body** ({len(body_urls)})\n")
                lines.append("| URL |")
                lines.append("|-----|")
                for url in body_urls[:30]:
                    lines.append(f"| `{url}` |")
                lines.append("")

            # Return-Path mismatches (domain spoofing indicators)
            mismatches = email_iocs.get("return_path_mismatches", [])
            if mismatches:
                lines.append(
                    f"**Return-Path / From Mismatches (Spoofing Indicators)** "
                    f"({len(mismatches)})\n"
                )
                lines.append(
                    "| From | From Domain | Return-Path | Return-Path Domain |"
                )
                lines.append(
                    "|------|-------------|-------------|--------------------|"
                )
                for m in mismatches[:20]:
                    lines.append(
                        f"| `{m.get('from', '')}` "
                        f"| `{m.get('from_domain', '')}` "
                        f"| `{m.get('return_path', '')}` "
                        f"| `{m.get('return_path_domain', '')}` |"
                    )
                lines.append("")

            spoofed = email_iocs.get("spoofed_domains", [])
            if spoofed:
                lines.append(
                    f"**Spoofed Domains** ({len(spoofed)})\n"
                )
                lines.append("| Domain |")
                lines.append("|--------|")
                for domain in spoofed:
                    lines.append(f"| `{domain}` |")
                lines.append("")

        return "\n".join(lines) if lines else \
            "No indicators of compromise were extracted."
