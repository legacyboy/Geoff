#!/usr/bin/env python3
"""
Geoff DFIR — Gap fills & novel features
Gap 3:  DNS_Specialist        — DNS forensics, DGA detection, tunneling detection
Gap 4:  YARA_Specialist       — YARA rule scanning
Gap 5:  HASH_Specialist       — file hashing, NSRL lookup
Novel 1: GeoffCriticPool      — dual-critic with confidence voting
Novel 2: AdaptivePlaybook     — compose investigation from unmatched findings
Novel 3: ConfidenceCalibrator — track critic agreement for per-finding confidence
Novel 4: ProvenanceDAG        — evidence derivation graph
Novel 5: AdaptivePass2        — intelligence-driven Pass 2 triggering
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import shutil
import subprocess
import tempfile
import threading
import urllib.request
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    from geoff_chain_of_custody import ChainOfCustodyLog as _ChainOfCustodyLog
except ImportError:
    _ChainOfCustodyLog = None

# ---------------------------------------------------------------------------
# Gap 3: DNS Forensics Specialist
# ---------------------------------------------------------------------------

class DNS_Specialist:
    """DNS forensics: query/response analysis, DGA detection, tunneling detection."""

    # Known benign TLDs and public resolvers (noise filter)
    _BENIGN_RESOLVERS = frozenset(['8.8.8.8', '8.8.4.4', '1.1.1.1', '9.9.9.9',
                                    '208.67.222.222', '208.67.220.220'])

    # iodine/dnscat2 subdomain length / entropy thresholds
    _TUNNEL_SUBDOMAIN_MIN_LEN = 20
    _TUNNEL_ENTROPY_THRESHOLD = 3.8

    # DGA entropy threshold (high-entropy = likely DGA)
    _DGA_ENTROPY_THRESHOLD = 3.5
    _DGA_MIN_LABEL_LEN = 8

    def _shannon_entropy(self, s: str) -> float:
        if not s:
            return 0.0
        freq = defaultdict(int)
        for c in s:
            freq[c] += 1
        n = len(s)
        return -sum((v / n) * math.log2(v / n) for v in freq.values() if v > 0)

    def _extract_dns_from_pcap(self, pcap_file: str) -> Dict[str, Any]:
        """Use tshark to extract DNS queries/responses from a pcap."""
        tshark = shutil.which('tshark')
        if not tshark:
            return {'error': 'tshark not found', 'queries': [], 'responses': []}
        try:
            r = subprocess.run(
                [tshark, '-r', pcap_file, '-Y', 'dns', '-T', 'fields',
                 '-e', 'frame.time_epoch', '-e', 'ip.src', '-e', 'ip.dst',
                 '-e', 'dns.qry.name', '-e', 'dns.resp.name',
                 '-e', 'dns.qry.type', '-e', 'dns.flags.response',
                 '-e', 'dns.a', '-e', 'dns.cname',
                 '-E', 'separator=|', '-E', 'header=n'],
                capture_output=True, text=True, timeout=300
            )
            queries, responses = [], []
            for line in r.stdout.splitlines():
                parts = line.split('|')
                if len(parts) < 8:
                    continue
                ts, src, dst, qname, rname, qtype, is_resp, answer_a, answer_cname = (parts + [''] * 9)[:9]
                entry = {
                    'timestamp': ts.strip(), 'src': src.strip(), 'dst': dst.strip(),
                    'name': (rname.strip() or qname.strip()), 'qtype': qtype.strip(),
                    'answer_a': answer_a.strip(), 'answer_cname': answer_cname.strip(),
                }
                if is_resp.strip() == '1':
                    responses.append(entry)
                else:
                    queries.append(entry)
            return {'queries': queries, 'responses': responses}
        except Exception as e:
            return {'error': str(e), 'queries': [], 'responses': []}

    def _score_dga(self, domain: str) -> Dict[str, Any]:
        """Score a domain for DGA characteristics."""
        labels = domain.rstrip('.').split('.')
        if not labels:
            return {'is_dga': False, 'score': 0.0}
        label = labels[0]
        entropy = self._shannon_entropy(label)
        consonant_run = len(re.findall(r'[bcdfghjklmnpqrstvwxyz]{4,}', label, re.I))
        digit_run = len(re.findall(r'\d{3,}', label))
        score = (
            (entropy / 5.0) * 0.5 +
            min(consonant_run * 0.15, 0.3) +
            min(digit_run * 0.1, 0.2)
        )
        is_dga = (entropy >= self._DGA_ENTROPY_THRESHOLD and len(label) >= self._DGA_MIN_LABEL_LEN)
        return {
            'domain': domain, 'label': label, 'entropy': round(entropy, 3),
            'score': round(score, 3), 'is_dga': is_dga,
            'consonant_runs': consonant_run, 'digit_runs': digit_run,
        }

    def _detect_tunneling(self, queries: List[Dict]) -> List[Dict]:
        """Detect potential DNS tunneling (iodine/dnscat2 patterns)."""
        suspicious = []
        domain_counts: Dict[str, int] = defaultdict(int)
        for q in queries:
            name = q.get('name', '')
            if not name:
                continue
            labels = name.rstrip('.').split('.')
            # Check for very long subdomains (iodine uses base32/base64 encoding)
            if labels and len(labels[0]) >= self._TUNNEL_SUBDOMAIN_MIN_LEN:
                entropy = self._shannon_entropy(labels[0])
                if entropy >= self._TUNNEL_ENTROPY_THRESHOLD:
                    suspicious.append({
                        **q,
                        'tunnel_indicator': 'long_encoded_subdomain',
                        'subdomain_len': len(labels[0]),
                        'entropy': round(entropy, 3),
                    })
            # dnscat2: many queries to same base domain
            if len(labels) >= 2:
                base = '.'.join(labels[-2:])
                domain_counts[base] += 1

        # Flag domains with unusually high query volume
        for base, count in domain_counts.items():
            if count > 50:
                suspicious.append({
                    'name': base, 'tunnel_indicator': 'high_query_volume',
                    'query_count': count,
                })
        return suspicious

    def analyze_dns_from_pcap(self, pcap_file: str) -> Dict[str, Any]:
        """Full DNS forensic analysis of a pcap."""
        raw = self._extract_dns_from_pcap(pcap_file)
        queries = raw.get('queries', [])
        responses = raw.get('responses', [])

        # DGA scoring
        unique_domains = {q.get('name', '') for q in queries if q.get('name')}
        dga_results = [self._score_dga(d) for d in unique_domains if d]
        dga_suspects = [r for r in dga_results if r['is_dga']]

        # Tunneling detection
        tunnel_suspects = self._detect_tunneling(queries)

        # NX domain ratio (high NXDOMAIN = beaconing / DGA)
        nx_domains = [r for r in responses if 'NXDOMAIN' in str(r)]

        return {
            'tool': 'dns_specialist', 'status': 'success',
            'pcap_file': pcap_file,
            'query_count': len(queries),
            'response_count': len(responses),
            'unique_domains': len(unique_domains),
            'dga_suspects': dga_suspects[:50],
            'dga_suspect_count': len(dga_suspects),
            'tunnel_suspects': tunnel_suspects[:50],
            'tunnel_suspect_count': len(tunnel_suspects),
            'nxdomain_count': len(nx_domains),
            'all_queries': queries[:200],
            'error': raw.get('error'),
            'timestamp': datetime.now().isoformat(),
        }

    def score_domain_dga(self, domain: str) -> Dict[str, Any]:
        """Score a single domain for DGA likelihood."""
        result = self._score_dga(domain)
        result['tool'] = 'dns_specialist'
        result['status'] = 'success'
        result['timestamp'] = datetime.now().isoformat()
        return result

    def detect_tunneling(self, pcap_file: str) -> Dict[str, Any]:
        """Focused DNS tunneling detection scan."""
        raw = self._extract_dns_from_pcap(pcap_file)
        suspects = self._detect_tunneling(raw.get('queries', []))
        return {
            'tool': 'dns_specialist', 'status': 'success',
            'pcap_file': pcap_file,
            'tunnel_suspects': suspects,
            'tunnel_suspect_count': len(suspects),
            'timestamp': datetime.now().isoformat(),
        }


# ---------------------------------------------------------------------------
# Gap 4: YARA Specialist
# ---------------------------------------------------------------------------

# Minimal built-in YARA rules for common forensic patterns
_BUILTIN_YARA_RULES = r"""
rule Suspicious_PE_Overlay {
    meta: description = "PE file with large overlay (common packer/dropper pattern)"
    strings:
        $mz = { 4D 5A }
    condition:
        $mz at 0 and filesize > 500KB and (filesize - uint32(uint32(0x3C) + 0x50)) > 100KB
}

rule Base64_PowerShell_Encoded {
    meta: description = "Base64-encoded PowerShell command"
    strings:
        $enc1 = "-EncodedCommand" nocase
        $enc2 = "FromBase64String" nocase
        $enc3 = "JAB" // common PowerShell base64 prefix
        $enc4 = "JABW" nocase
    condition:
        any of them
}

rule Ransomware_Note_Keywords {
    meta: description = "Common ransomware note keywords"
    strings:
        $r1 = "YOUR FILES HAVE BEEN ENCRYPTED" nocase
        $r2 = "bitcoin" nocase
        $r3 = "decrypt" nocase
        $r4 = "ransom" nocase
        $r5 = ".onion" nocase
    condition:
        3 of them
}

rule Credential_Dumping_Strings {
    meta: description = "Strings associated with credential dumping tools"
    strings:
        $s1 = "sekurlsa" nocase
        $s2 = "lsadump" nocase
        $s3 = "mimikatz" nocase
        $s4 = "wdigest" nocase
        $s5 = "kerberos" nocase
        $s6 = "sam dump" nocase
    condition:
        2 of them
}

rule Webshell_Keywords {
    meta: description = "Common web shell keywords"
    strings:
        $w1 = "eval(base64_decode" nocase
        $w2 = "system($_" nocase
        $w3 = "passthru($_" nocase
        $w4 = "shell_exec(" nocase
        $w5 = "cmd.exe /c" nocase
    condition:
        any of them
}
"""
