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

class AdaptivePlaybook:
    """
    Compose new investigation paths when a finding has no matching playbook.
    The Manager calls compose_for_finding() to get a list of (module, function, params)
    tuples that best cover the unmatched finding.
    """

    # Keyword→specialist affinity table
    _AFFINITY: List[Tuple[List[str], str, str, Dict]] = [
        (['dll', 'library', 'module'],    'volatility', 'dll_list',   {}),
        (['handle', 'mutex', 'mutant'],   'volatility', 'mutantscan', {}),
        (['hook', 'api hook', 'patch'],   'volatility', 'apihooks',   {}),
        (['kernel', 'driver', 'rootkit'], 'volatility', 'modscan',    {}),
        (['vad', 'virtual address', 'rwx'], 'volatility', 'vadinfo',  {}),
        (['dns', 'domain', 'dga', 'tunnel'], 'dns', 'analyze_dns_from_pcap', {}),
        (['yara', 'signature', 'rule'],   'yara', 'scan_file',        {}),
        (['hash', 'md5', 'sha1', 'sha256', 'nsrl'], 'hash_correlation', 'hash_file', {}),
        (['process', 'pid', 'pslist'],    'volatility', 'process_list', {}),
        (['network', 'connection', 'socket'], 'volatility', 'network_scan', {}),
        (['inject', 'hollowing', 'malfind'], 'volatility', 'find_malware', {}),
        (['credential', 'password', 'lsass'], 'memory', 'extract_credentials', {}),
        (['registry', 'hive', 'reg'],     'memory', 'extract_registry', {}),
    ]

    def compose_for_finding(self, finding: Dict[str, Any],
                             available_specialists: Dict[str, Any],
                             evidence_context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Given an unmatched finding, select and return candidate investigation steps.
        Returns list of {'module': ..., 'function': ..., 'params': ..., 'rationale': ...}
        """
        finding_text = ' '.join([
            str(finding.get('description', '')),
            str(finding.get('summary', '')),
            str(finding.get('finding', '')),
            str(finding.get('ioc', '')),
            str(finding.get('tool', '')),
        ]).lower()

        selected: List[Dict] = []
        seen: set = set()

        for keywords, module, function, base_params in self._AFFINITY:
            if module not in available_specialists:
                continue
            if any(kw in finding_text for kw in keywords):
                key = f'{module}.{function}'
                if key in seen:
                    continue
                seen.add(key)
                # Inject evidence context into params
                params = dict(base_params)
                if '{mem}' in str(params) or function in ('dll_list', 'handles', 'mutantscan',
                                                           'apihooks', 'modscan', 'vadinfo',
                                                           'find_malware', 'process_list',
                                                           'network_scan'):
                    mem = evidence_context.get('memory_dump', '')
                    if mem:
                        params['memory_dump'] = mem
                    else:
                        continue  # no memory dump available; skip
                if 'pcap' in function or module == 'dns':
                    pcap = evidence_context.get('pcap_file', '')
                    if pcap:
                        params['pcap_file'] = pcap
                    else:
                        continue
                if 'file_path' in str(base_params) or module == 'yara':
                    fpath = evidence_context.get('file_path', evidence_context.get('image', ''))
                    if fpath:
                        params['file_path'] = fpath
                    else:
                        continue

                selected.append({
                    'module': module,
                    'function': function,
                    'params': params,
                    'rationale': f'Adaptive: matched keywords {[k for k in keywords if k in finding_text]}',
                    '_adaptive': True,
                })

        return selected[:5]  # cap at 5 adaptive steps


# ---------------------------------------------------------------------------
# Novel 3: Confidence Calibrator
# ---------------------------------------------------------------------------
