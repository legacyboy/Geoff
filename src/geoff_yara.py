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

class YARA_Specialist:
    """YARA rule scanning for disk images, memory dumps, and extracted files."""

    def __init__(self):
        self.yara_available = shutil.which('yara') is not None
        self._rules_file = self._write_builtin_rules()

    def _write_builtin_rules(self) -> Optional[str]:
        try:
            rules_dir = Path('/tmp/geoff_yara_rules')
            rules_dir.mkdir(exist_ok=True)
            rules_path = rules_dir / 'builtin.yar'
            rules_path.write_text(_BUILTIN_YARA_RULES)
            return str(rules_path)
        except Exception:
            return None

    def _run_yara(self, rules_file: str, target: str, recursive: bool = False) -> Dict[str, Any]:
        if not self.yara_available:
            return {'error': 'yara binary not found', 'matches': []}
        cmd = ['yara', '-f', rules_file, target]
        if recursive:
            cmd.append('-r')
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            matches = []
            for line in r.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                parts = line.split(' ', 1)
                if len(parts) == 2:
                    matches.append({'rule': parts[0], 'file': parts[1]})
            return {'matches': matches, 'returncode': r.returncode}
        except subprocess.TimeoutExpired:
            return {'error': 'yara timeout', 'matches': []}
        except Exception as e:
            return {'error': str(e), 'matches': []}

    def scan_file(self, file_path: str, rules_path: Optional[str] = None) -> Dict[str, Any]:
        """Scan a single file with YARA rules."""
        rules = rules_path or self._rules_file
        if not rules:
            return {'tool': 'yara', 'status': 'error', 'error': 'No rules file available',
                    'timestamp': datetime.now().isoformat()}
        result = self._run_yara(rules, file_path)
        return {
            'tool': 'yara', 'status': 'success', 'target': file_path,
            'rules_file': rules, 'match_count': len(result.get('matches', [])),
            'matches': result.get('matches', []),
            'error': result.get('error'),
            'timestamp': datetime.now().isoformat(),
        }

    def scan_directory(self, directory: str, rules_path: Optional[str] = None) -> Dict[str, Any]:
        """Recursively scan a directory with YARA rules."""
        rules = rules_path or self._rules_file
        if not rules:
            return {'tool': 'yara', 'status': 'error', 'error': 'No rules file available',
                    'timestamp': datetime.now().isoformat()}
        result = self._run_yara(rules, directory, recursive=True)
        matches = result.get('matches', [])
        # Group by rule
        by_rule: Dict[str, List[str]] = defaultdict(list)
        for m in matches:
            by_rule[m['rule']].append(m['file'])
        return {
            'tool': 'yara', 'status': 'success', 'target': directory,
            'rules_file': rules, 'match_count': len(matches),
            'matches': matches[:200], 'matches_by_rule': dict(by_rule),
            'error': result.get('error'),
            'timestamp': datetime.now().isoformat(),
        }

    def scan_memory_dump(self, memory_dump: str, rules_path: Optional[str] = None) -> Dict[str, Any]:
        """Scan a memory dump with YARA rules."""
        return self.scan_file(memory_dump, rules_path)

    def scan_disk_image(self, image_path: str, rules_path: Optional[str] = None) -> Dict[str, Any]:
        """Scan a disk image with YARA rules (treats as flat file)."""
        return self.scan_file(image_path, rules_path)


# ---------------------------------------------------------------------------
# Gap 5: Hash Specialist (with NSRL lookup)
# ---------------------------------------------------------------------------
