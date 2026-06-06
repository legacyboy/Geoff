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

class HASH_Specialist:
    """File hashing, NSRL lookup for known-file elimination."""

    # NSRL REST service (bloom-filter based, no API key needed)
    _NSRL_URL = 'https://hash.nsrl.nist.gov/api/hash/'

    def hash_file(self, file_path: str) -> Dict[str, Any]:
        """Hash a single file (MD5/SHA1/SHA256) and check NSRL."""
        p = Path(file_path)
        if not p.is_file():
            return {'tool': 'hash_specialist', 'status': 'error',
                    'error': f'File not found: {file_path}',
                    'timestamp': datetime.now().isoformat()}
        try:
            data = p.read_bytes()
            md5 = hashlib.md5(data).hexdigest()
            sha1 = hashlib.sha1(data).hexdigest()
            sha256 = hashlib.sha256(data).hexdigest()
            nsrl = self._nsrl_lookup(sha1)
            return {
                'tool': 'hash_specialist', 'status': 'success',
                'file': file_path, 'size': len(data),
                'md5': md5, 'sha1': sha1, 'sha256': sha256,
                'nsrl': nsrl,
                'timestamp': datetime.now().isoformat(),
            }
        except Exception as e:
            return {'tool': 'hash_specialist', 'status': 'error', 'error': str(e),
                    'file': file_path, 'timestamp': datetime.now().isoformat()}

    def hash_files(self, file_list: List[str]) -> Dict[str, Any]:
        """Hash a list of files and check NSRL."""
        results = []
        nsrl_known, nsrl_unknown, errors = 0, 0, 0
        for f in file_list:
            r = self.hash_file(f)
            results.append(r)
            if r.get('status') == 'error':
                errors += 1
            elif r.get('nsrl', {}).get('in_nsrl'):
                nsrl_known += 1
            else:
                nsrl_unknown += 1
        return {
            'tool': 'hash_specialist', 'status': 'success',
            'file_count': len(file_list),
            'nsrl_known': nsrl_known, 'nsrl_unknown': nsrl_unknown,
            'errors': errors, 'results': results,
            'timestamp': datetime.now().isoformat(),
        }

    def hash_directory(self, directory: str, extensions: Optional[List[str]] = None) -> Dict[str, Any]:
        """Hash all files in a directory (optional extension filter)."""
        d = Path(directory)
        if not d.is_dir():
            return {'tool': 'hash_specialist', 'status': 'error',
                    'error': f'Directory not found: {directory}',
                    'timestamp': datetime.now().isoformat()}
        files = []
        for p in d.rglob('*'):
            if not p.is_file():
                continue
            if extensions and p.suffix.lower() not in extensions:
                continue
            files.append(str(p))
            if len(files) >= 10000:  # cap to prevent runaway
                break
        return self.hash_files(files)

    def _nsrl_lookup(self, sha1: str) -> Dict[str, Any]:
        """Check SHA1 against NSRL hash database (no API key required)."""
        try:
            url = f'{self._NSRL_URL}{sha1.upper()}'
            req = urllib.request.Request(url, headers={'User-Agent': 'Geoff-DFIR/1.0'})
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode())
                in_nsrl = bool(data.get('found') or data.get('in_nsrl'))
                return {'in_nsrl': in_nsrl, 'details': data}
        except Exception as e:
            return {'in_nsrl': None, 'error': str(e), 'note': 'NSRL lookup unavailable'}


# ---------------------------------------------------------------------------
# Novel 1: Dual-Critic Pool
# ---------------------------------------------------------------------------
