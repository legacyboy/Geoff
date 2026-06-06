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

class AdaptivePass2:
    """
    Intelligence-driven Pass 2: analyze Pass 1 findings, score playbooks,
    and return a prioritized list of Pass 2 playbooks to run.
    """

    # Scoring rules: finding attribute → (pass2_playbook_id, score_delta)
    _RULES: List[Tuple[str, str, float]] = [
        # keyword in finding text             playbook          score
        ('process chain',                    'PB-SIFT-100',    3.0),
        ('parent.*child',                    'PB-SIFT-100',    2.5),
        ('lateral movement',                 'PB-SIFT-101',    3.0),
        ('usb',                              'PB-SIFT-101',    2.0),
        ('removable',                        'PB-SIFT-101',    1.5),
        ('timestamp.*anomaly',               'PB-SIFT-102',    3.0),
        ('clock.*skew',                      'PB-SIFT-102',    2.0),
        ('ioc.*match',                       'PB-SIFT-103',    2.5),
        ('hash.*correlation',                'PB-SIFT-103',    2.0),
        ('dwell',                            'PB-SIFT-104',    3.0),
        ('persistence',                      'PB-SIFT-104',    1.5),
        ('long.*dwell',                      'PB-SIFT-104',    2.0),
    ]

    # Severity boost: HIGH/CRITICAL findings get a score multiplier
    _SEVERITY_BOOST = {'CRITICAL': 2.0, 'HIGH': 1.5, 'MEDIUM': 1.0, 'LOW': 0.5}

    def score_pass2_playbooks(self, pass1_findings: List[Dict]) -> Dict[str, float]:
        """Score all Pass 2 playbooks based on Pass 1 findings."""
        scores: Dict[str, float] = defaultdict(float)
        for finding in pass1_findings:
            text = ' '.join([
                str(finding.get('description', '')),
                str(finding.get('summary', '')),
                str(finding.get('finding', '')),
                str(finding.get('analyst_note', '')),
            ]).lower()
            severity = str(finding.get('severity', 'MEDIUM')).upper()
            boost = self._SEVERITY_BOOST.get(severity, 1.0)
            for pattern, playbook_id, delta in self._RULES:
                if re.search(pattern, text):
                    scores[playbook_id] += delta * boost
        return dict(scores)

    def select_pass2_playbooks(self, pass1_findings: List[Dict],
                                min_score: float = 2.0,
                                max_playbooks: int = 3) -> List[Dict[str, Any]]:
        """
        Return a prioritized list of Pass 2 playbooks to run.
        Each entry: {'playbook_id': str, 'score': float, 'rationale': str}
        """
        scores = self.score_pass2_playbooks(pass1_findings)
        sorted_pbs = sorted(scores.items(), key=lambda x: x[1], reverse=True)
        selected = []
        for pb_id, score in sorted_pbs:
            if score < min_score:
                break
            if len(selected) >= max_playbooks:
                break
            # Build rationale from matching findings
            matching = [f for f in pass1_findings if any(
                re.search(pat, ' '.join([str(f.get(k, '')) for k in
                          ('description', 'summary', 'finding', 'analyst_note')]).lower())
                for pat, pid, _ in self._RULES if pid == pb_id
            )]
            selected.append({
                'playbook_id': pb_id,
                'score': round(score, 2),
                'finding_count': len(matching),
                'rationale': f'{len(matching)} matching finding(s) triggered {pb_id}',
                'sample_findings': [f.get('summary', f.get('description', ''))[:80]
                                    for f in matching[:3]],
            })
        return selected

    def should_run_pass2(self, pass1_findings: List[Dict], threshold: float = 2.0) -> bool:
        """Quick check whether any Pass 2 playbook meets the threshold."""
        scores = self.score_pass2_playbooks(pass1_findings)
        return any(s >= threshold for s in scores.values())


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------
