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

class GeoffCriticPool:
    """
    Dual-critic pool: two independent GeoffCritic instances review findings.
    Confidence levels:
      BOTH_APPROVE  → VERY_HIGH
      ONE_APPROVES  → HIGH
      ONE_CHALLENGES → MEDIUM (flag for review)
      BOTH_CHALLENGE → LOW / likely false-positive
    """

    def __init__(self, critic_a=None, critic_b=None):
        # Import here to avoid circular imports
        from geoff_critic import GeoffCritic
        from geoff_config import AGENT_MODELS
        model_b = os.environ.get('GEOFF_CRITIC2_MODEL',
                                 AGENT_MODELS.get('critic2',
                                  os.environ.get('GEOFF_CRITIC_MODEL', 'qwen3.5:cloud')))
        self.critic_a = critic_a or GeoffCritic()
        self.critic_b = critic_b or GeoffCritic(model=model_b)
        self._lock = threading.Lock()
        self.agreement_log: List[Dict] = []

    def dual_validate(self, tool_name: str, tool_params: Dict,
                      raw_output: str, geoff_analysis: str) -> Dict[str, Any]:
        """Run both critics in parallel and merge results."""
        results: Dict[str, Any] = {}

        def run_critic(name: str, critic, out_dict: Dict):
            try:
                out_dict[name] = critic.validate_tool_output(
                    tool_name, tool_params, raw_output, geoff_analysis)
            except Exception as e:
                out_dict[name] = {'verdict': 'ERROR', 'error': str(e)}

        threads = [
            threading.Thread(target=run_critic, args=('a', self.critic_a, results)),
            threading.Thread(target=run_critic, args=('b', self.critic_b, results)),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=660)

        va = results.get('a', {})
        vb = results.get('b', {})
        verdict_a = va.get('verdict', 'UNKNOWN')
        verdict_b = vb.get('verdict', 'UNKNOWN')

        # Compute pool verdict and confidence
        if verdict_a == 'APPROVED' and verdict_b == 'APPROVED':
            pool_verdict = 'APPROVED'
            confidence = 'VERY_HIGH'
        elif verdict_a == 'APPROVED' or verdict_b == 'APPROVED':
            pool_verdict = 'APPROVED'
            confidence = 'HIGH'
            if verdict_a != verdict_b:
                confidence = 'MEDIUM'
        elif verdict_a == 'REQUIRES_REVIEW' or verdict_b == 'REQUIRES_REVIEW':
            pool_verdict = 'REQUIRES_REVIEW'
            confidence = 'MEDIUM'
        else:
            pool_verdict = 'REJECTED'
            confidence = 'LOW'

        merged = {
            'tool': 'critic_pool',
            'pool_verdict': pool_verdict,
            'confidence': confidence,
            'critic_a_verdict': verdict_a,
            'critic_b_verdict': verdict_b,
            'critic_a_result': va,
            'critic_b_result': vb,
            'critics_agree': verdict_a == verdict_b,
            'needs_review': confidence in ('MEDIUM', 'LOW') or pool_verdict == 'REQUIRES_REVIEW',
            'timestamp': datetime.now().isoformat(),
        }

        # Record for calibration
        with self._lock:
            self.agreement_log.append({
                'tool_name': tool_name,
                'verdict_a': verdict_a,
                'verdict_b': verdict_b,
                'pool_verdict': pool_verdict,
                'confidence': confidence,
                'ts': merged['timestamp'],
            })

        return merged

    def get_agreement_stats(self) -> Dict[str, Any]:
        """Return agreement statistics across all validations."""
        log = list(self.agreement_log)
        total = len(log)
        if not total:
            return {'total': 0}
        agree = sum(1 for e in log if e['verdict_a'] == e['verdict_b'])
        very_high = sum(1 for e in log if e['confidence'] == 'VERY_HIGH')
        high = sum(1 for e in log if e['confidence'] == 'HIGH')
        medium = sum(1 for e in log if e['confidence'] == 'MEDIUM')
        low = sum(1 for e in log if e['confidence'] == 'LOW')
        return {
            'total': total, 'agreement_rate': round(agree / total, 3),
            'VERY_HIGH': very_high, 'HIGH': high, 'MEDIUM': medium, 'LOW': low,
        }


# ---------------------------------------------------------------------------
# Novel 2: Adaptive Playbook Generation
# ---------------------------------------------------------------------------
