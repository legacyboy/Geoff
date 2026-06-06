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

class ConfidenceCalibrator:
    """
    Track Critic/Forensicator agreement patterns and assign per-finding confidence.
    Call record_outcome() after each Critic review, then get_confidence() on a finding.
    """

    VERY_HIGH = 'VERY_HIGH'
    HIGH      = 'HIGH'
    MEDIUM    = 'MEDIUM'
    LOW       = 'LOW'

    def __init__(self, case_work_dir: Optional[str] = None):
        self.case_work_dir = Path(case_work_dir) if case_work_dir else None
        self._records: List[Dict] = []
        self._lock = threading.Lock()

    def record_outcome(self, finding_id: str, critic_verdict: str,
                       forensicator_defended: bool = False,
                       dual_critic_result: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Record a critic review outcome and compute confidence.

        critic_verdict: APPROVED / REQUIRES_REVIEW / REJECTED
        forensicator_defended: True if the Forensicator successfully defended against challenge
        dual_critic_result: output from GeoffCriticPool.dual_validate() if available
        """
        if dual_critic_result:
            # Novel 1 path: use dual-critic confidence directly
            conf = dual_critic_result.get('confidence', self.MEDIUM)
        elif critic_verdict == 'APPROVED':
            conf = self.HIGH
        elif critic_verdict == 'REQUIRES_REVIEW' and forensicator_defended:
            conf = self.MEDIUM
        elif critic_verdict == 'REQUIRES_REVIEW' and not forensicator_defended:
            conf = self.MEDIUM
        elif critic_verdict == 'REJECTED' and forensicator_defended:
            conf = self.MEDIUM
        else:
            conf = self.LOW

        record = {
            'finding_id': finding_id,
            'critic_verdict': critic_verdict,
            'forensicator_defended': forensicator_defended,
            'confidence': conf,
            'dual_critic': bool(dual_critic_result),
            'timestamp': datetime.now().isoformat(),
        }
        with self._lock:
            self._records.append(record)
        self._persist()
        return record

    def get_confidence(self, finding_id: str) -> str:
        """Return calibrated confidence for a finding_id."""
        with self._lock:
            matches = [r for r in self._records if r['finding_id'] == finding_id]
        if not matches:
            return self.MEDIUM
        return matches[-1]['confidence']

    def annotate_findings(self, findings: List[Dict]) -> List[Dict]:
        """Add 'confidence' field to each finding based on recorded outcomes."""
        id_to_conf = {}
        with self._lock:
            for r in self._records:
                id_to_conf[r['finding_id']] = r['confidence']
        annotated = []
        for f in findings:
            fid = f.get('step_key') or f.get('id') or f.get('finding_id')
            conf = id_to_conf.get(fid, self.MEDIUM) if fid else self.MEDIUM
            annotated.append({**f, 'confidence': conf})
        return annotated

    def _persist(self):
        if not self.case_work_dir:
            return
        try:
            path = self.case_work_dir / 'confidence_calibration.json'
            with self._lock:
                data = list(self._records)
            path.write_text(json.dumps(data, indent=2))
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Novel 4: Evidence Provenance DAG
# ---------------------------------------------------------------------------
