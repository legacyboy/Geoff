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

class ProvenanceDAG:
    """
    Directed acyclic graph of evidence derivation.
    Each node: {'id': str, 'type': str, 'path': str, 'metadata': dict}
    Each edge: {'from': id, 'to': id, 'relationship': str}
    """

    def __init__(self, case_work_dir: Optional[str] = None, custody_log=None):
        self.case_work_dir = Path(case_work_dir) if case_work_dir else None
        self._nodes: Dict[str, Dict] = {}
        self._edges: List[Dict] = []
        self._lock = threading.Lock()
        self._custody_log = custody_log

    def add_source(self, source_id: str, source_type: str, path: str,
                   metadata: Optional[Dict] = None) -> str:
        """Register an original evidence source."""
        node = {
            'id': source_id, 'type': source_type, 'path': path,
            'metadata': metadata or {}, 'created': datetime.now().isoformat(),
        }
        with self._lock:
            self._nodes[source_id] = node
        return source_id

    def add_derived(self, derived_id: str, derived_type: str, path: str,
                    parent_id: str, relationship: str,
                    specialist: str = '', playbook: str = '',
                    metadata: Optional[Dict] = None) -> str:
        """Register a derived artifact and the edge from its parent."""
        node = {
            'id': derived_id, 'type': derived_type, 'path': path,
            'specialist': specialist, 'playbook': playbook,
            'metadata': metadata or {}, 'created': datetime.now().isoformat(),
        }
        edge = {'from': parent_id, 'to': derived_id, 'relationship': relationship,
                'specialist': specialist, 'playbook': playbook}
        with self._lock:
            self._nodes[derived_id] = node
            self._edges.append(edge)
        return derived_id

    def get_provenance_chain(self, node_id: str) -> List[Dict]:
        """Return the full derivation chain from root to node_id."""
        with self._lock:
            nodes = dict(self._nodes)
            edges = list(self._edges)

        # Build reverse adjacency
        parents: Dict[str, str] = {e['to']: e['from'] for e in edges}
        chain = []
        current = node_id
        visited = set()
        while current and current not in visited:
            visited.add(current)
            node = nodes.get(current)
            if node:
                node = dict(node)  # shallow copy
                if self._custody_log is not None:
                    cid = (node.get('metadata') or {}).get('custody_record_id')
                    if cid:
                        crecs = self._custody_log.get_custody_for_finding(cid)
                        if crecs:
                            node['custody_records'] = crecs
                            node['custody_verified'] = all(
                                r.get('verification_passed') is True
                                for r in crecs
                            )
                chain.append(node)
            current = parents.get(current)
        return list(reversed(chain))

    def finding_provenance(self, finding: Dict, specialist: str,
                            playbook: str, evidence_path: str) -> Dict:
        """Attach provenance metadata to a finding dict."""
        fid = finding.get('step_key') or finding.get('id') or id(finding)
        chain = self.get_provenance_chain(evidence_path)
        return {
            **finding,
            'provenance': {
                'finding_id': str(fid),
                'specialist': specialist,
                'playbook': playbook,
                'evidence_source': evidence_path,
                'derivation_chain': chain,
                'generated': datetime.now().isoformat(),
            }
        }

    def to_dict(self) -> Dict[str, Any]:
        with self._lock:
            return {'nodes': dict(self._nodes), 'edges': list(self._edges)}

    def save(self, path: Optional[str] = None) -> str:
        """Persist DAG to JSON file."""
        out_path = path or (str(self.case_work_dir / 'provenance_dag.json') if self.case_work_dir else '/tmp/provenance_dag.json')
        Path(out_path).write_text(json.dumps(self.to_dict(), indent=2))
        return out_path


# ---------------------------------------------------------------------------
# Novel 5: Adaptive Pass 2 Triggering
# ---------------------------------------------------------------------------
