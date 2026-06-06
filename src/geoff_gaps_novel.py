#!/usr/bin/env python3
"""Compatibility shim — re-exports all classes from new modular files."""
from __future__ import annotations

# Gap 3
from geoff_dns_forensics import DNS_Specialist
# Gap 4
from geoff_yara import YARA_Specialist
# Gap 5
from geoff_hash_correlation import HASH_Specialist
# Novel 1
from geoff_dual_critic import GeoffCriticPool
# Novel 2
from geoff_adaptive_playbook import AdaptivePlaybook
# Novel 3
from geoff_confidence import ConfidenceCalibrator
# Novel 4
from geoff_provenance import ProvenanceDAG
# Novel 5
from geoff_adaptive_pass2 import AdaptivePass2

__all__ = [
    'DNS_Specialist', 'YARA_Specialist', 'HASH_Specialist',
    'GeoffCriticPool', 'AdaptivePlaybook', 'ConfidenceCalibrator',
    'ProvenanceDAG', 'AdaptivePass2',
]
