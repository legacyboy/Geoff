"""
Pytest configuration for the Geoff test suite.

geoff_integrated.py initializes Flask, forensic tool imports, and singletons
at module level. We pre-patch sys.modules so those heavy/absent dependencies
become MagicMock instances before the module is imported.
"""

import sys
import os
import types
from unittest.mock import MagicMock, patch

# ---- Add src to path so test files can import source modules directly ----
# src/ must be FIRST: when geoff-dfir is pip-installed (editable .pth adds a
# trailing src entry) and pytest runs from the repo root, the CWD would
# otherwise let the root-level geoff_integrated.py wrapper shadow
# src/geoff_integrated.py.
SRC_DIR = os.path.join(os.path.dirname(__file__), "..", "src")
SRC_DIR = os.path.realpath(SRC_DIR)
if SRC_DIR in sys.path:
    sys.path.remove(SRC_DIR)
sys.path.insert(0, SRC_DIR)

SCRIPTS_DIR = os.path.join(os.path.dirname(__file__), "..", "scripts")
SCRIPTS_DIR = os.path.realpath(SCRIPTS_DIR)
if SCRIPTS_DIR in sys.path:
    sys.path.remove(SCRIPTS_DIR)
sys.path.insert(1, SCRIPTS_DIR)

# ---- Stub heavy forensic / optional dependencies ----
# These modules may not be installed in the test environment.
_STUB_MODULES = [
    "sift_specialists",
    "sift_specialists_extended",
    "sift_specialists_remnux",
    "geoff_forensicator",
    "geoff_investigation_worker",
    "geoff_worker",
    "jsonschema",
    "git",
    "gitpython",
    "dotenv",
]

for mod_name in _STUB_MODULES:
    if mod_name not in sys.modules:
        sys.modules[mod_name] = MagicMock()
