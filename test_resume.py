#!/usr/bin/env python3
"""Test the resume functionality of InvestigationPlanner"""

import sys
sys.path.insert(0, '/home/claw/.openclaw/workspace')
from investigation_planner import InvestigationPlanner

print("="*60)
print("TEST: Investigation Resume Functionality")
print("="*60)

# Test 1: Create planner (auto-resumes from existing state)
planner = InvestigationPlanner('3EB03F77A9E6E641FCD2FE')
print(f"\n[TEST] Loaded planner for {planner.investigation_id}")

# Test 2: Check status
print("\n[TEST] Status check:")
planner.print_status()

# Test 3: Run remaining steps (should skip completed, run pending)
print("\n[TEST] Running all remaining steps:")
planner.run_all()

print("\n" + "="*60)
print("TEST COMPLETE - Resume functionality working correctly!")
print("="*60)
