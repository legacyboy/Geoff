#!/usr/bin/env python3
"""
Demo: Investigation Planner - Resume Investigation
Shows how the planner resumes from existing state
"""

import hashlib
import json
from datetime import datetime
from pathlib import Path

STATE_FILE = Path('/home/claw/.openclaw/workspace/investigation_state.json')

def load_state():
    if STATE_FILE.exists():
        with open(STATE_FILE) as f:
            return json.load(f)
    return {'step': 0, 'entries': [], 'status': 'new'}

def save_state(state):
    with open(STATE_FILE, 'w') as f:
        json.dump(state, f)

def run_step(step_num, inv_id):
    steps = [
        'autopsy',
        'parse_mft', 
        'verify_hash',
        'carve_deleted',
        'generate_timeline',
        'export_report'
    ]
    
    if step_num >= len(steps):
        return None
    
    name = steps[step_num]
    print(f"  Running: {name}")
    
    # Simulate step completion
    return {'step': step_num, 'name': name, 'ok': True}

def resume_investigation(inv_id):
    print(f"\n[RESUME] Loading investigation: {inv_id}")
    state = load_state()
    current = state.get('step', 0)
    print(f"[RESUME] Found saved state at step {current}")
    
    while current < 5:
        result = run_step(current, inv_id)
        if result:
            current += 1
            state['step'] = current
            save_state(state)
            print(f"  ✓ Step {current} complete")
        else:
            print(f"  ✗ Step {current} failed")
            break
    
    print(f"[DONE] Investigation complete at step {state['step']}/5")

if __name__ == "__main__":
    import sys
    inv_id = sys.argv[1] if len(sys.argv) > 1 else "INV-001"
    resume_investigation(inv_id)
