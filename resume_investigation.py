#!/usr/bin/env python3
"""
Resume Investigation from investigation.json
"""

import json
from pathlib import Path
from investigation_planner import InvestigationPlanner

def resume_from_json(inv_id="3EB03F77A9E6E641FCD2FE"):
    # Load investigation.json
    json_path = Path(f'/home/claw/.openclaw/workspace/investigation.json')
    if not json_path.exists():
        print(f"[ERROR] {json_path} not found")
        return
    
    with open(json_path) as f:
        data = json.load(f)
    
    print(f"[RESUME] Investigation: {inv_id}")
    print(f"[RESUME] Current step: {data['current_step']}/{len(data['steps'])}")
    
    # Create planner
    planner = InvestigationPlanner(inv_id)
    
    # If planner has no steps, import from JSON
    if len(planner.steps) == 0:
        print("[INIT] Importing steps from investigation.json")
        planner.steps = data['steps']
        planner.current_step = data['current_step']
        planner._save()
        print(f"[INIT] Imported {len(planner.steps)} steps")
    
    # Show status
    planner.print_status()
    
    # Run remaining steps
    print("\n[RUN] Starting execution...")
    planner.run_all()
    
    # Update investigation.json
    data['current_step'] = planner.current_step
    for i, step in enumerate(planner.steps):
        data['steps'][i]['status'] = step['status']
    
    with open(json_path, 'w') as f:
        json.dump(data, f, indent=2)
    
    print(f"\n[SAVE] Updated {json_path}")

if __name__ == "__main__":
    import sys
    inv_id = sys.argv[1] if len(sys.argv) > 1 else "3EB03F77A9E6E641FCD2FE"
    resume_from_json(inv_id)
