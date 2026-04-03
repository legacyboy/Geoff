#!/usr/bin/env python3
"""
Demo: Investigation Planner with State Recovery
Shows how the planner resumes from existing state
"""

import sys
sys.path.insert(0, '/home/claw/.openclaw/workspace')

from investigation_planner import InvestigationPlanner

# Investigation ID
INV_ID = "3EB03F77A9E6E641FCD2FE"

# Create planner (auto-loads existing state)
planner = InvestigationPlanner(INV_ID)

# Check if this is a new investigation or resuming
if planner.current_step == 0 and len(planner.steps) == 0:
    print("[INIT] New investigation - setting up steps...")
    
    # Define the investigation steps
    planner.add_step('mft', 'autopsy', 
                   {'investigation_id': INV_ID},
                   'Initialize investigation and create MFT structure')
    
    planner.add_step('mft', 'parse_mft',
                   {'investigation_id': INV_ID},
                   'Parse Master File Table entries')
    
    planner.add_step('file_carver', 'verify_hash',
                   {'file_path': f'/evidence/{INV_ID}/disk.img'},
                   'Verify evidence integrity')
    
    planner.add_step('file_carver', 'carve_deleted',
                   {'investigation_id': INV_ID, 'disk_image': f'/evidence/{INV_ID}/disk.img'},
                   'Carve deleted files from disk image')
    
    planner.add_step('mft', 'generate_timeline',
                   {'investigation_id': INV_ID},
                   'Generate forensic timeline')
    
    planner.add_step('mft', 'export_report',
                   {'investigation_id': INV_ID, 'format': 'json'},
                   'Export investigation report')
    
    print(f"[INIT] Created {len(planner.steps)} steps")
else:
    print("[RESUME] Existing investigation found!")

# Show current status
planner.print_status()

# Ask what to do
print("\nActions:")
print("  1. Run next step")
print("  2. Run all remaining steps")
print("  3. Reset and start over")
print("  4. Exit (state is saved)")

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        action = sys.argv[1]
    else:
        action = input("\nChoose action (1-4): ").strip()
    
    if action == '1' or action == 'step':
        planner.run_step()
    elif action == '2' or action == 'run':
        planner.run_all()
    elif action == '3' or action == 'reset':
        planner.current_step = 0
        for s in planner.steps:
            s['status'] = 'pending'
        planner._save_state()
        print("[RESET] Investigation reset")
    else:
        print("[EXIT] State saved. Run again to resume.")
