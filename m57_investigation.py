#!/usr/bin/env python3
"""
M57-Jean Forensic Investigation
Full analysis of nps-2008-jean disk image
"""

import sys
sys.path.insert(0, '/home/claw/.openclaw/workspace')

from investigation_planner import InvestigationPlanner
from forensic_tools import mmls, fls, calculate_hash, fsstat
import json
from pathlib import Path

DISK_IMAGE = "/tmp/nps-2008-jean.E01"
INVESTIGATION_ID = "M57-JEAN-001"

def run_m57_investigation():
    """Complete forensic investigation of M57-Jean case"""
    
    print("="*70)
    print("M57-JEAN FORENSIC INVESTIGATION")
    print("="*70)
    print(f"Target: {DISK_IMAGE}")
    print(f"Size: 1.5 GB")
    print("Objective: Find evil — determine what happened")
    print("="*70 + "\n")
    
    # Create investigation
    planner = InvestigationPlanner(INVESTIGATION_ID)
    planner.steps = []
    planner.current_step = 0
    
    # Phase 1: Initial Assessment
    planner.add_step('forensic_tools', 'mmls',
                    {'disk_image': DISK_IMAGE},
                    'Analyze partition table — identify file systems')
    
    planner.add_step('forensic_tools', 'calculate_hash',
                    {'file_path': DISK_IMAGE, 'algorithm': 'sha256'},
                    'Verify disk image integrity (SHA256)')
    
    # Phase 2: File System Analysis (run on first partition)
    planner.add_step('forensic_tools', 'fsstat',
                    {'partition': f'{DISK_IMAGE}'},
                    'Analyze NTFS file system details')
    
    planner.add_step('forensic_tools', 'fls',
                    {'partition': DISK_IMAGE},
                    'List all files and directories (recursive)')
    
    # Phase 3: Evidence Collection
    planner.add_step('forensic_tools', 'photorec',
                    {'disk_image': DISK_IMAGE, 
                     'output_dir': f'/tmp/{INVESTIGATION_ID}_carved'},
                    'Carve deleted files with PhotoRec')
    
    # Phase 4: Analysis
    planner.add_step('forensic_tools', 'timeline',
                    {'partition': DISK_IMAGE},
                    'Generate MAC timeline from file system')
    
    # Run investigation
    planner.run_all()
    
    # Export findings
    planner.print_status()
    
    print("\n" + "="*70)
    print("INVESTIGATION COMPLETE")
    print("="*70)
    print(f"Artifacts:")
    print(f"  - State: investigation_{INVESTIGATION_ID}_state.json")
    print(f"  - Carved files: /tmp/{INVESTIGATION_ID}_carved/")
    print(f"  - All steps committed to git")
    print("\nReady to analyze findings...")
    
    return planner

if __name__ == "__main__":
    run_m57_investigation()
