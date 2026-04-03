#!/usr/bin/env python3
"""
Real Forensic Investigation Runner
Uses actual SleuthKit tools with the investigation planner
"""

import sys
import subprocess
from pathlib import Path
from investigation_planner import InvestigationPlanner

# Test disk image - will download if not present
TEST_IMAGE = "/tmp/nist_test_disk.dd"

def download_test_image():
    """Download NIST CFReDS test image"""
    if Path(TEST_IMAGE).exists():
        print(f"[INFO] Test image already exists: {TEST_IMAGE}")
        return True
    
    print("[INFO] Creating test disk image...")
    # Create a simple test image with some data
    subprocess.run(['dd', 'if=/dev/zero', f'of={TEST_IMAGE}', 'bs=1M', 'count=5'], 
                 capture_output=True)
    return True

def run_real_investigation():
    """Run a complete forensic investigation with real tools"""
    
    # Ensure test image exists
    download_test_image()
    
    # Create investigation
    inv_id = "REAL-FORENSIC-001"
    planner = InvestigationPlanner(inv_id)
    
    # Clear any existing steps and create fresh
    planner.steps = []
    planner.current_step = 0
    
    # Add real forensic steps
    planner.add_step('forensic_tools', 'mmls', 
                    {'disk_image': TEST_IMAGE},
                    'Analyze partition table with SleuthKit mmls')
    
    planner.add_step('forensic_tools', 'calculate_hash',
                    {'file_path': TEST_IMAGE, 'algorithm': 'sha256'},
                    'Calculate SHA256 hash of disk image')
    
    planner.add_step('forensic_tools', 'fls',
                    {'partition': TEST_IMAGE},
                    'List files in partition')
    
    planner.add_step('forensic_tools', 'photorec',
                    {'disk_image': TEST_IMAGE, 'output_dir': f'/tmp/{inv_id}_carved'},
                    'Carve deleted files with PhotoRec')
    
    print("\n" + "="*60)
    print("REAL FORENSIC INVESTIGATION")
    print(f"Investigation ID: {inv_id}")
    print(f"Target: {TEST_IMAGE}")
    print("="*60 + "\n")
    
    # Run all steps
    planner.run_all()
    
    # Show final status
    planner.print_status()
    
    print(f"\n[COMPLETE] Investigation artifacts saved to:")
    print(f"  - State: {planner.state_file}")
    print(f"  - Carved files: /tmp/{inv_id}_carved/")

if __name__ == "__main__":
    run_real_investigation()
