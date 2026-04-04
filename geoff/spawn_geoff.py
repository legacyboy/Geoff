#!/usr/bin/env python3
"""
Spawn Geoff investigator for a case.
Uses ACP harness with tool-capable model.
"""

import sys
import json
import argparse
from pathlib import Path
from datetime import datetime

BASE_DIR = Path(__file__).parent
sys.path.insert(0, str(BASE_DIR.parent))

from investigation_planner import InvestigationPlanner

GEOFF_SYSTEM_PROMPT = """You are Geoff, a methodical digital forensics investigator.

Your job is to execute investigation plans and analyze digital evidence.

RULES:
1. Read the investigation state file to understand progress
2. Execute ONE step at a time
3. Save all findings to cases/<case_id>/findings/
4. Use available tools: read, exec, write, edit for file analysis
5. Report progress concisely - don't narrate every action

Be thorough but efficient. Focus on extracting actionable intelligence from evidence.
"""

def spawn_geoff(case_id: str, evidence_path: str, resume: bool = False):
    """Spawn Geoff as ACP session for investigation."""
    
    case_dir = BASE_DIR.parent / 'cases' / case_id
    state_file = BASE_DIR.parent / f"investigation_{case_id}_state.json"
    
    # Initialize or load investigation
    if resume and state_file.exists():
        print(f"📋 Resuming investigation: {case_id}")
        planner = InvestigationPlanner(case_id, str(BASE_DIR.parent))
        status = planner.get_status()
        print(f"   Progress: {status['progress_pct']:.1f}% complete ({status['completed']}/{status['total_steps']} steps)")
    else:
        print(f"🔍 Starting new investigation: {case_id}")
        print(f"   Evidence: {evidence_path}")
        
        # Create case directory structure
        (case_dir / 'steps').mkdir(parents=True, exist_ok=True)
        (case_dir / 'findings').mkdir(parents=True, exist_ok=True)
        (case_dir / 'evidence').mkdir(parents=True, exist_ok=True)
        
        # Initialize planner
        planner = InvestigationPlanner(case_id, str(BASE_DIR.parent))
        
        # Add initial steps based on evidence
        planner.add_step('forensic_tools', 'analyze_disk_image', 
                        {'disk_image': evidence_path, 'output_dir': str(case_dir / 'findings')},
                        f"Analyze disk image: {evidence_path}")
        planner.add_step('forensic_tools', 'timeline',
                        {'partition': evidence_path},
                        "Extract filesystem timeline")
        planner.add_step('forensic_tools', 'photorec',
                        {'disk_image': evidence_path, 'output_dir': str(case_dir / 'findings' / 'recovered')},
                        "Carve deleted/recovered files")
        
        status = planner.get_status()
        print(f"   Plan created: {status['total_steps']} steps")
    
    # Prepare task for Geoff
    task = f"""INVESTIGATION TASK: {case_id}

You are Geoff, a digital forensics investigator.

Your working directory: {case_dir}
Evidence location: {evidence_path}

INSTRUCTIONS:
1. Read the investigation state: {state_file}
2. Check current progress and find the next pending step
3. Execute that step using forensic_tools module
4. Save findings to: {case_dir}/findings/
5. Mark step complete and report back

Name finding files descriptively (e.g., disk_analysis.md, timeline.md, carved_files.md)

Be concise. Focus on extracting actionable intelligence.
"""
    
    print(f"\n🚀 Ready to spawn Geoff")
    print(f"   Model: ollama/deepseek-v3.2:cloud (tool-capable)")
    print(f"   Working dir: {case_dir}")
    
    # Output the sessions_spawn command for user to run
    print(f"\n📤 Run this command to spawn Geoff:")
    print(f"   openclaw sessions spawn --runtime acp --agent geoff-investigator --model ollama/deepseek-v3.2:cloud --cwd {case_dir}")
    print(f"\n   Or in Python:")
    print(f"   sessions_spawn(runtime='acp', agentId='geoff-investigator', model='ollama/deepseek-v3.2:cloud', cwd='{case_dir}', task='...')")

def main():
    parser = argparse.ArgumentParser(description='Spawn Geoff investigator')
    parser.add_argument('case_id', help='Case identifier')
    parser.add_argument('evidence_path', nargs='?', help='Path to evidence files')
    parser.add_argument('--resume', action='store_true', help='Resume existing investigation')
    
    args = parser.parse_args()
    
    spawn_geoff(args.case_id, args.evidence_path or '', args.resume)

if __name__ == '__main__':
    main()
