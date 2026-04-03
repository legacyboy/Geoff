#!/usr/bin/env python3
"""
Investigation Planner - Resume from Existing State
"""

import json
import hashlib
from datetime import datetime
from pathlib import Path
import subprocess

class InvestigationPlanner:
    """
    Forensic investigation planner with state persistence.
    Resumes from saved state automatically.
    """
    
    def __init__(self, investigation_id, base_path="/home/claw/.openclaw/workspace"):
        self.investigation_id = investigation_id
        self.base_path = Path(base_path)
        self.state_file = self.base_path / f"investigation_{investigation_id}_state.json"
        self.steps = []
        self.current_step = 0
        self._load_or_init()
    
    def _load_or_init(self):
        """Load existing state or initialize new"""
        if self.state_file.exists():
            try:
                with open(self.state_file, 'r') as f:
                    state = json.load(f)
                    self.steps = state.get('steps', [])
                    self.current_step = state.get('current_step', 0)
                    print(f"[RESUME] Loaded state: step {self.current_step}/{len(self.steps)}")
            except:
                self.steps = []
                self.current_step = 0
                print(f"[INIT] New investigation: {self.investigation_id}")
        else:
            print(f"[INIT] New investigation: {self.investigation_id}")
    
    def _save(self):
        """Persist state to disk"""
        state = {
            'investigation_id': self.investigation_id,
            'steps': self.steps,
            'current_step': self.current_step,
            'last_updated': datetime.now().isoformat()
        }
        with open(self.state_file, 'w') as f:
            json.dump(state, f, indent=2)
    
    def _commit(self, message):
        """Git commit for this step"""
        try:
            subprocess.run(['git', 'add', str(self.state_file)], cwd=self.base_path, check=True, capture_output=True)
            subprocess.run(['git', 'commit', '-m', message], cwd=self.base_path, check=True, capture_output=True)
            print(f"[GIT] Committed: {message}")
        except subprocess.CalledProcessError:
            pass  # Git not available or nothing to commit
    
    def add_step(self, module, function, params=None, description=""):
        """Add investigation step"""
        step = {
            'index': len(self.steps),
            'module': module,
            'function': function,
            'params': params or {},
            'description': description,
            'status': 'pending',
            'added_at': datetime.now().isoformat()
        }
        self.steps.append(step)
        self._save()
        self._commit(f"[{self.investigation_id}] Add step: {module}.{function}")
        return step['index']
    
    def run_step(self, step_index=None):
        """Execute step with resume capability - only runs pending steps"""
        if step_index is None:
            step_index = self.current_step
            
        if step_index >= len(self.steps):
            print(f"[DONE] All {len(self.steps)} steps completed!")
            return True
            
        step = self.steps[step_index]
        
        # Skip already completed
        if step['status'] == 'completed':
            print(f"[SKIP] Step {step_index} already done - moving to next")
            self.current_step = step_index + 1
            return self.run_step(self.current_step)
        
        print(f"[STEP {step_index}] {step['module']}.{step['function']}")
        if step['description']:
            print(f"  Description: {step['description']}")
        
        try:
            # Execute the step
            result = self._execute(step)
            step['status'] = 'completed'
            step['completed_at'] = datetime.now().isoformat()
            step['result'] = result
            self.current_step = step_index + 1
            self._save()
            self._commit(f"[{self.investigation_id}] Step {step_index}: {step['module']}.{step['function']}")
            print(f"  ✓ Step {step_index} complete")
            return True
            
        except Exception as e:
            step['status'] = 'failed'
            step['error'] = str(e)
            self._save()
            print(f"  ✗ Step {step_index} failed: {e}")
            return False
    
    def _execute(self, step):
        """Execute step function"""
        module_name = step['module']
        func_name = step['function']
        params = step.get('params', {})
        
        # Import forensic_tools if needed
        if module_name == 'forensic_tools':
            import forensic_tools
            func = getattr(forensic_tools, func_name)
            return func(**params)
        
        # Legacy mock modules (for backwards compatibility)
        if module_name == 'mft':
            if func_name == 'autopsy':
                return f"Initialized MFT for {params.get('investigation_id', self.investigation_id)}"
            elif func_name == 'parse_mft':
                return f"Parsed MFT with {len(params)} entries"
            elif func_name == 'generate_timeline':
                return "Timeline generated"
            elif func_name == 'export_report':
                return f"Report exported"
        elif module_name == 'file_carver':
            if func_name == 'verify_hash':
                return f"Hash verified: {params.get('file_path', 'unknown')}"
            elif func_name == 'carve_deleted':
                return f"Carved files from image"
        return f"Step {step['index']} executed"
    
    def run_all(self):
        """Run all pending steps from current position"""
        print(f"[INIT] Starting from step {self.current_step}/{len(self.steps)}")
        while self.current_step < len(self.steps):
            if not self.run_step(self.current_step):
                print("[HALT] Stopping due to error")
                return False
        print(f"[DONE] All steps completed!")
        return True
    
    def get_status(self):
        """Get current status"""
        completed = sum(1 for s in self.steps if s['status'] == 'completed')
        total = len(self.steps)
        current = self.current_step
        progress = (completed / total * 100) if total else 0
        return {
            'investigation_id': self.investigation_id,
            'total_steps': total,
            'completed': completed,
            'pending': total - completed,
            'current_step': current,
            'progress_pct': progress
        }
    
    def print_status(self):
        """Print formatted status"""
        status = self.get_status()
        print(f"\n{'='*50}")
        print(f"Investigation: {status['investigation_id']}")
        print(f"Progress: {status['completed']}/{status['total_steps']} ({status['progress_pct']:.1f}%)")
        print(f"Current: Step {status['current_step']}")
        print(f"Pending: {status['pending']}")
        print(f"{'='*50}")
        for i, step in enumerate(self.steps):
            icon = "✓" if step['status'] == 'completed' else "○" if step['status'] == 'pending' else "✗"
            print(f"  [{icon}] Step {step['index']}: {step['module']}.{step['function']}")
            if step.get('description'):
                print(f"      {step['description']}")

# Demo
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: investigation_planner.py <investigation_id> [action]")
        print("Actions: status, run, step, reset")
        sys.exit(1)
    
    inv_id = sys.argv[1]
    action = sys.argv[2] if len(sys.argv) > 2 else "status"
    
    planner = InvestigationPlanner(inv_id)
    
    if action == "status":
        planner.print_status()
    elif action == "run":
        planner.run_all()
    elif action == "step":
        planner.run_step()
    elif action == "reset":
        planner.current_step = 0
        for s in planner.steps:
            s['status'] = 'pending'
        planner._save()
        print(f"[RESET] Investigation {inv_id} reset")
    else:
        print(f"Unknown action: {action}")