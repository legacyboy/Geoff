#!/bin/bash
#
# Quick setup script for Geoff development
# This script sets up the development environment
#

set -e

echo "=========================================="
echo "  Geoff Development Environment Setup"
echo "=========================================="
echo ""

GEOFF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$GEOFF_DIR"

# Create required directories
echo "Creating directory structure..."
mkdir -p cases uploads findings logs

# Check for Python virtual environment
if [ ! -d "venv" ]; then
    echo "Creating Python virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Install Python dependencies
echo "Installing Python dependencies..."
pip install -q --upgrade pip
pip install -q -r webui/requirements.txt

# Check for investigation_planner.py
if [ ! -f "investigation_planner.py" ]; then
    echo "Creating investigation_planner.py..."
    cat > investigation_planner.py << 'EOF'
"""Investigation state management for Geoff."""

import json
import time
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional

class InvestigationPlanner:
    """Manages investigation state and planning."""
    
    def __init__(self, case_id: str, base_dir: str):
        self.case_id = case_id
        self.base_dir = Path(base_dir)
        self.case_dir = self.base_dir / 'cases' / case_id
        self.state_file = self.case_dir / f'{case_id}_state.json'
        
        # Ensure case directory exists
        self.case_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize or load state
        if self.state_file.exists():
            with open(self.state_file) as f:
                self.state = json.load(f)
        else:
            self.state = {
                'case_id': case_id,
                'created': datetime.now().isoformat(),
                'status': 'initialized',
                'steps': [],
                'completed': 0,
                'progress_pct': 0,
                'last_updated': datetime.now().isoformat()
            }
            self._save_state()
    
    def add_step(self, category: str, tool: str, params: dict, description: str):
        """Add an investigation step."""
        step = {
            'id': f"step_{len(self.state['steps']) + 1}",
            'category': category,
            'tool': tool,
            'params': params,
            'description': description,
            'completed': False,
            'created': datetime.now().isoformat()
        }
        self.state['steps'].append(step)
        self._update_progress()
        self._save_state()
        return step['id']
    
    def complete_step(self, step_id: str, findings: Optional[str] = None):
        """Mark a step as complete."""
        for step in self.state['steps']:
            if step['id'] == step_id:
                step['completed'] = True
                step['completed_at'] = datetime.now().isoformat()
                if findings:
                    step['findings'] = findings
                break
        self._update_progress()
        self._save_state()
    
    def _update_progress(self):
        """Update completion percentage."""
        total = len(self.state['steps'])
        completed = sum(1 for s in self.state['steps'] if s['completed'])
        self.state['completed'] = completed
        self.state['progress_pct'] = (completed / total * 100) if total > 0 else 0
        
        # Update status
        if completed == 0:
            self.state['status'] = 'pending'
        elif completed == total:
            self.state['status'] = 'completed'
        else:
            self.state['status'] = 'active'
    
    def _save_state(self):
        """Save state to disk."""
        self.state['last_updated'] = datetime.now().isoformat()
        with open(self.state_file, 'w') as f:
            json.dump(self.state, f, indent=2)
    
    def get_status(self):
        """Get current investigation status."""
        return {
            'case_id': self.case_id,
            'status': self.state['status'],
            'total_steps': len(self.state['steps']),
            'completed': self.state['completed'],
            'progress_pct': self.state['progress_pct'],
            'last_updated': self.state['last_updated']
        }
    
    def get_next_step(self) -> Optional[Dict]:
        """Get the next pending step."""
        for step in self.state['steps']:
            if not step['completed']:
                return step
        return None

if __name__ == '__main__':
    # Test
    planner = InvestigationPlanner('test-case', str(Path.cwd()))
    planner.add_step('forensic_tools', 'test', {}, 'Test step')
    print(planner.get_status())
EOF
fi

# Make scripts executable
echo "Setting permissions..."
chmod +x *.sh 2>/dev/null || true
chmod +x *.py 2>/dev/null || true

echo ""
echo "=========================================="
echo "  Development environment ready!"
echo "=========================================="
echo ""
echo "To start the Web UI:"
echo "  source venv/bin/activate"
echo "  python webui/app.py"
echo ""
echo "Or run the full installer:"
echo "  ./install.sh"
echo ""
echo "=========================================="