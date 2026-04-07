#!/usr/bin/env python3
"""
Geoff Web UI - Digital Forensics Interface
Simple Flask-based web interface for Geoff investigations.
"""

import os
import sys
import json
import uuid
from pathlib import Path
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_from_directory

# Add parent to path for imports
BASE_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(BASE_DIR))

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 * 1024  # 16GB max upload

# Configuration
CASES_DIR = BASE_DIR / 'cases'
UPLOAD_DIR = BASE_DIR / 'uploads'
CONFIG_FILE = BASE_DIR / 'config.json'

# Ensure directories exist
CASES_DIR.mkdir(exist_ok=True)
UPLOAD_DIR.mkdir(exist_ok=True)

def load_config():
    """Load Geoff configuration."""
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE) as f:
            return json.load(f)
    return {
        'ollama_host': 'http://localhost:11434',
        'cloud_ollama': None,
        'default_model': 'deepseek-v3.2:cloud',
        'evidence_path': str(UPLOAD_DIR)
    }

def save_config(config):
    """Save Geoff configuration."""
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=2)

@app.route('/')
def index():
    """Main interface."""
    config = load_config()
    return render_template('index.html', config=config)

@app.route('/api/config', methods=['GET'])
def get_config():
    """Get current configuration."""
    return jsonify(load_config())

@app.route('/api/config', methods=['POST'])
def update_config():
    """Update configuration."""
    config = load_config()
    config.update(request.json)
    save_config(config)
    return jsonify({'status': 'ok', 'config': config})

@app.route('/api/cases', methods=['GET'])
def list_cases():
    """List all investigations."""
    cases = []
    if CASES_DIR.exists():
        for case_dir in CASES_DIR.iterdir():
            if case_dir.is_dir():
                state_file = case_dir / f'{case_dir.name}_state.json'
                if state_file.exists():
                    with open(state_file) as f:
                        state = json.load(f)
                    cases.append({
                        'id': case_dir.name,
                        'status': state.get('status', 'unknown'),
                        'progress': state.get('progress_pct', 0),
                        'updated': state.get('last_updated', 'never')
                    })
    return jsonify(cases)

@app.route('/api/cases/<case_id>', methods=['GET'])
def get_case(case_id):
    """Get case details."""
    case_dir = CASES_DIR / case_id
    state_file = case_dir / f'{case_id}_state.json'
    
    if not state_file.exists():
        return jsonify({'error': 'Case not found'}), 404
    
    with open(state_file) as f:
        state = json.load(f)
    
    # Get findings
    findings_dir = case_dir / 'findings'
    findings = []
    if findings_dir.exists():
        findings = [f.name for f in findings_dir.glob('*.md')]
    
    return jsonify({
        'id': case_id,
        'state': state,
        'findings': findings
    })

@app.route('/api/cases/<case_id>/findings/<path:filename>')
def get_finding(case_id, filename):
    """Get a finding file."""
    findings_dir = CASES_DIR / case_id / 'findings'
    return send_from_directory(findings_dir, filename)

@app.route('/api/upload', methods=['POST'])
def upload_evidence():
    """Upload evidence file."""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    case_id = request.form.get('case_id', str(uuid.uuid4())[:8])
    
    # Create case directory
    case_upload_dir = UPLOAD_DIR / case_id
    case_upload_dir.mkdir(parents=True, exist_ok=True)
    
    # Save file
    filepath = case_upload_dir / file.filename
    file.save(filepath)
    
    return jsonify({
        'status': 'ok',
        'case_id': case_id,
        'filename': file.filename,
        'path': str(filepath),
        'size': filepath.stat().st_size
    })

@app.route('/api/investigate', methods=['POST'])
def start_investigation():
    """Start or resume an investigation."""
    data = request.json
    case_id = data.get('case_id')
    evidence_path = data.get('evidence_path')
    resume = data.get('resume', False)
    
    if not case_id:
        return jsonify({'error': 'Case ID required'}), 400
    
    # Import and run spawn_geoff
    sys.path.insert(0, str(BASE_DIR))
    from spawn_geoff import spawn_geoff
    
    try:
        spawn_geoff(case_id, evidence_path, resume)
        return jsonify({
            'status': 'ok',
            'message': f'Investigation {"resumed" if resume else "started"}',
            'case_id': case_id
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/chat', methods=['POST'])
def chat():
    """Chat with Geoff (placeholder for direct interaction)."""
    data = request.json
    message = data.get('message')
    case_id = data.get('case_id')
    
    # This would integrate with the ACP session
    # For now, return status
    return jsonify({
        'status': 'ok',
        'message': 'Chat functionality requires ACP session',
        'case_id': case_id
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)