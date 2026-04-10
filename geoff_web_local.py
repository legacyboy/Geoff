#!/usr/bin/env python3
"""
Geoff DFIR - Fixed: No Upload, Full Evidence, LLM Chat
"""

import os
import json
import requests
from datetime import datetime
from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

EVIDENCE_BASE_DIR = "/home/sansforensics/evidence-storage/cases"
PORT = 8080

# LLM Configuration
OLLAMA_URL = "http://192.168.1.31:11434"
LLM_MODEL = "qwen3-coder-next:cloud"

GEOFF_PROMPT = """You are Geoff, an expert Digital Forensics and Incident Response (DFIR) investigator.

Your capabilities:
- Analyze forensic evidence files (disk images, memory dumps, logs, network captures)
- Identify indicators of compromise (IOCs)
- Timeline reconstruction
- Malware analysis
- Triage and prioritization

When analyzing evidence:
1. List all files found
2. Identify file types and forensic value
3. Provide analysis and recommendations
4. Suggest next steps

Be thorough, professional, and cite specific files."""

def call_llm(user_message):
    """Call Ollama LLM"""
    try:
        response = requests.post(
            f"{OLLAMA_URL}/api/generate",
            json={
                "model": LLM_MODEL,
                "prompt": f"{GEOFF_PROMPT}\n\nUser: {user_message}\n\nGeoff:",
                "stream": False,
                "options": {"temperature": 0.7}
            },
            timeout=120
        )
        if response.status_code == 200:
            return response.json().get('response', 'Analysis engine unavailable.')
    except Exception as e:
        print(f"LLM Error: {e}")
    return "I'm having trouble connecting to my analysis engine. Let me check the evidence directly."

def get_evidence_recursive(path, prefix=""):
    """Recursively get all files and folders"""
    items = []
    try:
        for item in sorted(os.listdir(path)):
            item_path = os.path.join(path, item)
            display_name = f"{prefix}{item}"
            if os.path.isdir(item_path):
                items.append(f"[DIR] {display_name}/")
                items.extend(get_evidence_recursive(item_path, f"{display_name}/"))
            else:
                size = os.path.getsize(item_path)
                items.append(f"{display_name} ({size} bytes)")
    except:
        pass
    return items

def get_all_cases():
    """Get ALL cases with ALL contents"""
    cases = {}
    if not os.path.exists(EVIDENCE_BASE_DIR):
        return cases
    try:
        for case_name in sorted(os.listdir(EVIDENCE_BASE_DIR)):
            case_path = os.path.join(EVIDENCE_BASE_DIR, case_name)
            if os.path.isdir(case_path):
                # Get ALL files recursively
                cases[case_name] = get_evidence_recursive(case_path)
    except Exception as e:
        print(f"Error reading cases: {e}")
    return cases

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Geoff DFIR</title>
    <meta charset="UTF-8">
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #0d1117;
            color: #c9d1d9;
            height: 100vh;
            display: flex;
            flex-direction: column;
        }
        
        header {
            background: #161b22;
            border-bottom: 1px solid #30363d;
            padding: 15px 25px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        h1 { color: #58a6ff; font-size: 1.4rem; }
        h1 span { color: #8b949e; font-size: 0.7em; font-weight: normal; }
        
        .status { color: #3fb950; font-size: 0.85rem; }
        
        .tabs {
            display: flex;
            background: #161b22;
            border-bottom: 1px solid #30363d;
            padding: 0 25px;
        }
        
        .tab {
            padding: 12px 24px;
            cursor: pointer;
            color: #8b949e;
            border-bottom: 2px solid transparent;
            transition: all 0.2s;
        }
        
        .tab:hover { color: #c9d1d9; }
        .tab.active { 
            color: #58a6ff; 
            border-bottom-color: #58a6ff;
            background: #0d1117;
        }
        
        .content {
            flex: 1;
            overflow: hidden;
            display: none;
        }
        
        .content.active { display: flex; flex-direction: column; }
        
        /* Chat Styles */
        #chat-content {
            flex: 1;
            overflow-y: auto;
            padding: 20px;
            display: flex;
            flex-direction: column;
            gap: 12px;
        }
        
        .message {
            max-width: 85%;
            padding: 12px 16px;
            border-radius: 8px;
            line-height: 1.6;
            font-size: 0.95rem;
            white-space: pre-wrap;
        }
        
        .message.user {
            align-self: flex-end;
            background: #1f6feb;
            color: white;
        }
        
        .message.geoff {
            align-self: flex-start;
            background: #21262d;
            border: 1px solid #30363d;
            color: #c9d1d9;
        }
        
        .message.system {
            align-self: center;
            background: transparent;
            color: #8b949e;
            font-style: italic;
            font-size: 0.85rem;
        }
        
        .message .label {
            font-size: 0.75rem;
            font-weight: 600;
            margin-bottom: 4px;
            opacity: 0.8;
            text-transform: uppercase;
        }
        
        .chat-input-area {
            padding: 15px 25px;
            background: #161b22;
            border-top: 1px solid #30363d;
            display: flex;
            gap: 10px;
        }
        
        #chat-input {
            flex: 1;
            padding: 12px 16px;
            background: #0d1117;
            border: 1px solid #30363d;
            border-radius: 6px;
            color: #c9d1d9;
            font-size: 0.95rem;
        }
        
        #chat-input:focus {
            outline: none;
            border-color: #58a6ff;
        }
        
        .send-btn {
            padding: 12px 24px;
            background: #238636;
            color: white;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-weight: 600;
        }
        
        .send-btn:hover { background: #2ea043; }
        
        /* Evidence Styles */
        #evidence-content {
            flex: 1;
            overflow-y: auto;
            padding: 20px 25px;
        }
        
        .case-list {
            display: flex;
            flex-direction: column;
            gap: 15px;
        }
        
        .case-card {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            overflow: hidden;
        }
        
        .case-header {
            padding: 12px 16px;
            background: #21262d;
            border-bottom: 1px solid #30363d;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .case-name {
            font-weight: 600;
            color: #58a6ff;
            font-size: 1.1rem;
        }
        
        .case-count {
            color: #8b949e;
            font-size: 0.85rem;
        }
        
        .case-files {
            padding: 12px 16px;
        }
        
        .file-item {
            padding: 6px 0;
            border-bottom: 1px solid #21262d;
            font-family: 'SF Mono', Monaco, monospace;
            font-size: 0.85rem;
            color: #c9d1d9;
        }
        
        .file-item:last-child { border-bottom: none; }
        
        .file-item.dir { color: #58a6ff; }
        .file-item.file { color: #a371f7; }
        
        .loading {
            text-align: center;
            padding: 40px;
            color: #8b949e;
        }
    </style>
</head>
<body>
    <header>
        <h1>Geoff <span>DFIR Investigation Platform</span></h1>
        <div class="status">● Online</div>
    </header>
    
    <div class="tabs">
        <div class="tab active" onclick="showTab('chat')">💬 Chat</div>
        <div class="tab" onclick="showTab('evidence')">📁 Evidence Store</div>
    </div>
    
    <div id="chat" class="content active">
        <div id="chat-content">
            <div class="message system">Welcome! I'm Geoff, your DFIR assistant. Ask me to analyze any case in the evidence store.</div>
        </div>
        <div class="chat-input-area">
            <input type="text" id="chat-input" placeholder="e.g., Analyze case 'tuck' and tell me what files are there..." onkeypress="if(event.key==='Enter') sendChat()">
            <button class="send-btn" onclick="sendChat()">Send</button>
        </div>
    </div>
    
    <div id="evidence" class="content">
        <div id="evidence-content">
            <div class="loading">Loading evidence...</div>
        </div>
    </div>
    
    <script>
        function showTab(tab) {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.content').forEach(c => c.classList.remove('active'));
            event.target.classList.add('active');
            document.getElementById(tab).classList.add('active');
            if(tab === 'evidence') loadEvidence();
        }
        
        function addMessage(text, type) {
            const chat = document.getElementById('chat-content');
            const div = document.createElement('div');
            div.className = 'message ' + type;
            if(type === 'user') {
                div.innerHTML = '<div class="label">You</div>' + text;
            } else if(type === 'geoff') {
                div.innerHTML = '<div class="label">Geoff</div>' + text;
            } else {
                div.textContent = text;
            }
            chat.appendChild(div);
            chat.scrollTop = chat.scrollHeight;
        }
        
        async function sendChat() {
            const input = document.getElementById('chat-input');
            const text = input.value.trim();
            if(!text) return;
            
            addMessage(text, 'user');
            input.value = '';
            addMessage('Analyzing...', 'system');
            
            try {
                const res = await fetch('/chat', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({message: text})
                });
                const data = await res.json();
                
                const chat = document.getElementById('chat-content');
                chat.removeChild(chat.lastChild);
                
                addMessage(data.response, 'geoff');
            } catch(e) {
                const chat = document.getElementById('chat-content');
                chat.removeChild(chat.lastChild);
                addMessage('Error: ' + e.message, 'system');
            }
        }
        
        async function loadEvidence() {
            const container = document.getElementById('evidence-content');
            container.innerHTML = '<div class="loading">Loading...</div>';
            
            try {
                const res = await fetch('/cases');
                const data = await res.json();
                const cases = data.cases || {};
                
                if(Object.keys(cases).length === 0) {
                    container.innerHTML = '<div class="loading">No cases found.</div>';
                    return;
                }
                
                let html = '<div class="case-list">';
                for(const [caseName, files] of Object.entries(cases)) {
                    html += '<div class="case-card">';
                    html += '<div class="case-header">';
                    html += '<span class="case-name">📁 ' + caseName + '</span>';
                    html += '<span class="case-count">' + files.length + ' items</span>';
                    html += '</div>';
                    html += '<div class="case-files">';
                    if(files.length === 0) {
                        html += '<div class="file-item">Empty case</div>';
                    } else {
                        files.forEach(f => {
                            const isDir = f.startsWith('[DIR]');
                            const cls = isDir ? 'dir' : 'file';
                            const display = isDir ? f.replace('[DIR] ', '') : f;
                            html += '<div class="file-item ' + cls + '">' + display + '</div>';
                        });
                    }
                    html += '</div></div>';
                }
                html += '</div>';
                container.innerHTML = html;
            } catch(e) {
                container.innerHTML = '<div class="loading">Error loading evidence: ' + e.message + '</div>';
            }
        }
        
        // Load evidence on page load
        loadEvidence();
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/chat', methods=['POST'])
def chat():
    """LLM-powered chat"""
    try:
        data = request.json
        user_msg = data.get('message', '')
        
        if not user_msg:
            return jsonify({'response': 'Please tell me what to analyze.'})
        
        # Check if user mentions a case
        case_match = None
        cases = get_all_cases()
        for case_name in cases.keys():
            if case_name.lower() in user_msg.lower():
                case_match = case_name
                break
        
        # Build context
        context = ""
        if case_match:
            files = cases[case_match]
            context = f"Case '{case_match}' contains {len(files)} items:\n"
            for f in files[:20]:  # Limit context
                context += f"- {f}\n"
            if len(files) > 20:
                context += f"... and {len(files) - 20} more items\n"
        else:
            context = f"Available cases: {', '.join(cases.keys())}"
        
        # Call LLM
        full_prompt = f"{GEOFF_PROMPT}\n\n{context}\n\nUser: {user_msg}\n\nGeoff:"
        response = call_llm(full_prompt)
        
        return jsonify({'response': response})
    except Exception as e:
        return jsonify({'response': f'Error: {str(e)}'})

@app.route('/cases', methods=['GET'])
def list_cases():
    """Return ALL cases with ALL files"""
    return jsonify({'cases': get_all_cases()})

if __name__ == '__main__':
    print(f'Geoff DFIR on port {PORT}')
    print(f'Evidence: {EVIDENCE_BASE_DIR}')
    app.run(host='0.0.0.0', port=PORT, debug=False, threaded=True)
