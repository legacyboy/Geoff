import os
import time
from datetime import datetime
from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS
from werkzeug.utils import secure_filename

app = Flask(__name__)
CORS(app)  # Fix CORS issues for uploads

# --- CONFIGURATION ---
EVIDENCE_BASE_DIR = "/mnt/evidence-storage/cases"
PORT = 8080

# Ensure the base directory exists
os.makedirs(EVIDENCE_BASE_DIR, exist_ok=True)

# HTML Templates
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Geoff DFIR Interface</title>
    <style>
        :root {
            --bg-dark: #121212;
            --bg-panel: #1e1e1e;
            --bg-input: #2d2d2d;
            --accent-blue: #4a9eff;
            --accent-green: #4caf50;
            --text-main: #e0e0e0;
            --text-dim: #a0a0a0;
            --border: #333;
        }
        body { font-family: 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; margin: 0; background: var(--bg-dark); color: var(--text-main); display: flex; flex-direction: column; height: 100vh; }
        .container { max-width: 1100px; margin: 0 auto; width: 100%; height: 100%; display: flex; flex-direction: column; }
        
        header { padding: 20px; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; }
        h1 { margin: 0; font-size: 1.5rem; letter-spacing: 1px; color: var(--accent-blue); }

        .tabs { display: flex; gap: 5px; padding: 10px 20px 0; }
        .tab { padding: 10px 20px; cursor: pointer; background: transparent; color: var(--text-dim); border: 1px solid var(--border); border-bottom: none; border-radius: 5px 5px 0 0; transition: 0.2s; }
        .tab.active { background: var(--bg-panel); color: var(--text-main); border-color: var(--border); font-weight: bold; box-shadow: 0 -2px 10px rgba(0,0,0,0.3); }
        
        .content-section { display: none; flex-grow: 1; padding: 20px; overflow-y: auto; }
        .content-section.active { display: flex; flex-direction: column; }
        
        #chat-box { background: var(--bg-panel); height: 60vh; overflow-y: auto; padding: 20px; border: 1px solid var(--border); border-radius: 8px; margin-bottom: 20px; display: flex; flex-direction: column; gap: 15px; }
        .msg { max-width: 80%; padding: 12px 16px; border-radius: 12px; line-height: 1.5; position: relative; }
        .msg-user { align-self: flex-end; background: var(--accent-blue); color: #000; border-bottom-right-radius: 2px; }
        .msg-geoff { align-self: flex-start; background: var(--bg-input); color: var(--text-main); border-bottom-left-radius: 2px; border: 1px solid var(--border); }
        .msg b { display: block; font-size: 0.75rem; margin-bottom: 4px; opacity: 0.8; text-transform: uppercase; }

        .input-area { display: flex; gap: 10px; background: var(--bg-panel); padding: 15px; border-radius: 8px; border: 1px solid var(--border); }
        input[type="text"] { flex-grow: 1; padding: 12px; background: var(--bg-input); color: #fff; border: 1px solid var(--border); border-radius: 4px; outline: none; }
        input[type="text"]:focus { border-color: var(--accent-blue); }
        
        .btn { padding: 10px 20px; cursor: pointer; background: var(--bg-input); color: #fff; border: 1px solid var(--border); border-radius: 4px; transition: 0.2s; font-weight: 500; }
        .btn:hover { background: #3d3d3d; border-color: var(--text-dim); }
        .btn-primary { background: var(--accent-blue); color: #000; border: none; }
        .btn-primary:hover { background: #66b2ff; }

        .evidence-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 20px; }
        .case-card { background: var(--bg-panel); padding: 15px; border-radius: 8px; border: 1px solid var(--border); border-top: 3px solid var(--accent-blue); }
        .case-card h3 { margin: 0 0 10px 0; font-size: 1.1rem; color: var(--accent-blue); }
        .file-list { font-size: 0.85rem; color: var(--text-dim); max-height: 200px; overflow-y: auto; }
        .file-item { padding: 4px 0; border-bottom: 1px solid #2a2a2a; display: flex; justify-content: space-between; }
        .file-item:last-child { border-bottom: none; }

        .upload-panel { margin-top: 20px; display: flex; gap: 10px; align-items: center; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>GEOFF <small style="font-size: 0.6em; color: var(--text-dim);">DFIR Analysis Engine</small></h1>
            <div id="status-indicator" style="font-size: 0.8rem; color: var(--accent-green);">● System Online</div>
        </header>
        
        <div class="tabs">
            <div class="tab active" onclick="showTab('chat', this)">Chat</div>
            <div class="tab" onclick="showTab('evidence', this)">Evidence Store</div>
        </div>

        <div id="chat" class="content-section active">
            <div id="chat-box"></div>
            <div class="input-area">
                <input type="text" id="chat-input" placeholder="Analyze case 'tuck'..." onkeypress="if(event.key === 'Enter') sendChat()">
                <button class="btn btn-primary" onclick="sendChat()">Send</button>
            </div>
            <div class="upload-panel">
                <input type="file" id="file-upload" style="display:none" onchange="uploadFile()">
                <button class="btn" onclick="document.getElementById('file-upload').click()">📤 Upload Evidence</button>
            </div>
        </div>

        <div id="evidence" class="content-section">
            <div class="evidence-grid" id="case-container"></div>
        </div>
    </div>

    <script>
        function showTab(tabId, element) {
            document.querySelectorAll('.content-section').forEach(s => s.classList.remove('active'));
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.getElementById(tabId).classList.add('active');
            element.classList.add('active');
            if(tabId === 'evidence') loadEvidence();
        }

        async function sendChat() {
            const input = document.getElementById('chat-input');
            const box = document.getElementById('chat-box');
            const text = input.value.trim();
            if(!text) return;

            box.innerHTML += `<div class="msg msg-user"><b>User</b>${text}</div>`;
            input.value = '';
            box.scrollTop = box.scrollHeight;

            try {
                const res = await fetch('/chat', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({message: text})
                });
                const data = await res.json();
                box.innerHTML += `<div class="msg msg-geoff"><b>Geoff</b>${data.response}</div>`;
            } catch (e) {
                box.innerHTML += `<div class="msg msg-geoff" style="color: #ff5555;"><b>Error</b>Could not connect to Geoff.</div>`;
            }
            box.scrollTop = box.scrollHeight;
        }

        async function uploadFile() {
            const fileInput = document.getElementById('file-upload');
            const file = fileInput.files[0];
            if(!file) return;

            const caseName = prompt('Enter case name for this file (e.g., case_001):');
            if(!caseName) return;

            const formData = new FormData();
            formData.append('file', file);
            formData.append('case', caseName);

            try {
                const res = await fetch('/upload', {
                    method: 'POST',
                    body: formData
                });
                const data = await res.json();
                alert(data.message);
            } catch (e) {
                alert('Upload failed: ' + e);
            }
            fileInput.value = '';
        }

        async function loadEvidence() {
            const container = document.getElementById('case-container');
            container.innerHTML = '<p>Loading cases...</p>';
            try {
                const res = await fetch('/cases');
                const data = await res.json();
                container.innerHTML = '';
                
                const caseNames = Object.keys(data);
                if(caseNames.length === 0) {
                    container.innerHTML = '<p>No cases found in storage.</p>';
                    return;
                }

                for (const caseName of caseNames) {
                    const files = data[caseName];
                    const card = document.createElement('div');
                    card.className = 'case-card';
                    
                    let fileHtml = files.map(f => `<div class="file-item"><span>${f}</span></div>`).join('');
                    if(files.length === 0) fileHtml = '<i>No files in case</i>';

                    card.innerHTML = `<h3>${caseName}</h3><div class="file-list">${fileHtml}</div>`;
                    container.appendChild(card);
                }
            } catch (e) {
                container.innerHTML = '<p style="color:red">Error loading evidence.</p>';
            }
        }
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/chat', methods=['POST'])
def chat():
    data = request.json
    msg = data.get('message', '').lower()
    
    if "process case" in msg:
        case_name = msg.replace("process case", "").strip()
        case_path = os.path.join(EVIDENCE_BASE_DIR, case_name)
        if os.path.exists(case_path) and os.path.isdir(case_path):
            files = os.listdir(case_path)
            return jsonify({"response": f"Processing case '{case_name}'. Found {len(files)} items. Starting analysis..."})
        else:
            return jsonify({"response": f"Case '{case_name}' not found in evidence storage."})
    
    return jsonify({"response": "I'm Geoff. Tell me to 'process case X' to begin analysis."})

@app.route('/upload', methods=['POST'])
def upload():
    case_name = request.form.get('case')
    if not case_name:
        return jsonify({"message": "Case name required"}), 400
    
    file = request.files.get('file')
    if not file:
        return jsonify({"message": "No file uploaded"}), 400
    
    # Sanitize case name to prevent path traversal
    safe_case_name = secure_filename(case_name)
    case_path = os.path.join(EVIDENCE_BASE_DIR, safe_case_name)
    
    try:
        os.makedirs(case_path, exist_ok=True)
        filename = secure_filename(file.filename)
        save_path = os.path.join(case_path, filename)
        file.save(save_path)
        return jsonify({"message": f"Uploaded {filename} to case {safe_case_name}"})
    except Exception as e:
        return jsonify({"message": f"Server error: {str(e)}"}), 500

@app.route('/cases', methods=['GET'])
def list_cases():
    cases = {}
    if os.path.exists(EVIDENCE_BASE_DIR):
        try:
            # List all items in the cases directory
            for item in os.listdir(EVIDENCE_BASE_DIR):
                item_path = os.path.join(EVIDENCE_BASE_DIR, item)
                if os.path.isdir(item_path):
                    # Show ALL files in the folder, regardless of extension
                    cases[item] = os.listdir(item_path)
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    return jsonify(cases)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=PORT)
