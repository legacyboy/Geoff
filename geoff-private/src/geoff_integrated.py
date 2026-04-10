#!/usr/bin/env python3
"""
Geoff DFIR - Integrated with SIFT Tool Specialists
"""

import os
import json
import sys
import subprocess
sys.path.insert(0, '/home/claw/.openclaw/workspace/geoff-private/src')

import requests
from datetime import datetime
from pathlib import Path
from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS

from sift_specialists import SpecialistOrchestrator, SLEUTHKIT_Specialist, VOLATILITY_Specialist, YARA_Specialist, STRINGS_Specialist
from sift_specialists_extended import ExtendedOrchestrator

# Context Window Management
class ContextManager:
    """Manages LLM context window to prevent overflow while keeping relevant info"""
    
    # qwen3-coder-next:cloud has 32K context window
    # Reserve 8K for response + system overhead
    MAX_CONTEXT_TOKENS = 24000  # ~96KB of text (4 chars per token estimate)
    
    def __init__(self):
        self.conversation_history = []  # Store last N exchanges for context
        self.max_history_turns = 5
    
    def estimate_tokens(self, text: str) -> int:
        """Rough token estimation: ~4 characters per token"""
        return len(text) // 4
    
    def truncate_text(self, text: str, max_tokens: int) -> str:
        """Truncate text to fit within token limit"""
        estimated_tokens = self.estimate_tokens(text)
        if estimated_tokens <= max_tokens:
            return text
        
        # Calculate max characters
        max_chars = max_tokens * 4
        
        # Keep beginning and end, truncate middle
        if len(text) > max_chars:
            half = max_chars // 2
            return text[:half] + "\n...[truncated for context]...\n" + text[-half:]
        return text
    
    def build_context(self, system_prompt: str, case_info: str, tool_info: str, 
                     user_message: str, evidence_files: list = None) -> str:
        """Build optimized context that fits within limits"""
        
        # Start with system prompt
        parts = [system_prompt]
        used_tokens = self.estimate_tokens(system_prompt)
        
        # Add case info with truncation for large file lists
        if evidence_files and len(evidence_files) > 50:
            # Summarize large file lists
            file_summary = f"Case has {len(evidence_files)} items. Key items:\n"
            file_summary += "\n".join(evidence_files[:30])
            file_summary += f"\n...[and {len(evidence_files) - 30} more files]"
            case_info = file_summary
        
        case_tokens = self.estimate_tokens(case_info)
        if used_tokens + case_tokens < self.MAX_CONTEXT_TOKENS * 0.6:
            parts.append(case_info)
            used_tokens += case_tokens
        else:
            # Truncate case info
            parts.append(self.truncate_text(case_info, 
                       int((self.MAX_CONTEXT_TOKENS - used_tokens) * 0.3)))
            used_tokens = self.estimate_tokens("\n".join(parts))
        
        # Add conversation history (recent exchanges)
        if self.conversation_history:
            history_text = "Recent conversation:\n"
            for turn in self.conversation_history[-self.max_history_turns:]:
                history_text += f"User: {turn['user'][:200]}\n"
                history_text += f"Geoff: {turn['geoff'][:200]}\n"
            
            history_tokens = self.estimate_tokens(history_text)
            if used_tokens + history_tokens < self.MAX_CONTEXT_TOKENS * 0.8:
                parts.append(history_text)
                used_tokens += history_tokens
        
        # Add tool info (shorter, always fits)
        remaining_tokens = self.MAX_CONTEXT_TOKENS - used_tokens
        if remaining_tokens > 500:
            parts.append(tool_info)
        
        return "\n\n".join(parts)
    
    def add_exchange(self, user_msg: str, geoff_response: str):
        """Add exchange to conversation history"""
        self.conversation_history.append({
            'user': user_msg,
            'geoff': geoff_response,
            'timestamp': datetime.now().isoformat()
        })
        
        # Keep only recent history
        if len(self.conversation_history) > self.max_history_turns * 2:
            self.conversation_history = self.conversation_history[-self.max_history_turns:]
    
    def clear_history(self):
        """Clear conversation history (e.g., new case)"""
        self.conversation_history = []

# Initialize global context manager
context_manager = ContextManager()

# Git Action Logger for audit trail
def git_commit_action(message: str, base_path: str = "/home/claw/.openclaw/workspace/geoff-private"):
    """Git commit for audit trail"""
    try:
        # Configure git if not already set
        subprocess.run(['git', 'config', 'user.email'], cwd=base_path, capture_output=True, check=True)
    except:
        # Set default git config
        subprocess.run(['git', 'config', 'user.email', 'geoff@dfir.local'], cwd=base_path, capture_output=True)
        subprocess.run(['git', 'config', 'user.name', 'Geoff DFIR'], cwd=base_path, capture_output=True)
    
    try:
        subprocess.run(['git', 'add', '.'], cwd=base_path, check=True, capture_output=True)
        subprocess.run(['git', 'commit', '-m', f"[GEOFF-ACTION] {message}"], cwd=base_path, capture_output=True)
        print(f"[GIT] Committed: {message}")
    except:
        pass  # Git not available or nothing to commit

class ActionLogger:
    """Logger for all Geoff actions with git integration"""
    
    def __init__(self, log_dir: str = "/home/claw/.openclaw/workspace/geoff-private/logs"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.action_log = self.log_dir / f"actions_{datetime.now().strftime('%Y%m')}.jsonl"
    
    def log(self, action_type: str, details: dict, commit: bool = True):
        """Log an action with optional git commit"""
        entry = {
            'timestamp': datetime.now().isoformat(),
            'action_type': action_type,
            'details': details
        }
        
        # Append to JSONL file
        with open(self.action_log, 'a') as f:
            f.write(json.dumps(entry) + '\n')
        
        # Git commit for audit trail
        if commit:
            git_commit_action(f"{action_type}: {details.get('description', 'action')}")
        
        return entry

# Initialize global action logger
action_logger = ActionLogger()

app = Flask(__name__)
CORS(app)

# Configuration
EVIDENCE_BASE_DIR = os.environ.get('GEOFF_EVIDENCE_PATH', "/home/sansforensics/evidence-storage/cases")
PORT = int(os.environ.get('GEOFF_PORT', 8080))
OLLAMA_URL = os.environ.get('OLLAMA_URL', "http://192.168.1.31:11434")
LLM_MODEL = os.environ.get('GEOFF_MODEL', "qwen3-coder-next:cloud")

# Initialize extended orchestrator with 100% coverage
orchestrator = ExtendedOrchestrator(EVIDENCE_BASE_DIR)

# Shared JSON Schema for investigation steps
INVESTIGATION_SCHEMA = {
    "type": "object",
    "required": ["investigation_id", "steps", "current_step"],
    "properties": {
        "investigation_id": {"type": "string"},
        "case_name": {"type": "string"},
        "created_at": {"type": "string", "format": "date-time"},
        "updated_at": {"type": "string", "format": "date-time"},
        "current_step": {"type": "integer", "minimum": 0},
        "steps": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["index", "module", "function", "status"],
                "properties": {
                    "index": {"type": "integer"},
                    "module": {
                        "type": "string",
                        "enum": ["sleuthkit", "volatility", "yara", "strings", "registry", "plaso", "network", "logs", "mobile", "chat", "analysis"]
                    },
                    "function": {"type": "string"},
                    "params": {"type": "object"},
                    "description": {"type": "string"},
                    "status": {
                        "type": "string",
                        "enum": ["pending", "running", "completed", "failed"]
                    },
                    "added_at": {"type": "string", "format": "date-time"},
                    "completed_at": {"type": "string", "format": "date-time"},
                    "result": {"type": "object"}
                }
            }
        },
        "artifacts": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "type": {"type": "string"},
                    "path": {"type": "string"},
                    "description": {"type": "string"},
                    "hash": {"type": "string"}
                }
            }
        }
    }
}

GEOFF_PROMPT = """You are Geoff, a digital forensics investigator who chats about evidence findings.

You have access to the complete SIFT forensics toolkit with 100% coverage:

**Disk Forensics (SleuthKit):**
- Partition analysis (mmls)
- File system stats (fsstat)
- File listing (fls)
- File extraction (icat)
- Inode analysis (istat, ils)

**Memory Forensics (Volatility):**
- Process lists (pslist)
- Network connections (netscan)
- Malware detection (malfind)
- Registry scanning
- Process dumping

**Malware Detection (YARA):**
- Signature scanning
- Directory scanning

**IOC Extraction (strings):**
- String extraction
- URL/IP/email detection
- Registry path extraction

**Windows Registry (RegRipper):**
- Hive parsing
- UserAssist (program execution)
- ShellBags (folder access)
- USB device history
- Autoruns/Startup
- Services
- Mounted devices

**Timeline Analysis (Plaso):**
- Timeline creation (log2timeline)
- Timeline sorting (psort)
- Super timeline generation

**Network Forensics:**
- PCAP analysis (tshark)
- TCP flow extraction
- HTTP traffic analysis
- DNS extraction

**Log Analysis:**
- Windows Event Logs (EVTX)
- Syslog parsing
- Authentication event extraction

**Mobile Forensics:**
- iOS backup analysis
- Android data analysis

Keep it conversational. Don't give orders or numbered instructions. Just talk about what you see and let the user decide what to do next. Be helpful but not bossy."""

def call_llm(user_message, context=""):
    """Call Ollama LLM"""
    try:
        full_prompt = f"{GEOFF_PROMPT}\n\n{context}\n\nUser: {user_message}\n\nGeoff:"
        response = requests.post(
            f"{OLLAMA_URL}/api/generate",
            json={
                "model": LLM_MODEL,
                "prompt": full_prompt,
                "stream": False,
                "options": {"temperature": 0.8}
            },
            timeout=120
        )
        if response.status_code == 200:
            return response.json().get('response', 'Hmm, let me check that again.')
    except Exception as e:
        print(f"LLM Error: {e}")
    return "Having trouble connecting. Let me look at the evidence directly."

def detect_tool_request(message: str) -> dict:
    """Detect if user is asking to run a forensic tool - 100% coverage"""
    message_lower = message.lower()
    
    # SleuthKit patterns
    if any(word in message_lower for word in ['mmls', 'partition table', 'partition layout']):
        return {'module': 'sleuthkit', 'function': 'analyze_partition_table', 'params': {}}
    
    if any(word in message_lower for word in ['fsstat', 'filesystem', 'file system stats']):
        return {'module': 'sleuthkit', 'function': 'analyze_filesystem', 'params': {}}
    
    if any(word in message_lower for word in ['fls', 'list files', 'show files', 'directory listing']):
        return {'module': 'sleuthkit', 'function': 'list_files', 'params': {'recursive': True}}
    
    if any(word in message_lower for word in ['icat', 'extract file', 'get file']):
        return {'module': 'sleuthkit', 'function': 'extract_file', 'params': {}}
    
    if any(word in message_lower for word in ['istat', 'file info', 'inode details']):
        return {'module': 'sleuthkit', 'function': 'get_file_info', 'params': {}}
    
    if any(word in message_lower for word in ['ils', 'list inodes']):
        return {'module': 'sleuthkit', 'function': 'list_inodes', 'params': {}}
    
    # Volatility patterns
    if any(word in message_lower for word in ['volatility', 'memory dump', 'process list', 'pslist']):
        return {'module': 'volatility', 'function': 'process_list', 'params': {}}
    
    if any(word in message_lower for word in ['netscan', 'network connections', 'connections']):
        return {'module': 'volatility', 'function': 'network_scan', 'params': {}}
    
    if any(word in message_lower for word in ['malfind', 'malware', 'injected code']):
        return {'module': 'volatility', 'function': 'find_malware', 'params': {}}
    
    if any(word in message_lower for word in ['dump process', 'proc dump']):
        return {'module': 'volatility', 'function': 'dump_process', 'params': {}}
    
    # YARA patterns
    if any(word in message_lower for word in ['yara', 'scan for malware', 'signature scan']):
        return {'module': 'yara', 'function': 'scan_file', 'params': {}}
    
    if any(word in message_lower for word in ['yara scan directory', 'scan folder']):
        return {'module': 'yara', 'function': 'scan_directory', 'params': {}}
    
    # Strings patterns
    if any(word in message_lower for word in ['strings', 'extract strings', 'find iocs']):
        return {'module': 'strings', 'function': 'extract_strings', 'params': {}}
    
    # Registry patterns
    if any(word in message_lower for word in ['registry', 'regripper', 'hive']):
        return {'module': 'registry', 'function': 'parse_hive', 'params': {}}
    
    if any(word in message_lower for word in ['userassist', 'program execution']):
        return {'module': 'registry', 'function': 'extract_user_assist', 'params': {}}
    
    if any(word in message_lower for word in ['shellbags', 'folder access']):
        return {'module': 'registry', 'function': 'extract_shellbags', 'params': {}}
    
    if any(word in message_lower for word in ['usb devices', 'usbstor']):
        return {'module': 'registry', 'function': 'extract_usb_devices', 'params': {}}
    
    if any(word in message_lower for word in ['autoruns', 'run keys']):
        return {'module': 'registry', 'function': 'extract_autoruns', 'params': {}}
    
    if any(word in message_lower for word in ['services', 'service config']):
        return {'module': 'registry', 'function': 'extract_services', 'params': {}}
    
    if any(word in message_lower for word in ['mounted devices']):
        return {'module': 'registry', 'function': 'extract_mounted_devices', 'params': {}}
    
    # Timeline/Plaso patterns
    if any(word in message_lower for word in ['timeline', 'log2timeline', 'plaso']):
        return {'module': 'plaso', 'function': 'create_timeline', 'params': {}}
    
    if any(word in message_lower for word in ['sort timeline', 'psort']):
        return {'module': 'plaso', 'function': 'sort_timeline', 'params': {}}
    
    # Network patterns
    if any(word in message_lower for word in ['pcap', 'network capture', 'packet']):
        return {'module': 'network', 'function': 'analyze_pcap', 'params': {}}
    
    if any(word in message_lower for word in ['tcpflow', 'extract flows']):
        return {'module': 'network', 'function': 'extract_flows', 'params': {}}
    
    if any(word in message_lower for word in ['http extract', 'web traffic']):
        return {'module': 'network', 'function': 'extract_http', 'params': {}}
    
    # Log patterns
    if any(word in message_lower for word in ['evtx', 'windows event log']):
        return {'module': 'logs', 'function': 'parse_evtx', 'params': {}}
    
    if any(word in message_lower for word in ['syslog', 'linux log']):
        return {'module': 'logs', 'function': 'parse_syslog', 'params': {}}
    
    # Mobile patterns
    if any(word in message_lower for word in ['ios', 'iphone', 'ipad']):
        return {'module': 'mobile', 'function': 'analyze_ios_backup', 'params': {}}
    
    if any(word in message_lower for word in ['android', 'mobile']):
        return {'module': 'mobile', 'function': 'analyze_android', 'params': {}}
    
    return None

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
                cases[case_name] = get_evidence_recursive(case_path)
    except Exception as e:
        print(f"Error reading cases: {e}")
    return cases

def get_available_tools_status():
    """Get status of all forensic tools"""
    return orchestrator.get_available_tools()

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
            white-space: pre-wrap;
        }
        
        .message.system {
            align-self: center;
            background: transparent;
            color: #8b949e;
            font-style: italic;
            font-size: 0.85rem;
        }
        
        .message.tool-result {
            align-self: flex-start;
            background: #1c4428;
            border: 1px solid #238636;
            color: #c9d1d9;
            font-family: 'SF Mono', Monaco, monospace;
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
        
        /* Tools Panel */
        #tools-content {
            flex: 1;
            overflow-y: auto;
            padding: 20px 25px;
        }
        
        .tool-category {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 16px;
            margin-bottom: 16px;
        }
        
        .tool-category h3 {
            color: #58a6ff;
            margin-bottom: 12px;
            font-size: 1rem;
        }
        
        .tool-status {
            display: flex;
            align-items: center;
            gap: 8px;
            margin-bottom: 8px;
            font-size: 0.9rem;
        }
        
        .tool-status.available { color: #3fb950; }
        .tool-status.unavailable { color: #f85149; }
        
        .tool-functions {
            font-family: 'SF Mono', Monaco, monospace;
            font-size: 0.8rem;
            color: #8b949e;
            margin-left: 20px;
        }
        
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
        <div class="tab" onclick="showTab('evidence')">📁 Evidence</div>
        <div class="tab" onclick="showTab('tools')">🛠️ Tools</div>
    </div>
    
    <div id="chat" class="content active">
        <div id="chat-content">
            <div class="message system">Hey! I'm Geoff. What case should we look at? I can also run forensic tools like SleuthKit, Volatility, YARA, and strings analysis.</div>
        </div>
        <div class="chat-input-area">
            <input type="text" id="chat-input" placeholder="e.g., Run mmls on the narcos disk image..." onkeypress="if(event.key==='Enter') sendChat()">
            <button class="send-btn" onclick="sendChat()">Send</button>
        </div>
    </div>
    
    <div id="evidence" class="content">
        <div id="evidence-content">
            <div class="loading">Loading evidence...</div>
        </div>
    </div>
    
    <div id="tools" class="content">
        <div id="tools-content">
            <div class="loading">Loading tools...</div>
        </div>
    </div>
    
    <script>
        function showTab(tab) {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.content').forEach(c => c.classList.remove('active'));
            event.target.classList.add('active');
            document.getElementById(tab).classList.add('active');
            if(tab === 'evidence') loadEvidence();
            if(tab === 'tools') loadTools();
        }
        
        function addMessage(text, type) {
            const chat = document.getElementById('chat-content');
            const div = document.createElement('div');
            div.className = 'message ' + type;
            if(type === 'user') {
                div.innerHTML = '<div class="label">You</div>' + text;
            } else if(type === 'geoff') {
                div.innerHTML = '<div class="label">Geoff</div>' + text;
            } else if(type === 'tool-result') {
                div.innerHTML = '<div class="label">Tool Output</div>' + text;
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
            addMessage('Looking...', 'system');
            
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
                
                // If tool was run, show result
                if(data.tool_result) {
                    addMessage(JSON.stringify(data.tool_result, null, 2), 'tool-result');
                }
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
        
        async function loadTools() {
            const container = document.getElementById('tools-content');
            container.innerHTML = '<div class="loading">Loading...</div>';
            
            try {
                const res = await fetch('/tools');
                const data = await res.json();
                const tools = data.tools || {};
                
                let html = '';
                for(const [tool, info] of Object.entries(tools)) {
                    const available = info.available === true || (typeof info.available === 'object' && Object.values(info.available).some(v => v));
                    const statusClass = available ? 'available' : 'unavailable';
                    const statusIcon = available ? '✅' : '❌';
                    
                    html += '<div class="tool-category">';
                    html += '<h3>' + tool.toUpperCase() + '</h3>';
                    html += '<div class="tool-status ' + statusClass + '">' + statusIcon + ' ' + (available ? 'Available' : 'Not Available') + '</div>';
                    
                    if(info.functions && info.functions.length > 0) {
                        html += '<div class="tool-functions">';
                        html += info.functions.join(', ');
                        html += '</div>';
                    }
                    html += '</div>';
                }
                container.innerHTML = html;
            } catch(e) {
                container.innerHTML = '<div class="loading">Error loading tools: ' + e.message + '</div>';
            }
        }
        
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
    """LLM-powered chat with tool detection"""
    try:
        data = request.json
        user_msg = data.get('message', '')
        
        if not user_msg:
            return jsonify({'response': 'What would you like to look at?'})
        
        # Detect if user wants to run a tool
        tool_request = detect_tool_request(user_msg)
        tool_result = None
        evidence_file = None
        
        # Check if user mentions a case
        cases = get_all_cases()
        case_match = None
        files = []
        for case_name in cases.keys():
            if case_name.lower() in user_msg.lower():
                case_match = case_name
                files = cases[case_name]
                break
        
        # If tool request detected, run it
        if tool_request and case_match:
            # Find evidence file from context
            case_path = Path(EVIDENCE_BASE_DIR) / case_match
            # Look for disk images or memory dumps
            for ext in ['.E01', '.dd', '.raw', '.mem', '.img']:
                matches = list(case_path.rglob(f'*{ext}'))
                if matches:
                    evidence_file = str(matches[0])
                    break
            
            if evidence_file:
                tool_request['params']['disk_image'] = evidence_file
                if 'partition' in tool_request['function']:
                    tool_request['params']['partition'] = evidence_file
            
            # Run the tool
            step = {
                'module': tool_request['module'],
                'function': tool_request['function'],
                'params': tool_request['params'],
                'status': 'running'
            }
            tool_result = orchestrator.run_playbook_step('chat-session', step)
        
        # Build optimized context using ContextManager
        case_info = ""
        if case_match:
            case_info = f"Case '{case_match}' has {len(files)} items.\n" + "\n".join(files)
        
        tool_info = """Available forensic tools:
- SleuthKit: mmls (partition), fls (list files), fsstat (filesystem), icat (extract), istat/ils (inodes)
- Volatility: process list, network scan, malware find, registry scan, process dump
- YARA: signature scan, directory scan
- Strings: extract IOCs (URLs, IPs, emails, registry paths)
- Registry: hive parsing, UserAssist, ShellBags, USB history, autoruns, services
- Timeline: log2timeline (create), psort (sort), super timeline
- Network: pcap analysis, tcpflow, HTTP extraction
- Logs: EVTX parsing, syslog analysis
- Mobile: iOS backup, Android data"""
        
        # Build optimized context
        context = context_manager.build_context(
            GEOFF_PROMPT,
            case_info,
            tool_info,
            user_msg,
            files if case_match else []
        )
        
        # Log the chat action
        action_logger.log('CHAT', {
            'user_message': user_msg,
            'case': case_match,
            'tool_executed': tool_request['module'] + '.' + tool_request['function'] if tool_request else None,
            'description': f"Chat with {case_match or 'no case'}"
        })
        
        # Call LLM
        response = call_llm(user_msg, context)
        
        # Add to conversation history (with truncation for large responses)
        context_manager.add_exchange(
            user_msg[:500],  # Truncate long user messages
            response[:1000]  # Truncate long responses
        )
        
        result = {'response': response}
        if tool_result:
            result['tool_result'] = tool_result
            # Log tool execution
            action_logger.log('TOOL_EXECUTION', {
                'module': tool_request['module'],
                'function': tool_request['function'],
                'case': case_match,
                'evidence_file': evidence_file,
                'description': f"Ran {tool_request['module']}.{tool_request['function']} on {case_match}"
            })
        
        return jsonify(result)
    except Exception as e:
        action_logger.log('ERROR', {'error': str(e), 'user_message': user_msg})
        return jsonify({'response': f'Error: {str(e)}'})

@app.route('/cases', methods=['GET'])
def list_cases():
    """Return ALL cases with ALL files"""
    return jsonify({'cases': get_all_cases()})

@app.route('/tools', methods=['GET'])
def list_tools():
    """Return available forensic tools"""
    return jsonify({'tools': get_available_tools_status()})

@app.route('/run-tool', methods=['POST'])
def run_tool():
    """Execute a forensic tool directly"""
    try:
        data = request.json
        module = data.get('module')
        function = data.get('function')
        params = data.get('params', {})
        
        # Log the tool execution request
        action_logger.log('TOOL_API_CALL', {
            'module': module,
            'function': function,
            'params': params,
            'description': f"API call to run {module}.{function}"
        })
        
        step = {
            'module': module,
            'function': function,
            'params': params,
            'status': 'running'
        }
        
        result = orchestrator.run_playbook_step('api-call', step)
        
        # Log successful execution
        action_logger.log('TOOL_API_SUCCESS', {
            'module': module,
            'function': function,
            'result_status': result.get('status'),
            'description': f"API {module}.{function} completed"
        })
        
        return jsonify(result)
    except Exception as e:
        action_logger.log('TOOL_API_ERROR', {
            'module': module,
            'function': function,
            'error': str(e),
            'description': f"API {module}.{function} failed"
        })
        return jsonify({'status': 'error', 'error': str(e)})

if __name__ == '__main__':
    print(f'Geoff DFIR on port {PORT}')
    print(f'Evidence: {EVIDENCE_BASE_DIR}')
    print(f'Ollama: {OLLAMA_URL}')
    print(f'Model: {LLM_MODEL}')
    app.run(host='0.0.0.0', port=PORT, debug=False, threaded=True)
