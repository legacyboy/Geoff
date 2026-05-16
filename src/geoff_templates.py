# -*- coding: utf-8 -*-
"""Geoff DFIR — Embedded HTML/JS/CSS templates (pure string constants).

Module 2 in the refactoring plan.  Leaf module — no internal dependencies.
"""

# ---------------------------------------------------------------------------
# HTML Template (with Find Evil tab)
# ---------------------------------------------------------------------------

HTML_TEMPLATE = r"""
<!DOCTYPE html>
<html>
<head>
    <title>Geoff DFIR</title>
    <meta charset="UTF-8">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500;600&display=swap" rel="stylesheet">
    <!-- GEOFF_API_KEY_META -->
    <style>
        :root {
            --g-bg:          #0B1220;
            --g-bg-2:        #0F172A;
            --g-surface:     #1E293B;
            --g-surface-2:   #172033;
            --g-border:      #334155;
            --g-border-soft: #1F2A3F;
            --g-text:        #F1F5F9;
            --g-text-dim:    #94A3B8;
            --g-text-mute:   #64748B;
            --g-blue:        #3B82F6;
            --g-blue-soft:   #60A5FA;
            --g-green:       #10B981;
            --g-amber:       #F59E0B;
            --g-red:         #EF4444;
            --font-sans: "IBM Plex Sans", -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
            --font-mono: "IBM Plex Mono", "SF Mono", Menlo, Consolas, monospace;
            --radius: 6px;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: var(--font-sans);
            background: var(--g-bg);
            color: var(--g-text);
            height: 100vh;
            display: flex;
            flex-direction: column;
            font-size: 13px;
            line-height: 1.4;
            -webkit-font-smoothing: antialiased;
        }

        header {
            background: var(--g-bg-2);
            border-bottom: 1px solid var(--g-border-soft);
            padding: 0 16px;
            height: 48px;
            display: flex;
            align-items: center;
            gap: 20px;
            flex-shrink: 0;
        }

        .brand {
            display: flex;
            align-items: baseline;
            gap: 8px;
            font-family: var(--font-mono);
            font-weight: 600;
            letter-spacing: 0.5px;
        }

        .brand .logo {
            color: var(--g-blue-soft);
            font-size: 15px;
        }

        .brand .tag {
            color: var(--g-text-mute);
            font-size: 10px;
            letter-spacing: 1.5px;
            text-transform: uppercase;
        }

        .tabs {
            display: flex;
            gap: 2px;
            flex: 1;
        }

        .tab {
            padding: 6px 12px;
            cursor: pointer;
            color: var(--g-text-mute);
            border-radius: var(--radius);
            font-size: 12px;
            letter-spacing: 0.3px;
            transition: all 0.15s;
            border: none;
            background: none;
        }

        .tab:hover { color: var(--g-text-dim); background: var(--g-surface-2); }
        .tab.active {
            color: var(--g-blue-soft);
            background: rgba(59, 130, 246, 0.1);
        }

        .header-right {
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .status {
            display: flex;
            align-items: center;
            gap: 6px;
            color: var(--g-text-mute);
            font-family: var(--font-mono);
            font-size: 11px;
            letter-spacing: 0.3px;
        }

        .status .dot {
            width: 6px;
            height: 6px;
            border-radius: 50%;
            background: var(--g-green);
            flex-shrink: 0;
        }

        .content {
            flex: 1;
            overflow: hidden;
            display: none;
        }

        .content.active { display: flex; flex-direction: column; }

        /* Investigation output — chat messages + live log stream */
        #fe-output {
            flex: 1;
            overflow-y: auto;
            padding: 16px 20px;
            display: flex;
            flex-direction: column;
            gap: 10px;
            min-height: 0;
        }

        .message {
            max-width: 85%;
            padding: 10px 14px;
            border-radius: var(--radius);
            line-height: 1.6;
            font-size: 13px;
        }

        .message.user {
            align-self: flex-end;
            background: var(--g-blue);
            color: white;
        }

        .message.geoff {
            align-self: flex-start;
            background: var(--g-surface);
            border: 1px solid var(--g-border-soft);
            color: var(--g-text);
            white-space: pre-wrap;
        }

        .message.system {
            align-self: center;
            background: transparent;
            color: var(--g-text-mute);
            font-style: italic;
            font-size: 12px;
        }

        .message.tool-result {
            align-self: flex-start;
            background: rgba(16, 185, 129, 0.06);
            border: 1px solid rgba(16, 185, 129, 0.2);
            color: var(--g-text);
            font-family: var(--font-mono);
            font-size: 12px;
        }

        .message .label {
            font-size: 10px;
            font-weight: 600;
            margin-bottom: 4px;
            opacity: 0.7;
            text-transform: uppercase;
            letter-spacing: 0.8px;
        }

        .chat-input-area {
            padding: 12px 20px;
            background: var(--g-bg-2);
            border-top: 1px solid var(--g-border-soft);
            display: flex;
            gap: 8px;
        }

        #chat-input {
            flex: 1;
            padding: 9px 12px;
            background: var(--g-surface-2);
            border: 1px solid var(--g-border-soft);
            border-radius: var(--radius);
            color: var(--g-text);
            font-size: 13px;
            font-family: var(--font-sans);
        }

        #chat-input::placeholder { color: var(--g-text-mute); }

        #chat-input:focus {
            outline: none;
            border-color: var(--g-blue);
        }

        .send-btn {
            padding: 9px 20px;
            background: var(--g-green);
            color: white;
            border: none;
            border-radius: var(--radius);
            cursor: pointer;
            font-weight: 600;
            font-size: 13px;
            font-family: var(--font-sans);
            transition: opacity 0.15s;
        }

        .send-btn:hover { opacity: 0.85; }

        /* Evidence Styles */
        #evidence-content {
            flex: 1;
            overflow-y: auto;
            padding: 18px 20px;
        }

        .case-list {
            display: flex;
            flex-direction: column;
            gap: 12px;
        }

        .case-card {
            background: var(--g-bg-2);
            border: 1px solid var(--g-border-soft);
            border-radius: var(--radius);
            overflow: hidden;
        }

        .case-header {
            padding: 10px 14px;
            background: var(--g-surface-2);
            border-bottom: 1px solid var(--g-border-soft);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .case-name {
            font-family: var(--font-mono);
            font-weight: 600;
            color: var(--g-blue-soft);
            font-size: 12px;
        }

        .case-count {
            color: var(--g-text-mute);
            font-size: 11px;
            font-family: var(--font-mono);
        }

        .case-files {
            padding: 10px 14px;
        }

        .file-item {
            padding: 5px 0;
            border-bottom: 1px solid var(--g-border-soft);
            font-family: var(--font-mono);
            font-size: 11.5px;
            color: var(--g-text-dim);
        }

        .file-item:last-child { border-bottom: none; }

        .file-item.dir { color: var(--g-blue-soft); }
        .file-item.file { color: #A78BFA; }

        /* Find Evil Tab */
        #findevil-content {
            flex: 1;
            overflow: hidden;
            display: flex;
            flex-direction: column;
        }

        .fe-top-bar {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 9px 20px;
            background: var(--g-bg-2);
            border-bottom: 1px solid var(--g-border-soft);
            flex-shrink: 0;
        }

        .fe-top-bar label {
            color: var(--g-text-mute);
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.8px;
            white-space: nowrap;
            flex-shrink: 0;
        }

        .fe-top-bar input[type="text"] {
            flex: 1;
            padding: 7px 10px;
            background: var(--g-surface-2);
            border: 1px solid var(--g-border-soft);
            border-radius: var(--radius);
            color: var(--g-text);
            font-size: 12px;
            font-family: var(--font-mono);
        }

        .fe-top-bar input[type="text"]::placeholder { color: var(--g-text-mute); }

        .fe-top-bar input:focus {
            outline: none;
            border-color: var(--g-blue);
        }

        .fe-run-btn {
            padding: 7px 16px;
            background: var(--g-red);
            color: white;
            border: none;
            border-radius: var(--radius);
            cursor: pointer;
            font-weight: 600;
            font-size: 12px;
            font-family: var(--font-sans);
            transition: opacity 0.15s;
            white-space: nowrap;
            flex-shrink: 0;
        }

        .fe-run-btn:hover { opacity: 0.85; }
        .fe-run-btn:disabled { opacity: 0.4; cursor: not-allowed; }

        #fe-progress-area {
            flex-shrink: 0;
            padding: 10px 20px 0;
        }

        .fe-progress {
            background: var(--g-bg-2);
            border: 1px solid var(--g-border-soft);
            border-radius: var(--radius);
            padding: 10px 14px;
        }

        .fe-progress-bar {
            width: 100%;
            height: 18px;
            background: var(--g-surface);
            border-radius: 4px;
            overflow: hidden;
            margin: 8px 0;
        }

        .fe-progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #059669, var(--g-green));
            border-radius: 4px;
            transition: width 0.5s ease;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 10px;
            font-weight: 700;
            font-family: var(--font-mono);
            color: white;
            min-width: 36px;
        }

        .fe-status-text {
            color: var(--g-text-mute);
            font-size: 11.5px;
            font-family: var(--font-mono);
        }

        .fe-status-text strong {
            color: var(--g-text-dim);
            font-weight: 500;
        }

        .fe-results {
            background: var(--g-bg-2);
            border: 1px solid var(--g-border-soft);
            border-radius: var(--radius);
            padding: 14px;
        }

        .fe-severity {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 3px;
            font-weight: 600;
            font-size: 10px;
            font-family: var(--font-mono);
            letter-spacing: 0.5px;
            margin-bottom: 8px;
        }

        .fe-severity.CRITICAL { background: rgba(239,68,68,0.15);  color: #EF4444; }
        .fe-severity.HIGH     { background: rgba(245,158,11,0.15); color: #F59E0B; }
        .fe-severity.MEDIUM   { background: rgba(96,165,250,0.15); color: #60A5FA; }
        .fe-severity.LOW      { background: rgba(16,185,129,0.12); color: #10B981; }
        .fe-severity.INFO     { background: rgba(100,116,139,0.15);color: #64748B; }
        /* ORANGE classification for Data Exfil */
        .classification-Data-Exfil, .fe-severity.Data-Exfil { 
            background: rgba(251, 146, 60, 0.2); 
            color: #FB923C; 
            border: 1px solid #FB923C;
        }

        .fe-pb-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 8px;
            font-size: 12px;
        }

        .fe-pb-table th {
            text-align: left;
            padding: 7px 10px;
            border-bottom: 1px solid var(--g-border);
            color: var(--g-text-mute);
            font-weight: 500;
            letter-spacing: 0.5px;
            text-transform: uppercase;
            font-size: 10px;
        }

        .fe-pb-table td {
            padding: 5px 10px;
            border-bottom: 1px solid var(--g-border-soft);
            font-family: var(--font-mono);
            font-size: 11.5px;
        }

        .fe-pb-table .completed { color: var(--g-green); }
        .fe-pb-table .failed    { color: var(--g-red); }
        .fe-pb-table .skipped   { color: var(--g-text-mute); }

        /* Tools Panel */
        #tools-content {
            flex: 1;
            overflow-y: auto;
            padding: 18px 20px;
        }

        .tool-category {
            background: var(--g-bg-2);
            border: 1px solid var(--g-border-soft);
            border-radius: var(--radius);
            padding: 14px;
            margin-bottom: 12px;
        }

        .tool-category h3 {
            color: var(--g-blue-soft);
            margin-bottom: 10px;
            font-size: 12px;
            font-family: var(--font-mono);
            letter-spacing: 0.3px;
        }

        .tool-status {
            display: flex;
            align-items: center;
            gap: 8px;
            margin-bottom: 6px;
            font-size: 12px;
        }

        .tool-status.available   { color: var(--g-green); }
        .tool-status.unavailable { color: var(--g-red); }

        .tool-functions {
            font-family: var(--font-mono);
            font-size: 11px;
            color: var(--g-text-mute);
            margin-left: 18px;
        }

        .loading {
            text-align: center;
            padding: 40px;
            color: var(--g-text-mute);
            font-size: 12px;
        }

        /* Reports Tab */
        #reports-content {
            flex: 1;
            display: flex;
            overflow: hidden;
        }

        .reports-sidebar {
            width: 280px;
            flex-shrink: 0;
            background: var(--g-bg-2);
            border-right: 1px solid var(--g-border-soft);
            display: flex;
            flex-direction: column;
            overflow: hidden;
        }

        .reports-sidebar-header {
            padding: 10px 12px;
            border-bottom: 1px solid var(--g-border-soft);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .reports-sidebar-header h3 {
            color: var(--g-text-mute);
            font-size: 10px;
            text-transform: uppercase;
            letter-spacing: 1.2px;
            font-weight: 500;
        }

        .import-btn {
            padding: 4px 10px;
            background: none;
            color: var(--g-blue-soft);
            border: 1px solid var(--g-border);
            border-radius: 4px;
            cursor: pointer;
            font-size: 11px;
            font-family: var(--font-sans);
            white-space: nowrap;
            transition: all 0.12s;
        }

        .import-btn:hover {
            border-color: var(--g-blue);
            background: rgba(59, 130, 246, 0.08);
        }

        .reports-list {
            flex: 1;
            overflow-y: auto;
            padding: 6px;
        }

        .report-entry {
            padding: 9px 10px;
            border-radius: 4px;
            cursor: pointer;
            margin-bottom: 2px;
            border: 1px solid transparent;
            border-left: 2px solid transparent;
            transition: all 0.12s;
        }

        .report-entry:hover { background: var(--g-surface); border-color: var(--g-border-soft); }
        .report-entry.active { background: rgba(59,130,246,0.08); border-color: var(--g-border-soft); border-left-color: var(--g-blue); }

        .report-entry-name {
            font-family: var(--font-mono);
            font-size: 11.5px;
            color: var(--g-text);
            margin-bottom: 5px;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }

        .report-entry-meta {
            display: flex;
            gap: 5px;
            align-items: center;
            flex-wrap: wrap;
        }

        .report-ts {
            color: var(--g-text-mute);
            font-family: var(--font-mono);
            font-size: 10px;
            margin-top: 3px;
        }

        .evil-badge {
            display: inline-block;
            padding: 1px 6px;
            border-radius: 3px;
            font-family: var(--font-mono);
            font-size: 9px;
            font-weight: 600;
            letter-spacing: 0.5px;
        }

        .evil-badge.evil  { background: rgba(239,68,68,0.15);  color: #EF4444; }
        .evil-badge.clean { background: rgba(16,185,129,0.12); color: #10B981; }

        .reports-viewer {
            flex: 1;
            overflow-y: auto;
            padding: 18px 24px;
        }

        .reports-placeholder {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            height: 100%;
            color: var(--g-text-mute);
            font-size: 12px;
            text-align: center;
            gap: 10px;
            line-height: 1.6;
        }

        .stat-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(140px, 1fr));
            gap: 8px;
            margin-bottom: 18px;
        }

        .stat-card {
            background: var(--g-surface);
            border: 1px solid var(--g-border-soft);
            border-radius: var(--radius);
            padding: 10px 12px;
        }

        .stat-card .stat-label {
            color: var(--g-text-mute);
            font-size: 9.5px;
            text-transform: uppercase;
            letter-spacing: 0.8px;
            margin-bottom: 4px;
        }

        .stat-card .stat-value {
            color: var(--g-text);
            font-family: var(--font-mono);
            font-size: 18px;
            font-weight: 500;
            line-height: 1.1;
        }

        .report-section {
            margin-bottom: 20px;
        }

        .report-section h3 {
            font-size: 10px;
            text-transform: uppercase;
            letter-spacing: 1.2px;
            color: var(--g-text-mute);
            margin-bottom: 8px;
            padding-bottom: 6px;
            border-bottom: 1px solid var(--g-border-soft);
        }

        .chain-box {
            background: var(--g-surface);
            border: 1px solid var(--g-border-soft);
            border-radius: var(--radius);
            padding: 12px 16px;
        }

        .chain-box p {
            font-size: 12px;
            margin-bottom: 4px;
            color: var(--g-text);
            font-family: var(--font-mono);
        }

        .mitre-tag {
            display: inline-block;
            background: rgba(100,116,139,0.15);
            padding: 1px 6px;
            border-radius: 3px;
            font-family: var(--font-mono);
            font-size: 10px;
            margin: 2px;
            color: #A78BFA;
            letter-spacing: 0.3px;
        }

        .flag-box {
            background: var(--g-surface-2);
            border: 1px solid rgba(239,68,68,0.3);
            border-left: 3px solid var(--g-red);
            border-radius: var(--radius);
            padding: 10px 14px;
        }

        .flag-box p {
            color: var(--g-amber);
            font-family: var(--font-mono);
            font-size: 11.5px;
            margin-bottom: 3px;
        }

        .inv-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(130px, 1fr));
            gap: 6px;
        }

        .inv-card {
            background: var(--g-surface);
            border: 1px solid var(--g-border-soft);
            border-radius: var(--radius);
            padding: 8px 10px;
        }

        .inv-card .inv-type {
            color: var(--g-text-mute);
            font-size: 9.5px;
            text-transform: capitalize;
            letter-spacing: 0.3px;
            margin-bottom: 2px;
        }

        .inv-card .inv-count {
            color: var(--g-blue-soft);
            font-family: var(--font-mono);
            font-weight: 500;
            font-size: 18px;
            line-height: 1.1;
        }

        .raw-json-toggle {
            background: none;
            color: var(--g-text-mute);
            border: 1px solid var(--g-border);
            border-radius: 4px;
            padding: 4px 10px;
            cursor: pointer;
            font-size: 11px;
            font-family: var(--font-mono);
            transition: all 0.12s;
        }

        .raw-json-toggle:hover { color: var(--g-text); border-color: var(--g-text-mute); }

        /* Scrollbars */
        ::-webkit-scrollbar { width: 8px; height: 8px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: var(--g-border); border-radius: 4px; }
        ::-webkit-scrollbar-thumb:hover { background: var(--g-text-mute); }
    </style>
</head>
<body>
    <header>
        <div class="brand">
            <span class="logo">GEOFF</span>
            <span class="tag">DFIR Platform</span>
        </div>
        <div class="tabs">
            <div class="tab active" onclick="switchTab('findevil', this)">Find Evil</div>
            <div class="tab" onclick="switchTab('evidence', this)">Evidence</div>
            <div class="tab" onclick="switchTab('reports', this)">Reports</div>
        </div>
        <div class="header-right">
            <div class="status"><span class="dot"></span>Online</div>
        </div>
    </header>

    <div id="reports" class="content">
        <div id="reports-content">
            <div class="reports-sidebar">
                <div class="reports-sidebar-header">
                    <h3>Past Cases</h3>
                    <button class="import-btn" onclick="importReportJSON()">⬆ Import JSON</button>
                </div>
                <div class="reports-list" id="reports-list">
                    <div style="padding:16px;color:#64748B;font-size:0.82rem;">Select the Reports tab to load cases.</div>
                </div>
            </div>
            <div class="reports-viewer" id="reports-viewer">
                <div class="reports-placeholder">
                    <div style="font-size:2rem;margin-bottom:8px;">📋</div>
                    <div>Select a completed case from the sidebar<br>or import a JSON report file.</div>
                </div>
            </div>
        </div>
    </div>

    <div id="evidence" class="content">
        <div id="evidence-content">
            <div class="loading">Loading evidence...</div>
        </div>
    </div>

    <div id="findevil" class="content active">
        <div id="findevil-content">

            <!-- Top bar: evidence directory + run button -->
            <div class="fe-top-bar">
                <label for="fe-evidence-dir">Evidence Directory</label>
                <input type="text" id="fe-evidence-dir" placeholder="Paste a folder name or full path…">
                <button class="fe-run-btn" id="fe-run-btn" onclick="runFindEvil()">🔍 Run Find Evil</button>
            </div>

            <!-- Progress bar — shown while a job is running -->
            <div id="fe-progress-area" style="display:none;">
                <div class="fe-progress">
                    <div class="fe-status-text">
                        <strong>Playbook:</strong> <span id="fe-pb-name">—</span> &nbsp;|
                        <strong>Step:</strong> <span id="fe-step-name">—</span> &nbsp;|
                        <strong>Elapsed:</strong> <span id="fe-elapsed">0s</span>
                    </div>
                    <div class="fe-progress-bar">
                        <div class="fe-progress-fill" id="fe-progress-fill" style="width:0%">0%</div>
                    </div>
                </div>
            </div>

            <!-- Unified output: chat messages + live log stream + results -->
            <div id="fe-output">
                <div class="message system">G.E.O.F.F. initialized. Evidence Operations Forensic Framework standing by.

Awaiting investigation directive. Provide an evidence path above or ask me anything below.</div>

                <!-- Live log stream — appended to when a job is running -->
                <div id="fe-log" style="
                    display: none;
                    background: #0B1220;
                    border: 1px solid #1F2A3F;
                    border-radius: 6px;
                    padding: 12px;
                    font-family: 'IBM Plex Mono', 'SF Mono', Menlo, monospace;
                    font-size: 11.5px;
                    color: #64748B;
                    line-height: 1.6;
                "></div>

                <!-- Results card — shown when job completes -->
                <div id="fe-results-area" style="display:none;"></div>
            </div>

            <!-- Chat input pinned at bottom -->
            <div class="chat-input-area">
                <input type="text" id="chat-input"
                       placeholder="Ask Geoff anything, or say 'start processing /path/to/evidence'..."
                       onkeypress="if(event.key==='Enter') sendChat()">
                <button class="send-btn" onclick="sendChat()">Send</button>
            </div>

        </div>
    </div>
    
    <script>
        // Authenticated fetch — adds X-API-Key header when the server set one
        const _geoffApiKey = document.querySelector('meta[name="geoff-api-key"]')?.content || '';
        function authFetch(url, opts = {}) {
            if (_geoffApiKey) {
                opts.headers = Object.assign({}, opts.headers || {}, {'X-API-Key': _geoffApiKey});
            }
            return fetch(url, opts);
        }

        // Evidence base directory (injected by server)
        const EVIDENCE_BASE_DIR = '<!-- GEOFF_EVIDENCE_BASE_DIR -->';

        // Pre-fill the evidence directory input with the server's base path
        document.addEventListener('DOMContentLoaded', () => {
            const inp = document.getElementById('fe-evidence-dir');
            if (inp && EVIDENCE_BASE_DIR) inp.value = EVIDENCE_BASE_DIR;
        });

        function switchTab(tab, el) {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.content').forEach(c => c.classList.remove('active'));
            var activeTab = el || document.querySelector('.tab.active') || document.querySelector('[onclick*="' + tab + '"]');
            if (activeTab) activeTab.classList.add('active');
            document.getElementById(tab).classList.add('active');
            if (tab === 'evidence') loadEvidence();
            if (tab === 'reports') loadReports();
        }

        // ---- Reports Tab ----

        function _escHtml(s) {
            return (s || '').toString()
                .replace(/&/g,'&amp;').replace(/</g,'&lt;')
                .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
        }

        async function loadReports() {
            const list = document.getElementById('reports-list');
            list.innerHTML = '<div style="padding:12px;color:#64748B;font-size:0.85rem;">Loading...</div>';
            try {
                const res = await authFetch('/reports');
                const data = await res.json();
                const reports = data.reports || [];
                list.innerHTML = '';
                if (reports.length === 0) {
                    list.innerHTML = '<div style="padding:16px;color:#64748B;font-size:0.82rem;line-height:1.6;">No completed reports yet.<br>Run Find Evil on an evidence directory to generate one.</div>';
                    return;
                }
                reports.forEach(r => {
                    const entry = document.createElement('div');
                    entry.className = 'report-entry';
                    entry.dataset.dir = r.dir;
                    // Format timestamp: 20240115_120130 → 15/01/2024 12:01
                    let ts = '';
                    if (r.timestamp) {
                        const m = r.timestamp.match(/^(\d{4})(\d{2})(\d{2})_(\d{2})(\d{2})/);
                        if (m) ts = m[3]+'/'+m[2]+'/'+m[1]+' '+m[4]+':'+m[5];
                    }
                    entry.innerHTML =
                        '<div class="report-entry-name">' + _escHtml(r.case_name) + '</div>' +
                        '<div class="report-entry-meta">' +
                            '<span class="evil-badge ' + (r.evil_found ? 'evil' : 'clean') + '">' + (r.evil_found ? 'EVIL' : 'CLEAN') + '</span>' +
                            '<span class="fe-severity ' + _escHtml(r.severity) + '" style="font-size:0.7rem;padding:1px 6px;">' + _escHtml(r.severity) + '</span>' +
                        '</div>' +
                        (ts ? '<div class="report-ts">' + ts + '</div>' : '');
                    entry.addEventListener('click', () => {
                        document.querySelectorAll('.report-entry').forEach(e => e.classList.remove('active'));
                        entry.classList.add('active');
                        viewReport(r.dir, r.case_name);
                    });
                    // Double-click opens the graph viewer
                    entry.addEventListener('dblclick', () => {
                        const viewerUrl = '/reports/viewer?case=' + encodeURIComponent(r.dir);
                        window.open(viewerUrl, '_blank');
                    });
                    list.appendChild(entry);
                });
            } catch(e) {
                list.innerHTML = '<div style="padding:12px;color:#EF4444;font-size:0.82rem;">Error: ' + _escHtml(e.message) + '</div>';
            }
        }

        async function viewReport(caseDir, title) {
            const viewer = document.getElementById('reports-viewer');
            viewer.innerHTML = '<div class="reports-placeholder"><span>Loading report\u2026</span></div>';
            try {
                const res = await authFetch('/reports/' + encodeURIComponent(caseDir) + '/json');
                if (!res.ok) throw new Error('HTTP ' + res.status);
                const report = await res.json();
                const graphLink = '/reports/viewer?case=' + encodeURIComponent(caseDir);
                const histBtn = '<button class="graph-open-btn" onclick="showCommandHistory(\'' + encodeURIComponent(caseDir) + '\')" style="margin-bottom:12px;padding:6px 14px;background:rgba(16,185,129,0.15);border:1px solid #10B981;border-radius:4px;color:#10B981;cursor:pointer;font-size:12px;margin-right:8px;">🔗 Command History</button>';
                const graphBtn = '<button class="graph-open-btn" onclick="window.open(\'' + graphLink + '\', \'' + '_blank' + '\')" style="margin-bottom:12px;padding:6px 14px;background:rgba(59,130,246,0.15);border:1px solid #3b82f6;border-radius:4px;color:#60a5fa;cursor:pointer;font-size:12px;">🕸 View as Graph</button>';
                window._reportChatCaseDir = caseDir;
                window._reportChatData = report;
                viewer.innerHTML = histBtn + graphBtn + _renderReportHtml(report, title || caseDir, caseDir);
            } catch(e) {
                viewer.innerHTML = '<div class="reports-placeholder"><span style="color:#EF4444;">Error: ' + _escHtml(e.message) + '</span></div>';
            }
        }

        function importReportJSON() {
            const inp = document.createElement('input');
            inp.type = 'file';
            inp.accept = '.json,application/json';
            inp.onchange = async (ev) => {
                const file = ev.target.files[0];
                if (!file) return;
                const viewer = document.getElementById('reports-viewer');
                viewer.innerHTML = '<div class="reports-placeholder"><span>Reading file\u2026</span></div>';
                try {
                    const text = await file.text();
                    const report = JSON.parse(text);
                    document.querySelectorAll('.report-entry').forEach(e => e.classList.remove('active'));
                    window._reportChatCaseDir = null;
                    window._reportChatData = report;
                    viewer.innerHTML = _renderReportHtml(report, file.name.replace(/\.json$/i, ''), null);
                } catch(e) {
                    viewer.innerHTML = '<div class="reports-placeholder"><span style="color:#EF4444;">Invalid JSON: ' + _escHtml(e.message) + '</span></div>';
                }
            };
            inp.click();
        }

        // System accounts to filter out when scanning file paths
        const SYS_ACCOUNTS = new Set([
            'All Users','Default','Default User','Public','Administrator','Guest',
            'sansforensics','claw','root','nobody','daemon','ubuntu','pi','vagrant'
        ]);

        function extractUsernameFromPath(filePath) {
            if (!filePath || typeof filePath !== 'string') return null;
            // Scan the ENTIRE path for embedded user directories.
            // Evidence paths look like: .../Protected Files/Users/mortysmith/NTUSER.DAT
            // or .../Users/ricksanchez/Crypto/Keys/...

            // Windows user paths: .../Users/username/ (anywhere in path)
            const winMatch = filePath.match(/[/\\]Users[/\\]([^/\\]+)/i);
            if (winMatch) {
                const u = winMatch[1];
                if (SYS_ACCOUNTS.has(u)) return null;
                return u;
            }

            // Linux home paths: /home/username/ (use LAST match to avoid analysis machine prefix)
            const linuxMatches = filePath.match(/[/\\]home[/\\]([^/\\]+)/gi);
            if (linuxMatches) {
                const lastMatch = linuxMatches[linuxMatches.length - 1];
                const m = lastMatch.match(/[/\\]home[/\\]([^/\\]+)/i);
                if (m) {
                    const u = m[1];
                    if (SYS_ACCOUNTS.has(u.toLowerCase())) return null;
                    return u;
                }
            }

            // Protected Files pattern: .../Protected Files/Users/username/
            const protMatch = filePath.match(/[/\\]Protected(?:\s+Files)?[/\\]Users[/\\]([^/\\]+)/i);
            if (protMatch) {
                const u = protMatch[1];
                if (SYS_ACCOUNTS.has(u)) return null;
                return u;
            }
            return null;
        }

        // Collect all evidence file paths from report for user extraction
        function getAllEvidencePaths(report) {
            const paths = [];
            // From device_map evidence_files
            const dm = report.device_map || {};
            for (const dev of Object.values(dm)) {
                if (Array.isArray(dev.evidence_files)) paths.push(...dev.evidence_files);
            }
            // From evidence_inventory
            const inv = report.evidence_inventory || {};
            for (const items of Object.values(inv)) {
                if (Array.isArray(items)) paths.push(...items);
            }
            return paths;
        }

        function _formatDuration(seconds) {
            if (!seconds || seconds < 0) return '0s';
            const s = Math.round(seconds);
            if (s < 60) return s + 's';
            const m = Math.floor(s / 60);
            const rs = s % 60;
            if (s < 3600) return m + 'm ' + rs + 's';
            const h = Math.floor(s / 3600);
            const rm = Math.floor((s % 3600) / 60);
            if (s < 86400) return h + 'h ' + rm + 'm';
            const d = Math.floor(s / 86400);
            const rh = Math.floor((s % 86400) / 3600);
            return d + 'd ' + rh + 'h ' + rm + 'm';
        }

        function _renderReportHtml(report, title, caseDirForMitre) {
            const sev = report.severity || 'INFO';
            const evil = report.evil_found;
            const sevDist = report.severity_distribution || {};
            const chain = report.attack_chain || {};
            const mitreObs = chain.mitre_techniques_observed || [];
            const pbs = report.playbooks_run || [];
            const devMap = report.device_map || {};
            const flags = report.behavioral_flags_summary || {};
            const hits = report.indicator_hits || [];
            const inv = report.evidence_inventory || {};
            const failures = report.failures || [];
            const findingsDetail = report.findings_detail || [];
        function _resolveHostname(deviceId, deviceMap) {
            if (!deviceId || !deviceMap) return deviceId || 'unknown';
            const dev = deviceMap[deviceId];
            if (dev) {
                return dev.hostname || dev.device_name || dev.owner || deviceId;
            }
            return deviceId;
        }
        function _normalizeDeviceType(dtype) {
            if (!dtype || typeof dtype !== 'string') return dtype || '\u2014';
            return dtype.replace(/^(mobile_|memdump_|pcap_)/, '').replace(/_/g, ' ');
        }

            const totalFlags = Object.values(flags).reduce((a, b) => a + b, 0);

            let h = '<div style="max-width:900px;">';

            // Header
            h += '<div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:20px;">';
            h += '<h2 style="color:#60A5FA;font-size:1.2rem;margin:0;">' + _escHtml(title) + '</h2>';
            h += '<span class="evil-badge ' + (evil ? 'evil' : 'clean') + '" style="font-size:0.85rem;padding:4px 12px;">' + (evil ? '\uD83D\uDD34 EVIL FOUND' : '\uD83D\uDFE2 CLEAN') + '</span>';
            h += '<span class="fe-severity ' + _escHtml(sev) + '">' + _escHtml(sev) + '</span>';
            h += '</div>';

            // ========== DOWNLOAD BUTTONS ==========
            if (caseDirForMitre) {
                h += '<div style="margin-bottom:16px;display:flex;flex-wrap:wrap;gap:8px;">';
                h += '<a href="/reports/' + encodeURIComponent(caseDirForMitre) + '/download/markdown" target="_blank" class="mitre-matrix-btn" style="display:inline-flex;align-items:center;gap:6px;padding:6px 12px;background:rgba(59,130,246,0.1);border:1px solid #3b82f6;border-radius:4px;color:#60A5FA;text-decoration:none;font-size:0.8rem;transition:all 120ms;">📥 Download Markdown Report</a>';
                h += '<a href="/reports/' + encodeURIComponent(caseDirForMitre) + '/download/json" target="_blank" class="mitre-matrix-btn" style="display:inline-flex;align-items:center;gap:6px;padding:6px 12px;background:rgba(245,158,11,0.1);border:1px solid #f59e0b;border-radius:4px;color:#FBBF24;text-decoration:none;font-size:0.8rem;transition:all 120ms;">📥 Download JSON Data</a>';
                h += '<a href="/reports/' + encodeURIComponent(caseDirForMitre) + '/download/summary" target="_blank" class="mitre-matrix-btn" style="display:inline-flex;align-items:center;gap:6px;padding:6px 12px;background:rgba(139,92,246,0.1);border:1px solid #8b5cf6;border-radius:4px;color:#A78BFA;text-decoration:none;font-size:0.8rem;transition:all 120ms;">📥 Download Executive Summary</a>';
                h += '</div>';
            }

            // Key stats
            const stepsFailed = pbs.reduce((a, pb) => a + (pb.steps_failed || 0), 0);
            h += '<div class="stat-grid">';
            [
                ['Classification', report.classification || '\u2014'],
                ['OS', report.os_type || '\u2014'],
                ['Elapsed', _formatDuration(report.elapsed_seconds || 0)],
                ['Playbooks Run', pbs.length],
                ['Critic Approval', (report.critic_approval_pct || 0) + '%'],
                ['Steps Failed', stepsFailed],
            ].forEach(([label, val]) => {
                h += '<div class="stat-card"><div class="stat-label">' + label + '</div><div class="stat-value">' + _escHtml(String(val)) + '</div></div>';
            });
            h += '</div>';

            // ========== EXECUTIVE SUMMARY (from narrative report) ==========
            const execSummary = report.executive_summary;
            if (execSummary && execSummary.length > 20) {
                h += '<div class="report-section" style="background:rgba(96,165,250,0.08);border:1px solid #60A5FA;border-radius:8px;padding:16px;margin:16px 0;">';
                h += '<h3 style="color:#60A5FA;margin:0 0 12px 0;">\ud83d\udcdd Executive Summary</h3>';
                h += '<div style="font-size:0.88rem;line-height:1.6;color:#E2E8F0;">' + _md2html(execSummary) + '</div>';
                h += '</div>';
            }

            // ========== PHISHING EVIDENCE DETAILS ==========
            (function() {
                const emailFindings = (report.findings_detail || []).filter(function(f) {
                    return f.playbook === 'EMAIL_DIRECT';
                });
                if (emailFindings.length === 0) return;

                h += '<div class="report-section" style="background:rgba(245,158,11,0.06);border:1px solid rgba(245,158,11,0.3);border-radius:8px;padding:16px;margin:16px 0;">';
                h += '<h3 style="color:#F59E0B;margin:0 0 12px 0;">\ud83c\udfaf Phishing Evidence Details</h3>';

                var phishingRows = [];
                emailFindings.forEach(function(f) {
                    var result = f.result || {};
                    var eiocs = result.email_iocs || {};
                    var subject = result.subject || (eiocs.subjects || [])[0] || '\u2014';
                    var fromAddr = (eiocs.from_addresses || [])[0] || '\u2014';
                    var toAddrs = (eiocs.to_addresses || []).slice(0, 3).join(', ') || '\u2014';
                    var dateVal = result.date || '\u2014';
                    var retPath = (eiocs.return_paths || [])[0] || '\u2014';
                    var senderIps = (eiocs.sender_ips || []).slice(0, 5).join(', ') || '\u2014';
                    var mismatches = eiocs.return_path_mismatches || [];
                    var spoofLabel = '\u2014';
                    var spoofColor = '#64748B';
                    if (mismatches.length > 0) {
                        spoofLabel = '\u2717 Mismatch';
                        spoofColor = '#EF4444';
                    } else if (retPath !== '\u2014' && fromAddr !== '\u2014') {
                        var fd = (fromAddr.match(/@([\\w.-]+)/) || [])[1];
                        var rd = (retPath.match(/@([\\w.-]+)/) || [])[1];
                        if (fd && rd && fd.toLowerCase() === rd.toLowerCase()) {
                            spoofLabel = '\u2713 Match';
                            spoofColor = '#10B981';
                        } else if (fd && rd) {
                            spoofLabel = '\u2717 Mismatch';
                            spoofColor = '#EF4444';
                        }
                    }
                    var commitHash = f.source_commit || '';
                    var commitLink = commitHash ? '<a href="#" data-commit="' + _escAttr(commitHash) + '" class="history-link" style="color:#60A5FA;font-size:0.72rem;">' + commitHash.substring(0, 8) + '</a>' : '\u2014';
                    phishingRows.push({from: fromAddr, to: toAddrs, subject: subject, date: dateVal, retPath: retPath, senderIps: senderIps, spoofLabel: spoofLabel, spoofColor: spoofColor, commitLink: commitLink, emlPath: f.source || '\u2014'});
                });

                if (phishingRows.length > 0) {
                    h += '<div style="max-height:400px;overflow-y:auto;border:1px solid #1F2A3F;border-radius:6px;">';
                    h += '<table class="fe-pb-table" style="margin-top:0;"><tr><th>From</th><th>To</th><th>Subject</th><th>Date</th><th>Return-Path</th><th>Sender IPs</th><th>Spoofing</th><th>Commit</th></tr>';
                    phishingRows.forEach(function(row) {
                        h += '<tr>';
                        h += '<td style="font-size:0.75rem;max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="' + _escAttr(row.from) + '">' + _escHtml(row.from) + '</td>';
                        h += '<td style="font-size:0.75rem;max-width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="' + _escAttr(row.to) + '">' + _escHtml(row.to) + '</td>';
                        h += '<td style="font-size:0.75rem;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="' + _escAttr(row.subject) + '">' + _escHtml(row.subject) + '</td>';
                        h += '<td style="font-size:0.72rem;color:#64748B;">' + _escHtml(row.date) + '</td>';
                        h += '<td style="font-size:0.72rem;max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="' + _escAttr(row.retPath) + '">' + _escHtml(row.retPath) + '</td>';
                        h += '<td style="font-size:0.72rem;max-width:140px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="' + _escAttr(row.senderIps) + '">' + _escHtml(row.senderIps) + '</td>';
                        h += '<td style="color:' + row.spoofColor + ';font-weight:600;font-size:0.75rem;">' + row.spoofLabel + '</td>';
                        h += '<td style="font-size:0.7rem;">' + row.commitLink + '</td>';
                        h += '</tr>';
                    });
                    h += '</table></div>';
                }
                h += '<p style="font-size:0.68rem;color:#64748B;margin-top:8px;">\u26A0 Spoofing check compares Return-Path domain against From header domain. Mismatch indicates sender spoofing (T1566.001).</p>';
                h += '</div>';
            })();


            // Evidence inventory
            const hasInv = Object.values(inv).some(v => Array.isArray(v) && v.length > 0);
            if (hasInv) {
                h += '<div class="report-section"><h3>\ud83d\udcc1 Evidence Inventory</h3><div class="inv-grid">';
                for (const [type, items] of Object.entries(inv)) {
                    if (Array.isArray(items) && items.length > 0) {
                        h += '<div class="inv-card">'
                           + '<div class="inv-type">' + _escHtml(type.replace(/_/g,' ')) + '</div>'
                           + '<div class="inv-count">' + items.length + '</div>'
                           + '</div>';
                    }
                }
                h += '</div></div>';
            }


            // ========== EVIDENCE CONFIDENCE & GAPS ==========
            (function() {
                const kp = (chain.kill_chain_phases || []).map(p => (p || '').toLowerCase());
                const cls = (report.classification || '').toLowerCase();
                const allText = cls + ' ' + kp.join(' ');
                const phaseStrengthMap = {
                    credential_theft: ['Credential Access', 'Strong'],
                    credential_access: ['Credential Access', 'Strong'],
                    lateral_movement: ['Lateral Movement', 'Moderate'],
                    exfiltration: ['Exfiltration', 'Moderate'],
                    phishing: ['Initial Access', 'Weak'],
                    initial_access: ['Initial Access', 'Weak'],
                    persistence: ['Persistence', 'Moderate'],
                    lolbin: ['Execution', 'Moderate'],
                    web_shell: ['Persistence', 'Strong'],
                    c2: ['Command & Control', 'Moderate'],
                    command_and_control: ['Command & Control', 'Moderate'],
                    cryptominer: ['Command & Control', 'Moderate'],
                    privilege_escalation: ['Privilege Escalation', 'Moderate'],
                    defense_evasion: ['Defense Evasion', 'Weak'],
                    discovery: ['Discovery', 'Weak'],
                };
                const basisMap = {
                    Strong: 'Artifacts confirmed in findings',
                    Moderate: 'Correlated indicators suggesting activity',
                    Weak: 'Classification metadata \u2014 no specific artifact confirmed',
                };

                const seen = new Set();
                const entries = [];
                kp.forEach(phase => {
                    const info = phaseStrengthMap[phase];
                    if (!info || seen.has(info[0])) return;
                    seen.add(info[0]);
                    entries.push({ category: info[0], strength: info[1], basis: basisMap[info[1]] });
                });

                if (!entries.length && cls) {
                    Object.entries(phaseStrengthMap).forEach(([pk, info]) => {
                        if (cls.indexOf(pk) !== -1 || cls.indexOf(pk.replace(/_/g, ' ')) !== -1) {
                            if (!seen.has(info[0])) {
                                seen.add(info[0]);
                                entries.push({ category: info[0], strength: info[1], basis: basisMap[info[1]] });
                            }
                        }
                    });
                }

                const totalSteps = (report.steps_completed || 0) + (report.steps_failed || 0) + (report.steps_skipped || 0);
                const gaps = [];
                if (totalSteps > 0 && failures.length > 0)
                    gaps.push(failures.length + ' of ' + totalSteps + ' analysis steps failed');
                if (!(inv.evtx_logs || []).length && !(inv.evt_logs || []).length) gaps.push('No Windows event log files (.evtx or .evt) in evidence scope');
                if (!(inv.syslogs || []).length) gaps.push('No syslog files in evidence scope');
                const devMapEntriesForGaps = Object.entries(devMap);
                const memDevs = devMapEntriesForGaps.filter(([id, d]) =>
                    (d.evidence_files || []).some(f => (f || '').toLowerCase().indexOf('memdump') !== -1 || (f || '').toLowerCase().indexOf('memory') !== -1)
                ).length;
                if (devMapEntriesForGaps.length > 0 && memDevs < devMapEntriesForGaps.length)
                    gaps.push('Memory captured for ' + memDevs + ' of ' + devMapEntriesForGaps.length + ' devices');
                if (!gaps.length) gaps.push('No significant evidence gaps identified');

                h += '<div class="report-section"><h3 style="color:#8B5CF6;">\ud83d\udd0d Evidence Confidence & Gaps</h3>';
                h += '<h4 style="margin:8px 0;">Evidence Strength</h4>';
                if (entries.length) {
                    h += '<table class="fe-pb-table"><tr><th>Finding Category</th><th>Strength</th><th>Basis</th></tr>';
                    entries.forEach(e => {
                        const sc = e.strength === 'Strong' ? '#10B981' : (e.strength === 'Moderate' ? '#F59E0B' : '#EF4444');
                        h += '<tr><td>' + _escHtml(e.category) + '</td><td style="color:' + sc + ';"><strong>' + e.strength + '</strong></td><td style="font-size:0.8rem;">' + _escHtml(e.basis) + '</td></tr>';
                    });
                    h += '</table>';
                } else {
                    h += '<p style="color:#64748B;font-size:0.82rem;">No finding categories available for strength assessment.</p>';
                }
                h += '<h4 style="margin:12px 0 8px 0;">Known Evidence Gaps</h4>';
                gaps.forEach(g => { h += '<p style="margin:2px 0;font-size:0.82rem;color:#CBD5E1;">\u2022 ' + _escHtml(g) + '</p>'; });
                h += '<p style="font-size:0.72rem;color:#64748B;margin-top:8px;">\u26A0 Ratings reflect automated analysis pipeline only. Manual review may upgrade confidence levels.</p>';
                h += '</div>';
            })();


            // ========== DWELL TIME & PROGRESSION ==========
            (function() {
                const hasData = chain.first_seen_ts || chain.last_seen_ts || (chain.kill_chain_phases || []).length > 0;
                if (!hasData && (chain.kill_chain_phases || []).length === 0) return;

                h += '<div class="report-section"><h3 style="color:#8B5CF6;">\u23F1 Dwell Time & Progression</h3>';

                // Dwell time table
                const kp = chain.kill_chain_phases || [];
                const phaseLabels = {
                    phishing: 'Initial Access', initial_access: 'Initial Access',
                    credential_theft: 'Credential Harvesting', credential_access: 'Credential Access',
                    privilege_escalation: 'Privilege Escalation', lateral_movement: 'Lateral Movement',
                    persistence: 'Persistence Established', exfiltration: 'Exfiltration',
                    c2: 'C2 Established', command_and_control: 'C2 Communications',
                    lolbin: 'Execution / LOLBin Usage', web_shell: 'Web Shell Deployment',
                    cryptominer: 'Crypto Mining Activity', defense_evasion: 'Defense Evasion',
                    discovery: 'Discovery / Reconnaissance',
                };

                h += '<h4 style="margin:8px 0;">Dwell Time & Progression</h4>';
                h += '<table class="fe-pb-table"><tr><th>Milestone</th><th>Estimated Timeframe</th></tr>';
                if (kp.length > 0) {
                    kp.forEach((phase, i) => {
                        const label = phaseLabels[(phase || '').toLowerCase()] || (phase || '').replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
                        let tf = i === 0 ? 'First detected' : '+' + (i * 2) + 'h (estimated)';
                        if (chain.dwell_days !== undefined && chain.dwell_days > 0 && i > 0) {
                            const frac = (i / kp.length) * chain.dwell_days * 24;
                            tf = frac < 1 ? '~' + Math.round(frac * 60) + 'm after initial' : '~' + frac.toFixed(1) + 'h after initial';
                        }
                        h += '<tr><td>' + _escHtml(label) + '</td><td>' + tf + '</td></tr>';
                    });
                } else {
                    h += '<tr><td>Initial Access</td><td>Unknown</td></tr>';
                }
                if (chain.dwell_days !== undefined) {
                    let dwellStr;
                    const dd = chain.dwell_days;
                    if (dd < 1/24) dwellStr = '~' + Math.round(dd * 1440) + ' minutes';
                    else if (dd < 1) dwellStr = '~' + (dd * 24).toFixed(1) + ' hours';
                    else if (dd < 30) dwellStr = '~' + dd.toFixed(1) + ' days';
                    else dwellStr = '~' + (dd / 30).toFixed(1) + ' months';
                    h += '<tr><td><strong>Total Dwell</strong></td><td><strong>' + dwellStr + '</strong></td></tr>';
                }
                if (chain.first_seen_ts || chain.last_seen_ts) {
                    h += '<tr><td>First Seen</td><td>' + _escHtml(chain.first_seen_ts || 'Unknown') + '</td></tr>';
                    h += '<tr><td>Last Seen</td><td>' + _escHtml(chain.last_seen_ts || 'Unknown') + '</td></tr>';
                }
                h += '</table>';

                h += '</div>';
            })();



            // ========== KILL CHAIN & TIMELINE RECONSTRUCTION ==========
            const killPhases = chain.kill_chain_phases || [];
            if (killPhases.length > 0 || (chain.mitre_techniques_observed || []).length > 0) {
                h += '<div class="report-section"><h3 style="color:#F59E0B;">\u23F0 Kill Chain & Timeline Reconstruction</h3>';
                h += '<table class="fe-pb-table"><tr><th>Timeframe</th><th>Event</th><th>MITRE Tactic</th><th>Log Source</th><th>Confidence</th></tr>';
                const phaseMitreMap = {
                    phishing: ['T1566', 'Initial Access'],
                    initial_access: ['T1190', 'Initial Access'],
                    credential_theft: ['T1003', 'Credential Access'],
                    credential_access: ['T1003', 'Credential Access'],
                    persistence: ['T1053', 'Persistence'],
                    lateral_movement: ['T1021', 'Lateral Movement'],
                    exfiltration: ['T1048', 'Exfiltration'],
                    c2: ['T1071', 'Command & Control'],
                    command_and_control: ['T1071', 'Command & Control'],
                    lolbin: ['T1218', 'Execution'],
                    web_shell: ['T1505.003', 'Persistence'],
                    cryptominer: ['T1496', 'Command & Control'],
                    privilege_escalation: ['T1055', 'Privilege Escalation'],
                    defense_evasion: ['T1070', 'Defense Evasion'],
                    discovery: ['T1083', 'Discovery'],
                };
                killPhases.forEach((phase, i) => {
                    const pLower = (phase || '').toLowerCase();
                    const map = phaseMitreMap[pLower];
                    if (map) {
                        const label = phase.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
                        const tf = i === 0 ? 'Initial' : '+' + (i * 2) + 'h';
                        h += '<tr><td>' + tf + '</td><td>' + _escHtml(label) + ' (' + map[0] + ')</td><td>' + map[1] + '</td><td>Forensic artifact</td><td>Artifact-Supported</td></tr>';
                    }
                });
                h += '</table><p style="font-size:0.75rem;color:#64748B;margin-top:8px;">\u26A0 Timeframes estimated from attack-chain phase ordering. Corroborate with network logs and EDR telemetry.</p></div>';
            }

            // ========== LATERAL MOVEMENT PATH (Kill Chain context) ==========
            const lmpFull = chain.lateral_movement_path || [];
            if (lmpFull.length > 0) {
                h += '<div class="report-section"><h3 style="color:#8B5CF6;">\ud83d\udd17 Lateral Movement Path</h3>';
                const deduped = [];
                const seenDevs = new Set();
                lmpFull.forEach(d => { if (!seenDevs.has(d)) { seenDevs.add(d); deduped.push(d); } });
                h += '<p style="font-size:0.85rem;font-family:monospace;color:#93C5FD;">' + deduped.map(d => _escHtml(_resolveHostname(d, devMap))).join(' \u2192 ') + '</p>';
                h += '<p style="font-size:0.75rem;color:#64748B;">' + deduped.length + ' devices in reconstructed path</p>';
                h += '</div>';
            }



            // Severity distribution
            const hasSev = Object.values(sevDist).some(v => v > 0);
            if (hasSev) {
                h += '<div class="report-section"><h3>Indicator Distribution</h3><div style="display:flex;gap:8px;flex-wrap:wrap;">';
                for (const [k, v] of Object.entries(sevDist)) {
                    if (v > 0) h += '<span class="fe-severity ' + _escHtml(k) + '">' + _escHtml(k) + ': ' + v + '</span>';
                }
                h += '</div></div>';
            }


            // Attack chain
            if (chain.dwell_days !== undefined || (chain.lateral_movement_path || []).length || mitreObs.length) {
                h += '<div class="report-section"><h3 style="color:#F59E0B;">\u26D3 Attack Chain</h3><div class="chain-box">';
                if (chain.first_seen_ts) h += '<p><strong>First Seen:</strong> ' + _escHtml(chain.first_seen_ts) + '</p>';
                if (chain.last_seen_ts)  h += '<p><strong>Last Seen:</strong> '  + _escHtml(chain.last_seen_ts)  + '</p>';
                if (chain.dwell_days !== undefined) h += '<p><strong>Dwell Time:</strong> ' + chain.dwell_days + ' days</p>';
                if ((chain.lateral_movement_path || []).length)
                    h += '<p><strong>Lateral Path:</strong> ' + chain.lateral_movement_path.map(d => _escHtml(_resolveHostname(d, devMap))).join(' \u2192 ') + ' (' + chain.lateral_movement_path.length + ' hops)</p>';
                if ((chain.kill_chain_phases || []).length)
                    h += '<p><strong>Kill Chain:</strong> ' + chain.kill_chain_phases.map(_escHtml).join(', ') + '</p>';
                if (mitreObs.length) {
                    h += '<div style="margin-top:10px;"><strong style="font-size:0.82rem;color:#64748B;">MITRE Techniques Observed</strong><div style="margin-top:6px;">';
                    h += mitreObs.map(t => '<a href="https://attack.mitre.org/techniques/' + _escHtml(t) + '/" target="_blank" class="mitre-tag" style="text-decoration:none;" title="View on MITRE ATT&CK">' + _escHtml(t) + '</a>').join('');
                    h += '</div></div>';
                }
                if (mitreObs.length && caseDirForMitre) {
                    h += '<div style="margin-top:12px;"><a href="/reports/mitre-matrix?case=' + encodeURIComponent(caseDirForMitre) + '" target="_blank" class="mitre-matrix-btn" style="display:inline-flex;align-items:center;gap:6px;padding:6px 12px;background:rgba(59,130,246,0.1);border:1px solid var(--g-blue);border-radius:4px;color:#60A5FA;text-decoration:none;font-size:0.8rem;transition:all 120ms;">🖱 View MITRE ATT&CK Matrix</a></div>';
                }
                h += '</div></div>';
            }

            // ========== BLAST RADIUS & BUSINESS IMPACT ==========
            (function() {
                const cls = (report.classification || '').toLowerCase();
                const kp = (chain.kill_chain_phases || []).map(p => (p || '').toLowerCase());
                const allText = cls + ' ' + kp.join(' ');

                // Affected assets
                const devMapEntries = Object.entries(devMap);
                let servers = 0, dcs = 0, workstations = 0, mobile = 0, network = 0, unknownType = 0;
                devMapEntries.forEach(([id, d]) => {
                    const dt = (d.device_type || '').toLowerCase();
                    const hn = (d.hostname || '').toLowerCase();
                    if (dt.indexOf('server') !== -1) servers++;
                    else if (dt.indexOf('dc') !== -1 || hn.indexOf('dc') !== -1) dcs++;
                    else if (dt.indexOf('pc') !== -1 || hn.indexOf('desktop') !== -1) workstations++;
                    else if (dt.indexOf('mobile') !== -1) mobile++;
                    else if (dt.indexOf('network') !== -1 || dt.indexOf('pcap') !== -1) network++;
                    else unknownType++;
                });
                const numDevices = devMapEntries.length;

                // Data categories at risk
                const dataCats = [];
                if (/phishing|email|credential/.test(allText)) dataCats.push('PII (credentials, email)');
                if (/exfiltration|exfil/.test(allText)) dataCats.push('intellectual property');
                if (/cryptominer|crypto/.test(allText)) dataCats.push('compute resources');
                if (!dataCats.length) dataCats.push('credentials, configuration data');

                // CIA
                let ciaC = 'MEDIUM', ciaI = 'MEDIUM', ciaA = 'LOW';
                let rC = 'No confirmed data breach', rI = 'No confirmed system modification', rA = 'No impact on service availability';
                if (evil) {
                    if (/exfiltration|credential/.test(allText)) { ciaC = 'HIGH'; rC = 'Credential theft and/or exfiltration detected'; }
                    else if (/phishing|lateral/.test(allText)) { ciaC = 'HIGH'; rC = 'Potential unauthorized access to sensitive data'; }
                    else { rC = 'Compromise confirmed \u2014 scope of data exposure unclear'; }
                    if (/persistence|web_shell|lolbin/.test(allText)) { ciaI = 'HIGH'; rI = 'Persistence mechanisms modified system state'; }
                    else { rI = 'Potential system modifications by attacker'; }
                    if (/cryptominer|ransomware/.test(allText)) { ciaA = 'HIGH'; rA = 'Resource consumption or destructive malware may impact service'; }
                }

                // Worst-case
                let worstParts = [];
                if (evil) {
                    if (/credential|privilege/.test(allText)) worstParts.push('credential theft enabling tenant-wide compromise');
                    if (/exfiltration|exfil/.test(allText)) worstParts.push('data exfiltration to criminal infrastructure');
                    if (!worstParts.length) worstParts.push('unauthorized access leading to data theft, sabotage, or ransomware');
                }
                const worstCase = evil
                    ? worstParts.map((s, i) => i === 0 ? s.charAt(0).toUpperCase() + s.slice(1) : s).join(' and ') + '.'
                    : 'No compromise confirmed. Unresolved anomalies should be investigated to rule out nascent threats.';

                h += '<div class="report-section"><h3 style="color:#EF4444;">\ud83d\udca5 Blast Radius & Business Impact</h3>';
                h += '<div style="background:rgba(239,68,68,0.06);border:1px solid rgba(239,68,68,0.2);border-radius:6px;padding:12px;">';

                h += '<h4 style="margin:0 0 8px 0;">Affected Assets</h4>';
                let assetParts = [];
                if (numDevices > 0) {
                    let typeParts = [];
                    if (servers) typeParts.push(servers + ' server' + (servers !== 1 ? 's' : ''));
                    if (dcs) typeParts.push(dcs + ' DC' + (dcs !== 1 ? 's' : ''));
                    if (workstations) typeParts.push(workstations + ' workstation' + (workstations !== 1 ? 's' : ''));
                    if (mobile) typeParts.push(mobile + ' mobile');
                    if (network) typeParts.push(network + ' network capture' + (network !== 1 ? 's' : ''));
                    if (unknownType) typeParts.push(unknownType + ' unknown');
                    assetParts.push('<b>' + numDevices + '</b> devices (' + typeParts.join(', ') + ')');
                }
                h += '<p style="margin:4px 0;font-size:0.85rem;">' + (assetParts.length ? assetParts.join(', ') : 'No assets identified in evidence scope') + '</p>';
                h += '<p style="margin:4px 0;font-size:0.85rem;"><strong>Data at risk:</strong> ' + dataCats.join(', ') + '</p>';

                h += '<h4 style="margin:12px 0 8px 0;">CIA Impact Assessment</h4>';
                h += '<table class="fe-pb-table"><tr><th>Dimension</th><th>Score</th><th>Rationale</th></tr>';
                h += '<tr><td>Confidentiality</td><td style="color:' + (ciaC === 'HIGH' ? '#EF4444' : '#F59E0B') + ';"><strong>' + ciaC + '</strong></td><td style="font-size:0.82rem;">' + rC + '</td></tr>';
                h += '<tr><td>Integrity</td><td style="color:' + (ciaI === 'HIGH' ? '#EF4444' : '#F59E0B') + ';"><strong>' + ciaI + '</strong></td><td style="font-size:0.82rem;">' + rI + '</td></tr>';
                h += '<tr><td>Availability</td><td style="color:' + (ciaA === 'HIGH' ? '#EF4444' : '#10B981') + ';"><strong>' + ciaA + '</strong></td><td style="font-size:0.82rem;">' + rA + '</td></tr>';
                h += '</table>';

                h += '<h4 style="margin:12px 0 8px 0;">Worst-Case Projection</h4>';
                h += '<p style="margin:4px 0;font-size:0.85rem;color:#FCA5A5;">If not contained: ' + _escHtml(worstCase) + '</p>';

                h += '</div></div>';
            })();


            // ========== DEVICES ==========
            if (Object.keys(devMap).length > 0) {
                h += '<div class="report-section"><h3>\ud83d\udda5\ufe0f Devices Discovered</h3>';
                h += '<table class="fe-pb-table"><tr><th>Device</th><th>Type</th><th>Owner</th><th>OS</th><th>Files</th></tr>';
                for (const [devId, dev] of Object.entries(devMap)) {
                    h += '<tr><td>' + _escHtml(devId) + '</td>'
                       + '<td>' + _escHtml(_normalizeDeviceType(dev.device_type)||'\u2014') + '</td>'
                       + '<td>' + _escHtml(dev.owner||'\u2014') + '</td>'
                       + '<td>' + _escHtml(dev.os_type||'\u2014') + '</td>'
                       + '<td>' + (dev.evidence_files ? dev.evidence_files.length : 0) + '</td></tr>';
                }
                h += '</table></div>';
            }



            // ========== USERS / ACCOUNTS ==========
            let userMap = report.user_map || {};
            let userEntries = Object.entries(userMap).filter(([k, v]) => k !== 'users' && typeof v === 'object');

            // If user_map is empty, extract users from device_map owners
            if (userEntries.length === 0) {
                const ownersFound = new Set();
                const ownerDevices = {};
                for (const [devId, dev] of Object.entries(devMap)) {
                    const owner = dev.owner;
                    if (owner && owner !== 'None' && owner !== 'unknown') {
                        ownersFound.add(owner);
                        if (!ownerDevices[owner]) ownerDevices[owner] = [];
                        ownerDevices[owner].push(devId);
                    }
                }
                if (ownersFound.size > 0) {
                    const syntheticUserMap = {};
                    ownersFound.forEach(o => {
                        syntheticUserMap[o] = { devices: ownerDevices[o] || [], owner: o };
                    });
                    userEntries = Object.entries(syntheticUserMap);
                }
            }

            // If still empty, scan ALL evidence file paths for embedded usernames
            if (userEntries.length === 0) {
                const allPaths = getAllEvidencePaths(report);
                const usersFound = new Map();
                for (const fp of allPaths) {
                    const uname = extractUsernameFromPath(fp);
                    if (uname) {
                        if (!usersFound.has(uname)) usersFound.set(uname, { devices: [], files: [] });
                        usersFound.get(uname).files.push(fp);
                    }
                }
                // Build synthetic user entries from path analysis
                if (usersFound.size > 0) {
                    const sorted = [...usersFound.entries()].sort((a, b) => a[0].localeCompare(b[0]));
                    userEntries = sorted.map(([uname, udata]) => [uname, {
                        devices: [],
                        files: udata.files,
                        source: 'evidence_paths'
                    }]);
                }
            }

            // Always show the Accounts section
            h += '<div class="report-section"><h3 style="color:#60A5FA;">\ud83d\udc64 Accounts Discovered (' + userEntries.length + ')</h3>';
            if (userEntries.length > 0) {
                h += '<table class="fe-pb-table"><tr><th>Username</th><th>SID</th><th>Evidence Files</th><th>Last Login</th></tr>';
                for (const [uname, udata] of userEntries) {
                    if (typeof udata !== 'object') continue;
                    // Show evidence file count instead of devices when extracted from paths
                    const fileCount = (udata.files && udata.files.length) ? udata.files.length : 0;
                    const fileInfo = fileCount > 0 ? (fileCount + ' file' + (fileCount !== 1 ? 's' : '')) : '\u2014';
                    const devices = udata.devices || [];
                    const devInfo = devices.length > 0 ? devices.map(_escHtml).join(', ') : '';
                    const evidenceInfo = devInfo || fileInfo;
                    h += '<tr><td><strong>' + _escHtml(uname) + '</strong></td>'
                       + '<td><code style="font-size:0.75rem;">' + _escHtml(udata.sid || udata.SID || '\u2014') + '</code></td>'
                       + '<td style="font-size:0.78rem;">' + _escHtml(evidenceInfo) + '</td>'
                       + '<td>' + _escHtml(udata.last_login || udata.lastLogon || '\u2014') + '</td></tr>';
                }
                h += '</table>';
            } else {
                h += '<p style="color:#64748B;font-size:0.82rem;margin:8px 0;">No accounts found in evidence. Users may need to be correlated from registry hives or memory analysis.</p>';
            }
            h += '</div>';

            // Correlated Users / Relationships
            const corrUsers = report.correlated_users || {};
            const corrEntries = Object.entries(corrUsers).filter(([k, v]) => typeof v === 'object');
            if (corrEntries.length > 0) {
                h += '<div class="report-section"><h3 style="color:#10B981;">\ud83d\udd17 User Relationships</h3>';
                for (const [uname, cdata] of corrEntries) {
                    h += '<div style="background:rgba(16,185,129,0.1);border:1px solid #10B981;border-radius:6px;padding:12px;margin-bottom:10px;">';
                    h += '<h4 style="margin:0 0 8px 0;color:#10B981;">\ud83d\udc64 ' + _escHtml(uname) + '</h4>';
                    if (cdata.devices && cdata.devices.length > 0) {
                        h += '<p style="margin:4px 0;font-size:0.82rem;"><strong>Devices:</strong> ' + cdata.devices.map(_escHtml).join(', ') + '</p>';
                    }
                    if (cdata.activity_profile) {
                        const prof = cdata.activity_profile;
                        if (prof.total_events) {
                            h += '<p style="margin:4px 0;font-size:0.82rem;"><strong>Total Events:</strong> ' + prof.total_events + '</p>';
                        }
                        if (prof.typical_hours && prof.typical_hours.length > 0) {
                            h += '<p style="margin:4px 0;font-size:0.82rem;"><strong>Active Hours:</strong> ' + prof.typical_hours.join(', ') + '</p>';
                        }
                    }
                    if (cdata.lateral_movement_indicators && cdata.lateral_movement_indicators.length > 0) {
                        h += '<div style="margin-top:8px;padding:8px;background:rgba(239,68,68,0.1);border-radius:4px;">';
                        h += '<strong style="color:#EF4444;font-size:0.82rem;">\u26a0 Lateral Movement Detected:</strong>';
                        cdata.lateral_movement_indicators.forEach(lm => {
                            h += '<div style="font-size:0.78rem;margin-top:4px;color:#cbd5e1;">';
                            h += _escHtml(_resolveHostname(lm.from_device, devMap)) + ' \u2192 ' + _escHtml(_resolveHostname(lm.to_device, devMap)) + ' via ' + _escHtml(lm.method);
                            h += '</div>';
                        });
                        h += '</div>';
                    }
                    h += '</div>';
                }
                h += '</div>';
            }


            // Behavioral flags
            if (totalFlags > 0) {
                h += '<div class="report-section"><h3 style="color:#EF4444;">\u26A0 Behavioral Flags: ' + totalFlags + '</h3><div class="flag-box">';
                for (const [devId, count] of Object.entries(flags)) {
                    if (count > 0) h += '<p>' + _escHtml(devId) + ': ' + count + ' flag' + (count !== 1 ? 's' : '') + '</p>';
                }
                h += '</div></div>';
            }


            // ========== INDICATOR HITS & IOCs ==========
            const iocs = report.iocs || {};
            const iocIps = iocs.ip_addresses || [];
            const iocUrls = iocs.urls || [];
            const iocEmails = iocs.email_addresses || [];
            const iocHashes = iocs.file_hashes || [];
            const iocPaths = iocs.file_paths || [];

            // Sanitize: clean up formatting artifacts (embedded \r\n, whitespace, empty strings)
            function _sanitizeIoc(str) {
                if (!str || typeof str !== 'string') return '';
                return str.replace(/\r/g, '').replace(/\n/g, ' ').trim().replace(/\s+/g, ' ');
            }
            // Deduplicate and sanitize IPs, hashes, and paths
            const cleanIps = [...new Set(iocIps.map(_sanitizeIoc).filter(s => s))];
            const cleanHashes = [...new Set(iocHashes.map(_sanitizeIoc).filter(s => s))];
            const cleanPaths = [...new Set(iocPaths.map(_sanitizeIoc).filter(s => s))];
            const hasIocs = cleanIps.length > 0 || iocUrls.length > 0 || iocEmails.length > 0 || cleanHashes.length > 0 || cleanPaths.length > 0 || hits.length > 0;

            // Build IOC → source provenance map from findings_detail
            const iocSourceMap = {};
            (report.findings_detail || []).forEach(function(f) {
                const commit = f.source_commit || '';
                const step = f.source_step || f.step_key || '';
                const pb = f.playbook || '';
                const result = f.result || {};
                if (result.email_iocs) {
                    var eiocs = result.email_iocs;
                    ['sender_ips','from_addresses','to_addresses','return_paths'].forEach(function(k) {
                        (eiocs[k] || []).forEach(function(v) {
                            if (v && !iocSourceMap[v]) iocSourceMap[v] = {commit: commit, step: step, playbook: pb};
                        });
                    });
                    (eiocs.urls_in_body || []).forEach(function(v) {
                        if (v && !iocSourceMap[v]) iocSourceMap[v] = {commit: commit, step: step, playbook: pb};
                    });
                }
            });

            function _iocAttrs(val) {
                var src = iocSourceMap[val] || {};
                var attrs = '';
                if (src.commit) attrs += ' data-commit="' + _escAttr(src.commit) + '"';
                if (src.step) attrs += ' data-step="' + _escAttr(src.step) + '"';
                if (src.playbook) attrs += ' data-playbook="' + _escAttr(src.playbook) + '"';
                return attrs;
            }

            if (hasIocs) {
                const totalIocs = hits.length + cleanIps.length + iocUrls.length + iocEmails.length + cleanHashes.length + cleanPaths.length;
                h += '<div class="report-section" style="border:2px solid #F59E0B;border-radius:8px;padding:16px;margin:16px 0;background:rgba(245,158,11,0.05);">';
                h += '<h3 style="color:#F59E0B;margin:0 0 12px 0;font-size:1.1rem;">\ud83c\udfaf Indicators of Compromise (' + totalIocs + ' total)</h3>';

                // IP Addresses
                if (cleanIps.length > 0) {
                    h += '<div style="margin-bottom:12px;"><strong style="font-size:0.82rem;color:#94A3B8;">IP Addresses (' + cleanIps.length + ')</strong>';
                    h += '<div style="display:flex;flex-wrap:wrap;gap:4px;margin-top:4px;">';
                    cleanIps.forEach(ip => {
                        var attrs = _iocAttrs(ip);
                        h += '<code' + attrs + ' style="background:#1E293B;color:#F59E0B;padding:2px 8px;border-radius:3px;font-size:0.78rem;font-family:monospace;' + (attrs ? 'cursor:pointer;' : '') + '" class="ioc-value" title="' + (attrs ? 'Click to view in Command History' : '') + '">' + _escHtml(ip) + '</code>';
                    });
                    h += '</div></div>';
                }

                // URLs
                if (iocUrls.length > 0) {
                    h += '<div style="margin-bottom:12px;"><strong style="font-size:0.82rem;color:#94A3B8;">URLs (' + iocUrls.length + ')</strong>';
                    h += '<div style="margin-top:4px;">';
                    iocUrls.forEach(url => {
                        var attrs = _iocAttrs(url);
                        h += '<div><code' + attrs + ' style="font-size:0.75rem;color:#60A5FA;word-break:break-all;' + (attrs ? 'cursor:pointer;' : '') + '" class="ioc-value" title="' + (attrs ? 'Click to view in Command History' : '') + '">' + _escHtml(url) + '</code></div>';
                    });
                    h += '</div></div>';
                }

                // Email Addresses
                if (iocEmails.length > 0) {
                    h += '<div style="margin-bottom:12px;"><strong style="font-size:0.82rem;color:#94A3B8;">Email Addresses (' + iocEmails.length + ')</strong>';
                    h += '<div style="margin-top:4px;">';
                    iocEmails.forEach(email => {
                        var attrs = _iocAttrs(email);
                        h += '<div><code' + attrs + ' style="font-size:0.75rem;color:#60A5FA;' + (attrs ? 'cursor:pointer;' : '') + '" class="ioc-value" title="' + (attrs ? 'Click to view in Command History' : '') + '">' + _escHtml(email) + '</code></div>';
                    });
                    h += '</div></div>';
                }

                // File Hashes
                if (cleanHashes.length > 0) {
                    h += '<div style="margin-bottom:12px;"><strong style="font-size:0.82rem;color:#94A3B8;">File Hashes (' + cleanHashes.length + ')</strong>';
                    h += '<div style="max-height:120px;overflow-y:auto;margin-top:4px;">';
                    h += '<table style="width:100%;font-size:0.72rem;border-collapse:collapse;"><tr><th style="text-align:left;color:#64748B;padding:2px 6px;">Hash</th><th style="text-align:left;color:#64748B;padding:2px 6px;">Type</th></tr>';
                    cleanHashes.slice(0, 50).forEach(hash => {
                        const hashLen = (hash || '').length;
                        const hashType = hashLen === 32 ? 'MD5' : hashLen === 40 ? 'SHA-1' : hashLen === 64 ? 'SHA-256' : hashLen + 'c';
                        h += '<tr><td style="padding:2px 6px;"><code style="font-size:0.7rem;color:#E2E8F0;">' + _escHtml(hash) + '</code></td><td style="padding:2px 6px;color:#64748B;">' + hashType + '</td></tr>';
                    });
                    if (cleanHashes.length > 50) h += '<tr><td colspan="2" style="color:#64748B;text-align:center;padding:4px;">\u2026 ' + (cleanHashes.length-50) + ' more hashes not shown</td></tr>';
                    h += '</table></div></div>';
                }

                // File Paths
                if (cleanPaths.length > 0) {
                    h += '<div style="margin-bottom:12px;"><strong style="font-size:0.82rem;color:#94A3B8;">Suspicious File Paths (' + cleanPaths.length + ')</strong>';
                    h += '<div style="max-height:200px;overflow-y:auto;margin-top:4px;background:#0F172A;border:1px solid #1E293B;border-radius:4px;padding:8px;">';
                    cleanPaths.slice(0, 100).forEach(fp => {
                        h += '<div style="margin:1px 0;"><code style="font-size:0.72rem;color:#94A3B8;">' + _escHtml(fp) + '</code></div>';
                    });
                    if (cleanPaths.length > 100) h += '<div style="color:#64748B;font-size:0.7rem;text-align:center;padding:4px;">\u2026 ' + (cleanPaths.length-100) + ' more paths not shown</div>';
                    h += '<div style="margin-top:8px;padding-top:6px;border-top:1px solid #1E293B;"><em style="font-size:0.68rem;color:#64748B;">\u26A0 Paths may contain formatting artifacts from the extraction process</em></div>';
                    h += '</div></div>';
                }

                // Indicator Hits (behavioral/pattern matches)
                if (hits.length > 0) {
                    h += '<div style="margin-top:14px;padding-top:12px;border-top:1px solid #1F2A3F;">';
                    h += '<h4 style="color:#F59E0B;margin:0 0 8px 0;font-size:0.95rem;">\ud83d\udd0d Pattern-Based Indicator Hits (' + hits.length + ')</h4>';
                    h += '<div style="max-height:350px;overflow-y:auto;border:1px solid #1F2A3F;border-radius:6px;">';
                    h += '<table class="fe-pb-table" style="margin-top:0;"><tr><th>Category</th><th>Pattern</th><th>Severity</th><th>Confidence</th><th>Source</th><th>MITRE</th><th>Context</th><th>File</th></tr>';
                    const shown = hits.slice(0, 100);
                    shown.forEach(hit => {
                        const sc = hit.severity || 'INFO';
                        const fileParts = (hit.file || '').replace(/\\/g,'/').split('/');
                        const shortFile = fileParts.slice(-2).join('/');
                        const mitres = hit.mitre_techniques || [];
                        // Compute confidence score & color
                        let confScore = hit.confidence;
                        if (typeof confScore === 'number') {
                            let confColor = confScore >= 70 ? '#22C55E' : confScore >= 40 ? '#F59E0B' : '#EF4444';
                            confScore = '<span style="color:' + confColor + ';font-weight:600;">' + confScore + '</span>/100';
                        } else {
                            confScore = _escHtml(String(confScore||''));
                        }
                        // Context tooltip
                        const ctx = hit.context || '';
                        const ctxShort = ctx.length > 60 ? ctx.substring(0, 57) + '...' : ctx;
                        h += '<tr>'
                           + '<td><strong>' + _escHtml(hit.category||'') + '</strong></td>'
                           + '<td><code style="font-size:0.78rem;">' + _escHtml(hit.pattern||'') + '</code></td>'
                           + '<td><span class="fe-severity ' + sc + '" style="font-size:0.7rem;padding:1px 5px;">' + sc + '</span></td>'
                           + '<td style="font-size:0.75rem;">' + confScore + '</td>'
                           + '<td style="font-size:0.75rem;color:#64748B;">' + _escHtml(hit.source||'') + '</td>'
                           + '<td style="font-size:0.72rem;">' + mitres.map(t => '<a href="https://attack.mitre.org/techniques/' + _escHtml(t) + '/" target="_blank" class="mitre-tag" style="text-decoration:none;">' + _escHtml(t) + '</a>').join(' ') + '</td>'
                           + '<td style="font-size:0.72rem;color:#94A3B8;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="' + _escHtml(ctx) + '">' + _escHtml(ctxShort) + '</td>'
                           + '<td style="font-size:0.75rem;color:#64748B;" title="' + _escHtml(hit.file||'') + '">' + _escHtml(shortFile) + '</td>'
                           + '</tr>';
                    });
                    if (hits.length > 100) h += '<tr><td colspan="8" style="color:#64748B;text-align:center;padding:8px;">\u2026 ' + (hits.length-100) + ' more hits not shown</td></tr>';
                    h += '</table></div></div>';
                }



                h += '</div>'; // close report-section
            }


            // ========== CONDENSED PLAYBOOK SUMMARY ==========


            // ========== CONDENSED PLAYBOOK SUMMARY ==========
            if (pbs.length > 0) {
                // Group by playbook_id
                const condensed = {};
                pbs.forEach(pb => {
                    const pid = pb.playbook_id || 'Unknown';
                    if (!condensed[pid]) {
                        condensed[pid] = { runs: 0, completed: 0, failed: 0, skipped: 0, unverified: 0 };
                    }
                    condensed[pid].runs += 1;
                    condensed[pid].completed += (pb.steps_completed || 0);
                    condensed[pid].failed += (pb.steps_failed || 0);
                    condensed[pid].skipped += (pb.steps_skipped || 0);
                    condensed[pid].unverified += (pb.steps_unverified || 0);
                });

                h += '<div class="report-section"><h3>\u2699\ufe0f Playbook Summary</h3>';
                h += '<table class="fe-pb-table"><tr><th>Playbook</th><th>Runs</th><th>Completed</th><th>Failed</th><th>Skipped</th><th>Total</th></tr>';
                const sortedPbs = Object.entries(condensed).sort((a, b) => a[0].localeCompare(b[0]));
                sortedPbs.forEach(([pid, c]) => {
                    const total = c.completed + c.failed + c.skipped + c.unverified;
                    h += '<tr>'
                       + '<td><strong>' + _escHtml(pid) + '</strong></td>'
                       + '<td>' + c.runs + 'x</td>'
                       + '<td class="' + (c.completed > 0 ? 'completed' : '') + '">' + c.completed + '</td>'
                       + '<td class="' + (c.failed > 0 ? 'failed' : '') + '">' + c.failed + '</td>'
                       + '<td class="' + (c.skipped > 0 ? 'skipped' : '') + '">' + c.skipped + '</td>'
                       + '<td>' + total + '</td></tr>';
                });
                h += '</table></div>';
            }


            // ========== FAILED STEPS ==========
            if (failures.length > 0) {
                h += '<div class="report-section"><h3 style="color:#EF4444;">\u26A0 Failed Steps (' + failures.length + ')</h3>';
                h += '<table class="fe-pb-table"><tr><th>#</th><th>Playbook</th><th>Step</th><th>Evidence File</th><th>Error</th></tr>';
        function _extractFailureReason(f) {
            let raw = '';
            if (f.error) {
                raw = String(f.error);
            } else if (f.reason) {
                raw = String(f.reason);
            } else {
                const result = f.result || {};
                if (result.error) raw = String(result.error);
                else if (result.stderr) raw = String(result.stderr);
                else if (f.status === 'skipped') return 'Skipped (tool/dependency missing)';
                else raw = f.status || 'Failed';
            }
            return raw.replace(/\|/g, '/').replace(/\n/g, ' ') || 'Unknown';
        }
                failures.forEach((f, i) => {
                    const pb = f.playbook || '?';
                    const step = (f.module && f.function) ? (f.module + '.' + f.function) : (f.module || f.function || '?');
                    const evFile = f.evidence_file ? f.evidence_file.replace(/.*[\\/]/, '') : '\u2014';
                    const reason = _extractFailureReason(f);
                    h += '<tr>'
                       + '<td>' + (i + 1) + '</td>'
                       + '<td>' + _escHtml(pb) + '</td>'
                       + '<td style="font-size:0.78rem;color:#94A3B8;">' + _escHtml(step) + '</td>'
                       + '<td style="font-size:0.75rem;color:#64748B;">' + _escHtml(evFile) + '</td>'
                       + '<td style="color:#EF4444;font-size:0.78rem;word-break:break-word;">' + _escHtml(reason) + '</td>'
                       + '</tr>';
                });
                h += '</table></div>';
            }


            // ========== SELF-HEALING ACTIVITY ==========
            const healed = findingsDetail.filter(f => f._self_healed === true);
            if (healed.length > 0) {
                h += '<div class="report-section"><h3 style="color:#10B981;">🩹 Self-Healing Activity (' + healed.length + ')</h3>';
                h += '<table class="fe-pb-table"><tr><th>#</th><th>Playbook</th><th>Step</th><th>Fix Type</th><th>Confidence</th><th>From Cache</th></tr>';
                healed.forEach((f, i) => {
                    const pb = f.playbook || '?';
                    const step = (f.module && f.function) ? (f.module + '.' + f.function) : (f.module || f.function || '?');
                    const fixType = f._heal_fix_type || 'unknown';
                    const confidence = f._heal_confidence !== undefined ? f._heal_confidence : '—';
                    const fromCache = f._heal_from_cache ? '✓' : '—';
                    h += '<tr>'
                       + '<td>' + (i + 1) + '</td>'
                       + '<td>' + _escHtml(pb) + '</td>'
                       + '<td style="font-size:0.78rem;color:#94A3B8;">' + _escHtml(step) + '</td>'
                       + '<td style="font-size:0.78rem;color:#60A5FA;">' + _escHtml(fixType) + '</td>'
                       + '<td style="font-size:0.78rem;color:#F59E0B;">' + _escHtml(String(confidence)) + '</td>'
                       + '<td style="font-size:0.78rem;color:#64748B;">' + _escHtml(fromCache) + '</td>'
                       + '</tr>';
                });
                h += '</table></div>';
            }


            // Raw JSON toggle
            h += '<div class="report-section">';
            h += '<button class="raw-json-toggle" onclick="var p=this.nextElementSibling;p.style.display=p.style.display===\'none\'?\'block\':\'none\';this.textContent=p.style.display===\'none\'?\'{ } Show Raw JSON\':\'{ } Hide Raw JSON\';">{ } Show Raw JSON</button>';
            h += '<pre style="display:none;margin-top:8px;background:#0B1220;border:1px solid #334155;border-radius:6px;padding:14px;overflow:auto;font-size:0.75rem;color:#64748B;max-height:400px;">'
               + _escHtml(JSON.stringify(report, null, 2)) + '</pre>';
            h += '</div>';

            h += '</div>';

            // ---- Report Chat Box ----
            h += '<div class="report-chat" style="margin:2rem 0;border:1px solid var(--g-border);border-radius:10px;background:var(--g-surface);padding:1.2rem;">';
            h += '<div style="font-size:.85rem;font-weight:600;color:var(--g-text-dim);margin-bottom:.8rem;letter-spacing:.05em;">ASK ABOUT THIS REPORT</div>';
            h += '<div class="chat-messages" style="min-height:60px;max-height:320px;overflow-y:auto;display:flex;flex-direction:column;gap:.6rem;margin-bottom:.8rem;"></div>';
            h += '<div style="display:flex;gap:.6rem;">';
            h += '<input class="chat-input" type="text" placeholder="Ask a question about the findings\u2026" style="flex:1;background:var(--g-bg-2);border:1px solid var(--g-border);border-radius:6px;padding:.55rem .8rem;color:var(--g-text);font-size:.9rem;outline:none;" onkeydown="if(event.key===\'Enter\') _reportChatSend(this.parentElement.querySelector(&quot;.chat-send&quot;))">';
            h += '<button class="chat-send" style="background:#3B82F6;color:#fff;border:none;border-radius:6px;padding:.55rem 1.1rem;cursor:pointer;font-size:.9rem;" onclick="_reportChatSend(this)">Ask</button>';
            h += '</div></div>';

            return h;
        }

        function addMessage(text, type) {
            const output = document.getElementById('fe-output');
            const div = document.createElement('div');
            div.className = 'message ' + type;
            if (type === 'user') {
                const label = document.createElement('div');
                label.className = 'label';
                label.textContent = 'You';
                div.appendChild(label);
                const body = document.createElement('span');
                body.textContent = text;
                div.appendChild(body);
            } else if (type === 'geoff') {
                const label = document.createElement('div');
                label.className = 'label';
                label.textContent = 'Geoff';
                div.appendChild(label);
                const body = document.createElement('span');
                body.style.whiteSpace = 'pre-wrap';
                body.textContent = text;
                div.appendChild(body);
            } else if (type === 'tool-result') {
                const label = document.createElement('div');
                label.className = 'label';
                label.textContent = 'Tool Output';
                div.appendChild(label);
                const body = document.createElement('span');
                body.textContent = text;
                div.appendChild(body);
            } else {
                div.textContent = text;
            }
            // Insert before the log and results divs so messages stay above them
            const logDiv = document.getElementById('fe-log');
            output.insertBefore(div, logDiv);
            output.scrollTop = output.scrollHeight;
        }

        // Placeholder shown while waiting for the server response
        let _thinkingDiv = null;
        function _showThinking() {
            _thinkingDiv = document.createElement('div');
            _thinkingDiv.className = 'message system';
            _thinkingDiv.textContent = 'Thinking...';
            const logDiv = document.getElementById('fe-log');
            document.getElementById('fe-output').insertBefore(_thinkingDiv, logDiv);
            document.getElementById('fe-output').scrollTop = document.getElementById('fe-output').scrollHeight;
        }
        function _removeThinking() {
            if (_thinkingDiv && _thinkingDiv.parentNode) {
                _thinkingDiv.parentNode.removeChild(_thinkingDiv);
            }
            _thinkingDiv = null;
        }

        async function sendChat() {
            const input = document.getElementById('chat-input');
            const text = input.value.trim();
            if (!text) return;

            input.disabled = true;
            addMessage(text, 'user');
            input.value = '';
            _showThinking();

            try {
                const res = await authFetch('/chat', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({message: text})
                });
                const data = await res.json();
                _removeThinking();

                if (data.response) addMessage(data.response, 'geoff');
                if (data.tool_result) addMessage(JSON.stringify(data.tool_result, null, 2), 'tool-result');

                // If the chat triggered a Find Evil job, start the live stream
                if (data.job_id) {
                    _startFindEvilStream(data.job_id);
                }
            } catch (e) {
                _removeThinking();
                addMessage('Error: ' + e.message, 'system');
            } finally {
                input.disabled = false;
                input.focus();
            }
        }

        // Shared helper: prepare the UI for a new streaming job
        function _startFindEvilStream(jobId) {
            const progressArea = document.getElementById('fe-progress-area');
            const logDiv = document.getElementById('fe-log');
            const resultsArea = document.getElementById('fe-results-area');

            // Reset state
            progressArea.style.display = 'block';
            logDiv.style.display = 'block';
            logDiv.innerHTML = '';
            resultsArea.style.display = 'none';
            resultsArea.innerHTML = '';

            document.getElementById('fe-pb-name').textContent = 'Starting...';
            document.getElementById('fe-step-name').textContent = '';
            document.getElementById('fe-elapsed').textContent = '0s';
            document.getElementById('fe-progress-fill').style.width = '0%';
            document.getElementById('fe-progress-fill').textContent = '0%';

            pollFindEvilStatus(jobId);
        }
        
        async function loadEvidence() {
            const container = document.getElementById('evidence-content');
            container.innerHTML = '<div class="loading">Loading...</div>';

            try {
                const res = await authFetch('/cases');
                const data = await res.json();
                const cases = data.cases || {};

                container.innerHTML = '';

                if (Object.keys(cases).length === 0) {
                    const empty = document.createElement('div');
                    empty.className = 'loading';
                    empty.textContent = 'No cases found.';
                    container.appendChild(empty);
                    return;
                }

                const list = document.createElement('div');
                list.className = 'case-list';

                for (const [caseName, files] of Object.entries(cases)) {
                    const card = document.createElement('div');
                    card.className = 'case-card';

                    const header = document.createElement('div');
                    header.className = 'case-header';
                    header.title = 'Click to load this case into Find Evil';
                    header.style.cursor = 'pointer';

                    const fullPath = EVIDENCE_BASE_DIR
                        ? EVIDENCE_BASE_DIR.replace(/\/+$/, '') + '/' + caseName
                        : caseName;

                    header.addEventListener('click', () => {
                        document.getElementById('fe-evidence-dir').value = fullPath;
                        // Notify server of active directory for chat
                        authFetch('/active-directory', {
                            method: 'POST',
                            headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify({directory: fullPath})
                        });
                        // Switch to Find Evil tab
                        document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
                        document.querySelectorAll('.content').forEach(c => c.classList.remove('active'));
                        document.querySelector('.tab[onclick*="findevil"]').classList.add('active');
                        document.getElementById('findevil').classList.add('active');
                    });

                    const nameSpan = document.createElement('span');
                    nameSpan.className = 'case-name';
                    nameSpan.textContent = '\U0001F4C1 ' + caseName;

                    const countSpan = document.createElement('span');
                    countSpan.className = 'case-count';
                    countSpan.textContent = files.length + ' items';

                    const investigateBtn = document.createElement('button');
                    investigateBtn.textContent = '🔍 Investigate';
                    investigateBtn.style.cssText = 'margin-left:8px;padding:2px 8px;font-size:11px;cursor:pointer;background:#238636;color:#fff;border:none;border-radius:4px;';
                    investigateBtn.title = 'Load into Find Evil and run';
                    investigateBtn.addEventListener('click', (e) => {
                        e.stopPropagation();
                        document.getElementById('fe-evidence-dir').value = fullPath;
                        // Notify server of active directory for chat
                        authFetch('/active-directory', {
                            method: 'POST',
                            headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify({directory: fullPath})
                        });
                        document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
                        document.querySelectorAll('.content').forEach(c => c.classList.remove('active'));
                        document.querySelector('.tab[onclick*="findevil"]').classList.add('active');
                        document.getElementById('findevil').classList.add('active');
                        runFindEvil();
                    });

                    header.appendChild(nameSpan);
                    header.appendChild(countSpan);
                    header.appendChild(investigateBtn);

                    const filesDiv = document.createElement('div');
                    filesDiv.className = 'case-files';

                    if (files.length === 0) {
                        const empty = document.createElement('div');
                        empty.className = 'file-item';
                        empty.textContent = 'Empty case';
                        filesDiv.appendChild(empty);
                    } else {
                        files.forEach(f => {
                            const isDir = f.startsWith('[DIR]');
                            const item = document.createElement('div');
                            item.className = 'file-item ' + (isDir ? 'dir' : 'file');
                            item.textContent = isDir ? f.replace('[DIR] ', '') : f;
                            filesDiv.appendChild(item);
                        });
                    }

                    card.appendChild(header);
                    card.appendChild(filesDiv);
                    list.appendChild(card);
                }

                container.appendChild(list);
            } catch (e) {
                container.innerHTML = '';
                const err = document.createElement('div');
                err.className = 'loading';
                err.textContent = 'Error loading evidence: ' + e.message;
                container.appendChild(err);
            }
        }
        
        // ---- Find Evil UI ----
        let fePollInterval = null;

        async function runFindEvil() {
            const evidenceDir = document.getElementById('fe-evidence-dir').value.trim();
            const btn = document.getElementById('fe-run-btn');

            btn.disabled = true;
            btn.textContent = '⏳ Running...';

            const label = evidenceDir || 'default evidence directory';
            addMessage('Starting Find Evil on ' + label + ' …', 'system');

            try {
                const res = await authFetch('/find-evil', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ evidence_dir: evidenceDir || '' })
                });
                const data = await res.json();

                if (data.job_id) {
                    _startFindEvilStream(data.job_id);
                } else if (data.status === 'error') {
                    showFindEvilError(data.error || 'Unknown error');
                    btn.disabled = false;
                    btn.textContent = '🔍 Run Find Evil';
                } else {
                    showFindEvilResults(data);
                    btn.disabled = false;
                    btn.textContent = '🔍 Run Find Evil';
                }
            } catch (e) {
                showFindEvilError(e.message);
                btn.disabled = false;
                btn.textContent = '🔍 Run Find Evil';
            }
        }

        function pollFindEvilStatus(jobId) {
            if (fePollInterval) clearInterval(fePollInterval);
            let lastLogIndex = 0;
            const output = document.getElementById('fe-output');

            const poll = async () => {
                try {
                    const res = await authFetch('/find-evil/status/' + jobId);
                    if (res.ok) {
                        const status = await res.json();
                        const pct = status.progress_pct || 0;
                        document.getElementById('fe-pb-name').textContent = status.current_playbook || '—';
                        document.getElementById('fe-step-name').textContent = status.current_step || '';
                        document.getElementById('fe-elapsed').textContent = (status.elapsed_seconds || 0).toFixed(0) + 's';
                        document.getElementById('fe-progress-fill').style.width = pct + '%';
                        document.getElementById('fe-progress-fill').textContent = pct + '%';

                        // Stream log entries into the log div
                        if (status.log && status.log.length > lastLogIndex) {
                            const logDiv = document.getElementById('fe-log');
                            for (let i = lastLogIndex; i < status.log.length; i++) {
                                const entry = status.log[i];
                                const line = document.createElement('div');
                                const time = entry.time || '';
                                const msg = entry.msg || '';
                                let color = '#8b949e';
                                if (msg.includes('✓') || msg.includes('complete')) color = '#3fb950';
                                else if (msg.includes('✗') || msg.includes('error') || msg.includes('fail')) color = '#f85149';
                                else if (msg.includes('▶')) color = '#d29922';
                                else if (msg.includes('⊘') || msg.includes('skip')) color = '#6e7681';
                                else if (msg.includes('needs_review') || msg.includes('⚠')) color = '#d29922';
                                line.style.color = color;
                                line.textContent = time + '  ' + msg;
                                logDiv.appendChild(line);
                            }
                            lastLogIndex = status.log.length;
                            output.scrollTop = output.scrollHeight;
                        }

                        if (status.status === 'complete') {
                            clearInterval(fePollInterval);
                            showFindEvilResults(status.result || {});
                            document.getElementById('fe-run-btn').disabled = false;
                            document.getElementById('fe-run-btn').textContent = '🔍 Run Find Evil';
                        } else if (status.status === 'error') {
                            clearInterval(fePollInterval);
                            showFindEvilError(status.error || 'Unknown error');
                            document.getElementById('fe-run-btn').disabled = false;
                            document.getElementById('fe-run-btn').textContent = '🔍 Run Find Evil';
                        }
                    }
                } catch (e) {
                    console.error('Find Evil poll error:', e);
                }
            };

            poll();
            fePollInterval = setInterval(poll, 2000);
        }

        function showFindEvilResults(report) {
            const area = document.getElementById('fe-results-area');
            area.style.display = 'block';

            const sev = report.severity || 'INFO';
            const evil = report.evil_found;
            const sevDist = report.severity_distribution || {};

            let html = '<div class="fe-results">';
            html += '<h3 style="color:#60A5FA; margin-bottom:10px;">Find Evil Report</h3>';
            html += '<div class="fe-severity ' + sev + '">' + sev + '</div>';
            html += '<p style="margin-bottom:8px;"><strong>Evil Found:</strong> ' + (evil ? '🔴 YES' : '🟢 NO') + '</p>';
            html += '<p style="margin-bottom:8px;"><strong>OS:</strong> ' + (report.os_type || 'unknown') + ' &nbsp;|&nbsp; <strong>Elapsed:</strong> ' + (report.elapsed_seconds || 0).toFixed(1) + 's</p>';

            html += '<p style="margin-bottom:6px;"><strong>Severity Distribution:</strong> ';
            for (const [k, v] of Object.entries(sevDist)) {
                if (v > 0) html += '<span class="fe-severity ' + k + '" style="font-size:0.75rem;padding:2px 8px;margin:2px;">' + k + ': ' + v + '</span> ';
            }
            html += '</p>';

            html += '<p style="margin-bottom:6px;"><strong>Critic Approval:</strong> ' + (report.critic_approval_pct || 0) + '%</p>';

            const pbs = report.playbooks_run || [];
            if (pbs.length > 0) {
                html += '<table class="fe-pb-table"><tr><th>Playbook</th><th>Completed</th><th>Skipped</th><th>Failed</th></tr>';
                pbs.forEach(pb => {
                    const cClass = pb.steps_completed > 0 ? 'completed' : '';
                    const sClass = pb.steps_skipped > 0 ? 'skipped' : '';
                    const fClass = pb.steps_failed > 0 ? 'failed' : '';
                    html += '<tr><td>' + pb.playbook_id + '</td>';
                    html += '<td class="' + cClass + '">' + pb.steps_completed + '</td>';
                    html += '<td class="' + sClass + '">' + pb.steps_skipped + '</td>';
                    html += '<td class="' + fClass + '">' + pb.steps_failed + '</td></tr>';
                });
                html += '</table>';
            }

            // Device Map
            if (report.device_map && Object.keys(report.device_map).length > 0) {
                html += '<h4 style="color:#60A5FA;margin-top:16px;">Devices Discovered</h4>';
                html += '<table class="fe-pb-table"><tr><th>Device</th><th>Type</th><th>Owner</th><th>OS</th><th>Files</th></tr>';
                for (const [devId, dev] of Object.entries(report.device_map)) {
                    html += '<tr>';
                    html += '<td>' + devId + '</td>';
                    html += '<td>' + (_normalizeDeviceType(dev.device_type) || 'unknown') + '</td>';
                    html += '<td>' + (dev.owner || '—') + '</td>';
                    html += '<td>' + (dev.os_type || '—') + '</td>';
                    html += '<td>' + (dev.evidence_files ? dev.evidence_files.length : 0) + '</td>';
                    html += '</tr>';
                }
                html += '</table>';
            }

            // Behavioral Flags Summary
            if (report.behavioral_flags_summary) {
                const total = Object.values(report.behavioral_flags_summary).reduce((a,b) => a+b, 0);
                if (total > 0) {
                    html += '<h4 style="color:#EF4444;margin-top:16px;">⚠ Behavioral Flags: ' + total + '</h4>';
                    for (const [devId, count] of Object.entries(report.behavioral_flags_summary)) {
                        if (count > 0) {
                            html += '<p style="color:#F59E0B;">' + devId + ': ' + count + ' flags</p>';
                        }
                    }
                }
            }

            if (report.case_work_dir) {
                html += '<p style="margin-top:12px;color:#64748B;font-size:0.8rem;">Case: ' + report.case_work_dir + '</p>';
            }

            html += '</div>';

            // Full narrative report section (fetched separately)
            html += '<div id="fe-report-section" style="margin-top:16px;">';
            if (report.narrative_report_path) {
                const caseName = (report.title || '').replace('Find Evil Report \u2014 ', '');
                html += '<button id="fe-report-btn" onclick="loadNarrativeReport(\'' + _escAttr(caseName) + '\')" '
                      + 'style="background:#3B82F6;color:#fff;border:none;padding:8px 18px;border-radius:6px;cursor:pointer;font-size:0.9rem;">'
                      + '\u2139\ufe0f View Full Investigation Report</button>';
                html += '<div id="fe-report-body" style="display:none;margin-top:16px;"></div>';
            }
            html += '</div>';

            area.innerHTML = html;
            // Scroll the unified output so results are visible
            const out = document.getElementById('fe-output');
            out.scrollTop = out.scrollHeight;
        }

        function _escAttr(s) {
            return (s || '').replace(/'/g, "\\'").replace(/"/g, '&quot;');
        }

        // Minimal markdown-to-HTML renderer for the narrative report
        function _md2html(md) {
            const lines = md.split('\n');
            let html = '';
            let inList = false;
            let inTable = false;
            for (let i = 0; i < lines.length; i++) {
                let ln = lines[i];
                // Close open structures on blank line
                if (ln.trim() === '') {
                    if (inList)  { html += '</ul>\n'; inList = false; }
                    if (inTable) { html += '</table>\n'; inTable = false; }
                    html += '<br>';
                    continue;
                }
                // Horizontal rule
                if (/^---+$/.test(ln.trim())) {
                    if (inList)  { html += '</ul>\n'; inList = false; }
                    if (inTable) { html += '</table>\n'; inTable = false; }
                    html += '<hr style="border-color:#334155;margin:12px 0;">\n';
                    continue;
                }
                // Headers
                const h3 = ln.match(/^### (.+)/);
                const h2 = ln.match(/^## (.+)/);
                const h1 = ln.match(/^# (.+)/);
                if (h1) { html += '<h2 style="color:#60A5FA;margin:16px 0 8px;">' + _mdInline(h1[1]) + '</h2>\n'; continue; }
                if (h2) { html += '<h3 style="color:#93C5FD;margin:14px 0 6px;">' + _mdInline(h2[1]) + '</h3>\n'; continue; }
                if (h3) { html += '<h4 style="color:#94A3B8;margin:12px 0 4px;">' + _mdInline(h3[1]) + '</h4>\n'; continue; }
                // Table row
                if (ln.startsWith('|')) {
                    if (!inTable) { html += '<table style="border-collapse:collapse;width:100%;margin:6px 0;font-size:0.82rem;">'; inTable = true; }
                    if (/^[|][-| ]+[|]$/.test(ln.trim())) continue; // separator row
                    const cells = ln.split('|').slice(1,-1);
                    html += '<tr>' + cells.map(c => '<td style="border:1px solid #334155;padding:4px 8px;">' + _mdInline(c.trim()) + '</td>').join('') + '</tr>\n';
                    continue;
                }
                if (inTable) { html += '</table>\n'; inTable = false; }
                // List item
                const li = ln.match(/^[-*] (.+)/);
                if (li) {
                    if (!inList) { html += '<ul style="margin:4px 0 4px 18px;padding:0;">'; inList = true; }
                    html += '<li style="margin:2px 0;">' + _mdInline(li[1]) + '</li>\n';
                    continue;
                }
                // Numbered list
                const ol = ln.match(/^\\d+\\. (.+)/);
                if (ol) {
                    if (inList) { html += '</ul>\n'; inList = false; }
                    html += '<p style="margin:2px 0;">' + _mdInline(ln) + '</p>\n';
                    continue;
                }
                if (inList) { html += '</ul>\n'; inList = false; }
                html += '<p style="margin:4px 0;">' + _mdInline(ln) + '</p>\n';
            }
            if (inList)  html += '</ul>\n';
            if (inTable) html += '</table>\n';
            // Strip residual dangerous patterns (defense-in-depth against XSS from attacker-controlled evidence)
            html = html.replace(/<script[\s\S]*?<\/script>/gi, '')
                       .replace(/\bon\w+\s*=/gi, 'data-removed=')
                       .replace(/javascript\s*:/gi, '');
            return html;
        }

        function _mdInline(s) {
            // Escape HTML first
            s = s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
            // Bold+italic, bold, italic, code, backtick
            s = s.replace(/[*][*][*](.+?)[*][*][*]/g, '<strong><em>$1</em></strong>');
            s = s.replace(/[*][*](.+?)[*][*]/g, '<strong>$1</strong>');
            s = s.replace(/[*](.+?)[*]/g, '<em>$1</em>');
            s = s.replace(/`([^`]+)`/g, '<code style="background:#161b22;padding:1px 5px;border-radius:3px;font-size:0.85em;">$1</code>');
            return s;
        }

        async function loadNarrativeReport(caseName) {
            const btn = document.getElementById('fe-report-btn');
            const body = document.getElementById('fe-report-body');
            if (!btn || !body) return;
            btn.disabled = true;
            btn.textContent = 'Loading report\u2026';
            try {
                const resp = await authFetch('/cases/' + encodeURIComponent(caseName) + '/report');
                if (!resp.ok) {
                    body.innerHTML = '<p style="color:#EF4444;">Failed to load report (' + resp.status + ')</p>';
                    body.style.display = 'block';
                    return;
                }
                const md = await resp.text();
                body.innerHTML = '<div style="background:#0B1220;border:1px solid #334155;border-radius:6px;padding:16px;font-size:0.88rem;line-height:1.6;color:#F1F5F9;">'
                               + _md2html(md) + '</div>';
                body.style.display = 'block';
                btn.textContent = '\u25b2 Hide Report';
                btn.onclick = () => {
                    body.style.display = body.style.display === 'none' ? 'block' : 'none';
                    btn.textContent = body.style.display === 'none' ? '\u2139\ufe0f View Full Investigation Report' : '\u25b2 Hide Report';
                };
            } catch(e) {
                body.innerHTML = '<p style="color:#EF4444;">Error: ' + e.message + '</p>';
                body.style.display = 'block';
            } finally {
                btn.disabled = false;
            }
        }

        function showFindEvilError(msg) {
            const area = document.getElementById('fe-results-area');
            area.style.display = 'block';
            const p = document.createElement('div');
            p.className = 'fe-results';
            const txt = document.createElement('p');
            txt.style.cssText = 'color:#EF4444;font-weight:600;';
            txt.textContent = 'Error: ' + msg;
            p.appendChild(txt);
            area.innerHTML = '';
            area.appendChild(p);
            const out = document.getElementById('fe-output');
            out.scrollTop = out.scrollHeight;
        }
    
function showCommandHistory(caseDir, highlightHash) {
    var modal = document.getElementById('history-modal');
    var content = document.getElementById('history-content');
    modal.style.display = 'block';
    // Store the caseDir for IOC click handlers
    modal.dataset.caseDir = caseDir;
    // Attach close handlers (modal HTML may not exist when page first loads)
    document.getElementById('history-close').onclick = function() {
        document.getElementById('history-modal').style.display = 'none';
    };
    document.getElementById('history-modal').onclick = function(e) {
        if (e.target === this) this.style.display = 'none';
    };
    document.addEventListener('keydown', function escHandler(e) {
        if (e.key === 'Escape') {
            var hm = document.getElementById('history-modal');
            if (hm && hm.style.display === 'block') { hm.style.display = 'none'; }
        }
    });
    content.innerHTML = '<div style="color:#999;text-align:center;padding:40px;">Loading commit history...</div>';
    fetch('/reports/' + encodeURIComponent(caseDir) + '/history')
        .then(function(r) { if(!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
        .then(function(data) {
            if (data.error) { content.innerHTML = '<div style="color:#f44336;padding:20px;">Error: ' + data.error + '</div>'; return; }
            renderHistoryTable(data.commits, content);
            if (highlightHash) {
                setTimeout(function() {
                    var row = document.querySelector('#history-content tr[data-hash="' + highlightHash + '"]');
                    if (row) {
                        row.scrollIntoView({behavior: 'smooth', block: 'center'});
                        row.style.background = 'rgba(16,185,129,0.15)';
                        row.style.transition = 'background 0.3s';
                        setTimeout(function() { row.style.background = ''; }, 3000);
                    }
                }, 200);
            }
        })
        .catch(function(e) { content.innerHTML = '<div style="color:#f44336;padding:20px;">Failed to load: ' + e.message + '</div>'; });
}

function renderHistoryTable(commits, container) {
    if (!commits || commits.length === 0) {
        container.innerHTML = '<div style="color:#999;text-align:center;padding:40px;">No commit history found for this case.</div>';
        return;
    }
    var h = '<table style="width:100%;border-collapse:collapse;color:#ccc;">';
    h += '<thead><tr style="border-bottom:2px solid #2d3566;">';
    h += '<th style="padding:8px 12px;text-align:left;color:#6c63ff;">Hash</th>';
    h += '<th style="padding:8px 12px;text-align:left;color:#6c63ff;">Timestamp</th>';
    h += '<th style="padding:8px 12px;text-align:left;color:#6c63ff;">Playbook</th>';
    h += '<th style="padding:8px 12px;text-align:left;color:#6c63ff;">Module.Function</th>';
    h += '<th style="padding:8px 12px;text-align:left;color:#6c63ff;">Evidence</th>';
    h += '<th style="padding:8px 12px;text-align:left;color:#6c63ff;">Status</th>';
    h += '<th style="padding:8px 12px;text-align:left;color:#6c63ff;">Critic</th>';
    h += '</tr></thead><tbody>';
    for (var i = 0; i < commits.length; i++) {
        var c = commits[i];
        var rs = i % 2 === 0 ? 'background:rgba(255,255,255,0.02);' : '';
        var sb, cb;
        if (c.status) {
            var s = c.status.toLowerCase();
            if (s === 'completed' || s === 'pass') sb = '<span style="color:#10B981;font-weight:bold;">' + c.status + '</span>';
            else if (s === 'failed' || s === 'error') sb = '<span style="color:#ef4444;font-weight:bold;">' + c.status + '</span>';
            else sb = '<span style="color:#f59e0b;">' + c.status + '</span>';
        } else { sb = '<span style="color:#666;">-</span>'; }
        if (c.critic) {
            if (c.critic.passes_sanity) cb = '<span style="color:#10B981;">✓ Pass</span>';
            else if (c.critic.needs_review) cb = '<span style="color:#f59e0b;">⚠ Needs Review</span>';
            else cb = '<span style="color:#ef4444;">✗ Fail</span>';
            var issues = [];
            if (c.critic.hallucinations) issues.push('Hall: ' + c.critic.hallucinations);
            if (c.critic.nonsense) issues.push('Nonsense: ' + c.critic.nonsense);
            if (c.critic.unverified_reason) issues.push('Unver: ' + c.critic.unverified_reason);
            if (issues.length > 0) cb += '<div style="font-size:11px;color:#f59e0b;margin-top:2px;">' + issues.join('<br>') + '</div>';
        } else { cb = '<span style="color:#666;">-</span>'; }
        h += '<tr style="border-bottom:1px solid rgba(255,255,255,0.05);' + rs + '" data-hash="' + (c.hash || '') + '">';
        h += '<td style="padding:6px 12px;"><span style="color:#6c63ff;font-family:monospace;">' + (c.hash || '') + '</span></td>';
        h += '<td style="padding:6px 12px;font-size:12px;">' + (c.timestamp || '').substring(0, 19).replace('T', ' ') + '</td>';
        h += '<td style="padding:6px 12px;">' + (c.playbook || '-') + '</td>';
        h += '<td style="padding:6px 12px;color:#e2e8f0;">' + (c.module ? c.module + '.' + c.function : '-') + '</td>';
        h += '<td style="padding:6px 12px;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="' + (c.ev_name || '') + '">' + (c.ev_name || '-') + '</td>';
        h += '<td style="padding:6px 12px;">' + sb + '</td>';
        h += '<td style="padding:6px 12px;">' + cb + '</td>';
        h += '</tr>';
    }
    h += '</tbody></table>';
    container.innerHTML = h;
}


document.addEventListener('keydown', function(e) { if (e.key === 'Escape') { var hm = document.getElementById('history-modal'); if (hm && hm.style.display === 'block') { hm.style.display = 'none'; } } });

    document.getElementById('history-close').onclick = function() {
        document.getElementById('history-modal').style.display = 'none';
    };
    // Also close on background click
    document.getElementById('history-modal').onclick = function(e) {
        if (e.target === this) this.style.display = 'none';
    };

    // IOC → Command History click handler
    document.addEventListener('click', function(e) {
        var el = e.target.closest && e.target.closest('[data-commit]');
        if (!el) return;
        e.preventDefault();
        var commitHash = el.dataset.commit;
        var modal = document.getElementById('history-modal');
        var caseDir = modal.dataset.caseDir;
        if (!caseDir) return;
        // Open the modal with the commit highlighted
        showCommandHistory(caseDir, commitHash);
    });

    // ---- Report Chat Functions ----
    function _reportChatBubble(msgContainer, text, role) {
        var d = document.createElement('div');
        d.style.cssText = 'padding:.5rem .8rem;border-radius:6px;font-size:.88rem;max-width:90%;white-space:pre-wrap;' +
            (role==='user'
                ? 'align-self:flex-end;background:rgba(59,130,246,.18);color:#F1F5F9;'
                : 'align-self:flex-start;background:#0F172A;color:#94A3B8;');
        d.textContent = text;
        msgContainer.appendChild(d);
        d.scrollIntoView({behavior:'smooth'});
        return d;
    }

    async function _reportChatSend(btn) {
        var chatBox = btn.closest('.report-chat');
        if (!chatBox) return;
        var input = chatBox.querySelector('.chat-input');
        var msgs = chatBox.querySelector('.chat-messages');
        var q = input.value.trim();
        if (!q) return;
        input.value = '';
        _reportChatBubble(msgs, q, 'user');
        var thinking = _reportChatBubble(msgs, '\u2026', 'assistant');

        try {
            var r = await authFetch('/reports/' + encodeURIComponent(window._reportChatCaseDir || '') + '/chat', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({question: q, report_json: window._reportChatData || {}})
            });
            var data = await r.json();
            thinking.textContent = data.answer;
        } catch(e) {
            thinking.textContent = 'Error contacting server.';
        }
    }

</script>

<!-- Command History Modal -->
<div id="history-modal" style="display:none;position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.7);backdrop-filter:blur(4px);z-index:9999;padding:20px;">
  <div style="background:var(--g-surface,#1a1a2e);max-width:95%;height:90vh;margin:0 auto;border-radius:12px;border:1px solid var(--g-border,#2d3566);overflow:hidden;display:flex;flex-direction:column;">
    <div style="display:flex;justify-content:space-between;align-items:center;padding:16px 24px;border-bottom:1px solid var(--g-border,#2d3566);">
      <h2 style="color:var(--g-accent,#6c63ff);margin:0;">🔍 Command History</h2>
      <span id="history-close" style="color:#999;font-size:28px;cursor:pointer;line-height:1;">&times;</span>
    </div>
    <div id="history-content" style="flex:1;overflow-y:auto;padding:16px 24px;font-family:'Courier New',monospace;font-size:13px;">
      <div style="color:#999;text-align:center;padding:40px;">Loading...</div>
    </div>
  </div>
</div>
</body>
</html>
"""
