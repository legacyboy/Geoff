// Geoff UI Application

const WS_URL = `ws://${window.location.host}/ws`;
const API_BASE = `http://${window.location.host}`;
const AUTH_TOKEN = localStorage.getItem('geoff-token') || 'geoff-default';

// State
let currentTab = 'chat';
let messages = [];
let files = [];
let isConnected = false;
let ws = null;
let isTyping = false;

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    initTabs();
    initChat();
    initUpload();
    initConfig();
    loadSavedConfig();
    checkStatus();
    initWebSocket();
    
    // Periodic status check
    setInterval(checkStatus, 10000);
});

// Initialize WebSocket connection
function initWebSocket() {
    try {
        ws = new WebSocket(WS_URL);
        
        ws.onopen = () => {
            console.log('WebSocket connected');
            updateStatus(true);
        };
        
        ws.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                handleWebSocketMessage(data);
            } catch (e) {
                console.log('Received:', event.data);
            }
        };
        
        ws.onclose = () => {
            console.log('WebSocket disconnected');
            updateStatus(false);
            // Auto-reconnect after 3 seconds
            setTimeout(initWebSocket, 3000);
        };
        
        ws.onerror = (err) => {
            console.error('WebSocket error:', err);
            updateStatus(false);
        };
    } catch (err) {
        console.error('Failed to initialize WebSocket:', err);
        updateStatus(false);
    }
}

function handleWebSocketMessage(data) {
    switch (data.type) {
        case 'system':
            addMessage('system', data.message, 'System');
            break;
        case 'assistant':
            hideTypingIndicator();
            addMessage('system', data.message, 'Geoff');
            break;
        case 'error':
            hideTypingIndicator();
            addMessage('error', data.message, 'Error');
            break;
        default:
            if (data.message) {
                hideTypingIndicator();
                addMessage('system', data.message, 'Geoff');
            }
    }
}

function updateStatus(connected) {
    isConnected = connected;
    const statusEl = document.getElementById('status');
    if (connected) {
        statusEl.textContent = 'Online';
        statusEl.className = 'status online';
    } else {
        statusEl.textContent = 'Offline - Run: geoff start';
        statusEl.className = 'status offline';
    }
}

// Tabs
function initTabs() {
    const tabBtns = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');

    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            const tab = btn.dataset.tab;
            
            // Update buttons
            tabBtns.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            
            // Update content
            tabContents.forEach(c => c.classList.remove('active'));
            document.getElementById(`${tab}-tab`).classList.add('active');
            
            currentTab = tab;
            
            // Load data for specific tabs
            if (tab === 'evidence') {
                loadEvidenceFiles();
            }
        });
    });
}

// Status Check (fallback when WebSocket not connected)
async function checkStatus() {
    if (isConnected && ws && ws.readyState === WebSocket.OPEN) {
        return; // Already connected via WebSocket
    }
    
    try {
        const response = await fetch(`${API_BASE}/api/health`, {
            headers: { 'Authorization': `Bearer ${AUTH_TOKEN}` },
            signal: AbortSignal.timeout(3000)
        });
        
        if (response.ok) {
            updateStatus(true);
        } else {
            updateStatus(false);
        }
    } catch (err) {
        updateStatus(false);
    }
}

// Chat
function initChat() {
    const chatInput = document.getElementById('chat-input');
    const sendBtn = document.getElementById('send-btn');

    // Send on Enter (Shift+Enter for new line)
    chatInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            sendMessage();
        }
    });

    sendBtn.addEventListener('click', sendMessage);
}

function showTypingIndicator() {
    const messagesContainer = document.getElementById('messages');
    const existingIndicator = document.getElementById('typing-indicator');
    if (existingIndicator) return;
    
    const indicator = document.createElement('div');
    indicator.id = 'typing-indicator';
    indicator.className = 'message system typing';
    indicator.innerHTML = `
        <div class="content">
            <span class="dot"></span>
            <span class="dot"></span>
            <span class="dot"></span>
        </div>
    `;
    messagesContainer.appendChild(indicator);
    messagesContainer.scrollTop = messagesContainer.scrollHeight;
    isTyping = true;
}

function hideTypingIndicator() {
    const indicator = document.getElementById('typing-indicator');
    if (indicator) {
        indicator.remove();
    }
    isTyping = false;
}

async function sendMessage() {
    const chatInput = document.getElementById('chat-input');
    const text = chatInput.value.trim();
    if (!text) return;

    // Add user message
    addMessage('user', text, 'You');
    chatInput.value = '';

    // Try WebSocket first
    if (ws && ws.readyState === WebSocket.OPEN) {
        showTypingIndicator();
        ws.send(JSON.stringify({ type: 'chat', content: text }));
        return;
    }

    // Fallback to HTTP API
    showTypingIndicator();
    
    try {
        const response = await fetch(`${API_BASE}/api/chat`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${AUTH_TOKEN}`
            },
            body: JSON.stringify({ message: text })
        });

        hideTypingIndicator();

        if (response.ok) {
            const data = await response.json();
            addMessage('system', data.response, 'Geoff');
        } else {
            addMessage('error', 'Error: Could not get response from Geoff', 'Error');
        }
    } catch (err) {
        hideTypingIndicator();
        addMessage('error', 'Error: Connection failed. Make sure Geoff is running.', 'Error');
    }
}

function addMessage(sender, text, label = null) {
    const messagesContainer = document.getElementById('messages');
    const time = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    const div = document.createElement('div');
    div.className = `message ${sender}`;
    div.innerHTML = `
        <div class="message-header">
            <span class="sender">${label || (sender === 'user' ? 'You' : 'Geoff')}</span>
            <span class="time">${time}</span>
        </div>
        <div class="content">${escapeHtml(text)}</div>
    `;
    messagesContainer.appendChild(div);
    messagesContainer.scrollTop = messagesContainer.scrollHeight;
}

// File Upload
function initUpload() {
    const uploadZone = document.getElementById('upload-zone');
    const fileInput = document.getElementById('file-input');
    const evidencePath = document.getElementById('evidence-path');

    // Drag and drop
    uploadZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        uploadZone.classList.add('dragover');
    });

    uploadZone.addEventListener('dragleave', () => {
        uploadZone.classList.remove('dragover');
    });

    uploadZone.addEventListener('drop', (e) => {
        e.preventDefault();
        uploadZone.classList.remove('dragover');
        handleFiles(e.dataTransfer.files);
    });

    // File input
    fileInput.addEventListener('change', (e) => {
        handleFiles(e.target.files);
    });

    // Change evidence path
    document.getElementById('change-evidence-path').addEventListener('click', () => {
        const newPath = prompt('Enter new evidence path:', evidencePath.value);
        if (newPath) {
            evidencePath.value = newPath;
            localStorage.setItem('geoff-evidence-path', newPath);
            document.getElementById('evidence-dir').value = newPath;
        }
    });

    // Load saved path
    const savedPath = localStorage.getItem('geoff-evidence-path');
    if (savedPath) {
        evidencePath.value = savedPath;
        document.getElementById('evidence-dir').value = savedPath;
    }
}

async function loadEvidenceFiles() {
    try {
        const response = await fetch(`${API_BASE}/api/evidence`, {
            headers: { 'Authorization': `Bearer ${AUTH_TOKEN}` }
        });
        
        if (response.ok) {
            const data = await response.json();
            files = data.files || [];
            renderFiles();
        }
    } catch (err) {
        console.error('Failed to load evidence files:', err);
    }
}

async function handleFiles(fileList) {
    const evidencePath = document.getElementById('evidence-path').value;
    
    for (const file of fileList) {
        const fileObj = {
            name: file.name,
            size: formatFileSize(file.size),
            status: 'pending',
            file: file
        };
        files.push(fileObj);
        renderFiles();
        await uploadFile(fileObj, evidencePath);
    }
}

async function uploadFile(fileObj, evidencePath) {
    try {
        fileObj.status = 'uploading';
        renderFiles();

        // Convert file to base64
        const base64Content = await fileToBase64(fileObj.file);
        
        const response = await fetch(`${API_BASE}/api/upload`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${AUTH_TOKEN}`
            },
            body: JSON.stringify({
                filename: fileObj.name,
                content: base64Content,
                filepath: evidencePath
            })
        });

        if (response.ok) {
            fileObj.status = 'uploaded';
        } else {
            const error = await response.json();
            fileObj.status = 'error';
            fileObj.error = error.error || 'Upload failed';
        }
    } catch (err) {
        fileObj.status = 'error';
        fileObj.error = err.message;
    }
    renderFiles();
}

function fileToBase64(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => {
            const base64 = reader.result.split(',')[1];
            resolve(base64);
        };
        reader.onerror = reject;
        reader.readAsDataURL(file);
    });
}

function renderFiles() {
    const filesContainer = document.getElementById('files-container');
    
    if (files.length === 0) {
        filesContainer.innerHTML = '<p class="empty">No files uploaded yet</p>';
        return;
    }

    filesContainer.innerHTML = files.map(f => `
        <div class="file-item ${f.status}">
            <div class="file-info">
                <span class="name">${escapeHtml(f.name)}</span>
                <span class="size">${f.size}</span>
            </div>
            <span class="status ${f.status}">${f.status}</span>
            ${f.error ? `<span class="error-msg">${escapeHtml(f.error)}</span>` : ''}
        </div>
    `).join('');
}

// Config
function initConfig() {
    const modelMode = document.getElementById('model-mode');
    const localGroup = document.getElementById('local-model-group');
    const cloudGroup = document.getElementById('cloud-model-group');
    const saveBtn = document.getElementById('save-config');
    const restartBtn = document.getElementById('restart-geoff');
    const showTokenBtn = document.getElementById('show-token');
    const tokenInput = document.getElementById('auth-token');

    // Model mode toggle
    modelMode.addEventListener('change', () => {
        if (modelMode.value === 'local') {
            localGroup.classList.remove('hidden');
            cloudGroup.classList.add('hidden');
        } else {
            localGroup.classList.add('hidden');
            cloudGroup.classList.remove('hidden');
        }
    });

    // Show/hide token
    showTokenBtn.addEventListener('click', () => {
        if (tokenInput.type === 'password') {
            tokenInput.type = 'text';
            showTokenBtn.textContent = 'Hide';
        } else {
            tokenInput.type = 'password';
            showTokenBtn.textContent = 'Show';
        }
    });

    // Save config
    saveBtn.addEventListener('click', saveConfiguration);

    // Restart Geoff
    restartBtn.addEventListener('click', async () => {
        if (!confirm('Restart Geoff? This may take a moment.')) return;
        
        try {
            const response = await fetch(`${API_BASE}/api/restart`, {
                method: 'POST',
                headers: { 'Authorization': `Bearer ${AUTH_TOKEN}` }
            });
            
            if (response.ok) {
                alert('Geoff is restarting...');
                updateStatus(false);
                setTimeout(checkStatus, 5000);
            } else {
                alert('Failed to restart Geoff');
            }
        } catch (err) {
            alert('Connection error. Geoff may not be running.');
        }
    });
}

async function loadSavedConfig() {
    try {
        const response = await fetch(`${API_BASE}/api/config`, {
            headers: { 'Authorization': `Bearer ${AUTH_TOKEN}` }
        });
        
        if (response.ok) {
            const config = await response.json();
            applyConfig(config);
        }
    } catch (err) {
        // Fall back to localStorage
        const savedConfig = localStorage.getItem('geoff-config');
        if (savedConfig) {
            applyConfig(JSON.parse(savedConfig));
        }
    }
}

function applyConfig(config) {
    if (config.modelMode) document.getElementById('model-mode').value = config.modelMode;
    if (config.localModel) document.getElementById('local-model').value = config.localModel;
    if (config.cloudModel) document.getElementById('cloud-model').value = config.cloudModel;
    if (config.evidenceDir) {
        document.getElementById('evidence-dir').value = config.evidenceDir;
        document.getElementById('evidence-path').value = config.evidenceDir;
    }
    if (config.autoProcess !== undefined) document.getElementById('auto-process').checked = config.autoProcess;
    if (config.gatewayPort) document.getElementById('gateway-port').value = config.gatewayPort;
    if (config.authToken) {
        document.getElementById('auth-token').value = config.authToken;
        localStorage.setItem('geoff-token', config.authToken);
    }
    
    // Trigger model mode change
    document.getElementById('model-mode').dispatchEvent(new Event('change'));
}

async function saveConfiguration() {
    const config = {
        modelMode: document.getElementById('model-mode').value,
        localModel: document.getElementById('local-model').value,
        cloudModel: document.getElementById('cloud-model').value,
        evidenceDir: document.getElementById('evidence-dir').value,
        autoProcess: document.getElementById('auto-process').checked,
        gatewayPort: document.getElementById('gateway-port').value,
        authToken: document.getElementById('auth-token').value
    };
    
    // Save locally first
    localStorage.setItem('geoff-config', JSON.stringify(config));
    localStorage.setItem('geoff-token', config.authToken);
    localStorage.setItem('geoff-evidence-path', config.evidenceDir);
    
    // Save to server
    try {
        const response = await fetch(`${API_BASE}/api/config`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${AUTH_TOKEN}`
            },
            body: JSON.stringify(config)
        });
        
        if (response.ok) {
            showNotification('Configuration saved!', 'success');
        } else {
            showNotification('Saved locally (server unavailable)', 'warning');
        }
    } catch (err) {
        showNotification('Saved locally (server unavailable)', 'warning');
    }
}

function showNotification(message, type = 'info') {
    const existing = document.querySelector('.notification');
    if (existing) existing.remove();
    
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.textContent = message;
    document.body.appendChild(notification);
    
    setTimeout(() => notification.remove(), 3000);
}

// Utilities
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}
