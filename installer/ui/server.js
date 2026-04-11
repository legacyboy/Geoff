#!/usr/bin/env node

// Geoff UI Server - HTTP server for the web UI
// Integrates with OpenClaw gateway for chat functionality

const http = require('http');
const fs = require('fs');
const path = require('path');
const url = require('url');
const os = require('os');

const PORT = process.env.GEOFF_UI_PORT || 8080;
const GATEWAY_URL = process.env.GEOFF_GATEWAY_URL || 'ws://127.0.0.1:18789';
const GATEWAY_HTTP_URL = process.env.GEOFF_GATEWAY_HTTP || 'http://127.0.0.1:18789';
const AUTH_TOKEN = process.env.GEOFF_TOKEN || 'geoff-default';
const EVIDENCE_DIR = process.env.GEOFF_EVIDENCE || path.join(os.homedir(), '.geoff', 'evidence');

const MIME_TYPES = {
    '.html': 'text/html',
    '.css': 'text/css',
    '.js': 'application/javascript',
    '.json': 'application/json',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.gif': 'image/gif',
    '.svg': 'image/svg+xml',
    '.ico': 'image/x-icon',
    '.pdf': 'application/pdf',
    '.txt': 'text/plain',
    '.md': 'text/markdown'
};

const UI_DIR = __dirname;

// Ensure evidence directory exists
function ensureEvidenceDir() {
    const evidencePath = EVIDENCE_DIR.replace('~', os.homedir());
    if (!fs.existsSync(evidencePath)) {
        fs.mkdirSync(evidencePath, { recursive: true });
    }
    return evidencePath;
}

function serveFile(res, filePath, statusCode = 200) {
    const ext = path.extname(filePath).toLowerCase();
    const contentType = MIME_TYPES[ext] || 'application/octet-stream';
    
    fs.readFile(filePath, (err, content) => {
        if (err) {
            if (err.code === 'ENOENT') {
                res.writeHead(404, { 'Content-Type': 'text/plain' });
                res.end('File not found');
            } else {
                res.writeHead(500, { 'Content-Type': 'text/plain' });
                res.end('Server error');
            }
            return;
        }
        
        res.writeHead(statusCode, { 
            'Content-Type': contentType,
            'Access-Control-Allow-Origin': '*'
        });
        res.end(content);
    });
}

// Handle file upload
async function handleUpload(req, res) {
    return new Promise((resolve) => {
        const evidencePath = ensureEvidenceDir();
        let body = '';
        
        req.on('data', chunk => {
            body += chunk.toString();
        });
        
        req.on('end', () => {
            try {
                const data = JSON.parse(body);
                const { filename, content, filepath } = data;
                
                if (!filename || !content) {
                    res.writeHead(400, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ error: 'Missing filename or content' }));
                    resolve();
                    return;
                }
                
                // Decode base64 content
                const fileBuffer = Buffer.from(content, 'base64');
                const targetPath = filepath ? 
                    path.join(filepath.replace('~', os.homedir()), filename) :
                    path.join(evidencePath, filename);
                
                // Ensure directory exists
                const targetDir = path.dirname(targetPath);
                if (!fs.existsSync(targetDir)) {
                    fs.mkdirSync(targetDir, { recursive: true });
                }
                
                fs.writeFileSync(targetPath, fileBuffer);
                
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ 
                    success: true, 
                    filename,
                    path: targetPath.replace(os.homedir(), '~')
                }));
            } catch (err) {
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: err.message }));
            }
            resolve();
        });
    });
}

// Handle config save
async function handleConfig(req, res) {
    return new Promise((resolve) => {
        let body = '';
        
        req.on('data', chunk => {
            body += chunk.toString();
        });
        
        req.on('end', () => {
            try {
                const config = JSON.parse(body);
                
                // Save config to file
                const configDir = path.join(os.homedir(), '.geoff');
                if (!fs.existsSync(configDir)) {
                    fs.mkdirSync(configDir, { recursive: true });
                }
                
                fs.writeFileSync(
                    path.join(configDir, 'ui-config.json'),
                    JSON.stringify(config, null, 2)
                );
                
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: true, config }));
            } catch (err) {
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: err.message }));
            }
            resolve();
        });
    });
}

// Handle chat proxy to OpenClaw
async function handleChat(req, res) {
    return new Promise((resolve) => {
        let body = '';
        
        req.on('data', chunk => {
            body += chunk.toString();
        });
        
        req.on('end', async () => {
            try {
                const data = JSON.parse(body);
                
                // Proxy to OpenClaw gateway
                const http = require('http');
                const url = require('url');
                const gatewayUrl = url.parse(`${GATEWAY_HTTP_URL}/v1/chat/completions`);
                
                const options = {
                    hostname: gatewayUrl.hostname,
                    port: gatewayUrl.port,
                    path: gatewayUrl.path,
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${AUTH_TOKEN}`
                    }
                };
                
                const proxyReq = http.request(options, (proxyRes) => {
                    let responseData = '';
                    proxyRes.on('data', chunk => {
                        responseData += chunk;
                    });
                    proxyRes.on('end', () => {
                        try {
                            const parsed = JSON.parse(responseData);
                            const message = parsed.choices?.[0]?.message?.content || 'No response';
                            res.writeHead(200, { 'Content-Type': 'application/json' });
                            res.end(JSON.stringify({ response: message }));
                        } catch (e) {
                            res.writeHead(200, { 'Content-Type': 'application/json' });
                            res.end(JSON.stringify({ response: responseData }));
                        }
                        resolve();
                    });
                });
                
                proxyReq.on('error', (err) => {
                    res.writeHead(500, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ error: 'Gateway error: ' + err.message }));
                    resolve();
                });
                
                proxyReq.write(JSON.stringify({
                    model: 'default',
                    messages: [{ role: 'user', content: data.message }]
                }));
                proxyReq.end();
                
            } catch (err) {
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: err.message }));
                resolve();
            }
        });
    });
}

// Health check
function handleHealth(req, res) {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok', timestamp: Date.now() }));
}

// Get config
function handleGetConfig(req, res) {
    try {
        const configPath = path.join(os.homedir(), '.geoff', 'ui-config.json');
        let config = {};
        if (fs.existsSync(configPath)) {
            config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(config));
    } catch (err) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: err.message }));
    }
}

// Get evidence files
function handleGetEvidence(req, res) {
    try {
        const evidencePath = ensureEvidenceDir();
        const files = [];
        
        function scanDir(dir, relativePath = '') {
            if (!fs.existsSync(dir)) return;
            const items = fs.readdirSync(dir);
            for (const item of items) {
                const fullPath = path.join(dir, item);
                const relPath = path.join(relativePath, item);
                const stat = fs.statSync(fullPath);
                if (stat.isDirectory()) {
                    scanDir(fullPath, relPath);
                } else {
                    files.push({
                        name: item,
                        path: relPath,
                        size: stat.size,
                        modified: stat.mtime.toISOString()
                    });
                }
            }
        }
        
        scanDir(evidencePath);
        
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ files }));
    } catch (err) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: err.message }));
    }
}

// Restart Geoff
async function handleRestart(req, res) {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ success: true, message: 'Restart command received' }));
    
    // Restart after response is sent
    setTimeout(() => {
        console.log('Restarting Geoff...');
        process.exit(0);
    }, 100);
}

// Setup WebSocket connection to OpenClaw gateway
function setupWebSocket(server) {
    const WebSocket = require('ws');
    const wss = new WebSocket.Server({ server, path: '/ws' });
    
    wss.on('connection', (ws, req) => {
        console.log('Client connected to WebSocket');
        
        let gatewayWs = null;
        let reconnectAttempts = 0;
        const maxReconnects = 5;
        
        function connectToGateway() {
            try {
                gatewayWs = new WebSocket(GATEWAY_URL, {
                    headers: { Authorization: `Bearer ${AUTH_TOKEN}` }
                });
                
                gatewayWs.on('open', () => {
                    console.log('Connected to OpenClaw gateway');
                    reconnectAttempts = 0;
                    if (ws.readyState === WebSocket.OPEN) {
                        ws.send(JSON.stringify({ type: 'system', message: 'Connected to Geoff' }));
                    }
                });
                
                gatewayWs.on('message', (data) => {
                    // Forward messages from gateway to client
                    try {
                        const message = JSON.parse(data);
                        if (ws.readyState === WebSocket.OPEN) {
                            ws.send(JSON.stringify({ type: 'assistant', message: message.content || message }));
                        }
                    } catch (e) {
                        if (ws.readyState === WebSocket.OPEN) {
                            ws.send(JSON.stringify({ type: 'assistant', message: data.toString() }));
                        }
                    }
                });
                
                gatewayWs.on('error', (err) => {
                    console.error('Gateway error:', err.message);
                    if (ws.readyState === WebSocket.OPEN) {
                        ws.send(JSON.stringify({ type: 'error', message: 'Gateway connection error: ' + err.message }));
                    }
                });
                
                gatewayWs.on('close', () => {
                    console.log('Gateway connection closed');
                    if (reconnectAttempts < maxReconnects) {
                        reconnectAttempts++;
                        console.log(`Reconnecting... (${reconnectAttempts}/${maxReconnects})`);
                        setTimeout(connectToGateway, 2000);
                    } else {
                        if (ws.readyState === WebSocket.OPEN) {
                            ws.send(JSON.stringify({ type: 'error', message: 'Lost connection to Geoff' }));
                        }
                    }
                });
            } catch (err) {
                console.error('Failed to connect to gateway:', err.message);
            }
        }
        
        connectToGateway();
        
        ws.on('message', (data) => {
            // Forward messages from client to gateway
            try {
                const message = JSON.parse(data);
                if (gatewayWs && gatewayWs.readyState === WebSocket.OPEN) {
                    gatewayWs.send(JSON.stringify({
                        type: 'chat',
                        message: message.content || message
                    }));
                }
            } catch (e) {
                console.error('Error processing message:', e);
            }
        });
        
        ws.on('close', () => {
            console.log('Client disconnected');
            if (gatewayWs) {
                gatewayWs.close();
            }
        });
        
        ws.on('error', (err) => {
            console.error('Client error:', err.message);
            if (gatewayWs) {
                gatewayWs.close();
            }
        });
    });
    
    console.log(`WebSocket proxy set up for ${GATEWAY_URL}`);
}

const server = http.createServer((req, res) => {
    // CORS headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    
    if (req.method === 'OPTIONS') {
        res.writeHead(200);
        res.end();
        return;
    }
    
    const parsedUrl = url.parse(req.url, true);
    const pathname = parsedUrl.pathname;
    
    // API Routes
    if (pathname === '/api/health') {
        handleHealth(req, res);
        return;
    }
    
    if (pathname === '/api/chat' && req.method === 'POST') {
        handleChat(req, res);
        return;
    }
    
    if (pathname === '/api/upload' && req.method === 'POST') {
        handleUpload(req, res);
        return;
    }
    
    if (pathname === '/api/config') {
        if (req.method === 'POST') {
            handleConfig(req, res);
        } else {
            handleGetConfig(req, res);
        }
        return;
    }
    
    if (pathname === '/api/evidence' && req.method === 'GET') {
        handleGetEvidence(req, res);
        return;
    }
    
    if (pathname === '/api/restart' && req.method === 'POST') {
        handleRestart(req, res);
        return;
    }
    
    // Static files
    let filePath = pathname === '/' ? '/index.html' : pathname;
    
    // Security: prevent directory traversal
    const safePath = path.normalize(filePath).replace(/^(\.\.[\/\\])+/, '');
    const fullPath = path.join(UI_DIR, safePath);
    
    // Check if file exists
    if (fs.existsSync(fullPath) && fs.statSync(fullPath).isFile()) {
        serveFile(res, fullPath);
    } else {
        // Try index.html for SPA routes
        const indexPath = path.join(UI_DIR, 'index.html');
        if (fs.existsSync(indexPath)) {
            serveFile(res, indexPath);
        } else {
            res.writeHead(404, { 'Content-Type': 'text/plain' });
            res.end('Not found');
        }
    }
});

server.listen(PORT, () => {
    console.log(`╔════════════════════════════════════════╗`);
    console.log(`║     Geoff UI Server                    ║`);
    console.log(`╠════════════════════════════════════════╣`);
    console.log(`║  URL: http://localhost:${PORT}            ║`);
    console.log(`║  Gateway: ${GATEWAY_URL}      ║`);
    console.log(`╚════════════════════════════════════════╝`);
});

// Setup WebSocket proxy if ws module is available
try {
    require('ws');
    setupWebSocket(server);
} catch (err) {
    console.log('Note: Install "ws" package for WebSocket support:');
    console.log('  npm install ws');
}

// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('Shutting down...');
    server.close(() => {
        process.exit(0);
    });
});

process.on('SIGINT', () => {
    console.log('Shutting down...');
    server.close(() => {
        process.exit(0);
    });
});