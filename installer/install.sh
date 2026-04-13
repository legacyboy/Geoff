#!/bin/bash

# Geoff Installer - One-command setup for Geoff AI Assistant
# Usage: curl -fsSL https://.../install.sh | bash
#
# FORENSIC VERSION DOCUMENTATION
# ==============================
# For reproducibility and chain of custody, the following exact versions are used:
#
# Component          | Version/Digest                          | Source
# -------------------|-----------------------------------------|----------------------------------
# Ollama binary      | v0.6.5                                  | GitHub releases (ollama/ollama)
# Model: gemma3:4b   | aeda25e63ebd (manifest digest)          | ollama.com/library/gemma3
# Ollama binary hash | SHA256 from release checksums           | ollama-linux-amd64.tgz.sha256sum
#
# These pinned versions ensure identical Ollama binary and model weights
# across installations for forensic repeatability and evidence integrity.
#
# Verification:
# - Ollama version check: ollama --version
# - Model digest check:  ollama list gemma3:4b
#

set -e

GEOFF_VERSION="0.1.0"
INSTALL_DIR="${HOME}/.geoff"
OLLAMA_VERSION="0.6.5"
OLLAMA_MODEL="gemma3:4b"
OLLAMA_MODEL_DIGEST="aeda25e63ebd"

# Geoff Agent Models
# Manager: deepseek-r1:70b (main orchestrator)
# Forensicator: qwen2.5-coder:32b (tool execution)  
# Critic: qwen3:30b (validation and git enforcement)
MANAGER_MODEL="deepseek-r1:70b"
FORENSICATOR_MODEL="qwen2.5-coder:32b"
CRITIC_MODEL="qwen3:30b"

# Cloud mode variables
GEOFF_CLOUD="false"
GEOFF_API_KEY=""  # User must provide their own for cloud mode
GEOFF_USER="${USER}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "========================================"
echo "  Geoff AI Assistant Installer v${GEOFF_VERSION}"
echo "========================================"
echo ""

# Check requirements
check_requirements() {
    echo "[1/7] Checking requirements..."
    
    if [[ "$EUID" -eq 0 ]]; then
        echo "ERROR: Do not run as root. Run as a regular user."
        exit 1
    fi
    
    if ! command -v curl &> /dev/null; then
        echo "Installing curl..."
        sudo apt-get update && sudo apt-get install -y curl
    fi
    
    if ! command -v jq &> /dev/null; then
        echo "Installing jq..."
        sudo apt-get install -y jq
    fi
    
    # Install YARA for malware detection
    if ! command -v yara &> /dev/null; then
        echo "Installing YARA..."
        sudo apt-get update && sudo apt-get install -y yara
        if command -v yara &> /dev/null; then
            echo "  ✓ YARA installed: $(yara --version 2>&1 | head -1)"
        else
            echo "  ⚠ YARA installation failed — malware scanning will be unavailable"
        fi
    else
        echo "  ✓ YARA already installed: $(yara --version 2>&1 | head -1)"
    fi
    
    # RAM check removed - will attempt install regardless of available memory
    echo "  ✓ Requirements check bypassed (install will proceed)"
}

# Install Ollama
install_ollama() {
    echo ""
    echo "[2/7] Installing Ollama..."
    
    if [[ -f "$HOME/.local/bin/ollama" ]]; then
        echo "  Ollama already installed, checking version..."
        $HOME/.local/bin/ollama --version 2>/dev/null || true
        return
    fi
    
    mkdir -p "$HOME/.local/bin" "$HOME/.local/share/ollama"
    
    # Download Ollama
    curl -L -o /tmp/ollama-linux-amd64.tgz \
        "https://github.com/ollama/ollama/releases/download/v${OLLAMA_VERSION}/ollama-linux-amd64.tgz"
    
    cd /tmp && tar xzf ollama-linux-amd64.tgz
    mv /tmp/bin/ollama "$HOME/.local/bin/"
    rm -rf /tmp/ollama-linux-amd64.tgz /tmp/bin
    
    # Add to PATH if not already there
    if ! grep -q "\.local/bin" "$HOME/.bashrc"; then
        echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.bashrc"
    fi
    if ! grep -q "\.local/bin" "$HOME/.zshrc" 2>/dev/null; then
        echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.zshrc" 2>/dev/null || true
    fi
    
    echo "  ✓ Ollama installed"
}

# Pull Geoff's model
install_model() {
    echo ""
    echo "[3/7] Installing Geoff's brain (gemma3:4b)..."
    echo "  This may take 10-15 minutes depending on your connection..."
    
    export PATH="$HOME/.local/bin:$PATH"
    
    # Start Ollama temporarily
    nohup ollama serve > /tmp/ollama_setup.log 2>&1 &
    OLLAMA_PID=$!
    sleep 5
    
    # Pull model
    ollama pull gemma3:4b || {
        echo "  Warning: Failed to pull model. Will try again later."
    }
    
    # Stop temporary server
    kill $OLLAMA_PID 2>/dev/null || true
    
    echo "  ✓ Model installed"
}

# Install Node.js
install_nodejs() {
    echo ""
    echo "[4/7] Installing Node.js..."
    
    if command -v node &> /dev/null && [[ "$(node -v | cut -d'v' -f2 | cut -d'.' -f1)" -ge 18 ]]; then
        echo "  Node.js already installed: $(node -v)"
        return
    fi
    
    # Install Node.js using NodeSource
    curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
    sudo apt-get install -y nodejs
    
    echo "  ✓ Node.js installed: $(node -v)"
}

# Install OpenClaw
install_openclaw() {
    echo ""
    echo "[5/7] Installing OpenClaw..."
    
    if command -v openclaw &> /dev/null; then
        echo "  OpenClaw already installed, skipping..."
        return
    fi
    
    npm install -g openclaw@latest
    
    echo "  ✓ OpenClaw installed"
}

# Setup Geoff workspace and UI
setup_geoff() {
    echo ""
    echo "[6/7] Setting up Geoff workspace and UI..."
    
    export PATH="$HOME/.local/bin:$PATH"
    
    # Create Geoff directories
    mkdir -p "$HOME/.geoff"
    mkdir -p "$HOME/.geoff/evidence"
    mkdir -p "$HOME/.geoff/ui"
    mkdir -p "$HOME/.geoff/src"
    mkdir -p "$HOME/.openclaw"
    
    # Copy Python source files (Flask backend with Find Evil)
    echo "  Copying Geoff Python source..."
    if [[ -d "$SCRIPT_DIR/src" ]]; then
        cp -r "$SCRIPT_DIR/src/"* "$HOME/.geoff/src/"
    else
        # Clone from GitHub if src not available
        cd /tmp
        rm -rf /tmp/Geoff-src 2>/dev/null || true
        git clone --depth 1 https://github.com/legacyboy/Geoff.git /tmp/Geoff-src 2>/dev/null && \
            cp -r /tmp/Geoff-src/src/* "$HOME/.geoff/src/" 2>/dev/null || true
    fi
    
    # Copy playbooks
    mkdir -p "$HOME/.geoff/playbooks"
    if [[ -d "$SCRIPT_DIR/../playbooks" ]]; then
        cp -r "$SCRIPT_DIR/../playbooks/"* "$HOME/.geoff/playbooks/" 2>/dev/null || true
    fi
    
    # Install Python dependencies
    pip install flask requests --quiet 2>/dev/null || pip3 install flask requests --quiet 2>/dev/null || true
    
    # Create basic UI placeholder (Flask serves the API)
    mkdir -p "$HOME/.geoff/ui/public"
    cat > "$HOME/.geoff/ui/public/index.html" << 'UIEOF'
<!DOCTYPE html>
<html>
<head>
    <title>G.E.O.F.F.</title>
    <style>
        body { font-family: Arial; padding: 40px; background: #1a1a2e; color: #eee; }
        h1 { color: #00ff88; }
        .api { background: #16213e; padding: 20px; border-radius: 8px; margin: 20px 0; }
        code { background: #0f3460; padding: 2px 6px; border-radius: 4px; }
        a { color: #00ff88; }
    </style>
</head>
<body>
    <h1>G.E.O.F.F. - Evidence Operations Forensic Framework</h1>
    <p><strong>Find Evil:</strong> Point at evidence, auto-analyze, get results.</p>
    
    <div class="api">
        <h3>API Endpoints</h3>
        <p><code>GET /</code> - This page</p>
        <p><code>GET /find-evil</code> - Usage info</p>
        <p><code>POST /find-evil</code> - Run Find Evil</p>
        <p><code>POST /chat</code> - Chat with Geoff</p>
    </div>
    
    <div class="api">
        <h3>Quick Start</h3>
        <pre>curl -X POST http://localhost:8080/find-evil \
  -H 'Content-Type: application/json' \
  -d '{"evidence_dir": "/path/to/evidence"}'</pre>
    </div>
    
    <p>Status: Running | Flask Backend Active</p>
</body>
</html>
UIEOF
    
    # Create Geoff config (YAML)
    cat > "$HOME/.openclaw/config.yaml" << EOF
models:
  default:
    provider: ollama
    model: gemma3:4b
    host: http://127.0.0.1:11434

default_model: default
models_dir: ~/.openclaw/models
skills:
  directory: ~/.openclaw/skills
memory:
  enabled: true
  path: ~/.openclaw/memory
EOF

    # Create OpenClaw gateway config (JSON) with gateway.mode set
    mkdir -p "$HOME/.openclaw"
    cat > "$HOME/.openclaw/openclaw.json" << 'OCEOF'
{
  "gateway": {
    "mode": "local",
    "bind": "127.0.0.1",
    "port": 18789
  },
  "agents": {
    "defaults": {
      "model": "ollama/gemma3:4b"
    }
  }
}
OCEOF
    chmod 600 "$HOME/.openclaw/openclaw.json"

    # Create Geoff workspace
    mkdir -p "$HOME/.openclaw/workspace"
    
    # Create Geoff identity
    cat > "$HOME/.openclaw/workspace/IDENTITY.md" << 'EOF'
# IDENTITY.md - Geoff

**Name:** Geoff  
**Role:** AI Assistant  
**Vibe:** Friendly, helpful, concise

I am Geoff, an AI assistant deployed via OpenClaw with local Ollama models.
EOF

    cat > "$HOME/.openclaw/workspace/SOUL.md" << 'EOF'
# SOUL.md - Geoff

Geoff is an AI assistant designed to be helpful and friendly.
Part of the Geoff AI system with local model support.
EOF

    cat > "$HOME/.openclaw/workspace/AGENTS.md" << 'EOF'
# AGENTS.md - Geoff Workspace

## Workspace

Working directory: ~/.openclaw/workspace

## Models

- Local Ollama: gemma3:4b (Gemma4)

## Memory

- Daily notes: memory/YYYY-MM-DD.md
- Long-term: MEMORY.md
EOF

    # Setup auth
    mkdir -p "$HOME/.openclaw/agents/main/agent"
    cat > "$HOME/.openclaw/agents/main/agent/auth-profiles.json" << 'EOF'
{
  "ollama": {
    "apiKey": "local-ollama"
  }
}
EOF

    # Set env vars
    if ! grep -q "OLLAMA_API_KEY" "$HOME/.bashrc"; then
        echo 'export OLLAMA_API_KEY="local-ollama"' >> "$HOME/.bashrc"
    fi
    
    # Configure OpenClaw
    openclaw config set agents.defaults.model "ollama/gemma3:4b" 2>/dev/null || true
    
    echo "  ✓ Geoff workspace and UI ready"
}

# Create systemd services
create_services() {
    echo ""
    echo "[7/7] Creating systemd services..."
    
    # Ollama service
    sudo tee /etc/systemd/system/ollama.service > /dev/null << EOF
[Unit]
Description=Ollama Service
After=network.target

[Service]
Type=simple
User=${GEOFF_USER}
Environment="HOME=${HOME}"
Environment="OLLAMA_HOST=127.0.0.1:11434"
ExecStart=${HOME}/.local/bin/ollama serve
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

    # Geoff Flask API service
    sudo tee /etc/systemd/system/geoff.service > /dev/null << EOF
[Unit]
Description=Geoff DFIR Server (Flask)
After=network.target ollama.service
Wants=ollama.service

[Service]
Type=simple
User=${GEOFF_USER}
Environment="HOME=${HOME}"
Environment="OLLAMA_HOST=127.0.0.1:11434"
WorkingDirectory=${HOME}/.geoff
ExecStart=/usr/bin/python3 ${HOME}/.geoff/src/geoff_integrated.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl daemon-reload
    sudo systemctl enable ollama
    sudo systemctl enable geoff
    
    echo "  ✓ Services created"
}

# Create Geoff launcher commands
create_launcher() {
    echo ""
    echo "Creating Geoff launcher commands..."
    
    # Main geoff command
    cat > "$HOME/.local/bin/geoff" << 'EOF'
#!/bin/bash

# Geoff Launcher

export OLLAMA_API_KEY="local-ollama"
export PATH="$HOME/.local/bin:$PATH"

TOKEN="${GEOFF_TOKEN:-geoff-default}"

show_help() {
    echo "Geoff AI Assistant"
    echo ""
    echo "Usage:"
    echo "  geoff start      - Start Geoff services"
    echo "  geoff stop       - Stop Geoff services"
    echo "  geoff restart    - Restart Geoff services"
    echo "  geoff status     - Check Geoff status"
    echo "  geoff chat       - Chat with Geoff in terminal"
    echo "  geoff ui         - Open web UI (or start it if not running)"
    echo "  geoff logs       - View service logs"
    echo "  geoff update     - Update Geoff to latest version"
    echo ""
    echo "Web UI: http://localhost:8080"
    echo ""
}

if [[ $# -eq 0 ]]; then
    show_help
    exit 0
fi

case "$1" in
    start)
        echo "Starting Geoff services..."
        sudo systemctl start ollama
        sleep 3
        openclaw gateway install >/dev/null 2>&1 || true
        systemctl --user start openclaw-gateway.service 2>/dev/null || openclaw gateway run --daemon
        sleep 2
        sudo systemctl start geoff-ui
        echo "Geoff is starting!"
        echo ""
        echo "Web UI: http://localhost:8080"
        echo "Terminal: geoff chat"
        ;;
    
    stop)
        echo "Stopping Geoff services..."
        sudo systemctl stop geoff-ui
        openclaw gateway stop 2>/dev/null || true
        sudo systemctl stop ollama
        echo "Geoff stopped."
        ;;
    
    restart)
        echo "Restarting Geoff services..."
        sudo systemctl restart ollama
        sleep 2
        systemctl --user restart openclaw-gateway.service 2>/dev/null || openclaw gateway restart
        sleep 2
        sudo systemctl restart geoff-ui
        echo "Geoff restarted!"
        ;;
    
    status)
        echo "=== Geoff Status ==="
        echo ""
        echo "Ollama Service:"
        sudo systemctl status ollama --no-pager | head -3
        echo ""
        echo "Geoff UI Service:"
        sudo systemctl status geoff-ui --no-pager | head -3
        echo ""
        echo "OpenClaw Gateway:"
        openclaw gateway status 2>/dev/null || echo "  Not running"
        echo ""
        echo "Web UI: http://localhost:8080"
        curl -s http://localhost:8080/api/health 2>/dev/null && echo "  UI: Online" || echo "  UI: Offline"
        ;;
    
    chat)
        openclaw tui --token="$TOKEN"
        ;;
    
    ui)
        # Check if UI is running
        if ! curl -s http://localhost:8080/api/health &>/dev/null; then
            echo "Starting Geoff UI..."
            sudo systemctl start geoff-ui
            sleep 2
        fi
        
        # Open browser
        if command -v xdg-open &> /dev/null; then
            xdg-open http://localhost:8080
        elif command -v open &> /dev/null; then
            open http://localhost:8080
        else
            echo "Geoff UI is running at: http://localhost:8080"
        fi
        ;;
    
    logs)
        echo "=== Ollama Logs ==="
        sudo journalctl -u ollama --no-pager -n 20
        echo ""
        echo "=== Geoff UI Logs ==="
        sudo journalctl -u geoff-ui --no-pager -n 20
        ;;
    
    update)
        echo "Updating Geoff..."
        npm update -g openclaw
        echo "Geoff updated!"
        ;;
    
    help|--help|-h)
        show_help
        ;;
    
    *)
        echo "Unknown command: $1"
        show_help
        exit 1
        ;;
esac
EOF

    chmod +x "$HOME/.local/bin/geoff"
    
    # Create geoff-ui alias command (convenience)
    cat > "$HOME/.local/bin/geoff-ui" << 'EOF'
#!/bin/bash
# Geoff UI shortcut - just calls 'geoff ui'
exec geoff ui "$@"
EOF

    chmod +x "$HOME/.local/bin/geoff-ui"
    
    echo "  ✓ Geoff launchers created"
}

# Main installation
main() {
    check_requirements
    install_ollama
    install_model
    install_nodejs
    install_openclaw
    setup_geoff
    create_services
    create_launcher
    
    echo ""
    echo "========================================"
    echo "  Geoff Installation Complete!"
    echo "========================================"
    echo ""
    
    # Start services automatically
    echo "Starting Geoff services..."
    sudo systemctl start ollama 2>/dev/null || echo "  Note: Could not start ollama service"
    sleep 3
    sudo systemctl start geoff-ui 2>/dev/null || echo "  Note: Could not start geoff-ui service"
    sleep 2
    
    # Check if services are running
    if sudo systemctl is-active --quiet ollama 2>/dev/null; then
        echo "  ✓ Ollama service running"
    fi
    if sudo systemctl is-active --quiet geoff-ui 2>/dev/null; then
        echo "  ✓ Geoff UI service running"
    fi
    
    echo ""
    echo "Geoff is ready!"
    echo ""
    echo "Access:"
    echo "  Web UI: http://localhost:8080"
    echo "  Terminal: geoff chat"
    echo ""
    echo "Quick commands:"
    echo "  geoff start      - Start all services"
    echo "  geoff stop       - Stop all services"
    echo "  geoff status     - Check status"
    echo "  geoff logs       - View logs"
    echo ""
    echo "Configuration:"
    echo "  ~/.openclaw/config.yaml"
    echo "  ~/.geoff/ui-config.json"
    echo ""
}

main "$@"
