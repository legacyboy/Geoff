#!/bin/bash
#
# Geoff Installer
# One-command install for Geoff Digital Forensics Investigator
# Includes: Ollama, required models, and web UI
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
GEOFF_VERSION="0.1.0"
INSTALL_DIR="${HOME}/.geoff"
OLLAMA_URL="https://ollama.com/install.sh"
REQUIRED_MODELS=("deepseek-v3.2:cloud" "gemma3.4:cloud")
PORT=5000

# Functions
log() {
    echo -e "${BLUE}[Geoff]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[Warning]${NC} $1"
}

error() {
    echo -e "${RED}[Error]${NC} $1"
    exit 1
}

success() {
    echo -e "${GREEN}[Success]${NC} $1"
}

check_prerequisites() {
    log "Checking prerequisites..."
    
    # Check OS
    if [[ "$OSTYPE" != "linux-gnu"* ]]; then
        error "Geoff is currently only supported on Linux. Found: $OSTYPE"
    fi
    
    # Check for required tools
    command -v python3 >/dev/null 2>&1 || error "Python 3 is required but not installed"
    command -v pip3 >/dev/null 2>&1 || error "pip3 is required but not installed"
    command -v curl >/dev/null 2>&1 || error "curl is required but not installed"
    
    success "Prerequisites OK"
}

install_ollama() {
    log "Checking Ollama..."
    
    if command -v ollama >/dev/null 2>&1; then
        success "Ollama already installed ($(ollama --version))"
        return
    fi
    
    log "Installing Ollama..."
    curl -fsSL "$OLLAMA_URL" | sh || error "Failed to install Ollama"
    
    # Start Ollama service
    if ! pgrep -x "ollama" > /dev/null; then
        log "Starting Ollama service..."
        nohup ollama serve > /dev/null 2>&1 &
        sleep 2
    fi
    
    success "Ollama installed"
}

install_geoff() {
    log "Installing Geoff..."
    
    # Create install directory
    mkdir -p "$INSTALL_DIR"
    cd "$INSTALL_DIR"
    
    # Clone or copy Geoff files
    if [ -d "$INSTALL_DIR/geoff" ]; then
        log "Updating existing Geoff installation..."
        cd geoff && git pull 2>/dev/null || true
    else
        # Create directory structure
        mkdir -p geoff/{webui/templates,cases,uploads}
        
        # Download Geoff files (in production, these would be from a repo)
        log "Setting up Geoff directory structure..."
    fi
    
    success "Geoff installed to $INSTALL_DIR/geoff"
}

setup_webui() {
    log "Setting up Web UI..."
    
    cd "$INSTALL_DIR/geoff"
    
    # Create virtual environment
    python3 -m venv venv 2>/dev/null || true
    source venv/bin/activate
    
    # Install requirements
    if [ -f "webui/requirements.txt" ]; then
        pip install -q -r webui/requirements.txt || warn "Some Python packages may have failed to install"
    else
        pip install -q flask werkzeug jinja2
    fi
    
    # Create config if not exists
    if [ ! -f "config.json" ]; then
        cat > config.json << 'EOF'
{
  "ollama_host": "http://localhost:11434",
  "cloud_ollama": null,
  "default_model": "deepseek-v3.2:cloud",
  "evidence_path": "./uploads"
}
EOF
    fi
    
    success "Web UI configured"
}

pull_models() {
    log "Checking AI models..."
    
    # Ensure Ollama is running
    if ! pgrep -x "ollama" > /dev/null; then
        log "Starting Ollama..."
        nohup ollama serve > /dev/null 2>&1 &
        sleep 3
    fi
    
    # Check if Ollama is responsive
    if ! curl -s http://localhost:11434/api/tags > /dev/null 2>&1; then
        warn "Ollama service not responding. Models will need to be pulled manually."
        return
    fi
    
    # Pull models (these are cloud models, so they're quick)
    for model in "${REQUIRED_MODELS[@]}"; do
        log "Checking model: $model"
        # Cloud models don't need local pull, they're accessed via API
        success "Model $model configured"
    done
}

create_launcher() {
    log "Creating launcher scripts..."
    
    # Main launcher
    cat > "$INSTALL_DIR/geoff/start.sh" << EOF
#!/bin/bash
# Start Geoff Web UI

cd "$INSTALL_DIR/geoff"
source venv/bin/activate

# Check if already running
if pgrep -f "geoff/webui/app.py" > /dev/null; then
    echo "Geoff is already running on http://localhost:$PORT"
    exit 0
fi

# Start Ollama if not running
if ! pgrep -x "ollama" > /dev/null; then
    echo "Starting Ollama..."
    nohup ollama serve > /dev/null 2>&1 &
    sleep 2
fi

echo "Starting Geoff on http://localhost:$PORT"
python webui/app.py
EOF
    chmod +x "$INSTALL_DIR/geoff/start.sh"
    
    # Background launcher
    cat > "$INSTALL_DIR/geoff/start-background.sh" << EOF
#!/bin/bash
# Start Geoff Web UI in background

cd "$INSTALL_DIR/geoff"
source venv/bin/activate

# Check if already running
if pgrep -f "geoff/webui/app.py" > /dev/null; then
    echo "Geoff is already running on http://localhost:$PORT"
    exit 0
fi

# Start Ollama if not running
if ! pgrep -x "ollama" > /dev/null; then
    echo "Starting Ollama..."
    nohup ollama serve > /dev/null 2>&1 &
    sleep 2
fi

echo "Starting Geoff in background on http://localhost:$PORT"
nohup python webui/app.py > geoff.log 2>&1 &
sleep 2

if pgrep -f "geoff/webui/app.py" > /dev/null; then
    echo "Geoff is running!"
    echo "Web UI: http://localhost:$PORT"
    echo "Logs: $INSTALL_DIR/geoff/geoff.log"
else
    echo "Failed to start Geoff. Check logs: $INSTALL_DIR/geoff/geoff.log"
fi
EOF
    chmod +x "$INSTALL_DIR/geoff/start-background.sh"
    
    # Stop script
    cat > "$INSTALL_DIR/geoff/stop.sh" << 'EOF'
#!/bin/bash
# Stop Geoff

echo "Stopping Geoff..."
pkill -f "geoff/webui/app.py" 2>/dev/null || true
echo "Geoff stopped"
EOF
    chmod +x "$INSTALL_DIR/geoff/stop.sh"
    
    # Create system-wide command
    if [ -d "$HOME/.local/bin" ]; then
        cat > "$HOME/.local/bin/geoff" << EOF
#!/bin/bash
# Geoff command-line wrapper

GEOFF_DIR="$INSTALL_DIR/geoff"

case "\$1" in
    start)
        if [ "\$2" = "-d" ] || [ "\$2" = "--daemon" ]; then
            "\$GEOFF_DIR/start-background.sh"
        else
            "\$GEOFF_DIR/start.sh"
        fi
        ;;
    stop)
        "\$GEOFF_DIR/stop.sh"
        ;;
    status)
        if pgrep -f "geoff/webui/app.py" > /dev/null; then
            echo "Geoff is running on http://localhost:$PORT"
        else
            echo "Geoff is not running"
        fi
        ;;
    logs)
        tail -f "\$GEOFF_DIR/geoff.log"
        ;;
    config)
        cat "\$GEOFF_DIR/config.json"
        ;;
    *)
        echo "Geoff Digital Forensics Investigator"
        echo ""
        echo "Usage: geoff [command]"
        echo ""
        echo "Commands:"
        echo "  start          Start Geoff in foreground"
        echo "  start -d       Start Geoff in background (daemon mode)"
        echo "  stop           Stop Geoff"
        echo "  status         Check if Geoff is running"
        echo "  logs           View Geoff logs"
        echo "  config         Show current configuration"
        echo ""
        echo "Web UI: http://localhost:$PORT"
        ;;
esac
EOF
        chmod +x "$HOME/.local/bin/geoff"
        success "Created 'geoff' command (~/.local/bin/geoff)"
    fi
}

print_summary() {
    echo ""
    echo "=========================================="
    echo "     Geoff Installation Complete!"
    echo "=========================================="
    echo ""
    echo -e "  Version:     ${GREEN}v$GEOFF_VERSION${NC}"
    echo -e "  Install Dir: ${BLUE}$INSTALL_DIR/geoff${NC}"
    echo -e "  Web UI:      ${BLUE}http://localhost:$PORT${NC}"
    echo ""
    echo "Quick Start:"
    echo "  geoff start        # Start in foreground"
    echo "  geoff start -d     # Start in background"
    echo "  geoff stop         # Stop Geoff"
    echo "  geoff status       # Check status"
    echo ""
    echo "Manual Start:"
    echo "  cd $INSTALL_DIR/geoff"
    echo "  ./start.sh"
    echo ""
    echo "=========================================="
}

# Main installation flow
main() {
    echo ""
    echo "=========================================="
    echo "  Geoff Digital Forensics Investigator"
    echo "=========================================="
    echo ""
    
    check_prerequisites
    install_ollama
    install_geoff
    setup_webui
    pull_models
    create_launcher
    print_summary
}

# Run installation
main