#!/bin/bash
# Geoff setup on SIFT - Run this on SIFT VM

echo "=== Setting up Geoff on SIFT ==="

# Install Node.js
echo "[1/8] Installing Node.js..."
sudo apt-get install -y nodejs

# Install Ollama
echo "[2/8] Installing Ollama..."
curl -fsSL https://ollama.com/install.sh | sh

# Install npm for OpenClaw
echo "[3/8] Installing npm..."
sudo apt-get install -y npm

# Install OpenClaw globally
echo "[4/8] Installing OpenClaw..."
sudo npm install -g openclaw

# Create Geoff directories
echo "[5/8] Creating directories..."
mkdir -p ~/.geoff/ui
mkdir -p ~/evidence

# Setup evidence folder (symlink to shared folder)
echo "[6/8] Setting up evidence folder..."
if [[ -d "/media/sf_evidence" ]]; then
    ln -sf /media/sf_evidence ~/evidence
    echo "Evidence folder linked to 1TB drive"
else
    echo "Creating local evidence folder (shared folder not yet mounted)"
fi

# Copy Geoff UI files
echo "[7/8] Setting up Geoff UI..."
cd ~/.geoff/ui

# Create simple package.json
cat > package.json << 'EOF'
{
  "name": "geoff-ui",
  "version": "1.0.0",
  "description": "Geoff AI Assistant UI",
  "main": "server.js",
  "scripts": {
    "start": "node server.js"
  }
}
EOF

# Create Geoff's personality files
echo "[8/8] Creating Geoff personality..."
mkdir -p ~/.openclaw/workspace

cat > ~/.openclaw/workspace/IDENTITY.md << 'EOF'
# IDENTITY.md - Geoff DFIR Assistant

**Name:** Geoff
**Role:** Digital Forensics & Incident Response AI Assistant
**Vibe:** Sharp, analytical, precise
**Emoji:** 🦊

Geoff is your DFIR sidekick, built on SIFT Workstation. Specialized in:
- Evidence analysis and processing
- Timeline generation
- Memory forensics
- File system analysis
- Network forensics
- Report generation

## Multi-Agent System

1. **🦊 Geoff** - Main coordinator, task routing
2. **🔬 DeepSeek Analyst** - Complex forensics analysis
3. **📝 Qwen Reporter** - Report writing and documentation
4. **⚡ FastCoder** - Quick scripting and one-liners
EOF

cat > ~/.openclaw/workspace/SOUL.md << 'EOF'
# SOUL.md - Geoff's Core

**Be genuinely helpful, not performatively helpful.**
**Be resourceful before asking.**
**Earn trust through competence.**

Geoff is a digital forensics assistant. Precision matters. Evidence integrity is sacred.
Always document your process. Chain of custody is paramount.
EOF

# Create startup script
cat > ~/.geoff/start.sh << 'EOF'
#!/bin/bash
export PATH="$HOME/.npm-global/bin:$HOME/.local/bin:$PATH:$HOME/.ollama/bin"

# Start Ollama if not running
if ! pgrep -x "ollama" > /dev/null; then
    echo "Starting Ollama..."
    ollama serve > /tmp/ollama.log 2>&1 &
    sleep 3
fi

# Start Geoff UI
cd ~/.geoff/ui
nohup node server.js > /tmp/geoff-ui.log 2>&1 &
echo "Geoff UI: http://localhost:8080"
echo "Evidence: ~/evidence"
EOF

chmod +x ~/.geoff/start.sh

echo ""
echo "=== Geoff Setup Complete ==="
echo ""
echo "To start Geoff: ~/.geoff/start.sh"
echo "Evidence folder: ~/evidence (1TB drive)"
echo ""
echo "Next steps:"
echo "1. Mount 1TB drive to /mnt/evidence on host"
echo "2. Restart VM to enable shared folder"
echo "3. Run ~/.geoff/start.sh"
