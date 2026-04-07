#!/bin/bash
# Setup Geoff on SIFT Workstation

echo "=== Geoff Setup on SIFT ==="

# Update system
echo "Updating system..."
sudo apt-get update -y

# Install Node.js for Geoff UI
echo "Installing Node.js..."
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt-get install -y nodejs

# Install Ollama
echo "Installing Ollama..."
curl -fsSL https://ollama.com/install.sh | sh

# Install OpenClaw
echo "Installing OpenClaw..."
npm install -g openclaw

# Create Geoff directories
mkdir -p ~/.geoff/ui
mkdir -p ~/.geoff/evidence
mkdir -p ~/evidence-storage

# Setup SSH key for evidence storage testing (NOT auto-mounted)
echo "=== Setting up SSH key for evidence storage (manual mount only) ==="
if [ ! -f "$HOME/.ssh/id_ed25519" ]; then
    echo "Generating SSH key for evidence mount (testing use only)..."
    ssh-keygen -t ed25519 -N "" -f "$HOME/.ssh/id_ed25519"
    echo ""
fi

echo "SSH key ready. Add to host's authorized_keys for testing:"
echo "  $(cat $HOME/.ssh/id_ed25519.pub)"
echo ""
echo "=== FOR TESTING: Mount 1TB evidence storage ==="
echo "  sshfs -o IdentityFile=~/.ssh/id_ed25519 claw@10.0.2.2:/mnt/evidence-storage ~/evidence-storage"
echo ""

# Copy Geoff files from workspace
echo "Copying Geoff UI..."
WORKSPACE_DIR="/home/claw/.openclaw/workspace"
if [ -d "$WORKSPACE_DIR/geoff" ]; then
    cp -r "$WORKSPACE_DIR/geoff"/* ~/.geoff/
    echo "Geoff files copied from workspace"
else
    echo "Warning: Workspace Geoff files not found at $WORKSPACE_DIR/geoff"
fi

# Create startup script
cat > ~/.geoff/start.sh << 'EOF'
#!/bin/bash
export PATH="$HOME/.npm-global/bin:$HOME/.local/bin:$PATH"

# Start OpenClaw gateway if not running
if ! pgrep -x "openclaw-gateway" > /dev/null; then
    echo "Starting OpenClaw gateway..."
    openclaw gateway start
    sleep 2
fi

# Start Geoff UI
cd ~/.geoff/ui
nohup node server.js > /tmp/geoff-ui.log 2>&1 &
echo "Geoff UI started on http://localhost:8080"
EOF
chmod +x ~/.geoff/start.sh

# Create systemd service for OpenClaw gateway
cat > /tmp/openclaw-gateway.service << 'EOF'
[Unit]
Description=OpenClaw Gateway
After=network.target

[Service]
Type=simple
User=sansforensics
ExecStart=/usr/bin/openclaw gateway start
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo cp /tmp/openclaw-gateway.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable openclaw-gateway

echo ""
echo "=== Setup Complete ==="
echo "To start Geoff: ~/.geoff/start.sh"
echo "To enable auto-start: sudo systemctl start openclaw-gateway"
echo ""
echo "=== FOR TESTING: Mount 1TB evidence storage ==="
echo "  sshfs -o IdentityFile=~/.ssh/id_ed25519 claw@10.0.2.2:/mnt/evidence-storage ~/evidence-storage"
