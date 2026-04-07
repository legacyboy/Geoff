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

# Setup evidence storage mount via SSHFS to host's 1TB drive
echo "=== Setting up evidence storage ==="
EVIDENCE_HOST="10.0.2.2"
EVIDENCE_PATH="/mnt/evidence-storage"
MOUNT_POINT="$HOME/evidence-storage"

# Install SSHFS
sudo apt-get install -y sshfs

# Create mount point
mkdir -p "$MOUNT_POINT"

# Generate SSH key if not exists
if [ ! -f "$HOME/.ssh/id_ed25519" ]; then
    echo "Generating SSH key for evidence mount..."
    ssh-keygen -t ed25519 -N "" -f "$HOME/.ssh/id_ed25519"
    echo ""
    echo "=== IMPORTANT: Add this key to host's authorized_keys ==="
    cat "$HOME/.ssh/id_ed25519.pub"
    echo "=== Run on host: echo '$(cat $HOME/.ssh/id_ed25519.pub)' >> ~/.ssh/authorized_keys ==="
    echo ""
fi

# Try to mount evidence storage
echo "Attempting to mount evidence storage..."
if sshfs -o IdentityFile="$HOME/.ssh/id_ed25519" "claw@$EVIDENCE_HOST:$EVIDENCE_PATH" "$MOUNT_POINT" 2>/dev/null; then
    echo "Evidence storage mounted at $MOUNT_POINT"
    echo "Available space: $(df -h "$MOUNT_POINT" | tail -1 | awk '{print $4}')"
else
    echo "WARNING: Could not mount evidence storage automatically."
    echo "Manual steps required:"
    echo "  1. Ensure host SSH key is in ~/.ssh/authorized_keys on host"
    echo "  2. Run: sshfs -o IdentityFile=~/.ssh/id_ed25519 claw@10.0.2.2:/mnt/evidence-storage ~/evidence-storage"
fi

# Create symlink for backward compatibility
ln -sf "$MOUNT_POINT" ~/geoff-evidence 2>/dev/null || true

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

# Mount evidence storage if not already mounted
if ! mountpoint -q ~/evidence-storage 2>/dev/null; then
    sshfs -o IdentityFile="$HOME/.ssh/id_ed25519",reconnect,ServerAliveInterval=60 claw@10.0.2.2:/mnt/evidence-storage ~/evidence-storage &
fi

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

# Create evidence mount service
cat > /tmp/geoff-evidence-mount.service << 'EOF'
[Unit]
Description=Geoff Evidence Storage Mount (SSHFS)
After=network-online.target
Wants=network-online.target

[Service]
Type=forking
User=sansforensics
ExecStartPre=/bin/mkdir -p /home/sansforensics/evidence-storage
ExecStart=/usr/bin/sshfs -o IdentityFile=/home/sansforensics/.ssh/id_ed25519,reconnect,ServerAliveInterval=60 claw@10.0.2.2:/mnt/evidence-storage /home/sansforensics/evidence-storage
ExecStop=/bin/fusermount -u /home/sansforensics/evidence-storage
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target
EOF

sudo cp /tmp/geoff-evidence-mount.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable geoff-evidence-mount

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
echo "To enable auto-start:"
echo "  sudo systemctl start openclaw-gateway"
echo "  sudo systemctl start geoff-evidence-mount"
echo "Evidence folder: ~/evidence-storage (938GB via SSHFS from host)"
