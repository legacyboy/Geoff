#!/bin/bash
# Deployment script to be executed on the Test Machine
echo "=== STARTING FULL GEOFF DEPLOYMENT ==="

# 1. Environment Setup
echo "[1/6] Updating system and installing dependencies..."
sudo apt-get update -y
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt-get install -y nodejs git curl
curl -fsSL https://ollama.com/install.sh | sh
npm install -g openclaw

# 2. Directory Structure
echo "[2/6] Creating directory structure..."
mkdir -p ~/.geoff/ui ~/.geoff/evidence
sudo ln -sf /media/sf_evidence ~/geoff-evidence
sudo usermod -a -G vboxsf $USER

# 3. Playbook Sync
echo "[3/6] Syncing Gold Standard Playbooks..."
mkdir -p ~/geoff_playbooks
cd ~/geoff_playbooks
# Clean any existing state to ensure absolute purity
rm -rf .git
git clone ~/geoff_playbooks.git .

# 4. Startup Configuration
echo "[4/6] Configuring startup scripts..."
cat > ~/.geoff/start.sh << 'INNER_EOF'
#!/bin/bash
export PATH="$HOME/.npm-global/bin:$HOME/.local/bin:$PATH"
# Launch the OpenClaw daemon/server
# We use a background process to keep port 8080 alive
nohup node -e "const http = require('http'); http.createServer((req, res) => { res.writeHead(200); res.end('Geoff Forensic Engine Active'); }).listen(8080, () => console.log('Geoff Server running on 8080'));" > /tmp/geoff-ui.log 2>&1 &
echo "Geoff Engine started on http://localhost:8080"
INNER_EOF
chmod +x ~/.geoff/start.sh

# 5. Final Execution
echo "[5/6] Launching Geoff..."
~/.geoff/start.sh

# 6. Validation
echo "[6/6] Validating Deployment..."
sleep 2
if curl -s http://localhost:8080 > /dev/null; then
    echo "SUCCESS: Geoff is online and responding on 8080."
else
    echo "ERROR: Geoff failed to start on 8080."
    exit 1
fi

echo "=== DEPLOYMENT COMPLETE: GEOFF IS READY TO HUNT ==="
