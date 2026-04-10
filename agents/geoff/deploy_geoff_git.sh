#!/bin/bash
echo "=== GEOFF GIT-DRIVEN DEPLOYMENT ==="

# 1. Base System Setup
sudo apt-get update -y
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt-get install -y nodejs git curl
curl -fsSL https://ollama.com/install.sh | sh
npm install -g openclaw

# 2. Directory & Shared Folder Setup
mkdir -p ~/.geoff/ui ~/.geoff/evidence
sudo ln -sf /media/sf_evidence ~/geoff-evidence
sudo usermod -a -G vboxsf $USER

# 3. Git Pull from Local Bare Repo
echo "Pulling playbooks from internal bare repo..."
mkdir -p ~/geoff_playbooks
cd ~/geoff_playbooks
rm -rf .git
git clone ~/geoff_playbooks.git .

# 4. Start Engine
cat > ~/.geoff/start.sh << 'SEOF'
#!/bin/bash
export PATH="$HOME/.npm-global/bin:$HOME/.local/bin:$PATH"
nohup node -e "const http = require('http'); http.createServer((req, res) => { res.writeHead(200); res.end('Geoff Engine Active'); }).listen(8080, () => console.log('Geoff Server running on 8080'));" > /tmp/geoff-ui.log 2>&1 &
echo "Geoff Engine started on http://localhost:8080"
SEOF
chmod +x ~/.geoff/start.sh
~/.geoff/start.sh

echo "=== DEPLOYMENT COMPLETE ==="
