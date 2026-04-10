#!/bin/bash
# FabHT Restart - Clean restart of bug hunting agents

echo "=== FabHT Bug Hunting Restart ==="
echo "Date: $(date)"

# Stop any existing fabht sessions
echo "[1/5] Checking fabht VM..."
sshpass -p 'fabht' ssh -o StrictHostKeyChecking=no -p 2223 fabht@localhost 'echo "VM OK"' 2>/dev/null || echo "ERROR: Cannot reach fabht VM"

# Check sources
echo "[2/5] Checking sources..."
sshpass -p 'fabht' ssh -o StrictHostKeyChecking=no -p 2223 fabht@localhost 'du -sh ~/chromium/src ~/firefox/mozilla-central 2>/dev/null | head -2'

# Setup findings directories
echo "[3/5] Setting up findings..."
sshpass -p 'fabht' ssh -o StrictHostKeyChecking=no -p 2223 fabht@localhost 'mkdir -p ~/chromium/findings/agent1 ~/chromium/findings/agent2 ~/chromium/findings/claude'

echo "[4/5] Running initial scan..."
# Run a quick security scan
sshpass -p 'fabht' ssh -o StrictHostKeyChecking=no -p 2223 fabht@localhost 'cd ~/chromium/src && grep -r "TODO.*sec\|FIXME.*sec\|TODO.*vuln\|security" v8/src/compiler/ --include="*.cc" 2>/dev/null | head -20' > /home/claw/.openclaw/workspace/fabht-research/security-todos-$(date +%Y%m%d).txt

echo "[5/5] Complete!"
echo ""
echo "=== Status ==="
echo "Chromium: $(sshpass -p 'fabht' ssh -p 2223 fabht@localhost 'du -sh ~/chromium/src' 2>/dev/null | cut -f1)"
echo "Firefox: $(sshpass -p 'fabht' ssh -p 2223 fabht@localhost 'du -sh ~/firefox/mozilla-central' 2>/dev/null | cut -f1)"
echo "Findings: $(sshpass -p 'fabht' ssh -p 2223 fabht@localhost 'ls ~/chromium/findings/agent1 2>/dev/null | wc -l') agent1, $(sshpass -p 'fabht' ssh -p 2223 fabht@localhost 'ls ~/chromium/findings/agent2 2>/dev/null | wc -l') agent2"
echo ""
echo "Next: Start Claude Code for deep analysis"
echo "  export ANTHROPIC_API_KEY=\$(cat ~/.config/claude/api_key)"
echo "  sshpass -p 'fabht' ssh -p 2223 fabht@localhost 'cd ~/chromium/src && claude --model sonnet'"
