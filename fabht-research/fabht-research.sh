#!/bin/bash
# fabht-research.sh - Automated vulnerability research on Chromium
# Runs from host, analyzes fabht VM via SSH

FABHT="sshpass -p 'fabht' ssh -o StrictHostKeyChecking=no -p 2223 fabht@localhost"
RESEARCH_DIR="/home/claw/.openclaw/workspace/fabht-research"
DATE=$(date +%Y-%m-%d)

mkdir -p $RESEARCH_DIR/findings $RESEARCH_DIR/analysis

echo "=== FABHT VULNERABILITY RESEARCH ==="
echo "Date: $DATE"
echo ""

# Search for security-sensitive patterns
echo "[1/5] Searching for use-after-free patterns..."
$FABHT 'cd ~/chromium/src && grep -r "reinterpret_cast" --include="*.cc" --include="*.h" v8/ | head -20' 2>/dev/null > $RESEARCH_DIR/analysis/uaf-candidates.txt

echo "[2/5] Searching for buffer operations..."
$FABHT 'cd ~/chromium/src && grep -r "memcpy\|memmove\|strcpy" --include="*.cc" --include="*.h" net/ sandbox/ mojo/ | head -30' 2>/dev/null > $RESEARCH_DIR/analysis/buffer-ops.txt

echo "[3/5] Security TODO/FIXME comments..."
$FABHT 'cd ~/chromium/src && grep -ri "TODO.*sec\|FIXME.*sec\|TODO.*vuln\|FIXME.*vuln\|TODO.*bug\|security" --include="*.cc" --include="*.h" v8/ mojo/ sandbox/ 2>/dev/null | head -20' > $RESEARCH_DIR/analysis/security-todos.txt

echo "[4/5] Recent git commits (potential regressions)..."
$FABHT 'cd ~/chromium/src && git log --oneline -20 2>/dev/null || echo "Git history not available"' > $RESEARCH_DIR/analysis/recent-commits.txt

echo "[5/5] Component sizes (attack surface)..."
$FABHT 'cd ~/chromium/src && du -sh v8 mojo sandbox content net gpu third_party/ffmpeg 2>/dev/null' > $RESEARCH_DIR/analysis/component-sizes.txt

echo ""
echo "Analysis complete. Results in: $RESEARCH_DIR/analysis/"
echo "Next: Review findings and create vulnerability reports in findings/"
