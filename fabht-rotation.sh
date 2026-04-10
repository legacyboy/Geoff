#!/bin/bash
# FabHT Rotation Script - Chrome → Firefox → PDFium
# Runs every 15 minutes, cycles through targets

FABHT="sshpass -p 'fabht' ssh -o StrictHostKeyChecking=no -p 2223 fabht@localhost"
LOG="/home/claw/.openclaw/workspace/fabht-research/rotation.log"
STATE_FILE="/home/claw/.openclaw/workspace/fabht-research/.rotation_state"

# Read current phase (default: chrome)
PHASE=$(cat $STATE_FILE 2>/dev/null || echo "chrome")
DATE=$(date '+%Y-%m-%d %H:%M')

echo "=== FabHT Rotation: $PHASE ===" | tee -a $LOG
echo "Time: $DATE" | tee -a $LOG

case $PHASE in
  chrome)
    echo "Phase 1: CHROME V8 Analysis" | tee -a $LOG
    $FABHT 'cd ~/chromium/src/v8 && echo "Checking V8 source..." && du -sh .' 2>/dev/null | tee -a $LOG
    # Trigger Chrome analysis via cron
    echo "Next: firefox" > $STATE_FILE
    ;;
  firefox)
    echo "Phase 2: FIREFOX SpiderMonkey Analysis" | tee -a $LOG
    $FABHT 'cd ~/firefox/mozilla-central/js/src && echo "Checking SpiderMonkey..." && ls -d *jit* 2>/dev/null | head -3' 2>/dev/null | tee -a $LOG
    # Trigger Firefox analysis
    echo "Next: pdfium" > $STATE_FILE
    ;;
  pdfium)
    echo "Phase 3: PDFIUM Analysis" | tee -a $LOG
    $FABHT 'cd ~/chromium/src/third_party/pdfium && echo "Checking PDFium..." && du -sh .' 2>/dev/null | tee -a $LOG
    # Back to chrome
    echo "Next: chrome" > $STATE_FILE
    ;;
esac

echo "Rotation complete. Next: $(cat $STATE_FILE)" | tee -a $LOG
echo "" | tee -a $LOG
