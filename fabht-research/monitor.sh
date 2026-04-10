#!/bin/bash
# FabHT Monitor - Check and restart bug hunting agents

FABHT="sshpass -p 'fabht' ssh -o StrictHostKeyChecking=no -p 2223 fabht@localhost"
LOG_FILE="/home/claw/.openclaw/workspace/fabht-research/monitor.log"

echo "=== FabHT Monitor ===" | tee -a $LOG_FILE
echo "Date: $(date)" | tee -a $LOG_FILE

# Check if fabht VM is reachable
echo "Checking fabht VM..." | tee -a $LOG_FILE
$FABHT 'echo "fabht VM OK"' 2>/dev/null || echo "ERROR: Cannot reach fabht VM" | tee -a $LOG_FILE

# Check Chromium source
echo "Checking Chromium source..." | tee -a $LOG_FILE
$FABHT 'du -sh ~/chromium/src' 2>/dev/null | tee -a $LOG_FILE

# Check Firefox source  
echo "Checking Firefox source..." | tee -a $LOG_FILE
$FABHT 'du -sh ~/firefox/mozilla-central' 2>/dev/null | tee -a $LOG_FILE

# Check findings directory
echo "Checking findings..." | tee -a $LOG_FILE
$FABHT 'ls -la ~/chromium/findings/ && find ~/chromium/findings -type f -mtime -1' 2>/dev/null | tee -a $LOG_FILE

# Check if agents are configured
if ! crontab -l | grep -q "fabht-aggressive-hunt"; then
    echo "WARNING: fabht cron jobs not found!" | tee -a $LOG_FILE
fi

echo "Monitor complete." | tee -a $LOG_FILE
echo "" | tee -a $LOG_FILE
