#!/usr/bin/env bash
# Lock file to prevent multiple instances running simultaneously
LOCK_FILE="/tmp/researcher_lock"
if [ -e "$LOCK_FILE" ]; then
echo "Researcher is already running."
exit 1
fi
touch $LOCK_FILE
trap 'rm -f $LOCK_FILE' EXIT
python3 /home/claw/.openclaw/workspace/trading-bot/agents/researcher.py >> /home/claw/.openclaw/workspace/trading-bot/logs/researcher.log 2>&1