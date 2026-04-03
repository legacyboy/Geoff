#!/bin/bash
# Defang Challenge Completion Loop - runs every 15 min
LOGFILE="/home/claw/.openclaw/workspace/sans-challenge/defang_loop.log"
echo "[$(date)] Starting Defang completion check..." >> $LOGFILE

cd /home/claw/.openclaw/workspace/sans-challenge

# Run the completion attempt
python3 t2_complete.py >> $LOGFILE 2>&1

# Check if actually complete
python3 check_both.py >> $LOGFILE 2>&1
if [ $? -eq 0 ]; then
    echo "[$(date)] ✓✓✓ DEFANG CONFIRMED COMPLETE!" >> $LOGFILE
    # Remove self from crontab once complete
    crontab -l 2>/dev/null | grep -v defang_loop | crontab -
    echo "[$(date)] Cron job removed - challenge complete!" >> $LOGFILE
else
    echo "[$(date)] ✗ Still pending, will retry in 15 min" >> $LOGFILE
fi
echo "---" >> $LOGFILE
