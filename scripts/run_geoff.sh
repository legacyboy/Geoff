#!/bin/bash
# Geoff launcher with crash logging
GEOFF_LOG=/tmp/geoff_crash.log
echo "[$(date)] Starting Geoff..." >> $GEOFF_LOG
cd /home/sansforensics/Geoff
python3 src/geoff_integrated.py
EXIT_CODE=$?
echo "[$(date)] Geoff exited with code $EXIT_CODE" >> $GEOFF_LOG
if [ $EXIT_CODE -ne 0 ]; then
    echo "[$(date)] Signal: $(kill -l $EXIT_CODE 2>/dev/null || echo 'none')" >> $GEOFF_LOG
    tail -20 /tmp/geoff.log >> $GEOFF_LOG 2>/dev/null
fi
exit $EXIT_CODE
