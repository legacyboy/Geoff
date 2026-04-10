#!/bin/bash
# Systematic File Analysis for CTF Bug Hunt
# Analyzes ALL files in Chromium, then Firefox, then PDFium

FABHT="sshpass -p 'fabht' ssh -o StrictHostKeyChecking=no -p 2223 fabht@localhost"
STATE_FILE="/home/claw/.openclaw/workspace/fabht-research/.analysis_state"
LOG="/home/claw/.openclaw/workspace/fabht-research/systematic.log"

# Initialize state if not exists
if [ ! -f "$STATE_FILE" ]; then
    echo "chromium:/home/fabht/chromium/src/v8/src/compiler" > "$STATE_FILE"
fi

read -r PHASE CURRENT_DIR < "$STATE_FILE"
DATE=$(date '+%Y-%m-%d %H:%M')

echo "=== Systematic Analysis: $PHASE ===" | tee -a "$LOG"
echo "Current: $CURRENT_DIR" | tee -a "$LOG"
echo "Time: $DATE" | tee -a "$LOG"

# Get next file to analyze
NEXT_FILE=$($FABHT "find $CURRENT_DIR -name '*.cc' -type f 2>/dev/null | head -1")

if [ -z "$NEXT_FILE" ]; then
    # Move to next phase
    case $PHASE in
        chromium)
            echo "firefox:/home/fabht/firefox/mozilla-central/js/src" > "$STATE_FILE"
            echo "Moving to Firefox analysis" | tee -a "$LOG"
            ;;
        firefox)
            echo "pdfium:/home/fabht/chromium/src/third_party/pdfium" > "$STATE_FILE"
            echo "Moving to PDFium analysis" | tee -a "$LOG"
            ;;
        pdfium)
            echo "COMPLETE" > "$STATE_FILE"
            echo "Analysis complete!" | tee -a "$LOG"
            ;;
    esac
else
    echo "Analyzing: $NEXT_FILE" | tee -a "$LOG"
    # Mark file as analyzed (rename or touch)
    $FABHT "echo 'Analyzed on $DATE' >> $NEXT_FILE.analyzed"
fi

echo "" | tee -a "$LOG"
