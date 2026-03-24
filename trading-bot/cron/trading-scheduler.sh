#!/bin/bash
# Trading Bot Scheduler
# Run this script via cron to execute the trading bot

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
LOG_DIR="$PROJECT_DIR/logs"
LOCK_FILE="$LOG_DIR/trader.lock"

# Create logs directory if needed
mkdir -p "$LOG_DIR"

# Check if already running
if [ -f "$LOCK_FILE" ]; then
    PID=$(cat "$LOCK_FILE" 2>/dev/null)
    if ps -p "$PID" > /dev/null 2>&1; then
        echo "$(date): Another instance is already running (PID: $PID)"
        exit 1
    else
        # Stale lock file
        rm -f "$LOCK_FILE"
    fi
fi

# Create lock file
echo $$ > "$LOCK_FILE"

# Run the trading bot
echo "$(date): Starting trading bot..."
cd "$PROJECT_DIR" || exit 1
python3 bot/trader.py >> "$LOG_DIR/trader.log" 2>&1
EXIT_CODE=$?

# Remove lock file
rm -f "$LOCK_FILE"

if [ $EXIT_CODE -eq 0 ]; then
    echo "$(date): Trading bot completed successfully"
else
    echo "$(date): Trading bot failed with exit code $EXIT_CODE"
fi

exit $EXIT_CODE
