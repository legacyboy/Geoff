#!/bin/bash
# Trump Monitor Cron Job - Runs every 10 minutes
# Fast scrape + analyze without getting blocked

cd /home/claw/.openclaw/workspace/trading-bot

# Run the pipeline
python3 agents/trump_pipeline.py > logs/trump_cron.log 2>&1

# If there's a trade decision, notify
if [ -f data/trump_monitor/latest_decision.json ]; then
    action=$(python3 -c "import json; print(json.load(open('data/trump_monitor/latest_decision.json')).get('action',''))")
    if [[ "$action" == *"NOW"* ]]; then
        echo "[$(date)] TRUMP ALERT: $action" >> logs/trump_alerts.log
    fi
fi
