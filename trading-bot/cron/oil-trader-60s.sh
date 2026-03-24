#!/bin/bash
# Oil Trader 60-Second Continuous Runner
# Runs the oil trader every 60 seconds

cd /home/claw/.openclaw/workspace/trading-bot

while true; do
    python3 bot/trader.py >> logs/trader.log 2>&1
    sleep 60
done
