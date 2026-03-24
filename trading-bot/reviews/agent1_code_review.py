#!/usr/bin/env python3
"""
Agent 1: deepseek-coder:33b (Primary Coder)
Task: Review CFD trading strategy for code correctness and implementation quality
"""

import subprocess
import json

PROMPT = """Review this oil CFD trading bot code for correctness and implementation issues:

FILE: /home/claw/.openclaw/workspace/trading-bot/bot/trader.py

Review aspects:
1. Code correctness - any bugs or logic errors?
2. OANDA API usage - correct endpoints and parameters?
3. CFD handling - are we properly managing CFD positions?
4. Order execution - market orders appropriate?
5. Error handling - robust enough?
6. Logging - sufficient for debugging?

Strategy summary:
- 60-second trading intervals
- Momentum-based entries (buy on -0.5% or +0.5% moves)
- Volatility-based position sizing (30%/70%/100%)
- Fixed $20 take profit, $10 stop loss
- Paper trading mode for testing

Provide specific code fixes if needed.
"""

result = subprocess.run(
    ['ollama', 'run', 'deepseek-coder:33b', PROMPT],
    capture_output=True, text=True, timeout=120
)

print("="*60)
print("AGENT 1: deepseek-coder:33b - CODE REVIEW")
print("="*60)
print(result.stdout)
if result.stderr:
    print("ERRORS:", result.stderr)
