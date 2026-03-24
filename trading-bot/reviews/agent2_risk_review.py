#!/usr/bin/env python3
"""
Agent 2: qwen3-coder:latest (Cloud Coder)
Task: Review CFD trading strategy for financial/risk management correctness
"""

import subprocess

PROMPT = """Review this oil CFD trading strategy from a financial risk management perspective:

STRATEGY:
- Asset: WTI Crude Oil CFD (XTI_USD)
- Timeframe: 60-second intervals
- Entry: Buy on -0.5% dip OR +0.5% momentum, if volatility < 3%
- Position sizing: 30%/70%/100% based on volatility (2% threshold)
- Exit: $20 take profit or $10 stop loss
- Leverage: OANDA default (approx 20:1 for oil)

Review aspects:
1. Risk of Ruin: Can this strategy blow up the account?
2. Position Sizing: Is volatility-based sizing appropriate for CFDs?
3. Fixed P&L: Should $10/$20 be percentage-based instead?
4. Leverage: How dangerous is 20:1 with this strategy?
5. 60s Noise: Is 1-minute timeframe viable or just noise?
6. Drawdown: What happens during consecutive losses?
7. Market Regime: Does this work in trending vs ranging markets?

Provide risk-adjusted recommendations.
"""

result = subprocess.run(
    ['ollama', 'run', 'qwen3-coder:latest', PROMPT],
    capture_output=True, text=True, timeout=120
)

print("="*60)
print("AGENT 2: qwen3-coder:latest - RISK MANAGEMENT REVIEW")
print("="*60)
print(result.stdout)
if result.stderr:
    print("ERRORS:", result.stderr)
