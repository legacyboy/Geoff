# Trading Bot Ecosystem

...

## Researcher Subagent

Spawn the researcher for market analysis:
```bash
# Research specific symbols
python3 agents/researcher_agent.py --symbols BTC,ETH,AAPL --type comprehensive

# Quick sentiment check
python3 agents/researcher_agent.py --symbols AAPL --type sentiment
```
