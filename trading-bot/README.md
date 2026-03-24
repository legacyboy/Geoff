# Trading Bot Ecosystem

An autonomous trading bot with OANDA forex integration, HTTPS monitoring dashboard, researcher subagent, and OpenClaw cron integration.

## 📁 Project Structure

```
trading-bot/
├── agents/
│   ├── researcher_agent.py      # Market research agent
│   ├── researcher.py            # Basic researcher
│   └── researcher_prompt.md     # Agent instructions
├── bot/
│   └── trader.py                # OANDA trading engine
├── web/
│   └── server.py                # HTTPS dashboard
├── systemd/
│   └── trading-bot-web.service  # Systemd service
├── config/
│   └── config.json              # Trading configuration
├── scripts/
│   └── install-service.sh       # Service installer
├── cron/                        # Scheduler scripts
├── data/
│   ├── reports/                 # Trade reports
│   └── research/                # Research reports
├── logs/
│   ├── trader.log               # Trading logs
│   └── researcher.log           # Researcher logs
├── certs/                       # SSL certificates
└── README.md
```

## 🚀 Quick Start

### 1. Install Dependencies

```bash
pip install flask requests
```

### 2. OANDA Setup

Edit `config/config.json` and add your OANDA account ID:
```json
{
  "oanda_api_key": "7df52e1cb6bb3836047627110754de3d-176b3febe32dc67248164c564e35f513",
  "oanda_account_type": "practice",
  "oanda_account_id": "YOUR-ACCOUNT-ID",
  "trading_pairs": ["EUR_USD", "GBP_USD", "USD_JPY"],
  "default_units": 100
}
```

Get your account ID from OANDA practice account dashboard.

### 3. Start Web Dashboard (Permanent)

```bash
cd /home/claw/.openclaw/workspace/trading-bot
./scripts/install-service.sh
```

Or run manually:
```bash
python3 web/server.py
```

Access at: **https://localhost:8443**

### 4. Run Trading Bot

```bash
python3 bot/trader.py
```

## 📊 Dashboard Features

### Main Dashboard (`/`)
- **Trader Status**: Running/stopped, last run, total trades
- **Researcher Activity**: Latest recommendations from researcher
- **Trade History**: Table of all executed trades
- **Live Logs**: Real-time trader log viewer
- **Configuration**: Display current settings

### Researcher Page (`/researcher`)
- **Research Reports**: View all market research
- **Recommendations**: Buy/Sell/Hold with color coding
- **Sentiment Scores**: Market sentiment analysis
- **Researcher Logs**: Live researcher activity log

## 🔬 Researcher Subagent

### Spawn for Market Analysis

```bash
# Comprehensive research on symbols
python3 agents/researcher_agent.py --symbols BTC,ETH,AAPL --type comprehensive

# Quick sentiment check
python3 agents/researcher_agent.py --symbols AAPL --type sentiment

# Technical analysis
python3 agents/researcher_agent.py --symbols EUR_USD --type technical
```

### View Researcher Activity

Researcher reports are automatically displayed on:
- Main dashboard (latest recommendation)
- Researcher page (`/researcher`) - full history

## 🕐 Cron Jobs (Automated)

### Trading Bot Cron
**Status**: Disabled by default

```bash
# Enable trading bot cron (runs hourly)
openclaw cron enable c121c0c2-9cc6-49a2-9b61-719101c101a2

# Check status
openclaw cron list
```

### Manual Setup
```bash
# Add to crontab for hourly trading
0 * * * * /home/claw/.openclaw/workspace/trading-bot/cron/trading-scheduler.sh
```

## 🔧 OANDA Trading Strategy

Current strategy: Simple position-based logic
- No position → Place buy order
- Has position → Hold

To implement custom strategies, edit `bot/trader.py`:
```python
def custom_strategy(self, instrument):
    # Add your technical analysis here
    # Return: {'action': 'buy'|'sell'|'hold', ...}
    pass
```

## 📝 Logs

- **Trading logs**: `logs/trader.log`
- **Researcher logs**: `logs/researcher.log`
- **Trade reports**: `data/reports/YYYYMMDD_HHMMSS.json`
- **Research reports**: `data/research/YYYYMMDD_HHMMSS_SYMBOLS.json`

## 🔒 Security

- HTTPS enabled with self-signed certificates
- API keys stored in config (not committed to git)
- Lock file prevents overlapping bot executions
- Practice account for testing

## 🛠️ Development

### Dev Agent Model
Current: `deepseek-coder:33b` (PrimaryCoder)

Configuration: `.devagent-model`

### Spawn Dev Agent
```python
sessions_spawn(
    model="ollama/deepseek-coder:33b",
    runtime="subagent",
    task="Your task here"
)
```

## 📈 Future Enhancements

- [ ] Live price charts
- [ ] Advanced trading strategies (TA-Lib)
- [ ] Multi-exchange support
- [ ] Telegram/Discord notifications
- [ ] Backtesting framework
- [ ] Machine learning predictions

## 🌐 Access Points

| Service | URL |
|---------|-----|
| Dashboard | https://localhost:8443 |
| Researcher | https://localhost:8443/researcher |
| Status | `openclaw status` |

## 🆘 Troubleshooting

**Web dashboard not loading?**
```bash
systemctl --user restart trading-bot-web.service
```

**Check service status:**
```bash
systemctl --user status trading-bot-web.service
```

**OANDA connection failed?**
- Verify API key in config.json
- Check account ID is set
- Ensure practice account is active

**View logs:**
```bash
tail -f /home/claw/.openclaw/workspace/trading-bot/logs/trader.log
tail -f /home/claw/.openclaw/workspace/trading-bot/logs/researcher.log
```

---
Built with OANDA API | Flask | OpenClaw
