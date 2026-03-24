# Trading Bot Framework

An autonomous trading bot with HTTPS monitoring dashboard and OpenClaw cron integration.

## 📁 Project Structure

```
trading-bot/
├── bot/
│   └── trader.py              # Core trading engine
├── web/
│   └── server.py              # HTTPS dashboard
├── config/
│   └── config.json            # Trading configuration
├── cron/
│   └── trading-scheduler.sh   # Cron job script
├── data/
│   └── reports/               # Trade reports (JSON)
├── logs/
│   └── trader.log             # Trading logs
├── certs/                     # SSL certificates (auto-generated)
└── README.md                  # This file
```

## 🚀 Quick Start

### 1. Install Dependencies

```bash
pip install flask
```

### 2. Run Trading Bot (Manual)

```bash
cd /home/claw/.openclaw/workspace/trading-bot
python3 bot/trader.py
```

### 3. Start Web Dashboard

```bash
python3 web/server.py
```

Access the dashboard at: **https://localhost:8443**

> Note: You'll get a browser warning about the self-signed certificate. Click "Advanced" → "Proceed" to continue.

## 📊 Dashboard Features

- **Status Overview**: Running/stopped status, last run time, total trades
- **Trade History**: Table of all executed trades with buy/sell decisions
- **Live Log**: Real-time log viewer
- **Configuration**: Display current trading parameters

## ⚙️ Configuration

Edit `config/config.json`:

```json
{
  "trading_interval_minutes": 60,
  "risk_level": "medium",
  "web_port": 8443,
  "data_retention_days": 30
}
```

## 🕐 Cron Job (Automated Trading)

A cron job has been created but is **DISABLED** by default.

**Job ID:** `c121c0c2-9cc6-49a2-9b61-719101c101a2`

### Enable the cron job:
```bash
openclaw cron enable c121c0c2-9cc6-49a2-9b61-719101c101a2
```

### Check cron status:
```bash
openclaw cron list
```

### Manual cron setup (alternative):
Add to crontab:
```bash
0 * * * * /home/claw/.openclaw/workspace/trading-bot/cron/trading-scheduler.sh
```

## 🔧 Trading Strategy

Currently uses a simple random strategy for demonstration. To implement real trading:

1. Edit `bot/trader.py`
2. Replace `random_strategy()` with your actual trading logic
3. Add API connections to trading platforms (Binance, Coinbase, etc.)

## 📝 Logs

- **Trading logs**: `logs/trader.log`
- **Trade reports**: `data/reports/YYYYMMDD_HHMMSS.json`

## 🔒 Security

- HTTPS enabled with self-signed certificates
- Certificates auto-generated on first run
- Lock file prevents overlapping bot executions

## 🛠️ Development

Built with:
- Python 3
- Flask (web dashboard)
- OpenSSL (HTTPS)
- OpenClaw (automation & scheduling)

## 📈 Future Enhancements

- [ ] Real trading API integration
- [ ] Advanced trading strategies
- [ ] Performance analytics
- [ ] Email/Telegram notifications
- [ ] Multi-exchange support
