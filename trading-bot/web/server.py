#!/usr/bin/env python3
"""
Trading Bot Web Dashboard with Researcher Tracking
HTTPS server with Flask for monitoring the trading bot and researcher.
"""

import json
import os
import ssl
import subprocess
from datetime import datetime
from flask import Flask, render_template_string

app = Flask(__name__)

# Paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROJECT_DIR = BASE_DIR
CONFIG_PATH = os.path.join(PROJECT_DIR, 'config', 'config.json')
LOGS_DIR = os.path.join(PROJECT_DIR, 'logs')
REPORTS_DIR = os.path.join(PROJECT_DIR, 'data', 'reports')
RESEARCH_DIR = os.path.join(PROJECT_DIR, 'data', 'research')
CERT_DIR = os.path.join(PROJECT_DIR, 'certs')

def load_config():
    """Load trading bot configuration."""
    try:
        with open(CONFIG_PATH) as f:
            return json.load(f)
    except Exception as e:
        return {'error': str(e)}

def get_trade_history(limit=20):
    """Get recent trade reports."""
    trades = []
    try:
        if os.path.exists(REPORTS_DIR):
            files = sorted([f for f in os.listdir(REPORTS_DIR) if f.endswith('.json')], reverse=True)
            for filename in files[:limit]:
                filepath = os.path.join(REPORTS_DIR, filename)
                with open(filepath) as f:
                    trade = json.load(f)
                    trades.append(trade)
    except Exception as e:
        trades.append({'time': 'Error', 'trade': str(e)})
    return trades

def get_research_history(limit=10):
    """Get recent research reports."""
    research = []
    try:
        if os.path.exists(RESEARCH_DIR):
            files = sorted([f for f in os.listdir(RESEARCH_DIR) if f.endswith('.json')], reverse=True)
            for filename in files[:limit]:
                filepath = os.path.join(RESEARCH_DIR, filename)
                try:
                    with open(filepath) as f:
                        data = json.load(f)
                        research.append({
                            'filename': filename,
                            'data': data
                        })
                except:
                    pass
    except Exception as e:
        pass
    return research

def get_latest_recommendation():
    """Get latest research recommendation."""
    try:
        research = get_research_history(1)
        if research:
            return research[0]
        return None
    except:
        return None

def get_live_log(log_type='trader', lines=50):
    """Get last N lines from logs."""
    log_path = os.path.join(LOGS_DIR, f'{log_type}.log')
    try:
        if os.path.exists(log_path):
            result = subprocess.run(['tail', '-n', str(lines), log_path], 
                                  capture_output=True, text=True)
            return result.stdout
        return f"No {log_type} log file found"
    except Exception as e:
        return f"Error reading log: {e}"

def get_status():
    """Get current bot status."""
    log_path = os.path.join(LOGS_DIR, 'trader.log')
    status = {
        'status': 'stopped',
        'last_run': 'Never',
        'total_trades': 0
    }
    
    try:
        if os.path.exists(log_path):
            result = subprocess.run(['tail', '-n', '1', log_path], 
                                  capture_output=True, text=True)
            if result.stdout:
                status['last_run'] = result.stdout.split(' - ')[0] if ' - ' in result.stdout else 'Unknown'
                status['status'] = 'running' if 'Trade' in result.stdout else 'idle'
        
        if os.path.exists(REPORTS_DIR):
            status['total_trades'] = len([f for f in os.listdir(REPORTS_DIR) if f.endswith('.json')])
    except Exception:
        pass
    
    return status

# Navigation HTML
NAV_HTML = """
<nav style="background: #0f3460; padding: 15px; margin-bottom: 20px; border-radius: 10px;">
    <a href="/" style="color: #00d4aa; text-decoration: none; margin-right: 20px; font-weight: bold;">🏠 Dashboard</a>
    <a href="/researcher" style="color: #00d4aa; text-decoration: none; font-weight: bold;">🔬 Researcher</a>
</nav>
"""

# Main Dashboard Template
DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Trading Bot Dashboard</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #1a1a2e;
            color: #eee;
            line-height: 1.6;
        }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        h1 { color: #00d4aa; margin-bottom: 20px; border-bottom: 2px solid #00d4aa; padding-bottom: 10px; }
        h2 { color: #00d4aa; margin: 30px 0 15px; }
        
        .status-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .status-card {
            background: #16213e;
            border-radius: 10px;
            padding: 20px;
            border-left: 4px solid #00d4aa;
        }
        .status-card h3 { color: #888; font-size: 0.9em; margin-bottom: 10px; text-transform: uppercase; }
        .status-card .value { font-size: 1.5em; font-weight: bold; }
        .status-running { color: #00d4aa; }
        .status-stopped { color: #e74c3c; }
        
        .research-card {
            background: #16213e;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
            border-left: 4px solid #3498db;
        }
        .research-card h3 { color: #3498db; margin-bottom: 10px; }
        .recommendation { display: inline-block; padding: 5px 15px; border-radius: 20px; font-weight: bold; }
        .rec-buy { background: #00d4aa; color: #1a1a2e; }
        .rec-sell { background: #e74c3c; color: white; }
        .rec-hold { background: #f39c12; color: #1a1a2e; }
        
        table {
            width: 100%;
            border-collapse: collapse;
            background: #16213e;
            border-radius: 10px;
            overflow: hidden;
        }
        th, td {
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #2a2a4a;
        }
        th {
            background: #0f3460;
            color: #00d4aa;
            font-weight: 600;
        }
        tr:hover { background: #1a1a3e; }
        .decision-buy { color: #00d4aa; font-weight: bold; }
        .decision-sell { color: #e74c3c; font-weight: bold; }
        
        .log-viewer {
            background: #0a0a1a;
            border-radius: 10px;
            padding: 20px;
            font-family: 'Courier New', monospace;
            font-size: 0.85em;
            max-height: 400px;
            overflow-y: auto;
            white-space: pre-wrap;
            color: #aaa;
        }
        
        .config-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            background: #16213e;
            padding: 20px;
            border-radius: 10px;
        }
        .config-item { display: flex; justify-content: space-between; }
        .config-item strong { color: #00d4aa; }
        
        .refresh-btn {
            background: #00d4aa;
            color: #1a1a2e;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
            font-weight: bold;
            margin-bottom: 20px;
        }
        .refresh-btn:hover { background: #00b894; }
        
        footer {
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #2a2a4a;
            color: #666;
            font-size: 0.9em;
        }
        
        nav a:hover { opacity: 0.8; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🤖 Trading Bot Dashboard</h1>
        
        """ + NAV_HTML + """
        
        <button class="refresh-btn" onclick="location.reload()">🔄 Refresh</button>
        
        <div class="status-grid">
            <div class="status-card">
                <h3>Trader Status</h3>
                <div class="value {{ 'status-running' if status.status == 'running' else 'status-stopped' }}">
                    {{ status.status.upper() }}
                </div>
            </div>
            <div class="status-card">
                <h3>Last Run</h3>
                <div class="value">{{ status.last_run }}</div>
            </div>
            <div class="status-card">
                <h3>Total Trades</h3>
                <div class="value">{{ status.total_trades }}</div>
            </div>
        </div>
        
        <h2>🔬 Researcher Activity</h2>
        <div class="research-card">
            {% if latest_research %}
                <h3>Latest Research: {{ latest_research.filename }}</h3>
                <p><strong>Date:</strong> {{ latest_research.data.get('date', 'Unknown') }}</p>
                <p><strong>Recommendations:</strong> 
                    {% for rec in latest_research.data.get('recommendations', []) %}
                    <span class="recommendation rec-{{ rec.lower() }}">{{ rec }}</span>
                    {% endfor %}
                </p>
                <p><a href="/researcher" style="color: #00d4aa;">View all research →</a></p>
            {% else %}
                <h3>No Research Data</h3>
                <p>Researcher hasn't run yet. <a href="/researcher" style="color: #00d4aa;">Go to Researcher →</a></p>
            {% endif %}
        </div>
        
        <h2>📊 Trade History</h2>
        <table>
            <thead>
                <tr>
                    <th>Date/Time</th>
                    <th>Action</th>
                    <th>Details</th>
                </tr>
            </thead>
            <tbody>
                {% for trade in trades %}
                <tr>
                    <td>{{ trade.time }}</td>
                    <td class="{{ 'decision-buy' if trade.trade.action == 'buy' else 'decision-sell' }}">
                        {{ trade.trade.action.upper() if trade.trade else 'N/A' }}
                    </td>
                    <td>{{ trade.trade.instrument if trade.trade else 'N/A' }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
        
        <h2>📜 Trader Log</h2>
        <div class="log-viewer">{{ log }}</div>
        
        <h2>⚙️ Configuration</h2>
        <div class="config-grid">
            {% for key, value in config.items() %}
            <div class="config-item">
                <strong>{{ key.replace('_', ' ').title() }}:</strong>
                <span>{{ '***' if 'key' in key.lower() else value }}</span>
            </div>
            {% endfor %}
        </div>
        
        <footer>
            <p>Trading Bot + OANDA Integration | Dashboard: https://localhost:8443</p>
            <p>OANDA Practice Account | Auto-refresh: Manual</p>
        </footer>
    </div>
</body>
</html>
"""

# Researcher Page Template
RESEARCHER_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Researcher Dashboard - Trading Bot</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #1a1a2e;
            color: #eee;
            line-height: 1.6;
        }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        h1 { color: #3498db; margin-bottom: 20px; border-bottom: 2px solid #3498db; padding-bottom: 10px; }
        h2 { color: #3498db; margin: 30px 0 15px; }
        
        nav {
            background: #0f3460;
            padding: 15px;
            margin-bottom: 20px;
            border-radius: 10px;
        }
        nav a {
            color: #00d4aa;
            text-decoration: none;
            margin-right: 20px;
            font-weight: bold;
        }
        nav a:hover { opacity: 0.8; }
        
        .research-item {
            background: #16213e;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 15px;
            border-left: 4px solid #3498db;
        }
        .research-item h3 {
            color: #3498db;
            margin-bottom: 10px;
        }
        .recommendation {
            display: inline-block;
            padding: 5px 15px;
            border-radius: 20px;
            font-weight: bold;
            margin-right: 10px;
        }
        .rec-buy { background: #00d4aa; color: #1a1a2e; }
        .rec-sell { background: #e74c3c; color: white; }
        .rec-hold { background: #f39c12; color: #1a1a2e; }
        
        .log-viewer {
            background: #0a0a1a;
            border-radius: 10px;
            padding: 20px;
            font-family: 'Courier New', monospace;
            font-size: 0.85em;
            max-height: 500px;
            overflow-y: auto;
            white-space: pre-wrap;
            color: #aaa;
        }
        
        .refresh-btn {
            background: #3498db;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
            font-weight: bold;
            margin-bottom: 20px;
        }
        .refresh-btn:hover { background: #2980b9; }
        
        footer {
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #2a2a4a;
            color: #666;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔬 Researcher Dashboard</h1>
        
        <nav>
            <a href="/">🏠 Dashboard</a>
            <a href="/researcher">🔬 Researcher</a>
        </nav>
        
        <button class="refresh-btn" onclick="location.reload()">🔄 Refresh</button>
        
        <h2>Recent Research Reports</h2>
        {% if research %}
            {% for item in research %}
            <div class="research-item">
                <h3>{{ item.filename }}</h3>
                <p><strong>Date:</strong> {{ item.data.get('date', 'Unknown') }}</p>
                <p><strong>Symbols:</strong> {{ item.data.get('symbols', 'N/A') }}</p>
                <p><strong>Recommendations:</strong> 
                    {% for rec in item.data.get('recommendations', []) %}
                    <span class="recommendation rec-{{ rec.lower() }}">{{ rec }}</span>
                    {% endfor %}
                </p>
                <p><strong>Sentiment Score:</strong> {{ item.data.get('sentiment_score', 'N/A') }}</p>
                <p><strong>Confidence:</strong> {{ item.data.get('confidence', 'N/A') }}%</p>
            </div>
            {% endfor %}
        {% else %}
            <p>No research data available. Run the researcher agent to generate reports.</p>
        {% endif %}
        
        <h2>📜 Researcher Log</h2>
        <div class="log-viewer">{{ log }}</div>
        
        <footer>
            <p>Trading Bot Researcher | Market Analysis Dashboard</p>
        </footer>
    </div>
</body>
</html>
"""

@app.route('/')
def index():
    """Main dashboard page."""
    config = load_config()
    trades = get_trade_history()
    log = get_live_log('trader', 50)
    status = get_status()
    latest_research = get_latest_recommendation()
    
    return render_template_string(DASHBOARD_TEMPLATE, 
                                  config=config, 
                                  trades=trades, 
                                  log=log, 
                                  status=status,
                                  latest_research=latest_research)

@app.route('/researcher')
def researcher():
    """Researcher activity page."""
    research = get_research_history(10)
    log = get_live_log('researcher', 100)
    
    return render_template_string(RESEARCHER_TEMPLATE,
                                  research=research,
                                  log=log)

def generate_ssl_cert():
    """Generate self-signed SSL certificate."""
    if not os.path.exists(CERT_DIR):
        os.makedirs(CERT_DIR)
    
    cert_file = os.path.join(CERT_DIR, 'cert.pem')
    key_file = os.path.join(CERT_DIR, 'key.pem')
    
    if not os.path.exists(cert_file) or not os.path.exists(key_file):
        print("Generating SSL certificates...")
        subprocess.run([
            'openssl', 'req', '-x509', '-newkey', 'rsa:4096',
            '-keyout', key_file, '-out', cert_file,
            '-days', '365', '-nodes',
            '-subj', '/CN=localhost'
        ], check=True, capture_output=True)
        print(f"Certificates created in {CERT_DIR}")
    
    return cert_file, key_file

if __name__ == '__main__':
    config = load_config()
    port = config.get('web_port', 8443)
    
    # Generate SSL certificates
    cert_file, key_file = generate_ssl_cert()
    
    print(f"Starting Trading Bot Dashboard on https://0.0.0.0:{port}")
    print(f"Access at: https://localhost:{port}")
    print(f"Researcher page: https://localhost:{port}/researcher")
    
    app.run(host='0.0.0.0', port=port, ssl_context=(cert_file, key_file))
