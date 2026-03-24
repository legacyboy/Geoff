#!/usr/bin/env python3
"""
Trading Bot Web Dashboard
HTTPS server with Flask for monitoring oil trading and research.
"""

import json
import os
import ssl
import subprocess
from datetime import datetime
from flask import Flask, render_template_string

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROJECT_DIR = BASE_DIR
CONFIG_PATH = os.path.join(PROJECT_DIR, 'config', 'config.json')
LOGS_DIR = os.path.join(PROJECT_DIR, 'logs')
REPORTS_DIR = os.path.join(PROJECT_DIR, 'data', 'reports')
RESEARCH_DIR = os.path.join(PROJECT_DIR, 'data', 'research')
OIL_TRACKER_DIR = os.path.join(PROJECT_DIR, 'data', 'oil_tracker')
CERT_DIR = os.path.join(PROJECT_DIR, 'certs')

def load_config():
    try:
        with open(CONFIG_PATH) as f:
            return json.load(f)
    except Exception as e:
        return {'error': str(e)}

def get_oil_reports():
    """Get oil volatility research reports."""
    reports = {'XTI_USD': [], 'XBR_USD': []}
    try:
        if os.path.exists(RESEARCH_DIR):
            files = sorted([f for f in os.listdir(RESEARCH_DIR) if f.endswith('.json')], reverse=True)
            for filename in files[:20]:
                filepath = os.path.join(RESEARCH_DIR, filename)
                try:
                    with open(filepath) as f:
                        data = json.load(f)
                        if data and 'asset' in data:
                            asset = data['asset']
                            if asset in reports:
                                reports[asset].append({'filename': filename, 'data': data})
                except:
                    pass
    except Exception as e:
        pass
    return reports

def get_live_log(log_type='trader', lines=50):
    log_path = os.path.join(LOGS_DIR, f'{log_type}.log')
    try:
        if os.path.exists(log_path):
            result = subprocess.run(['tail', '-n', str(lines), log_path], 
                                  capture_output=True, text=True)
            return result.stdout
        return f"No {log_type} log file found"
    except Exception as e:
        return f"Error reading log: {e}"

def get_oil_prices():
    """Get tracked oil prices."""
    prices = {}
    try:
        if os.path.exists(OIL_TRACKER_DIR):
            files = sorted([f for f in os.listdir(OIL_TRACKER_DIR) if f.startswith('oil_')], reverse=True)
            for filename in files[:10]:
                filepath = os.path.join(OIL_TRACKER_DIR, filename)
                try:
                    with open(filepath) as f:
                        data = json.load(f)
                        if data.get('asset') not in prices:
                            prices[data['asset']] = data
                except:
                    pass
    except:
        pass
    return prices

NAV_HTML = """
<nav style="background: #0f3460; padding: 15px; margin-bottom: 20px; border-radius: 10px;">
    <a href="/" style="color: #00d4aa; text-decoration: none; margin-right: 20px; font-weight: bold;">🏠 Dashboard</a>
    <a href="/oil-research" style="color: #00d4aa; text-decoration: none; margin-right: 20px; font-weight: bold;">🛢️ Oil Research</a>
    <a href="/tracker" style="color: #00d4aa; text-decoration: none; font-weight: bold;">📊 Oil Tracker</a>
</nav>
"""

# Main Dashboard Template
DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Oil Trading Dashboard</title>
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
        h3 { color: #3498db; margin: 20px 0 10px; }
        
        .oil-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .oil-card {
            background: #16213e;
            border-radius: 10px;
            padding: 20px;
            border-left: 4px solid;
        }
        .oil-card.wti { border-left-color: #e67e22; }
        .oil-card.brent { border-left-color: #3498db; }
        .oil-card h3 {
            color: #00d4aa;
            margin-bottom: 15px;
            font-size: 1.3em;
        }
        
        .metric-row {
            display: flex;
            justify-content: space-between;
            padding: 8px 0;
            border-bottom: 1px solid #2a2a4a;
        }
        .metric-row:last-child { border-bottom: none; }
        .metric-label { color: #888; }
        .metric-value { font-weight: bold; }
        
        .score-display {
            font-size: 2.5em;
            font-weight: bold;
            text-align: center;
            margin: 15px 0;
        }
        .score-high { color: #e74c3c; }
        .score-medium { color: #f39c12; }
        .score-low { color: #00d4aa; }
        
        .recommendation-badge {
            display: inline-block;
            padding: 8px 20px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 1.1em;
            text-align: center;
            margin: 10px 0;
        }
        .rec-reduce { background: #e67e22; color: white; }
        .rec-moderate { background: #f39c12; color: #1a1a2e; }
        .rec-trade { background: #00d4aa; color: #1a1a2e; }
        .rec-hold { background: #95a5a6; color: #1a1a2e; }
        
        .factor-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 10px;
            margin-top: 15px;
        }
        .factor-box {
            background: #1a1a3e;
            border-radius: 8px;
            padding: 10px;
            text-align: center;
        }
        .factor-box h4 {
            color: #3498db;
            font-size: 0.9em;
            margin-bottom: 5px;
        }
        .factor-score {
            font-size: 1.3em;
            font-weight: bold;
        }
        
        .status-indicator {
            display: inline-block;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            margin-right: 8px;
        }
        .status-online { background: #00d4aa; }
        .status-offline { background: #e74c3c; }
        
        .log-viewer {
            background: #0a0a1a;
            border-radius: 10px;
            padding: 20px;
            font-family: 'Courier New', monospace;
            font-size: 0.85em;
            max-height: 300px;
            overflow-y: auto;
            white-space: pre-wrap;
            color: #aaa;
        }
        
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
        
        .spread-indicator {
            background: #0f3460;
            border-radius: 10px;
            padding: 15px;
            margin: 20px 0;
            text-align: center;
        }
        .spread-value {
            font-size: 2em;
            color: #9b59b6;
            font-weight: bold;
        }
        
        nav a:hover { opacity: 0.8; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛢️ Oil Trading Dashboard</h1>
        
        """ + NAV_HTML + """
        
        <button class="refresh-btn" onclick="location.reload()">🔄 Refresh</button>
        
        <div class="spread-indicator">
            <h3>🔄 Brent-WTI Spread</h3>
            <div class="spread-value">~$3.50/barrel</div>
            <p>Brent typically trades at premium to WTI due to quality and location</p>
        </div>
        
        <h2>📊 Current Oil Analysis</h2>
        
        <div class="oil-grid">
            {% for asset, reports in oil_reports.items() %}
            {% if reports %}
            {% set report = reports[0].data %}
            <div class="oil-card {{ 'wti' if asset == 'XTI_USD' else 'brent' }}">
                <h3>{{ '🟠' if asset == 'XTI_USD' else '🔵' }} {{ report.asset_name }}</h3>
                <p style="color: #888; margin-bottom: 15px;">{{ report.origin }}</p>
                
                {% set score = report.volatility_score %}
                {% set level = report.volatility_level %}
                <div class="score-display score-{{ level }}">
                    {{ score }}/100
                </div>
                <p style="text-align: center; text-transform: uppercase; letter-spacing: 1px;">
                    {{ level }} Volatility
                </p>
                
                <div style="text-align: center; margin: 15px 0;">
                    <span class="recommendation-badge rec-{{ report.recommendation.lower() }}">
                        {{ report.recommendation }}
                    </span>
                </div>
                
                <div class="metric-row">
                    <span class="metric-label">Position Size:</span>
                    <span class="metric-value">{{ (report.position_size * 100)|int }}%</span>
                </div>
                <div class="metric-row">
                    <span class="metric-label">Confidence:</span>
                    <span class="metric-value">{{ report.confidence }}%</span>
                </div>
                
                <div class="factor-grid">
                    {% set factors = report.factors %}
                    <div class="factor-box">
                        <h4>🌍 Geo</h4>
                        <div class="factor-score {{ 'score-high' if factors.geopolitical.risk_level == 'high' else 'score-medium' if factors.geopolitical.risk_level == 'medium' else 'score-low' }}">
                            {{ factors.geopolitical.total_risk_score }}
                        </div>
                    </div>
                    
                    <div class="factor-box">
                        <h4>📦 Supply</h4>
                        <div class="factor-score">{{ factors.supply.total_impact }}</div>
                    </div>
                    
                    <div class="factor-box">
                        <h4>📈 Demand</h4>
                        <div class="factor-score">{{ factors.demand.total_impact }}</div>
                    </div>
                </div>
                
                <p style="margin-top: 15px; padding: 10px; background: #0a0a1a; border-radius: 5px; font-size: 0.9em;">
                    💡 {{ report.reasoning }}
                </p>
            </div>
            {% endif %}
            {% endfor %}
        </div>
        
        <h2>📜 Trading Log</h2>
        <div class="log-viewer">{{ log }}</div>
        
        <footer>
            <p>Brent & WTI Oil Trading Bot | OANDA Practice Account</p>
            <p>Trading every 60 seconds | Paper Trading Mode</p>
        </footer>
    </div>
</body>
</html>
"""

@app.route('/')
def index():
    """Main dashboard."""
    oil_reports = get_oil_reports()
    log = get_live_log('trader', 50)
    
    return render_template_string(DASHBOARD_TEMPLATE, 
                                  oil_reports=oil_reports,
                                  log=log)

@app.route('/oil-research')
def oil_research():
    """Detailed oil research page."""
    oil_reports = get_oil_reports()
    log = get_live_log('researcher', 100)
    
    template = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Oil Volatility Research</title>
        <style>
            body { 
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                background: #1a1a2e;
                color: #eee;
                line-height: 1.6;
                padding: 20px;
            }
            .container { max-width: 1200px; margin: 0 auto; }
            h1 { color: #00d4aa; border-bottom: 2px solid #00d4aa; padding-bottom: 10px; }
            h2 { color: #3498db; margin-top: 30px; }
            .report-card {
                background: #16213e;
                border-radius: 10px;
                padding: 20px;
                margin: 20px 0;
                border-left: 4px solid #3498db;
            }
            .score-breakdown {
                background: #0f3460;
                padding: 15px;
                border-radius: 8px;
                margin: 15px 0;
            }
            .factor-detail {
                background: #1a1a3e;
                padding: 10px;
                margin: 10px 0;
                border-radius: 5px;
            }
            .risk-high { color: #e74c3c; }
            .risk-medium { color: #f39c12; }
            .risk-low { color: #00d4aa; }
            .grid-3 {
                display: grid;
                grid-template-columns: repeat(3, 1fr);
                gap: 15px;
            }
            nav { background: #0f3460; padding: 15px; margin-bottom: 20px; border-radius: 10px; }
            nav a { color: #00d4aa; text-decoration: none; margin-right: 20px; font-weight: bold; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔬 Detailed Oil Volatility Research</h1>
            
            <nav>
                <a href="/">🏠 Dashboard</a>
                <a href="/oil-research">🔬 Research</a>
                <a href="/tracker">📊 Tracker</a>
            </nav>
            
            {% for asset, reports in oil_reports.items() %}
            {% if reports %}
            {% set r = reports[0].data %}
            <div class="report-card">
                <h2>{{ r.asset_name }} ({{ asset }})</h2>
                <p>📍 Origin: {{ r.origin }} | ⏰ {{ r.timestamp }}</p>
                
                <div class="score-breakdown">
                    <h3>📊 Volatility Score: {{ r.volatility_score }}/100 ({{ r.volatility_level.upper() }})</h3>                    
                    <p>{{ r.score_explanation.interpretation }}</p>
                    
                    <div class="grid-3">
                        {% for key, value in r.score_explanation.breakdown.items() %}
                        {% if key != 'Explanation' %}
                        <div class="factor-detail">
                            <strong>{{ key }}</strong>: {{ value }}
                        </div>
                        {% endif %}
                        {% endfor %}
                    </div>
                    
                    <p style="margin-top: 10px; font-style: italic;">{{ r.score_explanation.breakdown.Explanation }}</p>
                </div>
                
                <h3>🔍 Factor Analysis</h3>
                
                <div class="factor-detail">
                    <h4>🌍 Geopolitical ({{ r.factors.geopolitical.risk_level }})</h4>
                    <p>Total Risk Score: {{ r.factors.geopolitical.total_risk_score }}</p>
                    <ul>
                    {% for risk in r.factors.geopolitical.risks[:5] %}
                    <li>{{ risk.name }}: {{ risk.impact }}/20 pts - {{ risk.explanation }}</li>
                    {% endfor %}
                    </ul>
                </div>
                
                <div class="factor-detail">
                    <h4>📦 Supply Factors</h4>
                    <div class="grid-3">
                    {% for name, data in r.factors.supply.factors.items() %}
                    <div>
                        <strong>{{ name }}</strong>: {{ data.status }} ({{ data.impact }} pts)
                    </div>
                    {% endfor %}
                    </div>
                </div>
                
                <div class="factor-detail">
                    <h4>📈 Demand Factors</h4>
                    <div class="grid-3">
                    {% for name, data in r.factors.demand.factors.items() %}
                    <div>
                        <strong>{{ name }}</strong>: {{ data.trend }} ({{ data.impact }} pts)
                    </div>
                    {% endfor %}
                    </div>
                </div>
                
                <p style="margin-top: 15px; padding: 10px; background: #0a0a1a;">
                    <strong>🎯 Recommendation:</strong> {{ r.recommendation }} 
                    ({{ (r.position_size * 100)|int }}% position, {{ r.confidence }}% confidence)<br>
                    <em>{{ r.reasoning }}</em>
                </p>
            </div>
            {% endif %}
            {% endfor %}
            
            <h2>📜 Researcher Log</h2>
            <pre style="background: #0a0a1a; padding: 15px; border-radius: 10px; overflow-x: auto;">{{ log }}</pre>
        </div>
    </body>
    </html>
    """
    
    return render_template_string(template, oil_reports=oil_reports, log=log)

@app.route('/tracker')
def tracker():
    """Oil price tracker page."""
    prices = get_oil_prices()
    
    template = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Oil Price Tracker</title>
        <style>
            body { 
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                background: #1a1a2e;
                color: #eee;
                line-height: 1.6;
                padding: 20px;
            }
            .container { max-width: 1200px; margin: 0 auto; }
            h1 { color: #00d4aa; border-bottom: 2px solid #00d4aa; padding-bottom: 10px; }
            .price-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                gap: 20px;
                margin: 20px 0;
            }
            .price-card {
                background: #16213e;
                border-radius: 10px;
                padding: 20px;
                text-align: center;
            }
            .price-card.wti { border-top: 4px solid #e67e22; }
            .price-card.brent { border-top: 4px solid #3498db; }
            .price-value {
                font-size: 2.5em;
                font-weight: bold;
                color: #00d4aa;
            }
            .price-change {
                font-size: 1.2em;
                margin-top: 10px;
            }
            .positive { color: #00d4aa; }
            .negative { color: #e74c3c; }
            nav { background: #0f3460; padding: 15px; margin-bottom: 20px; border-radius: 10px; }
            nav a { color: #00d4aa; text-decoration: none; margin-right: 20px; font-weight: bold; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>📊 Oil Price Tracker</h1>
            
            <nav>
                <a href="/">🏠 Dashboard</a>
                <a href="/oil-research">🔬 Research</a>
                <a href="/tracker">📊 Tracker</a>
            </nav>
            
            <div class="price-grid">
                {% for asset, data in prices.items() %}
                <div class="price-card {{ 'wti' if asset == 'XTI_USD' else 'brent' }}">
                    <h2>{{ '🟠 WTI' if asset == 'XTI_USD' else '🔵 Brent' }}</h2>
                    <div class="price-value">${{ "%.2f"|format(data.price) }}</div>
                    <div class="price-change {{ 'positive' if data.volatility > 0 else 'negative' }}">
                        Volatility: {{ "%.2f"|format(data.volatility) }}%
                    </div>                    
                    <p style="color: #888; margin-top: 10px;">Last updated: {{ data.timestamp }}</p>
                </div>
                {% endfor %}
            </div>            
            <p style="text-align: center; color: #888; margin-top: 40px;">Prices update every 60 seconds during trading</p>
        </div>
    </body>
    </html>
    """
    
    return render_template_string(template, prices=prices)

def generate_ssl_cert():
    if not os.path.exists(CERT_DIR):
        os.makedirs(CERT_DIR)
    cert_file = os.path.join(CERT_DIR, 'cert.pem')
    key_file = os.path.join(CERT_DIR, 'key.pem')
    if not os.path.exists(cert_file) or not os.path.exists(key_file):
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:4096',
            '-keyout', key_file, '-out', cert_file, '-days', '365', '-nodes',
            '-subj', '/CN=localhost'], check=True, capture_output=True)
    return cert_file, key_file

if __name__ == '__main__':
    config = load_config()
    port = config.get('web_port', 8443)
    cert_file, key_file = generate_ssl_cert()
    print(f"Starting on https://0.0.0.0:{port}")
    app.run(host='0.0.0.0', port=port, ssl_context=(cert_file, key_file))
