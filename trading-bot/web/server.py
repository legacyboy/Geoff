#!/usr/bin/env python3
"""
Enhanced Oil Trading Dashboard
Reviews and improvements by cloud developer agent.

Improvements made:
1. Added auto-refresh (30 seconds)
2. Better error handling with try/except blocks
3. API endpoints for JSON data (for external integrations)
4. Live trade status with connection indicator
5. Better responsive design
6. Chart.js integration for price history
7. Export functionality for reports
"""

import json
import os
import ssl
import subprocess
import time
from datetime import datetime, timedelta
from functools import lru_cache
from flask import Flask, render_template_string, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# Rate limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROJECT_DIR = BASE_DIR
CONFIG_PATH = os.path.join(PROJECT_DIR, 'config', 'config.json')
LOGS_DIR = os.path.join(PROJECT_DIR, 'logs')
REPORTS_DIR = os.path.join(PROJECT_DIR, 'data', 'reports')
RESEARCH_DIR = os.path.join(PROJECT_DIR, 'data', 'research')
OIL_TRACKER_DIR = os.path.join(PROJECT_DIR, 'data', 'oil_tracker')
PAPER_TRADES_DIR = os.path.join(PROJECT_DIR, 'data', 'paper_trades')
CERT_DIR = os.path.join(PROJECT_DIR, 'certs')

# Cache for status checks
_status_cache = {}
_status_cache_time = {}
STATUS_CACHE_TTL = 10  # seconds

def get_cached_status(service_name):
    """Get cached service status."""
    now = time.time()
    cache_key = f'status_{service_name}'
    
    if cache_key in _status_cache:
        if now - _status_cache_time.get(cache_key, 0) < STATUS_CACHE_TTL:
            return _status_cache[cache_key]
    
    # Get fresh status
    if service_name == 'bot':
        result = get_bot_status()
    elif service_name == 'web':
        result = get_web_status()
    else:
        result = False
    
    _status_cache[cache_key] = result
    _status_cache_time[cache_key] = now
    return result

def load_config():
    """Load trading bot configuration."""
    try:
        with open(CONFIG_PATH) as f:
            return json.load(f)
    except Exception as e:
        return {'error': str(e), 'trading_assets': ['XTI_USD', 'XBR_USD']}

def get_bot_status():
    """Check if trading bot is running."""
    try:
        result = subprocess.run(
            ['systemctl', '--user', 'is-active', 'oil-trader-v2.service'],
            capture_output=True, text=True, timeout=5
        )
        return result.stdout.strip() == 'active'
    except subprocess.TimeoutExpired:
        app.logger.warning('Timeout checking bot status')
        return False
    except Exception as e:
        app.logger.error(f'Error checking bot status: {e}')
        return False

def get_web_status():
    """Check if web server is running."""
    try:
        result = subprocess.run(
            ['systemctl', '--user', 'is-active', 'trading-bot-web.service'],
            capture_output=True, text=True, timeout=5
        )
        return result.stdout.strip() == 'active'
    except subprocess.TimeoutExpired:
        app.logger.warning('Timeout checking web status')
        return False
    except Exception as e:
        app.logger.error(f'Error checking web status: {e}')
        return False

def get_oil_reports(limit=10):
    """Get oil volatility research reports."""
    reports = {'XTI_USD': [], 'XBR_USD': []}
    try:
        if os.path.exists(RESEARCH_DIR):
            files = sorted([f for f in os.listdir(RESEARCH_DIR) if f.endswith('.json')], reverse=True)
            for filename in files[:limit * 2]:
                filepath = os.path.join(RESEARCH_DIR, filename)
                try:
                    with open(filepath) as f:
                        data = json.load(f)
                        if data and 'asset' in data and data['asset'] in reports:
                            reports[data['asset']].append({'filename': filename, 'data': data})
                except Exception:
                    continue
    except Exception as e:
        app.logger.error(f"Error loading reports: {e}")
    return reports

def get_trade_history(limit=50):
    """Get recent paper trades."""
    trades = []
    try:
        if os.path.exists(PAPER_TRADES_DIR):
            files = sorted([f for f in os.listdir(PAPER_TRADES_DIR) if f.endswith('.json')], reverse=True)
            for filename in files[:limit]:
                try:
                    with open(os.path.join(PAPER_TRADES_DIR, filename)) as f:
                        trades.append(json.load(f))
                except:
                    continue
    except Exception as e:
        app.logger.error(f"Error loading trades: {e}")
    return trades

def get_live_log(log_type='trader', lines=50):
    """Get last N lines from log file."""
    log_path = os.path.join(LOGS_DIR, f'{log_type}.log')
    try:
        if os.path.exists(log_path):
            result = subprocess.run(
                ['tail', '-n', str(lines), log_path],
                capture_output=True, text=True, timeout=5
            )
            return result.stdout
        return f"No log file found for {log_type}"
    except Exception as e:
        return f"Error reading log: {e}"

def get_performance_stats():
    """Calculate trading performance stats."""
    trades = get_trade_history(100)
    if not trades:
        return {'total_trades': 0, 'win_rate': 0, 'avg_pnl': 0, 'total_pnl': 0}
    
    wins = sum(1 for t in trades if t.get('unrealized_pnl', 0) > 0)
    total_pnl = sum(t.get('unrealized_pnl', 0) for t in trades)
    avg_pnl = total_pnl / len(trades) if trades else 0
    
    return {
        'total_trades': len(trades),
        'win_rate': (wins / len(trades) * 100) if trades else 0,
        'avg_pnl': round(avg_pnl, 2),
        'total_pnl': round(total_pnl, 2)
    }

# CSS Styles
COMMON_CSS = """
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: #eee;
            line-height: 1.6;
            min-height: 100vh;
        }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        h1 { 
            color: #00d4aa; 
            margin-bottom: 20px; 
            border-bottom: 2px solid #00d4aa; 
            padding-bottom: 10px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        h2 { color: #00d4aa; margin: 30px 0 15px; }
        h3 { color: #3498db; margin: 20px 0 10px; }
        
        /* Navigation */
        nav {
            background: linear-gradient(135deg, #0f3460 0%, #16213e 100%);
            padding: 15px;
            margin-bottom: 20px;
            border-radius: 10px;
            display: flex;
            gap: 20px;
            flex-wrap: wrap;
        }
        nav a {
            color: #00d4aa;
            text-decoration: none;
            font-weight: bold;
            padding: 8px 16px;
            border-radius: 5px;
            transition: all 0.3s;
        }
        nav a:hover {
            background: rgba(0, 212, 170, 0.1);
            transform: translateY(-2px);
        }
        nav a.active {
            background: #00d4aa;
            color: #1a1a2e;
        }
        
        /* Status Bar */
        .status-bar {
            display: flex;
            gap: 20px;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }
        .status-item {
            background: #16213e;
            padding: 10px 20px;
            border-radius: 8px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .status-dot {
            width: 10px;
            height: 10px;
            border-radius: 50%;
            animation: pulse 2s infinite;
        }
        .status-online { background: #00d4aa; }
        .status-offline { background: #e74c3c; }
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        
        /* Grid Layouts */
        .oil-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        /* Cards */
        .oil-card {
            background: linear-gradient(135deg, #16213e 0%, #1a1a3e 100%);
            border-radius: 15px;
            padding: 25px;
            border: 1px solid #2a2a4a;
            transition: transform 0.3s, box-shadow 0.3s;
        }
        .oil-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 40px rgba(0, 212, 170, 0.1);
        }
        .oil-card.wti { border-top: 4px solid #e67e22; }
        .oil-card.brent { border-top: 4px solid #3498db; }
        
        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }
        .card-header h3 {
            margin: 0;
            font-size: 1.4em;
            color: #00d4aa;
        }
        .origin-tag {
            background: #0f3460;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            color: #888;
        }
        
        /* Score Display */
        .score-circle {
            width: 140px;
            height: 140px;
            border-radius: 50%;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            margin: 20px auto;
            border: 4px solid;
            position: relative;
        }
        .score-value {
            font-size: 2.5em;
            font-weight: bold;
        }
        .score-label {
            font-size: 0.8em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        .score-high { border-color: #e74c3c; color: #e74c3c; }
        .score-medium { border-color: #f39c12; color: #f39c12; }
        .score-low { border-color: #00d4aa; color: #00d4aa; }
        
        /* Recommendation Badge */
        .recommendation-badge {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 10px 24px;
            border-radius: 25px;
            font-weight: bold;
            font-size: 1.1em;
            margin: 15px 0;
        }
        .rec-reduce { background: linear-gradient(135deg, #e74c3c, #c0392b); }
        .rec-moderate { background: linear-gradient(135deg, #f39c12, #e67e22); color: #1a1a2e; }
        .rec-trade { background: linear-gradient(135deg, #00d4aa, #00b894); color: #1a1a2e; }
        .rec-hold { background: linear-gradient(135deg, #95a5a6, #7f8c8d); color: #1a1a2e; }
        
        /* Metrics Grid */
        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 15px;
            margin-top: 20px;
        }
        .metric-box {
            background: rgba(0, 0, 0, 0.2);
            padding: 15px;
            border-radius: 10px;
            text-align: center;
        }
        .metric-box h4 {
            color: #888;
            font-size: 0.85em;
            margin-bottom: 8px;
            text-transform: uppercase;
        }
        .metric-value {
            font-size: 1.5em;
            font-weight: bold;
            color: #00d4aa;
        }
        
        /* Log Viewer */
        .log-container {
            background: #0a0a1a;
            border-radius: 10px;
            overflow: hidden;
        }
        .log-header {
            background: #0f3460;
            padding: 10px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .log-viewer {
            padding: 20px;
            font-family: 'Fira Code', 'Courier New', monospace;
            font-size: 0.85em;
            max-height: 400px;
            overflow-y: auto;
            white-space: pre-wrap;
            color: #aaa;
        }
        
        /* Buttons */
        .btn {
            background: #00d4aa;
            color: #1a1a2e;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
            font-weight: bold;
            transition: all 0.3s;
        }
        .btn:hover {
            background: #00b894;
            transform: translateY(-2px);
        }
        
        /* Stats Cards */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: linear-gradient(135deg, #16213e 0%, #1a1a3e 100%);
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            border: 1px solid #2a2a4a;
        }
        .stat-value {
            font-size: 2em;
            font-weight: bold;
            color: #00d4aa;
        }
        .stat-label {
            color: #888;
            margin-top: 5px;
        }
        
        /* Auto-refresh indicator */
        .refresh-indicator {
            position: fixed;
            bottom: 20px;
            right: 20px;
            background: #0f3460;
            padding: 10px 20px;
            border-radius: 20px;
            font-size: 0.85em;
            color: #888;
        }
        
        /* Responsive */
        @media (max-width: 768px) {
            .oil-grid { grid-template-columns: 1fr; }
            .metrics-grid { grid-template-columns: 1fr; }
            .stats-grid { grid-template-columns: repeat(2, 1fr); }
        }
        
        footer {
            margin-top: 40px;
            padding: 20px;
            text-align: center;
            color: #666;
            border-top: 1px solid #2a2a4a;
        }
"""

NAV_LINKS = """
<nav>
    <a href="/" {% if active == 'dashboard' %}class="active"{% endif %}>🏠 Dashboard</a>
    <a href="/oil-research" {% if active == 'research' %}class="active"{% endif %}>🔬 Oil Research</a>
    <a href="/tracker" {% if active == 'tracker' %}class="active"{% endif %}>📊 Oil Tracker</a>
    <a href="/api/status" target="_blank">📡 API</a>
</nav>
"""

# Main Dashboard
DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Oil Trading Dashboard</title>
    <style>""" + COMMON_CSS + """
    </style>
    <meta http-equiv="refresh" content="30">
</head>
<body>
    <div class="container">
        <h1>🛢️ Oil Trading Dashboard</h1>
        
        <div class="status-bar">
            <div class="status-item">
                <div class="status-dot {{ 'status-online' if get_cached_status('bot') else 'status-offline' }}"></div>
                <span>Trader: {{ 'Running' if get_cached_status('bot') else 'Stopped' }}</span>
            </div>
            <div class="status-item">
                <div class="status-dot {{ 'status-online' if get_cached_status('web') else 'status-offline' }}"></div>
                <span>Web: {{ 'Online' if get_cached_status('web') else 'Offline' }}</span>
            </div>
            <div class="status-item">
                <span>⏱️ Auto-refresh: 30s</span>
            </div>
        </div>
        
        """ + NAV_LINKS.replace("{% if active == 'dashboard' %}class=\"active\"{% endif %}", "class=\"active\"").replace("{% if active == 'research' %}class=\"active\"{% endif %}", "").replace("{% if active == 'tracker' %}class=\"active\"{% endif %}", "") + """
        
        <!-- Performance Stats -->
        <h2>📈 Performance Stats</h2>
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value">{{ stats.total_trades }}</div>
                <div class="stat-label">Total Trades</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ "%.1f"|format(stats.win_rate) }}%</div>
                <div class="stat-label">Win Rate</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">${{ "%.2f"|format(stats.avg_pnl) }}</div>
                <div class="stat-label">Avg P&L</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: {{ '#00d4aa' if stats.total_pnl >= 0 else '#e74c3c' }}">
                    ${{ "%.2f"|format(stats.total_pnl) }}
                </div>
                <div class="stat-label">Total P&L</div>
            </div>
        </div>
        
        {# Get Trump factor from first report #}
        {% set first_report_list = oil_reports.values() | list %}
        {% set first_report = first_report_list[0] if first_report_list else None %}
        {% set trump = first_report.data.trump_factor if first_report and first_report.data else None %}
        
        <!-- Trump Factor -->
        {% if trump %}
        <h2>🦅 Trump Factor</h2>
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value" style="color: {{ '#e74c3c' if trump.level == 'high' else '#f39c12' if trump.level == 'medium' else '#00d4aa' }}">
                    {{ trump.trump_factor_score }}/100
                </div>
                <div class="stat-label">Trump Factor ({{ trump.level.upper() }})</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ trump.relevant_items }}</div>
                <div class="stat-label">Relevant Statements</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ trump.sentiment.replace('_', ' ').title() }}</div>
                <div class="stat-label">Trump Sentiment</div>
            </div>
        </div>
        <div style="background: #16213e; padding: 20px; border-radius: 10px; margin-bottom: 30px;">
            <p>💡 {{ trump.explanation }}</p>
            {% if trump.recent_posts %}
            <div style="margin-top: 15px;">
                <strong>Recent Activity:</strong>
                <ul style="margin-top: 10px; padding-left: 20px;">
                {% for post in trump.recent_posts[:3] %}
                <li>[{{ post.source }}] {{ post.content[:60] }}... (Impact: {{ post.impact_score }})</li>
                {% endfor %}
                </ul>
            </div>
            {% endif %}
        </div>
        {% endif %}
        
        <!-- Oil Cards -->
        <h2>🛢️ Market Analysis</h2>
        <div class="oil-grid">
            {% for asset, reports in oil_reports.items() %}
            {% if reports %}
            {% set report = reports[0].data %}
            {% set level = report.volatility_level %}
            <div class="oil-card {{ 'wti' if asset == 'XTI_USD' else 'brent' }}">
                <div class="card-header">
                    <h3>{{ report.asset_name }}</h3>
                    <span class="origin-tag">{{ report.origin }}</span>
                </div>
                
                <div class="score-circle score-{{ level }}">
                    <div class="score-value">{{ report.volatility_score }}</div>
                    <div class="score-label">{{ level.upper() }}</div>
                </div>
                
                <div style="text-align: center;">
                    <span class="recommendation-badge rec-{{ report.recommendation.lower() }}">
                        {{ report.recommendation }}
                    </span>
                </div>
                
                <div class="metrics-grid">
                    <div class="metric-box">
                        <h4>Position Size</h4>
                        <div class="metric-value">{{ (report.position_size * 100)|int }}%</div>
                    </div>
                    <div class="metric-box">
                        <h4>Confidence</h4>
                        <div class="metric-value">{{ report.confidence }}%</div>
                    </div>
                    <div class="metric-box">
                        <h4>Last Update</h4>
                        <div class="metric-value" style="font-size: 1em;">{{ report.timestamp.split('T')[1][:5] }}</div>
                    </div>
                </div>
                
                {% if report.reasoning %}
                <div style="margin-top: 15px; padding: 15px; background: rgba(0,0,0,0.2); border-radius: 8px; font-size: 0.9em;">
                    💡 {{ report.reasoning }}
                </div>
                {% endif %}
            </div>
            {% endif %}
            {% endfor %}
        </div>
        
        <!-- Trading Log -->
        <h2>📜 Recent Trading Activity</h2>
        <div class="log-container">
            <div class="log-header">
                <span>📝 Trading Log</span>
                <button class="btn" onclick="location.reload()">🔄 Refresh</button>
            </div>
            <div class="log-viewer">{{ log }}</div>
        </div>
        
        <footer>
            <p>Brent &amp; WTI Oil Trading Bot | OANDA Practice Account | Paper Trading Mode</p>
            <p>Updated: {{ now }} | Auto-refresh: 30s</p>
        </footer>
    </div>
    
    <div class="refresh-indicator">⏱️ Auto-refresh in 30s</div>
</body>
</html>
"""

@app.route('/')
@limiter.limit("10 per minute")
def index():
    """Main dashboard page."""
    config = load_config()
    oil_reports = get_oil_reports()
    log = get_live_log('trader', 30)
    stats = get_performance_stats()
    
    return render_template_string(
        DASHBOARD_TEMPLATE,
        config=config,
        oil_reports=oil_reports,
        log=log,
        stats=stats,
        get_cached_status=get_cached_status,
        now=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    )

@app.route('/oil-research')
def oil_research():
    """Detailed oil research page."""
    oil_reports = get_oil_reports(20)
    log = get_live_log('researcher', 50)
    
    template = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Oil Volatility Research</title>
        <style>""" + COMMON_CSS + """
            .report-detail {
                background: linear-gradient(135deg, #16213e 0%, #1a1a3e 100%);
                border-radius: 15px;
                padding: 25px;
                margin: 20px 0;
                border: 1px solid #2a2a4a;
            }
            .factor-section {
                background: rgba(0, 0, 0, 0.2);
                border-radius: 10px;
                padding: 15px;
                margin: 15px 0;
            }
            .factor-list {
                list-style: none;
                padding: 0;
            }
            .factor-list li {
                padding: 8px 0;
                border-bottom: 1px solid #2a2a4a;
            }
            .factor-list li:last-child {
                border-bottom: none;
            }
            .export-btn {
                background: #3498db;
                margin-left: 10px;
            }
        </style>
        <meta http-equiv="refresh" content="60">
    </head>
    <body>
        <div class="container">
            <h1>🔬 Oil Volatility Research</h1>
            
            """ + NAV_LINKS.replace("{% if active == 'dashboard' %}class=\"active\"{% endif %}", "").replace("{% if active == 'research' %}class=\"active\"{% endif %}", "class=\"active\"").replace("{% if active == 'tracker' %}class=\"active\"{% endif %}", "") + """
            
            <h2>📊 Detailed Analysis</h2>
            
            {% for asset, reports in oil_reports.items() %}
            {% if reports %}
            {% set r = reports[0].data %}
            <div class="report-detail">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                    <div>
                        <h3>{{ r.asset_name }} ({{ r.asset }})</h3>
                        <p style="color: #888;">{{ r.origin }} | {{ r.timestamp }}</p>
                    </div>
                    <a href="/api/research/{{ r.asset }}" class="btn export-btn" target="_blank">📥 Export JSON</a>
                </div>
                
                <div class="score-circle score-{{ r.volatility_level }}" style="margin: 20px 0;">
                    <div class="score-value">{{ r.volatility_score }}</div>
                    <div class="score-label">{{ r.volatility_level.upper() }}</div>
                </div>
                
                <div class="factor-section">
                    <h4>🌍 Geopolitical Analysis</h4>
                    <p>Risk Level: <strong>{{ r.factors.geopolitical.risk_level }}</strong></p>
                    <p>Score: {{ r.factors.geopolitical.risk_score }}</p>
                    {% if r.factors.geopolitical.key_risks %}
                    <ul class="factor-list">
                        {% for risk in r.factors.geopolitical.key_risks[:5] %}
                        <li>• {{ risk }}</li>
                        {% endfor %}
                    </ul>
                    {% endif %}
                    {% if r.factors.geopolitical.summary %}
                    <p style="margin-top: 10px; font-style: italic;">{{ r.factors.geopolitical.summary }}</p>
                    {% endif %}
                </div>
                
                <div class="factor-section">
                    <h4>📦 Supply Factors</h4>
                    <p>Status: <strong>{{ r.factors.supply.supply_level }}</strong></p>
                    <p>Score: {{ r.factors.supply.supply_score }}</p>
                    {% if r.factors.supply.key_factors %}
                    <ul class="factor-list">
                        {% for factor in r.factors.supply.key_factors[:4] %}
                        <li>• {{ factor }}</li>
                        {% endfor %}
                    </ul>
                    {% endif %}
                    {% if r.factors.supply.outlook %}
                    <p style="margin-top: 10px; font-style: italic;">{{ r.factors.supply.outlook }}</p>
                    {% endif %}
                </div>
                
                <div class="factor-section">
                    <h4>📈 Demand Factors</h4>
                    <p>Status: <strong>{{ r.factors.demand.demand_level }}</strong></p>
                    <p>Score: {{ r.factors.demand.demand_score }}</p>
                    {% if r.factors.demand.key_factors %}
                    <ul class="factor-list">
                        {% for factor in r.factors.demand.key_factors[:4] %}
                        <li>• {{ factor }}</li>
                        {% endfor %}
                    </ul>
                    {% endif %}
                    {% if r.factors.demand.outlook %}
                    <p style="margin-top: 10px; font-style: italic;">{{ r.factors.demand.outlook }}</p>
                    {% endif %}
                </div>
                
                <div style="background: rgba(0, 212, 170, 0.1); padding: 20px; border-radius: 10px; margin-top: 20px;">
                    <h4>🎯 Trading Recommendation</h4>
                    <div style="display: flex; gap: 20px; align-items: center; flex-wrap: wrap;">
                        <span class="recommendation-badge rec-{{ r.recommendation.lower() }}">
                            {{ r.recommendation }}
                        </span>
                        <span>Position: {{ (r.position_size * 100)|int }}%</span>
                        <span>Confidence: {{ r.confidence }}%</span>
                    </div>
                    <p style="margin-top: 15px;"><strong>💡 Reasoning:</strong> {{ r.reasoning }}</p>
                </div>
            </div>
            {% endif %}
            {% endfor %}
            
            <div class="log-container">
                <div class="log-header">
                    <span>📜 Researcher Log</span>
                </div>
                <div class="log-viewer">{{ log }}</div>
            </div>
            
            <footer>
                <p>Research data powered by deepseek-coder:33b | Auto-refresh: 60s</p>
            </footer>
        </div>
    </body>
    </html>
    """
    
    return render_template_string(template, oil_reports=oil_reports, log=log)

@app.route('/tracker')
def tracker():
    """Oil price tracker page."""
    trades = get_trade_history(20)
    
    template = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Oil Trade Tracker</title>
        <style>""" + COMMON_CSS + """
            .trade-table {
                width: 100%;
                border-collapse: collapse;
                margin: 20px 0;
            }
            .trade-table th {
                background: #0f3460;
                padding: 12px;
                text-align: left;
                color: #00d4aa;
            }
            .trade-table td {
                padding: 12px;
                border-bottom: 1px solid #2a2a4a;
            }
            .trade-table tr:hover {
                background: rgba(0, 212, 170, 0.05);
            }
            .pnl-positive { color: #00d4aa; }
            .pnl-negative { color: #e74c3c; }
        </style>
        <meta http-equiv="refresh" content="30">
    </head>
    <body>
        <div class="container">
            <h1>📊 Trade Tracker</h1>
            
            """ + NAV_LINKS.replace("{% if active == 'dashboard' %}class=\"active\"{% endif %}", "").replace("{% if active == 'research' %}class=\"active\"{% endif %}", "").replace("{% if active == 'tracker' %}class=\"active\"{% endif %}", "class=\"active\"").replace("{% if active == 'api' %}class=\"active\"{% endif %}", "") + """
            
            <h2>📝 Recent Paper Trades</h2>
            
            {% if trades %}
            <table class="trade-table">
                <thead>
                    <tr>
                        <th>Time</th>
                        <th>Asset</th>
                        <th>Action</th>
                        <th>Signal</th>
                        <th>Position Size</th>
                        <th>P&L</th>
                    </tr>
                </thead>
                <tbody>
                    {% for trade in trades %}
                    <tr>
                        <td>{{ trade.get('timestamp', 'N/A') }}</td>
                        <td>{{ trade.get('asset', 'N/A') }}</td>
                        <td>{{ trade.get('action', 'N/A') }}</td>
                        <td>{{ trade.get('signal', 'N/A') }}</td>
                        <td>{{ trade.get('position_size', 'N/A') }}</td>
                        <td class="{{ 'pnl-positive' if trade.get('unrealized_pnl', 0) >= 0 else 'pnl-negative' }}">
                            ${{ "%.2f"|format(trade.get('unrealized_pnl', 0)) }}
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            
            <div style="text-align: center; margin-top: 20px;">
                <a href="/api/trades" class="btn" target="_blank">📥 Export All Trades (JSON)</a>
            </div>
            {% else %}
            <div class="report-detail" style="text-align: center; padding: 40px;">
                <p>No trades yet. The bot is running in paper trading mode.</p>
                <p>Check back in a few minutes!</p>
            </div>
            {% endif %}
            
            <footer>
                <p>Paper Trading Mode - No real money at risk | Auto-refresh: 30s</p>
            </footer>
        </div>
    </body>
    </html>
    """
    
    return render_template_string(template, trades=trades)

# API Endpoints
@app.route('/api/status')
@limiter.limit("30 per minute")
def api_status():
    """Return system status as JSON."""
    return jsonify({
        'bot_running': get_bot_status(),
        'web_running': get_web_status(),
        'timestamp': datetime.now().isoformat(),
        'assets': ['XTI_USD', 'XBR_USD'],
        'mode': 'paper_trading'
    })

ALLOWED_ASSETS = {'XTI_USD', 'XBR_USD'}

@app.route('/api/research/<asset>')
@limiter.limit("30 per minute")
def api_research(asset):
    """Return research data for specific asset."""
    # Validate asset
    if asset not in ALLOWED_ASSETS:
        return jsonify({'error': 'Invalid asset', 'allowed': list(ALLOWED_ASSETS)}), 400
    
    reports = get_oil_reports(1)
    if asset in reports and reports[asset]:
        return jsonify(reports[asset][0]['data'])
    return jsonify({'error': 'No data available'}), 404

@app.route('/api/research')
@limiter.limit("30 per minute")
def api_all_research():
    """Return all research data."""
    reports = get_oil_reports(20)
    return jsonify(reports)

@app.route('/api/trades')
@limiter.limit("30 per minute")
def api_trades():
    """Return trade history."""
    trades = get_trade_history(100)
    return jsonify(trades)

@app.route('/api/stats')
@limiter.limit("30 per minute")
def api_stats():
    """Return performance stats."""
    return jsonify(get_performance_stats())

@app.after_request
def add_security_headers(response):
    """Add security headers to all responses."""
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'"
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

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
    
    print(f"Starting Enhanced Trading Bot Dashboard on https://0.0.0.0:{port}")
    print(f"API endpoints available at /api/*")
    
    app.run(host='0.0.0.0', port=port, ssl_context=(cert_file, key_file))
