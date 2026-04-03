#!/usr/bin/env python3
"""
Automated Geopolitical News Polling for Trading Bot
Updates intelligence.json with latest Trump/world news
Uses REAL NewsAPI for live data
"""

import json
import os
import sys
import requests
from datetime import datetime, timezone
from pathlib import Path

# Load environment variables
BASE_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(BASE_DIR))

# Try to load .env file
env_file = BASE_DIR / '.env'
if env_file.exists():
    with open(env_file) as f:
        for line in f:
            if '=' in line and not line.startswith('#'):
                key, value = line.strip().split('=', 1)
                os.environ[key] = value.strip('"\'')

NEWSAPI_KEY = os.getenv('NEWSAPI_KEY', '')

INTEL_FILE = BASE_DIR / 'data' / 'geopolitical' / 'intelligence.json'
LOG_FILE = BASE_DIR / 'logs' / 'geo_poll.log'

def log(message):
    timestamp = datetime.now(timezone.utc).isoformat()
    print(f"[{timestamp}] {message}")
    with open(LOG_FILE, 'a') as f:
        f.write(f"[{timestamp}] {message}\n")

def fetch_real_news():
    """Fetch real geopolitical news from NewsAPI."""
    if not NEWSAPI_KEY:
        log("ERROR: No NewsAPI key found")
        return None
    
    try:
        # Search for oil/energy/geopolitical news
        queries = [
            ('oil+price+energy', 'Oil & Energy'),
            ('trump+tariff+trade', 'Trump & Trade'),
            ('Iran+Middle+East', 'Middle East'),
            ('OPEC+production', 'OPEC')
        ]
        
        all_articles = []
        for query, category in queries[:2]:  # Limit to 2 queries to save quota
            url = f"https://newsapi.org/v2/everything?q={query}&sortBy=publishedAt&pageSize=5&apiKey={NEWSAPI_KEY}"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'ok':
                    for article in data.get('articles', []):
                        all_articles.append({
                            'title': article.get('title', ''),
                            'description': article.get('description', ''),
                            'source': article.get('source', {}).get('name', ''),
                            'published': article.get('publishedAt', ''),
                            'category': category
                        })
            else:
                log(f"NewsAPI error for {category}: {response.status_code}")
        
        return all_articles
    except Exception as e:
        log(f"News fetch error: {e}")
        return None

def analyze_threat_level(articles):
    """Analyze news articles for threat indicators."""
    critical_keywords = ['war', 'attack', 'strike', 'invasion', 'crisis', 'closure', 'threaten', 'nuclear', 'bombing']
    high_keywords = ['tension', 'sanctions', 'blockade', 'disruption', 'escalation', 'conflict', 'missile', 'drone']
    
    threat_score = 0
    event_summaries = []
    
    for article in articles[:10]:  # Analyze top 10
        text = f"{article.get('title', '')} {article.get('description', '')}".lower()
        
        if any(kw in text for kw in critical_keywords):
            threat_score += 3
            event_summaries.append(article.get('title', 'Unknown event'))
        elif any(kw in text for kw in high_keywords):
            threat_score += 1
    
    # Determine threat level
    if threat_score >= 5:
        return 'CRITICAL', event_summaries
    elif threat_score >= 3:
        return 'HIGH', event_summaries
    elif threat_score >= 1:
        return 'MEDIUM', event_summaries
    return 'LOW', event_summaries

def update_intelligence(articles, threat_level, events):
    """Update intelligence.json with real data."""
    intel = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "threat_level": threat_level,
            "primary_risk": events[0] if events else "None detected",
            "secondary_risk": events[1] if len(events) > 1 else "Monitoring",
            "market_impact": "Elevated" if threat_level in ['CRITICAL', 'HIGH'] else "Normal",
            "last_updated": datetime.now(timezone.utc).isoformat(),
            "data_source": "NewsAPI (Live)"
        },
        "key_events": [
            {
                "event": event,
                "source": "NewsAPI",
                "impact": "See details in full report"
            } for event in events[:5]
        ],
        "recent_articles": [
            {
                "title": a.get('title', '')[:100],
                "source": a.get('source', ''),
                "category": a.get('category', '')
            } for a in articles[:5]
        ],
        "trading_implications": {
            "oil_volatility": "High" if threat_level == 'CRITICAL' else "Elevated" if threat_level == 'HIGH' else "Normal",
            "position_sizing": "Reduce to 50%" if threat_level == 'CRITICAL' else "Reduce to 70%" if threat_level == 'HIGH' else "Normal sizing",
            "recommendation": "Cautious trading" if threat_level in ['CRITICAL', 'HIGH'] else "Normal operations"
        }
    }
    
    # Save to file
    INTEL_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(INTEL_FILE, 'w') as f:
        json.dump(intel, f, indent=2)
    
    return intel

def main():
    log("Starting geopolitical news poll with LIVE NewsAPI...")
    
    # Fetch real news
    articles = fetch_real_news()
    
    if articles is None:
        log("WARNING: Using fallback (check API key)")
        return
    
    log(f"Fetched {len(articles)} articles from NewsAPI")
    
    # Analyze threat level
    threat_level, events = analyze_threat_level(articles)
    log(f"Threat level: {threat_level}")
    
    if events:
        log(f"Key events detected: {len(events)}")
        for e in events[:3]:
            log(f"  - {e[:60]}...")
    
    # Update intelligence file
    intel = update_intelligence(articles, threat_level, events)
    log("Intelligence updated successfully (LIVE DATA)")
    
    # Print summary
    print(f"\n=== Live Geopolitical Update ===")
    print(f"Threat Level: {threat_level}")
    print(f"Articles: {len(articles)}")
    print(f"Position sizing: {intel['trading_implications']['position_sizing']}")

if __name__ == '__main__':
    main()
