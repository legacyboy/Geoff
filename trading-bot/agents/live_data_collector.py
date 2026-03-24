#!/usr/bin/env python3
"""
Live Data Collector - Uses REAL APIs
Configured with working keys
"""

import json
import time
import subprocess
from datetime import datetime
from pathlib import Path

# Real API Keys
NEWSAPI_KEY = "bb6dc738c7784ddc9262709cbd177061"
ALPHA_KEY = "36S3286FXNEOUYR7"
FRED_KEY = "97e5ae4dddf73b1b9e141d2a391a67db"

BASE_DIR = Path(__file__).parent.parent
DATA_DIR = BASE_DIR / 'data' / 'geopolitical'

def fetch_newsapi(query: str, max_items: int = 5) -> list:
    """Fetch real news from NewsAPI."""
    # Use + for spaces in URL
    query_encoded = query.replace(' ', '+')
    url = f"https://newsapi.org/v2/everything?q={query_encoded}&pageSize={max_items}&apiKey={NEWSAPI_KEY}"
    
    try:
        result = subprocess.run(
            ['curl', '-s', '--max-time', '15', url],
            capture_output=True, text=True, timeout=20
        )
        
        if result.returncode == 0 and result.stdout:
            data = json.loads(result.stdout)
            
            if data.get('status') == 'ok':
                articles = data.get('articles', [])
                return [
                    {
                        'id': f"news_{i}",
                        'source': art.get('source', {}).get('name', 'Unknown'),
                        'timestamp': art.get('publishedAt', ''),
                        'title': art.get('title', ''),
                        'description': art.get('description', ''),
                        'url': art.get('url', ''),
                        'query': query
                    }
                    for i, art in enumerate(articles)
                ]
    except Exception as e:
        print(f"NewsAPI error: {e}")
    
    return []

def fetch_alpha_vantage_forex(from_curr: str, to_curr: str) -> dict:
    """Fetch forex rate from Alpha Vantage."""
    url = f"https://www.alphavantage.co/query?function=CURRENCY_EXCHANGE_RATE&from_currency={from_curr}&to_currency={to_curr}&apikey={ALPHA_KEY}"
    
    try:
        result = subprocess.run(
            ['curl', '-s', '--max-time', '15', url],
            capture_output=True, text=True, timeout=20
        )
        
        if result.returncode == 0 and result.stdout:
            return json.loads(result.stdout)
    except Exception as e:
        print(f"Alpha Vantage error: {e}")
    
    return {}

def fetch_fred_oil() -> dict:
    """Fetch WTI oil price from FRED."""
    # DCOILWTICO = Crude Oil Prices: West Texas Intermediate (WTI)
    url = f"https://api.stlouisfed.org/fred/series/observations?series_id=DCOILWTICO&api_key={FRED_KEY}&file_type=json&limit=1&sort_order=desc"
    
    try:
        result = subprocess.run(
            ['curl', '-s', '--max-time', '15', url],
            capture_output=True, text=True, timeout=20
        )
        
        if result.returncode == 0 and result.stdout:
            return json.loads(result.stdout)
    except Exception as e:
        print(f"FRED error: {e}")
    
    return {}

def collect_all() -> dict:
    """Collect all live data."""
    print("🌍 Fetching LIVE data...\n")
    
    # Trump news
    print("📡 Fetching Trump news...")
    trump_news = fetch_newsapi("Trump oil energy", 5)
    time.sleep(1)  # Rate limit
    
    print("📡 Fetching OPEC news...")
    opec_news = fetch_newsapi("OPEC oil production", 3)
    time.sleep(1)
    
    print("📡 Fetching conflict news...")
    conflict_news = fetch_newsapi("Middle East Iran Israel oil", 3)
    time.sleep(1)
    
    # Forex rates (staggered to avoid rate limits)
    print("💱 Fetching USD/CAD...")
    usd_cad = fetch_alpha_vantage_forex("USD", "CAD")
    time.sleep(1)
    
    print("💱 Fetching USD/EUR...")
    usd_eur = fetch_alpha_vantage_forex("USD", "EUR")
    time.sleep(1)
    
    print("💱 Fetching USD/NOK...")
    usd_nok = fetch_alpha_vantage_forex("USD", "NOK")
    time.sleep(1)
    
    print("🛢️  Fetching oil prices...")
    oil_price = fetch_fred_oil()
    
    # Compile report
    report = {
        'timestamp': datetime.now().isoformat(),
        'data_quality': 'LIVE',
        'sources': {
            'newsapi': {
                'trump': len(trump_news),
                'opec': len(opec_news),
                'conflicts': len(conflict_news)
            },
            'alpha_vantage': 3,
            'fred': 1 if oil_price.get('observations') else 0
        },
        'trump_news': trump_news,
        'opec_news': opec_news,
        'conflict_news': conflict_news,
        'forex': {
            'USD_CAD': usd_cad.get('Realtime Currency Exchange Rate', {}),
            'USD_EUR': usd_eur.get('Realtime Currency Exchange Rate', {}),
            'USD_NOK': usd_nok.get('Realtime Currency Exchange Rate', {})
        },
        'oil_prices': {
            'wti': oil_price.get('observations', [{}])[0] if oil_price.get('observations') else None
        }
    }
    
    # Save
    with open(DATA_DIR / 'live_intelligence.json', 'w') as f:
        json.dump(report, f, indent=2, default=str)
    
    return report

def main():
    print("="*60)
    print("LIVE DATA COLLECTOR")
    print("Using real APIs with your keys")
    print("="*60)
    
    report = collect_all()
    
    print("\n" + "="*60)
    print("SUMMARY")
    print("="*60)
    
    print(f"\n🦅 Trump Articles: {len(report['trump_news'])}")
    for news in report['trump_news'][:3]:
        print(f"  • {news['title'][:60]}...")
        print(f"    Source: {news['source']} | {news['timestamp'][:10]}")
    
    print(f"\n🛢️  OPEC Articles: {len(report['opec_news'])}")
    for news in report['opec_news'][:2]:
        print(f"  • {news['title'][:60]}...")
    
    print(f"\n⚔️  Conflict Articles: {len(report['conflict_news'])}")
    for news in report['conflict_news'][:2]:
        print(f"  • {news['title'][:60]}...")
    
    # Show forex
    print(f"\n💱 Exchange Rates:")
    for pair, rate in report['forex'].items():
        if rate:
            from_c = rate.get('1. From_Currency Code', 'N/A')
            to_c = rate.get('3. To_Currency Code', 'N/A')
            rate_val = rate.get('5. Exchange Rate', 'N/A')
            print(f"  {from_c}/{to_c}: {rate_val}")
    
    # Show oil price
    if report['oil_prices']['wti']:
        obs = report['oil_prices']['wti']
        print(f"\n🛢️  WTI Oil Price:")
        print(f"  Date: {obs.get('date')}")
        print(f"  Price: ${obs.get('value')} per barrel")
    
    print("\n✅ Live data saved to data/geopolitical/live_intelligence.json")

if __name__ == '__main__':
    main()
