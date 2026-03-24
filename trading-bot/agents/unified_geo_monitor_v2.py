#!/usr/bin/env python3
"""
Unified Geopolitical Monitor v2.0
Uses REAL APIs: NewsAPI, EIA, Alpha Vantage, FRED
"""

import json
import os
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any

BASE_DIR = Path(__file__).parent.parent
DATA_DIR = BASE_DIR / 'data' / 'geopolitical'

class NewsAPIMonitor:
    """Real NewsAPI integration."""
    
    API_KEY = os.getenv('NEWSAPI_KEY') or "bb6dc738c7784ddc9262709cbd177061"
    
    def search(self, query: str) -> List[Dict]:
        """Search NewsAPI."""
        if not self.API_KEY:
            return []
        
        try:
            url = f"https://newsapi.org/v2/everything?q={query}&sortBy=publishedAt&pageSize=10&apiKey={self.API_KEY}"
            
            result = subprocess.run(
                ['curl', '-s', '--max-time', '15', url],
                capture_output=True, text=True, timeout=20
            )
            
            if result.returncode == 0 and result.stdout:
                data = json.loads(result.stdout)
                
                if data.get('status') == 'ok':
                    return [
                        {
                            'id': f"news_{i}",
                            'source': art.get('source', {}).get('name', 'NewsAPI'),
                            'timestamp': art.get('publishedAt', ''),
                            'title': art.get('title', ''),
                            'description': art.get('description', ''),
                            'url': art.get('url', ''),
                            'content': art.get('content', '')
                        }
                        for i, art in enumerate(data.get('articles', []))
                    ]
        except Exception as e:
            print(f"NewsAPI error: {e}")
        
        return []

class AlphaVantageMonitor:
    """Real Alpha Vantage integration."""
    
    API_KEY = os.getenv('ALPHA_VANTAGE_KEY') or "36S3286FXNEOUYR7"
    
    def get_commodity(self, symbol: str = "Brent") -> Dict:
        """Get commodity data."""
        if not self.API_KEY:
            return {}
        
        try:
            url = f"https://www.alphavantage.co/query?function=COMMODITY_INTERVAL&interval=daily&commodity={symbol}&apikey={self.API_KEY}"
            
            result = subprocess.run(
                ['curl', '-s', '--max-time', '15', url],
                capture_output=True, text=True, timeout=20
            )
            
            if result.returncode == 0 and result.stdout:
                data = json.loads(result.stdout)
                return data
        except Exception as e:
            print(f"Alpha Vantage error: {e}")
        
        return {}
    
    def get_forex(self, from_currency: str, to_currency: str) -> Dict:
        """Get forex rate."""
        if not self.API_KEY:
            return {}
        
        try:
            url = f"https://www.alphavantage.co/query?function=CURRENCY_EXCHANGE_RATE&from_currency={from_currency}&to_currency={to_currency}&apikey={self.API_KEY}"
            
            result = subprocess.run(
                ['curl', '-s', '--max-time', '15', url],
                capture_output=True, text=True, timeout=20
            )
            
            if result.returncode == 0 and result.stdout:
                data = json.loads(result.stdout)
                return data
        except Exception as e:
            print(f"Alpha Vantage forex error: {e}")
        
        return {}

class FREDMonitor:
    """Real FRED (Federal Reserve) integration."""
    
    API_KEY = os.getenv('FRED_API_KEY')
    
    def get_series(self, series_id: str) -> Dict:
        """Get FRED series data."""
        if not self.API_KEY:
            return {}
        
        try:
            url = f"https://api.stlouisfed.org/fred/series/observations?series_id={series_id}&api_key={self.API_KEY}&file_type=json&limit=5&sort_order=desc"
            
            result = subprocess.run(
                ['curl', '-s', '--max-time', '15', url],
                capture_output=True, text=True, timeout=20
            )
            
            if result.returncode == 0 and result.stdout:
                data = json.loads(result.stdout)
                return data
        except Exception as e:
            print(f"FRED error: {e}")
        
        return {}

class UnifiedMonitor:
    """Unified monitor using real APIs."""
    
    def __init__(self):
        self.newsapi = NewsAPIMonitor()
        self.alpha = AlphaVantageMonitor()
        self.fred = FREDMonitor()
    
    def collect_all(self) -> Dict:
        """Collect from all real sources."""
        print("🌍 Collecting REAL data from APIs...")
        
        # NewsAPI - Trump
        print("  📡 NewsAPI: Trump + Oil...")
        trump_news = self.newsapi.search("Trump oil energy sanctions")
        
        # NewsAPI - OPEC
        print("  📡 NewsAPI: OPEC...")
        opec_news = self.newsapi.search("OPEC production oil")
        
        # NewsAPI - Conflicts
        print("  📡 NewsAPI: Middle East...")
        conflict_news = self.newsapi.search("Middle East Iran Israel conflict oil")
        
        # Alpha Vantage - Commodity
        print("  📈 Alpha Vantage: Commodity data...")
        commodity_data = self.alpha.get_commodity("Brent")
        
        # Alpha Vantage - Forex
        print("  💱 Alpha Vantage: Forex rates...")
        usd_cad = self.alpha.get_forex("USD", "CAD")
        usd_eur = self.alpha.get_forex("USD", "EUR")
        
        # FRED - Economic data
        print("  🏛️  FRED: Economic indicators...")
        oil_price = self.fred.get_series("DCOILWTICO")  # WTI
        
        # Compile report
        report = {
            'timestamp': datetime.now().isoformat(),
            'data_quality': 'REAL',
            'sources': {
                'newsapi': len(trump_news) + len(opec_news) + len(conflict_news),
                'alpha_vantage': 1 if commodity_data else 0,
                'fred': 1 if oil_price else 0
            },
            'trump_news': trump_news[:5],
            'opec_news': opec_news[:3],
            'conflict_news': conflict_news[:3],
            'commodity': commodity_data,
            'forex': {
                'USD_CAD': usd_cad,
                'USD_EUR': usd_eur
            },
            'oil_prices': oil_price
        }
        
        # Save
        with open(DATA_DIR / 'real_time_intelligence.json', 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        return report

def main():
    print("="*60)
    print("UNIFIED GEO MONITOR v2.0 - REAL DATA")
    print("="*60)
    
    monitor = UnifiedMonitor()
    report = monitor.collect_all()
    
    print("\n" + "="*60)
    print("COLLECTION SUMMARY")
    print("="*60)
    
    for source, count in report['sources'].items():
        status = "✅" if count > 0 else "❌"
        print(f"  {status} {source}: {count} items")
    
    if report['trump_news']:
        print(f"\n🦅 Trump/Oil News:")
        for news in report['trump_news'][:3]:
            print(f"  - {news['title'][:60]}...")
    
    if report['opec_news']:
        print(f"\n🛢️  OPEC News:")
        for news in report['opec_news'][:2]:
            print(f"  - {news['title'][:60]}...")
    
    print("\n✅ Real-time intelligence saved")

if __name__ == '__main__':
    main()
