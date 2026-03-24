#!/usr/bin/env python3
"""
Currency Monitor - Track forex pairs for trading
Uses exchangerate-api (free tier) or alternative sources
"""

import json
import os
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any

BASE_DIR = Path(__file__).parent.parent
DATA_DIR = BASE_DIR / 'data' / 'forex'
DATA_DIR.mkdir(parents=True, exist_ok=True)

# Major currency pairs for oil trading
CURRENCY_PAIRS = {
    'USD_CAD': 'US Dollar / Canadian Dollar',  # Key for Canadian oil
    'USD_EUR': 'US Dollar / Euro',              # European markets
    'USD_GBP': 'US Dollar / British Pound',     # Brent trading
    'USD_JPY': 'US Dollar / Japanese Yen',      # Asian markets
    'USD_CNY': 'US Dollar / Chinese Yuan',      # China demand
    'USD_AUD': 'US Dollar / Australian Dollar', # Commodity currency
    'USD_CHF': 'US Dollar / Swiss Franc',       # Safe haven
    'USD_NOK': 'US Dollar / Norwegian Krone',     # Oil exporter
}

class CurrencyMonitor:
    """Monitor forex rates."""
    
    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.getenv('EXCHANGE_API_KEY')
    
    def fetch_rates(self) -> Dict[str, Any]:
        """Fetch current exchange rates from free API."""
        rates = {}
        
        # Try exchangerate-api free tier
        try:
            result = subprocess.run(
                ['curl', '-s', '--max-time', '10',
                 'https://api.exchangerate-api.com/v4/latest/USD'],
                capture_output=True, text=True, timeout=15
            )
            
            if result.returncode == 0 and result.stdout:
                data = json.loads(result.stdout)
                
                if data.get('rates'):
                    base_rates = data['rates']
                    
                    # Calculate cross rates
                    for pair, desc in CURRENCY_PAIRS.items():
                        base, quote = pair.split('_')
                        
                        if base == 'USD':
                            rate = base_rates.get(quote)
                            if rate:
                                rates[pair] = {
                                    'rate': rate,
                                    'description': desc,
                                    'timestamp': data.get('date', datetime.now().isoformat()),
                                    'base': base,
                                    'quote': quote
                                }
        
        except Exception as e:
            print(f"Forex fetch error: {e}")
        
        return rates
    
    def analyze_impact_on_oil(self, rates: Dict) -> Dict[str, Any]:
        """Analyze how currency rates impact oil prices."""
        analysis = {}
        
        # USD/CAD - Stronger USD = Cheaper oil for Canada
        if 'USD_CAD' in rates:
            usd_cad = rates['USD_CAD']['rate']
            analysis['USD_CAD'] = {
                'rate': usd_cad,
                'impact': 'bearish_canadian_oil' if usd_cad > 1.35 else 'bullish_canadian_oil',
                'description': f"USD/CAD at {usd_cad:.4f}: {'Expensive' if usd_cad > 1.35 else 'Cheap'} CAD makes Canadian oil {('more' if usd_cad > 1.35 else 'less')} expensive in USD terms"
            }
        
        # USD/NOK - Norway oil exports
        if 'USD_NOK' in rates:
            usd_nok = rates['USD_NOK']['rate']
            analysis['USD_NOK'] = {
                'rate': usd_nok,
                'impact': 'bearish_norwegian_oil' if usd_nok > 11 else 'bullish_norwegian_oil',
                'description': f"USD/NOK at {usd_nok:.2f}: Norwegian oil pricing"
            }
        
        # USD/CNY - China demand
        if 'USD_CNY' in rates:
            usd_cny = rates['USD_CNY']['rate']
            analysis['USD_CNY'] = {
                'rate': usd_cny,
                'impact': 'bullish_oil_demand' if usd_cny < 7.2 else 'bearish_oil_demand',
                'description': f"USD/CNY at {usd_cny:.2f}: Chinese demand indicator"
            }
        
        return analysis
    
    def get_full_report(self) -> Dict[str, Any]:
        """Generate full forex report."""
        rates = self.fetch_rates()
        analysis = self.analyze_impact_on_oil(rates)
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'source': 'exchangerate-api.com (free tier)',
            'rates': rates,
            'analysis': analysis,
            'base_currency': 'USD',
            'pairs_tracked': len(CURRENCY_PAIRS)
        }
        
        # Save
        with open(DATA_DIR / 'latest_forex.json', 'w') as f:
            json.dump(report, f, indent=2)
        
        return report

def main():
    print("💱 Currency Monitor")
    print("="*50)
    
    monitor = CurrencyMonitor()
    report = monitor.get_full_report()
    
    print(f"\nReport Time: {report['timestamp']}")
    print(f"Source: {report['source']}")
    
    print(f"\nExchange Rates (Base: USD):")
    for pair, data in report['rates'].items():
        print(f"  {pair}: {data['rate']:.4f}")
    
    if report['analysis']:
        print(f"\nOil Market Impact:")
        for pair, data in report['analysis'].items():
            print(f"  {pair}: {data['description']}")
    
    print(f"\n✅ Report saved")

if __name__ == '__main__':
    main()
