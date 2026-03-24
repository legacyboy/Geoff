#!/usr/bin/env python3
"""
EIA (US Energy Information Administration) Monitor
Free API for US oil data: production, inventories, prices
API Key required but FREE: https://www.eia.gov/opendata/register.php
"""

import json
import os
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any

BASE_DIR = Path(__file__).parent.parent
DATA_DIR = BASE_DIR / 'data' / 'eia'
DATA_DIR.mkdir(parents=True, exist_ok=True)

class EIAMonitor:
    """Monitor EIA data for US oil metrics."""
    
    API_KEY = os.getenv('EIA_API_KEY')
    BASE_URL = "https://api.eia.gov/v2"
    
    # Key series IDs
    SERIES = {
        'wti_price': 'PET.RWTC.D',  # WTI Spot Price
        'brent_price': 'PET.RBRTE.D',  # Brent Spot Price
        'crude_stocks': 'PET.WCRSTUS1.W',  # Crude Oil Stocks
        'gasoline_stocks': 'PET.WGASUS1.W',  # Gasoline Stocks
        'production': 'PET.MCRFPUS1.M',  # Field Production
        'imports': 'PET.MTTIMUS1.M',  # Imports
        'exports': 'PET.MTTEXUS1.M',  # Exports
        'refinery_input': 'PET.MCRRIUS1.M',  # Refinery Net Input
        'cushing_stocks': 'PET.WCESTUS1.W',  # Cushing Stocks
    }
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or self.API_KEY
    
    def fetch_series(self, series_id: str, length: int = 10) -> Dict[str, Any]:
        """Fetch a specific EIA series."""
        if not self.api_key:
            return {'error': 'EIA_API_KEY not set'}
        
        try:
            url = f"{self.BASE_URL}/seriesid/{series_id}/data?api_key={self.api_key}&length={length}"
            
            result = subprocess.run(
                ['curl', '-s', '--max-time', '15', url],
                capture_output=True, text=True, timeout=20
            )
            
            if result.returncode == 0 and result.stdout:
                data = json.loads(result.stdout)
                return data
            
        except Exception as e:
            print(f"EIA fetch error: {e}")
        
        return {}
    
    def get_wti_price(self) -> Dict[str, Any]:
        """Get current WTI price."""
        data = self.fetch_series('PET.RWTC.D', length=5)
        
        if data.get('response') and data['response'].get('data'):
            latest = data['response']['data'][0]
            return {
                'price': float(latest.get('value', 0)),
                'date': latest.get('period', ''),
                'unit': 'dollars per barrel',
                'trend': self._calculate_trend(data['response']['data'][:5])
            }
        
        return {'error': 'No data available', 'price': None}
    
    def get_crude_stocks(self) -> Dict[str, Any]:
        """Get US crude oil stocks (inventory)."""
        data = self.fetch_series('PET.WCRSTUS1.W', length=5)
        
        if data.get('response') and data['response'].get('data'):
            latest = data['response']['data'][0]
            return {
                'stocks_million_barrels': float(latest.get('value', 0)),
                'date': latest.get('period', ''),
                'trend': self._calculate_trend(data['response']['data'][:5])
            }
        
        return {'error': 'No data available', 'stocks': None}
    
    def get_production(self) -> Dict[str, Any]:
        """Get US crude oil production."""
        data = self.fetch_series('PET.MCRFPUS1.M', length=3)
        
        if data.get('response') and data['response'].get('data'):
            latest = data['response']['data'][0]
            return {
                'production_thousand_barrels_day': float(latest.get('value', 0)),
                'date': latest.get('period', ''),
                'trend': self._calculate_trend(data['response']['data'][:3])
            }
        
        return {'error': 'No data available', 'production': None}
    
    def _calculate_trend(self, data_points: List[Dict]) -> str:
        """Calculate trend from data points."""
        if len(data_points) < 2:
            return 'flat'
        
        values = [float(d.get('value', 0)) for d in data_points]
        
        if values[0] > values[-1] * 1.01:
            return 'increasing'
        elif values[0] < values[-1] * 0.99:
            return 'decreasing'
        return 'flat'
    
    def get_full_report(self) -> Dict[str, Any]:
        """Get comprehensive EIA report."""
        if not self.api_key:
            return {
                'status': 'error',
                'message': 'EIA_API_KEY not set. Get free key at: https://www.eia.gov/opendata/register.php'
            }
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'source': 'EIA (US Energy Information Administration)',
            'data': {
                'wti_price': self.get_wti_price(),
                'crude_stocks': self.get_crude_stocks(),
                'production': self.get_production()
            }
        }
        
        # Save
        self._save_report(report)
        
        return report
    
    def _save_report(self, report: Dict) -> None:
        """Save report to file."""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filepath = DATA_DIR / f'eia_report_{timestamp}.json'
        
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2)
        
        # Also save latest
        latest = DATA_DIR / 'latest_eia.json'
        with open(latest, 'w') as f:
            json.dump(report, f, indent=2)

def main():
    """Run EIA monitor."""
    print("🛢️ EIA Monitor")
    print("="*50)
    
    monitor = EIAMonitor()
    
    if not monitor.api_key:
        print("\n⚠️  EIA_API_KEY not set")
        print("Get free API key: https://www.eia.gov/opendata/register.php")
        print("\nThen run:")
        print("  export EIA_API_KEY='your_key'")
        print("  python eia_monitor.py")
        return
    
    report = monitor.get_full_report()
    
    print(f"\nReport generated: {report['timestamp']}")
    print(f"Source: {report['source']}\n")
    
    if 'error' not in report:
        for key, value in report['data'].items():
            if 'error' not in value:
                print(f"{key.upper()}:")
                for k, v in value.items():
                    print(f"  {k}: {v}")
                print()

if __name__ == '__main__':
    main()
