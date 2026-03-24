#!/usr/bin/env python3
"""
Geopolitical Monitor Service
Runs continuously, updating intelligence every 5 minutes
"""

import time
import sys
from pathlib import Path

# Add paths
BASE_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(BASE_DIR / 'agents'))
sys.path.insert(0, str(BASE_DIR / 'web'))

from geopolitical_monitor import GeopoliticalAggregator

def main():
    print("🌍 Geopolitical Monitor Service Started")
    print("Checking every 5 minutes...\n")
    
    aggregator = GeopoliticalAggregator()
    
    while True:
        try:
            report = aggregator.generate_intelligence_report()
            summary = report['summary']
            print(f"✅ Check complete: {summary['total_events_24h']} events, "
                  f"Threat: {summary['threat_level']}")
        except Exception as e:
            print(f"❌ Error: {e}")
        
        time.sleep(300)  # 5 minutes

if __name__ == '__main__':
    main()
