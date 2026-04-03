#!/usr/bin/env python3
"""
Trump Meter - Donald Trump Activity Tracker
Measures Trump's market-moving activity on a scale of 0 (quiet) to 10 (maximum chaos)
"""

import json
import random
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent
TRUMP_METER_FILE = BASE_DIR / 'data' / 'geopolitical' / 'trump_meter.json'

def calculate_trump_meter():
    """
    Calculate Trump's current market impact level.
    0 = Minimal activity/impact
    5 = Normal presidential activity
    10 = Maximum chaos/market-moving events
    """
    
    # Base factors that influence Trump's market impact
    factors = {
        'tariff_activity': 0.0,  # 0-2 points
        'social_media_volume': 0.0,  # 0-2 points
        'policy_announcements': 0.0,  # 0-2 points
        'market_tweets': 0.0,  # 0-2 points
        'geopolitical_comments': 0.0,  # 0-2 points
    }
    
    # Simulate current Trump activity (in production, this would scrape Twitter/news)
    # For now, using realistic ranges based on typical patterns
    
    # Tariff activity (currently high due to ongoing trade war)
    factors['tariff_activity'] = 1.8  # High tariff activity
    
    # Social media presence
    factors['social_media_volume'] = 1.5  # Very active
    
    # Policy announcements
    factors['policy_announcements'] = 1.2  # Several recent announcements
    
    # Market-specific tweets/comments
    factors['market_tweets'] = 1.7  # Very active on markets
    
    # Geopolitical commentary
    factors['geopolitical_comments'] = 1.5  # Active on Iran/Israel
    
    total_score = sum(factors.values())
    
    # Add volatility multiplier based on time of day (Trump is more active during US hours)
    current_hour = datetime.now(timezone.utc).hour
    if 12 <= current_hour <= 22:  # US trading hours
        total_score += 0.5
    
    # Cap at 10
    trump_meter = min(10.0, round(total_score, 1))
    
    return trump_meter, factors

def get_trump_impact_description(meter):
    """Get description of current Trump activity level."""
    if meter <= 2.0:
        return {
            'level': 'Quiet',
            'description': 'Minimal Trump activity. Markets breathing easy.',
            'impact': 'Low volatility expected.',
            'recommendation': 'Normal trading strategies.'
        }
    elif meter <= 4.0:
        return {
            'level': 'Active',
            'description': 'Standard presidential activity. Occasional market comments.',
            'impact': 'Mild volatility possible.',
            'recommendation': 'Monitor social media for surprises.'
        }
    elif meter <= 6.0:
        return {
            'level': 'Energized',
            'description': 'Multiple tweets/statements. Policy discussions active.',
            'impact': 'Moderate volatility expected.',
            'recommendation': 'Widen stop losses. Reduce position sizes by 10%.'
        }
    elif meter <= 8.0:
        return {
            'level': 'Volatile',
            'description': 'High activity. Multiple market-moving statements likely.',
            'impact': 'High volatility expected.',
            'recommendation': 'Reduce position sizes by 25%. Avoid new entries.'
        }
    else:
        return {
            'level': 'MAXIMUM CHAOS',
            'description': 'Peak Trump activity. Major policy announcements or conflicts.',
            'impact': 'Extreme volatility guaranteed.',
            'recommendation': 'CLOSE POSITIONS. Wait for stability. Cash is king.'
        }

def update_trump_meter():
    """Update Trump meter in data file."""
    TRUMP_METER_FILE.parent.mkdir(parents=True, exist_ok=True)
    
    meter, factors = calculate_trump_meter()
    impact = get_trump_impact_description(meter)
    
    trump_data = {
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'trump_meter': meter,
        'level': impact['level'],
        'description': impact['description'],
        'market_impact': impact['impact'],
        'trading_recommendation': impact['recommendation'],
        'factors': factors,
        'last_updated': datetime.now(timezone.utc).isoformat()
    }
    
    # Load existing history
    history = []
    if TRUMP_METER_FILE.exists():
        try:
            with open(TRUMP_METER_FILE) as f:
                existing = json.load(f)
                history = existing.get('history', [])[-99:]  # Keep last 100 readings
        except:
            pass
    
    history.append({
        'timestamp': trump_data['timestamp'],
        'meter': meter,
        'level': impact['level']
    })
    
    trump_data['history'] = history
    
    with open(TRUMP_METER_FILE, 'w') as f:
        json.dump(trump_data, f, indent=2)
    
    return trump_data

def main():
    """Run Trump meter update."""
    print("🎺 Trump Meter Update")
    print("=" * 40)
    
    data = update_trump_meter()
    
    # Visual meter bar
    meter_int = int(data['trump_meter'])
    bar = '█' * meter_int + '░' * (10 - meter_int)
    
    print(f"\nCurrent Level: {data['trump_meter']}/10")
    print(f"[{bar}]")
    print(f"Status: {data['level']}")
    print(f"\n{data['description']}")
    print(f"\nMarket Impact: {data['market_impact']}")
    print(f"\nTrading Recommendation:")
    print(f"  {data['trading_recommendation']}")
    
    print(f"\n📁 Saved to: {TRUMP_METER_FILE}")
    
    return data['trump_meter']

if __name__ == '__main__':
    main()