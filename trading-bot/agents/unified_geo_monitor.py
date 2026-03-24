#!/usr/bin/env python3
"""
Unified Geopolitical Monitor
Combines: Reddit, EIA (if key), NewsAPI (if key), Conflict data
Gracefully degrades when APIs unavailable
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any

BASE_DIR = Path(__file__).parent.parent
DATA_DIR = BASE_DIR / 'data' / 'geopolitical'

def load_available_data() -> Dict[str, Any]:
    """Load data from all available sources."""
    
    sources = {}
    
    # Reddit data (always available)
    reddit_file = DATA_DIR / 'multi_source_report_*.json'
    try:
        import subprocess
        result = subprocess.run(
            ['ls', '-t', str(reddit_file)],
            capture_output=True, text=True
        )
        if result.stdout:
            latest = result.stdout.split('\n')[0]
            with open(latest) as f:
                sources['reddit'] = json.load(f)
    except:
        sources['reddit'] = None
    
    # EIA data (if key available)
    eia_file = DATA_DIR / 'latest_eia.json'
    if eia_file.exists():
        with open(eia_file) as f:
            sources['eia'] = json.load(f)
    else:
        sources['eia'] = None
    
    # NewsAPI data (if key available)
    newsapi_file = DATA_DIR / 'latest_newsapi.json'
    if newsapi_file.exists():
        with open(newsapi_file) as f:
            sources['newsapi'] = json.load(f)
    else:
        sources['newsapi'] = None
    
    return sources

def compile_intelligence_report() -> Dict[str, Any]:
    """Compile intelligence from all sources."""
    
    sources = load_available_data()
    
    # Count available sources
    available = sum(1 for s in sources.values() if s is not None)
    total = len(sources)
    
    # Extract Trump mentions
    trump_mentions = []
    
    if sources.get('reddit') and sources['reddit'].get('trump_specific'):
        trump_mentions.extend(sources['reddit']['trump_specific'])
    
    if sources.get('newsapi') and sources['newsapi'].get('articles'):
        for art in sources['newsapi']['articles']:
            if 'trump' in art.get('title', '').lower():
                trump_mentions.append(art)
    
    # Extract oil price data
    price_data = {}
    if sources.get('eia') and 'data' in sources['eia']:
        if 'wti_price' in sources['eia']['data']:
            price_data['wti'] = sources['eia']['data']['wti_price']
    
    # Compile conflicts
    conflicts = []
    if sources.get('reddit') and sources['reddit'].get('conflicts'):
        conflicts.extend(sources['reddit']['conflicts'])
    
    report = {
        'timestamp': datetime.now().isoformat(),
        'sources_available': f"{available}/{total}",
        'source_status': {
            'reddit': '✅ Active' if sources.get('reddit') else '⏸️ Standby',
            'eia': '✅ Active' if sources.get('eia') else '⏸️ Needs EIA_API_KEY',
            'newsapi': '✅ Active' if sources.get('newsapi') else '⏸️ Needs NEWSAPI_KEY'
        },
        'summary': {
            'trump_mentions': len(trump_mentions),
            'conflicts_tracked': len(conflicts),
            'price_data_points': len(price_data),
            'total_articles': sum(len(s.get('articles', [])) for s in sources.values() if s)
        },
        'trump_activity': trump_mentions[:10],
        'conflicts': conflicts,
        'price_data': price_data,
        'recommendations': []
    }
    
    # Add recommendations
    if not sources.get('eia'):
        report['recommendations'].append({
            'priority': 'high',
            'source': 'EIA',
            'action': 'Get free API key',
            'url': 'https://www.eia.gov/opendata/register.php',
            'benefit': 'Real US oil production, inventory, price data'
        })
    
    if not sources.get('newsapi'):
        report['recommendations'].append({
            'priority': 'high',
            'source': 'NewsAPI',
            'action': 'Get free API key',
            'url': 'https://newsapi.org/register',
            'benefit': '30,000+ news sources including Trump coverage'
        })
    
    # Save report
    with open(DATA_DIR / 'unified_intelligence.json', 'w') as f:
        json.dump(report, f, indent=2)
    
    return report

def main():
    print("🌍 Unified Geopolitical Monitor")
    print("="*60)
    
    report = compile_intelligence_report()
    
    print(f"\nReport Time: {report['timestamp']}")
    print(f"Sources: {report['sources_available']}")
    
    print("\nSource Status:")
    for source, status in report['source_status'].items():
        print(f"  {source}: {status}")
    
    print(f"\nSummary:")
    print(f"  Trump mentions: {report['summary']['trump_mentions']}")
    print(f"  Conflicts: {report['summary']['conflicts_tracked']}")
    print(f"  Price data: {report['summary']['price_data_points']}")
    
    if report['recommendations']:
        print("\n⚠️  Recommended Actions:")
        for rec in report['recommendations']:
            print(f"\n  {rec['priority'].upper()} Priority")
            print(f"  Source: {rec['source']}")
            print(f"  Action: {rec['action']}")
            print(f"  URL: {rec['url']}")
            print(f"  Benefit: {rec['benefit']}")
    
    print("\n✅ Report saved")

if __name__ == '__main__':
    main()
