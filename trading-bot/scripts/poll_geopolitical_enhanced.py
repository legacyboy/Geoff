#!/usr/bin/env python3
"""
Enhanced Geopolitical News Polling with Search Module Integration
Uses SerpAPI for real-time news validation.
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

# Add workspace to path for search module
sys.path.insert(0, '/home/claw/.openclaw/workspace')
from search_module import web_search

BASE_DIR = Path(__file__).parent.parent
INTELLIGENCE_FILE = BASE_DIR / 'data' / 'geopolitical' / 'intelligence.json'

def poll_geopolitical_with_search():
    """Poll geopolitical news using search module."""
    print(f"[{datetime.now(timezone.utc).isoformat()}] Starting enhanced geopolitical news poll...")
    
    # Search for current geopolitical risks
    searches = [
        'Iran Israel conflict Strait Hormuz 2026',
        'Trump tariff policy market impact 2026',
        'oil supply disruption news',
        'Middle East escalation'
    ]
    
    findings = []
    for query in searches[:2]:  # Limit to 2 searches to save API quota
        results = web_search(query, num_results=3)
        for r in results:
            findings.append({
                'source': r['title'],
                'url': r['url'],
                'summary': r.get('snippet', '')[:200]
            })
    
    # Determine threat level based on findings
    threat_keywords = {
        'CRITICAL': ['war', 'attack', 'strike', 'invasion', 'closure', 'embargo'],
        'HIGH': ['tension', 'sanctions', 'dispute', 'crisis'],
        'MEDIUM': ['concern', 'warning', 'risk'],
        'LOW': ['negotiation', 'peace', 'agreement']
    }
    
    all_text = ' '.join([f['summary'].lower() for f in findings])
    
    threat_level = 'LOW'
    for level, keywords in threat_keywords.items():
        if any(kw in all_text for kw in keywords):
            threat_level = level
            break
    
    # Determine primary risk
    if 'hormuz' in all_text or 'iran' in all_text or 'israel' in all_text:
        primary_risk = 'Iran-Israel conflict / Strait of Hormuz closure'
    elif 'trump' in all_text or 'tariff' in all_text:
        primary_risk = 'US trade policy uncertainty'
    else:
        primary_risk = 'General geopolitical instability'
    
    # Position sizing based on threat
    sizing = {
        'CRITICAL': 'Reduce to 25% of normal (CRITICAL + Trump MAXIMUM CHAOS)',
        'HIGH': 'Reduce to 50% of normal',
        'MEDIUM': 'Reduce to 75% of normal',
        'LOW': 'Normal position sizing'
    }
    
    intelligence = {
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'threat_level': threat_level,
        'primary_risk': primary_risk,
        'position_sizing': sizing.get(threat_level, 'Normal sizing'),
        'recent_findings': findings[:5],
        'search_sources': len(findings)
    }
    
    # Save to file
    INTELLIGENCE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(INTELLIGENCE_FILE, 'w') as f:
        json.dump(intelligence, f, indent=2)
    
    print(f"[{datetime.now(timezone.utc).isoformat()}] Threat level: {threat_level}")
    print(f"[{datetime.now(timezone.utc).isoformat()}] Primary risk: {primary_risk}")
    print(f"[{datetime.now(timezone.utc).isoformat()}] Position sizing: {sizing.get(threat_level)}")
    print(f"[{datetime.now(timezone.utc).isoformat()}] Enhanced intelligence updated successfully")
    print(f"[{datetime.now(timezone.utc).isoformat()}] Sources analyzed: {len(findings)}")

if __name__ == '__main__':
    poll_geopolitical_with_search()
