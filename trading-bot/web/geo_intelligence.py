"""
Geopolitical Intelligence Integration for Dashboard
Provides real-time geo-political data to the web interface.
"""

import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any

BASE_DIR = Path(__file__).parent.parent
GEOPOLITICAL_DIR = BASE_DIR / 'data' / 'geopolitical'

def get_geopolitical_intelligence() -> Dict[str, Any]:
    """Get latest geopolitical intelligence report."""
    try:
        intel_file = GEOPOLITICAL_DIR / 'intelligence.json'
        if intel_file.exists():
            with open(intel_file) as f:
                return json.load(f)
    except Exception as e:
        print(f"Error loading geopolitical intelligence: {e}")
    
    return {
        'timestamp': datetime.now().isoformat(),
        'summary': {
            'total_events_24h': 0,
            'critical_events': 0,
            'threat_level': 'LOW',
            'primary_concerns': []
        },
        'attribution': {
            'trump': 0,
            'opec': 0,
            'conflicts': 0,
            'sanctions': 0,
            'other': 100
        },
        'threat_levels': {
            'overall': 'LOW',
            'trump_factor': 'LOW',
            'opec_stability': 'LOW',
            'conflict_risk': 'LOW',
            'sanctions_risk': 'LOW'
        },
        'key_factors': [],
        'supply_risks': [],
        'recent_events': []
    }

def get_trump_intelligence() -> Dict[str, Any]:
    """Get Trump-specific intelligence."""
    intel = get_geopolitical_intelligence()
    
    trump_data = intel.get('trump_activity', {})
    
    return {
        'active': trump_data.get('statements_24h', 0) > 0,
        'statements_24h': trump_data.get('statements_24h', 0),
        'impact_score': trump_data.get('impact_score', 0),
        'latest_statement': trump_data.get('latest_statement'),
        'attribution_pct': intel.get('attribution', {}).get('trump', 0),
        'threat_level': intel.get('threat_levels', {}).get('trump_factor', 'LOW'),
        'key_factors': [f for f in intel.get('key_factors', []) if f.get('factor') == 'Trump Activity']
    }

def get_volatility_breakdown() -> Dict[str, Any]:
    """Get detailed volatility attribution breakdown."""
    intel = get_geopolitical_intelligence()
    attribution = intel.get('attribution', {})
    
    return {
        'trump': {
            'pct': attribution.get('trump', 0),
            'description': 'Trump statements and policy announcements',
            'color': '#e74c3c' if attribution.get('trump', 0) > 30 else '#f39c12' if attribution.get('trump', 0) > 10 else '#00d4aa',
            'icon': '🦅'
        },
        'opec': {
            'pct': attribution.get('opec', 0),
            'description': 'OPEC production decisions and announcements',
            'color': '#3498db',
            'icon': '🛢️'
        },
        'conflicts': {
            'pct': attribution.get('conflicts', 0),
            'description': 'Geopolitical conflicts in oil-producing regions',
            'color': '#e74c3c',
            'icon': '⚔️'
        },
        'sanctions': {
            'pct': attribution.get('sanctions', 0),
            'description': 'Sanctions affecting oil-exporting nations',
            'color': '#9b59b6',
            'icon': '🚫'
        },
        'other': {
            'pct': attribution.get('other', 0),
            'description': 'Other market factors (supply/demand, technicals)',
            'color': '#95a5a6',
            'icon': '📊'
        }
    }

def get_active_threats() -> List[Dict[str, Any]]:
    """Get list of active geopolitical threats."""
    intel = get_geopolitical_intelligence()
    
    threats = []
    
    # Add threat level indicators
    threat_levels = intel.get('threat_levels', {})
    
    if threat_levels.get('trump_factor') in ['HIGH', 'CRITICAL']:
        threats.append({
            'type': 'trump',
            'level': threat_levels['trump_factor'],
            'title': 'High Trump Activity',
            'description': 'Significant Trump statements affecting oil markets',
            'icon': '🦅',
            'action_required': threat_levels['trump_factor'] == 'CRITICAL'
        })
    
    if threat_levels.get('conflict_risk') in ['HIGH', 'CRITICAL']:
        threats.append({
            'type': 'conflict',
            'level': threat_levels['conflict_risk'],
            'title': 'Geopolitical Conflict',
            'description': 'Active conflicts in oil-producing regions',
            'icon': '⚔️',
            'action_required': threat_levels['conflict_risk'] == 'CRITICAL'
        })
    
    if threat_levels.get('sanctions_risk') in ['HIGH', 'CRITICAL']:
        threats.append({
            'type': 'sanctions',
            'level': threat_levels['sanctions_risk'],
            'title': 'Sanctions Risk',
            'description': 'New or modified sanctions affecting oil trade',
            'icon': '🚫',
            'action_required': threat_levels['sanctions_risk'] == 'CRITICAL'
        })
    
    # Add supply risks
    for risk in intel.get('supply_risks', []):
        if risk.get('risk_level') in ['HIGH', 'CRITICAL']:
            threats.append({
                'type': 'supply',
                'level': risk['risk_level'],
                'title': f"{risk['region']} Supply Risk",
                'description': f"{risk['pct_global_supply']}% of global supply at risk",
                'icon': '⚠️',
                'action_required': risk['risk_level'] == 'CRITICAL',
                'details': risk
            })
    
    return threats

def get_key_contributors() -> List[Dict[str, Any]]:
    """Get key contributors to current volatility."""
    intel = get_geopolitical_intelligence()
    
    contributors = intel.get('key_factors', [])
    
    # Add recent events as contributors
    recent_events = intel.get('recent_events', [])[:5]
    for event in recent_events:
        contributors.append({
            'factor': event.get('title', 'Unknown Event'),
            'impact': event.get('impact_level', 1) * 20,  # Scale to 0-100
            'description': event.get('description', '')[:100],
            'timestamp': event.get('timestamp', ''),
            'type': event.get('event_type', 'unknown')
        })
    
    # Sort by impact
    contributors.sort(key=lambda x: x.get('impact', 0), reverse=True)
    
    return contributors[:8]  # Top 8 contributors

def format_for_dashboard() -> Dict[str, Any]:
    """Format all intelligence for dashboard display."""
    intel = get_geopolitical_intelligence()
    
    return {
        'overview': {
            'threat_level': intel.get('summary', {}).get('threat_level', 'LOW'),
            'critical_events': intel.get('summary', {}).get('critical_events', 0),
            'total_events': intel.get('summary', {}).get('total_events_24h', 0),
            'last_updated': intel.get('timestamp', datetime.now().isoformat())
        },
        'trump': get_trump_intelligence(),
        'volatility_breakdown': get_volatility_breakdown(),
        'active_threats': get_active_threats(),
        'key_contributors': get_key_contributors(),
        'recent_events': intel.get('recent_events', [])[:5],
        'supply_risks': intel.get('supply_risks', [])
    }
