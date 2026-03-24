"""
Trump Tracker Module - Integrated with Dashboard
Provides real-time Trump monitoring and volatility attribution
"""

import json
import os
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any

BASE_DIR = Path(__file__).parent.parent
TRUMP_DATA_DIR = BASE_DIR / 'data' / 'trump_monitor'

def get_latest_trump_analysis() -> Optional[Dict[str, Any]]:
    """Get the most recent Trump analysis from data files."""
    try:
        # Look for trump_analysis files
        analysis_files = sorted(
            TRUMP_DATA_DIR.glob('trump_analysis_*.json'),
            key=lambda x: x.stat().st_mtime,
            reverse=True
        )
        
        if analysis_files:
            with open(analysis_files[0]) as f:
                data = json.load(f)
                return data.get('trump_factor', {})
    except Exception as e:
        print(f"Error loading Trump analysis: {e}")
    
    return None

def get_trump_volatility_contributors() -> List[Dict[str, Any]]:
    """
    Analyze what factors are contributing to Trump-induced volatility.
    Returns list of factors with impact scores.
    """
    analysis = get_latest_trump_analysis()
    if not analysis:
        return []
    
    contributors = []
    
    # Priority posts analysis
    priority_posts = analysis.get('priority_posts', [])
    
    for post in priority_posts:
        content = post.get('content', '').lower()
        
        # Identify specific volatility drivers
        if any(word in content for word in ['drill', 'drilling', 'fracking', 'production']):
            contributors.append({
                'factor': 'Production Policy',
                'description': 'Trump pushing for increased domestic oil production',
                'impact': post.get('impact_score', 50),
                'sentiment': 'bearish_price',
                'source': post.get('source', 'Unknown'),
                'timestamp': post.get('timestamp', '')
            })
        
        if any(word in content for word in ['sanctions', 'iran', 'venezuela', 'embargo']):
            contributors.append({
                'factor': 'Supply Constraints',
                'description': 'Sanctions or restrictions on oil-producing nations',
                'impact': post.get('impact_score', 50),
                'sentiment': 'bullish_price',
                'source': post.get('source', 'Unknown'),
                'timestamp': post.get('timestamp', '')
            })
        
        if any(word in content for word in ['tariffs', 'trade war', 'import', 'export']):
            contributors.append({
                'factor': 'Trade Policy',
                'description': 'Tariffs or trade restrictions affecting oil markets',
                'impact': post.get('impact_score', 50),
                'sentiment': 'mixed',
                'source': post.get('source', 'Unknown'),
                'timestamp': post.get('timestamp', '')
            })
        
        if any(word in content for word in ['energy dominance', 'energy independent', 'domination']):
            contributors.append({
                'factor': 'Energy Dominance',
                'description': 'Strategic push for US energy independence',
                'impact': post.get('impact_score', 50),
                'sentiment': 'bearish_price',
                'source': post.get('source', 'Unknown'),
                'timestamp': post.get('timestamp', '')
            })
        
        if any(word in content for word in ['pipeline', 'keystone', 'infrastructure']):
            contributors.append({
                'factor': 'Infrastructure',
                'description': 'Pipeline or infrastructure policy changes',
                'impact': post.get('impact_score', 50),
                'sentiment': 'mixed',
                'source': post.get('source', 'Unknown'),
                'timestamp': post.get('timestamp', '')
            })
    
    # Sort by impact
    contributors.sort(key=lambda x: x['impact'], reverse=True)
    
    return contributors

def get_trump_metrics() -> Dict[str, Any]:
    """Get comprehensive Trump metrics for dashboard."""
    analysis = get_latest_trump_analysis()
    contributors = get_trump_volatility_contributors()
    
    if not analysis:
        return {
            'active': False,
            'score': 0,
            'level': 'none',
            'sentiment': 'neutral',
            'relevant_posts': 0,
            'explanation': 'No Trump activity detected',
            'contributors': [],
            'last_updated': datetime.now().isoformat()
        }
    
    return {
        'active': True,
        'score': analysis.get('trump_factor_score', 0),
        'level': analysis.get('level', 'none'),
        'sentiment': analysis.get('sentiment', 'neutral'),
        'relevant_posts': analysis.get('relevant_items', 0),
        'truth_social_count': analysis.get('truth_social_count', 0),
        'explanation': analysis.get('explanation', ''),
        'contributors': contributors[:5],  # Top 5 contributors
        'priority_posts': analysis.get('priority_posts', [])[:3],
        'last_updated': datetime.now().isoformat()
    }

def calculate_volatility_attribution(oil_reports: Dict[str, List[Dict]]) -> Dict[str, Any]:
    """
    Calculate how much of current volatility is attributed to Trump vs other factors.
    """
    trump = get_latest_trump_analysis()
    
    if not trump:
        return {
            'trump_attribution': 0,
            'market_attribution': 100,
            'geopolitical_attribution': 0,
            'breakdown': {
                'trump_factor': 0,
                'market_dynamics': 100,
                'geopolitical': 0,
                'technical': 0
            }
        }
    
    trump_score = trump.get('trump_factor_score', 0)
    
    # Get volatility from oil reports
    avg_volatility = 50  # Default
    for asset, reports in oil_reports.items():
        if reports and reports[0].get('data'):
            vol = reports[0]['data'].get('volatility_score', 50)
            avg_volatility = vol
            break
    
    # Calculate attribution (simplified model)
    # Trump factor contributes based on its score relative to other factors
    trump_attribution = min(trump_score * 0.6, 60)  # Cap at 60%
    
    remaining = 100 - trump_attribution
    market_attribution = remaining * 0.5  # 50% of remaining
    geopolitical_attribution = remaining * 0.3  # 30% of remaining
    technical_attribution = remaining * 0.2  # 20% of remaining
    
    return {
        'trump_attribution': round(trump_attribution, 1),
        'market_attribution': round(market_attribution, 1),
        'geopolitical_attribution': round(geopolitical_attribution, 1),
        'technical_attribution': round(technical_attribution, 1),
        'breakdown': {
            'trump_factor': round(trump_attribution, 1),
            'market_dynamics': round(market_attribution, 1),
            'geopolitical': round(geopolitical_attribution, 1),
            'technical': round(technical_attribution, 1)
        }
    }
