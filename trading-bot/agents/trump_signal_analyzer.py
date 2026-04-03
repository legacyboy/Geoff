#!/usr/bin/env python3
"""
Trump Signal Analyzer - Reads DB and generates trade decisions
Run after scraper to get actionable signals
"""

import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional

BASE_DIR = Path(__file__).parent.parent
DB_PATH = BASE_DIR / 'data' / 'trading.db'

class TrumpSignalAnalyzer:
    """Analyzes Trump posts and generates trade decisions."""
    
    def __init__(self):
        self.signals = []
        
    def _get_db(self) -> sqlite3.Connection:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        return conn
    
    def get_recent_high_impact(self, hours: int = 6, min_score: int = 40) -> List[Dict]:
        """Get high-impact posts from recent hours."""
        with self._get_db() as conn:
            cur = conn.execute("""
                SELECT * FROM trump_posts 
                WHERE oil_relevant = 1 
                AND impact_score >= ?
                AND timestamp > datetime('now', '-{} hours')
                ORDER BY impact_score DESC, timestamp DESC
            """.format(hours), (min_score,))
            return [dict(row) for row in cur.fetchall()]
    
    def get_unacted_signals(self) -> List[Dict]:
        """Get signals we haven't acted on yet."""
        with self._get_db() as conn:
            # Get signals not already in trades table
            cur = conn.execute("""
                SELECT tp.* FROM trump_posts tp
                WHERE tp.oil_relevant = 1
                AND tp.impact_score >= 40
                AND tp.trade_signal != 'HOLD'
                AND tp.trade_signal != 'MONITOR'
                AND NOT EXISTS (
                    SELECT 1 FROM trades t 
                    WHERE t.signal LIKE '%trump%'
                    AND t.timestamp > tp.timestamp
                )
                ORDER BY tp.impact_score DESC
            """)
            return [dict(row) for row in cur.fetchall()]
    
    def calculate_trump_factor(self, posts: List[Dict]) -> Dict[str, Any]:
        """Calculate overall Trump market factor."""
        if not posts:
            return {
                'score': 0,
                'level': 'none',
                'sentiment': 'neutral',
                'action': 'HOLD'
            }
        
        # Weight by recency and impact
        total_weight = 0
        sentiment_score = 0
        
        for post in posts:
            weight = post['impact_score'] / 100
            
            # Recency bonus
            try:
                post_time = datetime.fromisoformat(post['timestamp'].replace('Z', '+00:00'))
                hours_ago = (datetime.now() - post_time).total_seconds() / 3600
                if hours_ago < 1:
                    weight *= 2.0
                elif hours_ago < 3:
                    weight *= 1.5
            except:
                pass
            
            if post['sentiment'] == 'bearish':
                sentiment_score -= weight
            elif post['sentiment'] == 'bullish':
                sentiment_score += weight
            
            total_weight += weight
        
        avg_sentiment = sentiment_score / total_weight if total_weight > 0 else 0
        
        # Calculate final score
        avg_impact = sum(p['impact_score'] for p in posts) / len(posts)
        trump_score = min(int(abs(avg_sentiment) * 50 + avg_impact), 100)
        
        # Determine level
        if trump_score >= 70:
            level = 'critical'
        elif trump_score >= 50:
            level = 'high'
        elif trump_score >= 30:
            level = 'medium'
        else:
            level = 'low'
        
        # Determine action
        if level in ['critical', 'high']:
            if avg_sentiment < -0.3:
                action = 'SHORT_OIL_NOW'
            elif avg_sentiment > 0.3:
                action = 'LONG_OIL_NOW'
            else:
                action = 'HEDGE_POSITION'
        elif level == 'medium':
            action = 'MONITOR_CLOSELY'
        else:
            action = 'HOLD'
        
        return {
            'score': trump_score,
            'level': level,
            'sentiment': 'bearish' if avg_sentiment < -0.2 else 'bullish' if avg_sentiment > 0.2 else 'neutral',
            'sentiment_strength': abs(avg_sentiment),
            'action': action,
            'post_count': len(posts),
            'avg_impact': round(avg_impact, 1)
        }
    
    def generate_trade_decision(self) -> Optional[Dict]:
        """Generate a concrete trade decision if warranted."""
        posts = self.get_recent_high_impact(hours=4, min_score=35)
        factor = self.calculate_trump_factor(posts)
        
        if factor['level'] in ['critical', 'high']:
            # Get the highest impact post
            top_post = max(posts, key=lambda x: x['impact_score'])
            
            decision = {
                'timestamp': datetime.now().isoformat(),
                'trigger': 'trump_statement',
                'factor_score': factor['score'],
                'level': factor['level'],
                'action': factor['action'],
                'sentiment': factor['sentiment'],
                'rationale': self._generate_rationale(factor, top_post),
                'source_post': {
                    'content': top_post['content'][:200],
                    'impact': top_post['impact_score'],
                    'urgency': top_post['urgency'],
                    'url': top_post['url']
                },
                'recommended_trade': self._get_trade_params(factor['action'])
            }
            
            return decision
        
        return None
    
    def _generate_rationale(self, factor: Dict, post: Dict) -> str:
        """Generate human-readable rationale."""
        parts = [
            f"Trump Factor {factor['score']}/100 ({factor['level'].upper()})",
            f"Sentiment: {factor['sentiment']} (strength: {factor['sentiment_strength']:.2f})",
        ]
        
        if post['urgency'] == 'immediate':
            parts.append("IMMEDIATE ACTION FLAG - executive language detected")
        
        if 'drill' in post['content'].lower() or 'produce' in post['content'].lower():
            parts.append("Pro-production stance = supply increase = price pressure")
        elif 'sanctions' in post['content'].lower() or 'ban' in post['content'].lower():
            parts.append("Supply constraint stance = bullish pressure")
        
        return " | ".join(parts)
    
    def _get_trade_params(self, action: str) -> Optional[Dict]:
        """Get trade parameters based on action."""
        params = {
            'SHORT_OIL_NOW': {
                'direction': 'SHORT',
                'symbol': 'WTICO_USD',
                'units': 100,
                'confidence': 0.85
            },
            'LONG_OIL_NOW': {
                'direction': 'LONG',
                'symbol': 'WTICO_USD',
                'units': 100,
                'confidence': 0.85
            },
            'HEDGE_POSITION': {
                'direction': 'HEDGE',
                'symbol': 'WTICO_USD',
                'units': 50,
                'confidence': 0.70
            }
        }
        return params.get(action)
    
    def get_market_summary(self) -> str:
        """Get formatted summary for display."""
        posts = self.get_recent_high_impact(hours=24, min_score=30)
        factor = self.calculate_trump_factor(posts)
        decision = self.generate_trade_decision()
        
        lines = [
            "=" * 60,
            "🦅 TRUMP SIGNAL ANALYZER",
            "=" * 60,
            f"\nTrump Factor: {factor['score']}/100 ({factor['level'].upper()})",
            f"Sentiment: {factor['sentiment']}",
            f"Posts Analyzed: {factor['post_count']}",
            f"Avg Impact: {factor['avg_impact']}",
        ]
        
        if decision:
            lines.extend([
                f"\n🚨 ACTION REQUIRED: {decision['action']}",
                f"Rationale: {decision['rationale']}",
                f"\nSource: {decision['source_post']['content'][:100]}...",
            ])
            
            if decision['recommended_trade']:
                trade = decision['recommended_trade']
                lines.append(f"\n📈 Trade: {trade['direction']} {trade['symbol']} x{trade['units']}")
        else:
            lines.extend([
                f"\n✅ No immediate action required",
                f"Current stance: {factor['action']}"
            ])
        
        if posts:
            lines.extend(["\n📋 Recent High-Impact Posts:"])
            for p in posts[:3]:
                lines.append(f"   [{p['impact_score']}] {p['content'][:60]}...")
        
        lines.append("\n" + "=" * 60)
        
        return "\n".join(lines)
    
    def run(self):
        """Main run - print analysis."""
        print(self.get_market_summary())
        
        # Return decision for programmatic use
        return self.generate_trade_decision()


if __name__ == "__main__":
    analyzer = TrumpSignalAnalyzer()
    decision = analyzer.run()
    
    if decision:
        print("\n\n📤 DECISION JSON (for bot consumption):")
        print(json.dumps(decision, indent=2))
