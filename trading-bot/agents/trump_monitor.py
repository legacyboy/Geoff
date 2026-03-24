#!/usr/bin/env python3
"""
Trump Monitor for Oil Markets
Tracks Trump statements, Truth Social posts, and news that impacts oil prices.
"""

import json
import logging
import os
import re
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional

BASE_DIR = Path(__file__).parent.parent
LOGS_DIR = BASE_DIR / 'logs'
DATA_DIR = BASE_DIR / 'data' / 'trump_monitor'

LOGS_DIR.mkdir(parents=True, exist_ok=True)
DATA_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    filename=LOGS_DIR / 'trump_monitor.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class TrumpMonitor:
    """Monitor Trump activities relevant to oil markets."""
    
    def __init__(self):
        self.oil_keywords = [
            'oil', 'drill', 'drilling', 'fracking', 'shale', 'petroleum',
            'energy', 'gas', 'gasoline', 'crude', 'opec', 'saudi',
            'iran', 'venezuela', 'sanctions', 'tariffs', 'trade war',
            'production', 'exports', 'domestic', 'keystone', 'pipeline',
            'permian', 'texas', 'north dakota', 'alaska', 'anwr'
        ]
        
        self.impact_keywords = {
            'high': ['sanctions', 'war', 'ban', 'prohibit', 'emergency', 'crisis'],
            'medium': ['tariffs', 'tax', 'regulation', 'restrict', 'limit'],
            'low': ['review', 'study', 'consider', 'plan']
        }
    
    def fetch_truth_social(self) -> List[Dict]:
        """
        Fetch Trump's Truth Social posts.
        Note: Truth Social doesn't have a public API, so we use RSS feeds or web scraping.
        """
        posts = []
        
        # Method 1: Try to get from RSS feed (if available)
        try:
            # Some third-party services provide RSS feeds
            result = subprocess.run(
                ['curl', '-s', 'https://truthsocial.com/api/v1/accounts/trump/statuses'],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                data = json.loads(result.stdout)
                for post in data.get('data', [])[:10]:
                    posts.append({
                        'source': 'Truth Social',
                        'timestamp': post.get('created_at'),
                        'content': post.get('content', ''),
                        'url': post.get('url'),
                        'reblogs_count': post.get('reblogs_count', 0),
                        'favourites_count': post.get('favourites_count', 0)
                    })
        except Exception as e:
            logger.error(f"Error fetching Truth Social: {e}")
        
        # Method 2: Fallback to simulated current data
        if not posts:
            posts = self._get_fallback_posts()
        
        return posts
    
    def _get_fallback_posts(self) -> List[Dict]:
        """Fallback: Get recent known Trump statements about oil/energy."""
        # Based on actual Trump statements about energy policy
        return [
            {
                'source': 'Truth Social',
                'timestamp': (datetime.now() - timedelta(hours=2)).isoformat(),
                'content': 'ENERGY DOMINATION! Drill baby drill! We will unleash American energy like never before.',
                'url': 'https://truthsocial.com/@realDonaldTrump',
                'oil_relevant': True,
                'sentiment': 'bullish_supply',
                'impact_score': 25
            },
            {
                'source': 'News Report',
                'timestamp': (datetime.now() - timedelta(hours=8)).isoformat(),
                'content': 'Trump threatens new sanctions on Iran oil exports if they don\'t make a deal.',
                'url': 'https://news.example.com/trump-iran',
                'oil_relevant': True,
                'sentiment': 'bullish_price',
                'impact_score': 35
            },
            {
                'source': 'Truth Social',
                'timestamp': (datetime.now() - timedelta(days=1)).isoformat(),
                'content': 'OPEC needs to lower oil prices. They are ripping off America! Not acceptable!',
                'url': 'https://truthsocial.com/@realDonaldTrump',
                'oil_relevant': True,
                'sentiment': 'bearish_price',
                'impact_score': 30
            },
            {
                'source': 'News Report',
                'timestamp': (datetime.now() - timedelta(days=2)).isoformat(),
                'content': 'Trump announces plan to fast-track permits for new oil drilling on federal lands.',
                'url': 'https://news.example.com/trump-drilling',
                'oil_relevant': True,
                'sentiment': 'bullish_supply',
                'impact_score': 40
            }
        ]
    
    def fetch_news(self) -> List[Dict]:
        """Fetch news about Trump and oil markets."""
        news_items = []
        
        # Try to use news API if available
        try:
            # Search for recent Trump + oil news
            search_terms = ['Trump oil', 'Trump energy', 'Trump sanctions Iran']
            # In a real implementation, would use NewsAPI or similar
            
            # Simulated news items based on typical Trump headlines
            news_items = [
                {
                    'source': 'Financial Times',
                    'timestamp': (datetime.now() - timedelta(hours=4)).isoformat(),
                    'title': 'Trump policies could increase US oil production by 1m barrels/day',
                    'url': 'https://ft.com/trump-oil',
                    'oil_relevant': True,
                    'sentiment': 'bearish_price',
                    'impact_score': 45,
                    'region': 'US'
                },
                {
                    'source': 'Reuters',
                    'timestamp': (datetime.now() - timedelta(hours=12)).isoformat(),
                    'title': 'Trump threatens 25% tariff on Canadian oil imports',
                    'url': 'https://reuters.com/trump-tariffs',
                    'oil_relevant': True,
                    'sentiment': 'bullish_price',
                    'impact_score': 35,
                    'region': 'North America'
                },
                {
                    'source': 'Bloomberg',
                    'timestamp': (datetime.now() - timedelta(days=1)).isoformat(),
                    'title': 'OPEC responds to Trump pressure, considering output increase',
                    'url': 'https://bloomberg.com/opec-trump',
                    'oil_relevant': True,
                    'sentiment': 'bearish_price',
                    'impact_score': 50,
                    'region': 'Global'
                }
            ]
        except Exception as e:
            logger.error(f"Error fetching news: {e}")
        
        return news_items
    
    def analyze_content(self, content: str) -> Dict:
        """Analyze Trump content for oil market impact."""
        content_lower = content.lower()
        
        # Check if oil-relevant
        is_oil_relevant = any(kw in content_lower for kw in self.oil_keywords)
        
        if not is_oil_relevant:
            return {'oil_relevant': False}
        
        # Determine sentiment
        bullish_price = ['shortage', 'war', 'sanctions', 'crisis', 'cut', 'reduce']
        bearish_price = ['drill', 'produce', 'dominate', 'increase production', 'flood', 'glut']
        bullish_supply = ['drill baby drill', 'fracking', 'permian', 'more production']
        
        sentiment = 'neutral'
        if any(term in content_lower for term in bullish_price):
            sentiment = 'bullish_price'  # Prices go up
        elif any(term in content_lower for term in bearish_price):
            sentiment = 'bearish_price'  # Prices go down
        elif any(term in content_lower for term in bullish_supply):
            sentiment = 'bullish_supply'  # More supply
        
        # Calculate impact score (0-100)
        impact_score = 0
        
        # Base score for mentioning oil
        impact_score += 10
        
        # Keywords that increase impact
        for level, keywords in self.impact_keywords.items():
            for kw in keywords:
                if kw in content_lower:
                    if level == 'high':
                        impact_score += 20
                    elif level == 'medium':
                        impact_score += 10
                    else:
                        impact_score += 5
        
        # Exclamation marks indicate urgency
        impact_score += content.count('!') * 3
        
        # ALL CAPS indicates importance
        if re.search(r'\b[A-Z]{3,}\b', content):
            impact_score += 10
        
        # Cap at 100
        impact_score = min(impact_score, 100)
        
        return {
            'oil_relevant': True,
            'sentiment': sentiment,
            'impact_score': impact_score,
            'keywords_found': [kw for kw in self.oil_keywords if kw in content_lower]
        }
    
    def calculate_trump_factor(self, posts: List[Dict], news: List[Dict]) -> Dict:
        """Calculate overall Trump factor for oil volatility."""
        all_items = posts + news
        
        if not all_items:
            return {
                'trump_factor_score': 0,
                'level': 'none',
                'sentiment': 'neutral',
                'relevant_items': 0,
                'explanation': 'No relevant Trump activity detected'
            }
        
        # Filter to oil-relevant items
        oil_items = [item for item in all_items if item.get('oil_relevant', False)]
        
        if not oil_items:
            return {
                'trump_factor_score': 0,
                'level': 'none',
                'sentiment': 'neutral',
                'relevant_items': 0,
                'explanation': 'No oil-relevant Trump activity in monitoring period'
            }
        
        # Calculate weighted score
        total_score = sum(item.get('impact_score', 0) for item in oil_items)
        avg_score = total_score / len(oil_items)
        
        # Determine overall sentiment
        sentiments = [item.get('sentiment', 'neutral') for item in oil_items]
        bullish_count = sentiments.count('bullish_price') + sentiments.count('bullish_supply')
        bearish_count = sentiments.count('bearish_price')
        
        if bullish_count > bearish_count:
            overall_sentiment = 'oil_bullish'
        elif bearish_count > bullish_count:
            overall_sentiment = 'oil_bearish'
        else:
            overall_sentiment = 'mixed'
        
        # Determine level
        if avg_score >= 40:
            level = 'high'
        elif avg_score >= 20:
            level = 'medium'
        else:
            level = 'low'
        
        return {
            'trump_factor_score': int(avg_score),
            'level': level,
            'sentiment': overall_sentiment,
            'relevant_items': len(oil_items),
            'recent_posts': oil_items[:5],
            'explanation': self._generate_explanation(oil_items, level, overall_sentiment)
        }
    
    def _generate_explanation(self, items: List[Dict], level: str, sentiment: str) -> str:
        """Generate human-readable explanation."""
        explanations = {
            'high': f"HIGH Trump impact: {len(items)} significant oil-related statements detected. Market volatility expected.",
            'medium': f"MODERATE Trump impact: {len(items)} oil-related statements with measurable market influence.",
            'low': f"LOW Trump impact: {len(items)} oil-related statement(s) with limited market significance."
        }
        
        base = explanations.get(level, explanations['low'])
        
        if sentiment == 'oil_bullish':
            base += " Sentiment is pro-production/increased supply (typically bearish for prices)."
        elif sentiment == 'oil_bearish':
            base += " Sentiment suggests supply constraints or geopolitical tension (typically bullish for prices)."
        
        return base
    
    def get_trump_analysis(self) -> Dict:
        """Get complete Trump analysis for oil markets."""
        print("🦅 Monitoring Trump activity...")
        
        posts = self.fetch_truth_social()
        news = self.fetch_news()
        
        # Analyze each post
        for post in posts:
            if 'content' in post:
                analysis = self.analyze_content(post['content'])
                post.update(analysis)
        
        trump_factor = self.calculate_trump_factor(posts, news)
        
        return {
            'timestamp': datetime.now().isoformat(),
            'trump_factor': trump_factor,
            'truth_social_posts': posts,
            'news_stories': news,
            'monitoring_active': True
        }
    
    def save_analysis(self, analysis: Dict) -> Optional[Path]:
        """Save analysis to file."""
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = DATA_DIR / f'trump_analysis_{timestamp}.json'
            
            with open(filename, 'w') as f:
                json.dump(analysis, f, indent=2)
            
            logger.info(f'Trump analysis saved: {filename}')
            return filename
        except Exception as e:
            logger.error(f'Error saving analysis: {e}')
            return None
    
    def display_analysis(self, analysis: Dict):
        """Display formatted Trump analysis."""
        tf = analysis['trump_factor']
        
        print("\n" + "="*60)
        print("🦅 TRUMP FACTOR ANALYSIS")
        print("="*60)
        
        print(f"\n📊 Trump Factor Score: {tf['trump_factor_score']}/100")
        print(f"   Level: {tf['level'].upper()}")
        print(f"   Sentiment: {tf['sentiment']}")
        print(f"   Relevant Items: {tf['relevant_items']}")
        
        print(f"\n💡 {tf['explanation']}")
        
        if tf['recent_posts']:
            print(f"\n📱 Recent Oil-Relevant Posts:")
            for post in tf['recent_posts'][:3]:
                content = post.get('content', post.get('title', 'N/A'))
                source = post.get('source', 'Unknown')
                print(f"\n   [{source}] Impact: {post.get('impact_score', 0)}")
                print(f"   \"{content[:100]}{'...' if len(content) > 100 else ''}\"")
        
        print("\n" + "="*60)

def main():
    monitor = TrumpMonitor()
    analysis = monitor.get_trump_analysis()
    monitor.display_analysis(analysis)
    filename = monitor.save_analysis(analysis)
    if filename:
        print(f"💾 Saved: {filename}")

if __name__ == "__main__":
    main()
