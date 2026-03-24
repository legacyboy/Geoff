#!/usr/bin/env python3
"""
Trump Monitor - Truth Social Priority
Tracks Trump's Truth Social account as PRIMARY source for oil market impacts.
Falls back to news aggregators and RSS feeds if direct API fails.
"""

import json
import logging
import os
import re
import subprocess
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import xml.etree.ElementTree as ET

BASE_DIR = Path(__file__).parent.parent
LOGS_DIR = BASE_DIR / 'logs'
DATA_DIR = BASE_DIR / 'data' / 'trump_monitor'
CACHE_FILE = DATA_DIR / 'trump_cache.json'
SEEN_POSTS_FILE = DATA_DIR / 'seen_posts.json'

LOGS_DIR.mkdir(parents=True, exist_ok=True)
DATA_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    filename=LOGS_DIR / 'trump_monitor.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class TrumpTruthSocialMonitor:
    """
    Priority 1: Monitor Trump's Truth Social account.
    This is where he speaks FIRST before anywhere else.
    """
    
    TRUTH_SOCIAL_USER = 'realDonaldTrump'
    TRUTH_SOCIAL_ID = '107780257626128481'  # Trump's account ID
    
    # Multiple endpoints to try (in order of preference)
    ENDPOINTS = [
        # Direct Mastodon API (Truth Social uses Mastodon)
        f'https://truthsocial.com/api/v1/accounts/{TRUTH_SOCIAL_ID}/statuses',
        # Alternative RSS feeds
        'https://truthsocial.com/@realDonaldTrump.rss',
        'https://nitter.net/realDonaldTrump/rss',
        # Fallback to third-party aggregators
        'https://rss.app/feeds/TrumpTruthSocial.xml',
    ]
    
    def __init__(self):
        self.oil_keywords = [
            'oil', 'drill', 'drilling', 'fracking', 'shale', 'petroleum',
            'energy', 'gas', 'gasoline', 'crude', 'opec', 'saudi', 'keystone',
            'iran', 'venezuela', 'sanctions', 'tariffs', 'trade war',
            'production', 'exports', 'domestic', 'pipeline', 'permian',
            'texas', 'north dakota', 'alaska', 'anwr', 'energy dominance',
            'energy independent', 'drill baby drill'
        ]
        
        self.impact_keywords = {
            'critical': ['emergency', 'crisis', 'war', 'invasion', 'attack'],
            'high': ['sanctions', 'ban', 'prohibit', 'stop', 'end'],
            'medium': ['tariffs', 'tax', 'regulation', 'restrict', 'limit'],
            'low': ['review', 'study', 'consider', 'plan', 'thinking']
        }
        
        self.seen_posts = self._load_seen_posts()
        self.last_check = None
    
    def _load_seen_posts(self) -> set:
        """Load previously seen post IDs to avoid duplicates."""
        if SEEN_POSTS_FILE.exists():
            try:
                with open(SEEN_POSTS_FILE) as f:
                    return set(json.load(f))
            except:
                pass
        return set()
    
    def _save_seen_posts(self):
        """Save seen post IDs."""
        try:
            with open(SEEN_POSTS_FILE, 'w') as f:
                json.dump(list(self.seen_posts), f)
        except Exception as e:
            logger.error(f"Error saving seen posts: {e}")
    
    def fetch_truth_social_api(self) -> List[Dict]:
        """
        PRIMARY: Fetch from Truth Social Mastodon API.
        This is the most direct source.
        """
        posts = []
        
        try:
            # Use curl to avoid Python SSL issues
            headers = [
                '-H', 'Accept: application/json',
                '-H', 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.0'
            ]
            
            result = subprocess.run(
                ['curl', '-s', '-L', '--max-time', '15'] + headers + [self.ENDPOINTS[0]],
                capture_output=True, text=True, timeout=20
            )
            
            if result.returncode == 0 and result.stdout:
                data = json.loads(result.stdout)
                
                for post in data:
                    post_id = post.get('id', '')
                    content = post.get('content', '')
                    
                    # Clean HTML from content
                    content = re.sub(r'<[^\u003e]+>', '', content)
                    content = content.strip()
                    
                    if not content:
                        continue
                    
                    posts.append({
                        'id': post_id,
                        'source': 'Truth Social (PRIMARY)',
                        'timestamp': post.get('created_at'),
                        'content': content,
                        'url': post.get('url', f'https://truthsocial.com/@realDonaldTrump/posts/{post_id}'),
                        'reblogs': post.get('reblogs_count', 0),
                        'favourites': post.get('favourites_count', 0),
                        'replies': post.get('replies_count', 0),
                        'is_new': post_id not in self.seen_posts
                    })
                    
                    self.seen_posts.add(post_id)
                
                self._save_seen_posts()
                logger.info(f"Fetched {len(posts)} posts from Truth Social API")
                
        except Exception as e:
            logger.error(f"Truth Social API error: {e}")
        
        return posts
    
    def fetch_truth_social_rss(self) -> List[Dict]:
        """
        SECONDARY: Fetch from RSS feed.
        """
        posts = []
        
        rss_urls = [
            'https://truthsocial.com/@realDonaldTrump.rss',
            'https://rsshub.app/truthsocial/user/realDonaldTrump',
        ]
        
        for rss_url in rss_urls:
            try:
                result = subprocess.run(
                    ['curl', '-s', '-L', '--max-time', '10', rss_url],
                    capture_output=True, text=True, timeout=15
                )
                
                if result.returncode == 0 and result.stdout:
                    # Parse RSS XML
                    root = ET.fromstring(result.stdout)
                    
                    # Find items
                    for item in root.findall('.//item'):
                        title = item.find('title')
                        link = item.find('link')
                        pub_date = item.find('pubDate')
                        description = item.find('description')
                        
                        content = title.text if title is not None else ''
                        if description is not None and description.text:
                            content = description.text
                        
                        post_id = link.text.split('/')[-1] if link is not None else hash(content)
                        
                        if post_id not in self.seen_posts:
                            posts.append({
                                'id': str(post_id),
                                'source': 'Truth Social RSS',
                                'timestamp': pub_date.text if pub_date is not None else datetime.now().isoformat(),
                                'content': content,
                                'url': link.text if link is not None else '',
                                'is_new': True
                            })
                            self.seen_posts.add(post_id)
                
                if posts:
                    self._save_seen_posts()
                    logger.info(f"Fetched {len(posts)} posts from RSS: {rss_url}")
                    break
                    
            except Exception as e:
                logger.error(f"RSS error for {rss_url}: {e}")
                continue
        
        return posts
    
    def fetch_backup_sources(self) -> List[Dict]:
        """
        TERTIARY: Check news aggregators and Twitter/X mirrors.
        These are delayed but capture posts that might be missed.
        """
        posts = []
        
        # Check Google News for recent Trump + oil
        try:
            news_items = self._check_news_aggregators()
            posts.extend(news_items)
        except Exception as e:
            logger.error(f"News aggregator error: {e}")
        
        return posts
    
    def _check_news_aggregators(self) -> List[Dict]:
        """Check news for Trump statements about oil."""
        posts = []
        
        # In a real implementation, would use NewsAPI
        # For now, this is a placeholder
        
        return posts
    
    def get_all_truth_posts(self, hours: int = 24) -> Tuple[List[Dict], List[Dict]]:
        """
        Get ALL Trump posts from Truth Social as priority.
        Returns: (truth_social_posts, backup_posts)
        """
        print("🦅 Checking Truth Social FIRST (Trump's primary platform)...")
        
        # Priority 1: Direct Truth Social API
        truth_posts = self.fetch_truth_social_api()
        
        if not truth_posts:
            print("   ⚠️  Direct API failed, trying RSS...")
            # Priority 2: RSS feeds
            truth_posts = self.fetch_truth_social_rss()
        
        if truth_posts:
            print(f"   ✅ Found {len(truth_posts)} posts on Truth Social")
            new_posts = [p for p in truth_posts if p.get('is_new')]
            if new_posts:
                print(f"   🆕 {len(new_posts)} NEW posts since last check")
        else:
            print("   ⚠️  No posts found on Truth Social")
        
        # Priority 3: Backup sources
        print("🔍 Checking backup news sources...")
        backup_posts = self.fetch_backup_sources()
        
        self.last_check = datetime.now()
        
        return truth_posts, backup_posts
    
    def analyze_for_oil(self, posts: List[Dict]) -> List[Dict]:
        """Analyze posts for oil market relevance."""
        analyzed = []
        
        for post in posts:
            content = post.get('content', '').lower()
            
            # Check if oil-relevant
            found_keywords = [kw for kw in self.oil_keywords if kw.lower() in content]
            
            if not found_keywords:
                continue
            
            # Calculate impact score
            impact_score = self._calculate_impact(content)
            
            # Determine sentiment
            sentiment = self._determine_sentiment(content)
            
            # Determine urgency
            urgency = self._determine_urgency(content, post)
            
            post.update({
                'oil_relevant': True,
                'oil_keywords': found_keywords,
                'impact_score': impact_score,
                'sentiment': sentiment,
                'urgency': urgency,
                'analysis_time': datetime.now().isoformat()
            })
            
            analyzed.append(post)
        
        # Sort by impact score (highest first)
        analyzed.sort(key=lambda x: x.get('impact_score', 0), reverse=True)
        
        return analyzed
    
    def _calculate_impact(self, content: str) -> int:
        """Calculate impact score (0-100)."""
        score = 20  # Base score for mentioning oil
        content_lower = content.lower()
        
        # Check impact keywords
        for level, keywords in self.impact_keywords.items():
            for kw in keywords:
                if kw in content_lower:
                    if level == 'critical':
                        score += 25
                    elif level == 'high':
                        score += 15
                    elif level == 'medium':
                        score += 10
                    else:
                        score += 5
        
        # Exclamation marks
        score += content.count('!') * 3
        
        # ALL CAPS words (Trump style)
        caps_words = len(re.findall(r'\b[A-Z]{3,}\b', content))
        score += caps_words * 2
        
        # "Drill baby drill" - signature phrase
        if 'drill baby drill' in content_lower:
            score += 15
        
        # Energy dominance - key policy
        if 'energy dominance' in content_lower or 'energy domination' in content_lower:
            score += 20
        
        return min(score, 100)
    
    def _determine_sentiment(self, content: str) -> str:
        """Determine oil market sentiment."""
        content_lower = content.lower()
        
        # Bearish for oil prices (more supply)
        bearish_indicators = [
            'drill', 'produce', 'dominance', 'domination', 'unleash',
            'increase production', 'more oil', 'energy independent'
        ]
        
        # Bullish for oil prices (supply constraints)
        bullish_indicators = [
            'sanctions', 'war', 'stop', 'ban', 'crisis', 'shortage',
            'iran', 'venezuela', 'attack'
        ]
        
        bearish_score = sum(1 for ind in bearish_indicators if ind in content_lower)
        bullish_score = sum(1 for ind in bullish_indicators if ind in content_lower)
        
        if bearish_score > bullish_score:
            return 'bearish_price'  # Prices go down (more supply)
        elif bullish_score > bearish_score:
            return 'bullish_price'  # Prices go up (supply constraints)
        else:
            return 'neutral'
    
    def _determine_urgency(self, content: str, post: Dict) -> str:
        """Determine urgency level."""
        content_lower = content.lower()
        
        # Immediate action indicators
        immediate = ['emergency', 'now', 'immediate', 'today', 'executive order']
        if any(word in content_lower for word in immediate):
            return 'immediate'
        
        # High engagement = high urgency
        if post.get('reblogs', 0) > 10000 or post.get('favourites', 0) > 50000:
            return 'high'
        
        # Recent timestamp
        if post.get('is_new'):
            return 'high'
        
        return 'normal'
    
    def get_trump_factor(self) -> Dict:
        """Get comprehensive Trump analysis."""
        print("\n" + "="*60)
        print("🦅 TRUMP MONITOR - Truth Social Priority Mode")
        print("="*60)
        print("⚠️  Trump speaks FIRST on Truth Social - this is our #1 source")
        
        # Get posts from Truth Social first
        truth_posts, backup_posts = self.get_all_truth_posts(hours=24)
        
        # Analyze for oil relevance
        print("\n🔍 Analyzing posts for oil market impact...")
        analyzed_truth = self.analyze_for_oil(truth_posts)
        analyzed_backup = self.analyze_for_oil(backup_posts)
        
        all_relevant = analyzed_truth + analyzed_backup
        
        # Calculate Trump Factor
        trump_factor = self._calculate_trump_factor(all_relevant, analyzed_truth)
        
        return {
            'timestamp': datetime.now().isoformat(),
            'trump_factor': trump_factor,
            'truth_social_posts': analyzed_truth,
            'backup_posts': analyzed_backup,
            'total_posts_checked': len(truth_posts) + len(backup_posts),
            'oil_relevant_posts': len(all_relevant),
            'monitoring_active': True,
            'priority_source': 'Truth Social'
        }
    
    def _calculate_trump_factor(self, all_posts: List[Dict], truth_posts: List[Dict]) -> Dict:
        """Calculate overall Trump Factor score."""
        if not all_posts:
            return {
                'trump_factor_score': 0,
                'level': 'none',
                'sentiment': 'neutral',
                'relevant_items': 0,
                'explanation': 'No Trump oil-related activity detected in monitoring period',
                'priority_posts': []
            }
        
        # Calculate weighted score
        total_impact = sum(p.get('impact_score', 0) for p in all_posts)
        avg_impact = total_impact / len(all_posts)
        
        # Boost score for Truth Social posts (higher credibility)
        truth_boost = len(truth_posts) * 5
        
        final_score = min(int(avg_impact + truth_boost), 100)
        
        # Determine sentiment
        sentiments = [p.get('sentiment', 'neutral') for p in all_posts]
        bullish = sentiments.count('bullish_price')
        bearish = sentiments.count('bearish_price')
        
        if bearish > bullish:
            overall_sentiment = 'oil_bearish'
        elif bullish > bearish:
            overall_sentiment = 'oil_bullish'
        else:
            overall_sentiment = 'mixed'
        
        # Determine level
        if final_score >= 60:
            level = 'high'
        elif final_score >= 30:
            level = 'medium'
        else:
            level = 'low'
        
        # Get priority posts (from Truth Social first)
        priority_posts = sorted(
            all_posts,
            key=lambda x: (x.get('source') == 'Truth Social (PRIMARY)', x.get('impact_score', 0)),
            reverse=True
        )[:5]
        
        return {
            'trump_factor_score': final_score,
            'level': level,
            'sentiment': overall_sentiment,
            'relevant_items': len(all_posts),
            'truth_social_count': len(truth_posts),
            'explanation': self._generate_explanation(final_score, level, overall_sentiment, truth_posts),
            'priority_posts': priority_posts
        }
    
    def _generate_explanation(self, score: int, level: str, sentiment: str, truth_posts: List[Dict]) -> str:
        """Generate human-readable explanation."""
        base = f"Trump Factor: {score}/100 ({level.upper()}). "
        
        if truth_posts:
            base += f"{len(truth_posts)} oil-relevant post(s) on Truth Social. "
        
        if level == 'high':
            base += "IMMEDIATE ATTENTION REQUIRED - Major market impact expected."
        elif level == 'medium':
            base += "Notable impact likely - monitor closely."
        else:
            base += "Limited immediate impact expected."
        
        if sentiment == 'oil_bearish':
            base += " Pro-production stance suggests downward pressure on prices."
        elif sentiment == 'oil_bullish':
            base += " Supply-constraint stance suggests upward pressure on prices."
        
        return base
    
    def display_analysis(self, analysis: Dict):
        """Display formatted Trump analysis."""
        tf = analysis['trump_factor']
        
        print("\n" + "="*60)
        print("🦅 TRUMP FACTOR ANALYSIS")
        print("="*60)
        
        print(f"\n📊 Score: {tf['trump_factor_score']}/100 ({tf['level'].upper()})")
        print(f"   Sentiment: {tf['sentiment']}")
        print(f"   Relevant Posts: {tf['relevant_items']}")
        
        if tf.get('truth_social_count', 0) > 0:
            print(f"   ✅ From Truth Social: {tf['truth_social_count']}")
        
        print(f"\n💡 {tf['explanation']}")
        
        if tf.get('priority_posts'):
            print(f"\n📱 Top Priority Posts:")
            for i, post in enumerate(tf['priority_posts'][:3], 1):
                source = post.get('source', 'Unknown')
                content = post.get('content', '')[:80]
                impact = post.get('impact_score', 0)
                is_new = "🆕 " if post.get('is_new') else ""
                print(f"\n   {is_new}[{source}] Impact: {impact}")
                print(f"   \"{content}...\"")
        
        print("\n" + "="*60)
    
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

def main():
    monitor = TrumpTruthSocialMonitor()
    analysis = monitor.get_trump_factor()
    monitor.display_analysis(analysis)
    filename = monitor.save_analysis(analysis)
    if filename:
        print(f"💾 Saved: {filename}")

if __name__ == "__main__":
    main()
