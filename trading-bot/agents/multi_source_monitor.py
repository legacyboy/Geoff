#!/usr/bin/env python3
"""
Multi-Source Geopolitical Monitor
Aggregates from: NewsAPI, Reddit, RSS feeds, Conflict databases
"""

import os
import json
import re
import time
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any
from urllib.parse import quote

# Setup paths
BASE_DIR = Path(__file__).parent.parent
DATA_DIR = BASE_DIR / 'data' / 'geopolitical'
CACHE_DIR = DATA_DIR / 'cache'
CACHE_DIR.mkdir(parents=True, exist_ok=True)

# Logging
LOGS_DIR = BASE_DIR / 'logs'
LOGS_DIR.mkdir(exist_ok=True)
logging.basicConfig(
    filename=LOGS_DIR / 'multi_source_monitor.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class NewsAPIMonitor:
    """Monitor via NewsAPI.org (free tier: 100 req/day)"""
    
    API_KEY = None  # Will be set via env or config
    BASE_URL = "https://newsapi.org/v2/everything"
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv('NEWSAPI_KEY')
    
    def search(self, query: str, from_date: Optional[str] = None) -> List[Dict[str, Any]]:
        """Search news articles."""
        if not self.api_key:
            logger.warning("NewsAPI key not set")
            return []
        
        try:
            import subprocess
            
            if not from_date:
                from_date = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d')
            
            url = f"{self.BASE_URL}?q={quote(query)}&from={from_date}&sortBy=relevancy&apiKey={self.api_key}"
            
            result = subprocess.run(
                ['curl', '-s', '--max-time', '15', url],
                capture_output=True, text=True, timeout=20
            )
            
            if result.returncode == 0 and result.stdout:
                data = json.loads(result.stdout)
                
                if data.get('status') == 'ok':
                    articles = data.get('articles', [])
                    return [
                        {
                            'id': f"newsapi_{i}",
                            'source': art.get('source', {}).get('name', 'NewsAPI'),
                            'timestamp': art.get('publishedAt', ''),
                            'title': art.get('title', ''),
                            'description': art.get('description', ''),
                            'url': art.get('url', ''),
                            'content': art.get('content', '')
                        }
                        for i, art in enumerate(articles[:10])
                    ]
        
        except Exception as e:
            logger.error(f"NewsAPI error: {e}")
        
        return []

class RedditMonitor:
    """Monitor Reddit discussions (JSON API, no auth needed for read)"""
    
    SUBREDDITS = [
        'politics',
        'worldnews',
        'news',
        'oil',
        'energy',
        'geopolitics',
        'trump'
    ]
    
    def search_posts(self, query: str) -> List[Dict[str, Any]]:
        """Search Reddit posts via JSON API."""
        posts = []
        
        try:
            import subprocess
            
            # Search r/politics for Trump/oil
            for subreddit in ['politics', 'worldnews', 'oil']:
                url = f"https://www.reddit.com/r/{subreddit}/search.json?q={quote(query)}&sort=new&t=day&limit=10"
                
                result = subprocess.run(
                    ['curl', '-s', '--max-time', '10',
                     '-H', 'User-Agent: OilBot/1.0 (Research)',
                     url],
                    capture_output=True, text=True, timeout=15
                )
                
                if result.returncode == 0 and result.stdout:
                    try:
                        data = json.loads(result.stdout)
                        
                        if 'data' in data and 'children' in data['data']:
                            for i, child in enumerate(data['data']['children'][:5]):
                                post = child.get('data', {})
                                
                                posts.append({
                                    'id': f"reddit_{subreddit}_{i}",
                                    'source': f'Reddit r/{subreddit}',
                                    'timestamp': datetime.fromtimestamp(
                                        post.get('created_utc', 0)
                                    ).isoformat(),
                                    'title': post.get('title', ''),
                                    'content': post.get('selftext', '')[:500],
                                    'url': f"https://reddit.com{post.get('permalink', '')}",
                                    'engagement': post.get('score', 0)
                                })
                    except:
                        pass
        
        except Exception as e:
            logger.error(f"Reddit error: {e}")
        
        return posts

class RSSMonitor:
    """Monitor RSS feeds from news sources"""
    
    FEEDS = {
        'bbc_world': 'http://feeds.bbci.co.uk/news/world/rss.xml',
        'bbc_business': 'http://feeds.bbci.co.uk/news/business/rss.xml',
        'cbc_world': 'https://www.cbc.ca/cmlink/rss-world',
        'reuters_commodities': 'https://www.reutersagency.com/feed/?best-topics=business&post_type=reuters-best'
    }
    
    def fetch_feed(self, feed_name: str, url: str) -> List[Dict[str, Any]]:
        """Fetch and parse RSS feed."""
        items = []
        
        try:
            import subprocess
            import xml.etree.ElementTree as ET
            
            result = subprocess.run(
                ['curl', '-s', '--max-time', '15', url],
                capture_output=True, text=True, timeout=20
            )
            
            if result.returncode == 0 and result.stdout:
                try:
                    root = ET.fromstring(result.stdout)
                    
                    # Find items
                    for item in root.findall('.//item')[:10]:
                        title = item.find('title')
                        link = item.find('link')
                        pub_date = item.find('pubDate')
                        desc = item.find('description')
                        
                        title_text = title.text if title is not None else ''
                        
                        # Only keep oil/energy related
                        if any(kw in title_text.lower() for kw in ['oil', 'energy', 'trump', 'opec', 'crude', 'petrol']):
                            items.append({
                                'id': f"{feed_name}_{hash(title_text) % 10000}",
                                'source': feed_name.replace('_', ' ').title(),
                                'timestamp': pub_date.text if pub_date is not None else datetime.now().isoformat(),
                                'title': title_text,
                                'description': desc.text if desc is not None else '',
                                'url': link.text if link is not None else '',
                                'content': desc.text if desc is not None else ''
                            })
                
                except ET.ParseError:
                    logger.warning(f"RSS parse error for {feed_name}")
        
        except Exception as e:
            logger.error(f"RSS error for {feed_name}: {e}")
        
        return items
    
    def fetch_all(self) -> List[Dict[str, Any]]:
        """Fetch all configured RSS feeds."""
        all_items = []
        
        for name, url in self.FEEDS.items():
            items = self.fetch_feed(name, url)
            all_items.extend(items)
            time.sleep(0.5)  # Be nice to servers
        
        return all_items

class ConflictDataMonitor:
    """Monitor conflict data from various sources"""
    
    def get_active_conflicts(self) -> List[Dict[str, Any]]:
        """Get currently active conflicts affecting oil."""
        # Static data updated manually or via cron
        # In production, would integrate with ACLED API
        
        conflicts = [
            {
                'id': 'conflict_ukraine',
                'region': 'Russia/Ukraine',
                'status': 'active',
                'impact': 'high',
                'oil_supply_at_risk': 10000000,
                'description': 'Ongoing conflict affecting Russian oil exports and infrastructure'
            },
            {
                'id': 'conflict_gaza',
                'region': 'Middle East',
                'status': 'active',
                'impact': 'medium',
                'oil_supply_at_risk': 2000000,
                'description': 'Regional tensions affecting shipping lanes'
            },
            {
                'id': 'conflict_sudan',
                'region': 'East Africa',
                'status': 'active',
                'impact': 'low',
                'oil_supply_at_risk': 150000,
                'description': 'Civil conflict disrupting Sudanese oil production'
            }
        ]
        
        return conflicts

class MultiSourceAggregator:
    """Aggregate all data sources into unified intelligence."""
    
    def __init__(self, newsapi_key: Optional[str] = None):
        self.newsapi = NewsAPIMonitor(newsapi_key)
        self.reddit = RedditMonitor()
        self.rss = RSSMonitor()
        self.conflicts = ConflictDataMonitor()
    
    def collect_all(self) -> Dict[str, Any]:
        """Collect from all sources."""
        print("🌍 Collecting from multiple sources...")
        
        # NewsAPI
        print("📡 Fetching NewsAPI...")
        newsapi_articles = self.newsapi.search("Trump oil energy")
        
        # Reddit
        print("🔴 Fetching Reddit...")
        reddit_posts = self.reddit.search_posts("Trump oil OPEC")
        
        # RSS Feeds
        print("📰 Fetching RSS feeds...")
        rss_items = self.rss.fetch_all()
        
        # Conflicts
        print("⚔️ Checking conflicts...")
        conflicts = self.conflicts.get_active_conflicts()
        
        # Compile report
        report = {
            'timestamp': datetime.now().isoformat(),
            'sources': {
                'newsapi': len(newsapi_articles),
                'reddit': len(reddit_posts),
                'rss': len(rss_items),
                'conflicts': len(conflicts)
            },
            'articles': newsapi_articles[:5],
            'reddit_posts': reddit_posts[:5],
            'rss_items': rss_items[:5],
            'conflicts': conflicts,
            'trump_specific': self._extract_trump_content(newsapi_articles + reddit_posts + rss_items),
            'summary': self._generate_summary(newsapi_articles, reddit_posts, rss_items, conflicts)
        }
        
        # Save
        self._save_report(report)
        
        return report
    
    def _extract_trump_content(self, items: List[Dict]) -> List[Dict]:
        """Extract Trump-specific content."""
        trump_items = []
        
        for item in items:
            content = f"{item.get('title', '')} {item.get('description', '')} {item.get('content', '')}"
            
            if 'trump' in content.lower() or 'donald' in content.lower():
                trump_items.append({
                    'id': item.get('id'),
                    'source': item.get('source'),
                    'timestamp': item.get('timestamp'),
                    'title': item.get('title', ''),
                    'url': item.get('url', ''),
                    'relevance_score': self._score_trump_relevance(content)
                })
        
        trump_items.sort(key=lambda x: x['relevance_score'], reverse=True)
        return trump_items[:10]
    
    def _score_trump_relevance(self, content: str) -> int:
        """Score Trump content relevance."""
        score = 0
        content_lower = content.lower()
        
        # Oil/energy keywords
        oil_keywords = ['oil', 'energy', 'drill', 'fracking', 'opec', 'petroleum', 'gas']
        for kw in oil_keywords:
            if kw in content_lower:
                score += 10
        
        # Policy keywords
        policy_keywords = ['tariffs', 'sanctions', 'trade', 'policy', 'executive', 'order']
        for kw in policy_keywords:
            if kw in content_lower:
                score += 15
        
        return min(score, 100)
    
    def _generate_summary(self, *args) -> Dict[str, Any]:
        """Generate summary stats."""
        total_items = sum(len(a) for a in args)
        
        return {
            'total_items_collected': total_items,
            'collection_time': datetime.now().isoformat(),
            'sources_active': 4
        }
    
    def _save_report(self, report: Dict) -> None:
        """Save report to file."""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filepath = DATA_DIR / f'multi_source_report_{timestamp}.json'
        
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2)
        
        # Also save as latest
        latest_path = DATA_DIR / 'latest_multi_source.json'
        with open(latest_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"💾 Report saved: {filepath}")

def main():
    """Run the multi-source monitor."""
    print("="*60)
    print("MULTI-SOURCE GEOPOLITICAL MONITOR")
    print("Sources: NewsAPI, Reddit, RSS, Conflict Data")
    print("="*60)
    
    # Check for API key
    api_key = os.getenv('NEWSAPI_KEY')
    if not api_key:
        print("\n⚠️  NEWSAPI_KEY not set. Set it with:")
        print("   export NEWSAPI_KEY='your_key_here'")
        print("   Get free key at: https://newsapi.org/register")
    
    aggregator = MultiSourceAggregator(api_key)
    report = aggregator.collect_all()
    
    print("\n" + "="*60)
    print("COLLECTION SUMMARY")
    print("="*60)
    
    for source, count in report['sources'].items():
        print(f"  {source}: {count} items")
    
    if report['trump_specific']:
        print(f"\n🦅 Trump-specific items: {len(report['trump_specific'])}")
        for item in report['trump_specific'][:3]:
            print(f"  - {item['title'][:60]}... ({item['source']})")
    
    print("\n✅ Collection complete")

if __name__ == '__main__':
    main()
