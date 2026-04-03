#!/usr/bin/env python3
"""
Fast Truth Social Scraper - Anti-blocking with rotation
Saves directly to DB for market analysis
"""

import json
import sqlite3
import random
import time
import subprocess
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

BASE_DIR = Path(__file__).parent.parent
DB_PATH = BASE_DIR / 'data' / 'trading.db'
DATA_DIR = BASE_DIR / 'data' / 'trump_monitor'
DATA_DIR.mkdir(parents=True, exist_ok=True)

# Rotation pool - multiple ways to get the data
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.0',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.0',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1',
]

class FastTruthScraper:
    """Fast scraper with rotation and DB persistence."""
    
    TRUMP_ACCOUNT_ID = '107780257626128481'
    
    def __init__(self):
        self.oil_keywords = {
            'oil', 'drill', 'drilling', 'fracking', 'shale', 'petroleum', 'energy',
            'gas', 'gasoline', 'crude', 'opec', 'saudi', 'keystone', 'iran', 'venezuela',
            'sanctions', 'tariffs', 'production', 'exports', 'domestic', 'pipeline',
            'permian', 'texas', 'dominance', 'independent'
        }
        self.session = self._get_random_ua()
        
    def _get_random_ua(self) -> str:
        return random.choice(USER_AGENTS)
    
    def _get_db(self) -> sqlite3.Connection:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        return conn
    
    def _is_post_seen(self, post_id: str) -> bool:
        """Check if post already in DB."""
        with self._get_db() as conn:
            cur = conn.execute(
                "SELECT 1 FROM trump_posts WHERE post_id = ? LIMIT 1",
                (post_id,)
            )
            return cur.fetchone() is not None
    
    def _save_post(self, post: Dict) -> bool:
        """Save post to DB. Returns True if saved, False if duplicate."""
        try:
            with self._get_db() as conn:
                conn.execute("""
                    INSERT OR IGNORE INTO trump_posts 
                    (post_id, source, timestamp, content, url, reblogs, favourites, replies, is_new)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    post['id'],
                    post.get('source', 'unknown'),
                    post.get('timestamp', datetime.now().isoformat()),
                    post['content'],
                    post.get('url', ''),
                    post.get('reblogs', 0),
                    post.get('favourites', 0),
                    post.get('replies', 0),
                    post.get('is_new', True)
                ))
                conn.commit()
                return conn.total_changes > 0
        except Exception as e:
            print(f"DB error: {e}")
            return False
    
    def scrape_api(self, limit: int = 20) -> List[Dict]:
        """Scrape from Truth Social Mastodon API."""
        posts = []
        
        try:
            cmd = [
                'curl', '-s', '-L', '--max-time', '12',
                '-H', f'User-Agent: {self.session}',
                '-H', 'Accept: application/json',
                f'https://truthsocial.com/api/v1/accounts/{self.TRUMP_ACCOUNT_ID}/statuses?limit={limit}'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0 and result.stdout:
                data = json.loads(result.stdout)
                
                for item in data:
                    if not isinstance(item, dict):
                        continue
                        
                    content = item.get('content', '')
                    if content:
                        content = content.replace('<p>', '').replace('</p>', '').replace('<br>', '\n')
                        content = self._strip_html(content)
                    
                    post = {
                        'id': str(item.get('id', '')),
                        'source': 'truth_social_api',
                        'timestamp': item.get('created_at'),
                        'content': content,
                        'url': item.get('url'),
                        'reblogs': item.get('reblogs_count', 0),
                        'favourites': item.get('favourites_count', 0),
                        'replies': item.get('replies_count', 0),
                        'is_new': not self._is_post_seen(str(item.get('id', '')))
                    }
                    
                    if self._save_post(post):
                        posts.append(post)
                        
        except Exception as e:
            print(f"API scrape error: {e}")
            
        return posts
    
    def scrape_nitter(self) -> List[Dict]:
        """Backup: scrape from Nitter mirror."""
        posts = []
        
        nitter_instances = [
            'https://nitter.net',
            'https://nitter.cz',
            'https://nitter.privacydev.net',
        ]
        
        for instance in random.sample(nitter_instances, len(nitter_instances)):
            try:
                cmd = [
                    'curl', '-s', '-L', '--max-time', '8',
                    '-H', f'User-Agent: {self.session}',
                    f'{instance}/realDonaldTrump/rss'
                ]
                
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0 and '<item>' in result.stdout:
                    # Parse RSS
                    import xml.etree.ElementTree as ET
                    root = ET.fromstring(result.stdout)
                    
                    for item in root.findall('.//item'):
                        title = item.find('title')
                        link = item.find('link')
                        pub_date = item.find('pubDate')
                        
                        if title is None:
                            continue
                            
                        content = title.text or ''
                        post_id = link.text.split('/')[-1] if link else hash(content)
                        
                        post = {
                            'id': str(post_id),
                            'source': 'nitter_backup',
                            'timestamp': pub_date.text if pub_date else datetime.now().isoformat(),
                            'content': content,
                            'url': link.text if link else '',
                            'reblogs': 0,
                            'favourites': 0,
                            'replies': 0,
                            'is_new': not self._is_post_seen(str(post_id))
                        }
                        
                        if self._save_post(post):
                            posts.append(post)
                            
                    if posts:
                        break
                        
            except Exception as e:
                continue
                
        return posts
    
    def _strip_html(self, text: str) -> str:
        """Remove HTML tags."""
        import re
        return re.sub(r'<[^>]+>', '', text)
    
    def analyze_unanalyzed(self) -> List[Dict]:
        """Analyze posts not yet analyzed."""
        analyzed = []
        
        with self._get_db() as conn:
            cur = conn.execute("""
                SELECT * FROM trump_posts 
                WHERE analyzed = 0 
                ORDER BY timestamp DESC
                LIMIT 50
            """)
            rows = cur.fetchall()
        
        for row in rows:
            content = row['content'].lower()
            found_keywords = [kw for kw in self.oil_keywords if kw in content]
            
            if found_keywords:
                impact = self._calc_impact(content, row)
                sentiment = self._calc_sentiment(content)
                urgency = self._calc_urgency(content, row)
                
                # Determine trade signal
                signal = self._generate_signal(sentiment, impact, urgency)
                
                with self._get_db() as conn:
                    conn.execute("""
                        UPDATE trump_posts 
                        SET oil_relevant = 1,
                            oil_keywords = ?,
                            impact_score = ?,
                            sentiment = ?,
                            urgency = ?,
                            analyzed = 1,
                            trade_signal = ?,
                            analyzed_at = ?
                        WHERE id = ?
                    """, (
                        json.dumps(found_keywords),
                        impact,
                        sentiment,
                        urgency,
                        signal,
                        datetime.now().isoformat(),
                        row['id']
                    ))
                    conn.commit()
                
                analyzed.append({
                    'id': row['id'],
                    'content': row['content'][:100] + '...',
                    'impact': impact,
                    'sentiment': sentiment,
                    'urgency': urgency,
                    'signal': signal,
                    'keywords': found_keywords[:5]
                })
            else:
                # Mark non-oil as analyzed
                with self._get_db() as conn:
                    conn.execute(
                        "UPDATE trump_posts SET analyzed = 1, analyzed_at = ? WHERE id = ?",
                        (datetime.now().isoformat(), row['id'])
                    )
                    conn.commit()
        
        return analyzed
    
    def _calc_impact(self, content: str, post: Any) -> int:
        """Calculate impact score 0-100."""
        import re
        score = 15
        
        # Critical keywords
        critical = ['emergency', 'war', 'crisis', 'attack', 'invasion', 'sanctions']
        high = ['drill', 'produce', 'ban', 'stop', 'end', 'tariffs']
        
        for word in critical:
            if word in content:
                score += 20
        for word in high:
            if word in content:
                score += 10
        
        # Exclamation marks
        score += content.count('!') * 3
        
        # Caps
        caps = len(re.findall(r'\b[A-Z]{3,}\b', content))
        score += caps * 2
        
        # Engagement boost
        engagement = post['reblogs'] + post['favourites']
        if engagement > 50000:
            score += 10
        elif engagement > 10000:
            score += 5
        
        return min(score, 100)
    
    def _calc_sentiment(self, content: str) -> str:
        """Determine oil market sentiment."""
        bearish = ['drill', 'produce', 'dominance', 'unleash', 'increase', 'more oil']
        bullish = ['sanctions', 'war', 'stop', 'ban', 'crisis', 'shortage']
        
        b_score = sum(1 for w in bearish if w in content)
        u_score = sum(1 for w in bullish if w in content)
        
        if b_score > u_score:
            return 'bearish'  # Prices down (more supply)
        elif u_score > b_score:
            return 'bullish'  # Prices up (supply constraint)
        return 'neutral'
    
    def _calc_urgency(self, content: str, post: Any) -> str:
        """Determine urgency level."""
        immediate = ['emergency', 'now', 'immediate', 'today', 'executive order']
        
        if any(w in content for w in immediate):
            return 'immediate'
        if post['reblogs'] + post['favourites'] > 50000:
            return 'high'
        if post['is_new']:
            return 'high'
        return 'normal'
    
    def _generate_signal(self, sentiment: str, impact: int, urgency: str) -> str:
        """Generate trading signal."""
        if impact < 30:
            return 'HOLD'
        
        if sentiment == 'bearish' and impact >= 50:
            return 'SHORT_OIL' if urgency in ['immediate', 'high'] else 'REDUCE_LONG'
        elif sentiment == 'bullish' and impact >= 50:
            return 'LONG_OIL' if urgency in ['immediate', 'high'] else 'ADD_LONG'
        
        return 'MONITOR'
    
    def get_recent_signals(self, hours: int = 24) -> List[Dict]:
        """Get recent actionable signals."""
        with self._get_db() as conn:
            cur = conn.execute("""
                SELECT * FROM trump_posts 
                WHERE oil_relevant = 1 
                AND impact_score >= 30
                AND timestamp > datetime('now', '-? hours')
                ORDER BY impact_score DESC, timestamp DESC
                LIMIT 10
            """, (hours,))
            return [dict(row) for row in cur.fetchall()]
    
    def run(self) -> Dict:
        """Full run: scrape + analyze + report."""
        print("🦅 Fast Truth Social Scraper")
        print("=" * 50)
        
        # Scrape
        print("\n📡 Scraping Truth Social API...")
        api_posts = self.scrape_api(limit=20)
        print(f"   New posts from API: {len(api_posts)}")
        
        if not api_posts:
            print("\n📡 Trying Nitter backup...")
            backup_posts = self.scrape_nitter()
            print(f"   New posts from backup: {len(backup_posts)}")
        else:
            backup_posts = []
        
        total_new = len(api_posts) + len(backup_posts)
        
        # Analyze
        print("\n🔍 Analyzing for oil relevance...")
        analyzed = self.analyze_unanalyzed()
        oil_relevant = [a for a in analyzed if a['impact'] >= 30]
        
        print(f"   Analyzed: {len(analyzed)} | Oil-relevant: {len(oil_relevant)}")
        
        # Report signals
        signals = [a for a in oil_relevant if a['signal'] not in ['HOLD', 'MONITOR']]
        
        result = {
            'timestamp': datetime.now().isoformat(),
            'new_posts': total_new,
            'oil_relevant': len(oil_relevant),
            'signals': signals,
            'top_posts': oil_relevant[:3]
        }
        
        # Save snapshot
        snapshot_file = DATA_DIR / f"snapshot_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(snapshot_file, 'w') as f:
            json.dump(result, f, indent=2)
        
        # Display
        print("\n" + "=" * 50)
        print("📊 RESULTS")
        print("=" * 50)
        print(f"New posts: {total_new}")
        print(f"Oil-relevant: {len(oil_relevant)}")
        print(f"Trading signals: {len(signals)}")
        
        if signals:
            print("\n🚨 ACTIONABLE SIGNALS:")
            for s in signals:
                print(f"   [{s['signal']}] {s['content'][:60]}...")
                print(f"   Impact: {s['impact']} | Sentiment: {s['sentiment']}")
        
        if oil_relevant and not signals:
            print("\n📋 Top Oil-Relevant Posts (monitoring):")
            for p in oil_relevant[:2]:
                print(f"   [{p['impact']}] {p['content'][:60]}...")
        
        print(f"\n💾 Saved to: {snapshot_file}")
        
        return result


if __name__ == "__main__":
    scraper = FastTruthScraper()
    scraper.run()
