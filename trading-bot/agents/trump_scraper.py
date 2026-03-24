#!/usr/bin/env python3
"""
Trump Web Scraper - Fetches real posts from Truth Social
Uses requests + BeautifulSoup (or direct curl if blocked)
"""

import subprocess
import re
import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any

BASE_DIR = Path(__file__).parent.parent
DATA_DIR = BASE_DIR / 'data' / 'trump_monitor'
DATA_DIR.mkdir(parents=True, exist_ok=True)

def scrape_truth_social() -> List[Dict[str, Any]]:
    """Scrape Trump's Truth Social page."""
    posts = []
    
    try:
        # Fetch the page
        result = subprocess.run(
            ['curl', '-s', '-L', '--max-time', '20',
             '-H', 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
             'https://truthsocial.com/@realDonaldTrump'],
            capture_output=True, text=True, timeout=25
        )
        
        html = result.stdout
        
        # Look for JSON data in the page
        # Truth Social embeds data in __INITIAL_STATE__ or similar
        json_pattern = r'<script[^>]*>window\.__INITIAL_STATE__\s*=\s*(.+?)</script>'
        match = re.search(json_pattern, html, re.DOTALL)
        
        if match:
            json_str = match.group(1)
            data = json.loads(json_str)
            
            # Extract posts from the state
            # Structure varies, try common patterns
            if 'entities' in data and 'statuses' in data['entities']:
                statuses = data['entities']['statuses']
                for status_id, status in statuses.items():
                    content = status.get('content', '')
                    if content:
                        # Clean HTML
                        content = re.sub(r'<[^>]+>', '', content)
                        
                        posts.append({
                            'id': status_id,
                            'timestamp': status.get('created_at', datetime.now().isoformat()),
                            'content': content,
                            'url': f"https://truthsocial.com/@realDonaldTrump/posts/{status_id}",
                            'engagement': status.get('favourites_count', 0) + status.get('reblogs_count', 0),
                            'source': 'Truth Social (scraped)'
                        })
        
        # Alternative: Parse HTML directly for visible posts
        if not posts:
            # Look for post content in HTML
            post_pattern = r'<div[^>]*class="[^"]*status__content[^"]*"[^>]*>(.*?)</div>'
            matches = re.findall(post_pattern, html, re.DOTALL)
            
            for i, content_html in enumerate(matches[:10]):
                content = re.sub(r'<[^>]+>', ' ', content_html).strip()
                content = re.sub(r'\s+', ' ', content)
                
                if content and len(content) > 20:
                    posts.append({
                        'id': f'scraped_{i}',
                        'timestamp': datetime.now().isoformat(),
                        'content': content,
                        'url': 'https://truthsocial.com/@realDonaldTrump',
                        'engagement': 0,
                        'source': 'Truth Social (parsed)'
                    })
        
    except Exception as e:
        print(f"Scraping error: {e}")
    
    return posts

def analyze_oil_relevance(posts: List[Dict]) -> List[Dict]:
    """Analyze posts for oil relevance."""
    oil_keywords = [
        'oil', 'energy', 'drill', 'fracking', 'shale', 'petroleum', 'gas',
        'opec', 'saudi', 'iran', 'venezuela', 'production', 'supply',
        'tariffs', 'trade', 'canada', 'domestic', 'independence', 'dominance'
    ]
    
    analyzed = []
    
    for post in posts:
        content = post.get('content', '').lower()
        
        found_keywords = [kw for kw in oil_keywords if kw in content]
        
        if found_keywords:
            # Calculate impact
            impact = len(found_keywords) * 10
            if any(word in content for word in ['emergency', 'crisis', 'immediately', 'today']):
                impact += 30
            if '!' in post.get('content', ''):
                impact += len([c for c in post.get('content', '') if c == '!']) * 5
            
            post['oil_relevant'] = True
            post['oil_keywords'] = found_keywords
            post['impact_score'] = min(impact, 100)
            
            # Sentiment
            if any(word in content for word in ['drill', 'produce', 'dominance', 'domestic']):
                post['sentiment'] = 'bearish_price'
            elif any(word in content for word in ['sanctions', 'ban', 'war', 'conflict']):
                post['sentiment'] = 'bullish_price'
            else:
                post['sentiment'] = 'neutral'
            
            analyzed.append(post)
    
    return analyzed

def save_posts(posts: List[Dict]) -> None:
    """Save scraped posts."""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filepath = DATA_DIR / f'trump_scraped_{timestamp}.json'
    
    with open(filepath, 'w') as f:
        json.dump(posts, f, indent=2)
    
    print(f"Saved {len(posts)} posts to {filepath}")

def main():
    print("🦅 Scraping Trump's Truth Social...")
    
    posts = scrape_truth_social()
    print(f"Found {len(posts)} posts")
    
    if posts:
        oil_posts = analyze_oil_relevance(posts)
        print(f"{len(oil_posts)} are oil-relevant")
        
        if oil_posts:
            print("\n🛢️ Oil-Relevant Posts:")
            for post in oil_posts[:3]:
                print(f"\n[{post['timestamp'][:19]}]")
                print(f"Content: {post['content'][:120]}...")
                print(f"Keywords: {', '.join(post['oil_keywords'][:5])}")
                print(f"Impact: {post['impact_score']} | Sentiment: {post['sentiment']}")
        
        save_posts(posts)
    else:
        print("⚠️ Could not fetch posts (site may be blocking)")

if __name__ == '__main__':
    main()
