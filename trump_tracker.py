#!/usr/bin/env python3
"""
Trump News Tracker - Polls RSS feeds for Trump-related content
Sources: r/politics, NBC News
"""

import feedparser
import json
import os
from datetime import datetime
from pathlib import Path

# State file to track seen items
STATE_FILE = Path(__file__).parent / ".trump_tracker_state.json"

# RSS feeds to monitor
FEEDS = {
    "r/politics": "https://www.reddit.com/r/politics/search.rss?q=trump&restrict_sr=1&sort=new",
}

# Keywords to filter for (optional - set to None to get all)
KEYWORDS = ["trump", "donald"]

def load_state():
    """Load previously seen item IDs"""
    if STATE_FILE.exists():
        with open(STATE_FILE) as f:
            return json.load(f)
    return {}

def save_state(state):
    """Save seen item IDs"""
    with open(STATE_FILE, 'w') as f:
        json.dump(state, f, indent=2)

def fetch_feed(name, url):
    """Fetch and parse a single RSS feed"""
    try:
        feed = feedparser.parse(url)
        return feed.entries[:10]  # Last 10 items
    except Exception as e:
        print(f"Error fetching {name}: {e}")
        return []

def format_entry(entry, source):
    """Format a feed entry for display"""
    title = entry.get('title', 'No title')
    link = entry.get('link', '')
    published = entry.get('published', 'Unknown date')
    
    # Clean up Reddit links to point to actual article
    if 'reddit.com' in link and '/comments/' in link:
        # Extract the actual article link if available in content
        pass
    
    return {
        "source": source,
        "title": title,
        "link": link,
        "published": published,
        "id": entry.get('id', entry.get('link', ''))
    }

def main():
    state = load_state()
    new_items = []
    
    for name, url in FEEDS.items():
        entries = fetch_feed(name, url)
        seen_ids = state.get(name, [])
        
        for entry in entries:
            entry_id = entry.get('id', entry.get('link', ''))
            
            if entry_id not in seen_ids:
                formatted = format_entry(entry, name)
                new_items.append(formatted)
                seen_ids.append(entry_id)
        
        # Keep last 50 IDs per source
        state[name] = seen_ids[-50:]
    
    # Save updated state
    save_state(state)
    
    # Output results
    if new_items:
        print(f"\n📰 {len(new_items)} new Trump-related items found:\n")
        for item in new_items:
            print(f"[{item['source']}] {item['title']}")
            print(f"   Link: {item['link']}")
            print(f"   Published: {item['published']}")
            print()
    else:
        print("No new items found.")
    
    return new_items

if __name__ == "__main__":
    main()
