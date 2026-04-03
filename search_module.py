#!/usr/bin/env python3
"""
Shared Search Module for OpenClaw Agents
Provides SerpAPI web search with fallback to workspace files.
"""

import os
import json
import time
import random
from urllib.parse import urlencode
from datetime import datetime
from pathlib import Path

# API Configuration
SERPAPI_KEY = os.environ.get('SERPAPI_KEY', 'ec3a5cb3e034ff34eff1bedcd2220495511b3531b77558a95c9410805b4827fa')

def web_search(query, num_results=5, engine='google'):
    """
    Perform web search via SerpAPI.
    
    Args:
        query: Search query string
        num_results: Number of results (max 100)
        engine: Search engine ('google', 'bing', 'duckduckgo', 'yahoo')
    
    Returns:
        List of result dictionaries with title, url, snippet
    """
    if not SERPAPI_KEY:
        return []
    
    # Rate limiting
    time.sleep(random.uniform(1, 3))
    
    base_url = "https://serpapi.com/search"
    params = {
        'q': query,
        'engine': engine,
        'api_key': SERPAPI_KEY,
        'num': min(num_results, 100),
        'output': 'json'
    }
    
    try:
        import requests
        response = requests.get(base_url, params=params, timeout=15)
        data = response.json()
    except ImportError:
        # Fallback to curl
        import subprocess
        url = f"{base_url}?{urlencode(params)}"
        result = subprocess.run(
            ['curl', '-s', '--max-time', '15', url],
            capture_output=True, text=True, timeout=20
        )
        data = json.loads(result.stdout) if result.returncode == 0 else {}
    except Exception:
        return []
    
    results = []
    if 'organic_results' in data:
        for r in data['organic_results'][:num_results]:
            results.append({
                'title': r.get('title', ''),
                'url': r.get('link', ''),
                'snippet': r.get('snippet', ''),
                'source': 'web'
            })
    
    return results

def search_workspace(query, max_results=5):
    """
    Search local workspace files for relevant content.
    
    Args:
        query: Search query
        max_results: Maximum results to return
    
    Returns:
        List of result dictionaries
    """
    workspace_dir = Path('/home/claw/.openclaw/workspace')
    results = []
    terms = [t for t in query.lower().split() if len(t) > 2]
    
    # Priority files to search
    priority_files = [
        'money_making_ideas.md',
        'money_making_ideas_TOP50.md',
        'ios_game_ideas.md',
        'MEMORY.md'
    ]
    
    for filename in priority_files:
        file_path = workspace_dir / filename
        if not file_path.exists():
            continue
        
        try:
            content = file_path.read_text()
            lines = content.split('\n')
            
            for i, line in enumerate(lines):
                if any(t in line.lower() for t in terms):
                    results.append({
                        'title': line[:80].strip('# ') + '...',
                        'url': f'file://{file_path}#L{i+1}',
                        'snippet': line[:200],
                        'source': 'workspace',
                        'file': filename
                    })
                    
                    if len(results) >= max_results:
                        break
        except:
            pass
    
    return results

def search(query, num_results=5, use_web=True):
    """
    Hybrid search: Try web first, fallback to workspace.
    
    Args:
        query: Search query
        num_results: Number of results
        use_web: Whether to try web search first
    
    Returns:
        List of results
    """
    results = []
    
    # Try web search first
    if use_web and SERPAPI_KEY:
        web_results = web_search(query, num_results, 'google')
        if web_results:
            results.extend(web_results)
    
    # If no web results, try workspace
    if not results:
        workspace_results = search_workspace(query, max_results=num_results)
        results.extend(workspace_results)
    
    return results[:num_results]

def validate_market_data(idea_name, market_terms):
    """
    Validate business idea with web search.
    
    Args:
        idea_name: Name of the idea
        market_terms: List of terms to search for validation
    
    Returns:
        Dictionary with validation summary
    """
    validation = {
        'idea': idea_name,
        'searches': [],
        'sources': [],
        'timestamp': datetime.now().isoformat()
    }
    
    for term in market_terms[:2]:  # Limit to 2 searches per idea
        results = web_search(term, num_results=3)
        if results:
            validation['searches'].append({
                'query': term,
                'results_found': len(results)
            })
            for r in results:
                validation['sources'].append(r['url'])
        time.sleep(random.uniform(2, 4))
    
    return validation

# Export for use by other scripts
if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python search_module.py 'search query'")
        sys.exit(1)
    
    query = ' '.join(sys.argv[1:])
    results = search(query, num_results=5)
    
    print(f"Results for: {query}\n")
    for i, r in enumerate(results, 1):
        print(f"{i}. {r['title']}")
        print(f"   {r['url']}")
        if r.get('snippet'):
            print(f"   {r['snippet'][:150]}...")
        print(f"   [Source: {r.get('source', 'unknown')}]")
        print()
