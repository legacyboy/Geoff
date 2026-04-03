#!/usr/bin/env python3
"""
Web Search Agent with SerpAPI Integration
Primary: Google Search via SerpAPI
Fallback: Workspace file search
"""

import os
import json
import time
import random
from urllib.parse import quote_plus, urlencode
from datetime import datetime
from pathlib import Path

# SerpAPI configuration
SERPAPI_KEY = os.environ.get('SERPAPI_KEY', 'ec3a5cb3e034ff34eff1bedcd2220495511b3531b77558a95c9410805b4827fa')

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

class SearchAgent:
    def __init__(self):
        self.api_key = SERPAPI_KEY
        self.base_url = "https://serpapi.com/search"
        self.workspace_dir = Path('/home/claw/.openclaw/workspace')
        self.request_count = 0
        
    def search(self, query, num_results=10, engine='google'):
        """
        Search using SerpAPI.
        
        Args:
            query: Search query string
            num_results: Number of results (max 100)
            engine: Search engine ('google', 'bing', 'duckduckgo', etc.)
        
        Returns:
            List of result dictionaries
        """
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Searching: '{query}'")
        
        if not self.api_key:
            print("  ✗ No API key configured")
            return self._workspace_fallback(query)
        
        # Add random delay (be nice to API)
        delay = random.uniform(1, 3)
        print(f"  Using SerpAPI/{engine} (delay: {delay:.1f}s)...")
        time.sleep(delay)
        
        params = {
            'q': query,
            'engine': engine,
            'api_key': self.api_key,
            'num': min(num_results, 100),
            'output': 'json'
        }
        
        try:
            if REQUESTS_AVAILABLE:
                response = requests.get(self.base_url, params=params, timeout=15)
                data = response.json()
            else:
                # Fallback to curl
                import subprocess
                url = f"{self.base_url}?{urlencode(params)}"
                result = subprocess.run(
                    ['curl', '-s', '--max-time', '15', url],
                    capture_output=True, text=True, timeout=20
                )
                data = json.loads(result.stdout) if result.returncode == 0 else {}
            
            self.request_count += 1
            
            # Extract organic results
            results = []
            if 'organic_results' in data:
                for r in data['organic_results'][:num_results]:
                    results.append({
                        'title': r.get('title', ''),
                        'url': r.get('link', ''),
                        'snippet': r.get('snippet', ''),
                        'source': 'serpapi',
                        'engine': engine
                    })
            
            # Check for errors
            if 'error' in data:
                print(f"  ✗ API Error: {data['error']}")
                return self._workspace_fallback(query)
            
            if results:
                print(f"  ✓ Found {len(results)} results")
                return results
            else:
                print(f"  ✗ No results from API")
                return self._workspace_fallback(query)
                
        except Exception as e:
            print(f"  ✗ Request failed: {e}")
            return self._workspace_fallback(query)
    
    def _workspace_fallback(self, query):
        """Fallback to workspace file search."""
        print(f"  Falling back to workspace...")
        
        results = []
        terms = query.lower().split()
        
        for file_path in self.workspace_dir.glob('*.md'):
            try:
                content = file_path.read_text()
                lines = content.split('\n')
                
                for i, line in enumerate(lines):
                    if any(t in line.lower() for t in terms if len(t) > 2):
                        results.append({
                            'title': line[:70].strip('# ') + '...',
                            'url': f'file://{file_path}#L{i+1}',
                            'snippet': line[:150],
                            'source': 'workspace',
                            'engine': 'local'
                        })
                        
                        if len(results) >= 5:
                            break
            except:
                pass
        
        if results:
            print(f"  ✓ Found {len(results)} local results")
        else:
            print(f"  ✗ No results found")
        
        return results
    
    def multi_search(self, queries, engine='google'):
        """Search multiple queries."""
        all_results = {}
        for query in queries:
            all_results[query] = self.search(query, engine=engine)
            time.sleep(random.uniform(2, 4))  # Rate limiting
        return all_results
    
    def get_stats(self):
        """Get search statistics."""
        return {
            'requests_used': self.request_count,
            'api_key_configured': bool(self.api_key)
        }

# CLI interface
if __name__ == '__main__':
    import sys
    
    agent = SearchAgent()
    
    if len(sys.argv) < 2:
        print("Usage: python search_agent.py 'search query'")
        print("       python search_agent.py -m 'query1' 'query2' 'query3'")
        print("       python search_agent.py --engine bing 'query'")
        print("\nEngines: google, bing, duckduckgo, yahoo")
        sys.exit(1)
    
    # Parse arguments
    engine = 'google'
    args = sys.argv[1:]
    
    if '--engine' in args:
        idx = args.index('--engine')
        engine = args[idx + 1]
        args = args[:idx] + args[idx+2:]
    
    if args[0] == '-m':
        # Multi-search mode
        queries = args[1:]
        results = agent.multi_search(queries, engine=engine)
        
        for query, result_list in results.items():
            print(f"\n{'='*60}")
            print(f"Query: {query}")
            print('='*60)
            for i, r in enumerate(result_list, 1):
                print(f"\n{i}. {r['title']}")
                print(f"   {r['url']}")
                if r.get('snippet'):
                    print(f"   {r['snippet'][:120]}...")
                print(f"   [via {r['source']}/{r['engine']}]")
    else:
        # Single search
        query = ' '.join(args)
        results = agent.search(query, num_results=10, engine=engine)
        
        print(f"\n{'='*60}")
        print(f"Results for: {query}")
        print('='*60)
        
        for i, r in enumerate(results, 1):
            print(f"\n{i}. {r['title']}")
            print(f"   URL: {r['url']}")
            if r.get('snippet'):
                print(f"   {r['snippet'][:200]}...")
            print(f"   Source: {r['source']}/{r['engine']}")
        
        print(f"\n{'='*60}")
        stats = agent.get_stats()
        print(f"API Requests used: {stats['requests_used']}/100 (free tier)")
