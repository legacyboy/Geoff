#!/usr/bin/env python3
import sys
sys.path.insert(0, '/home/claw/.openclaw/workspace')
from search_module import web_search

queries = [
    'AI travel planning assistant market size 2026',
    'AI interior design market size 2026',
    'AI resume builder market size 2026',
    'AI tutoring homework help market size 2026',
    'AI meeting notes market size 2026',
    'AI writing assistant market size 2026'
]

for q in queries:
    print(f'\n=== {q} ===')
    results = web_search(q, num_results=2)
    for r in results:
        print(f"  Title: {r['title'][:70]}")
        print(f"  Snippet: {r['snippet'][:120]}")
        print()
