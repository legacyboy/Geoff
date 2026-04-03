#!/usr/bin/env python3
import sys
sys.path.insert(0, '/home/claw/.openclaw/workspace')
from search_module import web_search, search_workspace

# Check more potential ideas
terms = [
    ('AI real estate', 'real estate'),
    ('AI shopping', 'shopping'),
    ('AI music', 'music'),
    ('AI fitness', 'fitness'),
    ('AI coding interview', 'coding interview'),
    ('AI presentation', 'presentation'),
    ('AI meal prep', 'meal prep'),
    ('AI study notes', 'study notes'),
    ('AI book summary', 'book summary'),
    ('AI networking', 'networking'),
]

print('=== Checking Workspace for Existing Ideas ===')
for search_term, display_term in terms:
    results = search_workspace(search_term, max_results=2)
    if results:
        print(f'{display_term}: EXISTS')
    else:
        print(f'{display_term}: NEW POTENTIAL')

print('\n=== Market Research for New Ideas ===')
# Research promising gaps
queries = [
    'AI coding interview practice market size 2026',
    'AI presentation maker market size 2026', 
    'AI book summary market size 2026',
    'AI real estate agent market size 2026',
    'AI fitness coach market size 2026'
]

for q in queries:
    results = web_search(q, num_results=2)
    if results:
        print(f"\n{q}:")
        for r in results:
            print(f"  {r['title'][:70]}")
            print(f"    {r['snippet'][:100]}")
