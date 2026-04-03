#!/usr/bin/env python3
import sys
sys.path.insert(0, '/home/claw/.openclaw/workspace')
from search_module import search_workspace

terms = ['event planning', 'language learning', 'gift recommendation', 'pet care', 'legal']
for term in terms:
    print(f'Searching: {term}')
    results = search_workspace(term, max_results=3)
    if results:
        print(f'  Found {len(results)} matches')
    else:
        print('  No matches found')
