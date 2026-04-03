#!/usr/bin/env python3
import sys
sys.path.insert(0, '/home/claw/.openclaw/workspace')
from search_module import search_workspace

# Check if these ideas already exist
terms = [
    ('travel planning', 'travel'),
    ('interior design', 'design'),
    ('resume builder', 'resume'),
    ('tutoring', 'tutor'),
    ('meeting notes', 'meeting'),
    ('writing assistant', 'writing')
]

for search_term, display_term in terms:
    print(f'Checking: {display_term}')
    results = search_workspace(search_term, max_results=3)
    if results:
        print(f'  Found existing ideas')
    else:
        print(f'  No existing ideas found - POTENTIAL NEW IDEA')
    print()
