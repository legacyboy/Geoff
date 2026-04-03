

---

## Search Bot Integration - Standard Practice (2026-04-01)

**Decision:** All future projects must utilize the search module (`/home/claw/.openclaw/workspace/search_module.py`) for web data.

**Why:**
- SerpAPI integration provides reliable web search (100 free queries/month)
- Avoids rate limits of single APIs (Gemini, etc.)
- Shared module means consistent search capability across all bots
- Workspace fallback ensures functionality even when web is unavailable

**Current Projects Using Search Module:**
1. **Trading Bot** - Real-time geopolitical risk monitoring via `GeopoliticalAggregator`
2. **Business Ideas Bot** - Market validation before adding new ideas
3. **iOS Games Bot** - Trend research for game concepts

**How to Use:**
```python
import sys
sys.path.insert(0, '/home/claw/.openclaw/workspace')
from search_module import web_search, search_workspace

# Web search
results = web_search('your query', num_results=5)

# Local file search
local_results = search_workspace('your query')
```

**API Key:** Stored in module, SerpAPI free tier (100 searches/month)

**This is now standard for all future automation projects.**

