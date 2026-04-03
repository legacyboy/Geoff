#!/usr/bin/env python3
"""
Money Making Ideas Analyzer - Runs every 30 minutes
Called by cron job to spawn subagent analysis
"""

import os
import sys

# Add workspace to path for imports
sys.path.insert(0, '/home/claw/.openclaw/workspace')

def main():
    print("=" * 60)
    print("MONEY MAKING IDEAS - CRON ANALYSIS CYCLE")
    print("=" * 60)
    print()
    
    # This script is called by the subagent spawned via cron
    # The subagent receives the task instructions via the cron payload
    
    task = """
# Money Making Ideas Analysis Task

Your job: Generate and evaluate money-making ideas for an AI assistant.

## Current Status
Read: /home/claw/.openclaw/workspace/money_making_ideas.md
Review existing ideas and their scores.

## Tasks (do as many as possible in 20 minutes):

1. **Generate 2-3 NEW ideas** (be creative - look at current trends, gaps, AI capabilities)

2. **Evaluate existing ideas**: Adjust scores based on new research/thinking
   - Use scoring criteria from the file
   - Be critical but fair
   - Consider: can an AI actually do this?

3. **Research**: Quick web search on 1-2 promising ideas to validate assumptions

4. **Update**: Rewrite money_making_ideas.md with:
   - New ideas added
   - Updated scores
   - Brief notes on WHY scores changed
   - Timestamp of this cycle

## Scoring Criteria (1-10 scale, except where noted):
- **Feasibility**: Can an AI assistant actually execute this?
- **Difficulty**: Implementation complexity (1=easy, 10=hard)
- **Startup Costs**: $ (low), $$ (medium), $$$ (high)
- **Time to First $**: Days/weeks/months
- **Scalability**: Can revenue grow without linear time?
- **Competition**: Low/Med/High market saturation
- **Risk**: Low/Med/High chance of failure
- **AI Advantage**: Do I have edge over humans?

## Output Format
Each idea should include:
- Brief description (1-2 sentences)
- Score breakdown
- Total weighted score
- Notes/considerations

## Important
- Be realistic - not everything needs to be a unicorn
- Consider Dan's setup (OpenClaw, local Ollama, tools available)
- Think about ACTUAL implementation, not just theory
- Focus on things I can START doing, not just plan

After updating the file, summarize what you did in your response.
"""
    
    print(task)
    print()
    print("This task should be executed by a subagent with deepseek-v3.2 model")
    print("Subagent will read the markdown file and update it with new ideas/analysis")

if __name__ == "__main__":
    main()
