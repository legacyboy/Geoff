#!/usr/bin/env python3
"""
Trump Pipeline - Scrape + Analyze + Report
Fast execution with anti-blocking
"""

import sys
sys.path.insert(0, '/home/claw/.openclaw/workspace/trading-bot/agents')

from truth_social_fast import FastTruthScraper
from trump_signal_analyzer import TrumpSignalAnalyzer
import json
from datetime import datetime

def main():
    print("🦅 TRUMP PIPELINE - Scrape → Analyze → Trade Signal")
    print("=" * 60)
    
    # Step 1: Scrape
    scraper = FastTruthScraper()
    result = scraper.run()
    
    # Step 2: Analyze
    print("\n" + "=" * 60)
    analyzer = TrumpSignalAnalyzer()
    decision = analyzer.run()
    
    # Step 3: Summary
    print("\n" + "=" * 60)
    print("📊 PIPELINE SUMMARY")
    print("=" * 60)
    print(f"New posts scraped: {result['new_posts']}")
    print(f"Oil-relevant: {result['oil_relevant']}")
    print(f"Trading signals: {len(result['signals'])}")
    
    if decision:
        print(f"\n🚨 ACTIVE TRADE DECISION:")
        print(f"   Action: {decision['action']}")
        print(f"   Confidence: {decision['recommended_trade']['confidence'] if decision['recommended_trade'] else 'N/A'}")
        
        # Save decision for trading bot
        from pathlib import Path
        decision_file = Path('/home/claw/.openclaw/workspace/trading-bot/data/trump_monitor/latest_decision.json')
        decision_file.parent.mkdir(parents=True, exist_ok=True)
        with open(decision_file, 'w') as f:
            json.dump(decision, f, indent=2)
        print(f"\n💾 Decision saved: {decision_file}")
        
        return decision
    else:
        print(f"\n✅ No trade action needed")
        return None

if __name__ == "__main__":
    decision = main()
    sys.exit(0 if decision else 1)
