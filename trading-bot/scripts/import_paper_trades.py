#!/usr/bin/env python3
"""
Import existing paper trades into performance database
Run once to populate historical data
"""

import json
import os
import sqlite3
from pathlib import Path

# Import the tracker
import sys
sys.path.insert(0, '/home/claw/.openclaw/workspace/trading-bot/bot')
from performance_tracker import PerformanceTracker

BASE_DIR = Path('/home/claw/.openclaw/workspace/trading-bot')
PAPER_DIR = BASE_DIR / 'data' / 'paper_trades'

def import_existing_trades():
    """Import all existing paper trades into the database."""
    tracker = PerformanceTracker()
    
    # Get all trade files
    trade_files = sorted([f for f in PAPER_DIR.glob('*.json')])
    
    imported = 0
    skipped = 0
    
    print(f"Found {len(trade_files)} trade files to import...")
    
    for file_path in trade_files:
        try:
            with open(file_path) as f:
                trade = json.load(f)
            
            # Check if trade already has realized P&L (exit price)
            if 'exit_price' in trade or 'realized_pnl' in trade:
                # Import as closed trade
                tracker.add_trade(trade)
                imported += 1
            else:
                # Import as open trade
                tracker.add_trade(trade)
                imported += 1
                
        except Exception as e:
            print(f"  Skipped {file_path.name}: {e}")
            skipped += 1
    
    print(f"\n✅ Imported: {imported}")
    print(f"⚠️ Skipped: {skipped}")
    
    # Update daily summaries
    print("\n📊 Updating daily summaries...")
    # Get all unique dates from trades
    with sqlite3.connect(tracker.db_file) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT DISTINCT date FROM trades')
        dates = [row[0] for row in cursor.fetchall()]
        
        for date in dates:
            tracker._update_daily_summary(date)
    
    print("✅ Done!")
    
    # Print report
    tracker.print_daily_report()

if __name__ == '__main__':
    import_existing_trades()
