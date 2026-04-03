#!/usr/bin/env python3
"""
Generate P&L Report from Paper Trading Data
Shows current positions and estimated P&L
"""

import json
import os
from pathlib import Path
from datetime import datetime

BASE_DIR = Path('/home/claw/.openclaw/workspace/trading-bot')
PAPER_DIR = BASE_DIR / 'data' / 'paper_trades'

def load_trades():
    """Load all paper trades."""
    trades = []
    for f in sorted(PAPER_DIR.glob('*.json')):
        try:
            with open(f) as fp:
                trade = json.load(fp)
                trade['filename'] = f.name
                trades.append(trade)
        except:
            pass
    return trades

def calculate_pnl_report():
    """Calculate P&L from trade history."""
    trades = load_trades()
    
    if not trades:
        print("No trades found.")
        return
    
    # Separate buys and sells
    buys = [t for t in trades if t.get('side') == 'buy']
    sells = [t for t in trades if t.get('side') == 'sell']
    
    # Current price (last known)
    current_price = trades[-1].get('price', 0) if trades else 0
    
    print("="*70)
    print("📊 OIL TRADER v2 - PAPER TRADING P&L REPORT")
    print("="*70)
    print(f"\nGenerated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Current Oil Price: ${current_price:.2f}")
    
    # Summary stats
    print(f"\n{'='*70}")
    print("📈 TRADE SUMMARY")
    print("="*70)
    print(f"Total Trades: {len(trades)}")
    print(f"BUY Orders: {len(buys)}")
    print(f"SELL Orders: {len(sells)}")
    
    # Calculate total units and average cost
    total_buy_units = sum(t.get('units', 0) for t in buys)
    total_buy_value = sum(t.get('units', 0) * t.get('price', 0) for t in buys)
    avg_buy_price = total_buy_value / total_buy_units if total_buy_units > 0 else 0
    
    total_sell_units = sum(t.get('units', 0) for t in sells)
    total_sell_value = sum(t.get('units', 0) * t.get('price', 0) for t in sells)
    avg_sell_price = total_sell_value / total_sell_units if total_sell_units > 0 else 0
    
    print(f"\n{'='*70}")
    print("💰 POSITION ANALYSIS")
    print("="*70)
    print(f"Total BUY Volume: {total_buy_units} units @ avg ${avg_buy_price:.2f}")
    print(f"Total SELL Volume: {total_sell_units} units @ avg ${avg_sell_price:.2f}")
    
    # Net position
    net_units = total_buy_units - total_sell_units
    print(f"\nNet Position: {net_units} units {'LONG' if net_units > 0 else 'SHORT' if net_units < 0 else 'FLAT'}")
    
    if net_units != 0:
        # Estimate unrealized P&L
        if net_units > 0:
            # Long position - profit if price > avg buy
            unrealized_pnl = (current_price - avg_buy_price) * net_units
            print(f"\n📊 UNREALIZED P&L:")
            print(f"   Entry: ${avg_buy_price:.2f} x {net_units} units")
            print(f"   Current: ${current_price:.2f}")
            print(f"   P&L: ${unrealized_pnl:+.2f}")
        else:
            # Short position
            unrealized_pnl = (avg_sell_price - current_price) * abs(net_units)
            print(f"\n📊 UNREALIZED P&L:")
            print(f"   Entry: ${avg_sell_price:.2f} x {abs(net_units)} units")
            print(f"   Current: ${current_price:.2f}")
            print(f"   P&L: ${unrealized_pnl:+.2f}")
    
    # Recent trades
    print(f"\n{'='*70}")
    print("📝 RECENT TRADES (Last 10)")
    print("="*70)
    for t in trades[-10:]:
        time_str = t.get('time', 'Unknown')[:19] if t.get('time') else 'Unknown'
        side = t.get('side', 'N/A').upper()
        units = t.get('units', 0)
        price = t.get('price', 0)
        print(f"{time_str} | {side:4} {units:2} @ ${price:.2f}")
    
    # Overnight fee warning
    now = datetime.now()
    is_ny_afternoon = now.hour >= 18 and now.hour < 22  # 2-6 PM EST
    
    if is_ny_afternoon and net_units != 0:
        print(f"\n{'='*70}")
        print("⚠️ OVERNIGHT FEE WARNING")
        print("="*70)
        print(f"   Holding {net_units} units past 5 PM EST")
        print(f"   Estimated overnight fee: ~${abs(net_units) * 0.05:.2f} - ${abs(net_units) * 0.15:.2f}")
        print("   Positions will auto-close at 21:30 UTC to avoid fees")
        print("="*70)
    
    # Estimate realized P&L from matched trades (simplified FIFO)
    print(f"\n{'='*70}")
    print("💵 ESTIMATED REALIZED P&L (Simplified FIFO)")
    print("="*70)
    
    # Match buys and sells
    buy_queue = [(t.get('units', 0), t.get('price', 0)) for t in buys]
    sell_queue = [(t.get('units', 0), t.get('price', 0)) for t in sells]
    
    realized_pnl = 0
    
    for sell_units, sell_price in sell_queue:
        while sell_units > 0 and buy_queue:
            buy_units, buy_price = buy_queue[0]
            
            if buy_units <= sell_units:
                # Full buy consumed
                realized_pnl += (sell_price - buy_price) * buy_units
                sell_units -= buy_units
                buy_queue.pop(0)
            else:
                # Partial buy consumed
                realized_pnl += (sell_price - buy_price) * sell_units
                buy_queue[0] = (buy_units - sell_units, buy_price)
                sell_units = 0
    
    print(f"Realized P&L from closed trades: ${realized_pnl:+.2f}")
    
    # Total estimated P&L
    total_estimated = realized_pnl + (unrealized_pnl if net_units != 0 else 0)
    print(f"\n{'='*70}")
    print(f"💰 TOTAL ESTIMATED P&L: ${total_estimated:+.2f}")
    print("="*70)
    print("\nNote: This is paper trading (simulated) P&L")
    print("      Not actual trading with real money.")
    
    # Auto-close settings
    print(f"\n⚙️ Auto-Close Settings:")
    print(f"   Market Close: 22:00 UTC (5 PM EST)")
    print(f"   Buffer: 30 minutes")
    print(f"   Current UTC Time: {now.strftime('%H:%M')}")
    if now.hour >= 21 and now.hour < 22:
        print("   🔄 Auto-close window ACTIVE - positions will close soon")

if __name__ == '__main__':
    calculate_pnl_report()
