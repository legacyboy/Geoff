#!/usr/bin/env python3
"""
Trump-Integrated Oil Trader
Checks Trump signals before trading, executes on high-confidence signals
"""

import json
import sqlite3
import requests
import logging
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, Optional

# Add bot path
import sys
sys.path.insert(0, '/home/claw/.openclaw/workspace/trading-bot/bot')
from trader import OilTrader

BASE_DIR = Path('/home/claw/.openclaw/workspace/trading-bot')
DB_PATH = BASE_DIR / 'data' / 'trading.db'
CONFIG_PATH = BASE_DIR / 'config' / 'config.json'

class TrumpIntegratedTrader(OilTrader):
    """Oil trader that incorporates Trump signals."""
    
    def __init__(self):
        super().__init__()
        self.trump_override = False
        self.last_trump_check = None
        self.active_trump_signal = None
        
        # Trump trading settings
        self.trump_confidence_threshold = 0.80
        self.trump_cooldown_minutes = 30
        self.max_trump_position_size = 50  # Larger for news events
        
        self.logger.info('Trump-Integrated Trader initialized')
    
    def _get_db(self) -> sqlite3.Connection:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        return conn
    
    def check_trump_signal(self) -> Optional[Dict]:
        """Check for recent high-confidence Trump signals."""
        with self._get_db() as conn:
            # Get unacted high-impact signals from last hour
            cur = conn.execute("""
                SELECT * FROM trump_posts 
                WHERE oil_relevant = 1 
                AND impact_score >= 50
                AND urgency IN ('immediate', 'high')
                AND trade_signal != 'HOLD'
                AND trade_signal != 'MONITOR'
                AND timestamp > datetime('now', '-1 hour')
                AND (acted_at IS NULL OR acted_at < datetime('now', '-30 minutes'))
                ORDER BY impact_score DESC, timestamp DESC
                LIMIT 1
            """)
            row = cur.fetchone()
            
            if row:
                return dict(row)
        return None
    
    def mark_signal_acted(self, post_id: str):
        """Mark a Trump signal as acted upon."""
        with self._get_db() as conn:
            conn.execute(
                "UPDATE trump_posts SET acted_at = ? WHERE post_id = ?",
                (datetime.now().isoformat(), post_id)
            )
            conn.commit()
    
    def execute_trump_trade(self, signal: Dict) -> Optional[Dict]:
        """Execute trade based on Trump signal."""
        trade_signal = signal.get('trade_signal', '')
        sentiment = signal.get('sentiment', 'neutral')
        impact = signal.get('impact_score', 50)
        
        # Determine direction
        if 'SHORT' in trade_signal or sentiment == 'bearish':
            side = 'sell'
            direction = 'SHORT'
        elif 'LONG' in trade_signal or sentiment == 'bullish':
            side = 'buy'
            direction = 'LONG'
        else:
            return None
        
        # Size based on impact score
        if impact >= 70:
            units = self.max_trump_position_size
        elif impact >= 50:
            units = 30
        else:
            units = 20
        
        # Choose asset - prefer WTI, fallback to Brent
        asset = 'WTICO_USD' if 'WTICO' in self.config.get('trading_assets', []) else self.asset
        
        trade = {
            'timestamp': datetime.now().isoformat(),
            'signal_source': 'trump',
            'trump_post_id': signal.get('post_id'),
            'trump_content': signal.get('content', '')[:100],
            'trump_impact': impact,
            'trump_sentiment': sentiment,
            'asset': asset,
            'side': side,
            'units': units,
            'direction': direction,
            'reason': f"Trump signal: {signal.get('urgency', 'normal')} priority"
        }
        
        # Execute
        if self.paper_trading:
            # Paper trade
            price = self.get_current_price()
            trade.update({
                'status': 'paper_filled',
                'fill_price': price['bid'] if price else 0,
                'paper': True
            })
            
            # Save to DB
            self._save_trade_to_db(trade)
            self.logger.info(f"TRUMP PAPER TRADE: {direction} {units} {asset}")
        else:
            # Live trade
            result = self._execute_oanda_trade(asset, units, side)
            if result:
                trade.update({
                    'status': 'filled',
                    'oanda_order_id': result.get('orderFillTransaction', {}).get('id'),
                    'paper': False
                })
                self._save_trade_to_db(trade)
                self.logger.info(f"TRUMP LIVE TRADE: {direction} {units} {asset}")
        
        # Mark signal as acted
        self.mark_signal_acted(signal['post_id'])
        
        return trade
    
    def _execute_oanda_trade(self, asset: str, units: int, side: str) -> Optional[Dict]:
        """Execute real OANDA trade."""
        try:
            url = f'{self.base_url}/accounts/{self.account_id}/orders'
            order_units = units if side == 'buy' else -units
            order_data = {
                'order': {
                    'type': 'MARKET',
                    'instrument': asset,
                    'units': str(order_units),
                    'timeInForce': 'FOK',
                    'positionFill': 'DEFAULT'
                }
            }
            response = requests.post(url, headers=self.headers, json=order_data)
            if response.status_code == 201:
                return response.json()
        except Exception as e:
            self.logger.error(f'OANDA trade error: {e}')
        return None
    
    def _save_trade_to_db(self, trade: Dict):
        """Save Trump trade to database."""
        with self._get_db() as conn:
            conn.execute("""
                INSERT INTO trades 
                (timestamp, asset, action, signal, position_size, leverage, unrealized_pnl)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                trade['timestamp'],
                trade['asset'],
                trade['side'],
                f"trump:{trade.get('trump_post_id', 'unknown')}",
                trade['units'],
                1.0,
                0.0
            ))
            conn.commit()
    
    def trump_aware_strategy(self) -> Optional[Dict]:
        """Trading strategy that prioritizes Trump signals."""
        
        # Step 1: Check for Trump signals FIRST
        trump_signal = self.check_trump_signal()
        
        if trump_signal:
            print(f"\n🦅 TRUMP SIGNAL DETECTED!")
            print(f"   Impact: {trump_signal['impact_score']}/100")
            print(f"   Urgency: {trump_signal['urgency']}")
            print(f"   Sentiment: {trump_signal['sentiment']}")
            print(f"   Signal: {trump_signal['trade_signal']}")
            
            # Execute Trump trade
            trade = self.execute_trump_trade(trump_signal)
            if trade:
                print(f"\n✅ TRUMP TRADE EXECUTED")
                print(f"   {trade['direction']} {trade['units']} {trade['asset']}")
                print(f"   Reason: {trade['reason']}")
                return trade
        
        # Step 2: No Trump signal - run normal strategy
        return super().oil_trading_strategy()
    
    def run_trump_cycle(self):
        """Execute one Trump-aware trading cycle."""
        timestamp = datetime.now().strftime('%H:%M:%S')
        print(f"\n🛢️  [{timestamp}] Trump-Aware Trading Cycle")
        print("-" * 50)
        
        result = self.trump_aware_strategy()
        
        if result:
            if result.get('signal_source') == 'trump':
                print(f"\n📊 Trump Trade Result:")
                print(f"   Asset: {result['asset']}")
                print(f"   Direction: {result['direction']}")
                print(f"   Units: {result['units']}")
                print(f"   Status: {result['status']}")
            else:
                # Normal strategy result
                action = result.get('action', 'hold')
                if action != 'hold':
                    print(f"✅ {action.upper()} signal from technical strategy")
                else:
                    print(f"⏸️  HOLD: {result.get('reason', 'no signal')}")
        else:
            print("⚠️  No trading signal")
        
        return result
    
    def run_continuous_trump(self):
        """Run continuous Trump-aware trading loop."""
        self.logger.info(f'Starting Trump-integrated trading every {self.interval}s')
        print(f"🦅 TRUMP-INTEGRATED OIL TRADER")
        print(f"=" * 50)
        print(f"Asset: {self.asset_name}")
        print(f"Interval: {self.interval}s")
        print(f"Mode: {'PAPER' if self.paper_trading else 'LIVE'}")
        print(f"Trump Override: ENABLED")
        print(f"Confidence Threshold: {self.trump_confidence_threshold}")
        print(f"=" * 50)
        print(f"Press Ctrl+C to stop\n")
        
        try:
            while True:
                self.run_trump_cycle()
                print(f"\n⏳ Waiting {self.interval}s...")
                time.sleep(self.interval)
        except KeyboardInterrupt:
            print("\n🛑 Trump trader stopped")


def main():
    trader = TrumpIntegratedTrader()
    trader.run_continuous_trump()


if __name__ == "__main__":
    main()
