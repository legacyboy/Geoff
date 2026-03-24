#!/usr/bin/env python3
"""
OANDA Oil Trading Bot with 60-Second Intervals
Trades WTI Crude Oil (XTI_USD) with volatility-based position sizing.
"""

import json
import logging
import os
import requests
import time
from datetime import datetime
from pathlib import Path

# Configuration paths
BASE_DIR = Path(__file__).parent.parent
CONFIG_PATH = BASE_DIR / 'config' / 'config.json'
LOGS_DIR = BASE_DIR / 'logs'
DATA_DIR = BASE_DIR / 'data'
PAPER_DIR = DATA_DIR / 'paper_trades'
OIL_DATA_DIR = DATA_DIR / 'oil_tracking'

# Ensure directories exist
for d in [LOGS_DIR, DATA_DIR, PAPER_DIR, OIL_DATA_DIR]:
    d.mkdir(parents=True, exist_ok=True)

class OilTrader:
    """WTI Oil Trading Bot with Volatility Monitoring"""
    
    def __init__(self):
        # Load config
        with open(CONFIG_PATH) as f:
            self.config = json.load(f)
        
        # OANDA settings
        self.api_key = self.config.get('oanda_api_key')
        self.account_type = self.config.get('oanda_account_type', 'practice')
        self.account_id = self.config.get('oanda_account_id', '')
        self.paper_trading = self.config.get('paper_trading', True)
        
        # Oil trading settings
        self.asset = self.config.get('trading_asset', 'XTI_USD')
        self.asset_name = self.config.get('asset_name', 'WTI Crude Oil')
        self.interval = self.config.get('trading_interval_seconds', 60)
        self.volatility_threshold = self.config.get('volatility_threshold', 2.0)
        
        # API URL
        if self.account_type == 'practice':
            self.base_url = 'https://api-fxpractice.oanda.com/v3'
        else:
            self.base_url = 'https://api-fxtrade.oanda.com/v3'
        
        self.headers = {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json'
        }
        
        # Setup logging
        log_file = LOGS_DIR / 'trader.log'
        logging.basicConfig(
            filename=log_file,
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
        # Price history for volatility
        self.price_history = []
        self.max_history = 20
        
        self.logger.info(f'Oil Trader initialized for {self.asset_name} ({self.asset})')
    
    def get_current_price(self):
        """Get current oil price."""
        try:
            url = f'{self.base_url}/accounts/{self.account_id}/pricing'
            params = {'instruments': self.asset}
            response = requests.get(url, headers=self.headers, params=params)
            if response.status_code == 200:
                data = response.json()
                if 'prices' in data and len(data['prices']) > 0:
                    price_data = data['prices'][0]
                    return {
                        'bid': float(price_data['closeoutBid']),
                        'ask': float(price_data['closeoutAsk']),
                        'timestamp': datetime.now().isoformat()
                    }
        except Exception as e:
            self.logger.error(f'Error getting price: {e}')
        return None
    
    def calculate_volatility(self):
        """Calculate price volatility from history."""
        if len(self.price_history) < 5:
            return 0.0
        
        prices = [p['bid'] for p in self.price_history]
        avg_price = sum(prices) / len(prices)
        
        # Calculate standard deviation
        variance = sum((p - avg_price) ** 2 for p in prices) / len(prices)
        std_dev = variance ** 0.5
        
        # Volatility as percentage
        volatility = (std_dev / avg_price) * 100 if avg_price > 0 else 0
        return volatility
    
    def get_position_size(self):
        """Calculate position size based on volatility."""
        volatility = self.calculate_volatility()
        base_units = self.config.get('default_units', 10)
        
        if volatility > self.volatility_threshold * 2:
            # High volatility - reduce position
            multiplier = 0.3
            self.logger.info(f'High volatility ({volatility:.2f}%) - reducing position')
        elif volatility > self.volatility_threshold:
            # Medium volatility - normal position
            multiplier = 0.7
            self.logger.info(f'Medium volatility ({volatility:.2f}%) - cautious position')
        else:
            # Low volatility - full position
            multiplier = 1.0
            self.logger.info(f'Low volatility ({volatility:.2f}%) - full position')
        
        return int(base_units * multiplier)
    
    def get_open_position(self):
        """Check if we have an open oil position."""
        try:
            url = f'{self.base_url}/accounts/{self.account_id}/openPositions'
            response = requests.get(url, headers=self.headers)
            if response.status_code == 200:
                positions = response.json().get('positions', [])
                for pos in positions:
                    if pos['instrument'] == self.asset:
                        return {
                            'long_units': float(pos['long']['units']),
                            'short_units': float(pos['short']['units']),
                            'unrealized_pnl': float(pos.get('unrealizedPL', 0))
                        }
        except Exception as e:
            self.logger.error(f'Error getting positions: {e}')
        return None
    
    def place_order(self, units, side='buy'):
        """Place order (or simulate)."""
        if self.paper_trading:
            price = self.get_current_price()
            paper_trade = {
                'time': datetime.now().isoformat(),
                'instrument': self.asset,
                'asset_name': self.asset_name,
                'units': units,
                'side': side,
                'price': price['bid'] if price else 0,
                'status': 'paper_filled',
                'volatility': self.calculate_volatility()
            }
            self.save_paper_trade(paper_trade)
            return paper_trade
        
        # Real trading
        try:
            url = f'{self.base_url}/accounts/{self.account_id}/orders'
            order_units = units if side == 'buy' else -units
            order_data = {
                'order': {
                    'type': 'MARKET',
                    'instrument': self.asset,
                    'units': str(order_units),
                    'timeInForce': 'FOK',
                    'positionFill': 'DEFAULT'
                }
            }
            response = requests.post(url, headers=self.headers, json=order_data)
            if response.status_code == 201:
                self.logger.info(f'Order placed: {side} {units} {self.asset}')
                return response.json()
        except Exception as e:
            self.logger.error(f'Order error: {e}')
        return None
    
    def save_paper_trade(self, trade):
        """Save paper trade."""
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = PAPER_DIR / f'paper_{timestamp}.json'
            with open(filename, 'w') as f:
                json.dump(trade, f, indent=2)
            print(f"💾 Paper trade saved: {filename}")
        except Exception as e:
            self.logger.error(f'Error saving paper trade: {e}')
    
    def save_oil_data(self, price, volatility, decision):
        """Save oil tracking data."""
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            data = {
                'timestamp': timestamp,
                'asset': self.asset,
                'price': price,
                'volatility': volatility,
                'decision': decision
            }
            filename = OIL_DATA_DIR / f'oil_{timestamp}.json'
            with open(filename, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            self.logger.error(f'Error saving oil data: {e}')
    
    def oil_trading_strategy(self):
        """Oil trading strategy with volatility adjustment."""
        price = self.get_current_price()
        if not price:
            self.logger.error('Failed to get oil price')
            return None
        
        # Update price history
        self.price_history.append(price)
        if len(self.price_history) > self.max_history:
            self.price_history.pop(0)
        
        current_price = price['bid']
        volatility = self.calculate_volatility()
        position_size = self.get_position_size()
        open_pos = self.get_open_position()
        
        # Simple momentum strategy
        if len(self.price_history) >= 3:
            prev_price = self.price_history[-2]['bid']
            price_change = ((current_price - prev_price) / prev_price) * 100
            
            decision = {
                'timestamp': datetime.now().isoformat(),
                'asset': self.asset,
                'price': current_price,
                'volatility': volatility,
                'position_size': position_size,
                'price_change_1m': price_change
            }
            
            # Trading logic
            if not open_pos:
                if price_change < -0.5 and volatility < self.volatility_threshold * 1.5:
                    # Price dropped, low vol - buy
                    decision['action'] = 'buy'
                    decision['reason'] = 'dip_buy'
                    self.logger.info(f'BUY signal: {self.asset} at {current_price}')
                elif price_change > 0.5 and volatility < self.volatility_threshold * 1.5:
                    # Price rose, low vol - trend following
                    decision['action'] = 'buy'
                    decision['reason'] = 'momentum'
                    self.logger.info(f'MOMENTUM signal: {self.asset} at {current_price}')
                else:
                    decision['action'] = 'hold'
                    decision['reason'] = 'no_signal'
            else:
                # Have position - check for exit
                unrealized = open_pos.get('unrealized_pnl', 0)
                if unrealized > 20 or unrealized < -10:
                    decision['action'] = 'close'
                    decision['reason'] = 'take_profit_or_stop_loss'
                    self.logger.info(f'CLOSE signal: P&L {unrealized}')
                else:
                    decision['action'] = 'hold'
                    decision['reason'] = 'position_open'
            
            self.save_oil_data(current_price, volatility, decision)
            return decision
        
        return None
    
    def run_once(self):
        """Execute one trading cycle."""
        timestamp = datetime.now().strftime('%H:%M:%S')
        print(f"\n🛢️  [{timestamp}] Oil Trading Cycle - {self.asset_name}")
        
        signal = self.oil_trading_strategy()
        if signal:
            action = signal.get('action')
            
            if action == 'buy':
                size = signal.get('position_size', 10)
                result = self.place_order(size, 'buy')
                if result:
                    print(f"✅ BUY {size} {self.asset} @ {signal['price']:.2f} ({signal['reason']})")
                    print(f"📊 Volatility: {signal['volatility']:.2f}% | Change: {signal['price_change_1m']:.3f}%")
            
            elif action == 'close':
                print(f"🔴 CLOSE position: {signal['reason']}")
            
            elif action == 'hold':
                print(f"⏸️  HOLD: {signal['reason']} | Price: {signal['price']:.2f}")
        else:
            print("⚠️  No signal generated")
    
    def run_continuous(self):
        """Run continuous 60-second trading loop."""
        self.logger.info(f'Starting continuous oil trading every {self.interval}s')
        print(f"🛢️  OIL TRADER STARTED")
        print(f"Asset: {self.asset_name} ({self.asset})")
        print(f"Interval: {self.interval} seconds")
        print(f"Mode: {'PAPER' if self.paper_trading else 'LIVE'} TRADING")
        print(f"Press Ctrl+C to stop\n")
        
        try:
            while True:
                self.run_once()
                print(f"⏳ Waiting {self.interval}s for next cycle...")
                time.sleep(self.interval)
        except KeyboardInterrupt:
            print("\n🛑 Oil trader stopped by user")
            self.logger.info('Oil trader stopped')

def main():
    trader = OilTrader()
    trader.run_continuous()

if __name__ == "__main__":
    main()
