#!/usr/bin/env python3
"""
OANDA Trading Bot with Learning & Monitoring
Real forex trading via OANDA API with paper trading mode.
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
LEARNING_DIR = DATA_DIR / 'learning'
PAPER_DIR = DATA_DIR / 'paper_trades'

# Ensure directories exist
for d in [LOGS_DIR, DATA_DIR, LEARNING_DIR, PAPER_DIR]:
    d.mkdir(parents=True, exist_ok=True)

class OandaTrader:
    """OANDA Forex Trading Bot with Learning"""
    
    def __init__(self):
        # Load config
        with open(CONFIG_PATH) as f:
            self.config = json.load(f)
        
        # OANDA API settings
        self.api_key = self.config.get('oanda_api_key')
        self.account_type = self.config.get('oanda_account_type', 'practice')
        self.account_id = self.config.get('oanda_account_id', '')
        self.paper_trading = self.config.get('paper_trading', True)
        self.learning_mode = self.config.get('learning_mode', True)
        
        # API URL
        if self.account_type == 'practice':
            self.base_url = 'https://api-fxpractice.oanda.com/v3'
        else:
            self.base_url = 'https://api-fxtrade.oanda.com/v3'
        
        # Headers
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
        
        # Discover account if needed
        if not self.account_id:
            self.account_id = self.discover_account()
            if self.account_id:
                self.save_account_id()
        
        self.logger.info(f'OANDA Trader initialized (Paper: {self.paper_trading})')
    
    def discover_account(self):
        """Auto-discover OANDA account ID."""
        try:
            url = f'{self.base_url}/accounts'
            response = requests.get(url, headers=self.headers)
            if response.status_code == 200:
                accounts = response.json().get('accounts', [])
                if accounts:
                    account_id = accounts[0]['id']
                    self.logger.info(f'Discovered account: {account_id}')
                    return account_id
                else:
                    self.logger.error('No accounts found')
            else:
                self.logger.error(f'Failed to list accounts: {response.status_code}')
        except Exception as e:
            self.logger.error(f'Account discovery error: {e}')
        return None
    
    def save_account_id(self):
        """Save discovered account ID to config."""
        try:
            self.config['oanda_account_id'] = self.account_id
            with open(CONFIG_PATH, 'w') as f:
                json.dump(self.config, f, indent=2)
            self.logger.info(f'Saved account ID to config')
        except Exception as e:
            self.logger.error(f'Failed to save account ID: {e}')
    
    def get_account_summary(self):
        """Get account information from OANDA."""
        if not self.account_id:
            return None
        try:
            url = f'{self.base_url}/accounts/{self.account_id}/summary'
            response = requests.get(url, headers=self.headers)
            if response.status_code == 200:
                return response.json()
            else:
                self.logger.error(f'Failed to get account: {response.status_code}')
        except Exception as e:
            self.logger.error(f'Error getting account: {e}')
        return None
    
    def get_prices(self, instruments):
        """Get current prices for instruments."""
        if not self.account_id:
            return None
        try:
            url = f'{self.base_url}/accounts/{self.account_id}/pricing'
            params = {'instruments': ','.join(instruments)}
            response = requests.get(url, headers=self.headers, params=params)
            if response.status_code == 200:
                return response.json()
            else:
                self.logger.error(f'Failed to get prices: {response.status_code}')
        except Exception as e:
            self.logger.error(f'Error getting prices: {e}')
        return None
    
    def get_open_positions(self):
        """Get list of open positions."""
        if not self.account_id:
            return None
        try:
            url = f'{self.base_url}/accounts/{self.account_id}/openPositions'
            response = requests.get(url, headers=self.headers)
            if response.status_code == 200:
                return response.json()
            else:
                self.logger.error(f'Failed to get positions: {response.status_code}')
        except Exception as e:
            self.logger.error(f'Error getting positions: {e}')
        return None
    
    def get_trade_history(self):
        """Get OANDA trade history."""
        if not self.account_id:
            return None
        try:
            url = f'{self.base_url}/accounts/{self.account_id}/trades'
            response = requests.get(url, headers=self.headers)
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            self.logger.error(f'Error getting trade history: {e}')
        return None
    
    def place_order(self, instrument, units, side='buy'):
        """Place a market order (or simulate in paper mode)."""
        if not self.account_id:
            return None
        
        order_units = units if side == 'buy' else -units
        
        if self.paper_trading:
            # Paper trading - simulate order
            paper_trade = {
                'time': datetime.now().isoformat(),
                'instrument': instrument,
                'units': order_units,
                'side': side,
                'status': 'simulated',
                'price': self.get_current_price(instrument)
            }
            self.save_paper_trade(paper_trade)
            self.logger.info(f'PAPER TRADE: {side} {units} {instrument}')
            return paper_trade
        
        # Real trading
        try:
            url = f'{self.base_url}/accounts/{self.account_id}/orders'
            order_data = {
                'order': {
                    'type': 'MARKET',
                    'instrument': instrument,
                    'units': str(order_units),
                    'timeInForce': 'FOK',
                    'positionFill': 'DEFAULT'
                }
            }
            response = requests.post(url, headers=self.headers, json=order_data)
            if response.status_code == 201:
                result = response.json()
                self.logger.info(f'Order placed: {side} {units} {instrument}')
                return result
            else:
                self.logger.error(f'Order failed: {response.status_code}')
        except Exception as e:
            self.logger.error(f'Error placing order: {e}')
        return None
    
    def get_current_price(self, instrument):
        """Get current price for an instrument."""
        prices = self.get_prices([instrument])
        if prices and 'prices' in prices:
            return float(prices['prices'][0]['closeoutBid'])
        return 0.0
    
    def save_paper_trade(self, trade):
        """Save paper trade to file."""
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = PAPER_DIR / f'paper_{timestamp}.json'
            with open(filename, 'w') as f:
                json.dump(trade, f, indent=2)
        except Exception as e:
            self.logger.error(f'Error saving paper trade: {e}')
    
    def load_learning_data(self):
        """Load learning data from previous runs."""
        try:
            learning_file = LEARNING_DIR / 'performance.json'
            if learning_file.exists():
                with open(learning_file) as f:
                    return json.load(f)
        except Exception as e:
            self.logger.error(f'Error loading learning data: {e}')
        return {'trades': [], 'win_rate': 0.0, 'total_pnl': 0.0, 'total_trades': 0, 'wins': 0, 'losses': 0}
    
    def save_learning_data(self, data):
        """Save learning data."""
        try:
            learning_file = LEARNING_DIR / 'performance.json'
            with open(learning_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            self.logger.error(f'Error saving learning data: {e}')
    
    def analyze_performance(self):
        """Analyze trading performance."""
        data = self.load_learning_data()
        trades = data.get('trades', [])
        
        if not trades:
            return {
                'win_rate': 0.0,
                'total_pnl': 0.0,
                'avg_profit': 0.0,
                'total_trades': 0,
                'wins': 0,
                'losses': 0
            }
        
        wins = sum(1 for t in trades if t.get('pnl', 0) > 0)
        win_rate = (wins / len(trades)) * 100 if trades else 0
        total_pnl = sum(t.get('pnl', 0) for t in trades)
        avg_profit = total_pnl / len(trades) if trades else 0
        
        return {
            'win_rate': win_rate,
            'total_pnl': total_pnl,
            'avg_profit': avg_profit,
            'total_trades': len(trades),
            'wins': wins,
            'losses': len(trades) - wins
        }
    
    def learning_strategy(self, instrument='EUR_USD'):
        """Strategy that learns from past performance."""
        # Get current price
        prices = self.get_prices([instrument])
        if not prices or 'prices' not in prices:
            return None
        
        current_price = float(prices['prices'][0]['closeoutBid'])
        
        # Check open positions
        positions = self.get_open_positions()
        has_position = False
        position_side = None
        
        if positions and 'positions' in positions:
            for pos in positions['positions']:
                if pos['instrument'] == instrument:
                    has_position = True
                    position_side = 'buy' if float(pos['long']['units']) > 0 else 'sell'
                    break
        
        # Analyze past performance
        perf = self.analyze_performance()
        win_rate = perf['win_rate']
        
        # Learning: adjust confidence based on win rate
        confidence = min(win_rate / 100, 0.9) if win_rate > 0 else 0.5
        
        # Simple strategy with learning
        if not has_position:
            # Check recent performance before trading
            if perf['total_trades'] < 5 or win_rate >= 40:
                self.logger.info(f'Learning Signal: BUY {instrument} at {current_price} (confidence: {confidence:.2f})')
                return {'action': 'buy', 'instrument': instrument, 'price': current_price, 'confidence': confidence}
            else:
                self.logger.info(f'Learning: Skipping trade due to low win rate ({win_rate:.1f}%)')
                return {'action': 'hold', 'instrument': instrument, 'reason': 'low_win_rate'}
        else:
            self.logger.info(f'Holding position in {instrument} at {current_price}')
            return {'action': 'hold', 'instrument': instrument, 'price': current_price}
    
    def generate_report(self, trade_data):
        """Generate trade report."""
        try:
            report_time = datetime.now().strftime('%Y%m%d_%H%M%S')
            report_path = DATA_DIR / 'reports' / f'{report_time}.json'
            
            report_data = {
                'time': report_time,
                'trade': trade_data,
                'account_type': self.account_type,
                'account_id': self.account_id,
                'paper_trading': self.paper_trading
            }
            
            with open(report_path, 'w') as f:
                json.dump(report_data, f, indent=2)
            
            self.logger.info(f'Report saved: {report_path}')
            return str(report_path)
        except Exception as e:
            self.logger.error(f'Report generation error: {e}')
            return None
    
    def run(self):
        """Main trading loop."""
        self.logger.info('Starting trading bot with learning...')
        print(f'🤖 Trading Bot Started (Paper: {self.paper_trading})')
        
        # Check account
        account = self.get_account_summary()
        if account:
            acc = account.get('account', {})
            balance = acc.get('balance', 'N/A')
            nav = acc.get('NAV', 'N/A')
            print(f'💰 Account Balance: {balance} | NAV: {nav}')
            self.logger.info(f'Account balance: {balance}')
        else:
            self.logger.error('Failed to connect to account')
            print('❌ Failed to connect to OANDA account')
            return
        
        # Show performance
        perf = self.analyze_performance()
        total_trades = perf.get('total_trades', 0)
        print(f'📊 Performance: Win Rate {perf["win_rate"]:.1f}% | Total P&L: {perf["total_pnl"]:.2f} | Trades: {total_trades}')
        
        # Run strategy
        for pair in self.config.get('trading_pairs', ['EUR_USD']):
            signal = self.learning_strategy(pair)
            if signal:
                if signal['action'] == 'buy':
                    units = self.config.get('default_units', 100)
                    order = self.place_order(pair, units, 'buy')
                    if order:
                        self.generate_report(signal)
                        print(f"✅ Trade {'SIMULATED' if self.paper_trading else 'PLACED'}: BUY {units} {pair} at {signal['price']}")
                elif signal['action'] == 'hold':
                    reason = signal.get('reason', '')
                    print(f"⏸️  Holding {pair}: {reason}")

def main():
    trader = OandaTrader()
    trader.run()

if __name__ == "__main__":
    main()
