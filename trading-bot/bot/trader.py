#!/usr/bin/env python3
"""
OANDA Trading Bot
Real forex trading via OANDA API.
"""

import json
import logging
import os
import requests
import time
from datetime import datetime

# Configuration paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_PATH = os.path.join(BASE_DIR, 'config', 'config.json')
LOGS_DIR = os.path.join(BASE_DIR, 'logs')
DATA_DIR = os.path.join(BASE_DIR, 'data')

# Ensure directories exist
os.makedirs(LOGS_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(os.path.join(DATA_DIR, 'reports'), exist_ok=True)

class OandaTrader:
    """OANDA Forex Trading Bot"""
    
    def __init__(self):
        # Load config
        with open(CONFIG_PATH) as f:
            self.config = json.load(f)
        
        # OANDA API settings
        self.api_key = self.config.get('oanda_api_key')
        self.account_type = self.config.get('oanda_account_type', 'practice')
        self.account_id = self.config.get('oanda_account_id', '')
        
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
        log_file = os.path.join(LOGS_DIR, 'trader.log')
        logging.basicConfig(
            filename=log_file,
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
        self.logger.info('OANDA Trader initialized')
    
    def get_account_summary(self):
        """Get account information from OANDA."""
        try:
            url = f'{self.base_url}/accounts/{self.account_id}/summary'
            response = requests.get(url, headers=self.headers)
            if response.status_code == 200:
                return response.json()
            else:
                self.logger.error(f'Failed to get account: {response.status_code} - {response.text}')
                return None
        except Exception as e:
            self.logger.error(f'Error getting account: {e}')
            return None
    
    def get_prices(self, instruments):
        """Get current prices for instruments."""
        try:
            url = f'{self.base_url}/accounts/{self.account_id}/pricing'
            params = {'instruments': ','.join(instruments)}
            response = requests.get(url, headers=self.headers, params=params)
            if response.status_code == 200:
                return response.json()
            else:
                self.logger.error(f'Failed to get prices: {response.status_code}')
                return None
        except Exception as e:
            self.logger.error(f'Error getting prices: {e}')
            return None
    
    def get_open_positions(self):
        """Get list of open positions."""
        try:
            url = f'{self.base_url}/accounts/{self.account_id}/openPositions'
            response = requests.get(url, headers=self.headers)
            if response.status_code == 200:
                return response.json()
            else:
                self.logger.error(f'Failed to get positions: {response.status_code}')
                return None
        except Exception as e:
            self.logger.error(f'Error getting positions: {e}')
            return None
    
    def place_order(self, instrument, units, side='buy'):
        """Place a market order."""
        try:
            url = f'{self.base_url}/accounts/{self.account_id}/orders'
            
            # Determine direction
            if side == 'buy':
                order_units = units
            else:
                order_units = -units
            
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
                self.logger.error(f'Order failed: {response.status_code} - {response.text}')
                return None
        except Exception as e:
            self.logger.error(f'Error placing order: {e}')
            return None
    
    def simple_strategy(self, instrument='EUR_USD'):
        """Simple moving average crossover strategy."""
        try:
            # Get current price
            prices = self.get_prices([instrument])
            if not prices or 'prices' not in prices:
                return None
            
            current_price = float(prices['prices'][0]['closeoutBid'])
            
            # Check existing positions
            positions = self.get_open_positions()
            has_position = False
            if positions and 'positions' in positions:
                for pos in positions['positions']:
                    if pos['instrument'] == instrument:
                        has_position = True
                        break
            
            # Simple strategy: No position = buy, has position = hold
            # In production, add proper technical analysis
            if not has_position:
                self.logger.info(f'Signal: BUY {instrument} at {current_price}')
                return {'action': 'buy', 'instrument': instrument, 'price': current_price}
            else:
                self.logger.info(f'Holding position in {instrument} at {current_price}')
                return {'action': 'hold', 'instrument': instrument, 'price': current_price}
                
        except Exception as e:
            self.logger.error(f'Strategy error: {e}')
            return None
    
    def generate_report(self, trade_data):
        """Generate trade report."""
        try:
            report_time = datetime.now().strftime('%Y%m%d_%H%M%S')
            report_path = os.path.join(DATA_DIR, 'reports', f'{report_time}.json')
            
            report_data = {
                'time': report_time,
                'trade': trade_data,
                'account_type': self.account_type,
                'account_id': self.account_id
            }
            
            with open(report_path, 'w') as f:
                json.dump(report_data, f, indent=2)
            
            self.logger.info(f'Report saved: {report_path}')
            return report_path
        except Exception as e:
            self.logger.error(f'Report generation error: {e}')
            return None
    
    def run(self):
        """Main trading loop."""
        self.logger.info('Starting trading bot...')
        
        # Check account
        account = self.get_account_summary()
        if account:
            balance = account.get('account', {}).get('balance', 'N/A')
            self.logger.info(f'Account balance: {balance}')
            print(f'Account connected. Balance: {balance}')
        else:
            self.logger.error('Failed to connect to account')
            print('Failed to connect to OANDA account')
            return
        
        # Run strategy
        for pair in self.config.get('trading_pairs', ['EUR_USD']):
            signal = self.simple_strategy(pair)
            if signal:
                if signal['action'] == 'buy':
                    units = self.config.get('default_units', 100)
                    order = self.place_order(pair, units, 'buy')
                    if order:
                        self.generate_report(signal)
                        print(f"Trade executed: BUY {units} {pair} at {signal['price']}")
                elif signal['action'] == 'hold':
                    self.generate_report(signal)
                    print(f"Holding position in {pair} at {signal['price']}")

def main():
    trader = OandaTrader()
    trader.run()

if __name__ == "__main__":
    main()
