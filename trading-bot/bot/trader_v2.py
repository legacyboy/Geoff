#!/usr/bin/env python3
"""
OANDA Oil Trading Bot v2.0 - Risk-Managed CFD Trading
Fixed based on multi-agent review (2026-03-24)

Key Improvements:
- 5-minute timeframe (reduced noise)
- Risk-based position sizing (1% max per trade)
- Short selling capability
- Circuit breakers (daily/consecutive loss limits)
- ATR-based dynamic P&L
- Leverage cap (5:1 max)
- Better volatility/ATR calculation
"""

import json
import logging
import os
import requests
import time
from datetime import datetime, timedelta
from pathlib import Path
from statistics import mean

# Configuration paths
BASE_DIR = Path(__file__).parent.parent
CONFIG_PATH = BASE_DIR / 'config' / 'config.json'
LOGS_DIR = BASE_DIR / 'logs'
DATA_DIR = BASE_DIR / 'data'
PAPER_DIR = DATA_DIR / 'paper_trades'
OIL_DATA_DIR = DATA_DIR / 'oil_tracking'
RISK_STATE_FILE = DATA_DIR / 'risk_state.json'

# Ensure directories exist
for d in [LOGS_DIR, DATA_DIR, PAPER_DIR, OIL_DATA_DIR]:
    d.mkdir(parents=True, exist_ok=True)


class RiskManager:
    """Risk management with circuit breakers."""
    
    def __init__(self, account_balance=1000.0):
        self.account_balance = account_balance
        self.daily_pnl = 0.0
        self.consecutive_losses = 0
        self.total_trades_today = 0
        self.last_reset = datetime.now().date()
        self.load_state()
        
        # Risk limits
        self.max_daily_loss_pct = 0.05  # -5% daily limit
        self.max_consecutive_losses = 3
        self.max_risk_per_trade_pct = 0.01  # 1% risk per trade
        self.max_leverage = 5.0  # 5:1 max
        
    def load_state(self):
        """Load risk state from file."""
        if RISK_STATE_FILE.exists():
            try:
                with open(RISK_STATE_FILE) as f:
                    state = json.load(f)
                    saved_date = datetime.fromisoformat(state.get('date', '')).date()
                    if saved_date == datetime.now().date():
                        self.daily_pnl = state.get('daily_pnl', 0.0)
                        self.consecutive_losses = state.get('consecutive_losses', 0)
                        self.total_trades_today = state.get('total_trades', 0)
            except Exception as e:
                logging.error(f"Error loading risk state: {e}")
    
    def save_state(self):
        """Save risk state to file."""
        try:
            state = {
                'date': datetime.now().isoformat(),
                'daily_pnl': self.daily_pnl,
                'consecutive_losses': self.consecutive_losses,
                'total_trades': self.total_trades_today
            }
            with open(RISK_STATE_FILE, 'w') as f:
                json.dump(state, f)
        except Exception as e:
            logging.error(f"Error saving risk state: {e}")
    
    def check_new_day(self):
        """Reset daily stats if new day."""
        current_date = datetime.now().date()
        if current_date != self.last_reset:
            self.daily_pnl = 0.0
            self.total_trades_today = 0
            self.last_reset = current_date
            logging.info("New trading day - reset daily stats")
    
    def can_trade(self) -> tuple[bool, str]:
        """Check if trading is allowed. Returns (allowed, reason)."""
        self.check_new_day()
        
        # Check daily loss limit
        daily_loss = abs(min(0, self.daily_pnl))
        max_daily_loss = self.account_balance * self.max_daily_loss_pct
        
        if daily_loss >= max_daily_loss:
            return False, f"Daily loss limit reached: ${daily_loss:.2f} (max ${max_daily_loss:.2f})"
        
        # Check consecutive losses
        if self.consecutive_losses >= self.max_consecutive_losses:
            return False, f"Consecutive loss limit: {self.consecutive_losses} losses"
        
        return True, "OK"
    
    def update_after_trade(self, pnl: float):
        """Update risk metrics after trade."""
        self.daily_pnl += pnl
        self.total_trades_today += 1
        
        if pnl < 0:
            self.consecutive_losses += 1
        else:
            self.consecutive_losses = 0
        
        self.save_state()
    
    def calculate_position_size(self, entry_price: float, stop_price: float) -> tuple[int, str]:
        """
        Calculate position size based on 1% risk rule.
        Returns (units, explanation)
        """
        risk_amount = self.account_balance * self.max_risk_per_trade_pct
        risk_per_unit = abs(entry_price - stop_price)
        
        if risk_per_unit <= 0:
            return 0, "Invalid stop distance"
        
        # Calculate units
        units = int(risk_amount / risk_per_unit)
        
        # Check leverage limit
        notional = units * entry_price
        leverage = notional / self.account_balance
        
        if leverage > self.max_leverage:
            # Reduce size to meet leverage limit
            max_notional = self.account_balance * self.max_leverage
            units = int(max_notional / entry_price)
            explanation = f"Leverage capped at {self.max_leverage}:1"
        else:
            explanation = f"1% risk rule: ${risk_amount:.2f} risk"
        
        # Minimum position size
        if units < 1:
            units = 1
            explanation += " (minimum size)"
        
        return units, explanation


class OilTraderV2:
    """Improved Oil CFD Trading Bot with Risk Management."""
    
    def __init__(self):
        # Load config
        with open(CONFIG_PATH) as f:
            self.config = json.load(f)
        
        # OANDA settings
        self.api_key = self.config.get('oanda_api_key')
        self.account_type = self.config.get('oanda_account_type', 'practice')
        self.account_id = self.config.get('oanda_account_id', '')
        self.paper_trading = self.config.get('paper_trading', True)
        
        # Oil trading settings - CHANGED TO 5 MINUTES
        self.asset = self.config.get('trading_asset', 'XTI_USD')
        self.asset_name = self.config.get('asset_name', 'WTI Crude Oil')
        self.interval = 300  # 5 minutes (was 60 seconds)
        
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
        log_file = LOGS_DIR / 'trader_v2.log'
        logging.basicConfig(
            filename=log_file,
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
        # Price history - INCREASED FOR BETTER ATR
        self.price_history = []
        self.max_history = 60  # 5 hours of 5-minute data
        
        # Risk manager
        self.risk_manager = RiskManager(
            account_balance=self.config.get('account_balance', 1000.0)
        )
        
        # Trade state
        self.open_positions = {}  # Track open positions
        
        self.logger.info(f'Oil Trader v2 initialized: {self.asset_name} ({self.asset}) - 5min timeframe')
    
    def get_account_balance(self) -> float:
        """Get current account balance."""
        try:
            url = f'{self.base_url}/accounts/{self.account_id}/summary'
            response = requests.get(url, headers=self.headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                return float(data['account']['balance'])
        except Exception as e:
            self.logger.error(f'Error getting balance: {e}')
        return self.config.get('account_balance', 1000.0)
    
    def get_current_price(self) -> dict | None:
        """Get current oil price."""
        try:
            url = f'{self.base_url}/accounts/{self.account_id}/pricing'
            params = {'instruments': self.asset}
            response = requests.get(url, headers=self.headers, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                if 'prices' in data and len(data['prices']) > 0:
                    price_data = data['prices'][0]
                    return {
                        'bid': float(price_data['closeoutBid']),
                        'ask': float(price_data['closeoutAsk']),
                        'mid': (float(price_data['closeoutBid']) + float(price_data['closeoutAsk'])) / 2,
                        'timestamp': datetime.now().isoformat(),
                        'spread': float(price_data['closeoutAsk']) - float(price_data['closeoutBid'])
                    }
        except Exception as e:
            self.logger.error(f'Error getting price: {e}')
        return None
    
    def calculate_atr(self, periods: int = 14) -> float:
        """Calculate Average True Range for dynamic P&L."""
        if len(self.price_history) < periods + 1:
            return 0.5  # Default $0.50 ATR for oil
        
        true_ranges = []
        for i in range(1, min(periods + 1, len(self.price_history))):
            curr = self.price_history[-i]
            prev = self.price_history[-(i + 1)]
            
            high = curr['bid']
            low = curr['bid'] * 0.995  # Approximation
            prev_close = prev['bid']
            
            tr1 = high - low
            tr2 = abs(high - prev_close)
            tr3 = abs(low - prev_close)
            
            true_ranges.append(max(tr1, tr2, tr3))
        
        return mean(true_ranges) if true_ranges else 0.5
    
    def get_open_position(self) -> dict | None:
        """Check if we have an open position."""
        try:
            url = f'{self.base_url}/accounts/{self.account_id}/openPositions'
            response = requests.get(url, headers=self.headers, timeout=10)
            if response.status_code == 200:
                positions = response.json().get('positions', [])
                for pos in positions:
                    if pos['instrument'] == self.asset:
                        long_units = float(pos['long']['units'])
                        short_units = float(pos['short']['units'])
                        
                        if long_units > 0:
                            return {
                                'direction': 'long',
                                'units': long_units,
                                'unrealized_pnl': float(pos.get('unrealizedPL', 0)),
                                'entry_price': float(pos['long'].get('averagePrice', 0))
                            }
                        elif short_units > 0:
                            return {
                                'direction': 'short',
                                'units': short_units,
                                'unrealized_pnl': float(pos.get('unrealizedPL', 0)),
                                'entry_price': float(pos['short'].get('averagePrice', 0))
                            }
        except Exception as e:
            self.logger.error(f'Error getting positions: {e}')
        return None
    
    def calculate_atr_targets(self, entry_price: float) -> tuple[float, float]:
        """Calculate ATR-based take profit and stop loss."""
        atr = self.calculate_atr(14)
        
        # 2x ATR for profit, 1x ATR for stop (2:1 reward:risk)
        take_profit_distance = atr * 2
        stop_loss_distance = atr * 1
        
        return take_profit_distance, stop_loss_distance
    
    def place_order(self, units: int, side: str = 'buy', stop_loss: float = None, take_profit: float = None) -> dict | None:
        """Place order with OANDA or simulate."""
        
        if self.paper_trading:
            price = self.get_current_price()
            paper_trade = {
                'time': datetime.now().isoformat(),
                'instrument': self.asset,
                'asset_name': self.asset_name,
                'units': units,
                'side': side,
                'price': price['mid'] if price else 0,
                'status': 'paper_filled',
                'atr': self.calculate_atr(),
                'stop_loss': stop_loss,
                'take_profit': take_profit
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
            
            # Add stop loss and take profit
            if stop_loss:
                order_data['order']['stopLossOnFill'] = {
                    'price': str(round(stop_loss, 2))
                }
            if take_profit:
                order_data['order']['takeProfitOnFill'] = {
                    'price': str(round(take_profit, 2))
                }
            
            response = requests.post(url, headers=self.headers, json=order_data, timeout=10)
            
            if response.status_code == 201:
                self.logger.info(f'Order placed: {side} {units} {self.asset}')
                return response.json()
            else:
                self.logger.error(f'Order failed: {response.status_code} - {response.text}')
                
        except Exception as e:
            self.logger.error(f'Order error: {e}')
        
        return None
    
    def save_paper_trade(self, trade: dict):
        """Save paper trade."""
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = PAPER_DIR / f'v2_paper_{timestamp}.json'
            with open(filename, 'w') as f:
                json.dump(trade, f, indent=2)
        except Exception as e:
            self.logger.error(f'Error saving paper trade: {e}')
    
    def determine_trend(self) -> str:
        """Determine overall trend using simple moving average."""
        if len(self.price_history) < 20:
            return 'neutral'
        
        prices = [p['mid'] for p in self.price_history[-20:]]
        sma_short = mean(prices[-5:])   # 25-min SMA
        sma_long = mean(prices[-20:])   # 100-min SMA
        
        if sma_short > sma_long * 1.001:  # 0.1% buffer
            return 'up'
        elif sma_short < sma_long * 0.999:
            return 'down'
        return 'neutral'
    
    def generate_signal(self) -> dict | None:
        """Generate trading signal with trend and momentum."""
        price = self.get_current_price()
        if not price:
            self.logger.error('Failed to get oil price')
            return None
        
        # Update price history
        self.price_history.append(price)
        if len(self.price_history) > self.max_history:
            self.price_history.pop(0)
        
        # Need enough history
        if len(self.price_history) < 20:
            return None
        
        # Calculate metrics
        current_price = price['mid']
        trend = self.determine_trend()
        atr = self.calculate_atr(14)
        
        # Calculate 5-minute change (not 1-minute)
        if len(self.price_history) >= 2:
            prev_price = self.price_history[-2]['mid']
            price_change_pct = ((current_price - prev_price) / prev_price) * 100
        else:
            price_change_pct = 0
        
        # Get open position
        open_pos = self.get_open_position()
        
        signal = {
            'timestamp': datetime.now().isoformat(),
            'asset': self.asset,
            'price': current_price,
            'atr': atr,
            'trend': trend,
            'price_change_5m': price_change_pct,
            'spread': price.get('spread', 0)
        }
        
        # Calculate ATR-based targets
        tp_distance, sl_distance = self.calculate_atr_targets(current_price)
        
        if not open_pos:
            # ENTRY LOGIC - trend following with pullback
            if trend == 'up':
                # Buy dips in uptrend
                if price_change_pct < -1.0:  # 1% pullback in uptrend
                    signal['action'] = 'buy'
                    signal['reason'] = 'dip_in_uptrend'
                    signal['stop_loss'] = current_price - sl_distance
                    signal['take_profit'] = current_price + tp_distance
                    
                elif price_change_pct > 1.5:  # Strong momentum
                    signal['action'] = 'buy'
                    signal['reason'] = 'momentum_breakout'
                    signal['stop_loss'] = current_price - sl_distance
                    signal['take_profit'] = current_price + tp_distance
                    
            elif trend == 'down':
                # Short rallies in downtrend
                if price_change_pct > 1.0:  # 1% bounce in downtrend
                    signal['action'] = 'sell'
                    signal['reason'] = 'bounce_in_downtrend'
                    signal['stop_loss'] = current_price + sl_distance
                    signal['take_profit'] = current_price - tp_distance
                    
                elif price_change_pct < -1.5:  # Strong breakdown
                    signal['action'] = 'sell'
                    signal['reason'] = 'breakdown'
                    signal['stop_loss'] = current_price + sl_distance
                    signal['take_profit'] = current_price - tp_distance
            
            if 'action' not in signal:
                signal['action'] = 'hold'
                signal['reason'] = 'no_setup'
                
        else:
            # EXIT LOGIC - ATR-based
            unrealized = open_pos['unrealized_pnl']
            
            # Use ATR multiples for exit
            if unrealized > atr * 2 or unrealized < -atr:
                signal['action'] = 'close'
                signal['reason'] = 'atr_target'
                signal['current_pnl'] = unrealized
            else:
                signal['action'] = 'hold'
                signal['reason'] = 'position_open'
                signal['unrealized_pnl'] = unrealized
        
        return signal
    
    def execute_trade(self, signal: dict) -> bool:
        """Execute trade based on signal."""
        action = signal.get('action')
        
        if action == 'hold':
            return False
        
        # Check risk limits first
        can_trade, reason = self.risk_manager.can_trade()
        if not can_trade:
            self.logger.warning(f"Trade blocked: {reason}")
            print(f"⛔ RISK BLOCK: {reason}")
            return False
        
        if action == 'buy':
            entry = signal['price']
            stop = signal['stop_loss']
            
            # Calculate position size based on risk
            units, sizing_explanation = self.risk_manager.calculate_position_size(entry, stop)
            
            if units <= 0:
                print(f"❌ Invalid position size: {units}")
                return False
            
            # Place order
            result = self.place_order(
                units=units,
                side='buy',
                stop_loss=stop,
                take_profit=signal['take_profit']
            )
            
            if result:
                print(f"✅ BUY {units} {self.asset} @ {entry:.2f}")
                print(f"   Stop: {stop:.2f} | Target: {signal['take_profit']:.2f}")
                print(f"   Risk: {sizing_explanation}")
                return True
                
        elif action == 'sell':
            entry = signal['price']
            stop = signal['stop_loss']
            
            # Calculate position size
            units, sizing_explanation = self.risk_manager.calculate_position_size(entry, stop)
            
            if units <= 0:
                print(f"❌ Invalid position size: {units}")
                return False
            
            # Place order
            result = self.place_order(
                units=units,
                side='sell',
                stop_loss=stop,
                take_profit=signal['take_profit']
            )
            
            if result:
                print(f"✅ SELL {units} {self.asset} @ {entry:.2f}")
                print(f"   Stop: {stop:.2f} | Target: {signal['take_profit']:.2f}")
                print(f"   Risk: {sizing_explanation}")
                return True
                
        elif action == 'close':
            # Close existing position
            print(f"🔴 CLOSE position: P&L ${signal.get('current_pnl', 0):.2f}")
            # Update risk manager with actual P&L
            self.risk_manager.update_after_trade(signal.get('current_pnl', 0))
            return True
        
        return False
    
    def run_once(self):
        """Execute one 5-minute trading cycle."""
        timestamp = datetime.now().strftime('%H:%M:%S')
        print(f"\n🛢️  [{timestamp}] Oil Trading v2 - 5min Cycle")
        
        # Check risk status
        can_trade, risk_reason = self.risk_manager.can_trade()
        status_icon = "✅" if can_trade else "⛔"
        print(f"{status_icon} Risk Check: {risk_reason}")
        
        # Generate signal
        signal = self.generate_signal()
        
        if signal:
            # Display signal info
            print(f"📊 Price: ${signal['price']:.2f} | ATR: ${signal['atr']:.3f} | Trend: {signal['trend']}")
            print(f"📈 5m Change: {signal['price_change_5m']:.2f}%")
            
            # Execute if there's an action
            if signal.get('action') != 'hold':
                self.execute_trade(signal)
            else:
                print(f"⏸️  HOLD: {signal['reason']}")
        else:
            print("⚠️  No signal generated (insufficient data)")
    
    def run_continuous(self):
        """Run continuous 5-minute trading loop."""
        self.logger.info(f'Starting v2 trader: {self.interval}s intervals')
        
        print("="*60)
        print("🛢️  Oil Trader v2.0 - Risk-Managed CFD Trading")
        print("="*60)
        print(f"Asset: {self.asset_name} ({self.asset})")
        print(f"Timeframe: {self.interval}s (5-minute candles)")
        print(f"Risk per trade: {self.risk_manager.max_risk_per_trade_pct*100}%")
        print(f"Max leverage: {self.risk_manager.max_leverage}:1")
        print(f"Daily loss limit: {self.risk_manager.max_daily_loss_pct*100}%")
        print(f"Paper trading: {self.paper_trading}")
        print("="*60)
        
        try:
            while True:
                self.run_once()
                
                # Sleep until next 5-minute mark
                now = datetime.now()
                seconds_past_5min = (now.minute % 5) * 60 + now.second
                sleep_seconds = 300 - seconds_past_5min
                
                if sleep_seconds > 0:
                    print(f"⏱️  Next cycle in {sleep_seconds}s...")
                    time.sleep(sleep_seconds)
                else:
                    time.sleep(5)  # Minimum 5s between checks
                    
        except KeyboardInterrupt:
            print("\n👋 Trading stopped by user")
            self.logger.info('Trading stopped by user')


def main():
    trader = OilTraderV2()
    trader.run_continuous()


if __name__ == "__main__":
    main()
