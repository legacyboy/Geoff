#!/usr/bin/env python3
"""
Performance Tracker for Trading Bot v2
Tracks P&L, win rate, and generates daily reports
"""

import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional

BASE_DIR = Path(__file__).parent.parent
DATA_DIR = BASE_DIR / 'data'
PAPER_DIR = DATA_DIR / 'paper_trades'
PERF_DIR = DATA_DIR / 'performance'
DB_FILE = DATA_DIR / 'performance.db'

# Ensure directories exist
PERF_DIR.mkdir(parents=True, exist_ok=True)


class PerformanceTracker:
    """Track trading performance and P&L."""
    
    def __init__(self):
        self.db_file = DB_FILE
        self._init_db()
    
    def _init_db(self):
        """Initialize SQLite database for performance tracking."""
        with sqlite3.connect(self.db_file) as conn:
            cursor = conn.cursor()
            
            # Trades table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS trades (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    date TEXT NOT NULL,
                    instrument TEXT NOT NULL,
                    side TEXT NOT NULL,
                    units REAL NOT NULL,
                    entry_price REAL NOT NULL,
                    exit_price REAL,
                    stop_loss REAL,
                    take_profit REAL,
                    status TEXT NOT NULL,
                    realized_pnl REAL,
                    holding_minutes REAL
                )
            ''')
            
            # Daily summary table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS daily_summary (
                    date TEXT PRIMARY KEY,
                    total_trades INTEGER DEFAULT 0,
                    winning_trades INTEGER DEFAULT 0,
                    losing_trades INTEGER DEFAULT 0,
                    total_pnl REAL DEFAULT 0.0,
                    avg_win REAL DEFAULT 0.0,
                    avg_loss REAL DEFAULT 0.0,
                    largest_win REAL DEFAULT 0.0,
                    largest_loss REAL DEFAULT 0.0,
                    win_rate REAL DEFAULT 0.0
                )
            ''')
            
            conn.commit()
    
    def add_trade(self, trade: Dict):
        """Add a trade to the database."""
        timestamp = trade.get('time', datetime.now().isoformat())
        date = timestamp[:10]  # YYYY-MM-DD
        
        with sqlite3.connect(self.db_file) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO trades 
                (timestamp, date, instrument, side, units, entry_price, 
                 stop_loss, take_profit, status, realized_pnl)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                timestamp,
                date,
                trade.get('instrument', 'WTICO_USD'),
                trade.get('side', 'buy'),
                trade.get('units', 0),
                trade.get('price', 0),
                trade.get('stop_loss'),
                trade.get('take_profit'),
                trade.get('status', 'open'),
                trade.get('realized_pnl')
            ))
            conn.commit()
    
    def close_trade(self, trade_id: int, exit_price: float, realized_pnl: float):
        """Close a trade and update P&L."""
        with sqlite3.connect(self.db_file) as conn:
            cursor = conn.cursor()
            
            # Get trade entry time
            cursor.execute('SELECT timestamp FROM trades WHERE id = ?', (trade_id,))
            result = cursor.fetchone()
            
            if result:
                entry_time = datetime.fromisoformat(result[0])
                exit_time = datetime.now()
                holding_minutes = (exit_time - entry_time).total_seconds() / 60
                
                cursor.execute('''
                    UPDATE trades 
                    SET exit_price = ?, realized_pnl = ?, status = 'closed', 
                        holding_minutes = ?
                    WHERE id = ?
                ''', (exit_price, realized_pnl, holding_minutes, trade_id))
                
                conn.commit()
                self._update_daily_summary(entry_time.date().isoformat())
    
    def _update_daily_summary(self, date: str):
        """Recalculate daily summary."""
        with sqlite3.connect(self.db_file) as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT 
                    COUNT(*) as total,
                    SUM(CASE WHEN realized_pnl > 0 THEN 1 ELSE 0 END) as wins,
                    SUM(CASE WHEN realized_pnl < 0 THEN 1 ELSE 0 END) as losses,
                    SUM(realized_pnl) as total_pnl,
                    AVG(CASE WHEN realized_pnl > 0 THEN realized_pnl END) as avg_win,
                    AVG(CASE WHEN realized_pnl < 0 THEN realized_pnl END) as avg_loss,
                    MAX(realized_pnl) as largest_win,
                    MIN(realized_pnl) as largest_loss
                FROM trades 
                WHERE date = ? AND status = 'closed'
            ''', (date,))
            
            result = cursor.fetchone()
            
            if result and result[0] > 0:
                total, wins, losses, total_pnl, avg_win, avg_loss, largest_win, largest_loss = result
                win_rate = (wins / total * 100) if total > 0 else 0
                
                cursor.execute('''
                    INSERT OR REPLACE INTO daily_summary 
                    (date, total_trades, winning_trades, losing_trades, total_pnl,
                     avg_win, avg_loss, largest_win, largest_loss, win_rate)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (date, total, wins, losses, total_pnl, avg_win or 0, 
                      avg_loss or 0, largest_win or 0, largest_loss or 0, win_rate))
                
                conn.commit()
    
    def get_daily_report(self, date: Optional[str] = None) -> Dict:
        """Get performance report for a specific date or today."""
        if date is None:
            date = datetime.now().date().isoformat()
        
        with sqlite3.connect(self.db_file) as conn:
            cursor = conn.cursor()
            
            # Get summary
            cursor.execute('''
                SELECT * FROM daily_summary WHERE date = ?
            ''', (date,))
            
            row = cursor.fetchone()
            
            if row:
                return {
                    'date': row[0],
                    'total_trades': row[1],
                    'winning_trades': row[2],
                    'losing_trades': row[3],
                    'total_pnl': row[4],
                    'avg_win': row[5],
                    'avg_loss': row[6],
                    'largest_win': row[7],
                    'largest_loss': row[8],
                    'win_rate': row[9]
                }
            
            # Return empty report if no data
            return {
                'date': date,
                'total_trades': 0,
                'winning_trades': 0,
                'losing_trades': 0,
                'total_pnl': 0.0,
                'avg_win': 0.0,
                'avg_loss': 0.0,
                'largest_win': 0.0,
                'largest_loss': 0.0,
                'win_rate': 0.0
            }
    
    def get_open_trades(self) -> List[Dict]:
        """Get all open trades."""
        with sqlite3.connect(self.db_file) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM trades WHERE status = 'paper_filled' OR status = 'open'
                ORDER BY timestamp DESC
            ''')
            
            return [dict(row) for row in cursor.fetchall()]
    
    def calculate_unrealized_pnl(self, current_price: float) -> Dict:
        """Calculate unrealized P&L for open positions."""
        open_trades = self.get_open_trades()
        
        total_unrealized = 0
        position_count = 0
        
        for trade in open_trades:
            entry = trade['entry_price']
            units = trade['units']
            side = trade['side']
            
            if side == 'buy':
                unrealized = (current_price - entry) * units
            else:  # sell
                unrealized = (entry - current_price) * units
            
            total_unrealized += unrealized
            position_count += 1
        
        return {
            'open_positions': position_count,
            'unrealized_pnl': total_unrealized,
            'current_price': current_price
        }
    
    def get_all_time_stats(self) -> Dict:
        """Get all-time performance statistics."""
        with sqlite3.connect(self.db_file) as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT 
                    COUNT(*) as total_trades,
                    SUM(CASE WHEN realized_pnl > 0 THEN 1 ELSE 0 END) as wins,
                    SUM(CASE WHEN realized_pnl < 0 THEN 1 ELSE 0 END) as losses,
                    SUM(realized_pnl) as total_pnl,
                    AVG(realized_pnl) as avg_pnl,
                    COUNT(DISTINCT date) as trading_days
                FROM trades 
                WHERE status = 'closed'
            ''')
            
            result = cursor.fetchone()
            
            if result and result[0] > 0:
                total, wins, losses, total_pnl, avg_pnl, days = result
                win_rate = (wins / total * 100) if total > 0 else 0
                
                return {
                    'total_trades': total,
                    'wins': wins,
                    'losses': losses,
                    'total_pnl': total_pnl,
                    'avg_pnl_per_trade': avg_pnl,
                    'win_rate': win_rate,
                    'trading_days': days,
                    'profit_factor': abs((wins * avg_pnl) / (losses * avg_pnl)) if losses > 0 and avg_pnl else 0
                }
            
            return {
                'total_trades': 0,
                'wins': 0,
                'losses': 0,
                'total_pnl': 0.0,
                'avg_pnl_per_trade': 0.0,
                'win_rate': 0.0,
                'trading_days': 0,
                'profit_factor': 0.0
            }
    
    def print_daily_report(self, date: Optional[str] = None):
        """Print a formatted daily report."""
        report = self.get_daily_report(date)
        unrealized = self.calculate_unrealized_pnl(0)  # Will need current price
        all_time = self.get_all_time_stats()
        
        print("\n" + "="*60)
        print(f"📊 TRADING PERFORMANCE REPORT - {report['date']}")
        print("="*60)
        print(f"\n📈 TODAY'S TRADING:")
        print(f"   Total Trades: {report['total_trades']}")
        print(f"   Wins: {report['winning_trades']} | Losses: {report['losing_trades']}")
        print(f"   Win Rate: {report['win_rate']:.1f}%")
        print(f"   Total P&L: ${report['total_pnl']:+.2f}")
        
        if report['total_trades'] > 0:
            print(f"\n💰 AVERAGE TRADE:")
            print(f"   Avg Win: ${report['avg_win']:.2f}")
            print(f"   Avg Loss: ${report['avg_loss']:.2f}")
            print(f"   Largest Win: ${report['largest_win']:.2f}")
            print(f"   Largest Loss: ${report['largest_loss']:.2f}")
        
        print(f"\n📊 ALL-TIME STATS:")
        print(f"   Total Trades: {all_time['total_trades']}")
        print(f"   Overall Win Rate: {all_time['win_rate']:.1f}%")
        print(f"   Total P&L: ${all_time['total_pnl']:+.2f}")
        print(f"   Trading Days: {all_time['trading_days']}")
        
        print("="*60 + "\n")


if __name__ == '__main__':
    # Test the tracker
    tracker = PerformanceTracker()
    tracker.print_daily_report()
