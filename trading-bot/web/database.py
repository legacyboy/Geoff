"""Database models and utilities for trading bot."""

import sqlite3
import json
import os
from datetime import datetime
from typing import Optional, List, Dict, Any
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent
DB_PATH = BASE_DIR / 'data' / 'trading.db'

def get_db_connection() -> sqlite3.Connection:
    """Get database connection with row factory."""
    os.makedirs(DB_PATH.parent, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), timeout=30.0)
    conn.row_factory = sqlite3.Row
    return conn

def init_database():
    """Initialize database with tables."""
    os.makedirs(DB_PATH.parent, exist_ok=True)
    
    with get_db_connection() as conn:
        conn.executescript('''
            CREATE TABLE IF NOT EXISTS trades (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                asset TEXT NOT NULL,
                action TEXT NOT NULL,
                signal TEXT,
                position_size INTEGER,
                entry_price REAL,
                stop_loss REAL,
                take_profit REAL,
                unrealized_pnl REAL,
                realized_pnl REAL,
                leverage REAL DEFAULT 1.0,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            );
            
            CREATE INDEX IF NOT EXISTS idx_trades_timestamp ON trades(timestamp);
            CREATE INDEX IF NOT EXISTS idx_trades_asset ON trades(asset);
            
            CREATE TABLE IF NOT EXISTS research (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                asset TEXT NOT NULL,
                volatility_score INTEGER,
                trend TEXT,
                recommendation TEXT,
                data JSON,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            );
            
            CREATE INDEX IF NOT EXISTS idx_research_timestamp ON research(timestamp);
            CREATE INDEX IF NOT EXISTS idx_research_asset ON research(asset);
            
            CREATE TABLE IF NOT EXISTS oil_tracker (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                price REAL,
                change_percent REAL,
                volatility REAL,
                signal TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            );
            
            CREATE INDEX IF NOT EXISTS idx_tracker_timestamp ON oil_tracker(timestamp);
            
            CREATE TABLE IF NOT EXISTS performance_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
                total_trades INTEGER,
                win_rate REAL,
                total_pnl REAL,
                avg_pnl REAL
            );
        ''')
        conn.commit()
    
    print(f"✅ Database initialized at {DB_PATH}")

def migrate_json_to_sqlite():
    """Migrate existing JSON data to SQLite."""
    init_database()
    
    paper_trades_dir = BASE_DIR / 'data' / 'paper_trades'
    research_dir = BASE_DIR / 'data' / 'research'
    
    trades_migrated = 0
    research_migrated = 0
    
    with get_db_connection() as conn:
        # Migrate trades
        if paper_trades_dir.exists():
            for file_path in paper_trades_dir.glob('*.json'):
                try:
                    with open(file_path) as f:
                        trade = json.load(f)
                    
                    conn.execute('''
                        INSERT INTO trades 
                        (timestamp, asset, action, position_size, 
                         entry_price, leverage)
                        VALUES (?, ?, ?, ?, ?, ?)
                    ''', (
                        trade.get('time', trade.get('timestamp')),
                        trade.get('instrument', trade.get('asset')),
                        trade.get('side', trade.get('action')),
                        trade.get('units', trade.get('position_size')),
                        trade.get('price', trade.get('entry_price')),
                        trade.get('leverage', 1.0)
                    ))
                    trades_migrated += 1
                except Exception as e:
                    print(f"Warning: Could not migrate trade {file_path}: {e}")
        
        # Migrate research
        if research_dir.exists():
            for file_path in research_dir.glob('*.json'):
                try:
                    with open(file_path) as f:
                        data = json.load(f)
                    
                    asset = data.get('asset', 'unknown')
                    report = data.get('data', {})
                    
                    conn.execute('''
                        INSERT INTO research 
                        (timestamp, asset, volatility_score, trend, recommendation, data)
                        VALUES (?, ?, ?, ?, ?, ?)
                    ''', (
                        data.get('timestamp', datetime.now().isoformat()),
                        asset,
                        report.get('volatility_score'),
                        report.get('trend'),
                        report.get('recommendation'),
                        json.dumps(report)
                    ))
                    research_migrated += 1
                except Exception as e:
                    print(f"Warning: Could not migrate research {file_path}: {e}")
        
        conn.commit()
    
    print(f"✅ Migration complete: {trades_migrated} trades, {research_migrated} research items")
    return trades_migrated, research_migrated

# CRUD Operations
def get_trades(limit: int = 100, asset: Optional[str] = None) -> List[Dict[str, Any]]:
    """Get trades from database."""
    query = 'SELECT * FROM trades ORDER BY timestamp DESC LIMIT ?'
    params = [limit]
    
    if asset:
        query = 'SELECT * FROM trades WHERE asset = ? ORDER BY timestamp DESC LIMIT ?'
        params = [asset, limit]
    
    with get_db_connection() as conn:
        rows = conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]

def add_trade(trade_data: Dict[str, Any]) -> int:
    """Add a new trade to database."""
    with get_db_connection() as conn:
        cursor = conn.execute('''
            INSERT INTO trades 
            (timestamp, asset, action, signal, position_size, 
             entry_price, stop_loss, take_profit, unrealized_pnl, 
             realized_pnl, leverage)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            trade_data.get('timestamp'),
            trade_data.get('asset'),
            trade_data.get('action'),
            trade_data.get('signal'),
            trade_data.get('position_size'),
            trade_data.get('entry_price'),
            trade_data.get('stop_loss'),
            trade_data.get('take_profit'),
            trade_data.get('unrealized_pnl'),
            trade_data.get('realized_pnl'),
            trade_data.get('leverage', 1.0)
        ))
        conn.commit()
        return cursor.lastrowid

def get_research(limit: int = 10, asset: Optional[str] = None) -> List[Dict[str, Any]]:
    """Get research reports from database."""
    query = 'SELECT * FROM research ORDER BY timestamp DESC LIMIT ?'
    params = [limit]
    
    if asset:
        query = 'SELECT * FROM research WHERE asset = ? ORDER BY timestamp DESC LIMIT ?'
        params = [asset, limit]
    
    with get_db_connection() as conn:
        rows = conn.execute(query, params).fetchall()
        results = []
        for row in rows:
            row_dict = dict(row)
            if row_dict.get('data'):
                row_dict['data'] = json.loads(row_dict['data'])
            results.append(row_dict)
        return results

def add_research(research_data: Dict[str, Any]) -> int:
    """Add research report to database."""
    report = research_data.get('data', {})
    
    with get_db_connection() as conn:
        cursor = conn.execute('''
            INSERT INTO research 
            (timestamp, asset, volatility_score, trend, recommendation, data)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            research_data.get('timestamp', datetime.now().isoformat()),
            research_data.get('asset', 'unknown'),
            report.get('volatility_score'),
            report.get('trend'),
            report.get('recommendation'),
            json.dumps(report)
        ))
        conn.commit()
        return cursor.lastrowid

def get_performance_stats() -> Dict[str, Any]:
    """Calculate performance stats from database."""
    with get_db_connection() as conn:
        # Total trades
        total = conn.execute('SELECT COUNT(*) FROM trades').fetchone()[0]
        
        if total == 0:
            return {
                'total_trades': 0,
                'win_rate': 0.0,
                'avg_pnl': 0.0,
                'total_pnl': 0.0
            }
        
        # Win count (positive P&L)
        wins = conn.execute('''
            SELECT COUNT(*) FROM trades 
            WHERE COALESCE(unrealized_pnl, 0) + COALESCE(realized_pnl, 0) > 0
        ''').fetchone()[0]
        
        # P&L stats
        pnl_stats = conn.execute('''
            SELECT 
                COALESCE(SUM(COALESCE(unrealized_pnl, 0) + COALESCE(realized_pnl, 0)), 0) as total_pnl,
                COALESCE(AVG(COALESCE(unrealized_pnl, 0) + COALESCE(realized_pnl, 0)), 0) as avg_pnl
            FROM trades
        ''').fetchone()
        
        return {
            'total_trades': total,
            'win_rate': round((wins / total * 100) if total > 0 else 0, 2),
            'avg_pnl': round(pnl_stats['avg_pnl'], 2),
            'total_pnl': round(pnl_stats['total_pnl'], 2)
        }

if __name__ == '__main__':
    migrate_json_to_sqlite()
