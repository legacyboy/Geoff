#!/usr/bin/env python3
"""
Machine Learning Performance Tracker
Tracks trading performance daily and adjusts strategy parameters.

Features:
- Daily performance snapshots
- Win rate analysis by geo threat level
- Asset correlation analysis
- Parameter auto-tuning suggestions
"""

import json
import sqlite3
import statistics
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Tuple

BASE_DIR = Path(__file__).parent.parent
DB_PATH = BASE_DIR / 'data' / 'trading.db'
PERFORMANCE_DIR = BASE_DIR / 'data' / 'performance_snapshots'
GEO_FILE = BASE_DIR / 'data' / 'geopolitical' / 'intelligence.json'

PERFORMANCE_DIR.mkdir(parents=True, exist_ok=True)


class PerformanceML:
    """Machine learning for trading strategy optimization."""
    
    def __init__(self):
        self.db_path = DB_PATH
        self.performance_dir = PERFORMANCE_DIR
        
    def get_db_connection(self) -> sqlite3.Connection:
        """Get database connection."""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn
    
    def calculate_daily_performance(self) -> Dict[str, Any]:
        """Calculate performance metrics for last 24 hours."""
        conn = self.get_db_connection()
        cursor = conn.cursor()
        
        # Get trades from last 24h
        yesterday = (datetime.now() - timedelta(days=1)).isoformat()
        cursor.execute("""
            SELECT * FROM trades 
            WHERE timestamp > ? 
            ORDER BY timestamp DESC
        """, (yesterday,))
        
        trades = cursor.fetchall()
        conn.close()
        
        if not trades:
            return {
                'date': datetime.now().isoformat(),
                'total_trades': 0,
                'win_rate': 0.0,
                'avg_pnl': 0.0,
                'total_pnl': 0.0,
                'status': 'NO_TRADES'
            }
        
        # Calculate metrics
        pnls = []
        for t in trades:
            realized = t['realized_pnl'] if t['realized_pnl'] is not None else 0
            unrealized = t['unrealized_pnl'] if t['unrealized_pnl'] is not None else 0
            pnls.append(realized + unrealized)
        wins = [p for p in pnls if p > 0]
        losses = [p for p in pnls if p <= 0]
        
        return {
            'date': datetime.now().isoformat(),
            'total_trades': len(trades),
            'wins': len(wins),
            'losses': len(losses),
            'win_rate': len(wins) / len(trades) * 100 if trades else 0,
            'avg_win': statistics.mean(wins) if wins else 0,
            'avg_loss': statistics.mean(losses) if losses else 0,
            'total_pnl': sum(pnls),
            'avg_pnl': statistics.mean(pnls),
            'max_win': max(wins) if wins else 0,
            'max_loss': min(losses) if losses else 0,
            'sharpe_ratio': self._calculate_sharpe(pnls),
            'status': 'ACTIVE'
        }
    
    def _calculate_sharpe(self, returns: List[float], risk_free_rate: float = 0.02) -> float:
        """Calculate Sharpe ratio."""
        if len(returns) < 2:
            return 0.0
        
        avg_return = statistics.mean(returns)
        std_return = statistics.stdev(returns) if len(returns) > 1 else 0.001
        
        if std_return == 0:
            return 0.0
        
        return (avg_return - risk_free_rate) / std_return
    
    def analyze_by_geo_threat(self) -> Dict[str, Any]:
        """Analyze performance by geopolitical threat level."""
        # Load from geo intelligence file
        try:
            with open(GEO_FILE) as f:
                intel = json.load(f)
                current_threat = intel.get('summary', {}).get('threat_level', 'LOW')
        except Exception:
            current_threat = 'LOW'
        
        conn = self.get_db_connection()
        cursor = conn.cursor()
        
        # Get all trades from last 30 days
        thirty_days_ago = (datetime.now() - timedelta(days=30)).isoformat()
        cursor.execute("""
            SELECT * FROM trades 
            WHERE timestamp > ?
            ORDER BY timestamp DESC
        """, (thirty_days_ago,))
        
        trades = cursor.fetchall()
        conn.close()
        
        # Group by threat level (for now, categorize by date ranges based on geo file)
        by_threat = {'LOW': [], 'MEDIUM': [], 'HIGH': [], 'CRITICAL': []}
        
        for trade in trades:
            # For now, categorize recent trades under current threat level
            # In a more advanced version, we'd look up threat level by date
            threat = current_threat
            realized = trade['realized_pnl'] if trade['realized_pnl'] is not None else 0
            unrealized = trade['unrealized_pnl'] if trade['unrealized_pnl'] is not None else 0
            pnl = realized + unrealized
            by_threat[threat].append(pnl)
        
        analysis = {}
        for threat, pnls in by_threat.items():
            if pnls:
                wins = [p for p in pnls if p > 0]
                analysis[threat] = {
                    'trades': len(pnls),
                    'win_rate': len(wins) / len(pnls) * 100,
                    'total_pnl': sum(pnls),
                    'avg_pnl': statistics.mean(pnls),
                    'sharpe': self._calculate_sharpe(pnls)
                }
        
        return analysis
    
    def get_strategy_recommendations(self) -> List[Dict[str, Any]]:
        """Generate strategy optimization recommendations."""
        daily = self.calculate_daily_performance()
        geo_analysis = self.analyze_by_geo_threat()
        
        recommendations = []
        
        # Check if we need to adjust based on performance
        if daily['total_trades'] >= 10:
            if daily['win_rate'] < 40:
                recommendations.append({
                    'priority': 'HIGH',
                    'area': 'Signal Generation',
                    'issue': f"Low win rate: {daily['win_rate']:.1f}%",
                    'recommendation': 'Consider tightening entry criteria or reducing position size'
                })
            
            if daily['avg_loss'] < -daily['avg_win'] * 1.5:
                recommendations.append({
                    'priority': 'MEDIUM',
                    'area': 'Risk Management',
                    'issue': f"Losses ({daily['avg_loss']:.2f}) much larger than wins ({daily['avg_win']:.2f})",
                    'recommendation': 'Tighten stop losses or reduce leverage'
                })
        
        # Geo-based recommendations
        for threat, data in geo_analysis.items():
            if data['win_rate'] < 35:
                recommendations.append({
                    'priority': 'MEDIUM',
                    'area': f'Geo-{threat} Trading',
                    'issue': f"Poor performance in {threat} threat environment",
                    'recommendation': f"Consider reducing position size during {threat} threat by additional 10-20%"
                })
        
        # Load historical snapshots for trend analysis
        snapshots = self._load_historical_snapshots()
        if len(snapshots) >= 7:
            recent_pnl = [s['total_pnl'] for s in snapshots[-7:]]
            if all(p < 0 for p in recent_pnl):
                recommendations.append({
                    'priority': 'CRITICAL',
                    'area': 'Overall Strategy',
                    'issue': '7 consecutive days of losses',
                    'recommendation': 'STOP TRADING and review strategy. Consider paper trading only.'
                })
        
        return recommendations
    
    def _load_historical_snapshots(self, days: int = 30) -> List[Dict]:
        """Load historical performance snapshots."""
        snapshots = []
        cutoff = datetime.now() - timedelta(days=days)
        
        for file in sorted(self.performance_dir.glob('snapshot_*.json')):
            try:
                with open(file) as f:
                    snap = json.load(f)
                    snap_date = datetime.fromisoformat(snap.get('date', ''))
                    if snap_date > cutoff:
                        snapshots.append(snap)
            except Exception:
                continue
        
        return sorted(snapshots, key=lambda x: x.get('date', ''))
    
    def save_daily_snapshot(self):
        """Save daily performance snapshot."""
        snapshot = self.calculate_daily_performance()
        
        # Add geo threat info
        try:
            with open(GEO_FILE) as f:
                intel = json.load(f)
                snapshot['geo_threat_level'] = intel.get('summary', {}).get('threat_level', 'LOW')
                snapshot['geo_attribution'] = intel.get('attribution', {})
        except Exception:
            pass
        
        # Save to file
        date_str = datetime.now().strftime('%Y%m%d')
        filename = self.performance_dir / f'snapshot_{date_str}.json'
        
        with open(filename, 'w') as f:
            json.dump(snapshot, f, indent=2)
        
        return snapshot
    
    def generate_ml_report(self) -> str:
        """Generate machine learning performance report."""
        snapshot = self.save_daily_snapshot()
        geo_analysis = self.analyze_by_geo_threat()
        recommendations = self.get_strategy_recommendations()
        
        report = []
        report.append("=" * 60)
        report.append("🤖 DAILY ML PERFORMANCE REPORT")
        report.append("=" * 60)
        report.append(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
        report.append("")
        
        # Daily performance
        report.append("📊 Daily Performance:")
        report.append(f"  Trades: {snapshot['total_trades']}")
        report.append(f"  Win Rate: {snapshot.get('win_rate', 0):.1f}%")
        report.append(f"  Total P&L: ${snapshot['total_pnl']:.2f}")
        report.append(f"  Sharpe Ratio: {snapshot.get('sharpe_ratio', 0):.2f}")
        report.append("")
        
        # Geo analysis
        report.append("🌍 Performance by Geo Threat Level:")
        for threat, data in geo_analysis.items():
            report.append(f"  {threat}: {data['win_rate']:.1f}% win rate, ${data['total_pnl']:.2f} total")
        report.append("")
        
        # Recommendations
        if recommendations:
            report.append("⚠️ ML Recommendations:")
            for rec in sorted(recommendations, key=lambda x: {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}.get(x['priority'], 4)):
                emoji = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}.get(rec['priority'], '⚪')
                report.append(f"  {emoji} [{rec['priority']}] {rec['area']}")
                report.append(f"     Issue: {rec['issue']}")
                report.append(f"     Action: {rec['recommendation']}")
        else:
            report.append("✅ No recommendations - strategy performing well")
        
        report.append("")
        report.append("=" * 60)
        
        return "\n".join(report)


def main():
    """Run daily ML analysis."""
    ml = PerformanceML()
    report = ml.generate_ml_report()
    print(report)


if __name__ == '__main__':
    main()
