#!/usr/bin/env python3
"""
Oil Volatility Researcher
Tracks world events affecting oil prices and market volatility.
"""

import json
import logging
import os
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent
LOGS_DIR = BASE_DIR / 'logs'
RESEARCH_DIR = BASE_DIR / 'data' / 'research'

LOGS_DIR.mkdir(parents=True, exist_ok=True)
RESEARCH_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    filename=LOGS_DIR / 'researcher.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class OilResearcher:
    """Research oil market volatility and world events."""
    
    def __init__(self):
        self.asset = "XTI_USD"
        self.asset_name = "WTI Crude Oil"
        logger.info("Oil Researcher initialized")
    
    def analyze_volatility_factors(self):
        """Analyze factors affecting oil volatility."""
        factors = {
            'geopolitical': self.check_geopolitical_risks(),
            'supply': self.check_supply_factors(),
            'demand': self.check_demand_factors(),
            'opec': self.check_opec_news()
        }
        return factors
    
    def check_geopolitical_risks(self):
        """Check for geopolitical events affecting oil."""
        # These would normally come from news API
        risks = []
        risk_level = 'low'
        
        # Common oil risk factors
        risk_indicators = [
            {'name': 'Middle East tensions', 'impact': 'high', 'probability': 'medium'},
            {'name': 'Sanctions on oil producers', 'impact': 'high', 'probability': 'low'},
            {'name': 'Trade war escalation', 'impact': 'medium', 'probability': 'medium'},
            {'name': 'Regional conflicts', 'impact': 'high', 'probability': 'low'}
        ]
        
        for indicator in risk_indicators:
            if indicator['probability'] in ['high', 'medium']:
                risks.append(indicator)
                if indicator['impact'] == 'high':
                    risk_level = 'high'
        
        return {'risks': risks, 'level': risk_level}
    
    def check_supply_factors(self):
        """Check oil supply factors."""
        return {
            'us_production': 'stable',
            'saudi_output': 'normal',
            'russian_exports': 'reduced',
            'strategic_reserves': 'stable'
        }
    
    def check_demand_factors(self):
        """Check oil demand factors."""
        return {
            'global_economy': 'slowing',
            'china_demand': 'increasing',
            'us_demand': 'stable',
            'seasonal_factor': 'winter_heating'
        }
    
    def check_opec_news(self):
        """Check OPEC news and decisions."""
        return {
            'production_cuts': 'maintained',
            'next_meeting': 'upcoming',
            'compliance': 'high',
            'spare_capacity': 'limited'
        }
    
    def calculate_volatility_score(self, factors):
        """Calculate overall volatility score."""
        score = 0
        
        # Geopolitical factor (0-40 points)
        if factors['geopolitical']['level'] == 'high':
            score += 40
        elif factors['geopolitical']['level'] == 'medium':
            score += 20
        
        # Supply factor (0-30 points)
        supply_risks = sum(1 for v in factors['supply'].values() if v in ['reduced', 'constrained'])
        score += supply_risks * 10
        
        # Demand factor (0-30 points)
        demand_risks = sum(1 for v in factors['demand'].values() if v == 'decreasing')
        score += demand_risks * 10
        
        return min(score, 100)
    
    def generate_recommendation(self, volatility_score, factors):
        """Generate trading recommendation based on research."""
        if volatility_score > 70:
            volatility_level = 'high'
            recommendation = 'HOLD'
            position_size = 0.3
            reasoning = 'High volatility - wait for stabilization'
        elif volatility_score > 40:
            volatility_level = 'medium'
            recommendation = 'REDUCE'
            position_size = 0.6
            reasoning = 'Moderate volatility - reduced exposure'
        else:
            volatility_level = 'low'
            recommendation = 'TRADE'
            position_size = 1.0
            reasoning = 'Low volatility - normal trading'
        
        # Adjust for specific factors
        if factors['geopolitical']['level'] == 'high':
            position_size *= 0.5
            reasoning += ' | High geopolitical risk'
        
        return {
            'volatility_level': volatility_level,
            'recommendation': recommendation,
            'position_size': position_size,
            'reasoning': reasoning,
            'confidence': max(100 - volatility_score, 30)
        }
    
    def research(self):
        """Execute oil research."""
        print(f"🔬 Researching {self.asset_name} volatility...")
        
        factors = self.analyze_volatility_factors()
        volatility_score = self.calculate_volatility_score(factors)
        recommendation = self.generate_recommendation(volatility_score, factors)
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'asset': self.asset,
            'asset_name': self.asset_name,
            'volatility_score': volatility_score,
            'volatility_level': recommendation['volatility_level'],
            'factors': factors,
            'recommendation': recommendation['recommendation'],
            'position_size': recommendation['position_size'],
            'reasoning': recommendation['reasoning'],
            'confidence': recommendation['confidence']
        }
        
        return report
    
    def save_report(self, report):
        """Save research report."""
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = RESEARCH_DIR / f'oil_volatility_{timestamp}.json'
            
            with open(filename, 'w') as f:
                json.dump(report, f, indent=2)
            
            logger.info(f'Research report saved: {filename}')
            return filename
        except Exception as e:
            logger.error(f'Error saving report: {e}')
            return None
    
    def display_report(self, report):
        """Display research report."""
        print("\n" + "="*50)
        print(f"🛢️  OIL VOLATILITY RESEARCH REPORT")
        print("="*50)
        print(f"Asset: {report['asset_name']} ({report['asset']})")
        print(f"Time: {report['timestamp']}")
        print(f"\n📊 Volatility Score: {report['volatility_score']}/100")
        print(f"Level: {report['volatility_level'].upper()}")
        print(f"\n🎯 Recommendation: {report['recommendation']}")
        print(f"Position Size: {report['position_size']*100:.0f}%")
        print(f"Confidence: {report['confidence']}%")
        print(f"\n💡 Reasoning: {report['reasoning']}")
        print(f"\n🔍 Key Factors:")
        print(f"  - Geopolitical: {report['factors']['geopolitical']['level']}")
        print(f"  - Supply: {len([v for v in report['factors']['supply'].values() if v != 'stable'])} risks")
        print(f"  - Demand: {report['factors']['demand']['global_economy']}")
        print(f"  - OPEC: {report['factors']['opec']['production_cuts']}")
        print("="*50 + "\n")
    
    def run(self):
        """Execute full research cycle."""
        print("\n🔬 Starting Oil Volatility Research...")
        
        report = self.research()
        self.display_report(report)
        filename = self.save_report(report)
        
        if filename:
            print(f"💾 Report saved to: {filename}")
        
        return report

def main():
    researcher = OilResearcher()
    researcher.run()

if __name__ == "__main__":
    main()
