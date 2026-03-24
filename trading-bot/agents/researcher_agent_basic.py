#!/usr/bin/env python3
"""
Brent & WTI Oil Volatility Researcher
Tracks both Brent (XBR_USD) and WTI (XTI_USD) with detailed scoring.
"""

import json
import logging
import os
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent
LOGS_DIR = BASE_DIR / 'logs'
RESEARCH_DIR = BASE_DIR / 'data' / 'research'
OIL_TRACKER_DIR = BASE_DIR / 'data' / 'oil_tracker'

LOGS_DIR.mkdir(parents=True, exist_ok=True)
RESEARCH_DIR.mkdir(parents=True, exist_ok=True)
OIL_TRACKER_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    filename=LOGS_DIR / 'researcher.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class OilResearcher:
    """Research both Brent and WTI oil volatility."""
    
    def __init__(self):
        self.assets = {
            'XTI_USD': {'name': 'WTI Crude Oil', 'origin': 'USA (Cushing, Oklahoma)'},
            'XBR_USD': {'name': 'Brent Crude Oil', 'origin': 'North Sea (Europe)'}
        }
        logger.info("Brent & WTI Oil Researcher initialized")
    
    def explain_volatility_score(self, score):
        """Explain what goes into the volatility score."""
        explanation = {
            'score': score,
            'breakdown': {}
        }
        
        # Break down the score components
        if score <= 40:
            explanation['level'] = 'low'
            explanation['interpretation'] = 'Market is stable. Good conditions for normal position sizing.'
            explanation['breakdown'] = {
                'Geopolitical Risk': f'{min(score, 15)}/40 points',
                'Supply Stability': f'{min(max(score-15, 0), 15)}/30 points', 
                'Demand Consistency': f'{min(max(score-30, 0), 15)}/30 points',
                'Explanation': 'Low volatility indicates steady supply/demand and minimal market disruption.'
            }
        elif score <= 70:
            explanation['level'] = 'medium'
            explanation['interpretation'] = 'Moderate uncertainty. Consider reduced position sizes.'
            explanation['breakdown'] = {
                'Geopolitical Risk': f'{min(score, 25)}/40 points',
                'Supply Stability': f'{min(max(score-25, 0), 20)}/30 points',
                'Demand Concerns': f'{min(max(score-45, 0), 25)}/30 points',
                'Explanation': 'Medium volatility suggests some market uncertainty - could be OPEC announcements, geopolitical tensions, or shifting demand patterns.'
            }
        else:
            explanation['level'] = 'high'
            explanation['interpretation'] = 'High uncertainty. Consider very small positions or holding.'
            explanation['breakdown'] = {
                'Geopolitical Risk': f'{min(score, 35)}/40 points',
                'Supply Disruption': f'{min(max(score-35, 0), 30)}/30 points',
                'Demand Shock': f'{min(max(score-65, 0), 35)}/30 points',
                'Explanation': 'High volatility indicates significant market stress - war, major supply disruptions, or economic shocks. High risk of large moves.'
            }
        
        return explanation
    
    def analyze_geopolitical(self, asset):
        """Analyze geopolitical factors for oil."""
        risks = []
        
        # Brent-specific factors (Europe/North Sea focus)
        if asset == 'XBR_USD':
            risks.extend([
                {'name': 'Russia-Ukraine conflict', 'impact': 20, 'explanation': 'Affects European supply routes'},
                {'name': 'North Sea production', 'impact': 10, 'explanation': 'Weather/technical issues in UK/Norway'},
                {'name': 'European energy policy', 'impact': 8, 'explanation': 'Sanctions on Russian oil affect Brent markets'}
            ])
        
        # WTI-specific factors (Americas focus)
        if asset == 'XTI_USD':
            risks.extend([
                {'name': 'US-Iran tensions', 'impact': 15, 'explanation': 'Strait of Hormuz risk affects global supply'},
                {'name': 'Venezuela sanctions', 'impact': 10, 'explanation': 'Heavy oil supply disruptions'},
                {'name': 'US shale production', 'impact': 8, 'explanation': 'Domestic supply fluctuations'}
            ])
        
        # Common factors
        risks.extend([
            {'name': 'Middle East tensions', 'impact': 15, 'explanation': 'Saudi Arabia, Iran, Iraq stability affects both benchmarks'},
            {'name': 'OPEC+ decisions', 'impact': 12, 'explanation': 'Production cuts/quotas directly impact prices'},
            {'name': 'China demand', 'impact': 10, 'explanation': 'Largest oil importer - economic health matters'},
            {'name': 'US Dollar strength', 'impact': 8, 'explanation': 'Oil priced in USD - currency fluctuations matter'}
        ])
        
        # Calculate total risk
        total_risk = sum(r['impact'] for r in risks)
        max_possible = len(risks) * 20  # Each risk max 20 points
        risk_percentage = (total_risk / max_possible) * 100
        
        return {
            'risks': risks,
            'total_risk_score': total_risk,
            'risk_level': 'high' if risk_percentage > 60 else 'medium' if risk_percentage > 30 else 'low',
            'explanation': f'Geopolitical risk contributes {total_risk} points to volatility score'
        }
    
    def analyze_supply(self, asset):
        """Analyze supply factors."""
        if asset == 'XBR_USD':
            return {
                'factors': {
                    'North Sea Production': {'status': 'stable', 'impact': 5, 'explanation': 'Norway/UK output steady'},
                    'Russian Exports': {'status': 'constrained', 'impact': 25, 'explanation': 'Sanctions limit Brent-relevant supply'},
                    'OPEC Compliance': {'status': 'high', 'impact': 10, 'explanation': 'Most members following quotas'},
                    'Strategic Reserves': {'status': 'normal', 'impact': 3, 'explanation': 'IEA stockpiles adequate'}
                },
                'total_impact': 43,
                'explanation': 'Brent supply constrained by Russian sanctions; North Sea stable'
            }
        else:  # WTI
            return {
                'factors': {
                    'US Shale': {'status': 'increasing', 'impact': 15, 'explanation': 'Permian Basin production growing'},
                    'Strategic Reserve': {'status': 'releasing', 'impact': 12, 'explanation': 'SPR draws affect domestic supply'},
                    'Canada Imports': {'status': 'stable', 'impact': 5, 'explanation': 'Heavy oil from Canada steady'},
                    'Refinery Capacity': {'status': 'tight', 'impact': 15, 'explanation': 'Limited upgrading capacity'}
                },
                'total_impact': 47,
                'explanation': 'WTI supply growing from shale but constrained by infrastructure'
            }
    
    def analyze_demand(self, asset):
        """Analyze demand factors."""
        common_demand = {
            'Global GDP Growth': {'trend': 'slowing', 'impact': 20, 'explanation': 'Recession fears reduce oil demand outlook'},
            'China Recovery': {'trend': 'uncertain', 'impact': 18, 'explanation': 'Post-COVID reopening speed unclear'},
            'Inventory Levels': {'trend': 'low', 'impact': 12, 'explanation': 'Low stocks support prices despite demand concerns'},
            'Seasonal Factor': {'trend': 'winter_heating', 'impact': 8, 'explanation': 'Northern hemisphere heating season'}
        }
        
        if asset == 'XBR_USD':
            common_demand['Europe Energy Crisis'] = {'trend': 'ongoing', 'impact': 22, 'explanation': 'EU oil demand affected by gas-to-oil switching'}
        else:
            common_demand['US Driving Season'] = {'trend': 'approaching', 'impact': 15, 'explanation': 'Summer gasoline demand typically rises'}
        
        total_impact = sum(f['impact'] for f in common_demand.values())
        
        return {
            'factors': common_demand,
            'total_impact': total_impact,
            'explanation': 'Demand concerns from slowing global economy offset by China reopening hopes'
        }
    
    def analyze_brent_wti_spread(self):
        """Analyze the Brent-WTI price spread."""
        # In reality, fetch actual prices
        # Brent typically trades at premium to WTI due to quality/location
        spread_explanation = {
            'normal_range': '$2-$5 per barrel',
            'current_estimate': '$3.50',  # Placeholder
            'explanation': 'Brent trades at premium due to:',
            'reasons': [
                'Brent is lighter/sweeter (better quality)',
                'Brent reflects global supply (Middle East, Africa)',
                'WTI is landlocked (Cushing) - transport constraints',
                'Brent includes shipping costs to Europe/Asia'
            ],
            'trading_implication': 'Narrowing spread may indicate US export capacity improving; widening spread suggests global supply tightness'
        }
        return spread_explanation
    
    def research_asset(self, asset):
        """Research specific oil asset."""
        print(f"\n🔬 Researching {self.assets[asset]['name']}...")
        
        # Gather all factors
        geo = self.analyze_geopolitical(asset)
        supply = self.analyze_supply(asset)
        demand = self.analyze_demand(asset)
        
        # Calculate volatility score
        score = min(geo['total_risk_score'] + supply['total_impact']//3 + demand['total_impact']//4, 100)
        
        # Get explanation
        explanation = self.explain_volatility_score(score)
        
        # Generate recommendation
        if explanation['level'] == 'high':
            rec = 'REDUCE'
            position = 0.3
            reasoning = f"High volatility ({score}/100) - {explanation['breakdown']['Explanation']}"
        elif explanation['level'] == 'medium':
            rec = 'MODERATE'
            position = 0.6
            reasoning = f"Moderate volatility - {explanation['breakdown']['Explanation']}"
        else:
            rec = 'TRADE'
            position = 1.0
            reasoning = f"Low volatility - {explanation['breakdown']['Explanation']}"
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'asset': asset,
            'asset_name': self.assets[asset]['name'],
            'origin': self.assets[asset]['origin'],
            'volatility_score': score,
            'volatility_level': explanation['level'],
            'score_explanation': explanation,
            'factors': {
                'geopolitical': geo,
                'supply': supply,
                'demand': demand
            },
            'recommendation': rec,
            'position_size': position,
            'reasoning': reasoning,
            'confidence': max(100 - score, 25)
        }
        
        return report
    
    def save_report(self, report):
        """Save research report."""
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            asset_code = report['asset'].replace('_', '')
            filename = RESEARCH_DIR / f'{asset_code}_volatility_{timestamp}.json'
            
            with open(filename, 'w') as f:
                json.dump(report, f, indent=2)
            
            logger.info(f'Research report saved: {filename}')
            return filename
        except Exception as e:
            logger.error(f'Error saving report: {e}')
            return None
    
    def display_detailed_report(self, report):
        """Display detailed research report."""
        r = report
        exp = r['score_explanation']
        
        print("\n" + "="*60)
        print(f"🛢️  {r['asset_name'].upper()} VOLATILITY RESEARCH")
        print("="*60)
        
        print(f"\n📍 Origin: {r['origin']}")
        print(f"⏰ Time: {r['timestamp']}")
        
        print(f"\n{'─'*60}")
        print("📊 VOLATILITY SCORE BREAKDOWN")
        print(f"{'─'*60}")
        print(f"\n🎯 TOTAL SCORE: {r['volatility_score']}/100 ({r['volatility_level'].upper()})")
        print(f"\n💭 Interpretation: {exp['interpretation']}")
        print(f"\n📋 Score Components:")
        for key, value in exp['breakdown'].items():
            if key != 'Explanation':
                print(f"   • {key}: {value}")
        print(f"\n📖 What this means: {exp['breakdown'].get('Explanation', 'N/A')}")
        
        print(f"\n{'─'*60}")
        print("🔍 DETAILED FACTOR ANALYSIS")
        print(f"{'─'*60}")
        
        # Geopolitical
        geo = r['factors']['geopolitical']
        print(f"\n🌍 GEOPOLITICAL FACTORS (Risk Level: {geo['risk_level'].upper()})")
        print(f"   Total Risk Score: {geo['total_risk_score']}")
        for risk in geo['risks']:
            print(f"   • {risk['name']}: {risk['impact']}/20 points")
            print(f"     └─ {risk['explanation']}")
        
        # Supply
        sup = r['factors']['supply']
        print(f"\n📦 SUPPLY FACTORS (Impact: {sup['total_impact']})")
        for factor, data in sup['factors'].items():
            print(f"   • {factor}: {data['status']} ({data['impact']} pts)")
            print(f"     └─ {data['explanation']}")
        print(f"   └─ Summary: {sup['explanation']}")
        
        # Demand
        dem = r['factors']['demand']
        print(f"\n📈 DEMAND FACTORS (Impact: {dem['total_impact']})")
        for factor, data in dem['factors'].items():
            print(f"   • {factor}: {data['trend']} ({data['impact']} pts)")
            print(f"     └─ {data['explanation']}")
        print(f"   └─ Summary: {dem['explanation']}")
        
        print(f"\n{'─'*60}")
        print("🎯 TRADING RECOMMENDATION")
        print(f"{'─'*60}")
        print(f"   Recommendation: {r['recommendation']}")
        print(f"   Position Size: {r['position_size']*100:.0f}%")
        print(f"   Confidence: {r['confidence']}%")
        print(f"\n   💡 Reasoning: {r['reasoning']}")
        
        print("\n" + "="*60)
    
    def run(self):
        """Execute full research cycle for both Brent and WTI."""
        print("\n" + "="*60)
        print("🔬 BRENT & WTI OIL VOLATILITY RESEARCH")
        print("="*60)
        print("\nResearching both major oil benchmarks...")
        print("(Brent = global benchmark, WTI = US benchmark)")
        
        reports = {}
        for asset in self.assets:
            report = self.research_asset(asset)
            self.display_detailed_report(report)
            reports[asset] = report
            filename = self.save_report(report)
            if filename:
                print(f"💾 Report saved: {filename}")
        
        # Brent-WTI spread analysis
        print(f"\n{'─'*60}")
        print("🔄 BRENT-WTI SPREAD ANALYSIS")
        print(f"{'─'*60}")
        spread = self.analyze_brent_wti_spread()
        print(f"\nNormal Range: {spread['normal_range']}")
        print(f"Explanation: {spread['explanation']}")
        for reason in spread['reasons']:
            print(f"   • {reason}")
        print(f"\n💡 Trading Implication: {spread['trading_implication']}")
        print("\n" + "="*60)
        
        return reports

def main():
    researcher = OilResearcher()
    researcher.run()

if __name__ == "__main__":
    main()
