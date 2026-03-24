#!/usr/bin/env python3
"""
Enhanced Oil Volatility Researcher with Trump Monitoring
Uses deepseek-coder:33b and tracks Trump activity for oil markets.
"""

import json
import logging
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

# Add parent directory to path for imports
BASE_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(BASE_DIR / 'agents'))

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

def query_llm(prompt, model="deepseek-coder:33b"):
    """Query Ollama for intelligent analysis."""
    try:
        result = subprocess.run(
            ['ollama', 'run', model, prompt],
            capture_output=True,
            text=True,
            timeout=120
        )
        return result.stdout.strip()
    except Exception as e:
        logger.error(f"LLM query failed: {e}")
        return None

class OilResearcher:
    """Research oil with Trump factor integration."""
    
    def __init__(self):
        self.model = "deepseek-coder:33b"
        self.assets = {
            'XTI_USD': {'name': 'WTI Crude Oil', 'origin': 'USA (Cushing, Oklahoma)'},
            'XBR_USD': {'name': 'Brent Crude Oil', 'origin': 'North Sea (Europe)'}
        }
        self.trump_monitor = None
        logger.info(f"Oil Researcher initialized with model: {self.model}")
    
    def get_trump_factor(self):
        """Get Trump monitoring data - TRUTH SOCIAL IS PRIORITY #1."""
        try:
            from trump_monitor import TrumpTruthSocialMonitor
            monitor = TrumpTruthSocialMonitor()
            return monitor.get_trump_factor()
        except Exception as e:
            logger.error(f"Trump monitor error: {e}")
            return None
    
    def get_llm_analysis(self, asset, trump_factor=None):
        """Get comprehensive LLM analysis including Trump impact."""
        asset_name = self.assets[asset]['name']
        
        trump_context = ""
        if trump_factor and trump_factor.get('trump_factor'):
            tf = trump_factor['trump_factor']
            trump_context = f"""
            TRUMP FACTOR (Current):
            - Trump Factor Score: {tf.get('trump_factor_score', 0)}/100
            - Level: {tf.get('level', 'unknown')}
            - Sentiment: {tf.get('sentiment', 'neutral')}
            - Recent Statements: {tf.get('relevant_items', 0)} relevant items
            
            Trump's current stance: {tf.get('explanation', 'N/A')}
            """
        
        prompt = f"""Analyze {asset_name} oil market conditions for March 2026.
        
        {trump_context}
        
        Consider:
        1. Geopolitical risks (Middle East, Russia-Ukraine, US policy)
        2. Supply factors (OPEC+, US shale, inventories)
        3. Demand factors (global economy, China, seasonal)
        4. Trump policy impact on oil markets
        
        Return JSON:
        {{
            "geopolitical": {{
                "risk_level": "low|medium|high",
                "risk_score": 0-100,
                "key_risks": ["risk1", "risk2", "risk3"],
                "trump_impact": "description"
            }},
            "supply": {{
                "supply_level": "tight|balanced|abundant",
                "supply_score": 0-100,
                "key_factors": ["factor1", "factor2"],
                "outlook": "description"
            }},
            "demand": {{
                "demand_level": "strong|moderate|weak",
                "demand_score": 0-100,
                "key_factors": ["factor1", "factor2"],
                "outlook": "description"
            }},
            "trump_influence": {{
                "impact_score": 0-100,
                "direction": "bullish|bearish|neutral",
                "key_policies": ["policy1", "policy2"]
            }}
        }}
        """
        
        response = query_llm(prompt, self.model)
        if response:
            try:
                json_start = response.find('{')
                json_end = response.rfind('}') + 1
                if json_start >= 0 and json_end > json_start:
                    return json.loads(response[json_start:json_end])
            except Exception as e:
                logger.error(f"JSON parse error: {e}")
        
        # Fallback
        return {
            "geopolitical": {"risk_level": "medium", "risk_score": 50, "key_risks": ["Middle East tensions"], "trump_impact": "Pro-production policies"},
            "supply": {"supply_level": "balanced", "supply_score": 50, "key_factors": ["OPEC compliance"], "outlook": "Stable"},
            "demand": {"demand_level": "moderate", "demand_score": 50, "key_factors": ["China recovery"], "outlook": "Mixed"},
            "trump_influence": {"impact_score": 40, "direction": "bearish", "key_policies": ["Drill baby drill"]}
        }
    
    def calculate_volatility_score(self, analysis):
        """Calculate composite volatility score with Trump factor."""
        geo = analysis['geopolitical']
        supply = analysis['supply']
        demand = analysis['demand']
        trump = analysis.get('trump_influence', {})
        
        # Base score
        base_score = (geo['risk_score'] * 0.35 + 
                      supply['supply_score'] * 0.25 + 
                      (100 - demand['demand_score']) * 0.25)
        
        # Add Trump factor (can increase or decrease volatility)
        trump_score = trump.get('impact_score', 0) * 0.15
        
        total_score = base_score + trump_score
        return min(int(total_score), 100)
    
    def explain_score(self, score, trump_data):
        """Explain volatility with Trump context."""
        trump_desc = trump_data.get('explanation', '') if trump_data else ''
        
        if score >= 70:
            return {
                "level": "high",
                "interpretation": f"High volatility expected. {trump_desc}",
                "factors": ["Geopolitical tensions", "Policy uncertainty", "Trump statements"],
                "action": "Reduce to 30% position size. High risk of rapid moves."
            }
        elif score >= 40:
            return {
                "level": "medium",
                "interpretation": f"Moderate volatility. {trump_desc}",
                "factors": ["Mixed signals", "Some Trump uncertainty"],
                "action": "Trade with 60% position size and tight stops."
            }
        else:
            return {
                "level": "low",
                "interpretation": f"Relatively stable conditions. {trump_desc}",
                "factors": ["Balanced market", "Limited Trump disruption"],
                "action": "Full position size appropriate."
            }
    
    def generate_recommendation(self, score, explanation, trump_influence):
        """Generate recommendation including Trump analysis."""
        trump_dir = trump_influence.get('direction', 'neutral') if trump_influence else 'neutral'
        
        if score >= 70:
            return {
                "recommendation": "REDUCE",
                "position_size": 0.3,
                "confidence": max(100 - score, 20),
                "reasoning": f"High volatility ({score}/100). {explanation['action']} Trump sentiment: {trump_dir}."
            }
        elif score >= 40:
            return {
                "recommendation": "MODERATE",
                "position_size": 0.6,
                "confidence": max(100 - score, 30),
                "reasoning": f"Medium volatility. {explanation['action']} Trump direction: {trump_dir}."
            }
        else:
            return {
                "recommendation": "TRADE",
                "position_size": 1.0,
                "confidence": max(100 - score, 40),
                "reasoning": f"Low volatility. {explanation['action']} Limited Trump market impact."
            }
    
    def research_asset(self, asset, trump_factor=None):
        """Research asset with Trump monitoring."""
        print(f"\n🔬 Researching {self.assets[asset]['name']}...")
        
        # Get analysis
        analysis = self.get_llm_analysis(asset, trump_factor)
        trump_influence = analysis.get('trump_influence', {})
        
        # Calculate scores
        volatility_score = self.calculate_volatility_score(analysis)
        explanation = self.explain_score(volatility_score, trump_factor.get('trump_factor') if trump_factor else None)
        recommendation = self.generate_recommendation(volatility_score, explanation, trump_influence)
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'asset': asset,
            'asset_name': self.assets[asset]['name'],
            'origin': self.assets[asset]['origin'],
            'model_used': self.model,
            'volatility_score': volatility_score,
            'volatility_level': explanation['level'],
            'factors': {
                'geopolitical': analysis['geopolitical'],
                'supply': analysis['supply'],
                'demand': analysis['demand'],
                'trump_influence': trump_influence
            },
            'score_explanation': explanation,
            'recommendation': recommendation['recommendation'],
            'position_size': recommendation['position_size'],
            'confidence': recommendation['confidence'],
            'reasoning': recommendation['reasoning'],
            'trump_factor': trump_factor.get('trump_factor') if trump_factor else None
        }
        
        return report
    
    def display_report(self, report):
        """Display formatted report with Trump section."""
        r = report
        exp = r['score_explanation']
        trump = r.get('trump_factor', {})
        
        print("\n" + "="*60)
        print(f"🛢️  {r['asset_name'].upper()} ANALYSIS")
        print("="*60)
        
        if trump:
            print(f"\n🦅 TRUMP FACTOR: {trump.get('trump_factor_score', 0)}/100 ({trump.get('level', 'N/A')})")
            print(f"   Sentiment: {trump.get('sentiment', 'N/A')}")
        
        print(f"\n📊 VOLATILITY SCORE: {r['volatility_score']}/100 ({exp['level'].upper()})")
        print(f"💭 {exp['interpretation']}")
        
        print(f"\n🎯 {r['recommendation']} | Position: {r['position_size']*100:.0f}% | Confidence: {r['confidence']}%")
        print(f"💡 {r['reasoning']}")
        
        print("\n" + "="*60)
    
    def save_report(self, report):
        """Save research report."""
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            asset_code = report['asset'].replace('_', '')
            filename = RESEARCH_DIR / f'{asset_code}_volatility_{timestamp}.json'
            
            with open(filename, 'w') as f:
                json.dump(report, f, indent=2)
            
            logger.info(f'Report saved: {filename}')
            return filename
        except Exception as e:
            logger.error(f'Error saving: {e}')
            return None
    
    def run(self):
        """Execute full research cycle with Trump monitoring."""
        print("\n" + "="*60)
        print("🔬 OIL RESEARCH WITH TRUMP MONITORING")
        print("="*60)
        
        # Get Trump factor first
        print("\n🦅 Getting Trump factor analysis...")
        trump_factor = self.get_trump_factor()
        
        if trump_factor and trump_factor.get('trump_factor'):
            tf = trump_factor['trump_factor']
            print(f"   Trump Factor: {tf.get('trump_factor_score', 0)}/100 ({tf.get('level', 'N/A')})")
        
        # Research each asset
        for asset in self.assets:
            report = self.research_asset(asset, trump_factor)
            self.display_report(report)
            filename = self.save_report(report)
            if filename:
                print(f"💾 Saved: {filename}\n")
        
        print("Research complete.")

def main():
    researcher = OilResearcher()
    researcher.run()

if __name__ == "__main__":
    main()
