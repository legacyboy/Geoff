#!/usr/bin/env python3
"""
Enhanced Oil Volatility Researcher using deepseek-coder:33b
Uses Ollama for intelligent market analysis.
"""

import json
import logging
import os
import subprocess
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
    """Research both Brent and WTI oil volatility using deepseek-coder:33b."""
    
    def __init__(self):
        self.model = "deepseek-coder:33b"
        self.assets = {
            'XTI_USD': {'name': 'WTI Crude Oil', 'origin': 'USA (Cushing, Oklahoma)'},
            'XBR_USD': {'name': 'Brent Crude Oil', 'origin': 'North Sea (Europe)'}
        }
        logger.info(f"Oil Researcher initialized with model: {self.model}")
    
    def get_llm_geopolitical_analysis(self, asset):
        """Get geopolitical analysis from LLM."""
        asset_name = self.assets[asset]['name']
        
        prompt = f"""Analyze the current geopolitical factors affecting {asset_name} prices.
        Consider: Middle East tensions, OPEC decisions, Russia-Ukraine conflict, US-Iran relations,
        sanctions, production disruptions, and global economic factors.
        
        Return a JSON response with this structure:
        {{
            "risk_level": "low|medium|high",
            "risk_score": 0-100,
            "key_risks": ["risk1", "risk2", "risk3"],
            "summary": "brief summary"
        }}
        
        Be realistic about current market conditions (March 2026)."""
        
        response = query_llm(prompt, self.model)
        if response:
            try:
                # Extract JSON from response
                json_start = response.find('{')
                json_end = response.rfind('}') + 1
                if json_start >= 0 and json_end > json_start:
                    return json.loads(response[json_start:json_end])
            except:
                pass
        
        # Fallback
        return {
            "risk_level": "medium",
            "risk_score": 50,
            "key_risks": ["Middle East tensions", "OPEC production cuts", "Global demand uncertainty"],
            "summary": "Moderate geopolitical risk due to ongoing tensions and OPEC policy."
        }
    
    def get_llm_supply_analysis(self, asset):
        """Get supply analysis from LLM."""
        asset_name = self.assets[asset]['name']
        
        prompt = f"""Analyze the current supply situation for {asset_name}.
        Consider: US shale production, OPEC+ output, strategic reserves, inventory levels,
        North Sea production, Russian exports, refinery capacity.
        
        Return a JSON response with this structure:
        {{
            "supply_level": "tight|balanced|abundant",
            "supply_score": 0-100 (higher = more constrained),
            "key_factors": ["factor1", "factor2"],
            "outlook": "1-2 sentence outlook"
        }}
        
        Be realistic about current market conditions (March 2026)."""
        
        response = query_llm(prompt, self.model)
        if response:
            try:
                json_start = response.find('{')
                json_end = response.rfind('}') + 1
                if json_start >= 0 and json_end > json_start:
                    return json.loads(response[json_start:json_end])
            except:
                pass
        
        return {
            "supply_level": "balanced",
            "supply_score": 50,
            "key_factors": ["OPEC compliance", "US production"],
            "outlook": "Supply remains relatively stable with OPEC maintaining discipline."
        }
    
    def get_llm_demand_analysis(self, asset):
        """Get demand analysis from LLM."""
        asset_name = self.assets[asset]['name']
        
        prompt = f"""Analyze the current demand situation for {asset_name}.
        Consider: Global GDP growth, China demand, US demand, seasonal factors,
        inventory draws, economic recession fears, energy transition impacts.
        
        Return a JSON response with this structure:
        {{
            "demand_level": "strong|moderate|weak",
            "demand_score": 0-100 (higher = stronger),
            "key_factors": ["factor1", "factor2"],
            "outlook": "1-2 sentence outlook"
        }}
        
        Be realistic about current market conditions (March 2026)."""
        
        response = query_llm(prompt, self.model)
        if response:
            try:
                json_start = response.find('{')
                json_end = response.rfind('}') + 1
                if json_start >= 0 and json_end > json_start:
                    return json.loads(response[json_start:json_end])
            except:
                pass
        
        return {
            "demand_level": "moderate",
            "demand_score": 50,
            "key_factors": ["China recovery", "US driving season"],
            "outlook": "Demand remains moderate with mixed signals from major economies."
        }
    
    def calculate_volatility_score(self, geo, supply, demand):
        """Calculate composite volatility score."""
        # Weights: Geopolitical 40%, Supply 30%, Demand 30%
        score = (geo['risk_score'] * 0.4 + 
                 supply['supply_score'] * 0.3 + 
                 (100 - demand['demand_score']) * 0.3)  # Invert demand (low demand = high volatility)
        return min(int(score), 100)
    
    def explain_score(self, score):
        """Explain what the score means."""
        if score >= 70:
            return {
                "level": "high",
                "interpretation": "High market uncertainty. Consider minimal positions or holding.",
                "factors": ["Geopolitical tensions", "Supply disruptions", "Demand shocks"],
                "action": "Reduce position size to 30% or wait for stabilization."
            }
        elif score >= 40:
            return {
                "level": "medium",
                "interpretation": "Moderate uncertainty. Reduced position sizes recommended.",
                "factors": ["Mixed signals", "Some geopolitical risk", "Balanced supply/demand"],
                "action": "Trade with 60% position size and tight stops."
            }
        else:
            return {
                "level": "low",
                "interpretation": "Market conditions favorable for normal trading.",
                "factors": ["Stable geopolitics", "Balanced supply", "Steady demand"],
                "action": "Full position size appropriate with normal risk management."
            }
    
    def generate_recommendation(self, score, explanation):
        """Generate trading recommendation."""
        if score >= 70:
            return {
                "recommendation": "REDUCE",
                "position_size": 0.3,
                "confidence": 100 - score,
                "reasoning": f"High volatility ({score}/100). {explanation['action']}"
            }
        elif score >= 40:
            return {
                "recommendation": "MODERATE",
                "position_size": 0.6,
                "confidence": 100 - score,
                "reasoning": f"Medium volatility ({score}/100). {explanation['action']}"
            }
        else:
            return {
                "recommendation": "TRADE",
                "position_size": 1.0,
                "confidence": 100 - score,
                "reasoning": f"Low volatility ({score}/100). {explanation['action']}"
            }
    
    def research_asset(self, asset):
        """Research specific oil asset using LLM."""
        print(f"\n🔬 Researching {self.assets[asset]['name']} with {self.model}...")
        
        # Get LLM analysis
        geo = self.get_llm_geopolitical_analysis(asset)
        supply = self.get_llm_supply_analysis(asset)
        demand = self.get_llm_demand_analysis(asset)
        
        # Calculate scores
        volatility_score = self.calculate_volatility_score(geo, supply, demand)
        explanation = self.explain_score(volatility_score)
        recommendation = self.generate_recommendation(volatility_score, explanation)
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'asset': asset,
            'asset_name': self.assets[asset]['name'],
            'origin': self.assets[asset]['origin'],
            'model_used': self.model,
            'volatility_score': volatility_score,
            'volatility_level': explanation['level'],
            'factors': {
                'geopolitical': geo,
                'supply': supply,
                'demand': demand
            },
            'score_explanation': explanation,
            'recommendation': recommendation['recommendation'],
            'position_size': recommendation['position_size'],
            'confidence': recommendation['confidence'],
            'reasoning': recommendation['reasoning']
        }
        
        return report
    
    def display_report(self, report):
        """Display formatted report."""
        r = report
        exp = r['score_explanation']
        
        print("\n" + "="*60)
        print(f"🛢️  {r['asset_name'].upper()} ANALYSIS (via {r['model_used']})")
        print("="*60)
        print(f"\n📍 {r['origin']}")
        print(f"⏰ {r['timestamp']}")
        
        print(f"\n{'─'*60}")
        print(f"📊 VOLATILITY SCORE: {r['volatility_score']}/100 ({exp['level'].upper()})")
        print(f"{'─'*60}")
        print(f"\n💭 {exp['interpretation']}")
        print(f"\n📋 Key Factors: {', '.join(exp['factors'])}")
        
        print(f"\n🌍 Geopolitical: {r['factors']['geopolitical']['risk_level']}")
        print(f"   Score: {r['factors']['geopolitical']['risk_score']}")
        print(f"   Risks: {', '.join(r['factors']['geopolitical']['key_risks'][:3])}")
        
        print(f"\n📦 Supply: {r['factors']['supply']['supply_level']}")
        print(f"   Score: {r['factors']['supply']['supply_score']}")
        print(f"   Factors: {', '.join(r['factors']['supply']['key_factors'][:2])}")
        
        print(f"\n📈 Demand: {r['factors']['demand']['demand_level']}")
        print(f"   Score: {r['factors']['demand']['demand_score']}")
        print(f"   Factors: {', '.join(r['factors']['demand']['key_factors'][:2])}")
        
        print(f"\n{'─'*60}")
        print(f"🎯 {r['recommendation']} | Position: {r['position_size']*100:.0f}% | Confidence: {r['confidence']}%")
        print(f"💡 {r['reasoning']}")
        print("="*60)
    
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
        """Execute full research cycle."""
        print("\n" + "="*60)
        print(f"🔬 OIL RESEARCH WITH {self.model.upper()}")
        print("="*60)
        
        for asset in self.assets:
            report = self.research_asset(asset)
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
