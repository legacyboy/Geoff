"""
Geopolitical Monitor - Comprehensive Oil Market Intelligence
Tracks: Trump activities, OPEC decisions, conflicts, sanctions, supply disruptions
"""

import json
import logging
import os
import re
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, asdict
from enum import Enum
import threading
import time

# Setup logging
BASE_DIR = Path(__file__).parent.parent
DATA_DIR = BASE_DIR / 'data' / 'geopolitical'
LOGS_DIR = BASE_DIR / 'logs'
DATA_DIR.mkdir(parents=True, exist_ok=True)
LOGS_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    filename=LOGS_DIR / 'geopolitical_monitor.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class EventType(Enum):
    TRUMP_STATEMENT = "trump_statement"
    OPEC_DECISION = "opec_decision"
    CONFLICT_ESCALATION = "conflict_escalation"
    SANCTIONS = "sanctions"
    SUPPLY_DISRUPTION = "supply_disruption"
    WEATHER_EVENT = "weather_event"
    POLICY_CHANGE = "policy_change"
    GEOPOLITICAL_TENSION = "geopolitical_tension"

class ImpactLevel(Enum):
    CRITICAL = 5  # Immediate market impact >5%
    HIGH = 4      # Significant impact 2-5%
    MEDIUM = 3    # Moderate impact 1-2%
    LOW = 2       # Minor impact <1%
    MINIMAL = 1   # Background noise

@dataclass
class GeopoliticalEvent:
    """Represents a geopolitical event affecting oil markets."""
    id: str
    timestamp: str
    event_type: str
    source: str
    title: str
    description: str
    impact_level: int
    regions_affected: List[str]
    oil_market_impact: Dict[str, Any]
    sentiment: str  # bullish, bearish, mixed
    keywords: List[str]
    verified: bool = False
    sources_confirmed: int = 1
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

class TrumpMonitor:
    """Dedicated Trump monitoring from Truth Social and related sources."""
    
    def __init__(self):
        self.data_dir = DATA_DIR / 'trump'
        self.data_dir.mkdir(exist_ok=True)
        
        self.oil_keywords = {
            'production': ['drill', 'drilling', 'fracking', 'shale', 'production', 'output', 'supply'],
            'policy': ['energy dominance', 'energy independence', 'domestic', 'america first'],
            'sanctions': ['sanctions', 'iran', 'venezuela', 'russia', 'embargo', 'ban'],
            'trade': ['tariffs', 'trade war', 'import', 'export', 'china', 'trade deal'],
            'infrastructure': ['pipeline', 'keystone', 'infrastructure', 'permian', 'gulf'],
            'strategic': ['spr', 'strategic reserve', 'emergency', 'stockpile'],
            'conflict': ['war', 'attack', 'military', 'threat', 'conflict', 'tension']
        }
        
        self.impact_phrases = {
            'critical': ['emergency', 'crisis', 'immediately', 'today', 'executive order'],
            'high': ['major', 'significant', 'big', 'huge', 'massive', 'ban', 'stop'],
            'medium': ['consider', 'review', 'planning', 'thinking', 'looking at'],
            'low': ['maybe', 'perhaps', 'someday', 'future']
        }
    
    def fetch_truth_social(self) -> List[Dict[str, Any]]:
        """Fetch Trump's Truth Social posts."""
        posts = []
        
        # Trump's account ID on Truth Social
        account_id = '107780257626128481'
        
        try:
            result = subprocess.run(
                ['curl', '-s', '-L', '--max-time', '15',
                 f'https://truthsocial.com/api/v1/accounts/{account_id}/statuses'],
                capture_output=True, text=True, timeout=20
            )
            
            if result.returncode == 0 and result.stdout:
                data = json.loads(result.stdout)
                
                for post in data:
                    content = re.sub(r'<[^>]+>', '', post.get('content', ''))
                    
                    # Check for oil relevance
                    relevance = self._check_oil_relevance(content)
                    
                    if relevance['is_relevant']:
                        posts.append({
                            'id': post.get('id'),
                            'source': 'Truth Social',
                            'timestamp': post.get('created_at'),
                            'content': content,
                            'url': post.get('url', ''),
                            'engagement': {
                                'reblogs': post.get('reblogs_count', 0),
                                'favourites': post.get('favourites_count', 0)
                            },
                            'relevance': relevance,
                            'raw_data': post
                        })
        
        except Exception as e:
            logger.error(f"Error fetching Truth Social: {e}")
        
        return posts
    
    def _check_oil_relevance(self, content: str) -> Dict[str, Any]:
        """Check if content is oil-relevant."""
        content_lower = content.lower()
        
        found_keywords = []
        categories = set()
        
        for category, keywords in self.oil_keywords.items():
            for kw in keywords:
                if kw in content_lower:
                    found_keywords.append(kw)
                    categories.add(category)
        
        # Calculate urgency
        urgency = 'low'
        for level, phrases in self.impact_phrases.items():
            for phrase in phrases:
                if phrase in content_lower:
                    urgency = level
                    break
        
        return {
            'is_relevant': len(found_keywords) > 0,
            'keywords': list(set(found_keywords)),
            'categories': list(categories),
            'urgency': urgency,
            'score': len(found_keywords) * 10 + (5 if urgency == 'critical' else 3 if urgency == 'high' else 1)
        }

class OPECMonitor:
    """Monitor OPEC decisions and statements."""
    
    def __init__(self):
        self.data_dir = DATA_DIR / 'opec'
        self.data_dir.mkdir(exist_ok=True)
        
        self.opec_sources = [
            'https://www.opec.org/opec_web/en/press_room/press_releases.htm',
            'https://www.opec.org/basket/basketDayArchives.xml',
            'https://www.reuters.com/subjects/oilreport'
        ]
    
    def check_production_changes(self) -> List[Dict[str, Any]]:
        """Check for OPEC production decisions."""
        events = []
        
        # Check OPEC basket price (indicator of market conditions)
        try:
            result = subprocess.run(
                ['curl', '-s', '-L', '--max-time', '10',
                 'https://www.opec.org/basket/basketDay.xml'],
                capture_output=True, text=True, timeout=15
            )
            
            if result.returncode == 0 and 'OPEC_Reference_Basket' in result.stdout:
                # Parse XML for price data
                import xml.etree.ElementTree as ET
                root = ET.fromstring(result.stdout)
                
                # Extract price data
                data_elem = root.find('.//Data')
                if data_elem is not None:
                    price = data_elem.get('VAL', '0')
                    date = data_elem.get('TIME', '')
                    
                    events.append({
                        'id': f'opec_basket_{date}',
                        'source': 'OPEC',
                        'timestamp': datetime.now().isoformat(),
                        'title': 'OPEC Reference Basket Price Update',
                        'description': f'OPEC basket price: ${price}',
                        'impact_level': 2,
                        'type': 'opec_price'
                    })
        
        except Exception as e:
            logger.error(f"Error checking OPEC: {e}")
        
        return events

class ConflictMonitor:
    """Monitor geopolitical conflicts affecting oil supply."""
    
    def __init__(self):
        self.data_dir = DATA_DIR / 'conflicts'
        self.data_dir.mkdir(exist_ok=True)
        
        # Key oil-producing regions
        self.regions = {
            'middle_east': {
                'countries': ['saudi_arabia', 'iraq', 'iran', 'kuwait', 'uae', 'qatar', 'oman'],
                'supply_pct': 35,
                'risk_level': 'high'
            },
            'russia_caspian': {
                'countries': ['russia', 'kazakhstan', 'azerbaijan'],
                'supply_pct': 12,
                'risk_level': 'high'
            },
            'venezuela': {
                'countries': ['venezuela'],
                'supply_pct': 2,
                'risk_level': 'medium'
            },
            'north_sea': {
                'countries': ['norway', 'uk'],
                'supply_pct': 3,
                'risk_level': 'low'
            }
        }
        
        self.conflict_indicators = [
            'attack', 'bombing', 'missile', 'war', 'invasion', 'sanctions',
            'embargo', 'port closure', 'pipeline explosion', 'facility attack'
        ]
    
    def check_active_conflicts(self) -> List[Dict[str, Any]]:
        """Check for active conflicts in oil-producing regions."""
        conflicts = []
        
        # Check recent events
        try:
            # Use GDELT or other news API for conflict data
            # For now, check local cached data
            conflict_file = self.data_dir / 'active_conflicts.json'
            if conflict_file.exists():
                with open(conflict_file) as f:
                    data = json.load(f)
                    conflicts = data.get('conflicts', [])
        
        except Exception as e:
            logger.error(f"Error checking conflicts: {e}")
        
        return conflicts
    
    def assess_supply_risk(self, region: str) -> Dict[str, Any]:
        """Assess supply risk for a region."""
        if region not in self.regions:
            return {'risk_level': 'unknown', 'supply_impact': 0}
        
        region_data = self.regions[region]
        
        return {
            'region': region,
            'risk_level': region_data['risk_level'],
            'supply_impact_pct': region_data['supply_pct'],
            'countries': region_data['countries'],
            'estimated_bpd_at_risk': self._calculate_bpd_at_risk(region)
        }
    
    def _calculate_bpd_at_risk(self, region: str) -> int:
        """Estimate barrels per day at risk."""
        global_supply = 100_000_000  # ~100M bpd global
        
        if region in self.regions:
            pct = self.regions[region]['supply_pct']
            return int(global_supply * (pct / 100))
        
        return 0

class SanctionsMonitor:
    """Monitor sanctions affecting oil trade."""
    
    def __init__(self):
        self.data_dir = DATA_DIR / 'sanctions'
        self.data_dir.mkdir(exist_ok=True)
        
        self.sanction_targets = {
            'iran': {'oil_exports_bpd': 1_000_000, 'impact_high': True},
            'venezuela': {'oil_exports_bpd': 500_000, 'impact_high': True},
            'russia': {'oil_exports_bpd': 5_000_000, 'impact_high': True},
            'libya': {'oil_exports_bpd': 1_200_000, 'impact_high': False}
        }
    
    def check_sanction_changes(self) -> List[Dict[str, Any]]:
        """Check for new or modified sanctions."""
        events = []
        
        # Check OFAC (US Treasury) updates
        try:
            # Would parse OFAC XML feed in production
            pass
        except Exception as e:
            logger.error(f"Error checking sanctions: {e}")
        
        return events
    
    def calculate_sanction_impact(self, target: str) -> Dict[str, Any]:
        """Calculate impact of sanctions on target country."""
        if target not in self.sanction_targets:
            return {'impact': 0, 'description': 'Unknown target'}
        
        target_data = self.sanction_targets[target]
        
        return {
            'target': target,
            'daily_exports_bpd': target_data['oil_exports_bpd'],
            'global_supply_pct': round(target_data['oil_exports_bpd'] / 100_000_000 * 100, 2),
            'impact_high': target_data['impact_high'],
            'potential_price_impact_pct': 2 if target_data['impact_high'] else 0.5
        }

class GeopoliticalAggregator:
    """Aggregates all geopolitical data into actionable intelligence."""
    
    def __init__(self):
        self.trump_monitor = TrumpMonitor()
        self.opec_monitor = OPECMonitor()
        self.conflict_monitor = ConflictMonitor()
        self.sanctions_monitor = SanctionsMonitor()
        
        self.events_file = DATA_DIR / 'events.json'
        self.intelligence_file = DATA_DIR / 'intelligence.json'
    
    def collect_all_events(self) -> List[GeopoliticalEvent]:
        """Collect events from all monitors."""
        events = []
        
        # Trump statements
        trump_posts = self.trump_monitor.fetch_truth_social()
        for post in trump_posts:
            relevance = post.get('relevance', {})
            events.append(GeopoliticalEvent(
                id=post['id'],
                timestamp=post['timestamp'],
                event_type=EventType.TRUMP_STATEMENT.value,
                source='Truth Social',
                title='Trump Statement on Oil/Energy',
                description=post['content'][:200],
                impact_level=self._map_urgency_to_impact(relevance.get('urgency', 'low')),
                regions_affected=['united_states'],
                oil_market_impact={
                    'sentiment': self._determine_sentiment(relevance),
                    'keywords': relevance.get('keywords', []),
                    'categories': relevance.get('categories', [])
                },
                sentiment=self._determine_sentiment(relevance),
                keywords=relevance.get('keywords', []),
                verified=True
            ))
        
        # OPEC decisions
        opec_events = self.opec_monitor.check_production_changes()
        for event in opec_events:
            events.append(GeopoliticalEvent(
                id=event['id'],
                timestamp=event['timestamp'],
                event_type=EventType.OPEC_DECISION.value,
                source='OPEC',
                title=event['title'],
                description=event['description'],
                impact_level=event['impact_level'],
                regions_affected=['middle_east', 'global'],
                oil_market_impact={'type': 'price_reference'},
                sentiment='neutral',
                keywords=['opec', 'production', 'price']
            ))
        
        # Conflicts
        conflicts = self.conflict_monitor.check_active_conflicts()
        for conflict in conflicts:
            events.append(GeopoliticalEvent(
                id=conflict['id'],
                timestamp=conflict['timestamp'],
                event_type=EventType.CONFLICT_ESCALATION.value,
                source=conflict.get('source', 'News'),
                title=conflict['title'],
                description=conflict['description'],
                impact_level=conflict.get('impact_level', 3),
                regions_affected=conflict.get('regions', []),
                oil_market_impact={'supply_risk': conflict.get('supply_risk', 0)},
                sentiment='bullish' if conflict.get('supply_risk', 0) > 50 else 'mixed',
                keywords=conflict.get('keywords', [])
            ))
        
        return events
    
    def _map_urgency_to_impact(self, urgency: str) -> int:
        """Map urgency string to impact level."""
        mapping = {
            'critical': 5,
            'high': 4,
            'medium': 3,
            'low': 2
        }
        return mapping.get(urgency, 1)
    
    def _determine_sentiment(self, relevance: Dict) -> str:
        """Determine market sentiment from relevance data."""
        categories = relevance.get('categories', [])
        
        if 'sanctions' in categories or 'conflict' in categories:
            return 'bullish'  # Supply constraints
        elif 'production' in categories:
            return 'bearish'  # More supply
        
        return 'mixed'
    
    def generate_intelligence_report(self) -> Dict[str, Any]:
        """Generate comprehensive intelligence report."""
        events = self.collect_all_events()
        
        # Sort by impact and timestamp
        events.sort(key=lambda e: (e.impact_level, e.timestamp), reverse=True)
        
        # Calculate threat levels
        threat_levels = self._calculate_threat_levels(events)
        
        # Identify key factors
        key_factors = self._identify_key_factors(events)
        
        # Attribution breakdown
        attribution = self._calculate_attribution(events)
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'total_events_24h': len(events),
                'critical_events': len([e for e in events if e.impact_level >= 4]),
                'high_events': len([e for e in events if e.impact_level == 3]),
                'threat_level': threat_levels['overall'],
                'primary_concerns': key_factors[:5]
            },
            'threat_levels': threat_levels,
            'attribution': attribution,
            'key_factors': key_factors,
            'recent_events': [e.to_dict() for e in events[:10]],
            'trump_activity': {
                'statements_24h': len([e for e in events if e.event_type == EventType.TRUMP_STATEMENT.value]),
                'impact_score': sum(e.impact_level for e in events if e.event_type == EventType.TRUMP_STATEMENT.value),
                'latest_statement': events[0].to_dict() if events and events[0].event_type == EventType.TRUMP_STATEMENT.value else None
            },
            'opec_status': {
                'last_meeting': None,  # Would populate from data
                'production_policy': 'stable',
                'compliance_rate': 100
            },
            'supply_risks': self._assess_supply_risks(events)
        }
        
        # Save report
        self._save_report(report)
        
        return report
    
    def _calculate_threat_levels(self, events: List[GeopoliticalEvent]) -> Dict[str, Any]:
        """Calculate threat levels by category."""
        return {
            'overall': 'HIGH' if any(e.impact_level >= 4 for e in events) else 'MEDIUM' if any(e.impact_level >= 3 for e in events) else 'LOW',
            'trump_factor': 'HIGH' if any(e.impact_level >= 4 and e.event_type == EventType.TRUMP_STATEMENT.value for e in events) else 'MEDIUM',
            'opec_stability': 'LOW',
            'conflict_risk': 'MEDIUM' if any(e.event_type == EventType.CONFLICT_ESCALATION.value for e in events) else 'LOW',
            'sanctions_risk': 'MEDIUM'
        }
    
    def _identify_key_factors(self, events: List[GeopoliticalEvent]) -> List[Dict[str, Any]]:
        """Identify key volatility factors."""
        factors = []
        
        # Analyze event types
        trump_events = [e for e in events if e.event_type == EventType.TRUMP_STATEMENT.value]
        conflict_events = [e for e in events if e.event_type == EventType.CONFLICT_ESCALATION.value]
        opec_events = [e for e in events if e.event_type == EventType.OPEC_DECISION.value]
        
        if trump_events:
            avg_impact = sum(e.impact_level for e in trump_events) / len(trump_events)
            factors.append({
                'factor': 'Trump Activity',
                'impact': avg_impact,
                'description': f'{len(trump_events)} Trump statements affecting oil markets',
                'sentiment': trump_events[0].sentiment if trump_events else 'neutral'
            })
        
        if conflict_events:
            factors.append({
                'factor': 'Geopolitical Conflict',
                'impact': max(e.impact_level for e in conflict_events),
                'description': 'Active conflicts in oil-producing regions',
                'regions': list(set(r for e in conflict_events for r in e.regions_affected))
            })
        
        if opec_events:
            factors.append({
                'factor': 'OPEC Policy',
                'impact': max(e.impact_level for e in opec_events),
                'description': 'OPEC production or pricing decisions'
            })
        
        return sorted(factors, key=lambda x: x['impact'], reverse=True)
    
    def _calculate_attribution(self, events: List[GeopoliticalEvent]) -> Dict[str, float]:
        """Calculate volatility attribution by source."""
        if not events:
            return {
                'trump': 0,
                'opec': 0,
                'conflicts': 0,
                'sanctions': 0,
                'other': 100
            }
        
        total_impact = sum(e.impact_level for e in events)
        
        if total_impact == 0:
            return {'trump': 0, 'opec': 0, 'conflicts': 0, 'sanctions': 0, 'other': 100}
        
        trump_impact = sum(e.impact_level for e in events if e.event_type == EventType.TRUMP_STATEMENT.value)
        opec_impact = sum(e.impact_level for e in events if e.event_type == EventType.OPEC_DECISION.value)
        conflict_impact = sum(e.impact_level for e in events if e.event_type == EventType.CONFLICT_ESCALATION.value)
        sanctions_impact = sum(e.impact_level for e in events if e.event_type == EventType.SANCTIONS.value)
        
        return {
            'trump': round(trump_impact / total_impact * 100, 1),
            'opec': round(opec_impact / total_impact * 100, 1),
            'conflicts': round(conflict_impact / total_impact * 100, 1),
            'sanctions': round(sanctions_impact / total_impact * 100, 1),
            'other': round((total_impact - trump_impact - opec_impact - conflict_impact - sanctions_impact) / total_impact * 100, 1)
        }
    
    def _assess_supply_risks(self, events: List[GeopoliticalEvent]) -> List[Dict[str, Any]]:
        """Assess current supply risks."""
        risks = []
        
        # Check for Middle East tensions
        me_events = [e for e in events if 'middle_east' in e.regions_affected]
        if me_events:
            risks.append({
                'region': 'Middle East',
                'risk_level': 'HIGH',
                'supply_at_risk_bpd': 35_000_000,
                'pct_global_supply': 35,
                'active_threats': len(me_events)
            })
        
        # Check for Russia/Ukraine related
        ru_events = [e for e in events if 'russia' in e.regions_affected or 'ukraine' in e.description.lower()]
        if ru_events:
            risks.append({
                'region': 'Russia/Ukraine',
                'risk_level': 'MEDIUM',
                'supply_at_risk_bpd': 10_000_000,
                'pct_global_supply': 10,
                'active_threats': len(ru_events)
            })
        
        return risks
    
    def _save_report(self, report: Dict[str, Any]) -> None:
        """Save intelligence report to file."""
        try:
            with open(self.intelligence_file, 'w') as f:
                json.dump(report, f, indent=2)
            
            # Also save events
            with open(self.events_file, 'w') as f:
                json.dump(report.get('recent_events', []), f, indent=2)
            
            logger.info(f"Intelligence report saved: {self.intelligence_file}")
        
        except Exception as e:
            logger.error(f"Error saving report: {e}")

def main():
    """Run the geopolitical monitor."""
    print("🌍 Initializing Geopolitical Monitor...")
    
    aggregator = GeopoliticalAggregator()
    report = aggregator.generate_intelligence_report()
    
    print("\n" + "="*60)
    print("GEOPOLITICAL INTELLIGENCE REPORT")
    print("="*60)
    
    summary = report['summary']
    print(f"\n📊 Summary:")
    print(f"   Total Events (24h): {summary['total_events_24h']}")
    print(f"   Critical Events: {summary['critical_events']}")
    print(f"   Overall Threat Level: {summary['threat_level']}")
    
    print(f"\n🦅 Trump Activity:")
    trump = report['trump_activity']
    print(f"   Statements: {trump['statements_24h']}")
    print(f"   Impact Score: {trump['impact_score']}")
    
    print(f"\n📈 Attribution:")
    for source, pct in report['attribution'].items():
        if pct > 0:
            print(f"   {source.capitalize()}: {pct}%")
    
    print(f"\n⚠️  Supply Risks:")
    for risk in report['supply_risks']:
        print(f"   {risk['region']}: {risk['risk_level']} ({risk['pct_global_supply']}% global supply)")
    
    print(f"\n💾 Report saved to: {aggregator.intelligence_file}")
    print("="*60)

if __name__ == '__main__':
    main()
