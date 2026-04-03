#!/usr/bin/env python3
"""
AI Subscription Audit Service
Analyzes bank statements and SaaS subscriptions to identify waste
"""

import re
import json
from datetime import datetime, timedelta
from collections import defaultdict
from pathlib import Path

class SubscriptionAuditor:
    def __init__(self):
        self.common_saas_patterns = [
            r'ADOBE.*CREATIVE',
            r'NOTION',
            r'SLACK',
            r'ZOOM',
            r'GITHUB',
            r'HEROKU',
            r'VERCEL',
            r'NETLIFY',
            r'AWS',
            r'GCP.*GOOGLE',
            r'DROPBOX',
            r'BOX\s+INC',
            r'CALENDLY',
            r'CAL\.COM',
            r'FIGMA',
            r'FIGJAM',
            r'MIRO',
            r'MURAL',
            r'ASANA',
            r'TRELLO',
            r'NOTION',
            r'LINEAR',
            r'JIRA',
            r'CONFLUENCE',
            r'SEMRUSH',
            r'AHREFS',
            r'MOZ',
            r'BUFFER',
            r'LATER',
            r'HOOTSUITE',
            r'SPRINKLR',
            r'SALESFORCE',
            r'HUBSPOT',
            r'MAILCHIMP',
            r'CONVERTKIT',
            r'SUBSTACK',
            r'BEEHIIV',
            r'RAILWAY',
            r'RENDER',
            r'FLY\.IO',
            r'SUPABASE',
            r'PLANETSCALE',
            r'UPSTASH',
            r'OPENAI',
            r'ANTHROPIC',
            r'COHERE',
            r'PIECE',
            r'N8N',
            r'MAKE',
            r'ZAPIER',
            r'WORKATO',
            r'CLAY',
            r'APOLLO',
            r'LUSHA',
            r'HUNTER',
            r'ROCKETREACH',
            r'COGNISM',
            r'GONG',
            r'CHORUS',
            r'FIREFLIES',
            r'OTTER',
            r'GRAIN',
            r'FATHOM',
            r'RECAPPED',
            r'DOCK',
            r'PANDADOC',
            r'DOCSEND',
            r'PAPERCUP',
            r'DESKRIP',
            r'LOOM',
            r'SCREENCASTIFY',
            r'VEED',
            r'DESCRIPT',
            r'OPUS',
            r'RE purpose',
            r'KAJABI',
            r'TEACHABLE',
            r'THINKIFIC',
            r'PODIA',
            r'GURU',
            r'LESSONLY',
            r'360LEARNING',
            r'CHAMBER',
            r'MEMBERFUL',
            r'GHOST',
            r'WORDPRESS',
            r'SQUARESPACE',
            r'WIX',
            r'WEBFLOW',
            r'FRAMER',
            r'EDITORX',
            r'SHOPIFY',
            r'BIGCOMMERCE',
            r'MAGENTO',
            r'WOOCOMMERCE',
            r'STRIPE',
            r'PADDLE',
            r'LEMONSQUEEZY',
            r'GUMROAD',
            r'POLAR',
            r'CHARGE',
            r'BILLING',
            r'AWS\s+MARKETPLACE',
            r'GCP\s+MARKETPLACE',
            r'AZURE\s+MARKET',
        ]
        
        self.pricing_intel = {
            'Slack': {'min': 7.25, 'max': 15, 'unit': 'per user/month'},
            'Notion': {'min': 8, 'max': 15, 'unit': 'per user/month'},
            'Zoom': {'min': 13.99, 'max': 19.99, 'unit': 'per user/month'},
            'GitHub': {'min': 4, 'max': 21, 'unit': 'per user/month'},
            'Figma': {'min': 12, 'max': 45, 'unit': 'per user/month'},
            'Calendly': {'min': 10, 'max': 16, 'unit': 'per user/month'},
            'Heroku': {'min': 7, 'max': 250, 'unit': 'dyno/month'},
            'Vercel': {'min': 20, 'max': 0, 'unit': 'pro plan'},
            'AWS': {'min': 0, 'max': 0, 'unit': 'variable'},
            'OpenAI': {'min': 0, 'max': 0, 'unit': 'usage-based'},
            'Anthropic': {'min': 0, 'max': 0, 'unit': 'usage-based'},
        }
    
    def parse_statement_text(self, text):
        """Parse bank/credit card statement text"""
        transactions = []
        
        # Pattern for typical statement lines
        # Date, Description, Amount
        lines = text.split('\n')
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
                
            # Try to extract transaction
            # Common patterns: "MM/DD/YYYY DESCRIPTION $XX.XX" or "DESCRIPTION $XX.XX MM/DD"
            amount_match = re.search(r'\$([\d,]+\.\d{2})', line)
            if amount_match:
                amount = float(amount_match.group(1).replace(',', ''))
                
                # Extract date if present
                date_match = re.search(r'(\d{1,2}/\d{1,2}/\d{2,4})', line)
                date = date_match.group(1) if date_match else None
                
                # Extract description (everything except amount and date)
                desc = re.sub(r'\$[\d,]+\.\d{2}', '', line)
                desc = re.sub(r'\d{1,2}/\d{1,2}/\d{2,4}', '', desc)
                desc = re.sub(r'\s+', ' ', desc).strip()
                
                transactions.append({
                    'date': date,
                    'description': desc,
                    'amount': amount,
                    'is_recurring': False,
                    'service': None
                })
        
        return transactions
    
    def identify_saas_services(self, transactions):
        """Identify SaaS services from transaction descriptions"""
        for txn in transactions:
            desc_upper = txn['description'].upper()
            
            for pattern in self.common_saas_patterns:
                if re.search(pattern, desc_upper):
                    # Extract service name
                    service_name = pattern.replace(r'\s+', ' ').replace(r'\.IO', ' IO').replace(r'\.', '.').strip()
                    service_name = re.sub(r'[^A-Z0-9\s]', '', service_name).strip()
                    if len(service_name) > 2:
                        txn['service'] = service_name
                        txn['is_saas'] = True
                        break
            else:
                txn['is_saas'] = False
        
        return transactions
    
    def find_recurring_charges(self, transactions):
        """Find recurring monthly/quarterly/annual charges"""
        # Group by service
        service_groups = defaultdict(list)
        
        for txn in transactions:
            if txn.get('is_saas') and txn['service']:
                service_groups[txn['service']].append(txn)
        
        # Check for recurring patterns
        recurring = []
        for service, txns in service_groups.items():
            if len(txns) >= 2:
                # Check if amounts are similar (within 10%)
                amounts = [t['amount'] for t in txns]
                avg_amount = sum(amounts) / len(amounts)
                
                similar_amounts = all(
                    abs(a - avg_amount) / avg_amount < 0.1 
                    for a in amounts
                )
                
                if similar_amounts:
                    for t in txns:
                        t['is_recurring'] = True
                        t['frequency'] = self._estimate_frequency(txns)
                    
                    recurring.append({
                        'service': service,
                        'avg_monthly_cost': avg_amount,
                        'transaction_count': len(txns),
                        'frequency': self._estimate_frequency(txns),
                        'total_spent': sum(amounts)
                    })
        
        return recurring
    
    def _estimate_frequency(self, transactions):
        """Estimate billing frequency from transaction dates"""
        # Simplified - in real implementation would parse dates
        if len(transactions) >= 10:
            return 'monthly'
        elif len(transactions) >= 3:
            return 'quarterly'
        else:
            return 'annual'
    
    def detect_duplicates(self, transactions):
        """Detect potentially duplicate/overlapping services"""
        duplicates = []
        
        # Known duplicate categories
        duplicate_groups = [
            ['SLACK', 'TEAMS', 'DISCORD', 'MATTERMOST'],
            ['NOTION', 'CONFLUENCE', 'SLAB', 'DOCS'],
            ['ZOOM', 'MEET', 'TEAMS', 'GOTO'],
            ['FIGMA', 'SKETCH', 'ADOBE XD'],
            ['ASANA', 'TRELLO', 'LINEAR', 'JIRA'],
            ['MAILCHIMP', 'CONVERTKIT', 'SUBSTACK', 'BEEHIIV'],
            ['CALENDLY', 'CAL.COM', 'SAVVYCAl'],
            ['HEROKU', 'RAILWAY', 'RENDER', 'FLY'],
            ['AWS', 'GCP', 'AZURE'],
            ['SUPABASE', 'PLANETSCALE', 'FIREBASE'],
        ]
        
        active_services = set()
        for txn in transactions:
            if txn.get('is_saas') and txn.get('is_recurring'):
                active_services.add(txn.get('service', '').upper())
        
        for group in duplicate_groups:
            matches = [s for s in active_services if any(g in s for g in group)]
            if len(matches) > 1:
                duplicates.append({
                    'category': group[0],
                    'services': matches,
                    'potential_savings': 'Review to consolidate'
                })
        
        return duplicates
    
    def generate_report(self, transactions, output_path=None):
        """Generate comprehensive audit report"""
        # Identify services
        transactions = self.identify_saas_services(transactions)
        
        # Find recurring
        recurring = self.find_recurring_charges(transactions)
        
        # Detect duplicates
        duplicates = self.detect_duplicates(transactions)
        
        # Calculate totals
        total_monthly = sum(r['avg_monthly_cost'] for r in recurring)
        total_annual = total_monthly * 12
        
        # Generate recommendations
        recommendations = []
        
        for dup in duplicates:
            recommendations.append({
                'type': 'duplicate',
                'priority': 'high',
                'message': f"Consider consolidating {', '.join(dup['services'])} — you may be paying for overlapping tools",
                'potential_savings': 'See individual services'
            })
        
        # Find low-usage candidates (single transactions = might be unused)
        single_use = [t for t in transactions if t.get('is_saas') and not t.get('is_recurring')]
        for s in single_use[:5]:  # Top 5
            recommendations.append({
                'type': 'unused',
                'priority': 'medium',
                'message': f"{s.get('service', 'Unknown service')}: Only seen once — verify if still needed",
                'potential_savings': f"${s['amount']:.2f}/month"
            })
        
        report = {
            'generated_at': datetime.now().isoformat(),
            'summary': {
                'total_transactions_analyzed': len(transactions),
                'saas_services_found': len([t for t in transactions if t.get('is_saas')]),
                'recurring_services': len(recurring),
                'estimated_monthly_spend': total_monthly,
                'estimated_annual_spend': total_annual,
                'duplicate_categories': len(duplicates)
            },
            'recurring_services': sorted(recurring, key=lambda x: x['avg_monthly_cost'], reverse=True),
            'duplicates': duplicates,
            'recommendations': sorted(recommendations, key=lambda x: {'high': 0, 'medium': 1, 'low': 2}[x['priority']]),
            'pricing_intel': self._generate_pricing_insights(recurring)
        }
        
        if output_path:
            with open(output_path, 'w') as f:
                json.dump(report, f, indent=2)
        
        return report
    
    def _generate_pricing_insights(self, recurring):
        """Compare current pricing to market rates"""
        insights = []
        
        for service in recurring:
            service_name = service['service']
            current_cost = service['avg_monthly_cost']
            
            # Check if we have pricing intel
            for known, pricing in self.pricing_intel.items():
                if known.upper() in service_name or service_name in known.upper():
                    if pricing['max'] > 0 and current_cost > pricing['max']:
                        insights.append({
                            'service': service_name,
                            'current_cost': current_cost,
                            'market_range': f"${pricing['min']}-{pricing['max']}",
                            'suggestion': f"May be overpaying — market rate is {pricing['unit']}"
                        })
        
        return insights


def demo():
    """Demo with sample data"""
    auditor = SubscriptionAuditor()
    
    # Sample statement text (simulated)
    sample_text = """
01/15/2024 SLACK TECHNOLOGIES $87.50
02/15/2024 SLACK TECHNOLOGIES $87.50
03/15/2024 SLACK TECHNOLOGIES $87.50
01/20/2024 NOTION LABS INC $48.00
02/20/2024 NOTION LABS INC $48.00
03/20/2024 NOTION LABS INC $48.00
01/05/2024 ZOOM VIDEO $149.90
02/05/2024 ZOOM VIDEO $149.90
03/05/2024 ZOOM VIDEO $149.90
01/10/2024 GITHUB INC $44.00
02/10/2024 GITHUB INC $44.00
03/10/2024 GITHUB INC $44.00
01/25/2024 FIGMA INC $135.00
02/25/2024 FIGMA INC $135.00
03/25/2024 FIGMA INC $135.00
01/03/2024 CALENDLY LLC $19.99
02/03/2024 CALENDLY LLC $19.99
03/03/2024 CALENDLY LLC $19.99
01/12/2024 OPENAI API $45.67
02/12/2024 OPENAI API $52.34
03/12/2024 OPENAI API $38.91
01/08/2024 AWS SERVICES $234.56
02/08/2024 AWS SERVICES $198.43
03/08/2024 AWS SERVICES $267.89
01/18/2024 VERCEL INC $20.00
02/18/2024 VERCEL INC $20.00
03/18/2024 VERCEL INC $20.00
"""
    
    print("=" * 60)
    print("AI SUBSCRIPTION AUDIT - DEMO REPORT")
    print("=" * 60)
    
    transactions = auditor.parse_statement_text(sample_text)
    report = auditor.generate_report(transactions)
    
    print(f"\n📊 SUMMARY")
    print(f"   Total Transactions: {report['summary']['total_transactions_analyzed']}")
    print(f"   SaaS Services Found: {report['summary']['saas_services_found']}")
    print(f"   Recurring Services: {report['summary']['recurring_services']}")
    print(f"   💰 Estimated Monthly: ${report['summary']['estimated_monthly_spend']:.2f}")
    print(f"   💰 Estimated Annual: ${report['summary']['estimated_annual_spend']:.2f}")
    
    print(f"\n🔄 TOP RECURRING SERVICES (by cost)")
    for svc in report['recurring_services'][:10]:
        print(f"   • {svc['service']}: ${svc['avg_monthly_cost']:.2f}/mo (${svc['total_spent']:.2f} total)")
    
    if report['duplicates']:
        print(f"\n⚠️  POTENTIAL DUPLICATES")
        for dup in report['duplicates']:
            print(f"   • {dup['category']}: {', '.join(dup['services'])}")
    
    print(f"\n💡 RECOMMENDATIONS")
    for rec in report['recommendations'][:5]:
        icon = "🔴" if rec['priority'] == 'high' else "🟡" if rec['priority'] == 'medium' else "🟢"
        print(f"   {icon} {rec['message']}")
        if 'potential_savings' in rec:
            print(f"      Potential Savings: {rec['potential_savings']}")
    
    print(f"\n" + "=" * 60)
    print("Report saved to: subscription_audit_report.json")
    print("=" * 60)
    
    # Save JSON
    auditor.generate_report(transactions, 'subscription_audit_report.json')
    
    return report


if __name__ == '__main__':
    demo()
