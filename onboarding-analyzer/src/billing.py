"""
Stripe billing integration for Onboarding Analyzer
"""

import stripe
import os
from typing import Optional, Dict
from datetime import datetime

# Initialize Stripe
stripe.api_key = os.getenv('STRIPE_SECRET_KEY')

# Pricing tiers
PRICING_TIERS = {
    'free': {
        'name': 'Free',
        'price': 0,
        'analyses_per_month': 3,
        'funnels_limit': 1,
        'features': ['Basic analysis', 'CSV upload', 'Standard reports']
    },
    'pro': {
        'name': 'Pro',
        'price_id': 'price_pro',  # Replace with actual Stripe price ID
        'price': 49,
        'analyses_per_month': float('inf'),
        'funnels_limit': 10,
        'features': ['Unlimited analyses', 'AI hypotheses', 'Email reports', 'API access']
    },
    'team': {
        'name': 'Team',
        'price_id': 'price_team',  # Replace with actual Stripe price ID
        'price': 199,
        'analyses_per_month': float('inf'),
        'funnels_limit': float('inf'),
        'features': ['Everything in Pro', 'Unlimited team', 'White-label', 'Priority support']
    }
}


class BillingManager:
    """Handle Stripe billing operations"""
    
    def __init__(self):
        self.stripe = stripe
    
    def create_customer(self, email: str, user_id: str) -> str:
        """Create a Stripe customer"""
        try:
            customer = self.stripe.Customer.create(
                email=email,
                metadata={'user_id': user_id}
            )
            return customer.id
        except stripe.error.StripeError as e:
            print(f"Error creating customer: {e}")
            return None
    
    def create_checkout_session(self, customer_id: str, tier: str, success_url: str, cancel_url: str) -> Optional[str]:
        """Create Stripe Checkout session"""
        try:
            tier_config = PRICING_TIERS.get(tier)
            if not tier_config or tier == 'free':
                return None
            
            session = self.stripe.checkout.Session.create(
                customer=customer_id,
                payment_method_types=['card'],
                line_items=[{
                    'price': tier_config['price_id'],
                    'quantity': 1,
                }],
                mode='subscription',
                success_url=success_url,
                cancel_url=cancel_url,
                metadata={'tier': tier}
            )
            return session.url
        except stripe.error.StripeError as e:
            print(f"Error creating checkout: {e}")
            return None
    
    def cancel_subscription(self, subscription_id: str) -> bool:
        """Cancel a subscription"""
        try:
            self.stripe.Subscription.delete(subscription_id)
            return True
        except stripe.error.StripeError as e:
            print(f"Error canceling subscription: {e}")
            return False
    
    def get_subscription(self, subscription_id: str) -> Optional[Dict]:
        """Get subscription details"""
        try:
            sub = self.stripe.Subscription.retrieve(subscription_id)
            return {
                'id': sub.id,
                'status': sub.status,
                'current_period_end': datetime.fromtimestamp(sub.current_period_end),
                'cancel_at_period_end': sub.cancel_at_period_end
            }
        except stripe.error.StripeError as e:
            print(f"Error getting subscription: {e}")
            return None
    
    def handle_webhook(self, payload: str, sig_header: str) -> Optional[Dict]:
        """Handle Stripe webhook"""
        webhook_secret = os.getenv('STRIPE_WEBHOOK_SECRET')
        try:
            event = self.stripe.Webhook.construct_event(
                payload, sig_header, webhook_secret
            )
            return event
        except Exception as e:
            print(f"Webhook error: {e}")
            return None


def check_usage_limits(user_plan: str, analyses_this_month: int, funnels_count: int) -> Dict:
    """Check if user is within their plan limits"""
    tier = PRICING_TIERS.get(user_plan, PRICING_TIERS['free'])
    
    return {
        'can_analyze': analyses_this_month < tier['analyses_per_month'],
        'can_create_funnel': funnels_count < tier['funnels_limit'],
        'analyses_remaining': max(0, tier['analyses_per_month'] - analyses_this_month),
        'funnels_remaining': max(0, tier['funnels_limit'] - funnels_count),
        'analyses_limit': tier['analyses_per_month'],
        'funnels_limit': tier['funnels_limit'],
        'upgrade_needed': analyses_this_month >= tier['analyses_per_month'] or funnels_count >= tier['funnels_limit']
    }


def get_pricing_page_html() -> str:
    """Generate pricing page HTML"""
    html = """
    <div style="display: flex; gap: 2rem; justify-content: center; flex-wrap: wrap;">
    """
    
    for tier_key, tier in PRICING_TIERS.items():
        price_display = f"${tier['price']}/mo" if tier['price'] > 0 else "Free"
        features_html = "<ul>" + "".join([f"<li>{f}</li>" for f in tier['features']]) + "</ul>"
        
        html += f"""
        <div style="border: 1px solid #ddd; border-radius: 8px; padding: 1.5rem; width: 280px;">
            <h3>{tier['name']}</h3>
            <p style="font-size: 2rem; font-weight: bold;">{price_display}</p>
            {features_html}
        </div>
        """
    
    html += "</div>"
    return html
