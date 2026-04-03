# Onboarding Drop-off Analyzer - Deployment Guide

## Quick Deploy to Railway

### 1. Setup Railway Account
```bash
npm install -g @railway/cli
railway login
```

### 2. Deploy Streamlit App
```bash
cd ~/.openclaw/workspace/onboarding-analyzer
railway init
railway add
# Select "Deploy from Dockerfile"
railway up
```

### 3. Environment Variables
Set in Railway dashboard:
- `OPENAI_API_KEY` - Required for AI hypotheses
- `STRIPE_SECRET_KEY` - For billing
- `STRIPE_PUBLISHABLE_KEY` - For frontend
- `SUPABASE_URL` - For auth & data
- `SUPABASE_KEY` - For auth & data

---

## Alternative: Deploy to Render

### 1. Create render.yaml
```yaml
services:
  - type: web
    name: onboarding-analyzer
    env: python
    buildCommand: pip install -r requirements.txt
    startCommand: streamlit run dashboard.py --server.port=$PORT
    envVars:
      - key: OPENAI_API_KEY
        sync: false
      - key: STRIPE_SECRET_KEY
        sync: false
```

### 2. Deploy
```bash
git push render main
```

---

## Environment Setup

### Required Secrets
```bash
# Stripe (billing)
STRIPE_SECRET_KEY=sk_live_...
STRIPE_PUBLISHABLE_KEY=pk_live_...
STRIPE_WEBHOOK_SECRET=whsec_...

# Supabase (auth & database)
SUPABASE_URL=https://...supabase.co
SUPABASE_KEY=eyJ...

# OpenAI (AI features)
OPENAI_API_KEY=sk-...

# App
APP_URL=https://your-app.railway.app
```

---

## Database Schema (Supabase)

```sql
-- Users table (linked to Supabase Auth)
create table users (
  id uuid references auth.users primary key,
  email text not null,
  stripe_customer_id text,
  stripe_subscription_id text,
  plan text default 'free',
  created_at timestamp with time zone default timezone('utc'::text, now())
);

-- Funnels table
create table funnels (
  id uuid default gen_random_uuid() primary key,
  user_id uuid references users(id),
  name text not null,
  data jsonb,
  results jsonb,
  created_at timestamp with time zone default timezone('utc'::text, now())
);

-- Usage tracking
create table usage (
  id uuid default gen_random_uuid() primary key,
  user_id uuid references users(id),
  analyses_count int default 0,
  period_start date,
  period_end date
);
```

---

## Post-Deploy Checklist

- [ ] App loads at custom domain
- [ ] Sign up / login works
- [ ] Stripe checkout creates subscription
- [ ] Free tier limits enforced
- [ ] Analysis runs without errors
- [ ] AI hypotheses generate (if API key set)
- [ ] Email reports send (if configured)

---

## Pricing Tiers

**Free:**
- 3 analyses/month
- 1 funnel saved
- Basic reports

**Pro ($49/mo):**
- Unlimited analyses
- 10 funnels saved
- AI hypotheses
- Email reports
- Priority support

**Team ($199/mo):**
- Everything in Pro
- Unlimited team members
- API access
- White-label reports
- Custom integrations

---

## Customer Acquisition Plan

### Week 1: Validation
- [ ] Post in IndieHackers: "Free onboarding audit for 5 PLG companies"
- [ ] Post in Product-Led Growth Slack communities
- [ ] DM 20 PLG founders on Twitter

### Week 2: Convert
- [ ] Deliver free audits manually
- [ ] Ask for $49/mo to continue weekly reports
- [ ] Target: 3 paying customers

### Week 3: Scale
- [ ] Product Hunt launch
- [ ] Hacker News Show HN
- [ ] Write case studies from early customers

---

*Last updated: 2026-03-29*
