#!/bin/bash
# API Key Configuration Setup
# This script prepares the system - you must complete signups manually

echo "=========================================="
echo "  Geopolitical Data Sources Setup"
echo "=========================================="
echo ""
echo "⚠️  I cannot create accounts for you (violates ToS)"
echo "    But I'll prepare everything for easy configuration"
echo ""

ENV_FILE="/home/claw/.openclaw/workspace/trading-bot/.env"
CONFIG_FILE="/home/claw/.openclaw/workspace/trading-bot/config/api_keys.json"

# Create .env template
cat > "$ENV_FILE" << 'EOF'
# ============================================
# Geopolitical Data Sources - API Keys
# ============================================
# Fill these in after signing up at the URLs below

# 1. NewsAPI (Most Important)
# Get free key: https://newsapi.org/register
NEWSAPI_KEY=""

# 2. EIA (US Energy Data)
# Get free key: https://www.eia.gov/opendata/register.php
EIA_API_KEY=""

# 3. Alpha Vantage (Market Data)
# Get free key: https://www.alphavantage.co/support/#api-key
ALPHA_VANTAGE_KEY=""

# 4. FRED (Economic Data)
# Get free key: https://fred.stlouisfed.org/docs/api/api_key.html
FRED_API_KEY=""

# ============================================
EOF

echo "✅ Created template: $ENV_FILE"
echo ""

# Create config directory
mkdir -p "$(dirname $CONFIG_FILE)"

# Create JSON config template
cat > "$CONFIG_FILE" << 'EOF'
{
  "sources": {
    "newsapi": {
      "enabled": false,
      "key": "",
      "rate_limit": 100,
      "period": "day",
      "signup_url": "https://newsapi.org/register",
      "docs_url": "https://newsapi.org/docs"
    },
    "eia": {
      "enabled": false,
      "key": "",
      "rate_limit": 1000,
      "period": "day",
      "signup_url": "https://www.eia.gov/opendata/register.php",
      "docs_url": "https://www.eia.gov/opendata/"
    },
    "alpha_vantage": {
      "enabled": false,
      "key": "",
      "rate_limit": 25,
      "period": "day",
      "signup_url": "https://www.alphavantage.co/support/#api-key",
      "docs_url": "https://www.alphavantage.co/documentation/"
    },
    "fred": {
      "enabled": false,
      "key": "",
      "rate_limit": 120,
      "period": "minute",
      "signup_url": "https://fred.stlouisfed.org/docs/api/api_key.html",
      "docs_url": "https://fred.stlouisfed.org/docs/api/fred/"
    }
  },
  "free_no_key": {
    "reddit": {
      "enabled": true,
      "rate_limit": "30/min",
      "note": "JSON API, no key needed"
    },
    "un_comtrade": {
      "enabled": true,
      "rate_limit": "100/hour",
      "note": "Trade data API"
    }
  }
}
EOF

echo "✅ Created config: $CONFIG_FILE"
echo ""

echo "=========================================="
echo "  Signup Instructions"
echo "=========================================="
echo ""
echo "1. NEWSAPI (MOST IMPORTANT):"
echo "   URL: https://newsapi.org/register"
echo "   Email required: Yes"
echo "   Verification: Instant"
echo "   Cost: FREE (100 req/day)"
echo ""
echo "2. EIA:"
echo "   URL: https://www.eia.gov/opendata/register.php"
echo "   Email required: Yes"
echo "   Verification: Email link"
echo "   Cost: FREE"
echo ""
echo "3. Alpha Vantage:"
echo "   URL: https://www.alphavantage.co/support/#api-key"
echo "   Email required: Yes"
echo "   Verification: Instant"
echo "   Cost: FREE (25 req/day)"
echo ""
echo "4. FRED:"
echo "   URL: https://fred.stlouisfed.org/docs/api/api_key.html"
echo "   Account required: Yes"
echo "   Verification: Email"
echo "   Cost: FREE (120 req/min)"
echo ""
echo "=========================================="
echo "  After Signup - Configure:"
echo "=========================================="
echo ""
echo "Edit: $ENV_FILE"
echo "Add your keys between the quotes"
echo ""
echo "Then run:"
echo "  source $ENV_FILE"
echo "  ./test_apis.sh"
echo ""
