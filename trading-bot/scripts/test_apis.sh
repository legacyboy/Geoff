#!/bin/bash
# Test API connections

echo "=========================================="
echo "  Testing API Connections"
echo "=========================================="
echo ""

# Load environment
if [ -f "/home/claw/.openclaw/workspace/trading-bot/.env" ]; then
    source /home/claw/.openclaw/workspace/trading-bot/.env
    echo "✅ Loaded environment"
else
    echo "❌ No .env file found"
    echo "   Run: ./setup_data_sources.sh"
    exit 1
fi

echo ""

# Test NewsAPI
if [ -n "$NEWSAPI_KEY" ]; then
    echo "Testing NewsAPI..."
    RESPONSE=$(curl -s "https://newsapi.org/v2/everything?q=oil&pageSize=1&apiKey=$NEWSAPI_KEY")
    if echo "$RESPONSE" | grep -q '"status":"ok"'; then
        echo "  ✅ NewsAPI: Connected"
        echo "$RESPONSE" | grep -o '"totalResults":[0-9]*'
    else
        echo "  ❌ NewsAPI: Failed"
        echo "$RESPONSE" | head -1
    fi
else
    echo "⏭️  NewsAPI: No key set"
fi

echo ""

# Test EIA
if [ -n "$EIA_API_KEY" ]; then
    echo "Testing EIA API..."
    RESPONSE=$(curl -s "https://api.eia.gov/v2/petroleum/pri/spt/data?api_key=$EIA_API_KEY&length=1")
    if echo "$RESPONSE" | grep -q '"response"'; then
        echo "  ✅ EIA: Connected"
    else
        echo "  ❌ EIA: Failed"
    fi
else
    echo "⏭️  EIA: No key set"
fi

echo ""

# Test Alpha Vantage
if [ -n "$ALPHA_VANTAGE_KEY" ]; then
    echo "Testing Alpha Vantage..."
    RESPONSE=$(curl -s "https://www.alphavantage.co/query?function=GLOBAL_QUOTE&symbol=OIL&apikey=$ALPHA_VANTAGE_KEY")
    if echo "$RESPONSE" | grep -q '"Global Quote"'; then
        echo "  ✅ Alpha Vantage: Connected"
    else
        echo "  ❌ Alpha Vantage: Failed"
    fi
else
    echo "⏭️  Alpha Vantage: No key set"
fi

echo ""

# Test FRED
if [ -n "$FRED_API_KEY" ]; then
    echo "Testing FRED..."
    RESPONSE=$(curl -s "https://api.stlouisfed.org/fred/series/observations?series_id=DCOILWTICO&api_key=$FRED_API_KEY&file_type=json&limit=1")
    if echo "$RESPONSE" | grep -q '"observations"'; then
        echo "  ✅ FRED: Connected"
    else
        echo "  ❌ FRED: Failed"
    fi
else
    echo "⏭️  FRED: No key set"
fi

echo ""
echo "=========================================="
echo "  Test Complete"
echo "=========================================="
