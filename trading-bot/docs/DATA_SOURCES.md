# Free Geopolitical Data Sources Configuration

## ✅ Ready to Use (No Signup Required)

### 1. Reddit JSON API
- **Cost**: FREE
- **Limit**: 30 requests/minute
- **Data**: Real-time discussions
- **Status**: ✅ Already configured

### 2. EIA (US Energy Information)
- **Cost**: FREE
- **API Key**: Required but instant
- **Data**: US oil production, inventories, prices
- **Signup**: https://www.eia.gov/opendata/register.php

### 3. UN Comtrade (Trade Data)
- **Cost**: FREE
- **Data**: Global oil imports/exports
- **API**: https://comtrade.un.org/api/

### 4. World Bank Open Data
- **Cost**: FREE
- **Data**: Energy statistics, GDP, sanctions
- **API**: https://data.worldbank.org/indicator

## 🔑 Requires API Key (Free Tier)

### 5. NewsAPI.org ⭐ PRIORITY
- **Cost**: FREE (100 requests/day)
- **Data**: News from 30,000+ sources
- **Signup**: https://newsapi.org/register
- **Key Format**: 32-character hex string

### 6. GDELT Project
- **Cost**: FREE (BigQuery credits required)
- **Data**: Global events, conflicts, protests
- **Access**: https://www.gdeltproject.org/

### 7. ACLED (Conflict Data)
- **Cost**: FREE for non-commercial
- **Data**: Armed conflict locations
- **Signup**: https://acleddata.com/

### 8. OpenCorporates
- **Cost**: FREE tier (200 requests/day)
- **Data**: Oil company structures, sanctions
- **Key**: Required

## 📊 Financial/Economic Data

### 9. Alpha Vantage
- **Cost**: FREE (25 requests/day)
- **Data**: Oil stock prices, commodity data
- **Key**: https://www.alphavantage.co/support/#api-key

### 10. Quandl (Now Nasdaq Data Link)
- **Cost**: FREE tier available
- **Data**: Oil futures, historical prices
- **Key**: Required

### 11. FRED (Federal Reserve)
- **Cost**: FREE
- **Data**: Economic indicators, oil prices
- **Key**: https://fred.stlouisfed.org/docs/api/api_key.html

## 🌐 RSS Feeds (Free but unstable)

### Working RSS Sources:
- Reuters Energy: ❌ Cloudflare blocked
- BBC Business: ❌ Cloudflare blocked
- Oilprice.com: ✅ Works (limited)
- OPEC Monthly Report: ❌ PDF only

## 📋 Configuration Summary

### Priority Setup Order:

1. **NewsAPI** (Most valuable)
   ```bash
   # Get key at: https://newsapi.org/register
   export NEWSAPI_KEY="your_key_here"
   ```

2. **EIA** (US energy data)
   ```bash
   # Get key at: https://www.eia.gov/opendata/register.php
   export EIA_API_KEY="your_key_here"
   ```

3. **Alpha Vantage** (Market data)
   ```bash
   # Get key at: https://www.alphavantage.co/support/#api-key
   export ALPHA_VANTAGE_KEY="your_key_here"
   ```

4. **FRED** (Economic data)
   ```bash
   # Get key at: https://fred.stlouisfed.org/docs/api/api_key.html
   export FRED_API_KEY="your_key_here"
   ```

## 🔧 Implementation Status

| Source | Status | Code Ready |
|--------|--------|------------|
| Reddit | ✅ Working | Yes |
| EIA | ⏳ Needs Key | Yes |
| NewsAPI | ⏳ Needs Key | Yes |
| Alpha Vantage | ⏳ Needs Key | Yes |
| FRED | ⏳ Needs Key | Yes |
| GDELT | ⏳ Complex | Partial |

## 📊 Expected Data Coverage With All Sources

| Category | Sources | Coverage |
|----------|---------|----------|
| Trump News | NewsAPI + Reddit | 90% |
| OPEC Data | EIA + RSS | 70% |
| Conflicts | GDELT + ACLED | 85% |
| Sanctions | NewsAPI + Reddit | 80% |
| Prices | Alpha Vantage + FRED | 95% |
| Trade Data | UN Comtrade | 60% |

## ⚡ Quick Start Commands

```bash
# Create environment file
cat > ~/.openclaw/workspace/trading-bot/.env << 'EOF'
# Free API Keys - Get these from signup URLs above
NEWSAPI_KEY=""
EIA_API_KEY=""
ALPHA_VANTAGE_KEY=""
FRED_API_KEY=""
EOF

# Load environment
export $(cat .env | xargs)

# Test NewsAPI
curl "https://newsapi.org/v2/everything?q=trump+oil&apiKey=$NEWSAPI_KEY"
```

## 📝 Notes

- All sources above are **free tier available**
- Reddit works without any keys
- Most APIs reset daily at midnight UTC
- Rate limits apply - don't abuse services
- Some require attribution (I'll handle in code)

**Next Step**: Get NewsAPI key first - it's the most valuable single source.
