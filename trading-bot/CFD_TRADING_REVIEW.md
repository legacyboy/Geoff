# CFD Trading Logic Review

## Current Trading Bot Logic Summary

### Assets Traded
- **XTI_USD**: WTI Crude Oil CFD
- **XBR_USD**: Brent Crude Oil CFD (config only, not implemented in trader yet)

### Strategy Overview
**Timeframe**: 60-second intervals
**Strategy Type**: Momentum-based mean reversion with volatility adjustment
**Risk Management**: Position sizing based on volatility

### Current Logic Flow

#### 1. Price Collection
```python
- Fetch current bid/ask from OANDA
- Store in rolling 20-period price history
- Calculate volatility as std_dev / avg_price * 100
```

#### 2. Volatility Calculation
```python
volatility_threshold = 2.0% (config)

if volatility > 4.0%:  # 2x threshold
    position_multiplier = 0.3  # 30% size
elif volatility > 2.0%:  # threshold
    position_multiplier = 0.7  # 70% size
else:
    position_multiplier = 1.0  # 100% size
```

#### 3. Entry Signals (Momentum Strategy)
```python
# Calculate 1-minute price change
price_change = ((current - previous) / previous) * 100

# Entry conditions
if price_change < -0.5% AND volatility < 3.0%:
    signal = BUY (dip buying)
    reason = 'dip_buy'

elif price_change > 0.5% AND volatility < 3.0%:
    signal = BUY (trend following)
    reason = 'momentum'

else:
    signal = HOLD
```

#### 4. Exit Signals
```python
if position_open:
    unrealized_pnl = current_pnl
    
    if unrealized_pnl > +$20:  # Take profit
        signal = CLOSE
    
    elif unrealized_pnl < -$10:  # Stop loss
        signal = CLOSE
    
    else:
        signal = HOLD
```

#### 5. Order Execution (Paper Trading)
```python
if paper_trading:
    # Simulate order
    save to data/paper_trades/
    log timestamp, price, units, side
else:
    # Real OANDA order
    POST /v3/accounts/{account_id}/orders
    {
        "order": {
            "type": "MARKET",
            "instrument": "XTI_USD",
            "units": str(units),  # positive=buy, negative=sell
            "timeInForce": "FOK",
            "positionFill": "DEFAULT"
        }
    }
```

### Risk Management Current State

| Aspect | Current Implementation |
|--------|----------------------|
| Position Sizing | Volatility-based (30%/70%/100%) |
| Stop Loss | Fixed $10 loss per trade |
| Take Profit | Fixed $20 gain per trade |
| Max Position | Base units * multiplier |
| Leverage | Not explicitly controlled (OANDA default) |
| Drawdown Protection | None |
| Correlation Risk | None (single asset) |

### CFD-Specific Considerations

#### Current Gaps:
1. **Leverage**: No explicit leverage control (OANDA CFDs typically 20:1 for oil)
2. **Margin Requirements**: Not calculated
3. **Overnight Fees**: Not considered (holding costs)
4. **Spread Costs**: Not factored into P&L calculations
5. **Rollover**: Not handled for multi-day positions
6. **Guaranteed Stop Loss**: Not implemented (GSL available on OANDA)

### Issues Identified

#### Critical
1. **No Risk of Ruin Protection**: Can lose entire account with consecutive losses
2. **Fixed $10/$20 P&L**: No adjustment for position size or volatility
3. **Only Long Positions**: No short selling capability
4. **Single Asset**: No diversification
5. **No Leverage Control**: 20:1 leverage with 30% position still = 6:1 effective

#### Medium
1. **1-Minute Noise**: 60s timeframe has high noise-to-signal ratio
2. **No Trend Filter**: Trading against trend without confirmation
3. **Volatility Calculation**: Simple std dev may not capture regime changes
4. **No Backtesting**: Strategy not validated on historical data

#### Low
1. **No Position Scaling**: All-in entry, no pyramiding
2. **No Correlation Check**: Brent/WTI spread not used
3. **No News Filter**: Trump factor not integrated into trading
4. **Logging Only**: No real-time alerting

### Questions for Agent Review

1. **Is 60-second trading viable for CFDs?**
   - Spread costs vs. profit targets
   - Slippage on market orders
   - API rate limits

2. **Risk Management Adequacy**
   - Is $10/$20 fixed P&L appropriate?
   - Should it be percentage-based?
   - Need trailing stops?

3. **Position Sizing Logic**
   - Is volatility-based sizing correct?
   - Should incorporate Kelly Criterion?
   - Account for current drawdown?

4. **Strategy Edge**
   - Is momentum on 1m timeframe profitable?
   - Better to use mean reversion?
   - Need ML-based prediction?

5. **CFD Best Practices**
   - How to handle leverage responsibly?
   - Overnight position rules?
   - Margin call prevention?

### Code Files
- `/trading-bot/bot/trader.py` - Main trading logic
- `/trading-bot/config/config.json` - Trading parameters

### Configuration Parameters
```json
{
  "trading_interval_seconds": 60,
  "trading_assets": ["XTI_USD", "XBR_USD"],
  "default_units": 10,
  "volatility_threshold": 2.0,
  "paper_trading": true,
  "risk_level": "high"
}
```

## Review Tasks

Please review and provide feedback on:
1. Strategy viability for CFD trading
2. Risk management adequacy
3. Position sizing methodology
4. Entry/exit logic improvements
5. CFD-specific risk controls needed
