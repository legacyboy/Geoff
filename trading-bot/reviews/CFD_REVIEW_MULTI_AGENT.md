# Multi-Agent CFD Trading Review

## Review Date: 2026-03-24
## Agents: deepseek-coder:33b, qwen3-coder:latest
## Subject: Oil CFD Trading Strategy

---

## EXECUTIVE SUMMARY

**Risk Level: HIGH** ⚠️

The current CFD trading strategy has significant risk management gaps that could lead to account blowup. While the code is functional, the financial logic needs substantial improvements before going live.

---

## AGENT 1: deepseek-coder:33b - CODE REVIEW

### Code Quality: C+

#### Issues Found:

1. **Critical: No Position Direction Control**
   - Only buys (long positions), never sells short
   - Missing: `side` parameter handling for short positions
   - Fix: Add short selling capability for bearish signals

2. **Medium: Volatility Window Too Small**
   - `max_history = 20` periods at 60s intervals = only 20 minutes
   - Should use at least 2-4 hours for meaningful volatility
   - Fix: Increase to 120-240 periods

3. **Medium: Missing Order Validation**
   - No check if order size exceeds account margin
   - No validation of minimum/maximum position sizes
   - Fix: Add margin calculation before order placement

4. **Low: Price History Not Persisted**
   - `price_history` is lost on restart
   - Volatility calculation starts from scratch each run
   - Fix: Save/load price history to file

5. **Low: No Rate Limit Protection**
   - Could exceed OANDA API limits
   - Fix: Add `time.sleep()` between calls, track request count

#### Code Corrections:

```python
# Fix 1: Add short selling
if price_change > 0.5 and volatility < threshold:
    signal = 'sell'  # Short on upward spike

# Fix 2: Larger volatility window
self.max_history = 120  # 2 hours of 60s data

# Fix 3: Margin check
def check_margin(self, units):
    margin_required = units * price / leverage
    return margin_required < available_margin
```

---

## AGENT 2: qwen3-coder:latest - RISK MANAGEMENT REVIEW

### Risk Assessment: D+

#### Critical Issues:

1. **Risk of Ruin: HIGH** ⚠️⚠️⚠️
   - Fixed $10 stop loss with 20:1 leverage
   - 10 units × $0.50 move = $5 loss × 20 leverage = $100 at risk
   - Just 10 consecutive losses = -$100 (could be 20%+ of account)
   - **Recommendation**: Use 1% risk per trade maximum

2. **Position Sizing Flawed**
   - Current: 30%/70%/100% of 10 units based on volatility
   - Problem: Higher volatility = smaller position, but volatility predicts larger moves
   - Should be INVERSE: Lower volatility = larger positions
   - **Recommendation**: Use ATR-based position sizing

3. **Fixed P&L Dangerous**
   - $20 take profit / $10 stop loss = 2:1 reward:risk
   - But doesn't account for spread (~$0.03-0.05 on oil)
   - On small position, spread could be 10-20% of profit target
   - **Recommendation**: Use ATR multiples for dynamic P&L

4. **60-Second Timeframe: Noise**
   - Oil moves ~0.1-0.3% per minute normally
   - 0.5% threshold = 1.5-3x normal move = chasing outliers
   - High probability of false signals
   - **Recommendation**: Use 5-minute or 15-minute timeframe

5. **Leverage Not Explicitly Controlled**
   - OANDA allows ~20:1 for oil CFDs
   - 10 units × $70 = $700 notional exposure
   - $700 / $35 margin = 20:1 leverage
   - **Recommendation**: Limit leverage to 5:1 maximum

6. **No Drawdown Circuit Breaker**
   - Continues trading during losing streaks
   - No daily/weekly loss limits
   - **Recommendation**: Stop trading after -5% daily loss

7. **Single Asset Risk**
   - No diversification
   - Oil can gap 5%+ on news
   - **Recommendation**: Add Brent (XBR_USD) for pair trading

---

## RECOMMENDED STRATEGY CHANGES

### 1. Risk Management Overhaul

```python
# Maximum risk per trade: 1% of account
account_balance = get_account_balance()
max_risk = account_balance * 0.01  # $10 on $1000 account

# Position size based on stop distance
stop_distance = current_price * 0.02  # 2% stop
position_size = max_risk / stop_distance

# Maximum leverage check
notional = position_size * current_price
if notional / account_balance > 5:  # 5:1 max leverage
    position_size = account_balance * 5 / current_price
```

### 2. Timeframe Adjustment

```python
# Change to 5-minute candles
interval = 300  # seconds

# Or implement multi-timeframe
if hourly_trend == 'up' and 5min_signal == 'buy':
    execute_long()
```

### 3. Dynamic P&L

```python
# Use ATR-based targets
atr = calculate_atr(14)  # 14-period ATR

take_profit = current_price + (atr * 2)  # 2x ATR
stop_loss = current_price - (atr * 1)   # 1x ATR

# Ensure minimum 1:1.5 risk:reward
if (take_profit - current_price) / (current_price - stop_loss) < 1.5:
    skip_trade()
```

### 4. Add Short Selling

```python
# Complete strategy with both directions
def generate_signal(price_change, volatility, trend):
    if trend == 'up':
        if price_change < -2:  # 2% dip in uptrend
            return 'buy'
    elif trend == 'down':
        if price_change > 2:   # 2% spike in downtrend
            return 'sell'
```

### 5. Circuit Breakers

```python
class RiskManager:
    def __init__(self):
        self.daily_loss = 0
        self.consecutive_losses = 0
    
    def can_trade(self):
        if self.daily_loss < -account_balance * 0.05:  # -5% day
            return False
        if self.consecutive_losses >= 3:
            return False
        return True
```

---

## IMPLEMENTATION PRIORITY

### Must Fix (Before Live Trading):
1. ✅ Change to 5-minute timeframe
2. ✅ Implement 1% risk per trade
3. ✅ Add short selling
4. ✅ Add circuit breakers
5. ✅ Limit leverage to 5:1

### Should Fix (Before Scaling):
6. Persist price history
7. Add margin checks
8. Implement ATR-based P&L
9. Add Brent for diversification

### Nice to Have:
10. Backtesting framework
11. Machine learning signal enhancement
12. News/sentiment integration

---

## CONCLUSION

**Current Strategy Status: NOT RECOMMENDED FOR LIVE TRADING**

The strategy works in paper trading but has dangerous risk characteristics:
- Risk of ruin within 50-100 trades
- Fixed P&L doesn't adapt to market conditions
- 60s timeframe is noise-dominated
- No short selling limits opportunities

**Recommendation**: Implement all "Must Fix" items before considering live deployment. Start with minimum account size ($500-1000) and strict daily loss limits.

---

## NEXT STEPS

1. Modify trader.py with risk management fixes
2. Paper trade for minimum 2 weeks with new rules
3. Analyze win rate, drawdown, risk-adjusted returns
4. Only then consider live trading with small size

**Signed**: deepseek-coder:33b & qwen3-coder:latest
**Date**: 2026-03-24
