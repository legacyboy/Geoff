# AI Customer Onboarding Drop-off Analyzer

## Quick Start

### 1. Install Dependencies

```bash
pip install pandas openai
```

### 2. Set OpenAI API Key (Optional but recommended)

```bash
export OPENAI_API_KEY="your-key-here"
```

### 3. Prepare Your Data

Export funnel data from Mixpanel, Amplitude, or Segment as CSV with columns:
- `user_id`: Unique user identifier
- `step_name`: Name of the onboarding step
- `timestamp`: When the event occurred

Example:
```csv
user_id,step_name,timestamp
user_123,signup_start,2026-03-29T10:00:00
user_123,email_verified,2026-03-29T10:05:00
user_123,profile_created,2026-03-29T10:10:00
user_123,integration_connected,2026-03-29T10:30:00
user_456,signup_start,2026-03-29T11:00:00
user_456,email_verified,2026-03-29T11:02:00
```

### 4. Run Analysis

```python
from src.analyzer import OnboardingAnalyzer

# Initialize
analyzer = OnboardingAnalyzer()

# Load data
df = analyzer.load_csv_data('my_funnel_export.csv')

# Run full analysis
results = analyzer.full_analysis(df)

# Print report
print(results['report'])

# Access specific data
for step in results['funnel_steps']:
    print(f"{step.name}: {step.conversion_rate:.1%} conversion")

# Critical dropoffs
for dropoff in results['critical_dropoffs']:
    print(f"Fix {dropoff.name} - {dropoff.dropoff_count:,} users lost")
```

## Example Output

```
============================================================
ONBOARDING HEALTH REPORT
Generated: 2026-03-29 14:30
============================================================

OVERALL ACTIVATION RATE: 23.4%
Total Users Entered: 10,000
Total Users Activated: 2,340
Total Drop-offs: 7,660

FUNNEL OVERVIEW:
------------------------------------------------------------
Step 1: signup_start
  Entered: 10,000 → Completed: 8,500
  Conversion: 85.0% | Drop-offs: 1,500

Step 2: email_verified
  Entered: 8,500 → Completed: 6,200
  Conversion: 72.9% | Drop-offs: 2,300

Step 3: integration_connected
  Entered: 6,200 → Completed: 2,340
  Conversion: 37.7% | Drop-offs: 3,860

============================================================
CRITICAL FINDINGS (1 issues found)
============================================================

1. STEP 3: "integration_connected"
   Severity: 2425 (HIGH)
   Conversion: 37.7%
   Users Lost: 3,860
   Avg Time: 180s

   PROJECTED IMPACT: Fixing this step could recover ~1,158 users

   HYPOTHESIS 1 (High confidence):
   Users don't understand which integration to choose
   Experiment: Add integration selector wizard

   HYPOTHESIS 2 (Medium confidence):
   OAuth flow is confusing
   Experiment: Add progress indicator and clearer instructions
```

## Configuration

### Custom Step Order

If steps aren't naturally ordered alphabetically, specify the order:

```python
step_order = [
    'landing_page',
    'signup_start', 
    'email_verified',
    'profile_created',
    'integration_connected',
    'first_project_created',
    'activated'
]

results = analyzer.full_analysis(df, step_order=step_order)
```

### Column Mapping

If your CSV uses different column names:

```python
funnel_steps = analyzer.parse_funnel(
    df,
    user_id_col='distinct_id',
    step_col='event',
    timestamp_col='time'
)
```

## Without AI (No OpenAI Key)

The analyzer works without OpenAI - it just won't generate AI hypotheses. You'll still get:
- Funnel conversion rates
- Drop-off identification
- Severity scoring
- Projected impact estimates

## Next Steps

1. ✅ Run analysis on your data
2. ✅ Identify critical drop-offs
3. ✅ Review AI hypotheses
4. → Validate hypotheses with user interviews
5. → Run experiments to fix drop-offs
6. → Re-analyze to measure improvement

## API Integration (Coming Soon)

Instead of CSV exports, connect directly to:
- Mixpanel API
- Amplitude API  
- Segment
- Google Analytics 4

## Session Replay Integration (Coming Soon)

Flag specific sessions in:
- FullStory
- LogRocket
- Hotjar

To see exactly what users did before dropping off.
