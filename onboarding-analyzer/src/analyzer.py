"""
AI Customer Onboarding Drop-off Analyzer
MVP Implementation

Analyzes user onboarding funnels to identify friction points and generate actionable insights.
"""

import pandas as pd
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from collections import defaultdict
import openai
import os


@dataclass
class FunnelStep:
    """Represents a step in the onboarding funnel"""
    name: str
    step_number: int
    users_entered: int
    users_completed: int
    avg_time_seconds: float
    
    @property
    def conversion_rate(self) -> float:
        if self.users_entered == 0:
            return 0.0
        return self.users_completed / self.users_entered
    
    @property
    def dropoff_count(self) -> int:
        return self.users_entered - self.users_completed
    
    @property
    def severity_score(self) -> float:
        """Severity = volume × (1 - conversion rate)"""
        return self.dropoff_count * (1 - self.conversion_rate)


@dataclass
class DropoffInsight:
    """Represents an insight about a drop-off point"""
    step: FunnelStep
    hypotheses: List[Dict]
    recommendations: List[str]
    projected_impact: Optional[int] = None
    

class OnboardingAnalyzer:
    """Main analyzer class"""
    
    def __init__(self, openai_api_key: Optional[str] = None):
        self.openai_api_key = openai_api_key or os.getenv('OPENAI_API_KEY')
        if self.openai_api_key:
            self.client = openai.OpenAI(api_key=self.openai_api_key)
        else:
            self.client = None
            print("Warning: No OpenAI API key provided. Hypothesis generation disabled.")
    
    def load_csv_data(self, filepath: str) -> pd.DataFrame:
        """Load funnel data from CSV export"""
        df = pd.read_csv(filepath)
        print(f"Loaded {len(df)} records from {filepath}")
        print(f"Columns: {list(df.columns)}")
        return df
    
    def parse_funnel(self, df: pd.DataFrame, 
                     user_id_col: str = 'user_id',
                     step_col: str = 'step_name',
                     timestamp_col: str = 'timestamp',
                     step_order: Optional[List[str]] = None) -> List[FunnelStep]:
        """
        Parse raw event data into funnel steps.
        
        Args:
            df: DataFrame with user events
            user_id_col: Column name for user ID
            step_col: Column name for step/event name
            timestamp_col: Column name for timestamp
            step_order: Optional ordered list of step names
        """
        # Ensure timestamp is datetime
        df[timestamp_col] = pd.to_datetime(df[timestamp_col])
        
        # Get unique steps (ordered if provided)
        if step_order:
            steps = step_order
        else:
            steps = df[step_col].unique().tolist()
        
        funnel_steps = []
        
        for i, step_name in enumerate(steps, 1):
            step_events = df[df[step_col] == step_name]
            
            # Count unique users who entered this step
            users_entered = step_events[user_id_col].nunique()
            
            # For conversion calculation, we need to see who reached the NEXT step
            if i < len(steps):
                next_step_name = steps[i]
                next_step_events = df[df[step_col] == next_step_name]
                users_completed = next_step_events[user_id_col].nunique()
            else:
                # Final step - all who entered completed
                users_completed = users_entered
            
            # Calculate avg time on step
            avg_time = self._calculate_avg_time(df, step_name, steps, i, 
                                               user_id_col, step_col, timestamp_col)
            
            funnel_step = FunnelStep(
                name=step_name,
                step_number=i,
                users_entered=users_entered,
                users_completed=users_completed,
                avg_time_seconds=avg_time
            )
            funnel_steps.append(funnel_step)
        
        return funnel_steps
    
    def _calculate_avg_time(self, df: pd.DataFrame, current_step: str, 
                           all_steps: List[str], step_index: int,
                           user_id_col: str, step_col: str, timestamp_col: str) -> float:
        """Calculate average time spent on a step"""
        try:
            if step_index == 0:
                return 0.0
            
            current_events = df[df[step_col] == current_step]
            times = []
            
            for user_id in current_events[user_id_col].unique():
                user_events = df[df[user_id_col] == user_id].sort_values(timestamp_col)
                step_event = user_events[user_events[step_col] == current_step]
                
                if len(step_event) > 0:
                    step_time = step_event[timestamp_col].iloc[0]
                    # Time from previous step
                    prev_events = user_events[user_events[timestamp_col] < step_time]
                    if len(prev_events) > 0:
                        prev_time = prev_events[timestamp_col].iloc[-1]
                        time_diff = (step_time - prev_time).total_seconds()
                        times.append(time_diff)
            
            return sum(times) / len(times) if times else 0.0
        except Exception as e:
            print(f"Error calculating time for step {current_step}: {e}")
            return 0.0
    
    def identify_critical_dropoffs(self, funnel_steps: List[FunnelStep], 
                                   threshold: float = 0.7) -> List[FunnelStep]:
        """
        Identify steps with concerning drop-off rates.
        
        Args:
            funnel_steps: List of funnel steps
            threshold: Conversion rate threshold (steps below this are flagged)
        """
        critical = [
            step for step in funnel_steps 
            if step.conversion_rate < threshold and step.dropoff_count > 10
        ]
        return sorted(critical, key=lambda x: x.severity_score, reverse=True)
    
    def generate_hypotheses(self, step: FunnelStep, 
                          user_data: Optional[Dict] = None) -> List[Dict]:
        """
        Generate AI-powered hypotheses about why users drop off.
        
        Args:
            step: The funnel step to analyze
            user_data: Optional additional user behavior data
        """
        if not self.client:
            return [{"hypothesis": "OpenAI API key required for AI hypotheses", 
                    "confidence": "N/A"}]
        
        context = f"""
Onboarding Step Analysis:
- Step Name: {step.name}
- Step Number: {step.step_number}
- Users Entered: {step.users_entered:,}
- Users Completed: {step.users_completed:,}
- Users Dropped: {step.dropoff_count:,}
- Conversion Rate: {step.conversion_rate:.1%}
- Average Time: {step.avg_time_seconds:.0f} seconds
"""
        
        if user_data:
            context += f"""
Additional User Data:
- Top Referrers: {user_data.get('referrers', 'N/A')}
- Device Breakdown: {user_data.get('devices', 'N/A')}
- Common Actions Before Drop: {user_data.get('prev_actions', 'N/A')}
"""
        
        prompt = f"""
You are an expert product analyst specializing in user onboarding optimization.

Analyze this onboarding drop-off point and generate 3-5 hypotheses about WHY users are dropping off here.

{context}

For each hypothesis, provide:
1. A clear hypothesis statement
2. Confidence level (High/Medium/Low)
3. Supporting evidence or reasoning
4. A specific, actionable experiment to validate this hypothesis

Format as JSON:
[
  {{
    "hypothesis": "...",
    "confidence": "High/Medium/Low",
    "reasoning": "...",
    "experiment": "..."
  }}
]
"""
        
        try:
            response = self.client.chat.completions.create(
                model="gpt-4-turbo-preview",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.3,
                response_format={"type": "json_object"}
            )
            
            result = json.loads(response.choices[0].message.content)
            return result.get('hypotheses', [])
        
        except Exception as e:
            print(f"Error generating hypotheses: {e}")
            return [{"hypothesis": "Error generating AI hypotheses", "confidence": "N/A"}]
    
    def generate_report(self, funnel_steps: List[FunnelStep],
                       critical_dropoffs: List[FunnelStep]) -> str:
        """Generate a human-readable report"""
        
        report = []
        report.append("=" * 60)
        report.append("ONBOARDING HEALTH REPORT")
        report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
        report.append("=" * 60)
        report.append("")
        
        # Overall metrics
        if funnel_steps:
            total_entered = funnel_steps[0].users_entered
            total_completed = funnel_steps[-1].users_completed
            overall_conversion = total_completed / total_entered if total_entered > 0 else 0
            
            report.append(f"OVERALL ACTIVATION RATE: {overall_conversion:.1%}")
            report.append(f"Total Users Entered: {total_entered:,}")
            report.append(f"Total Users Activated: {total_completed:,}")
            report.append(f"Total Drop-offs: {total_entered - total_completed:,}")
            report.append("")
        
        # Funnel overview
        report.append("FUNNEL OVERVIEW:")
        report.append("-" * 60)
        for step in funnel_steps:
            report.append(f"Step {step.step_number}: {step.name}")
            report.append(f"  Entered: {step.users_entered:,} → Completed: {step.users_completed:,}")
            report.append(f"  Conversion: {step.conversion_rate:.1%} | Drop-offs: {step.dropoff_count:,}")
            report.append("")
        
        # Critical findings
        if critical_dropoffs:
            report.append("=" * 60)
            report.append(f"CRITICAL FINDINGS ({len(critical_dropoffs)} issues found)")
            report.append("=" * 60)
            report.append("")
            
            for i, step in enumerate(critical_dropoffs[:5], 1):
                report.append(f"{i}. STEP {step.step_number}: \"{step.name}\"")
                report.append(f"   Severity: {step.severity_score:.0f} (HIGH)" if step.severity_score > 100 else f"   Severity: {step.severity_score:.0f}")
                report.append(f"   Conversion: {step.conversion_rate:.1%}")
                report.append(f"   Users Lost: {step.dropoff_count:,}")
                report.append(f"   Avg Time: {step.avg_time_seconds:.0f}s")
                report.append("")
                
                # Projected impact
                if step.step_number < len(funnel_steps):
                    potential_recovery = int(step.dropoff_count * 0.3)  # Assume 30% recovery possible
                    report.append(f"   PROJECTED IMPACT: Fixing this step could recover ~{potential_recovery:,} users")
                report.append("")
        else:
            report.append("No critical drop-offs detected (all steps >70% conversion)")
        
        return "\n".join(report)
    
    def full_analysis(self, df: pd.DataFrame, 
                     step_order: Optional[List[str]] = None,
                     generate_ai_insights: bool = True) -> Dict:
        """
        Run complete analysis pipeline.
        
        Returns:
            Dictionary with funnel steps, critical dropoffs, and insights
        """
        print("\n" + "=" * 60)
        print("RUNNING FULL ONBOARDING ANALYSIS")
        print("=" * 60 + "\n")
        
        # Parse funnel
        funnel_steps = self.parse_funnel(df, step_order=step_order)
        print(f"✓ Parsed {len(funnel_steps)} funnel steps\n")
        
        # Identify critical dropoffs
        critical = self.identify_critical_dropoffs(funnel_steps)
        print(f"✓ Identified {len(critical)} critical drop-off points\n")
        
        # Generate insights for critical dropoffs
        insights = []
        if generate_ai_insights and self.client:
            print("Generating AI hypotheses...")
            for step in critical[:3]:  # Analyze top 3
                print(f"  Analyzing Step {step.step_number}: {step.name}...")
                hypotheses = self.generate_hypotheses(step)
                insights.append({
                    'step': step,
                    'hypotheses': hypotheses
                })
            print(f"✓ Generated hypotheses for {len(insights)} steps\n")
        
        # Generate report
        report = self.generate_report(funnel_steps, critical)
        
        return {
            'funnel_steps': funnel_steps,
            'critical_dropoffs': critical,
            'insights': insights,
            'report': report
        }


def main():
    """Example usage"""
    print("\n" + "=" * 60)
    print("AI CUSTOMER ONBOARDING DROP-OFF ANALYZER")
    print("=" * 60 + "\n")
    
    # Initialize analyzer
    analyzer = OnboardingAnalyzer()
    
    # Example: Load sample data
    # df = analyzer.load_csv_data('sample_funnel_data.csv')
    
    print("\nAnalyzer initialized!")
    print("\nExample usage:")
    print("  df = analyzer.load_csv_data('your_export.csv')")
    print("  results = analyzer.full_analysis(df)")
    print("  print(results['report'])")
    print("\n" + "=" * 60)


if __name__ == "__main__":
    main()
