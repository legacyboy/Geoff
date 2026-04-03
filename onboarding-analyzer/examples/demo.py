#!/usr/bin/env python3
"""
Demo script for Onboarding Analyzer
Shows basic usage without requiring API keys
"""

import sys
sys.path.insert(0, '..')

from src.analyzer import OnboardingAnalyzer

def main():
    print("=" * 60)
    print("ONBOARDING ANALYZER DEMO")
    print("=" * 60)
    
    # Initialize analyzer (no API key needed for basic analysis)
    analyzer = OnboardingAnalyzer()
    
    # Load sample data
    print("\n[1/4] Loading sample data...")
    df = analyzer.load_csv_data('sample_funnel_data.csv')
    
    # Run analysis
    print("\n[2/4] Analyzing funnel...")
    results = analyzer.full_analysis(
        df, 
        step_order=[
            'landing_page',
            'signup_start',
            'email_verified', 
            'profile_created',
            'integration_connected',
            'first_project_created'
        ],
        generate_ai_insights=False  # Skip AI for demo (no API key needed)
    )
    
    # Print report
    print("\n[3/4] Generating report...")
    print("\n" + results['report'])
    
    # Summary
    print("\n[4/4] Summary:")
    print("-" * 60)
    print(f"Total steps analyzed: {len(results['funnel_steps'])}")
    print(f"Critical drop-offs found: {len(results['critical_dropoffs'])}")
    
    if results['critical_dropoffs']:
        print("\nPriority fixes:")
        for i, dropoff in enumerate(results['critical_dropoffs'][:3], 1):
            recovery = int(dropoff.dropoff_count * 0.3)
            print(f"  {i}. {dropoff.name}: {dropoff.conversion_rate:.1%} conversion → {recovery:,} users recoverable")
    
    print("\n" + "=" * 60)
    print("Demo complete!")
    print("=" * 60)
    print("\nNext steps:")
    print("  1. Get your own Mixpanel/Amplitude export")
    print("  2. Set OPENAI_API_KEY for AI hypotheses")
    print("  3. Run: python demo.py")

if __name__ == "__main__":
    main()
