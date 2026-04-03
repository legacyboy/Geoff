# Onboarding Analyzer - Tests

import unittest
import pandas as pd
from datetime import datetime
import sys
sys.path.insert(0, '../src')

from analyzer import OnboardingAnalyzer, FunnelStep


class TestFunnelStep(unittest.TestCase):
    
    def test_conversion_rate(self):
        step = FunnelStep(
            name="test_step",
            step_number=1,
            users_entered=100,
            users_completed=75,
            avg_time_seconds=30.0
        )
        self.assertEqual(step.conversion_rate, 0.75)
        self.assertEqual(step.dropoff_count, 25)
        self.assertEqual(step.severity_score, 6.25)  # 25 * 0.25


class TestOnboardingAnalyzer(unittest.TestCase):
    
    def setUp(self):
        self.analyzer = OnboardingAnalyzer()
    
    def test_identify_critical_dropoffs(self):
        steps = [
            FunnelStep("step1", 1, 100, 90, 10.0),   # 90% - not critical
            FunnelStep("step2", 2, 90, 50, 20.0),    # 55% - critical
            FunnelStep("step3", 3, 50, 45, 15.0),   # 90% - not critical
        ]
        
        critical = self.analyzer.identify_critical_dropoffs(steps, threshold=0.7)
        
        self.assertEqual(len(critical), 1)
        self.assertEqual(critical[0].name, "step2")


if __name__ == '__main__':
    unittest.main()
