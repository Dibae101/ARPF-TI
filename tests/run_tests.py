#!/usr/bin/env python
"""
Main test runner for ARPF-TI tests.
This script allows running all tests or specific test categories.
"""
import os
import sys
import unittest
import argparse

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.dirname(os.path.dirname(__file__))))

# Import and run test setup function immediately
from tests import setup_django_test_environment
setup_django_test_environment()

# Now import test modules (after Django is configured)
from tests.threat_intelligence.test_threat_intel import ThreatIntelSourceTests, run_manual_tests as run_ti_manual_tests
from tests.ai_models.test_ai_models import AIModelTests, AIModelUploadTests, run_manual_tests as run_ai_manual_tests
from tests.rules.test_rules import RuleTests, run_manual_tests as run_rules_manual_tests

def main():
    """Main entry point for the test runner."""
    parser = argparse.ArgumentParser(description='Run ARPF-TI tests')
    parser.add_argument('--category', choices=['all', 'ti', 'ai', 'rules'], default='all',
                      help='Test category to run (default: all)')
    parser.add_argument('--manual', action='store_true',
                      help='Run manual tests instead of unit tests')
    
    args = parser.parse_args()
    
    if args.manual:
        # Run manual tests
        print("Running manual tests...")
        
        if args.category in ['all', 'ti']:
            print("\n=== THREAT INTELLIGENCE MANUAL TESTS ===")
            run_ti_manual_tests()
        
        if args.category in ['all', 'ai']:
            print("\n=== AI MODELS MANUAL TESTS ===")
            run_ai_manual_tests()
        
        if args.category in ['all', 'rules']:
            print("\n=== RULES MANUAL TESTS ===")
            run_rules_manual_tests()
    else:
        # Configure test suite
        loader = unittest.TestLoader()
        suite = unittest.TestSuite()
        
        # Add test cases based on category
        if args.category in ['all', 'ti']:
            suite.addTest(loader.loadTestsFromTestCase(ThreatIntelSourceTests))
        
        if args.category in ['all', 'ai']:
            suite.addTest(loader.loadTestsFromTestCase(AIModelTests))
            suite.addTest(loader.loadTestsFromTestCase(AIModelUploadTests))
        
        if args.category in ['all', 'rules']:
            suite.addTest(loader.loadTestsFromTestCase(RuleTests))
        
        # Run the tests
        runner = unittest.TextTestRunner(verbosity=2)
        result = runner.run(suite)
        
        # Exit with error code if tests failed
        if not result.wasSuccessful():
            sys.exit(1)

if __name__ == '__main__':
    main()