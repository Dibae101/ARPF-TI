"""
Test script for rules functionality in ARPF-TI.
"""
import os
import re
import unittest
import json
from django.test import TestCase, RequestFactory
from django.http import HttpResponse, JsonResponse
from django.contrib.auth.models import User

# Import needed modules
from core.models import Rule
from core.middleware import RequestLoggerMiddleware

class RuleTests(TestCase):
    """Tests for Rule model and related functionality."""
    
    def setUp(self):
        """Set up test data."""
        # Create a test user
        self.user = User.objects.create_user(
            username='testuser',
            password='testpassword'
        )
        
        # Create test rules
        self.ip_rule = Rule.objects.create(
            name='Block Suspicious IP',
            rule_type='ip',
            pattern=r'^192\.168\.1\.\d+$',
            action='block',
            priority=10,
            is_active=True,
            description='Block all IPs in the 192.168.1.0/24 subnet'
        )
        
        self.path_rule = Rule.objects.create(
            name='Block Admin Paths',
            rule_type='path',
            pattern=r'^/admin/.*$',
            action='block',
            priority=5,
            is_active=True,
            description='Block access to admin paths'
        )
        
        self.user_agent_rule = Rule.objects.create(
            name='Alert on Suspicious User Agents',
            rule_type='user_agent',
            pattern=r'sqlmap|nikto|nmap|dirbuster',
            action='alert',
            priority=15,
            is_active=True,
            description='Alert on known scanner user agents'
        )
        
        self.inactive_rule = Rule.objects.create(
            name='Inactive Rule',
            rule_type='method',
            pattern=r'^(PUT|DELETE)$',
            action='block',
            priority=20,
            is_active=False,
            description='Block PUT and DELETE methods (inactive)'
        )
        
        # Create request factory for testing middleware
        self.factory = RequestFactory()
        
        # Create middleware instance
        self.middleware = RequestLoggerMiddleware(get_response=lambda r: HttpResponse("OK"))
    
    def test_rule_creation(self):
        """Test that rules are created correctly."""
        self.assertEqual(self.ip_rule.name, 'Block Suspicious IP')
        self.assertEqual(self.ip_rule.rule_type, 'ip')
        self.assertEqual(self.ip_rule.pattern, r'^192\.168\.1\.\d+$')
        self.assertEqual(self.ip_rule.action, 'block')
        self.assertTrue(self.ip_rule.is_active)
        
    def test_rule_str_representation(self):
        """Test the string representation of a Rule."""
        self.assertTrue('Block Suspicious IP' in str(self.ip_rule))
        self.assertTrue('block' in str(self.ip_rule))
        
    def test_active_rules_filter(self):
        """Test filtering for active rules."""
        active_rules = Rule.objects.filter(is_active=True)
        self.assertEqual(active_rules.count(), 3)
        self.assertIn(self.ip_rule, active_rules)
        self.assertIn(self.path_rule, active_rules)
        self.assertIn(self.user_agent_rule, active_rules)
        self.assertNotIn(self.inactive_rule, active_rules)
        
    def test_rule_priority_ordering(self):
        """Test that rules are ordered by priority."""
        rules = Rule.objects.filter(is_active=True).order_by('priority')
        self.assertEqual(rules[0], self.path_rule)  # Priority 5
        self.assertEqual(rules[1], self.ip_rule)    # Priority 10
        self.assertEqual(rules[2], self.user_agent_rule)  # Priority 15
        
    def test_rule_pattern_matching(self):
        """Test rule pattern matching against test data."""
        # IP pattern matching
        self.assertTrue(re.match(self.ip_rule.pattern, '192.168.1.1'))
        self.assertFalse(re.match(self.ip_rule.pattern, '10.0.0.1'))
        
        # Path pattern matching
        self.assertTrue(re.match(self.path_rule.pattern, '/admin/login'))
        self.assertFalse(re.match(self.path_rule.pattern, '/about'))
        
        # User agent pattern matching
        self.assertTrue(re.match(self.user_agent_rule.pattern, 'Mozilla/5.0 sqlmap/1.0'))
        self.assertFalse(re.match(self.user_agent_rule.pattern, 'Mozilla/5.0 Chrome/90.0'))
        
    def test_middleware_rule_loading(self):
        """Test that the middleware loads rules correctly."""
        self.middleware._load_rules()
        self.assertEqual(len(self.middleware.active_rules), 3)
        
    def test_middleware_ip_rule_matching(self):
        """Test that the middleware correctly matches IP rules."""
        request = self.factory.get('/')
        request.META['REMOTE_ADDR'] = '192.168.1.5'
        
        self.middleware._load_rules()
        matched_rule = self.middleware._evaluate_rules(request, '192.168.1.5')
        
        self.assertIsNotNone(matched_rule)
        self.assertEqual(matched_rule.rule_type, 'ip')
        self.assertEqual(matched_rule.action, 'block')
        
    def test_middleware_path_rule_matching(self):
        """Test that the middleware correctly matches path rules."""
        request = self.factory.get('/admin/settings')
        request.META['REMOTE_ADDR'] = '10.0.0.1'  # Non-matching IP
        
        self.middleware._load_rules()
        matched_rule = self.middleware._evaluate_rules(request, '10.0.0.1')
        
        self.assertIsNotNone(matched_rule)
        self.assertEqual(matched_rule.rule_type, 'path')
        self.assertEqual(matched_rule.action, 'block')
        
    def test_middleware_user_agent_rule_matching(self):
        """Test that the middleware correctly matches user agent rules."""
        request = self.factory.get('/')
        request.META['REMOTE_ADDR'] = '10.0.0.1'  # Non-matching IP
        request.META['HTTP_USER_AGENT'] = 'Mozilla/5.0 (compatible; nmap)'
        
        self.middleware._load_rules()
        matched_rule = self.middleware._evaluate_rules(request, '10.0.0.1')
        
        self.assertIsNotNone(matched_rule)
        self.assertEqual(matched_rule.rule_type, 'user_agent')
        self.assertEqual(matched_rule.action, 'alert')
        
    def test_middleware_no_rule_matching(self):
        """Test the case where no rules match."""
        request = self.factory.get('/about')
        request.META['REMOTE_ADDR'] = '10.0.0.1'  # Non-matching IP
        request.META['HTTP_USER_AGENT'] = 'Mozilla/5.0 Chrome/90.0'  # Non-matching UA
        
        self.middleware._load_rules()
        matched_rule = self.middleware._evaluate_rules(request, '10.0.0.1')
        
        self.assertIsNone(matched_rule)
        
    def test_middleware_localhost_self_protection(self):
        """Test that the middleware doesn't block localhost (self-protection)."""
        # Create a rule that would normally block localhost
        localhost_rule = Rule.objects.create(
            name='Block Localhost',
            rule_type='ip',
            pattern=r'^127\.0\.0\.1$',
            action='block',
            priority=1,  # Highest priority
            is_active=True,
            description='This rule would block localhost if not for self-protection'
        )
        
        request = self.factory.get('/')
        request.META['REMOTE_ADDR'] = '127.0.0.1'
        
        self.middleware._load_rules()
        matched_rule = self.middleware._evaluate_rules(request, '127.0.0.1')
        
        # The middleware should modify the rule action to 'allow' to protect self-access
        self.assertIsNotNone(matched_rule)
        self.assertEqual(matched_rule.action, 'allow')
        self.assertNotEqual(matched_rule.id, localhost_rule.id)  # Should be a modified copy
        
        # Clean up
        localhost_rule.delete()
        
    def test_middleware_block_response(self):
        """Test that the middleware returns the correct response for blocked requests."""
        block_response = self.middleware._create_block_response(self.ip_rule)
        
        self.assertIsInstance(block_response, JsonResponse)
        self.assertEqual(block_response.status_code, 403)
        
        # Check response content
        content = json.loads(block_response.content)
        self.assertIn('error', content)
        self.assertIn('message', content)

# Manual test function to run outside of Django test runner
def run_manual_tests():
    """Run manual tests for rules against real HTTP requests."""
    from tests import setup_django_test_environment
    setup_django_test_environment()
    
    print("=== Testing Rules Against Sample Requests ===")
    
    # Get all active rules
    rules = Rule.objects.filter(is_active=True).order_by('priority')
    print(f"Found {rules.count()} active rules")
    
    # Define some sample requests
    sample_requests = [
        {
            'path': '/',
            'method': 'GET',
            'ip': '192.168.1.100',
            'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/90.0'
        },
        {
            'path': '/admin/login',
            'method': 'GET',
            'ip': '10.0.0.1',
            'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/90.0'
        },
        {
            'path': '/api/data',
            'method': 'GET',
            'ip': '8.8.8.8',
            'user_agent': 'sqlmap/1.5 (https://sqlmap.org)'
        }
    ]
    
    # Create middleware instance
    middleware = RequestLoggerMiddleware(get_response=lambda r: HttpResponse("OK"))
    middleware._load_rules()
    
    # Create request factory
    factory = RequestFactory()
    
    # Test each sample request
    for i, req_data in enumerate(sample_requests):
        print(f"\nTesting request #{i+1}: {req_data['method']} {req_data['path']} from {req_data['ip']}")
        
        # Create request object
        request = factory.get(req_data['path'])
        request.META['REMOTE_ADDR'] = req_data['ip']
        request.META['HTTP_USER_AGENT'] = req_data['user_agent']
        
        # Evaluate rules
        matched_rule = middleware._evaluate_rules(request, req_data['ip'])
        
        if matched_rule:
            print(f"✓ Rule matched: {matched_rule.name} (type: {matched_rule.rule_type}, action: {matched_rule.action})")
            
            if matched_rule.action == 'block':
                print(f"✓ Request would be blocked")
                response = middleware._create_block_response(matched_rule)
                print(f"✓ Response code: {response.status_code}")
            else:
                print(f"✓ Request would be allowed, but logged with action: {matched_rule.action}")
        else:
            print(f"✓ No rules matched, request would be allowed")

if __name__ == '__main__':
    # Run Django tests if called directly
    if os.environ.get('RUN_MANUAL_TESTS') == '1':
        run_manual_tests()
    else:
        # Run the Django tests
        unittest.main()