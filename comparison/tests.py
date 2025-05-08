from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth.models import User
from django.utils import timezone
from datetime import timedelta

from core.models import Rule, RequestLog
from alerts.models import Alert, GeminiSuggestion
from threat_intelligence.models import SuggestedFirewallRule
from comparison.templatetags.comparison_extras import filter_by_rule_type, subtract, multiply

class ComparisonViewTests(TestCase):
    def setUp(self):
        # Create test user
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123'
        )
        self.client = Client()
        
        # Create test rules
        self.manual_rule = Rule.objects.create(
            name='Manual Test Rule',
            rule_type='ip',
            pattern='192.168.1.1',
            action='block'
        )
        
        self.ai_rule = Rule.objects.create(
            name='AI Generated Rule',
            rule_type='path',
            pattern='/admin/*',
            action='block'
        )
        
        # Create test request logs with required fields
        RequestLog.objects.create(
            source_ip='192.168.1.1',
            path='/test',
            matched_rule=self.manual_rule,
            response_code=403,
            response_time_ms=150  # Add required field
        )
        
        RequestLog.objects.create(
            source_ip='10.0.0.1',
            path='/admin',
            matched_rule=self.ai_rule,
            response_code=403,
            response_time_ms=120  # Add required field
        )
        
        # Create test alerts and suggestions
        self.alert = Alert.objects.create(
            title='Test Alert',
            description='Test Description',
            severity='high',
            status='pending'
        )
        
        self.suggestion = GeminiSuggestion.objects.create(
            alert=self.alert,
            suggestion='Test suggestion',
            confidence_score=0.85
        )

    def test_comparison_view_requires_login(self):
        """Test that the comparison view requires login"""
        response = self.client.get(reverse('comparison:index'))
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.url.startswith('/accounts/login/'))
        
        # Test with logged in user
        self.client.login(username='testuser', password='testpass123')
        response = self.client.get(reverse('comparison:index'))
        self.assertEqual(response.status_code, 200)

    def test_comparison_view_context(self):
        """Test that the comparison view returns correct context"""
        self.client.login(username='testuser', password='testpass123')
        response = self.client.get(reverse('comparison:index'))
        
        self.assertEqual(response.context['manual_rules'], 1)
        self.assertEqual(response.context['ai_rules'], 1)
        self.assertEqual(response.context['manual_rule_matches'], 1)
        self.assertEqual(response.context['ai_rule_matches'], 1)
        self.assertEqual(response.context['total_alerts'], 1)
        self.assertEqual(response.context['ai_analyzed_alerts'], 1)
        self.assertEqual(response.context['avg_ai_confidence'], 85.0)

    def test_template_filters(self):
        """Test custom template filters"""
        test_queryset = [
            {'rule_type': 'ip', 'count': 5},
            {'rule_type': 'path', 'count': 3}
        ]
        
        # Test filter_by_rule_type
        self.assertEqual(filter_by_rule_type(test_queryset, 'ip'), 5)
        self.assertEqual(filter_by_rule_type(test_queryset, 'path'), 3)
        self.assertEqual(filter_by_rule_type(test_queryset, 'unknown'), 0)
        
        # Test subtract filter
        self.assertEqual(subtract(10, 3), 7)
        self.assertEqual(subtract(5, 8), -3)
        
        # Test multiply filter
        self.assertEqual(multiply(5, 2), 10)
        self.assertEqual(multiply(None, 2), 0)

    def test_response_time_calculation(self):
        """Test response time calculation for alerts"""
        now = timezone.now()
        
        # Create resolved alerts with different timings
        manual_alert = Alert.objects.create(
            title='Manual Alert',
            status='resolved',
            created_at=now - timedelta(hours=2),
            resolved_at=now - timedelta(hours=1)
        )
        
        ai_alert = Alert.objects.create(
            title='AI Alert',
            status='resolved',
            created_at=now - timedelta(hours=2),
            resolved_at=now - timedelta(minutes=30)
        )
        GeminiSuggestion.objects.create(
            alert=ai_alert,
            suggestion='AI Suggestion',
            confidence_score=0.9
        )
        
        self.client.login(username='testuser', password='testpass123')
        response = self.client.get(reverse('comparison:index'))
        
        # Check that response times are calculated correctly
        manual_time = response.context['manual_response_time']
        ai_time = response.context['ai_response_time']
        
        self.assertIsNotNone(manual_time)
        self.assertIsNotNone(ai_time)
        self.assertTrue(ai_time < manual_time)  # AI should be faster
