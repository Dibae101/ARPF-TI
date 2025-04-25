"""
Test script for the Threat Intelligence module.
"""
import os
import unittest
from django.test import TestCase
from django.utils import timezone
from django.contrib.auth.models import User

# Import needed modules
from threat_intelligence.models import ThreatIntelSource, ThreatIntelEntry, AIClassifierModel
from threat_intelligence.fetcher import threat_intel_fetcher

class ThreatIntelSourceTests(TestCase):
    """Tests for ThreatIntelSource model and related functionality."""
    
    def setUp(self):
        """Set up test data."""
        # Create a test user
        self.user = User.objects.create_user(
            username='testuser',
            password='testpassword'
        )
        
        # Create a test source
        self.source = ThreatIntelSource.objects.create(
            name='Test Source',
            description='A test threat intelligence source',
            source_type='feed',
            url='https://example.com/threats.json',
            api_key='test_api_key',
            update_frequency=3600,
            is_active=True
        )
        
        # Create some test entries
        self.entry1 = ThreatIntelEntry.objects.create(
            source=self.source,
            value='192.168.1.1',
            entry_type='ip',
            confidence_score=85,
            first_seen=timezone.now(),
            last_seen=timezone.now(),
            context={'type': 'malware C2'}
        )
        
        self.entry2 = ThreatIntelEntry.objects.create(
            source=self.source,
            value='malware.example.com',
            entry_type='domain',
            confidence_score=90,
            first_seen=timezone.now(),
            last_seen=timezone.now(),
            context={'type': 'phishing'}
        )
    
    def test_source_creation(self):
        """Test that a ThreatIntelSource is created correctly."""
        self.assertEqual(self.source.name, 'Test Source')
        self.assertEqual(self.source.source_type, 'feed')
        self.assertTrue(self.source.is_active)
        
    def test_source_str_representation(self):
        """Test the string representation of a ThreatIntelSource."""
        self.assertEqual(str(self.source), 'Test Source')
        
    def test_entry_creation(self):
        """Test that a ThreatIntelEntry is created correctly."""
        self.assertEqual(self.entry1.value, '192.168.1.1')
        self.assertEqual(self.entry1.entry_type, 'ip')
        self.assertEqual(self.entry1.confidence_score, 85)
        
    def test_entry_str_representation(self):
        """Test the string representation of a ThreatIntelEntry."""
        self.assertTrue('192.168.1.1' in str(self.entry1))
        
    def test_source_entries_relationship(self):
        """Test the relationship between sources and entries."""
        entries = ThreatIntelEntry.objects.filter(source=self.source)
        self.assertEqual(entries.count(), 2)
        self.assertIn(self.entry1, entries)
        self.assertIn(self.entry2, entries)
        
    def test_entry_filtering(self):
        """Test filtering entries by type and confidence."""
        high_confidence = ThreatIntelEntry.objects.filter(confidence_score__gte=85)
        self.assertEqual(high_confidence.count(), 2)
        
        ip_entries = ThreatIntelEntry.objects.filter(entry_type='ip')
        self.assertEqual(ip_entries.count(), 1)
        self.assertEqual(ip_entries.first(), self.entry1)
        
        domain_entries = ThreatIntelEntry.objects.filter(entry_type='domain')
        self.assertEqual(domain_entries.count(), 1)
        self.assertEqual(domain_entries.first(), self.entry2)

# Manual test function to run outside of Django test runner
def run_manual_tests():
    """Run manual tests for the threat intelligence fetcher."""
    from tests import setup_django_test_environment
    setup_django_test_environment()
    
    print("=== Testing Threat Intelligence Fetcher ===")
    
    # Get all active sources
    sources = ThreatIntelSource.objects.filter(is_active=True)
    print(f"Found {sources.count()} active sources")
    
    for source in sources:
        print(f"\nTesting source: {source.name} ({source.source_type})")
        
        # Test the fetcher with a single source
        try:
            threat_intel_fetcher.fetch_source_data(source.id)
            print(f"✓ Successfully fetched data from {source.name}")
            
            # Count entries from this source
            entry_count = ThreatIntelEntry.objects.filter(source=source).count()
            print(f"✓ Source has {entry_count} entries in the database")
            
        except Exception as e:
            print(f"✗ Error fetching data: {str(e)}")

if __name__ == '__main__':
    # Run Django tests if called directly
    if os.environ.get('RUN_MANUAL_TESTS') == '1':
        run_manual_tests()
    else:
        # Run the Django tests
        unittest.main()