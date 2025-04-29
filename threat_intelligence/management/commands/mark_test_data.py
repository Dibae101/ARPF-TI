from django.core.management.base import BaseCommand
from threat_intelligence.models import ThreatIntelEntry, ThreatIntelSource
import re
import ipaddress

class Command(BaseCommand):
    help = 'Identifies and marks test/dummy data in threat intelligence entries'

    def add_arguments(self, parser):
        parser.add_argument(
            '--mark-only',
            action='store_true',
            help='Only mark test data without deleting'
        )
        parser.add_argument(
            '--delete',
            action='store_true',
            help='Delete identified test data instead of marking'
        )

    def handle(self, *args, **options):
        mark_only = options['mark_only']
        delete = options['delete']

        # Counter for statistics
        stats = {
            'total': 0,
            'identified_test': 0,
            'marked': 0,
            'deleted': 0
        }

        # Get all entries
        entries = ThreatIntelEntry.objects.all()
        stats['total'] = entries.count()
        self.stdout.write(f"Examining {stats['total']} threat intelligence entries...")

        # List of test data patterns
        test_patterns = [
            r'^test',
            r'dummy',
            r'example\.',
            r'sample',
            r'placeholder',
            r'^192\.0\.2\.',  # TEST-NET-1
            r'^198\.51\.100\.', # TEST-NET-2
            r'^203\.0\.113\.', # TEST-NET-3
            r'\.example\.com',
            r'\.test$',
            r'example\.org',
            r'example\.net',
            r'0\.0\.0\.0',
            r'255\.255\.255\.255',
        ]

        # List of test source names
        test_source_names = [
            'test', 
            'demo', 
            'sample', 
            'example',
            'development',
        ]

        # Find test sources
        test_sources = ThreatIntelSource.objects.filter(
            name__iregex=r'(' + '|'.join(test_source_names) + ')'
        )
        
        for entry in entries:
            is_test = False
            
            # Check if from a test source
            if test_sources.filter(id=entry.source.id).exists():
                is_test = True
                self.stdout.write(f"  Marked as test: {entry} (from test source)")
            
            # Check value against test patterns
            if not is_test:
                for pattern in test_patterns:
                    if re.search(pattern, entry.value, re.IGNORECASE):
                        is_test = True
                        self.stdout.write(f"  Marked as test: {entry} (matches pattern)")
                        break
            
            # Check if metadata contains test indicators
            if not is_test and entry.metadata:
                metadata_str = str(entry.metadata).lower()
                for term in ['test', 'dummy', 'sample', 'example']:
                    if term in metadata_str:
                        is_test = True
                        self.stdout.write(f"  Marked as test: {entry} (metadata contains test term)")
                        break
            
            # Check if created for testing
            if not is_test and entry.category:
                if any(test_term in entry.category.lower() for test_term in ['test', 'demo', 'sample', 'example']):
                    is_test = True
                    self.stdout.write(f"  Marked as test: {entry} (category indicates test data)")
            
            # If identified as test data
            if is_test:
                stats['identified_test'] += 1
                
                if delete:
                    entry.delete()
                    stats['deleted'] += 1
                else:
                    entry.is_test_data = True
                    entry.save()
                    stats['marked'] += 1

        # Print summary
        self.stdout.write(self.style.SUCCESS(
            f"Processed {stats['total']} entries: "
            f"{stats['identified_test']} identified as test data, "
            f"{stats['marked']} marked, "
            f"{stats['deleted']} deleted."
        ))