"""
Common test utility functions and configurations for ARPF-TI tests.
"""
import os
import sys
import django
from django.conf import settings

# Set up Django environment for standalone test scripts
def setup_django_test_environment():
    """Set up Django test environment for standalone test scripts."""
    # Add project root to path
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
    
    # Configure Django settings
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'arpf_ti.settings')
    django.setup()
    
    # Use in-memory SQLite database for tests
    settings.DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': ':memory:',
        }
    }
    
    # Disable logging during tests
    settings.LOGGING = {
        'version': 1,
        'disable_existing_loggers': True,
    }