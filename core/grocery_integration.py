"""
GroceryApp Integration Module for ARPF-TI

This module provides functionality to integrate and monitor the GroceryApp
with the ARPF-TI security platform.
"""

import logging
import requests
from datetime import datetime
from django.conf import settings

# Import the GroceryApp configuration
from config.grocery_app_config import GROCERY_APP_CONFIG

# Set up logging
logger = logging.getLogger(__name__)

class GroceryAppMonitor:
    """Class to monitor and analyze GroceryApp activity."""
    
    def __init__(self):
        self.base_url = GROCERY_APP_CONFIG['base_url']
        self.endpoints = GROCERY_APP_CONFIG['monitored_endpoints']
        self.security_rules = GROCERY_APP_CONFIG['security_rules']
        self.request_history = {}  # Store recent requests for analysis
    
    def health_check(self):
        """Check if the GroceryApp is accessible."""
        try:
            response = requests.get(f"{self.base_url}")
            if response.status_code == 200:
                logger.info("GroceryApp is accessible")
                return True
            else:
                logger.warning(f"GroceryApp returned status code {response.status_code}")
                return False
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to connect to GroceryApp: {str(e)}")
            return False
    
    def monitor_request(self, request, response):
        """
        Monitor a request to the GroceryApp.
        
        Args:
            request: The HTTP request object
            response: The HTTP response object
        
        Returns:
            dict: Analysis results with any detected security issues
        """
        # Extract relevant information from the request
        endpoint = request.path
        method = request.method
        user_id = request.user.id if request.user.is_authenticated else None
        ip_address = self._get_client_ip(request)
        status_code = response.status_code
        
        # Record the request in history
        self._record_request(endpoint, method, user_id, ip_address, status_code)
        
        # Analyze the request for security issues
        return self._analyze_request(endpoint, method, user_id, ip_address, status_code)
    
    def _get_client_ip(self, request):
        """Extract the client IP address from a request."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
    
    def _record_request(self, endpoint, method, user_id, ip_address, status_code):
        """Record a request in the request history."""
        timestamp = datetime.now()
        
        # Initialize history structure if needed
        if ip_address not in self.request_history:
            self.request_history[ip_address] = []
        
        # Add the request to history
        self.request_history[ip_address].append({
            'endpoint': endpoint,
            'method': method,
            'user_id': user_id,
            'status_code': status_code,
            'timestamp': timestamp
        })
        
        # Clean up old history entries (older than 1 hour)
        self._clean_history(ip_address)
    
    def _clean_history(self, ip_address):
        """Remove old entries from request history."""
        now = datetime.now()
        one_hour_ago = now.timestamp() - 3600  # 1 hour in seconds
        
        if ip_address in self.request_history:
            self.request_history[ip_address] = [
                req for req in self.request_history[ip_address]
                if req['timestamp'].timestamp() > one_hour_ago
            ]
    
    def _analyze_request(self, endpoint, method, user_id, ip_address, status_code):
        """
        Analyze a request for security issues.
        
        Returns:
            dict: Analysis results with any detected issues
        """
        results = {
            'issues': [],
            'severity': 'low'
        }
        
        # Check for failed login attempts (status code 401 or 403 on login endpoint)
        if '/accounts/login/' in endpoint and status_code in [401, 403]:
            login_failures = self._count_recent_failures(ip_address, '/accounts/login/')
            
            # Get the threshold from the security rules
            login_rule = next((rule for rule in self.security_rules 
                              if rule['name'] == 'grocery_login_attempts'), None)
            
            if login_rule and login_failures >= login_rule['threshold']:
                results['issues'].append({
                    'type': 'brute_force_attempt',
                    'description': f"Possible brute force attack: {login_failures} failed login attempts",
                    'ip_address': ip_address,
                    'severity': login_rule['severity']
                })
                results['severity'] = login_rule['severity']
        
        # Check for rapid item manipulation
        if any(s in endpoint for s in ['/items/add/', '/items/edit/', '/items/delete/']):
            item_operations = self._count_recent_operations(ip_address, 
                                                          ['/items/add/', '/items/edit/', '/items/delete/'])
            
            item_rule = next((rule for rule in self.security_rules 
                            if rule['name'] == 'grocery_item_manipulation'), None)
            
            if item_rule and item_operations >= item_rule['threshold']:
                results['issues'].append({
                    'type': 'suspicious_item_manipulation',
                    'description': f"Unusual rate of item operations: {item_operations} in a short period",
                    'ip_address': ip_address,
                    'severity': item_rule['severity']
                })
                if item_rule['severity'] == 'medium' and results['severity'] == 'low':
                    results['severity'] = 'medium'
        
        # Check for admin access attempts
        if '/admin/' in endpoint and status_code in [401, 403]:
            admin_failures = self._count_recent_failures(ip_address, '/admin/')
            
            admin_rule = next((rule for rule in self.security_rules 
                              if rule['name'] == 'grocery_admin_access'), None)
            
            if admin_rule and admin_failures >= admin_rule['threshold']:
                results['issues'].append({
                    'type': 'unauthorized_admin_access',
                    'description': f"Attempted unauthorized admin access: {admin_failures} attempts",
                    'ip_address': ip_address,
                    'severity': admin_rule['severity']
                })
                results['severity'] = 'critical'  # Always highest severity
        
        return results
    
    def _count_recent_failures(self, ip_address, endpoint_pattern):
        """Count recent failed requests (401/403) to a specific endpoint pattern."""
        if ip_address not in self.request_history:
            return 0
        
        now = datetime.now()
        five_minutes_ago = now.timestamp() - 300  # 5 minutes in seconds
        
        return sum(
            1 for req in self.request_history[ip_address]
            if endpoint_pattern in req['endpoint']
            and req['status_code'] in [401, 403]
            and req['timestamp'].timestamp() > five_minutes_ago
        )
    
    def _count_recent_operations(self, ip_address, endpoint_patterns):
        """Count recent operations matching any of the provided endpoint patterns."""
        if ip_address not in self.request_history:
            return 0
        
        now = datetime.now()
        one_minute_ago = now.timestamp() - 60  # 1 minute in seconds
        
        return sum(
            1 for req in self.request_history[ip_address]
            if any(pattern in req['endpoint'] for pattern in endpoint_patterns)
            and req['timestamp'].timestamp() > one_minute_ago
        )

# Create a singleton instance
grocery_monitor = GroceryAppMonitor()

def get_grocery_monitor():
    """Get the GroceryApp monitor instance."""
    return grocery_monitor