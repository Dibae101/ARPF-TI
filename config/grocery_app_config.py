"""
GroceryApp Integration Configuration for ARPF-TI

This file defines the endpoints from GroceryApp that will be monitored by ARPF-TI
"""

GROCERY_APP_CONFIG = {
    # Base URL of the GroceryApp (adjust this to match your deployment)
    'base_url': 'http://localhost:8000',
    
    # Endpoints to monitor
    'monitored_endpoints': [
        # Authentication endpoints
        '/accounts/login/',
        '/accounts/logout/',
        '/accounts/register/',
        
        # Item endpoints
        '/items/',
        '/items/add/',
        '/items/edit/<int:id>/',
        '/items/delete/<int:id>/',
        
        # Basket endpoints
        '/basket/',
        '/basket/add/<int:item_id>/',
        '/basket/remove/<int:item_id>/',
        
        # Group endpoints
        '/groups/',
        '/groups/create/',
        '/groups/<int:group_id>/',
        '/groups/join/<int:group_id>/',
        '/groups/leave/<int:group_id>/',
    ],
    
    # Security rules specific to GroceryApp
    'security_rules': [
        {
            'name': 'grocery_login_attempts',
            'description': 'Detect brute force login attempts on GroceryApp',
            'threshold': 5,  # Number of failed attempts
            'time_window': 300,  # In seconds (5 minutes)
            'severity': 'high'
        },
        {
            'name': 'grocery_item_manipulation',
            'description': 'Detect suspicious item manipulation',
            'threshold': 10,
            'time_window': 60,
            'severity': 'medium'
        },
        {
            'name': 'grocery_admin_access',
            'description': 'Unauthorized admin access attempts',
            'threshold': 2,
            'time_window': 600,
            'severity': 'critical'
        }
    ]
}