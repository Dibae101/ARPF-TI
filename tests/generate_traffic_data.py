#!/usr/bin/env python
import os
import sys
import django
import random
from datetime import timedelta

# Add the project root to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'arpf_ti.settings')
django.setup()

from django.utils import timezone
from core.models import RequestLog, Rule
from django.contrib.auth.models import User

def generate_traffic_data(num_entries=200):
    """
    Generate realistic traffic data entries over the past 24 hours
    """
    print(f"Generating {num_entries} traffic data entries...")
    
    # Sample data
    methods = ['GET', 'POST', 'PUT', 'DELETE']
    paths = ['/api/users', '/admin/login', '/dashboard', '/api/products', '/api/orders', '/contact', '/login', '/register']
    ips = [f'192.168.1.{i}' for i in range(1, 20)]
    ips.extend([f'10.0.0.{i}' for i in range(1, 10)])
    ips.extend([f'203.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}' for _ in range(10)])
    
    user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36',
    ]
    
    countries = ['US', 'DE', 'GB', 'CN', 'RU', 'JP', 'FR', 'BR', 'IN', 'CA']
    actions = ['allow', 'block', 'log']
    
    # Get some existing rules if available
    rules = list(Rule.objects.filter(is_active=True)[:5])
    
    # Time range - past 24 hours with higher concentration in certain hours
    now = timezone.now()
    
    # Create request logs with a realistic distribution
    logs_to_create = []
    for i in range(num_entries):
        # Create a more realistic time distribution with peaks and valleys
        hour_offset = random.choices(
            list(range(24)),
            # More traffic during business hours
            weights=[0.5, 0.3, 0.2, 0.1, 0.1, 0.2, 0.5, 1, 2, 3, 4, 4, 3, 4, 4, 3, 2, 1.5, 1, 0.8, 0.7, 0.5, 0.4, 0.3],
            k=1
        )[0]
        
        minute_offset = random.randint(0, 59)
        second_offset = random.randint(0, 59)
        
        timestamp = now - timedelta(hours=hour_offset, minutes=minute_offset, seconds=second_offset)
        
        # Create some blocked requests (about 15-20% of traffic)
        was_blocked = random.random() < 0.17
        action_taken = 'block' if was_blocked else 'allow'
        
        # Generate response code based on whether it was blocked
        if was_blocked:
            response_code = random.choice([403, 429, 400, 401])
        else:
            response_code = random.choice([200, 200, 200, 200, 201, 204, 302, 304, 404, 500])
        
        # Add matched rule for some requests
        matched_rule = random.choice(rules) if rules and random.random() < 0.3 else None
        
        logs_to_create.append(RequestLog(
            timestamp=timestamp,
            source_ip=random.choice(ips),
            method=random.choice(methods),
            path=random.choice(paths),
            response_code=response_code,
            response_time_ms=random.randint(10, 1000),
            user_agent=random.choice(user_agents),
            was_blocked=was_blocked,
            action_taken=action_taken,
            matched_rule=matched_rule,
            country=random.choice(countries) if random.random() > 0.1 else None,
            headers={'User-Agent': random.choice(user_agents)}
        ))
    
    # Bulk create logs
    RequestLog.objects.bulk_create(logs_to_create)
    print(f"Successfully generated {num_entries} traffic data entries!")

if __name__ == '__main__':
    num_entries = 200
    if len(sys.argv) > 1:
        try:
            num_entries = int(sys.argv[1])
        except ValueError:
            print("Please provide a valid number for entries")
            sys.exit(1)
    
    generate_traffic_data(num_entries)