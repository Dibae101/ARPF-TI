#!/usr/bin/env python
import os
import django
import random
from datetime import timedelta

# Set up Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'arpf_ti.settings')
django.setup()

from django.utils import timezone
from alerts.models import Alert, GeminiSuggestion
from alerts.alert_system import alert_system

def create_sample_alerts():
    """Create sample alerts across all categories: standard, suggested, and confirmed."""
    print("Creating sample alerts...")
    
    # Set of alert types and descriptions
    alert_types = [
        ('rule_match', 'Rule violation detected'),
        ('xss_attempt', 'Cross-site scripting attempt detected'),
        ('sqli_attempt', 'SQL injection attempt detected'),
        ('bot_activity', 'Suspicious bot activity detected'),
        ('rate_limit', 'Rate limit exceeded'),
        ('geo_violation', 'Geographic restriction violation'),
        ('honeypot_hit', 'Honeypot accessed'),
        ('ai_detected', 'AI model detected suspicious activity'),
        ('scan_detected', 'Port scanning detected'),
    ]
    
    severity_levels = ['low', 'medium', 'high', 'critical']
    source_ips = [
        '185.220.101.33',
        '95.216.145.1',
        '193.36.119.95',
        '23.129.64.102',
        '108.61.122.88',
        '45.132.192.41',
        '89.38.98.114',
        '190.211.254.193',
    ]
    
    # 1. Create standard alerts
    print("Creating standard alerts...")
    standard_alerts = []
    for i in range(5):
        alert_type, description_prefix = random.choice(alert_types)
        severity = random.choice(severity_levels)
        source_ip = random.choice(source_ips)
        
        # Generate a title and description
        title = f"{description_prefix} from {source_ip}"
        description = f"The system detected a potential {alert_type} from IP {source_ip}. This may indicate an attempted security breach."
        
        # Create alert
        alert = Alert.objects.create(
            alert_type=alert_type,
            severity=severity,
            title=title,
            description=description,
            source_ip=source_ip,
            alert_status='standard',
            timestamp=timezone.now() - timedelta(hours=random.randint(1, 12)),
        )
        standard_alerts.append(alert)
        print(f"Created standard alert: {alert.title}")
    
    # 2. Create suggested alerts (with Gemini suggestions)
    print("\nCreating suggested alerts...")
    for i in range(3):
        alert_type, description_prefix = random.choice(alert_types)
        severity = random.choice(['medium', 'high', 'critical'])  # Higher severity for suggestions
        source_ip = random.choice(source_ips)
        
        # Generate a title and description
        title = f"[AI] {description_prefix} from {source_ip}"
        description = f"The AI system detected a potential {alert_type} from IP {source_ip}. This may require attention."
        
        # Create alert with suggested status
        alert = Alert.objects.create(
            alert_type=alert_type,
            severity=severity,
            title=title,
            description=description,
            source_ip=source_ip,
            alert_status='suggested',  # Mark as suggested
            timestamp=timezone.now() - timedelta(hours=random.randint(1, 8)),
        )
        
        # Create a matching Gemini suggestion
        suggestion = GeminiSuggestion.objects.create(
            alert=alert,
            should_notify=True,
            assessment=f"This appears to be a genuine {alert_type} attempt",
            reasoning=f"The pattern of requests from {source_ip} matches known {alert_type} signatures. Multiple failed attempts indicate persistence.",
            suggested_actions=f"Block {source_ip} for 24 hours and monitor for similar patterns from the same network range.",
            confidence_score=random.uniform(0.85, 0.98),
            raw_response={"generated_text": f"Detailed analysis of {source_ip} activity..."}
        )
        
        print(f"Created suggested alert: {alert.title}")
    
    # 3. Create confirmed alerts
    print("\nCreating confirmed alerts...")
    for i in range(4):
        alert_type, description_prefix = random.choice(alert_types)
        severity = random.choice(['high', 'critical'])  # Higher severity for confirmed
        source_ip = random.choice(source_ips)
        
        # Generate a title and description
        title = f"[CONFIRMED] {description_prefix} from {source_ip}"
        description = f"Confirmed {alert_type} attack from IP {source_ip}. Immediate action required."
        
        # Create alert with confirmed status
        alert = Alert.objects.create(
            alert_type=alert_type,
            severity=severity,
            title=title,
            description=description,
            source_ip=source_ip,
            alert_status='confirmed',  # Mark as confirmed
            notification_sent=True,    # Mark as sent
            timestamp=timezone.now() - timedelta(hours=random.randint(1, 24)),
            is_acknowledged=random.choice([True, False]),  # Some are acknowledged
        )
        
        # Add acknowledged info for some
        if alert.is_acknowledged:
            alert.acknowledged_by = "admin"
            alert.acknowledged_at = timezone.now() - timedelta(minutes=random.randint(5, 60))
            alert.save()
        
        print(f"Created confirmed alert: {alert.title}")
    
    total_alerts = Alert.objects.count()
    print(f"\nTotal alerts in database: {total_alerts}")
    print(f"Standard alerts: {Alert.objects.filter(alert_status='standard').count()}")
    print(f"Suggested alerts: {Alert.objects.filter(alert_status='suggested').count()}")
    print(f"Confirmed alerts: {Alert.objects.filter(alert_status='confirmed').count()}")

if __name__ == "__main__":
    create_sample_alerts()
    print("\nSample alerts created successfully! Refresh your alerts page to see them.")