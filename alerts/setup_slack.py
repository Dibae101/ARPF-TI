#!/usr/bin/env python
import os
import sys
import json
import django

# Set up Django environment
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'arpf_ti.settings')
django.setup()

from alerts.models import AlertNotificationConfig

def setup_slack_integration():
    """Set up a Slack integration with the provided webhook URL."""
    # Get the webhook URL from environment variable
    webhook_url = os.environ.get('SLACK_WEBHOOK_URL')
    
    if not webhook_url:
        print("Error: SLACK_WEBHOOK_URL environment variable is not set.")
        return False
    
    # Check if a Slack configuration already exists
    existing_config = AlertNotificationConfig.objects.filter(notification_type='slack').first()
    
    if existing_config:
        # Update existing configuration to filter for high severity
        existing_config.name = "Slack High Severity Alerts"
        existing_config.is_active = True
        existing_config.min_severity = "high"  # Only notify for high severity and above
        existing_config.recipients = "security-alerts"  # Slack channel name
        existing_config.configuration = {'webhook_url': webhook_url}
        existing_config.save()
        print(f"Updated existing Slack notification configuration (ID: {existing_config.id}) to high severity")
    else:
        # Create new configuration for high severity alerts
        new_config = AlertNotificationConfig(
            name="Slack High Severity Alerts",
            notification_type='slack',
            is_active=True,
            min_severity="high",  # Only notify for high severity and above
            recipients="security-alerts",  # Slack channel name
            configuration={'webhook_url': webhook_url}
        )
        new_config.save()
        print(f"Created new Slack notification configuration for high severity alerts (ID: {new_config.id})")
    
    return True

def test_slack_integration():
    """Test the Slack integration by sending a test high severity alert."""
    from alerts.alert_system import AlertSystem
    
    # Get the Slack notification configuration
    slack_config = AlertNotificationConfig.objects.filter(notification_type='slack').first()
    
    if not slack_config:
        print("Error: No Slack notification configuration found.")
        return False
    
    # Create a test high severity alert
    test_alert = AlertSystem.create_alert(
        alert_type='other',
        severity='high',
        title='Test High Severity Alert - Slack Integration',
        description='This is a high severity test alert to verify that the Slack integration is working correctly.',
        source_ip='127.0.0.1'  # Test IP
    )
    
    if test_alert:
        print(f"Test high severity alert created (ID: {test_alert.id})")
        
        # Send a Slack notification manually
        from alerts.alert_system import AlertSystem
        success = AlertSystem._send_slack_notification(test_alert, slack_config)
        
        if success:
            print("Test high severity notification sent to Slack. Please check your Slack channel.")
        else:
            print("Failed to send test notification to Slack. Check your webhook URL.")
        return success
    else:
        print("Error: Failed to create test alert.")
        return False

if __name__ == "__main__":
    print("Setting up Slack integration for high severity alerts...")
    if setup_slack_integration():
        print("\nTesting Slack integration with a high severity alert...")
        test_slack_integration()
    print("\nDone!")