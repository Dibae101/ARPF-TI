import json
import logging
import smtplib
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from django.conf import settings
from django.utils import timezone
from .models import Alert, AlertNotificationConfig

logger = logging.getLogger('arpf_ti')

class AlertSystem:
    """
    Alert system for generating and sending notifications
    about security events.
    """
    
    @classmethod
    def create_alert(cls, alert_type, severity, title, description, source_ip=None, 
                   triggered_rule=None, related_logs=None):
        """
        Create a new alert and send notifications as needed.
        """
        try:
            # Create the alert record
            alert = Alert(
                alert_type=alert_type,
                severity=severity,
                title=title,
                description=description,
                source_ip=source_ip,
                triggered_rule=triggered_rule
            )
            alert.save()
            
            # Add related logs if any
            if related_logs:
                alert.related_logs.set(related_logs)
            
            # Send notifications
            cls.send_notifications(alert)
            
            return alert
        
        except Exception as e:
            logger.error(f"Error creating alert: {str(e)}")
            return None
    
    @classmethod
    def send_notifications(cls, alert):
        """
        Send notifications for an alert based on configured channels.
        """
        if not settings.ENABLE_ALERTS:
            logger.info("Alerts are disabled, skipping notifications")
            return
        
        try:
            # Get notification configurations that match this alert's severity
            configs = AlertNotificationConfig.objects.filter(is_active=True)
            
            for config in configs:
                if not config.should_notify(alert):
                    continue
                
                if config.notification_type == 'email':
                    cls._send_email_notification(alert, config)
                
                elif config.notification_type == 'slack':
                    cls._send_slack_notification(alert, config)
                
                elif config.notification_type == 'webhook':
                    cls._send_webhook_notification(alert, config)
                
                elif config.notification_type == 'sms':
                    cls._send_sms_notification(alert, config)
        
        except Exception as e:
            logger.error(f"Error sending alert notifications: {str(e)}")
    
    @classmethod
    def _send_email_notification(cls, alert, config):
        """
        Send an email notification.
        """
        try:
            # Get recipient list
            recipients = [r.strip() for r in config.recipients.split(',') if r.strip()]
            if not recipients:
                logger.warning(f"No recipients configured for email notification {config.name}")
                return
            
            # Create email message
            msg = MIMEMultipart()
            msg['From'] = settings.EMAIL_HOST_USER
            msg['To'] = ", ".join(recipients)
            msg['Subject'] = f"ARPF-TI Security Alert: {alert.title}"
            
            # Create email body
            body = f"""
            <html>
            <body>
                <h2>Security Alert: {alert.title}</h2>
                <p><strong>Severity:</strong> {alert.get_severity_display()}</p>
                <p><strong>Type:</strong> {alert.get_alert_type_display()}</p>
                <p><strong>Time:</strong> {alert.timestamp}</p>
                <p><strong>Source IP:</strong> {alert.source_ip or 'N/A'}</p>
                <p><strong>Description:</strong> {alert.description}</p>
            </body>
            </html>
            """
            
            msg.attach(MIMEText(body, 'html'))
            
            # Send email
            with smtplib.SMTP(settings.EMAIL_HOST, settings.EMAIL_PORT) as server:
                if settings.EMAIL_USE_TLS:
                    server.starttls()
                
                if settings.EMAIL_HOST_USER and settings.EMAIL_HOST_PASSWORD:
                    server.login(settings.EMAIL_HOST_USER, settings.EMAIL_HOST_PASSWORD)
                
                server.send_message(msg)
            
            logger.info(f"Email alert sent to {len(recipients)} recipients")
        
        except Exception as e:
            logger.error(f"Error sending email notification: {str(e)}")
    
    @classmethod
    def _send_slack_notification(cls, alert, config):
        """
        Send a Slack notification.
        """
        try:
            # Get Slack webhook URL from settings or config
            webhook_url = settings.SLACK_WEBHOOK_URL
            if not webhook_url and 'webhook_url' in config.configuration:
                webhook_url = config.configuration.get('webhook_url')
            
            if not webhook_url:
                logger.warning("No Slack webhook URL configured")
                return
            
            # Create Slack message payload
            severity_colors = {
                'info': '#4287f5',
                'low': '#42f5ef',
                'medium': '#f5d442',
                'high': '#f58442',
                'critical': '#f54242'
            }
            
            color = severity_colors.get(alert.severity, '#4287f5')
            
            payload = {
                "attachments": [
                    {
                        "fallback": f"Security Alert: {alert.title}",
                        "color": color,
                        "title": f"Security Alert: {alert.title}",
                        "fields": [
                            {
                                "title": "Severity",
                                "value": alert.get_severity_display(),
                                "short": True
                            },
                            {
                                "title": "Type",
                                "value": alert.get_alert_type_display(),
                                "short": True
                            },
                            {
                                "title": "Time",
                                "value": alert.timestamp.isoformat(),
                                "short": True
                            },
                            {
                                "title": "Source IP",
                                "value": alert.source_ip or "N/A",
                                "short": True
                            },
                            {
                                "title": "Description",
                                "value": alert.description,
                                "short": False
                            }
                        ],
                        "footer": "ARPF-TI Web Application Firewall",
                        "ts": int(alert.timestamp.timestamp())
                    }
                ]
            }
            
            # Send Slack notification
            response = requests.post(webhook_url, json=payload)
            response.raise_for_status()
            
            logger.info("Slack notification sent successfully")
        
        except Exception as e:
            logger.error(f"Error sending Slack notification: {str(e)}")
    
    @classmethod
    def _send_webhook_notification(cls, alert, config):
        """
        Send a notification to a custom webhook.
        """
        try:
            # Get webhook URL from config
            webhook_url = config.configuration.get('webhook_url')
            if not webhook_url:
                logger.warning(f"No webhook URL configured for {config.name}")
                return
            
            # Create webhook payload
            payload = {
                "alert_id": alert.id,
                "alert_type": alert.alert_type,
                "severity": alert.severity,
                "title": alert.title,
                "description": alert.description,
                "source_ip": alert.source_ip,
                "timestamp": alert.timestamp.isoformat(),
                "is_acknowledged": alert.is_acknowledged
            }
            
            # Add custom headers if configured
            headers = config.configuration.get('headers', {})
            
            # Send webhook notification
            response = requests.post(webhook_url, json=payload, headers=headers)
            response.raise_for_status()
            
            logger.info(f"Webhook notification sent to {webhook_url}")
        
        except Exception as e:
            logger.error(f"Error sending webhook notification: {str(e)}")
    
    @classmethod
    def _send_sms_notification(cls, alert, config):
        """
        Send an SMS notification. Implementation depends on your SMS provider.
        """
        # This is a placeholder for SMS notification logic
        # You would implement this based on your chosen SMS provider
        logger.info("SMS notification not implemented yet")

# Create a singleton instance
alert_system = AlertSystem()

# Create a wrapper function to make it easier to use the alert system
def create_alert(title, description, severity="medium", source="system", source_id=None, related_object=None, source_ip=None):
    """
    Create an alert and send notifications.
    
    Args:
        title: The alert title
        description: The alert description
        severity: Alert severity (low, medium, high, critical)
        source: The source of the alert (e.g., 'waf', 'ai', 'system')
        source_id: An identifier for the source object
        related_object: A Django model instance related to this alert
        source_ip: The source IP address if applicable
    
    Returns:
        The created Alert object or None if creation failed
    """
    try:
        # Determine alert type based on source
        alert_type_map = {
            'waf': 'rule_match',
            'ai': 'ai_detection',
            'system': 'system',
            'manual': 'manual'
        }
        alert_type = alert_type_map.get(source, 'other')
        
        # Extract triggered rule if available
        triggered_rule = None
        related_logs = None
        
        # Handle special case for WAF rule matches
        if source == 'waf' and related_object:
            if hasattr(related_object, 'matched_rule') and related_object.matched_rule:
                triggered_rule = related_object.matched_rule
            related_logs = [related_object]
        
        # Create the alert
        return AlertSystem.create_alert(
            alert_type=alert_type,
            severity=severity,
            title=title,
            description=description,
            source_ip=source_ip,
            triggered_rule=triggered_rule,
            related_logs=related_logs
        )
    except Exception as e:
        logger.error(f"Error creating alert: {str(e)}")
        return None