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
                triggered_rule=triggered_rule,
                alert_status='standard'  # Set default status to standard
            )
            alert.save()
            
            # Add related logs if any
            if related_logs:
                alert.related_logs.set(related_logs)
            
            # Don't automatically send notifications, wait for confirmation
            # by removing this line: cls.send_notifications(alert)
            
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
            return False
        
        try:
            # Get notification configurations that match this alert's severity
            configs = AlertNotificationConfig.objects.filter(is_active=True)
            
            sent_count = 0
            for config in configs:
                if not config.should_notify(alert):
                    continue
                
                success = cls.send_notification(config, alert)
                if success:
                    sent_count += 1
            
            # Update the alert as having notifications sent
            if sent_count > 0:
                alert.notification_sent = True
                alert.save()
                return True
                
            return False
        
        except Exception as e:
            logger.error(f"Error sending alert notifications: {str(e)}")
            return False
    
    @classmethod
    def send_notification(cls, config, alert_or_message):
        """
        Send a notification using a specific configuration.
        
        Args:
            config: The AlertNotificationConfig to use
            alert_or_message: Either an Alert object or a dictionary with alert data
            
        Returns:
            bool: True if notification was sent successfully, False otherwise
        """
        try:
            # Determine if we're dealing with an Alert object or a dictionary
            is_alert_obj = isinstance(alert_or_message, Alert)
            
            notification_type = config.notification_type
            
            if notification_type == 'email':
                return cls._send_email_notification(alert_or_message, config, is_alert_obj)
            
            elif notification_type == 'slack':
                return cls._send_slack_notification(alert_or_message, config, is_alert_obj)
            
            elif notification_type == 'webhook':
                return cls._send_webhook_notification(alert_or_message, config, is_alert_obj)
            
            elif notification_type == 'sms':
                return cls._send_sms_notification(alert_or_message, config, is_alert_obj)
            
            logger.warning(f"Unknown notification type: {notification_type}")
            return False
            
        except Exception as e:
            logger.error(f"Error sending notification: {str(e)}")
            return False
    
    @classmethod
    def _send_email_notification(cls, alert_or_message, config, is_alert_obj=True):
        """
        Send an email notification.
        """
        try:
            # Get recipient list
            recipients = [r.strip() for r in config.recipients.split(',') if r.strip()]
            if not recipients:
                logger.warning(f"No recipients configured for email notification {config.name}")
                return False
            
            # Create email message
            msg = MIMEMultipart()
            msg['From'] = settings.EMAIL_HOST_USER
            msg['To'] = ", ".join(recipients)
            
            if is_alert_obj:
                # It's an Alert object
                alert = alert_or_message
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
            else:
                # It's a dictionary
                message = alert_or_message
                msg['Subject'] = f"ARPF-TI Security Alert: {message.get('title', 'No Title')}"
                
                # Create email body
                body = f"""
                <html>
                <body>
                    <h2>Security Alert: {message.get('title', 'No Title')}</h2>
                    <p><strong>Severity:</strong> {message.get('severity', 'Unknown')}</p>
                    <p><strong>Source:</strong> {message.get('source', 'Unknown')}</p>
                    <p><strong>Time:</strong> {message.get('timestamp', timezone.now())}</p>
                    <p><strong>Message:</strong> {message.get('message', 'No message provided')}</p>
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
            return True
        
        except Exception as e:
            logger.error(f"Error sending email notification: {str(e)}")
            return False
    
    @classmethod
    def _send_slack_notification(cls, alert_or_message, config, is_alert_obj=True):
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
                return False
            
            # Create Slack message payload
            severity_colors = {
                'info': '#4287f5',
                'low': '#42f5ef',
                'medium': '#f5d442',
                'high': '#f58442',
                'critical': '#f54242'
            }
            
            if is_alert_obj:
                # It's an Alert object
                alert = alert_or_message
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
            else:
                # It's a dictionary
                message = alert_or_message
                severity = message.get('severity', 'medium')
                color = severity_colors.get(severity, '#4287f5')
                
                payload = {
                    "attachments": [
                        {
                            "fallback": f"Security Alert: {message.get('title', 'No Title')}",
                            "color": color,
                            "title": f"Security Alert: {message.get('title', 'No Title')}",
                            "fields": [
                                {
                                    "title": "Severity",
                                    "value": message.get('severity', 'Unknown'),
                                    "short": True
                                },
                                {
                                    "title": "Source",
                                    "value": message.get('source', 'Unknown'),
                                    "short": True
                                },
                                {
                                    "title": "Message",
                                    "value": message.get('message', 'No message provided'),
                                    "short": False
                                }
                            ],
                            "footer": "ARPF-TI Web Application Firewall",
                            "ts": int(timezone.now().timestamp())
                        }
                    ]
                }
            
            # Send Slack notification
            response = requests.post(webhook_url, json=payload)
            response.raise_for_status()
            
            logger.info("Slack notification sent successfully")
            return True
        
        except Exception as e:
            logger.error(f"Error sending Slack notification: {str(e)}")
            return False
    
    @classmethod
    def _send_webhook_notification(cls, alert_or_message, config, is_alert_obj=True):
        """
        Send a notification to a custom webhook.
        """
        try:
            # Get webhook URL from config
            webhook_url = config.configuration.get('webhook_url')
            if not webhook_url:
                logger.warning(f"No webhook URL configured for {config.name}")
                return False
            
            # Create webhook payload
            if is_alert_obj:
                # It's an Alert object
                alert = alert_or_message
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
            else:
                # It's a dictionary - pass it directly
                payload = alert_or_message
            
            # Add custom headers if configured
            headers = {}
            try:
                if 'headers' in config.configuration:
                    if isinstance(config.configuration['headers'], str):
                        headers = json.loads(config.configuration['headers'])
                    else:
                        headers = config.configuration['headers']
            except (json.JSONDecodeError, TypeError):
                logger.warning(f"Invalid headers configuration for webhook {config.name}")
            
            # Send webhook notification
            response = requests.post(webhook_url, json=payload, headers=headers)
            response.raise_for_status()
            
            logger.info(f"Webhook notification sent to {webhook_url}")
            return True
        
        except Exception as e:
            logger.error(f"Error sending webhook notification: {str(e)}")
            return False
    
    @classmethod
    def _send_sms_notification(cls, alert_or_message, config, is_alert_obj=True):
        """
        Send an SMS notification. Implementation depends on your SMS provider.
        """
        # This is a placeholder for SMS notification logic
        # You would implement this based on your chosen SMS provider
        logger.info("SMS notification not implemented yet")
        return False

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
            'ai': 'ai_detected',
            'system': 'other',
            'manual': 'other'
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
        
        # Create the alert - don't automatically send notifications
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