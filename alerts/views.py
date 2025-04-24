from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.utils import timezone
from .models import Alert, AlertNotificationConfig
from .alert_system import alert_system

@login_required
def alert_list(request):
    """Display a list of all alerts with filtering options."""
    alerts = Alert.objects.all().order_by('-timestamp')
    
    # Filtering options
    severity_filter = request.GET.get('severity')
    acknowledged_filter = request.GET.get('acknowledged')
    type_filter = request.GET.get('type')
    
    if severity_filter:
        alerts = alerts.filter(severity=severity_filter)
    
    if acknowledged_filter:
        is_acknowledged = acknowledged_filter == '1'
        alerts = alerts.filter(is_acknowledged=is_acknowledged)
    
    if type_filter:
        alerts = alerts.filter(alert_type=type_filter)
    
    context = {
        'alerts': alerts,
        'severity_filter': severity_filter,
        'acknowledged_filter': acknowledged_filter,
        'type_filter': type_filter,
        'alert_types': Alert.ALERT_TYPES,
        'severity_levels': Alert.SEVERITY_LEVELS
    }
    
    return render(request, 'alerts/alert_list.html', context)

@login_required
def alert_detail(request, alert_id):
    """Display details of a specific alert."""
    alert = get_object_or_404(Alert, id=alert_id)
    return render(request, 'alerts/alert_detail.html', {'alert': alert})

@login_required
def alert_acknowledge(request, alert_id):
    """Acknowledge an alert."""
    alert = get_object_or_404(Alert, id=alert_id)
    
    if request.method == 'POST':
        username = request.user.username
        alert.acknowledge(username)
        messages.success(request, f'Alert #{alert.id} has been acknowledged.')
        
        # If AJAX request, return JSON response
        if request.headers.get('x-requested-with') == 'XMLHttpRequest':
            return JsonResponse({'status': 'success'})
        
        return redirect('alerts:alert_list')
    
    return render(request, 'alerts/alert_acknowledge.html', {'alert': alert})

@login_required
def notification_config_list(request):
    """Display a list of notification configurations."""
    configs = AlertNotificationConfig.objects.all()
    return render(request, 'alerts/notification_config_list.html', {'configs': configs})

@login_required
def notification_config_add(request):
    """Add a new notification configuration."""
    if request.method == 'POST':
        name = request.POST.get('name')
        notification_type = request.POST.get('notification_type')
        min_severity = request.POST.get('min_severity')
        recipients = request.POST.get('recipients')
        
        # JSON configuration based on notification type
        configuration = {}
        if notification_type == 'email':
            # Email specific config
            pass
        elif notification_type == 'slack':
            configuration['webhook_url'] = request.POST.get('webhook_url')
        elif notification_type == 'webhook':
            configuration['webhook_url'] = request.POST.get('webhook_url')
            configuration['headers'] = request.POST.get('headers', '{}')
        
        config = AlertNotificationConfig(
            name=name,
            notification_type=notification_type,
            min_severity=min_severity,
            recipients=recipients,
            configuration=configuration,
            is_active=True
        )
        config.save()
        
        messages.success(request, 'Notification configuration created successfully.')
        return redirect('alerts:notification_config_list')
    
    context = {
        'notification_types': AlertNotificationConfig.NOTIFICATION_TYPES,
        'severity_levels': Alert.SEVERITY_LEVELS
    }
    
    return render(request, 'alerts/notification_config_form.html', context)

@login_required
def notification_config_edit(request, config_id):
    """Edit an existing notification configuration."""
    config = get_object_or_404(AlertNotificationConfig, id=config_id)
    
    if request.method == 'POST':
        config.name = request.POST.get('name')
        config.notification_type = request.POST.get('notification_type')
        config.min_severity = request.POST.get('min_severity')
        config.recipients = request.POST.get('recipients')
        config.is_active = request.POST.get('is_active') == 'on'
        
        # Update configuration based on notification type
        configuration = {}
        if config.notification_type == 'email':
            # Email specific config
            pass
        elif config.notification_type == 'slack':
            configuration['webhook_url'] = request.POST.get('webhook_url')
        elif config.notification_type == 'webhook':
            configuration['webhook_url'] = request.POST.get('webhook_url')
            configuration['headers'] = request.POST.get('headers', '{}')
        
        config.configuration = configuration
        config.save()
        
        messages.success(request, 'Notification configuration updated successfully.')
        return redirect('alerts:notification_config_list')
    
    context = {
        'config': config,
        'notification_types': AlertNotificationConfig.NOTIFICATION_TYPES,
        'severity_levels': Alert.SEVERITY_LEVELS
    }
    
    return render(request, 'alerts/notification_config_form.html', context)

@login_required
def notification_config_delete(request, config_id):
    """Delete a notification configuration."""
    config = get_object_or_404(AlertNotificationConfig, id=config_id)
    
    if request.method == 'POST':
        config.delete()
        messages.success(request, 'Notification configuration deleted successfully.')
        return redirect('alerts:notification_config_list')
    
    return render(request, 'alerts/notification_config_confirm_delete.html', {'config': config})

@login_required
def notification_config_test(request, config_id):
    """Test a notification configuration by sending a test alert."""
    config = get_object_or_404(AlertNotificationConfig, id=config_id)
    
    if request.method == 'POST' or request.method == 'GET':
        try:
            # Create a test alert content
            test_message = {
                'title': 'Test Alert',
                'message': f'This is a test alert sent from ARPF-TI at {timezone.now()}',
                'severity': config.min_severity,
                'source': 'Manual test',
                'timestamp': timezone.now().isoformat()
            }
            
            # Use the alert system to send the test notification
            success = alert_system.send_notification(config, test_message)
            
            if success:
                messages.success(request, f'Test notification sent successfully using {config.name}.')
            else:
                messages.error(request, f'Failed to send test notification using {config.name}.')
        
        except Exception as e:
            messages.error(request, f'Error sending test notification: {str(e)}')
    
    return redirect('alerts:notification_config_list')
