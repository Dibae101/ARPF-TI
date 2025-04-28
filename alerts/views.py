from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse, HttpResponse
from django.utils import timezone
import json
import csv
from .models import Alert, AlertNotificationConfig, AlertComment
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

@login_required
def add_comment(request, alert_id):
    """Add a comment to an alert."""
    alert = get_object_or_404(Alert, id=alert_id)
    
    if request.method == 'POST':
        content = request.POST.get('content')
        if content:
            comment = AlertComment(
                alert=alert,
                user=request.user,
                content=content
            )
            comment.save()
            messages.success(request, 'Comment added successfully.')
        else:
            messages.error(request, 'Comment cannot be empty.')
    
    return redirect('alerts:alert_detail', alert_id=alert_id)

@login_required
def mark_as_false_positive(request, alert_id):
    """Mark an alert as a false positive."""
    alert = get_object_or_404(Alert, id=alert_id)
    
    alert.is_false_positive = True
    alert.acknowledge(request.user.username)
    alert.save()
    
    # Add a system comment noting this was marked as false positive
    comment = AlertComment(
        alert=alert,
        user=request.user,
        content="This alert was marked as a false positive."
    )
    comment.save()
    
    messages.success(request, f'Alert #{alert.id} has been marked as a false positive.')
    return redirect('alerts:alert_detail', alert_id=alert_id)

@login_required
def export_alert(request, alert_id):
    """Export alert data as JSON or CSV."""
    alert = get_object_or_404(Alert, id=alert_id)
    format_type = request.GET.get('format', 'json')
    
    # Create a dictionary with alert data
    alert_data = {
        'id': alert.id,
        'title': alert.title,
        'description': alert.description,
        'alert_type': alert.alert_type,
        'severity': alert.severity,
        'source_ip': alert.source_ip,
        'timestamp': alert.timestamp.isoformat(),
        'is_acknowledged': alert.is_acknowledged,
        'acknowledged_by': alert.acknowledged_by,
        'acknowledged_at': alert.acknowledged_at.isoformat() if alert.acknowledged_at else None,
        'is_false_positive': getattr(alert, 'is_false_positive', False)
    }
    
    # Include comments if they exist
    comments = []
    for comment in AlertComment.objects.filter(alert=alert).order_by('created_at'):
        comments.append({
            'user': comment.user.username,
            'content': comment.content,
            'created_at': comment.created_at.isoformat()
        })
    
    if comments:
        alert_data['comments'] = comments
    
    # Export in the requested format
    if format_type == 'csv':
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = f'attachment; filename="alert_{alert.id}.csv"'
        
        writer = csv.writer(response)
        writer.writerow(['Field', 'Value'])
        
        # Write alert data
        for key, value in alert_data.items():
            if key != 'comments':
                writer.writerow([key, value])
        
        # Write comments if any
        if comments:
            writer.writerow([])
            writer.writerow(['Comments'])
            writer.writerow(['User', 'Content', 'Created At'])
            for comment in comments:
                writer.writerow([comment['user'], comment['content'], comment['created_at']])
        
        return response
    else:
        # JSON format is the default
        response = HttpResponse(json.dumps(alert_data, indent=2), content_type='application/json')
        response['Content-Disposition'] = f'attachment; filename="alert_{alert.id}.json"'
        return response
