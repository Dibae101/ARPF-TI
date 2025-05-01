from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse, HttpResponse
from django.utils import timezone
import json
import csv
import logging
from .models import Alert, AlertNotificationConfig, AlertComment
from .alert_system import alert_system
from .gemini_integration import gemini_integration

@login_required
def alert_list(request):
    """Display a list of all alerts with filtering options."""
    # Get the current tab from the query parameters
    current_tab = request.GET.get('tab', 'all')
    
    # Initialize queryset based on the selected tab
    if current_tab == 'suggested':
        alerts = Alert.objects.filter(alert_status='suggested').order_by('-timestamp')
    elif current_tab == 'confirmed':
        alerts = Alert.objects.filter(alert_status='confirmed').order_by('-timestamp')
    elif current_tab == 'standard':
        alerts = Alert.objects.filter(alert_status='standard').order_by('-timestamp')
    else:  # 'all' tab or any other value
        alerts = Alert.objects.all().order_by('-timestamp')
    
    # Additional filtering options
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
    
    # Fetch counts for each category for the badges
    suggested_alerts_count = Alert.objects.filter(alert_status='suggested').count()
    confirmed_alerts_count = Alert.objects.filter(alert_status='confirmed').count()
    standard_alerts_count = Alert.objects.filter(alert_status='standard').count()
    
    context = {
        'alerts': alerts,
        'current_tab': current_tab,
        'suggested_alerts_count': suggested_alerts_count,
        'confirmed_alerts_count': confirmed_alerts_count,
        'standard_alerts_count': standard_alerts_count,
        'severity_filter': severity_filter,
        'acknowledged_filter': acknowledged_filter,
        'type_filter': type_filter,
        'alert_types': Alert.ALERT_TYPES,
        'severity_levels': Alert.SEVERITY_LEVELS,
        'alert_statuses': Alert.ALERT_STATUS
    }
    
    return render(request, 'alerts/alert_list.html', context)

@login_required
def alert_detail(request, alert_id):
    """Display details of a specific alert."""
    alert = get_object_or_404(Alert, id=alert_id)
    
    # Get comments for this alert
    comments = AlertComment.objects.filter(alert=alert).order_by('created_at')
    
    # Get similar alerts (optional)
    similar_alerts = Alert.objects.filter(alert_type=alert.alert_type).exclude(id=alert.id).order_by('-timestamp')[:5]
    
    context = {
        'alert': alert,
        'comments': comments,
        'similar_alerts': similar_alerts,
    }
    
    return render(request, 'alerts/alert_detail.html', context)

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
def confirm_alert(request, alert_id):
    """Confirm an alert suggestion and send it to notification channels."""
    alert = get_object_or_404(Alert, id=alert_id)
    
    if request.method == 'POST':
        # Update alert status to confirmed
        alert.alert_status = 'confirmed'
        
        # Send the alert to notification channels
        notification_success = alert_system.send_notifications(alert)
        
        # Mark the alert as having notifications sent
        if notification_success:
            alert.notification_sent = True
            messages.success(request, f'Alert #{alert.id} has been confirmed and sent to notification channels.')
        else:
            messages.warning(request, f'Alert #{alert.id} has been confirmed but notification sending failed. Check notification settings.')
        
        alert.save()
        
        # If AJAX request, return JSON response
        if request.headers.get('x-requested-with') == 'XMLHttpRequest':
            return JsonResponse({'status': 'success'})
        
        return redirect('alerts:alert_list')
    
    return render(request, 'alerts/alert_confirm.html', {'alert': alert})

@login_required
def ignore_alert_suggestion(request, alert_id):
    """Ignore an alert suggestion."""
    alert = get_object_or_404(Alert, id=alert_id)
    
    if request.method == 'POST':
        # Update alert status to ignored
        alert.alert_status = 'ignored'
        alert.save()
        
        messages.success(request, f'Alert #{alert.id} suggestion has been ignored.')
        
        # If AJAX request, return JSON response
        if request.headers.get('x-requested-with') == 'XMLHttpRequest':
            return JsonResponse({'status': 'success'})
        
        return redirect('alerts:alert_list')
    
    return render(request, 'alerts/alert_ignore.html', {'alert': alert})

@login_required
def view_gemini_suggestion(request, alert_id):
    """View Gemini's suggestion for an alert."""
    alert = get_object_or_404(Alert, id=alert_id)
    
    # Get the GeminiSuggestion object for this alert
    try:
        suggestion = alert.gemini_suggestion
        if suggestion is None:
            # If no suggestion exists yet, generate one
            suggestion = gemini_integration.analyze_alert(alert)
            if not suggestion:
                messages.error(request, "Could not generate AI analysis for this alert.")
                return redirect('alerts:alert_detail', alert_id=alert.id)
    except Exception as e:
        messages.error(request, f"Error retrieving AI analysis: {str(e)}")
        return redirect('alerts:alert_detail', alert_id=alert.id)
    
    # Prepare data for the template
    suggestion_data = {
        'suggestion': suggestion.assessment,
        'reasoning': suggestion.reasoning,
        'suggested_actions': suggestion.suggested_actions,
        'confidence_score': suggestion.confidence_score,
        'additional_info': getattr(suggestion, 'additional_info', None)
    }
    
    context = {
        'alert': alert,
        'suggestion_data': suggestion_data
    }
    
    return render(request, 'alerts/alert_suggestion_detail.html', context)

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
    
    # Mark as false positive
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
        is_active = request.POST.get('is_active') == 'on'
        
        # JSON configuration based on notification type
        configuration = {}
        if notification_type == 'email':
            # Email specific config
            configuration['smtp_port'] = request.POST.get('smtp_port')
            configuration['use_tls'] = request.POST.get('use_tls') == 'on'
        elif notification_type == 'slack':
            configuration['webhook_url'] = request.POST.get('webhook_url')
        elif notification_type == 'webhook':
            configuration['webhook_url'] = request.POST.get('webhook_url')
            configuration['headers'] = request.POST.get('headers', '{}')
        elif notification_type == 'sms':
            configuration['provider'] = request.POST.get('provider')
            configuration['api_key'] = request.POST.get('api_key')
        
        config = AlertNotificationConfig(
            name=name,
            notification_type=notification_type,
            min_severity=min_severity,
            recipients=recipients,
            configuration=configuration,
            is_active=is_active
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
            configuration['smtp_port'] = request.POST.get('smtp_port')
            configuration['use_tls'] = request.POST.get('use_tls') == 'on'
        elif config.notification_type == 'slack':
            configuration['webhook_url'] = request.POST.get('webhook_url')
        elif config.notification_type == 'webhook':
            configuration['webhook_url'] = request.POST.get('webhook_url')
            configuration['headers'] = request.POST.get('headers', '{}')
        elif config.notification_type == 'sms':
            configuration['provider'] = request.POST.get('provider')
            configuration['api_key'] = request.POST.get('api_key')
        
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
                'subject': 'Test Alert from ARPF-TI',
                'body': f'This is a test alert sent from ARPF-TI at {timezone.now().strftime("%Y-%m-%d %H:%M:%S")}',
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
def generate_alert_suggestions(request):
    """Generate alert suggestions using Gemini AI for all unacknowledged standard alerts."""
    # Get counts for alerts that can be analyzed
    standard_alerts = Alert.objects.filter(
        is_acknowledged=False, 
        alert_status='standard',
        gemini_suggestion__isnull=True
    )
    
    pending_count = standard_alerts.count()
    
    if request.method == 'POST':
        # Get all unacknowledged standard alerts without suggestions
        suggestion_count = 0
        errors = 0
        
        for alert in standard_alerts:
            try:
                # Get suggestion from Gemini
                suggestion = gemini_integration.analyze_alert(alert)
                
                if suggestion:
                    # If Gemini suggests sending the alert, mark it as suggested
                    if suggestion.should_notify:
                        alert.alert_status = 'suggested'
                        suggestion_count += 1
                    
                    # The suggestion is already saved by the analyze_alert method
                else:
                    errors += 1
            except Exception as e:
                errors += 1
                logger = logging.getLogger(__name__)
                logger.error(f"Error generating suggestion for alert {alert.id}: {str(e)}")
        
        if suggestion_count > 0:
            messages.success(request, f'Generated {suggestion_count} new alert suggestions.')
        
        if errors > 0:
            messages.warning(request, f'Failed to generate suggestions for {errors} alerts. Check the logs for details.')
            
        return redirect('alerts:alert_list')
    
    # Get recent suggestions
    recent_suggestions = Alert.objects.filter(
        alert_status='suggested',
        gemini_suggestion__isnull=False
    ).order_by('-timestamp')[:5]
    
    context = {
        'pending_count': pending_count,
        'recent_suggestions': recent_suggestions
    }
    
    return render(request, 'alerts/generate_suggestions.html', context)
