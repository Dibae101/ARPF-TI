from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.db.models import Count, Avg, Sum
from django.utils import timezone
from datetime import timedelta
from .models import DashboardMetric, DashboardSettings
from core.models import RequestLog, Rule
from alerts.models import Alert

@login_required
def dashboard(request):
    """Main dashboard view showing overview of system status."""
    # Get dashboard settings
    settings, created = DashboardSettings.objects.get_or_create(id=1)
    
    # Calculate time range based on settings
    time_range = request.GET.get('range', settings.default_time_range)
    if time_range == 'hour':
        start_time = timezone.now() - timedelta(hours=1)
        interval_unit = 'minute'
        chart_format = '%H:%M'
    elif time_range == 'day':
        start_time = timezone.now() - timedelta(days=1)
        interval_unit = 'hour'
        chart_format = '%H:00'
    elif time_range == 'week':
        start_time = timezone.now() - timedelta(weeks=1)
        interval_unit = 'day'
        chart_format = '%a'
    elif time_range == 'month':
        start_time = timezone.now() - timedelta(days=30)
        interval_unit = 'day'
        chart_format = '%d %b'
    else:
        start_time = timezone.now() - timedelta(days=1)  # Default to last 24 hours
        interval_unit = 'hour'
        chart_format = '%H:00'
    
    # Get basic metrics
    total_requests = RequestLog.objects.filter(timestamp__gte=start_time).count()
    blocked_requests = RequestLog.objects.filter(timestamp__gte=start_time, was_blocked=True).count()
    avg_response_time = RequestLog.objects.filter(timestamp__gte=start_time).aggregate(Avg('response_time_ms'))['response_time_ms__avg'] or 0
    
    # Get previous period data for comparison
    if time_range == 'hour':
        prev_start_time = start_time - timedelta(hours=1)
    elif time_range == 'day':
        prev_start_time = start_time - timedelta(days=1)
    elif time_range == 'week':
        prev_start_time = start_time - timedelta(weeks=1)
    elif time_range == 'month':
        prev_start_time = start_time - timedelta(days=30)
    else:
        prev_start_time = start_time - timedelta(days=1)
    
    prev_total_requests = RequestLog.objects.filter(timestamp__gte=prev_start_time, timestamp__lt=start_time).count()
    
    # Calculate percentage change
    if prev_total_requests > 0:
        request_change_pct = round((total_requests - prev_total_requests) / prev_total_requests * 100, 1)
    else:
        request_change_pct = 0
    
    # Active rules
    active_rules_count = Rule.objects.filter(is_active=True).count()
    active_rules_list = Rule.objects.filter(is_active=True).order_by('-priority')[:10]
    
    # Recent logs
    recent_logs = RequestLog.objects.order_by('-timestamp')[:10]
    
    # Top triggered rules
    top_rules = RequestLog.objects.filter(
        timestamp__gte=start_time, 
        matched_rule__isnull=False
    ).values(
        'matched_rule__id', 
        'matched_rule__name'
    ).annotate(
        count=Count('id')
    ).order_by('-count')[:5]
    
    # Top blocked IPs
    top_blocked_ips = RequestLog.objects.filter(
        timestamp__gte=start_time, 
        was_blocked=True
    ).values('source_ip').annotate(
        count=Count('id')
    ).order_by('-count')[:5]
    
    # Top source countries
    top_countries = RequestLog.objects.filter(
        timestamp__gte=start_time,
        country__isnull=False
    ).values('country').annotate(
        request_count=Count('id')
    ).order_by('-request_count')[:5]
    
    # Calculate percentages for countries
    if total_requests > 0:
        for country in top_countries:
            country['percentage'] = round((country['request_count'] / total_requests) * 100)
            # Add country name and flag placeholder
            country['name'] = country['country'] or 'Unknown'
            country['flag'] = '🌍'  # Default flag
            # You can add a mapping for country codes to flag emojis
    
    # Recent alerts
    try:
        recent_alerts = Alert.objects.order_by('-created_at')[:5]
        recent_alerts_count = Alert.objects.filter(created_at__gte=start_time).count()
    except:
        # Handle case where Alert model might not exist or be accessible
        recent_alerts = []
        recent_alerts_count = 0
    
    # Generate traffic chart data based on time intervals
    if interval_unit == 'minute':
        # For hourly view, group by minute
        intervals = 60
        timedelta_unit = timedelta(minutes=1)
    elif interval_unit == 'hour':
        # For daily view, group by hour
        intervals = 24
        timedelta_unit = timedelta(hours=1)
    elif interval_unit == 'day':
        # For weekly or monthly view, group by day
        intervals = 30 if time_range == 'month' else 7
        timedelta_unit = timedelta(days=1)
    
    # Generate time slots
    time_slots = [(start_time + (i * timedelta_unit)) for i in range(intervals)]
    
    # Initialize data structures
    labels = []
    all_requests_data = []
    blocked_requests_data = []
    
    # Process each time slot
    for i, slot_start in enumerate(time_slots):
        if i < len(time_slots) - 1:
            slot_end = time_slots[i + 1]
        else:
            slot_end = timezone.now()
        
        # Format the label
        labels.append(slot_start.strftime(chart_format))
        
        # Count requests in this time slot
        slot_requests = RequestLog.objects.filter(timestamp__gte=slot_start, timestamp__lt=slot_end)
        total_in_slot = slot_requests.count()
        blocked_in_slot = slot_requests.filter(was_blocked=True).count()
        
        all_requests_data.append(total_in_slot)
        blocked_requests_data.append(blocked_in_slot)
    
    # Prepare chart data for the template
    chart_data = {
        'labels': labels,
        'all_requests': all_requests_data,
        'blocked_requests': blocked_requests_data
    }
    
    context = {
        'settings': settings,
        'time_range': time_range,
        'total_requests': total_requests,
        'blocked_requests': blocked_requests,
        'request_change_pct': request_change_pct,
        'block_rate': round((blocked_requests / total_requests * 100) if total_requests else 0, 1),
        'avg_response_time': round(avg_response_time, 2),
        'active_rules': active_rules_count,
        'active_rules_list': active_rules_list,
        'recent_logs': recent_logs,
        'top_rules': top_rules,
        'top_blocked_ips': top_blocked_ips,
        'top_countries': top_countries,
        'recent_alerts': recent_alerts_count,
        'recent_alert_list': recent_alerts,
        'rule_trigger_count': sum(rule['count'] for rule in top_rules) if top_rules else 0,
        'chart_data': chart_data,
    }
    
    return render(request, 'dashboard/index.html', context)

@login_required
def metrics(request):
    """View showing detailed metrics and charts."""
    # Get time range from request or use default
    settings, created = DashboardSettings.objects.get_or_create(id=1)
    time_range = request.GET.get('range', settings.default_time_range)
    
    # Convert time range to start time
    if time_range == 'hour':
        start_time = timezone.now() - timedelta(hours=1)
        interval = 'minute'
    elif time_range == 'day':
        start_time = timezone.now() - timedelta(days=1)
        interval = 'hour'
    elif time_range == 'week':
        start_time = timezone.now() - timedelta(weeks=1)
        interval = 'day'
    elif time_range == 'month':
        start_time = timezone.now() - timedelta(days=30)
        interval = 'day'
    else:
        start_time = timezone.now() - timedelta(days=1)
        interval = 'hour'
    
    context = {
        'settings': settings,
        'time_range': time_range,
        'interval': interval,
    }
    
    return render(request, 'dashboard/metrics.html', context)

@login_required
def metrics_api(request):
    """API endpoint for retrieving metric data for charts."""
    # Get time range from request or use default
    settings, created = DashboardSettings.objects.get_or_create(id=1)
    time_range = request.GET.get('range', settings.default_time_range)
    metric_type = request.GET.get('metric', 'request_count')
    
    # Convert time range to start time
    if time_range == 'hour':
        start_time = timezone.now() - timedelta(hours=1)
    elif time_range == 'day':
        start_time = timezone.now() - timedelta(days=1)
    elif time_range == 'week':
        start_time = timezone.now() - timedelta(weeks=1)
    elif time_range == 'month':
        start_time = timezone.now() - timedelta(days=30)
    else:
        start_time = timezone.now() - timedelta(days=1)
    
    # Get metrics from database
    metrics = DashboardMetric.objects.filter(
        timestamp__gte=start_time,
        metric_type=metric_type
    ).order_by('timestamp')
    
    # Format data for chart
    data = {
        'labels': [m.timestamp.strftime('%Y-%m-%d %H:%M:%S') for m in metrics],
        'data': [m.value for m in metrics],
    }
    
    return JsonResponse(data)

@login_required
def geo_map(request):
    """View showing geographical distribution of requests."""
    # Get time range from request or use default
    settings, created = DashboardSettings.objects.get_or_create(id=1)
    time_range = request.GET.get('range', settings.default_time_range)
    
    # Convert time range to start time
    if time_range == 'hour':
        start_time = timezone.now() - timedelta(hours=1)
    elif time_range == 'day':
        start_time = timezone.now() - timedelta(days=1)
    elif time_range == 'week':
        start_time = timezone.now() - timedelta(weeks=1)
    elif time_range == 'month':
        start_time = timezone.now() - timedelta(days=30)
    else:
        start_time = timezone.now() - timedelta(days=1)
    
    # Get country distribution
    country_data = RequestLog.objects.filter(
        timestamp__gte=start_time,
        country__isnull=False
    ).values('country').annotate(
        count=Count('id')
    ).order_by('-count')
    
    # Prepare data for the map
    geo_data = {
        'type': 'FeatureCollection',
        'features': []
    }
    
    context = {
        'settings': settings,
        'time_range': time_range,
        'country_data': country_data,
        'geo_data': geo_data,
    }
    
    return render(request, 'dashboard/geo_map.html', context)

@login_required
def settings(request):
    """View for configuring dashboard settings."""
    settings_obj, created = DashboardSettings.objects.get_or_create(id=1)
    
    if request.method == 'POST':
        # Update settings based on form data
        settings_obj.refresh_interval = int(request.POST.get('refresh_interval', 30))
        settings_obj.default_time_range = request.POST.get('default_time_range', 'day')
        settings_obj.enable_geo_map = request.POST.get('enable_geo_map') == 'on'
        settings_obj.enable_realtime_alerts = request.POST.get('enable_realtime_alerts') == 'on'
        settings_obj.max_items_per_widget = int(request.POST.get('max_items_per_widget', 10))
        settings_obj.save()
        
        return redirect('dashboard:index')
    
    context = {
        'settings': settings_obj,
    }
    
    return render(request, 'dashboard/settings.html', context)

@login_required
def traffic_data_api(request):
    """API endpoint for retrieving real-time traffic data."""
    time_range = request.GET.get('range', 'day')
    
    # Calculate start time based on range
    if time_range == 'hour':
        start_time = timezone.now() - timedelta(hours=1)
        interval_unit = 'minute'
        chart_format = '%H:%M'
        intervals = 60
        timedelta_unit = timedelta(minutes=1)
    elif time_range == 'day':
        start_time = timezone.now() - timedelta(days=1)
        interval_unit = 'hour'
        chart_format = '%H:00'
        intervals = 24
        timedelta_unit = timedelta(hours=1)
    elif time_range == 'week':
        start_time = timezone.now() - timedelta(weeks=1)
        interval_unit = 'day'
        chart_format = '%a'
        intervals = 7
        timedelta_unit = timedelta(days=1)
    elif time_range == 'month':
        start_time = timezone.now() - timedelta(days=30)
        interval_unit = 'day'
        chart_format = '%d %b'
        intervals = 30
        timedelta_unit = timedelta(days=1)
    else:
        start_time = timezone.now() - timedelta(days=1)
        interval_unit = 'hour'
        chart_format = '%H:00'
        intervals = 24
        timedelta_unit = timedelta(hours=1)
    
    # Generate time slots
    time_slots = [(start_time + (i * timedelta_unit)) for i in range(intervals)]
    
    # Initialize data structures
    labels = []
    all_requests_data = []
    blocked_requests_data = []
    
    # Process each time slot
    for i, slot_start in enumerate(time_slots):
        if i < len(time_slots) - 1:
            slot_end = time_slots[i + 1]
        else:
            slot_end = timezone.now()
        
        # Format the label
        labels.append(slot_start.strftime(chart_format))
        
        # Count requests in this time slot
        slot_requests = RequestLog.objects.filter(timestamp__gte=slot_start, timestamp__lt=slot_end)
        total_in_slot = slot_requests.count()
        blocked_in_slot = slot_requests.filter(was_blocked=True).count()
        
        all_requests_data.append(total_in_slot)
        blocked_requests_data.append(blocked_in_slot)
    
    # Return data as JSON
    return JsonResponse({
        'labels': labels,
        'all_requests': all_requests_data,
        'blocked_requests': blocked_requests_data
    })
