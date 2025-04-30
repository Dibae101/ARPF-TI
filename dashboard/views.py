from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.db.models import Count, Avg, Sum
from django.utils import timezone as django_timezone  # Renamed to avoid shadowing
from django.conf import settings as django_settings  # Added for accessing DEBUG setting
from datetime import timedelta
from math import sin  # Import sin function for sample data generation
import random
import logging

from .models import DashboardMetric, DashboardSettings
from core.models import RequestLog, Rule
from alerts.models import Alert

logger = logging.getLogger(__name__)

@login_required
def dashboard(request):
    """Main dashboard view showing overview of system status."""
    # Get dashboard settings
    settings, created = DashboardSettings.objects.get_or_create(id=1)
    
    # Calculate time range based on settings
    time_range = request.GET.get('range', settings.default_time_range)
    if time_range == 'hour':
        start_time = django_timezone.now() - timedelta(hours=1)
        interval_unit = 'minute'
        chart_format = '%H:%M'
    elif time_range == 'day':
        start_time = django_timezone.now() - timedelta(days=1)
        interval_unit = 'hour'
        chart_format = '%H:00'
    elif time_range == 'week':
        start_time = django_timezone.now() - timedelta(weeks=1)
        interval_unit = 'day'
        chart_format = '%a'
    elif time_range == 'month':
        start_time = django_timezone.now() - timedelta(days=30)
        interval_unit = 'day'
        chart_format = '%d %b'
    else:
        start_time = django_timezone.now() - timedelta(days=1)  # Default to last 24 hours
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
    
    # If there are no active rules, create some sample data for display
    if not active_rules_list and django_settings.DEBUG:
        sample_rules = []
        
        rule_names = [
            "Block SQL Injection Attempts", 
            "Rate Limit API Requests", 
            "Block Suspicious User Agents",
            "Prevent Path Traversal", 
            "Block XSS Attacks", 
            "Country Blocking"
        ]
        
        for i in range(6):
            rule = Rule(
                id=i+1,
                name=rule_names[i],
                description=f"Sample rule for {rule_names[i].lower()}",
                is_active=True,
                priority=random.choice([30, 50, 70, 90]),
                action="block" if random.random() > 0.3 else "log"
            )
            sample_rules.append(rule)
        
        active_rules_list = sample_rules
        active_rules_count = len(sample_rules)
    
    # Recent logs - add fallback for empty database
    recent_logs = RequestLog.objects.order_by('-timestamp')[:10]
    
    # If there are no logs, create some sample data for the display
    if not recent_logs.exists() and django_settings.DEBUG:
        # Create some example logs for demo purposes only
        import string
        
        # Sample methods, paths and IPs
        methods = ['GET', 'POST', 'PUT', 'DELETE']
        paths = ['/api/users', '/admin/login', '/dashboard', '/api/products', '/api/orders']
        ips = ['192.168.1.' + str(i) for i in range(1, 20)]
        
        # Generate sample data
        sample_logs = []
        for i in range(10):
            # Basic log info
            log = RequestLog(
                timestamp=django_timezone.now() - timedelta(minutes=random.randint(1, 60)),
                source_ip=random.choice(ips),
                method=random.choice(methods),
                path=random.choice(paths),
                status_code=random.choice([200, 200, 200, 404, 500, 403]),
                response_time_ms=random.randint(10, 1000),
                user_agent='Mozilla/5.0 (Example)',
                was_blocked=random.choice([True, False, False]),
                country=random.choice(['US', 'DE', 'GB', 'CN', 'RU', None])
            )
            sample_logs.append(log)
            
        # Use the sample logs instead
        recent_logs = sample_logs
    
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
    
    # Add fallback sample country data if none exists
    if not top_countries and django_settings.DEBUG:
        sample_countries = [
            {'country': 'US', 'request_count': 245},
            {'country': 'CN', 'request_count': 186},
            {'country': 'DE', 'request_count': 132},
            {'country': 'GB', 'request_count': 97},
            {'country': 'RU', 'request_count': 76}
        ]
        top_countries = sample_countries
    
    # Calculate percentages for countries
    if total_requests > 0:
        total_country_requests = sum(country['request_count'] for country in top_countries)
        for country in top_countries:
            country['percentage'] = round((country['request_count'] / max(total_country_requests, 1)) * 100)
            # Add country name and flag placeholder
            country['name'] = country['country'] or 'Unknown'
            # Add flag emojis
            flag_map = {
                'US': '🇺🇸', 'CN': '🇨🇳', 'DE': '🇩🇪', 'GB': '🇬🇧', 'RU': '🇷🇺',
                'JP': '🇯🇵', 'FR': '🇫🇷', 'BR': '🇧🇷', 'IN': '🇮🇳', 'CA': '🇨🇦'
            }
            country['flag'] = flag_map.get(country['country'], '🌍')
    
    # Recent alerts
    try:
        recent_alerts = Alert.objects.order_by('-timestamp')[:5]
        recent_alerts_count = Alert.objects.filter(timestamp__gte=start_time).count()
        
        # Add sample alert data if none exists
        if not recent_alerts and django_settings.DEBUG:
            sample_alert_titles = [
                "Unusual traffic spike detected",
                "Potential SQL injection attempt",
                "Brute force login attempt",
                "Suspicious IP activity",
                "XSS attack blocked"
            ]
            
            sample_severities = ['low', 'medium', 'high', 'critical']
            
            sample_alerts = []
            for i in range(5):
                alert = Alert(
                    id=i+1,
                    title=sample_alert_titles[i],
                    description=f"Sample alert for {sample_alert_titles[i].lower()}",
                    severity=sample_severities[random.randint(0, len(sample_severities)-1)],
                    timestamp=django_timezone.now() - timedelta(hours=random.randint(1, 24)),
                    resolved=random.choice([True, False, False])
                )
                sample_alerts.append(alert)
            
            recent_alerts = sample_alerts
            recent_alerts_count = len(sample_alerts)
    except Exception as e:
        # Handle case where Alert model might not exist or be accessible
        logger.error(f"Error fetching recent alerts: {str(e)}")
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
            slot_end = django_timezone.now()
        
        # Format the label
        labels.append(slot_start.strftime(chart_format))
        
        # Count requests in this time slot
        slot_requests = RequestLog.objects.filter(timestamp__gte=slot_start, timestamp__lt=slot_end)
        total_in_slot = slot_requests.count()
        blocked_in_slot = slot_requests.filter(was_blocked=True).count()
        
        all_requests_data.append(total_in_slot)
        blocked_requests_data.append(blocked_in_slot)
    
    # Prepare chart data for the template
    import json
    chart_data = {
        'labels': json.dumps(labels),
        'all_requests': json.dumps(all_requests_data),
        'blocked_requests': json.dumps(blocked_requests_data)
    }
    
    # Add fallback data for when JavaScript can't parse the JSON
    fallback_chart_data = {
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
        'fallback_chart_data': fallback_chart_data,
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
        start_time = django_timezone.now() - timedelta(hours=1)
        interval = 'minute'
    elif time_range == 'day':
        start_time = django_timezone.now() - timedelta(days=1)
        interval = 'hour'
    elif time_range == 'week':
        start_time = django_timezone.now() - timedelta(weeks=1)
        interval = 'day'
    elif time_range == 'month':
        start_time = django_timezone.now() - timedelta(days=30)
        interval = 'day'
    else:
        start_time = django_timezone.now() - timedelta(days=1)
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
        start_time = django_timezone.now() - timedelta(hours=1)
    elif time_range == 'day':
        start_time = django_timezone.now() - timedelta(days=1)
    elif time_range == 'week':
        start_time = django_timezone.now() - timedelta(weeks=1)
    elif time_range == 'month':
        start_time = django_timezone.now() - timedelta(days=30)
    else:
        start_time = django_timezone.now() - timedelta(days=1)
    
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
        start_time = django_timezone.now() - timedelta(hours=1)
        interval_unit = 'minute'
        chart_format = '%H:%M'
        intervals = 60
        timedelta_unit = timedelta(minutes=1)
    elif time_range == 'day':
        start_time = django_timezone.now() - timedelta(days=1)
        interval_unit = 'hour'
        chart_format = '%H:00'
        intervals = 24
        timedelta_unit = timedelta(hours=1)
    elif time_range == 'week':
        start_time = django_timezone.now() - timedelta(weeks=1)
        interval_unit = 'day'
        chart_format = '%a'
        intervals = 7
        timedelta_unit = timedelta(days=1)
    elif time_range == 'month':
        start_time = django_timezone.now() - timedelta(days=30)
        interval_unit = 'day'
        chart_format = '%d %b'
        intervals = 30
        timedelta_unit = timedelta(days=1)
    else:
        start_time = django_timezone.now() - timedelta(days=1)
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
            slot_end = django_timezone.now()
        
        # Format the label
        labels.append(slot_start.strftime(chart_format))
        
        # Count requests in this time slot
        slot_requests = RequestLog.objects.filter(timestamp__gte=slot_start, timestamp__lt=slot_end)
        total_in_slot = slot_requests.count()
        blocked_in_slot = slot_requests.filter(was_blocked=True).count()
        
        all_requests_data.append(total_in_slot)
        blocked_requests_data.append(blocked_in_slot)
    
    # If we have no data, generate sample data based on the time period
    if sum(all_requests_data) == 0 and django_settings.DEBUG:
        # Generate sample data appropriate for each time range
        if time_range == 'hour':
            base_requests = 5
            peak_factor = 3
        elif time_range == 'day':
            base_requests = 20
            peak_factor = 5
        elif time_range == 'week':
            base_requests = 50
            peak_factor = 3
        else:  # month
            base_requests = 100
            peak_factor = 2
        
        # Generate more realistic sample data with patterns
        for i in range(len(labels)):
            # Create a pattern with higher values in the middle of the period
            pattern_factor = 1 + abs(sin(i / len(labels) * 3.14)) * peak_factor
            
            # Add some randomness
            requests = int(base_requests * pattern_factor * (0.7 + random.random() * 0.6))
            blocked = int(requests * random.uniform(0.1, 0.3))
            
            all_requests_data[i] = requests
            blocked_requests_data[i] = blocked
    
    # Return data as JSON
    return JsonResponse({
        'labels': labels,
        'all_requests': all_requests_data,
        'blocked_requests': blocked_requests_data,
        'time_range': time_range
    })
