from django.db import models
from django.utils import timezone

class DashboardMetric(models.Model):
    """
    Stores aggregated metrics for dashboard visualization
    """
    METRIC_TYPES = [
        ('request_count', 'Request Count'),
        ('blocked_count', 'Blocked Request Count'),
        ('country_distribution', 'Country Distribution'),
        ('rule_matches', 'Rule Match Count'),
        ('response_time', 'Average Response Time'),
        ('threat_score', 'Average Threat Score'),
        ('active_ips', 'Active IP Addresses')
    ]
    
    AGGREGATION_PERIODS = [
        ('minute', 'Per Minute'),
        ('hour', 'Hourly'),
        ('day', 'Daily'),
        ('week', 'Weekly'),
        ('month', 'Monthly')
    ]
    
    metric_type = models.CharField(max_length=30, choices=METRIC_TYPES)
    value = models.FloatField(default=0.0)
    aggregation_period = models.CharField(max_length=10, choices=AGGREGATION_PERIODS)
    timestamp = models.DateTimeField(default=timezone.now)
    dimension = models.CharField(max_length=255, blank=True, null=True, 
                               help_text="Optional dimension (e.g., country code, rule ID)")
    
    class Meta:
        indexes = [
            models.Index(fields=['metric_type', 'aggregation_period', 'timestamp']),
            models.Index(fields=['dimension']),
        ]
    
    def __str__(self):
        dimension_str = f" - {self.dimension}" if self.dimension else ""
        return f"{self.get_metric_type_display()} ({self.timestamp}){dimension_str}"


class GeoIPCache(models.Model):
    """
    Cache for GeoIP lookups to reduce external API calls
    """
    ip_address = models.GenericIPAddressField(unique=True)
    country_code = models.CharField(max_length=2, blank=True, null=True)
    country_name = models.CharField(max_length=255, blank=True, null=True)
    city = models.CharField(max_length=255, blank=True, null=True)
    latitude = models.FloatField(null=True, blank=True)
    longitude = models.FloatField(null=True, blank=True)
    isp = models.CharField(max_length=255, blank=True, null=True)
    last_updated = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        country = self.country_code or 'Unknown'
        return f"{self.ip_address} ({country})"


class DashboardSettings(models.Model):
    """
    Settings for the dashboard display
    """
    refresh_interval = models.IntegerField(default=30, help_text="Dashboard refresh interval in seconds")
    default_time_range = models.CharField(max_length=10, default='day',
                                        choices=[('hour', 'Last Hour'), 
                                                ('day', 'Last 24 Hours'),
                                                ('week', 'Last Week'),
                                                ('month', 'Last Month')])
    enable_geo_map = models.BooleanField(default=True)
    enable_realtime_alerts = models.BooleanField(default=True)
    max_items_per_widget = models.IntegerField(default=10)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name_plural = "Dashboard settings"
    
    def __str__(self):
        return f"Dashboard Settings (Updated: {self.updated_at})"
