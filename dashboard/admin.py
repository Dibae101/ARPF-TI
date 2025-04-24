from django.contrib import admin
from .models import DashboardMetric, GeoIPCache, DashboardSettings

@admin.register(DashboardMetric)
class DashboardMetricAdmin(admin.ModelAdmin):
    list_display = ('metric_type', 'value', 'aggregation_period', 'timestamp', 'dimension')
    list_filter = ('metric_type', 'aggregation_period')
    search_fields = ('dimension',)
    readonly_fields = ('timestamp',)
    ordering = ('-timestamp',)


@admin.register(GeoIPCache)
class GeoIPCacheAdmin(admin.ModelAdmin):
    list_display = ('ip_address', 'country_code', 'country_name', 'city', 'isp', 'last_updated')
    list_filter = ('country_code',)
    search_fields = ('ip_address', 'country_name', 'city', 'isp')
    readonly_fields = ('last_updated',)
    ordering = ('ip_address',)


@admin.register(DashboardSettings)
class DashboardSettingsAdmin(admin.ModelAdmin):
    list_display = ('id', 'refresh_interval', 'default_time_range', 'enable_geo_map', 'enable_realtime_alerts')
    readonly_fields = ('created_at', 'updated_at')
    
    def has_add_permission(self, request):
        # Only allow one settings object
        return DashboardSettings.objects.count() == 0
