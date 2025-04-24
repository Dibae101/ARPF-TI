from django.contrib import admin
from .models import Alert, AlertNotificationConfig

@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    list_display = ('title', 'alert_type', 'severity', 'source_ip', 'is_acknowledged', 'timestamp')
    list_filter = ('alert_type', 'severity', 'is_acknowledged')
    search_fields = ('title', 'description', 'source_ip')
    readonly_fields = ('timestamp', 'acknowledged_at')
    ordering = ('-timestamp',)
    filter_horizontal = ('related_logs',)


@admin.register(AlertNotificationConfig)
class AlertNotificationConfigAdmin(admin.ModelAdmin):
    list_display = ('name', 'notification_type', 'min_severity', 'is_active')
    list_filter = ('notification_type', 'min_severity', 'is_active')
    search_fields = ('name', 'recipients')
    ordering = ('name',)
