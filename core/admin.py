from django.contrib import admin
from .models import Rule, RequestLog, ProxyConfig

@admin.register(Rule)
class RuleAdmin(admin.ModelAdmin):
    list_display = ('name', 'rule_type', 'action', 'priority', 'is_active')
    list_filter = ('rule_type', 'action', 'is_active')
    search_fields = ('name', 'pattern', 'description')
    ordering = ('priority', 'name')


@admin.register(RequestLog)
class RequestLogAdmin(admin.ModelAdmin):
    list_display = ('source_ip', 'path', 'method', 'was_blocked', 'response_code', 'timestamp')
    list_filter = ('method', 'was_blocked', 'action_taken')
    search_fields = ('source_ip', 'path', 'user_agent')
    readonly_fields = ('timestamp', 'source_ip', 'path', 'method', 'user_agent', 'headers', 
                      'matched_rule', 'action_taken', 'was_blocked', 'response_code', 
                      'response_time_ms', 'country')
    ordering = ('-timestamp',)


@admin.register(ProxyConfig)
class ProxyConfigAdmin(admin.ModelAdmin):
    list_display = ('name', 'target_host', 'target_port', 'use_https', 'is_active')
    list_filter = ('use_https', 'is_active')
    search_fields = ('name', 'target_host')
    ordering = ('name',)
