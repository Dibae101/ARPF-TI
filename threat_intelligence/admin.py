from django.contrib import admin
from .models import ThreatIntelSource, ThreatIntelEntry, SuggestedFirewallRule

@admin.register(ThreatIntelSource)
class ThreatIntelSourceAdmin(admin.ModelAdmin):
    list_display = ('name', 'source_type', 'is_active', 'last_updated')
    list_filter = ('source_type', 'is_active')
    search_fields = ('name', 'description', 'url')
    readonly_fields = ('last_updated',)
    ordering = ('name',)


@admin.register(ThreatIntelEntry)
class ThreatIntelEntryAdmin(admin.ModelAdmin):
    list_display = ('value', 'entry_type', 'source', 'category', 'confidence_score', 'is_active')
    list_filter = ('entry_type', 'source', 'is_active')
    search_fields = ('value', 'category')
    readonly_fields = ('first_seen', 'last_seen')
    ordering = ('-last_seen',)


@admin.register(SuggestedFirewallRule)
class SuggestedFirewallRuleAdmin(admin.ModelAdmin):
    list_display = ('rule_type', 'pattern', 'status', 'confidence', 'created_at')
    list_filter = ('rule_type', 'status')
    search_fields = ('pattern', 'description')
    readonly_fields = ('created_at', 'reviewed_at')
    ordering = ('-created_at',)
