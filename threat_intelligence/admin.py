from django.contrib import admin
from .models import ThreatIntelSource, ThreatIntelEntry, AIClassifierModel

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


@admin.register(AIClassifierModel)
class AIClassifierModelAdmin(admin.ModelAdmin):
    list_display = ('name', 'model_type', 'is_active', 'accuracy', 'updated_at')
    list_filter = ('model_type', 'is_active')
    search_fields = ('name', 'description', 'file_path')
    readonly_fields = ('created_at', 'updated_at')
    ordering = ('-updated_at',)
