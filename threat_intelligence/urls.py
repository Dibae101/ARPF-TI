from django.urls import path, re_path
from . import views

app_name = 'threat_intelligence'

urlpatterns = [
    # Main index page for threat intelligence
    path('', views.index, name='index'),
    # Traffic analysis
    path('analyze-traffic/', views.analyze_traffic, name='analyze_traffic'),
    # Source management
    path('sources/', views.sources_list, name='sources_list'),
    path('sources/add/', views.source_add, name='source_add'),
    path('sources/<int:source_id>/', views.source_detail, name='source_detail'),
    path('sources/<int:source_id>/edit/', views.source_edit, name='source_edit'),
    path('sources/<int:source_id>/delete/', views.source_delete, name='source_delete'),
    path('sources/<int:source_id>/update/', views.update_source_now, name='update_source_now'),
    # Entries
    path('entries/', views.entries_list, name='entries_list'),
    # Special actions for entries - these must come BEFORE the generic entry_detail pattern
    path('entries/<str:entry_id>/create-rule/', views.create_firewall_rule, name='create_firewall_rule'),
    path('entries/<str:entry_id>/toggle-status/', views.toggle_entry_status, name='toggle_entry_status'),
    # Support both UUID and integer IDs for entries - this must come AFTER the more specific patterns
    re_path(r'entries/(?P<entry_id>\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/', 
            views.entry_detail, name='entry_detail'),
    # Suggested rules
    path('suggested-rules/', views.suggested_rules_list, name='suggested_rules_list'),
    path('suggested-rules/<uuid:rule_id>/', views.suggested_rule_detail, name='suggested_rule_detail'),
    path('suggested-rules/bulk-actions/', views.bulk_action, name='bulk_action'),
    path('suggested-rules/<uuid:rule_id>/approve/', views.approve_rule, name='approve_rule'),
    path('suggested-rules/<uuid:rule_id>/reject/', views.reject_rule, name='reject_rule'),
]