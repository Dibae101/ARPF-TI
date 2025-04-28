from django.urls import path
from . import views

app_name = 'threat_intelligence'

urlpatterns = [
    # Existing URLs
    path('', views.dashboard, name='dashboard'),
    path('', views.dashboard, name='index'),  # Add an alias for the 'index' name
    path('sources/', views.sources_list, name='sources_list'),
    path('sources/add/', views.source_add, name='source_add'),
    path('sources/<int:source_id>/', views.source_detail, name='source_detail'),
    path('sources/<int:source_id>/edit/', views.source_edit, name='source_edit'),
    path('sources/<int:source_id>/delete/', views.source_delete, name='source_delete'),
    path('sources/<int:source_id>/update-now/', views.update_source_now, name='update_source_now'),
    path('entries/', views.entries_list, name='entries_list'),
    path('entries/<int:entry_id>/', views.entry_detail, name='entry_detail'),  # Added missing entry_detail URL
    path('ai-models/', views.ai_models_list, name='ai_models_list'),
    path('ai-models/add/', views.ai_model_add, name='ai_model_add'),
    path('ai-models/<int:model_id>/edit/', views.ai_model_edit, name='ai_model_edit'),
    path('ai-models/<int:model_id>/delete/', views.ai_model_delete, name='ai_model_delete'),
    
    # Firewall Rules URLs
    path('firewall-rules/', views.firewall_rules_list, name='firewall_rules_list'),
    path('firewall-rules/add/', views.firewall_rule_add, name='firewall_rule_add'),
    path('firewall-rules/<uuid:rule_id>/', views.firewall_rule_detail, name='firewall_rule_detail'),
    path('firewall-rules/<uuid:rule_id>/edit/', views.firewall_rule_edit, name='firewall_rule_edit'),
    path('firewall-rules/<uuid:rule_id>/delete/', views.firewall_rule_delete, name='firewall_rule_delete'),
    path('firewall-rules/<uuid:rule_id>/toggle/', views.firewall_rule_toggle, name='firewall_rule_toggle'),
    path('firewall-rules/import/', views.firewall_rule_import, name='firewall_rule_import'),
    path('firewall-rules/export/', views.firewall_rules_export, name='firewall_rules_export'),
    path('firewall-rules/presets/', views.firewall_presets, name='firewall_presets'),
]