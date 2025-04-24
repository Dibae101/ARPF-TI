from django.urls import path
from . import views

app_name = 'threat_intelligence'

urlpatterns = [
    path('', views.dashboard, name='index'),  # Dashboard page is both index and dashboard
    path('dashboard/', views.dashboard, name='dashboard'),
    path('sources/', views.sources_list, name='sources_list'),
    path('sources/add/', views.source_add, name='source_add'),
    path('sources/<int:source_id>/', views.source_detail, name='source_detail'),
    path('sources/<int:source_id>/edit/', views.source_edit, name='source_edit'),
    path('sources/<int:source_id>/delete/', views.source_delete, name='source_delete'),
    path('entries/', views.entries_list, name='entries_list'),
    path('ai-models/', views.ai_models_list, name='ai_models_list'),  # Changed from ai_model_list to ai_models_list
    path('ai-models/add/', views.ai_model_add, name='ai_model_add'),
    path('ai-models/<int:model_id>/', views.ai_model_edit, name='ai_model_edit'),
    path('ai-models/<int:model_id>/delete/', views.ai_model_delete, name='ai_model_delete'),
    path('update-now/<int:source_id>/', views.update_source_now, name='update_source_now'),
]