from django.urls import path
from . import views

app_name = 'core'

urlpatterns = [
    # Rules management
    path('rules/', views.rule_list, name='rule_list'),
    path('rules/add/', views.rule_add, name='rule_add'),
    path('rules/<int:rule_id>/', views.rule_detail, name='rule_detail'),
    path('rules/<int:rule_id>/edit/', views.rule_edit, name='rule_edit'),
    path('rules/<int:rule_id>/delete/', views.rule_delete, name='rule_delete'),
    
    # Logs management
    path('logs/', views.log_list, name='log_list'),
    path('logs/<int:log_id>/', views.log_detail, name='log_detail'),
    
    # Proxy configuration
    path('proxy/configs/', views.proxy_config_list, name='proxy_config_list'),
    path('proxy/configs/add/', views.proxy_config_add, name='proxy_config_add'),
    path('proxy/configs/<int:config_id>/edit/', views.proxy_config_edit, name='proxy_config_edit'),
    path('proxy/configs/<int:config_id>/delete/', views.proxy_config_delete, name='proxy_config_delete'),
]