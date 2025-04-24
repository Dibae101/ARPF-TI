from django.urls import path
from . import views

app_name = 'alerts'

urlpatterns = [
    path('', views.alert_list, name='alert_list'),
    path('<int:alert_id>/', views.alert_detail, name='alert_detail'),
    path('<int:alert_id>/acknowledge/', views.alert_acknowledge, name='alert_acknowledge'),
    path('configurations/', views.notification_config_list, name='notification_config_list'),
    path('configurations/add/', views.notification_config_add, name='notification_config_add'),
    path('configurations/<int:config_id>/', views.notification_config_edit, name='notification_config_edit'),
    path('configurations/<int:config_id>/delete/', views.notification_config_delete, name='notification_config_delete'),
    path('configurations/<int:config_id>/test/', views.notification_config_test, name='notification_config_test'),
]