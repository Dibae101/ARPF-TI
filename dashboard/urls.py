from django.urls import path
from . import views

app_name = 'dashboard'

urlpatterns = [
    path('', views.dashboard, name='index'),
    path('metrics/', views.metrics, name='metrics'),
    path('metrics/api/', views.metrics_api, name='metrics_api'),
    path('geo-map/', views.geo_map, name='geo_map'),
    path('settings/', views.settings, name='settings'),
    path('api/traffic-data/', views.traffic_data_api, name='traffic_data_api'),
]