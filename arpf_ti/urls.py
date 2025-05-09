"""
URL configuration for arpf_ti project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from core.views import login_view, logout_view, signup_view
from django.shortcuts import redirect

def logs_redirect(request):
    return redirect('core:log_list')

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('dashboard.urls')),
    path('core/', include('core.urls')),
    path('alerts/', include('alerts.urls')),
    path('threat-intelligence/', include('threat_intelligence.urls')),
    path('comparison/', include('comparison.urls')),  # Add the new comparison URLs
    
    # Authentication URLs
    path('accounts/login/', login_view, name='login'),
    path('accounts/logout/', logout_view, name='logout'),
    path('accounts/signup/', signup_view, name='signup'),
    
    # Redirect shortcuts
    path('logs/', logs_redirect, name='logs_redirect'),
]
