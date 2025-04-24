from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.http import JsonResponse
from .models import Rule, RequestLog, ProxyConfig
from .forms import RuleForm, ProxyConfigForm
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.forms import AuthenticationForm

@login_required
def rule_list(request):
    """Display a list of all firewall rules."""
    rules = Rule.objects.all().order_by('priority')
    return render(request, 'core/rules/list.html', {'rules': rules})

@login_required
def rule_add(request):
    """Add a new firewall rule."""
    if request.method == 'POST':
        form = RuleForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, 'Rule created successfully.')
            return redirect('core:rule_list')
    else:
        form = RuleForm()
    
    return render(request, 'core/rule_form.html', {'form': form, 'title': 'Add Rule'})

@login_required
def rule_detail(request, rule_id):
    """Display details of a specific rule."""
    rule = get_object_or_404(Rule, id=rule_id)
    matched_logs = RequestLog.objects.filter(matched_rule=rule).order_by('-timestamp')[:50]
    
    return render(request, 'core/rules/detail.html', {
        'rule': rule,
        'matched_logs': matched_logs
    })

@login_required
def rule_edit(request, rule_id):
    """Edit an existing firewall rule."""
    rule = get_object_or_404(Rule, id=rule_id)
    
    if request.method == 'POST':
        form = RuleForm(request.POST, instance=rule)
        if form.is_valid():
            form.save()
            messages.success(request, 'Rule updated successfully.')
            return redirect('core:rule_detail', rule_id=rule.id)
    else:
        form = RuleForm(instance=rule)
    
    return render(request, 'core/rule_form.html', {
        'form': form,
        'title': 'Edit Rule',
        'rule': rule
    })

@login_required
def rule_delete(request, rule_id):
    """Delete a firewall rule."""
    rule = get_object_or_404(Rule, id=rule_id)
    
    if request.method == 'POST':
        rule.delete()
        messages.success(request, 'Rule deleted successfully.')
        return redirect('core:rule_list')
    
    return render(request, 'core/rule_confirm_delete.html', {'rule': rule})

@login_required
def log_list(request):
    """Display a list of request logs with filtering options."""
    logs = RequestLog.objects.all().order_by('-timestamp')
    
    # Filtering options
    ip_filter = request.GET.get('ip')
    path_filter = request.GET.get('path')
    blocked_filter = request.GET.get('blocked')
    
    if ip_filter:
        logs = logs.filter(source_ip__icontains=ip_filter)
    
    if path_filter:
        logs = logs.filter(path__icontains=path_filter)
    
    if blocked_filter:
        logs = logs.filter(was_blocked=(blocked_filter == '1'))
    
    # Pagination
    paginator = Paginator(logs, 50)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    return render(request, 'core/logs/list.html', {
        'page_obj': page_obj,
        'ip_filter': ip_filter,
        'path_filter': path_filter,
        'blocked_filter': blocked_filter
    })

@login_required
def log_detail(request, log_id):
    """Display details of a specific request log."""
    log = get_object_or_404(RequestLog, id=log_id)
    return render(request, 'core/log_detail.html', {'log': log})

@login_required
def proxy_config_list(request):
    """Display a list of proxy configurations."""
    configs = ProxyConfig.objects.all()
    return render(request, 'core/proxy_config_list.html', {'configs': configs})

@login_required
def proxy_config_add(request):
    """Add a new proxy configuration."""
    if request.method == 'POST':
        form = ProxyConfigForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, 'Proxy configuration created successfully.')
            return redirect('core:proxy_config_list')
    else:
        form = ProxyConfigForm()
    
    return render(request, 'core/proxy_config_form.html', {
        'form': form,
        'title': 'Add Proxy Configuration'
    })

@login_required
def proxy_config_edit(request, config_id):
    """Edit an existing proxy configuration."""
    config = get_object_or_404(ProxyConfig, id=config_id)
    
    if request.method == 'POST':
        form = ProxyConfigForm(request.POST, instance=config)
        if form.is_valid():
            form.save()
            messages.success(request, 'Proxy configuration updated successfully.')
            return redirect('core:proxy_config_list')
    else:
        form = ProxyConfigForm(instance=config)
    
    return render(request, 'core/proxy_config_form.html', {
        'form': form,
        'title': 'Edit Proxy Configuration',
        'config': config
    })

@login_required
def proxy_config_delete(request, config_id):
    """Delete a proxy configuration."""
    config = get_object_or_404(ProxyConfig, id=config_id)
    
    if request.method == 'POST':
        config.delete()
        messages.success(request, 'Proxy configuration deleted successfully.')
        return redirect('core:proxy_config_list')
    
    return render(request, 'core/proxy_config_confirm_delete.html', {'config': config})

def login_view(request):
    """Handle user login"""
    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(username=username, password=password)
            if user is not None:
                login(request, user)
                messages.success(request, f"Welcome back, {username}!")
                next_url = request.GET.get('next', 'dashboard:index')
                return redirect(next_url)
            else:
                messages.error(request, "Invalid username or password.")
        else:
            messages.error(request, "Invalid username or password.")
    else:
        form = AuthenticationForm()
    return render(request, 'accounts/login.html', {'form': form})

def logout_view(request):
    """Handle user logout"""
    logout(request)
    messages.success(request, "You have been logged out.")
    return redirect('dashboard:index')
