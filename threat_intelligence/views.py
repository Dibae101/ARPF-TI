from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib import messages
from django.core.paginator import Paginator
from django.http import JsonResponse, HttpResponseRedirect
from django.urls import reverse
from django.utils import timezone
from .models import ThreatIntelEntry, ThreatIntelSource, SuggestedFirewallRule
from core.models import Rule as FirewallRule, RequestLog
from .forms import SourceForm
from .traffic_analyzer import traffic_analyzer

@login_required
def index(request):
    """Main dashboard for the threat intelligence module"""
    # Get most recent threat intelligence entries - focus on real traffic-based entries
    recent_entries = ThreatIntelEntry.objects.filter(
        is_active=True, 
        is_test_data=False,
        # Prioritize entries from traffic analysis sources
        source__name__startswith='Traffic Analysis'
    ).order_by('-last_seen')[:10]
    
    # If no traffic-based entries exist, fall back to other real (non-test) entries
    if not recent_entries:
        recent_entries = ThreatIntelEntry.objects.filter(
            is_active=True, 
            is_test_data=False
        ).order_by('-last_seen')[:10]
    
    # Get configured threat intelligence sources
    sources = ThreatIntelSource.objects.filter(is_active=True)
    
    # Get counts for dashboard stats - exclude test data
    total_entries = ThreatIntelEntry.objects.filter(is_active=True, is_test_data=False).count()
    recent_entries_count = ThreatIntelEntry.objects.filter(
        is_active=True, 
        is_test_data=False,
        last_seen__gte=timezone.now() - timezone.timedelta(days=7)
    ).count()
    
    # Get counts specific to traffic analysis
    traffic_analysis_entries = ThreatIntelEntry.objects.filter(
        source__name__startswith='Traffic Analysis',
        is_active=True
    ).count()
    
    # Get suggested rules stats
    pending_rules = SuggestedFirewallRule.objects.filter(status='pending').count()
    
    # Get sources stats for the template
    sources_count = ThreatIntelSource.objects.count()
    active_sources_count = ThreatIntelSource.objects.filter(is_active=True).count()
    recent_updates_count = ThreatIntelEntry.objects.filter(
        is_test_data=False,
        last_seen__gte=timezone.now() - timezone.timedelta(hours=24)
    ).count()
    high_confidence_count = ThreatIntelEntry.objects.filter(is_test_data=False, confidence_score__gte=0.75).count()
    
    # Get recent sources for the dashboard
    recent_sources = ThreatIntelSource.objects.all().order_by('-last_updated')[:5]
    
    # Check when traffic analysis was last run
    traffic_analysis_sources = ThreatIntelSource.objects.filter(name__startswith='Traffic Analysis')
    last_traffic_analysis = None
    if traffic_analysis_sources.exists():
        last_traffic_analysis = traffic_analysis_sources.order_by('-last_updated').first().last_updated
    
    context = {
        'recent_entries': recent_entries,
        'sources': sources,
        'total_entries': total_entries,
        'recent_entries_count': recent_entries_count,
        'traffic_analysis_entries': traffic_analysis_entries,
        'pending_rules': pending_rules,
        'sources_count': sources_count,
        'active_sources_count': active_sources_count,
        'entries_count': total_entries,
        'recent_updates_count': recent_updates_count,
        'high_confidence_count': high_confidence_count,
        'recent_sources': recent_sources,
        'last_traffic_analysis': last_traffic_analysis,
    }
    
    return render(request, 'threat_intelligence/index.html', context)

@login_required
def sources_list(request):
    """View to list all threat intelligence sources"""
    sources = ThreatIntelSource.objects.all().order_by('-is_active', 'name')
    
    paginator = Paginator(sources, 20)  # Show 20 sources per page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    context = {
        'page_obj': page_obj,
    }
    
    return render(request, 'threat_intelligence/sources_list.html', context)

@login_required
@user_passes_test(lambda u: u.is_staff)
def source_add(request):
    """View to add a new threat intelligence source"""
    # Check if user is applying a recommendation
    recommendation_id = request.GET.get('recommendation')
    
    if request.method == 'POST':
        form = SourceForm(request.POST)
        if form.is_valid():
            source = form.save(commit=False)
            source.created_by = request.user.username
            source.save()
            messages.success(request, f"Source '{source.name}' created successfully.")
            return redirect('threat_intelligence:sources_list')
    else:
        # Check if recommended source should be pre-filled
        initial_data = {}
        if recommendation_id:
            try:
                # Get AI recommendations
                recommendations = traffic_analyzer.get_source_recommendations()
                
                # Find the selected recommendation
                if recommendations and 0 <= int(recommendation_id) < len(recommendations):
                    recommended_source = recommendations[int(recommendation_id)]
                    initial_data = {
                        'name': recommended_source['name'],
                        'source_type': recommended_source['source_type'],
                        'description': recommended_source['description'],
                        'url': recommended_source['url'],
                        'is_active': True,
                    }
                    messages.info(request, f"Form pre-filled with AI-recommended source: {recommended_source['name']}")
            except (ValueError, IndexError) as e:
                pass
                
        form = SourceForm(initial=initial_data)
    
    # Get AI recommendations based on recent traffic
    recommendations = traffic_analyzer.get_source_recommendations()
    
    context = {
        'form': form,
        'title': 'Add Threat Intelligence Source',
        'recommendations': recommendations,
        'source_types': dict(ThreatIntelSource.SOURCE_TYPES),
    }
    
    return render(request, 'threat_intelligence/source_form.html', context)

@login_required
def source_detail(request, source_id):
    """View to show details of a threat intelligence source"""
    source = get_object_or_404(ThreatIntelSource, id=source_id)
    
    # Get recent entries from this source - exclude test data
    entries = ThreatIntelEntry.objects.filter(source=source, is_test_data=False).order_by('-last_seen')[:20]
    
    # Get stats - exclude test data
    entry_count = ThreatIntelEntry.objects.filter(source=source, is_test_data=False).count()
    active_entry_count = ThreatIntelEntry.objects.filter(source=source, is_active=True, is_test_data=False).count()
    
    context = {
        'source': source,
        'entries': entries,
        'entry_count': entry_count,
        'active_entry_count': active_entry_count,
    }
    
    return render(request, 'threat_intelligence/source_detail.html', context)

@login_required
def entries_list(request):
    """View to list all threat intelligence entries with filtering options"""
    # Apply filters
    entry_type_filter = request.GET.get('entry_type', '')
    category_filter = request.GET.get('category', '')
    source_filter = request.GET.get('source', '')
    min_confidence = request.GET.get('min_confidence', 0)
    
    # Start with all non-test entries
    entries = ThreatIntelEntry.objects.filter(is_test_data=False)
    
    if entry_type_filter:
        entries = entries.filter(entry_type=entry_type_filter)
    if category_filter:
        entries = entries.filter(category=category_filter)
    if source_filter:
        entries = entries.filter(source_id=source_filter)
    if min_confidence:
        entries = entries.filter(confidence_score__gte=min_confidence)
    
    # Default sorting by newest first
    entries = entries.order_by('-last_seen')
    
    paginator = Paginator(entries, 20)  # Show 20 entries per page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    # Get filters for template - also exclude test data from these options
    sources = ThreatIntelSource.objects.all()
    entry_types = ThreatIntelEntry.objects.filter(is_test_data=False).values_list('entry_type', flat=True).distinct()
    categories = ThreatIntelEntry.objects.filter(is_test_data=False).values_list('category', flat=True).distinct()
    
    context = {
        'page_obj': page_obj,
        'sources': sources,
        'entry_types': entry_types,
        'categories': categories,
        'entry_type_filter': entry_type_filter,
        'category_filter': category_filter,
        'source_filter': source_filter,
        'min_confidence': min_confidence,
    }
    
    return render(request, 'threat_intelligence/entries_list.html', context)

@login_required
def entry_detail(request, entry_id):
    """View to show details of a threat intelligence entry"""
    entry = get_object_or_404(ThreatIntelEntry, id=entry_id)
    
    context = {
        'entry': entry,
    }
    
    return render(request, 'threat_intelligence/entry_detail.html', context)

@login_required
@user_passes_test(lambda u: u.is_staff)
def suggested_rules_list(request):
    """View to list all suggested firewall rules with filtering options"""
    status_filter = request.GET.get('status', '')
    rule_type_filter = request.GET.get('rule_type', '')
    min_confidence = request.GET.get('min_confidence', 0)
    
    rules = SuggestedFirewallRule.objects.all()
    
    if status_filter:
        rules = rules.filter(status=status_filter)
    if rule_type_filter:
        rules = rules.filter(rule_type=rule_type_filter)
    if min_confidence:
        rules = rules.filter(confidence__gte=min_confidence)
    
    # Default sorting by newest first
    rules = rules.order_by('-created_at')
    
    paginator = Paginator(rules, 20)  # Show 20 rules per page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    context = {
        'page_obj': page_obj,
        'status_filter': status_filter,
        'rule_type_filter': rule_type_filter,
        'min_confidence': min_confidence,
        'status_choices': SuggestedFirewallRule.STATUS_CHOICES,
        'rule_type_choices': SuggestedFirewallRule.RULE_TYPE_CHOICES,
    }
    
    return render(request, 'threat_intelligence/suggested_rules_list.html', context)

@login_required
@user_passes_test(lambda u: u.is_staff)
def suggested_rule_detail(request, rule_id):
    """View to show details of a suggested rule and approve/reject it"""
    rule = get_object_or_404(SuggestedFirewallRule, id=rule_id)
    
    if request.method == 'POST':
        action = request.POST.get('action')
        
        if action == 'approve':
            firewall_rule = rule.approve(request.user)
            messages.success(request, f"Rule approved and firewall rule created: {firewall_rule}")
            return redirect('threat_intelligence:suggested_rules_list')
        
        elif action == 'reject':
            rule.reject(request.user)
            messages.success(request, f"Rule rejected: {rule}")
            return redirect('threat_intelligence:suggested_rules_list')
    
    context = {
        'rule': rule,
    }
    
    return render(request, 'threat_intelligence/suggested_rule_detail.html', context)

@login_required
@user_passes_test(lambda u: u.is_staff)
def approve_rule(request, rule_id):
    """Quick approve a rule from the list view"""
    if request.method == 'POST':
        rule = get_object_or_404(SuggestedFirewallRule, id=rule_id)
        firewall_rule = rule.approve(request.user)
        messages.success(request, f"Rule approved and firewall rule created: {firewall_rule}")
    
    return redirect('threat_intelligence:suggested_rules_list')

@login_required
@user_passes_test(lambda u: u.is_staff)
def reject_rule(request, rule_id):
    """Quick reject a rule from the list view"""
    if request.method == 'POST':
        rule = get_object_or_404(SuggestedFirewallRule, id=rule_id)
        rule.reject(request.user)
        messages.success(request, f"Rule rejected: {rule}")
    
    return redirect('threat_intelligence:suggested_rules_list')

@login_required
@user_passes_test(lambda u: u.is_staff)
def bulk_action(request):
    """Handle bulk actions on multiple suggested rules"""
    if request.method == 'POST':
        rule_ids = request.POST.getlist('rule_ids')
        action = request.POST.get('bulk_action')
        
        if not rule_ids:
            messages.error(request, "No rules selected")
            return redirect('threat_intelligence:suggested_rules_list')
        
        rules = SuggestedFirewallRule.objects.filter(id__in=rule_ids)
        
        if action == 'approve':
            for rule in rules:
                rule.approve(request.user)
            messages.success(request, f"{len(rules)} rules approved and firewall rules created")
        
        elif action == 'reject':
            for rule in rules:
                rule.reject(request.user)
            messages.success(request, f"{len(rules)} rules rejected")
    
    return redirect('threat_intelligence:suggested_rules_list')

@login_required
@user_passes_test(lambda u: u.is_staff)
def update_source_now(request, source_id):
    """Manually trigger an update for a threat intelligence source"""
    source = get_object_or_404(ThreatIntelSource, id=source_id)
    
    try:
        # Here we would normally call the actual update function that fetches data
        # For now, we'll just update the last_updated timestamp
        source.last_updated = timezone.now()
        source.save()
        
        # This is a placeholder for the actual update logic
        # In a real implementation, you would call something like:
        # from .fetcher import update_source
        # update_count = update_source(source)
        update_count = 0
        
        messages.success(
            request, 
            f"Source '{source.name}' updated successfully. {update_count} new entries."
        )
    except Exception as e:
        messages.error(
            request, 
            f"Error updating source '{source.name}': {str(e)}"
        )
    
    return redirect('threat_intelligence:source_detail', source_id=source.id)

@login_required
@user_passes_test(lambda u: u.is_staff)
def source_edit(request, source_id):
    """View to edit a threat intelligence source"""
    source = get_object_or_404(ThreatIntelSource, id=source_id)
    
    if request.method == 'POST':
        form = SourceForm(request.POST, instance=source)
        if form.is_valid():
            form.save()
            messages.success(request, f"Source '{source.name}' updated successfully.")
            return redirect('threat_intelligence:source_detail', source_id=source.id)
    else:
        form = SourceForm(instance=source)
    
    context = {
        'form': form,
        'source': source,
        'title': f'Edit Source: {source.name}',
    }
    
    return render(request, 'threat_intelligence/source_form.html', context)

@login_required
@user_passes_test(lambda u: u.is_staff)
def source_delete(request, source_id):
    """View to delete a threat intelligence source"""
    source = get_object_or_404(ThreatIntelSource, id=source_id)
    
    if request.method == 'POST':
        # Store the name for the success message
        source_name = source.name
        
        # Delete entries first to avoid foreign key constraint errors
        # Using a separate variable to avoid modifying the QuerySet during iteration
        entries = ThreatIntelEntry.objects.filter(source=source)
        entries_count = entries.count()
        entries.delete()
        
        # Then delete the source
        source.delete()
        
        messages.success(
            request, 
            f"Source '{source_name}' and {entries_count} associated entries deleted successfully."
        )
        return redirect('threat_intelligence:sources_list')
    
    context = {
        'source': source,
        'entry_count': ThreatIntelEntry.objects.filter(source=source).count(),
    }
    
    return render(request, 'threat_intelligence/source_confirm_delete.html', context)

@login_required
@user_passes_test(lambda u: u.is_staff)
def create_firewall_rule(request, entry_id):
    """Create a firewall rule based on a threat intelligence entry"""
    entry = get_object_or_404(ThreatIntelEntry, id=entry_id)
    
    if request.method == 'POST':
        # Create a new firewall rule based on the entry
        rule_type = 'ip' if entry.entry_type == 'ip' else 'custom'
        
        # Map entry types to rule types
        entry_to_rule_type = {
            'ip': 'ip',
            'ip_range': 'ip_range',
            'domain': 'domain',
            'hash': 'custom',
            'country': 'country'
        }
        
        rule_type = entry_to_rule_type.get(entry.entry_type, 'custom')
        
        # Create the firewall rule
        rule = FirewallRule(
            name=f"TI Rule: {entry.value[:30]}",
            description=f"Automatically created from threat intelligence entry. Source: {entry.source.name}",
            rule_type=rule_type,
            pattern=entry.value,
            action='block',
            is_active=True,
            priority=50  # Medium priority
        )
        rule.save()
        
        messages.success(request, f"Firewall rule created successfully: {rule.name}")
        return redirect('threat_intelligence:entry_detail', entry_id=entry.id)
    
    # Show confirmation page for GET requests
    context = {
        'entry': entry,
    }
    
    return render(request, 'threat_intelligence/create_firewall_rule.html', context)

@login_required
@user_passes_test(lambda u: u.is_staff)
def toggle_entry_status(request, entry_id):
    """Toggle the active status of a threat intelligence entry"""
    entry = get_object_or_404(ThreatIntelEntry, id=entry_id)
    
    if request.method == 'POST':
        # Toggle the is_active status
        entry.is_active = not entry.is_active
        entry.save()
        
        status_message = "activated" if entry.is_active else "deactivated"
        messages.success(request, f"Entry {status_message} successfully: {entry.value}")
        return redirect('threat_intelligence:entry_detail', entry_id=entry.id)
    
    # Show confirmation page for GET requests
    action = "deactivate" if entry.is_active else "activate"
    
    context = {
        'entry': entry,
        'action': action
    }
    
    return render(request, 'threat_intelligence/toggle_entry_status.html', context)

@login_required
@user_passes_test(lambda u: u.is_staff)
def analyze_traffic(request):
    """Run traffic analysis to generate threat intelligence from real traffic"""
    # Default to 7 days if not specified
    days_back = request.GET.get('days', 7)
    try:
        days_back = int(days_back)
    except ValueError:
        days_back = 7
    
    try:
        # Run the traffic analysis using ARPF Defense
        results = traffic_analyzer.analyze_logs(days=days_back)
        
        # Update timestamps for the Traffic Analysis sources
        for source in ThreatIntelSource.objects.filter(name__startswith='Traffic Analysis'):
            source.last_updated = timezone.now()
            source.save()
        
        messages.success(
            request, 
            f"ARPF Defense traffic analysis completed successfully! Analyzed {results['total_logs_analyzed']} requests, "
            f"identified {results['potential_threats_found']} potential threats. "
            f"Created {results['threat_intel_entries_created']} new threat intelligence entries and "
            f"{results.get('suggested_rules_created', 0)} suggested firewall rules."
        )
        
    except Exception as e:
        messages.error(
            request, 
            f"Error running ARPF Defense traffic analysis: {str(e)}"
        )
    
    return redirect('threat_intelligence:index')
