from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.core.paginator import Paginator
from django.http import JsonResponse, HttpResponseRedirect
from django.urls import reverse
from django.db.models import Q, Count
from django.utils import timezone
from django.views.decorators.http import require_POST
from django.contrib.auth.decorators import login_required
from .models import ThreatIntelSource, ThreatIntelEntry, AIClassifierModel, FirewallRule
from .forms import SourceForm, AIModelForm, EntryFilterForm
import datetime
import json
import csv
from io import StringIO
import os
import uuid
from .fetcher import threat_intel_fetcher

# Create directory for model files if it doesn't exist
MODEL_FILES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'threat_intelligence', 'model_files')
os.makedirs(MODEL_FILES_DIR, exist_ok=True)

@login_required
def sources_list(request):
    """Display a list of all threat intelligence sources."""
    sources = ThreatIntelSource.objects.all().order_by('name')
    
    # Count entries for each source
    for source in sources:
        source.entry_count = ThreatIntelEntry.objects.filter(source=source).count()
    
    return render(request, 'threat_intelligence/sources_list.html', {'sources': sources})

@login_required
def source_add(request):
    """Add a new threat intelligence source."""
    if request.method == 'POST':
        name = request.POST.get('name')
        description = request.POST.get('description')
        source_type = request.POST.get('source_type')
        url = request.POST.get('url')
        api_key = request.POST.get('api_key')
        update_frequency = int(request.POST.get('update_frequency', 86400))
        
        source = ThreatIntelSource(
            name=name,
            description=description,
            source_type=source_type,
            url=url,
            api_key=api_key,
            update_frequency=update_frequency,
            is_active=True
        )
        source.save()
        
        # Schedule the source for updates
        threat_intel_fetcher._schedule_source(source)
        
        messages.success(request, 'Threat intelligence source added successfully.')
        return redirect('threat_intelligence:sources_list')
    
    context = {
        'source_types': ThreatIntelSource.SOURCE_TYPES
    }
    
    return render(request, 'threat_intelligence/source_form.html', context)

@login_required
def source_detail(request, source_id):
    """Display details about a specific threat intelligence source."""
    source = get_object_or_404(ThreatIntelSource, id=source_id)
    
    # Get recent entries for this source
    recent_entries = ThreatIntelEntry.objects.filter(source=source).order_by('-last_seen')[:100]
    
    # Get entry count by type
    entry_counts = (
        ThreatIntelEntry.objects.filter(source=source)
        .values('entry_type')
        .annotate(count=Count('id'))
    )
    
    context = {
        'source': source,
        'recent_entries': recent_entries,
        'entry_counts': entry_counts,
        'entry_types': ThreatIntelEntry.ENTRY_TYPES
    }
    
    return render(request, 'threat_intelligence/source_detail.html', context)

@login_required
def source_edit(request, source_id):
    """Edit an existing threat intelligence source."""
    source = get_object_or_404(ThreatIntelSource, id=source_id)
    
    if request.method == 'POST':
        source.name = request.POST.get('name')
        source.description = request.POST.get('description')
        source.source_type = request.POST.get('source_type')
        source.url = request.POST.get('url')
        source.api_key = request.POST.get('api_key')
        source.update_frequency = int(request.POST.get('update_frequency', 86400))
        source.is_active = request.POST.get('is_active') == 'on'
        source.save()
        
        # Reschedule the source for updates if active
        if source.is_active:
            threat_intel_fetcher._schedule_source(source)
        
        messages.success(request, 'Threat intelligence source updated successfully.')
        return redirect('threat_intelligence:source_detail', source_id=source.id)
    
    context = {
        'source': source,
        'source_types': ThreatIntelSource.SOURCE_TYPES
    }
    
    return render(request, 'threat_intelligence/source_form.html', context)

@login_required
def source_delete(request, source_id):
    """Delete a threat intelligence source."""
    source = get_object_or_404(ThreatIntelSource, id=source_id)
    
    if request.method == 'POST':
        # Delete all entries for this source
        ThreatIntelEntry.objects.filter(source=source).delete()
        
        # Delete the source
        source.delete()
        
        messages.success(request, 'Threat intelligence source deleted successfully.')
        return redirect('threat_intelligence:sources_list')
    
    return render(request, 'threat_intelligence/source_confirm_delete.html', {'source': source})

@login_required
def entries_list(request):
    """Display a list of all threat intelligence entries with filtering options."""
    # Gather filtering parameters
    type_filter = request.GET.get('type')
    source_filter = request.GET.get('source')
    time_filter = request.GET.get('time')
    
    # Start with all entries
    entries = ThreatIntelEntry.objects.all().order_by('-first_seen')  # Use first_seen instead of created_at
    selected_source = None
    
    # Apply filters
    if type_filter:
        entries = entries.filter(entry_type=type_filter)
    
    if source_filter:
        selected_source = get_object_or_404(ThreatIntelSource, id=source_filter)
        entries = entries.filter(source=selected_source)
    
    if time_filter:
        now = timezone.now()
        if time_filter == 'today':
            entries = entries.filter(first_seen__date=now.date())
        elif time_filter == 'week':
            entries = entries.filter(first_seen__gte=now - timezone.timedelta(days=7))
        elif time_filter == 'month':
            entries = entries.filter(first_seen__gte=now - timezone.timedelta(days=30))
    
    # Pagination
    paginator = Paginator(entries, 50)
    page_number = request.GET.get('page')
    entries_page = paginator.get_page(page_number)
    
    # Prepare entries data for JavaScript
    entries_data = {}
    for entry in entries_page:
        entries_data[str(entry.id)] = {
            'value': entry.value,
            'type': entry.get_entry_type_display(),
            'source': entry.source.name,
            'confidence_score': entry.confidence_score,
            'timestamp': entry.first_seen.strftime('%Y-%m-%d %H:%M:%S'),
            'category': entry.category or 'N/A',
        }
    
    context = {
        'entries': entries_page,
        'selected_source': selected_source,
        'type_filter': type_filter,
        'source_filter': source_filter,
        'time_filter': time_filter,
        'entry_types': ThreatIntelEntry.ENTRY_TYPES,
        'entries_data': entries_data  # This will be rendered as JSON in the template
    }
    
    return render(request, 'threat_intelligence/entries_list.html', context)

@login_required
def entry_detail(request, entry_id):
    """Display details about a specific threat intelligence entry."""
    entry = get_object_or_404(ThreatIntelEntry, id=entry_id)
    
    # Get related entries (same source or same value)
    related_entries = ThreatIntelEntry.objects.filter(
        Q(source=entry.source) | Q(value=entry.value)
    ).exclude(id=entry.id)[:10]
    
    context = {
        'entry': entry,
        'related_entries': related_entries,
    }
    
    return render(request, 'threat_intelligence/entry_detail.html', context)

@login_required
def update_source_now(request, source_id):
    """Manually trigger an update for a threat intelligence source."""
    source = get_object_or_404(ThreatIntelSource, id=source_id)
    
    if not source.is_active:
        messages.error(request, 'Cannot update an inactive source.')
        return redirect('threat_intelligence:source_detail', source_id=source.id)
    
    try:
        # Trigger the update
        threat_intel_fetcher.fetch_source_data(source.id)
        
        # Update the last_updated timestamp
        source.last_updated = timezone.now()
        source.save()
        
        messages.success(request, f'Update triggered for {source.name}.')
    except Exception as e:
        messages.error(request, f'Error updating source: {str(e)}')
    
    return redirect('threat_intelligence:source_detail', source_id=source.id)

@login_required
def ai_models_list(request):
    """Display a list of all AI classifier models."""
    models = AIClassifierModel.objects.all().order_by('-updated_at')  # Using updated_at instead of created_at
    return render(request, 'threat_intelligence/ai_models_list.html', {'models': models})

@login_required
def ai_model_add(request):
    """Add a new AI classifier model."""
    if request.method == 'POST':
        name = request.POST.get('name')
        model_type = request.POST.get('model_type')
        description = request.POST.get('description')
        
        # Check if model file was uploaded
        model_file = request.FILES.get('model_file')
        
        if model_file:
            # Generate a unique filename with the original extension preserved
            file_name = f"{uuid.uuid4()}_{model_file.name}"
            file_path = os.path.join(MODEL_FILES_DIR, file_name)
            
            # Save the uploaded file to the model_files directory
            with open(file_path, 'wb+') as destination:
                for chunk in model_file.chunks():
                    destination.write(chunk)
                    
            # Store the relative path to the model file
            relative_path = os.path.join('model_files', file_name)
        else:
            # Use manual path if provided
            relative_path = request.POST.get('file_path', '')
        
        # Create model with basic information
        model = AIClassifierModel(
            name=name,
            model_type=model_type,
            description=description,
            file_path=relative_path,
            is_active=True
        )
        
        # Process model-specific parameters
        model_params = {}
        
        # For Llama models
        if model_type in ['llama', 'llama_quantized']:
            # Process Llama-specific parameters
            model_params['llama_model_type'] = request.POST.get('llama_model_type', 'llama2')
            model_params['quantization'] = request.POST.get('quantization', '4bit')
            model_params['max_length'] = int(request.POST.get('max_length', 2048))
            model_params['temperature'] = float(request.POST.get('temperature', 0.7))
            model_params['top_p'] = float(request.POST.get('top_p', 0.9))
            model_params['repetition_penalty'] = float(request.POST.get('repetition_penalty', 1.1))
            model_params['system_prompt'] = request.POST.get('system_prompt', '')
            model_params['device'] = request.POST.get('device', 'auto')
            
            # For custom Hugging Face models
            if request.POST.get('llama_model_type') == 'custom':
                model_params['custom_model_path'] = request.POST.get('custom_model_path', '')
        
        # For sklearn models
        elif model_type in ['random_forest', 'naive_bayes']:
            model_params['sklearn_module'] = request.POST.get('sklearn_module', '')
        
        # For neural network models
        elif model_type == 'neural_network':
            model_params['tf_input_shape'] = request.POST.get('tf_input_shape', '')
        
        # For custom models
        elif model_type == 'custom':
            model_params['custom_module'] = request.POST.get('custom_module', '')
            model_params['custom_class'] = request.POST.get('custom_class', '')
        
        # Save model parameters
        model.model_params = model_params
        model.save()
        
        messages.success(request, 'AI model added successfully.')
        return redirect('threat_intelligence:ai_models_list')
    
    context = {
        'model_types': AIClassifierModel.MODEL_TYPES
    }
    
    return render(request, 'threat_intelligence/ai_model_form.html', context)

@login_required
def ai_model_edit(request, model_id):
    """Edit an existing AI classifier model."""
    model = get_object_or_404(AIClassifierModel, id=model_id)
    
    if request.method == 'POST':
        model.name = request.POST.get('name')
        model.model_type = request.POST.get('model_type')
        model.description = request.POST.get('description')
        
        # Check if a new model file was uploaded
        model_file = request.FILES.get('model_file')
        
        if model_file:
            # Generate a unique filename with the original extension preserved
            file_name = f"{uuid.uuid4()}_{model_file.name}"
            file_path = os.path.join(MODEL_FILES_DIR, file_name)
            
            # Save the uploaded file to the model_files directory
            with open(file_path, 'wb+') as destination:
                for chunk in model_file.chunks():
                    destination.write(chunk)
                    
            # Store the relative path to the model file
            model.file_path = os.path.join('model_files', file_name)
        else:
            # Use manual path if provided and different from current
            new_path = request.POST.get('file_path', '')
            if new_path and new_path != model.file_path:
                model.file_path = new_path
        
        model.is_active = request.POST.get('is_active') == 'on'
        
        # Process model-specific parameters
        model_params = {}
        
        # For Llama models
        if model.model_type in ['llama', 'llama_quantized']:
            # Process Llama-specific parameters
            model_params['llama_model_type'] = request.POST.get('llama_model_type', 'llama2')
            model_params['quantization'] = request.POST.get('quantization', '4bit')
            model_params['max_length'] = int(request.POST.get('max_length', 2048))
            model_params['temperature'] = float(request.POST.get('temperature', 0.7))
            model_params['top_p'] = float(request.POST.get('top_p', 0.9))
            model_params['repetition_penalty'] = float(request.POST.get('repetition_penalty', 1.1))
            model_params['system_prompt'] = request.POST.get('system_prompt', '')
            model_params['device'] = request.POST.get('device', 'auto')
            
            # For custom Hugging Face models
            if request.POST.get('llama_model_type') == 'custom':
                model_params['custom_model_path'] = request.POST.get('custom_model_path', '')
        
        # For sklearn models
        elif model.model_type in ['random_forest', 'naive_bayes']:
            model_params['sklearn_module'] = request.POST.get('sklearn_module', '')
        
        # For neural network models
        elif model.model_type == 'neural_network':
            model_params['tf_input_shape'] = request.POST.get('tf_input_shape', '')
        
        # For custom models
        elif model.model_type == 'custom':
            model_params['custom_module'] = request.POST.get('custom_module', '')
            model_params['custom_class'] = request.POST.get('custom_class', '')
        
        # Save model parameters
        model.model_params = model_params
        model.save()
        
        messages.success(request, 'AI model updated successfully.')
        return redirect('threat_intelligence:ai_models_list')
    
    context = {
        'model': model,
        'model_types': AIClassifierModel.MODEL_TYPES,
        'model_params': model.model_params  # Pass model parameters to template
    }
    
    return render(request, 'threat_intelligence/ai_model_form.html', context)

@login_required
def ai_model_delete(request, model_id):
    """Delete an AI classifier model."""
    model = get_object_or_404(AIClassifierModel, id=model_id)
    
    if request.method == 'POST':
        model.delete()
        messages.success(request, 'AI model deleted successfully.')
        return redirect('threat_intelligence:ai_models_list')
    
    return render(request, 'threat_intelligence/ai_model_confirm_delete.html', {'model': model})

@login_required
def dashboard(request):
    """Display the threat intelligence dashboard overview."""
    # Get summary statistics
    sources_count = ThreatIntelSource.objects.count()
    active_sources_count = ThreatIntelSource.objects.filter(is_active=True).count()
    entries_count = ThreatIntelEntry.objects.count()
    high_confidence_count = ThreatIntelEntry.objects.filter(confidence_score__gte=75).count()
    ai_models_count = AIClassifierModel.objects.count()
    active_models_count = AIClassifierModel.objects.filter(is_active=True).count()
    
    # Get recent updates (last 24 hours)
    one_day_ago = timezone.now() - timezone.timedelta(days=1)
    # Use first_seen instead of created_at since that's the field that exists
    recent_updates_count = ThreatIntelEntry.objects.filter(first_seen__gte=one_day_ago).count()
    
    # Get recent sources
    recent_sources = ThreatIntelSource.objects.all().order_by('-last_updated')[:5]
    for source in recent_sources:
        source.entries_count = ThreatIntelEntry.objects.filter(source=source).count()
    
    # Get recent entries - using first_seen instead of created_at
    recent_entries = ThreatIntelEntry.objects.all().order_by('-first_seen')[:10]
    
    # Get entry type distribution
    entry_types_summary = []
    total_entries = max(entries_count, 1)  # Avoid division by zero
    
    for entry_type, display_name in ThreatIntelEntry.ENTRY_TYPES:
        count = ThreatIntelEntry.objects.filter(entry_type=entry_type).count()
        percentage = round((count / total_entries) * 100)
        entry_types_summary.append({
            'type': entry_type,
            'display_name': display_name,
            'count': count,
            'percentage': percentage
        })
    
    context = {
        'sources_count': sources_count,
        'active_sources_count': active_sources_count,
        'entries_count': entries_count,
        'high_confidence_count': high_confidence_count,
        'ai_models_count': ai_models_count,
        'active_models_count': active_models_count,
        'recent_updates_count': recent_updates_count,
        'recent_sources': recent_sources,
        'recent_entries': recent_entries,
        'entry_types_summary': entry_types_summary,
    }
    
    return render(request, 'threat_intelligence/dashboard.html', context)

@login_required
def firewall_rules_list(request):
    """View to list all firewall rules."""
    query = request.GET.get('q', '')
    rule_type = request.GET.get('type', '')
    action = request.GET.get('action', '')
    category = request.GET.get('category', '')
    is_active = request.GET.get('is_active', '')
    
    rules = FirewallRule.objects.all()
    
    # Apply filters
    if query:
        rules = rules.filter(
            Q(name__icontains=query) | 
            Q(description__icontains=query) | 
            Q(value__icontains=query)
        )
    
    if rule_type:
        rules = rules.filter(rule_type=rule_type)
    
    if action:
        rules = rules.filter(action=action)
        
    if category:
        rules = rules.filter(category=category)
    
    if is_active:
        is_active_bool = is_active.lower() == 'true'
        rules = rules.filter(is_active=is_active_bool)
    
    # Pagination
    paginator = Paginator(rules, 20)  # Show 20 rules per page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    context = {
        'page_obj': page_obj,
        'rule_types': FirewallRule.RULE_TYPES,
        'actions': FirewallRule.ACTIONS,
        'categories': FirewallRule.CATEGORIES,
        'query': query,
        'selected_type': rule_type,
        'selected_action': action,
        'selected_category': category,
        'selected_is_active': is_active,
    }
    
    return render(request, 'threat_intelligence/firewall_rules_list.html', context)

@login_required
def firewall_rule_add(request):
    """View to add a new firewall rule."""
    if request.method == 'POST':
        try:
            # Extract data from the form
            name = request.POST.get('name')
            description = request.POST.get('description', '')
            rule_type = request.POST.get('rule_type')
            value = request.POST.get('value')
            action = request.POST.get('action')
            category = request.POST.get('category')
            direction = request.POST.get('direction')
            protocol = request.POST.get('protocol', None)
            port = request.POST.get('port', None)
            port_end = request.POST.get('port_end', None)
            priority = request.POST.get('priority', 100)
            is_active = request.POST.get('is_active') == 'on'
            is_temporary = request.POST.get('is_temporary') == 'on'
            
            # Handle expiry date for temporary rules
            expiry_date = None
            if is_temporary and request.POST.get('expiry_date'):
                expiry_date = timezone.datetime.strptime(
                    request.POST.get('expiry_date'), 
                    '%Y-%m-%dT%H:%M'
                )
            
            # Convert port values to integers if provided
            if port and port.isdigit():
                port = int(port)
            else:
                port = None
                
            if port_end and port_end.isdigit():
                port_end = int(port_end)
            else:
                port_end = None
            
            # Create the rule
            rule = FirewallRule(
                name=name,
                description=description,
                rule_type=rule_type,
                value=value,
                action=action,
                category=category,
                direction=direction,
                protocol=protocol,
                port=port,
                port_end=port_end,
                priority=int(priority),
                is_active=is_active,
                is_temporary=is_temporary,
                expiry_date=expiry_date,
                source='manual'
            )
            
            # Validate the rule
            rule.clean()
            
            # Save it
            rule.save()
            
            messages.success(request, f'Firewall rule "{name}" added successfully.')
            return redirect('threat_intelligence:firewall_rules_list')
            
        except Exception as e:
            messages.error(request, f'Error adding firewall rule: {str(e)}')
    
    # Prepare the context for the form
    context = {
        'rule_types': FirewallRule.RULE_TYPES,
        'actions': FirewallRule.ACTIONS,
        'categories': FirewallRule.CATEGORIES,
        'directions': FirewallRule.DIRECTIONS,
        'protocols': FirewallRule.PROTOCOLS,
    }
    
    return render(request, 'threat_intelligence/firewall_rule_form.html', context)

@login_required
def firewall_rule_edit(request, rule_id):
    """View to edit an existing firewall rule."""
    rule = get_object_or_404(FirewallRule, id=rule_id)
    
    if request.method == 'POST':
        try:
            # Extract data from the form
            rule.name = request.POST.get('name')
            rule.description = request.POST.get('description', '')
            rule.rule_type = request.POST.get('rule_type')
            rule.value = request.POST.get('value')
            rule.action = request.POST.get('action')
            rule.category = request.POST.get('category')
            rule.direction = request.POST.get('direction')
            rule.protocol = request.POST.get('protocol', None)
            
            # Convert port values to integers if provided
            port = request.POST.get('port', None)
            port_end = request.POST.get('port_end', None)
            
            if port and port.isdigit():
                rule.port = int(port)
            else:
                rule.port = None
                
            if port_end and port_end.isdigit():
                rule.port_end = int(port_end)
            else:
                rule.port_end = None
            
            rule.priority = int(request.POST.get('priority', 100))
            rule.is_active = request.POST.get('is_active') == 'on'
            rule.is_temporary = request.POST.get('is_temporary') == 'on'
            
            # Handle expiry date for temporary rules
            if rule.is_temporary and request.POST.get('expiry_date'):
                rule.expiry_date = timezone.datetime.strptime(
                    request.POST.get('expiry_date'), 
                    '%Y-%m-%dT%H:%M'
                )
            else:
                rule.expiry_date = None
            
            # Validate and save the rule
            rule.clean()
            rule.save()
            
            messages.success(request, f'Firewall rule "{rule.name}" updated successfully.')
            return redirect('threat_intelligence:firewall_rules_list')
            
        except Exception as e:
            messages.error(request, f'Error updating firewall rule: {str(e)}')
    
    # Prepare the context for the form
    context = {
        'rule': rule,
        'rule_types': FirewallRule.RULE_TYPES,
        'actions': FirewallRule.ACTIONS,
        'categories': FirewallRule.CATEGORIES,
        'directions': FirewallRule.DIRECTIONS,
        'protocols': FirewallRule.PROTOCOLS,
    }
    
    return render(request, 'threat_intelligence/firewall_rule_form.html', context)

@login_required
def firewall_rule_detail(request, rule_id):
    """View to show details of a specific firewall rule."""
    rule = get_object_or_404(FirewallRule, id=rule_id)
    
    context = {
        'rule': rule,
    }
    
    return render(request, 'threat_intelligence/firewall_rule_detail.html', context)

@require_POST
@login_required
def firewall_rule_toggle(request, rule_id):
    """Toggle a rule's active status."""
    rule = get_object_or_404(FirewallRule, id=rule_id)
    rule.is_active = not rule.is_active
    rule.save()
    
    return JsonResponse({
        'success': True, 
        'is_active': rule.is_active,
        'message': f'Rule "{rule.name}" is now {"active" if rule.is_active else "inactive"}'
    })

@require_POST
@login_required
def firewall_rule_delete(request, rule_id):
    """Delete a firewall rule."""
    rule = get_object_or_404(FirewallRule, id=rule_id)
    name = rule.name
    rule.delete()
    
    messages.success(request, f'Firewall rule "{name}" deleted successfully.')
    
    # Check if we should redirect to a specific page
    next_url = request.POST.get('next')
    if next_url:
        return HttpResponseRedirect(next_url)
        
    return redirect('threat_intelligence:firewall_rules_list')

@login_required
def firewall_rule_import(request):
    """Import multiple firewall rules from various formats."""
    if request.method == 'POST':
        # Check if we're getting JSON or CSV upload
        format_type = request.POST.get('format', 'csv')
        file_obj = request.FILES.get('rules_file')
        
        if not file_obj:
            messages.error(request, 'No file uploaded.')
            return redirect('threat_intelligence:firewall_rules_list')
        
        try:
            rules_added = 0
            
            if format_type == 'json':
                # Process JSON import
                json_data = json.loads(file_obj.read().decode('utf-8'))
                
                for rule_data in json_data:
                    # Basic validation
                    if 'name' not in rule_data or 'rule_type' not in rule_data or 'value' not in rule_data:
                        continue
                    
                    # Create the rule
                    rule = FirewallRule(
                        name=rule_data.get('name'),
                        description=rule_data.get('description', ''),
                        rule_type=rule_data.get('rule_type'),
                        value=rule_data.get('value'),
                        action=rule_data.get('action', 'block'),
                        category=rule_data.get('category', 'security'),
                        direction=rule_data.get('direction', 'inbound'),
                        protocol=rule_data.get('protocol'),
                        port=rule_data.get('port'),
                        port_end=rule_data.get('port_end'),
                        priority=rule_data.get('priority', 100),
                        is_active=rule_data.get('is_active', True),
                        is_temporary=rule_data.get('is_temporary', False),
                        source='import'
                    )
                    
                    # Set expiry date if applicable
                    if rule.is_temporary and 'expiry_date' in rule_data:
                        rule.expiry_date = timezone.datetime.strptime(
                            rule_data['expiry_date'], 
                            '%Y-%m-%dT%H:%M:%S'
                        )
                    
                    try:
                        rule.clean()
                        rule.save()
                        rules_added += 1
                    except Exception:
                        # Skip invalid rules
                        continue
                    
            else:
                # Process CSV import
                csv_data = StringIO(file_obj.read().decode('utf-8'))
                reader = csv.reader(csv_data)
                
                # Skip header row
                header = next(reader)
                
                for row in reader:
                    # Basic validation - ensure minimum required fields
                    if len(row) < 3:
                        continue
                    
                    # Create a rule from CSV row
                    rule = FirewallRule(
                        name=row[0],
                        rule_type=row[1],
                        value=row[2],
                        action=row[3] if len(row) > 3 else 'block',
                        category='security',
                        direction='inbound',
                        priority=100,
                        is_active=True,
                        is_temporary=False,
                        source='import'
                    )
                    
                    # Add additional fields if available
                    if len(row) > 4:
                        rule.description = row[4]
                    
                    if len(row) > 5 and row[5]:
                        try:
                            rule.port = int(row[5])
                        except ValueError:
                            pass
                    
                    try:
                        rule.clean()
                        rule.save()
                        rules_added += 1
                    except Exception:
                        # Skip invalid rules
                        continue
            
            messages.success(request, f'Successfully imported {rules_added} firewall rules.')
            
        except Exception as e:
            messages.error(request, f'Error importing rules: {str(e)}')
        
        return redirect('threat_intelligence:firewall_rules_list')
    
    return render(request, 'threat_intelligence/firewall_rule_import.html')

@login_required
def firewall_rules_export(request):
    """Export firewall rules to JSON format."""
    rules = FirewallRule.objects.all()
    
    # Apply filters if provided
    rule_type = request.GET.get('type', '')
    action = request.GET.get('action', '')
    
    if rule_type:
        rules = rules.filter(rule_type=rule_type)
    
    if action:
        rules = rules.filter(action=action)
    
    # Convert rules to a list of dictionaries
    rules_data = []
    for rule in rules:
        rule_dict = {
            'name': rule.name,
            'description': rule.description,
            'rule_type': rule.rule_type,
            'value': rule.value,
            'action': rule.action,
            'category': rule.category,
            'direction': rule.direction,
            'protocol': rule.protocol,
            'port': rule.port,
            'port_end': rule.port_end,
            'priority': rule.priority,
            'is_active': rule.is_active,
            'is_temporary': rule.is_temporary,
        }
        
        if rule.expiry_date:
            rule_dict['expiry_date'] = rule.expiry_date.strftime('%Y-%m-%dT%H:%M:%S')
        
        rules_data.append(rule_dict)
    
    # Return the data as a downloadable JSON file
    response = JsonResponse(rules_data, safe=False, json_dumps_params={'indent': 2})
    response['Content-Disposition'] = 'attachment; filename="firewall_rules.json"'
    
    return response

@login_required
def firewall_presets(request):
    """View to show and apply predefined firewall rule presets."""
    if request.method == 'POST':
        preset_id = request.POST.get('preset_id')
        
        # Get preset rules based on the selected preset
        preset_rules = []
        
        if preset_id == 'basic_security':
            preset_rules = get_basic_security_preset()
        elif preset_id == 'country_block':
            preset_rules = get_country_block_preset()
        elif preset_id == 'malicious_ips':
            preset_rules = get_malicious_ips_preset()
        elif preset_id == 'common_ports':
            preset_rules = get_common_ports_preset()
        elif preset_id == 'all_presets':
            preset_rules = (get_basic_security_preset() + 
                            get_country_block_preset() + 
                            get_malicious_ips_preset() + 
                            get_common_ports_preset())
        
        # Add the preset rules to the database
        rules_added = 0
        rules_skipped = 0
        
        for rule_data in preset_rules:
            # Check if a similar rule already exists
            existing_rules = FirewallRule.objects.filter(
                rule_type=rule_data['rule_type'],
                value=rule_data['value']
            )
            
            if existing_rules.exists():
                rules_skipped += 1
                continue
            
            # Create and save the rule
            try:
                rule = FirewallRule(
                    name=rule_data['name'],
                    description=rule_data.get('description', ''),
                    rule_type=rule_data['rule_type'],
                    value=rule_data['value'],
                    action=rule_data.get('action', 'block'),
                    category=rule_data.get('category', 'security'),
                    direction=rule_data.get('direction', 'inbound'),
                    protocol=rule_data.get('protocol'),
                    port=rule_data.get('port'),
                    port_end=rule_data.get('port_end'),
                    priority=rule_data.get('priority', 100),
                    is_active=True,
                    source='preset'
                )
                
                rule.clean()
                rule.save()
                rules_added += 1
            except Exception:
                rules_skipped += 1
        
        messages.success(
            request, 
            f'Successfully added {rules_added} preset rules. {rules_skipped} rules were skipped.'
        )
        return redirect('threat_intelligence:firewall_rules_list')
    
    # Show the presets page
    context = {
        'presets': [
            {
                'id': 'basic_security',
                'name': 'Basic Security Rules',
                'description': 'Essential security rules to protect against common attacks',
                'rules_count': len(get_basic_security_preset())
            },
            {
                'id': 'country_block',
                'name': 'High-Risk Country Blocks',
                'description': 'Block IPs from countries with high cybercrime rates',
                'rules_count': len(get_country_block_preset())
            },
            {
                'id': 'malicious_ips',
                'name': 'Known Malicious IPs',
                'description': 'Block IPs known for malicious activities',
                'rules_count': len(get_malicious_ips_preset())
            },
            {
                'id': 'common_ports',
                'name': 'Common Ports Protection',
                'description': 'Rules to secure commonly targeted ports',
                'rules_count': len(get_common_ports_preset())
            },
            {
                'id': 'all_presets',
                'name': 'All Preset Rules',
                'description': 'Apply all preset rules at once',
                'rules_count': (len(get_basic_security_preset()) + 
                               len(get_country_block_preset()) + 
                               len(get_malicious_ips_preset()) + 
                               len(get_common_ports_preset()))
            }
        ]
    }
    
    return render(request, 'threat_intelligence/firewall_presets.html', context)

# Preset Rules Functions
def get_basic_security_preset():
    """Return a list of basic security firewall rules."""
    return [
        {
            'name': 'Block Null Packets',
            'description': 'Block packets with no flags set',
            'rule_type': 'custom',
            'value': 'tcp flags:0',
            'action': 'block',
            'category': 'security',
            'direction': 'inbound',
            'protocol': 'tcp',
            'priority': 10,
        },
        {
            'name': 'Block Invalid TCP Flags',
            'description': 'Block packets with invalid TCP flag combinations',
            'rule_type': 'custom',
            'value': 'tcp flags:FIN,URG,PSH and not SYN',
            'action': 'block',
            'category': 'security',
            'direction': 'inbound',
            'protocol': 'tcp',
            'priority': 10,
        },
        {
            'name': 'Block XMAS Packets',
            'description': 'Block XMAS scan packets (FIN, PSH, URG flags all set)',
            'rule_type': 'custom',
            'value': 'tcp flags:FIN,PSH,URG',
            'action': 'block',
            'category': 'security',
            'direction': 'inbound',
            'protocol': 'tcp',
            'priority': 10,
        },
        {
            'name': 'Block Excessive ICMP',
            'description': 'Prevent ICMP flood attacks',
            'rule_type': 'protocol',
            'value': 'rate-limit:10/s',
            'action': 'block',
            'category': 'security',
            'direction': 'inbound',
            'protocol': 'icmp',
            'priority': 20,
        },
        {
            'name': 'Block Loopback Traffic from External',
            'description': 'Block external traffic claiming to be from loopback addresses',
            'rule_type': 'ip_range',
            'value': '127.0.0.0/8',
            'action': 'block',
            'category': 'security',
            'direction': 'inbound',
            'priority': 5,
        },
        {
            'name': 'Block Private IP Spoofing',
            'description': 'Block external traffic claiming to be from private IP ranges',
            'rule_type': 'ip_range',
            'value': '10.0.0.0/8',
            'action': 'block',
            'category': 'security',
            'direction': 'inbound',
            'priority': 5,
        },
        {
            'name': 'Block Private IP Spoofing (Class B)',
            'description': 'Block external traffic claiming to be from private IP ranges',
            'rule_type': 'ip_range',
            'value': '172.16.0.0/12',
            'action': 'block',
            'category': 'security',
            'direction': 'inbound',
            'priority': 5,
        },
        {
            'name': 'Block Private IP Spoofing (Class C)',
            'description': 'Block external traffic claiming to be from private IP ranges',
            'rule_type': 'ip_range',
            'value': '192.168.0.0/16',
            'action': 'block',
            'category': 'security',
            'direction': 'inbound',
            'priority': 5,
        },
        {
            'name': 'Block Multicast Spoofing',
            'description': 'Block traffic spoofing multicast addresses',
            'rule_type': 'ip_range',
            'value': '224.0.0.0/4',
            'action': 'block',
            'category': 'security',
            'direction': 'inbound',
            'priority': 5,
        },
    ]

def get_country_block_preset():
    """Return a list of high-risk country blocking rules."""
    return [
        {
            'name': 'Block Traffic from North Korea',
            'description': 'Block all traffic from North Korea (KP)',
            'rule_type': 'country',
            'value': 'KP',
            'action': 'block',
            'category': 'security',
            'direction': 'both',
            'priority': 50,
        },
        {
            'name': 'Block Traffic from Russia',
            'description': 'Block all traffic from Russia (RU)',
            'rule_type': 'country',
            'value': 'RU',
            'action': 'block',
            'category': 'security',
            'direction': 'both',
            'priority': 50,
        },
        {
            'name': 'Block Traffic from China',
            'description': 'Block all traffic from China (CN)',
            'rule_type': 'country',
            'value': 'CN',
            'action': 'block',
            'category': 'security',
            'direction': 'both',
            'priority': 50,
        },
        {
            'name': 'Block Traffic from Iran',
            'description': 'Block all traffic from Iran (IR)',
            'rule_type': 'country',
            'value': 'IR',
            'action': 'block',
            'category': 'security',
            'direction': 'both',
            'priority': 50,
        },
        {
            'name': 'Block Traffic from Nigeria',
            'description': 'Block all traffic from Nigeria (NG)',
            'rule_type': 'country',
            'value': 'NG',
            'action': 'block',
            'category': 'security',
            'direction': 'both',
            'priority': 50,
        },
        {
            'name': 'Block Traffic from Romania',
            'description': 'Block all traffic from Romania (RO)',
            'rule_type': 'country',
            'value': 'RO',
            'action': 'block',
            'category': 'security',
            'direction': 'both',
            'priority': 50,
        },
        {
            'name': 'Block Traffic from Venezuela',
            'description': 'Block all traffic from Venezuela (VE)',
            'rule_type': 'country',
            'value': 'VE',
            'action': 'block',
            'category': 'security',
            'direction': 'both',
            'priority': 50,
        },
    ]

def get_malicious_ips_preset():
    """Return a list of known malicious IP addresses."""
    return [
        {
            'name': 'Tor Exit Node Blocking',
            'description': 'Block known Tor exit node',
            'rule_type': 'ip',
            'value': '185.220.101.35',
            'action': 'block',
            'category': 'security',
            'direction': 'inbound',
            'priority': 30,
        },
        {
            'name': 'Tor Exit Node Blocking',
            'description': 'Block known Tor exit node',
            'rule_type': 'ip',
            'value': '185.220.101.43',
            'action': 'block',
            'category': 'security',
            'direction': 'inbound',
            'priority': 30,
        },
        {
            'name': 'Malicious IP - Russia',
            'description': 'Known malicious IP from Russia',
            'rule_type': 'ip',
            'value': '45.137.21.9',
            'action': 'block',
            'category': 'security',
            'direction': 'both',
            'priority': 30,
        },
        {
            'name': 'Malicious IP - Netherlands',
            'description': 'Known malicious IP from Netherlands',
            'rule_type': 'ip',
            'value': '45.155.205.233',
            'action': 'block',
            'category': 'security',
            'direction': 'both',
            'priority': 30,
        },
        {
            'name': 'Malicious IP - China',
            'description': 'Known malicious IP from China',
            'rule_type': 'ip',
            'value': '221.181.185.159',
            'action': 'block',
            'category': 'security',
            'direction': 'both',
            'priority': 30,
        },
        {
            'name': 'Malicious IP - Ukraine',
            'description': 'Known malicious IP from Ukraine',
            'rule_type': 'ip',
            'value': '176.119.7.175',
            'action': 'block',
            'category': 'security',
            'direction': 'both',
            'priority': 30,
        },
        {
            'name': 'Malicious IP - China',
            'description': 'Known malicious IP from China',
            'rule_type': 'ip',
            'value': '123.160.221.255',
            'action': 'block',
            'category': 'security',
            'direction': 'both',
            'priority': 30,
        },
        {
            'name': 'Malicious IP - United States',
            'description': 'Known malicious IP from United States',
            'rule_type': 'ip',
            'value': '34.94.172.226',
            'action': 'block',
            'category': 'security',
            'direction': 'both',
            'priority': 30,
        },
        {
            'name': 'Malicious IP Range - Russian Botnet',
            'description': 'Known botnet IP range from Russia',
            'rule_type': 'ip_range',
            'value': '91.242.217.0/24',
            'action': 'block',
            'category': 'security',
            'direction': 'both',
            'priority': 30,
        },
        {
            'name': 'Malicious IP Range - Chinese Scanners',
            'description': 'Known scanner IP range from China',
            'rule_type': 'ip_range',
            'value': '120.92.0.0/16',
            'action': 'block',
            'category': 'security',
            'direction': 'both',
            'priority': 30,
        },
    ]

def get_common_ports_preset():
    """Return a list of rules for protecting common ports."""
    return [
        {
            'name': 'Block Telnet',
            'description': 'Block Telnet access (insecure protocol)',
            'rule_type': 'port',
            'value': 'telnet',
            'action': 'block',
            'category': 'security',
            'direction': 'inbound',
            'protocol': 'tcp',
            'port': 23,
            'priority': 40,
        },
        {
            'name': 'Block FTP Control',
            'description': 'Block unencrypted FTP control channel',
            'rule_type': 'port',
            'value': 'ftp-control',
            'action': 'block',
            'category': 'security',
            'direction': 'inbound',
            'protocol': 'tcp',
            'port': 21,
            'priority': 40,
        },
        {
            'name': 'Block SMTP (External)',
            'description': 'Block external access to SMTP server',
            'rule_type': 'port',
            'value': 'smtp',
            'action': 'block',
            'category': 'security',
            'direction': 'inbound',
            'protocol': 'tcp',
            'port': 25,
            'priority': 40,
        },
        {
            'name': 'Block NetBIOS',
            'description': 'Block NetBIOS ports (Windows sharing)',
            'rule_type': 'port_range',
            'value': 'netbios',
            'action': 'block',
            'category': 'security',
            'direction': 'inbound',
            'protocol': 'tcp',
            'port': 137,
            'port_end': 139,
            'priority': 40,
        },
        {
            'name': 'Block SMB / CIFS',
            'description': 'Block Windows file sharing',
            'rule_type': 'port',
            'value': 'smb',
            'action': 'block',
            'category': 'security',
            'direction': 'inbound',
            'protocol': 'tcp',
            'port': 445,
            'priority': 40,
        },
        {
            'name': 'Block RDP',
            'description': 'Block Remote Desktop Protocol (allow only from trusted IPs)',
            'rule_type': 'port',
            'value': 'rdp',
            'action': 'block',
            'category': 'security',
            'direction': 'inbound',
            'protocol': 'tcp',
            'port': 3389,
            'priority': 40,
        },
        {
            'name': 'Block MySQL',
            'description': 'Block external access to MySQL database',
            'rule_type': 'port',
            'value': 'mysql',
            'action': 'block',
            'category': 'security',
            'direction': 'inbound',
            'protocol': 'tcp',
            'port': 3306,
            'priority': 40,
        },
        {
            'name': 'Block PostgreSQL',
            'description': 'Block external access to PostgreSQL database',
            'rule_type': 'port',
            'value': 'postgresql',
            'action': 'block',
            'category': 'security',
            'direction': 'inbound',
            'protocol': 'tcp',
            'port': 5432,
            'priority': 40,
        },
        {
            'name': 'Block Redis',
            'description': 'Block external access to Redis database',
            'rule_type': 'port',
            'value': 'redis',
            'action': 'block',
            'category': 'security',
            'direction': 'inbound',
            'protocol': 'tcp',
            'port': 6379,
            'priority': 40,
        },
        {
            'name': 'Block MongoDB',
            'description': 'Block external access to MongoDB database',
            'rule_type': 'port',
            'value': 'mongodb',
            'action': 'block',
            'category': 'security',
            'direction': 'inbound',
            'protocol': 'tcp',
            'port': 27017,
            'priority': 40,
        },
    ]
