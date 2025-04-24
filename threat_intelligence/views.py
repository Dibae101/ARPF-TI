from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.utils import timezone
from django.db import models
from django.core.paginator import Paginator
from django.conf import settings
import os
import uuid
from .models import ThreatIntelSource, ThreatIntelEntry, AIClassifierModel
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
        .annotate(count=models.Count('id'))
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
