from django import forms
from .models import ThreatIntelSource, ThreatIntelEntry
from core.models import Rule

class SourceForm(forms.ModelForm):
    """Form for adding/editing a threat intelligence source."""
    
    class Meta:
        model = ThreatIntelSource
        fields = ['name', 'description', 'source_type', 'url', 'api_key', 'update_frequency', 'is_active']
        widgets = {
            'description': forms.Textarea(attrs={'rows': 3}),
            'api_key': forms.PasswordInput(render_value=True),
        }

class EntryFilterForm(forms.Form):
    """Form for filtering threat intelligence entries."""
    
    TYPE_CHOICES = [('', '-- All Types --')] + list(ThreatIntelEntry.ENTRY_TYPES)
    SOURCE_CHOICES = []  # Will be populated dynamically
    
    entry_type = forms.ChoiceField(choices=TYPE_CHOICES, required=False)
    source = forms.ChoiceField(choices=SOURCE_CHOICES, required=False)
    confidence_min = forms.FloatField(min_value=0, max_value=1, required=False)
    date_from = forms.DateField(widget=forms.DateInput(attrs={'type': 'date'}), required=False)
    date_to = forms.DateField(widget=forms.DateInput(attrs={'type': 'date'}), required=False)
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Dynamically populate source choices
        sources = ThreatIntelSource.objects.all().order_by('name')
        self.fields['source'].choices = [('', '-- All Sources --')] + [(str(source.id), source.name) for source in sources]

class FirewallRuleForm(forms.ModelForm):
    """Form for adding/editing a firewall rule."""
    
    class Meta:
        model = Rule  # Using the Rule model from core instead of FirewallRule
        fields = [
            'name', 'description', 'rule_type', 'pattern', 'action',  
            'priority', 'is_active'
        ]
        widgets = {
            'description': forms.Textarea(attrs={'rows': 2}),
        }