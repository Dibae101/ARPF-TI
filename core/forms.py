from django import forms
from .models import Rule, ProxyConfig
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User

class RuleForm(forms.ModelForm):
    """Form for creating and editing firewall rules."""
    
    class Meta:
        model = Rule
        fields = ['name', 'description', 'rule_type', 'pattern', 'action', 'priority', 'is_active']
        widgets = {
            'description': forms.Textarea(attrs={'rows': 3}),
            'pattern': forms.TextInput(attrs={'class': 'monospace-input', 'placeholder': 'e.g., ^192\.168\.1\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'}),
        }
    
    def clean_pattern(self):
        """Validate that the pattern is a valid regular expression."""
        pattern = self.cleaned_data['pattern']
        import re
        try:
            re.compile(pattern)
        except re.error:
            raise forms.ValidationError("Invalid regular expression pattern")
        return pattern


class ProxyConfigForm(forms.ModelForm):
    """Form for creating and editing proxy configurations."""
    
    class Meta:
        model = ProxyConfig
        fields = ['name', 'target_host', 'target_port', 'use_https', 'timeout_seconds', 'is_active', 'preserve_host_header']
        widgets = {
            'target_host': forms.TextInput(attrs={'placeholder': 'e.g., example.com'}),
            'target_port': forms.NumberInput(attrs={'min': '1', 'max': '65535'}),
            'timeout_seconds': forms.NumberInput(attrs={'min': '1', 'max': '300'}),
        }


class UserRegistrationForm(UserCreationForm):
    """Form for user registration."""
    email = forms.EmailField(required=True, help_text="Required. Enter a valid email address.")
    
    class Meta:
        model = User
        fields = ['username', 'email', 'password1', 'password2']
        
    def clean_email(self):
        """Ensure email is unique."""
        email = self.cleaned_data.get('email')
        if User.objects.filter(email=email).exists():
            raise forms.ValidationError("This email is already in use.")
        return email