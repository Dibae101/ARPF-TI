from django.db import models
from django.utils import timezone
from core.models import Rule
import uuid
import json

class ThreatIntelSource(models.Model):
    """Model for storing threat intelligence sources."""
    SOURCE_TYPES = [
        ('taxii', 'TAXII Server'),
        ('misp', 'MISP Instance'),
        ('stix', 'STIX Files'),
        ('custom', 'Custom API'),
        ('ip_list', 'IP Blocklist'),
        ('vpn_ips', 'VPN IP Addresses'),
        ('cloud_ips', 'Cloud Provider IPs'),
        ('botnet', 'Botnet Tracker'),
        ('geo_block', 'Geographic Block List'),
    ]
    
    AUTH_METHODS = [
        ('header', 'API Key in Header'),
        ('parameter', 'API Key as URL Parameter'),
        ('basic', 'Basic Authentication'),
        ('none', 'No Authentication'),
    ]
    
    name = models.CharField(max_length=255, unique=True)
    description = models.TextField(blank=True, null=True)
    url = models.URLField(help_text="URL of the threat intelligence feed")
    source_type = models.CharField(max_length=20, choices=SOURCE_TYPES)
    api_key = models.CharField(max_length=255, blank=True, null=True, help_text="API key if required")
    username = models.CharField(max_length=255, blank=True, null=True)
    password = models.CharField(max_length=255, blank=True, null=True)
    update_frequency = models.IntegerField(default=3600, help_text="Update frequency in seconds")
    is_active = models.BooleanField(default=True)
    last_updated = models.DateTimeField(blank=True, null=True)
    created_at = models.DateTimeField(default=timezone.now)
    config = models.JSONField(default=dict, blank=True, help_text="Additional configuration parameters")
    
    # Add TAXII-specific fields
    taxii_collection_id = models.CharField(max_length=255, blank=True, null=True, help_text="ID of the TAXII collection")
    taxii_collection_name = models.CharField(max_length=255, blank=True, null=True, help_text="Name of the TAXII collection")
    
    # Add MISP-specific fields
    misp_verify_ssl = models.BooleanField(default=True, help_text="Verify SSL certificate for MISP connection")
    misp_event_limit = models.IntegerField(default=100, help_text="Maximum number of MISP events to fetch")
    
    # Add Custom API-specific fields
    api_auth_method = models.CharField(max_length=20, choices=AUTH_METHODS, default='header', help_text="Authentication method for custom API")
    api_headers = models.JSONField(default=dict, blank=True, help_text="Custom headers for API requests")
    api_params = models.JSONField(default=dict, blank=True, help_text="Default URL parameters for API requests")
    
    def __str__(self):
        return f"{self.name} ({self.get_source_type_display()})"
    
    class Meta:
        ordering = ['name']
        verbose_name_plural = "Threat intelligence sources"
        
    def get_config_value(self, key, default=None):
        """Get a configuration value from the config JSON field"""
        try:
            return self.config.get(key, default)
        except (AttributeError, json.JSONDecodeError):
            return default


class ThreatIntelEntry(models.Model):
    """Model for storing threat intelligence data."""
    ENTRY_TYPES = [
        ('ip', 'IP Address'),
        ('ip_range', 'IP Range'),
        ('country', 'Country Code'),
        ('asn', 'Autonomous System Number'),
        ('domain', 'Domain Name'),
        ('hash', 'File Hash'),
        ('other', 'Other'),
        # Add STIX-specific entry types
        ('indicator', 'STIX Indicator'),
        ('threat_actor', 'STIX Threat Actor'),
        ('malware', 'STIX Malware'),
        ('attack_pattern', 'STIX Attack Pattern'),
        ('campaign', 'STIX Campaign'),
        ('vulnerability', 'STIX Vulnerability')
    ]
    
    source = models.ForeignKey('ThreatIntelSource', on_delete=models.CASCADE, related_name='entries')
    entry_type = models.CharField(max_length=20, choices=ENTRY_TYPES)
    value = models.CharField(max_length=255, help_text="The actual value to block or monitor")
    category = models.CharField(max_length=255, blank=True, null=True, help_text="Category of the threat")
    confidence_score = models.FloatField(default=1.0, help_text="Confidence score (0.0 to 1.0)")
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)
    is_test_data = models.BooleanField(default=False, help_text="Flag to mark test/dummy data")
    
    # Add fields for enhanced TI metadata
    stix_id = models.CharField(max_length=255, blank=True, null=True, help_text="STIX ID for the object")
    misp_event_id = models.CharField(max_length=255, blank=True, null=True, help_text="MISP Event ID")
    misp_attribute_id = models.CharField(max_length=255, blank=True, null=True, help_text="MISP Attribute ID")
    metadata = models.JSONField(default=dict, blank=True, help_text="Additional metadata in JSON format")
    
    class Meta:
        verbose_name_plural = "Threat intelligence entries"
        unique_together = ('source', 'entry_type', 'value')
    
    def __str__(self):
        return f"{self.value} ({self.get_entry_type_display()} from {self.source.name})"
    
    @property
    def created_at(self):
        """Backward compatibility for templates that use created_at instead of first_seen."""
        return self.first_seen
    
    def get_metadata_value(self, key, default=None):
        """Safely get a metadata value"""
        try:
            return self.metadata.get(key, default)
        except (AttributeError, json.JSONDecodeError):
            return default
            
    @property
    def tlp(self):
        """Get Traffic Light Protocol level from metadata"""
        return self.get_metadata_value('tlp', 'WHITE')
    
    @property
    def stix_type(self):
        """Get STIX type from metadata"""
        return self.get_metadata_value('stix_type', '')
    
    @property
    def kill_chain_phases(self):
        """Get kill chain phases from metadata"""
        return self.get_metadata_value('kill_chain_phases', [])


class SuggestedFirewallRule(models.Model):
    """Model for storing firewall rules suggested by the AI based on threat detection"""
    STATUS_CHOICES = (
        ('pending', 'Pending Review'),
        ('approved', 'Approved'),
        ('auto_approved', 'Auto-Approved'),
        ('rejected', 'Rejected'),
    )
    
    RULE_TYPE_CHOICES = (
        ('ip', 'IP Address'),
        ('path', 'Request Path'),
        ('user_agent', 'User Agent'),
        ('country', 'Country'),
        ('combination', 'Combination'),
    )
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    rule_type = models.CharField(max_length=20, choices=RULE_TYPE_CHOICES)
    pattern = models.CharField(max_length=255, help_text="The pattern to match (IP, path, etc.)")
    description = models.TextField(help_text="AI-generated description of why this rule was suggested")
    confidence = models.IntegerField(default=0, help_text="AI confidence level (0-100)")
    attack_type = models.CharField(max_length=100, blank=True, null=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    source_ip = models.GenericIPAddressField(blank=True, null=True)
    request_path = models.CharField(max_length=255, blank=True, null=True)
    user_agent = models.TextField(blank=True, null=True)
    country = models.CharField(max_length=100, blank=True, null=True)
    additional_data = models.JSONField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    reviewed_at = models.DateTimeField(blank=True, null=True)
    reviewed_by = models.ForeignKey(
        'auth.User', 
        on_delete=models.SET_NULL, 
        blank=True, 
        null=True,
        related_name='reviewed_rules'
    )
    
    def approve(self, user=None):
        """Approve this suggested rule and create an actual firewall rule"""
        self.status = 'approved'
        self.reviewed_at = timezone.now()
        self.reviewed_by = user
        self.save()
        
        # Create an actual firewall rule
        firewall_rule = Rule(
            name=f"AI Suggested Rule - {self.rule_type} - {self.pattern[:30]}",
            rule_type=self.rule_type,
            pattern=self.pattern,
            description=self.description,
            is_active=True,
            action='block'  # Default to block action
        )
        firewall_rule.save()
        return firewall_rule
    
    def auto_approve(self):
        """Auto-approve high-confidence rules"""
        self.status = 'auto_approved'
        self.reviewed_at = timezone.now()
        self.save()
        
        # Create an actual firewall rule
        firewall_rule = Rule(
            name=f"AI Auto-Approved Rule - {self.rule_type} - {self.pattern[:30]}",
            rule_type=self.rule_type,
            pattern=self.pattern,
            description=self.description,
            is_active=True,
            action='block'  # Default to block action
        )
        firewall_rule.save()
        return firewall_rule
        
    def reject(self, user=None):
        """Reject this suggested rule"""
        self.status = 'rejected'
        self.reviewed_at = timezone.now()
        self.reviewed_by = user
        self.save()
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['rule_type']),
            models.Index(fields=['status']),
            models.Index(fields=['confidence']),
        ]

    def __str__(self):
        return f"{self.get_rule_type_display()}: {self.pattern} ({self.get_status_display()})"
