from django.db import models
import json

class ThreatIntelSource(models.Model):
    """
    A source of threat intelligence data, such as IP blocklists, VPN databases, etc.
    """
    SOURCE_TYPES = [
        ('ip_list', 'IP Blocklist'),
        ('vpn_ips', 'VPN IP Addresses'),
        ('cloud_ips', 'Cloud Provider IPs'),
        ('botnet', 'Botnet Tracker'),
        ('geo_block', 'Geographic Blocklist'),
        ('custom', 'Custom Source'),
        # Adding new source types for TAXII and MISP
        ('taxii', 'TAXII Feed'),
        ('misp', 'MISP Instance'),
        ('stix', 'STIX File/Feed')
    ]
    
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    source_type = models.CharField(max_length=20, choices=SOURCE_TYPES)
    url = models.URLField(help_text="URL for fetching the threat intelligence data")
    api_key = models.CharField(max_length=255, blank=True, null=True, help_text="API key if required for access")
    is_active = models.BooleanField(default=True)
    last_updated = models.DateTimeField(null=True, blank=True)
    update_frequency = models.IntegerField(default=86400, help_text="Update frequency in seconds")
    
    # Adding configuration fields for TAXII, MISP, and Custom API
    config = models.JSONField(default=dict, blank=True, help_text="Additional configuration parameters in JSON format")
    
    def __str__(self):
        return f"{self.name} ({self.get_source_type_display()})"
    
    def get_config_value(self, key, default=None):
        """Safely get a configuration value"""
        try:
            return self.config.get(key, default)
        except (AttributeError, json.JSONDecodeError):
            return default
    
    @property
    def taxii_collection_name(self):
        """Get TAXII collection name from config"""
        return self.get_config_value('collection_name', '')
    
    @property
    def taxii_collection_id(self):
        """Get TAXII collection ID from config"""
        return self.get_config_value('collection_id', '')
    
    @property
    def taxii_version(self):
        """Get TAXII version from config"""
        return self.get_config_value('taxii_version', '2.1')
    
    @property
    def misp_verify_ssl(self):
        """Get MISP SSL verification setting from config"""
        return self.get_config_value('verify_ssl', True)
    
    @property
    def misp_event_limit(self):
        """Get MISP event limit from config"""
        return self.get_config_value('event_limit', 100)
    
    @property
    def api_auth_method(self):
        """Get custom API authentication method from config"""
        return self.get_config_value('auth_method', 'header')
    
    @property
    def api_headers(self):
        """Get custom API headers from config"""
        return self.get_config_value('headers', {})
    
    @property
    def api_params(self):
        """Get custom API parameters from config"""
        return self.get_config_value('params', {})


class ThreatIntelEntry(models.Model):
    """
    An individual entry from a threat intelligence source, such as an IP address or range.
    """
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
    
    source = models.ForeignKey(ThreatIntelSource, on_delete=models.CASCADE, related_name='entries')
    entry_type = models.CharField(max_length=20, choices=ENTRY_TYPES)
    value = models.CharField(max_length=255, help_text="The actual value to block or monitor")
    category = models.CharField(max_length=255, blank=True, null=True, help_text="Category of the threat")
    confidence_score = models.FloatField(default=1.0, help_text="Confidence score (0.0 to 1.0)")
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)
    
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


class AIClassifierModel(models.Model):
    """
    Represents an AI model used for classifying requests as malicious or benign.
    """
    MODEL_TYPES = [
        ('random_forest', 'Random Forest'),
        ('naive_bayes', 'Naive Bayes'),
        ('neural_network', 'Neural Network'),
        ('gpt', 'GPT-based Model'),
        ('llama', 'Llama Model'),
        ('llama_quantized', 'Llama Quantized'),
        ('custom', 'Custom Model')
    ]
    
    name = models.CharField(max_length=255)
    model_type = models.CharField(max_length=20, choices=MODEL_TYPES)
    description = models.TextField(blank=True, null=True)
    file_path = models.CharField(max_length=255, help_text="Path to the model file")
    model_params = models.JSONField(default=dict, blank=True, help_text="Additional model parameters in JSON format")
    is_active = models.BooleanField(default=True)
    accuracy = models.FloatField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"{self.name} ({self.get_model_type_display()})"
