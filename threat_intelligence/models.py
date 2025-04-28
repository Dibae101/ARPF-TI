from django.db import models
from django.utils import timezone
import uuid
import ipaddress
import re
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


class FirewallRule(models.Model):
    """Model representing a firewall rule for blocking or allowing traffic."""
    
    # Rule types
    TYPE_IP = 'ip'
    TYPE_IP_RANGE = 'ip_range'
    TYPE_COUNTRY = 'country'
    TYPE_PORT = 'port'
    TYPE_PORT_RANGE = 'port_range'
    TYPE_PROTOCOL = 'protocol'
    TYPE_CUSTOM = 'custom'
    
    RULE_TYPES = [
        (TYPE_IP, 'Single IP Address'),
        (TYPE_IP_RANGE, 'IP Address Range/CIDR'),
        (TYPE_COUNTRY, 'Country Code'),
        (TYPE_PORT, 'Single Port'),
        (TYPE_PORT_RANGE, 'Port Range'),
        (TYPE_PROTOCOL, 'Protocol'),
        (TYPE_CUSTOM, 'Custom Expression'),
    ]
    
    # Actions
    ACTION_BLOCK = 'block'
    ACTION_ALLOW = 'allow'
    ACTION_LOG = 'log'
    
    ACTIONS = [
        (ACTION_BLOCK, 'Block'),
        (ACTION_ALLOW, 'Allow'),
        (ACTION_LOG, 'Log Only'),
    ]
    
    # Common protocols
    PROTOCOL_TCP = 'tcp'
    PROTOCOL_UDP = 'udp'
    PROTOCOL_ICMP = 'icmp'
    PROTOCOL_HTTP = 'http'
    PROTOCOL_HTTPS = 'https'
    PROTOCOL_FTP = 'ftp'
    PROTOCOL_SSH = 'ssh'
    PROTOCOL_SMTP = 'smtp'
    PROTOCOL_DNS = 'dns'
    
    PROTOCOLS = [
        (PROTOCOL_TCP, 'TCP'),
        (PROTOCOL_UDP, 'UDP'),
        (PROTOCOL_ICMP, 'ICMP'),
        (PROTOCOL_HTTP, 'HTTP'),
        (PROTOCOL_HTTPS, 'HTTPS'),
        (PROTOCOL_FTP, 'FTP'),
        (PROTOCOL_SSH, 'SSH'),
        (PROTOCOL_SMTP, 'SMTP'),
        (PROTOCOL_DNS, 'DNS'),
    ]
    
    # Rule categories
    CATEGORY_SECURITY = 'security'
    CATEGORY_COMPLIANCE = 'compliance'
    CATEGORY_TRAFFIC = 'traffic'
    CATEGORY_CUSTOM = 'custom'
    
    CATEGORIES = [
        (CATEGORY_SECURITY, 'Security'),
        (CATEGORY_COMPLIANCE, 'Compliance'),
        (CATEGORY_TRAFFIC, 'Traffic Management'),
        (CATEGORY_CUSTOM, 'Custom'),
    ]
    
    # Direction of traffic
    DIRECTION_INBOUND = 'inbound'
    DIRECTION_OUTBOUND = 'outbound'
    DIRECTION_BOTH = 'both'
    
    DIRECTIONS = [
        (DIRECTION_INBOUND, 'Inbound'),
        (DIRECTION_OUTBOUND, 'Outbound'),
        (DIRECTION_BOTH, 'Both Directions'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    rule_type = models.CharField(max_length=20, choices=RULE_TYPES)
    value = models.CharField(max_length=255, help_text="IP, CIDR, country code, etc.")
    action = models.CharField(max_length=20, choices=ACTIONS, default=ACTION_BLOCK)
    category = models.CharField(max_length=20, choices=CATEGORIES, default=CATEGORY_SECURITY)
    direction = models.CharField(max_length=20, choices=DIRECTIONS, default=DIRECTION_INBOUND)
    protocol = models.CharField(max_length=20, choices=PROTOCOLS, blank=True, null=True)
    port = models.IntegerField(blank=True, null=True)
    port_end = models.IntegerField(blank=True, null=True, help_text="End port for range")
    priority = models.IntegerField(default=100, help_text="Lower number = higher priority")
    is_active = models.BooleanField(default=True)
    is_temporary = models.BooleanField(default=False)
    expiry_date = models.DateTimeField(blank=True, null=True)
    source = models.CharField(max_length=255, blank=True, null=True, help_text="Source of this rule (e.g. manual, auto, api)")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['priority', 'created_at']
        verbose_name = "Firewall Rule"
        verbose_name_plural = "Firewall Rules"
    
    def __str__(self):
        return f"{self.name} ({self.get_action_display()} {self.get_rule_type_display()})"
    
    def clean(self):
        from django.core.exceptions import ValidationError
        
        # Validate IP addresses
        if self.rule_type == self.TYPE_IP:
            try:
                ipaddress.ip_address(self.value)
            except ValueError:
                raise ValidationError({'value': 'Invalid IP address format'})
        
        # Validate IP ranges/CIDR
        elif self.rule_type == self.TYPE_IP_RANGE:
            try:
                ipaddress.ip_network(self.value, strict=False)
            except ValueError:
                raise ValidationError({'value': 'Invalid IP range or CIDR format'})
        
        # Validate country codes (ISO 3166-1 alpha-2)
        elif self.rule_type == self.TYPE_COUNTRY:
            if not re.match(r'^[A-Z]{2}$', self.value):
                raise ValidationError({'value': 'Country code must be a 2-letter ISO code (e.g., US, GB)'})
        
        # Validate port ranges
        elif self.rule_type == self.TYPE_PORT_RANGE:
            if self.port is None or self.port_end is None:
                raise ValidationError('Both start and end ports are required for port ranges')
            if self.port < 1 or self.port > 65535 or self.port_end < 1 or self.port_end > 65535:
                raise ValidationError('Ports must be between 1 and 65535')
            if self.port > self.port_end:
                raise ValidationError('Start port must be less than or equal to end port')
    
    def is_expired(self):
        """Check if a temporary rule has expired."""
        if not self.is_temporary:
            return False
        if self.expiry_date is None:
            return False
        return timezone.now() > self.expiry_date
    
    @classmethod
    def get_active_rules(cls):
        """Return all active, non-expired rules."""
        active_rules = cls.objects.filter(is_active=True)
        return [rule for rule in active_rules if not rule.is_expired()]
