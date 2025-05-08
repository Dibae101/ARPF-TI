from django.db import models

class Rule(models.Model):
    """
    The Rule model represents firewall rules for filtering requests.
    Rules can be based on IP, user-agent, path, etc.
    """
    RULE_TYPES = [
        ('ip', 'IP Address'),
        ('country', 'Country Code'),
        ('user_agent', 'User Agent'),
        ('path', 'URL Path'),
        ('header', 'HTTP Header'),
        ('method', 'HTTP Method'),
        ('custom', 'Custom Rule')
    ]
    
    ACTION_TYPES = [
        ('block', 'Block'),
        ('allow', 'Allow'),
        ('log', 'Log Only'),
        ('alert', 'Alert')
    ]
    
    SOURCE_TYPES = [
        ('manual', 'Manually Created'),
        ('ai', 'AI Generated')
    ]
    
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    rule_type = models.CharField(max_length=20, choices=RULE_TYPES)
    pattern = models.TextField(help_text="Pattern to match (regex supported)")
    action = models.CharField(max_length=20, choices=ACTION_TYPES, default='block')
    priority = models.IntegerField(default=100, help_text="Rules are processed in priority order (lower numbers first)")
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    # Rule source and effectiveness metrics
    source = models.CharField(max_length=10, choices=SOURCE_TYPES, default='manual', help_text="Source of the rule creation")
    true_positive_count = models.IntegerField(default=0, help_text="Number of true positive matches")
    false_positive_count = models.IntegerField(default=0, help_text="Number of false positive matches")
    last_triggered = models.DateTimeField(null=True, blank=True, help_text="Last time this rule was triggered")
    
    class Meta:
        ordering = ['priority', 'name']
    
    def __str__(self):
        return f"{self.name} ({self.get_rule_type_display()}: {self.pattern})"
        
    @property
    def is_ai_generated(self):
        return 'AI' in self.name or self.source == 'ai'
        
    @property
    def precision(self):
        """Calculate precision (percentage of correct blocks)"""
        total = self.true_positive_count + self.false_positive_count
        if total == 0:
            return 0
        return (self.true_positive_count / total) * 100


class RequestLog(models.Model):
    """
    The RequestLog model stores information about processed requests including
    source IP, path, headers, and the rule that matched (if any).
    """
    timestamp = models.DateTimeField(auto_now_add=True)
    source_ip = models.GenericIPAddressField()
    path = models.CharField(max_length=2048)
    method = models.CharField(max_length=10)
    user_agent = models.TextField(blank=True, null=True)
    headers = models.JSONField(default=dict)
    matched_rule = models.ForeignKey(Rule, on_delete=models.SET_NULL, null=True, blank=True)
    action_taken = models.CharField(max_length=20)
    was_blocked = models.BooleanField(default=False)
    response_code = models.IntegerField()
    response_time_ms = models.IntegerField()
    country = models.CharField(max_length=2, blank=True, null=True)
    extra_data = models.JSONField(default=dict, blank=True, null=True)
    
    def __str__(self):
        return f"{self.source_ip} - {self.path} ({self.timestamp})"


class ProxyConfig(models.Model):
    """
    The ProxyConfig model stores the configuration for the reverse proxy.
    """
    name = models.CharField(max_length=255)
    target_host = models.CharField(max_length=255, help_text="Target host to proxy requests to (e.g., example.com)")
    target_port = models.IntegerField(default=80)
    use_https = models.BooleanField(default=True)
    timeout_seconds = models.IntegerField(default=30)
    is_active = models.BooleanField(default=True)
    preserve_host_header = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        protocol = "https" if self.use_https else "http"
        return f"{self.name}: {protocol}://{self.target_host}:{self.target_port}"
