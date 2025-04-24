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
    
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    rule_type = models.CharField(max_length=20, choices=RULE_TYPES)
    pattern = models.TextField(help_text="Pattern to match (regex supported)")
    action = models.CharField(max_length=20, choices=ACTION_TYPES, default='block')
    priority = models.IntegerField(default=100, help_text="Rules are processed in priority order (lower numbers first)")
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['priority', 'name']
    
    def __str__(self):
        return f"{self.name} ({self.get_rule_type_display()}: {self.pattern})"


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
