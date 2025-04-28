import json
import time
import logging
import re
import socket
from django.conf import settings
from django.utils import timezone
from django.http import HttpResponse, JsonResponse
from django.utils.deprecation import MiddlewareMixin
from .models import Rule, RequestLog, ProxyConfig
from threat_intelligence.integrations.gemini_connector import GeminiConnector

logger = logging.getLogger('arpf_ti')

class RequestLoggerMiddleware(MiddlewareMixin):
    """
    Middleware for logging HTTP requests and applying firewall rules.
    This is the core of the ARPF-TI WAF functionality with integrated
    Gemini-powered AI threat analysis.
    """
    
    def __init__(self, get_response=None):
        super().__init__(get_response)  # Correctly call parent's __init__
        self.get_response = get_response
        self.active_rules = None
        self.last_rules_check = 0
        self.rules_cache_ttl = 60  # Cache rules for 60 seconds
        self._load_rules()
        # Get excluded IPs from settings
        self.excluded_ips = set(getattr(settings, 'EXCLUDED_IPS', []))
        # Always add 64.130.127.37 to the excluded IPs
        self.excluded_ips.add('64.130.127.37')
        # Auto-detect host IPs if enabled
        if getattr(settings, 'EXCLUDE_HOST_IPS', True):
            self.excluded_ips.update(self._get_host_ips())
        logger.info(f"Excluded IPs from logging: {', '.join(self.excluded_ips)}")
        
        # Initialize Gemini AI connector
        self.enable_gemini = getattr(settings, 'ENABLE_GEMINI', True)
        self.gemini = GeminiConnector() if self.enable_gemini else None
        if self.enable_gemini:
            logger.info("Gemini AI threat detection initialized")
        
        # Add this attribute for Django compatibility
        self.async_mode = False # Ensure this is correctly indented
    
    def _get_host_ips(self):
        """Detect all IP addresses of the host machine."""
        host_ips = set(['localhost', '127.0.0.1', '::1'])
        
        # Try to get the hostname and resolve it
        try:
            hostname = socket.gethostname()
            host_ips.add(hostname)
            # Get IPs from hostname
            try:
                host_ip = socket.gethostbyname(hostname)
                host_ips.add(host_ip)
            except socket.gaierror:
                pass
            
            # Try to get all addresses from hostname
            try:
                for addrinfo in socket.getaddrinfo(hostname, None):
                    host_ips.add(addrinfo[4][0])
            except socket.gaierror:
                pass
        except Exception as e:
            logger.warning(f"Error getting host IPs: {e}")
        
        return host_ips
    
    def _load_rules(self):
        """Load active rules from the database."""
        if not self.active_rules or (time.time() - self.last_rules_check) > self.rules_cache_ttl:
            self.active_rules = list(Rule.objects.filter(is_active=True).order_by('priority'))
            self.last_rules_check = time.time()
            logger.info(f"Loaded {len(self.active_rules)} active rules")
    
    def _get_client_ip(self, request):
        """Extract the client IP address from the request."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', '')
        
        # Check if this IP should be excluded from logging
        request._excluded_from_logging = ip in self.excluded_ips
        if request._excluded_from_logging:
            logger.debug(f"Request from excluded IP: {ip}")
        
        return ip
    
    def _check_rule_match(self, rule, request, ip_address):
        """Check if a request matches a rule."""
        # Remove the duplicate self-block prevention here since it's handled in _evaluate_rules
        
        if rule.rule_type == 'ip':
            return re.match(rule.pattern, ip_address) is not None
        
        elif rule.rule_type == 'country':
            country_code = self._get_country_code(ip_address)
            return country_code and re.match(rule.pattern, country_code) is not None
        
        elif rule.rule_type == 'user_agent':
            user_agent = request.META.get('HTTP_USER_AGENT', '')
            return re.match(rule.pattern, user_agent) is not None
        
        elif rule.rule_type == 'path':
            return re.match(rule.pattern, request.path) is not None
        
        elif rule.rule_type == 'header':
            # For header rules, pattern should be in format: "Header-Name:value"
            if ':' in rule.pattern:
                header_name, header_value = rule.pattern.split(':', 1)
                header_actual = request.META.get(f'HTTP_{header_name.replace("-", "_").upper()}', '')
                return re.match(header_value.strip(), header_actual) is not None
            return False
        
        elif rule.rule_type == 'method':
            return re.match(rule.pattern, request.method) is not None
        
        elif rule.rule_type == 'custom':
            # Custom rules should be implemented based on specific requirements
            # This is a placeholder for custom rule logic
            return False
        
        return False
    
    def _get_country_code(self, ip_address):
        """Get country code for an IP address using GeoIP cache or service."""
        # This is a placeholder - in a real implementation, you would:
        # 1. Check the GeoIPCache model first
        # 2. If not found, query an external service (like MaxMind GeoIP)
        # 3. Cache the result
        # For simplicity, we're returning a dummy value
        return None
    
    def _evaluate_rules(self, request, ip_address):
        """Evaluate all rules against the request."""
        for rule in self.active_rules:
            if self._check_rule_match(rule, request, ip_address):
                # If the rule is a block rule and the source IP matches the rule's IP pattern,
                # we should not block the request as this would lock out the admin
                if rule.rule_type == 'ip' and rule.action == 'block' and ip_address == '127.0.0.1':
                    logger.warning(f"Detected self-block attempt: Localhost IP {ip_address} matches block rule {rule.name} ({rule.pattern}). Allowing access.")
                    # For localhost (127.0.0.1), we'll always allow access regardless of rules
                    # Create a modified copy of the rule with action set to 'allow'
                    modified_rule = Rule(
                        id=rule.id,
                        name=f"{rule.name} (Self-Access Exception)",
                        rule_type=rule.rule_type,
                        pattern=rule.pattern,
                        action='allow',  # Change action to allow
                        priority=rule.priority,
                        is_active=rule.is_active,
                        description=f"Auto-modified from {rule.action} to allow for self-access: {rule.description}"
                    )
                    return modified_rule
                return rule
        return None
    
    def _create_log_entry(self, request, ip_address, matched_rule, action_taken, start_time, response=None):
        """Create a log entry for the request."""
        # Explicit check for the problematic IP
        if ip_address == '64.130.127.37':
            logger.info(f"Explicitly blocking log entry for IP: {ip_address}")
            return None
            
        # Skip logging for excluded IPs
        if hasattr(request, '_excluded_from_logging') and request._excluded_from_logging:
            logger.debug(f"Skipping log entry creation for excluded IP: {ip_address}")
            return None
            
        headers = {}
        for key, value in request.META.items():
            if key.startswith('HTTP_'):
                header_name = key[5:].replace('_', '-').title()
                headers[header_name] = value
        
        # Calculate response time in milliseconds
        response_time = int((time.time() - start_time) * 1000)
        
        # Get response code, default to 0 if no response
        response_code = getattr(response, 'status_code', 0) if response else 0
        
        country_code = self._get_country_code(ip_address)
        
        log_entry = RequestLog(
            source_ip=ip_address,
            path=request.path,
            method=request.method,
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            headers=headers,
            matched_rule=matched_rule,
            action_taken=action_taken,
            was_blocked=(action_taken == 'block'),
            response_code=response_code,
            response_time_ms=response_time,
            country=country_code
        )
        log_entry.save()
        
        # Update metrics for the dashboard
        self._update_metrics(log_entry)
        
        return log_entry
    
    def _update_metrics(self, log_entry):
        """Update dashboard metrics based on the log entry."""
        # This will be implemented later when we implement the dashboard app
        pass
    
    def _create_block_response(self, rule):
        """Create a response for blocked requests."""
        return JsonResponse({
            'error': 'Access Denied',
            'message': 'Your request has been blocked by the web application firewall.'
        }, status=403)
    
    def process_request(self, request):
        """Process the incoming request and apply firewall rules and AI threat detection."""
        start_time = time.time()
        request._request_start_time = start_time
        self._load_rules()
        
        ip_address = self._get_client_ip(request)
        
        # Skip rule evaluation and AI analysis for excluded IPs
        if hasattr(request, '_excluded_from_logging') and request._excluded_from_logging:
            logger.debug(f"Skipping rule evaluation for excluded IP: {ip_address}")
            return None
        
        # First apply traditional rule-based detection
        matched_rule = self._evaluate_rules(request, ip_address)
        request._matched_rule = matched_rule
        
        # Apply Gemini AI threat detection if enabled
        ai_threat_detected = False
        if self.enable_gemini and self.gemini:
            ai_result = self._analyze_request_with_gemini(request, ip_address)
            request._ai_analysis = ai_result
            
            # If AI detects a high-confidence threat, block the request
            if ai_result and ai_result.get('recommended_action') == 'block' and ai_result.get('confidence', 0) >= 75:
                ai_threat_detected = True
                logger.warning(f"Gemini AI detected high-confidence threat from {ip_address}: {ai_result.get('attack_type')}")
                
                # Create a synthetic rule for logging purposes
                ai_rule = Rule(
                    name=f"Gemini AI Detection: {ai_result.get('attack_type', 'Unknown Threat')}",
                    rule_type='ai',
                    pattern='ai_detection',
                    action='block',
                    is_active=True,
                    description=f"AI-detected threat: {ai_result.get('explanation', 'No explanation provided')}"
                )
                
                # Create log entry for blocked request
                log_entry = self._create_log_entry(
                    request, ip_address, ai_rule, 'block', start_time
                )
                
                # Create alert for AI-detected threat
                if log_entry:
                    self._create_alert_if_needed(log_entry, ai_rule)
                
                # Mark as already logged
                request._request_already_logged = True
                
                # Return block response
                return JsonResponse({
                    'error': 'Access Denied',
                    'message': 'Your request has been blocked by the next-generation AI firewall.',
                    'reason': ai_result.get('explanation', 'Suspicious activity detected')
                }, status=403)
        
        # Handle traditional rule-based detections if no AI block
        if matched_rule and not ai_threat_detected:
            if matched_rule.action == 'block':
                # Create log entry for blocked request
                log_entry = self._create_log_entry(
                    request, ip_address, matched_rule, 'block', start_time
                )
                
                # Create alert if configured
                self._create_alert_if_needed(log_entry, matched_rule)
                
                # Mark as already logged
                request._request_already_logged = True
                
                # Return block response
                return self._create_block_response(matched_rule)
            
            elif matched_rule.action == 'alert':
                # Allow request but create an alert
                log_entry = self._create_log_entry(
                    request, ip_address, matched_rule, 'alert', start_time
                )
                # Alert will be created after response in process_response
        
        # For requests that aren't blocked, continue processing
        # Actual logging will happen in process_response
        return None
    
    def _analyze_request_with_gemini(self, request, ip_address):
        """
        Analyze a request using the Gemini AI for advanced threat detection.
        
        Args:
            request: The HTTP request to analyze
            ip_address: The client IP address
            
        Returns:
            dict: Analysis results from Gemini, or None if analysis failed
        """
        try:
            # Format request data for analysis
            request_data = {
                'source_ip': ip_address,
                'path': request.path,
                'method': request.method,
                'user_agent': request.META.get('HTTP_USER_AGENT', ''),
                'headers': {}
            }
            
            # Extract headers
            for key, value in request.META.items():
                if key.startswith('HTTP_'):
                    header_name = key[5:].replace('_', '-').title()
                    request_data['headers'][header_name] = value
            
            # Call Gemini for analysis
            analysis_result = self.gemini.analyze_request(request_data)
            logger.debug(f"Gemini analysis for {ip_address}: {json.dumps(analysis_result)}")
            
            return analysis_result
            
        except Exception as e:
            logger.error(f"Error analyzing request with Gemini: {str(e)}")
            return None
    
    def process_response(self, request, response):
        """Process the response before it's sent back to the client and include AI analysis in logs."""
        ip_address = self._get_client_ip(request)
        
        # Skip logging for excluded IPs
        if hasattr(request, '_excluded_from_logging') and request._excluded_from_logging:
            return response
        
        # Check if this was already logged in process_request (for blocked requests)
        # If not, log it now
        if not getattr(request, '_request_already_logged', False):
            matched_rule = getattr(request, '_matched_rule', None)
            action = 'allow'  # Default action for requests that don't match any rule
            
            # Create log entry
            log_entry = self._create_log_entry(
                request, ip_address, matched_rule, action, 
                getattr(request, '_request_start_time', time.time()),
                response
            )
            
            # Add AI analysis information to the log entry if available
            ai_analysis = getattr(request, '_ai_analysis', None)
            if log_entry and ai_analysis:
                # Store AI analysis data in the extra_data field
                extra_data = log_entry.extra_data or {}
                extra_data['ai_analysis'] = {
                    'attack_type': ai_analysis.get('attack_type', 'unknown'),
                    'confidence': ai_analysis.get('confidence', 0),
                    'explanation': ai_analysis.get('explanation', ''),
                    'engine': 'gemini',
                }
                log_entry.extra_data = extra_data
                log_entry.save()
            
            # Create alert if needed
            if matched_rule and matched_rule.action == 'alert':
                self._create_alert_if_needed(log_entry, matched_rule)
                
            # Create alert for medium-confidence AI detections that weren't blocked
            if log_entry and ai_analysis and ai_analysis.get('confidence', 0) >= 50:
                # Create a synthetic rule for the AI alert
                ai_rule = Rule(
                    name=f"Gemini AI Alert: {ai_analysis.get('attack_type', 'Suspicious Activity')}",
                    rule_type='ai',
                    pattern='ai_detection',
                    action='alert',
                    is_active=True,
                    description=f"AI-detected suspicious activity: {ai_analysis.get('explanation', 'No explanation provided')}"
                )
                self._create_alert_if_needed(log_entry, ai_rule)
        
        return response


class ReverseProxyMiddleware(MiddlewareMixin):
    """
    Middleware for proxying requests to backend servers.
    """
    def __init__(self, get_response=None):
        super().__init__(get_response)  # Call parent's __init__
        self.get_response = get_response
        self.proxy_configs = {}
        self.last_config_check = 0
        self.config_cache_ttl = 60  # Cache configs for 60 seconds
        self._load_proxy_configs()
        # Add this attribute for Django compatibility
        self.async_mode = False
    
    def _load_proxy_configs(self):
        """Load active proxy configurations from the database."""
        if not self.proxy_configs or (time.time() - self.last_config_check) > self.config_cache_ttl:
            configs = ProxyConfig.objects.filter(is_active=True)
            self.proxy_configs = {config.id: config for config in configs}
            self.last_config_check = time.time()
            logger.info(f"Loaded {len(self.proxy_configs)} active proxy configurations")
    
    def process_request(self, request):
        """Process requests and proxy them to the target server."""
        # This would implement the actual reverse proxy functionality
        # For simplicity, we'll just return None here to continue the request
        # In a real implementation, this would make HTTP requests to the backend
        # and return the response
        return None