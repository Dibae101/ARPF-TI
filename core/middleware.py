import json
import time
import logging
import re
import socket
import ipaddress
from django.conf import settings
from django.utils import timezone
from django.http import HttpResponse, JsonResponse
from django.utils.deprecation import MiddlewareMixin
from .models import Rule, RequestLog, ProxyConfig
from threat_intelligence.integrations.gemini_connector import GeminiConnector

# Import the alert system
try:
    from alerts.alert_system import create_alert
    ALERTS_ENABLED = True
except ImportError:
    ALERTS_ENABLED = False
    logging.warning("Alerts app not installed or configured. Alert functionality disabled.")

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
        # Try HTTP_X_FORWARDED_FOR first (most common proxy header)
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            # Only get the first address in the chain which is the client's IP
            ip = x_forwarded_for.split(',')[0].strip()
            logger.debug(f"Using IP from X-Forwarded-For: {ip}")
            
        # Try other common proxy headers if X-Forwarded-For isn't present
        elif request.META.get('HTTP_X_REAL_IP'):
            ip = request.META.get('HTTP_X_REAL_IP')
            logger.debug(f"Using IP from X-Real-IP: {ip}")
            
        elif request.META.get('HTTP_CLIENT_IP'):
            ip = request.META.get('HTTP_CLIENT_IP')
            logger.debug(f"Using IP from Client-IP: {ip}")
            
        # Fall back to REMOTE_ADDR if no proxy headers are present
        else:
            ip = request.META.get('REMOTE_ADDR', '')
            logger.debug(f"Using IP from REMOTE_ADDR: {ip}")
        
        # Check if this IP should be excluded from logging
        if ip in self.excluded_ips:
            request._excluded_from_logging = True
            logger.debug(f"Request from excluded IP: {ip}")
        else:
            request._excluded_from_logging = False
        
        return ip
    
    def _check_rule_match(self, rule, request, ip_address):
        """Check if a request matches a rule."""
        # Logging for debugging
        logger.debug(f"Checking rule match for type '{rule.rule_type}', pattern '{rule.pattern}', IP '{ip_address}'")
        
        # IP or ip_range rule type
        if rule.rule_type in ['ip', 'ip_range']:
            try:
                # Try to interpret the pattern as a CIDR range
                if '/' in rule.pattern:
                    network = ipaddress.ip_network(rule.pattern)
                    ip = ipaddress.ip_address(ip_address)
                    match = ip in network
                else:
                    # Simple string comparison for single IPs
                    match = ip_address == rule.pattern
                
                logger.debug(f"IP match result: {match} for {ip_address} against {rule.pattern}")
                return match
            except (ValueError, ipaddress.AddressValueError):
                # If we can't parse as CIDR, fall back to regex
                logger.warning(f"Failed to parse IP/range '{rule.pattern}', falling back to regex")
                return re.match(rule.pattern, ip_address) is not None
        
        # Country code rule type
        elif rule.rule_type == 'country':
            country_code = self._get_country_code(ip_address)
            if country_code:
                # Direct string comparison is more reliable than regex for 2-letter codes
                if rule.pattern == country_code:
                    match = True
                else:
                    # Fall back to regex for more complex patterns
                    match = re.match(rule.pattern, country_code) is not None
                
                logger.debug(f"Country match result: {match} for {country_code} against pattern '{rule.pattern}'")
                return match
            return False
        
        # Handle other rule types similar to before
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
        """Get country code for an IP address using the IP patterns from our simulator."""
        # This is a simplified implementation that maps IPs to countries based on our simulation patterns
        # In a production environment, you'd use GeoIP2 or a similar service
        
        # Map from our simulation data in COUNTRY_IP_RANGES
        country_ranges = {
            'Russia': ['5.188.0.0/16', '31.13.0.0/16', '77.75.0.0/16', '95.213.0.0/16'],
            'China': ['1.202.0.0/16', '14.204.0.0/16', '27.184.0.0/16', '36.48.0.0/16'],
            'USA': ['8.0.0.0/16', '104.16.0.0/16', '184.0.0.0/16', '216.58.0.0/16'],
            'Germany': ['46.0.0.0/16', '78.48.0.0/16', '91.0.0.0/16', '217.0.0.0/16'],
            'Brazil': ['45.4.0.0/16', '131.255.0.0/16', '177.124.0.0/16', '187.1.0.0/16'],
            'India': ['14.139.0.0/16', '27.56.0.0/16', '59.144.0.0/16', '115.240.0.0/16'],
            'UK': ['5.148.0.0/16', '51.68.0.0/16', '82.132.0.0/16', '109.170.0.0/16'],
            'Australia': ['1.120.0.0/16', '27.121.0.0/16', '49.176.0.0/16', '101.0.0.0/16'],
            'Nigeria': ['41.58.0.0/16', '41.184.0.0/16', '105.112.0.0/16', '154.120.0.0/16'],
            'North Korea': ['175.45.176.0/24', '210.52.109.0/24'],
            'Iran': ['2.144.0.0/16', '5.160.0.0/16', '37.156.0.0/16', '91.108.0.0/16']
        }
        
        try:
            # Parse the IP address
            ip_obj = None
            try:
                ip_obj = ipaddress.ip_address(ip_address)
            except ValueError:
                logger.warning(f"Invalid IP address: {ip_address}")
                return None
                
            # Check each country's ranges
            for country, ip_ranges in country_ranges.items():
                for ip_range in ip_ranges:
                    try:
                        network = ipaddress.ip_network(ip_range)
                        if ip_obj in network:
                            # Return country code (2-letter code)
                            country_codes = {
                                'Russia': 'RU', 'China': 'CN', 'USA': 'US', 'Germany': 'DE', 
                                'Brazil': 'BR', 'India': 'IN', 'UK': 'GB', 'Australia': 'AU', 
                                'Nigeria': 'NG', 'North Korea': 'KP', 'Iran': 'IR'
                            }
                            country_code = country_codes.get(country, 'XX')
                            logger.debug(f"Determined country code {country_code} for IP {ip_address}")
                            return country_code
                    except ValueError:
                        logger.warning(f"Invalid IP range: {ip_range}")
                        continue
                        
            # Not found in any known range
            logger.debug(f"No country code found for IP {ip_address}")
            return None
            
        except Exception as e:
            logger.error(f"Error determining country for IP {ip_address}: {str(e)}")
            return None
    
    def _evaluate_rules(self, request, ip_address):
        """Evaluate all rules against the request."""
        logger.debug(f"Evaluating rules for request from {ip_address}")
        for rule in self.active_rules:
            if self._check_rule_match(rule, request, ip_address):
                logger.info(f"Rule match: {rule.name} ({rule.rule_type}:{rule.pattern}) matched for IP {ip_address}")
                
                # Special handling for localhost to prevent lockout
                if rule.rule_type in ['ip', 'ip_range'] and rule.action == 'block' and ip_address == '127.0.0.1':
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
                
                # IMPORTANT FIX: Always enforce all rules, not just block rules
                # This ensures alert rules also trigger correctly
                return rule
                
        logger.debug(f"No rules matched for IP {ip_address}")
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
        country_code = self._get_country_code(ip_address)
        
        # Add debug logging to help with troubleshooting
        if country_code:
            logger.info(f"Request from IP {ip_address} detected as country code {country_code}")
        
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
            logger.info(f"Rule matched: {matched_rule.name} with action '{matched_rule.action}' for IP {ip_address}")
            
            if matched_rule.action == 'block':
                logger.warning(f"Blocking request from IP {ip_address} due to rule: {matched_rule.name}")
                
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
                logger.info(f"Alerting for request from IP {ip_address} due to rule: {matched_rule.name}")
                
                # Allow request but create an alert
                log_entry = self._create_log_entry(
                    request, ip_address, matched_rule, 'alert', start_time
                )
                # Create alert
                self._create_alert_if_needed(log_entry, matched_rule)
        
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
                try:
                    # Handle the case where extra_data might not exist
                    if not hasattr(log_entry, 'extra_data') or log_entry.extra_data is None:
                        log_entry.extra_data = {}
                    
                    # Store AI analysis data in the extra_data field
                    log_entry.extra_data['ai_analysis'] = {
                        'attack_type': ai_analysis.get('attack_type', 'unknown'),
                        'confidence': ai_analysis.get('confidence', 0),
                        'explanation': ai_analysis.get('explanation', ''),
                        'engine': 'gemini',
                    }
                    log_entry.save()
                except Exception as e:
                    logger.error(f"Error updating log entry with AI analysis: {str(e)}")
            
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
    
    def _create_alert_if_needed(self, log_entry, rule):
        """Create an alert if the alerts app is enabled."""
        if not log_entry:
            return
            
        if ALERTS_ENABLED:
            try:
                # Determine alert severity based on rule action
                severity = 'high' if rule.action == 'block' else 'medium'
                
                # Create alert
                create_alert(
                    title=f"{rule.action.title()} - {rule.name}",
                    message=f"Rule triggered for IP {log_entry.source_ip} on path {log_entry.path}",
                    source="WAF",
                    severity=severity,
                    source_id=str(rule.id) if hasattr(rule, 'id') and rule.id else "no_id",
                    details={
                        'rule_name': rule.name,
                        'rule_type': rule.rule_type,
                        'pattern': rule.pattern,
                        'action': rule.action,
                        'ip_address': log_entry.source_ip,
                        'path': log_entry.path,
                        'method': log_entry.method,
                        'user_agent': log_entry.user_agent,
                        'log_entry_id': log_entry.id
                    }
                )
            except Exception as e:
                logger.error(f"Error creating alert: {str(e)}")
        else:
            logger.debug("Alerts functionality is disabled. No alert created.")


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