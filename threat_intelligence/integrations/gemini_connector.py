import json
import logging
import requests
import ipaddress
from django.conf import settings
from django.utils import timezone
from ..models import ThreatIntelEntry

logger = logging.getLogger('arpf_ti')

class GeminiConnector:
    """
    Connector for Google's Gemini AI API for threat detection.
    This class handles all interactions with the Gemini API for analyzing 
    and detecting potential threats in network traffic and requests.
    """
    
    def __init__(self, source=None):
        """Initialize the Gemini connector."""
        self.source = source
        self.api_key = settings.GEMINI_API_KEY
        self.api_url = settings.GEMINI_API_URL
        
        # Common attack patterns to enhance detection
        self.attack_patterns = {
            'sql_injection': [
                "SELECT", "UNION", "INSERT", "UPDATE", "DELETE", "DROP", 
                "1=1", "OR 1=", "--", "/*", "#", "';", "WAITFOR DELAY"
            ],
            'xss': [
                "<script>", "javascript:", "onerror=", "onload=", "eval(", 
                "document.cookie", "alert(", "String.fromCharCode", "<img src"
            ],
            'path_traversal': [
                "../", "..", "/..", "%2e%2e", "etc/passwd", "boot.ini", 
                "wp-config.php", "web.config", "\\..\\", "%c0%ae%c0%ae/"
            ],
            'command_injection': [
                "; ", "& ", "| ", "`", "$", "$(", "cat ", "wget ", "curl ", 
                "ping ", "chmod ", "nc ", "bash ", "/bin/sh"
            ],
            'suspicious_ips': []
        }
        
        # Load suspicious country CIDR blocks
        self.suspicious_country_blocks = self._load_suspicious_country_blocks()
        
        # Enhanced country block list - more comprehensive
        self.blocked_countries = [
            'RU', 'CN', 'KP', 'IR', 'SY', 'VE', 'BY', 'MM'
        ]
        
        # Create an in-memory cache of recently analyzed requests to avoid duplicates
        self.analysis_cache = {}
        self.cache_ttl = 300  # 5 minutes
        
    def _load_suspicious_country_blocks(self):
        """Load suspicious country IP blocks for enhanced detection"""
        # This would typically load from database, but we'll hardcode for now
        return {
            'north_korea': ['175.45.176.0/24', '210.52.109.0/24'],
            'russia': ['95.213.0.0/16', '178.248.232.0/21'],
            'china': ['27.16.0.0/12', '124.192.0.0/14', '61.128.0.0/10'],
            'iran': ['91.98.0.0/15', '5.160.0.0/13'],
            'known_attack_sources': [
                '185.220.101.0/24', # Tor exit nodes
                '89.248.0.0/16',    # Common scanning source
                '134.209.0.0/16',   # Digital Ocean (common VPS for attacks)
                '103.103.0.0/24',   # Known attack source
                '185.156.73.0/24',  # Known bot network
                '92.118.160.0/24'   # Scanning network
            ]
        }
        
    def analyze_request(self, request_data):
        """
        Analyze a request using Gemini to determine if it's a potential threat.
        
        Args:
            request_data (dict): Data about the request to analyze (IP, headers, path, etc.)
            
        Returns:
            dict: Analysis results including threat score, reason, and recommended action
        """
        # Check cache first to avoid reanalyzing recent requests
        cache_key = self._generate_cache_key(request_data)
        if cache_key in self.analysis_cache:
            cached_result = self.analysis_cache[cache_key]
            if timezone.now().timestamp() - cached_result['timestamp'] < self.cache_ttl:
                return cached_result['result']
        
        # Pre-analyze using pattern matching for faster detection
        preliminary_analysis = self._pre_analyze_request(request_data)
        
        # If pre-analysis detected a high-confidence threat, return immediately
        if preliminary_analysis and preliminary_analysis.get('confidence', 0) >= 90:
            logger.info(f"Fast-track threat detection: {preliminary_analysis.get('attack_type')} from {request_data.get('source_ip')}")
            
            # Store in cache
            self.analysis_cache[cache_key] = {
                'result': preliminary_analysis,
                'timestamp': timezone.now().timestamp()
            }
            
            return preliminary_analysis
        
        # Format the request data for Gemini analysis with enhanced context
        prompt = self._format_request_for_analysis(request_data, preliminary_analysis)
        
        # Call Gemini API for analysis
        response = self._call_gemini_api(prompt)
        
        # Process and interpret the response
        analysis_result = self._interpret_gemini_response(response, request_data, preliminary_analysis)
        
        # Enhance the result with firewall rule suggestion
        analysis_result = self._add_firewall_rule_suggestion(analysis_result, request_data)
        
        # Store in cache
        self.analysis_cache[cache_key] = {
            'result': analysis_result,
            'timestamp': timezone.now().timestamp()
        }
        
        return analysis_result
    
    def _generate_cache_key(self, request_data):
        """Generate a unique cache key for a request."""
        ip = request_data.get('source_ip', '')
        path = request_data.get('path', '')
        method = request_data.get('method', '')
        return f"{ip}:{method}:{path}"
    
    def _pre_analyze_request(self, request_data):
        """
        Perform quick pattern-based analysis before calling the API.
        This catches obvious attacks without waiting for API response.
        """
        ip = request_data.get('source_ip', '')
        path = request_data.get('path', '')
        user_agent = request_data.get('user_agent', '')
        headers = request_data.get('headers', {})
        method = request_data.get('method', '')
        query_params = request_data.get('query_params', {})
        
        # Check for known bad IP ranges
        ip_threat_score = self._check_ip_threat(ip)
        if ip_threat_score >= 90:
            return {
                "attack_type": "suspicious_source",
                "confidence": 95,
                "recommended_action": "block",
                "explanation": f"IP address {ip} is from a known threat source",
                "source_ip": ip,
                "request_path": path,
                "timestamp": timezone.now().isoformat(),
                "rule_suggestion": {
                    "type": "ip",
                    "pattern": ip,
                    "description": "Automatically detected malicious IP address"
                }
            }
        
        # Check for known country blocks
        country_code = self._get_country_code(ip)
        if country_code and country_code in self.blocked_countries:
            return {
                "attack_type": "blocked_country",
                "confidence": 95,
                "recommended_action": "block",
                "explanation": f"Traffic from blocked country {country_code}",
                "source_ip": ip,
                "request_path": path,
                "timestamp": timezone.now().isoformat(),
                "rule_suggestion": {
                    "type": "country",
                    "pattern": country_code,
                    "description": f"Traffic from blocked country {country_code}"
                }
            }
        
        # Check for SQL injection patterns
        sql_injection_score = 0
        for pattern in self.attack_patterns['sql_injection']:
            if pattern.lower() in path.lower() or pattern.lower() in str(headers).lower() or pattern.lower() in str(query_params).lower():
                sql_injection_score += 30
                if sql_injection_score >= 90:
                    return {
                        "attack_type": "sql_injection",
                        "confidence": 95,
                        "recommended_action": "block",
                        "explanation": f"SQL injection attempt detected in request",
                        "source_ip": ip,
                        "request_path": path,
                        "timestamp": timezone.now().isoformat(),
                        "rule_suggestion": {
                            "type": "path",
                            "pattern": path,
                            "description": "SQL injection attempt"
                        }
                    }
        
        # Check for XSS patterns
        xss_score = 0
        for pattern in self.attack_patterns['xss']:
            if pattern.lower() in path.lower() or pattern.lower() in str(headers).lower() or pattern.lower() in str(query_params).lower():
                xss_score += 30
                if xss_score >= 90:
                    return {
                        "attack_type": "xss",
                        "confidence": 95,
                        "recommended_action": "block",
                        "explanation": f"Cross-site scripting attempt detected",
                        "source_ip": ip,
                        "request_path": path,
                        "timestamp": timezone.now().isoformat(),
                        "rule_suggestion": {
                            "type": "path",
                            "pattern": path,
                            "description": "XSS attempt"
                        }
                    }
        
        # Check for path traversal
        path_traversal_score = 0
        for pattern in self.attack_patterns['path_traversal']:
            if pattern.lower() in path.lower() or pattern.lower() in str(query_params).lower():
                path_traversal_score += 30
                if path_traversal_score >= 90:
                    return {
                        "attack_type": "path_traversal",
                        "confidence": 95,
                        "recommended_action": "block",
                        "explanation": f"Path traversal attempt detected",
                        "source_ip": ip,
                        "request_path": path,
                        "timestamp": timezone.now().isoformat(),
                        "rule_suggestion": {
                            "type": "path",
                            "pattern": path,
                            "description": "Path traversal attempt"
                        }
                    }
        
        # Check for command injection
        cmd_injection_score = 0
        for pattern in self.attack_patterns['command_injection']:
            if pattern.lower() in path.lower() or pattern.lower() in str(query_params).lower():
                cmd_injection_score += 30
                if cmd_injection_score >= 90:
                    return {
                        "attack_type": "command_injection",
                        "confidence": 95,
                        "recommended_action": "block",
                        "explanation": f"Command injection attempt detected",
                        "source_ip": ip,
                        "request_path": path,
                        "timestamp": timezone.now().isoformat(),
                        "rule_suggestion": {
                            "type": "path",
                            "pattern": path,
                            "description": "Command injection attempt"
                        }
                    }
        
        # Check for malicious user agents
        if user_agent:
            # Check for empty or suspicious user agents
            if len(user_agent) < 5 or user_agent in ["", "-", "curl", "wget"]:
                return {
                    "attack_type": "suspicious_user_agent",
                    "confidence": 80,
                    "recommended_action": "block",
                    "explanation": f"Suspicious or empty user agent: {user_agent}",
                    "source_ip": ip,
                    "request_path": path,
                    "timestamp": timezone.now().isoformat(),
                    "rule_suggestion": {
                        "type": "user_agent",
                        "pattern": user_agent,
                        "description": "Suspicious user agent"
                    }
                }
            
            # Check for known bot/crawler user agents
            bot_patterns = ["bot", "crawler", "spider", "scan", "exploit"]
            if any(pattern in user_agent.lower() for pattern in bot_patterns):
                # Check if this is a legitimate crawler
                legitimate_bots = ["googlebot", "bingbot", "yandexbot", "slurp", "duckduckbot", "baiduspider"]
                if not any(bot in user_agent.lower() for bot in legitimate_bots):
                    return {
                        "attack_type": "suspicious_bot",
                        "confidence": 85,
                        "recommended_action": "block",
                        "explanation": f"Suspicious bot/crawler: {user_agent}",
                        "source_ip": ip,
                        "request_path": path,
                        "timestamp": timezone.now().isoformat(),
                        "rule_suggestion": {
                            "type": "user_agent",
                            "pattern": user_agent,
                            "description": "Suspicious bot/crawler"
                        }
                    }
        
        # If nothing was detected with high confidence, return None or low-confidence analysis
        if sql_injection_score > 0 or xss_score > 0 or path_traversal_score > 0 or cmd_injection_score > 0:
            # Return a composite score for further analysis
            return {
                "attack_type": "potential_attack",
                "confidence": max(sql_injection_score, xss_score, path_traversal_score, cmd_injection_score),
                "recommended_action": "analyze",
                "explanation": "Potential attack signature detected but needs further analysis",
                "source_ip": ip,
                "request_path": path,
                "timestamp": timezone.now().isoformat()
            }
        
        return None
        
    def _check_ip_threat(self, ip):
        """
        Check if an IP is from a suspicious source.
        Returns a threat score from 0-100.
        """
        if not ip:
            return 0
            
        threat_score = 0
        
        # Check if IP is in suspicious blocks
        for country, cidr_blocks in self.suspicious_country_blocks.items():
            for cidr in cidr_blocks:
                try:
                    if ipaddress.ip_address(ip) in ipaddress.ip_network(cidr):
                        threat_score += 60  # High baseline score for suspicious ranges
                        logger.info(f"IP {ip} matched suspicious CIDR block {cidr} ({country})")
                        break
                except ValueError:
                    continue
        
        # Check ThreatIntelEntry database for known malicious IPs
        try:
            # Fixed field names: 'entry_type' instead of 'indicator_type' and 'value' instead of 'indicator_value'
            if ThreatIntelEntry.objects.filter(entry_type='ip', value=ip, is_active=True).exists():
                threat_score += 70
                logger.info(f"IP {ip} matched known threat intelligence entry")
        except Exception as e:
            logger.error(f"Error checking threat intel for IP {ip}: {e}")
        
        # Cap the score at 100
        return min(threat_score, 100)
    
    def _get_country_code(self, ip):
        """Get country code for an IP address."""
        # This would normally use a GeoIP database or service
        # For demonstration, we'll return a dummy value
        # In production, use MaxMind GeoIP or similar
        if not ip:
            return None
        
        # Dummy country mapping for demonstration
        dummy_mappings = {
            "185.220": "RU",
            "89.248": "CN", 
            "134.209": "IR",
            "103.103": "KP",
            "45.227": "VE",
            "91.192": "BY",
            "103.195": "RU",
            "193.163": "RU"
        }
        
        # Check if IP prefix matches any in our dummy mappings
        for prefix, country in dummy_mappings.items():
            if ip.startswith(prefix):
                return country
                
        return None
        
    def _format_request_for_analysis(self, request_data, preliminary_analysis=None):
        """
        Format the request data for Gemini analysis.
        """
        ip = request_data.get('source_ip', '')
        path = request_data.get('path', '')
        user_agent = request_data.get('user_agent', '')
        headers = request_data.get('headers', {})
        method = request_data.get('method', '')
        
        # Create a more descriptive prompt for Gemini
        prompt = f"""
        Analyze this web request for security threats:
        
        Source IP: {ip}
        Method: {method}
        Path: {path}
        User-Agent: {user_agent}
        
        Headers:
        {json.dumps(headers, indent=2)}
        
        Preliminary Analysis: {json.dumps(preliminary_analysis) if preliminary_analysis else "None"}
        
        Analyze for:
        1. SQL Injection
        2. Cross-Site Scripting (XSS)
        3. Path Traversal
        4. Command Injection
        5. Suspicious IP/Source
        6. Unusual User-Agent
        7. Known attack patterns
        8. Unauthorized access attempts
        
        Provide: 
        - Attack type (if detected)
        - Confidence score (0-100)
        - Recommended action (block, alert, allow)
        - Brief explanation
        """
        
        return prompt
        
    def _call_gemini_api(self, prompt):
        """
        Call the Gemini API for threat analysis.
        
        Args:
            prompt: The formatted prompt for analysis
            
        Returns:
            The API response text
        """
        try:
            # For demonstration, we'll simulate an API response
            # In production, this would make an actual API call
            
            # Simulate Gemini API call response
            response = {
                "attack_type": None,
                "confidence": 0,
                "recommended_action": "allow",
                "explanation": "No threats detected"
            }
            
            # Log the API call
            logger.debug(f"Simulated Gemini API call for threat detection")
            
            return json.dumps(response)
        except Exception as e:
            logger.error(f"Error calling Gemini API: {str(e)}")
            return None
            
    def _interpret_gemini_response(self, response_text, request_data, preliminary_analysis=None):
        """
        Interpret the Gemini API response to extract threat information.
        
        Args:
            response_text: The API response text
            request_data: The original request data
            preliminary_analysis: Any preliminary analysis already performed
            
        Returns:
            dict: Interpreted threat analysis results
        """
        if not response_text:
            return {
                "attack_type": "unknown",
                "confidence": 0,
                "recommended_action": "allow",
                "explanation": "Failed to analyze request",
                "source_ip": request_data.get('source_ip', ''),
                "request_path": request_data.get('path', ''),
                "timestamp": timezone.now().isoformat()
            }
        
        try:
            # Parse the response - in production this would extract JSON from the API response
            response_data = json.loads(response_text)
            
            # If we already have preliminary analysis with higher confidence, use that
            if preliminary_analysis and preliminary_analysis.get('confidence', 0) > response_data.get('confidence', 0):
                return preliminary_analysis
            
            # Add source IP and request path for context
            response_data['source_ip'] = request_data.get('source_ip', '')
            response_data['request_path'] = request_data.get('path', '')
            response_data['timestamp'] = timezone.now().isoformat()
            
            return response_data
        except Exception as e:
            logger.error(f"Error interpreting Gemini response: {str(e)}")
            
            # Default to using preliminary analysis if available, or create a safe default
            if preliminary_analysis:
                return preliminary_analysis
                
            return {
                "attack_type": "unknown",
                "confidence": 0,
                "recommended_action": "allow",
                "explanation": f"Failed to interpret analysis: {str(e)}",
                "source_ip": request_data.get('source_ip', ''),
                "request_path": request_data.get('path', ''),
                "timestamp": timezone.now().isoformat()
            }
            
    def _add_firewall_rule_suggestion(self, analysis_result, request_data):
        """
        Add a firewall rule suggestion to the analysis result if the threat is detected.
        Also store the suggestion in the database for admin review.
        
        Args:
            analysis_result: The analysis result from Gemini
            request_data: The original request data
            
        Returns:
            The enhanced analysis result with rule suggestion
        """
        if not analysis_result or analysis_result.get('recommended_action') != 'block':
            return analysis_result
        
        # Skip if confidence is too low
        confidence = analysis_result.get('confidence', 0)
        if confidence < 70:  # Only suggest rules for medium-to-high confidence threats
            return analysis_result
        
        # Get relevant data
        attack_type = analysis_result.get('attack_type', 'unknown')
        source_ip = request_data.get('source_ip', '')
        request_path = request_data.get('path', '')
        user_agent = request_data.get('user_agent', '')
        
        # Determine rule type and pattern based on attack type
        rule_type = 'custom'
        pattern = ''
        description = f"Auto-suggested rule for {attack_type} attack"
        
        if attack_type in ['sql_injection', 'xss', 'path_traversal', 'command_injection']:
            rule_type = 'path'
            pattern = request_path
            description = f"Blocking path due to detected {attack_type} attack"
        elif attack_type in ['suspicious_source', 'blocked_country']:
            rule_type = 'ip'
            pattern = source_ip
            description = f"Blocking IP associated with {attack_type}"
        elif attack_type == 'suspicious_user_agent':
            rule_type = 'user_agent'
            pattern = user_agent
            description = f"Blocking suspicious user agent: {user_agent}"
        
        # Create rule suggestion
        try:
            from ..models import SuggestedFirewallRule
            
            # Check if this exact rule has been suggested recently
            existing = SuggestedFirewallRule.objects.filter(
                rule_type=rule_type,
                pattern=pattern,
                created_at__gte=timezone.now() - timezone.timedelta(hours=24)
            ).exists()
            
            if not existing:
                suggestion = SuggestedFirewallRule(
                    rule_type=rule_type,
                    pattern=pattern,
                    description=description,
                    confidence=confidence,
                    attack_type=attack_type,
                    source_ip=source_ip,
                    request_path=request_path,
                    # Auto-approve high confidence threats
                    status='auto_approved' if confidence >= 90 else 'pending'
                )
                suggestion.save()
                
                # Auto-apply rules with very high confidence
                if confidence >= 90:
                    rule = suggestion.apply_rule()
                    logger.info(f"Auto-applied firewall rule: {description}")
        
        except Exception as e:
            logger.error(f"Error creating firewall rule suggestion: {str(e)}")
        
        # Add suggestion to analysis result
        analysis_result['rule_suggestion'] = {
            'type': rule_type,
            'pattern': pattern,
            'description': description
        }
        
        return analysis_result