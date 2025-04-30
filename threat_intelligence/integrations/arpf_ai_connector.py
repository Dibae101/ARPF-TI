import logging
import re
import ipaddress
import random
from datetime import datetime, timedelta
from django.utils import timezone

logger = logging.getLogger('arpf_ti')

class ARPFAIConnector:
    """
    ARPF AI Connector - Advanced Recursive Pattern Finding and Threat Intelligence system
    
    This connector provides AI-powered threat analysis capabilities:
    1. Continuous Learning: Analyzes patterns in network traffic and threat data
    2. Adaptive Defense: Evolves defense strategies based on observed attack patterns
    3. Traffic Analysis: Examines requests, responses, and data flows
    4. Automated Response: Suggests or implements countermeasures for threats
    """
    
    def __init__(self, source="default"):
        """
        Initialize the ARPF AI connector.
        
        Args:
            source: Source identifier for logging purposes
        """
        self.source = source
        self.learned_patterns = {}
        self.known_attack_signatures = self._load_attack_signatures()
        self.ip_reputation_cache = {}
        self.request_history = []
        self.max_history = 1000  # Maximum requests to keep in memory
        self.known_bad_user_agents = self.known_attack_signatures.get('suspicious_user_agents', [])
        self.threat_patterns = {'ip': set(), 'path': set(), 'user_agent': set()}
        self.normal_traffic_patterns = {'common_paths': set(['/','index.html','/about','/login'])}
        self.version = "2.3.0"
        self.last_updated = timezone.now()
        logger.info(f"ARPF AI Connector initialized for source: {source}")
    
    def _load_attack_signatures(self):
        """Load known attack signatures for pattern matching."""
        # In a real implementation, these would be loaded from a database or file
        return {
            'sql_injection': [
                r"['\"]\s*(?:or|OR|Or)\s*['\"]\s*=\s*['\"]",  # Basic OR-based SQLi
                r"(?:UNION|union)(?:\s+ALL|\s+all|\s+All)?\s+SELECT",  # UNION SELECT
                r"(?:--|\#|\/\*)+",  # SQL comment markers
                r"(?:SLEEP|sleep)\s*\(\s*\d+\s*\)",  # Time-based SQLi
                r"(?:BENCHMARK|benchmark)\s*\(",  # Benchmark function
                r"(?:DROP|drop|Truncate|TRUNCATE|delete|DELETE)\s+(?:TABLE|table|DATABASE|database)",  # Destructive SQL
                r"[;]\s*(?:DROP|INSERT|UPDATE|DELETE)\s+",  # Multiple statements
                r"INTO\s+(?:OUTFILE|outfile|dumpfile|DUMPFILE)",  # File operations
                r"(?:LOAD_FILE|load_file|LOAD DATA|load data)"  # File reading
            ],
            'xss': [
                r"<script\b[^>]*>",  # Basic script tag
                r"<img\b[^>]*on\w+\s*=",  # Image with event handler
                r"javascript\s*:",  # JavaScript protocol 
                r"(?:on\w+\s*=)",  # Event handlers
                r"(?:<[^>]*\s+on\w+\s*=)",  # Tag with event handler
                r"(?:&#x?\d+;)",  # Numeric character reference
                r"document\.(?:cookie|location|referrer|domain|write|createElement)",  # DOM manipulation
                r"(?:alert|confirm|prompt)\s*\(",  # Alert dialogs
                r"(?:eval|Function|setTimeout|setInterval)\s*\("  # JS execution functions
            ],
            'path_traversal': [
                r"\.{2,}[\/\\]",  # Basic directory traversal
                r"%2e%2e%2f",  # URL encoded ../ 
                r"%252e%252e%252f",  # Double URL encoded ../
                r"\.+[\/\\](?:etc|windows|system|boot|root|usr|var|bin|tmp)",  # Targeting specific directories
                r"(?:etc|passwd|shadow|hosts|group|config)",  # Sensitive files
                r"(?:\.ini|\.conf|\.config|\.xml|\.json|\.env|\.yml)\b",  # Config file extensions
                r"(?:wp-config\.php|config\.php|web\.config|settings\.php)"  # Web app configs
            ],
            'command_injection': [
                r"[;&|`]\s*(?:cat|ls|dir|pwd|cd|echo|wget|curl|nc|bash|sh)",  # Basic commands
                r"\|\s*(?:cat|grep|awk|sed|perl|python|ruby)",  # Piped commands
                r"(?:ping|nslookup|dig|host|traceroute)\s+(?:\d{1,3}\.){3}\d{1,3}",  # Network tools
                r"(?:wget|curl)\s+(?:https?|ftp)\:\/\/",  # Downloads
                r"(?:chmod|chown|touch|mkdir|rm|cp|mv)\s+[\w\/\.]+"  # File operations
            ],
            'suspicious_user_agents': [
                r"(?:sqlmap|nikto|nmap|dirbuster|gobuster|wpscan|hydra|medusa)",  # Security tools
                r"(?:zgrab|masscan|shodan|censys)",  # Internet scanners
                r"^(?:curl|wget|python-requests|go-http-client|ruby|perl)",  # API clients/scrapers
                r"(?:harvest|crawler|spider|bot)",  # Crawler indication
                r"^(?:Mozilla\/\d+\.\d+\s+\(compatible;)",  # Suspicious compatible strings
                r"(?:testing|pentest|security|vulnerability)"  # Security testing indicators
            ]
        }
    
    def analyze_request(self, request_data):
        """
        Analyze a single HTTP request for potential threats.
        
        Args:
            request_data: Dictionary containing request data (ip, path, method, user_agent, etc.)
            
        Returns:
            dict: Analysis results with threat assessment
        """
        # Add request to history for pattern learning
        self._add_to_history(request_data)
        
        # Build analysis result
        result = {
            'is_threat': False,
            'attack_type': 'none',
            'confidence': 0,
            'explanation': '',
            'recommended_action': 'allow',
            'timestamp': timezone.now().isoformat(),
            'source_ip': request_data.get('source_ip'),
            'request_path': request_data.get('path'),
            'user_agent': request_data.get('user_agent'),
            'rule_suggestion': None
        }
        
        # Check IP reputation
        ip_analysis = self._analyze_ip_reputation(request_data.get('source_ip', ''))
        if ip_analysis['is_threat']:
            result.update({
                'is_threat': True,
                'attack_type': ip_analysis['attack_type'],
                'confidence': ip_analysis['confidence'],
                'explanation': ip_analysis['explanation'],
                'recommended_action': ip_analysis['recommended_action']
            })
            
            # Early return for high-confidence IP threats
            if ip_analysis['confidence'] >= 90:
                return result
        
        # Check for attack signatures in the path and query parameters
        signature_analysis = self._analyze_signatures(request_data)
        if signature_analysis['is_threat'] and (not result['is_threat'] or signature_analysis['confidence'] > result['confidence']):
            result.update({
                'is_threat': True,
                'attack_type': signature_analysis['attack_type'],
                'confidence': signature_analysis['confidence'],
                'explanation': signature_analysis['explanation'],
                'recommended_action': signature_analysis['recommended_action']
            })
        
        # Check user agent for suspiciousness
        ua_analysis = self._analyze_user_agent(request_data.get('user_agent', ''))
        if ua_analysis['is_threat'] and (not result['is_threat'] or ua_analysis['confidence'] > result['confidence']):
            result.update({
                'is_threat': True,
                'attack_type': ua_analysis['attack_type'],
                'confidence': ua_analysis['confidence'],
                'explanation': ua_analysis['explanation'],
                'recommended_action': ua_analysis['recommended_action']
            })
        
        # Apply behavioral analysis
        behavior_analysis = self._analyze_behavior(request_data.get('source_ip', ''))
        if behavior_analysis['is_threat'] and (not result['is_threat'] or behavior_analysis['confidence'] > result['confidence']):
            result.update({
                'is_threat': True,
                'attack_type': behavior_analysis['attack_type'],
                'confidence': behavior_analysis['confidence'],
                'explanation': behavior_analysis['explanation'],
                'recommended_action': behavior_analysis['recommended_action']
            })
        
        # Generate rule suggestion if needed
        if result['is_threat'] and result['confidence'] >= 75:
            result['rule_suggestion'] = self._generate_rule_suggestion(result, request_data)
        
        # Apply continuous learning - update patterns based on this analysis
        self._update_learned_patterns(request_data, result)
        
        # If nothing triggered, this is probably benign traffic
        if not result['is_threat']:
            result['explanation'] = "No threat indicators detected in the request"
        
        return result
    
    def _add_to_history(self, request_data):
        """Add a request to history for pattern learning."""
        self.request_history.append({
            'timestamp': timezone.now(),
            'source_ip': request_data.get('source_ip'),
            'path': request_data.get('path'),
            'method': request_data.get('method'),
            'user_agent': request_data.get('user_agent')
        })
        
        # Trim history if needed
        if len(self.request_history) > self.max_history:
            self.request_history = self.request_history[-self.max_history:]
    
    def _analyze_ip_reputation(self, ip):
        """
        Analyze IP reputation using multiple sources and techniques.
        
        Args:
            ip: The IP address to analyze
            
        Returns:
            dict: Analysis result for the IP
        """
        # Use cached result if available
        if ip in self.ip_reputation_cache:
            return self.ip_reputation_cache[ip]
        
        result = {
            'is_threat': False,
            'attack_type': 'none',
            'confidence': 0,
            'explanation': '',
            'recommended_action': 'allow'
        }
        
        # Check for private/reserved IP ranges
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private or ip_obj.is_reserved or ip_obj.is_loopback:
                # Usually not a threat, but could be in some contexts
                # For our purposes, we'll consider these low-risk
                result = {
                    'is_threat': False,
                    'attack_type': 'internal_ip',
                    'confidence': 10,
                    'explanation': f"IP {ip} is a private/reserved address",
                    'recommended_action': 'allow'
                }
                self.ip_reputation_cache[ip] = result
                return result
        except ValueError:
            # Invalid IP address format
            result = {
                'is_threat': True,
                'attack_type': 'invalid_ip',
                'confidence': 80,
                'explanation': f"Invalid IP address format: {ip}",
                'recommended_action': 'block'
            }
            self.ip_reputation_cache[ip] = result
            return result
        
        # In a real implementation, we would check against:
        # 1. Local IP reputation database
        # 2. External IP intelligence services (AbuseIPDB, VirusTotal, etc.)
        # 3. Known bot networks and Tor exit nodes
        
        # For this implementation, we'll use a simulated check based on the IP
        # to demonstrate the functionality
        
        # Simulated threat intelligence for specific IPs
        known_bad_ips = {
            # Tor exit nodes
            "185.220.101.34": {"confidence": 80, "type": "tor_exit_node", "action": "monitor"},
            "51.15.43.205": {"confidence": 80, "type": "tor_exit_node", "action": "monitor"},
            
            # Known scanners
            "89.248.167.131": {"confidence": 90, "type": "scanner", "action": "block"},
            "45.227.255.98": {"confidence": 85, "type": "scanner", "action": "block"},
            "92.118.161.17": {"confidence": 80, "type": "scanning", "action": "block"},
            "185.156.73.54": {"confidence": 95, "type": "scanning", "action": "block"},
            
            # Attack sources
            "134.209.82.14": {"confidence": 95, "type": "attack_source", "action": "block"},
            "103.103.0.100": {"confidence": 90, "type": "attack_source", "action": "block"},
            "92.118.160.1": {"confidence": 85, "type": "scanning", "action": "block"},
        }
        
        # Check if the IP is in our known bad list
        if ip in known_bad_ips:
            bad_ip_info = known_bad_ips[ip]
            result = {
                'is_threat': True,
                'attack_type': bad_ip_info['type'],
                'confidence': bad_ip_info['confidence'],
                'explanation': f"IP {ip} identified as {bad_ip_info['type'].replace('_', ' ')}",
                'recommended_action': bad_ip_info['action']
            }
            self.ip_reputation_cache[ip] = result
            return result
        
        # Probabilistic check for IPs not in our explicit list
        # This simulates a more sophisticated reputation check
        ip_parts = ip.split('.')
        if len(ip_parts) == 4:
            # Convert the last two octets to integers
            try:
                octet3 = int(ip_parts[2])
                octet4 = int(ip_parts[3])
                
                # Deterministic randomness based on the IP
                combined = octet3 * 256 + octet4
                
                # Suspicious ranges (simulating reputation data)
                if ip.startswith('198.51.100.'):
                    # Test net - use as slightly suspicious
                    result = {
                        'is_threat': combined % 10 == 0,  # 10% chance of being flagged
                        'attack_type': 'suspicious_source',
                        'confidence': 60 + (combined % 20),
                        'explanation': f"IP {ip} has moderate negative reputation",
                        'recommended_action': 'monitor'
                    }
                elif ip.startswith('203.0.113.'):
                    # Test net - generally good reputation
                    result = {
                        'is_threat': False, 
                        'attack_type': 'none',
                        'confidence': 0,
                        'explanation': f"IP {ip} has good reputation",
                        'recommended_action': 'allow'
                    }
                else:
                    # Random check for other IPs
                    hash_val = combined % 100  # 0-99
                    
                    # Flag as suspicious with low probability
                    if hash_val < 5:  # 5% chance
                        result = {
                            'is_threat': True,
                            'attack_type': 'suspicious_source',
                            'confidence': 65 + hash_val,
                            'explanation': f"IP {ip} has some suspicious activity history",
                            'recommended_action': 'monitor'
                        }
            except ValueError:
                # Invalid IP octet format
                pass
        
        # Cache the result
        self.ip_reputation_cache[ip] = result
        return result
    
    def _analyze_signatures(self, request_data):
        """
        Analyze request for known attack signatures.
        
        Args:
            request_data: Dictionary containing request data
            
        Returns:
            dict: Analysis result based on signature detection
        """
        result = {
            'is_threat': False,
            'attack_type': 'none',
            'confidence': 0,
            'explanation': '',
            'recommended_action': 'allow'
        }
        
        # Combine path and query parameters for analysis
        path = request_data.get('path', '')
        query_string = ''
        
        if '?' in path:
            path_parts = path.split('?', 1)
            path = path_parts[0]
            query_string = path_parts[1]
        
        # Check for signatures in the full request path
        full_path = request_data.get('path', '')
        
        for attack_type, patterns in self.known_attack_signatures.items():
            if attack_type == 'suspicious_user_agents':
                continue  # Skip, we handle this separately
                
            for pattern in patterns:
                if re.search(pattern, full_path, re.IGNORECASE):
                    confidence = self._calculate_signature_confidence(attack_type, pattern, full_path)
                    
                    if confidence > result['confidence']:
                        result = {
                            'is_threat': True,
                            'attack_type': attack_type,
                            'confidence': confidence,
                            'explanation': f"Detected {attack_type.replace('_', ' ')} pattern in request path",
                            'recommended_action': 'block' if confidence >= 80 else 'monitor'
                        }
        
        # Check query parameters individually for more precise detection
        query_params = request_data.get('query_params', {})
        for param_name, param_value in query_params.items():
            for attack_type, patterns in self.known_attack_signatures.items():
                if attack_type == 'suspicious_user_agents':
                    continue  # Skip, we handle this separately
                    
                for pattern in patterns:
                    if re.search(pattern, param_value, re.IGNORECASE):
                        confidence = self._calculate_signature_confidence(attack_type, pattern, param_value)
                        
                        if confidence > result['confidence']:
                            result = {
                                'is_threat': True,
                                'attack_type': attack_type,
                                'confidence': confidence,
                                'explanation': f"Detected {attack_type.replace('_', ' ')} pattern in parameter '{param_name}'",
                                'recommended_action': 'block' if confidence >= 80 else 'monitor'
                            }
        
        return result
    
    def _calculate_signature_confidence(self, attack_type, pattern, matched_string):
        """
        Calculate confidence score for a signature match.
        
        Args:
            attack_type: Type of attack detected
            pattern: Pattern that matched
            matched_string: String that contained the match
            
        Returns:
            int: Confidence score (0-100)
        """
        # Base confidence by attack type
        base_confidence = {
            'sql_injection': 80,
            'xss': 75,
            'path_traversal': 85,
            'command_injection': 90,
            'suspicious_user_agents': 65
        }.get(attack_type, 70)
        
        # Adjust based on pattern specificity and match quality
        adjustment = 0
        
        # More complex patterns are more reliable
        pattern_complexity = len(pattern) / 10  # 0-10 points for complexity
        adjustment += min(10, pattern_complexity)
        
        # More of the input string matched = higher confidence
        match = re.search(pattern, matched_string, re.IGNORECASE)
        if match:
            match_ratio = len(match.group(0)) / len(matched_string)
            adjustment += match_ratio * 10  # 0-10 points for match ratio
        
        # Exact parameter names that are commonly attacked
        if attack_type == 'sql_injection' and re.search(r'(?:id|user|pass|login|query|search)', matched_string, re.IGNORECASE):
            adjustment += 5
        
        # False positive patterns
        false_positive_indicators = {
            'sql_injection': [r'O\'Reilly', r'isn\'t', r'don\'t', r'--disable', r'--help'],
            'xss': [r'<script src=[\'"]https?://[^\'">]+[\'"]></script>'],
            'path_traversal': [r'../templates/', r'../includes/', r'../assets/'],
            'command_injection': [r'echo chamber', r'cat picture', r'cat=', r'grep=']
        }
        
        # Check for false positive indicators
        if attack_type in false_positive_indicators:
            for fp_pattern in false_positive_indicators[attack_type]:
                if re.search(fp_pattern, matched_string, re.IGNORECASE):
                    adjustment -= 20  # Significant penalty for false positive matches
                    break
        
        return max(0, min(100, base_confidence + adjustment))  # Ensure confidence is between 0 and 100
    
    def _analyze_user_agent(self, user_agent):
        """
        Analyze the user agent string for suspicious characteristics.
        
        Args:
            user_agent: The user agent string to analyze
            
        Returns:
            dict: Analysis result for the user agent
        """
        result = {
            'is_threat': False,
            'attack_type': 'none',
            'confidence': 0,
            'explanation': '',
            'recommended_action': 'allow'
        }
        
        # Check against known bad user agents
        for bad_ua in self.known_bad_user_agents:
            if re.search(bad_ua, user_agent, re.IGNORECASE):
                result = {
                    'is_threat': True,
                    'attack_type': 'suspicious_user_agent',
                    'confidence': 90,
                    'explanation': f"User agent matches known bad pattern: {bad_ua}",
                    'recommended_action': 'block'
                }
                return result
        
        # Check for unusual user agent patterns (e.g., headless browsers, old versions, etc.)
        if "Headless" in user_agent or "bot" in user_agent:
            result = {
                'is_threat': True,
                'attack_type': 'suspicious_user_agent',
                'confidence': 70,
                'explanation': "User agent indicates a headless browser or bot",
                'recommended_action': 'monitor'
            }
        
        return result
    
    def _analyze_behavior(self, ip):
        """
        Analyze the behavior of the source IP for suspicious activity.
        
        Args:
            ip: The source IP address
            
        Returns:
            dict: Behavioral analysis result
        """
        result = {
            'is_threat': False,
            'attack_type': 'none',
            'confidence': 0,
            'explanation': '',
            'recommended_action': 'allow'
        }
        
        # This is a placeholder for behavioral analysis logic
        # In a real implementation, this would analyze patterns over time, request rates, etc.
        
        # Look for recent requests from this IP
        recent_requests = [req for req in self.request_history if req.get('source_ip') == ip]
        
        # If no history for this IP, return the default result
        if not recent_requests:
            return result
            
        # Get the most recent request path
        latest_request = recent_requests[-1]
        request_path = latest_request.get('path', '')
        
        # Check if the access path is unusual for this IP
        is_unusual_path = request_path not in self.normal_traffic_patterns['common_paths']
        
        # This would normally have more complex logic based on historical patterns
        # For now, just return a simple example
        if is_unusual_path and '/admin/' in request_path:
            result = {
                'is_threat': True,
                'attack_type': 'suspicious_access',
                'confidence': 60,
                'explanation': f"Unusual access pattern: accessing admin path from unrecognized IP",
                'recommended_action': 'monitor'
            }
            return result
            
        return result
    
    def _generate_rule_suggestion(self, analysis_result, request_data):
        """
        Generate a firewall rule suggestion based on the threat analysis.
        
        Args:
            analysis_result: The results of the threat analysis
            request_data: The original request data
            
        Returns:
            dict: A suggested firewall rule
        """
        # Skip if not a threat or confidence is too low
        if not analysis_result.get('is_threat', False) or analysis_result.get('confidence', 0) < 75:
            return None
            
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
            description = f"Block path due to detected {attack_type} attack"
        elif attack_type in ['suspicious_source', 'tor_exit_node', 'scanner', 'attack_source', 'scanning']:
            rule_type = 'ip'
            pattern = source_ip
            description = f"Block IP associated with {attack_type}"
        elif attack_type == 'suspicious_user_agent':
            rule_type = 'user_agent'
            pattern = user_agent
            description = f"Block suspicious user agent: {user_agent[:30]}..." if len(user_agent) > 30 else user_agent
        elif attack_type == 'suspicious_access':
            rule_type = 'ip'
            pattern = source_ip
            description = f"Block IP attempting suspicious access: {source_ip}"
        
        # Create rule suggestion
        return {
            'rule_type': rule_type,
            'pattern': pattern,
            'description': description,
            'confidence': analysis_result.get('confidence', 0),
            'recommended_action': analysis_result.get('recommended_action', 'block')
        }
        
    def _update_learned_patterns(self, request_data, analysis_result):
        """
        Update learned patterns based on analysis results.
        This enables continuous learning from detected threats.
        
        Args:
            request_data: The original request data
            analysis_result: The results of the threat analysis
        """
        # Only learn from high-confidence detections
        confidence = analysis_result.get('confidence', 0)
        if confidence < 75 or not analysis_result.get('is_threat', False):
            return
            
        # Get relevant data
        source_ip = request_data.get('source_ip', '')
        request_path = request_data.get('path', '')
        user_agent = request_data.get('user_agent', '')
        
        # Update threat patterns
        if source_ip and confidence >= 85:
            self.threat_patterns['ip'].add(source_ip)
            
        if request_path and confidence >= 85 and analysis_result.get('attack_type') in ['sql_injection', 'xss', 'path_traversal', 'command_injection']:
            self.threat_patterns['path'].add(request_path)
            
        if user_agent and confidence >= 90 and analysis_result.get('attack_type') == 'suspicious_user_agent':
            self.threat_patterns['user_agent'].add(user_agent)
            
        # Log the learning event
        logger.debug(f"ARPF AI: Learned new pattern for {analysis_result.get('attack_type')} with confidence {confidence}")
    
    def analyze_traffic_patterns(self, days=7, request_history=None):
        """
        Analyze traffic patterns from request history to identify potential threats and generate insights.
        
        Args:
            days: Number of days of logs to analyze (default: 7)
            request_history: Optional request history to analyze (if None, uses self.request_history)
            
        Returns:
            dict: Analysis results including identified patterns and suggested rules
        """
        logger.info(f"Analyzing traffic patterns from the past {days} days")
        
        # Use provided request history or class request history
        history = request_history if request_history is not None else self.request_history
        
        # Filter history by date if needed
        if days > 0:
            cutoff_time = timezone.now() - timezone.timedelta(days=days)
            history = [req for req in history if req.get('timestamp', timezone.now()) >= cutoff_time]
        
        # Initialize results structure
        results = {
            'analyzed_requests': len(history),
            'identified_patterns': [],
            'suggested_rules': [],
            'timestamp': timezone.now().isoformat()
        }
        
        if not history:
            logger.warning("No request history available for traffic pattern analysis")
            return results
        
        # Group requests by source IP
        ip_groups = {}
        for req in history:
            ip = req.get('source_ip')
            if not ip:
                continue
                
            if ip not in ip_groups:
                ip_groups[ip] = []
            ip_groups[ip].append(req)
        
        # Analyze high-frequency IPs (potential scanning or brute force)
        for ip, requests in ip_groups.items():
            if len(requests) >= 50:  # Threshold for high frequency
                # Calculate request rate (requests per minute)
                if len(requests) >= 2:
                    # Sort by timestamp
                    sorted_reqs = sorted(requests, key=lambda x: x.get('timestamp', timezone.now()))
                    time_span = (sorted_reqs[-1].get('timestamp', timezone.now()) - 
                                sorted_reqs[0].get('timestamp', timezone.now()))
                    minutes = time_span.total_seconds() / 60.0 if time_span.total_seconds() > 0 else 1.0
                    req_per_min = len(requests) / minutes
                    
                    if req_per_min >= 10:  # More than 10 requests per minute
                        # Check request paths
                        paths = [req.get('path', '') for req in requests]
                        unique_paths = len(set(paths))
                        
                        # Potential scanner (many unique paths)
                        if unique_paths >= 10:
                            pattern = {
                                'type': 'scanning',
                                'source_ip': ip,
                                'requests': len(requests),
                                'unique_paths': unique_paths,
                                'req_per_min': round(req_per_min, 2),
                                'confidence': min(95, 60 + int(req_per_min / 2))
                            }
                            results['identified_patterns'].append(pattern)
                            
                            # Add suggested rule
                            rule = {
                                'rule_type': 'ip',
                                'pattern': ip,
                                'description': f"Block scanning IP (detected {unique_paths} unique paths, {round(req_per_min, 1)} req/min)",
                                'confidence': pattern['confidence'],
                                'recommended_action': 'block'
                            }
                            results['suggested_rules'].append(rule)
                        
                        # Potential brute force (few unique paths, high frequency)
                        elif unique_paths <= 3 and req_per_min >= 15:
                            # Check if paths contain login/admin endpoints
                            login_paths = [p for p in paths if any(term in p.lower() for term in ['login', 'admin', 'user', 'auth'])]
                            if login_paths:
                                pattern = {
                                    'type': 'brute_force',
                                    'source_ip': ip,
                                    'requests': len(requests),
                                    'target_path': max(set(paths), key=paths.count),
                                    'req_per_min': round(req_per_min, 2),
                                    'confidence': min(90, 65 + int(req_per_min / 2))
                                }
                                results['identified_patterns'].append(pattern)
                                
                                # Add suggested rule
                                rule = {
                                    'rule_type': 'ip',
                                    'pattern': ip,
                                    'description': f"Block potential brute force attack ({round(req_per_min, 1)} req/min to login)",
                                    'confidence': pattern['confidence'],
                                    'recommended_action': 'block'
                                }
                                results['suggested_rules'].append(rule)
        
        # Analyze for user agent patterns
        ua_counts = {}
        for req in history:
            ua = req.get('user_agent', '')
            if not ua:
                continue
                
            if ua not in ua_counts:
                ua_counts[ua] = 0
            ua_counts[ua] += 1
            
        # Find suspicious user agents
        for ua, count in ua_counts.items():
            if count >= 10:  # Threshold for analysis
                # Check against known patterns
                for pattern in self.known_bad_user_agents:
                    if re.search(pattern, ua, re.IGNORECASE):
                        ua_pattern = {
                            'type': 'suspicious_user_agent',
                            'user_agent': ua,
                            'requests': count,
                            'matching_pattern': pattern,
                            'confidence': min(95, 70 + (count // 5))
                        }
                        results['identified_patterns'].append(ua_pattern)
                        
                        # Add suggested rule if high confidence
                        if ua_pattern['confidence'] >= 80:
                            rule = {
                                'rule_type': 'user_agent',
                                'pattern': ua,
                                'description': f"Block suspicious user agent: {ua[:40]}..." if len(ua) > 40 else ua,
                                'confidence': ua_pattern['confidence'],
                                'recommended_action': 'block'
                            }
                            results['suggested_rules'].append(rule)
                        break
        
        # Analyze for attack patterns (SQL injection, XSS, etc.)
        attack_paths = {}
        for attack_type, patterns in self.known_attack_signatures.items():
            if attack_type == 'suspicious_user_agents':
                continue  # Already handled above
                
            attack_paths[attack_type] = []
            
            # Check paths against attack patterns
            for req in history:
                path = req.get('path', '')
                if not path:
                    continue
                    
                for pattern in patterns:
                    if re.search(pattern, path, re.IGNORECASE):
                        # Calculate confidence
                        confidence = self._calculate_signature_confidence(attack_type, pattern, path)
                        
                        # Only consider medium-high confidence matches
                        if confidence >= 65:
                            attack_paths[attack_type].append({
                                'path': path,
                                'source_ip': req.get('source_ip', ''),
                                'timestamp': req.get('timestamp', timezone.now()),
                                'confidence': confidence,
                                'pattern': pattern
                            })
                        break
        
        # Add detected attack patterns to results
        for attack_type, detections in attack_paths.items():
            if detections:
                # Group by source IP to detect repeat offenders
                ip_attack_counts = {}
                for detection in detections:
                    ip = detection.get('source_ip', '')
                    if ip:
                        if ip not in ip_attack_counts:
                            ip_attack_counts[ip] = 0
                        ip_attack_counts[ip] += 1
                
                # Find IPs with multiple detected attacks
                for ip, count in ip_attack_counts.items():
                    if count >= 3:  # Threshold for repeat attacks
                        pattern = {
                            'type': attack_type,
                            'source_ip': ip,
                            'attack_count': count,
                            'confidence': min(95, 70 + (count * 5))
                        }
                        results['identified_patterns'].append(pattern)
                        
                        # Add suggested rule
                        rule = {
                            'rule_type': 'ip',
                            'pattern': ip,
                            'description': f"Block IP with multiple {attack_type.replace('_', ' ')} attacks",
                            'confidence': pattern['confidence'],
                            'recommended_action': 'block'
                        }
                        results['suggested_rules'].append(rule)
                
                # For high-confidence detections, suggest pattern-based rules
                high_conf_detections = [d for d in detections if d.get('confidence', 0) >= 85]
                if high_conf_detections:
                    # Group similar paths
                    path_patterns = {}
                    for detection in high_conf_detections:
                        path = detection.get('path', '')
                        # Simplify path to create a pattern (remove specific IDs, etc.)
                        simplified = re.sub(r'\d+', 'X', path)
                        simplified = re.sub(r'=[^&]+', '=X', simplified)
                        
                        if simplified not in path_patterns:
                            path_patterns[simplified] = []
                        path_patterns[simplified].append(detection)
                    
                    # Suggest rules for common patterns
                    for simplified, matches in path_patterns.items():
                        if len(matches) >= 2:  # Multiple matches for same pattern
                            avg_confidence = sum(m.get('confidence', 0) for m in matches) / len(matches)
                            
                            # Create path pattern rule
                            rule = {
                                'rule_type': 'path_pattern',
                                'pattern': simplified,
                                'description': f"Block {attack_type.replace('_', ' ')} attack pattern",
                                'confidence': min(95, int(avg_confidence)),
                                'recommended_action': 'block'
                            }
                            results['suggested_rules'].append(rule)
        
        # Log summary
        logger.info(f"Traffic pattern analysis complete: found {len(results['identified_patterns'])} patterns "
                   f"and suggested {len(results['suggested_rules'])} rules")
        
        return results