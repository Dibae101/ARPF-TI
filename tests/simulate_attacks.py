#!/usr/bin/env python
"""
ARPF-TI Attack Simulation Script

This script simulates attacks from multiple IP addresses, locations, and using various
attack techniques to test the ARPF-TI application's defense capabilities.

Usage:
    python3 simulate_attacks.py --target http://your-arpf-ti-host:8000
"""
import os
import sys
import time
import random
import argparse
import requests
import ipaddress
from datetime import datetime
from requests.exceptions import RequestException
from concurrent.futures import ThreadPoolExecutor

# Disable SSL warnings for testing
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Known attack patterns
ATTACK_VECTORS = {
    # SQL Injection attempts
    'sql_injection': [
        "' OR 1=1 --",
        "admin' --",
        "1'; DROP TABLE users; --",
        "' UNION SELECT * FROM information_schema.tables --",
        "' OR '1'='1",
        "1' OR '1' = '1",
        "' OR ''='",
        "1' OR ''='",
        "' OR 1=1#",
        "' OR 1=1/*",
    ],
    
    # XSS attempts
    'xss': [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<body onload=alert('XSS')>",
        "<svg/onload=alert('XSS')>",
        "javascript:alert('XSS')",
        "\"><script>alert('XSS')</script>",
        "'><script>alert('XSS')</script>",
        "<script>alert(document.cookie)</script>",
        "<scr<script>ipt>alert('XSS')</script>",
        "'-alert(1)-'",
    ],
    
    # Path traversal attempts
    'path_traversal': [
        "../../../../../etc/passwd",
        "..\\..\\..\\..\\windows\\win.ini",
        "../../../../../../var/www/html",
        "../../../../../../../../boot.ini",
        "./../.../././../etc/passwd",
        "/.../...//../../../../../../../../etc/hosts",
        "../../../../../../../../../../../../../../../etc/shadow",
        "../../../../../../../../../../../../../../../../etc/passwd%00",
        "../../logs",
        "../../db",
    ],
    
    # Command injection attempts
    'command_injection': [
        "& cat /etc/passwd",
        "; ls -la",
        "| id",
        "`id`",
        "$(cat /etc/passwd)",
        "; ping -c 3 google.com",
        "\"; ping -c 3 google.com",
        "'; ping -c 3 google.com",
        "& ping -c 3 google.com",
        "&& ping -c 3 google.com",
    ],
    
    # Open redirect attempts
    'open_redirect': [
        "/redirect?url=https://evil.com",
        "/redirect?url=//evil.com",
        "/redirect?url=\\\\evil.com",
        "/redirect?url=javascript:alert(1)",
        "/redirect?to=https://evil.com",
        "/redirect?to=//evil.com",
        "/login?next=https://evil.com",
        "/login?next=//evil.com",
        "/logout?next=https://evil.com",
        "/logout?next=//evil.com",
    ]
}

# User agent strings to simulate different clients and attack tools
USER_AGENTS = [
    # Regular browsers (to blend in)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/117.0",
    
    # Attack tools and scanners
    "sqlmap/1.7.2#dev (https://sqlmap.org)",
    "Nikto/2.1.6",
    "w3af/2.0.0-dev",
    "Nessus SOAP v0.0.1 (Nessus.org)",
    "masscan/1.3",
    "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)",
    "WPScan v3.8.22 (https://wpscan.org/)",
    "gobuster/3.5",
    "Dirbuster/1.0-RC",
    "ZAP/2.14.0",
    
    # Bots (some malicious)
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
    "msnbot/2.0b (+http://search.msn.com/msnbot.htm)",
    "Baiduspider/2.0; (+http://www.baidu.com/search/spider.html)",
    "MJ12bot/v1.4.8 (http://majestic12.co.uk/bot.php?+)",
    "AhrefsBot/7.0; +http://ahrefs.com/robot/)",
    "zgrab/0.x",
    "Xenu Link Sleuth/1.3.8",
    "MegaIndex.ru/2.0",
    "YandexBot/3.0",
    "PetalBot"
]

# Countries and their IP ranges (simplified for simulation)
COUNTRY_IP_RANGES = {
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

# Target endpoints that are commonly attacked
TARGET_ENDPOINTS = [
    "/",
    "/login",
    "/admin",
    "/admin/login",
    "/dashboard",
    "/api/data",
    "/api/users",
    "/api/v1/auth",
    "/console",
    "/phpMyAdmin",
    "/wp-admin",
    "/wp-login.php",
    "/config",
    "/backup",
    "/upload",
    "/files",
    "/includes",
    "/js",
    "/api/search",
    "/.git"
]

# HTTP methods to use in attacks
HTTP_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'HEAD', 'PATCH']

class AttackSimulator:
    """Simulates attacks from multiple sources against a target."""
    
    def __init__(self, target, rate_limit=10, timeout=5, verbose=True):
        """
        Initialize the attack simulator.
        
        Args:
            target: Target URL to attack
            rate_limit: Maximum requests per second
            timeout: Request timeout in seconds
            verbose: Whether to print detailed output
        """
        self.target = target
        self.rate_limit = rate_limit
        self.timeout = timeout
        self.verbose = verbose
        self.session = requests.Session()
        self.attack_stats = {
            'total_requests': 0,
            'successful_requests': 0,
            'blocked_requests': 0,
            'failed_requests': 0,
            'countries': {},
            'attack_types': {},
            'endpoints': {},
            'user_agents': {},
            'start_time': datetime.now()
        }
    
    def _get_random_ip(self, country=None):
        """Get a random IP address, optionally from a specific country."""
        if country and country in COUNTRY_IP_RANGES:
            # Pick a random IP range from the country
            ip_range = random.choice(COUNTRY_IP_RANGES[country])
            # Generate a random IP from that range
            network = ipaddress.ip_network(ip_range)
            # Get a random integer index within the network range
            random_index = random.randint(0, network.num_addresses - 1)
            # Convert to IP address (skip network and broadcast addresses for bigger networks)
            if network.num_addresses > 3:
                random_index = max(1, min(random_index, network.num_addresses - 2))
            return str(network[random_index])
        else:
            # Generate a completely random IP
            return f"{random.randint(1, 254)}.{random.randint(0, 254)}.{random.randint(0, 254)}.{random.randint(1, 254)}"

    def _make_request(self, endpoint, attack_type=None, country=None, specific_ip=None, 
                    user_agent=None, method='GET', data=None, delay=0):
        """Make a request to the target with specified attack parameters."""
        # Apply rate limiting
        if delay > 0:
            time.sleep(delay)
        
        # Configure the request
        url = f"{self.target.rstrip('/')}{endpoint}"
        
        # Set specific IP address or generate one
        if specific_ip:
            ip = specific_ip
            country_name = "Unknown"
            for country_key, ip_ranges in COUNTRY_IP_RANGES.items():
                for ip_range in ip_ranges:
                    if ipaddress.ip_address(ip) in ipaddress.ip_network(ip_range):
                        country_name = country_key
                        break
        else:
            country_name = country if country else random.choice(list(COUNTRY_IP_RANGES.keys()))
            ip = self._get_random_ip(country_name)
        
        # Select user agent
        if not user_agent:
            user_agent = random.choice(USER_AGENTS)
        
        # Set up headers
        headers = {
            'User-Agent': user_agent,
            'X-Forwarded-For': ip,
            'Client-IP': ip,
            'X-Real-IP': ip
        }
        
        # Attack data if needed
        if attack_type and not data and method in ['GET', 'POST', 'PUT', 'PATCH']:
            if attack_type in ATTACK_VECTORS:
                payload = random.choice(ATTACK_VECTORS[attack_type])
                if method == 'GET':
                    if '?' in endpoint:
                        url = f"{url}&q={payload}"
                    else:
                        url = f"{url}?q={payload}"
                else:
                    data = {'q': payload, 'search': payload, 'id': payload, 'input': payload}

        # Update statistics for this request
        self.attack_stats['total_requests'] += 1
        self.attack_stats['countries'][country_name] = self.attack_stats['countries'].get(country_name, 0) + 1
        if attack_type:
            self.attack_stats['attack_types'][attack_type] = self.attack_stats['attack_types'].get(attack_type, 0) + 1
        self.attack_stats['endpoints'][endpoint] = self.attack_stats['endpoints'].get(endpoint, 0) + 1
        self.attack_stats['user_agents'][user_agent[:30]] = self.attack_stats['user_agents'].get(user_agent[:30], 0) + 1
        
        # Execute the request
        try:
            start_time = time.time()
            if method == 'GET':
                response = self.session.get(url, headers=headers, timeout=self.timeout, verify=False)
            elif method == 'POST':
                response = self.session.post(url, headers=headers, data=data, timeout=self.timeout, verify=False)
            elif method == 'PUT':
                response = self.session.put(url, headers=headers, data=data, timeout=self.timeout, verify=False)
            elif method == 'DELETE':
                response = self.session.delete(url, headers=headers, timeout=self.timeout, verify=False)
            elif method == 'HEAD':
                response = self.session.head(url, headers=headers, timeout=self.timeout, verify=False)
            elif method == 'OPTIONS':
                response = self.session.options(url, headers=headers, timeout=self.timeout, verify=False)
            elif method == 'PATCH':
                response = self.session.patch(url, headers=headers, data=data, timeout=self.timeout, verify=False)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")
            
            # Record the response
            duration = time.time() - start_time
            status_class = response.status_code // 100
            
            if status_class == 2:
                self.attack_stats['successful_requests'] += 1
                status_info = "successful"
            elif status_class == 4:
                if response.status_code == 403:
                    self.attack_stats['blocked_requests'] += 1
                    status_info = "BLOCKED"
                else:
                    self.attack_stats['failed_requests'] += 1
                    status_info = "failed"
            elif status_class == 5:
                self.attack_stats['failed_requests'] += 1
                status_info = "failed (server error)"
            else:
                self.attack_stats['failed_requests'] += 1
                status_info = "unknown result"
            
            # Print the result if verbose
            if self.verbose:
                attack_info = f" ({attack_type})" if attack_type else ""
                print(f"{method} {endpoint}{attack_info} from {ip} ({country_name}) - {response.status_code} {status_info} ({duration:.2f}s)")
            
            return response
            
        except RequestException as e:
            self.attack_stats['failed_requests'] += 1
            if self.verbose:
                print(f"Error making request to {endpoint}: {str(e)}")
            return None
    
    def simulate_random_attack(self):
        """Simulate a single random attack."""
        # Pick a random endpoint
        endpoint = random.choice(TARGET_ENDPOINTS)
        
        # Pick a random attack type (or None for a benign request)
        attack_type = random.choice(list(ATTACK_VECTORS.keys()) + [None])
        
        # Pick a random country
        country = random.choice(list(COUNTRY_IP_RANGES.keys()))
        
        # Pick a random user agent
        user_agent = random.choice(USER_AGENTS)
        
        # Pick a random HTTP method
        if attack_type in ['sql_injection', 'xss', 'command_injection']:
            # These work better with POST
            method = 'POST'
        elif attack_type == 'open_redirect':
            # Open redirect typically uses GET
            method = 'GET'
        else:
            method = random.choice(HTTP_METHODS)
        
        # Make the request
        return self._make_request(
            endpoint=endpoint,
            attack_type=attack_type,
            country=country,
            user_agent=user_agent,
            method=method
        )
    
    def simulate_targeted_attack(self, country, attack_types, endpoints, count=10):
        """Simulate a targeted attack from a specific country using specific attack types."""
        print(f"\n=== Simulating targeted attack from {country} ({count} requests) ===")
        
        for _ in range(count):
            attack_type = random.choice(attack_types)
            endpoint = random.choice(endpoints)
            
            # Pick a method appropriate for the attack
            if attack_type in ['sql_injection', 'xss', 'command_injection']:
                method = 'POST'
            else:
                method = random.choice(['GET', 'POST'])
                
            self._make_request(
                endpoint=endpoint,
                attack_type=attack_type,
                country=country,
                method=method,
                delay=1/self.rate_limit  # Basic rate limiting
            )
    
    def simulate_distributed_attack(self, countries, attack_type, endpoint, count_per_country=5):
        """Simulate a distributed attack from multiple countries using the same attack type."""
        print(f"\n=== Simulating distributed {attack_type} attack on {endpoint} from {len(countries)} countries ===")
        
        with ThreadPoolExecutor(max_workers=min(len(countries), 10)) as executor:
            for country in countries:
                for _ in range(count_per_country):
                    executor.submit(
                        self._make_request,
                        endpoint=endpoint,
                        attack_type=attack_type,
                        country=country,
                        delay=1/self.rate_limit  # Basic rate limiting
                    )
    
    def simulate_attack_sequence(self, count=100):
        """Simulate a sequence of random attacks."""
        print(f"\n=== Starting attack simulation with {count} requests ===")
        
        for _ in range(count):
            self.simulate_random_attack()
            # Apply rate limiting
            time.sleep(1/self.rate_limit)
    
    def simulate_realistic_attack_scenario(self):
        """Simulate a realistic attack scenario with reconnaissance and targeted attacks."""
        print("\n=== Simulating realistic attack scenario ===")
        
        # Phase 1: Reconnaissance (light scanning from different IPs)
        print("\n--- Phase 1: Reconnaissance ---")
        recon_endpoints = ['/', '/robots.txt', '/sitemap.xml', '/admin', '/login', '/wp-login.php']
        recon_countries = ['USA', 'Germany', 'Russia', 'China']
        
        for country in recon_countries:
            for endpoint in recon_endpoints:
                self._make_request(
                    endpoint=endpoint,
                    country=country,
                    method='GET',
                    delay=random.uniform(0.5, 2.0)
                )
        
        # Phase 2: Vulnerability scanning (more aggressive)
        print("\n--- Phase 2: Vulnerability scanning ---")
        scanner_user_agents = [ua for ua in USER_AGENTS if any(scanner in ua.lower() for scanner in 
                                ['scan', 'nikto', 'nessus', 'nuclei', 'gobuster', 'dirbuster', 'wpscan'])]
        
        scan_countries = ['Russia', 'China']  # Focus on specific countries
        
        for _ in range(20):
            self._make_request(
                endpoint=random.choice(TARGET_ENDPOINTS),
                country=random.choice(scan_countries),
                user_agent=random.choice(scanner_user_agents or USER_AGENTS),
                method=random.choice(['GET', 'HEAD']),
                delay=random.uniform(0.2, 0.5)
            )
        
        # Phase 3: Targeted attacks from suspicious countries
        print("\n--- Phase 3: Targeted attacks ---")
        
        # SQL injection attack on login
        self.simulate_targeted_attack(
            country='Russia',
            attack_types=['sql_injection'],
            endpoints=['/login', '/admin/login', '/api/auth'],
            count=10
        )
        
        # XSS attacks on various endpoints
        self.simulate_targeted_attack(
            country='North Korea',
            attack_types=['xss'],
            endpoints=['/search', '/', '/api/search'],
            count=8
        )
        
        # Path traversal from multiple sources
        self.simulate_distributed_attack(
            countries=['China', 'Iran', 'Nigeria'],
            attack_type='path_traversal',
            endpoint='/api/files',
            count_per_country=5
        )
        
        # Command injection attempts
        self.simulate_targeted_attack(
            country='Iran',
            attack_types=['command_injection'],
            endpoints=['/api/process', '/admin/settings'],
            count=6
        )
        
        # Phase 4: Mix of legitimate and malicious traffic
        print("\n--- Phase 4: Mixed traffic ---")
        for _ in range(30):
            # 70% chance of legitimate request, 30% chance of attack
            if random.random() < 0.7:
                self._make_request(
                    endpoint=random.choice(['/', '/about', '/contact', '/products']),
                    country=random.choice(['USA', 'UK', 'Germany', 'Australia']),
                    method='GET',
                    delay=random.uniform(0.1, 0.3)
                )
            else:
                self.simulate_random_attack()
                time.sleep(random.uniform(0.1, 0.3))
    
    def print_statistics(self):
        """Print attack statistics."""
        duration = (datetime.now() - self.attack_stats['start_time']).total_seconds()
        
        print("\n=== Attack Simulation Statistics ===")
        print(f"Duration: {duration:.2f} seconds")
        print(f"Total requests: {self.attack_stats['total_requests']}")
        print(f"Successful requests: {self.attack_stats['successful_requests']}")
        print(f"Blocked requests: {self.attack_stats['blocked_requests']}")
        print(f"Failed requests: {self.attack_stats['failed_requests']}")
        
        if self.attack_stats['total_requests'] > 0:
            block_rate = (self.attack_stats['blocked_requests'] / self.attack_stats['total_requests']) * 100
            print(f"Block rate: {block_rate:.2f}%")
        
        print("\nTop countries:")
        for country, count in sorted(self.attack_stats['countries'].items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {country}: {count} requests")
        
        if self.attack_stats['attack_types']:
            print("\nAttack types:")
            for attack_type, count in sorted(self.attack_stats['attack_types'].items(), key=lambda x: x[1], reverse=True):
                print(f"  {attack_type}: {count} requests")
        
        print("\nTop endpoints:")
        for endpoint, count in sorted(self.attack_stats['endpoints'].items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {endpoint}: {count} requests")

def main():
    """Main entry point for the script."""
    parser = argparse.ArgumentParser(description='Simulate attacks against ARPF-TI application')
    parser.add_argument('--target', required=True, help='Target URL (e.g., http://example.com:8000)')
    parser.add_argument('--rate', type=int, default=5, help='Maximum requests per second (default: 5)')
    parser.add_argument('--count', type=int, default=50, help='Number of random attacks to simulate (default: 50)')
    parser.add_argument('--timeout', type=int, default=5, help='Request timeout in seconds (default: 5)')
    parser.add_argument('--scenario', action='store_true', help='Run a realistic attack scenario')
    parser.add_argument('--quiet', action='store_true', help='Suppress detailed output')
    
    args = parser.parse_args()
    
    # Create the simulator
    simulator = AttackSimulator(
        target=args.target,
        rate_limit=args.rate,
        timeout=args.timeout,
        verbose=not args.quiet
    )
    
    try:
        # Run the simulation
        if args.scenario:
            simulator.simulate_realistic_attack_scenario()
        else:
            simulator.simulate_attack_sequence(count=args.count)
            
            # Also simulate a targeted attack from a high-risk country
            simulator.simulate_targeted_attack(
                country=random.choice(['Russia', 'North Korea', 'China']),
                attack_types=['sql_injection', 'xss'],
                endpoints=['/login', '/admin', '/api/users'],
                count=10
            )
            
            # And a distributed attack
            simulator.simulate_distributed_attack(
                countries=['Russia', 'China', 'Iran', 'Nigeria', 'North Korea'],
                attack_type='path_traversal',
                endpoint='/admin',
                count_per_country=3
            )
        
        # Print statistics
        simulator.print_statistics()
    
    except KeyboardInterrupt:
        print("\nAttack simulation interrupted.")
        simulator.print_statistics()
    except Exception as e:
        print(f"\nError during attack simulation: {str(e)}")
        
    print("\nAttack simulation completed.")

if __name__ == '__main__':
    main()