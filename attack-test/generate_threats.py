#!/usr/bin/env python3
"""
Threat Intelligence Data Generator
This script generates fake threat intelligence data for testing purposes.
It creates a simple web server that serves IP addresses and other IOCs.
"""

import http.server
import socketserver
import random
import argparse
import time
import json
from datetime import datetime

# Sample data for generating threat intelligence
SAMPLE_IPS = [
    "192.168.1.100", "192.168.1.101", "10.0.0.25", "172.16.0.50",
    "45.33.32.156", "92.118.36.210", "103.235.46.108", "185.176.26.217",
    "217.138.211.215", "45.131.230.218", "104.244.72.115", "185.220.100.240",
]

SAMPLE_DOMAINS = [
    "malicious-example.com", "fakephishing.org", "malware-distribution.net",
    "suspiciousdomain.xyz", "evil-tracker.info", "ransomware-c2.com"
]

SAMPLE_FILE_HASHES = [
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # SHA-256
    "d41d8cd98f00b204e9800998ecf8427e",  # MD5
    "da39a3ee5e6b4b0d3255bfef95601890afd80709",  # SHA-1
    "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",  # SHA-256
    "5eb63bbbe01eeed093cb22bb8f5acdc3"  # MD5
]

SAMPLE_CATEGORIES = ["malware", "phishing", "botnet", "ransomware", "scanning", "exploit"]

class ThreatIntelHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.format = kwargs.pop('format', 'txt')
        self.entry_type = kwargs.pop('entry_type', 'ip')
        self.delay = kwargs.pop('delay', 0)
        super().__init__(*args, **kwargs)

    def do_GET(self):
        if self.delay > 0:
            time.sleep(self.delay)
            
        if self.path == "/threats":
            self.send_response(200)
            
            if self.format == 'json':
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(self.generate_json_response().encode())
            else:
                self.send_header("Content-type", "text/plain")
                self.end_headers()
                self.wfile.write(self.generate_txt_response().encode())
        else:
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"""
            <html>
            <head><title>Test Attack Server</title></head>
            <body>
                <h1>Test Attack Server</h1>
                <p>This server simulates a threat intelligence feed for testing.</p>
                <p>Access the <a href="/threats">threat data</a> to get the current list.</p>
            </body>
            </html>
            """)
    
    def generate_txt_response(self):
        """Generate a simple text list of indicators"""
        if self.entry_type == 'ip':
            items = random.sample(SAMPLE_IPS, k=min(5, len(SAMPLE_IPS)))
        elif self.entry_type == 'domain':
            items = random.sample(SAMPLE_DOMAINS, k=min(3, len(SAMPLE_DOMAINS)))
        elif self.entry_type == 'file_hash':
            items = random.sample(SAMPLE_FILE_HASHES, k=min(4, len(SAMPLE_FILE_HASHES)))
        else:
            items = random.sample(SAMPLE_IPS + SAMPLE_DOMAINS, k=5)
            
        return "\n".join(items)
    
    def generate_json_response(self):
        """Generate a more structured JSON response with additional metadata"""
        result = {"generated_at": datetime.now().isoformat(), "indicators": []}
        
        if self.entry_type == 'ip':
            items = random.sample(SAMPLE_IPS, k=min(5, len(SAMPLE_IPS)))
            for ip in items:
                result["indicators"].append({
                    "value": ip,
                    "type": "ip",
                    "category": random.choice(SAMPLE_CATEGORIES),
                    "confidence_score": random.randint(60, 95),
                    "first_seen": (datetime.now().isoformat())
                })
        elif self.entry_type == 'domain':
            items = random.sample(SAMPLE_DOMAINS, k=min(3, len(SAMPLE_DOMAINS)))
            for domain in items:
                result["indicators"].append({
                    "value": domain,
                    "type": "domain",
                    "category": random.choice(SAMPLE_CATEGORIES),
                    "confidence_score": random.randint(60, 95),
                    "first_seen": (datetime.now().isoformat())
                })
        elif self.entry_type == 'file_hash':
            items = random.sample(SAMPLE_FILE_HASHES, k=min(4, len(SAMPLE_FILE_HASHES)))
            for file_hash in items:
                result["indicators"].append({
                    "value": file_hash,
                    "type": "file_hash",
                    "category": random.choice(SAMPLE_CATEGORIES),
                    "confidence_score": random.randint(60, 95),
                    "first_seen": (datetime.now().isoformat())
                })
        
        return json.dumps(result, indent=2)

def run_server(port=8080, format='txt', entry_type='ip', delay=0):
    handler = lambda *args, **kwargs: ThreatIntelHandler(*args, format=format, entry_type=entry_type, delay=delay, **kwargs)
    
    with socketserver.TCPServer(("", port), handler) as httpd:
        print(f"Server running at http://localhost:{port}/")
        print(f"Threat data available at http://localhost:{port}/threats")
        print(f"Format: {format}, Entry Type: {entry_type}, Response Delay: {delay}s")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("Server stopped.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Run a simple threat intelligence feed server for testing')
    parser.add_argument('--port', type=int, default=8080, help='Port to run the server on')
    parser.add_argument('--format', choices=['txt', 'json'], default='txt', help='Format of the threat data')
    parser.add_argument('--type', choices=['ip', 'domain', 'file_hash', 'mixed'], default='ip', help='Type of threat indicators')
    parser.add_argument('--delay', type=int, default=0, help='Simulated delay in seconds')
    
    args = parser.parse_args()
    run_server(args.port, args.format, args.type, args.delay)