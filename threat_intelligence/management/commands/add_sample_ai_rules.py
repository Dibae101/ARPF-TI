from django.core.management.base import BaseCommand
from django.utils import timezone
from core.models import Rule
import random

class Command(BaseCommand):
    help = 'Adds sample AI-generated rules to the database for testing the comparison dashboard'

    def handle(self, *args, **options):
        # Sample data for AI rules
        ai_rules_data = [
            {
                'name': 'AI SQL Injection Protection',
                'description': 'AI-generated rule to block SQL injection attempts',
                'rule_type': 'path',
                'pattern': r'(\'|\"|;|\-\-|\/\*|\*\/|union\s+select|select\s+.*\s+from|insert\s+into|drop\s+table)',
                'action': 'block',
                'priority': 25,
                'source': 'ai',
                'true_positive_count': random.randint(20, 45),
                'false_positive_count': random.randint(1, 5),
            },
            {
                'name': 'AI XSS Attack Blocker',
                'description': 'AI-generated rule to prevent cross-site scripting attacks',
                'rule_type': 'path',
                'pattern': r'(<script>|javascript:|onerror=|onload=|eval\(|document\.cookie|alert\()',
                'action': 'block',
                'priority': 30,
                'source': 'ai',
                'true_positive_count': random.randint(25, 40),
                'false_positive_count': random.randint(1, 4),
            },
            {
                'name': 'AI Path Traversal Detector',
                'description': 'AI-generated rule to detect directory traversal attempts',
                'rule_type': 'path',
                'pattern': r'(\.\./|\.\.\%2f|\.\.\\|\.\.\%5c|/etc/passwd|/etc/shadow|/proc/self)',
                'action': 'block',
                'priority': 20,
                'source': 'ai',
                'true_positive_count': random.randint(15, 30),
                'false_positive_count': random.randint(0, 3),
            },
            {
                'name': 'AI Bad IP Blocker',
                'description': 'AI-generated rule to block known malicious IP addresses',
                'rule_type': 'ip',
                'pattern': r'^(185\.143\.223\.\d+|193\.169\.252\.\d+|45\.227\.255\.\d+)$',
                'action': 'block',
                'priority': 10,
                'source': 'ai',
                'true_positive_count': random.randint(30, 50),
                'false_positive_count': random.randint(0, 2),
            },
            {
                'name': 'AI Suspicious User Agent Detector',
                'description': 'AI-generated rule to identify suspicious user agents',
                'rule_type': 'user_agent',
                'pattern': r'(nmap|nikto|sqlmap|dirbuster|hydra|gobuster|masscan|ZmEu|zgrab|curl|wget\/[0-9])',
                'action': 'block',
                'priority': 35,
                'source': 'ai',
                'true_positive_count': random.randint(20, 35),
                'false_positive_count': random.randint(2, 6),
            },
            {
                'name': 'AI Command Injection Blocker',
                'description': 'AI-generated rule to prevent command injection attacks',
                'rule_type': 'path',
                'pattern': r'(;|\||\|\||&&|\$\(|\`|\${|system\(|exec\(|passthru\(|shell_exec\()',
                'action': 'block',
                'priority': 15,
                'source': 'ai',
                'true_positive_count': random.randint(18, 28),
                'false_positive_count': random.randint(1, 3),
            },
            {
                'name': 'AI Country Restriction',
                'description': 'AI-generated rule to block traffic from high-risk countries',
                'rule_type': 'country',
                'pattern': r'^(RU|CN|KP|IR)$',
                'action': 'block',
                'priority': 50,
                'source': 'ai',
                'true_positive_count': random.randint(40, 80),
                'false_positive_count': random.randint(5, 10),
            },
            {
                'name': 'AI Malicious Header Detection',
                'description': 'AI-generated rule to detect malicious HTTP headers',
                'rule_type': 'header',
                'pattern': r'X-Forwarded-For:\s*(localhost|127\.0\.0\.1)',
                'action': 'block',
                'priority': 40,
                'source': 'ai',
                'true_positive_count': random.randint(10, 20),
                'false_positive_count': random.randint(0, 4),
            },
            {
                'name': 'AI HTTP Method Restriction',
                'description': 'AI-generated rule to restrict unusual HTTP methods',
                'rule_type': 'method',
                'pattern': r'^(TRACE|CONNECT|OPTIONS)$',
                'action': 'log',
                'priority': 60,
                'source': 'ai',
                'true_positive_count': random.randint(5, 15),
                'false_positive_count': random.randint(10, 20),
            },
            {
                'name': 'AI File Inclusion Detector',
                'description': 'AI-generated rule to prevent file inclusion attacks',
                'rule_type': 'path',
                'pattern': r'(include=|file=|document=|root=|path=|folder=).*\.(php|asp|aspx|jsp)',
                'action': 'block',
                'priority': 45,
                'source': 'ai',
                'true_positive_count': random.randint(12, 25),
                'false_positive_count': random.randint(1, 5),
            },
        ]

        # Create AI rules
        rules_created = 0
        rules_updated = 0

        for rule_data in ai_rules_data:
            # Check if rule already exists to avoid duplicates
            existing_rule = Rule.objects.filter(name=rule_data['name']).first()
            
            if existing_rule:
                # Update existing rule
                for key, value in rule_data.items():
                    setattr(existing_rule, key, value)
                existing_rule.updated_at = timezone.now()
                existing_rule.save()
                rules_updated += 1
                self.stdout.write(f"Updated rule: {rule_data['name']}")
            else:
                # Create new rule
                rule = Rule.objects.create(**rule_data)
                rules_created += 1
                self.stdout.write(f"Created rule: {rule_data['name']}")
        
        self.stdout.write(self.style.SUCCESS(
            f'Successfully added sample AI rules: {rules_created} created, {rules_updated} updated'))