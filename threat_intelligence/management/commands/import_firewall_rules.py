import logging
from django.core.management.base import BaseCommand
from django.db import transaction
from threat_intelligence.models import FirewallRule
from threat_intelligence.views import (
    get_basic_security_preset,
    get_country_block_preset,
    get_malicious_ips_preset,
    get_common_ports_preset
)

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Import preset firewall rules into the application'

    def add_arguments(self, parser):
        parser.add_argument(
            '--preset',
            type=str,
            choices=['basic', 'country', 'ips', 'ports', 'all'],
            default='all',
            help='Specific preset to import (default: all)'
        )
        parser.add_argument(
            '--force',
            action='store_true',
            help='Force import even if rules already exist'
        )

    def handle(self, *args, **options):
        preset_choice = options['preset']
        force = options['force']
        
        # Get preset rules based on the selected preset
        preset_rules = []
        
        if preset_choice == 'basic' or preset_choice == 'all':
            preset_rules.extend(get_basic_security_preset())
            self.stdout.write(f"Added {len(get_basic_security_preset())} basic security rules to import queue")
            
        if preset_choice == 'country' or preset_choice == 'all':
            preset_rules.extend(get_country_block_preset())
            self.stdout.write(f"Added {len(get_country_block_preset())} country block rules to import queue")
            
        if preset_choice == 'ips' or preset_choice == 'all':
            preset_rules.extend(get_malicious_ips_preset())
            self.stdout.write(f"Added {len(get_malicious_ips_preset())} malicious IP rules to import queue")
            
        if preset_choice == 'ports' or preset_choice == 'all':
            preset_rules.extend(get_common_ports_preset())
            self.stdout.write(f"Added {len(get_common_ports_preset())} common ports rules to import queue")
        
        # Add the preset rules to the database
        rules_added = 0
        rules_skipped = 0
        rules_failed = 0
        
        with transaction.atomic():
            for rule_data in preset_rules:
                # Check if a similar rule already exists
                existing_rules = FirewallRule.objects.filter(
                    rule_type=rule_data['rule_type'],
                    value=rule_data['value']
                )
                
                if existing_rules.exists() and not force:
                    rules_skipped += 1
                    continue
                
                # Create and save the rule
                try:
                    rule = FirewallRule(
                        name=rule_data['name'],
                        description=rule_data.get('description', ''),
                        rule_type=rule_data['rule_type'],
                        value=rule_data['value'],
                        action=rule_data.get('action', 'block'),
                        category=rule_data.get('category', 'security'),
                        direction=rule_data.get('direction', 'inbound'),
                        protocol=rule_data.get('protocol'),
                        port=rule_data.get('port'),
                        port_end=rule_data.get('port_end'),
                        priority=rule_data.get('priority', 100),
                        is_active=True,
                        source='management_command'
                    )
                    
                    rule.clean()
                    rule.save()
                    rules_added += 1
                    
                except Exception as e:
                    rules_failed += 1
                    logger.error(f"Failed to add rule {rule_data['name']}: {str(e)}")
        
        # Output results
        self.stdout.write(self.style.SUCCESS(f"Successfully added {rules_added} firewall rules"))
        if rules_skipped > 0:
            self.stdout.write(self.style.WARNING(f"{rules_skipped} rules were skipped (already exist)"))
        if rules_failed > 0:
            self.stdout.write(self.style.ERROR(f"{rules_failed} rules failed to import"))
            
        self.stdout.write(self.style.SUCCESS("Done. Use --force to reimport existing rules if needed."))