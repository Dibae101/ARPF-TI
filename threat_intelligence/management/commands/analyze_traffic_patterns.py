import logging
from django.core.management.base import BaseCommand
from django.utils import timezone
from threat_intelligence.traffic_analyzer import traffic_analyzer
from alerts.alert_system import AlertSystem

logger = logging.getLogger('arpf_ti')

class Command(BaseCommand):
    help = 'Analyze traffic patterns to identify threats and generate intelligence entries'

    def add_arguments(self, parser):
        parser.add_argument(
            '--days',
            type=int,
            default=7,
            help='Number of days of logs to analyze (default: 7)'
        )
        parser.add_argument(
            '--create-alerts',
            action='store_true',
            help='Create alerts for detected patterns'
        )

    def handle(self, *args, **options):
        days = options['days']
        create_alerts = options['create_alerts']
        
        self.stdout.write(self.style.SUCCESS(f"Starting traffic analysis for the past {days} days"))
        
        try:
            # Run the traffic analyzer
            results = traffic_analyzer.analyze_logs(days=days)
            
            # Output the results
            self.stdout.write(self.style.SUCCESS(f"Analysis complete!"))
            self.stdout.write(f"Total logs analyzed: {results['total_logs_analyzed']}")
            self.stdout.write(f"Potential threats found: {results['potential_threats_found']}")
            self.stdout.write(f"Threat intel entries created: {results['threat_intel_entries_created']}")
            self.stdout.write(f"Suggested firewall rules: {results['suggested_rules_created']}")
            
            # Show categories
            if results.get('threat_categories'):
                self.stdout.write("\nThreat categories detected:")
                for category, count in results['threat_categories'].items():
                    self.stdout.write(f"  - {category}: {count}")
            
            # Create alerts if requested
            if create_alerts and results['threat_intel_entries_created'] > 0:
                from threat_intelligence.models import ThreatIntelEntry
                from django.utils import timezone
                
                # Get recently created entries
                recent_entries = ThreatIntelEntry.objects.filter(
                    created_at__gte=timezone.now() - timezone.timedelta(hours=1)
                )
                
                if recent_entries:
                    self.stdout.write(f"\nCreating alerts for {len(recent_entries)} recent threat intelligence entries")
                    alert_count = AlertSystem.create_intel_alerts(recent_entries)
                    self.stdout.write(self.style.SUCCESS(f"Created {alert_count} alerts"))
                else:
                    self.stdout.write("No recent threat intelligence entries found for alert creation")
            
            # Output source recommendations if available
            source_recommendations = traffic_analyzer.get_source_recommendations()
            if source_recommendations:
                self.stdout.write("\nRecommended threat intelligence sources to add:")
                for source in source_recommendations:
                    self.stdout.write(f"  - {source['name']} ({source['confidence']}% confidence)")
                    self.stdout.write(f"    {source['description']}")
                    self.stdout.write(f"    URL: {source['url']}")
            
            # Return a summary message instead of the dictionary
            return f"Traffic analysis complete: {results['threat_intel_entries_created']} threat intelligence entries created, {results['suggested_rules_created']} firewall rules suggested"
            
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Error during traffic analysis: {str(e)}"))
            logger.error(f"Error during traffic analysis command: {str(e)}", exc_info=True)
            return f"Error during traffic analysis: {str(e)}"

# Add a convenience function for calling from other code
def run_traffic_analysis(days=7, create_alerts=True):
    """
    Run traffic analysis and return the results.
    
    Args:
        days: Number of days of logs to analyze
        create_alerts: Whether to create alerts for detected patterns
        
    Returns:
        dict: Analysis results
    """
    cmd = Command()
    # Get the results dictionary before it's converted to a string
    try:
        results = traffic_analyzer.analyze_logs(days=days)
        
        # Create alerts if requested
        if create_alerts and results['threat_intel_entries_created'] > 0:
            from threat_intelligence.models import ThreatIntelEntry
            from django.utils import timezone
            
            # Get recently created entries
            recent_entries = ThreatIntelEntry.objects.filter(
                created_at__gte=timezone.now() - timezone.timedelta(hours=1)
            )
            
            if recent_entries:
                alert_count = AlertSystem.create_intel_alerts(recent_entries)
                results['alerts_created'] = alert_count
        
        return results
    except Exception as e:
        logger.error(f"Error during traffic analysis: {str(e)}", exc_info=True)
        return {
            "error": str(e),
            "timestamp": timezone.now().isoformat()
        }