import json
import logging
import requests
from datetime import datetime
from django.utils import timezone
from django.conf import settings
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from .models import ThreatIntelSource, ThreatIntelEntry

# Import the new connectors
from .integrations.taxii_connector import TAXIIConnector
from .integrations.misp_connector import MISPConnector
from .integrations.custom_api_connector import CustomAPIConnector

logger = logging.getLogger('arpf_ti')

class ThreatIntelFetcher:
    """
    Fetches threat intelligence data from configured sources
    and updates the database.
    """
    
    def __init__(self):
        self.scheduler = BackgroundScheduler()
        self.api_key = settings.API_KEY
    
    def start(self):
        """Start the background scheduler."""
        if not self.scheduler.running:
            self.scheduler.start()
            logger.info("Threat intelligence scheduler started")
            
            # Schedule initial fetch for all active sources
            self._schedule_all_sources()
    
    def stop(self):
        """Stop the background scheduler."""
        if self.scheduler.running:
            self.scheduler.shutdown()
            logger.info("Threat intelligence scheduler stopped")
    
    def _schedule_all_sources(self):
        """Schedule fetch jobs for all active sources."""
        sources = ThreatIntelSource.objects.filter(is_active=True)
        for source in sources:
            self._schedule_source(source)
    
    def _schedule_source(self, source):
        """Schedule a fetch job for a specific source."""
        # Calculate seconds for the update frequency
        seconds = source.update_frequency
        
        # Add the job to the scheduler
        self.scheduler.add_job(
            self.fetch_source_data,
            trigger=IntervalTrigger(seconds=seconds),
            args=[source.id],
            id=f"threat_intel_{source.id}",
            replace_existing=True
        )
        logger.info(f"Scheduled {source.name} to update every {seconds} seconds")
    
    def fetch_source_data(self, source_id):
        """Fetch data from a specific threat intelligence source."""
        try:
            source = ThreatIntelSource.objects.get(id=source_id, is_active=True)
            logger.info(f"Fetching threat intelligence data from {source.name}")
            
            # Different handling based on source type
            if source.source_type == 'taxii':
                # Use TAXII connector
                connector = TAXIIConnector(source)
                success = connector.fetch_data()
            elif source.source_type == 'misp':
                # Use MISP connector
                connector = MISPConnector(source)
                success = connector.fetch_data()
            elif source.source_type == 'stix':
                # Handle STIX files
                self._fetch_stix_data(source)
                success = True
            elif source.source_type == 'custom':
                # Use enhanced custom API connector
                connector = CustomAPIConnector(source)
                success = connector.fetch_data()
            elif source.source_type == 'ip_list':
                self._fetch_ip_list(source)
                success = True
            elif source.source_type == 'vpn_ips':
                self._fetch_vpn_ips(source)
                success = True
            elif source.source_type == 'cloud_ips':
                self._fetch_cloud_ips(source)
                success = True
            elif source.source_type == 'botnet':
                self._fetch_botnet_data(source)
                success = True
            elif source.source_type == 'geo_block':
                self._fetch_geo_block_data(source)
                success = True
            else:
                logger.warning(f"Unknown source type: {source.source_type}")
                success = False
            
            # Update the last_updated timestamp
            if success:
                source.last_updated = timezone.now()
                source.save()
                logger.info(f"Successfully updated threat intelligence from {source.name}")
            else:
                logger.warning(f"Failed to update threat intelligence from {source.name}")
                
        except Exception as e:
            logger.error(f"Error fetching threat intelligence from source {source_id}: {str(e)}")
    
    def _fetch_stix_data(self, source):
        """Fetch and process STIX files."""
        try:
            # Download the STIX file
            response = requests.get(source.url, headers={'Accept': 'application/json'})
            response.raise_for_status()
            
            # Parse STIX content
            from stix2 import parse as stix_parse
            stix_objects = response.json()
            
            # Process each STIX object
            for obj in stix_objects.get('objects', []):
                parsed_obj = stix_parse(obj)
                stix_type = parsed_obj.get('type', '')
                
                # We can reuse the TAXIIConnector's processing methods
                connector = TAXIIConnector(source)
                if stix_type == 'indicator':
                    connector._process_indicator(parsed_obj)
                elif stix_type == 'threat-actor':
                    connector._process_threat_actor(parsed_obj)
                elif stix_type == 'malware':
                    connector._process_malware(parsed_obj)
                elif stix_type == 'attack-pattern':
                    connector._process_attack_pattern(parsed_obj)
                elif stix_type == 'campaign':
                    connector._process_campaign(parsed_obj)
                elif stix_type == 'vulnerability':
                    connector._process_vulnerability(parsed_obj)
            
            return True
        except Exception as e:
            logger.error(f"Error processing STIX file: {str(e)}")
            return False
    
    def _make_request(self, url, headers=None, params=None):
        """Make an HTTP request to a threat intelligence API."""
        if headers is None:
            headers = {}
        
        if self.api_key and 'key' not in params and 'api_key' not in params:
            params = params or {}
            params['api_key'] = self.api_key
        
        response = requests.get(url, headers=headers, params=params, timeout=30)
        response.raise_for_status()
        return response.json()
    
    def _fetch_ip_list(self, source):
        """Fetch IP blocklist data."""
        data = self._make_request(source.url)
        self._process_ip_list(source, data)
    
    def _fetch_vpn_ips(self, source):
        """Fetch VPN IP address data."""
        data = self._make_request(source.url)
        self._process_vpn_ips(source, data)
    
    def _fetch_cloud_ips(self, source):
        """Fetch cloud provider IP ranges."""
        data = self._make_request(source.url)
        self._process_cloud_ips(source, data)
    
    def _fetch_botnet_data(self, source):
        """Fetch botnet tracker data."""
        data = self._make_request(source.url)
        self._process_botnet_data(source, data)
    
    def _fetch_geo_block_data(self, source):
        """Fetch geographic block data."""
        data = self._make_request(source.url)
        self._process_geo_block_data(source, data)
    
    def _process_ip_list(self, source, data):
        """Process IP blocklist data."""
        # This is a generic implementation - adjust based on actual data format
        ips = data.get('ips', [])
        self._add_or_update_entries(source, 'ip', ips)
    
    def _process_vpn_ips(self, source, data):
        """Process VPN IP address data."""
        # Adjust based on actual data format from your VPN IP source
        ips = data.get('vpn_ips', [])
        self._add_or_update_entries(source, 'ip', ips, category='vpn')
    
    def _process_cloud_ips(self, source, data):
        """Process cloud provider IP ranges."""
        # Adjust based on actual data format from your cloud IP source
        ip_ranges = data.get('prefixes', [])
        entries = []
        for ip_range in ip_ranges:
            prefix = ip_range.get('ip_prefix')
            if prefix:
                entries.append({'value': prefix, 'category': ip_range.get('service', 'cloud')})
        
        self._add_or_update_entries(source, 'ip_range', entries)
    
    def _process_botnet_data(self, source, data):
        """Process botnet tracker data."""
        # Adjust based on actual data format from your botnet tracker
        botnet_ips = data.get('botnet_ips', [])
        entries = []
        for ip_data in botnet_ips:
            entries.append({
                'value': ip_data.get('ip'),
                'category': ip_data.get('botnet_name', 'botnet'),
                'confidence_score': ip_data.get('confidence', 1.0)
            })
        
        self._add_or_update_entries(source, 'ip', entries)
    
    def _process_geo_block_data(self, source, data):
        """Process geographic block data."""
        # Adjust based on actual data format from your geo block source
        countries = data.get('countries', [])
        self._add_or_update_entries(source, 'country', countries)
    
    def _add_or_update_entries(self, source, entry_type, entries, category=None):
        """Add or update threat intelligence entries in the database."""
        # For simple string lists
        if isinstance(entries, list) and all(isinstance(entry, str) for entry in entries):
            for entry_value in entries:
                ThreatIntelEntry.objects.update_or_create(
                    source=source,
                    entry_type=entry_type,
                    value=entry_value,
                    defaults={
                        'category': category,
                        'is_active': True,
                        'last_seen': timezone.now(),
                        'is_test_data': False  # Ensure entries are marked as real data
                    }
                )
        
        # For list of dictionaries with more details
        elif isinstance(entries, list) and all(isinstance(entry, dict) for entry in entries):
            for entry_data in entries:
                if 'value' in entry_data:
                    ThreatIntelEntry.objects.update_or_create(
                        source=source,
                        entry_type=entry_type,
                        value=entry_data['value'],
                        defaults={
                            'category': entry_data.get('category', category),
                            'confidence_score': entry_data.get('confidence_score', 1.0),
                            'is_active': True,
                            'last_seen': timezone.now(),
                            'is_test_data': False  # Ensure entries are marked as real data
                        }
                    )

# Create a singleton instance
threat_intel_fetcher = ThreatIntelFetcher()