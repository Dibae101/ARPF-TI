import os
import logging
from datetime import datetime, timedelta
from django.utils import timezone
from taxii2client.v21 import Server, Collection, ApiRoot
from stix2 import parse as stix_parse
# Fix the import - use a more compatible approach with different STIX2 versions
from stix2.datastore import CompositeDataSource
# Create a simple MemoryStore alternative
from collections import defaultdict

from ..models import ThreatIntelSource, ThreatIntelEntry

logger = logging.getLogger('arpf_ti')

# Simple MemoryStore implementation for compatibility
class SimpleMemoryStore:
    def __init__(self):
        self.objects = defaultdict(dict)
    
    def add(self, stix_obj):
        try:
            obj_type = stix_obj.get('type')
            obj_id = stix_obj.get('id')
            if obj_type and obj_id:
                self.objects[obj_type][obj_id] = stix_obj
            return True
        except Exception as e:
            logger.warning(f"Failed to add object to memory store: {str(e)}")
            return False
    
    def query(self, query):
        # Basic implementation - just return all objects
        results = []
        for obj_type in self.objects:
            results.extend(list(self.objects[obj_type].values()))
        return results

class TAXIIConnector:
    """
    Connector class for TAXII 2.1 servers and STIX content
    """
    
    def __init__(self, source):
        """
        Initialize with a ThreatIntelSource object of type 'taxii'
        """
        self.source = source
        self.server = None
        self.collection = None
        self.datastore = CompositeDataSource()
    
    def connect(self):
        """
        Connect to the TAXII server and authenticate
        """
        try:
            server_url = self.source.url
            
            # Connect to TAXII server
            logger.info(f"Connecting to TAXII server at {server_url}")
            
            # Authentication based on config
            if self.source.api_key:
                # Using API key-based authentication
                self.server = Server(server_url, user=self.source.get_config_value('username', ''), 
                                    password=self.source.api_key, verify=self.source.get_config_value('verify_ssl', True))
            else:
                # No authentication
                self.server = Server(server_url, verify=self.source.get_config_value('verify_ssl', True))
            
            # Get the API roots
            api_roots = self.server.api_roots
            
            if not api_roots:
                logger.error(f"No API roots found for TAXII server at {server_url}")
                return False
            
            # Get the specified API root or use the first one
            api_root_name = self.source.get_config_value('api_root', None)
            if api_root_name:
                api_root = next((root for root in api_roots if root.title == api_root_name), api_roots[0])
            else:
                api_root = api_roots[0]
            
            # Get the specified collection or use the first available one
            collection_id = self.source.taxii_collection_id
            collection_name = self.source.taxii_collection_name
            
            collections = api_root.collections
            
            if collection_id:
                self.collection = next((col for col in collections if col.id == collection_id), None)
            elif collection_name:
                self.collection = next((col for col in collections if col.title == collection_name), None)
            else:
                self.collection = collections[0] if collections else None
            
            if not self.collection:
                logger.error("No collection found matching criteria")
                return False
            
            logger.info(f"Successfully connected to TAXII collection: {self.collection.title}")
            return True
            
        except Exception as e:
            logger.error(f"Error connecting to TAXII server: {str(e)}")
            return False
    
    def fetch_data(self):
        """
        Fetch STIX objects from the TAXII collection
        """
        try:
            if not self.collection:
                if not self.connect():
                    return False
            
            # Get the time range to fetch data for
            time_range = self.source.get_config_value('time_range', 'day')
            
            if time_range == 'hour':
                added_after = datetime.now() - timedelta(hours=1)
            elif time_range == 'day':
                added_after = datetime.now() - timedelta(days=1)
            elif time_range == 'week':
                added_after = datetime.now() - timedelta(weeks=1)
            elif time_range == 'month':
                added_after = datetime.now() - timedelta(days=30)
            else:
                # Default to last 24 hours
                added_after = datetime.now() - timedelta(days=1)
            
            # Fetch objects
            stix_objects = self.collection.get_objects(added_after=added_after)
            
            # Use our simple memory store implementation instead of the stix2.datastore.MemoryStore
            memory_store = SimpleMemoryStore()
            for obj in stix_objects.get('objects', []):
                try:
                    memory_store.add(stix_parse(obj))
                except Exception as e:
                    logger.warning(f"Failed to parse STIX object: {str(e)}")
            
            # Process objects directly without using the datastore
            return self.process_stix_objects(stix_objects.get('objects', []))
        
        except Exception as e:
            logger.error(f"Error fetching data from TAXII collection: {str(e)}")
            return False
    
    def process_stix_objects(self, stix_objects):
        """
        Process STIX objects and store them in the database
        """
        if not stix_objects:
            logger.warning("No STIX objects found to process")
            return False
        
        counter = 0
        
        for obj in stix_objects:
            try:
                parsed_obj = stix_parse(obj) if isinstance(obj, dict) else obj
                stix_type = parsed_obj.get('type', '')
                
                # Process different types of STIX objects
                if stix_type == 'indicator':
                    self._process_indicator(parsed_obj)
                    counter += 1
                elif stix_type == 'threat-actor':
                    self._process_threat_actor(parsed_obj)
                    counter += 1
                elif stix_type == 'malware':
                    self._process_malware(parsed_obj)
                    counter += 1
                elif stix_type == 'attack-pattern':
                    self._process_attack_pattern(parsed_obj)
                    counter += 1
                elif stix_type == 'campaign':
                    self._process_campaign(parsed_obj)
                    counter += 1
                elif stix_type == 'vulnerability':
                    self._process_vulnerability(parsed_obj)
                    counter += 1
                # Other types can be added here as needed
            
            except Exception as e:
                logger.warning(f"Error processing STIX object: {str(e)}")
        
        logger.info(f"Processed {counter} STIX objects from {self.source.name}")
        
        # Update the last_updated timestamp for the source
        self.source.last_updated = timezone.now()
        self.source.save()
        
        return counter > 0
    
    def _process_indicator(self, indicator):
        """Process a STIX indicator object"""
        try:
            # Extract the pattern value (e.g., [ipv4-addr:value = '1.2.3.4'])
            pattern = indicator.get('pattern', '')
            pattern_type = indicator.get('pattern_type', 'stix')
            
            if pattern_type != 'stix':
                logger.warning(f"Unsupported pattern type: {pattern_type}")
                return
            
            # Basic pattern parsing - this would need to be enhanced for complex patterns
            value = None
            entry_type = 'indicator'
            
            # Try to extract the indicator value and determine its type
            if 'ipv4-addr:value' in pattern:
                entry_type = 'ip'
                import re
                ip_match = re.search(r"'((?:\d{1,3}\.){3}\d{1,3})'", pattern)
                if ip_match:
                    value = ip_match.group(1)
            elif 'domain-name:value' in pattern:
                entry_type = 'domain'
                import re
                domain_match = re.search(r"'([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})'", pattern)
                if domain_match:
                    value = domain_match.group(1)
            elif 'file:hashes' in pattern:
                entry_type = 'hash'
                import re
                hash_match = re.search(r"'([a-fA-F0-9]{32,})'", pattern)
                if hash_match:
                    value = hash_match.group(1)
            else:
                # For other pattern types, store the whole pattern
                value = pattern
            
            if not value:
                logger.warning(f"Failed to extract value from pattern: {pattern}")
                return
            
            # Calculate confidence score (normalized to 0.0-1.0)
            confidence_score = float(indicator.get('confidence', 75)) / 100
            if confidence_score > 1.0:
                confidence_score = 1.0
            elif confidence_score < 0.0:
                confidence_score = 0.0
            
            # Get or create the entry
            entry, created = ThreatIntelEntry.objects.get_or_create(
                source=self.source,
                entry_type=entry_type,
                value=value,
                defaults={
                    'confidence_score': confidence_score,
                    'category': indicator.get('indicator_types', ['unknown'])[0] if indicator.get('indicator_types') else 'unknown',
                    'stix_id': indicator.get('id', ''),
                    'metadata': {
                        'stix_type': 'indicator',
                        'name': indicator.get('name', ''),
                        'description': indicator.get('description', ''),
                        'pattern': pattern,
                        'pattern_type': pattern_type,
                        'valid_from': indicator.get('valid_from', ''),
                        'valid_until': indicator.get('valid_until', ''),
                        'kill_chain_phases': indicator.get('kill_chain_phases', []),
                        'tlp': indicator.get('object_marking_refs', ['tlp:white'])[0].split(':')[1].upper() if indicator.get('object_marking_refs') else 'WHITE'
                    }
                }
            )
            
            # Update the last_seen timestamp for existing entries
            if not created:
                entry.last_seen = timezone.now()
                entry.confidence_score = confidence_score
                entry.save()
            
        except Exception as e:
            logger.error(f"Error processing indicator: {str(e)}")
    
    def _process_threat_actor(self, threat_actor):
        """Process a STIX threat actor object"""
        try:
            # Create a threat actor entry
            value = threat_actor.get('name', threat_actor.get('id', ''))
            
            if not value:
                logger.warning("Threat actor has no name or ID")
                return
            
            entry, created = ThreatIntelEntry.objects.get_or_create(
                source=self.source,
                entry_type='threat_actor',
                value=value,
                defaults={
                    'confidence_score': float(threat_actor.get('confidence', 75)) / 100,
                    'category': threat_actor.get('threat_actor_types', ['unknown'])[0] if threat_actor.get('threat_actor_types') else 'unknown',
                    'stix_id': threat_actor.get('id', ''),
                    'metadata': {
                        'stix_type': 'threat-actor',
                        'description': threat_actor.get('description', ''),
                        'aliases': threat_actor.get('aliases', []),
                        'roles': threat_actor.get('roles', []),
                        'goals': threat_actor.get('goals', []),
                        'sophistication': threat_actor.get('sophistication', ''),
                        'resource_level': threat_actor.get('resource_level', ''),
                        'primary_motivation': threat_actor.get('primary_motivation', ''),
                        'secondary_motivations': threat_actor.get('secondary_motivations', []),
                        'tlp': threat_actor.get('object_marking_refs', ['tlp:white'])[0].split(':')[1].upper() if threat_actor.get('object_marking_refs') else 'WHITE'
                    }
                }
            )
            
            # Update the last_seen timestamp for existing entries
            if not created:
                entry.last_seen = timezone.now()
                entry.save()
                
        except Exception as e:
            logger.error(f"Error processing threat actor: {str(e)}")
    
    def _process_malware(self, malware):
        """Process a STIX malware object"""
        try:
            # Create a malware entry
            value = malware.get('name', malware.get('id', ''))
            
            if not value:
                logger.warning("Malware has no name or ID")
                return
            
            entry, created = ThreatIntelEntry.objects.get_or_create(
                source=self.source,
                entry_type='malware',
                value=value,
                defaults={
                    'confidence_score': 0.8,  # Default confidence for malware
                    'category': malware.get('malware_types', ['unknown'])[0] if malware.get('malware_types') else 'unknown',
                    'stix_id': malware.get('id', ''),
                    'metadata': {
                        'stix_type': 'malware',
                        'description': malware.get('description', ''),
                        'is_family': malware.get('is_family', False),
                        'aliases': malware.get('aliases', []),
                        'kill_chain_phases': malware.get('kill_chain_phases', []),
                        'capabilities': malware.get('capabilities', []),
                        'tlp': malware.get('object_marking_refs', ['tlp:white'])[0].split(':')[1].upper() if malware.get('object_marking_refs') else 'WHITE'
                    }
                }
            )
            
            # Update the last_seen timestamp for existing entries
            if not created:
                entry.last_seen = timezone.now()
                entry.save()
                
        except Exception as e:
            logger.error(f"Error processing malware: {str(e)}")
    
    def _process_attack_pattern(self, attack_pattern):
        """Process a STIX attack pattern object"""
        # Implementation similar to threat actor and malware
        try:
            value = attack_pattern.get('name', attack_pattern.get('id', ''))
            
            if not value:
                logger.warning("Attack pattern has no name or ID")
                return
            
            entry, created = ThreatIntelEntry.objects.get_or_create(
                source=self.source,
                entry_type='attack_pattern',
                value=value,
                defaults={
                    'confidence_score': 0.9,  # Default confidence for attack patterns
                    'category': attack_pattern.get('attack_pattern_types', ['unknown'])[0] if attack_pattern.get('attack_pattern_types') else 'unknown',
                    'stix_id': attack_pattern.get('id', ''),
                    'metadata': {
                        'stix_type': 'attack-pattern',
                        'description': attack_pattern.get('description', ''),
                        'external_references': attack_pattern.get('external_references', []),
                        'kill_chain_phases': attack_pattern.get('kill_chain_phases', []),
                        'tlp': attack_pattern.get('object_marking_refs', ['tlp:white'])[0].split(':')[1].upper() if attack_pattern.get('object_marking_refs') else 'WHITE'
                    }
                }
            )
            
            if not created:
                entry.last_seen = timezone.now()
                entry.save()
                
        except Exception as e:
            logger.error(f"Error processing attack pattern: {str(e)}")
    
    def _process_campaign(self, campaign):
        """Process a STIX campaign object"""
        # Implementation similar to other types
        try:
            value = campaign.get('name', campaign.get('id', ''))
            
            if not value:
                logger.warning("Campaign has no name or ID")
                return
            
            entry, created = ThreatIntelEntry.objects.get_or_create(
                source=self.source,
                entry_type='campaign',
                value=value,
                defaults={
                    'confidence_score': 0.8,
                    'category': campaign.get('campaign_types', ['unknown'])[0] if campaign.get('campaign_types') else 'unknown',
                    'stix_id': campaign.get('id', ''),
                    'metadata': {
                        'stix_type': 'campaign',
                        'description': campaign.get('description', ''),
                        'aliases': campaign.get('aliases', []),
                        'first_seen': campaign.get('first_seen', ''),
                        'last_seen': campaign.get('last_seen', ''),
                        'objective': campaign.get('objective', ''),
                        'tlp': campaign.get('object_marking_refs', ['tlp:white'])[0].split(':')[1].upper() if campaign.get('object_marking_refs') else 'WHITE'
                    }
                }
            )
            
            if not created:
                entry.last_seen = timezone.now()
                entry.save()
                
        except Exception as e:
            logger.error(f"Error processing campaign: {str(e)}")
    
    def _process_vulnerability(self, vulnerability):
        """Process a STIX vulnerability object"""
        try:
            value = vulnerability.get('name', vulnerability.get('id', ''))
            
            if not value:
                logger.warning("Vulnerability has no name or ID")
                return
            
            entry, created = ThreatIntelEntry.objects.get_or_create(
                source=self.source,
                entry_type='vulnerability',
                value=value,
                defaults={
                    'confidence_score': 0.9,
                    'category': 'vulnerability',
                    'stix_id': vulnerability.get('id', ''),
                    'metadata': {
                        'stix_type': 'vulnerability',
                        'description': vulnerability.get('description', ''),
                        'external_references': vulnerability.get('external_references', []),
                        'tlp': vulnerability.get('object_marking_refs', ['tlp:white'])[0].split(':')[1].upper() if vulnerability.get('object_marking_refs') else 'WHITE'
                    }
                }
            )
            
            if not created:
                entry.last_seen = timezone.now()
                entry.save()
                
        except Exception as e:
            logger.error(f"Error processing vulnerability: {str(e)}")