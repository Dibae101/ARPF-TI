import os
import logging
from datetime import datetime, timedelta
from django.utils import timezone
from pymisp import PyMISP, MISPEvent

from ..models import ThreatIntelSource, ThreatIntelEntry

logger = logging.getLogger('arpf_ti')

class MISPConnector:
    """
    Connector class for MISP (Malware Information Sharing Platform) instances
    """
    
    def __init__(self, source):
        """
        Initialize with a ThreatIntelSource object of type 'misp'
        """
        self.source = source
        self.misp = None
    
    def connect(self):
        """
        Connect to the MISP instance and authenticate
        """
        try:
            misp_url = self.source.url
            misp_key = self.source.api_key
            
            if not misp_key:
                logger.error("No API key provided for MISP instance")
                return False
            
            # Connect to MISP
            logger.info(f"Connecting to MISP instance at {misp_url}")
            verify_ssl = self.source.misp_verify_ssl
            
            self.misp = PyMISP(misp_url, misp_key, ssl=verify_ssl)
            
            # Test connection by fetching the MISP version
            result = self.misp.get_version()
            if not result or 'version' not in result:
                logger.error("Failed to connect to MISP instance")
                return False
            
            logger.info(f"Successfully connected to MISP instance (version: {result['version']})")
            return True
            
        except Exception as e:
            logger.error(f"Error connecting to MISP instance: {str(e)}")
            return False
    
    def fetch_data(self):
        """
        Fetch events from the MISP instance
        """
        try:
            if not self.misp:
                if not self.connect():
                    return False
            
            # Get time range to fetch data for
            time_range = self.source.get_config_value('time_range', 'day')
            
            if time_range == 'hour':
                days = 0.042  # 1 hour in days
            elif time_range == 'day':
                days = 1
            elif time_range == 'week':
                days = 7
            elif time_range == 'month':
                days = 30
            else:
                # Default to last 24 hours
                days = 1
            
            # Get event limit
            limit = self.source.misp_event_limit
            
            # Fetch events
            logger.info(f"Fetching events from MISP (last {days} days, limit: {limit})")
            
            events = self.misp.search(controller='events', 
                                     published=True, 
                                     date_from=datetime.now() - timedelta(days=days),
                                     limit=limit, 
                                     metadata=False)
            
            if not events:
                logger.warning("No events found in MISP instance")
                return False
            
            processed_count = self.process_misp_events(events)
            
            # Update the last_updated timestamp for the source
            self.source.last_updated = timezone.now()
            self.source.save()
            
            return processed_count > 0
            
        except Exception as e:
            logger.error(f"Error fetching data from MISP instance: {str(e)}")
            return False
    
    def process_misp_events(self, events):
        """
        Process MISP events and store them in the database
        """
        if not events:
            return 0
        
        counter = 0
        
        for event_data in events:
            try:
                # Convert to MISPEvent object if it's not already
                if isinstance(event_data, dict):
                    event = MISPEvent()
                    event.from_dict(**event_data)
                else:
                    event = event_data
                
                # Get event metadata
                event_id = str(event.id)
                event_info = event.info
                event_tags = [tag.name for tag in event.tags] if hasattr(event, 'tags') and event.tags else []
                event_tlp = 'WHITE'  # Default
                
                # Extract TLP from tags
                for tag in event_tags:
                    if tag.startswith('tlp:'):
                        event_tlp = tag.split(':')[1].upper()
                        break
                
                # Process attributes
                if hasattr(event, 'attributes') and event.attributes:
                    for attribute in event.attributes:
                        self._process_misp_attribute(attribute, event_id, event_info, event_tlp, event_tags)
                        counter += 1
                
                # Process objects and their attributes
                if hasattr(event, 'objects') and event.objects:
                    for obj in event.objects:
                        obj_name = obj.name if hasattr(obj, 'name') else 'unknown'
                        
                        if hasattr(obj, 'attributes') and obj.attributes:
                            for attribute in obj.attributes:
                                self._process_misp_attribute(attribute, event_id, event_info, event_tlp, event_tags, obj_name)
                                counter += 1
            
            except Exception as e:
                logger.warning(f"Error processing MISP event: {str(e)}")
        
        logger.info(f"Processed {counter} indicators from {len(events)} MISP events")
        return counter
    
    def _process_misp_attribute(self, attribute, event_id, event_info, event_tlp, event_tags, obj_name=None):
        """Process a MISP attribute and store it in the database"""
        try:
            # Get attribute properties
            attr_type = attribute.type if hasattr(attribute, 'type') else ''
            attr_value = attribute.value if hasattr(attribute, 'value') else ''
            attr_id = str(attribute.id) if hasattr(attribute, 'id') else ''
            attr_category = attribute.category if hasattr(attribute, 'category') else ''
            attr_to_ids = attribute.to_ids if hasattr(attribute, 'to_ids') else False
            
            if not attr_value or not attr_type:
                return
            
            # Map MISP attribute types to our entry types
            entry_type = self._map_misp_type_to_entry_type(attr_type)
            
            # Skip unsupported types
            if not entry_type:
                logger.debug(f"Skipping unsupported MISP attribute type: {attr_type}")
                return
            
            # Calculate confidence score
            confidence_score = 0.8  # Default
            if attr_to_ids:
                confidence_score = 0.9  # Higher confidence for IDS-flagged indicators
            
            # Get or create entry
            entry, created = ThreatIntelEntry.objects.get_or_create(
                source=self.source,
                entry_type=entry_type,
                value=attr_value,
                defaults={
                    'confidence_score': confidence_score,
                    'category': attr_category or obj_name or 'unknown',
                    'misp_event_id': event_id,
                    'misp_attribute_id': attr_id,
                    'metadata': {
                        'event_info': event_info,
                        'attribute_type': attr_type,
                        'to_ids': attr_to_ids,
                        'object_name': obj_name,
                        'tags': event_tags,
                        'tlp': event_tlp
                    }
                }
            )
            
            # Update the last_seen timestamp for existing entries
            if not created:
                entry.last_seen = timezone.now()
                entry.confidence_score = confidence_score
                entry.save()
            
        except Exception as e:
            logger.error(f"Error processing MISP attribute: {str(e)}")
    
    def _map_misp_type_to_entry_type(self, misp_type):
        """Map MISP attribute types to our entry types"""
        type_mapping = {
            'ip-src': 'ip',
            'ip-dst': 'ip',
            'ip-src|port': 'ip',
            'ip-dst|port': 'ip',
            'domain': 'domain',
            'hostname': 'domain',
            'domain|ip': 'domain',
            'md5': 'hash',
            'sha1': 'hash',
            'sha256': 'hash',
            'filename|md5': 'hash',
            'filename|sha1': 'hash',
            'filename|sha256': 'hash',
            'url': 'other',
            'threat-actor': 'threat_actor',
            'vulnerability': 'vulnerability',
            'malware-sample': 'malware',
            'mutex': 'other',
            'registry-key': 'other',
            'email-src': 'other',
            'email-dst': 'other',
            'as': 'asn'
        }
        
        return type_mapping.get(misp_type, None)