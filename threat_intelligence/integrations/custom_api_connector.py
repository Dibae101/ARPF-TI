import os
import json
import logging
import requests
from datetime import datetime, timedelta
from django.utils import timezone
import validators

from ..models import ThreatIntelSource, ThreatIntelEntry

logger = logging.getLogger('arpf_ti')

class CustomAPIConnector:
    """
    Connector class for custom API integrations with flexible configuration
    """
    
    def __init__(self, source):
        """
        Initialize with a ThreatIntelSource object of type 'custom'
        """
        self.source = source
        self.session = requests.Session()
    
    def connect(self):
        """
        Set up the connection parameters for the custom API
        """
        try:
            # Configure session with common headers and auth
            self.session = requests.Session()
            
            # Set up authentication based on config
            auth_method = self.source.api_auth_method
            
            if auth_method == 'header':
                # API key in header
                auth_header = self.source.get_config_value('auth_header', 'Authorization')
                auth_prefix = self.source.get_config_value('auth_prefix', 'Bearer')
                
                if auth_prefix and self.source.api_key:
                    self.session.headers.update({auth_header: f"{auth_prefix} {self.source.api_key}"})
                elif self.source.api_key:
                    self.session.headers.update({auth_header: self.source.api_key})
            
            elif auth_method == 'parameter':
                # API key as URL parameter
                # This will be added at request time
                pass
            
            elif auth_method == 'basic':
                # Basic authentication
                username = self.source.get_config_value('username', '')
                password = self.source.api_key or self.source.get_config_value('password', '')
                self.session.auth = (username, password)
            
            # Add custom headers from config
            custom_headers = self.source.api_headers
            if custom_headers:
                self.session.headers.update(custom_headers)
            
            # Set default content type if not specified
            if 'Content-Type' not in self.session.headers:
                self.session.headers.update({'Content-Type': 'application/json'})
            
            # Set SSL verification
            self.session.verify = self.source.get_config_value('verify_ssl', True)
            
            return True
            
        except Exception as e:
            logger.error(f"Error setting up custom API connector: {str(e)}")
            return False
    
    def fetch_data(self):
        """
        Fetch threat intelligence data from the custom API
        """
        try:
            if not self.connect():
                return False
            
            # Get the endpoint URL
            url = self.source.url
            
            # Get request parameters
            method = self.source.get_config_value('method', 'GET').upper()
            params = self.source.api_params.copy() if self.source.api_params else {}
            
            # Add API key as parameter if using parameter auth method
            if self.source.api_auth_method == 'parameter':
                param_name = self.source.get_config_value('auth_param_name', 'api_key')
                params[param_name] = self.source.api_key
            
            # Add time-based parameters if configured
            time_range = self.source.get_config_value('time_range', 'day')
            time_param = self.source.get_config_value('time_param_name')
            time_format = self.source.get_config_value('time_format', '%Y-%m-%dT%H:%M:%SZ')
            
            if time_param and time_format:
                if time_range == 'hour':
                    time_value = (datetime.now() - timedelta(hours=1)).strftime(time_format)
                elif time_range == 'day':
                    time_value = (datetime.now() - timedelta(days=1)).strftime(time_format)
                elif time_range == 'week':
                    time_value = (datetime.now() - timedelta(weeks=1)).strftime(time_format)
                elif time_range == 'month':
                    time_value = (datetime.now() - timedelta(days=30)).strftime(time_format)
                else:
                    # Default to last 24 hours
                    time_value = (datetime.now() - timedelta(days=1)).strftime(time_format)
                
                params[time_param] = time_value
            
            # Build request data/body if needed
            data = None
            if method in ['POST', 'PUT', 'PATCH']:
                data_template = self.source.get_config_value('request_body', {})
                if data_template:
                    # Create a deep copy of the template
                    data = json.dumps(data_template)
            
            # Make the request
            logger.info(f"Making {method} request to {url}")
            
            response = None
            if method == 'GET':
                response = self.session.get(url, params=params)
            elif method == 'POST':
                response = self.session.post(url, params=params, data=data)
            elif method == 'PUT':
                response = self.session.put(url, params=params, data=data)
            elif method == 'PATCH':
                response = self.session.patch(url, params=params, data=data)
            elif method == 'DELETE':
                response = self.session.delete(url, params=params)
            else:
                logger.error(f"Unsupported HTTP method: {method}")
                return False
            
            # Check response status
            if not response.ok:
                logger.error(f"API request failed: {response.status_code} - {response.text}")
                return False
            
            # Extract data using JSON path if specified
            json_data = response.json()
            
            json_path = self.source.get_config_value('json_path', None)
            if json_path:
                try:
                    from jsonpath_ng import parse
                    jsonpath_expr = parse(json_path)
                    matches = [match.value for match in jsonpath_expr.find(json_data)]
                    if matches:
                        json_data = matches
                    else:
                        logger.warning(f"No data found at JSON path: {json_path}")
                        return False
                except Exception as e:
                    logger.error(f"Error extracting data with JSON path: {str(e)}")
                    return False
            
            # Process the data based on the response format
            return self.process_api_data(json_data)
            
        except Exception as e:
            logger.error(f"Error fetching data from custom API: {str(e)}")
            return False
    
    def process_api_data(self, data):
        """
        Process the API response data and store it in the database
        """
        try:
            # Get mapping configuration
            item_path = self.source.get_config_value('item_path')
            value_path = self.source.get_config_value('value_path')
            type_path = self.source.get_config_value('type_path')
            default_type = self.source.get_config_value('default_type', 'ip')
            confidence_path = self.source.get_config_value('confidence_path')
            category_path = self.source.get_config_value('category_path')
            
            # Validate required paths
            if not value_path:
                logger.error("No value_path specified in source configuration")
                return False
            
            # Process data items
            items = data
            if item_path:
                # Extract items from nested structure
                try:
                    from jsonpath_ng import parse
                    jsonpath_expr = parse(item_path)
                    items = [match.value for match in jsonpath_expr.find(data)]
                except Exception as e:
                    logger.error(f"Error extracting items with JSON path: {str(e)}")
                    return False
            
            if not isinstance(items, list):
                if isinstance(items, dict):
                    # Single item as dictionary
                    items = [items]
                else:
                    logger.error(f"Unexpected data format: {type(items)}")
                    return False
            
            # Process each item
            counter = 0
            for item in items:
                try:
                    # Extract value
                    value = self._extract_path_value(item, value_path)
                    if not value:
                        continue
                    
                    # Extract entry type
                    if type_path:
                        entry_type = self._extract_path_value(item, type_path)
                        if not entry_type:
                            entry_type = self._infer_entry_type(value, default_type)
                    else:
                        entry_type = self._infer_entry_type(value, default_type)
                    
                    # Extract confidence score
                    confidence_score = 0.75  # Default
                    if confidence_path:
                        conf_value = self._extract_path_value(item, confidence_path)
                        if conf_value:
                            try:
                                # Handle different confidence formats
                                if isinstance(conf_value, (int, float)):
                                    if conf_value <= 1.0:
                                        confidence_score = float(conf_value)
                                    else:
                                        # Assume percentage or 0-100 scale
                                        confidence_score = float(conf_value) / 100.0
                                elif isinstance(conf_value, str):
                                    if conf_value.lower() in ['high', 'critical']:
                                        confidence_score = 0.9
                                    elif conf_value.lower() == 'medium':
                                        confidence_score = 0.7
                                    elif conf_value.lower() == 'low':
                                        confidence_score = 0.5
                                    else:
                                        # Try to convert to float
                                        try:
                                            confidence_score = float(conf_value)
                                            if confidence_score > 1.0:
                                                confidence_score = confidence_score / 100.0
                                        except:
                                            # Keep default
                                            pass
                            except Exception as e:
                                logger.warning(f"Error processing confidence score: {str(e)}")
                    
                    # Extract category
                    category = 'unknown'
                    if category_path:
                        category_value = self._extract_path_value(item, category_path)
                        if category_value:
                            category = str(category_value)
                    
                    # Cap confidence score between 0 and 1
                    if confidence_score > 1.0:
                        confidence_score = 1.0
                    elif confidence_score < 0.0:
                        confidence_score = 0.0
                    
                    # Store entry in database
                    entry, created = ThreatIntelEntry.objects.get_or_create(
                        source=self.source,
                        entry_type=entry_type,
                        value=value,
                        defaults={
                            'confidence_score': confidence_score,
                            'category': category,
                            'metadata': {
                                'raw_data': item  # Store the original data for reference
                            }
                        }
                    )
                    
                    # Update the last_seen timestamp for existing entries
                    if not created:
                        entry.last_seen = timezone.now()
                        entry.confidence_score = confidence_score
                        entry.save()
                    
                    counter += 1
                    
                except Exception as e:
                    logger.warning(f"Error processing item: {str(e)}")
            
            logger.info(f"Processed {counter} entries from custom API")
            
            # Update the last_updated timestamp for the source
            self.source.last_updated = timezone.now()
            self.source.save()
            
            return counter > 0
            
        except Exception as e:
            logger.error(f"Error processing API data: {str(e)}")
            return False
    
    def _extract_path_value(self, item, path):
        """
        Extract a value from an item using dot notation or JSON path
        """
        try:
            # Try simple dot notation first
            if '.' in path:
                parts = path.split('.')
                value = item
                for part in parts:
                    if isinstance(value, dict) and part in value:
                        value = value[part]
                    else:
                        return None
                return value
            elif path in item:
                return item[path]
            
            # If simple path fails, try JSON path
            try:
                from jsonpath_ng import parse
                jsonpath_expr = parse(f"$.{path}")
                matches = [match.value for match in jsonpath_expr.find(item)]
                if matches:
                    return matches[0]
            except:
                pass
            
            return None
        except Exception as e:
            logger.warning(f"Error extracting path value: {str(e)}")
            return None
    
    def _infer_entry_type(self, value, default_type):
        """
        Infer the entry type based on the value format
        """
        if validators.ipv4(value) or validators.ipv6(value):
            return 'ip'
        elif validators.domain(value):
            return 'domain'
        elif validators.md5(value) or validators.sha1(value) or validators.sha256(value):
            return 'hash'
        elif validators.url(value):
            return 'other'  # URL type
        
        # Check for ASN format
        if isinstance(value, str) and value.upper().startswith('AS') and value[2:].isdigit():
            return 'asn'
        
        # Check for IP range format (CIDR)
        if isinstance(value, str) and '/' in value:
            ip_part = value.split('/')[0]
            if validators.ipv4(ip_part) or validators.ipv6(ip_part):
                return 'ip_range'
        
        # Default type if we can't determine
        return default_type