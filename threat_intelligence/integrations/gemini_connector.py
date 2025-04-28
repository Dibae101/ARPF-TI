import json
import logging
import requests
from django.conf import settings
from django.utils import timezone
from ..models import ThreatIntelEntry

logger = logging.getLogger('arpf_ti')

class GeminiConnector:
    """
    Connector for Google's Gemini AI API for threat detection.
    This class handles all interactions with the Gemini API for analyzing 
    and detecting potential threats in network traffic and requests.
    """
    
    def __init__(self, source=None):
        """Initialize the Gemini connector."""
        self.source = source
        self.api_key = settings.GEMINI_API_KEY
        self.api_url = settings.GEMINI_API_URL
        
    def analyze_request(self, request_data):
        """
        Analyze a request using Gemini to determine if it's a potential threat.
        
        Args:
            request_data (dict): Data about the request to analyze (IP, headers, path, etc.)
            
        Returns:
            dict: Analysis results including threat score, reason, and recommended action
        """
        # Format the request data for Gemini analysis
        prompt = self._format_request_for_analysis(request_data)
        
        # Call Gemini API for analysis
        response = self._call_gemini_api(prompt)
        
        # Process and interpret the response
        analysis_result = self._interpret_gemini_response(response, request_data)
        
        return analysis_result
    
    def analyze_ip(self, ip_address, context=None):
        """
        Analyze an IP address to determine if it's a potential threat.
        
        Args:
            ip_address (str): The IP address to analyze
            context (dict, optional): Additional context about the IP
            
        Returns:
            dict: Analysis results including threat score and reason
        """
        # Create prompt for IP analysis
        prompt = f"""As a next-generation firewall, analyze this IP address for potential threats: {ip_address}
        
Additional context: {json.dumps(context) if context else 'No additional context'}

Please provide a security assessment with the following:
1. Is this IP likely malicious? (yes/no/uncertain)
2. Threat score (0-100)
3. Specific threat categories this IP might belong to (e.g., botnet, scanner, VPN)
4. Recommended action (block, alert, allow)
5. Brief explanation for your assessment

Format your response as JSON with fields: is_malicious, threat_score, threat_categories, recommended_action, explanation"""
        
        # Call Gemini API for analysis
        response = self._call_gemini_api(prompt)
        
        # Process and interpret the response
        try:
            # Extract the text content from the Gemini response
            text_content = self._extract_text_from_response(response)
            
            # Try to parse JSON from the response
            json_start = text_content.find('{')
            json_end = text_content.rfind('}') + 1
            
            if json_start >= 0 and json_end > json_start:
                json_str = text_content[json_start:json_end]
                analysis = json.loads(json_str)
            else:
                # Fallback if JSON parsing fails
                analysis = {
                    "is_malicious": "uncertain",
                    "threat_score": 50,
                    "threat_categories": [],
                    "recommended_action": "alert",
                    "explanation": "Could not determine threat level from analysis"
                }
                
            # Add the raw IP to the result
            analysis["ip_address"] = ip_address
            
            # Log the analysis
            logger.info(f"Gemini analysis for IP {ip_address}: Threat score {analysis.get('threat_score')}, Action: {analysis.get('recommended_action')}")
            
            return analysis
            
        except Exception as e:
            logger.error(f"Error interpreting Gemini response for IP analysis: {str(e)}")
            return {
                "ip_address": ip_address,
                "is_malicious": "error",
                "threat_score": 0,
                "threat_categories": [],
                "recommended_action": "alert",
                "explanation": f"Error analyzing IP: {str(e)}"
            }
    
    def analyze_traffic_pattern(self, traffic_data):
        """
        Analyze traffic patterns to identify potential attacks or anomalies.
        
        Args:
            traffic_data (dict): Data about traffic patterns
            
        Returns:
            dict: Analysis results including threat assessment and recommendations
        """
        # Create prompt for traffic pattern analysis
        prompt = f"""As a next-generation firewall security system, analyze this traffic pattern for potential threats:
        
Traffic Data: {json.dumps(traffic_data)}

Analyze this traffic pattern for:
1. Signs of DDoS attacks
2. Brute force attempts
3. Web application attacks (SQL injection, XSS, etc.)
4. Unusual access patterns
5. Data exfiltration attempts

Provide your assessment with: type of potential attack (if any), confidence level (0-100), 
and recommended security measures. Format as JSON."""
        
        # Call Gemini API for analysis
        response = self._call_gemini_api(prompt)
        
        # Process the response
        try:
            # Extract the text content from the response
            text_content = self._extract_text_from_response(response)
            
            # Try to parse JSON from the response
            json_start = text_content.find('{')
            json_end = text_content.rfind('}') + 1
            
            if json_start >= 0 and json_end > json_start:
                json_str = text_content[json_start:json_end]
                analysis = json.loads(json_str)
            else:
                # Fallback if JSON parsing fails
                analysis = {
                    "attack_type": "unknown",
                    "confidence": 0,
                    "recommendations": ["Monitor traffic", "Enable enhanced logging"]
                }
            
            return analysis
            
        except Exception as e:
            logger.error(f"Error interpreting Gemini response for traffic analysis: {str(e)}")
            return {
                "attack_type": "error",
                "confidence": 0,
                "recommendations": ["Error in analysis", "Monitor traffic manually"]
            }
    
    def _format_request_for_analysis(self, request_data):
        """Format the request data into a prompt for Gemini."""
        prompt = f"""As a next-generation firewall security system, analyze this HTTP request for potential security threats:

IP Address: {request_data.get('source_ip', 'Unknown')}
Method: {request_data.get('method', 'Unknown')}
Path: {request_data.get('path', 'Unknown')}
User Agent: {request_data.get('user_agent', 'Unknown')}
Headers: {json.dumps(request_data.get('headers', {}))}

Analyze this request for:
1. Potential web attacks (SQL injection, XSS, LFI, etc.)
2. Suspicious user agent or header values
3. Signs of scanning or reconnaissance
4. Indicators of automated attacks
5. Potential exploitation attempts

Provide your assessment with: type of potential attack (if any), confidence level (0-100), 
and recommended action (block, alert, or allow). Format as JSON."""
        
        return prompt
    
    def _call_gemini_api(self, prompt):
        """
        Call the Gemini API with the given prompt.
        
        Args:
            prompt (str): The prompt to send to Gemini
            
        Returns:
            dict: The JSON response from the Gemini API
        """
        try:
            # Construct the API request payload
            data = {
                "contents": [{
                    "parts": [{"text": prompt}]
                }]
            }
            
            # Add API key to URL
            url = f"{self.api_url}?key={self.api_key}"
            
            # Make the API call
            response = requests.post(
                url,
                json=data,
                headers={"Content-Type": "application/json"}
            )
            
            # Check if the request was successful
            response.raise_for_status()
            
            # Return the JSON response
            return response.json()
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Error calling Gemini API: {str(e)}")
            if hasattr(e, 'response') and e.response:
                logger.error(f"Response content: {e.response.text}")
            return {"error": str(e)}
    
    def _extract_text_from_response(self, response):
        """Extract text content from Gemini API response."""
        try:
            # Navigate the response structure to get the text
            if 'candidates' in response and response['candidates']:
                candidate = response['candidates'][0]
                if 'content' in candidate and 'parts' in candidate['content']:
                    parts = candidate['content']['parts']
                    for part in parts:
                        if 'text' in part:
                            return part['text']
            
            # If we couldn't find the text through the expected path
            logger.warning(f"Unexpected Gemini API response structure: {json.dumps(response)}")
            return ""
            
        except Exception as e:
            logger.error(f"Error extracting text from Gemini response: {str(e)}")
            return ""
    
    def _interpret_gemini_response(self, response, request_data):
        """
        Interpret the Gemini API response for a request analysis.
        
        Args:
            response (dict): The Gemini API response
            request_data (dict): The original request data that was analyzed
            
        Returns:
            dict: Structured analysis results
        """
        try:
            # Extract the text content from the response
            text_content = self._extract_text_from_response(response)
            
            # Try to parse JSON from the response
            json_start = text_content.find('{')
            json_end = text_content.rfind('}') + 1
            
            if json_start >= 0 and json_end > json_start:
                json_str = text_content[json_start:json_end]
                analysis = json.loads(json_str)
            else:
                # Fallback if JSON parsing fails
                analysis = {
                    "attack_type": "unknown",
                    "confidence": 50,
                    "recommended_action": "alert",
                    "explanation": "Could not determine threat level from analysis"
                }
            
            # Add the original request data for reference
            analysis["source_ip"] = request_data.get('source_ip', 'Unknown')
            analysis["request_path"] = request_data.get('path', 'Unknown')
            analysis["timestamp"] = timezone.now().isoformat()
            
            return analysis
            
        except Exception as e:
            logger.error(f"Error interpreting Gemini response: {str(e)}")
            return {
                "attack_type": "error",
                "confidence": 0,
                "recommended_action": "alert",
                "explanation": f"Error in analysis: {str(e)}",
                "source_ip": request_data.get('source_ip', 'Unknown'),
                "request_path": request_data.get('path', 'Unknown'),
                "timestamp": timezone.now().isoformat()
            }