"""
ARPF AI Defense integration for the ARPF-TI threat intelligence system.
This module implements the ARPF Defense system for the application.

The ARPF Defense system provides advanced threat detection and analysis
capabilities for the application using pattern recognition, machine learning,
and behavioral analysis techniques.
"""

import logging
import random
import hashlib
from datetime import datetime, timedelta
from django.utils import timezone
from ..models import ThreatIntelEntry, SuggestedFirewallRule
from ..integrations.arpf_ai_connector import ARPFAIConnector

logger = logging.getLogger(__name__)

# Create a singleton instance for the application to use
arpf_defense = ARPFAIConnector(source="core_defense")

# Re-export the ARPFAIConnector for easier imports
__all__ = ['ARPFAIConnector', 'arpf_defense', 'analyze_request', 'generate_insights', 'get_model_info']

def analyze_request(request_data):
    """
    Analyze a request using the ARPF Defense system.
    
    Args:
        request_data: Dictionary with request information
        
    Returns:
        dict: Analysis results with threat assessment
    """
    return arpf_defense.analyze_request(request_data)

def generate_insights(days=7):
    """
    Generate security insights based on recent traffic patterns.
    
    Args:
        days: Number of days to analyze
        
    Returns:
        dict: Insights and recommendations
    """
    return arpf_defense.analyze_traffic_patterns(days=days)

def get_model_info():
    """
    Get information about the current ARPF Defense model.
    
    Returns:
        dict: Model information including version and capabilities
    """
    model_info = arpf_defense.get_model_details()
    
    # Add system stats
    try:
        model_info.update({
            "entries_analyzed": ThreatIntelEntry.objects.count(),
            "rules_suggested": SuggestedFirewallRule.objects.count(),
            "rules_implemented": SuggestedFirewallRule.objects.filter(
                status__in=['approved', 'auto_approved']
            ).count(),
        })
    except Exception as e:
        logger.error(f"Error getting model stats: {e}")
    
    return model_info

def update_model():
    """
    Update the ARPF Defense model with the latest threat intelligence.
    
    Returns:
        dict: Update status information
    """
    return arpf_defense.update_model()

class LegacyModelManager:
    """
    Placeholder class to provide clear error messages when legacy functionality is accessed.
    This project exclusively uses ARPF Defense for threat detection.
    """
    
    @classmethod
    def load_model(*args, **kwargs):
        raise NotImplementedError(
            "Legacy models are not supported in this project. "
            "This project exclusively uses ARPF Defense for threat detection."
        )
    
    @classmethod
    def generate_text(*args, **kwargs):
        raise NotImplementedError(
            "Legacy text generation is not supported. "
            "This project exclusively uses ARPF Defense for threat detection."
        )
    
    @classmethod
    def classify_text(*args, **kwargs):
        raise NotImplementedError(
            "Legacy text classification is not supported. "
            "This project exclusively uses ARPF Defense for threat detection."
        )