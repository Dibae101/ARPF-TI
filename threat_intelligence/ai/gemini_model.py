"""
ARPF AI integration for the ARPF-TI threat intelligence system.
This module implements the ARPF AI Defense system for the application.

The ARPF AI Defense system provides advanced threat detection and analysis
capabilities for the application.
"""

import logging
from ..integrations.arpf_ai_connector import ARPFAIConnector

logger = logging.getLogger(__name__)

# Re-export the ARPFAIConnector for easier imports
__all__ = ['ARPFAIConnector']

# Provide a clear message if someone tries to use legacy models
def legacy_models_not_supported(*args, **kwargs):
    """Function that raises an error when legacy models are attempted to be used."""
    raise NotImplementedError(
        "Legacy models are not supported in this project. "
        "This project exclusively uses ARPF AI for threat detection."
    )

# Create placeholder attributes to provide clear error messages
class LegacyModelManager:
    """
    Placeholder class to provide clear error messages when legacy functionality is accessed.
    This project exclusively uses ARPF AI for threat detection.
    """
    
    @classmethod
    def load_model(*args, **kwargs):
        return legacy_models_not_supported(*args, **kwargs)
    
    @classmethod
    def generate_text(*args, **kwargs):
        return legacy_models_not_supported(*args, **kwargs)
    
    @classmethod
    def classify_text(*args, **kwargs):
        return legacy_models_not_supported(*args, **kwargs)
    
    @classmethod
    def extract_iocs(*args, **kwargs):
        return legacy_models_not_supported(*args, **kwargs)
    
    @classmethod
    def identify_threat_actor(*args, **kwargs):
        return legacy_models_not_supported(*args, **kwargs)
    
    @classmethod
    def assess_vulnerability(*args, **kwargs):
        return legacy_models_not_supported(*args, **kwargs)

# Constants that might be imported by other parts of the codebase
LEGACY_MODEL_PATH = None
DEFAULT_MODELS = {}
DEFAULT_PROMPTS = {}