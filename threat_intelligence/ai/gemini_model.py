"""
Gemini AI integration for the ARPF-TI threat intelligence system.
This module serves as documentation that ONLY Google's Gemini is used for AI-based
threat detection in this project. All other AI models have been removed.

The actual Gemini implementation is in the threat_intelligence/integrations/gemini_connector.py file.
"""

import logging
from ..integrations.gemini_connector import GeminiConnector

logger = logging.getLogger(__name__)

# Re-export the GeminiConnector for easier imports
__all__ = ['GeminiConnector']

# Provide a clear message if someone tries to use Llama models
def llama_not_supported(*args, **kwargs):
    """Function that raises an error when Llama models are attempted to be used."""
    raise NotImplementedError(
        "Llama models are not supported in this project. "
        "This project exclusively uses Gemini for AI-based threat detection."
    )

# Create placeholder attributes to provide clear error messages
class LlamaModelManager:
    """
    Placeholder class to provide clear error messages when Llama functionality is accessed.
    This project exclusively uses Gemini for AI-based threat detection.
    """
    
    @classmethod
    def load_model(*args, **kwargs):
        return llama_not_supported(*args, **kwargs)
    
    @classmethod
    def generate_text(*args, **kwargs):
        return llama_not_supported(*args, **kwargs)
    
    @classmethod
    def classify_text(*args, **kwargs):
        return llama_not_supported(*args, **kwargs)
    
    @classmethod
    def extract_iocs(*args, **kwargs):
        return llama_not_supported(*args, **kwargs)
    
    @classmethod
    def identify_threat_actor(*args, **kwargs):
        return llama_not_supported(*args, **kwargs)
    
    @classmethod
    def assess_vulnerability(*args, **kwargs):
        return llama_not_supported(*args, **kwargs)

# Constants that might be imported by other parts of the codebase
TINYLLAMA_PICKLE_PATH = None
DEFAULT_MODELS = {}
DEFAULT_PROMPTS = {}