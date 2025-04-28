from django.apps import AppConfig
import os
import logging

logger = logging.getLogger(__name__)

class ThreatIntelligenceConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'threat_intelligence'
    
    def ready(self):
        """
        Called when the application is ready. This is a good place to perform
        initialization tasks.
        """
        logger.info("Initializing Threat Intelligence module with Gemini AI")
        # Use only Gemini for AI threat detection - no additional initialization needed
