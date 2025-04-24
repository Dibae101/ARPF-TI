from django.apps import AppConfig
import os
import logging
import threading

logger = logging.getLogger(__name__)

class ThreatIntelligenceConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'threat_intelligence'
    
    def ready(self):
        """
        Called when the application is ready. This is a good place to perform
        initialization tasks like creating the TinyLlama pickle file.
        """
        # Import here to avoid app registry not ready error
        from threat_intelligence.ai.llama_model import TINYLLAMA_PICKLE_PATH, LlamaModelManager
        
        # Check if the TinyLlama pickle file already exists
        if not os.path.exists(TINYLLAMA_PICKLE_PATH):
            logger.info("TinyLlama pickle file not found. Creating it in the background...")
            
            # Create the pickle file in a separate thread to avoid blocking app startup
            def create_pickle():
                try:
                    # Default parameters for TinyLlama
                    model_params = {
                        "load_in_4bit": True,
                        "use_cache": True
                    }
                    
                    # Create the pickle file
                    pickle_path = LlamaModelManager.save_model_to_pickle(
                        model_path="tinyllama-1.1b",
                        output_path=TINYLLAMA_PICKLE_PATH,
                        model_params=model_params
                    )
                    
                    logger.info(f"TinyLlama model successfully serialized to: {pickle_path}")
                except Exception as e:
                    logger.error(f"Failed to create TinyLlama pickle file: {str(e)}")
            
            # Start the background thread to create the pickle file
            pickle_thread = threading.Thread(target=create_pickle)
            pickle_thread.daemon = True
            pickle_thread.start()
        else:
            logger.info(f"TinyLlama pickle file already exists at {TINYLLAMA_PICKLE_PATH}")
