#!/usr/bin/env python
"""
Script to create a serialized .pkl file for the TinyLlama model.
This makes model loading significantly faster for subsequent uses.
"""

import os
import sys
import logging
import pickle
from pathlib import Path

# Add the project root to the path so we can import our modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import our LlamaModelManager
from threat_intelligence.ai.llama_model import LlamaModelManager, TINYLLAMA_PICKLE_PATH

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def main():
    """
    Generate a pickle file for the TinyLlama model for faster loading.
    """
    logger.info("Creating pickle file for TinyLlama model...")
    
    # Default parameters for TinyLlama
    model_params = {
        "load_in_4bit": True,
        "use_cache": True
    }
    
    try:
        # Create the pickle file for TinyLlama
        pickle_path = LlamaModelManager.save_model_to_pickle(
            model_path="tinyllama-1.1b",
            output_path=TINYLLAMA_PICKLE_PATH,
            model_params=model_params
        )
        
        logger.info(f"TinyLlama model successfully serialized to: {pickle_path}")
        logger.info("The model will now be loaded by default when TinyLlama is selected.")
        
    except Exception as e:
        logger.error(f"Failed to create TinyLlama pickle file: {str(e)}")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())