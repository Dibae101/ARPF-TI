#!/usr/bin/env python
"""
Download script for TinyLlama model files.
This script downloads the TinyLlama model from Hugging Face to the designated directory.
TinyLlama is a lightweight model that can run without GPU.
"""

import os
from transformers import AutoTokenizer, AutoModelForCausalLM

# Set the target directory for the model files
MODEL_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), 
    "threat_intelligence", 
    "model_files", 
    "tinyllama"
)

print(f"Will download TinyLlama model to: {MODEL_DIR}")
print("This may take a while depending on your internet connection...")

# Ensure the directory exists
os.makedirs(MODEL_DIR, exist_ok=True)

try:
    # Download the model and tokenizer
    print("Downloading tokenizer...")
    tokenizer = AutoTokenizer.from_pretrained(
        "TinyLlama/TinyLlama-1.1B-Chat-v1.0", 
        cache_dir=MODEL_DIR
    )
    
    print("Downloading model (this will take some time)...")
    model = AutoModelForCausalLM.from_pretrained(
        "TinyLlama/TinyLlama-1.1B-Chat-v1.0", 
        cache_dir=MODEL_DIR,
        # Removed GPU-specific parameters
        low_cpu_mem_usage=True,  # Helps with memory usage on CPU
    )
    
    print(f"Successfully downloaded TinyLlama model to {MODEL_DIR}")
    print("You can now add this model to your ARPF-TI system through the web interface.")
    
except Exception as e:
    print(f"Error downloading model: {str(e)}")
    print("\nPossible solutions:")
    print("1. Check your internet connection")
    print("2. Ensure you have enough disk space")
    print("3. Verify that all required dependencies are installed")