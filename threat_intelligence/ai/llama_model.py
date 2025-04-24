"""
Llama model integration for the ARPF-TI threat intelligence system.
This module provides functionality to load and use lightweight open-source Llama models
for various threat intelligence tasks.
"""

import os
import json
import logging
import pickle
from typing import Dict, List, Any, Optional, Union, Tuple
from pathlib import Path

import torch
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    BitsAndBytesConfig,
    pipeline
)

logger = logging.getLogger(__name__)

# Default models that users can select from HuggingFace hub
DEFAULT_MODELS = {
    "llama2-7b": "meta-llama/Llama-2-7b-hf",
    "llama2-7b-chat": "meta-llama/Llama-2-7b-chat-hf",
    "llama3-8b": "meta-llama/Meta-Llama-3-8B",
    "llama3-8b-instruct": "meta-llama/Meta-Llama-3-8B-Instruct",
    "tinyllama-1.1b": "TinyLlama/TinyLlama-1.1B-Chat-v1.0",
    "orca-mini-3b": "psmathur/orca_mini_3b",
}

# Path to the default serialized TinyLlama model
TINYLLAMA_PICKLE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "model_files", 
    "tinyllama",
    "tinyllama_model.pkl"
)

# Default prompt templates for threat intelligence tasks
DEFAULT_PROMPTS = {
    "threat_classification": (
        "System: You are a cybersecurity threat intelligence analyst. Analyze the following text and determine "
        "if it contains indications of a cyber threat. Your response should be exactly one of these categories: "
        "'BENIGN', 'SUSPICIOUS', or 'MALICIOUS'.\n\n"
        "User: {text}\n\n"
        "Assistant:"
    ),
    "threat_actor_identification": (
        "System: You are a cybersecurity threat intelligence analyst specializing in threat actor identification. "
        "Based on the techniques, tools, and patterns described in the following text, identify any known threat "
        "actors or APT groups that might be responsible. If uncertain, indicate that.\n\n"
        "User: {text}\n\n"
        "Assistant:"
    ),
    "ioc_extraction": (
        "System: You are a cybersecurity analyst. Extract all potential Indicators of Compromise (IOCs) from the "
        "following text. Format them as a JSON list with the following structure: "
        "[{\"type\": \"ip\"|\"domain\"|\"url\"|\"hash\"|\"email\", \"value\": \"actual_ioc\", \"context\": \"brief context\"}].\n\n"
        "User: {text}\n\n"
        "Assistant:"
    ),
    "vulnerability_assessment": (
        "System: You are a vulnerability analyst. Assess the following vulnerability description and provide: "
        "1. A severity rating (Critical, High, Medium, Low) "
        "2. Potential impact "
        "3. Recommended mitigation steps\n\n"
        "User: {text}\n\n"
        "Assistant:"
    ),
}

class LlamaModelManager:
    """
    Manager for Llama models in the threat intelligence system.
    Handles loading, caching, and inference with Llama models.
    """
    _loaded_models = {}  # Cache for loaded models
    
    @classmethod
    def save_model_to_pickle(cls, model_path: str, output_path: str = TINYLLAMA_PICKLE_PATH, model_params: Dict = None) -> str:
        """
        Create a serialized .pkl file from a model for faster loading.
        
        Args:
            model_path: Path to the model or HuggingFace model ID
            output_path: Path where to save the .pkl file
            model_params: Additional parameters for model loading
            
        Returns:
            str: Path to the saved .pkl file
        """
        try:
            # Load the model and tokenizer
            model, tokenizer = cls.load_model(model_path, model_params)
            
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            
            # Save the model and tokenizer to pickle file
            with open(output_path, 'wb') as f:
                pickle.dump((model, tokenizer), f)
                
            logger.info(f"Successfully saved model to {output_path}")
            return output_path
            
        except Exception as e:
            logger.error(f"Failed to save model to pickle file: {str(e)}")
            raise RuntimeError(f"Failed to save model: {str(e)}")
    
    @classmethod
    def load_model(cls, model_path: str, model_params: Dict = None) -> Tuple[Any, Any]:
        """
        Load a Llama model from the specified path or HuggingFace model ID.
        
        Args:
            model_path: Path to the model file or HuggingFace model ID
            model_params: Additional parameters for model loading
        
        Returns:
            tuple: (model, tokenizer)
        
        Raises:
            RuntimeError: If model loading fails
            ValueError: If invalid parameters are provided
        """
        if model_path in cls._loaded_models:
            logger.info(f"Using cached model: {model_path}")
            return cls._loaded_models[model_path]
        
        if model_params is None:
            model_params = {}
        
        # Check if it's a default model reference
        if model_path in DEFAULT_MODELS:
            # For TinyLlama, try to use the .pkl file first if it exists
            if model_path == "tinyllama-1.1b" and os.path.exists(TINYLLAMA_PICKLE_PATH):
                try:
                    logger.info(f"Loading TinyLlama from pickle file: {TINYLLAMA_PICKLE_PATH}")
                    with open(TINYLLAMA_PICKLE_PATH, 'rb') as f:
                        model, tokenizer = pickle.load(f)
                    cls._loaded_models[model_path] = (model, tokenizer)
                    return model, tokenizer
                except Exception as e:
                    logger.warning(f"Failed to load model from pickle file: {str(e)}. Falling back to HuggingFace.")
            
            model_path = DEFAULT_MODELS[model_path]
        
        # Check if it's a pickle file
        if model_path.endswith('.pkl'):
            try:
                logger.info(f"Loading model from pickle file: {model_path}")
                with open(model_path, 'rb') as f:
                    model, tokenizer = pickle.load(f)
                cls._loaded_models[model_path] = (model, tokenizer)
                return model, tokenizer
            except Exception as e:
                logger.error(f"Failed to load model from pickle file: {str(e)}")
                raise RuntimeError(f"Failed to load model from pickle: {str(e)}")
        
        logger.info(f"Loading Llama model from: {model_path}")
        
        try:
            # Check if quantization is requested
            quantization = model_params.get('quantization', None)
            if quantization:
                logger.info(f"Using {quantization}-bit quantization")
                
                if quantization == '4bit':
                    quantization_config = BitsAndBytesConfig(
                        load_in_4bit=True,
                        bnb_4bit_compute_dtype=torch.float16,
                        bnb_4bit_quant_type="nf4",
                    )
                elif quantization == '8bit':
                    quantization_config = BitsAndBytesConfig(
                        load_in_8bit=True
                    )
                else:
                    quantization_config = None
                    
                model = AutoModelForCausalLM.from_pretrained(
                    model_path,
                    device_map="auto",
                    quantization_config=quantization_config,
                    **model_params.get('model_args', {})
                )
            else:
                # Load in the highest precision the hardware supports
                if torch.cuda.is_available():
                    device = "cuda"
                elif hasattr(torch.backends, 'mps') and torch.backends.mps.is_available():
                    device = "mps"  # Apple Silicon support
                else:
                    device = "cpu"
                
                model = AutoModelForCausalLM.from_pretrained(
                    model_path,
                    device_map="auto" if device == "cuda" else None,
                    **model_params.get('model_args', {})
                )
                
                if device == "mps":
                    model = model.to("mps")
                elif device == "cpu":
                    logger.warning("Running Llama model on CPU - this will be slow!")
            
            # Load tokenizer
            tokenizer = AutoTokenizer.from_pretrained(
                model_path,
                **model_params.get('tokenizer_args', {})
            )
            
            # Cache the model
            cls._loaded_models[model_path] = (model, tokenizer)
            
            return model, tokenizer
            
        except Exception as e:
            logger.error(f"Failed to load model {model_path}: {str(e)}")
            raise RuntimeError(f"Failed to load model: {str(e)}")
    
    @classmethod
    def generate_text(cls, model_path: str, prompt: str, model_params: Dict = None) -> str:
        """
        Generate text from a prompt using the specified Llama model.
        
        Args:
            model_path: Path to the model or HuggingFace model ID
            prompt: Text prompt to generate from
            model_params: Additional parameters for generation
        
        Returns:
            str: Generated text
        """
        # Load or get cached model
        model, tokenizer = cls.load_model(model_path, model_params)
        
        # Set generation parameters
        generation_config = {
            'max_new_tokens': 256,
            'temperature': 0.7,
            'top_p': 0.9,
            'do_sample': True,
        }
        
        # Override with user params if provided
        if model_params and 'generation_config' in model_params:
            generation_config.update(model_params['generation_config'])
        
        # Create generator pipeline
        generator = pipeline(
            "text-generation",
            model=model,
            tokenizer=tokenizer,
        )
        
        # Generate text
        outputs = generator(
            prompt,
            **generation_config
        )
        
        # Extract and return generated text
        generated_text = outputs[0]['generated_text']
        
        # Remove the prompt from the generated text
        if generated_text.startswith(prompt):
            generated_text = generated_text[len(prompt):].strip()
            
        return generated_text
    
    @classmethod
    def classify_text(cls, model_path: str, text: str, 
                     classification_prompt: str = None,
                     model_params: Dict = None) -> Dict[str, float]:
        """
        Classify text using a Llama model with a classification prompt.
        
        Args:
            model_path: Path to the model or HuggingFace model ID
            text: Text to classify
            classification_prompt: Prompt template for classification
            model_params: Additional parameters for model and generation
            
        Returns:
            dict: Classification results with classes and scores
        """
        if classification_prompt is None:
            classification_prompt = DEFAULT_PROMPTS["threat_classification"]
        
        # Format the classification prompt
        full_prompt = classification_prompt.format(text=text)
        
        # Generate the classification response
        response = cls.generate_text(model_path, full_prompt, model_params)
        
        # Process the response based on expected format
        # This implementation assumes a simple classification output
        response = response.strip().upper()
        
        # Create a classification result dictionary
        result = {
            "BENIGN": 0.0,
            "SUSPICIOUS": 0.0,
            "MALICIOUS": 0.0
        }
        
        # Simple logic to set the score based on the response
        if "BENIGN" in response:
            result["BENIGN"] = 1.0
        elif "SUSPICIOUS" in response:
            result["SUSPICIOUS"] = 1.0
        elif "MALICIOUS" in response:
            result["MALICIOUS"] = 1.0
        else:
            # If we can't parse a clear result, set suspicious
            result["SUSPICIOUS"] = 0.5
            
        return result
    
    @classmethod
    def extract_iocs(cls, model_path: str, text: str, model_params: Dict = None) -> List[Dict[str, str]]:
        """
        Extract Indicators of Compromise (IOCs) from text using a Llama model.
        
        Args:
            model_path: Path to the model or HuggingFace model ID
            text: Text to extract IOCs from
            model_params: Additional parameters for model and generation
            
        Returns:
            list: Extracted IOCs as a list of dictionaries
        """
        # Use the IOC extraction prompt
        ioc_prompt = DEFAULT_PROMPTS["ioc_extraction"]
        
        # Format the prompt
        full_prompt = ioc_prompt.format(text=text)
        
        # Set specific generation parameters for structured output
        generation_params = {
            'generation_config': {
                'max_new_tokens': 1024,
                'temperature': 0.2,  # Lower temperature for more deterministic output
                'top_p': 0.9,
                'do_sample': True,
            }
        }
        
        # Merge with user-provided params if any
        if model_params:
            if 'generation_config' in model_params:
                generation_params['generation_config'].update(model_params['generation_config'])
            
            # Copy other parameters
            for k, v in model_params.items():
                if k != 'generation_config':
                    generation_params[k] = v
        
        # Generate the IOC extraction response
        response = cls.generate_text(model_path, full_prompt, generation_params)
        
        # Try to parse JSON from the response
        try:
            # Find JSON array in the response
            import re
            json_match = re.search(r'\[\s*{.*}\s*\]', response, re.DOTALL)
            
            if json_match:
                iocs = json.loads(json_match.group(0))
            else:
                # If no JSON array found, try to parse the whole response
                iocs = json.loads(response)
                
            # Validate the structure of each IOC
            validated_iocs = []
            for ioc in iocs:
                if isinstance(ioc, dict) and 'type' in ioc and 'value' in ioc:
                    validated_iocs.append(ioc)
            
            return validated_iocs
        except json.JSONDecodeError:
            logger.warning(f"Failed to parse IOCs as JSON from model response")
            return []
    
    @classmethod
    def identify_threat_actor(cls, model_path: str, text: str, model_params: Dict = None) -> Dict[str, Any]:
        """
        Identify potential threat actors from text using a Llama model.
        
        Args:
            model_path: Path to the model or HuggingFace model ID
            text: Text to analyze for threat actor identification
            model_params: Additional parameters for model and generation
            
        Returns:
            dict: Identified threat actors with confidence scores and details
        """
        # Use the threat actor identification prompt
        actor_prompt = DEFAULT_PROMPTS["threat_actor_identification"]
        
        # Format the prompt
        full_prompt = actor_prompt.format(text=text)
        
        # Set specific generation parameters
        generation_params = {
            'generation_config': {
                'max_new_tokens': 512,
                'temperature': 0.3,
                'top_p': 0.9,
                'do_sample': True,
            }
        }
        
        # Merge with user-provided params if any
        if model_params:
            if 'generation_config' in model_params:
                generation_params['generation_config'].update(model_params['generation_config'])
            
            # Copy other parameters
            for k, v in model_params.items():
                if k != 'generation_config':
                    generation_params[k] = v
        
        # Generate the threat actor identification response
        response = cls.generate_text(model_path, full_prompt, generation_params)
        
        # Parse the response for threat actor information
        # This is a simplified implementation
        result = {
            "identified_actors": [],
            "confidence": "low",
            "analysis": response.strip()
        }
        
        # Known APT groups and threat actors to look for
        known_actors = [
            "APT1", "APT10", "APT28", "APT29", "APT32", "APT33", "APT34", "APT38", 
            "APT40", "APT41", "Lazarus Group", "Cobalt Group", "FIN7", "FIN8",
            "Carbanak", "Turla", "Kimsuky", "DarkHydrus", "OceanLotus", "Winnti",
            "BlackTech", "Silence", "TA505", "Wizard Spider", "Evil Corp"
        ]
        
        # Check for mentions of known threat actors
        for actor in known_actors:
            if actor.lower() in response.lower():
                result["identified_actors"].append(actor)
        
        # Set confidence level based on clarity of identification
        if len(result["identified_actors"]) > 0:
            if "high confidence" in response.lower() or "strongly associated" in response.lower():
                result["confidence"] = "high"
            elif "medium confidence" in response.lower() or "possibly associated" in response.lower():
                result["confidence"] = "medium"
        
        return result
    
    @classmethod
    def assess_vulnerability(cls, model_path: str, text: str, model_params: Dict = None) -> Dict[str, Any]:
        """
        Assess a vulnerability description using a Llama model.
        
        Args:
            model_path: Path to the model or HuggingFace model ID
            text: Vulnerability description to assess
            model_params: Additional parameters for model and generation
            
        Returns:
            dict: Vulnerability assessment including severity, impact, and mitigation
        """
        # Use the vulnerability assessment prompt
        assessment_prompt = DEFAULT_PROMPTS["vulnerability_assessment"]
        
        # Format the prompt
        full_prompt = assessment_prompt.format(text=text)
        
        # Generate the vulnerability assessment
        response = cls.generate_text(model_path, full_prompt, model_params)
        
        # Parse the response to extract structured information
        # This is a simplified implementation
        result = {
            "severity": "Unknown",
            "impact": "",
            "mitigation": "",
            "full_assessment": response.strip()
        }
        
        # Try to extract severity rating
        severity_map = {
            "critical": "Critical",
            "high": "High",
            "medium": "Medium",
            "low": "Low"
        }
        
        for key, value in severity_map.items():
            if key in response.lower():
                result["severity"] = value
                break
        
        # Try to extract impact and mitigation sections
        lines = response.split('\n')
        current_section = None
        
        for line in lines:
            line = line.strip()
            
            if "impact" in line.lower() and ":" in line:
                current_section = "impact"
                result["impact"] = line.split(":", 1)[1].strip()
            elif "mitigation" in line.lower() and ":" in line:
                current_section = "mitigation"
                result["mitigation"] = line.split(":", 1)[1].strip()
            elif current_section == "impact" and line and not any(x in line.lower() for x in ["mitigation", "severity"]):
                result["impact"] += " " + line
            elif current_section == "mitigation" and line:
                result["mitigation"] += " " + line
        
        return result
    
    @classmethod
    def unload_model(cls, model_path: str) -> bool:
        """
        Unload a model from memory.
        
        Args:
            model_path: Path or identifier of the model to unload
            
        Returns:
            bool: True if model was unloaded, False if not found
        """
        if model_path in cls._loaded_models:
            del cls._loaded_models[model_path]
            # Force garbage collection to free up memory
            import gc
            gc.collect()
            if torch.cuda.is_available():
                torch.cuda.empty_cache()
            logger.info(f"Unloaded model: {model_path}")
            return True
        return False

    @classmethod
    def get_available_models(cls) -> Dict[str, str]:
        """
        Get a dictionary of available default Llama models.
        
        Returns:
            dict: Model name to HuggingFace path mapping
        """
        return DEFAULT_MODELS.copy()
    
    @classmethod
    def get_prompt_templates(cls) -> Dict[str, str]:
        """
        Get a dictionary of available prompt templates for threat intelligence tasks.
        
        Returns:
            dict: Template name to prompt template mapping
        """
        return DEFAULT_PROMPTS.copy()
    
    @classmethod
    def check_model_health(cls, model_path: str) -> Dict[str, Any]:
        """
        Check if a model can be loaded and is functioning properly.
        
        Args:
            model_path: Path to the model or HuggingFace model ID
            
        Returns:
            dict: Health check results
        """
        result = {
            "status": "unknown",
            "error": None,
            "memory_usage": None,
            "device": None
        }
        
        try:
            # Try to load the model
            model, tokenizer = cls.load_model(model_path)
            
            # Determine what device the model is on
            if hasattr(model, 'device'):
                result["device"] = str(model.device)
            elif next(model.parameters()).is_cuda:
                result["device"] = f"cuda:{next(model.parameters()).get_device()}"
            elif hasattr(torch, 'mps') and next(model.parameters()).is_mps:
                result["device"] = "mps"
            else:
                result["device"] = "cpu"
            
            # Run a simple inference test
            test_prompt = "Hello, world!"
            _ = cls.generate_text(model_path, test_prompt, {"generation_config": {"max_new_tokens": 5}})
            
            # Get memory usage stats if on CUDA
            if torch.cuda.is_available() and result["device"].startswith("cuda"):
                result["memory_usage"] = {
                    "allocated_gb": torch.cuda.memory_allocated() / (1024 ** 3),
                    "reserved_gb": torch.cuda.memory_reserved() / (1024 ** 3),
                    "max_memory_gb": torch.cuda.get_device_properties(0).total_memory / (1024 ** 3)
                }
            
            result["status"] = "healthy"
            
        except Exception as e:
            result["status"] = "error"
            result["error"] = str(e)
            logger.error(f"Model health check failed for {model_path}: {str(e)}")
        
        return result
    
    @classmethod
    def iterate_analysis(cls, model_path: str, texts: List[str], 
                        analysis_type: str = "classify", 
                        model_params: Dict = None,
                        batch_size: int = 10,
                        custom_prompt: str = None) -> List[Dict[str, Any]]:
        """
        Iterate through multiple texts and perform the specified analysis on each.
        
        Args:
            model_path: Path to the model or HuggingFace model ID
            texts: List of text samples to analyze
            analysis_type: Type of analysis to perform ('classify', 'extract_iocs', 
                          'identify_threat_actor', or 'assess_vulnerability')
            model_params: Additional parameters for model and generation
            batch_size: Number of items to process before yielding results
            custom_prompt: Optional custom prompt template to use
            
        Returns:
            list: Results of the analysis for each text
        """
        if not texts:
            return []
            
        logger.info(f"Starting batch analysis of {len(texts)} texts using {analysis_type}")
        
        results = []
        
        # Map analysis type to corresponding method
        analysis_methods = {
            "classify": cls.classify_text,
            "extract_iocs": cls.extract_iocs,
            "identify_threat_actor": cls.identify_threat_actor,
            "assess_vulnerability": cls.assess_vulnerability
        }
        
        if analysis_type not in analysis_methods:
            raise ValueError(f"Unsupported analysis type: {analysis_type}. "
                           f"Supported types: {', '.join(analysis_methods.keys())}")
        
        # Get the appropriate analysis method
        analysis_method = analysis_methods[analysis_type]
        
        # Process texts in batches
        for i in range(0, len(texts), batch_size):
            batch = texts[i:i+batch_size]
            batch_results = []
            
            for text in batch:
                try:
                    if custom_prompt:
                        # For classification, the custom prompt is passed as classification_prompt
                        if analysis_type == "classify":
                            result = analysis_method(model_path, text, custom_prompt, model_params)
                        else:
                            # For other methods, we need to update the prompt in model_params
                            if model_params is None:
                                model_params = {}
                            temp_params = model_params.copy()
                            temp_params['custom_prompt'] = custom_prompt
                            result = analysis_method(model_path, text, temp_params)
                    else:
                        result = analysis_method(model_path, text, model_params)
                    
                    batch_results.append({
                        "text": text[:100] + "..." if len(text) > 100 else text,  # Text preview
                        "result": result,
                        "success": True
                    })
                except Exception as e:
                    logger.error(f"Error analyzing text: {str(e)}")
                    batch_results.append({
                        "text": text[:100] + "..." if len(text) > 100 else text,
                        "result": None,
                        "success": False,
                        "error": str(e)
                    })
            
            # Add batch results to the overall results
            results.extend(batch_results)
            
            # Log progress
            logger.info(f"Processed {min(i+batch_size, len(texts))}/{len(texts)} texts")
        
        return results
    
    @classmethod
    def continue_iteration(cls, previous_results: List[Dict[str, Any]], 
                          next_analysis_type: str,
                          model_path: str = None,
                          model_params: Dict = None,
                          custom_prompt: str = None) -> List[Dict[str, Any]]:
        """
        Continue iteration with a different analysis type on previously processed texts.
        
        Args:
            previous_results: Results from a previous iterate_analysis call
            next_analysis_type: Next analysis type to perform
            model_path: Path to the model or HuggingFace model ID (can be different from previous)
            model_params: Additional parameters for model and generation
            custom_prompt: Optional custom prompt template to use
            
        Returns:
            list: Results of the new analysis for each text
        """
        # Extract texts from previous results
        texts = [item.get("text", "") for item in previous_results if item.get("success", False)]
        
        # If no model path is provided, try to use the one from previous results
        if model_path is None and previous_results and len(previous_results) > 0:
            # Assuming model_path might be stored in the first result
            model_path = previous_results[0].get("model_path", "tinyllama-1.1b")
        
        # Perform the next analysis
        return cls.iterate_analysis(
            model_path=model_path,
            texts=texts,
            analysis_type=next_analysis_type,
            model_params=model_params,
            custom_prompt=custom_prompt
        )