import json
import logging
import random
import hashlib
import time
import asyncio
import concurrent.futures
import datetime
from django.conf import settings
from django.utils import timezone
from django.core.cache import cache

# Set up logging
logger = logging.getLogger('arpf_ti')

class CircuitBreaker:
    """
    Circuit Breaker pattern implementation for API reliability.
    Prevents repeated calls to failing services and allows for recovery.
    """
    def __init__(self, failure_threshold=5, recovery_timeout=300):
        self.failure_count = 0
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout  # seconds
        self.state = "CLOSED"  # CLOSED, OPEN, HALF_OPEN
        self.last_failure_time = None
        
    def record_success(self):
        """Record a successful API call"""
        if self.state == "HALF_OPEN":
            self.state = "CLOSED"
        self.failure_count = 0
        
    def record_failure(self):
        """Record a failed API call"""
        self.failure_count += 1
        self.last_failure_time = time.time()
        if self.failure_count >= self.failure_threshold:
            self.state = "OPEN"
            
    def is_open(self):
        """Check if the circuit breaker is open (preventing calls)"""
        if self.state == "OPEN":
            # Check if recovery timeout has elapsed
            if self.last_failure_time and (time.time() - self.last_failure_time) > self.recovery_timeout:
                self.state = "HALF_OPEN"
                
        return self.state == "OPEN"
        
    def allow_request(self):
        """Determine if the request should be allowed"""
        if self.state == "CLOSED":
            return True
        if self.state == "HALF_OPEN":
            return True
        return False

class GeminiIntegration:
    """
    Integration with Google's Gemini AI for analyzing security alerts
    and suggesting actions.
    """
    
    def __init__(self):
        """Initialize the Gemini integration."""
        from django.conf import settings
        
        # Initialize settings with defaults if not specified in Django settings
        self.api_key = getattr(settings, 'GEMINI_API_KEY', None)
        self.model_name = getattr(settings, 'GEMINI_MODEL_NAME', 'gemini-pro')
        self.temperature = getattr(settings, 'GEMINI_TEMPERATURE', 0.2)
        self.max_tokens = getattr(settings, 'GEMINI_MAX_OUTPUT_TOKENS', 1024)
        self.top_p = getattr(settings, 'GEMINI_TOP_P', 0.8)
        self.top_k = getattr(settings, 'GEMINI_TOP_K', 40)
        
        # Settings for caching
        self.use_cache = getattr(settings, 'GEMINI_USE_CACHE', True)
        self.cache_timeout = getattr(settings, 'GEMINI_CACHE_TIMEOUT', 3600)  # 1 hour default
        
        # Settings for rate limiting
        self.rate_limit_enabled = getattr(settings, 'GEMINI_RATE_LIMIT_ENABLED', True)
        self.rate_limit_calls = getattr(settings, 'GEMINI_RATE_LIMIT_CALLS', 60)  # calls
        self.rate_limit_period = getattr(settings, 'GEMINI_RATE_LIMIT_PERIOD', 60)  # seconds
        
        # Settings for feedback utilization
        self.feedback_utilization_enabled = getattr(settings, 'GEMINI_FEEDBACK_UTILIZATION_ENABLED', True)
        
        # Initialize the counter and timestamp for rate limiting
        self.api_calls_count = 0
        self.rate_limit_start_time = time.time()
        
        # Check if we can use the Google client library
        self.use_google_client = True
        try:
            import google.generativeai as genai
            self.genai = genai
        except ImportError:
            self.use_google_client = False
            logger.warning("Google Generative AI client library not found. Using direct REST API calls instead.")
            
        # Initialize Google client if API key is provided
        if self.api_key and self.use_google_client:
            try:
                self.genai.configure(api_key=self.api_key)
                logger.info(f"Initialized Gemini with model: {self.model_name}")
            except Exception as e:
                logger.error(f"Failed to initialize Gemini client: {str(e)}")
                self.api_key = None
        
        # Async processing configuration
        self.use_async = getattr(settings, 'GEMINI_USE_ASYNC', False)
        self.max_workers = getattr(settings, 'GEMINI_MAX_WORKERS', 5)
        self.thread_pool = concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers)
        
        # Circuit breaker for API reliability
        self.circuit_breaker = CircuitBreaker(
            failure_threshold=getattr(settings, 'GEMINI_CIRCUIT_BREAKER_THRESHOLD', 5),
            recovery_timeout=getattr(settings, 'GEMINI_CIRCUIT_BREAKER_TIMEOUT', 300)
        )
        
        # Initialize structured logging context
        self.request_id_counter = 0
    
    async def analyze_alert_async(self, alert):
        """
        Analyze an alert asynchronously.
        
        Args:
            alert: The Alert object to analyze
            
        Returns:
            GeminiSuggestion: The created or updated suggestion object
        """
        from alerts.models import GeminiSuggestion
        
        if not self.api_key:
            logger.warning("Gemini API key is not configured, returning mock analysis")
            return self._create_suggestion_from_response(alert, self._get_mock_analysis(alert))
        
        try:
            # Generate a unique request ID for tracking this request through logs
            request_id = f"gemini-{alert.id}-{self.request_id_counter}"
            self.request_id_counter += 1
            log_context = {"request_id": request_id, "alert_id": alert.id}
            
            # Check circuit breaker
            if not self.circuit_breaker.allow_request():
                logger.warning(f"Circuit breaker open, skipping Gemini API call", extra=log_context)
                error_response = {
                    "suggestion": "No (Service unavailable)",
                    "reasoning": "The Gemini API service is temporarily unavailable. Circuit breaker is open.",
                    "suggested_actions": "Please try again later or check the service status.",
                    "confidence_score": 0.0,
                    "error": "circuit_breaker_open"
                }
                return self._create_suggestion_from_response(alert, error_response)
            
            # Check cache first if enabled
            if self.use_cache:
                cache_key = self._get_cache_key(alert)
                cached_response = cache.get(cache_key)
                if cached_response:
                    logger.info(f"Using cached Gemini analysis", extra=log_context)
                    return self._create_suggestion_from_response(alert, cached_response)
            
            # Use the real Gemini API integration
            logger.info(f"Analyzing alert with Gemini AI", extra=log_context)
            prompt = self._build_analysis_prompt(alert)
            
            # Call API asynchronously
            loop = asyncio.get_event_loop() if asyncio.get_event_loop_policy().get_event_loop().is_running() else asyncio.new_event_loop()
            future = loop.run_in_executor(self.thread_pool, self._call_gemini_api, prompt, log_context)
            
            # Use asyncio.wait_for to implement a timeout
            try:
                response = await asyncio.wait_for(future, timeout=30.0)  # 30-second timeout
                
                # Log the raw response for debugging purposes
                logger.debug(f"Gemini raw response: {response[:500]}...", extra=log_context)
                
                parsed_response = self._parse_gemini_response(response)
                
                # Record successful API call for circuit breaker
                self.circuit_breaker.record_success()
                
                # Cache the response if caching is enabled
                if self.use_cache:
                    cache_key = self._get_cache_key(alert)
                    cache.set(cache_key, parsed_response, self.cache_timeout)
                
                # Log successful analysis with suggestion details
                logger.info(f"Successfully analyzed alert with Gemini AI. " 
                           f"Suggestion: {parsed_response.get('suggestion')}, "
                           f"Confidence: {parsed_response.get('confidence_score', 0.0):.2f}", 
                           extra=log_context)
                
                return self._create_suggestion_from_response(alert, parsed_response)
                
            except asyncio.TimeoutError:
                error_msg = "Gemini API call timed out after 30 seconds"
                logger.error(error_msg, extra=log_context)
                self.circuit_breaker.record_failure()
                error_response = {
                    "suggestion": "No (Timeout)",
                    "reasoning": error_msg,
                    "suggested_actions": "Check API service status and try again later.",
                    "confidence_score": 0.0,
                    "error": "timeout"
                }
                return self._create_suggestion_from_response(alert, error_response)
                
        except Exception as e:
            logger.error(f"Error analyzing alert with Gemini: {str(e)}", exc_info=True)
            self.circuit_breaker.record_failure()
            # Update the timestamp to show when the error occurred
            error_response = {
                "suggestion": "No (Error)",
                "reasoning": f"Failed to analyze alert: {str(e)}",
                "suggested_actions": "Please check the system logs for more details.",
                "confidence_score": 0.0,
                "error_timestamp": timezone.now().isoformat(),
                "error": "exception"
            }
            return self._create_suggestion_from_response(alert, error_response)
    
    def analyze_alert(self, alert):
        """
        Analyze an alert and suggest whether it should be sent as a notification.
        
        Args:
            alert: The Alert object to analyze
            
        Returns:
            GeminiSuggestion: The created or updated suggestion object
        """
        # If async mode is enabled, run asynchronously
        if self.use_async:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                return loop.run_until_complete(self.analyze_alert_async(alert))
            finally:
                loop.close()
        
        # Otherwise, run synchronously (original implementation)
        from alerts.models import GeminiSuggestion
        
        if not self.api_key:
            logger.warning("Gemini API key is not configured, returning mock analysis")
            return self._create_suggestion_from_response(alert, self._get_mock_analysis(alert))
        
        try:
            # Generate a unique request ID for tracking this request through logs
            request_id = f"gemini-{alert.id}-{self.request_id_counter}"
            self.request_id_counter += 1
            log_context = {"request_id": request_id, "alert_id": alert.id}
            
            # Check circuit breaker
            if not self.circuit_breaker.allow_request():
                logger.warning(f"Circuit breaker open, skipping Gemini API call", extra=log_context)
                error_response = {
                    "suggestion": "No (Service unavailable)",
                    "reasoning": "The Gemini API service is temporarily unavailable. Circuit breaker is open.",
                    "suggested_actions": "Please try again later or check the service status.",
                    "confidence_score": 0.0,
                    "error": "circuit_breaker_open"
                }
                return self._create_suggestion_from_response(alert, error_response)
                
            # Check cache first if enabled
            if self.use_cache:
                cache_key = self._get_cache_key(alert)
                cached_response = cache.get(cache_key)
                if cached_response:
                    logger.info(f"Using cached Gemini analysis for alert {alert.id}", extra=log_context)
                    return self._create_suggestion_from_response(alert, cached_response)
            
            # Use the real Gemini API integration
            logger.info(f"Analyzing alert {alert.id} with Gemini AI", extra=log_context)
            prompt = self._build_analysis_prompt(alert)
            response = self._call_gemini_api(prompt, log_context)
            
            # Log the raw response for debugging purposes
            logger.debug(f"Gemini raw response for alert {alert.id}: {response[:500]}...", extra=log_context)
            
            parsed_response = self._parse_gemini_response(response)
            
            # Record successful API call for circuit breaker
            self.circuit_breaker.record_success()
            
            # Cache the response if caching is enabled
            if self.use_cache:
                cache_key = self._get_cache_key(alert)
                cache.set(cache_key, parsed_response, self.cache_timeout)
            
            # Log successful analysis with suggestion details
            logger.info(f"Successfully analyzed alert {alert.id} with Gemini AI. " 
                       f"Suggestion: {parsed_response.get('suggestion')}, "
                       f"Confidence: {parsed_response.get('confidence_score', 0.0):.2f}",
                       extra=log_context)
            
            return self._create_suggestion_from_response(alert, parsed_response)
            
        except Exception as e:
            logger.error(f"Error analyzing alert {alert.id} with Gemini: {str(e)}", exc_info=True)
            # Record failure for circuit breaker
            self.circuit_breaker.record_failure()
            # Update the timestamp to show when the error occurred
            error_response = {
                "suggestion": "No (Error)",
                "reasoning": f"Failed to analyze alert: {str(e)}",
                "suggested_actions": "Please check the system logs for more details.",
                "confidence_score": 0.0,
                "error_timestamp": timezone.now().isoformat(),
                "error": "exception"
            }
            return self._create_suggestion_from_response(alert, error_response)
    
    def _get_cache_key(self, alert):
        """
        Generate a unique cache key for an alert.
        The key is based on the alert's essential properties.
        """
        # Create a unique string representation of the alert's key properties
        key_parts = [
            f"id:{alert.id}",
            f"title:{alert.title}",
            f"description:{alert.description}",
            f"severity:{alert.severity}",
            f"type:{alert.alert_type}",
            f"source_ip:{alert.source_ip or 'None'}"
        ]
        key_string = "|".join(key_parts)
        
        # Create a hash to use as the cache key
        return f"gemini_alert_analysis:{hashlib.md5(key_string.encode()).hexdigest()}"
    
    def _create_suggestion_from_response(self, alert, response_data):
        """
        Create or update a GeminiSuggestion object for an alert based on the API response.
        
        Args:
            alert: The Alert object
            response_data: Dictionary with the parsed Gemini response
            
        Returns:
            GeminiSuggestion: The created or updated suggestion object
        """
        from alerts.models import GeminiSuggestion
        
        # Get confidence score if present, default to a random value for mock data
        confidence_score = response_data.get('confidence_score')
        if confidence_score is None and 'suggestion' in response_data:
            # For mock data, generate a random confidence that aligns with the suggestion
            confidence_base = 0.7 if response_data['suggestion'].lower() == 'yes' else 0.3
            confidence_score = confidence_base + (random.random() * 0.3)
        
        # Check if a suggestion already exists
        suggestion, created = GeminiSuggestion.objects.update_or_create(
            alert=alert,
            defaults={
                'should_notify': response_data.get('suggestion', '').lower() == 'yes',
                'assessment': response_data.get('suggestion', 'No assessment available'),
                'reasoning': response_data.get('reasoning', 'No reasoning provided'),
                'suggested_actions': response_data.get('suggested_actions', 'No actions suggested'),
                'confidence_score': confidence_score,
                'raw_response': response_data
            }
        )
        
        # Update the alert's status based on Gemini's suggestion
        if created or alert.alert_status == 'standard':
            alert.alert_status = 'suggested' if suggestion.should_notify else 'standard'
            alert.save(update_fields=['alert_status'])
        
        return suggestion
    
    def _get_mock_reasoning_actions(self, alert, should_send):
        """
        Get mock reasoning and actions based on alert type and decision.
        
        Args:
            alert: The Alert object
            should_send: Boolean indicating whether the notification should be sent
            
        Returns:
            dict: Dictionary with reasoning and suggested_actions keys
        """
        # Base reasoning and actions by alert type
        alert_type_responses = {
            'unauthorized_access': {
                'yes': {
                    'reasoning': 'Unauthorized access attempts can indicate an active breach attempt.',
                    'suggested_actions': 'Investigate the source IP, block it temporarily, and review access logs for similar patterns.'
                },
                'no': {
                    'reasoning': 'This appears to be a low-risk unauthorized access attempt, possibly a misconfiguration.',
                    'suggested_actions': 'Add to watchlist but no immediate action needed. Review during regular security audits.'
                }
            },
            'malware': {
                'yes': {
                    'reasoning': 'Malware detection indicates a potential active infection or compromise.',
                    'suggested_actions': 'Isolate affected systems, run full antivirus scan, and investigate the infection vector.'
                },
                'no': {
                    'reasoning': 'This appears to be a low-risk malware alert, possibly a false positive.',
                    'suggested_actions': 'Verify with secondary scan and add to watchlist for future monitoring.'
                }
            },
            'data_breach': {
                'yes': {
                    'reasoning': 'Potential data breach detected, which requires immediate attention.',
                    'suggested_actions': 'Lock affected accounts, initiate incident response plan, and prepare for possible disclosure requirements.'
                },
                'no': {
                    'reasoning': 'This data access pattern is unusual but within acceptable parameters.',
                    'suggested_actions': 'Flag for review during next security meeting and add to monitoring watchlist.'
                }
            },
            'suspicious_activity': {
                'yes': {
                    'reasoning': 'Suspicious activity pattern matches known attack signatures.',
                    'suggested_actions': 'Increase monitoring of affected systems, review related logs, and consider temporary access restrictions.'
                },
                'no': {
                    'reasoning': 'Activity is unusual but doesn\'t match known attack patterns.',
                    'suggested_actions': 'Add source to monitoring list but no immediate action required.'
                }
            },
            'network_anomaly': {
                'yes': {
                    'reasoning': 'Network traffic patterns indicate potential data exfiltration or command and control activity.',
                    'suggested_actions': 'Temporarily block suspicious connections, analyze traffic patterns, and scan affected systems.'
                },
                'no': {
                    'reasoning': 'Network anomaly is likely due to system maintenance or legitimate but unusual activity.',
                    'suggested_actions': 'Monitor for continued anomalies but no immediate action needed.'
                }
            },
            'policy_violation': {
                'yes': {
                    'reasoning': 'Serious policy violation detected that could compromise security.',
                    'suggested_actions': 'Document violation, review with employee/team, and implement additional controls if needed.'
                },
                'no': {
                    'reasoning': 'Minor policy violation detected, likely accidental or low-impact.',
                    'suggested_actions': 'Add to compliance review list for follow-up during regular security audits.'
                }
            },
            'system_failure': {
                'yes': {
                    'reasoning': 'Critical system failure that may impact availability or security.',
                    'suggested_actions': 'Initiate recovery procedures, check redundant systems, and investigate root cause.'
                },
                'no': {
                    'reasoning': 'Non-critical system issue with minimal impact on operations.',
                    'suggested_actions': 'Schedule maintenance during next window and monitor for worsening conditions.'
                }
            }
        }
        
        # Default responses if alert type isn't specifically handled
        default_responses = {
            'yes': {
                'reasoning': 'This alert has characteristics that warrant immediate attention based on severity and type.',
                'suggested_actions': 'Investigate the alert details, check for related system activity, and follow standard response procedures.'
            },
            'no': {
                'reasoning': 'This alert appears to be low priority and doesn\'t require immediate notification.',
                'suggested_actions': 'Add to regular review queue and monitor for escalation or pattern development.'
            }
        }
        
        # Get the appropriate response based on alert type and decision
        decision_key = 'yes' if should_send else 'no'
        type_responses = alert_type_responses.get(alert.alert_type, default_responses)
        response = type_responses.get(decision_key, default_responses[decision_key])
        
        return response
    
    def utilize_feedback_for_prompt_improvement(self, alert):
        """
        Utilizes historical feedback to improve the prompt for similar alerts.
        
        Args:
            alert: The Alert object for which we're building a prompt
            
        Returns:
            str: Additional prompt context based on feedback
        """
        if not self.feedback_utilization_enabled:
            return ""
            
        from alerts.models import GeminiSuggestion
        
        try:
            # Get similar alerts based on type and severity
            similar_suggestions = GeminiSuggestion.objects.filter(
                alert__alert_type=alert.alert_type,
                alert__severity=alert.severity,
                feedback_rating__isnull=False  # Only include suggestions with feedback
            ).order_by('-feedback_timestamp')[:10]  # Get the 10 most recent with feedback
            
            if not similar_suggestions:
                return ""
                
            # Analyze feedback to extract patterns
            positive_feedback = []
            negative_feedback = []
            
            for suggestion in similar_suggestions:
                if suggestion.feedback_rating >= 4:  # Positive feedback (4 or 5 stars)
                    feedback_data = {
                        "suggestion": suggestion.assessment,
                        "reasoning": suggestion.reasoning,
                        "feedback_notes": suggestion.feedback_notes
                    }
                    positive_feedback.append(feedback_data)
                    
                elif suggestion.feedback_rating <= 2:  # Negative feedback (1 or 2 stars)
                    feedback_data = {
                        "suggestion": suggestion.assessment,
                        "reasoning": suggestion.reasoning,
                        "feedback_notes": suggestion.feedback_notes
                    }
                    negative_feedback.append(feedback_data)
            
            # Generate additional context based on feedback patterns
            additional_context = ""
            
            if positive_feedback:
                additional_context += "\nPREVIOUS SUCCESSFUL ASSESSMENTS:\n"
                for i, feedback in enumerate(positive_feedback[:3], 1):  # Include top 3 positive examples
                    additional_context += f"{i}. Assessment: {feedback['suggestion']}\n"
                    additional_context += f"   Reasoning: {feedback['reasoning']}\n"
                    if feedback['feedback_notes']:
                        additional_context += f"   Admin notes: {feedback['feedback_notes']}\n"
            
            if negative_feedback:
                additional_context += "\nPREVIOUS UNSUCCESSFUL ASSESSMENTS TO AVOID:\n"
                for i, feedback in enumerate(negative_feedback[:2], 1):  # Include top 2 negative examples
                    additional_context += f"{i}. Assessment: {feedback['suggestion']}\n"
                    additional_context += f"   Reasoning: {feedback['reasoning']}\n"
                    if feedback['feedback_notes']:
                        additional_context += f"   Admin notes: {feedback['feedback_notes']}\n"
            
            return additional_context
        
        except Exception as e:
            logger.error(f"Error utilizing feedback for prompt improvement: {str(e)}")
            return ""  # Return empty string on error
    
    def _build_analysis_prompt(self, alert):
        """
        Build a prompt for Gemini to analyze the alert.
        """
        # Format the alert details for the prompt
        alert_details = {
            "id": alert.id,
            "title": alert.title,
            "description": alert.description,
            "severity": alert.get_severity_display(),
            "type": alert.get_alert_type_display(),
            "source_ip": alert.source_ip or "Unknown",
            "timestamp": alert.timestamp.isoformat(),
            "is_acknowledged": alert.is_acknowledged
        }
        
        # Get additional context from feedback history
        feedback_context = self.utilize_feedback_for_prompt_improvement(alert)
        
        # This is the actual prompt we'd send to Gemini
        prompt = f"""
        You are a cybersecurity AI assistant. Analyze the following security alert and determine if it should be sent as an emergency notification to administrators.
        
        ALERT DETAILS:
        {json.dumps(alert_details, indent=2)}
        
        Your task:
        1. Determine if this alert is important enough to send as a notification (Yes/No)
        2. Provide a brief reasoning for your decision
        3. Suggest specific actions based on the alert type and severity
        4. Provide a confidence score for your assessment (0.0 to 1.0)
        
        Format your response as a JSON object with the following keys:
        - suggestion: "Yes" or "No"
        - reasoning: A brief explanation of your decision
        - suggested_actions: Specific actions to take
        - confidence_score: A number between 0.0 and 1.0
        {feedback_context}
        """
        
        return prompt
    
    def _call_gemini_api(self, prompt, log_context=None):
        """
        Call the Gemini API with the given prompt.
        """
        if log_context is None:
            log_context = {}
            
        start_time = time.time()
        
        try:
            # Apply rate limiting if enabled
            if self.rate_limit_enabled:
                current_time = time.time()
                # Reset counter if rate limit period has passed
                if current_time - self.rate_limit_start_time > self.rate_limit_period:
                    self.api_calls_count = 0
                    self.rate_limit_start_time = current_time
                
                # Check if we've exceeded the rate limit
                if self.api_calls_count >= self.rate_limit_calls:
                    time_to_wait = self.rate_limit_period - (current_time - self.rate_limit_start_time)
                    if time_to_wait > 0:
                        logger.warning(f"Rate limit reached. Waiting {time_to_wait:.2f} seconds before making API call", 
                                      extra=log_context)
                        time.sleep(time_to_wait)
                        # Reset the counter and timestamp after waiting
                        self.api_calls_count = 0
                        self.rate_limit_start_time = time.time()
            
            # Increment API call counter
            self.api_calls_count += 1
            
            # Implementing actual API calls to Gemini
            response_text = None
            
            # First try using the Google Generative AI client library
            if self.use_google_client:
                try:
                    model = self.genai.GenerativeModel(
                        self.model_name,
                        generation_config={
                            "temperature": self.temperature,
                            "top_p": self.top_p,
                            "top_k": self.top_k,
                            "max_output_tokens": self.max_tokens,
                        },
                        safety_settings=[
                            {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
                            {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
                            {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
                            {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
                        ]
                    )
                    
                    logger.debug(f"Sending prompt to Gemini API", extra={**log_context, "prompt_length": len(prompt)})
                    
                    start_time = time.time()
                    response = model.generate_content(prompt)
                    elapsed_time = time.time() - start_time
                    
                    logger.info(f"Gemini API call successful. Time taken: {elapsed_time:.2f}s", 
                               extra={**log_context, "api_latency": elapsed_time})
                    
                    response_text = response.text
                    
                except Exception as e:
                    logger.error(f"Google client API call failed: {str(e)}", extra=log_context, exc_info=True)
                    # Fall back to direct API call
                    self.use_google_client = False
            
            # Fallback to direct API call if the client library failed or is not available
            if not self.use_google_client or response_text is None:
                import requests
                
                api_url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent"
                
                headers = {
                    "Content-Type": "application/json",
                    "x-goog-api-key": self.api_key
                }
                
                data = {
                    "contents": [{
                        "parts": [{
                            "text": prompt
                        }]
                    }],
                    "generationConfig": {
                        "temperature": self.temperature,
                        "topP": self.top_p,
                        "topK": self.top_k,
                        "maxOutputTokens": self.max_tokens
                    },
                    "safetySettings": [
                        {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
                        {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
                        {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
                        {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_MEDIUM_AND_ABOVE"}
                    ]
                }
                
                logger.debug(f"Sending prompt to Gemini REST API", extra={**log_context, "prompt_length": len(prompt)})
                
                start_time = time.time()
                response = requests.post(api_url, headers=headers, json=data, timeout=25)
                elapsed_time = time.time() - start_time
                
                logger.info(f"Gemini REST API call completed with status {response.status_code}. Time taken: {elapsed_time:.2f}s", 
                           extra={**log_context, "api_latency": elapsed_time, "status_code": response.status_code})
                
                if response.status_code == 200:
                    result = response.json()
                    # Extract the text from the response
                    if 'candidates' in result and len(result['candidates']) > 0:
                        if 'content' in result['candidates'][0]:
                            content = result['candidates'][0]['content']
                            if 'parts' in content and len(content['parts']) > 0:
                                response_text = content['parts'][0]['text']
                                
                        # Check if there's a 'continue' field indicating more content is available
                        if response_text and 'finishReason' in result['candidates'][0] and result['candidates'][0]['finishReason'] == 'RECITATION':
                            logger.warning(f"Response was truncated (finishReason: RECITATION). Consider increasing max tokens.", extra=log_context)
                        
                        # Handle specific continuation flags in the response
                        if 'continue' in result:
                            logger.warning(f"Response contains continuation flag. Content may be incomplete.", extra=log_context)
                
                if response_text is None:
                    # If we couldn't extract text properly, raise an exception
                    raise Exception(f"Failed to parse Gemini API response. Status code: {response.status_code}")
            
            return response_text
                
        except Exception as e:
            elapsed_time = time.time() - start_time
            logger.error(f"Gemini API call failed after {elapsed_time:.2f}s: {str(e)}", 
                        extra={**log_context, "api_latency": elapsed_time}, exc_info=True)
            raise
    
    def _parse_gemini_response(self, response_text):
        """
        Parse the response from the Gemini API into a structured format.
        Expected format:
        ```json
        {
            "suggestion": "Yes/No",
            "reasoning": "Explanation of reasoning",
            "suggested_actions": "Suggested actions to take",
            "confidence_score": 0.95
        }
        ```
        """
        try:
            # Look for a JSON blob in the response
            import re
            json_match = re.search(r'```json\s*(.*?)\s*```', response_text, re.DOTALL)
            
            if json_match:
                json_str = json_match.group(1)
                parsed = json.loads(json_str)
            else:
                # Try to parse the entire response as JSON
                parsed = json.loads(response_text)
            
            # Validate that we have all required fields
            required_fields = ["suggestion", "reasoning", "suggested_actions", "confidence_score"]
            for field in required_fields:
                if field not in parsed:
                    logger.warning(f"Missing required field '{field}' in Gemini response")
                    # Add default values for missing fields
                    if field == "suggestion":
                        parsed[field] = "No"
                    elif field == "reasoning":
                        parsed[field] = "Incomplete API response"
                    elif field == "suggested_actions":
                        parsed[field] = "Review alert manually"
                    elif field == "confidence_score":
                        parsed[field] = 0.5
            
            # Ensure suggestion is in correct format
            if "suggestion" in parsed:
                # Normalize to "Yes" or "No"
                suggestion = parsed["suggestion"].strip().lower()
                if "yes" in suggestion or "true" in suggestion or "send" in suggestion:
                    parsed["suggestion"] = "Yes"
                else:
                    parsed["suggestion"] = "No"
            
            # Ensure confidence score is a float between 0 and 1
            if "confidence_score" in parsed:
                try:
                    score = float(parsed["confidence_score"])
                    parsed["confidence_score"] = max(0.0, min(1.0, score))  # Clamp between 0 and 1
                except (ValueError, TypeError):
                    logger.warning(f"Invalid confidence score format: {parsed['confidence_score']}")
                    parsed["confidence_score"] = 0.5
            
            return parsed
            
        except Exception as e:
            logger.error(f"Failed to parse Gemini response: {str(e)}", exc_info=True)
            # Return a default response
            return {
                "suggestion": "No",
                "reasoning": f"Failed to parse Gemini response: {str(e)}",
                "suggested_actions": "Please review the alert manually",
                "confidence_score": 0.0
            }
    
    def _get_mock_analysis(self, alert):
        """
        Generate a mock analysis for demo purposes.
        """
        # Determine if the alert should be sent based on severity
        severity_weights = {
            'info': 0.2,
            'low': 0.4,
            'medium': 0.7,
            'high': 0.9,
            'critical': 1.0
        }
        
        # Get the probability based on severity
        probability = severity_weights.get(alert.severity, 0.5)
        
        # Generate a random decision based on probability
        should_send = random.random() < probability
        
        # Get specific mock reasoning and actions based on alert type
        reasoning_actions = self._get_mock_reasoning_actions(alert, should_send)
        
        # Generate a confidence score that aligns with the decision
        confidence_base = 0.7 if should_send else 0.3
        confidence = confidence_base + (random.random() * 0.3)
        
        return {
            "suggestion": "Yes" if should_send else "No",
            "reasoning": reasoning_actions["reasoning"],
            "suggested_actions": reasoning_actions["actions"],
            "confidence_score": round(confidence, 2)
        }
    
    def _get_mock_reasoning_actions(self, alert, should_send):
        """
        Get mock reasoning and actions based on alert type and decision.
        
        Args:
            alert: The Alert object
            should_send: Boolean indicating whether the notification should be sent
            
        Returns:
            dict: Dictionary with reasoning and suggested_actions keys
        """
        # Base reasoning and actions by alert type
        alert_type_responses = {
            'unauthorized_access': {
                'yes': {
                    'reasoning': 'Unauthorized access attempts can indicate an active breach attempt.',
                    'suggested_actions': 'Investigate the source IP, block it temporarily, and review access logs for similar patterns.'
                },
                'no': {
                    'reasoning': 'This appears to be a low-risk unauthorized access attempt, possibly a misconfiguration.',
                    'suggested_actions': 'Add to watchlist but no immediate action needed. Review during regular security audits.'
                }
            },
            'malware': {
                'yes': {
                    'reasoning': 'Malware detection indicates a potential active infection or compromise.',
                    'suggested_actions': 'Isolate affected systems, run full antivirus scan, and investigate the infection vector.'
                },
                'no': {
                    'reasoning': 'This appears to be a low-risk malware alert, possibly a false positive.',
                    'suggested_actions': 'Verify with secondary scan and add to watchlist for future monitoring.'
                }
            },
            'data_breach': {
                'yes': {
                    'reasoning': 'Potential data breach detected, which requires immediate attention.',
                    'suggested_actions': 'Lock affected accounts, initiate incident response plan, and prepare for possible disclosure requirements.'
                },
                'no': {
                    'reasoning': 'This data access pattern is unusual but within acceptable parameters.',
                    'suggested_actions': 'Flag for review during next security meeting and add to monitoring watchlist.'
                }
            },
            'suspicious_activity': {
                'yes': {
                    'reasoning': 'Suspicious activity pattern matches known attack signatures.',
                    'suggested_actions': 'Increase monitoring of affected systems, review related logs, and consider temporary access restrictions.'
                },
                'no': {
                    'reasoning': 'Activity is unusual but doesn\'t match known attack patterns.',
                    'suggested_actions': 'Add source to monitoring list but no immediate action required.'
                }
            },
            'network_anomaly': {
                'yes': {
                    'reasoning': 'Network traffic patterns indicate potential data exfiltration or command and control activity.',
                    'suggested_actions': 'Temporarily block suspicious connections, analyze traffic patterns, and scan affected systems.'
                },
                'no': {
                    'reasoning': 'Network anomaly is likely due to system maintenance or legitimate but unusual activity.',
                    'suggested_actions': 'Monitor for continued anomalies but no immediate action needed.'
                }
            },
            'policy_violation': {
                'yes': {
                    'reasoning': 'Serious policy violation detected that could compromise security.',
                    'suggested_actions': 'Document violation, review with employee/team, and implement additional controls if needed.'
                },
                'no': {
                    'reasoning': 'Minor policy violation detected, likely accidental or low-impact.',
                    'suggested_actions': 'Add to compliance review list for follow-up during regular security audits.'
                }
            },
            'system_failure': {
                'yes': {
                    'reasoning': 'Critical system failure that may impact availability or security.',
                    'suggested_actions': 'Initiate recovery procedures, check redundant systems, and investigate root cause.'
                },
                'no': {
                    'reasoning': 'Non-critical system issue with minimal impact on operations.',
                    'suggested_actions': 'Schedule maintenance during next window and monitor for worsening conditions.'
                }
            }
        }
        
        # Default responses if alert type isn't specifically handled
        default_responses = {
            'yes': {
                'reasoning': 'This alert has characteristics that warrant immediate attention based on severity and type.',
                'suggested_actions': 'Investigate the alert details, check for related system activity, and follow standard response procedures.'
            },
            'no': {
                'reasoning': 'This alert appears to be low priority and doesn\'t require immediate notification.',
                'suggested_actions': 'Add to regular review queue and monitor for escalation or pattern development.'
            }
        }
        
        # Get the appropriate response based on alert type and decision
        decision_key = 'yes' if should_send else 'no'
        type_responses = alert_type_responses.get(alert.alert_type, default_responses)
        response = type_responses.get(decision_key, default_responses[decision_key])
        
        return response
    
    def analyze_alert_async(self, alert):
        """
        Analyze a security alert asynchronously using Gemini API.
        Returns a future object that can be awaited.
        """
        return self.thread_pool.submit(self.analyze_alert, alert)
        
    async def analyze_alert_async_wrapper(self, alert):
        """
        Async wrapper for analyze_alert that can be awaited in async contexts.
        """
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(self.thread_pool, self.analyze_alert, alert)
    
    def batch_analyze_alerts(self, alerts):
        """
        Analyze multiple alerts in parallel using the thread pool.
        
        Args:
            alerts: List of Alert objects to analyze
            
        Returns:
            Dictionary mapping alert IDs to analysis results
        """
        futures = {alert.id: self.analyze_alert_async(alert) for alert in alerts}
        results = {}
        
        for alert_id, future in futures.items():
            try:
                results[alert_id] = future.result()
            except Exception as e:
                logger.error(f"Failed to analyze alert {alert_id}: {str(e)}")
                results[alert_id] = None
                
        return results

# Create a singleton instance
gemini_integration = GeminiIntegration()