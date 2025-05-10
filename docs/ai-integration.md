# AI Integration

ARPF-TI integrates advanced AI capabilities to enhance threat detection, analyze security alerts, and generate optimized firewall rules. This guide explains the AI integration features and how to configure them for your environment.

![AI vs Manual Rule Comparison](/research_paper/images/comparision1.png)

## AI Models Overview

ARPF-TI uses two complementary AI models:

1. **Google Gemini**: Cloud-based API for sophisticated threat analysis
2. **TinyLlama (1.1B)**: Optional local model for offline environments

### Google Gemini Integration

Gemini provides advanced natural language processing capabilities for:
- Analyzing network traffic patterns
- Detecting sophisticated attack techniques
- Generating security recommendations
- Evaluating threat intelligence feeds

### TinyLlama Local Model (Optional)

TinyLlama is a lightweight local model that can be used in environments without internet access or when privacy concerns prohibit sending data to external APIs:
- 1.1B parameter LLM
- Can run on modest hardware (minimum 8GB RAM)
- Provides basic threat detection capabilities
- No external API calls required

## Setting Up AI Integration

### Configuring Gemini AI

1. **Obtain API Key**:
   - Register for Google AI Studio at [ai.google.dev](https://ai.google.dev)
   - Create a new API key for the Gemini API
   - Note: You may need to set up billing for production usage

2. **Configure Environment Variables**:
   - Add to your `.env` file:
     ```
     GEMINI_API_KEY=your_api_key_here
     GEMINI_MODEL_NAME=gemini-pro
     GEMINI_TEMPERATURE=0.2
     GEMINI_MAX_OUTPUT_TOKENS=1024
     GEMINI_TOP_P=0.8
     GEMINI_TOP_K=40
     GEMINI_RATE_LIMIT_ENABLED=True
     GEMINI_RATE_LIMIT_CALLS=60
     GEMINI_RATE_LIMIT_PERIOD=60
     GEMINI_FEEDBACK_UTILIZATION_ENABLED=True
     ```

3. **Verify Setup**:
   - Navigate to **Threat Intelligence > Gemini AI**
   - You should see "Gemini AI is active and ready for threat analysis"

### Configuring TinyLlama (Optional)

1. **Download the Model**:
   ```bash
   python manage.py download_local_model
   ```

2. **Configure Environment Variables**:
   - Add to your `.env` file:
     ```
     USE_LOCAL_MODEL=True
     LOCAL_MODEL_PATH=/path/to/models/tinyllama
     ```

3. **Verify Local Model Setup**:
   - Navigate to **System > AI Configuration**
   - Check "Local Model Status"

### AI Fallback Configuration

Configure fallback behavior for when the primary AI model is unavailable:

1. Navigate to **System > AI Configuration**
2. Set the "AI Fallback Strategy":
   - **Cloud-First**: Use Gemini with TinyLlama as fallback (recommended)
   - **Local-First**: Use TinyLlama with Gemini as fallback
   - **Cloud-Only**: Use only Gemini, no fallback
   - **Local-Only**: Use only TinyLlama, no fallback

## AI-Enhanced Features

### Threat Detection and Analysis

AI enhances threat detection by:

1. **Pattern Recognition**: Identifying anomalous patterns in network traffic
2. **Context-Aware Analysis**: Understanding the context of requests
3. **Behavioral Analysis**: Detecting deviations from normal behavior
4. **Signature Bypass Detection**: Identifying attempts to bypass signature-based rules

Configure AI threat detection settings:

1. Navigate to **Threat Intelligence > AI Settings**
2. Adjust:
   - Detection Sensitivity (1-10)
   - Minimum Confidence Threshold (0-100%)
   - Analysis Depth (Basic, Standard, Deep)

### Automated Rule Generation

AI can automatically suggest firewall rules based on:

1. **Traffic Analysis**: Patterns in actual traffic
2. **Threat Intelligence**: Emerging threats from feeds
3. **Historical Data**: Past attacks and alerts
4. **False Positive Learning**: Feedback on previous rule effectiveness

Configure rule generation settings:

1. Navigate to **Threat Intelligence > AI Settings > Rule Generation**
2. Adjust:
   - Auto-Generation Threshold (0-100%)
   - Rule Types to Generate
   - Maximum Daily Suggestions
   - Auto-Approval Threshold (recommended: 90%)

### Alert Triage and Enrichment

AI enriches security alerts with:

1. **Severity Assessment**: Evaluating true risk level
2. **Context Information**: Adding relevant background
3. **Recommended Actions**: Suggesting response steps
4. **Root Cause Analysis**: Identifying underlying issues

Configure alert enrichment:

1. Navigate to **Alerts > AI Settings**
2. Enable/disable:
   - AI Severity Adjustment
   - Context Enrichment
   - Automatic Notification for High-Confidence Alerts
   - Response Recommendation Generation

## AI Feedback System

The AI models improve over time through feedback:

### Providing Feedback

1. Navigate to an AI-generated alert assessment or rule
2. Click "Provide Feedback"
3. Rate accuracy (1-5 stars)
4. Add optional feedback notes
5. Submit

### Feedback Dashboard

View AI performance metrics:

1. Navigate to **System > AI Performance**
2. Review:
   - Accuracy Trends
   - False Positive/Negative Rates
   - User Feedback Summaries
   - Model Performance Comparisons

## Advanced AI Configuration

### Custom Context Settings

Improve AI accuracy by configuring custom context:

1. Navigate to **Threat Intelligence > AI Settings > Advanced**
2. Add:
   - Environment Description
   - Specific Threats of Concern
   - Protected Application Types
   - Industry-Specific Context

### Prompt Templates

Customize the AI analysis prompts:

1. Navigate to **Threat Intelligence > AI Settings > Prompt Templates**
2. Modify templates for:
   - Request Analysis
   - Alert Evaluation
   - Rule Generation
   - Threat Classification

### API Integration

Use the AI analysis capabilities in your own applications:

1. Generate an API key in **User Settings > API Keys**
2. Make requests to `/api/v1/ai/analyze-request/` (see [API Reference](api-reference.md))

## Performance Optimization

### Rate Limiting Configuration

Adjust API usage to balance cost and performance:

1. Navigate to **System > AI Settings > Performance**
2. Configure:
   - Maximum API Calls per Minute
   - Caching Duration
   - Batch Analysis Settings

### Caching Strategy

Configure caching to reduce API calls:

1. Navigate to **System > AI Settings > Caching**
2. Set:
   - Cache Lifetime
   - Cache Size Limit
   - Cache Clearing Schedule

## Monitoring AI Performance

### Performance Dashboard

1. Navigate to **System > AI Performance**
2. View:
   - API Usage Statistics
   - Response Times
   - Error Rates
   - Cost Tracking (for cloud API)

### Alert Integration

Get notified about AI system issues:

1. Navigate to **Alerts > Alert Rules**
2. Enable notifications for:
   - AI Service Disruptions
   - High API Usage
   - Unusual Error Rates
   - Model Performance Degradation

## Comparison with Manual Rules

ARPF-TI provides tools to compare AI-generated rules with manually created ones:

![Rule Effectiveness](/research_paper/images/comparision2.png)

1. Navigate to **Comparison > Rule Effectiveness**
2. View metrics like:
   - Precision Rate
   - True Positives
   - False Positives
   - Response Time
   - Coverage Metrics

## Troubleshooting

### API Connection Issues

If Gemini API connections fail:

1. Verify API key in environment variables
2. Check network connectivity to Google AI APIs
3. Review API rate limits
4. Check for API service disruptions

### Local Model Issues

If TinyLlama model isn't working:

1. Verify model files are downloaded completely
2. Check system memory availability
3. Review file permissions
4. Try reinstalling the model: `python manage.py download_local_model --force`

### Poor AI Performance

If AI detection quality is low:

1. Increase detection sensitivity
2. Provide more feedback to train the system
3. Add more custom context
4. Check if your traffic patterns are very unusual or specialized

## Best Practices

1. **Start with Human Oversight**: Review AI-generated rules before auto-applying them
2. **Provide Regular Feedback**: Help the models improve by rating suggestions
3. **Balance Sensitivity**: Set appropriate thresholds to balance security and false positives
4. **Use Both Models When Possible**: The combined approach provides the best security coverage
5. **Monitor API Usage**: Keep track of cloud API costs in production environments
6. **Regular Retraining**: Periodically retrain the local model with new data

## Advanced Topics

### Custom Model Integration

For specialized environments, you can integrate custom models:

1. Prepare your model in ONNX format
2. Place in the `models/custom` directory
3. Configure in `.env`:
   ```
   USE_CUSTOM_MODEL=True
   CUSTOM_MODEL_PATH=/path/to/models/custom/my_model.onnx
   ```
4. Implement adaptation layer in `threat_intelligence/ai/adapters/`

### Fine-tuning for Your Environment

For enterprise deployments, fine-tune models on your specific traffic:

1. Export anonymized traffic samples:
   ```bash
   python manage.py export_training_data --anonymize
   ```
2. Upload to your model provider for fine-tuning
3. Configure the fine-tuned model

## Further Reading

- [Installation Guide](installation.md)
- [Rule Configuration](rule-configuration.md)
- [Threat Intelligence](threat-intelligence.md)
- [API Reference](api-reference.md)
