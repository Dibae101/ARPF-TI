# ARPF-TI: Advanced Request Processing Framework with Threat Intelligence

ARPF-TI is a robust system designed to process web requests with integrated threat intelligence capabilities, focusing on security and analysis. The platform combines traditional rule-based filtering with advanced AI-powered threat detection to provide comprehensive protection and insights.

## Features

### Request Processing

- **Request Filtering**: Filter incoming HTTP/HTTPS requests based on configurable rules
- **Pattern Matching**: Identify malicious patterns in request parameters, headers, and body
- **Rate Limiting**: Prevent abuse through configurable rate limiting by IP, user, or endpoint
- **Proxy Management**: Configure and manage proxy settings for outbound connections
- **Access Control**: Define and enforce access control policies based on various parameters
- **Custom Rules Engine**: Create, test, and deploy custom rules without service disruption

### Threat Intelligence

- **Multi-source Integration**: Connect to various threat intelligence feeds including MISP, TAXII, and custom APIs
- **Indicator Management**: Store, categorize, and manage Indicators of Compromise (IoCs)
- **Automated Updates**: Schedule and automate the retrieval of the latest threat data
- **Confidence Scoring**: Assign and adjust confidence scores to threat intelligence entries
- **Contextual Enrichment**: Enrich request data with threat context for better decision making
- **Export Capabilities**: Export threat data in various formats (CSV, JSON, STIX)

### AI-Powered Detection

- **TinyLlama Integration**: Leverage the TinyLlama 1.1B model for advanced threat detection
- **Request Analysis**: Analyze request patterns to identify suspicious behavior
- **Anomaly Detection**: Identify unusual patterns that may indicate zero-day threats
- **Custom Model Training**: Train models based on your specific traffic patterns
- **Model Management**: Upload, configure, and manage different AI models
- **Inference Settings**: Configure inference parameters like temperature and token limits
- **Performance Monitoring**: Monitor model performance and resource usage

### Dashboard

- **Real-time Monitoring**: View system activity and threats in real-time
- **Traffic Visualization**: Interactive charts showing request volumes and patterns
- **Threat Maps**: Geographical visualization of threat sources
- **Rule Performance**: Monitor rule effectiveness and trigger rates
- **System Health**: Track system performance and resource utilization
- **Custom Time Ranges**: Analyze data across different time periods (hour, day, week, month)
- **Export Reports**: Generate and export dashboard reports in multiple formats

### Alerts System

- **Alert Configuration**: Define alert conditions based on threat severity and types
- **Multiple Channels**: Receive alerts via email, webhook, Slack, or custom integrations
- **Alert Prioritization**: Set priority levels to focus on critical issues first
- **Alert Grouping**: Group related alerts to reduce noise and improve response
- **Scheduled Digests**: Configure daily or weekly alert digests
- **Alert Management**: Acknowledge, assign, and resolve alerts through the interface

## Setup and Installation

### Prerequisites

- Python 3.8+
- Django 3.2+
- Required packages (see requirements.txt)
- 4GB+ RAM for AI model inference
- 2GB+ disk space for models and databases

### Installation

1. Clone the repository:
   ```
   git clone <repository-url>
   cd ARPF-TI
   ```

2. Create and activate a virtual environment:
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

4. Set up the database:
   ```
   python manage.py migrate
   ```

5. Create a superuser:
   ```
   python manage.py createsuperuser
   ```

6. Run the development server:
   ```
   python manage.py runserver
   ```

### AI Model Setup

ARPF-TI uses TinyLlama for advanced threat detection. Follow these steps to set up the model:

#### Automatic Model Download

The simplest way to download and set up the TinyLlama model:

1. Run the provided download script:
   ```
   python download_tinyllama.py
   ```
   This script will:
   - Download the TinyLlama 1.1B Chat model from Hugging Face
   - Store it in the appropriate directory structure
   - Display progress during download

2. Generate the optimized pickle file:
   ```
   python create_tinyllama_pickle.py
   ```
   This process:
   - Loads the downloaded model
   - Optimizes it for inference
   - Creates a pickle file for faster loading
   - May take 5-10 minutes depending on your hardware

#### Manual Model Setup

If you prefer to set up the model manually:

1. Download the TinyLlama model from Hugging Face:
   ```
   # Install huggingface_hub if not already installed
   pip install huggingface_hub
   
   # Use the huggingface_hub CLI
   huggingface-cli download TinyLlama/TinyLlama-1.1B-Chat-v1.0 --local-dir ./threat_intelligence/model_files/tinyllama/models--TinyLlama--TinyLlama-1.1B-Chat-v1.0
   ```

2. Create the pickle file:
   ```python
   # Create a Python script with similar content to create_tinyllama_pickle.py
   from transformers import AutoModelForCausalLM, AutoTokenizer
   import pickle
   import os
   
   # Set paths
   model_path = './threat_intelligence/model_files/tinyllama/models--TinyLlama--TinyLlama-1.1B-Chat-v1.0'
   pickle_path = './threat_intelligence/model_files/tinyllama/tinyllama_model.pkl'
   
   # Load model and tokenizer
   model = AutoModelForCausalLM.from_pretrained(model_path)
   tokenizer = AutoTokenizer.from_pretrained(model_path)
   
   # Create directory if needed
   os.makedirs(os.path.dirname(pickle_path), exist_ok=True)
   
   # Save as pickle
   with open(pickle_path, 'wb') as f:
       pickle.dump((model, tokenizer), f)
   
   print(f"Model saved to {pickle_path}")
   ```

#### Using Alternative Models

You can also use other compatible models:

1. Access the AI model management page in the threat_intelligence section
2. Click "Add New Model"
3. Provide the model details:
   - Name: A descriptive name for the model
   - Model Type: Select the appropriate model architecture
   - Model Path: Path to the model files
   - Parameters: Configure model parameters like max tokens, temperature
4. Click "Save" to register the model
5. To activate the model, select it and click "Set as Active"

## Detailed Feature Guide

### Dashboard Interface

The dashboard is your central control point for monitoring system activity:

**Top Stats Row**:
- **Total Requests**: Shows the total number of requests processed with percentage change
- **Blocked Requests**: Displays number of blocked requests with block rate percentage
- **Active Rules**: Shows number of currently active rules with trigger count
- **Recent Alerts**: Displays count of recent alerts with link to details

**Traffic Overview**:
- Interactive line chart showing request volume over time
- Toggle between allowed and blocked requests
- Change time period using Day/Week/Month buttons
- Hover for detailed metrics at specific points

**Request Logs**:
- Comprehensive table of recent requests
- Shows timestamp, source IP, HTTP method, path, and status
- Color-coded status indicators (green for allowed, red for blocked)
- Click on a timestamp to view detailed request information
- "View all" link to access complete logs

**Top Source Countries**:
- Shows geographic distribution of request sources
- Displays country name, request count, and percentage of total
- Helps identify traffic patterns and potential attack sources

**Active Rules**:
- Lists currently active security rules
- Shows rule name, description, and priority
- Color-coded priority indicators for severity
- "View all" link to access complete rule management

**Recent Alerts**:
- Shows latest security alerts generated by the system
- Color-coded by severity (red for critical, orange for high, etc.)
- Displays alert title and timestamp
- Click to view detailed alert information
- "View all" link to access complete alert history

### Rule Management

The rule management interface allows you to create and manage filtering rules:

**Rule List**:
- Overview of all rules with status, priority, and last trigger
- Filter rules by status (active/inactive), type, or priority
- Sort by various attributes (name, priority, creation date)
- Bulk actions for enabling/disabling multiple rules
- Search functionality to find specific rules

**Rule Creation/Editing**:
- Form-based interface for creating new rules
- Rule name and description fields
- Priority slider (1-100) to set rule importance
- Rule conditions builder:
  - Select parameter type (header, query, path, body)
  - Choose matching method (contains, equals, regex, etc.)
  - Define the pattern to match
  - Add multiple conditions with AND/OR logic
- Action selection (block, log, alert)
- Testing tool to validate rule against sample requests
- Enable/disable toggle for quick activation/deactivation

### Threat Intelligence Management

Manage and integrate with threat intelligence sources:

**Sources List**:
- Overview of configured threat intelligence sources
- Source type indicator (MISP, TAXII, custom API)
- Connection status and last update timestamp
- Entry count from each source
- Actions for refresh, edit, and delete

**Source Configuration**:
- Form for adding new intelligence sources
- Source type selection
- Connection parameters (URL, API key, authentication)
- Update frequency settings
- Confidence threshold configuration
- Test connection button to validate settings

**Entries Browser**:
- Browse all threat intelligence entries
- Filter by source, type, confidence score
- Search functionality for specific indicators
- View entry details including metadata
- Export selected entries in various formats

**AI Model Management**:
- List of available AI models
- Model type and status indicators
- Performance metrics (accuracy, resource usage)
- Interface for uploading new models
- Configuration panel for model parameters

### Log Analysis

Detailed view and analysis of request logs:

**Log List**:
- Comprehensive view of all logged requests
- Advanced filtering by date, IP, status, path, etc.
- Customizable columns for different log attributes
- Bulk actions for export or tagging
- Timeline view option for chronological analysis

**Log Detail**:
- Complete request information including:
  - Request headers, parameters, and body
  - Server response details
  - Matched rules and actions taken
  - Geographic information about source IP
  - Related threat intelligence
- AI analysis results when available
- Timeline of request processing steps
- Related requests from same source
- Export options for sharing or further analysis

### Alert System

Configure and manage security alerts:

**Alert List**:
- Overview of all system alerts
- Filter by severity, status, or date range
- Sort by various attributes
- Bulk actions for acknowledging or resolving
- Search to find specific alerts

**Alert Detail**:
- Complete alert information
- Related request data
- Trigger conditions and matched rules
- Suggested remediation steps
- Comment thread for team collaboration
- Status management (new, acknowledged, resolved)

**Notification Configuration**:
- Configure alert delivery channels
- Set up email recipients
- Configure webhook endpoints
- Slack/Teams integration settings
- Schedule for alert digests
- Filter which alert types go to which channels
- Test notification button to verify setup

## API Reference

ARPF-TI provides a comprehensive API for integration with other systems:

**Authentication Endpoints**:
- `/api/auth/token/` - Obtain authentication token
- `/api/auth/refresh/` - Refresh authentication token

**Logs API**:
- `GET /api/logs/` - Retrieve logs with filtering
- `GET /api/logs/{id}/` - Get specific log details

**Rules API**:
- `GET /api/rules/` - List all rules
- `POST /api/rules/` - Create new rule
- `GET /api/rules/{id}/` - Get rule details
- `PUT /api/rules/{id}/` - Update rule
- `DELETE /api/rules/{id}/` - Delete rule
- `POST /api/rules/{id}/toggle/` - Enable/disable rule

**Threat Intelligence API**:
- `GET /api/threat-intel/sources/` - List sources
- `GET /api/threat-intel/entries/` - List entries
- `POST /api/threat-intel/sources/{id}/refresh/` - Refresh source

**Alert API**:
- `GET /api/alerts/` - List alerts
- `GET /api/alerts/{id}/` - Get alert details
- `PUT /api/alerts/{id}/status/` - Update alert status
- `GET /api/alerts/stats/` - Get alert statistics

## Project Structure

- `alerts/`: Alert system management and notification logic
- `arpf_ti/`: Main Django project settings and configuration
- `core/`: Core request processing functionality and rule engine
- `dashboard/`: System analytics, visualization, and monitoring
- `threat_intelligence/`: Threat intelligence sources and AI model integration
  - `ai/`: AI model implementation and inference logic
  - `integrations/`: Connectors for external threat intelligence sources
  - `model_files/`: Storage for AI model files and data

## Contributing

Please read our [CONTRIBUTING.md](CONTRIBUTING.md) for details on how to contribute to this project.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.