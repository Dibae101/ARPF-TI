# ARPF-TI: Advanced Request Processing Framework with Threat Intelligence

ARPF-TI is a robust system designed to process web requests with integrated threat intelligence capabilities, focusing on security and analysis. The platform combines traditional rule-based filtering with advanced AI-powered threat detection to provide comprehensive protection and insights.

## Quick Start

```bash
# Clone the repository
git clone https://github.com/yourusername/ARPF-TI.git
cd ARPF-TI

# Install dependencies
pip install -r requirements.txt

# Run database migrations
python manage.py migrate

# Create admin user
python manage.py createsuperuser

# Start the server
python manage.py runserver 0.0.0.0:8000
```

Visit [http://localhost:8000](http://localhost:8000) or [http://your-server-ip:8000](http://your-server-ip:8000) to access the dashboard.

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

- **Gemini AI Integration**: Leverage AI for advanced threat detection and pattern analysis
- **TinyLlama Integration**: Optional use of the TinyLlama 1.1B model for local inference
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

## Detailed Setup and Installation

### Prerequisites

- Python 3.8+ (3.12 recommended)
- Django 3.2+
- Required packages (see requirements.txt)
- 4GB+ RAM for AI model inference
- 2GB+ disk space for models and databases

### Installation Options

#### Standard Installation

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/ARPF-TI.git
   cd ARPF-TI
   ```

2. Create and activate a virtual environment:
   ```
   python -m venv env
   source env/bin/activate  # On Windows: env\Scripts\activate
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
   python manage.py runserver 0.0.0.0:8000
   ```

7. Access the application:
   - Dashboard: http://localhost:8000/
   - Admin interface: http://localhost:8000/admin/

#### Docker Installation

For production environments, Docker is recommended:

1. Make sure Docker and Docker Compose are installed on your system
2. Build and start the containers:
   ```
   docker-compose up -d
   ```

3. Create a superuser in the Docker container:
   ```
   docker-compose exec web python manage.py createsuperuser
   ```

4. Access the application:
   - Dashboard: http://localhost:8000/
   - Admin interface: http://localhost:8000/admin/

See [docker-readme.md](docker-readme.md) for detailed Docker configuration options.

### Production Deployment

For production environments, additional configurations are recommended:

1. Use a proper web server like Nginx or Apache as a reverse proxy
2. Configure HTTPS with SSL certificates
3. Use a production-grade database (PostgreSQL recommended)
4. Set up proper logging
5. Configure email for alerts

Example Nginx configuration:
```nginx
server {
    listen 80;
    server_name yourserver.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    server_name yourserver.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /static/ {
        alias /path/to/ARPF-TI/staticfiles/;
    }
}
```

### AI Model Setup

ARPF-TI uses AI for advanced threat detection. You can use either the online Gemini AI integration or the local TinyLlama model:

#### 1. Gemini AI Integration (Recommended)

The easiest option is to use the integrated Gemini AI service:

1. Go to Settings > Threat Intelligence > AI Settings
2. Enable "Use Gemini AI for threat analysis"
3. The system will use the pre-configured Gemini AI service without any additional setup

#### 2. TinyLlama Setup (Optional for local inference)

For local AI inference or offline environments:

##### Automatic Model Download

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

3. Verify model setup in admin panel:
   - Go to Admin > Threat Intelligence > AI Models
   - Confirm that TinyLlama model status shows "Active"

##### Manual Model Setup

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

#### 3. Using Alternative Models

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

## Setting Up Threat Intelligence Sources

ARPF-TI comes with several pre-configured threat intelligence sources, but you can add your own custom sources:

### 1. Using Built-in Sources

Run the setup script to configure default sources:
```
python create_test_sources.py
```

This will set up:
- AlienVault OTX
- MISP Community Feed
- Abuse.ch URLhaus
- PhishTank
- Emerging Threats Community

### 2. Adding Custom Sources

To add your own threat intelligence sources:

1. Go to Threat Intelligence > Sources > Add New Source
2. Fill in the required information:
   - Name: A descriptive name for the source
   - URL: The API endpoint or feed URL
   - Source Type: Select from dropdown (MISP, TAXII, API, etc.)
   - API Key: If required for authentication
   - Update Frequency: How often to fetch new data
   - Confidence Score: Default confidence for entries from this source
3. Click "Test Connection" to verify the source is accessible
4. Click "Save" to add the source
5. Click "Fetch Now" to immediately download threat data

### 3. Manual Entry

You can also manually add threat intelligence entries:

1. Go to Threat Intelligence > Entries > Add New Entry
2. Select the entry type (IP, Domain, URL, Hash, etc.)
3. Enter the value and additional metadata
4. Set confidence score and expiry date
5. Click "Save" to add the entry to the database

## Detailed Feature Guide

### Dashboard Interface

The dashboard is your central control point for monitoring system activity:

**Top Stats Row**:
- **Total Requests**: Shows the total number of requests processed with percentage change
- **Blocked Requests**: Displays number of blocked requests with block rate percentage
- **Active Rules**: Shows number of currently active rules with trigger count
- **Recent Alerts**: Displays count of recent alerts with link to details
- **Gemini AI Status**: Shows whether AI analysis is active and learning from patterns

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

### Example Rule Creation

**Creating a SQL Injection Protection Rule**:

1. Go to Rules > Add New Rule
2. Set basic information:
   - Name: "SQL Injection Protection"
   - Description: "Block common SQL injection attempts in query parameters"
   - Priority: 85 (high)
3. Add conditions:
   - Parameter Type: Query Parameters
   - Matching Method: Regex Match
   - Pattern: `'((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))`
   - Click "Add Condition"
   - Join Type: OR
   - Parameter Type: Query Parameters
   - Matching Method: Regex Match
   - Pattern: `((\%27)|(\'))union((\%20)|(\s))((\%73)|s|(\%53))((\%65)|e|(\%45))((\%6C)|l|(\%4C))((\%65)|e|(\%45))((\%63)|c|(\%43))((\%74)|t|(\%54))`
4. Set Action: Block Request
5. Advanced Options:
   - Alert: Enabled
   - Alert Severity: High
   - Log Detail Level: Full
6. Test the rule:
   - Enter sample URL: `/search?q=test' OR 1=1--`
   - Click "Test Rule" - should show "Rule would block this request"
7. Save the rule by clicking "Create Rule"

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

### Traffic Analysis

The Traffic Analyzer is a powerful feature that helps identify potential threats:

1. Access via Threat Intelligence > Traffic Analysis
2. Configure analysis parameters:
   - Time period to analyze (default: last 7 days)
   - Minimum confidence threshold (default: 70%)
   - Analysis depth (Quick, Standard, Deep)
3. Click "Start Analysis" to begin processing
4. View results in the Analysis Report:
   - Total logs analyzed
   - Potential threats identified
   - New threat intelligence entries created
   - Suggested firewall rules
   - Breakdown by threat categories
5. Review and apply suggested rules
6. Schedule automated analysis:
   - Daily, Weekly, or Monthly
   - Configurable parameters for each schedule
   - Option to auto-approve high-confidence rules

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

**Slack Integration**:
1. Go to Alerts > Notification Settings > Slack
2. Click "Configure Slack Integration"
3. Enter your Slack Webhook URL
4. Configure which alert types to send to Slack
5. Set up formatting options
6. Click "Test" to verify the connection
7. Save the configuration

## API Reference

ARPF-TI provides a comprehensive API for integration with other systems:

**Authentication Endpoints**:
- `POST /api/auth/token/`: Obtain authentication token
  ```json
  {
    "username": "your_username",
    "password": "your_password"
  }
  ```
- `POST /api/auth/refresh/`: Refresh authentication token
  ```json
  {
    "refresh": "your_refresh_token"
  }
  ```

**Logs API**:
- `GET /api/logs/`: Retrieve logs with filtering
  - Query params: `start_date`, `end_date`, `source_ip`, `status`, etc.
- `GET /api/logs/{id}/`: Get specific log details

**Rules API**:
- `GET /api/rules/`: List all rules
- `POST /api/rules/`: Create new rule
  ```json
  {
    "name": "Example Rule",
    "description": "Block suspicious requests",
    "is_active": true,
    "priority": 75,
    "conditions": [
      {
        "parameter_type": "query",
        "match_type": "contains",
        "pattern": "malicious"
      }
    ],
    "action": "block"
  }
  ```
- `GET /api/rules/{id}/`: Get rule details
- `PUT /api/rules/{id}/`: Update rule
- `DELETE /api/rules/{id}/`: Delete rule
- `POST /api/rules/{id}/toggle/`: Enable/disable rule

**Threat Intelligence API**:
- `GET /api/threat-intel/sources/`: List sources
- `GET /api/threat-intel/entries/`: List entries
  - Query params: `entry_type`, `value`, `confidence_min`, etc.
- `POST /api/threat-intel/sources/{id}/refresh/`: Refresh source

**Alert API**:
- `GET /api/alerts/`: List alerts
- `GET /api/alerts/{id}/`: Get alert details
- `PUT /api/alerts/{id}/status/`: Update alert status
- `GET /api/alerts/stats/`: Get alert statistics

**Complete API documentation is available at `/api/docs/` when the server is running.**

## Project Structure

- `alerts/`: Alert system management and notification logic
  - `alert_system.py`: Core alert generation and routing
  - `setup_slack.py`: Slack integration configuration
- `arpf_ti/`: Main Django project settings and configuration
- `core/`: Core request processing functionality and rule engine
  - `middleware.py`: Request interception and processing
  - `models.py`: Rule definitions and log storage
- `dashboard/`: System analytics, visualization, and monitoring
  - `views.py`: Dashboard data processing
  - `templatetags/`: Custom template filters and tags
- `threat_intelligence/`: Threat intelligence sources and AI model integration
  - `ai/`: AI model implementation and inference logic
  - `integrations/`: Connectors for external threat intelligence sources
  - `model_files/`: Storage for AI model files and data
  - `traffic_analyzer.py`: Traffic pattern analysis
- `templates/`: HTML templates for the web interface
- `static/`: CSS, JavaScript, and image assets
- `tests/`: Automated tests and attack simulations

## Troubleshooting

### Common Issues

**Installation Problems**:
- If you encounter issues with package installation, try: `pip install --upgrade pip` before installing requirements
- For specific package errors, check the [requirements-dev.txt](requirements-dev.txt) for alternative versions

**Database Errors**:
- If database migration fails, try: `python manage.py migrate --fake-initial`
- For database connection issues: Check database settings in `settings.py`

**AI Model Issues**:
- If TinyLlama fails to load: Verify model files exist in `threat_intelligence/model_files/tinyllama/`
- For CUDA/GPU errors: Set environment variable `FORCE_CPU=1` to use CPU only

**Web Server Issues**:
- If the server won't start: Check port availability with `netstat -tulpn | grep 8000`
- For 500 errors: Check logs in `logs/arpf_ti.log`

### Getting Help

If you encounter issues not covered here:
1. Check the logs in `logs/arpf_ti.log`
2. Visit our [GitHub Issues page](https://github.com/yourusername/ARPF-TI/issues)
3. Join our community forum at [community.arpf-ti.org](https://community.arpf-ti.org)

## Contributing

Please read our [CONTRIBUTING.md](CONTRIBUTING.md) for details on how to contribute to this project.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgements

- TinyLlama model by [TinyLlama team](https://github.com/jzhang38/TinyLlama)
- Django framework
- All open-source libraries and threat intelligence feeds used in this project