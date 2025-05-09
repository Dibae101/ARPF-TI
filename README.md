# ARPF-TI: Advanced Rule-based Protection Framework with Threat Intelligence

A modern security platform integrating AI-powered threat detection with traditional rule-based filtering for comprehensive web request protection.

![Threat Intelligence Dashboard](/research_paper/images/threat-intelligence-dashboard.png)

## Key Features

- 🔒 **Request Filtering** - Identify and block malicious requests using customizable rules
- 🧠 **AI Integration** - Leverage Gemini AI and TinyLlama for advanced threat detection
- 🌐 **Threat Intelligence** - Connect to multiple threat feeds (MISP, TAXII, AlienVault, etc.)
- 📊 **Comparison System** - Evaluate AI vs. manual rule effectiveness
- 🚨 **Alert Management** - Configurable notifications via email, Slack and webhooks
- 📈 **Real-time Monitoring** - Comprehensive dashboard with traffic visualization

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

Visit [http://localhost:8000](http://localhost:8000) to access the dashboard.

## AI-Powered Protection

ARPF-TI combines traditional rule-based filtering with advanced AI models:

- **Gemini AI Integration** - Cloud-based API for sophisticated threat analysis
- **TinyLlama (1.1B)** - Optional local model for offline environments
- **Adaptive Learning** - System improves by learning from verified threats

![AI vs Manual Rule Comparison](/research_paper/images/comparision1.png)

## System Architecture

The platform consists of six integrated components:

1. **Core Processing Engine** - Request filtering and rule evaluation
2. **Threat Intelligence Module** - Fetch and manage threat data 
3. **AI Analysis System** - Intelligent pattern detection
4. **Alert Management** - Notification and response system
5. **Dashboard and Analytics** - Visualization and monitoring
6. **Comparison Framework** - Performance metrics and evaluation

![Firewall Rules Interface](/research_paper/images/firewall-rules.png)

## Deployment Options

### Standard Installation
```bash
# Create virtual environment
python -m venv env
source env/bin/activate  # On Windows: env\Scripts\activate

# Install and run
pip install -r requirements.txt
python manage.py migrate
python manage.py runserver
```

### Docker Installation
```bash
# Build and start containers
docker-compose up -d

# Create superuser
docker-compose exec web python manage.py createsuperuser
```

See [docker-readme.md](docker-readme.md) for detailed Docker options.

## Alert Management

The integrated alert system provides:

- Multi-channel notifications (email, Slack, webhooks)
- AI-enhanced analysis of potential threats
- Customizable severity levels and filtering
- Alert acknowledgment and resolution tracking

![Alert System](/research_paper/images/alerts.png)

## Rule Comparison

Compare the effectiveness of AI-generated vs manually created rules:

| Metric | AI Rules | Manual Rules | Improvement |
|--------|----------|--------------|-------------|
| Precision Rate | 89.2% | 71.5% | 17.7% |
| True Positives | 267 | 184 | 45.1% |
| False Positives | 33 | 74 | 55.4% reduction |
| Response Time | 35.7 min | 42.8 min | 16.6% reduction |

![Rule Effectiveness](/research_paper/images/comparision2.png)

## Threat Intelligence

Connect to multiple threat intelligence sources:

- MISP (Malware Information Sharing Platform)
- TAXII/STIX feeds
- AlienVault OTX
- Abuse.ch URLhaus
- PhishTank
- Custom API integrations

![Adding Threat Intelligence Source](/research_paper/images/dashboard.png)

## Documentation

For comprehensive documentation:

- [Installation Guide](docs/installation.md)
- [API Reference](docs/api-reference.md)
- [Rule Configuration](docs/rule-configuration.md)
- [AI Integration](docs/ai-integration.md)
- [Threat Intelligence](docs/threat-intelligence.md)

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.