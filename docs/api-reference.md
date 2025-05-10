# API Reference

ARPF-TI provides a comprehensive set of APIs for integration with other security tools and services. This document outlines the available endpoints, authentication methods, and example usage patterns.

## Authentication

All API requests require authentication using token-based authentication.

### Obtaining an API Token

1. Log in to the ARPF-TI web interface
2. Navigate to User Settings > API Tokens
3. Generate a new token with the required permissions
4. Store this token securely - it will only be displayed once

### Authentication Header

Include your API token in each request:

```
Authorization: Token YOUR_API_TOKEN_HERE
```

## Core API Endpoints

### Request Logs

#### List Request Logs

```
GET /api/v1/request-logs/
```

Query parameters:
- `page`: Page number for pagination
- `per_page`: Number of items per page (default: 20, max: 100)
- `start_date`: Filter by start date (ISO format)
- `end_date`: Filter by end date (ISO format)
- `source_ip`: Filter by source IP
- `was_blocked`: Filter by blocking status (true/false)

#### Get Request Log Details

```
GET /api/v1/request-logs/{id}/
```

### Rules

#### List Rules

```
GET /api/v1/rules/
```

Query parameters:
- `page`: Page number for pagination
- `per_page`: Number of items per page (default: 20, max: 100)
- `rule_type`: Filter by rule type
- `is_active`: Filter active rules (true/false)

#### Get Rule Details

```
GET /api/v1/rules/{id}/
```

#### Create Rule

```
POST /api/v1/rules/
```

Request body:
```json
{
  "name": "Block Suspicious IP",
  "description": "Block requests from suspicious IP address",
  "rule_type": "ip",
  "value": "192.168.1.1",
  "action": "block",
  "is_active": true,
  "priority": 100
}
```

#### Update Rule

```
PUT /api/v1/rules/{id}/
```

#### Delete Rule

```
DELETE /api/v1/rules/{id}/
```

#### Toggle Rule Status

```
POST /api/v1/rules/{id}/toggle/
```

### Alerts

#### List Alerts

```
GET /api/v1/alerts/
```

Query parameters:
- `page`: Page number for pagination
- `per_page`: Number of items per page (default: 20, max: 100)
- `severity`: Filter by severity (info, low, medium, high, critical)
- `is_acknowledged`: Filter by acknowledgment status (true/false)

#### Get Alert Details

```
GET /api/v1/alerts/{id}/
```

#### Acknowledge Alert

```
POST /api/v1/alerts/{id}/acknowledge/
```

### Threat Intelligence

#### List Threat Intelligence Sources

```
GET /api/v1/threat-intelligence/sources/
```

#### Get Source Details

```
GET /api/v1/threat-intelligence/sources/{id}/
```

#### List Threat Intelligence Entries

```
GET /api/v1/threat-intelligence/entries/
```

Query parameters:
- `page`: Page number for pagination
- `per_page`: Number of items per page (default: 20, max: 100)
- `entry_type`: Filter by entry type (ip, domain, hash, url)
- `source_id`: Filter by source ID
- `value`: Search by value

#### Create Firewall Rule from Threat Entry

```
POST /api/v1/threat-intelligence/entries/{id}/create-rule/
```

## Dashboard API

### Get Dashboard Metrics

```
GET /api/v1/dashboard/metrics/
```

Query parameters:
- `period`: Time period (hour, day, week, month)
- `metric_type`: Type of metric (request_count, blocked_count, threat_score, etc.)

### Get Geolocation Data

```
GET /api/v1/dashboard/geo-data/
```

## AI Integration API

### Analyze Request 

```
POST /api/v1/ai/analyze-request/
```

Request body:
```json
{
  "request_data": {
    "source_ip": "192.168.1.1",
    "path": "/admin/login",
    "method": "POST",
    "user_agent": "Mozilla/5.0...",
    "headers": {
      "Content-Type": "application/json",
      "X-Forwarded-For": "10.0.0.1"
    }
  }
}
```

### Get AI Suggested Rules

```
GET /api/v1/ai/suggested-rules/
```

Query parameters:
- `status`: Filter by status (pending, approved, rejected, auto_approved)
- `confidence`: Minimum confidence score (0-100)

### Apply Suggested Rule

```
POST /api/v1/ai/suggested-rules/{id}/apply/
```

## Comparison API

### Get Comparison Metrics

```
GET /api/v1/comparison/metrics/
```

Query parameters:
- `period`: Time period (day, week, month)
- `rule_type`: Type of rules to compare (ai, manual, all)

## Rate Limiting

API requests are rate-limited to prevent abuse. Current limits:

- 60 requests per minute for standard users
- 300 requests per minute for administrator users

When rate limited, you'll receive a 429 status code with a `Retry-After` header.

## Webhook Integration

ARPF-TI can send webhook notifications for various events:

### Register Webhook

```
POST /api/v1/webhooks/
```

Request body:
```json
{
  "url": "https://your-service.com/webhook",
  "secret": "your_webhook_secret",
  "events": ["alert.created", "rule.matched"],
  "is_active": true
}
```

Events include:
- `alert.created`: New alert created
- `alert.acknowledged`: Alert acknowledged
- `rule.created`: New rule created
- `rule.matched`: Rule triggered
- `threat.detected`: New threat detected

## Error Handling

All API errors return a JSON response with appropriate HTTP status codes:

- `400 Bad Request`: Invalid parameters
- `401 Unauthorized`: Missing or invalid authentication
- `403 Forbidden`: Insufficient permissions
- `404 Not Found`: Resource not found
- `429 Too Many Requests`: Rate limit exceeded
- `500 Internal Server Error`: Server-side error

Example error response:
```json
{
  "error": "invalid_parameters",
  "message": "Rule type must be one of: ip, ip_range, country, port, port_range, path, user_agent, protocol, custom",
  "details": {
    "rule_type": ["Invalid rule type provided"]
  }
}
```

## API Client Libraries

- Python: [arpf-ti-client](https://github.com/yourusername/arpf-ti-client-python)
- JavaScript: [arpf-ti-js](https://github.com/yourusername/arpf-ti-client-js)

## Example Usage

### Python Client Example

```python
import arpf_ti_client

# Initialize client
client = arpf_ti_client.Client(api_key="YOUR_API_KEY")

# Get active rules
rules = client.rules.list(is_active=True)

# Create a new rule
new_rule = client.rules.create(
    name="Block Tor Exit Nodes",
    description="Block known Tor exit nodes",
    rule_type="ip_range",
    value="185.220.101.0/24",
    action="block",
    is_active=True
)

# Get recent alerts
alerts = client.alerts.list(
    severity=["high", "critical"],
    is_acknowledged=False
)
```

### cURL Examples

List active rules:
```bash
curl -H "Authorization: Token YOUR_API_TOKEN" \
  https://your-arpf-ti-instance.com/api/v1/rules/?is_active=true
```

Create a new rule:
```bash
curl -X POST \
  -H "Authorization: Token YOUR_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"Block Suspicious IP","rule_type":"ip","value":"192.168.1.1","action":"block"}' \
  https://your-arpf-ti-instance.com/api/v1/rules/
```
