# Rule Configuration

This guide explains how to configure and manage firewall rules in ARPF-TI to protect your web applications from malicious traffic.

![Firewall Rules Interface](/research_paper/images/firewall-rules.png)

## Rule Basics

ARPF-TI uses a flexible rule-based system to filter incoming and outgoing traffic. Each rule consists of:

- **Rule Type**: What the rule matches against (IP, path, user agent, etc.)
- **Pattern/Value**: The specific pattern to match
- **Action**: What to do when the rule matches (block, allow, log)
- **Direction**: Whether the rule applies to inbound, outbound, or both directions
- **Priority**: Determines the order of rule evaluation (lower number = higher priority)

## Rule Types

ARPF-TI supports the following rule types:

| Rule Type | Description | Example Pattern |
|-----------|-------------|-----------------|
| IP | Single IP address | `192.168.1.1` |
| IP Range | CIDR notation for IP range | `192.168.1.0/24` |
| Country | Two-letter country code | `RU`, `CN` |
| Port | Specific port | `3306` (MySQL) |
| Port Range | Range of ports | `6000-7000` |
| Path | URL path pattern | `/admin/.*`, `/wp-login.php` |
| User Agent | Browser/client identifier | `Bad-Bot`, `Scanbot` |
| Protocol | Network protocol | `http`, `ssh` |
| Custom | Advanced custom rule | `rate:10:60` (10 req/min) |

## Creating Rules

### Through the Web Interface

1. Navigate to **Threat Intelligence > Firewall Rules**
2. Click **Add Rule**
3. Fill in the required fields:
   - Name (descriptive identifier)
   - Rule Type
   - Value/Pattern
   - Action (Block, Allow, Log)
   - Direction (Inbound, Outbound, Both)
   - Priority
   - Optional fields as needed
4. Click **Save Rule**

### Using Presets

ARPF-TI comes with preset rule collections for common protection scenarios:

1. Navigate to **Threat Intelligence > Firewall Rules**
2. Click **Rule Presets**
3. Choose a category:
   - Common Protection (block private IPs, bogon IPs, etc.)
   - Country Blocks (geo-blocking)
   - Common Ports (block or allow specific services)
   - Attack Protection (DDoS, web application attacks)
   - Miscellaneous (P2P blocking, VPN access, etc.)
4. Select the presets you want to apply and click **Add These Rules**

### From Threat Intelligence Entries

You can convert threat intelligence entries directly into firewall rules:

1. Navigate to **Threat Intelligence > Entries**
2. Find an entry you want to block
3. Click **Create Rule**
4. Review the rule details
5. Click **Create Rule**

### Using the API

See the [API Reference](api-reference.md) for details on programmatically creating rules.

## Rule Priority and Evaluation

Rules are evaluated based on their priority (1-1000), with lower numbers having higher priority. When multiple rules match a request:

1. The highest priority rule's action is applied first
2. If that rule is a block rule, the request is blocked
3. If that rule is an allow rule, the request is allowed regardless of lower priority rules
4. If that rule is a log rule, the request is logged and evaluation continues

**Best Practice**: Set critical allow rules to highest priority (1-10), block rules to medium priority (11-100), and log rules to lowest priority (101+).

## Examples of Common Rules

### Blocking Known Malicious IP Addresses

```
Name: Block Known Attacker
Rule Type: IP
Value: 185.220.101.35
Action: Block
Direction: Inbound
Priority: 50
```

### Allowing Internal Network Access

```
Name: Allow Internal Traffic
Rule Type: IP Range
Value: 10.0.0.0/8
Action: Allow
Direction: Both
Priority: 10
```

### Blocking Access to Sensitive Paths

```
Name: Block Admin Access
Rule Type: Path
Value: /admin/.*
Action: Block
Direction: Inbound
Priority: 20
```

### Blocking by Country

```
Name: Block High-Risk Countries
Rule Type: Country
Value: RU
Action: Block
Direction: Inbound
Priority: 60
```

### Rate Limiting Login Attempts

```
Name: Rate Limit Login
Rule Type: Custom
Value: rate:5:60:/login
Action: Block
Direction: Inbound
Priority: 15
```

## Managing Rules

### Viewing Rules

The main Firewall Rules page displays all configured rules with filtering options:

- Search by rule name or pattern
- Filter by rule type, action, status
- Sort by various fields

### Editing Rules

1. Click on the rule name or the edit icon
2. Modify the rule configuration
3. Click **Save Changes**

### Enabling/Disabling Rules

Toggle the status switch next to a rule to enable or disable it without deleting it.

### Deleting Rules

1. Click the delete icon next to a rule
2. Confirm the deletion in the prompt

### Bulk Operations

1. Select multiple rules using the checkboxes
2. Choose an action from the bulk actions dropdown:
   - Enable Selected
   - Disable Selected
   - Delete Selected

## Rule Testing

ARPF-TI provides tools to test rules before deploying them to production:

1. Navigate to **Threat Intelligence > Test Rules**
2. Enter sample request details:
   - Source IP
   - URL Path
   - HTTP Method
   - User Agent
   - Headers
3. Click **Test Rules**
4. Review the matching rules and final action that would be taken

## Importing and Exporting Rules

### Exporting Rules

1. Navigate to **Threat Intelligence > Firewall Rules**
2. Click the **Import/Export** dropdown
3. Select **Export Rules**
4. Choose the export format (JSON, CSV, YAML)
5. Click **Export**

### Importing Rules

1. Navigate to **Threat Intelligence > Firewall Rules**
2. Click the **Import/Export** dropdown
3. Select **Import Rules**
4. Choose a file to import
5. Select import options (overwrite, skip duplicates)
6. Click **Import**

## AI-Suggested Rules

ARPF-TI can automatically suggest rules based on AI analysis:

1. Navigate to **Threat Intelligence > Suggested Rules**
2. Review suggested rules with their confidence scores
3. Choose to:
   - Apply: Implement the rule as suggested
   - Modify & Apply: Edit the rule before implementing
   - Reject: Dismiss the suggestion

Rules with confidence scores above 90% are automatically applied if configured to do so.

## Best Practices

1. **Start with restrictive rules**: Begin with a strict rule set and add exceptions as needed
2. **Use allow rules sparingly**: Only create explicit allow rules for trusted traffic
3. **Prioritize correctly**: Critical infrastructure protection rules should have highest priority
4. **Document rules**: Use clear names and descriptions for all rules
5. **Test before applying**: Use the rule tester before implementing in production
6. **Review regularly**: Audit rules periodically and remove outdated ones
7. **Monitor false positives**: Track legitimate traffic that gets blocked accidentally

## Advanced Configuration

### Custom Rule Syntax

Custom rules allow complex matching logic:

- `rate:X:Y[:path]`: Rate limiting (X requests per Y seconds, optional path)
- `regex:pattern`: Regular expression matching
- `combo:type1:value1:type2:value2`: Combine multiple conditions
- `script:filename.js`: Use a custom JavaScript rule script

### Using Rule Templates

1. Navigate to **Threat Intelligence > Rule Templates**
2. Select a template
3. Customize the parameters
4. Apply the template

### Integrating with Other Security Tools

ARPF-TI can import rules from:

- ModSecurity rule sets
- Snort/Suricata signatures
- MISP threat intelligence feeds
- Custom APIs

## Troubleshooting

### Rule Not Matching

1. Check the rule priority
2. Verify the rule syntax and pattern
3. Ensure the rule is active
4. Review exact match conditions (case sensitivity, exact patterns)

### Too Many False Positives

1. Make rule patterns more specific
2. Add allow rules for legitimate traffic
3. Use AI-enhanced rule suggestions
4. Consider using log-only mode for monitoring before blocking

### Rule Conflicts

1. Identify rules with conflicting actions
2. Adjust priorities to ensure correct evaluation order
3. Consolidate similar rules
4. Use the rule tester to verify behavior

## Further Reading

- [Installation Guide](installation.md)
- [AI Integration Guide](ai-integration.md)
- [Threat Intelligence Guide](threat-intelligence.md)
- [API Reference](api-reference.md)
