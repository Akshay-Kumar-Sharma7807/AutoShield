# Configuration Guide

This guide explains how to configure the Security Hardening Tool for your specific environment and requirements.

## Configuration Overview

The tool uses a hierarchical configuration system:

1. **Built-in Parameters**: Default security parameters for each hardening level
2. **Custom Parameters**: User-defined overrides and additions
3. **Runtime Parameters**: Command-line options and GUI selections

## Configuration Files

### Default Configuration Locations

```
security_hardening_tool/config/
├── basic_parameters.yaml      # Basic hardening level
├── moderate_parameters.yaml   # Moderate hardening level
├── strict_parameters.yaml     # Strict hardening level
├── custom_parameters_example.json  # Custom parameter template
└── batch_example.yaml         # Batch operation template
```

### User Configuration Directory

```
~/.security_hardening/
├── custom_parameters.yaml     # User custom parameters
├── batch_configs/            # Batch operation configurations
├── logs/                     # Application logs
└── backups/                  # Configuration backups
```

## Hardening Levels

### Basic Level
- Essential security settings with minimal impact
- Suitable for general-purpose systems
- Low risk of breaking applications

### Moderate Level (Recommended)
- Balanced security and usability
- Recommended for most environments
- Some applications may require adjustment

### Strict Level
- Maximum security settings
- May impact application compatibility
- Recommended for high-security environments

## Custom Parameters

### Creating Custom Parameters

#### YAML Format
```yaml
# custom_parameters.yaml
windows:
  account_policies:
    password_history:
      target_value: 24
      enabled: true
      severity: "high"
      description: "Enforce password history of 24 passwords"
    
    password_max_age:
      target_value: 90
      enabled: true
      severity: "medium"

linux:
  sysctl:
    net.ipv4.ip_forward:
      target_value: 0
      enabled: true
      severity: "high"
      description: "Disable IP forwarding"
    
    kernel.dmesg_restrict:
      target_value: 1
      enabled: true
      severity: "medium"
```

#### JSON Format
```json
{
  "windows": {
    "security_options": {
      "interactive_logon_message_title": {
        "target_value": "Authorized Use Only",
        "enabled": true,
        "severity": "low",
        "description": "Set logon message title"
      }
    }
  },
  "linux": {
    "ssh": {
      "permit_root_login": {
        "target_value": "no",
        "enabled": true,
        "severity": "critical",
        "description": "Disable SSH root login"
      }
    }
  }
}
```

### Parameter Structure

Each parameter must include:

```yaml
parameter_id:
  target_value: <expected_value>    # Required: The desired value
  enabled: <true|false>             # Required: Whether to check/apply this parameter
  severity: <critical|high|medium|low|info>  # Optional: Risk level
  description: <string>             # Optional: Human-readable description
  compliance_frameworks: [<list>]   # Optional: Compliance mappings
  requires_reboot: <true|false>     # Optional: Whether reboot is needed
```

### Loading Custom Parameters

#### Command Line
```bash
# Using custom configuration file
python -m security_hardening_tool.cli.main assess --config-file custom_parameters.yaml

# Multiple configuration files
python -m security_hardening_tool.cli.main assess --config-file config1.yaml --config-file config2.json
```

#### GUI
1. Open the GUI application
2. Navigate to "Parameter Customization" section
3. Click "Load Custom Parameters"
4. Select your configuration file

## Batch Configuration

### Batch Operations File

```yaml
# batch_operations.yaml
metadata:
  name: "Enterprise Security Hardening"
  description: "Multi-stage security assessment and hardening"
  version: "1.0"

operations:
  - name: "Initial_Assessment"
    type: "assess"
    level: "basic"
    description: "Baseline security assessment"
    
  - name: "Moderate_Hardening"
    type: "remediate"
    level: "moderate"
    backup: true
    description: "Apply moderate security hardening"
    parameters:
      windows.account_policies.password_history:
        target_value: 24
        enabled: true
    
  - name: "Post_Hardening_Assessment"
    type: "assess"
    level: "moderate"
    description: "Verify hardening was applied"

settings:
  continue_on_error: true
  output_format: "json"
  create_backups: true
  log_level: "INFO"
```

### Running Batch Operations

```bash
# Execute batch configuration
python -m security_hardening_tool.cli.main batch --config batch_operations.yaml

# With output directory
python -m security_hardening_tool.cli.main batch --config batch_operations.yaml --output-dir ./results

# Quiet mode for automation
python -m security_hardening_tool.cli.main batch --config batch_operations.yaml --quiet
```

## Environment-Specific Configuration

### Development Environment
```yaml
# dev_config.yaml
settings:
  log_level: "DEBUG"
  create_backups: false
  continue_on_error: true

parameters:
  # Relaxed settings for development
  windows.account_policies.password_complexity:
    enabled: false
  linux.ssh.password_authentication:
    enabled: false
```

### Production Environment
```yaml
# prod_config.yaml
settings:
  log_level: "INFO"
  create_backups: true
  continue_on_error: false

parameters:
  # Strict settings for production
  windows.security_options.interactive_logon_message_title:
    target_value: "PRODUCTION SYSTEM - AUTHORIZED ACCESS ONLY"
    enabled: true
    severity: "high"
```

### Testing Environment
```yaml
# test_config.yaml
settings:
  log_level: "DEBUG"
  create_backups: true
  continue_on_error: true
  dry_run: true  # Assessment only, no changes

parameters:
  # Test-specific overrides
  windows.services.test_service:
    target_value: "disabled"
    enabled: true
```

## Compliance Framework Mapping

### Supported Frameworks
- **CIS Controls**: Center for Internet Security
- **NIST**: National Institute of Standards and Technology
- **ISO 27001**: International Organization for Standardization
- **PCI DSS**: Payment Card Industry Data Security Standard
- **HIPAA**: Health Insurance Portability and Accountability Act

### Framework Configuration
```yaml
compliance_mapping:
  cis_controls:
    version: "8.0"
    enabled: true
  nist_csf:
    version: "1.1"
    enabled: true
  iso_27001:
    version: "2013"
    enabled: false

parameters:
  windows.account_policies.password_complexity:
    target_value: true
    compliance_frameworks:
      - "cis_controls:5.2"
      - "nist_csf:PR.AC-1"
      - "iso_27001:A.9.4.3"
```

## Advanced Configuration

### Custom Validation Rules
```yaml
parameters:
  custom_parameter:
    target_value: 30
    validation_rules:
      - rule_type: "range"
        rule_value: [1, 365]
        error_message: "Value must be between 1 and 365"
      - rule_type: "regex"
        rule_value: "^[0-9]+$"
        error_message: "Value must be numeric"
```

### Conditional Parameters
```yaml
parameters:
  windows.services.spooler:
    target_value: "disabled"
    enabled: true
    conditions:
      - type: "os_version"
        operator: "gte"
        value: "10.0"
      - type: "role"
        operator: "not_equals"
        value: "print_server"
```

### Parameter Dependencies
```yaml
parameters:
  parent_parameter:
    target_value: true
    enabled: true
    
  dependent_parameter:
    target_value: "secure_value"
    enabled: true
    depends_on:
      - parameter: "parent_parameter"
        condition: "equals"
        value: true
```

## Configuration Validation

### Validate Configuration Files
```bash
# Validate custom parameters
python -m security_hardening_tool.cli.main validate --config-file custom_parameters.yaml

# Validate batch configuration
python -m security_hardening_tool.cli.main validate --batch-config batch_operations.yaml

# Validate system readiness
python -m security_hardening_tool.cli.main validate --system
```

### Configuration Testing
```bash
# Dry run with custom configuration
python -m security_hardening_tool.cli.main assess --config-file custom_parameters.yaml --dry-run

# Test batch operations without execution
python -m security_hardening_tool.cli.main batch --config batch_operations.yaml --dry-run
```

## Best Practices

### 1. Configuration Management
- Version control your configuration files
- Use descriptive names and comments
- Test configurations in non-production environments first
- Maintain separate configurations for different environments

### 2. Parameter Selection
- Start with basic level and gradually increase
- Review each parameter's impact before enabling
- Consider application compatibility
- Document any custom parameters

### 3. Backup Strategy
- Always create backups before applying changes
- Test backup restoration procedures
- Maintain multiple backup versions
- Store backups securely

### 4. Monitoring and Validation
- Regularly validate configuration compliance
- Monitor system behavior after changes
- Set up automated compliance checking
- Review and update configurations periodically

## Troubleshooting Configuration

### Common Issues

#### 1. Invalid Parameter Values
```bash
# Check parameter validation
python -m security_hardening_tool.cli.main validate --config-file config.yaml --verbose
```

#### 2. Conflicting Parameters
```bash
# Review parameter conflicts
python -m security_hardening_tool.cli.main assess --config-file config.yaml --check-conflicts
```

#### 3. Missing Dependencies
```bash
# Check parameter dependencies
python -m security_hardening_tool.cli.main validate --dependencies
```

### Configuration Debugging
```bash
# Enable debug logging
python -m security_hardening_tool.cli.main --log-level DEBUG assess --config-file config.yaml

# Export effective configuration
python -m security_hardening_tool.cli.main config --export --output effective_config.yaml
```

## Next Steps

After configuring the tool:
1. Review the [User Guide](USER_GUIDE.md) for operation procedures
2. Explore [Automation options](AUTOMATION.md) for advanced workflows
3. Check [Troubleshooting](TROUBLESHOOTING.md) for common issues