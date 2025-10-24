# User Guide

This comprehensive guide covers how to use the Security Hardening Tool for both GUI and command-line interfaces.

## Table of Contents

1. [First Run](#first-run)
2. [GUI Interface](#gui-interface)
3. [Command Line Interface](#command-line-interface)
4. [Security Assessments](#security-assessments)
5. [Hardening Operations](#hardening-operations)
6. [Backup and Rollback](#backup-and-rollback)
7. [Reporting](#reporting)
8. [Best Practices](#best-practices)

## First Run

### System Requirements Check
```bash
# Check system compatibility
python -m security_hardening_tool.cli.main info

# Validate system readiness
python -m security_hardening_tool.cli.main validate

# Test basic functionality
python test_gui.py
```

### Initial Setup
1. **Run as Administrator/Root**: For full functionality
2. **Check Permissions**: Ensure proper access rights
3. **Verify Installation**: Test basic commands
4. **Review Default Settings**: Understand default configurations

## GUI Interface

### Launching the GUI
```bash
# Standard launch
python -m security_hardening_tool.cli.main gui

# With specific log level
python -m security_hardening_tool.cli.main --log-level DEBUG gui
```

### GUI Components

#### 1. System Information Panel
- **OS Detection**: Automatically detects platform and version
- **System Details**: Shows hostname, architecture, and build information
- **Module Status**: Indicates which hardening modules are available

#### 2. Assessment Configuration
- **Hardening Level Selection**: Choose Basic, Moderate, or Strict
- **Custom Parameters**: Load and configure custom parameter files
- **Assessment Options**: Configure assessment scope and options

#### 3. Assessment Results
- **Parameter List**: Shows all assessed security parameters
- **Compliance Status**: Visual indicators for compliant/non-compliant items
- **Severity Levels**: Color-coded severity indicators
- **Details View**: Detailed information for each parameter

#### 4. Hardening Operations
- **Apply Hardening**: Execute hardening configurations
- **Backup Options**: Configure backup creation
- **Progress Tracking**: Real-time progress indicators
- **Results Summary**: Summary of applied changes

### GUI Workflow

#### Running an Assessment
1. **Launch GUI**: Start the application
2. **Select Level**: Choose appropriate hardening level
3. **Load Custom Parameters** (Optional): Add custom configurations
4. **Run Assessment**: Click "Run Assessment" button
5. **Review Results**: Examine compliance status and recommendations
6. **Export Results** (Optional): Generate reports

#### Applying Hardening
1. **Complete Assessment**: Run assessment first
2. **Review Changes**: Understand what will be modified
3. **Create Backup**: Ensure backup option is enabled
4. **Apply Hardening**: Click "Apply Hardening" button
5. **Monitor Progress**: Watch real-time progress
6. **Verify Results**: Review applied changes

## Command Line Interface

### Basic Commands

#### Help and Information
```bash
# Show main help
python -m security_hardening_tool.cli.main --help

# Show command-specific help
python -m security_hardening_tool.cli.main assess --help
python -m security_hardening_tool.cli.main remediate --help

# Display system information
python -m security_hardening_tool.cli.main info

# Show automation capabilities
python -m security_hardening_tool.cli.main automation
```

#### Assessment Commands
```bash
# Basic assessment
python -m security_hardening_tool.cli.main assess --level basic

# Assessment with custom parameters
python -m security_hardening_tool.cli.main assess --level moderate --config-file custom.yaml

# Assessment with JSON output
python -m security_hardening_tool.cli.main assess --level strict --format json --output assessment.json

# Quiet assessment (minimal output)
python -m security_hardening_tool.cli.main assess --level basic --quiet
```

#### Hardening Commands
```bash
# Apply hardening with backup
python -m security_hardening_tool.cli.main remediate --level moderate --backup

# Apply hardening without confirmation (automation)
python -m security_hardening_tool.cli.main remediate --level basic --yes

# Apply hardening with custom parameters
python -m security_hardening_tool.cli.main remediate --level strict --config-file custom.yaml --backup

# Apply hardening with JSON output
python -m security_hardening_tool.cli.main remediate --level moderate --format json --output hardening.json
```

## Security Assessments

### Assessment Types

#### 1. Basic Assessment
- **Purpose**: Quick security check
- **Scope**: Essential security parameters
- **Time**: 2-5 minutes
- **Impact**: Read-only, no system changes

```bash
python -m security_hardening_tool.cli.main assess --level basic
```

#### 2. Moderate Assessment
- **Purpose**: Comprehensive security evaluation
- **Scope**: Balanced security parameters
- **Time**: 5-15 minutes
- **Impact**: Read-only, no system changes

```bash
python -m security_hardening_tool.cli.main assess --level moderate --verbose
```

#### 3. Strict Assessment
- **Purpose**: Maximum security evaluation
- **Scope**: All available security parameters
- **Time**: 10-30 minutes
- **Impact**: Read-only, no system changes

```bash
python -m security_hardening_tool.cli.main assess --level strict --output detailed_assessment.json
```

### Assessment Results

#### Understanding Results
- **✅ Compliant**: Parameter meets security requirements
- **❌ Non-Compliant**: Parameter needs attention
- **⚠️ Warning**: Parameter has issues but not critical
- **ℹ️ Info**: Informational parameter

#### Severity Levels
- **Critical**: Immediate security risk
- **High**: Significant security concern
- **Medium**: Moderate security issue
- **Low**: Minor security improvement
- **Info**: Informational only

#### Result Formats

##### Text Output (Default)
```
Assessment Results (45 parameters checked):
------------------------------------------------------------
✓ COMPLIANT [HIGH] windows.account_policies.password_complexity
✗ NON-COMPLIANT [CRITICAL] windows.account_policies.password_min_length
  Current: 8
  Expected: 14
  Risk: Weak passwords increase breach risk
```

##### JSON Output
```json
{
  "metadata": {
    "operation": "assessment",
    "timestamp": "2024-10-24T19:31:14.123456",
    "total_items": 45
  },
  "results": [
    {
      "parameter_id": "windows.account_policies.password_complexity",
      "current_value": true,
      "expected_value": true,
      "compliant": true,
      "severity": "high"
    }
  ],
  "summary": {
    "total_parameters": 45,
    "compliant_parameters": 38,
    "compliance_percentage": 84.4
  }
}
```

## Hardening Operations

### Pre-Hardening Checklist
1. **Run Assessment**: Understand current state
2. **Review Changes**: Know what will be modified
3. **Create Backup**: Always backup before changes
4. **Test Environment**: Test in non-production first
5. **Plan Rollback**: Have rollback procedure ready

### Hardening Workflow

#### 1. Assessment Phase
```bash
# Assess current state
python -m security_hardening_tool.cli.main assess --level moderate --output pre_hardening.json
```

#### 2. Planning Phase
```bash
# Review what will be changed (dry run)
python -m security_hardening_tool.cli.main remediate --level moderate --dry-run
```

#### 3. Backup Phase
```bash
# Create manual backup
python -m security_hardening_tool.cli.main backup --create --description "Pre-hardening backup"
```

#### 4. Hardening Phase
```bash
# Apply hardening
python -m security_hardening_tool.cli.main remediate --level moderate --backup --output hardening_results.json
```

#### 5. Verification Phase
```bash
# Verify changes were applied
python -m security_hardening_tool.cli.main assess --level moderate --output post_hardening.json
```

### Hardening Results

#### Success Indicators
- **✅ SUCCESS**: Parameter was successfully modified
- **❌ FAILED**: Parameter modification failed
- **⚠️ PARTIAL**: Parameter partially modified
- **🔄 REBOOT REQUIRED**: System reboot needed

#### Example Output
```
Hardening Results (42 parameters processed):
------------------------------------------------------------
✓ SUCCESS windows.account_policies.password_min_length
  Previous: 8
  Applied: 14
✗ FAILED windows.services.telnet
  Error: Service not found
🔄 SUCCESS windows.security_options.uac_admin_approval_mode
  Previous: false
  Applied: true
  Requires Reboot: Yes
```

## Backup and Rollback

### Backup Management

#### Creating Backups
```bash
# Automatic backup during hardening
python -m security_hardening_tool.cli.main remediate --level moderate --backup

# Manual backup creation
python -m security_hardening_tool.cli.main backup --create --description "Monthly backup"

# Backup with custom location
python -m security_hardening_tool.cli.main backup --create --path /custom/backup/path
```

#### Listing Backups
```bash
# List all backups
python -m security_hardening_tool.cli.main backups

# List backups with details
python -m security_hardening_tool.cli.main backups --verbose

# List backups in JSON format
python -m security_hardening_tool.cli.main backups --format json
```

#### Backup Information
```
Available Backups:
------------------------------------------------------------
ID: backup_20241024_193114
Date: 2024-10-24 19:31:14
OS: Windows 11 (Build 22000)
Parameters: 42
Description: Pre-moderate-hardening backup
Size: 2.3 MB
Integrity: ✓ Verified
```

### Rollback Operations

#### Rolling Back Changes
```bash
# Rollback to specific backup
python -m security_hardening_tool.cli.main rollback --backup-id backup_20241024_193114

# Rollback with confirmation
python -m security_hardening_tool.cli.main rollback --backup-id backup_20241024_193114 --confirm

# Rollback specific parameters only
python -m security_hardening_tool.cli.main rollback --backup-id backup_20241024_193114 --parameters "windows.account_policies.*"
```

#### Rollback Results
```
Rollback Results:
------------------------------------------------------------
Backup ID: backup_20241024_193114
Restored Parameters: 38/42
Success Rate: 90.5%

✓ SUCCESS windows.account_policies.password_min_length
  Restored: 8 (from 14)
✗ FAILED windows.services.custom_service
  Error: Service configuration locked
```

## Reporting

### Report Types

#### 1. Assessment Reports
```bash
# Generate PDF assessment report
python -m security_hardening_tool.cli.main report --type assessment --output assessment_report.pdf

# Generate HTML report
python -m security_hardening_tool.cli.main report --type assessment --format html --output report.html

# Generate compliance report
python -m security_hardening_tool.cli.main report --type compliance --framework CIS --output compliance_report.pdf
```

#### 2. Hardening Reports
```bash
# Generate hardening summary report
python -m security_hardening_tool.cli.main report --type hardening --output hardening_report.pdf

# Generate detailed hardening report
python -m security_hardening_tool.cli.main report --type hardening --detailed --output detailed_hardening.pdf
```

#### 3. Compliance Reports
```bash
# CIS compliance report
python -m security_hardening_tool.cli.main report --type compliance --framework CIS --output cis_compliance.pdf

# NIST compliance report
python -m security_hardening_tool.cli.main report --type compliance --framework NIST --output nist_compliance.pdf

# Multiple frameworks
python -m security_hardening_tool.cli.main report --type compliance --framework CIS,NIST --output multi_compliance.pdf
```

### Report Customization

#### Custom Report Templates
```bash
# Use custom template
python -m security_hardening_tool.cli.main report --type assessment --template custom_template.html --output custom_report.pdf

# Include specific sections
python -m security_hardening_tool.cli.main report --type assessment --sections summary,details,recommendations --output focused_report.pdf
```

#### Report Scheduling
```bash
# Generate weekly reports (cron job example)
0 9 * * 1 /usr/bin/python3 -m security_hardening_tool.cli.main assess --level moderate --format json --output /reports/weekly_$(date +\%Y\%m\%d).json
```

## Best Practices

### 1. Assessment Best Practices

#### Regular Assessments
- **Weekly**: Basic assessments for monitoring
- **Monthly**: Moderate assessments for compliance
- **Quarterly**: Strict assessments for comprehensive review

#### Assessment Strategy
```bash
# Baseline assessment
python -m security_hardening_tool.cli.main assess --level basic --output baseline.json

# Trend analysis
python -m security_hardening_tool.cli.main assess --level moderate --output monthly_$(date +%Y%m).json

# Compliance checking
python -m security_hardening_tool.cli.main assess --level strict --format json | jq '.summary.compliance_percentage'
```

### 2. Hardening Best Practices

#### Phased Approach
1. **Phase 1**: Basic hardening (low risk)
2. **Phase 2**: Moderate hardening (test applications)
3. **Phase 3**: Strict hardening (high-security environments)

#### Testing Strategy
```bash
# Test in development
python -m security_hardening_tool.cli.main remediate --level basic --dry-run

# Apply to staging
python -m security_hardening_tool.cli.main remediate --level basic --backup

# Verify in staging
python -m security_hardening_tool.cli.main assess --level basic

# Deploy to production
python -m security_hardening_tool.cli.main remediate --level basic --backup --yes
```

### 3. Backup Best Practices

#### Backup Strategy
- **Before Hardening**: Always create backups
- **Regular Backups**: Weekly configuration backups
- **Retention Policy**: Keep backups for 90 days
- **Verification**: Regularly verify backup integrity

#### Backup Automation
```bash
# Daily backup script
#!/bin/bash
BACKUP_ID=$(python -m security_hardening_tool.cli.main backup --create --description "Daily backup $(date)" --format json | jq -r '.backup_id')
echo "Created backup: $BACKUP_ID"

# Cleanup old backups (keep last 10)
python -m security_hardening_tool.cli.main backups --cleanup --keep 10
```

### 4. Monitoring and Maintenance

#### Continuous Monitoring
```bash
# Monitor compliance drift
python -m security_hardening_tool.cli.main assess --level moderate --format json | jq '.summary.compliance_percentage < 90'

# Alert on critical findings
python -m security_hardening_tool.cli.main assess --level basic --format json | jq '.results[] | select(.severity == "critical" and .compliant == false)'
```

#### Maintenance Schedule
- **Daily**: Automated assessments
- **Weekly**: Review assessment results
- **Monthly**: Apply hardening updates
- **Quarterly**: Full security review

## Troubleshooting

### Common Issues

#### 1. Permission Errors
```bash
# Windows: Run as Administrator
# Linux: Use sudo
sudo python -m security_hardening_tool.cli.main assess --level basic
```

#### 2. Module Not Available
```bash
# Check available modules
python -m security_hardening_tool.cli.main info

# Validate system compatibility
python -m security_hardening_tool.cli.main validate
```

#### 3. Configuration Errors
```bash
# Validate configuration
python -m security_hardening_tool.cli.main validate --config-file custom.yaml

# Debug configuration loading
python -m security_hardening_tool.cli.main --log-level DEBUG assess --config-file custom.yaml
```

### Getting Help

#### Debug Information
```bash
# Enable verbose logging
python -m security_hardening_tool.cli.main --verbose assess --level basic

# Generate debug report
python -m security_hardening_tool.cli.main info --debug --output debug_info.txt
```

#### Support Resources
- Check [Troubleshooting Guide](TROUBLESHOOTING.md)
- Review [Configuration Guide](CONFIGURATION.md)
- File issues on GitHub with debug information

## Next Steps

After mastering the basic usage:
1. Explore [Automation capabilities](AUTOMATION.md)
2. Set up [Advanced Configuration](CONFIGURATION.md)
3. Implement [Enterprise Deployment](AUTOMATION.md#enterprise-deployment)