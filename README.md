# Cross-Platform Security Hardening Tool

A comprehensive, automated security hardening tool that applies industry-standard security configurations across Windows and Linux operating systems. The tool implements security baselines from Annexure-A (Windows) and Annexure-B (Linux) with comprehensive reporting, rollback capabilities, and compliance tracking.

## Features

- **Cross-Platform Support**: Windows 10/11, Ubuntu 20.04+, CentOS 7+
- **Automated Hardening**: 350+ security parameters across both platforms
- **Configurable Levels**: Basic, Moderate, and Strict hardening levels
- **Backup & Rollback**: Secure backup and restoration of configurations
- **Comprehensive Reporting**: PDF reports with compliance mapping
- **Dual Interface**: Command-line and optional GUI interfaces
- **Audit Trail**: Tamper-evident logging for all operations

## Quick Start

### Installation

```bash
pip install -r requirements.txt
python setup.py install
```

### Basic Usage

```bash
# Assess current security posture
security-hardening assess --level moderate

# Apply hardening configurations
security-hardening remediate --level moderate --backup

# Rollback to previous configuration
security-hardening rollback --backup-id <backup_id>

# Generate compliance report
security-hardening report --type assessment --output report.pdf
```

## Architecture

The tool follows a modular architecture with platform-specific hardening modules:

- **Core Engine**: Orchestrates operations and manages workflow
- **OS Detection**: Automatic platform and version detection
- **Hardening Modules**: Windows and Linux specific implementations
- **Configuration Management**: Parameter validation and level management
- **Backup System**: Secure backup storage with integrity checking
- **Report Engine**: PDF generation with compliance mapping

## Security Parameters

### Windows (Annexure-A)
- Account Policies (password policy, account lockout)
- Local Policies (user rights assignment)
- Security Options (accounts, interactive logon, network security)
- System Settings (UAC, 26 system services)
- Windows Defender Firewall (22 profile settings)
- Advanced Audit Policy (15 audit configurations)
- Microsoft Defender Application Guard (5 security settings)

### Linux (Annexure-B)
- Filesystem configuration (kernel modules, partition security)
- Package Management (bootloader, process hardening)
- Services (server/client services, time synchronization)
- Network configuration (kernel parameters, security settings)
- Host-Based Firewall (UFW configuration)
- Access Control (SSH hardening, privilege escalation, PAM)
- User Accounts and Environment (shadow password suite)
- Logging and Auditing (systemd-journald, rsyslog, auditd)
- System Maintenance (file permissions, user/group validation)

## Requirements

- Python 3.8+
- Administrator/root privileges for system modifications
- Platform-specific dependencies (see requirements.txt)

## License

MIT License - see LICENSE file for details.

## Contributing

Please read CONTRIBUTING.md for details on our code of conduct and the process for submitting pull requests.

## Support

For support and documentation, please visit our [documentation site](https://docs.example.com) or file an issue on GitHub.