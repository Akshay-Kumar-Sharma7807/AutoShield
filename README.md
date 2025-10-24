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

## Screenshots

### GUI Interface
The tool provides an intuitive graphical user interface for easy security assessment and hardening:

#### Main Dashboard
![Main Interface](images/Screenshot%202025-10-24%20193114.png)
*Main GUI interface showing system information, hardening level selection, and assessment configuration options*

#### Assessment Results
![Assessment Results](images/Screenshot%202025-10-24%20193127.png)
*Security assessment results displaying compliance status, severity levels, and risk descriptions for each parameter*

#### Parameter Details
![Detailed View](images/Screenshot%202025-10-24%20193151.png)
*Detailed parameter view showing current vs expected values with remediation recommendations*

#### Configuration Management
![Configuration Options](images/Screenshot%202025-10-24%20193202.png)
*Hardening level selection and custom parameter configuration interface*

## Quick Start

### Installation

#### Automated Installation

**Linux/macOS:**
```bash
# Make script executable (Linux/macOS only)
chmod +x install_linux.sh

# Run installation script
./install_linux.sh

# Or with virtual environment
./install_linux.sh --venv
```

**Windows:**
```cmd
# Run as Administrator for full functionality
install_windows.bat
```

#### Manual Installation

```bash
# Install dependencies
pip install -r requirements.txt

# Install the tool
python setup.py install
```

#### Virtual Environment (Recommended)

```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# Linux/macOS:
source venv/bin/activate
# Windows:
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
python setup.py install
```

### GUI Usage

```bash
# Launch the graphical interface
python -m security_hardening_tool.cli.main gui
```

### Command Line Usage

```bash
# Assess current security posture
python -m security_hardening_tool.cli.main assess --level moderate

# Apply hardening configurations
python -m security_hardening_tool.cli.main remediate --level moderate --backup

# Rollback to previous configuration
python -m security_hardening_tool.cli.main rollback --backup-id <backup_id>

# Generate compliance report
python -m security_hardening_tool.cli.main report --type assessment --output report.pdf
```

## Architecture

The tool follows a modular architecture with platform-specific hardening modules:

- **Core Engine**: Orchestrates operations and manages workflow
- **OS Detection**: Automatic platform and version detection
- **Hardening Modules**: Windows and Linux specific implementations
- **Configuration Management**: Parameter validation and level management
- **Backup System**: Secure backup storage with integrity checking
- **Report Engine**: PDF generation with compliance mapping

## User Interfaces

### Graphical User Interface (GUI)
The GUI provides an intuitive interface for security professionals and system administrators:

- **System Information Panel**: Displays detected OS, version, and system details
- **Assessment Configuration**: Select hardening levels (Basic, Moderate, Strict)
- **Real-time Results**: View assessment results with compliance status
- **Parameter Details**: Detailed view of security parameters and recommendations
- **Progress Tracking**: Visual progress indicators for long-running operations
- **Export Capabilities**: Generate PDF reports and export configurations

### Command Line Interface (CLI)
Full-featured CLI for automation and scripting:

- **Batch Operations**: Execute multiple assessments and hardening tasks
- **JSON/XML Output**: Machine-readable output for integration
- **Custom Parameters**: Load custom security configurations
- **Audit Trail**: Comprehensive logging and audit capabilities

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

## Getting Started

### Prerequisites
- Python 3.8+
- Administrator/root privileges for system modifications
- Platform-specific dependencies (see requirements.txt)

### First Run
1. **Install dependencies**: `pip install -r requirements.txt`
2. **Install the tool**: `python setup.py install`
3. **Launch GUI**: `python -m security_hardening_tool.cli.main gui`
4. **Run assessment**: Select hardening level and click "Run Assessment"

### Permission Requirements
- **Windows**: Run as Administrator for full functionality
- **Linux**: Run with sudo privileges for system modifications
- **Limited Mode**: GUI works without admin rights for demonstration

### Testing the Tool
```bash
# Test GUI components
python test_gui.py

# Test system information
python -m security_hardening_tool.cli.main info

# Safe assessment (read-only)
python -m security_hardening_tool.cli.main assess --level basic
```

## Troubleshooting

### Common Issues

#### Linux: "No module named 'setuptools'"
```bash
# Install setuptools
pip3 install setuptools

# Or use system package manager
sudo apt install python3-setuptools  # Ubuntu/Debian
sudo yum install python3-setuptools  # CentOS/RHEL
```

#### GUI Not Working
```bash
# Install tkinter
sudo apt install python3-tk  # Ubuntu/Debian
sudo yum install python3-tkinter  # CentOS/RHEL

# For SSH connections, use X11 forwarding
ssh -X username@hostname
```

#### Permission Errors
```bash
# Windows: Run as Administrator
# Linux: Use sudo for system modifications
sudo python3 -m security_hardening_tool.cli.main assess --level basic
```

#### "No hardening modules available"
This is normal when running without administrator/root privileges. The tool will show a warning but continue in demonstration mode.

For detailed troubleshooting, see [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md)

## License

MIT License - see LICENSE file for details.

## Contributing

Please read CONTRIBUTING.md for details on our code of conduct and the process for submitting pull requests.

## Support

For support and documentation, please visit our [documentation site](https://docs.example.com) or file an issue on GitHub.