# Installation Guide

This guide covers the complete installation process for the Security Hardening Tool on Windows and Linux systems.

## System Requirements

### Minimum Requirements
- **Python**: 3.8 or higher
- **Memory**: 512 MB RAM
- **Storage**: 100 MB free space
- **Network**: Internet connection for initial setup

### Platform-Specific Requirements

#### Windows
- Windows 10/11 (64-bit recommended)
- Administrator privileges for full functionality
- PowerShell 5.1 or higher

#### Linux
- Ubuntu 20.04+, CentOS 7+, or equivalent
- Root/sudo privileges for system modifications
- Standard development tools (gcc, make)

## Installation Methods

### Method 1: Standard Installation (Recommended)

#### Windows
```powershell
# Open PowerShell as Administrator
# Navigate to project directory
cd C:\path\to\AutoShield

# Install dependencies
pip install -r requirements.txt

# Install the tool
python setup.py install

# Verify installation
security-hardening --help
```

#### Linux
```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Install Python and development tools
sudo apt install python3 python3-pip python3-setuptools python3-dev build-essential -y

# Navigate to project directory
cd /path/to/AutoShield

# Install dependencies
pip3 install -r requirements.txt

# Install the tool
python3 setup.py install

# Verify installation
python3 -m security_hardening_tool.cli.main --help
```

### Method 2: Development Installation

For developers or testing environments:

```bash
# Clone or extract the project
cd /path/to/AutoShield

# Install in development mode
pip install -e .

# Or run directly without installation
pip install -r requirements.txt
python -m security_hardening_tool.cli.main --help
```

### Method 3: Virtual Environment (Recommended for Testing)

```bash
# Create virtual environment
python -m venv security_hardening_env

# Activate virtual environment
# Windows:
security_hardening_env\Scripts\activate
# Linux/Mac:
source security_hardening_env/bin/activate

# Install dependencies
pip install -r requirements.txt

# Install the tool
python setup.py install
```

## Post-Installation Setup

### 1. Verify Installation

```bash
# Test basic functionality
python -m security_hardening_tool.cli.main info

# Test GUI components (if using GUI)
python test_gui.py

# Check system compatibility
python -m security_hardening_tool.cli.main validate
```

### 2. Configure Permissions

#### Windows
- Ensure the tool is run as Administrator for full functionality
- Configure Windows Defender exclusions if needed
- Set up audit policy permissions

#### Linux
- Add user to necessary groups (sudo, adm)
- Configure sudo permissions for specific commands
- Set up audit daemon permissions

### 3. Initial Configuration

```bash
# Create configuration directory
mkdir -p ~/.security_hardening/config

# Copy default configurations
cp security_hardening_tool/config/*.yaml ~/.security_hardening/config/

# Set up logging directory
mkdir -p ~/.security_hardening/logs
```

## Dependency Installation

### Core Dependencies
```bash
pip install click>=8.0.0 pydantic>=1.10.0 pyyaml>=6.0 cryptography>=3.4.8
```

### Reporting Dependencies
```bash
pip install reportlab>=3.6.0 jinja2>=3.0.0
```

### Platform-Specific Dependencies

#### Windows
```bash
pip install pywin32>=227 wmi>=1.5.1
```

#### Linux
```bash
pip install psutil>=5.8.0
```

### Development Dependencies (Optional)
```bash
pip install pytest>=7.0.0 pytest-cov>=4.0.0 black>=22.0.0 flake8>=5.0.0 mypy>=0.991
```

## GUI Installation

### Windows
GUI should work out of the box with standard Python installation.

### Linux
```bash
# Install tkinter for GUI
sudo apt install python3-tk -y

# For remote access (SSH with X11 forwarding)
sudo apt install xauth -y

# Connect with X11 forwarding
ssh -X username@server-ip
```

## Troubleshooting Installation

### Common Issues

#### "setuptools not found" (Linux)
```bash
sudo apt install python3-setuptools
# or
pip install setuptools
```

#### "Permission denied" errors
```bash
# Use sudo for system-wide installation
sudo python setup.py install

# Or use user installation
pip install --user -r requirements.txt
```

#### "Module not found" errors
```bash
# Ensure Python path is correct
export PYTHONPATH="${PYTHONPATH}:/path/to/AutoShield"

# Or reinstall dependencies
pip install --force-reinstall -r requirements.txt
```

#### GUI not working on Linux
```bash
# Install GUI dependencies
sudo apt install python3-tk python3-dev

# Check X11 forwarding
echo $DISPLAY

# Test tkinter
python3 -c "import tkinter; tkinter.Tk()"
```

## Verification Tests

### Basic Functionality Test
```bash
# Test CLI
python -m security_hardening_tool.cli.main --help

# Test system detection
python -m security_hardening_tool.cli.main info

# Test assessment (safe, read-only)
python -m security_hardening_tool.cli.main assess --level basic --quiet
```

### GUI Test
```bash
# Test GUI components
python test_gui.py

# Launch GUI
python -m security_hardening_tool.cli.main gui
```

### Advanced Test
```bash
# Test with custom configuration
python -m security_hardening_tool.cli.main assess --config-file test_config.yaml

# Test batch operations
python -m security_hardening_tool.cli.main batch --config security_hardening_tool/config/batch_example.yaml --output-dir ./test_results
```

## Uninstallation

### Standard Uninstall
```bash
pip uninstall security-hardening-tool
```

### Complete Cleanup
```bash
# Remove installed package
pip uninstall security-hardening-tool

# Remove configuration files
rm -rf ~/.security_hardening/

# Remove logs
rm -rf /var/log/security_hardening/

# Remove any created backups
rm -rf /var/backups/security_hardening/
```

## Next Steps

After successful installation:
1. Read the [Configuration Guide](CONFIGURATION.md)
2. Follow the [User Guide](USER_GUIDE.md) for first-time usage
3. Set up [Automation](AUTOMATION.md) if needed