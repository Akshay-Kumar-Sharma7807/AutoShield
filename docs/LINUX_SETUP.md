# Linux Setup Guide

This guide provides detailed instructions for setting up the Security Hardening Tool on various Linux distributions.

## Prerequisites

### System Requirements
- Linux distribution: Ubuntu 18.04+, CentOS 7+, Debian 9+, Fedora 30+
- Python 3.8 or higher
- Root/sudo privileges for system modifications
- At least 1GB free disk space

### Check Python Version
```bash
python3 --version
# Should show Python 3.8.0 or higher
```

## Installation by Distribution

### Ubuntu/Debian
```bash
# Update package list
sudo apt update

# Install Python and development tools
sudo apt install python3 python3-pip python3-setuptools python3-dev python3-tk -y

# Install build tools
sudo apt install build-essential -y

# Install additional dependencies
sudo apt install git curl wget -y
```

### CentOS/RHEL 7/8
```bash
# Enable EPEL repository (if not already enabled)
sudo yum install epel-release -y

# Install Python and development tools
sudo yum install python3 python3-pip python3-setuptools python3-devel python3-tkinter -y

# Install build tools
sudo yum groupinstall "Development Tools" -y
```

### Fedora
```bash
# Install Python and development tools
sudo dnf install python3 python3-pip python3-setuptools python3-devel python3-tkinter -y

# Install build tools
sudo dnf groupinstall "Development Tools" -y
```

### Arch Linux
```bash
# Install Python and development tools
sudo pacman -S python python-pip python-setuptools python-tkinter base-devel
```

## Tool Installation

### Method 1: Standard Installation
```bash
# Clone or download the project
cd /path/to/AutoShield

# Install Python dependencies
pip3 install -r requirements.txt

# Install the tool
python3 setup.py install

# Verify installation
python3 -m security_hardening_tool.cli.main --help
```

### Method 2: Development Installation
```bash
# Install in development mode (recommended for testing)
pip3 install -e .

# Or install dependencies only
pip3 install -r requirements.txt
```

### Method 3: Virtual Environment (Recommended)
```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Install the tool
python setup.py install
```

## Common Issues and Solutions

### Issue 1: setuptools Not Found
```bash
# Error: ModuleNotFoundError: No module named 'setuptools'
# Solution:
pip3 install setuptools wheel
```

### Issue 2: Permission Denied
```bash
# Error: Permission denied when installing
# Solution 1: Use --user flag
pip3 install --user -r requirements.txt

# Solution 2: Use virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Issue 3: tkinter Not Available
```bash
# Error: No module named '_tkinter'
# Ubuntu/Debian:
sudo apt install python3-tk

# CentOS/RHEL:
sudo yum install python3-tkinter

# Fedora:
sudo dnf install python3-tkinter
```

### Issue 4: Build Tools Missing
```bash
# Error: Microsoft Visual C++ 14.0 is required (on WSL)
# Or: error: gcc not found
# Ubuntu/Debian:
sudo apt install build-essential python3-dev

# CentOS/RHEL:
sudo yum groupinstall "Development Tools"
sudo yum install python3-devel
```

### Issue 5: SSL Certificate Issues
```bash
# Error: SSL certificate verify failed
# Solution:
pip3 install --trusted-host pypi.org --trusted-host pypi.python.org --trusted-host files.pythonhosted.org -r requirements.txt
```

## Testing the Installation

### Basic Tests
```bash
# Test component imports
python3 test_gui.py

# Test system information
python3 -m security_hardening_tool.cli.main info

# Test assessment (safe, read-only)
python3 -m security_hardening_tool.cli.main assess --level basic
```

### GUI Testing
```bash
# Test GUI dependencies
python3 -c "import tkinter; print('tkinter available')"

# Launch GUI (requires X11 forwarding if using SSH)
python3 -m security_hardening_tool.cli.main gui
```

### SSH with X11 Forwarding
```bash
# Connect with X11 forwarding enabled
ssh -X username@server-ip

# Test X11 forwarding
xclock  # Should open a clock window

# Launch the GUI
python3 -m security_hardening_tool.cli.main gui
```

## Running with Privileges

### For Full Functionality
```bash
# Run with sudo for system modifications
sudo python3 -m security_hardening_tool.cli.main assess --level moderate

# Run hardening with backup
sudo python3 -m security_hardening_tool.cli.main remediate --level basic --backup
```

### Security Considerations
- Always review changes before applying hardening
- Create backups before making system modifications
- Test in a virtual machine first
- Use the assessment mode to understand what will be changed

## Troubleshooting Commands

### Check Dependencies
```bash
# Check Python version
python3 --version

# Check pip version
pip3 --version

# List installed packages
pip3 list

# Check specific package
pip3 show pyyaml
```

### System Information
```bash
# Check OS version
cat /etc/os-release

# Check available space
df -h

# Check memory
free -h

# Check Python path
which python3
```

### Log Files
```bash
# Check application logs
ls -la ~/.security_hardening/logs/

# View recent logs
tail -f ~/.security_hardening/logs/application.log
```

## Performance Optimization

### For Large Systems
```bash
# Increase timeout for slow systems
export HARDENING_TIMEOUT=300

# Run with verbose output
python3 -m security_hardening_tool.cli.main -v assess --level basic
```

### Memory Usage
```bash
# Monitor memory usage during assessment
top -p $(pgrep -f security_hardening)

# Run with limited memory
ulimit -v 1048576  # Limit to 1GB virtual memory
```

## Uninstallation

### Remove Installed Package
```bash
# If installed with setup.py
pip3 uninstall security-hardening-tool

# Remove configuration files
rm -rf ~/.security_hardening/

# Remove logs
rm -rf ~/.security_hardening/logs/
```

### Clean Virtual Environment
```bash
# Deactivate and remove virtual environment
deactivate
rm -rf venv/
```

## Getting Help

### Command Help
```bash
# General help
python3 -m security_hardening_tool.cli.main --help

# Command-specific help
python3 -m security_hardening_tool.cli.main assess --help
```

### Debug Mode
```bash
# Run with debug output
python3 -m security_hardening_tool.cli.main -v --log-level DEBUG assess --level basic
```

### Report Issues
When reporting issues, include:
- Linux distribution and version
- Python version
- Complete error message
- Steps to reproduce
- Output of `python3 -m security_hardening_tool.cli.main info`