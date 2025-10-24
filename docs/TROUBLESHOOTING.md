# Troubleshooting Guide

This guide helps resolve common issues when using the Security Hardening Tool.

## Common Installation Issues

### 1. ModuleNotFoundError: No module named 'setuptools'

**Problem**: setuptools is not installed
```
Traceback (most recent call last):
  File "setup.py", line 3, in <module>
    from setuptools import setup, find_packages
ModuleNotFoundError: No module named 'setuptools'
```

**Solutions**:
```bash
# Option 1: Install setuptools
pip3 install setuptools

# Option 2: Install with system package manager
# Ubuntu/Debian:
sudo apt install python3-setuptools

# CentOS/RHEL:
sudo yum install python3-setuptools

# Option 3: Skip setup.py installation
pip3 install -r requirements.txt
python3 -m security_hardening_tool.cli.main --help
```

### 2. Permission Denied Errors

**Problem**: Insufficient permissions during installation
```
ERROR: Could not install packages due to an EnvironmentError: [Errno 13] Permission denied
```

**Solutions**:
```bash
# Option 1: Install for current user only
pip3 install --user -r requirements.txt

# Option 2: Use virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Option 3: Use sudo (not recommended)
sudo pip3 install -r requirements.txt
```

### 3. tkinter Not Available

**Problem**: GUI dependencies missing
```
ModuleNotFoundError: No module named '_tkinter'
```

**Solutions**:
```bash
# Ubuntu/Debian:
sudo apt install python3-tk

# CentOS/RHEL:
sudo yum install python3-tkinter

# Fedora:
sudo dnf install python3-tkinter

# Test tkinter:
python3 -c "import tkinter; print('tkinter works')"
```

## Runtime Issues

### 4. "Object of type ValidationResult is not JSON serializable"

**Problem**: JSON serialization error in assessment results

**Solution**: This should be fixed in the latest version. If you still see this error:
```bash
# Update to latest version
git pull origin main
python3 setup.py install --force
```

### 5. "No hardening modules are available"

**Problem**: Platform modules failed to load due to insufficient privileges

**Solutions**:
```bash
# Windows: Run as Administrator
# Right-click Command Prompt -> "Run as administrator"

# Linux: Run with sudo
sudo python3 -m security_hardening_tool.cli.main assess --level basic

# Check what modules are registered:
python3 -m security_hardening_tool.cli.main info
```

### 6. GUI Doesn't Launch

**Problem**: GUI fails to start

**Diagnostic Steps**:
```bash
# Test GUI components
python3 test_gui.py

# Check X11 forwarding (if using SSH)
echo $DISPLAY
xclock  # Should open a window

# Test tkinter directly
python3 -c "import tkinter; root = tkinter.Tk(); root.mainloop()"
```

**Solutions**:
```bash
# For SSH connections:
ssh -X username@hostname

# For WSL:
# Install VcXsrv or similar X server on Windows
export DISPLAY=:0

# For headless servers:
# Use CLI instead of GUI
python3 -m security_hardening_tool.cli.main assess --level basic
```

### 7. Assessment Fails with Permission Errors

**Problem**: Cannot read system configuration

**Windows Solutions**:
```cmd
# Run as Administrator
# Right-click Command Prompt -> "Run as administrator"
python -m security_hardening_tool.cli.main assess --level basic
```

**Linux Solutions**:
```bash
# Run with sudo
sudo python3 -m security_hardening_tool.cli.main assess --level basic

# Check file permissions
ls -la /etc/passwd /etc/shadow /etc/ssh/sshd_config
```

### 8. Slow Performance

**Problem**: Assessment takes too long

**Solutions**:
```bash
# Run with basic level first
python3 -m security_hardening_tool.cli.main assess --level basic

# Use verbose mode to see progress
python3 -m security_hardening_tool.cli.main -v assess --level basic

# Check system resources
top
df -h
free -h
```

## Network and Connectivity Issues

### 9. SSL Certificate Errors

**Problem**: Cannot download packages due to SSL issues
```
SSL: CERTIFICATE_VERIFY_FAILED
```

**Solutions**:
```bash
# Temporary workaround (not recommended for production)
pip3 install --trusted-host pypi.org --trusted-host pypi.python.org --trusted-host files.pythonhosted.org -r requirements.txt

# Better solution: Update certificates
# Ubuntu/Debian:
sudo apt update && sudo apt install ca-certificates

# CentOS/RHEL:
sudo yum update ca-certificates
```

### 10. Proxy Issues

**Problem**: Cannot connect through corporate proxy

**Solutions**:
```bash
# Set proxy environment variables
export http_proxy=http://proxy.company.com:8080
export https_proxy=http://proxy.company.com:8080

# Install with proxy
pip3 install --proxy http://proxy.company.com:8080 -r requirements.txt
```

## Configuration Issues

### 11. Invalid Configuration File

**Problem**: Custom configuration file causes errors

**Solutions**:
```bash
# Validate YAML syntax
python3 -c "import yaml; yaml.safe_load(open('config.yaml'))"

# Use example configuration
cp security_hardening_tool/config/custom_parameters_example.json my_config.json

# Test with basic configuration
python3 -m security_hardening_tool.cli.main assess --level basic
```

### 12. Log File Permissions

**Problem**: Cannot write to log directory

**Solutions**:
```bash
# Check log directory permissions
ls -la ~/.security_hardening/

# Create log directory manually
mkdir -p ~/.security_hardening/logs
chmod 755 ~/.security_hardening/logs

# Use alternative log location
export HARDENING_LOG_DIR=/tmp/hardening_logs
```

## Platform-Specific Issues

### Windows Issues

#### 13. PowerShell Execution Policy
```powershell
# Check current policy
Get-ExecutionPolicy

# Set policy (run as Administrator)
Set-ExecutionPolicy RemoteSigned
```

#### 14. Windows Defender Blocking
- Add tool directory to Windows Defender exclusions
- Temporarily disable real-time protection for testing

### Linux Issues

#### 15. SELinux Blocking Operations
```bash
# Check SELinux status
sestatus

# Temporarily disable (not recommended for production)
sudo setenforce 0

# Check audit logs
sudo ausearch -m avc -ts recent
```

#### 16. AppArmor Restrictions
```bash
# Check AppArmor status
sudo apparmor_status

# Check for denials
sudo dmesg | grep -i apparmor
```

## Debugging Commands

### System Information
```bash
# Get detailed system info
python3 -m security_hardening_tool.cli.main info

# Check Python environment
python3 -c "import sys; print(sys.path)"
python3 -c "import sys; print(sys.version)"

# Check installed packages
pip3 list | grep -E "(pyyaml|click|pydantic|reportlab)"
```

### Verbose Logging
```bash
# Enable debug logging
python3 -m security_hardening_tool.cli.main -v --log-level DEBUG assess --level basic

# Check log files
tail -f ~/.security_hardening/logs/application.log
tail -f ~/.security_hardening/logs/audit.log
```

### Test Individual Components
```bash
# Test OS detection
python3 -c "from security_hardening_tool.core.os_detector import OSDetector; print(OSDetector().get_system_info())"

# Test configuration loading
python3 -c "from security_hardening_tool.core.config_manager import ConfigurationManager; cm = ConfigurationManager(); print(cm.load_parameters('basic'))"
```

## Getting Help

### Before Reporting Issues

1. **Check the logs**:
   ```bash
   ls -la ~/.security_hardening/logs/
   tail -20 ~/.security_hardening/logs/error.log
   ```

2. **Run diagnostics**:
   ```bash
   python3 test_gui.py
   python3 -m security_hardening_tool.cli.main info
   ```

3. **Check system requirements**:
   ```bash
   python3 --version
   pip3 --version
   uname -a  # Linux
   systeminfo  # Windows
   ```

### Information to Include in Bug Reports

- Operating system and version
- Python version
- Complete error message and traceback
- Steps to reproduce the issue
- Output of diagnostic commands
- Configuration files (remove sensitive data)

### Community Support

- Check existing issues on GitHub
- Search documentation for similar problems
- Use verbose mode to get detailed error information
- Test in a clean virtual environment

### Emergency Recovery

If the tool causes system issues:

```bash
# Check for backup files
ls -la ~/.security_hardening/backups/

# Restore from backup (if available)
python3 -m security_hardening_tool.cli.main rollback --backup-id <backup_id>

# Manual recovery (Linux)
sudo systemctl restart ssh  # Restore SSH access
sudo ufw --force reset      # Reset firewall rules

# Manual recovery (Windows)
# Use System Restore or Safe Mode to revert changes
```