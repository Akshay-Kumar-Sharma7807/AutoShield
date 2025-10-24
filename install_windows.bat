@echo off
REM Security Hardening Tool - Windows Installation Script
REM This script automates the installation process on Windows systems

setlocal enabledelayedexpansion

echo ========================================
echo Security Hardening Tool - Windows Installer
echo ========================================
echo.

REM Check if running as Administrator
net session >nul 2>&1
if %errorLevel% == 0 (
    echo [INFO] Running with Administrator privileges
) else (
    echo [WARNING] Not running as Administrator. Some features may be limited.
    echo [INFO] For full functionality, right-click and "Run as administrator"
    echo.
)

REM Check if Python is installed
python --version >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] Python is not installed or not in PATH
    echo [INFO] Please install Python 3.8+ from https://python.org
    echo [INFO] Make sure to check "Add Python to PATH" during installation
    pause
    exit /b 1
)

REM Check Python version
for /f "tokens=2" %%i in ('python --version 2^>^&1') do set PYTHON_VERSION=%%i
echo [INFO] Python version: %PYTHON_VERSION%

REM Check if we're in the right directory
if not exist "setup.py" (
    echo [ERROR] setup.py not found
    echo [INFO] Please run this script from the AutoShield project directory
    pause
    exit /b 1
)

if not exist "requirements.txt" (
    echo [ERROR] requirements.txt not found
    echo [INFO] Please run this script from the AutoShield project directory
    pause
    exit /b 1
)

echo [INFO] Installing Python dependencies...

REM Upgrade pip
python -m pip install --upgrade pip
if %errorLevel% neq 0 (
    echo [ERROR] Failed to upgrade pip
    pause
    exit /b 1
)

REM Install setuptools and wheel
python -m pip install setuptools wheel
if %errorLevel% neq 0 (
    echo [ERROR] Failed to install setuptools and wheel
    pause
    exit /b 1
)

REM Install requirements
python -m pip install -r requirements.txt
if %errorLevel% neq 0 (
    echo [ERROR] Failed to install requirements
    echo [INFO] Try running: pip install --trusted-host pypi.org --trusted-host pypi.python.org --trusted-host files.pythonhosted.org -r requirements.txt
    pause
    exit /b 1
)

echo [SUCCESS] Python dependencies installed

echo [INFO] Installing Security Hardening Tool...
python setup.py install
if %errorLevel% neq 0 (
    echo [ERROR] Failed to install the tool
    pause
    exit /b 1
)

echo [SUCCESS] Tool installed successfully

echo [INFO] Testing installation...

REM Test basic import
python -c "import security_hardening_tool" >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] Module import failed
    pause
    exit /b 1
)
echo [SUCCESS] Module import successful

REM Test CLI
python -m security_hardening_tool.cli.main --help >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] CLI interface failed
    pause
    exit /b 1
)
echo [SUCCESS] CLI interface working

REM Test GUI components
python test_gui.py >nul 2>&1
if %errorLevel% neq 0 (
    echo [WARNING] GUI components may have issues
) else (
    echo [SUCCESS] GUI components working
)

echo.
echo [SUCCESS] Installation completed successfully!
echo.
echo [INFO] Usage examples:
echo   # Get system information:
echo   python -m security_hardening_tool.cli.main info
echo.
echo   # Run security assessment (as Administrator):
echo   python -m security_hardening_tool.cli.main assess --level basic
echo.
echo   # Launch GUI:
echo   python -m security_hardening_tool.cli.main gui
echo.
echo   # Get help:
echo   python -m security_hardening_tool.cli.main --help
echo.
echo [INFO] For full functionality, run as Administrator
echo [INFO] Documentation available in docs\ directory

echo.
echo System Information:
python -m security_hardening_tool.cli.main info

echo.
pause