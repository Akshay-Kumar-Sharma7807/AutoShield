#!/bin/bash

# Security Hardening Tool - Linux Installation Script
# This script automates the installation process on Linux systems

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to detect Linux distribution
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$ID
        VERSION=$VERSION_ID
    else
        print_error "Cannot detect Linux distribution"
        exit 1
    fi
    print_status "Detected: $PRETTY_NAME"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to install system dependencies
install_system_deps() {
    print_status "Installing system dependencies..."
    
    case $DISTRO in
        ubuntu|debian)
            sudo apt update
            sudo apt install -y python3 python3-pip python3-setuptools python3-dev python3-tk build-essential git curl
            ;;
        centos|rhel)
            sudo yum install -y epel-release
            sudo yum install -y python3 python3-pip python3-setuptools python3-devel python3-tkinter gcc gcc-c++ make git curl
            ;;
        fedora)
            sudo dnf install -y python3 python3-pip python3-setuptools python3-devel python3-tkinter gcc gcc-c++ make git curl
            ;;
        arch)
            sudo pacman -S --noconfirm python python-pip python-setuptools python-tkinter base-devel git curl
            ;;
        *)
            print_warning "Unsupported distribution: $DISTRO"
            print_status "Please install Python 3.8+, pip, setuptools, and development tools manually"
            ;;
    esac
}

# Function to check Python version
check_python() {
    if command_exists python3; then
        PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
        print_status "Python version: $PYTHON_VERSION"
        
        # Check if version is >= 3.8
        if python3 -c 'import sys; exit(0 if sys.version_info >= (3, 8) else 1)'; then
            print_success "Python version is compatible"
        else
            print_error "Python 3.8 or higher is required. Current version: $PYTHON_VERSION"
            exit 1
        fi
    else
        print_error "Python 3 is not installed"
        exit 1
    fi
}

# Function to install Python dependencies
install_python_deps() {
    print_status "Installing Python dependencies..."
    
    # Upgrade pip first
    python3 -m pip install --upgrade pip
    
    # Install setuptools and wheel
    python3 -m pip install setuptools wheel
    
    # Install project requirements
    if [ -f "requirements.txt" ]; then
        python3 -m pip install -r requirements.txt
        print_success "Python dependencies installed"
    else
        print_error "requirements.txt not found"
        exit 1
    fi
}

# Function to install the tool
install_tool() {
    print_status "Installing Security Hardening Tool..."
    
    if [ -f "setup.py" ]; then
        python3 setup.py install
        print_success "Tool installed successfully"
    else
        print_error "setup.py not found"
        exit 1
    fi
}

# Function to test installation
test_installation() {
    print_status "Testing installation..."
    
    # Test basic import
    if python3 -c "import security_hardening_tool" 2>/dev/null; then
        print_success "Module import successful"
    else
        print_error "Module import failed"
        return 1
    fi
    
    # Test CLI
    if python3 -m security_hardening_tool.cli.main --help >/dev/null 2>&1; then
        print_success "CLI interface working"
    else
        print_error "CLI interface failed"
        return 1
    fi
    
    # Test GUI components
    if python3 test_gui.py >/dev/null 2>&1; then
        print_success "GUI components working"
    else
        print_warning "GUI components may have issues (this is normal on headless systems)"
    fi
    
    # Test system info
    print_status "System information:"
    python3 -m security_hardening_tool.cli.main info
}

# Function to create virtual environment (optional)
create_venv() {
    if [ "$USE_VENV" = "yes" ]; then
        print_status "Creating virtual environment..."
        python3 -m venv venv
        source venv/bin/activate
        print_success "Virtual environment created and activated"
    fi
}

# Function to show usage instructions
show_usage() {
    print_success "Installation completed successfully!"
    echo
    print_status "Usage examples:"
    echo "  # Get system information:"
    echo "  python3 -m security_hardening_tool.cli.main info"
    echo
    echo "  # Run security assessment:"
    echo "  sudo python3 -m security_hardening_tool.cli.main assess --level basic"
    echo
    echo "  # Launch GUI (if X11 is available):"
    echo "  python3 -m security_hardening_tool.cli.main gui"
    echo
    echo "  # Get help:"
    echo "  python3 -m security_hardening_tool.cli.main --help"
    echo
    print_status "For full functionality, run commands with sudo privileges"
    print_status "Documentation available in docs/ directory"
}

# Main installation function
main() {
    echo "========================================"
    echo "Security Hardening Tool - Linux Installer"
    echo "========================================"
    echo
    
    # Check if running as root
    if [ "$EUID" -eq 0 ]; then
        print_warning "Running as root. Consider using a regular user account."
    fi
    
    # Parse command line arguments
    USE_VENV="no"
    SKIP_SYSTEM_DEPS="no"
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --venv)
                USE_VENV="yes"
                shift
                ;;
            --skip-system-deps)
                SKIP_SYSTEM_DEPS="yes"
                shift
                ;;
            --help)
                echo "Usage: $0 [OPTIONS]"
                echo "Options:"
                echo "  --venv              Create and use virtual environment"
                echo "  --skip-system-deps  Skip system dependency installation"
                echo "  --help              Show this help message"
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done
    
    # Check if we're in the right directory
    if [ ! -f "setup.py" ] || [ ! -f "requirements.txt" ]; then
        print_error "Please run this script from the AutoShield project directory"
        exit 1
    fi
    
    # Detect distribution
    detect_distro
    
    # Install system dependencies
    if [ "$SKIP_SYSTEM_DEPS" = "no" ]; then
        install_system_deps
    else
        print_status "Skipping system dependency installation"
    fi
    
    # Check Python
    check_python
    
    # Create virtual environment if requested
    create_venv
    
    # Install Python dependencies
    install_python_deps
    
    # Install the tool
    install_tool
    
    # Test installation
    test_installation
    
    # Show usage instructions
    show_usage
}

# Run main function
main "$@"