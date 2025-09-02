#!/bin/bash
# Digital Forensics Lab Setup Script
# =================================
# 
# Automated setup script for installing digital forensics tools
# and dependencies for the lab environment.
#
# Usage: chmod +x setup.sh && ./setup.sh
#
# Author: Digital Forensics Lab
# License: MIT

set -e  # Exit on any error

echo "🚀 Digital Forensics Lab Setup"
echo "=============================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_section() {
    echo -e "${BLUE}[SECTION]${NC} $1"
}

# Check if running as root for some operations
check_root() {
    if [[ $EUID -eq 0 ]]; then
        print_warning "Running as root. Some operations may not work correctly."
    fi
}

# Detect operating system
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if command -v apt-get &> /dev/null; then
            OS="ubuntu"
            PACKAGE_MANAGER="apt"
        elif command -v yum &> /dev/null; then
            OS="centos"
            PACKAGE_MANAGER="yum"
        elif command -v pacman &> /dev/null; then
            OS="arch"
            PACKAGE_MANAGER="pacman"
        else
            print_error "Unsupported Linux distribution"
            exit 1
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
        PACKAGE_MANAGER="brew"
    else
        print_error "Unsupported operating system: $OSTYPE"
        exit 1
    fi
    
    print_status "Detected OS: $OS with package manager: $PACKAGE_MANAGER"
}

# Install package based on OS
install_package() {
    local package=$1
    
    case $PACKAGE_MANAGER in
        "apt")
            sudo apt-get install -y $package
            ;;
        "yum")
            sudo yum install -y $package
            ;;
        "pacman")
            sudo pacman -S --noconfirm $package
            ;;
        "brew")
            brew install $package
            ;;
        *)
            print_error "Unknown package manager: $PACKAGE_MANAGER"
            exit 1
            ;;
    esac
}

# Update package lists
update_packages() {
    print_section "Updating package lists..."
    
    case $PACKAGE_MANAGER in
        "apt")
            sudo apt-get update
            ;;
        "yum")
            sudo yum update -y
            ;;
        "pacman")
            sudo pacman -Sy
            ;;
        "brew")
            brew update
            ;;
    esac
    
    print_status "Package lists updated"
}

# Install Python and pip
install_python() {
    print_section "Installing Python and pip..."
    
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
        print_status "Python3 already installed: $PYTHON_VERSION"
    else
        case $OS in
            "ubuntu"|"centos")
                install_package python3
                install_package python3-pip
                ;;
            "arch")
                install_package python
                install_package python-pip
                ;;
            "macos")
                install_package python3
                ;;
        esac
    fi
    
    # Ensure pip is available
    if ! command -v pip3 &> /dev/null; then
        case $OS in
            "ubuntu")
                install_package python3-pip
                ;;
            "macos")
                python3 -m ensurepip --upgrade
                ;;
        esac
    fi
    
    print_status "Python and pip installation completed"
}

# Install disk imaging tools
install_disk_tools() {
    print_section "Installing disk imaging tools..."
    
    case $OS in
        "ubuntu")
            install_package dc3dd
            install_package ddrescue
            install_package sleuthkit
            ;;
        "centos")
            # Enable EPEL repository first
            sudo yum install -y epel-release
            install_package dc3dd
            install_package ddrescue
            install_package sleuthkit
            ;;
        "arch")
            install_package ddrescue
            # sleuthkit might be in AUR
            if command -v yay &> /dev/null; then
                yay -S --noconfirm sleuthkit
            else
                print_warning "sleuthkit not available, install from AUR manually"
            fi
            ;;
        "macos")
            install_package ddrescue
            print_warning "dc3dd and sleuthkit may need manual installation on macOS"
            ;;
    esac
    
    print_status "Disk imaging tools installation completed"
}

# Install memory acquisition tools
install_memory_tools() {
    print_section "Installing memory acquisition tools..."
    
    case $OS in
        "ubuntu")
            install_package volatility3
            # Try to install LiME
            if apt-cache search lime-forensics-dkms | grep -q lime-forensics-dkms; then
                install_package lime-forensics-dkms
            else
                print_warning "LiME not available in repositories, will download manually"
                download_lime
            fi
            ;;
        "centos")
            print_warning "Volatility3 may need manual installation on CentOS"
            download_lime
            ;;
        "arch")
            # Volatility might be in AUR
            if command -v yay &> /dev/null; then
                yay -S --noconfirm volatility3
            else
                print_warning "Volatility3 not available, install from AUR manually"
            fi
            download_lime
            ;;
        "macos")
            install_package volatility
            print_warning "LiME is Linux-specific, not available on macOS"
            ;;
    esac
    
    print_status "Memory acquisition tools installation completed"
}

# Download and compile LiME
download_lime() {
    print_status "Downloading LiME (Linux Memory Extractor)..."
    
    # Create tools directory
    mkdir -p tools
    cd tools
    
    # Download LiME
    if [ ! -d "LiME" ]; then
        git clone https://github.com/504ensicsLabs/LiME.git
    fi
    
    cd LiME/src
    
    # Try to compile LiME
    if command -v make &> /dev/null && [ -d "/lib/modules/$(uname -r)" ]; then
        print_status "Compiling LiME kernel module..."
        make
        if [ -f lime.ko ]; then
            print_status "LiME compiled successfully"
        else
            print_warning "LiME compilation failed, manual compilation may be needed"
        fi
    else
        print_warning "Cannot compile LiME - missing build tools or kernel headers"
    fi
    
    cd ../../..
}

# Install network capture tools
install_network_tools() {
    print_section "Installing network capture tools..."
    
    case $OS in
        "ubuntu")
            install_package wireshark-common
            install_package tcpdump
            install_package nmap
            # Add user to wireshark group
            if groups | grep -q wireshark; then
                print_status "User already in wireshark group"
            else
                sudo usermod -a -G wireshark $USER
                print_warning "Added to wireshark group. Please log out and back in."
            fi
            ;;
        "centos")
            install_package wireshark
            install_package tcpdump
            install_package nmap
            ;;
        "arch")
            install_package wireshark-qt
            install_package tcpdump
            install_package nmap
            ;;
        "macos")
            install_package wireshark
            install_package tcpdump
            install_package nmap
            ;;
    esac
    
    print_status "Network capture tools installation completed"
}

# Install verification and hashing tools
install_verification_tools() {
    print_section "Installing verification and hashing tools..."
    
    case $OS in
        "ubuntu")
            install_package hashdeep
            install_package md5deep
            ;;
        "centos")
            install_package hashdeep
            ;;
        "arch")
            install_package hashdeep
            ;;
        "macos")
            install_package hashdeep
            ;;
    esac
    
    print_status "Verification tools installation completed"
}

# Install Python dependencies
install_python_deps() {
    print_section "Installing Python dependencies..."
    
    # Create requirements.txt if it doesn't exist
    if [ ! -f requirements.txt ]; then
        cat > requirements.txt << EOF
# Digital Forensics Lab Python Dependencies
requests>=2.25.0
psutil>=5.8.0
python-magic>=0.4.0
cryptography>=3.4.0
pynput>=1.7.0
scapy>=2.4.0
hashlib
json
datetime
pathlib
EOF
    fi
    
    # Install Python dependencies
    if command -v pip3 &> /dev/null; then
        pip3 install -r requirements.txt
        print_status "Python dependencies installed"
    else
        print_error "pip3 not found, cannot install Python dependencies"
    fi
}

# Create directory structure
create_directories() {
    print_section "Creating directory structure..."
    
    # Create main directories
    mkdir -p evidence
    mkdir -p labs/{01-disk-acquisition,02-memory-acquisition,03-network-acquisition}
    mkdir -p tools
    mkdir -p docs
    mkdir -p examples
    
    # Create evidence subdirectories
    mkdir -p evidence/{disk-images,memory-dumps,network-captures,reports}
    
    # Set appropriate permissions
    chmod 755 scripts/*.py 2>/dev/null || true
    
    print_status "Directory structure created"
}

# Create example configuration files
create_configs() {
    print_section "Creating configuration files..."
    
    # Create .gitignore
    cat > .gitignore << EOF
# Evidence files
evidence/
*.dd
*.raw
*.E01
*.pcap
*.pcapng
*.mem
*.dmp

# Log files
*.log

# Python cache
__pycache__/
*.pyc
*.pyo

# OS files
.DS_Store
Thumbs.db

# IDE files
.vscode/
.idea/
*.swp
*.swo

# Temporary files
*.tmp
*.temp
EOF

    # Create sample lab configuration
    cat > config/lab_config.json << EOF
{
    "lab_settings": {
        "default_evidence_path": "./evidence",
        "default_hash_algorithm": "md5",
        "enable_logging": true,
        "log_level": "INFO"
    },
    "tools": {
        "disk_imaging": {
            "preferred_tool": "dc3dd",
            "fallback_tools": ["ddrescue", "dd"]
        },
        "memory_acquisition": {
            "preferred_tool": "lime",
            "fallback_tools": ["dd"]
        },
        "network_capture": {
            "preferred_tool": "tshark",
            "fallback_tools": ["tcpdump"]
        }
    }
}
EOF

    mkdir -p config
    print_status "Configuration files created"
}

# Main installation function
main() {
    print_status "Starting Digital Forensics Lab setup..."
    
    check_root
    detect_os
    
    # Ask for confirmation
    echo ""
    echo "This script will install digital forensics tools including:"
    echo "- Python 3 and pip"
    echo "- Disk imaging tools (dc3dd, ddrescue, sleuthkit)"
    echo "- Memory acquisition tools (volatility3, LiME)"
    echo "- Network tools (wireshark, tcpdump, nmap)"
    echo "- Verification tools (hashdeep, md5deep)"
    echo ""
    read -p "Continue with installation? (y/N): " -n 1 -r
    echo
    
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_status "Installation cancelled"
        exit 0
    fi
    
    # Run installation steps
    update_packages
    install_python
    install_disk_tools
    install_memory_tools
    install_network_tools
    install_verification_tools
    install_python_deps
    create_directories
    create_configs
    
    print_status "Setup completed successfully!"
    echo ""
    echo "🎉 Digital Forensics Lab is ready!"
    echo ""
    echo "Next steps:"
    echo "1. Review the tools installed with: ls scripts/"
    echo "2. Check the lab modules in: ls labs/"
    echo "3. Start with the README.md for usage instructions"
    echo "4. For network capture, you may need to restart your session"
    echo ""
    print_warning "Some tools may require root privileges to run"
    print_warning "Always ensure proper legal authorization before conducting forensic activities"
}

# Run main function
main "$@"
