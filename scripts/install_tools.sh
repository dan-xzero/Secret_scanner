#!/bin/bash

# ===================================
# AUTOMATED SECRETS SCANNER - TOOLS INSTALLATION
# ===================================

set -euo pipefail

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Installation paths
GO_BIN_PATH="$HOME/go/bin"
LOCAL_BIN_PATH="$HOME/.local/bin"

# ===================================
# HELPER FUNCTIONS
# ===================================

print_banner() {
    echo -e "${BLUE}"
    echo "====================================="
    echo "Automated Secrets Scanner"
    echo "Tools Installation Script"
    echo "====================================="
    echo -e "${NC}"
}

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

check_command() {
    if command -v "$1" &> /dev/null; then
        return 0
    else
        return 1
    fi
}

ensure_path() {
    local path=$1
    if [[ ":$PATH:" != *":$path:"* ]]; then
        log_info "Adding $path to PATH"
        echo "export PATH=\"$path:\$PATH\"" >> "$HOME/.bashrc"
        export PATH="$path:$PATH"
    fi
}

# ===================================
# SYSTEM DETECTION
# ===================================

detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if [ -f /etc/debian_version ]; then
            OS="debian"
            PACKAGE_MANAGER="apt-get"
        elif [ -f /etc/redhat-release ]; then
            OS="redhat"
            PACKAGE_MANAGER="yum"
        elif [ -f /etc/arch-release ]; then
            OS="arch"
            PACKAGE_MANAGER="pacman"
        else
            OS="linux"
            PACKAGE_MANAGER="unknown"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
        PACKAGE_MANAGER="brew"
    else
        OS="unknown"
        PACKAGE_MANAGER="unknown"
    fi
    
    log_info "Detected OS: $OS"
    log_info "Package manager: $PACKAGE_MANAGER"
}

# ===================================
# PREREQUISITE CHECKS
# ===================================

check_prerequisites() {
    log_info "Checking prerequisites..."
    
    local missing_prereqs=()
    
    # Check for sudo (if not root)
    if [ "$EUID" -ne 0 ]; then
        if ! check_command sudo; then
            missing_prereqs+=("sudo")
        fi
    fi
    
    # Check for curl
    if ! check_command curl; then
        missing_prereqs+=("curl")
    fi
    
    # Check for git
    if ! check_command git; then
        missing_prereqs+=("git")
    fi
    
    # Check for make
    if ! check_command make; then
        missing_prereqs+=("make")
    fi
    
    # Check for gcc/build tools
    if ! check_command gcc && ! check_command clang; then
        missing_prereqs+=("build-essential/gcc")
    fi
    
    if [ ${#missing_prereqs[@]} -ne 0 ]; then
        log_error "Missing prerequisites: ${missing_prereqs[*]}"
        log_error "Please install these manually before running this script"
        exit 1
    fi
    
    log_success "All prerequisites are installed"
}

# ===================================
# PYTHON INSTALLATION
# ===================================

install_python() {
    log_info "Checking Python installation..."
    
    if check_command python3; then
        local python_version=$(python3 --version | cut -d' ' -f2)
        log_info "Python $python_version is already installed"
        
        # Check pip
        if ! check_command pip3; then
            log_info "Installing pip3..."
            curl -s https://bootstrap.pypa.io/get-pip.py | python3
        fi
    else
        log_info "Installing Python 3..."
        
        case $PACKAGE_MANAGER in
            apt-get)
                sudo apt-get update
                sudo apt-get install -y python3 python3-pip python3-venv python3-dev
                ;;
            yum)
                sudo yum install -y python3 python3-pip python3-devel
                ;;
            brew)
                brew install python3
                ;;
            *)
                log_error "Cannot install Python automatically on this system"
                log_error "Please install Python 3.8+ manually"
                exit 1
                ;;
        esac
    fi
    
    # Install Python dependencies
    log_info "Installing Python dependencies..."
    cd "$PROJECT_ROOT"
    
    # Create virtual environment if it doesn't exist
    if [ ! -d "venv" ]; then
        log_info "Creating Python virtual environment..."
        python3 -m venv venv
    fi
    
    # Activate virtual environment and install dependencies
    source venv/bin/activate
    pip install --upgrade pip setuptools wheel
    pip install -r requirements.txt
    
    # Install Playwright browsers
    if pip show playwright &> /dev/null; then
        log_info "Installing Playwright browsers..."
        playwright install chromium firefox webkit
        playwright install-deps
    fi
    
    deactivate
    
    log_success "Python setup completed"
}

# ===================================
# NODE.JS INSTALLATION
# ===================================

install_nodejs() {
    log_info "Checking Node.js installation..."
    
    if check_command node; then
        local node_version=$(node --version)
        log_info "Node.js $node_version is already installed"
        
        # Check npm
        if ! check_command npm; then
            log_error "npm is not installed but Node.js is present"
            exit 1
        fi
    else
        log_info "Installing Node.js..."
        
        # Install using NodeSource repository for consistent versions
        curl -fsSL https://deb.nodesource.com/setup_lts.x | sudo -E bash -
        
        case $PACKAGE_MANAGER in
            apt-get)
                sudo apt-get install -y nodejs
                ;;
            yum)
                sudo yum install -y nodejs
                ;;
            brew)
                brew install node
                ;;
            *)
                log_error "Cannot install Node.js automatically on this system"
                log_error "Please install Node.js 14+ manually"
                exit 1
                ;;
        esac
    fi
    
    # Install Node.js dependencies
    log_info "Installing Node.js dependencies..."
    cd "$PROJECT_ROOT"
    npm install
    
    log_success "Node.js setup completed"
}

# ===================================
# GO INSTALLATION
# ===================================

install_go() {
    log_info "Checking Go installation..."
    
    if check_command go; then
        local go_version=$(go version | cut -d' ' -f3)
        log_info "Go $go_version is already installed"
    else
        log_info "Installing Go..."
        
        # Download and install Go
        local go_version="1.21.5"
        local go_arch="amd64"
        
        if [[ "$(uname -m)" == "aarch64" ]] || [[ "$(uname -m)" == "arm64" ]]; then
            go_arch="arm64"
        fi
        
        local go_tarball="go${go_version}.linux-${go_arch}.tar.gz"
        if [[ "$OS" == "macos" ]]; then
            go_tarball="go${go_version}.darwin-${go_arch}.tar.gz"
        fi
        
        curl -L "https://go.dev/dl/$go_tarball" -o "/tmp/$go_tarball"
        sudo rm -rf /usr/local/go
        sudo tar -C /usr/local -xzf "/tmp/$go_tarball"
        rm "/tmp/$go_tarball"
        
        # Add Go to PATH
        echo 'export PATH=/usr/local/go/bin:$PATH' >> "$HOME/.bashrc"
        export PATH=/usr/local/go/bin:$PATH
    fi
    
    # Ensure Go bin path is in PATH
    mkdir -p "$GO_BIN_PATH"
    ensure_path "$GO_BIN_PATH"
    
    log_success "Go setup completed"
}

# ===================================
# GO TOOLS INSTALLATION
# ===================================

install_go_tools() {
    log_info "Installing Go-based security tools..."
    
    # Ensure Go is available
    if ! check_command go; then
        log_error "Go is not installed"
        exit 1
    fi
    
    # Install gau (GetAllURLs)
    if ! check_command gau; then
        log_info "Installing gau..."
        go install github.com/lc/gau/v2/cmd/gau@latest
    else
        log_info "gau is already installed"
    fi
    
    # Install waybackurls
    if ! check_command waybackurls; then
        log_info "Installing waybackurls..."
        go install github.com/tomnomnom/waybackurls@latest
    else
        log_info "waybackurls is already installed"
    fi
    
    # Install wayurls (optional, as it's similar to waybackurls)
    if ! check_command wayurls; then
        log_info "Installing wayurls..."
        go install github.com/alwalxed/wayurls@latest || log_warn "Failed to install wayurls (optional)"
    else
        log_info "wayurls is already installed"
    fi
    
    log_success "Go tools installation completed"
}

# ===================================
# SECRET SCANNERS INSTALLATION
# ===================================

install_trufflehog() {
    log_info "Installing TruffleHog..."
    
    if check_command trufflehog; then
        log_info "TruffleHog is already installed"
        # Update to latest version
        log_info "Updating TruffleHog to latest version..."
    fi
    
    # Install TruffleHog
    case $OS in
        linux|debian|redhat|arch)
            # Download latest release
            local latest_version=$(curl -s https://api.github.com/repos/trufflesecurity/trufflehog/releases/latest | grep '"tag_name":' | sed -E 's/.*"v([^"]+)".*/\1/')
            local download_url="https://github.com/trufflesecurity/trufflehog/releases/download/v${latest_version}/trufflehog_${latest_version}_linux_amd64.tar.gz"
            
            if [[ "$(uname -m)" == "aarch64" ]] || [[ "$(uname -m)" == "arm64" ]]; then
                download_url="https://github.com/trufflesecurity/trufflehog/releases/download/v${latest_version}/trufflehog_${latest_version}_linux_arm64.tar.gz"
            fi
            
            curl -L "$download_url" -o /tmp/trufflehog.tar.gz
            mkdir -p "$LOCAL_BIN_PATH"
            tar -xzf /tmp/trufflehog.tar.gz -C "$LOCAL_BIN_PATH" trufflehog
            chmod +x "$LOCAL_BIN_PATH/trufflehog"
            rm /tmp/trufflehog.tar.gz
            ;;
        macos)
            brew install trufflehog
            ;;
        *)
            log_error "Cannot install TruffleHog automatically on this system"
            log_error "Please install TruffleHog manually from: https://github.com/trufflesecurity/trufflehog"
            return 1
            ;;
    esac
    
    ensure_path "$LOCAL_BIN_PATH"
    log_success "TruffleHog installed successfully"
}

install_gitleaks() {
    log_info "Installing Gitleaks..."
    
    if check_command gitleaks; then
        log_info "Gitleaks is already installed"
        # Update to latest version
        log_info "Updating Gitleaks to latest version..."
    fi
    
    # Install Gitleaks
    case $OS in
        linux|debian|redhat|arch)
            # Download latest release
            local latest_version=$(curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest | grep '"tag_name":' | sed -E 's/.*"v([^"]+)".*/\1/')
            local download_url="https://github.com/gitleaks/gitleaks/releases/download/v${latest_version}/gitleaks_${latest_version}_linux_x64.tar.gz"
            
            if [[ "$(uname -m)" == "aarch64" ]] || [[ "$(uname -m)" == "arm64" ]]; then
                download_url="https://github.com/gitleaks/gitleaks/releases/download/v${latest_version}/gitleaks_${latest_version}_linux_arm64.tar.gz"
            fi
            
            curl -L "$download_url" -o /tmp/gitleaks.tar.gz
            mkdir -p "$LOCAL_BIN_PATH"
            tar -xzf /tmp/gitleaks.tar.gz -C "$LOCAL_BIN_PATH" gitleaks
            chmod +x "$LOCAL_BIN_PATH/gitleaks"
            rm /tmp/gitleaks.tar.gz
            ;;
        macos)
            brew install gitleaks
            ;;
        *)
            log_error "Cannot install Gitleaks automatically on this system"
            log_error "Please install Gitleaks manually from: https://github.com/gitleaks/gitleaks"
            return 1
            ;;
    esac
    
    ensure_path "$LOCAL_BIN_PATH"
    log_success "Gitleaks installed successfully"
}

# ===================================
# PATTERN DATABASE SETUP
# ===================================

setup_patterns_db() {
    log_info "Setting up Secrets Patterns Database..."
    
    cd "$PROJECT_ROOT"
    
    # Clone or update secrets-patterns-db
    if [ -d "patterns/secrets-patterns-db" ]; then
        log_info "Updating existing patterns database..."
        cd patterns/secrets-patterns-db
        git pull origin main || log_warn "Failed to update patterns database"
        cd "$PROJECT_ROOT"
    else
        log_info "Cloning patterns database..."
        mkdir -p patterns
        cd patterns
        git clone https://github.com/mazen160/secrets-patterns-db.git
        cd "$PROJECT_ROOT"
    fi
    
    log_success "Patterns database setup completed"
}

# ===================================
# SYSTEM DEPENDENCIES
# ===================================

install_system_deps() {
    log_info "Installing system dependencies..."
    
    case $PACKAGE_MANAGER in
        apt-get)
            sudo apt-get update
            sudo apt-get install -y \
                build-essential \
                libssl-dev \
                libffi-dev \
                libxml2-dev \
                libxslt1-dev \
                zlib1g-dev \
                libjpeg-dev \
                libpng-dev \
                libwebp-dev \
                chromium-browser \
                firefox \
                xvfb
            ;;
        yum)
            sudo yum groupinstall -y "Development Tools"
            sudo yum install -y \
                openssl-devel \
                libffi-devel \
                libxml2-devel \
                libxslt-devel \
                zlib-devel \
                libjpeg-devel \
                libpng-devel \
                libwebp-devel \
                chromium \
                firefox \
                xorg-x11-server-Xvfb
            ;;
        brew)
            # macOS generally has most dependencies
            brew install libxml2 libxslt
            ;;
        *)
            log_warn "Cannot install system dependencies automatically"
            ;;
    esac
    
    log_success "System dependencies installed"
}

# ===================================
# VERIFICATION
# ===================================

verify_installation() {
    log_info "Verifying installation..."
    
    local failed_checks=()
    
    # Check Python
    if ! check_command python3; then
        failed_checks+=("Python 3")
    fi
    
    # Check Node.js
    if ! check_command node; then
        failed_checks+=("Node.js")
    fi
    
    # Check Go
    if ! check_command go; then
        failed_checks+=("Go")
    fi
    
    # Check URL discovery tools
    if ! check_command gau; then
        failed_checks+=("gau")
    fi
    
    if ! check_command waybackurls; then
        failed_checks+=("waybackurls")
    fi
    
    # Check secret scanners
    if ! check_command trufflehog; then
        failed_checks+=("TruffleHog")
    fi
    
    if ! check_command gitleaks; then
        failed_checks+=("Gitleaks")
    fi
    
    # Check patterns database
    if [ ! -d "$PROJECT_ROOT/patterns/secrets-patterns-db" ]; then
        failed_checks+=("Secrets Patterns Database")
    fi
    
    if [ ${#failed_checks[@]} -eq 0 ]; then
        log_success "All tools are installed successfully!"
        
        echo -e "\n${GREEN}Installation Summary:${NC}"
        echo "✓ Python $(python3 --version | cut -d' ' -f2)"
        echo "✓ Node.js $(node --version)"
        echo "✓ Go $(go version | cut -d' ' -f3)"
        echo "✓ gau $(gau -version 2>&1 | head -n1 || echo 'installed')"
        echo "✓ waybackurls installed"
        echo "✓ TruffleHog $(trufflehog --version 2>&1 | head -n1 || echo 'installed')"
        echo "✓ Gitleaks $(gitleaks version 2>&1 | head -n1 || echo 'installed')"
        echo "✓ Secrets Patterns Database installed"
        
        echo -e "\n${GREEN}Next Steps:${NC}"
        echo "1. Reload your shell or run: source ~/.bashrc"
        echo "2. Configure your environment variables in .env"
        echo "3. Add target domains to config/domains.txt"
        echo "4. Run the scanner: python scripts/run_scan.py"
    else
        log_error "Some tools failed to install: ${failed_checks[*]}"
        exit 1
    fi
}

# ===================================
# MAIN EXECUTION
# ===================================

main() {
    print_banner
    
    # Detect operating system
    detect_os
    
    # Check prerequisites
    check_prerequisites
    
    # Create necessary directories
    mkdir -p "$LOCAL_BIN_PATH"
    mkdir -p "$GO_BIN_PATH"
    
    # Install components
    install_system_deps
    install_python
    install_nodejs
    install_go
    install_go_tools
    install_trufflehog
    install_gitleaks
    setup_patterns_db
    
    # Verify installation
    verify_installation
    
    log_success "Installation completed!"
}

# Handle script arguments
case "${1:-}" in
    --python-only)
        print_banner
        install_python
        ;;
    --node-only)
        print_banner
        install_nodejs
        ;;
    --go-only)
        print_banner
        install_go
        install_go_tools
        ;;
    --scanners-only)
        print_banner
        install_trufflehog
        install_gitleaks
        ;;
    --verify)
        print_banner
        verify_installation
        ;;
    --help|-h)
        echo "Usage: $0 [option]"
        echo "Options:"
        echo "  --python-only    Install only Python dependencies"
        echo "  --node-only      Install only Node.js dependencies"
        echo "  --go-only        Install only Go and Go tools"
        echo "  --scanners-only  Install only secret scanners"
        echo "  --verify         Verify installation"
        echo "  --help           Show this help message"
        echo ""
        echo "Without options, the script will install all components."
        ;;
    *)
        main
        ;;
esac