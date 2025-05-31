#!/bin/bash

# ===================================
# AUTOMATED SECRETS SCANNER - ENHANCED TOOLS INSTALLATION
# Version: 2.0
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
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Installation paths
GO_BIN_PATH="$HOME/go/bin"
LOCAL_BIN_PATH="$HOME/.local/bin"
TOOLS_DIR="$PROJECT_ROOT/tools"

# Version tracking
VERSIONS_FILE="$PROJECT_ROOT/.tool-versions"

# ===================================
# HELPER FUNCTIONS
# ===================================

print_banner() {
    echo -e "${BLUE}"
    cat << "EOF"
     _____                     _       _____                                 
    / ____|                   | |     / ____|                                
   | (___   ___  ___ _ __ ___| |_   | (___   ___ __ _ _ __  _ __   ___ _ __ 
    \___ \ / _ \/ __| '__/ _ \ __|   \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
    ____) |  __/ (__| | |  __/ |_    ____) | (_| (_| | | | | | | |  __/ |   
   |_____/ \___|\___|_|  \___|\__|  |_____/ \___\__,_|_| |_|_| |_|\___|_|   
                                                                             
EOF
    echo "  Automated Secrets Scanner - Enhanced Installation Script v2.0"
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

log_section() {
    echo -e "\n${PURPLE}=== $1 ===${NC}\n"
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
        echo "export PATH=\"$path:\$PATH\"" >> "$HOME/.zshrc" 2>/dev/null || true
        export PATH="$path:$PATH"
    fi
}

get_latest_release() {
    local repo=$1
    curl -s "https://api.github.com/repos/$repo/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/'
}

download_with_progress() {
    local url=$1
    local output=$2
    log_info "Downloading from: $url"
    curl -L --progress-bar "$url" -o "$output"
}

# ===================================
# SYSTEM DETECTION
# ===================================

detect_os() {
    log_section "System Detection"
    
    # Detect container environment
    if [ -f /.dockerenv ]; then
        CONTAINER_ENV="docker"
        log_info "Running in Docker container"
    elif [ -f /run/.containerenv ]; then
        CONTAINER_ENV="podman"
        log_info "Running in Podman container"
    else
        CONTAINER_ENV="none"
    fi
    
    # Detect OS
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if [ -f /etc/debian_version ]; then
            OS="debian"
            PACKAGE_MANAGER="apt-get"
            DISTRO=$(lsb_release -si 2>/dev/null || echo "Debian")
            VERSION=$(lsb_release -sr 2>/dev/null || cat /etc/debian_version)
        elif [ -f /etc/redhat-release ]; then
            OS="redhat"
            PACKAGE_MANAGER="yum"
            if command -v dnf &> /dev/null; then
                PACKAGE_MANAGER="dnf"
            fi
            DISTRO=$(cat /etc/redhat-release | awk '{print $1}')
            VERSION=$(cat /etc/redhat-release | grep -oE '[0-9]+\.[0-9]+' | head -1)
        elif [ -f /etc/arch-release ]; then
            OS="arch"
            PACKAGE_MANAGER="pacman"
            DISTRO="Arch Linux"
            VERSION="Rolling"
        elif [ -f /etc/alpine-release ]; then
            OS="alpine"
            PACKAGE_MANAGER="apk"
            DISTRO="Alpine Linux"
            VERSION=$(cat /etc/alpine-release)
        else
            OS="linux"
            PACKAGE_MANAGER="unknown"
            DISTRO="Unknown Linux"
            VERSION="Unknown"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
        PACKAGE_MANAGER="brew"
        DISTRO="macOS"
        VERSION=$(sw_vers -productVersion)
    else
        OS="unknown"
        PACKAGE_MANAGER="unknown"
        DISTRO="Unknown OS"
        VERSION="Unknown"
    fi
    
    # Architecture detection
    ARCH=$(uname -m)
    case $ARCH in
        x86_64)
            ARCH_ALT="amd64"
            ;;
        aarch64|arm64)
            ARCH_ALT="arm64"
            ;;
        *)
            ARCH_ALT=$ARCH
            ;;
    esac
    
    log_info "Detected OS: $DISTRO $VERSION ($OS)"
    log_info "Architecture: $ARCH ($ARCH_ALT)"
    log_info "Package manager: $PACKAGE_MANAGER"
    log_info "Container environment: $CONTAINER_ENV"
}

# ===================================
# PREREQUISITE CHECKS
# ===================================

check_prerequisites() {
    log_section "Checking Prerequisites"
    
    local missing_prereqs=()
    
    # Check for sudo (if not root and not in container)
    if [ "$EUID" -ne 0 ] && [ "$CONTAINER_ENV" == "none" ]; then
        if ! check_command sudo; then
            missing_prereqs+=("sudo")
        fi
    fi
    
    # Check for curl or wget
    if ! check_command curl && ! check_command wget; then
        missing_prereqs+=("curl or wget")
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
    
    # Check for unzip
    if ! check_command unzip; then
        missing_prereqs+=("unzip")
    fi
    
    # Check for jq (useful for JSON parsing)
    if ! check_command jq; then
        log_warn "jq not found (optional but recommended)"
    fi
    
    if [ ${#missing_prereqs[@]} -ne 0 ]; then
        log_error "Missing prerequisites: ${missing_prereqs[*]}"
        log_error "Please install these manually before running this script"
        
        # Provide installation hints
        case $PACKAGE_MANAGER in
            apt-get)
                log_info "Try: sudo apt-get update && sudo apt-get install -y curl git make build-essential unzip"
                ;;
            yum|dnf)
                log_info "Try: sudo $PACKAGE_MANAGER install -y curl git make gcc gcc-c++ unzip"
                ;;
            brew)
                log_info "Try: brew install curl git make gcc unzip"
                ;;
        esac
        
        exit 1
    fi
    
    log_success "All prerequisites are installed"
}

# ===================================
# PYTHON INSTALLATION
# ===================================

install_python() {
    log_section "Python Setup"
    
    local required_version="3.8"
    
    if check_command python3; then
        local python_version=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
        log_info "Python $python_version is already installed"
        
        # Check if version is sufficient
        if ! python3 -c "import sys; exit(0 if sys.version_info >= (3, 8) else 1)"; then
            log_error "Python version $python_version is too old. Required: $required_version+"
            exit 1
        fi
        
        # Check pip
        if ! check_command pip3; then
            log_info "Installing pip3..."
            if check_command wget; then
                wget -q https://bootstrap.pypa.io/get-pip.py
                python3 get-pip.py
                rm get-pip.py
            else
                curl -s https://bootstrap.pypa.io/get-pip.py | python3
            fi
        fi
    else
        log_info "Installing Python 3..."
        
        case $PACKAGE_MANAGER in
            apt-get)
                sudo apt-get update
                sudo apt-get install -y python3 python3-pip python3-venv python3-dev
                ;;
            yum|dnf)
                sudo $PACKAGE_MANAGER install -y python3 python3-pip python3-devel
                ;;
            brew)
                brew install python3
                ;;
            apk)
                apk add --no-cache python3 py3-pip python3-dev
                ;;
            *)
                log_error "Cannot install Python automatically on this system"
                log_error "Please install Python $required_version+ manually"
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
    
    # Create requirements.txt if it doesn't exist
    if [ ! -f requirements.txt ]; then
        log_info "Creating requirements.txt..."
        cat > requirements.txt << 'EOF'
# Core dependencies
requests>=2.31.0
beautifulsoup4>=4.12.0
lxml>=4.9.0
urllib3>=2.0.0

# Crawling and browser automation
playwright>=1.40.0
selenium>=4.15.0
scrapy>=2.11.0

# Security and validation
pyyaml>=6.0
python-dotenv>=1.0.0
cryptography>=41.0.0

# Parsing and processing
jinja2>=3.1.0
markupsafe>=2.1.0
html5lib>=1.1

# Logging and monitoring
loguru>=0.7.0
tqdm>=4.66.0
rich>=13.7.0

# Slack integration
slack-sdk>=3.26.0
aiohttp>=3.9.0

# Data handling
pandas>=2.1.0
numpy>=1.24.0

# Testing and development
pytest>=7.4.0
pytest-asyncio>=0.21.0
black>=23.0.0
flake8>=6.1.0
mypy>=1.7.0

# Utilities
click>=8.1.0
pytz>=2023.3
python-dateutil>=2.8.0
EOF
    fi
    
    pip install -r requirements.txt
    
    # Install Playwright browsers
    if pip show playwright &> /dev/null; then
        log_info "Installing Playwright browsers..."
        playwright install chromium firefox
        playwright install-deps
    fi
    
    # Install additional Python tools
    pip install httpx aiofiles validators
    
    deactivate
    
    log_success "Python setup completed"
}

# ===================================
# NODE.JS INSTALLATION
# ===================================

install_nodejs() {
    log_section "Node.js Setup"
    
    local required_version="14"
    
    if check_command node; then
        local node_version=$(node --version | cut -d'v' -f2 | cut -d'.' -f1)
        log_info "Node.js v$(node --version | cut -d'v' -f2) is already installed"
        
        # Check if version is sufficient
        if [ "$node_version" -lt "$required_version" ]; then
            log_error "Node.js version is too old. Required: v$required_version+"
            exit 1
        fi
        
        # Check npm
        if ! check_command npm; then
            log_error "npm is not installed but Node.js is present"
            exit 1
        fi
    else
        log_info "Installing Node.js..."
        
        # Install using NodeSource repository for consistent versions
        if [[ "$OS" == "debian" ]] || [[ "$OS" == "redhat" ]]; then
            curl -fsSL https://deb.nodesource.com/setup_lts.x | sudo -E bash -
        fi
        
        case $PACKAGE_MANAGER in
            apt-get)
                sudo apt-get install -y nodejs
                ;;
            yum|dnf)
                sudo $PACKAGE_MANAGER install -y nodejs
                ;;
            brew)
                brew install node
                ;;
            apk)
                apk add --no-cache nodejs npm
                ;;
            *)
                log_error "Cannot install Node.js automatically on this system"
                log_error "Please install Node.js $required_version+ manually"
                exit 1
                ;;
        esac
    fi
    
    # Create package.json if it doesn't exist
    cd "$PROJECT_ROOT"
    if [ ! -f package.json ]; then
        log_info "Creating package.json..."
        cat > package.json << 'EOF'
{
  "name": "automated-secrets-scanner",
  "version": "2.0.0",
  "description": "Automated web secrets scanner",
  "main": "index.js",
  "scripts": {
    "test": "echo \"Error: no test specified\" && exit 1"
  },
  "dependencies": {
    "crawlee": "^3.5.0",
    "playwright": "^1.40.0",
    "puppeteer": "^21.6.0",
    "cheerio": "^1.0.0-rc.12",
    "axios": "^1.6.0",
    "dotenv": "^16.3.0"
  },
  "devDependencies": {
    "eslint": "^8.55.0",
    "prettier": "^3.1.0"
  }
}
EOF
    fi
    
    # Install Node.js dependencies
    log_info "Installing Node.js dependencies..."
    npm install
    
    # Install global tools
    log_info "Installing global Node.js tools..."
    npm install -g yarn pm2 nodemon 2>/dev/null || log_warn "Some global tools failed to install"
    
    log_success "Node.js setup completed"
}

# ===================================
# GO INSTALLATION
# ===================================

install_go() {
    log_section "Go Setup"
    
    local required_version="1.19"
    
    if check_command go; then
        local go_version=$(go version | grep -oE '[0-9]+\.[0-9]+' | head -1)
        log_info "Go $go_version is already installed"
        
        # Check if version is sufficient
        local major=$(echo "$go_version" | cut -d'.' -f1)
        local minor=$(echo "$go_version" | cut -d'.' -f2)
        if [ "$major" -lt 1 ] || ([ "$major" -eq 1 ] && [ "$minor" -lt 19 ]); then
            log_warn "Go version $go_version is old. Recommended: $required_version+"
        fi
    else
        log_info "Installing Go..."
        
        # Get latest stable version
        local go_version="1.21.5"
        local go_tarball="go${go_version}.linux-${ARCH_ALT}.tar.gz"
        
        if [[ "$OS" == "macos" ]]; then
            go_tarball="go${go_version}.darwin-${ARCH_ALT}.tar.gz"
        fi
        
        download_with_progress "https://go.dev/dl/$go_tarball" "/tmp/$go_tarball"
        sudo rm -rf /usr/local/go
        sudo tar -C /usr/local -xzf "/tmp/$go_tarball"
        rm "/tmp/$go_tarball"
        
        # Add Go to PATH
        echo 'export PATH=/usr/local/go/bin:$PATH' >> "$HOME/.bashrc"
        echo 'export PATH=/usr/local/go/bin:$PATH' >> "$HOME/.zshrc" 2>/dev/null || true
        export PATH=/usr/local/go/bin:$PATH
    fi
    
    # Ensure Go bin path is in PATH
    mkdir -p "$GO_BIN_PATH"
    ensure_path "$GO_BIN_PATH"
    
    # Set Go environment
    go env -w GO111MODULE=on
    go env -w GOPROXY=https://proxy.golang.org,direct
    
    log_success "Go setup completed"
}

# ===================================
# GO TOOLS INSTALLATION
# ===================================

install_go_tools() {
    log_section "Installing Go-based Security Tools"
    
    # Ensure Go is available
    if ! check_command go; then
        log_error "Go is not installed"
        exit 1
    fi
    
    # Tool installation function
    install_go_tool() {
        local name=$1
        local package=$2
        local version=${3:-"latest"}
        
        if ! check_command "$name"; then
            log_info "Installing $name..."
            go install "${package}@${version}" || {
                log_error "Failed to install $name"
                return 1
            }
        else
            log_info "$name is already installed"
            # Update to latest
            log_info "Updating $name to latest version..."
            go install "${package}@${version}" || log_warn "Failed to update $name"
        fi
    }
    
    # Install URL discovery tools
    install_go_tool "gau" "github.com/lc/gau/v2/cmd/gau"
    install_go_tool "waybackurls" "github.com/tomnomnom/waybackurls"
    install_go_tool "wayurls" "github.com/alwalxed/wayurls"
    
    # Install Katana (important for JavaScript crawling)
    install_go_tool "katana" "github.com/projectdiscovery/katana/cmd/katana"
    
    # Install other useful tools
    install_go_tool "httpx" "github.com/projectdiscovery/httpx/cmd/httpx"
    install_go_tool "subfinder" "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
    install_go_tool "nuclei" "github.com/projectdiscovery/nuclei/v3/cmd/nuclei"
    
    log_success "Go tools installation completed"
}

# ===================================
# SECRET SCANNERS INSTALLATION
# ===================================

install_trufflehog() {
    log_section "Installing TruffleHog"
    
    if check_command trufflehog; then
        log_info "TruffleHog is already installed"
        log_info "Checking for updates..."
    fi
    
    # Get latest version
    local latest_version=$(get_latest_release "trufflesecurity/trufflehog" | sed 's/v//')
    
    if [ -z "$latest_version" ]; then
        log_error "Failed to get latest TruffleHog version"
        return 1
    fi
    
    log_info "Installing TruffleHog v${latest_version}..."
    
    # Install TruffleHog
    case $OS in
        linux|debian|redhat|arch|alpine)
            local download_url="https://github.com/trufflesecurity/trufflehog/releases/download/v${latest_version}/trufflehog_${latest_version}_linux_${ARCH_ALT}.tar.gz"
            
            download_with_progress "$download_url" "/tmp/trufflehog.tar.gz"
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
            log_info "Please install TruffleHog manually from: https://github.com/trufflesecurity/trufflehog"
            return 1
            ;;
    esac
    
    ensure_path "$LOCAL_BIN_PATH"
    
    # Verify installation
    if check_command trufflehog; then
        log_success "TruffleHog v${latest_version} installed successfully"
        echo "trufflehog=${latest_version}" >> "$VERSIONS_FILE"
    else
        log_error "TruffleHog installation verification failed"
        return 1
    fi
}

install_gitleaks() {
    log_section "Installing Gitleaks"
    
    if check_command gitleaks; then
        log_info "Gitleaks is already installed"
        log_info "Checking for updates..."
    fi
    
    # Get latest version
    local latest_version=$(get_latest_release "gitleaks/gitleaks" | sed 's/v//')
    
    if [ -z "$latest_version" ]; then
        log_error "Failed to get latest Gitleaks version"
        return 1
    fi
    
    log_info "Installing Gitleaks v${latest_version}..."
    
    # Install Gitleaks
    case $OS in
        linux|debian|redhat|arch|alpine)
            local download_url="https://github.com/gitleaks/gitleaks/releases/download/v${latest_version}/gitleaks_${latest_version}_linux_${ARCH}.tar.gz"
            
            # Try alternative naming if first fails
            if ! curl -fsSL "$download_url" &>/dev/null; then
                download_url="https://github.com/gitleaks/gitleaks/releases/download/v${latest_version}/gitleaks_${latest_version}_linux_${ARCH_ALT}.tar.gz"
            fi
            
            download_with_progress "$download_url" "/tmp/gitleaks.tar.gz"
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
            log_info "Please install Gitleaks manually from: https://github.com/gitleaks/gitleaks"
            return 1
            ;;
    esac
    
    ensure_path "$LOCAL_BIN_PATH"
    
    # Verify installation
    if check_command gitleaks; then
        log_success "Gitleaks v${latest_version} installed successfully"
        echo "gitleaks=${latest_version}" >> "$VERSIONS_FILE"
    else
        log_error "Gitleaks installation verification failed"
        return 1
    fi
}

install_additional_scanners() {
    log_section "Installing Additional Security Tools"
    
    # Install Semgrep
    if ! check_command semgrep; then
        log_info "Installing Semgrep..."
        if check_command pip3; then
            pip3 install semgrep
        else
            log_warn "Cannot install Semgrep - pip3 not available"
        fi
    else
        log_info "Semgrep is already installed"
    fi
    
    # Install detect-secrets
    if ! check_command detect-secrets; then
        log_info "Installing detect-secrets..."
        if check_command pip3; then
            pip3 install detect-secrets
        else
            log_warn "Cannot install detect-secrets - pip3 not available"
        fi
    else
        log_info "detect-secrets is already installed"
    fi
}

# ===================================
# PATTERN DATABASE SETUP
# ===================================

setup_patterns_db() {
    log_section "Setting up Secrets Patterns Database"
    
    cd "$PROJECT_ROOT"
    
    # Clone or update secrets-patterns-db
    if [ -d "patterns/secrets-patterns-db" ]; then
        log_info "Updating existing patterns database..."
        cd patterns/secrets-patterns-db
        git fetch origin
        git reset --hard origin/main || git reset --hard origin/master
        cd "$PROJECT_ROOT"
    else
        log_info "Cloning patterns database..."
        mkdir -p patterns
        cd patterns
        git clone https://github.com/mazen160/secrets-patterns-db.git
        cd "$PROJECT_ROOT"
    fi
    
    # Create custom patterns directory
    mkdir -p patterns/custom
    
    # Create example custom pattern if it doesn't exist
    if [ ! -f "patterns/custom/custom_patterns.yaml" ]; then
        log_info "Creating example custom patterns file..."
        cat > patterns/custom/custom_patterns.yaml << 'EOF'
# Custom patterns for organization-specific secrets
patterns:
  - id: internal_api_key
    name: Internal API Key
    pattern: 'INT_KEY_[A-Z0-9]{32}'
    severity: high
    confidence: 0.9
    keywords:
      - internal_key
      - int_key
  
  - id: jwt_token
    name: JWT Token
    pattern: 'eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+'
    severity: medium
    confidence: 0.8
    keywords:
      - jwt
      - bearer
EOF
    fi
    
    log_success "Patterns database setup completed"
}

# ===================================
# SYSTEM DEPENDENCIES
# ===================================

install_system_deps() {
    log_section "Installing System Dependencies"
    
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
                xvfb \
                jq \
                tree \
                htop \
                tmux
            ;;
        yum|dnf)
            sudo $PACKAGE_MANAGER groupinstall -y "Development Tools"
            sudo $PACKAGE_MANAGER install -y \
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
                xorg-x11-server-Xvfb \
                jq \
                tree \
                htop \
                tmux
            ;;
        brew)
            # macOS generally has most dependencies
            brew install libxml2 libxslt jq tree htop tmux
            ;;
        apk)
            apk add --no-cache \
                build-base \
                openssl-dev \
                libffi-dev \
                libxml2-dev \
                libxslt-dev \
                zlib-dev \
                jpeg-dev \
                libpng-dev \
                libwebp-dev \
                chromium \
                firefox \
                xvfb \
                jq \
                tree \
                htop \
                tmux
            ;;
        *)
            log_warn "Cannot install system dependencies automatically"
            ;;
    esac
    
    log_success "System dependencies installed"
}

# ===================================
# CONFIGURATION SETUP
# ===================================

setup_configuration() {
    log_section "Setting up Configuration"
    
    cd "$PROJECT_ROOT"
    
    # Create necessary directories
    mkdir -p config data/{urls,content,scans/{raw,validated,state,results,intermediate},baselines,reports} logs patterns/custom tools
    
    # Create .env file if it doesn't exist
    if [ ! -f .env ]; then
        log_info "Creating .env file..."
        cat > .env << 'EOF'
# === AUTOMATED SECRETS SCANNER CONFIGURATION ===

# Environment
APP_ENV=production
DEBUG=false

# Slack Configuration
SLACK_WEBHOOK_URL=
ENABLE_SLACK=true
SLACK_CHANNEL=#security-alerts
SLACK_USERNAME=Secret Scanner Bot
SLACK_ALERT_ON_CRITICAL=true
SLACK_ALERT_ON_HIGH=true
SLACK_ALERT_ON_MEDIUM=false
SLACK_ALERT_ON_LOW=false

# Discovery Tools
ENABLE_KATANA=true
ENABLE_GAU=true
ENABLE_WAYBACKURLS=true
ENABLE_WAYURLS=false
KATANA_HEADLESS=true
KATANA_DEPTH=3
KATANA_JS_CRAWL=true
KATANA_TIMEOUT=10000
KATANA_PARALLELISM=10

# Scanning Configuration
ENABLE_TRUFFLEHOG=true
ENABLE_GITLEAKS=true
ENABLE_CUSTOM_PATTERNS=true
ENABLE_VALIDATION=true
VERIFY_SECRETS=true

# Performance
CONCURRENT_REQUESTS=10
SCAN_TIMEOUT=30000
CRAWLER_BATCH_SIZE=50
MAX_URLS_PER_DOMAIN=10000
MAX_WORKERS=10
REQUESTS_PER_SECOND=10

# Features
ENABLE_PROGRESS_MONITORING=true
SAVE_INTERMEDIATE_RESULTS=true
DRY_RUN=false
USE_STATIC_FALLBACK=true
INCLUDE_PROBLEMATIC_URLS=false

# Logging
LOG_LEVEL=INFO
LOG_FILE_PATH=./logs

# Paths
DATA_STORAGE_PATH=./data
RAW_SECRETS_PATH=./data/scans/raw
REPORTS_PATH=./data/reports
BASELINE_FILE=./data/baselines/baseline_secrets.json

# Scanning Settings
ENTROPY_THRESHOLD=4.0
MIN_SECRET_LENGTH=8
MAX_SECRET_LENGTH=500
SCAN_FILE_SIZE_LIMIT=10485760
EOF
        log_info "Please update .env file with your Slack webhook URL"
    fi
    
    # Create domains.txt if it doesn't exist
    if [ ! -f config/domains.txt ]; then
        log_info "Creating example domains.txt..."
        cat > config/domains.txt << 'EOF'
# Add target domains here (one per line)
# Lines starting with # or ! are ignored
# example.com
# app.example.com
EOF
    fi
    
    # Create config files
    for config_file in trufflehog_config.yaml gitleaks.toml slack_config.json; do
        if [ ! -f "config/$config_file" ]; then
            touch "config/$config_file"
        fi
    done
    
    log_success "Configuration setup completed"
}

# ===================================
# DOCKER SETUP (OPTIONAL)
# ===================================

setup_docker() {
    log_section "Docker Setup (Optional)"
    
    if check_command docker; then
        log_info "Docker is already installed"
        
        # Create Dockerfile if it doesn't exist
        if [ ! -f Dockerfile ]; then
            log_info "Creating Dockerfile..."
            cat > Dockerfile << 'EOF'
FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git curl wget unzip build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Go
RUN wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz && \
    rm go1.21.5.linux-amd64.tar.gz
ENV PATH="/usr/local/go/bin:$PATH"

WORKDIR /app

# Copy and install dependencies
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

# Install tools
RUN ./scripts/install_tools.sh --skip-interactive

CMD ["python", "scripts/run_scan.py"]
EOF
        fi
        
        # Create docker-compose.yml if it doesn't exist
        if [ ! -f docker-compose.yml ]; then
            log_info "Creating docker-compose.yml..."
            cat > docker-compose.yml << 'EOF'
version: '3.8'

services:
  scanner:
    build: .
    volumes:
      - ./data:/app/data
      - ./logs:/app/logs
      - ./config:/app/config
    env_file:
      - .env
    restart: unless-stopped
EOF
        fi
    else
        log_info "Docker not installed - skipping Docker setup"
    fi
}

# ===================================
# VERIFICATION
# ===================================

verify_installation() {
    log_section "Verifying Installation"
    
    local failed_checks=()
    local warning_checks=()
    
    # Core languages
    check_command python3 || failed_checks+=("Python 3")
    check_command node || failed_checks+=("Node.js")
    check_command go || failed_checks+=("Go")
    
    # URL discovery tools
    check_command gau || failed_checks+=("gau")
    check_command waybackurls || failed_checks+=("waybackurls")
    check_command katana || failed_checks+=("Katana")
    check_command wayurls || warning_checks+=("wayurls (optional)")
    
    # Secret scanners
    check_command trufflehog || failed_checks+=("TruffleHog")
    check_command gitleaks || failed_checks+=("Gitleaks")
    check_command semgrep || warning_checks+=("Semgrep (optional)")
    check_command detect-secrets || warning_checks+=("detect-secrets (optional)")
    
    # Additional tools
    check_command httpx || warning_checks+=("httpx (optional)")
    check_command nuclei || warning_checks+=("Nuclei (optional)")
    
    # Check patterns database
    [ -d "$PROJECT_ROOT/patterns/secrets-patterns-db" ] || failed_checks+=("Secrets Patterns Database")
    
    # Display results
    echo -e "\n${CYAN}=== Installation Summary ===${NC}\n"
    
    if [ ${#failed_checks[@]} -eq 0 ]; then
        log_success "All required tools are installed successfully!"
        
        echo -e "${GREEN}✓ Core Languages:${NC}"
        echo "  • Python $(python3 --version | cut -d' ' -f2)"
        echo "  • Node.js $(node --version)"
        echo "  • Go $(go version | cut -d' ' -f3)"
        
        echo -e "\n${GREEN}✓ URL Discovery Tools:${NC}"
        check_command gau && echo "  • gau $(gau -version 2>&1 | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo 'installed')"
        check_command waybackurls && echo "  • waybackurls installed"
        check_command katana && echo "  • Katana $(katana -version 2>&1 | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo 'installed')"
        
        echo -e "\n${GREEN}✓ Secret Scanners:${NC}"
        check_command trufflehog && echo "  • TruffleHog $(trufflehog --version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo 'installed')"
        check_command gitleaks && echo "  • Gitleaks $(gitleaks version 2>&1 | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo 'installed')"
        
        echo -e "\n${GREEN}✓ Configuration:${NC}"
        echo "  • Patterns Database installed"
        echo "  • Configuration files created"
        echo "  • Directory structure initialized"
        
        if [ ${#warning_checks[@]} -gt 0 ]; then
            echo -e "\n${YELLOW}⚠ Optional tools not installed:${NC}"
            for tool in "${warning_checks[@]}"; do
                echo "  • $tool"
            done
        fi
        
        echo -e "\n${GREEN}=== Next Steps ===${NC}"
        echo "1. Update your Slack webhook URL in .env file:"
        echo "   ${CYAN}nano .env${NC}"
        echo ""
        echo "2. Add target domains to config/domains.txt:"
        echo "   ${CYAN}echo 'example.com' >> config/domains.txt${NC}"
        echo ""
        echo "3. Reload your shell or run:"
        echo "   ${CYAN}source ~/.bashrc${NC}"
        echo ""
        echo "4. Run a test scan:"
        echo "   ${CYAN}python scripts/run_scan.py --domain example.com --dry-run${NC}"
        echo ""
        echo "5. Run your first real scan:"
        echo "   ${CYAN}python scripts/run_scan.py --validate --slack${NC}"
        
    else
        log_error "Some required tools failed to install:"
        for tool in "${failed_checks[@]}"; do
            echo "  ✗ $tool"
        done
        
        echo -e "\nPlease check the logs above for error messages."
        exit 1
    fi
}

# ===================================
# MAIN EXECUTION
# ===================================

main() {
    print_banner
    
    # Create log file
    LOG_FILE="$PROJECT_ROOT/install_$(date +%Y%m%d_%H%M%S).log"
    exec 1> >(tee -a "$LOG_FILE")
    exec 2>&1
    
    # Detect operating system
    detect_os
    
    # Check prerequisites
    check_prerequisites
    
    # Create necessary directories
    mkdir -p "$LOCAL_BIN_PATH" "$GO_BIN_PATH" "$TOOLS_DIR"
    
    # Install components
    install_system_deps
    install_python
    install_nodejs
    install_go
    install_go_tools
    install_trufflehog
    install_gitleaks
    install_additional_scanners
    setup_patterns_db
    setup_configuration
    setup_docker
    
    # Verify installation
    verify_installation
    
    log_success "Installation completed successfully!"
    echo -e "\n${GREEN}Log file saved to: $LOG_FILE${NC}"
}

# Handle script arguments
case "${1:-}" in
    --python-only)
        print_banner
        detect_os
        install_python
        ;;
    --node-only)
        print_banner
        detect_os
        install_nodejs
        ;;
    --go-only)
        print_banner
        detect_os
        install_go
        install_go_tools
        ;;
    --scanners-only)
        print_banner
        detect_os
        install_trufflehog
        install_gitleaks
        install_additional_scanners
        ;;
    --patterns-only)
        print_banner
        setup_patterns_db
        ;;
    --verify)
        print_banner
        verify_installation
        ;;
    --skip-interactive)
        # For Docker builds
        main
        ;;
    --help|-h)
        echo "Enhanced Automated Secrets Scanner - Installation Script v2.0"
        echo ""
        echo "Usage: $0 [option]"
        echo ""
        echo "Options:"
        echo "  --python-only       Install only Python dependencies"
        echo "  --node-only         Install only Node.js dependencies"
        echo "  --go-only           Install only Go and Go tools"
        echo "  --scanners-only     Install only secret scanners"
        echo "  --patterns-only     Setup only patterns database"
        echo "  --verify            Verify installation"
        echo "  --skip-interactive  Skip interactive prompts (for automation)"
        echo "  --help              Show this help message"
        echo ""
        echo "Without options, the script will install all components."
        echo ""
        echo "Examples:"
        echo "  $0                  # Full installation"
        echo "  $0 --verify         # Check if everything is installed"
        echo "  $0 --scanners-only  # Update just the scanners"
        ;;
    *)
        main
        ;;
esac