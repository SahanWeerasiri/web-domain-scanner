#!/bin/bash

# Web Domain Scanner - Environment Setup Script
# This script sets up the complete environment for the domain scanner

set -e

echo "=========================================="
echo "Web Domain Scanner - Environment Setup"
echo "=========================================="

# Check if running as root for system packages
if [ "$EUID" -eq 0 ]; then
    echo "Please do not run this script as root. It will prompt for sudo when needed."
    exit 1
fi

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_DIR="$PROJECT_DIR/.venv"

echo "Project directory: $PROJECT_DIR"

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

# Check Python version
print_status "Checking Python version..."
if ! command -v python3 &> /dev/null; then
    print_error "Python 3 is not installed. Please install Python 3.7 or higher."
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
REQUIRED_VERSION="3.7"

if ! python3 -c "import sys; exit(0 if sys.version_info >= (3,7) else 1)"; then
    print_error "Python $PYTHON_VERSION is installed, but version $REQUIRED_VERSION or higher is required."
    exit 1
fi

print_status "Python $PYTHON_VERSION is compatible."

# Install system dependencies
print_status "Installing system dependencies..."
if command -v apt-get &> /dev/null; then
    # Debian/Ubuntu/Kali
    sudo apt-get update -qq
    sudo apt-get install -y nmap dnsutils curl wget git
elif command -v yum &> /dev/null; then
    # CentOS/RHEL/Fedora
    sudo yum install -y nmap bind-utils curl wget git
elif command -v brew &> /dev/null; then
    # macOS
    brew install nmap
else
    print_warning "Could not detect package manager. Please install nmap and dnsutils manually."
fi

# Create virtual environment if it doesn't exist
if [ ! -d "$VENV_DIR" ]; then
    print_status "Creating Python virtual environment..."
    python3 -m venv "$VENV_DIR"
else
    print_status "Virtual environment already exists."
fi

# Activate virtual environment
print_status "Activating virtual environment..."
source "$VENV_DIR/bin/activate"

# Upgrade pip
print_status "Upgrading pip..."
pip install --upgrade pip

# Install Python dependencies
print_status "Installing Python dependencies..."
if [ -f "$PROJECT_DIR/requirements.txt" ]; then
    pip install -r "$PROJECT_DIR/requirements.txt"
else
    print_error "requirements.txt not found!"
    exit 1
fi

# Create .env file if it doesn't exist
if [ ! -f "$PROJECT_DIR/.env" ]; then
    print_status "Creating .env file from template..."
    if [ -f "$PROJECT_DIR/.env.example" ]; then
        cp "$PROJECT_DIR/.env.example" "$PROJECT_DIR/.env"
        print_warning "Please edit .env file and add your Gemini API key for AI-powered features."
    else
        print_warning ".env.example not found. Creating basic .env file..."
        cat > "$PROJECT_DIR/.env" << 'EOL'
# Gemini AI API Key (Required for AI-powered endpoint discovery)
GEMINI_API_KEY=your_gemini_api_key_here

# Scanner Configuration (Optional - defaults will be used if not set)
MAX_THREADS=15
RATE_LIMIT=5
REQUEST_TIMEOUT=10
SCAN_TIMEOUT=300

# Output Settings (Optional)
OUTPUT_DIR=scan_results
LOG_LEVEL=INFO

# SSL Verification (Set to false for self-signed certificates)
VERIFY_SSL=true
EOL
    fi
else
    print_status ".env file already exists."
fi

# Create necessary directories
print_status "Creating necessary directories..."
mkdir -p "$PROJECT_DIR/scan_results"
mkdir -p "$PROJECT_DIR/logs"

# Set proper permissions
chmod +x "$PROJECT_DIR/scripts/"*.sh 2>/dev/null || true

# Verify installation
print_status "Verifying installation..."
if python3 -c "import requests, beautifulsoup4, dns.resolver, nmap" 2>/dev/null; then
    print_status "All Python dependencies are correctly installed."
else
    print_error "Some Python dependencies failed to install correctly."
    exit 1
fi

# Check nmap installation
if command -v nmap &> /dev/null; then
    print_status "nmap is correctly installed."
else
    print_warning "nmap is not available in PATH. Some features may not work."
fi

echo ""
echo "=========================================="
print_status "Setup completed successfully!"
echo "=========================================="
echo ""
echo "Next steps:"
echo "1. Edit .env file to add your Gemini API key (optional but recommended)"
echo "2. Activate the virtual environment: source .venv/bin/activate"
echo "3. Run the scanner: python src/main.py example.com"
echo ""
echo "For AI-powered endpoint discovery, get a Gemini API key from:"
echo "https://aistudio.google.com/apikey"
echo ""
