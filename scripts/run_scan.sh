#!/bin/bash

# Web Domain Scanner - Quick Start Script
# Run a domain scan with proper environment activation

set -e

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_DIR="$PROJECT_DIR/.venv"

# Color codes
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Check if domain is provided
if [ $# -eq 0 ]; then
    echo "Usage: $0 <domain> [gemini-api-key]"
    echo "Example: $0 example.com"
    echo "Example: $0 example.com AIzaSyXXXXXXXXXXXX"
    exit 1
fi

DOMAIN=$1
GEMINI_KEY=${2:-""}

# Check if virtual environment exists
if [ ! -d "$VENV_DIR" ]; then
    print_error "Virtual environment not found. Please run setup_environment.sh first."
    exit 1
fi

# Activate virtual environment
print_status "Activating virtual environment..."
source "$VENV_DIR/bin/activate"

# Change to project directory
cd "$PROJECT_DIR"

# Run the scanner
print_status "Starting domain reconnaissance for: $DOMAIN"
if [ -n "$GEMINI_KEY" ]; then
    python src/main.py "$DOMAIN" --gemini-key "$GEMINI_KEY"
else
    python src/main.py "$DOMAIN"
fi

print_status "Scan completed! Check the generated output directory for results."
