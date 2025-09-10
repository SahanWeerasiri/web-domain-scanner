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

# Function to print usage
print_usage() {
    echo "Usage: $0 <domain> [options]"
    echo ""
    echo "Options:"
    echo "  --gemini-key <key>     Specify Gemini API key"
    echo "  --openai-key <key>     Specify OpenAI API key"
    echo "  --anthropic-key <key>  Specify Anthropic API key"
    echo "  --async                Use asynchronous processing"
    echo ""
    echo "Examples:"
    echo "  $0 example.com"
    echo "  $0 example.com --gemini-key YOURKEY"
    echo "  $0 example.com --openai-key YOURKEY --async"
    echo "  $0 example.com --gemini-key YOURKEY --openai-key YOURKEY --anthropic-key YOURKEY"
}

# Check if domain is provided
if [ $# -eq 0 ]; then
    print_usage
    exit 1
fi

# Parse arguments
DOMAIN=$1
shift

# Default values
GEMINI_KEY=""
OPENAI_KEY=""
ANTHROPIC_KEY=""
ASYNC_FLAG=""

# Parse options
while [ $# -gt 0 ]; do
    case "$1" in
        --gemini-key)
            GEMINI_KEY="$2"
            shift 2
            ;;
        --openai-key)
            OPENAI_KEY="$2"
            shift 2
            ;;
        --anthropic-key)
            ANTHROPIC_KEY="$2"
            shift 2
            ;;
        --async)
            ASYNC_FLAG="--async"
            shift
            ;;
        *)
            print_error "Unknown option: $1"
            print_usage
            exit 1
            ;;
    esac
done

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

# Build command
COMMAND="python src/main.py \"$DOMAIN\""
if [ -n "$GEMINI_KEY" ]; then
    COMMAND="$COMMAND --gemini-key \"$GEMINI_KEY\""
fi
if [ -n "$OPENAI_KEY" ]; then
    COMMAND="$COMMAND --openai-key \"$OPENAI_KEY\""
fi
if [ -n "$ANTHROPIC_KEY" ]; then
    COMMAND="$COMMAND --anthropic-key \"$ANTHROPIC_KEY\""
fi
if [ -n "$ASYNC_FLAG" ]; then
    COMMAND="$COMMAND $ASYNC_FLAG"
fi

# Run the scanner
print_status "Starting domain reconnaissance for: $DOMAIN"
eval $COMMAND

print_status "Scan completed! Check the generated output directory for results."
