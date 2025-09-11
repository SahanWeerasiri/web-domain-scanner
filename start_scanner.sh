#!/bin/bash

# Web Domain Scanner - Complete Startup Script
# This script starts both the FastAPI server and Streamlit UI

set -e

echo "=========================================="
echo "    Web Domain Scanner - Startup"
echo "=========================================="

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_DIR="$PROJECT_DIR/src"
UI_DIR="$PROJECT_DIR/ui"

# Color codes for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    print_error "Python 3 is not installed. Please install Python 3.8 or higher."
    exit 1
fi

print_status "Python found: $(python3 --version)"

# Install UI dependencies
print_status "Installing UI dependencies..."
cd "$UI_DIR"
if [ -f "requirements_ui.txt" ]; then
    pip install -r requirements_ui.txt
    print_status "UI dependencies installed successfully!"
else
    print_warning "requirements_ui.txt not found. Installing basic dependencies..."
    pip install streamlit requests pandas plotly
fi

# Check if server dependencies are installed
cd "$PROJECT_DIR"
if [ -f "requirements.txt" ]; then
    print_status "Installing server dependencies..."
    pip install -r requirements.txt
fi

# Function to start the FastAPI server
start_server() {
    print_status "Starting FastAPI server..."
    cd "$SERVER_DIR"
    python server.py &
    SERVER_PID=$!
    echo $SERVER_PID > server.pid
    print_status "Server started with PID: $SERVER_PID"
}

# Function to start the Streamlit UI
start_ui() {
    print_status "Starting Streamlit UI..."
    cd "$UI_DIR"
    streamlit run streamlit_app.py --server.port 8501 --server.address localhost &
    UI_PID=$!
    echo $UI_PID > ui.pid
    print_status "UI started with PID: $UI_PID"
}

# Function to stop services
stop_services() {
    print_status "Stopping services..."
    
    if [ -f "$SERVER_DIR/server.pid" ]; then
        SERVER_PID=$(cat "$SERVER_DIR/server.pid")
        if kill -0 $SERVER_PID 2>/dev/null; then
            kill $SERVER_PID
            print_status "Server stopped"
        fi
        rm -f "$SERVER_DIR/server.pid"
    fi
    
    if [ -f "$UI_DIR/ui.pid" ]; then
        UI_PID=$(cat "$UI_DIR/ui.pid")
        if kill -0 $UI_PID 2>/dev/null; then
            kill $UI_PID
            print_status "UI stopped"
        fi
        rm -f "$UI_DIR/ui.pid"
    fi
}

# Trap to ensure cleanup on exit
trap stop_services EXIT

# Check if services are already running
if [ -f "$SERVER_DIR/server.pid" ]; then
    SERVER_PID=$(cat "$SERVER_DIR/server.pid")
    if kill -0 $SERVER_PID 2>/dev/null; then
        print_warning "Server is already running with PID: $SERVER_PID"
    else
        rm -f "$SERVER_DIR/server.pid"
    fi
fi

if [ -f "$UI_DIR/ui.pid" ]; then
    UI_PID=$(cat "$UI_DIR/ui.pid")
    if kill -0 $UI_PID 2>/dev/null; then
        print_warning "UI is already running with PID: $UI_PID"
    else
        rm -f "$UI_DIR/ui.pid"
    fi
fi

# Start services
start_server
sleep 3  # Give server time to start

# Test if server is responding
print_status "Testing server connection..."
if curl -s http://localhost:8000 > /dev/null 2>&1; then
    print_status "Server is responding!"
else
    print_warning "Server might not be fully ready yet. Starting UI anyway..."
fi

start_ui

print_info "=========================================="
print_info "    Services Started Successfully!"
print_info "=========================================="
print_info "FastAPI Server: http://localhost:8000"
print_info "Streamlit UI:   http://localhost:8501"
print_info "=========================================="
print_info "Press Ctrl+C to stop all services"
print_info "=========================================="

# Wait for services
wait
