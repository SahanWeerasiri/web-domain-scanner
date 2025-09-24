#!/bin/bash

# Web Domain Scanner - Docker Build and Run Script

set -e

# Color codes for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_header() {
    echo -e "${BLUE}[BUILD]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

print_header "Web Domain Scanner - Docker Build Script"

# Change to project directory
cd "$PROJECT_DIR"

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    print_error "Docker is not installed. Please install Docker first."
    exit 1
fi

# Check if docker-compose is available
if command -v docker-compose &> /dev/null; then
    COMPOSE_CMD="docker-compose"
elif docker compose version &> /dev/null; then
    COMPOSE_CMD="docker compose"
else
    print_error "Docker Compose is not available. Please install Docker Compose."
    exit 1
fi

# Build the Docker image
print_status "Building Docker image..."
docker build -t web-domain-scanner .

if [ $? -eq 0 ]; then
    print_status "Docker image built successfully!"
else
    print_error "Failed to build Docker image"
    exit 1
fi

# Ask user what to do next
echo ""
echo "What would you like to do next?"
echo "1) Run with Docker Compose (recommended)"
echo "2) Run with Docker directly"
echo "3) Just build (exit)"
read -p "Enter your choice (1-3): " choice

case $choice in
    1)
        print_status "Starting with Docker Compose..."
        $COMPOSE_CMD up -d
        if [ $? -eq 0 ]; then
            print_status "Container started successfully!"
            print_status "API Documentation: http://localhost:8000/api/docs"
            print_status "Health Check: http://localhost:8000/health"
            print_status "View logs: $COMPOSE_CMD logs -f web-domain-scanner"
        else
            print_error "Failed to start container with Docker Compose"
            exit 1
        fi
        ;;
    2)
        print_status "Starting with Docker directly..."
        docker run -d \
            --name web-domain-scanner \
            -p 8000:8000 \
            -v "$PROJECT_DIR/logs:/app/logs" \
            -v "$PROJECT_DIR/output:/app/output" \
            web-domain-scanner
        
        if [ $? -eq 0 ]; then
            print_status "Container started successfully!"
            print_status "API Documentation: http://localhost:8000/api/docs"
            print_status "Health Check: http://localhost:8000/health"
            print_status "View logs: docker logs web-domain-scanner"
        else
            print_error "Failed to start container"
            exit 1
        fi
        ;;
    3)
        print_status "Build complete. Use 'docker run' or 'docker-compose up' to start the scanner."
        ;;
    *)
        print_error "Invalid choice"
        exit 1
        ;;
esac

print_status "Done!"