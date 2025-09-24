# Use Python 3.11 slim image as base
FROM python:3.11-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system dependencies required for the scanner
RUN apt-get update && apt-get install -y \
    # Network tools for scanning
    nmap \
    dnsutils \
    curl \
    wget \
    # Browser dependencies for SeleniumBase
    chromium \
    chromium-driver \
    # Build tools for Python packages
    gcc \
    g++ \
    make \
    # Git for potential dependency installations
    git \
    # Clean up apt cache
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Set display port to avoid issues with headless browser
ENV DISPLAY=:99

# Create app directory
WORKDIR /app

# Copy requirements first to leverage Docker layer caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --upgrade pip && \
    pip install -r requirements.txt

# Copy the entire application
COPY . .

# Set Python path to include src directory for proper imports
ENV PYTHONPATH="/app:/app/src"

# Create necessary directories for logs and output
RUN mkdir -p /app/logs /app/output /app/temp

# Set proper permissions
RUN chmod +x scripts/*.sh 2>/dev/null || true

# Create a non-root user for security
RUN useradd -m -u 1000 scanner && \
    chown -R scanner:scanner /app
USER scanner

# Expose the port that the FastAPI server runs on
EXPOSE 8000

# Health check to ensure the server is running
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Default command to run the FastAPI server
CMD ["uvicorn", "src.server:app", "--host", "0.0.0.0", "--port", "8000"]