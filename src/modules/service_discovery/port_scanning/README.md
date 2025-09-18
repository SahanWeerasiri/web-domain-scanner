# Port Scanning Module

## Overview
The Port Scanning module provides comprehensive port scanning capabilities with multiple scanning modes optimized for different use cases and security requirements.

## Features
- **Multiple Scanning Modes**: Quick, Smart, and Deep scanning modes
- **Concurrent Scanning**: Multi-threaded port scanning for efficiency
- **Rate Limiting**: Built-in rate limiting to avoid overwhelming target systems
- **Service Detection**: Basic service identification during scanning
- **Banner Grabbing**: Automatic banner collection from open ports
- **Smart Extensions**: Intelligent port selection based on discovered services

## Scanning Modes

### Quick Scan
- Scans common ports only
- Fast execution time
- Basic service detection
- Suitable for initial reconnaissance

### Smart Scan
- Starts with common ports
- Extends scan based on discovered services
- Intelligent port fuzzing
- Enhanced service detection
- Balanced speed and thoroughness

### Deep Scan
- Comprehensive port range scanning
- Multiple verification attempts
- Enhanced banner grabbing
- Advanced service analysis
- Security implications assessment

## Main Classes

### PortScanner
Primary class for port scanning operations.

**Key Methods:**
- `scan_ports(ports, scan_mode, **kwargs)`: Main scanning method
- `get_results()`: Retrieve scan results
- `get_errors()`: Get error information

## Configuration
The module uses `ServiceDiscoveryConfig` for configuration management, including:
- Scan timeout settings
- Maximum worker threads
- Rate limiting parameters
- Banner grabbing timeouts

## Usage Example

### Programmatic Usage
```python
from service_discovery.port_scanning import PortScanner
from service_discovery.config import ServiceDiscoveryConfig

# Initialize scanner
config = ServiceDiscoveryConfig()
scanner = PortScanner("192.168.1.1", config)

# Perform quick scan
ports = [80, 443, 22, 21, 25]
results = scanner.scan_ports(ports, 'quick')

# Get open ports
open_ports = results.get('open_ports', {})
```

### Standalone Command Line Usage
The module can be run independently from the command line:

```bash
# Basic port scan
python port_scanning.py example.com

# Custom port range and mode
python port_scanning.py 192.168.1.1 --ports 80,443,22 --mode deep

# Port range scanning with output file
python port_scanning.py example.com --ports 1-1000 --mode smart --output results.json

# Verbose scanning with custom workers and timeout
python port_scanning.py target.com --mode deep --workers 50 --timeout 5 --verbose

# CIDR range scanning (if supported)
python port_scanning.py 192.168.1.0/24 --mode quick --ports 80,443
```

### Command Line Options
- `target`: Target IP address, hostname, or CIDR range
- `--ports`: Port range (e.g., "1-1000") or comma-separated ports (e.g., "80,443,22")
- `--mode`: Scanning mode (quick, smart, deep)
- `--workers`: Number of concurrent workers (default: 100)
- `--timeout`: Connection timeout in seconds (default: 3)
- `--output`: Save results to JSON file
- `--verbose`: Enable verbose logging

## Error Handling
The module includes comprehensive error handling for:
- Connection timeouts
- Network unreachable errors
- Permission denied errors
- Rate limiting responses

## Dependencies
- Python standard library (socket, threading, concurrent.futures)
- Service discovery base utilities
- Configuration module