# Service Identification Module

## Overview
The Service Identification module provides advanced service identification and fingerprinting capabilities including banner grabbing, protocol-specific probing, and comprehensive service analysis.

## Features
- **Advanced Banner Grabbing**: Multi-protocol banner collection
- **Service Fingerprinting**: Pattern-based service identification
- **Protocol Probing**: Protocol-specific connection attempts
- **SSL/TLS Analysis**: Certificate and cipher suite detection
- **Web Technology Detection**: Framework and technology identification
- **Version Detection**: Software version extraction from banners

## Identification Methods

### Port-Based Identification
- Uses standard port-to-service mappings
- Provides baseline service identification
- Fast and reliable for standard services

### Banner Analysis
- Analyzes service banners for detailed information
- Pattern matching against known service signatures
- Version and product information extraction

### Protocol Probing
- HTTP/HTTPS specific probing
- SSH version detection
- FTP welcome message analysis
- SMTP greeting collection

### SSL/TLS Analysis
- Certificate information extraction
- Cipher suite identification
- Protocol version detection
- Security configuration assessment

## Main Classes

### ServiceIdentifier
Primary class for comprehensive service identification.

**Key Methods:**
- `identify_service(ip, port, banner)`: Complete service identification
- `grab_banner(ip, port, timeout)`: Banner grabbing functionality

### BannerGrabber
Specialized class for banner collection operations.

**Key Methods:**
- `grab_banners(ip, ports)`: Multi-port banner grabbing
- `get_errors()`: Error information retrieval

## Service Detection Capabilities

### Web Services
- Server software identification (nginx, Apache, IIS)
- Framework detection (WordPress, Joomla, Drupal)
- Technology stack analysis (PHP, ASP.NET, Node.js)
- JavaScript library identification

### Database Services
- MySQL, PostgreSQL, MSSQL detection
- MongoDB and Redis identification
- Version information extraction
- Connection security analysis

### Remote Access Services
- SSH version and configuration
- RDP service detection
- VNC identification
- Telnet service analysis

## Configuration
Uses `ServiceDiscoveryConfig` for:
- Banner grabbing timeouts
- Maximum banner size limits
- Protocol-specific probe settings
- SSL/TLS analysis parameters

## Usage Example

### Programmatic Usage
```python
from service_discovery.service_identification import ServiceIdentifier
from service_discovery.config import ServiceDiscoveryConfig

# Initialize identifier
config = ServiceDiscoveryConfig()
identifier = ServiceIdentifier(config)

# Identify service on specific port
result = identifier.identify_service("192.168.1.1", 80)

# Access identification results
service = result.get('service')
version = result.get('version')
confidence = result.get('confidence')
```

### Standalone Command Line Usage
The module can be run independently for service identification:

```bash
# Basic service identification
python service_identification.py example.com --port 80

# Force SSL analysis
python service_identification.py 192.168.1.1 --port 443 --ssl

# Banner-only mode for faster results
python service_identification.py example.com --port 22 --banner-only

# Verbose output with custom timeout
python service_identification.py target.com --port 80 --timeout 10 --verbose

# Save detailed results to file
python service_identification.py example.com --port 443 --ssl --output results.json
```

### Command Line Options
- `target`: Target IP address or hostname
- `--port`: Port number to identify service on (required)
- `--ssl`: Force SSL/TLS analysis
- `--banner-only`: Only grab banner, skip advanced identification
- `--timeout`: Connection timeout in seconds (default: 5)
- `--output`: Save results to JSON file
- `--verbose`: Enable verbose logging

### Output Information
The standalone mode provides detailed service information including:
- Service name and confidence level
- Banner information and version detection
- Protocol-specific details (HTTP headers, SSH version, etc.)
- SSL/TLS certificate information (when applicable)
- Detected technologies for web services
- Security notes and recommendations

## Error Handling
Comprehensive error handling for:
- Connection failures
- Timeout conditions
- SSL/TLS handshake errors
- Malformed banner responses
- Protocol-specific errors

## Dependencies
- Python standard library (socket, ssl, re)
- Service discovery base utilities
- Configuration module
- Optional: requests library for HTTP probing