# Service Identification Module

## Overview
The Service Identification module provides comprehensive service identification and fingerprinting capabilities by analyzing open ports, grabbing service banners, and performing protocol-specific probing. It integrates with port scanner results to identify services, versions, and security configurations.

## Features
- **Banner Grabbing**: Automated banner collection from open ports with protocol-specific probes
- **Service Fingerprinting**: Pattern-based service identification using banner analysis
- **SSL/TLS Detection**: Automatic SSL/TLS service detection and certificate analysis
- **HTTP Service Analysis**: Web server identification with status code and header analysis
- **Version Extraction**: Software version detection from service banners
- **Port Scanner Integration**: Seamless integration with existing port scanning results

## Installation

### Prerequisites
- Python 3.6 or higher
- Standard Python libraries (socket, ssl, urllib, json, logging)
- Network connectivity to target systems
- Appropriate permissions for network connections

### Installation Steps
1. Clone or download the web-domain-scanner repository
2. Navigate to the service identification module directory
3. No additional package installation required (uses built-in libraries)
4. Ensure proper network permissions for scanning activities

## Configuration

### Configuration Options
- **Timeout**: Connection timeout for banner grabbing (default: 5 seconds)
- **SSL Context**: Unverified SSL context for HTTPS probing
- **Protocol Probes**: Custom probe data for different services
- **Common Ports**: Pre-defined service-to-port mappings

### Service Detection Methods

#### Port-Based Identification
- Uses standard port-to-service mappings for 17 common services
- Provides baseline service identification for FTP, SSH, HTTP, HTTPS, databases, etc.
- Fast and reliable for standard services on default ports

#### Banner Analysis
- Analyzes service banners using pattern matching
- Identifies services like SSH, HTTP, FTP, SMTP, MySQL, PostgreSQL, Redis
- Extracts version information using regex patterns
- Handles encoding errors gracefully

#### SSL/TLS Detection
- Automatic SSL/TLS service detection for common encrypted ports
- Certificate and cipher information extraction
- Support for both standard SSL ports and SSL-enabled services on custom ports

#### HTTP Service Analysis
- HTTP/HTTPS specific probing with HEAD requests
- Server header identification and content-type detection
- Status code analysis and response handling

## Usage

### Basic Usage
```bash
# Identify services on common ports
python service_identification.py example.com

# Identify services on specific ports
python service_identification.py 192.168.1.1 -p 80,443,22

# Identify services with custom timeout
python service_identification.py target.com -p 1-1000 -t 10
```

### Advanced Usage
```bash
# Verbose output with detailed logging
python service_identification.py example.com -p 80,443,22,21,25 --verbose

# Save results to JSON file
python service_identification.py target.com -p 1-100 --output results.json

# Integration with port scanner results (programmatic)
python service_identification.py example.com -p 80,443 -v -o detailed_scan.json
```

### Programmatic Usage
```python
from service_identification import SimpleServiceIdentifier, identify_services_from_scanner

# Direct service identification
identifier = SimpleServiceIdentifier(timeout=5)
results = identifier.identify_services("example.com", [80, 443, 22])

# Integration with port scanner
port_scan_results = {
    'method': 'quick',
    'open_ports': [22, 80, 443, 3306],
    'output': "Nmap scan results..."
}

service_results = identify_services_from_scanner("example.com", port_scan_results)
print(service_results)
```

## Methods

### identify_services(target, ports)
Identifies services on multiple ports, returning comprehensive information including banners, versions, and SSL status.

### identify_services_from_scanner(target, scan_results)
Integrates with port scanner results to perform service identification on discovered open ports.

### _grab_banner(target, port)
Performs banner grabbing with protocol-specific probes for enhanced service detection.

## Output

### Output Format
Returns structured JSON data containing:
- Target information and scan metadata
- Service identification results per port
- Banner information and version detection
- SSL/TLS status and certificate details
- HTTP service information (headers, status codes)
- Summary statistics and service distribution

### Results Interpretation
- **Service Name**: Identified service type (SSH, HTTP, MySQL, etc.)
- **Banner**: Raw service banner or greeting message
- **Version**: Extracted version information when available
- **SSL Status**: Whether the service supports SSL/TLS encryption
- **Protocol Info**: Additional protocol-specific details (HTTP headers, SSL certificates)
- **Error Messages**: Connection or identification error details

## Examples

### Example 1: Basic Service Identification
```bash
python service_identification.py scanme.nmap.org -p 22,80,443
```

### Example 2: Comprehensive Service Analysis
```bash
python service_identification.py 192.168.1.100 -p 21,22,23,25,53,80,110,143,443,993,995 -v -o scan_results.json
```

### Example 3: Integration with Port Scanner
```bash
# First run port scanner, then identify services
python ../port_scanning/port_scanner.py example.com quick
python service_identification.py example.com -p 80,443,22 -v
```