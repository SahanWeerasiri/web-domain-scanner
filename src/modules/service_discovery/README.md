# Service Discovery Module

## Overview
The Service Discovery module provides comprehensive service discovery and port scanning capabilities for network reconnaissance. It combines multiple scanning techniques, service identification methods, and external tool integration to deliver thorough and accurate results.

## Features
- **Multiple Scanning Modes**: Quick, Smart, and Deep scanning approaches
- **Advanced Service Identification**: Banner analysis and protocol fingerprinting
- **External Tools Integration**: Support for nmap, rustscan, and masscan
- **Intelligent Rate Limiting**: Adaptive rate control to avoid detection
- **Comprehensive Reporting**: Detailed results with security analysis
- **Modular Architecture**: Clean separation of concerns for maintainability

## Module Structure

### Core Components
- **`main.py`**: Main orchestrator coordinating all submodules
- **`config.py`**: Configuration management for all scanning operations
- **`base.py`**: Shared utilities and common functionality
- **`__init__.py`**: Package initialization and public API

### Submodules
- **`port_scanning/`**: Port scanning with multiple modes and techniques (standalone capable)
- **`service_identification/`**: Service fingerprinting and banner analysis (standalone capable)  
- **`external_tools/`**: Integration with external scanning tools (standalone capable)

## Scanning Modes

### Quick Scan
- Fast reconnaissance of common ports
- Basic service identification
- Minimal resource usage
- Suitable for initial discovery

### Smart Scan
- Intelligent port selection based on discovered services
- Enhanced service detection capabilities
- Balanced speed and thoroughness
- Adaptive scanning techniques

### Deep Scan
- Comprehensive port range analysis
- External tools integration
- Advanced service fingerprinting
- Security implications assessment

## Main Classes

### ServiceDiscovery
Primary orchestrator class providing unified interface.

**Key Methods:**
- `discover_services(common_ports, scan_mode, **kwargs)`: Main discovery method
- `get_comprehensive_results()`: Complete results retrieval
- `generate_report()`: Comprehensive report generation
- `get_errors()`: Error information access

### ServiceDiscoveryConfig
Configuration management for all scanning operations.

**Key Features:**
- Scan timeout and worker configuration
- Rate limiting parameters
- External tools settings
- Security and performance options

## Usage Examples

### Basic Usage
```python
from service_discovery import ServiceDiscovery, ServiceDiscoveryConfig

# Initialize with default configuration
scanner = ServiceDiscovery("example.com")

# Perform quick scan
results = scanner.discover_services(scan_mode='quick')

# Access open ports
open_ports = results['services']['open_ports']
```

### Advanced Configuration
```python
from service_discovery import ServiceDiscovery, ServiceDiscoveryConfig

# Create custom configuration
config = ServiceDiscoveryConfig()
config.scan_timeout = 5.0
config.max_workers = 30
config.enable_external_tools = True

# Initialize scanner with custom config
scanner = ServiceDiscovery("target.com", config)

# Perform deep scan with custom ports
custom_ports = {80: 'HTTP', 443: 'HTTPS', 22: 'SSH'}
results = scanner.discover_services(custom_ports, scan_mode='deep')

# Generate comprehensive report
report = scanner.generate_report()
```

### Command Line Usage
```bash
# Quick scan of domain
python -m service_discovery.main example.com --mode quick

# Deep scan with external tools and verbose output
python -m service_discovery.main example.com --mode deep --verbose

# Custom configuration with timeout and workers
python -m service_discovery.main example.com --mode smart --timeout 10 --max-workers 50

# Save results to JSON file
python -m service_discovery.main example.com --mode deep --output results.json
```

### Standalone Submodule Usage
Each submodule can be run independently for specific tasks:

```bash
# Port scanning only
python port_scanning/port_scanning.py example.com --ports 80,443,22 --mode smart

# Service identification for specific port
python service_identification/service_identification.py example.com --port 80 --ssl

# External tools scanning
python external_tools/external_tools.py example.com --tool nmap --mode deep

# Check external tool availability
python external_tools/external_tools.py --check-tools
```

## Configuration Options

### Scan Parameters
- `scan_timeout`: Connection timeout for port scanning
- `max_workers`: Maximum concurrent scanning threads
- `rate_limit`: Requests per second limitation
- `retry_attempts`: Failed connection retry count

### Banner Grabbing
- `banner_timeout`: Banner collection timeout
- `banner_max_bytes`: Maximum banner size
- `enable_banner_grab`: Banner grabbing toggle

### External Tools
- `enable_external_tools`: External tools usage
- `prefer_rustscan`: Rustscan preference setting
- `nmap_timeout`: Nmap execution timeout
- `rustscan_timeout`: Rustscan execution timeout

## Output Format
Results are returned in structured dictionary format containing:
- **Open Ports**: Detailed information about discovered services
- **Scan Statistics**: Timing and performance metrics
- **Discovery Summary**: High-level findings overview
- **Security Analysis**: Risk assessment and recommendations
- **Error Information**: Detailed error logging

## Error Handling
Comprehensive error handling includes:
- Network connectivity issues
- Target resolution failures
- Tool execution problems
- Configuration validation errors
- Resource limitation handling

## Security Considerations
- Rate limiting to avoid overwhelming targets
- Stealth mode options for discrete scanning
- Configurable timeout values
- Error handling to prevent information leakage
- Optional external tool integration

## Dependencies
- Python 3.7+ standard library
- Optional: requests (for enhanced HTTP probing)
- Optional: dnspython (for advanced DNS operations)
- External tools: nmap, rustscan, masscan (optional)

## Integration
The module integrates seamlessly with the larger web domain scanner framework, sharing:
- Common network utilities
- Configuration management patterns
- Error handling strategies
- Logging infrastructure
- Result formatting standards