# Service Discovery Module

## Overview
The Service Discovery module provides a unified interface for comprehensive network reconnaissance by combining port scanning and service identification capabilities. It orchestrates NMAP-based port scanning with intelligent service fingerprinting to deliver complete service discovery results with detailed analysis and reporting.

## Features
- **Unified Interface**: Single entry point combining port scanning and service identification
- **Multiple Scanning Modes**: Quick (top 100), Smart (top 1000), and Deep (all ports) scanning approaches
- **Integrated Service Identification**: Automatic service fingerprinting on discovered open ports
- **Flexible Output Formats**: Support for both human-readable text and structured JSON output
- **Comprehensive Results**: Combined scan results with timing, statistics, and service details
- **Error Handling**: Robust error handling with detailed logging and recovery mechanisms

## Installation

### Prerequisites
- Python 3.6 or higher
- NMAP installed and accessible from command line
- Standard Python libraries (json, logging, argparse, sys)
- Network connectivity and appropriate scanning permissions

### Installation Steps
1. Ensure NMAP is installed on your system
2. Clone or download the web-domain-scanner repository
3. Navigate to the service discovery module directory
4. No additional Python packages required (uses subprocess and built-in libraries)

## Configuration

### Configuration Options
- **Scan Mode**: Choose between quick, smart, or deep scanning approaches
- **Port Specification**: Custom port ranges or comma-separated port lists
- **Output Format**: Text (human-readable) or JSON (structured data)
- **Verbosity**: Enable detailed logging for debugging and monitoring
- **File Output**: Save results to JSON files for further analysis

### Scanning Modes

#### Quick Scan
- Scans top 100 most common ports using NMAP
- Fast execution suitable for initial reconnaissance
- Basic service identification on discovered ports
- Minimal resource usage and network footprint

#### Smart Scan (Default)
- Scans top 1000 ports with service version detection
- Includes OS fingerprinting and default script scanning
- Balanced approach between thoroughness and speed
- Enhanced service identification with banner analysis

#### Deep Scan
- Comprehensive scan of all 65535 ports
- Includes vulnerability detection scripts
- Advanced service enumeration and detailed analysis
- Complete security assessment capabilities

## Usage

### Basic Usage
```bash
# Default smart scan
python main.py example.com

# Quick scan for rapid reconnaissance
python main.py 192.168.1.1 --mode quick

# Deep comprehensive scan
python main.py target.com --mode deep
```

### Advanced Usage
```bash
# Custom port specification with verbose output
python main.py example.com --mode smart --ports 80,443,22,21,25 --verbose

# JSON output format for automation
python main.py 192.168.1.100 --mode deep --format json

# Save results to file with custom port range
python main.py target.com --mode smart --ports 1-1000 --output results.json
```

### Programmatic Usage
```python
from main import run_service_discovery

# Basic service discovery
results = run_service_discovery('smart', 'example.com')

# Custom port specification
results = run_service_discovery('quick', '192.168.1.1', ports='80,443,22')

# With verbose logging and custom settings
results = run_service_discovery(
    scan_mode='deep',
    target='target.com',
    ports='1-1000',
    output_format='json',
    verbose=True
)

# Check results
if results['success']:
    print(f"Found {results['summary']['open_ports_count']} open ports")
    services = results['service_results']['services']
else:
    print(f"Scan failed: {results['error']}")
```

## Methods

### run_service_discovery(scan_mode, target, ports=None, output_format='json', verbose=False)
Main function that orchestrates complete service discovery including port scanning and service identification.

### print_results(results, format_type='text')
Formats and displays service discovery results in either human-readable text or JSON format.

### main()
Command-line interface function that handles argument parsing and coordinates the scanning process.

## Output

### Output Format
Returns structured dictionary containing:
- **Success Status**: Boolean indicating scan completion status
- **Target Information**: Target hostname/IP and scan parameters
- **Scan Results**: Raw NMAP output and scan duration metrics
- **Service Results**: Detailed service identification results per port
- **Summary Statistics**: Open port counts, services identified, and timing information
- **Error Information**: Detailed error messages when applicable

### Results Interpretation
- **Open Ports Count**: Number of accessible services discovered
- **Services Identified**: Number of services successfully fingerprinted
- **Scan Duration**: Total time taken for port scanning phase
- **Service Details**: Per-port information including service name, banner, and SSL status
- **Confidence Levels**: Service identification reliability indicators

## Examples

### Example 1: Quick Network Reconnaissance
```bash
python main.py scanme.nmap.org --mode quick
```

### Example 2: Comprehensive Security Assessment
```bash
python main.py 192.168.1.1 --mode deep --ports 1-65535 --verbose --output security_assessment.json
```

### Example 3: Targeted Service Analysis
```bash
python main.py example.com --mode smart --ports 21,22,23,25,53,80,110,143,443,993,995 --format json
```