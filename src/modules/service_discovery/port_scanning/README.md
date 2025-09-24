# Port Scanning Module

## Overview
The Port Scanning module provides a simplified interface to NMAP for comprehensive port scanning capabilities. It offers three distinct scanning modes optimized for different reconnaissance needs and security assessment requirements.

## Features
- **Multiple Scanning Modes**: Quick (top 100 ports), Smart (top 1000 ports with service detection), and Deep (comprehensive all ports scan)
- **NMAP Integration**: Leverages the power and reliability of NMAP for port scanning
- **Service Detection**: Automatic service identification and version detection
- **Vulnerability Scanning**: Built-in vulnerability detection scripts in deep scan mode
- **OS Fingerprinting**: Operating system detection capabilities
- **Flexible Port Selection**: Support for custom port ranges and specific port lists

## Installation

### Prerequisites
- Python 3.6 or higher
- NMAP installed and accessible from command line
- Appropriate permissions for network scanning

### Installation Steps
1. Ensure NMAP is installed on your system
2. Clone or download the web-domain-scanner repository
3. Navigate to the port scanning module directory
4. No additional Python packages required (uses subprocess)

## Configuration

### Configuration Options
- **Timeout**: Scan timeout settings (default: 1800 seconds)
- **Scan Speed**: NMAP timing template T4 for balanced speed and accuracy
- **Port Range**: Customizable port ranges for targeted scanning
- **Script Selection**: Configurable NMAP scripts for enhanced detection

### Scanning Modes

#### Quick Scan
- Scans top 100 most common ports
- Fast execution time suitable for initial reconnaissance
- Uses TCP SYN scan (-sS) for stealth
- Shows only open ports

#### Smart Scan  
- Scans top 1000 ports with service version detection
- Includes OS fingerprinting and default scripts
- Balanced approach between speed and thoroughness
- Enhanced service identification

#### Deep Scan
- Comprehensive scan of all 65535 ports
- Includes vulnerability detection scripts
- Advanced service enumeration and banner grabbing
- Provides detailed reasoning for port states

## Usage

### Basic Usage
```bash
# Quick scan of a target
python port_scanner.py example.com quick

# Smart scan with service detection
python port_scanner.py 192.168.1.1 smart

# Deep comprehensive scan
python port_scanner.py target.com deep
```

### Advanced Usage
```bash
# Quick scan with custom ports
python port_scanner.py example.com quick -p 80,443,22,21

# Smart scan with port range
python port_scanner.py target.com smart -p 1-1000

# Deep scan with specific ports
python port_scanner.py 192.168.1.100 deep -p 1-65535
```

### Programmatic Usage
```python
from port_scanner import SimplePortScanner, scan_target

# Using the class directly
scanner = SimplePortScanner("example.com")
result = scanner.quick()
print(result)

# Using the function interface
result = scan_target("smart", "192.168.1.1", "80,443,22")
print(result)

# With custom port ranges
result = scan_target("deep", "target.com", "1-1000")
print(result)
```

## Methods

### quick(custom_ports=None)
Performs a quick scan of the top 100 most common ports. Fast and efficient for initial reconnaissance.

### smart(custom_ports=None)
Comprehensive scan of top 1000 ports with service detection, OS fingerprinting, and default scripts.

### deep(custom_ports=None)
Extensive scan covering all ports with vulnerability detection, comprehensive service analysis, and detailed reporting.

## Output

### Output Format
Returns NMAP's standard text output containing:
- Open ports and their states
- Service names and versions
- Operating system information (when detected)
- Script results and vulnerability findings
- Scan timing and statistics

### Results Interpretation
- **Open ports**: Services accessible on the target
- **Service versions**: Specific software versions running
- **OS fingerprint**: Detected operating system
- **Script results**: Security findings and additional information
- **Filtered ports**: Ports behind firewall or filtered

## Examples

### Example 1: Quick Network Reconnaissance
```bash
python port_scanner.py scanme.nmap.org quick
```

### Example 2: Detailed Service Analysis
```bash
python port_scanner.py 192.168.1.1 smart -p 21,22,23,25,53,80,110,443,993,995
```

### Example 3: Comprehensive Security Assessment
```bash
python port_scanner.py target.example.com deep -p 1-65535
```