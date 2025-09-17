# External Tools Module

## Overview
The External Tools module provides integration with popular external scanning tools including nmap, rustscan, and masscan for comprehensive port scanning and service detection capabilities.

## Features
- **Multi-Tool Support**: Integration with nmap, rustscan, and masscan
- **Automatic Tool Detection**: Checks tool availability at runtime
- **Flexible Configuration**: Configurable timeouts and scan parameters
- **Output Parsing**: Intelligent parsing of tool-specific output formats
- **Fallback Strategy**: Graceful degradation when tools are unavailable
- **Advanced Scripting**: Nmap script engine integration

## Supported Tools

### Rustscan
- Ultra-fast port scanner written in Rust
- Preferred tool for initial port discovery
- Configurable ulimit and timeout settings
- Greppable output format support

### Nmap
- Industry-standard network exploration tool
- Comprehensive service version detection
- Operating system fingerprinting
- Script engine for advanced analysis

### Masscan
- High-speed port scanner
- Optimized for large-scale scanning
- Rate-controlled scanning capabilities
- Minimal resource usage

## Main Classes

### ExternalToolsManager
Primary class for managing external tool integration.

**Key Methods:**
- `scan_with_external_tools(target_ip, scan_mode)`: Execute external tool scans
- `get_available_tools()`: List available tools
- `is_tool_available(tool_name)`: Check specific tool availability
- `get_tool_info()`: Detailed tool information

### NmapScriptEngine
Specialized class for nmap script execution.

**Key Methods:**
- `run_nmap_scripts(target_ip, ports, script_categories)`: Execute nmap scripts
- `get_errors()`: Script execution error information

## Scan Modes

### Quick Mode
- Fast scanning with minimal resource usage
- Limited port ranges for rapid results
- Basic tool configurations

### Smart Mode
- Balanced scanning approach
- Medium port ranges with version detection
- Intelligent tool parameter selection

### Deep Mode
- Comprehensive scanning with full capabilities
- Complete port ranges and advanced features
- Maximum tool functionality utilization

## Tool Configuration

### Rustscan Parameters
- Port range specification
- Ulimit configuration
- Timeout settings
- Output format selection

### Nmap Parameters
- Timing templates
- Service version detection
- Script categories
- Output verbosity

### Masscan Parameters
- Rate limiting
- Port range specification
- Output format control
- Performance optimization

## Usage Example

### Programmatic Usage
```python
from service_discovery.external_tools import ExternalToolsManager
from service_discovery.config import ServiceDiscoveryConfig

# Initialize tools manager
config = ServiceDiscoveryConfig()
tools_manager = ExternalToolsManager(config)

# Check available tools
available_tools = tools_manager.get_available_tools()
print(f"Available tools: {available_tools}")

# Perform external tool scan
results = tools_manager.scan_with_external_tools("192.168.1.1", "deep")

# Access results
open_ports = results.get('open_ports', {})
tools_used = results.get('tools_used', [])
```

### Standalone Command Line Usage
The module can be run independently for external tool scanning:

```bash
# Automatic tool selection
python external_tools.py example.com

# Specify tool and mode
python external_tools.py 192.168.1.1 --tool nmap --mode deep

# Use rustscan for fast scanning
python external_tools.py target.com --tool rustscan --mode quick

# Check available tools
python external_tools.py --check-tools

# Run with nmap scripts
python external_tools.py example.com --tool nmap --scripts --verbose

# Custom timeout and output
python external_tools.py target.com --timeout 600 --output scan_results.json
```

### Command Line Options
- `target`: Target IP address or hostname
- `--tool`: External tool to use (nmap, rustscan, masscan, auto)
- `--mode`: Scanning mode (quick, smart, deep)
- `--check-tools`: Check tool availability and exit
- `--scripts`: Run nmap scripts (requires nmap and open ports)
- `--timeout`: Scan timeout in seconds (default: 300)
- `--output`: Save results to JSON file
- `--verbose`: Enable verbose logging

### Tool Availability Check
The `--check-tools` option provides detailed information about:
- Which external tools are installed and available
- Tool version information
- Preferred tool selection
- Configuration parameters
- Installation recommendations for missing tools

## Output Parsing

### Rustscan Output
- Parses greppable output format
- Extracts port and protocol information
- Maps to standard service definitions

### Nmap Output
- Processes standard nmap output
- Extracts service versions and details
- Handles additional nmap information

### Masscan Output
- Parses discovery output format
- Extracts port and timing information
- Maps to service classifications

## Error Handling
Comprehensive error handling for:
- Tool execution failures
- Timeout conditions
- Invalid command parameters
- Output parsing errors
- Permission issues

## Dependencies
- Python standard library (subprocess, re, xml.etree.ElementTree)
- Service discovery base utilities
- Configuration module
- External tools: nmap, rustscan, masscan (optional)