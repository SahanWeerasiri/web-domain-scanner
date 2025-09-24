# Passive Domain Enumeration Module

## Overview
This module provides comprehensive passive subdomain discovery using external sources without directly probing the target infrastructure. It implements a configurable passive enumeration system with enhanced certificate transparency analysis and multiple data source integration.

## Features
- **Enhanced Certificate Transparency Analysis**: Comprehensive crt.sh queries with detailed certificate parsing
- **Dual Query Approach**: General certificate search + specific certificate details extraction
- **CT Log Analysis**: Extracts Certificate Transparency logs, fingerprints, and SANs
- **Multiple Data Sources**: Support for SSL certificates, Wayback Machine, threat intelligence
- **Configurable Sources**: Enable/disable specific enumeration methods
- **Performance Optimization**: Concurrent requests with rate limiting
- **Comprehensive Configuration**: Full pre-execution parameter configuration
- **Error Handling**: Robust failure management with detailed logging
- **Programmatic Interface**: Function-based configuration without command line dependency

## Installation

### Prerequisites
- Python 3.7+
- requests library
- python-dotenv
- urllib3

### Installation Steps
1. Clone the repository
2. Install dependencies: `pip install -r requirements.txt`
3. Set up environment variables (optional)

## Usage

### Basic Usage
```python
from passive_enumeration import execute_passive_enumeration

# Simple enumeration with defaults
results = execute_passive_enumeration("example.com")
```

### Advanced Usage
```python
# Advanced configuration
results = execute_passive_enumeration(
    domain="example.com",
    sources=['certificate_transparency', 'ssl_certificates'],
    ct_sources=['crt_sh'],
    concurrent_requests=3,
    request_delay=1.0,
    timeout=15,
    verbose=True
)
```

### Programmatic Usage
```python
from passive_enumeration import ConfigurablePassiveEnumerator, PassiveEnumerationConfig

# Create custom configuration
config = PassiveEnumerationConfig()
config.enabled_sources = ['certificate_transparency']
config.ct_sources = ['crt_sh']
config.verbose_output = True

# Initialize enumerator
enumerator = ConfigurablePassiveEnumerator("example.com", config)

# Run comprehensive enumeration
results = enumerator.run_comprehensive_enumeration()

# Extract subdomains
subdomains = results.get('subdomains', set())
print(f"Found {len(subdomains)} subdomains")
```

### Command Line Usage
```bash
python passive_enumeration.py example.com --verbose
```

## Configuration

### Configuration Options
- **enabled_sources**: List of passive sources to use (default: ['certificate_transparency'])
- **ct_sources**: Certificate transparency sources (default: ['crt_sh'])
- **max_concurrent_requests**: Maximum concurrent HTTP requests (default: 5)
- **request_delay**: Delay between requests in seconds (default: 0.5)
- **ct_timeout**: Certificate transparency timeout (default: 10)
- **ssl_timeout**: SSL certificate query timeout (default: 15)
- **verbose_output**: Enable detailed logging (default: False)

### Configuration File
```python
from passive_enumeration import PassiveEnumerationConfig

config = PassiveEnumerationConfig()
config.enabled_sources = ['certificate_transparency', 'ssl_certificates']
config.ct_sources = ['crt_sh']
config.max_concurrent_requests = 3
config.request_delay = 1.0
config.ct_timeout = 15
config.verbose_output = True
```

## Methods

### execute_passive_enumeration
Enhanced function with direct parameter configuration for programmatic use

### ConfigurablePassiveEnumerator.run_comprehensive_enumeration
Main enumeration method that executes all configured passive sources

### _query_crtsh_enhanced
Enhanced crt.sh query with comprehensive certificate analysis and dual-query approach

## Output

### Output Format
```python
{
    'domain': 'example.com',
    'timestamp': 1695551234.567,
    'configuration': {...},
    'sources': {
        'certificate_transparency': {
            'crt_sh': {
                'subdomains': ['sub1.example.com', 'sub2.example.com'],
                'certificates': {
                    '12345': {
                        'sha256_fingerprint': 'ABC123...',
                        'ct_logs': [...],
                        'subject_alternative_names': [...]
                    }
                },
                'total_certificates': 76
            }
        }
    },
    'subdomains': {'sub1.example.com', 'sub2.example.com'},
    'statistics': {
        'total_duration': 4.08,
        'total_subdomains': 2,
        'successful_sources': 1,
        'success_rate': 100.0
    }
}
```

### Results Interpretation
- **subdomains**: Set of all discovered subdomains across all sources
- **sources**: Detailed results from each enumeration source
- **certificates**: Certificate analysis with CT logs and fingerprints
- **statistics**: Performance metrics and success rates

## Examples

### Example 1: Basic Enumeration
```python
from passive_enumeration import execute_passive_enumeration

# Simple domain enumeration
results = execute_passive_enumeration("online.uom.lk")
print(f"Found {len(results['subdomains'])} subdomains")
```

### Example 2: Advanced Configuration
```python
# Custom configuration with multiple sources
results = execute_passive_enumeration(
    domain="example.com",
    sources=['certificate_transparency', 'ssl_certificates'],
    ct_sources=['crt_sh'],
    concurrent_requests=3,
    timeout=20,
    verbose=True
)

# Access certificate details
ct_results = results['sources']['certificate_transparency']['crt_sh']
print(f"Analyzed {ct_results.get('total_certificates', 0)} certificates")
```

### Example 3: Command Line Usage
```bash
# Basic enumeration
python passive_enumeration.py example.com

# With verbose output
python passive_enumeration.py example.com --verbose

# Custom CT sources
python passive_enumeration.py example.com --ct-sources crt_sh --timeout 20
```

## Data Sources

### ✅ Currently Implemented
- **Enhanced crt.sh**: Comprehensive certificate transparency analysis with dual queries
- **Certificate Analysis**: Extracts CT logs, SANs, fingerprints, and certificate metadata
- **VirusTotal SSL**: Certificate-based subdomain discovery (when API key available)

### ⚠️ Partially Implemented
- **Wayback Machine**: Basic historical data (disabled by default due to API issues)
- **SSL Certificate Sources**: Framework ready, requires API keys

### 🔄 Planned Sources
- **Google CT**: Certificate transparency logs
- **Censys**: Certificate and host data
- **Shodan**: SSL certificate information
- **SecurityTrails**: DNS history and passive DNS
- **Threat Intelligence**: AlienVault, ThreatCrowd integration

## API Keys (Optional)

The module works primarily with free sources, but API keys enhance results:

```bash
# VirusTotal API key (enhances SSL certificate queries)
export VIRUSTOTAL_API_KEY="your_api_key_here"

# Censys API credentials (for enhanced certificate data)
export CENSYS_API_KEY="your_censys_key"

# Shodan API key (for SSL certificate analysis)
export SHODAN_API_KEY="your_shodan_key"

# SecurityTrails API key (for DNS history)
export SECURITYTRAILS_API_KEY="your_securitytrails_key"

# AI Integration (optional)
export GEMINI_API_KEY="your_gemini_key"
```

**Note**: The enhanced crt.sh implementation works without any API keys and provides comprehensive certificate analysis.

## Error Handling

```python
# Get errors encountered during enumeration
enumerator = ConfigurablePassiveEnumerator("example.com")
results = enumerator.run_comprehensive_enumeration()
errors = results.get('errors', {})

for source, error_list in errors.items():
    print(f"{source}: {len(error_list)} errors")
```

Common error types handled:
- Network timeouts and connection errors
- SSL certificate verification failures
- API rate limiting and service unavailability
- DNS resolution failures
- Certificate parsing errors
- HTTP status errors (502, 503, 404)

### Performance Optimization
- **Enhanced retry strategy**: Configurable retry attempts with backoff
- **Concurrent processing**: Multiple requests with rate limiting
- **Intelligent error handling**: Skip failing sources quickly
- **Certificate caching**: Avoid redundant certificate queries

## Dependencies

Required packages:
- `requests`: HTTP client with session management
- `python-dotenv`: Environment variable management
- `urllib3`: Advanced HTTP features and retry strategies
- `re`: Regular expression processing for certificate parsing
- `time`: Timing and delay management
- `logging`: Comprehensive error tracking

## Troubleshooting

### If you get no results:
1. **Check domain validity**: Ensure the domain exists and has certificates
2. **Network connectivity**: Verify internet access and firewall settings
3. **Certificate availability**: Domain must have SSL certificates for CT analysis
4. **Service status**: crt.sh may be temporarily unavailable
5. **Domain age**: Very new domains may not have certificate history

### Common Error Messages:
- `"crt.sh wildcard: Found 0 certificates"`: Domain has no certificate history
- `"Certificate HTML length: 0 chars"`: Certificate details unavailable
- `"JSON parsing failed"`: crt.sh returned invalid data
- `"HTTPSConnectionPool... Max retries exceeded"`: Network connectivity issues
- `"DNS resolution failed"`: Domain doesn't exist or DNS issues

### Performance Tips:
- Use `verbose=True` for detailed debugging information
- Reduce `concurrent_requests` if experiencing rate limiting
- Increase `timeout` for slow network connections
- Monitor certificate analysis logs for parsing issues