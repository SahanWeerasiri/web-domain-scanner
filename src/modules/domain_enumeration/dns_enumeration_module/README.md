# DNS Domain Enumeration Module

## Overview
This module provides comprehensive DNS record enumeration and analysis with full pre-execution configuration capabilities. It discovers subdomains through various DNS record types, performs infrastructure analysis, and provides detailed security assessments of DNS configurations.

## Features
- **Configurable DNS Record Enumeration**: Support for A, AAAA, MX, NS, TXT, CNAME, SOA record queries
- **Advanced Subdomain Extraction**: Automatic subdomain discovery from DNS responses with configurable extraction methods
- **Infrastructure Analysis**: DNS infrastructure mapping and configuration analysis with security record assessment
- **Parent Domain Analysis**: Recursive analysis of parent domains up to configurable depth levels
- **Custom DNS Server Support**: Ability to use custom DNS servers including DNS-over-HTTPS (DoH)
- **Flexible TXT Record Analysis**: Multiple analysis depths (basic, advanced, deep) for comprehensive TXT record parsing
- **Performance Optimization**: Configurable parallel queries, caching, and batch processing
- **Comprehensive Error Handling**: Robust error management with detailed error reporting and recovery mechanisms

## Installation

### Prerequisites
- Python 3.7 or higher
- `dnspython` library for DNS operations
- Network connectivity for DNS queries

### Installation Steps
1. Install required dependencies: `pip install dnspython`
2. Ensure the module files are in your Python path
3. Import the module in your project

## Usage

### Basic Usage
```bash
# Simple DNS enumeration
python dns_enumeration.py example.com

# With verbose output
python dns_enumeration.py example.com --verbose
```

### Advanced Usage
```bash
# Custom DNS servers and timeout
python dns_enumeration.py example.com --dns-servers 8.8.8.8 1.1.1.1 --timeout 10 --retries 3

# Specific record types only
python dns_enumeration.py example.com --record-types A AAAA MX

# Deep TXT analysis with additional records
python dns_enumeration.py example.com --deep --additional-records

# Disable parent domain analysis
python dns_enumeration.py example.com --no-parent-domain --no-analysis
```

### Programmatic Usage
```python
from dns_enumeration import ConfigurableDNSEnumerator, DNSEnumerationConfig, execute_dns_enumeration

# Simple function call
results = execute_dns_enumeration(
    domain="example.com",
    timeout=10,
    verbose=True,
    txt_analysis_depth='advanced'
)

# Advanced configuration
config = DNSEnumerationConfig()
config.dns_servers = ['8.8.8.8', '1.1.1.1']
config.query_timeout = 10
config.parallel_queries = 10
config.txt_analysis_depth = 'deep'
config.perform_infrastructure_analysis = True

enumerator = ConfigurableDNSEnumerator("example.com", config)
results = enumerator.run_comprehensive_enumeration()
```

## Configuration

### Configuration Options
- **dns_servers**: Custom DNS servers to use (default: system default)
- **query_timeout**: DNS query timeout in seconds (default: 5)
- **query_retries**: Number of retry attempts for failed queries (default: 2)
- **record_types**: DNS record types to query (default: ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA'])
- **include_parent_domain**: Enable parent domain analysis (default: True)
- **parent_domain_depth**: Levels up to check for parent domains (default: 2)
- **parallel_queries**: Number of parallel DNS queries (default: 5)
- **txt_analysis_depth**: TXT record analysis depth - 'basic', 'advanced', or 'deep' (default: 'basic')
- **perform_infrastructure_analysis**: Enable infrastructure analysis (default: True)
- **enable_caching**: Enable DNS response caching (default: True)
- **cache_ttl**: Cache time-to-live in seconds (default: 300)

### Configuration File
```python
from dns_enumeration import DNSEnumerationConfig

config = DNSEnumerationConfig()

# DNS Query Configuration
config.dns_servers = ['8.8.8.8', '1.1.1.1']
config.query_timeout = 10
config.query_retries = 3
config.enable_doh = False

# Record Type Configuration
config.record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
config.include_parent_domain = True
config.parent_domain_depth = 3

# Analysis Configuration
config.txt_analysis_depth = 'deep'
config.perform_infrastructure_analysis = True
config.analyze_security_records = True

# Performance Configuration
config.parallel_queries = 10
config.enable_caching = True
config.cache_ttl = 600
```

## Methods

### run_comprehensive_enumeration()
Executes the complete DNS enumeration process with all configured parameters, returning comprehensive results including DNS records, subdomains, analysis, and statistics.

### _enumerate_dns_records()
Performs DNS record queries for the target domain and optionally parent domains, supporting all configured record types with retry mechanisms.

### _extract_subdomains()
Extracts potential subdomains from various DNS record types (CNAME, MX, NS, TXT) using configurable extraction methods and validation.

### _analyze_infrastructure()
Analyzes DNS infrastructure including nameservers, mail servers, CDN detection, and security configurations.

### _query_additional_records()
Performs additional DNS queries on discovered subdomains to gather more comprehensive information about the DNS infrastructure.

## Output

### Output Format
The module returns a comprehensive dictionary structure containing:

```python
{
    'domain': 'example.com',
    'timestamp': 1634567890.123,
    'configuration': {
        'dns_servers': ['8.8.8.8'],
        'timeout': 5,
        'record_types': ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA'],
        'analysis_enabled': True
    },
    'dns_records': {
        'A': ['192.168.1.1', '10.0.0.1'],
        'AAAA': ['2001:db8::1'],
        'MX': ['10 mail.example.com', '20 backup-mail.example.com'],
        'NS': ['ns1.example.com', 'ns2.example.com'],
        'TXT': ['v=spf1 include:_spf.google.com ~all', 'v=DMARC1; p=reject;'],
        'CNAME': ['www.example.com'],
        'SOA': ['ns1.example.com admin.example.com 2023092401 3600 1800 604800 86400']
    },
    'subdomains': {'mail.example.com', 'www.example.com', 'ns1.example.com'},
    'analysis': {
        'infrastructure': {
            'nameservers': ['ns1.example.com', 'ns2.example.com'],
            'mail_servers': ['mail.example.com'],
            'cdn_detection': {},
            'cloud_services': []
        },
        'security_records': {
            'spf_enabled': True,
            'dmarc_enabled': True,
            'dkim_enabled': False
        },
        'txt_analysis': {
            'verification_records': ['google-site-verification=...'],
            'service_records': ['v=spf1 include:_spf.google.com ~all']
        }
    },
    'statistics': {
        'total_duration': 2.34,
        'total_records': 15,
        'total_subdomains': 5,
        'queries_performed': 28,
        'successful_queries': 25,
        'failed_queries': 3
    },
    'errors': {
        'query_errors': [],
        'parsing_errors': [],
        'network_errors': []
    }
}
```

### Results Interpretation
- **dns_records**: Contains all discovered DNS records organized by type
- **subdomains**: Set of unique subdomains extracted from DNS records
- **analysis**: Infrastructure and security analysis results
- **statistics**: Performance metrics and query statistics
- **errors**: Detailed error information for troubleshooting

## Examples

### Example 1: Basic Enumeration
```bash
python dns_enumeration.py google.com
# Output: Basic DNS enumeration with standard record types and infrastructure analysis
```

### Example 2: Advanced Configuration
```bash
python dns_enumeration.py example.com --dns-servers 8.8.8.8 1.1.1.1 --timeout 15 --deep --additional-records --verbose
# Output: Comprehensive enumeration with custom DNS servers, extended timeout, deep TXT analysis, and additional record queries
```

### Example 3: Programmatic Usage with Custom Configuration
```python
from dns_enumeration import execute_dns_enumeration

results = execute_dns_enumeration(
    domain="target.com",
    dns_servers=['8.8.8.8', '1.1.1.1'],
    timeout=10,
    record_types=['A', 'MX', 'TXT'],
    txt_analysis_depth='deep',
    perform_analysis=True,
    verbose=True
)

print(f"Found {len(results['subdomains'])} subdomains")
print(f"Security records: {results['analysis']['security_records']}")
```

## Error Handling

The module implements comprehensive error handling for various DNS-related issues:

```python
# Access detailed error information
errors = results.get('errors', {})
for error_type, error_list in errors.items():
    print(f"{error_type}: {len(error_list)} errors")
    for error in error_list:
        print(f"  - {error}")
```

**Common Error Types:**
- **NXDOMAIN**: Domain does not exist or is not configured
- **NoAnswer**: No records of the requested type exist
- **Timeout**: DNS query exceeded the configured timeout period
- **ServerFailure**: DNS server encountered an internal error
- **NetworkError**: Network connectivity issues
- **ParseError**: Issues parsing DNS response data

## Dependencies

**Required Packages:**
- `dnspython>=2.0.0`: Core DNS operations and record parsing
- `logging`: Built-in Python logging (standard library)
- `argparse`: Command-line argument parsing (standard library)
- `json`: JSON data handling (standard library)
- `time`: Time utilities (standard library)
- `sys`: System-specific parameters and functions (standard library)