# Domain Enumeration Module

## Overview

The Domain Enumeration module (`domain_enumeration.py`) is a comprehensive subdomain discovery and reconnaissance tool designed for cybersecurity professionals and penetration testers. It implements multiple enumeration techniques to discover subdomains, DNS records, and web technologies associated with a target domain.

## Features

### 🔍 **Passive Enumeration**
- **Certificate Transparency Logs**: Queries multiple CT log sources (crt.sh, Google CT, CertSpotter)
- **SSL Certificate Analysis**: Searches Censys, Shodan, and VirusTotal certificate databases
- **Wayback Machine**: Extracts historical subdomains from web archive data
- **Threat Intelligence APIs**: Integrates with various threat intel sources
- **DNS History**: Queries historical DNS record databases

### ⚡ **Active Enumeration**
- **Enhanced Brute Force**: Rate-limited subdomain brute forcing with intelligent wordlists
- **DNS Permutation Attacks**: Generates and tests domain permutations and variations
- **DNS Zone Transfer**: Attempts AXFR zone transfers when possible
- **DNS Cache Snooping**: Probes public DNS servers for cached subdomain records
- **DNS-over-HTTPS (DoH)**: Fallback queries using Cloudflare and Google DoH

### 🧠 **Intelligent Wordlist Generation**
- **Context-Aware Terms**: Generates target-specific subdomains based on domain analysis
- **LLM-Based Generation**: Creates domain-appropriate terms for different organization types
- **Character Permutations**: Systematically generates variations using common patterns
- **Common Subdomain Lists**: Incorporates well-known subdomain dictionaries

### 🌐 **Web Fingerprinting**
- **Technology Detection**: Identifies web technologies and frameworks in use
- **Service Discovery**: Maps discovered subdomains to their services
- **CDN Detection**: Identifies and attempts to bypass CDN protections

### 🛡️ **Security & Performance**
- **Rate Limiting**: Token-bucket algorithm prevents overwhelming target servers
- **Error Handling**: Comprehensive error recovery and retry mechanisms
- **DoH Fallback**: Ensures enumeration continues even with DNS filtering
- **Threading**: Concurrent execution for improved performance

## Quick Start

### Basic Usage

```python
from modules.domain_enumeration import DomainEnumeration, EnumerationConfig

# Initialize with default configuration
domain = "example.com"
enumerator = DomainEnumeration(domain)

# Run comprehensive enumeration
enumerator.passive_enumeration()
enumerator.dns_enumeration()
enumerator.enhanced_active_enumeration()
enumerator.web_fingerprinting()

# Get consolidated results
final_subdomains = enumerator.correlate_results()
print(f"Found {len(final_subdomains)} subdomains")
```

### Custom Configuration

```python
# Create custom configuration
config = EnumerationConfig()
config.rate_limit = 20          # 20 requests per second
config.timeout = 5              # 5 second timeout
config.thread_count = 15        # 15 concurrent threads
config.doh_fallback = True      # Enable DoH fallback
config.cdn_bypass = True        # Enable CDN bypass techniques

enumerator = DomainEnumeration("example.com", config)
```

### Targeted Enumeration

```python
# Passive enumeration only (stealth mode)
passive_results = enumerator.passive_enumeration()

# Active enumeration with custom wordlist
custom_wordlist = ['api', 'admin', 'staging', 'dev']
active_results = enumerator.enhanced_active_enumeration(wordlist=custom_wordlist)

# DNS enumeration only
dns_results = enumerator.dns_enumeration()
```

## Configuration Options

### EnumerationConfig Class

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `rate_limit` | int | 10 | Requests per second (1-100) |
| `timeout` | int | 30 | Request timeout in seconds |
| `retry_attempts` | int | 3 | Number of retry attempts for failed requests |
| `doh_fallback` | bool | True | Enable DNS-over-HTTPS fallback |
| `cdn_bypass` | bool | True | Enable CDN bypass techniques |
| `thread_count` | int | 10 | Number of concurrent threads (1-50) |
| `rate_limiting_enabled` | bool | True | Enable/disable rate limiting |

### Environment Variables

Set these environment variables for enhanced functionality:

```bash
# API Keys (optional but recommended)
VIRUSTOTAL_API_KEY=your_vt_api_key
CENSYS_API_ID=your_censys_id
CENSYS_API_SECRET=your_censys_secret
SHODAN_API_KEY=your_shodan_key

# Custom wordlist paths
CUSTOM_SUBDOMAIN_WORDLIST=/path/to/custom/wordlist.txt
```

## Method Reference

### Core Methods

#### `passive_enumeration()`
Performs comprehensive passive data collection without directly probing the target.

**Returns**: `Dict` containing results from all passive sources

#### `enhanced_active_enumeration(wordlist=None)`
Executes advanced active enumeration techniques.

**Parameters**:
- `wordlist` (List[str], optional): Custom wordlist for brute force

**Returns**: `Dict` containing results from all active methods

#### `dns_enumeration()`
Performs DNS record enumeration for various record types.

**Returns**: `Dict` containing DNS records by type

#### `web_fingerprinting()`
Identifies web technologies and services on discovered subdomains.

**Returns**: `Dict` containing technology fingerprints

#### `correlate_results()`
Correlates and deduplicates findings from all enumeration methods.

**Returns**: `List[str]` of verified unique subdomains

### Advanced Methods

#### `subdomain_discovery(wordlist=None)`
High-level method that combines passive and active techniques.

#### `_check_subdomain(subdomain)`
Verifies if a subdomain exists using DNS resolution with DoH fallback.

#### `_generate_dynamic_wordlist()`
Creates intelligent, context-aware wordlists for the target domain.

## Output Structure

### Results Dictionary

```python
enumerator.results = {
    'subdomains': {},           # Final verified subdomains
    'dns_records': {},          # DNS records by type
    'passive_data': {           # Passive enumeration results
        'certificate_transparency': {},
        'ssl_certificates': {},
        'wayback_machine': {},
        'threat_intelligence': {},
        'dns_history': {}
    },
    'active_discovery': {       # Active enumeration results
        'bruteforce': [],
        'dns_permutations': [],
        'dns_zone_transfer': [],
        'dns_cache_snooping': []
    },
    'web_technologies': {},     # Web fingerprinting results
    'errors': {}               # Error tracking by method
}
```

## Performance Considerations

### Rate Limiting
The module implements intelligent rate limiting to avoid overwhelming target servers:

```python
# Configure conservative settings for sensitive targets
config = EnumerationConfig()
config.rate_limit = 5           # 5 requests/second
config.thread_count = 3         # 3 concurrent threads
config.timeout = 10             # 10 second timeout
```

### Memory Usage
For large-scale enumeration:
- Use iterator methods for processing large wordlists
- Consider chunking results for very large datasets
- Monitor memory usage with extensive passive data collection

### Network Considerations
- Respect target server resources and terms of service
- Use VPN/proxy rotation for large-scale enumeration
- Be aware of potential IP blocking from aggressive scanning

## Error Handling

The module provides comprehensive error handling and logging:

```python
# Errors are automatically logged and stored
if 'errors' in enumerator.results:
    for method, errors in enumerator.results['errors'].items():
        print(f"Errors in {method}: {errors}")
```

Common error scenarios:
- DNS resolution failures
- API rate limiting
- Network timeouts
- Invalid domain names
- Permission denied (zone transfers)

## Integration Examples

### With Custom APIs

```python
class CustomEnumerator(DomainEnumeration):
    def _query_custom_api(self):
        """Add your custom API integration"""
        # Custom implementation
        pass
    
    def enhanced_passive_enumeration(self):
        # Extend passive enumeration
        results = super().passive_enumeration()
        results['custom_api'] = self._query_custom_api()
        return results
```

### With Database Storage

```python
import sqlite3

def store_results(domain, results):
    conn = sqlite3.connect('enumeration_results.db')
    # Store results in database
    for subdomain in results:
        conn.execute(
            "INSERT INTO subdomains (domain, subdomain, discovered_at) VALUES (?, ?, ?)",
            (domain, subdomain, datetime.now())
        )
    conn.commit()
    conn.close()

# Usage
results = enumerator.correlate_results()
store_results("example.com", results)
```

## Security Considerations

### Ethical Usage
- Only enumerate domains you own or have explicit permission to test
- Respect robots.txt and terms of service
- Be mindful of the legal implications in your jurisdiction

### Operational Security
- Use appropriate rate limiting to avoid detection
- Consider using proxy chains or VPN services
- Implement proper logging and audit trails
- Sanitize and validate all inputs

### Data Privacy
- Handle discovered data responsibly
- Implement appropriate data retention policies
- Secure storage of enumeration results
- Comply with relevant data protection regulations

## Troubleshooting

### Common Issues

#### Import Errors
```bash
# Ensure dependencies are installed
pip install -r requirements.txt

# Check Python path
export PYTHONPATH="${PYTHONPATH}:/path/to/src"
```

#### DNS Resolution Issues
```python
# Enable DoH fallback
config.doh_fallback = True

# Try alternative DNS servers
config.custom_dns_servers = ['8.8.8.8', '1.1.1.1']
```

#### Rate Limiting
```python
# Reduce rate limits
config.rate_limit = 1
config.thread_count = 1
config.timeout = 30
```

#### Memory Issues
```python
# Process results in chunks
for chunk in enumerator.get_results_chunks(chunk_size=1000):
    process_chunk(chunk)
```

## Dependencies

### Required Packages
```
requests>=2.31.0
dnspython>=2.4.0
python-dotenv>=1.0.0
concurrent.futures (Python 3.2+)
```

### Optional Packages
```
selenium>=4.11.0          # For advanced web crawling
beautifulsoup4>=4.12.0    # For HTML parsing
wappalyzer>=0.5.1         # For technology detection
```

## Contributing

### Development Setup
1. Clone the repository
2. Install development dependencies: `pip install -r requirements-test.txt`
3. Run tests: `python -m pytest tests/`
4. Follow the coding standards and add tests for new features

### Adding New Enumeration Methods
1. Implement the method in the appropriate section
2. Add error handling using `_handle_enumeration_errors()`
3. Include rate limiting with `self.rate_limiter.acquire()`
4. Add comprehensive tests
5. Update documentation

## License

This module is part of the web-domain-scanner project. Please refer to the project's main LICENSE file for licensing information.

## Support

For bug reports, feature requests, or questions:
- Create an issue in the project repository
- Follow the contribution guidelines
- Provide detailed information about your use case and environment

---

**Warning**: This tool is designed for authorized security testing only. Users are responsible for ensuring they have proper authorization before scanning any domains. Unauthorized use may violate terms of service and applicable laws.