# Passive Domain Enumeration Module

This module provides stealth subdomain discovery using external sources without directly probing the target infrastructure. It focuses on currently working sources for reliable results.

## Features

- **HackerTarget API**: Multiple endpoints for subdomain discovery
- **Working Sources**: Subdomain Center, VirusTotal public interface
- **Certificate Transparency**: Basic crt.sh queries (when available)
- **Web Archive Data**: Wayback Machine historical data
- **Stealth Reconnaissance**: No direct target interaction
- **Rate Limiting**: Respectful request timing
- **Error Handling**: Robust failure management

## Usage

### Basic Usage
```python
from passive_enumeration import PassiveEnumerator

# Create enumerator instance
enumerator = PassiveEnumerator("example.com")

# Run passive enumeration
results = enumerator.run_passive_enumeration()

# Extract all discovered subdomains
subdomains = enumerator._extract_all_subdomains(results)
print(f"Found {len(subdomains)} subdomains")
```

### With Custom Configuration
```python
from config import EnumerationConfig

# Create custom config
config = EnumerationConfig()
config.timeout = 20
config.retry_attempts = 5

# Use with enumerator
enumerator = PassiveEnumerator("example.com", config)
results = enumerator.run_passive_enumeration()
```

### Command Line Usage
```bash
python passive_enumeration.py example.com
```

## Configuration

### Basic Configuration
```python
from config import EnumerationConfig

config = EnumerationConfig()
config.timeout = 10         # Request timeout in seconds
config.retry_attempts = 3   # Number of retry attempts
```

### Available Settings
- `timeout`: Request timeout in seconds (default: 10)
- `retry_attempts`: Number of retry attempts (default: 3)

## Results Structure

```python
{
    'certificate_transparency': {
        'hackertarget': {'subdomains': [...]},
        'additional_sources': {'subdomains': [...]},
        'crt_sh': {'subdomains': [...]}  # When available
    },
    'wayback_machine': {'subdomains': [...]},
    'ssl_certificates': {'aggregated_subdomains': []},
    'threat_intelligence': {},
    'dns_history': {}
}
```

## Data Sources

### ✅ Working Sources
- **HackerTarget API**: Reliable, finds 2+ subdomains typically
- **Subdomain Center**: Web scraping with domain pattern matching
- **VirusTotal Public**: No API key required
- **Wayback Machine**: Usually functional

### ⚠️ Limited Sources
- **Simple crt.sh**: Works intermittently (frequent 502 errors)

### ❌ Disabled Sources
- **Traditional CT logs**: Frequent timeouts and 502 errors
- **SSL APIs**: Require paid API keys
- **Third-party services**: SSL errors, DNS failures, 403 responses

## API Keys (Optional)

Most sources work without API keys, but you can configure them for enhanced results:

```bash
# VirusTotal API key (optional - public interface used by default)
export VIRUSTOTAL_API_KEY="your_api_key_here"

# AI Integration (optional)
export GEMINI_API_KEY="your_gemini_key"
```

**Note**: The module works well without any API keys using HackerTarget and other free sources.

## Error Handling

```python
# Get errors encountered during enumeration
errors = enumerator.get_errors()
for source, error_list in errors.items():
    print(f"{source}: {len(error_list)} errors")
```

Common error types handled:
- Network timeouts and connection errors
- SSL certificate verification failures
- API rate limiting
- Service unavailability (502, 503, 404)
- DNS resolution failures

### Optimization Strategy
- **Fail-fast approach**: Skip unreliable sources quickly
- **Focus on working sources**: Prioritize HackerTarget and reliable APIs
- **Minimal timeout values**: Avoid long waits for broken services

## Dependencies

Required packages:
- `requests`: HTTP library with session management
- `python-dotenv`: Environment variable management
- `urllib3`: Advanced HTTP client features

## Troubleshooting

### If you get no results:
1. **Check domain validity**: Ensure the domain exists and is accessible
2. **Network connectivity**: Verify internet connection and firewall settings
3. **Service status**: Some external sources may be temporarily down
4. **Domain popularity**: Lesser-known domains may have fewer subdomain records

### Common Error Messages:
- `"SSL: CERTIFICATE_VERIFY_FAILED"`: Service has SSL issues (automatically skipped)
- `"Failed to resolve"`: DNS resolution issues (automatically skipped)  
- `"Max retries exceeded"`: Service is down/overloaded (automatically skipped)
- `"timeout"`: Service is slow (automatically skipped after timeout)