# Active Domain Enumeration Module

This module provides active subdomain discovery using direct probing techniques including brute force attacks, DNS permutation, and intelligent wordlist generation.

## Features

- **Brute Force Attack**: Rate-limited subdomain brute forcing with custom wordlists
- **DNS Permutation Attack**: Intelligent domain variations and permutations
- **DNS Zone Transfer**: Automated zone transfer attempts on name servers
- **DNS Cache Snooping**: Queries public DNS servers for cached records
- **DNS-over-HTTPS Fallback**: DoH support when traditional DNS fails
- **AI-Enhanced Wordlists**: Smart wordlist generation using AI integration
- **Rate Limiting**: Configurable request throttling to avoid detection

## Usage

### Basic Usage
```python
from active_enumeration import ActiveEnumerator

# Create enumerator instance
enumerator = ActiveEnumerator("example.com")

# Run active enumeration
results = enumerator.run_active_enumeration()

# Get all discovered subdomains
all_subdomains = set()
for method, subdomains in results.items():
    all_subdomains.update(subdomains)
    
print(f"Found {len(all_subdomains)} subdomains")
```

### With Custom Wordlist
```python
# Load custom wordlist
with open('wordlist.txt', 'r') as f:
    wordlist = [line.strip() for line in f]

# Run with custom wordlist
results = enumerator.run_active_enumeration(wordlist)
```

### Command Line Usage
```bash
# Basic usage
python active_enumeration.py example.com

# With custom parameters
python active_enumeration.py example.com --threads 20 --rate-limit 15

# With custom wordlist
python active_enumeration.py example.com --wordlist custom_words.txt
```

## Configuration

### Basic Configuration
```python
from config import EnumerationConfig

config = EnumerationConfig()
config.rate_limit = 10          # Requests per second
config.thread_count = 10        # Concurrent threads
config.timeout = 5              # Request timeout
config.doh_fallback = True      # Enable DoH fallback
```

### Available Settings
- `rate_limit`: Maximum requests per second (default: 10)
- `thread_count`: Number of concurrent threads (default: 10)
- `timeout`: Request timeout in seconds (default: 5)
- `rate_limiting_enabled`: Enable/disable rate limiting (default: True)
- `doh_fallback`: Enable DNS-over-HTTPS fallback (default: True)

## Results Structure

```python
{
    'bruteforce': ['www.example.com', 'mail.example.com'],
    'dns_permutations': ['test-example.com', 'example-dev.com'],
    'dns_zone_transfer': ['internal.example.com'],
    'dns_cache_snooping': ['cached.example.com']
}
```

## Wordlist Generation

The module automatically generates intelligent wordlists using:

1. **Common Subdomains**: Standard subdomain dictionary (www, mail, ftp, admin, etc.)
2. **Target-Specific Terms**: Generated based on domain analysis
3. **Character Permutations**: Number additions, character substitutions
4. **AI-Enhanced Terms**: Context-aware suggestions when AI integration is available

## Error Handling

```python
# Get errors encountered during enumeration
errors = enumerator.get_errors()
for method, error_list in errors.items():
    print(f"{method}: {len(error_list)} errors")
```

Common error types handled:
- Network timeouts and connection errors
- DNS resolution failures (NXDOMAIN)
- Rate limiting and quota errors
- DNS server failures

## Dependencies

Required packages:
- `requests`: HTTP client library
- `dnspython`: DNS operations
- `concurrent.futures`: Threading support

Optional:
- `ai_integration`: Enhanced wordlist generation