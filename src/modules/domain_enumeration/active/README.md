# Active Domain Enumeration Module

## Overview
The Active Domain Enumeration module provides comprehensive subdomain discovery using multiple active reconnaissance techniques. It combines brute force attacks, DNS permutation, zone transfers, cache snooping, and AI-enhanced wordlist generation to discover subdomains through direct probing methods.

## Features
- **Configurable Brute Force Attack**: Rate-limited subdomain enumeration with custom wordlists and retry logic
- **Intelligent DNS Permutation**: Generates domain variations based on numeric, regional, and environment patterns
- **DNS Zone Transfer Attempts**: Automated zone transfer discovery on target nameservers
- **DNS Cache Snooping**: Queries multiple public DNS servers for cached subdomain records
- **AI-Enhanced Wordlist Generation**: Context-aware subdomain suggestions using machine learning
- **DNS-over-HTTPS (DoH) Support**: Fallback to DoH when traditional DNS queries fail
- **Advanced Rate Limiting**: Configurable request throttling to avoid detection and rate limits
- **Multi-threaded Execution**: Concurrent processing for improved performance
- **Comprehensive Error Handling**: Robust error management with detailed logging
- **Flexible Configuration**: Extensive parameter customization for different use cases
- **Page Content Analysis**: Fetches and analyzes target website content for AI-enhanced wordlist generation

## Installation

### Prerequisites
- Python 3.7+
- Internet connection for DNS queries and page content fetching
- Optional: AI API keys (Gemini, OpenAI, Anthropic) for enhanced wordlist generation

### Installation Steps
1. Install required Python packages:
   ```bash
   pip install requests dnspython
   ```
2. Set up AI integration (optional):
   ```bash
   export GEMINI_API_KEY="your_gemini_api_key"
   export OPENAI_API_KEY="your_openai_api_key"  
   export ANTHROPIC_API_KEY="your_anthropic_api_key"
   ```
3. Ensure wordlist files are available in `config/wordlists/` directory

## Usage

### Basic Usage
```bash
python active_enumeration.py example.com
```

### Advanced Usage
```bash
# Custom threading and rate limiting
python active_enumeration.py example.com --threads 20 --rate-limit 15 --timeout 10

# Specific enumeration methods
python active_enumeration.py example.com --methods bruteforce dns_permutations

# Custom wordlist
python active_enumeration.py example.com --wordlist api_endpoints.txt

# Disable AI wordlist generation
python active_enumeration.py example.com --no-ai
```

### Programmatic Usage
```python
from active_enumeration import execute_active_enumeration

# Basic enumeration
results = execute_active_enumeration("example.com")

# Advanced configuration
results = execute_active_enumeration(
    domain="example.com",
    threads=20,
    rate_limit=15,
    timeout=10,
    methods=['bruteforce', 'dns_permutations'],
    wordlist_file="custom_wordlist.txt",
    enable_ai=True
)

print(f"Total subdomains found: {results['statistics']['total_subdomains']}")
```

## Configuration

### Configuration Options
- `threads`: Number of concurrent threads (default: 10)
- `rate_limit`: Requests per second limit (default: 10)
- `timeout`: DNS query timeout in seconds (default: 5)
- `bruteforce_retries`: Number of retry attempts for failed queries (default: 2)
- `permutation_depth`: Depth of DNS permutation patterns (default: 3)
- `dns_servers`: Custom DNS servers for cache snooping
- `methods`: Enumeration methods to enable
- `wordlist_file`: Path to custom wordlist file
- `enable_ai`: Enable AI-enhanced wordlist generation (default: True)

### Configuration File
```python
from active_enumeration import EnhancedEnumerationConfig

config = EnhancedEnumerationConfig()
config.thread_count = 20
config.rate_limit = 15
config.timeout = 10
config.bruteforce_retries = 3
config.permutation_depth = 5
config.enabled_methods = ['bruteforce', 'dns_permutations', 'cache_snooping']
config.wordlist_ai_enabled = True
config.include_numeric_permutations = True
config.include_regional_permutations = True
```

## Methods

### Brute Force Enumeration
Performs dictionary-based subdomain enumeration using wordlists. Supports retry logic, DNS-over-HTTPS fallback, and configurable timeouts.

### DNS Permutation Attack
Generates intelligent domain variations including:
- Numeric permutations (domain1, domain-01, domain_1)
- Regional variations (domain-us, domain-eu, asia-domain)
- Environment permutations (dev-domain, domain-prod, test-domain)

### DNS Zone Transfer
Attempts zone transfer attacks on discovered nameservers with configurable retry attempts and timeout values.

### DNS Cache Snooping
Queries multiple public DNS servers (Google, Cloudflare, OpenDNS, Quad9) to discover cached subdomain records.

### AI-Enhanced Wordlist Generation
Uses machine learning to generate context-aware subdomain suggestions based on:
- Domain characteristics and TLD analysis
- Website content analysis
- Industry-specific terminology
- Technology stack detection

## Output

### Output Format
```python
{
    'domain': 'example.com',
    'timestamp': 1695123456.789,
    'configuration': {
        'enabled_methods': ['bruteforce', 'dns_permutations'],
        'thread_count': 10,
        'rate_limit': 10
    },
    'methods': {
        'bruteforce': ['www.example.com', 'mail.example.com'],
        'dns_permutations': ['dev-example.com', 'example-prod.com'],
        'zone_transfer': [],
        'cache_snooping': ['api.example.com']
    },
    'statistics': {
        'total_duration': 45.67,
        'total_subdomains': 15,
        'methods_breakdown': {'bruteforce': 8, 'dns_permutations': 5, 'cache_snooping': 2},
        'completion_time': '2024-09-24 10:30:45'
    },
    'errors': {}
}
```

### Results Interpretation
- **methods**: Contains discovered subdomains organized by enumeration method
- **statistics**: Provides performance metrics and summary information
- **errors**: Details any errors encountered during enumeration
- **configuration**: Shows the parameters used for the enumeration session

## Examples

### Example 1: Basic Educational Domain Scan
```bash
python active_enumeration.py university.edu --threads 15 --rate-limit 12
```

### Example 2: Corporate Domain with Custom Wordlist
```bash
python active_enumeration.py company.com --wordlist corporate_subdomains.txt --methods bruteforce dns_permutations
```

### Example 3: Government Domain with Conservative Settings
```bash
python active_enumeration.py government.gov --threads 5 --rate-limit 3 --timeout 15 --bruteforce-retries 1
```

### Example 4: High-Performance Scan with AI Enhancement
```bash
python active_enumeration.py target.com --threads 50 --rate-limit 25 --permutation-depth 5 --no-ai false
```

## Dependencies

### Required Packages
- `requests`: HTTP client for web page fetching and DoH queries
- `dnspython`: DNS operations and zone transfer attempts
- `concurrent.futures`: Multi-threading support for parallel processing
- `socket`: Low-level network operations
- `base64`: Content encoding for AI analysis
- `argparse`: Command-line argument parsing
- `logging`: Comprehensive logging and debugging
- `time`: Performance timing and rate limiting

### Optional Packages
- `ai_integration`: Enhanced wordlist generation using AI/ML models
- Environment variables for API keys (GEMINI_API_KEY, OPENAI_API_KEY, ANTHROPIC_API_KEY)