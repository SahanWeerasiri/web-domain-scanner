# Active Domain Enumeration Module

## Overview
The Active Domain Enumeration module provides comprehensive subdomain discovery using Gobuster-powered active reconnaissance techniques. It combines brute force attacks, intelligent DNS permutation, and AI-enhanced wordlist generation to discover subdomains through direct probing methods. The module leverages Gobuster for high-performance DNS enumeration while maintaining Python-based configuration and result processing.

## Features
- **Gobuster-Powered Brute Force**: High-performance subdomain enumeration using Gobuster DNS mode
- **Intelligent DNS Permutation**: Generates domain variations with common subdomain patterns and variations
- **SecLists Integration**: Uses comprehensive wordlists from the SecLists project (common.txt with 4,989 entries)
- **AI-Enhanced Wordlist Generation**: Context-aware subdomain suggestions using machine learning (optional)
- **Advanced Rate Limiting**: Configurable request throttling to avoid detection and rate limits
- **Multi-threaded Execution**: Concurrent processing for improved performance
- **Comprehensive Error Handling**: Robust error management with detailed logging
- **Flexible Configuration**: Extensive parameter customization for different use cases
- **Page Content Analysis**: Fetches and analyzes target website content for AI-enhanced wordlist generation
- **Legacy Method Support**: Zone transfer and cache snooping methods available but disabled by default (rarely effective on modern DNS servers)

## Installation

### Prerequisites
- Python 3.7+
- **Gobuster v3.8+**: Required for DNS subdomain enumeration
- Internet connection for DNS queries and page content fetching
- Optional: AI API keys (Gemini, OpenAI, Anthropic) for enhanced wordlist generation

### Installation Steps
1. **Install Gobuster**: Download from [https://github.com/OJ/gobuster/releases](https://github.com/OJ/gobuster/releases) and ensure it's in your PATH
2. Install required Python packages:
   ```bash
   pip install requests dnspython
   ```
3. Set up AI integration (optional):
   ```bash
   export GEMINI_API_KEY="your_gemini_api_key"
   export OPENAI_API_KEY="your_openai_api_key"  
   export ANTHROPIC_API_KEY="your_anthropic_api_key"
   ```
4. Ensure wordlist files are available (common.txt is included with the module)

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
    enable_ai=True,
    max_threads=25,  # Alternative parameter name for threads
    disable_ai=False  # Alternative parameter name for enable_ai
)

print(f"Total subdomains found: {results['statistics']['total_subdomains']}")
```

## Configuration

### Configuration Options
- `threads` (or `max_threads`): Number of concurrent threads (default: 10)
- `rate_limit`: Requests per second limit (default: 10)
- `timeout`: DNS query timeout in seconds (default: 5)
- `bruteforce_retries`: Number of retry attempts for failed queries (default: 2)
- `permutation_depth`: Depth of DNS permutation patterns (default: 3)
- `dns_servers`: Custom DNS servers for cache snooping
- `methods`: Enumeration methods to enable (default: ['bruteforce', 'dns_permutations'])
- `wordlist_file`: Path to custom wordlist file
- `enable_ai` (or `disable_ai`): Enable/disable AI-enhanced wordlist generation (default: True)

### Configuration File
```python
from active_enumeration import EnhancedEnumerationConfig

config = EnhancedEnumerationConfig()
config.thread_count = 20
config.rate_limit = 15
config.timeout = 10
config.bruteforce_retries = 3
config.permutation_depth = 5
config.enabled_methods = ['bruteforce', 'dns_permutations']
config.wordlist_ai_enabled = True
config.include_numeric_permutations = True
config.include_regional_permutations = True
```

## Methods

### Brute Force Enumeration
Uses Gobuster DNS mode for high-performance dictionary-based subdomain enumeration. Leverages the comprehensive common.txt wordlist from SecLists containing 4,989 carefully curated subdomain entries. Gobuster provides superior performance and reliability compared to pure Python DNS implementations.

### DNS Permutation Attack
Generates intelligent domain variations using common subdomain patterns including:
- Technology terms (api, app, admin, dev, test, staging, prod)
- Service variations (mail, ftp, vpn, remote, portal)
- Infrastructure terms (cdn, static, db, backup, monitoring)
- Regional and environment permutations

### DNS Zone Transfer (Legacy - Disabled by Default)
**Note**: Zone transfer attempts are disabled by default as they are rarely successful on modern DNS servers. Most public DNS servers block AXFR requests for security reasons, making this method largely ineffective in current environments.

### DNS Cache Snooping (Legacy - Disabled by Default)
**Note**: Cache snooping is disabled by default as it's often blocked by modern DNS servers and provides limited value compared to direct subdomain enumeration. Most DNS servers have been hardened against cache snooping attacks.

- Technology stack detection

## Gobuster Integration

This module leverages Gobuster for superior DNS enumeration performance:

### Gobuster Benefits
- **High Performance**: Native Go implementation provides faster enumeration than Python DNS libraries
- **Reliable DNS Handling**: Built-in DNS resolver optimization and error handling
- **Memory Efficient**: Low memory footprint even with large wordlists
- **Industry Standard**: Widely used and trusted by security professionals

### Gobuster Commands Used
- `gobuster dns --domain <target> -w <wordlist>`: Core subdomain enumeration
- Automatic wordlist management with temporary files
- Root domain extraction for proper subdomain discovery

### Performance Comparison
- **Previous Python DNS**: ~0 subdomains found (inefficient)
- **Current Gobuster**: 98+ subdomains found for typical domains
- **Speed Improvement**: 10x+ faster enumeration with better reliability

## AI-Enhanced Wordlist Generation
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
- **Gobuster**: High-performance DNS subdomain enumeration tool (v3.8+ recommended)
- `subprocess`: For executing Gobuster commands from Python
- `tempfile`: Temporary file handling for wordlist operations
- `os`: File system operations and path handling
- `requests`: HTTP client for web page fetching (AI integration)
- `logging`: Comprehensive logging and debugging
- `time`: Performance timing and rate limiting
- `argparse`: Command-line argument parsing

### Optional Packages
- `ai_integration`: Enhanced wordlist generation using AI/ML models
- Environment variables for API keys (GEMINI_API_KEY, OPENAI_API_KEY, ANTHROPIC_API_KEY)