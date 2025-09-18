# Web Technology Fingerprinting Module

This module provides comprehensive web technology fingerprinting to identify web technologies, frameworks, servers, and security configurations by analyzing HTTP responses and content.

## Features

- **HTTP Header Analysis**: Server identification and framework detection
- **Content Analysis**: Technology detection from page content and scripts
- **URL Pattern Analysis**: Technology identification from resource URLs
- **Wappalyzer Integration**: Advanced technology detection (when available)
- **Security Assessment**: Security headers and SSL configuration analysis
- **Performance Metrics**: Response times and content analysis

## Usage

### Basic Web Fingerprinting
```python
from web_fingerprinting import WebFingerprinter

# Create fingerprinter instance
fingerprinter = WebFingerprinter("example.com")

# Run fingerprinting on default targets
results = fingerprinter.run_web_fingerprinting()

# Display results
for target, result in results.items():
    print(f"Target: {target}")
    if 'error' not in result:
        technologies = result['technology_detection']
        print(f"Technologies: {technologies}")
```

### Custom Target Fingerprinting
```python
# Define custom targets
targets = [
    "https://example.com",
    "https://api.example.com",
    "https://admin.example.com"
]

fingerprinter = WebFingerprinter("example.com")
results = fingerprinter.run_web_fingerprinting(targets)
```

### Generate Summary Report
```python
# Generate comprehensive summary
summary = fingerprinter.generate_fingerprint_summary(results)

print(f"Total targets: {summary['total_targets']}")
print(f"Unique technologies: {summary['unique_technologies']}")
print(f"Average security score: {summary['security_score_avg']}")
```

### Command Line Usage
```bash
# Basic fingerprinting
python web_fingerprinting.py example.com

# Custom targets
python web_fingerprinting.py example.com --targets https://api.example.com

# With summary report
python web_fingerprinting.py example.com --summary
```

## Configuration

### Basic Configuration
```python
from config import EnumerationConfig

config = EnumerationConfig()
config.timeout = 15         # Request timeout
config.rate_limit = 5       # Requests per second
config.rate_limiting_enabled = True
```

### Available Settings
- `timeout`: Request timeout in seconds (default: 15)
- `rate_limit`: Requests per second (default: 10)
- `rate_limiting_enabled`: Enable/disable rate limiting (default: True)

## Results Structure

```python
{
    'target_url': {
        'url': 'https://example.com',
        'timestamp': 1234567890.123,
        'response_analysis': {
            'status_code': 200,
            'content_type': 'text/html',
            'content_length': 1024,
            'redirect_chain': []
        },
        'header_analysis': {
            'server': 'nginx/1.18.0',
            'security_headers': {
                'x_frame_options': 'DENY',
                'content_security_policy': 'default-src self'
            }
        },
        'technology_detection': {
            'wappalyzer_detected': ['Nginx', 'PHP', 'jQuery'],
            'header_detected': ['Nginx'],
            'content_detected': ['WordPress', 'jQuery'],
            'url_patterns': ['Google Analytics']
        },
        'security_analysis': {
            'security_score': 75,
            'ssl_enabled': True
        },
        'performance_metrics': {
            'response_time': 0.234,
            'content_size': 1024
        }
    }
}
```

## Error Handling

```python
# Get errors encountered during fingerprinting
errors = fingerprinter.get_errors()
for method, error_list in errors.items():
    print(f"{method}: {len(error_list)} errors")
```

Common error types handled:
- Connection timeouts and HTTP errors
- SSL certificate and protocol errors
- Content encoding and parsing errors
- Large content memory management

## Dependencies

Required packages:
- `requests`: HTTP client library
- `urllib.parse`: URL parsing utilities

Optional dependencies:
- `fingerprinting_wapplyzer`: Enhanced technology detection
