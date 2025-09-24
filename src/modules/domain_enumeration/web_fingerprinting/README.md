# Web Technology Fingerprinting Module

## Overview
This module provides comprehensive web technology fingerprinting with full pre-execution configuration. It identifies web technologies, frameworks, servers, and security configurations through multi-method analysis including HTTP headers, content analysis, URL patterns, Wappalyzer integration, and AI-enhanced detection.

## Features
- **Multi-Method Detection**: Headers, content analysis, URL patterns, Wappalyzer, and AI integration
- **DNS Validation**: Intelligent target validation to avoid resolution errors
- **Security Analysis**: Comprehensive security headers and SSL configuration assessment
- **Performance Metrics**: Response time analysis and content size monitoring
- **Technology Insights**: Categorized technology stack analysis with security implications
- **Configurable Sources**: Enable/disable specific detection methods
- **Multiple Output Formats**: Detailed, summary, and minimal reporting options
- **Programmatic Interface**: Function-based configuration without command line dependency
- **Error Handling**: Robust failure management with detailed logging
- **Concurrent Processing**: Multi-threaded requests with rate limiting

## Installation

### Prerequisites
- Python 3.7+
- requests library
- urllib3
- Optional: Wappalyzer for enhanced detection

### Installation Steps
1. Clone the repository
2. Install dependencies: `pip install requests urllib3`
3. Install optional Wappalyzer: `pip install python-Wappalyzer`

## Usage

### Basic Usage
```python
from web_fingerprinting import execute_fingerprinting

# Simple fingerprinting with defaults
results = execute_fingerprinting("example.com")
```

### Advanced Usage
```python
# Advanced configuration with custom settings
results = execute_fingerprinting(
    domain="example.com",
    include_www=True,
    detection_methods=['headers', 'content', 'wappalyzer'],
    timeout=45,
    verbose=True,
    output_format='summary'
)
```

### Programmatic Usage
```python
from web_fingerprinting import ConfigurableWebFingerprinter, WebFingerprintingConfig

# Create custom configuration
config = WebFingerprintingConfig()
config.detection_methods = ['headers', 'content', 'url_patterns', 'wappalyzer']
config.enable_security_analysis = True
config.request_timeout = 30
config.verbose_output = True

# Initialize fingerprinter
fingerprinter = ConfigurableWebFingerprinter("example.com", config)

# Run comprehensive fingerprinting
results = fingerprinter.run_comprehensive_fingerprinting()

# Access detailed results
for target, result in results['targets'].items():
    if 'error' not in result:
        print(f"Target: {target}")
        technologies = result['technology_detection']
        security = result['security_analysis']
        print(f"Technologies detected: {len(technologies)}")
        print(f"Security score: {security.get('security_score', 0)}%")
```

## Configuration

### Configuration Options
- **detection_methods**: Technology detection methods (default: ['headers', 'content', 'url_patterns', 'wappalyzer'])
- **enable_wappalyzer**: Enable Wappalyzer detection (default: True)
- **enable_ai_analysis**: Enable AI-enhanced analysis (default: True)
- **enable_security_analysis**: Enable security assessment (default: True)
- **request_timeout**: Request timeout in seconds (default: 30)
- **concurrent_requests**: Maximum concurrent requests (default: 3)
- **include_www_variant**: Include www subdomain (default: False)
- **include_http**: Include HTTP targets (default: False)
- **output_format**: Output format - 'detailed', 'summary', 'minimal' (default: 'detailed')

### Configuration File
```python
from web_fingerprinting import WebFingerprintingConfig

config = WebFingerprintingConfig()
config.detection_methods = ['headers', 'content', 'wappalyzer', 'ai']
config.enable_security_analysis = True
config.enable_technology_insights = True
config.request_timeout = 45
config.concurrent_requests = 5
config.include_www_variant = True
config.verbose_output = True
config.output_format = 'detailed'
```

## Methods

### execute_fingerprinting
Enhanced function with direct parameter configuration for programmatic use

### ConfigurableWebFingerprinter.run_comprehensive_fingerprinting
Main fingerprinting method that executes all configured detection methods

### _detect_technologies
Multi-method technology detection using headers, content, URL patterns, Wappalyzer, and AI

## Output

### Output Format
```python
{
    'domain': 'example.com',
    'timestamp': 1695551234.567,
    'configuration': {...},
    'targets': {
        'https://example.com': {
            'url': 'https://example.com',
            'timestamp': 1695551234.567,
            'response_analysis': {
                'status_code': 200,
                'content_type': 'text/html; charset=UTF-8',
                'content_length': 15234,
                'title': 'Example Website',
                'has_html': True,
                'redirect_chain': []
            },
            'header_analysis': {
                'server': 'Apache/2.4.62 (Rocky Linux) OpenSSL/3.2.2',
                'server_info': {
                    'name': 'Apache',
                    'components': ['Apache/2.4.62', '(Rocky', 'Linux)', 'OpenSSL/3.2.2']
                },
                'framework_info': {'framework': 'PHP'},
                'x_powered_by': 'PHP/8.1.29'
            },
            'technology_detection': {
                'wappalyzer_detected': ['Apache', 'PHP'],
                'header_detected': ['Apache', 'PHP'],
                'content_detected': ['Font Awesome', 'Google Services'],
                'url_patterns': ['CDN', 'Google Services']
            },
            'security_analysis': {
                'security_score': 0.0,
                'missing_headers': ['X-Frame-Options', 'Content-Security-Policy', ...],
                'ssl_info': {'uses_ssl': True, 'ssl_grade': 'Needs Improvement'}
            },
            'performance_metrics': {
                'response_time': 0.65,
                'content_length': 15234,
                'redirect_count': 1
            }
        }
    },
    'summary': {
        'total_targets': 1,
        'successful_scans': 1,
        'unique_technologies': ['Apache', 'PHP', 'Font Awesome', 'CDN'],
        'security_score_avg': 0.0
    },
    'statistics': {
        'total_duration': 0.65,
        'success_rate': 100.0
    }
}
```

### Results Interpretation
- **targets**: Individual results for each fingerprinted URL
- **technology_detection**: Technologies detected by different methods
- **security_analysis**: Security score and missing security headers
- **performance_metrics**: Response time and content analysis
- **summary**: Aggregated statistics across all targets

## Examples

### Example 1: Basic Fingerprinting
```python
from web_fingerprinting import execute_fingerprinting

# Simple domain fingerprinting
results = execute_fingerprinting("online.uom.lk")
print(f"Fingerprinted {len(results['targets'])} targets")
```

### Example 2: Advanced Configuration
```python
# Custom configuration with specific methods
results = execute_fingerprinting(
    domain="example.com",
    detection_methods=['headers', 'content', 'wappalyzer'],
    include_www=True,
    timeout=45,
    verbose=True,
    output_format='summary'
)

# Access technology insights
for target, result in results['targets'].items():
    if 'technology_insights' in result:
        stack = result['technology_insights']['technology_stack']
        print(f"Web Server: {stack.get('web_server', [])}")
        print(f"Programming Language: {stack.get('programming_language', [])}")
```

### Example 3: Command Line Usage
```bash
# Basic fingerprinting
python web_fingerprinting.py example.com

# With verbose output and custom timeout
python web_fingerprinting.py example.com --verbose --timeout 45

# Custom detection methods
python web_fingerprinting.py example.com --detection-methods headers content wappalyzer
```

## Technology Detection

### ✅ Currently Implemented
- **Header Analysis**: Server identification from HTTP headers (Server, X-Powered-By)
- **Content Analysis**: Technology detection from HTML content and JavaScript
- **URL Pattern Analysis**: Technology identification from resource URLs and CDNs
- **Wappalyzer Integration**: Advanced technology detection when available
- **AI-Enhanced Analysis**: AI-powered technology detection (when configured)

### Detection Categories
- **Web Servers**: Apache, Nginx, IIS, Cloudflare
- **Programming Languages**: PHP, Python, Java, ASP.NET, Node.js
- **Frameworks**: Django, Laravel, Express, Rails
- **CMS**: WordPress, Drupal, Joomla, Moodle
- **JavaScript Libraries**: jQuery, React, Angular, Vue.js
- **CDN Services**: Cloudflare, AWS CloudFront, Azure CDN
- **Analytics**: Google Analytics, Google Tag Manager

## Security Analysis

### Security Score Calculation

The module calculates a comprehensive security score based on the presence of critical security headers. This quantitative assessment helps evaluate web application security posture.

#### Security Headers Evaluated (7 total):
1. **X-Frame-Options** - Prevents clickjacking attacks
2. **Content-Security-Policy** - Prevents XSS and data injection attacks  
3. **Strict-Transport-Security** - Enforces HTTPS connections (HSTS)
4. **X-Content-Type-Options** - Prevents MIME-type sniffing attacks
5. **X-XSS-Protection** - Enables XSS filtering in browsers
6. **Referrer-Policy** - Controls referrer information sent with requests
7. **Permissions-Policy** - Controls browser feature permissions

#### Score Calculation Formula:
```
Security Score = (Present Headers / Total Headers) × 100
Security Score = (Present Headers / 7) × 100
```

#### Score Interpretation:
- **90-100%** (6-7 headers): 🟢 Excellent security - Well protected
- **70-89%** (5 headers): 🟡 Good security - Minor improvements needed
- **50-69%** (3-4 headers): 🟠 Moderate security - Several vulnerabilities
- **30-49%** (2 headers): 🔴 Poor security - Major risks present
- **0-29%** (0-1 headers): ⚠️ Critical issues - Immediate attention required

#### Security Analysis Output Example:
```json
{
  "security_analysis": {
    "security_score": 71.4,
    "security_headers": {
      "X-Frame-Options": "SAMEORIGIN",
      "Content-Security-Policy": "default-src 'self'",
      "Strict-Transport-Security": "max-age=31536000",
      "X-Content-Type-Options": "nosniff",
      "X-XSS-Protection": "1; mode=block",
      "Referrer-Policy": null,
      "Permissions-Policy": null
    },
    "missing_headers": [
      "Referrer-Policy",
      "Permissions-Policy"
    ],
    "present_headers": [
      "X-Frame-Options",
      "Content-Security-Policy",
      "Strict-Transport-Security",
      "X-Content-Type-Options",
      "X-XSS-Protection"
    ],
    "recommendations": [
      "Add Referrer-Policy header to control referrer information",
      "Implement Permissions-Policy to control browser features"
    ],
    "ssl_info": {
      "uses_ssl": true,
      "url_scheme": "https",
      "ssl_grade": "Good"
    }
  }
}
```

### SSL/TLS Analysis
- **HTTPS Detection**: Automatically detects SSL/TLS usage
- **Certificate Validation**: Checks for valid SSL certificates
- **Security Grade**: Overall SSL security assessment
- **Protocol Analysis**: Evaluates encryption and protocol versions

## Error Handling

```python
# Get errors encountered during fingerprinting
fingerprinter = ConfigurableWebFingerprinter("example.com")
results = fingerprinter.run_comprehensive_fingerprinting()
errors = results.get('errors', {})

for source, error_list in errors.items():
    print(f"{source}: {len(error_list)} errors")
```

Common error types handled:
- DNS resolution failures (automatically skipped)
- Connection timeouts and HTTP errors
- SSL certificate verification failures
- Content encoding and parsing errors
- Large content memory management
- Wappalyzer integration errors

## Dependencies

Required packages:
- `requests`: HTTP client with session management
- `urllib3`: Advanced HTTP features and retry strategies
- `socket`: DNS resolution validation
- `re`: Regular expression processing
- `time`: Performance timing
- `logging`: Comprehensive error tracking

Optional dependencies:
- `fingerprinting_wapplyzer`: Enhanced technology detection
- AI integration libraries (for AI-enhanced analysis)

## Troubleshooting

### If you get DNS resolution errors:
1. **Domain validation**: Ensure the domain exists and is accessible
2. **www subdomain**: Disable `include_www` if www subdomain doesn't exist
3. **Network connectivity**: Check internet connection and DNS settings
4. **Firewall issues**: Verify outbound HTTPS connections are allowed

### Common Error Messages:
- `"Skipping www.example.com - DNS resolution failed"`: www subdomain doesn't exist (automatically handled)
- `"Request failed for https://example.com"`: Connection or HTTP error
- `"Wappalyzer detection failed"`: Wappalyzer integration issue (falls back to other methods)
- `"HTTPSConnectionPool... Max retries exceeded"`: Network connectivity problems

### Performance Tips:
- Use `verbose=True` for detailed debugging information
- Reduce `concurrent` requests if experiencing rate limiting
- Increase `timeout` for slow network connections
- Use `output_format='minimal'` for faster processing
- Disable unused detection methods to improve speed
