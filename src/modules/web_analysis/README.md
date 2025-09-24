# Web Analysis Module

## Overview
The Web Analysis module provides a comprehensive reconnaissance toolkit that combines CDN detection and web crawling into a unified analysis platform. It intelligently detects CDN usage, attempts bypassing when content is blocked, and performs extensive API endpoint discovery and web crawling. The module orchestrates multiple sub-components to deliver complete web security assessment capabilities.

## Features
- **Intelligent CDN Detection**: Automatic detection of CDN usage with multiple detection methods
- **Smart CDN Bypass**: Automated bypass attempts for blocked content with browser automation
- **Comprehensive Web Crawling**: Multi-level crawling with AI-enhanced API discovery
- **API Endpoint Discovery**: Intelligent discovery of REST APIs, GraphQL, and Swagger endpoints
- **Flexible Analysis Modes**: Support for normal and deep crawling operations
- **Structured Results**: Detailed JSON output with comprehensive metadata and statistics

## Installation

### Prerequisites
- Python 3.8 or higher
- Required Python packages: requests, beautifulsoup4, selenium, dotenv
- Browser dependencies for CDN bypass (Chrome/Chromium)
- Network connectivity for web analysis and crawling
- Appropriate permissions for browser automation

### Installation Steps
1. Clone or download the web-domain-scanner repository
2. Navigate to the web analysis module directory
3. Install required dependencies: `pip install requests beautifulsoup4 selenium python-dotenv`
4. Set up browser automation dependencies (ChromeDriver)
5. Configure environment variables for AI integration (optional)

## Configuration

### Configuration Options
- **CDN Bypass**: Toggle CDN bypass attempts when content blocking is detected
- **Deep Crawl Mode**: Enable comprehensive deep crawling for thorough analysis
- **Output Directory**: Configurable directory for saving analysis results
- **File Output**: Optional JSON file export for automated processing
- **Logging Control**: Configurable logging levels and output destinations

### Analysis Workflow Configuration
The module follows an intelligent workflow:
1. **CDN Detection** → Identify CDN usage and providers
2. **Blocking Assessment** → Check if content is actually blocked
3. **Smart Bypass** → Attempt bypass only when necessary
4. **API Discovery** → Comprehensive endpoint discovery with AI enhancement
5. **Deep Crawling** → Optional extensive content analysis

## Usage

### Basic Usage
```bash
# Basic reconnaissance analysis
python main.py example.com

# Analysis with CDN bypass disabled
python main.py example.com --no-bypass

# Deep crawling mode for comprehensive analysis
python main.py example.com --deep-crawl
```

### Advanced Usage
```bash
# Comprehensive analysis with file output
python main.py example.com --deep-crawl --save-to-file --output-dir custom_results

# Analysis with custom output directory
python main.py example.com --output-dir /path/to/results --save-to-file

# Skip CDN bypass with deep crawling
python main.py example.com --no-bypass --deep-crawl --save-to-file
```

### Programmatic Usage
```python
from main import execute_web_analysis, ReconToolkit

# Basic programmatic usage
results = execute_web_analysis("example.com")

# Advanced programmatic usage with custom parameters
results = execute_web_analysis(
    domain="example.com",
    bypass_cdn=True,
    deep_crawl=True,
    save_to_file=True,
    output_dir="security_analysis",
    verbose=False,
    setup_logging=False
)

# Using ReconToolkit class directly
toolkit = ReconToolkit("example.com")
results = toolkit.run(bypass_cdn=True, deep_crawl=True)
output_file = toolkit.save_results("results")

# Process results
if results.get('success', True):
    cdn_detected = results['cdn_detection']['cdn_detected']
    if 'web_crawl' in results:
        api_count = len(results['web_crawl'].get('apis', []))
        print(f"CDN: {cdn_detected}, APIs found: {api_count}")
else:
    print(f"Analysis failed: {results['error']}")
```

## Methods

### execute_web_analysis(domain, bypass_cdn=True, deep_crawl=False, output_dir="results", save_to_file=False, verbose=True, setup_logging=True)
Main function that orchestrates the complete web analysis process including CDN detection, bypass attempts, and comprehensive web crawling.

### ReconToolkit.run(bypass_cdn=True, deep_crawl=False)
Core method that executes the reconnaissance workflow, handling CDN detection, content blocking assessment, and intelligent bypass operations.

### ReconToolkit.save_results(output_dir="results")
Saves analysis results to JSON file with structured formatting and returns the output file path for further processing.

## Output

### Output Format
Returns comprehensive structured dictionary containing:
- **CDN Detection Results**: Provider identification, detection methods, and confidence levels
- **Blocking Assessment**: Content accessibility analysis and blocking phrase detection
- **Bypass Results**: CDN bypass success status, methods used, and effectiveness metrics
- **Web Crawling Data**: Discovered pages, URLs, API endpoints with detailed categorization
- **API Discovery**: REST APIs, GraphQL endpoints, Swagger documentation with response codes
- **Execution Metadata**: Analysis parameters, timing information, and success status

### Results Interpretation
- **CDN Detection**: Boolean flag with provider name and detection confidence
- **Content Blocking**: Assessment of whether content is actually blocked by CDN
- **Bypass Success**: Effectiveness of CDN bypass attempts and methods used
- **API Categories**: Organized endpoint discovery (REST, GraphQL, Swagger, Other)
- **Crawl Statistics**: Page counts, URL discovery metrics, and analysis depth
- **Error Information**: Detailed error messages and failure diagnostics

## Examples

### Example 1: Basic Security Assessment
```bash
python main.py scanme.nmap.org --save-to-file
```

### Example 2: Comprehensive Enterprise Analysis
```bash
python main.py corporate.example.com --deep-crawl --save-to-file --output-dir enterprise_analysis
```

### Example 3: CDN-Protected Site Analysis
```bash
python main.py protected.example.com --deep-crawl --save-to-file
```

### Example 4: Programmatic Integration
```python
# Automated security assessment pipeline
domains = ["target1.com", "target2.com", "target3.com"]
all_results = []

for domain in domains:
    results = execute_web_analysis(
        domain=domain,
        deep_crawl=True,
        save_to_file=True,
        verbose=False,
        output_dir=f"analysis_{domain.replace('.', '_')}"
    )
    
    # Extract key metrics
    analysis_summary = {
        'domain': domain,
        'cdn_detected': results['cdn_detection']['cdn_detected'],
        'bypass_successful': results.get('cdn_bypass', {}).get('bypass_successful', False),
        'api_endpoints_found': len(results.get('web_crawl', {}).get('apis', [])),
        'pages_analyzed': len(results.get('web_crawl', {}).get('pages', [])),
        'success': results.get('success', True)
    }
    
    all_results.append(analysis_summary)
    
    # Process API discoveries
    if 'web_crawl' in results:
        api_discovery = results['web_crawl'].get('api_discovery', {})
        print(f"{domain}: Found {len(api_discovery.get('rest_apis', []))} REST APIs, "
              f"{len(api_discovery.get('graphql_endpoints', []))} GraphQL endpoints")

# Generate consolidated report
print(f"Analysis complete: {len(all_results)} domains processed")
```