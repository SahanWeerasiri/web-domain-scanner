# Web Crawler Module

## Overview
The Web Crawler module provides comprehensive web crawling and content analysis capabilities with CDN awareness and AI-enhanced API discovery. It performs intelligent web crawling, extracts useful information from web pages, and discovers API endpoints using both pattern-based detection and AI-powered analysis. The module supports multiple crawl levels and can work with pre-bypassed CDN content for enhanced analysis.

## Features
- **Multi-Level Crawling**: Quick, Smart, and Deep crawling modes with configurable limits
- **AI-Enhanced API Discovery**: Intelligent endpoint generation using multiple AI providers (Gemini, OpenAI, Anthropic)
- **CDN Bypass Integration**: Works with pre-bypassed content from CDN detection modules
- **Comprehensive Content Analysis**: Extracts links, forms, JavaScript references, and potential API endpoints
- **Async API Discovery**: High-performance asynchronous endpoint testing and validation
- **Flexible Output Options**: Configurable result saving and verbose output control

## Installation

### Prerequisites
- Python 3.8 or higher
- Required Python packages: requests, beautifulsoup4, asyncio, dotenv
- Browser manager dependencies (for content retrieval)
- AI integration dependencies (optional, for enhanced discovery)
- Network connectivity for crawling and API testing

### Installation Steps
1. Clone or download the web-domain-scanner repository
2. Navigate to the web crawler module directory
3. Install required dependencies: `pip install requests beautifulsoup4 python-dotenv`
4. Set up environment variables for AI integration (optional)
5. Ensure proper network permissions for web crawling activities

## Configuration

### Configuration Options
- **Crawl Levels**: Three predefined levels with different resource limits and capabilities
- **AI Integration**: Optional AI providers for intelligent endpoint generation
- **Environment Variables**: API keys loaded from .env file or system environment
- **Browser Manager**: Integration with browser automation for content retrieval
- **Output Control**: Configurable result saving and verbosity settings

### Crawl Level Configuration
```python
crawl_levels = {
    'quick': {
        'max_pages': 10,
        'max_api_endpoints': 50,
        'use_ai': False
    },
    'smart': {
        'max_pages': 30,
        'max_api_endpoints': 100,
        'use_ai': True
    },
    'deep': {
        'max_pages': 100,
        'max_api_endpoints': 200,
        'use_ai': True
    }
}
```

## Usage

### Basic Usage
```bash
# Quick crawl with basic analysis
python web_crawler.py example.com --crawl-level quick

# Smart crawl with AI-enhanced discovery (default)
python web_crawler.py example.com

# Deep comprehensive crawl
python web_crawler.py example.com --crawl-level deep
```

### Advanced Usage
```bash
# Use pre-fetched content from CDN bypass
python web_crawler.py example.com --content-file bypassed_content.html --crawl-level smart

# Quiet mode without verbose output
python web_crawler.py example.com --crawl-level deep --quiet

# Skip saving results to file
python web_crawler.py example.com --no-save --crawl-level quick
```

### Programmatic Usage
```python
from web_crawler import WebCrawler, execute_web_crawler

# Basic programmatic usage
results = execute_web_crawler("example.com")

# Advanced programmatic usage with custom parameters
results = execute_web_crawler(
    domain="example.com",
    crawl_level="deep",
    content_file="cached_content.html",
    save_results=True,
    verbose=False
)

# Using WebCrawler class directly
crawler = WebCrawler("example.com")
crawl_results = crawler.run_crawl_level("smart")
api_endpoints = crawler.discover_api_endpoints("deep")
crawler.close()

# Check results
if results.get('success', True):
    print(f"Found {len(results['apis'])} API endpoints")
    print(f"Discovered {len(results['discovered_urls'])} URLs")
else:
    print(f"Crawl failed: {results['error']}")
```

## Methods

### execute_web_crawler(domain, crawl_level='smart', content_file=None, save_results=True, verbose=True)
Main function that orchestrates the complete web crawling process with configurable parameters and returns comprehensive results.

### WebCrawler.run_crawl_level(level, content=None)
Executes a specific crawl level operation, performing content analysis and AI-enhanced API discovery based on the specified level configuration.

### WebCrawler.discover_api_endpoints_async(crawl_level='smart', custom_endpoints=None, content_for_ai=None)
Performs asynchronous API endpoint discovery using AI-generated suggestions, common patterns, and intelligent categorization.

### WebCrawler.analyze_page_content(html_content, url)
Analyzes HTML content to extract useful information including links, forms, JavaScript references, and potential API endpoints.

### WebCrawler.crawl_with_cdn_bypass(content=None, crawl_level='smart')
Performs web crawling using CDN-bypassed content with AI-enhanced API discovery and comprehensive content analysis.

## Output

### Output Format
Returns structured dictionary containing:
- **Pages Analysis**: Extracted page information, titles, meta descriptions, and content
- **API Discovery**: Categorized endpoints (REST APIs, GraphQL, Swagger/OpenAPI, Other APIs)
- **URL Discovery**: All discovered URLs and links from crawled pages
- **Execution Metadata**: Domain, crawl level, timing information, and configuration details
- **Error Information**: Detailed error messages and debugging information when applicable

### Results Interpretation
- **REST APIs**: Standard REST API endpoints with HTTP methods and JSON responses
- **GraphQL Endpoints**: GraphQL and GraphiQL interfaces for API exploration
- **Swagger/OpenAPI**: API documentation and specification endpoints
- **Other APIs**: Miscellaneous API endpoints that don't fit standard categories
- **Success Status**: Boolean indicating successful completion of crawling process
- **Content Analysis**: Extracted forms, JavaScript files, and potential security endpoints

## Examples

### Example 1: Basic Web Crawling and API Discovery
```bash
python web_crawler.py scanme.nmap.org --crawl-level smart
```

### Example 2: Comprehensive Security Assessment
```bash
python web_crawler.py target.example.com --crawl-level deep --content-file cached_page.html
```

### Example 3: Automated Integration with CDN Bypass
```python
# Integration with CDN bypass results
from web_crawler import execute_web_crawler

# Use bypassed content for enhanced analysis
results = execute_web_crawler(
    domain="protected.example.com",
    crawl_level="deep",
    content_file="bypassed_content.html",
    verbose=True
)

# Process discovered APIs
api_discovery = results.get('api_discovery', {})
print(f"Found {len(api_discovery['rest_apis'])} REST APIs")
print(f"Found {len(api_discovery['graphql_endpoints'])} GraphQL endpoints")
```