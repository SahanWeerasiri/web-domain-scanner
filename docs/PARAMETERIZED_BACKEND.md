# Parameterized Backend System Documentation

## Overview

The web domain scanner backend has been enhanced to accept detailed configuration parameters for all modules, allowing fine-tuned control over scanning behavior. This enables users to customize the scanning process based on their specific requirements.

## Key Features

- **Modular Configuration**: Each module can be configured independently
- **Pipeline Configuration**: Full pipeline runs can be customized with module-specific parameters
- **API Parameter Support**: RESTful API endpoints accept configuration parameters
- **Backward Compatibility**: Existing functionality remains unchanged when no parameters are provided

## Module Parameters

### 1. Service Discovery

Configure port scanning behavior with three scanning modes and additional parameters:

**Available Parameters:**
- `scan_mode`: `"quick"` | `"smart"` | `"deep"`
- `timeout`: Connection timeout in seconds (default: 3.0)
- `max_workers`: Maximum concurrent workers (default: 20)

**Scan Modes:**
- **Quick**: Scans common ports only (fastest)
- **Smart**: Intelligent fuzzing and extended port discovery
- **Deep**: Comprehensive scan using external tools (nmap/rustscan)

**Example Configuration:**
```json
{
  "service_discovery": {
    "scan_mode": "smart",
    "timeout": 2.5,
    "max_workers": 15
  }
}
```

### 2. Domain Enumeration

Configure subdomain discovery and DNS enumeration:

**Available Parameters:**
- `rate_limit`: Requests per second limit (default: 10)
- `timeout`: Request timeout in seconds (default: 5.0)
- `retry_attempts`: Number of retry attempts (default: 3)
- `doh_fallback`: Enable DNS over HTTPS fallback (default: true)
- `cdn_bypass`: Enable CDN bypass techniques (default: true)
- `thread_count`: Number of concurrent threads (default: 10)
- `rate_limiting_enabled`: Enable rate limiting (default: true)
- `wordlist`: Path to custom subdomain wordlist

**Example Configuration:**
```json
{
  "domain_enumeration": {
    "rate_limit": 5,
    "timeout": 3.0,
    "retry_attempts": 2,
    "thread_count": 8,
    "wordlist": "/path/to/custom/subdomains.txt"
  }
}
```

### 3. Web Crawling

Configure website crawling depth and behavior:

**Available Parameters:**
- `crawl_level`: `"quick"` | `"smart"` | `"deep"`
- `max_pages`: Maximum pages to crawl
- `wordlist_size`: Size of wordlist for directory discovery
- `wordlist_path`: Path to custom wordlist file
- `recursive`: Enable recursive crawling
- `use_ai`: Use AI for intelligent crawling

**Crawl Levels:**
- **Quick**: 10 pages, 20 wordlist terms, no recursion, no AI
- **Smart**: 30 pages, 50 wordlist terms, recursion enabled, AI enabled
- **Deep**: 100 pages, full wordlist, recursion enabled, AI enabled

**Example Configuration:**
```json
{
  "web_crawling": {
    "crawl_level": "smart",
    "max_pages": 25,
    "wordlist_size": 40,
    "recursive": true,
    "use_ai": true
  }
}
```

### 4. Directory Bruteforce

Configure directory discovery parameters:

**Available Parameters:**
- `wordlist_path`: Path to directory wordlist file
- `extensions`: Array of file extensions to check
- `recursive`: Enable recursive scanning
- `depth`: Maximum recursion depth
- `max_urls`: Maximum URLs to test

**Example Configuration:**
```json
{
  "directory_bruteforce": {
    "wordlist_path": "/path/to/directories.txt",
    "extensions": ["php", "html", "aspx", "json"],
    "recursive": true,
    "depth": 3,
    "max_urls": 1000
  }
}
```

### 5. API Discovery

Configure API endpoint discovery:

**Available Parameters:**
- `custom_paths`: Array of custom API paths to check
- `wordlist_path`: Path to API endpoints wordlist file
- `max_endpoints`: Maximum number of endpoints to test
- `use_ai`: Use AI for endpoint generation

**Example Configuration:**
```json
{
  "api_discovery": {
    "custom_paths": ["api/v1", "api/v2", "graphql", "webhook"],
    "max_endpoints": 200,
    "use_ai": true
  }
}
```

### 6. Cloud Detection

Configure cloud service and CDN detection:

**Available Parameters:**
- `common_buckets_patterns`: Array of bucket name patterns
- `cdn_indicators`: Object mapping CDN names to indicators
- `timeout`: Request timeout for cloud checks
- `max_buckets`: Maximum number of buckets to test

**Example Configuration:**
```json
{
  "cloud_detection": {
    "common_buckets_patterns": ["{domain}", "{domain}-assets", "{domain}-backup"],
    "cdn_indicators": {
      "Cloudflare": ["cloudflare", "cf-ray"],
      "AWS CloudFront": ["cloudfront"]
    },
    "timeout": 5,
    "max_buckets": 10
  }
}
```

### 7. AI Integration

Configure AI-powered features:

**Available Parameters:**
- `cache_size`: Size of AI response cache
- `feedback_db_path`: Path to feedback database file

**Example Configuration:**
```json
{
  "ai_integration": {
    "cache_size": 256,
    "feedback_db_path": "/path/to/feedback.json"
  }
}
```

## API Usage

### Pipeline Endpoint

Start a full pipeline scan with custom configuration:

```bash
POST /api/pipeline
```

**Request Body:**
```json
{
  "domain": "example.com",
  "scan_mode": "smart",
  "modules": ["subdomain_discovery", "service_discovery", "web_crawl"],
  "module_config": {
    "service_discovery": {
      "scan_mode": "smart",
      "timeout": 2.0,
      "max_workers": 15
    },
    "web_crawling": {
      "crawl_level": "smart",
      "max_pages": 20,
      "use_ai": true
    }
  }
}
```

### Module Endpoint

Run individual modules with custom parameters:

```bash
POST /api/module
```

**Request Body:**
```json
{
  "domain": "example.com",
  "module": "service_discovery",
  "module_params": {
    "scan_mode": "deep"
  },
  "module_config": {
    "service_discovery": {
      "timeout": 5.0,
      "max_workers": 25
    }
  }
}
```

### Status Endpoint

Check the status of running scans:

```bash
GET /api/status/{request_id}
```

### Modules Info Endpoint

Get available modules and their parameters:

```bash
GET /api/modules
```

## Command Line Usage

The main.py script also supports the new parameter system:

```bash
# Run with custom config file
python src/main.py example.com --config-file config.json

# Run individual module with parameters
python src/main.py example.com --mode module --module service_discovery --scan-mode smart

# Run pipeline with specific modules
python src/main.py example.com --modules subdomain_discovery service_discovery --scan-mode smart
```

## Configuration File Format

Create a JSON configuration file for complex setups:

```json
{
  "domain_enum": {
    "rate_limit": 8,
    "timeout": 4.0,
    "thread_count": 12
  },
  "service_disc": {
    "scan_mode": "smart",
    "timeout": 3.0,
    "max_workers": 20
  },
  "web_crawler": {
    "crawl_level": "deep",
    "max_pages": 50,
    "recursive": true,
    "use_ai": true
  },
  "api_discovery": {
    "max_endpoints": 300,
    "use_ai": true
  },
  "cloud_detector": {
    "timeout": 4,
    "max_buckets": 15
  },
  "ai_integration": {
    "cache_size": 512
  }
}
```

## Testing

Test the parameterized system using the provided test scripts:

```bash
# Test the backend parameter system
python test_parameterized_backend.py

# Test the API endpoints (requires server to be running)
python test_api_parameters.py
```

## Benefits

1. **Customizable Performance**: Adjust timeouts, worker counts, and other parameters for optimal performance
2. **Flexible Scanning**: Choose between quick reconnaissance and deep analysis
3. **Resource Management**: Control resource usage with worker limits and rate limiting
4. **Targeted Discovery**: Use custom wordlists and paths for specific targets
5. **Scalable Configuration**: Easy to extend with new parameters as needed

## Migration Guide

Existing code will continue to work without changes. To leverage the new parameters:

1. **API Users**: Add `module_config` to your request bodies
2. **CLI Users**: Use `--config-file` or module-specific flags
3. **Python Users**: Pass `module_config` dictionary to `DomainRecon` constructor

The system gracefully falls back to default values when parameters are not provided.