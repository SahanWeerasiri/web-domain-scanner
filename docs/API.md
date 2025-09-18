# Web Domain Scanner API Documentation

This document describes the REST API endpoints available in the Web Domain Scanner application for integration with custom clients or scripts.

## Base URL

All API endpoints are accessible from the base URL:

```
http://localhost:8000/api/
```

## API Documentation

Interactive API documentation is available at:
- Swagger UI: `http://localhost:8000/api/docs`
- ReDoc: `http://localhost:8000/api/redoc`

## Authentication

Currently, the API does not require authentication. This is intended for local development use only.

## Endpoints

### Pipeline Execution

Run a complete reconnaissance pipeline with multiple modules.

**Endpoint:** `/api/pipeline`  
**Method:** `POST`  
**Content Type:** `application/json`  

**Request Body:**

```json
{
  "domain": "example.com",
  "scan_mode": "quick",  // Optional: "quick", "smart", or "deep"
  "modules": [           // Optional: specify modules to run
    "subdomain_discovery",
    "service_discovery",
    "web_crawl"
  ],
  "gemini_key": "YOUR_GEMINI_API_KEY",  // Optional
  "openai_key": "YOUR_OPENAI_API_KEY",  // Optional
  "anthropic_key": "YOUR_CLAUDE_API_KEY",  // Optional
  "use_async": false,    // Optional: use async processing
  "module_config": {     // Optional: advanced module configuration
    "domain_enum": {
      "wordlist": "config/wordlists/subdomains.txt"
    },
    "service_disc": {
      "max_workers": 20,
      "timeout": 3
    },
    "web_crawler": {
      "max_pages": 30,
      "depth": 2,
      "respect_robots": true,
      "directory_bruteforce": {
        "wordlist_path": "config/wordlists/common_directories.txt",
        "extensions": ["php", "html", "asp", "aspx", "jsp"],
        "recursive": false,
        "max_depth": 2
      },
      "api_discovery": {
        "max_endpoints": 500,
        "custom_paths": ["api/v1", "api/v2", "graphql"]
      }
    },
    "ai_integration": {
      "cache_size": 128
    },
    "cloud_detector": {
      "common_buckets_patterns": ["s3", "storage", "assets", "static"]
    }
  }
}
```

**Response:**

```json
{
  "request_id": "uuid-string"
}
```

### Module Execution

Run a single reconnaissance module with custom parameters.

**Endpoint:** `/api/module`  
**Method:** `POST`  
**Content Type:** `application/json`  

**Request Body:**

```json
{
  "domain": "example.com",
  "module": "subdomain_discovery",  // Required: module name
  "module_params": {                // Optional: module-specific parameters
    "wordlist": "config/wordlists/subdomains.txt"
  },
  "gemini_key": "YOUR_GEMINI_API_KEY",  // Optional
  "openai_key": "YOUR_OPENAI_API_KEY",  // Optional
  "anthropic_key": "YOUR_CLAUDE_API_KEY",  // Optional
  "use_async": false    // Optional: use async processing
}
```

**Response:**

```json
{
  "request_id": "uuid-string"
}
```

### Get Scan Status

Check the status of a running or completed scan.

**Endpoint:** `/api/status/{request_id}`  
**Method:** `GET`  

**Response:**

```json
{
  "request_id": "uuid-string",
  "domain": "example.com",
  "state": "running",  // "pending", "running", "completed", "error"
  "message": "Scanning subdomains...",
  "progress": 45.5,    // 0.0 to 100.0
  "found": {
    "subdomains": 5,
    "services": 3
    // Other metrics...
  },
  "result": {
    // Complete scan results (when state is "completed")
  }
}
```

### Get Available Modules

Get a list of all available modules and their configurable parameters.

**Endpoint:** `/api/modules`  
**Method:** `GET`  

**Response:**

```json
{
  "subdomain_discovery": {
    "description": "Discover subdomains for the target domain",
    "parameters": {
      "wordlist": {
        "type": "string",
        "description": "Path to subdomain wordlist file"
      }
    }
  },
  "service_discovery": {
    "description": "Discover services running on the domain",
    "parameters": {
      "scan_mode": {
        "type": "string",
        "enum": ["quick", "smart", "deep"],
        "description": "Port scanning mode"
      }
    }
  }
  // Other modules...
}
```

## Module Names

The following module names can be used in API requests:

- `subdomain_discovery`: Find subdomains
- `dns_enumeration`: Enumerate DNS records
- `service_discovery`: Discover open ports and services
- `web_crawl`: Crawl website for links and content
- `web_fingerprinting`: Fingerprint web technologies
- `directory_bruteforce`: Discover directories on the web server
- `api_discovery`: Discover API endpoints
- `cloud_detection`: Detect cloud services and CDNs

## Error Handling

Errors are returned with appropriate HTTP status codes:

- `400 Bad Request`: Invalid request parameters
- `404 Not Found`: Request ID not found
- `500 Internal Server Error`: Server-side error

Error responses include a detail message explaining the error:

```json
{
  "detail": "Error message"
}
```

## Example Usage

### cURL Examples

**Run pipeline scan:**

```bash
curl -X POST "http://localhost:8000/api/pipeline" \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com",
    "scan_mode": "quick",
    "modules": ["subdomain_discovery", "service_discovery"],
    "module_config": {
      "service_disc": {
        "max_workers": 30
      }
    }
  }'
```

**Run individual module:**

```bash
curl -X POST "http://localhost:8000/api/module" \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com",
    "module": "subdomain_discovery",
    "module_params": {
      "wordlist": "config/wordlists/subdomains.txt"
    }
  }'
```

**Check scan status:**

```bash
curl -X GET "http://localhost:8000/api/status/YOUR_REQUEST_ID"
```

**Get available modules:**

```bash
curl -X GET "http://localhost:8000/api/modules"
```

## Python Example

```python
import requests
import time
import json

API_BASE_URL = "http://localhost:8000/api"

# Run a pipeline scan
def run_pipeline_scan(domain, modules=None, module_config=None):
    payload = {
        "domain": domain,
        "scan_mode": "quick",
    }
    
    if modules:
        payload["modules"] = modules
        
    if module_config:
        payload["module_config"] = module_config
        
    response = requests.post(
        f"{API_BASE_URL}/pipeline",
        json=payload
    )
    
    if response.status_code == 202:
        return response.json()["request_id"]
    else:
        print(f"Error: {response.text}")
        return None

# Check scan status
def check_scan_status(request_id):
    response = requests.get(f"{API_BASE_URL}/status/{request_id}")
    
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error: {response.text}")
        return None

# Example usage
if __name__ == "__main__":
    domain = "example.com"
    
    # Configure modules
    module_config = {
        "service_disc": {
            "max_workers": 25,
            "timeout": 5
        }
    }
    
    # Run scan
    request_id = run_pipeline_scan(
        domain, 
        modules=["subdomain_discovery", "service_discovery"],
        module_config=module_config
    )
    
    if request_id:
        print(f"Scan started with request ID: {request_id}")
        
        # Poll status until completion
        while True:
            status = check_scan_status(request_id)
            
            if not status:
                break
                
            print(f"Status: {status['state']} - Progress: {status['progress']}%")
            
            if status['state'] in ['completed', 'error']:
                if status['state'] == 'completed':
                    print("Scan completed successfully!")
                    print(json.dumps(status['result'], indent=2))
                else:
                    print(f"Scan failed: {status['message']}")
                break
                
            time.sleep(2)
```
