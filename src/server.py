from fastapi import FastAPI, BackgroundTasks, HTTPException, Query
from pydantic import BaseModel
from typing import Dict, Any, Optional, List, Union
import json
import os
import uuid
import threading
import time
from enum import Enum

from main import DomainRecon
from modules.web_crawling import WebCrawler

app = FastAPI(
    title="Web Domain Scanner API",
    description="API for running domain reconnaissance with advanced module configuration",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

# Enum for available modules
class ModuleEnum(str, Enum):
    SUBDOMAIN_DISCOVERY = "subdomain_discovery"
    DNS_ENUMERATION = "dns_enumeration"
    SERVICE_DISCOVERY = "service_discovery"
    WEB_CRAWL = "web_crawl"
    WEB_FINGERPRINTING = "web_fingerprinting"
    DIRECTORY_BRUTEFORCE = "directory_bruteforce"
    API_DISCOVERY = "api_discovery" 
    CLOUD_DETECTION = "cloud_detection"

# Enum for scan modes
class ScanModeEnum(str, Enum):
    QUICK = "quick"
    SMART = "smart"
    DEEP = "deep"

# State object for each request
class ReconState(BaseModel):
    request_id: str
    domain: str
    state: str  # e.g., 'pending', 'running', 'completed', 'error'
    message: str
    progress: float  # 0.0 to 100.0
    found: Dict[str, Any]  # e.g., {'subdomains': 10, 'services': 5, ...}
    result: Optional[Dict[str, Any]] = None

# Service Discovery Configuration
class ServiceDiscoveryConfig(BaseModel):
    scan_mode: ScanModeEnum = ScanModeEnum.QUICK
    timeout: Optional[float] = 3.0
    max_workers: Optional[int] = 20

# Domain Enumeration Configuration
class DomainEnumerationConfig(BaseModel):
    rate_limit: Optional[int] = 10
    timeout: Optional[float] = 5.0
    retry_attempts: Optional[int] = 3
    doh_fallback: Optional[bool] = True
    cdn_bypass: Optional[bool] = True
    thread_count: Optional[int] = 10
    rate_limiting_enabled: Optional[bool] = True
    wordlist: Optional[str] = None  # Custom wordlist path

# Web Crawling Configuration  
class WebCrawlingConfig(BaseModel):
    crawl_level: Optional[str] = "smart"
    max_pages: Optional[int] = None
    wordlist_size: Optional[int] = None
    wordlist_path: Optional[str] = None
    recursive: Optional[bool] = None
    use_ai: Optional[bool] = None

# Directory Bruteforce Configuration
class DirectoryBruteforceConfig(BaseModel):
    wordlist_path: Optional[str] = None
    extensions: Optional[List[str]] = ["php", "html", "aspx", "jsp", "json"]
    recursive: Optional[bool] = False
    depth: Optional[int] = 2
    max_urls: Optional[int] = None

# API Discovery Configuration
class APIDiscoveryConfig(BaseModel):
    custom_paths: Optional[List[str]] = None
    wordlist_path: Optional[str] = None
    max_endpoints: Optional[int] = 500
    use_ai: Optional[bool] = True

# Cloud Detection Configuration
class CloudDetectionConfig(BaseModel):
    common_buckets_patterns: Optional[List[str]] = None
    cdn_indicators: Optional[Dict[str, List[str]]] = None

# AI Integration Configuration
class AIIntegrationConfig(BaseModel):
    cache_size: Optional[int] = 128
    feedback_db_path: Optional[str] = None

# Complete module configuration
class ModuleConfiguration(BaseModel):
    service_discovery: Optional[ServiceDiscoveryConfig] = None
    domain_enumeration: Optional[DomainEnumerationConfig] = None
    web_crawling: Optional[WebCrawlingConfig] = None
    directory_bruteforce: Optional[DirectoryBruteforceConfig] = None
    api_discovery: Optional[APIDiscoveryConfig] = None
    cloud_detection: Optional[CloudDetectionConfig] = None
    ai_integration: Optional[AIIntegrationConfig] = None

# Pipeline request model
class PipelineRequest(BaseModel):
    domain: str
    scan_mode: ScanModeEnum = ScanModeEnum.QUICK
    modules: Optional[List[ModuleEnum]] = None
    gemini_key: Optional[str] = None
    openai_key: Optional[str] = None
    anthropic_key: Optional[str] = None
    use_async: bool = False
    module_config: Optional[ModuleConfiguration] = None

# Module request models
class ModuleRequest(BaseModel):
    domain: str
    module: ModuleEnum
    module_params: Dict[str, Any] = {}
    gemini_key: Optional[str] = None
    openai_key: Optional[str] = None
    anthropic_key: Optional[str] = None
    use_async: bool = False
    module_config: Optional[ModuleConfiguration] = None


STATE_FILE = "recon_states.json"
recon_states: Dict[str, ReconState] = {}

# Load states from disk if available
def load_states():
    global recon_states
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r") as f:
                data = json.load(f)
                recon_states = {k: ReconState(**v) for k, v in data.items()}
        except Exception:
            recon_states = {}
load_states()

# Save states to disk
def save_states():
    with open(STATE_FILE, "w") as f:
        json.dump({k: v.dict() for k, v in recon_states.items()}, f)

# Helper to update state

def update_state(request_id, **kwargs):
    state = recon_states.get(request_id)
    if state:
        for k, v in kwargs.items():
            setattr(state, k, v)
        save_states()

# Background pipeline process
def run_pipeline_process(
    request_id: str, 
    domain: str, 
    scan_mode: str,
    modules: List[str] = None,
    gemini_key: Optional[str] = None,
    openai_key: Optional[str] = None,
    anthropic_key: Optional[str] = None,
    use_async: bool = False,
    module_config: ModuleConfiguration = None
):
    try:
        update_state(request_id, state='running', message='Pipeline started', progress=5.0)
        
        # Convert module enum values to strings if needed
        module_list = None
        if modules:
            module_list = [m.value if hasattr(m, 'value') else m for m in modules]
        
        # Convert ModuleConfiguration to dict format expected by DomainRecon
        config_dict = {}
        if module_config:
            if module_config.domain_enumeration:
                config_dict['domain_enum'] = module_config.domain_enumeration.dict(exclude_none=True)
            if module_config.service_discovery:
                config_dict['service_disc'] = module_config.service_discovery.dict(exclude_none=True)
            if module_config.web_crawling:
                config_dict['web_crawler'] = module_config.web_crawling.dict(exclude_none=True)
            if module_config.ai_integration:
                config_dict['ai_integration'] = module_config.ai_integration.dict(exclude_none=True)
            if module_config.cloud_detection:
                config_dict['cloud_detector'] = module_config.cloud_detection.dict(exclude_none=True)
            if module_config.directory_bruteforce:
                config_dict['directory_bruteforce'] = module_config.directory_bruteforce.dict(exclude_none=True)
            if module_config.api_discovery:
                config_dict['api_discovery'] = module_config.api_discovery.dict(exclude_none=True)
        
        # Initialize the DomainRecon class with all parameters
        recon = DomainRecon(
            domain,
            gemini_api_key=gemini_key,
            openai_api_key=openai_key,
            anthropic_api_key=anthropic_key,
            use_async=use_async,
            module_config=config_dict
        )
        
        # Run the pipeline with selected modules or all modules
        recon.run_all(scan_mode=scan_mode, modules_to_run=module_list)
        
        # Update state with final results
        report_info = recon.save_final_report()
        update_state(
            request_id, 
            state='completed', 
            message='Recon complete',
            progress=100.0,
            result=recon.results
        )
        
    except Exception as e:
        update_state(request_id, state='error', message=str(e), progress=100.0)

# Background module process
def run_module_process(
    request_id: str,
    domain: str,
    module_name: str,
    module_params: Dict[str, Any],
    gemini_key: Optional[str] = None,
    openai_key: Optional[str] = None,
    anthropic_key: Optional[str] = None,
    use_async: bool = False,
    module_config: ModuleConfiguration = None
):
    try:
        update_state(request_id, state='running', message=f'Module {module_name} started', progress=10.0)
        
        # Convert ModuleConfiguration to dict format expected by DomainRecon
        config_dict = {}
        if module_config:
            if module_config.domain_enumeration:
                config_dict['domain_enum'] = module_config.domain_enumeration.dict(exclude_none=True)
            if module_config.service_discovery:
                config_dict['service_disc'] = module_config.service_discovery.dict(exclude_none=True)
            if module_config.web_crawling:
                config_dict['web_crawler'] = module_config.web_crawling.dict(exclude_none=True)
            if module_config.ai_integration:
                config_dict['ai_integration'] = module_config.ai_integration.dict(exclude_none=True)
            if module_config.cloud_detection:
                config_dict['cloud_detector'] = module_config.cloud_detection.dict(exclude_none=True)
            if module_config.directory_bruteforce:
                config_dict['directory_bruteforce'] = module_config.directory_bruteforce.dict(exclude_none=True)
            if module_config.api_discovery:
                config_dict['api_discovery'] = module_config.api_discovery.dict(exclude_none=True)
        
        # Initialize the DomainRecon class
        recon = DomainRecon(
            domain,
            gemini_api_key=gemini_key,
            openai_api_key=openai_key,
            anthropic_api_key=anthropic_key,
            use_async=use_async,
            module_config=config_dict
        )
        
        # Run the specific module
        result = recon.run_module(module_name, **module_params)
        
        # Update state with the results
        update_state(
            request_id, 
            state='completed',
            message=f'Module {module_name} complete',
            progress=100.0,
            found={module_name: len(result) if isinstance(result, (list, dict)) else 0},
            result={module_name: result}
        )
        
    except Exception as e:
        update_state(request_id, state='error', message=str(e), progress=100.0)

# Endpoint to start a pipeline recon process
@app.post("/api/pipeline")
def start_pipeline(request: PipelineRequest):
    # Generate a new request_id
    while True:
        request_id = str(uuid.uuid4())
        if request_id not in recon_states:
            break
            
    # Create initial state
    recon_states[request_id] = ReconState(
        request_id=request_id,
        domain=request.domain,
        state='pending',
        message='Pipeline recon request received',
        progress=0.0,
        found={},
        result=None
    )
    save_states()
    
    # Start pipeline process in a thread
    thread = threading.Thread(
        target=run_pipeline_process, 
        args=(
            request_id, 
            request.domain, 
            request.scan_mode.value,
            request.modules,
            request.gemini_key,
            request.openai_key,
            request.anthropic_key,
            request.use_async,
            request.module_config
        )
    )
    thread.start()
    
    return {"request_id": request_id}

# Endpoint to run a specific module
@app.post("/api/module")
def run_module(request: ModuleRequest):
    # Generate a new request_id
    while True:
        request_id = str(uuid.uuid4())
        if request_id not in recon_states:
            break
            
    # Create initial state
    recon_states[request_id] = ReconState(
        request_id=request_id,
        domain=request.domain,
        state='pending',
        message=f'Module {request.module.value} request received',
        progress=0.0,
        found={},
        result=None
    )
    save_states()
    
    # Start module process in a thread
    thread = threading.Thread(
        target=run_module_process,
        args=(
            request_id,
            request.domain,
            request.module.value,
            request.module_params,
            request.gemini_key,
            request.openai_key,
            request.anthropic_key,
            request.use_async,
            request.module_config
        )
    )
    thread.start()
    
    return {"request_id": request_id}

# Endpoint to get status/state
@app.get("/api/status/{request_id}")
def get_status(request_id: str):
    state = recon_states.get(request_id)
    if not state:
        raise HTTPException(status_code=404, detail="Request ID not found")
    return state

# Endpoint to get available modules and their parameters
@app.get("/api/modules")
def get_modules():
    """Return a list of all available modules and their configurable parameters"""
    modules = {
        "subdomain_discovery": {
            "description": "Discover subdomains for the target domain",
            "parameters": {
                "wordlist": {"type": "string", "description": "Path to subdomain wordlist file"},
                "rate_limit": {"type": "integer", "description": "Requests per second limit", "default": 10},
                "timeout": {"type": "number", "description": "Request timeout in seconds", "default": 5.0},
                "retry_attempts": {"type": "integer", "description": "Number of retry attempts", "default": 3},
                "thread_count": {"type": "integer", "description": "Number of concurrent threads", "default": 10},
                "doh_fallback": {"type": "boolean", "description": "Enable DNS over HTTPS fallback", "default": True},
                "cdn_bypass": {"type": "boolean", "description": "Enable CDN bypass techniques", "default": True}
            }
        },
        "dns_enumeration": {
            "description": "Enumerate DNS records for the domain",
            "parameters": {
                "timeout": {"type": "number", "description": "DNS query timeout", "default": 5.0},
                "retry_attempts": {"type": "integer", "description": "Number of retry attempts", "default": 3}
            }
        },
        "service_discovery": {
            "description": "Discover services running on the domain",
            "parameters": {
                "scan_mode": {"type": "string", "enum": ["quick", "smart", "deep"], "description": "Port scanning mode", "default": "quick"},
                "timeout": {"type": "number", "description": "Port scan timeout", "default": 3.0},
                "max_workers": {"type": "integer", "description": "Maximum concurrent workers", "default": 20}
            }
        },
        "web_crawl": {
            "description": "Crawl website for links and content",
            "parameters": {
                "crawl_level": {"type": "string", "enum": ["quick", "smart", "deep"], "description": "Crawl depth level", "default": "smart"},
                "max_pages": {"type": "integer", "description": "Maximum pages to crawl"},
                "wordlist_size": {"type": "integer", "description": "Size of wordlist for directory discovery"},
                "wordlist_path": {"type": "string", "description": "Path to wordlist file for crawling"},
                "recursive": {"type": "boolean", "description": "Enable recursive crawling"},
                "use_ai": {"type": "boolean", "description": "Use AI for intelligent crawling"}
            }
        },
        "web_fingerprinting": {
            "description": "Fingerprint web technologies used by the website",
            "parameters": {
                "timeout": {"type": "number", "description": "Request timeout", "default": 5.0}
            }
        },
        "directory_bruteforce": {
            "description": "Discover directories on the web server",
            "parameters": {
                "wordlist_path": {"type": "string", "description": "Path to directory wordlist file"},
                "extensions": {"type": "array", "items": {"type": "string"}, "description": "File extensions to check", "default": ["php", "html", "aspx", "jsp", "json"]},
                "recursive": {"type": "boolean", "description": "Enable recursive scanning", "default": False},
                "depth": {"type": "integer", "description": "Maximum recursion depth", "default": 2},
                "max_urls": {"type": "integer", "description": "Maximum URLs to test"}
            }
        },
        "api_discovery": {
            "description": "Discover API endpoints",
            "parameters": {
                "custom_paths": {"type": "array", "items": {"type": "string"}, "description": "Custom API paths to check"},
                "wordlist_path": {"type": "string", "description": "Path to API endpoints wordlist file"},
                "max_endpoints": {"type": "integer", "description": "Maximum number of endpoints to test", "default": 500},
                "use_ai": {"type": "boolean", "description": "Use AI for endpoint generation", "default": True}
            }
        },
        "cloud_detection": {
            "description": "Detect cloud services and CDNs",
            "parameters": {
                "common_buckets_patterns": {"type": "array", "items": {"type": "string"}, "description": "Common bucket name patterns"},
                "cdn_indicators": {"type": "object", "description": "CDN detection indicators"}
            }
        }
    }
    
    # Add configuration schema
    config_schema = {
        "module_configuration": {
            "service_discovery": {
                "scan_mode": {"type": "string", "enum": ["quick", "smart", "deep"]},
                "timeout": {"type": "number"},
                "max_workers": {"type": "integer"}
            },
            "domain_enumeration": {
                "rate_limit": {"type": "integer"},
                "timeout": {"type": "number"},
                "retry_attempts": {"type": "integer"},
                "doh_fallback": {"type": "boolean"},
                "cdn_bypass": {"type": "boolean"},
                "thread_count": {"type": "integer"},
                "rate_limiting_enabled": {"type": "boolean"},
                "wordlist": {"type": "string"}
            },
            "web_crawling": {
                "crawl_level": {"type": "string", "enum": ["quick", "smart", "deep"]},
                "max_pages": {"type": "integer"},
                "wordlist_size": {"type": "integer"},
                "wordlist_path": {"type": "string"},
                "recursive": {"type": "boolean"},
                "use_ai": {"type": "boolean"}
            },
            "directory_bruteforce": {
                "wordlist_path": {"type": "string"},
                "extensions": {"type": "array", "items": {"type": "string"}},
                "recursive": {"type": "boolean"},
                "depth": {"type": "integer"},
                "max_urls": {"type": "integer"}
            },
            "api_discovery": {
                "custom_paths": {"type": "array", "items": {"type": "string"}},
                "wordlist_path": {"type": "string"},
                "max_endpoints": {"type": "integer"},
                "use_ai": {"type": "boolean"}
            },
            "cloud_detection": {
                "common_buckets_patterns": {"type": "array", "items": {"type": "string"}},
                "cdn_indicators": {"type": "object"}
            },
            "ai_integration": {
                "cache_size": {"type": "integer"},
                "feedback_db_path": {"type": "string"}
            }
        }
    }
    
    return {
        "modules": modules,
        "configuration_schema": config_schema
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000) 