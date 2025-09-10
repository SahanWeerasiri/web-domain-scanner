from fastapi import FastAPI, BackgroundTasks, HTTPException
from pydantic import BaseModel
from typing import Dict, Any, Optional
import json
import os
import uuid
import threading
import time

from main import DomainRecon
from modules.web_crawling import WebCrawler

app = FastAPI()

# State object for each request
class ReconState(BaseModel):
    request_id: str
    domain: str
    state: str  # e.g., 'pending', 'running', 'completed', 'error'
    message: str
    progress: float  # 0.0 to 100.0
    found: Dict[str, Any]  # e.g., {'subdomains': 10, 'services': 5, ...}
    result: Optional[Dict[str, Any]] = None


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

# Background recon process

def run_recon_process(request_id: str, domain: str, gemini_key: Optional[str] = None):
    try:
        update_state(request_id, state='running', message='Recon started', progress=5.0)
        recon = DomainRecon(domain, gemini_key)
        # Stepwise progress updates
        recon.subdomain_discovery()
        update_state(request_id, message='Subdomain discovery complete', progress=20.0, found={'subdomains': len(recon.results.get('subdomains', []))})
        recon.dns_enumeration()
        update_state(request_id, message='DNS enumeration complete', progress=30.0, found={**recon_states[request_id].found, 'dns_records': len(recon.results.get('dns_records', []))})
        recon.service_discovery()
        update_state(request_id, message='Service discovery complete', progress=40.0, found={**recon_states[request_id].found, 'services': len(recon.results.get('services', []))})
        # Use only main.py (DomainRecon) for all recon and web crawling logic
        recon.web_crawl(crawl_level='smart', wordlist_path='../config/wordlists/common_directories.txt')
        crawl_results = recon.results.get('web_crawl', {})
        update_state(
            request_id,
            message='Web crawling complete',
            progress=80.0,
            found={**recon_states[request_id].found,
                   'web_fingerprinting': len(crawl_results.get('fingerprinting', {})),
                   'directories': len(crawl_results.get('directory_bruteforce', [])),
                   'api_endpoints': sum(len(v) for v in crawl_results.get('api_discovery', {}).values())}
        )
        recon.cloud_detection()
        update_state(request_id, message='Cloud detection complete', progress=90.0, found={**recon_states[request_id].found, 'cloud_services': len(recon.results.get('cloud_services', []))})
        recon.save_final_report()
        update_state(request_id, state='completed', message='Recon complete', progress=100.0, result=recon.results)
    except Exception as e:
        update_state(request_id, state='error', message=str(e), progress=100.0)

# Endpoint to start a recon process
@app.get("/api/data")
def start_recon(domain: str, gemini_key: Optional[str] = None):
    # Always generate a new request_id and state, never reuse
    while True:
        request_id = str(uuid.uuid4())
        if request_id not in recon_states:
            break
    recon_states[request_id] = ReconState(
        request_id=request_id,
        domain=domain,
        state='pending',
        message='Recon request received',
        progress=0.0,
        found={},
        result=None
    )
    save_states()
    thread = threading.Thread(target=run_recon_process, args=(request_id, domain, gemini_key))
    thread.start()
    return {"request_id": request_id}

# Endpoint to get status/state
@app.get("/api/status/{request_id}")
def get_status(request_id: str):
    state = recon_states.get(request_id)
    if not state:
        raise HTTPException(status_code=404, detail="Request ID not found")
    return state


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000) 