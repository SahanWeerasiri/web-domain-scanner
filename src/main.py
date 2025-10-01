#!/usr/bin/env python3
"""
Flask Web Server for Unified Web Domain Scanner
===============================================

This Flask server provides REST API endpoints for running domain reconnaissance jobs:
- POST /api/scan - Submit a new scan job
- GET /api/status/<job_id> - Check job status and get results

Author: Web Domain Scanner Project
License: See LICENSE file in project root
"""

import os
import sys
import json
import uuid
import time
import threading
import logging
from datetime import datetime
from typing import Dict, Any, Optional
from flask import Flask, request, jsonify
from flask_cors import CORS
import traceback

# Add modules path for imports
current_dir = os.path.dirname(os.path.abspath(__file__))
modules_dir = os.path.join(current_dir, 'modules')
sys.path.append(modules_dir)

try:
    from modules.main import execute_unified_scan_with_params
    SCANNER_AVAILABLE = True
except ImportError as e:
    print(f"Error: Could not import unified scanner: {e}")
    SCANNER_AVAILABLE = False

# Flask app initialization
app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('flask_server.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Global job storage (in production, use Redis or database)
jobs = {}
job_lock = threading.Lock()


class JobStatus:
    """Job status constants"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class ScanJob:
    """Represents a scan job with status tracking"""
    
    def __init__(self, job_id: str, parameters: Dict[str, Any]):
        self.job_id = job_id
        self.parameters = parameters
        self.status = JobStatus.PENDING
        self.created_at = datetime.now()
        self.started_at = None
        self.completed_at = None
        self.current_module = None
        self.progress = {}
        self.results = None
        self.error = None
        self.verbose_logs = []
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert job to dictionary for JSON response"""
        return {
            'job_id': self.job_id,
            'status': self.status,
            'created_at': self.created_at.isoformat(),
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'current_module': self.current_module,
            'progress': self.progress,
            'parameters': self.parameters,
            'results': self.results,
            'error': self.error,
            'verbose_logs': self.verbose_logs[-10:] if self.verbose_logs else []  # Last 10 logs
        }


def validate_scan_parameters(data: Dict[str, Any]) -> tuple[bool, str]:
    """Validate scan parameters"""
    
    # Required parameter
    if 'domain' not in data:
        return False, "Missing required parameter: domain"
    
    domain = data['domain']
    if not domain or not isinstance(domain, str):
        return False, "Domain must be a non-empty string"
    
    # Validate optional parameters
    valid_modules = ['domain_enumeration', 'service_discovery', 'web_analysis']
    if 'enabled_modules' in data:
        if not isinstance(data['enabled_modules'], list):
            return False, "enabled_modules must be a list"
        for module in data['enabled_modules']:
            if module not in valid_modules:
                return False, f"Invalid module: {module}. Valid modules: {valid_modules}"
    
    valid_domain_modules = ['passive', 'active', 'dns', 'fingerprinting']
    if 'domain_enum_modules' in data:
        if not isinstance(data['domain_enum_modules'], list):
            return False, "domain_enum_modules must be a list"
        for module in data['domain_enum_modules']:
            if module not in valid_domain_modules:
                return False, f"Invalid domain module: {module}. Valid modules: {valid_domain_modules}"
    
    valid_scan_modes = ['quick', 'smart', 'deep']
    if 'scan_mode' in data:
        if data['scan_mode'] not in valid_scan_modes:
            return False, f"Invalid scan_mode: {data['scan_mode']}. Valid modes: {valid_scan_modes}"
    
    # Validate numeric parameters
    numeric_params = {
        'passive_timeout': int,
        'active_threads': int,
        'dns_timeout': int,
        'fingerprint_timeout': int
    }
    
    for param, param_type in numeric_params.items():
        if param in data:
            try:
                data[param] = param_type(data[param])
                if data[param] <= 0:
                    return False, f"{param} must be a positive integer"
            except (ValueError, TypeError):
                return False, f"{param} must be a valid {param_type.__name__}"
    
    # Validate boolean parameters
    boolean_params = ['verbose', 'save_results', 'no_ai', 'bypass_cdn', 'deep_crawl', 'setup_logging']
    for param in boolean_params:
        if param in data:
            if not isinstance(data[param], bool):
                return False, f"{param} must be a boolean"
    
    return True, "Parameters are valid"


def execute_scan_job(job: ScanJob):
    """Execute scan job in background thread with parallel module execution"""
    
    with job_lock:
        job.status = JobStatus.RUNNING
        job.started_at = datetime.now()
        job.verbose_logs.append(f"[{job.started_at.strftime('%H:%M:%S')}] Starting scan for domain: {job.parameters['domain']}")
    
    try:
        # Prepare parameters with defaults
        scan_params = {
            'target_domain': job.parameters['domain'],
            'enabled_modules': job.parameters.get('enabled_modules', ['domain_enumeration', 'service_discovery', 'web_analysis']),
            'verbose': job.parameters.get('verbose', True),
            'output_dir': job.parameters.get('output_dir', 'results'),
            'save_results': job.parameters.get('save_results', True),
            # Domain enumeration params
            'domain_enum_modules': job.parameters.get('domain_enum_modules', ['passive', 'active', 'dns', 'fingerprinting']),
            'passive_timeout': job.parameters.get('passive_timeout', 10),
            'active_threads': job.parameters.get('active_threads', 10),
            'dns_timeout': job.parameters.get('dns_timeout', 5),
            'fingerprint_timeout': job.parameters.get('fingerprint_timeout', 30),
            'wordlist': job.parameters.get('wordlist'),
            'no_ai': job.parameters.get('no_ai', False),
            # Service discovery params
            'scan_mode': job.parameters.get('scan_mode', 'smart'),
            'ports': job.parameters.get('ports'),
            'service_output_format': job.parameters.get('service_output_format', 'json'),
            # Web analysis params
            'bypass_cdn': job.parameters.get('bypass_cdn', True),
            'deep_crawl': job.parameters.get('deep_crawl', False),
            'setup_logging': job.parameters.get('setup_logging', False)  # Disable to avoid logging conflicts
        }
        
        # Get enabled modules and initialize progress
        enabled_modules = scan_params['enabled_modules']
        total_modules = len(enabled_modules)
        
        # Initialize progress
        with job_lock:
            job.progress = {
                'current_module': 'initializing',
                'completed_modules': 0,
                'total_modules': total_modules,
                'percentage': 0
            }
        
        logger.info(f"Job {job.job_id}: Starting parallel scan with {total_modules} modules")
        
        # Initialize results structure
        results = {
            'target_domain': scan_params['target_domain'],
            'scan_timestamp': datetime.now().isoformat(),
            'enabled_modules': enabled_modules,
            'modules': {},
            'summary': {},
            'execution_time': 0
        }
        
        # Thread-safe storage for module results
        module_results = {}
        module_errors = {}
        completed_count = {'value': 0}  # Use dict for mutable reference
        module_lock = threading.Lock()
        
        # Helper function to update progress (thread-safe)
        def update_progress_safe(module_name: str, status: str = "running"):
            with job_lock:
                if status == "starting":
                    job.verbose_logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] Starting {module_name}...")
                elif status == "completed":
                    job.verbose_logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] Completed {module_name}")
                elif status == "failed":
                    job.verbose_logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] Failed {module_name}")
                
                # Update current running modules
                with module_lock:
                    running_modules = [m for m in enabled_modules if m in module_results and module_results[m] is None]
                    job.current_module = ", ".join(running_modules) if running_modules else "finalizing"
                    
                    job.progress = {
                        'current_module': job.current_module,
                        'completed_modules': completed_count['value'],
                        'total_modules': total_modules,
                        'percentage': int((completed_count['value'] / total_modules) * 100)
                    }
        
        # Module execution function
        def execute_module(module_name: str):
            """Execute a single module in its own thread"""
            update_progress_safe(module_name, "starting")
            
            try:
                if module_name == 'domain_enumeration':
                    # Import and execute domain enumeration
                    from modules.domain_enumeration.main import execute_domain_enumeration, DomainEnumerationConfig
                    
                    # Create domain enumeration configuration
                    domain_config = DomainEnumerationConfig()
                    domain_config.domain = scan_params['target_domain']
                    domain_config.verbose = scan_params['verbose']
                    domain_config.enabled_modules = scan_params['domain_enum_modules']
                    
                    # Configure sub-modules
                    domain_config.passive_config['timeout'] = scan_params['passive_timeout']
                    domain_config.active_config['max_threads'] = scan_params['active_threads']
                    domain_config.dns_config['timeout'] = scan_params['dns_timeout']
                    domain_config.fingerprinting_config['timeout'] = scan_params['fingerprint_timeout']
                    if scan_params['wordlist']:
                        domain_config.active_config['wordlist_file'] = scan_params['wordlist']
                    domain_config.active_config['disable_ai'] = scan_params['no_ai']
                    
                    module_result = execute_domain_enumeration(domain_config)
                    
                elif module_name == 'service_discovery':
                    # Import and execute service discovery
                    from modules.service_discovery.main import execute_service_discovery
                    
                    module_result = execute_service_discovery(
                        scan_mode=scan_params['scan_mode'],
                        target=scan_params['target_domain'],
                        ports=scan_params['ports'],
                        output_format=scan_params['service_output_format'],
                        verbose=scan_params['verbose']
                    )
                    
                elif module_name == 'web_analysis':
                    # Import and execute web analysis
                    from modules.web_analysis.main import execute_web_analysis
                    
                    module_result = execute_web_analysis(
                        domain=scan_params['target_domain'],
                        bypass_cdn=scan_params['bypass_cdn'],
                        deep_crawl=scan_params['deep_crawl'],
                        output_dir=scan_params['output_dir'],
                        save_to_file=scan_params['save_results'],
                        verbose=scan_params['verbose'],
                        setup_logging=scan_params['setup_logging']
                    )
                
                # Store successful result
                with module_lock:
                    module_results[module_name] = module_result
                    completed_count['value'] += 1
                
                update_progress_safe(module_name, "completed")
                logger.info(f"Job {job.job_id}: Completed {module_name} ({completed_count['value']}/{total_modules})")
                
            except Exception as module_error:
                logger.error(f"Job {job.job_id}: Module {module_name} failed: {str(module_error)}")
                
                # Store error result
                with module_lock:
                    module_errors[module_name] = str(module_error)
                    module_results[module_name] = {
                        'success': False,
                        'error': str(module_error)
                    }
                    completed_count['value'] += 1
                
                update_progress_safe(module_name, "failed")
        
        # Start all modules in parallel threads
        module_threads = []
        for module_name in enabled_modules:
            thread = threading.Thread(target=execute_module, args=(module_name,))
            thread.daemon = True
            thread.start()
            module_threads.append((module_name, thread))
            
            # Initialize result placeholder
            with module_lock:
                module_results[module_name] = None
        
        # Wait for all modules to complete
        for module_name, thread in module_threads:
            thread.join()  # Wait for this module to finish
            logger.info(f"Job {job.job_id}: Thread for {module_name} completed")
        
        # Compile final results
        results['modules'] = {k: v for k, v in module_results.items() if v is not None}
        
        # Compile summary (similar to unified scanner)
        from modules.main import compile_unified_summary
        results['summary'] = compile_unified_summary(results)
        results['execution_time'] = (datetime.now() - job.started_at).total_seconds()
        
        # Job completed successfully
        with job_lock:
            job.status = JobStatus.COMPLETED
            job.completed_at = datetime.now()
            job.results = results
            job.current_module = None
            job.progress = {
                'current_module': 'completed',
                'completed_modules': total_modules,
                'total_modules': total_modules,
                'percentage': 100
            }
            job.verbose_logs.append(f"[{job.completed_at.strftime('%H:%M:%S')}] Scan completed successfully")
        
        logger.info(f"Job {job.job_id}: Completed successfully in {results['execution_time']:.2f} seconds")
        
    except Exception as e:
        error_msg = f"Scan failed: {str(e)}"
        logger.error(f"Job {job.job_id}: {error_msg}")
        logger.error(f"Job {job.job_id}: Traceback: {traceback.format_exc()}")
        
        with job_lock:
            job.status = JobStatus.FAILED
            job.completed_at = datetime.now()
            job.error = error_msg
            job.verbose_logs.append(f"[{job.completed_at.strftime('%H:%M:%S')}] ERROR: {error_msg}")


@app.route('/api/scan', methods=['POST'])
def submit_scan():
    """
    Submit a new scan job
    
    Expected JSON body:
    {
        "domain": "example.com",  # Required
        "enabled_modules": ["domain_enumeration", "service_discovery"],  # Optional
        "verbose": true,  # Optional
        "scan_mode": "smart",  # Optional
        "bypass_cdn": true,  # Optional
        ... other parameters
    }
    
    Returns:
    {
        "job_id": "uuid",
        "status": "pending",
        "message": "Job submitted successfully"
    }
    """
    
    if not SCANNER_AVAILABLE:
        return jsonify({
            'error': 'Scanner module not available',
            'message': 'The unified scanner could not be imported'
        }), 500
    
    try:
        # Get JSON data
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 400
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Empty JSON body'}), 400
        
        # Validate parameters
        is_valid, error_message = validate_scan_parameters(data)
        if not is_valid:
            return jsonify({'error': error_message}), 400
        
        # Generate unique job ID
        job_id = str(uuid.uuid4())
        
        # Create job
        job = ScanJob(job_id, data)
        
        # Store job
        with job_lock:
            jobs[job_id] = job
        
        # Start job in background thread
        thread = threading.Thread(target=execute_scan_job, args=(job,))
        thread.daemon = True
        thread.start()
        
        logger.info(f"Job {job_id}: Submitted with domain {data['domain']}")
        
        return jsonify({
            'job_id': job_id,
            'status': job.status,
            'message': 'Job submitted successfully',
            'created_at': job.created_at.isoformat(),
            'parameters': {
                'domain': data['domain'],
                'enabled_modules': data.get('enabled_modules', ['domain_enumeration', 'service_discovery', 'web_analysis']),
                'scan_mode': data.get('scan_mode', 'smart')
            }
        }), 202
        
    except Exception as e:
        logger.error(f"Error submitting scan job: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({
            'error': 'Internal server error',
            'message': str(e)
        }), 500


@app.route('/api/status/<job_id>', methods=['GET'])
def check_status(job_id: str):
    """
    Check job status and get results
    
    Returns:
    {
        "job_id": "uuid",
        "status": "running|completed|failed|pending",
        "current_module": "domain_enumeration",  # If running
        "progress": {...},  # Progress information
        "results": {...},  # If completed
        "error": "...",  # If failed
        "verbose_logs": [...]  # Recent log entries
    }
    """
    
    try:
        # Check if job exists
        with job_lock:
            if job_id not in jobs:
                return jsonify({
                    'error': 'Job not found',
                    'message': f'Job ID {job_id} does not exist'
                }), 404
            
            job = jobs[job_id]
            job_data = job.to_dict()
        
        # Include additional metadata
        response = {
            **job_data,
            'message': {
                JobStatus.PENDING: 'Job is waiting to start',
                JobStatus.RUNNING: f'Job is running - {job.current_module or "initializing"}',
                JobStatus.COMPLETED: 'Job completed successfully',
                JobStatus.FAILED: 'Job failed'
            }.get(job.status, 'Unknown status')
        }
        
        # Add execution time if available
        if job.started_at:
            if job.completed_at:
                execution_time = (job.completed_at - job.started_at).total_seconds()
                response['execution_time_seconds'] = execution_time
            else:
                running_time = (datetime.now() - job.started_at).total_seconds()
                response['running_time_seconds'] = running_time
        
        logger.info(f"Job {job_id}: Status checked - {job.status}")
        return jsonify(response), 200
        
    except Exception as e:
        logger.error(f"Error checking job status {job_id}: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({
            'error': 'Internal server error',
            'message': str(e)
        }), 500


@app.route('/api/jobs', methods=['GET'])
def list_jobs():
    """
    List all jobs (for debugging/monitoring)
    
    Returns:
    {
        "jobs": [
            {
                "job_id": "uuid",
                "status": "completed",
                "domain": "example.com",
                "created_at": "2024-01-01T12:00:00"
            }
        ],
        "total_jobs": 5
    }
    """
    
    try:
        with job_lock:
            job_list = []
            for job_id, job in jobs.items():
                job_list.append({
                    'job_id': job_id,
                    'status': job.status,
                    'domain': job.parameters.get('domain'),
                    'created_at': job.created_at.isoformat(),
                    'started_at': job.started_at.isoformat() if job.started_at else None,
                    'completed_at': job.completed_at.isoformat() if job.completed_at else None
                })
        
        # Sort by creation time (newest first)
        job_list.sort(key=lambda x: x['created_at'], reverse=True)
        
        return jsonify({
            'jobs': job_list,
            'total_jobs': len(job_list)
        }), 200
        
    except Exception as e:
        logger.error(f"Error listing jobs: {e}")
        return jsonify({
            'error': 'Internal server error',
            'message': str(e)
        }), 500


@app.route('/api/health', methods=['GET'])
def health_check():
    """
    Health check endpoint
    
    Returns:
    {
        "status": "healthy",
        "scanner_available": true,
        "timestamp": "2024-01-01T12:00:00Z"
    }
    """
    
    return jsonify({
        'status': 'healthy',
        'scanner_available': SCANNER_AVAILABLE,
        'timestamp': datetime.now().isoformat(),
        'version': '1.0.0'
    }), 200


@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({
        'error': 'Not found',
        'message': 'The requested endpoint does not exist'
    }), 404


@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    return jsonify({
        'error': 'Internal server error',
        'message': 'An unexpected error occurred'
    }), 500


def cleanup_old_jobs():
    """Clean up old completed jobs (run periodically)"""
    current_time = datetime.now()
    jobs_to_remove = []
    
    with job_lock:
        for job_id, job in jobs.items():
            # Remove jobs older than 24 hours
            if job.completed_at and (current_time - job.completed_at).total_seconds() > 86400:
                jobs_to_remove.append(job_id)
        
        for job_id in jobs_to_remove:
            del jobs[job_id]
            logger.info(f"Cleaned up old job: {job_id}")


if __name__ == '__main__':
    print("="*60)
    print("UNIFIED WEB DOMAIN SCANNER - FLASK SERVER")
    print("="*60)
    print(f"Scanner Available: {SCANNER_AVAILABLE}")
    print(f"Server Starting: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*60)
    print("\nAPI Endpoints:")
    print("  POST /api/scan          - Submit new scan job")
    print("  GET  /api/status/<id>   - Check job status")
    print("  GET  /api/jobs          - List all jobs")
    print("  GET  /api/health        - Health check")
    print("\nExample Usage:")
    print('  curl -X POST http://localhost:5000/api/scan \\')
    print('       -H "Content-Type: application/json" \\')
    print('       -d \'{"domain": "example.com", "verbose": true}\'')
    print("="*60)
    
    # Start periodic cleanup (every hour)
    cleanup_thread = threading.Thread(target=lambda: [time.sleep(3600) or cleanup_old_jobs() for _ in iter(int, 1)])
    cleanup_thread.daemon = True
    cleanup_thread.start()
    
    # Start Flask server
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=True,
        threaded=True
    )
