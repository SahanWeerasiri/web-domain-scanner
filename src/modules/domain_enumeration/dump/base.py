#!/usr/bin/env python3
"""
Base utilities and common classes for domain enumeration.

This module contains shared utilities, rate limiting, and common functionality
used across all domain enumeration sub-modules.

Author: Web Domain Scanner Project
License: See LICENSE file in project root
"""

import time
import logging
import socket
import random
from typing import Set, List, Dict
try:
    import dns.resolver
except ImportError:
    print("Warning: dnspython package not installed. DNS functionality will be limited.")
    dns = None    
# Configure module-level logging first
logger = logging.getLogger(__name__)

# Configure module-level logging
logger = logging.getLogger(__name__)


class RateLimiter:
    """Token bucket rate limiter implementation"""
    
    def __init__(self, rate: int):
        self.rate = rate
        self.tokens = rate
        self.last_update = time.time()
    
    def acquire(self):
        while self.tokens < 1:
            self._add_tokens()
            time.sleep(0.1)
        self.tokens -= 1
    
    def _add_tokens(self):
        now = time.time()
        elapsed = now - self.last_update
        new_tokens = elapsed * self.rate
        self.tokens = min(self.rate, self.tokens + new_tokens)
        self.last_update = now


class EnumerationErrorHandler:
    """Centralized error handling for enumeration methods"""
    
    def __init__(self):
        self.errors = {}
    
    def handle_error(self, method: str, error: Exception) -> None:
        """Handle and log enumeration errors"""
        error_msg = f"Error in {method}: {str(error)}"
        
        # Log based on error type
        if isinstance(error, socket.timeout) or "timeout" in str(error).lower():
            logger.warning(f"Timeout in {method}: {error}")
        elif isinstance(error, ConnectionError) or "connection" in str(error).lower():
            logger.warning(f"Connection error in {method}: {error}")
        elif dns and isinstance(error, dns.resolver.NXDOMAIN):
            logger.debug(f"Domain not found in {method}: {error}")
        elif dns and isinstance(error, dns.resolver.NoAnswer):
            logger.debug(f"No answer in {method}: {error}")
        else:
            logger.error(error_msg)
            
        # Store error for analysis
        if method not in self.errors:
            self.errors[method] = []
        self.errors[method].append(str(error))
        
        # Implement specific error recovery strategies
        if "rate limit" in str(error).lower():
            logger.warning("Rate limit detected, implementing backoff")
            time.sleep(random.randint(5, 15))
        elif "quota" in str(error).lower():
            logger.warning("API quota exceeded, pausing operations")
            time.sleep(60)
    
    def get_errors(self) -> Dict:
        """Get all stored errors"""
        return self.errors


class SubdomainValidator:
    """Utility class for validating and verifying subdomains"""
    
    @staticmethod
    def is_valid_subdomain(subdomain: str, target_domain: str) -> bool:
        """Check if a subdomain is valid for the target domain"""
        if not subdomain or not isinstance(subdomain, str):
            return False
        
        # Basic validation
        if not subdomain.endswith(target_domain):
            return False
        
        # Check for valid characters
        allowed_chars = set('abcdefghijklmnopqrstuvwxyz0123456789.-')
        if not all(c.lower() in allowed_chars for c in subdomain):
            return False
        
        return True
    
    @staticmethod
    def extract_subdomain_from_url(url: str, target_domain: str) -> str:
        """Extract subdomain from URL"""
        try:
            # Remove protocol
            if '://' in url:
                url = url.split('://', 1)[1]
            
            # Remove path
            if '/' in url:
                url = url.split('/', 1)[0]
            
            # Remove port
            if ':' in url:
                url = url.split(':', 1)[0]
            
            # Check if it's a subdomain of target domain
            if url.endswith(target_domain) and url != target_domain:
                return url
            
        except Exception as e:
            logger.debug(f"Error extracting subdomain from {url}: {e}")
        
        return None
    
    @staticmethod
    def verify_subdomain_dns(subdomain: str) -> bool:
        """Verify if subdomain resolves via DNS"""
        try:
            socket.gethostbyname(subdomain)
            return True
        except socket.gaierror:
            return False
        except Exception as e:
            logger.debug(f"Error verifying {subdomain}: {e}")
            return False


class ResultsManager:
    """Manages and correlates results from different enumeration methods"""
    
    def __init__(self):
        self.results = {
            'subdomains': {},
            'dns_records': {},
            'passive_data': {},
            'active_discovery': {},
            'web_technologies': {},
            'errors': {}
        }
    
    def add_passive_results(self, data: Dict) -> None:
        """Add passive enumeration results"""
        self.results['passive_data'].update(data)
    
    def add_active_results(self, data: Dict) -> None:
        """Add active enumeration results"""
        self.results['active_discovery'].update(data)
    
    def add_dns_results(self, data: Dict) -> None:
        """Add DNS enumeration results"""
        self.results['dns_records'].update(data)
    
    def add_web_tech_results(self, data: Dict) -> None:
        """Add web technology results"""
        self.results['web_technologies'].update(data)
    
    def add_errors(self, errors: Dict) -> None:
        """Add error information"""
        self.results['errors'].update(errors)
    
    def get_all_results(self) -> Dict:
        """Get all results"""
        return self.results
    
    def extract_all_subdomains(self, target_domain: str) -> Set[str]:
        """Extract all unique subdomains from all sources"""
        all_subdomains = set()
        
        # Extract from passive data
        passive_data = self.results.get('passive_data', {})
        for source, data in passive_data.items():
            if isinstance(data, dict):
                for key, value in data.items():
                    if key == 'subdomains' and isinstance(value, list):
                        all_subdomains.update(value)
                    elif isinstance(value, dict) and 'subdomains' in value:
                        if isinstance(value['subdomains'], list):
                            all_subdomains.update(value['subdomains'])
        
        # Extract from active discovery
        active_data = self.results.get('active_discovery', {})
        for method, subdomains in active_data.items():
            if isinstance(subdomains, list):
                all_subdomains.update(subdomains)
        
        # Extract from DNS records
        dns_data = self.results.get('dns_records', {})
        for record_type, records in dns_data.items():
            if isinstance(records, list):
                for record in records:
                    if isinstance(record, str) and target_domain in record:
                        all_subdomains.add(record)
        
        # Filter valid subdomains
        valid_subdomains = set()
        for subdomain in all_subdomains:
            if SubdomainValidator.is_valid_subdomain(subdomain, target_domain):
                valid_subdomains.add(subdomain)
        
        return valid_subdomains