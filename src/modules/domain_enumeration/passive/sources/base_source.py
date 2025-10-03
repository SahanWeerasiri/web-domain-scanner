#!/usr/bin/env python3
"""
Base classes and interfaces for passive enumeration sources
"""

import logging
import time
from abc import ABC, abstractmethod
from typing import Dict, List, Set, Any, Optional
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)


class PassiveSourceBase(ABC):
    """Abstract base class for all passive enumeration sources"""
    
    def __init__(self, domain: str, config: Any = None, session: requests.Session = None):
        self.domain = domain.lower().strip()
        self.config = config
        self.session = session or self._create_default_session()
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
    
    def _create_default_session(self) -> requests.Session:
        """Create a default HTTP session with retry strategy"""
        session = requests.Session()
        
        # Configure headers
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json,text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        })
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        return session
    
    @abstractmethod
    def enumerate(self) -> Dict[str, Any]:
        """
        Perform passive enumeration and return results
        
        Returns:
            Dict containing:
            - subdomains: List of discovered subdomains
            - source: Source name
            - metadata: Additional source-specific data
            - error: Error message if failed
        """
        pass
    
    @abstractmethod
    def get_source_name(self) -> str:
        """Return the name of this source"""
        pass
    
    def is_available(self) -> bool:
        """Check if this source is available/configured"""
        return True
    
    def validate_subdomain(self, subdomain: str) -> bool:
        """Validate if a subdomain is valid for the target domain"""
        try:
            # Import here to avoid circular imports
            from modules.domain_enumeration.base import SubdomainValidator
            return SubdomainValidator.is_valid_subdomain(subdomain, self.domain)
        except ImportError:
            # Fallback validation
            return (subdomain.endswith(f".{self.domain}") or subdomain == self.domain) and \
                   self._is_valid_domain_format(subdomain)
    
    def _is_valid_domain_format(self, domain: str) -> bool:
        """Basic domain format validation"""
        import re
        pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$'
        return bool(re.match(pattern, domain)) and len(domain) <= 253
    
    def _make_request(self, url: str, **kwargs) -> requests.Response:
        """Make an HTTP request with error handling"""
        try:
            timeout = kwargs.pop('timeout', getattr(self.config, 'timeout', 10))
            response = self.session.get(url, timeout=timeout, **kwargs)
            response.raise_for_status()
            return response
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Request failed for {url}: {e}")
            raise
    
    def _apply_rate_limit(self):
        """Apply rate limiting if configured"""
        if hasattr(self.config, 'request_delay') and self.config.request_delay > 0:
            time.sleep(self.config.request_delay)


class CertificateTransparencySource(PassiveSourceBase):
    """Base class for Certificate Transparency sources"""
    
    @abstractmethod
    def query_ct_source(self) -> Dict[str, Any]:
        """Query the specific CT source"""
        pass
    
    def enumerate(self) -> Dict[str, Any]:
        """Standard enumerate implementation for CT sources"""
        try:
            self._apply_rate_limit()
            return self.query_ct_source()
        except Exception as e:
            self.logger.error(f"CT source {self.get_source_name()} failed: {e}")
            return {
                'subdomains': [],
                'source': self.get_source_name(),
                'error': str(e)
            }


class SSLCertificateSource(PassiveSourceBase):
    """Base class for SSL Certificate sources"""
    
    def __init__(self, domain: str, config: Any = None, session: requests.Session = None):
        super().__init__(domain, config, session)
        self.api_key = self._get_api_key()
    
    @abstractmethod
    def _get_api_key(self) -> Optional[str]:
        """Get API key for this source"""
        pass
    
    @abstractmethod
    def query_ssl_source(self) -> Dict[str, Any]:
        """Query the specific SSL source"""
        pass
    
    def is_available(self) -> bool:
        """Check if API key is configured"""
        return self.api_key is not None
    
    def enumerate(self) -> Dict[str, Any]:
        """Standard enumerate implementation for SSL sources"""
        if not self.is_available():
            return {
                'subdomains': [],
                'source': self.get_source_name(),
                'error': 'API key not configured'
            }
        
        try:
            self._apply_rate_limit()
            return self.query_ssl_source()
        except Exception as e:
            self.logger.error(f"SSL source {self.get_source_name()} failed: {e}")
            return {
                'subdomains': [],
                'source': self.get_source_name(),
                'error': str(e)
            }


class ThreatIntelligenceSource(PassiveSourceBase):
    """Base class for Threat Intelligence sources"""
    
    def __init__(self, domain: str, config: Any = None, session: requests.Session = None):
        super().__init__(domain, config, session)
        self.api_key = self._get_api_key()
    
    @abstractmethod
    def _get_api_key(self) -> Optional[str]:
        """Get API key for this source"""
        pass
    
    @abstractmethod
    def query_threat_intel_source(self) -> Dict[str, Any]:
        """Query the specific threat intelligence source"""
        pass
    
    def is_available(self) -> bool:
        """Check if API key is configured or if it's a free source"""
        return True  # Some threat intel sources are free
    
    def enumerate(self) -> Dict[str, Any]:
        """Standard enumerate implementation for threat intel sources"""
        try:
            self._apply_rate_limit()
            return self.query_threat_intel_source()
        except Exception as e:
            self.logger.error(f"Threat intel source {self.get_source_name()} failed: {e}")
            return {
                'subdomains': [],
                'source': self.get_source_name(),
                'error': str(e)
            }


class WebArchiveSource(PassiveSourceBase):
    """Base class for Web Archive sources"""
    
    @abstractmethod
    def query_archive_source(self) -> Dict[str, Any]:
        """Query the specific web archive source"""
        pass
    
    def enumerate(self) -> Dict[str, Any]:
        """Standard enumerate implementation for web archive sources"""
        try:
            self._apply_rate_limit()
            return self.query_archive_source()
        except Exception as e:
            self.logger.error(f"Web archive source {self.get_source_name()} failed: {e}")
            return {
                'subdomains': [],
                'source': self.get_source_name(),
                'error': str(e)
            }


class PassiveSourceManager:
    """Manager for handling multiple passive enumeration sources"""
    
    def __init__(self, domain: str, config: Any = None):
        self.domain = domain
        self.config = config
        self.sources = {}
        self.session = self._create_shared_session()
    
    def _create_shared_session(self) -> requests.Session:
        """Create a shared HTTP session for all sources"""
        session = requests.Session()
        
        # Configure session based on config
        if hasattr(self.config, 'max_concurrent_requests'):
            pool_size = self.config.max_concurrent_requests
        else:
            pool_size = 5
        
        # Configure headers
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json,text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        })
        
        # Configure retry strategy and connection pooling
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=pool_size,
            pool_maxsize=pool_size * 2
        )
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        return session
    
    def register_source(self, source_class: type, source_name: str = None):
        """Register a passive enumeration source"""
        source_name = source_name or source_class.__name__
        source_instance = source_class(self.domain, self.config, self.session)
        self.sources[source_name] = source_instance
    
    def get_available_sources(self) -> List[str]:
        """Get list of available sources"""
        return [name for name, source in self.sources.items() if source.is_available()]
    
    def enumerate_source(self, source_name: str) -> Dict[str, Any]:
        """Enumerate using a specific source"""
        if source_name not in self.sources:
            return {
                'subdomains': [],
                'source': source_name,
                'error': f'Source {source_name} not registered'
            }
        
        source = self.sources[source_name]
        if not source.is_available():
            return {
                'subdomains': [],
                'source': source_name,
                'error': f'Source {source_name} not available (missing API key or configuration)'
            }
        
        return source.enumerate()
    
    def enumerate_all_sources(self, source_names: List[str] = None) -> Dict[str, Any]:
        """Enumerate using multiple sources"""
        if source_names is None:
            source_names = self.get_available_sources()
        
        results = {}
        for source_name in source_names:
            results[source_name] = self.enumerate_source(source_name)
        
        return results