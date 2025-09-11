"""
Shared networking utilities
"""
import requests
import socket
import time
import logging
from urllib.parse import urlparse
from typing import Optional, Dict, Any

from .constants import DEFAULT_TIMEOUT, DEFAULT_USER_AGENT, SSL_VERIFY_EXCEPTIONS


class NetworkUtils:
    """Shared networking utilities for all modules"""
    
    @staticmethod
    def create_session(user_agent: str = None) -> requests.Session:
        """Create a configured requests session"""
        session = requests.Session()
        session.headers.update({
            'User-Agent': user_agent or DEFAULT_USER_AGENT
        })
        return session
    
    @staticmethod
    def should_verify_ssl(url: str) -> bool:
        """Determine if SSL should be verified for a given URL"""
        return not any(domain in url for domain in SSL_VERIFY_EXCEPTIONS)
    
    @staticmethod
    def safe_request(url: str, method: str = 'GET', timeout: int = DEFAULT_TIMEOUT, 
                    verify_ssl: bool = None, **kwargs) -> Optional[requests.Response]:
        """Make a safe HTTP request with proper error handling"""
        try:
            if verify_ssl is None:
                verify_ssl = NetworkUtils.should_verify_ssl(url)
            
            session = kwargs.pop('session', None) or requests.Session()
            session.headers.update({'User-Agent': DEFAULT_USER_AGENT})
            
            response = session.request(
                method=method,
                url=url,
                timeout=timeout,
                verify=verify_ssl,
                **kwargs
            )
            return response
            
        except requests.exceptions.SSLError:
            # Retry without SSL verification
            try:
                return session.request(
                    method=method,
                    url=url,
                    timeout=timeout,
                    verify=False,
                    **kwargs
                )
            except Exception as e:
                logging.warning(f"Failed to make request to {url}: {e}")
                return None
                
        except Exception as e:
            logging.warning(f"Request failed for {url}: {e}")
            return None
    
    @staticmethod
    def check_port(host: str, port: int, timeout: int = DEFAULT_TIMEOUT) -> bool:
        """Check if a port is open on a host"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((host, port))
                return result == 0
        except Exception:
            return False
    
    @staticmethod
    def get_banner(host: str, port: int, timeout: int = DEFAULT_TIMEOUT) -> str:
        """Attempt to grab banner from a service"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                sock.connect((host, port))
                
                # Send a basic HTTP request for web services
                if port in [80, 443, 8080, 8443]:
                    sock.send(b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n")
                
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                return banner.strip()
        except Exception:
            return "No banner"
    
    @staticmethod
    def resolve_domain(domain: str) -> Optional[str]:
        """Resolve domain to IP address"""
        try:
            return socket.gethostbyname(domain)
        except socket.gaierror:
            return None


class RateLimiter:
    """Token bucket rate limiter implementation"""
    
    def __init__(self, rate: int):
        self.rate = rate
        self.tokens = rate
        self.last_update = time.time()
    
    def acquire(self):
        """Acquire a token (blocks if necessary)"""
        self._add_tokens()
        while self.tokens < 1:
            time.sleep(0.1)
            self._add_tokens()
        self.tokens -= 1
    
    def _add_tokens(self):
        """Add tokens based on elapsed time"""
        now = time.time()
        elapsed = now - self.last_update
        self.tokens = min(self.rate, self.tokens + elapsed * self.rate)
        self.last_update = now
