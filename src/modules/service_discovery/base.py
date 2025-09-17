#!/usr/bin/env python3
"""
Base utilities and common classes for service discovery.

This module contains shared utilities, rate limiting, error handling, and common functionality
used across all service discovery sub-modules.

Author: Web Domain Scanner Project
License: See LICENSE file in project root
"""

import time
import logging
import socket
import random
import threading
from typing import Set, List, Dict, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configure module-level logging
logger = logging.getLogger(__name__)


class ServiceDiscoveryRateLimiter:
    """
    Thread-safe token bucket rate limiter implementation for service discovery.
    """
    
    def __init__(self, rate: int):
        """
        Initialize rate limiter.
        
        Args:
            rate (int): Maximum requests per second
        """
        self.rate = rate
        self.tokens = rate
        self.last_update = time.time()
        self.lock = threading.Lock()
    
    def acquire(self):
        """Acquire a token for making a request."""
        with self.lock:
            while self.tokens < 1:
                self._add_tokens()
                if self.tokens < 1:
                    time.sleep(0.1)
            self.tokens -= 1
    
    def _add_tokens(self):
        """Add tokens based on elapsed time."""
        now = time.time()
        elapsed = now - self.last_update
        new_tokens = elapsed * self.rate
        self.tokens = min(self.rate, self.tokens + new_tokens)
        self.last_update = now


class ServiceDiscoveryErrorHandler:
    """
    Centralized error handling for service discovery operations.
    """
    
    def __init__(self):
        self.errors = {}
        self.error_counts = {}
        self.lock = threading.Lock()
    
    def handle_error(self, method: str, error: Exception, context: str = None) -> None:
        """
        Handle and log service discovery errors.
        
        Args:
            method (str): The method where the error occurred
            error (Exception): The exception that occurred
            context (str): Additional context about the error
        """
        error_msg = f"Error in {method}: {str(error)}"
        if context:
            error_msg += f" (Context: {context})"
        
        # Log based on error type
        if isinstance(error, socket.timeout) or "timeout" in str(error).lower():
            logger.debug(f"Timeout in {method}: {error}")
        elif isinstance(error, ConnectionError) or "connection" in str(error).lower():
            logger.debug(f"Connection error in {method}: {error}")
        elif isinstance(error, socket.gaierror):
            logger.debug(f"DNS resolution error in {method}: {error}")
        elif "permission denied" in str(error).lower():
            logger.warning(f"Permission denied in {method}: {error}")
        else:
            logger.error(error_msg)
        
        # Store error for analysis
        with self.lock:
            if method not in self.errors:
                self.errors[method] = []
                self.error_counts[method] = 0
            
            self.errors[method].append({
                'error': str(error),
                'context': context,
                'timestamp': time.time()
            })
            self.error_counts[method] += 1
            
            # Implement error recovery strategies
            if "rate limit" in str(error).lower():
                logger.warning("Rate limit detected, implementing backoff")
                time.sleep(random.randint(2, 8))
            elif self.error_counts[method] > 10:
                logger.warning(f"High error rate in {method}, implementing extended backoff")
                time.sleep(random.randint(5, 15))
    
    def get_errors(self) -> Dict:
        """Get all stored errors."""
        with self.lock:
            return dict(self.errors)
    
    def get_error_summary(self) -> Dict:
        """Get error summary statistics."""
        with self.lock:
            return {
                'total_errors': sum(self.error_counts.values()),
                'error_counts_by_method': dict(self.error_counts),
                'methods_with_errors': list(self.error_counts.keys())
            }


class PortValidator:
    """
    Utility class for validating and processing port information.
    """
    
    @staticmethod
    def is_valid_port(port: int) -> bool:
        """
        Check if a port number is valid.
        
        Args:
            port (int): Port number to validate
            
        Returns:
            bool: True if port is valid, False otherwise
        """
        return isinstance(port, int) and 1 <= port <= 65535
    
    @staticmethod
    def normalize_port_list(ports) -> List[int]:
        """
        Normalize port list to ensure all ports are valid integers.
        
        Args:
            ports: Port list (can be strings, integers, or mixed)
            
        Returns:
            List[int]: List of valid port numbers
        """
        normalized_ports = []
        
        if not ports:
            return normalized_ports
        
        for port in ports:
            try:
                port_int = int(port)
                if PortValidator.is_valid_port(port_int):
                    normalized_ports.append(port_int)
            except (ValueError, TypeError):
                logger.debug(f"Invalid port value: {port}")
                continue
        
        return sorted(list(set(normalized_ports)))  # Remove duplicates and sort
    
    @staticmethod
    def generate_port_range(start: int, end: int) -> List[int]:
        """
        Generate a list of ports within a specified range.
        
        Args:
            start (int): Starting port number
            end (int): Ending port number
            
        Returns:
            List[int]: List of port numbers in the range
        """
        if not (PortValidator.is_valid_port(start) and PortValidator.is_valid_port(end)):
            return []
        
        if start > end:
            start, end = end, start
        
        return list(range(start, end + 1))


class NetworkUtils:
    """
    Network utility functions for service discovery.
    """
    
    @staticmethod
    def resolve_domain(domain: str) -> Optional[str]:
        """
        Resolve domain name to IP address.
        
        Args:
            domain (str): Domain name to resolve
            
        Returns:
            Optional[str]: IP address if resolution successful, None otherwise
        """
        try:
            ip_address = socket.gethostbyname(domain)
            logger.debug(f"Resolved {domain} to {ip_address}")
            return ip_address
        except socket.gaierror as e:
            logger.error(f"Failed to resolve domain {domain}: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error resolving {domain}: {e}")
            return None
    
    @staticmethod
    def check_port(ip: str, port: int, timeout: float = 3.0) -> bool:
        """
        Check if a port is open on the specified IP address.
        
        Args:
            ip (str): IP address to check
            port (int): Port number to check
            timeout (float): Connection timeout in seconds
            
        Returns:
            bool: True if port is open, False otherwise
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((ip, port))
                return result == 0
        except Exception as e:
            logger.debug(f"Error checking port {port} on {ip}: {e}")
            return False
    
    @staticmethod
    def get_banner(ip: str, port: int, timeout: float = 2.0, max_bytes: int = 1024) -> str:
        """
        Attempt to grab banner from an open port.
        
        Args:
            ip (str): IP address
            port (int): Port number
            timeout (float): Connection timeout in seconds
            max_bytes (int): Maximum bytes to read
            
        Returns:
            str: Banner text or "No banner" if none available
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                sock.connect((ip, port))
                
                # Try to receive banner
                banner = sock.recv(max_bytes).decode('utf-8', errors='ignore').strip()
                
                if banner:
                    # Clean up banner text
                    banner = ' '.join(banner.split())  # Normalize whitespace
                    return banner[:200]  # Limit banner length
                else:
                    return "No banner"
                    
        except socket.timeout:
            return "No banner (timeout)"
        except Exception as e:
            logger.debug(f"Error getting banner from {ip}:{port}: {e}")
            return "No banner"


class ServiceResultsManager:
    """
    Manages and organizes results from service discovery operations.
    """
    
    def __init__(self):
        self.results = {
            'scan_info': {},
            'open_ports': {},
            'scan_statistics': {},
            'errors': {}
        }
        self.lock = threading.Lock()
    
    def add_scan_info(self, info: Dict) -> None:
        """Add general scan information."""
        with self.lock:
            self.results['scan_info'].update(info)
    
    def add_open_port(self, port: int, service_info: Dict) -> None:
        """
        Add information about an open port.
        
        Args:
            port (int): Port number
            service_info (Dict): Service information for the port
        """
        with self.lock:
            self.results['open_ports'][port] = service_info
    
    def add_scan_statistics(self, stats: Dict) -> None:
        """Add scan statistics."""
        with self.lock:
            self.results['scan_statistics'].update(stats)
    
    def add_errors(self, errors: Dict) -> None:
        """Add error information."""
        with self.lock:
            self.results['errors'].update(errors)
    
    def get_all_results(self) -> Dict:
        """Get all results."""
        with self.lock:
            return dict(self.results)
    
    def get_open_ports(self) -> Dict:
        """Get only open ports information."""
        with self.lock:
            return dict(self.results['open_ports'])
    
    def get_port_count(self) -> int:
        """Get count of open ports."""
        with self.lock:
            return len(self.results['open_ports'])
    
    def get_services_summary(self) -> Dict:
        """Get summary of detected services."""
        with self.lock:
            services = {}
            for port, info in self.results['open_ports'].items():
                service = info.get('service', 'Unknown')
                if service not in services:
                    services[service] = []
                services[service].append(port)
            return services


class PortRange:
    """
    Utility class for handling port ranges and common port lists.
    """
    
    # Common service ports
    COMMON_PORTS = {
        20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'TELNET', 25: 'SMTP',
        53: 'DNS', 69: 'TFTP', 80: 'HTTP', 110: 'POP3', 119: 'NNTP',
        135: 'RPC', 139: 'NetBIOS', 143: 'IMAP', 161: 'SNMP', 194: 'IRC',
        389: 'LDAP', 443: 'HTTPS', 445: 'SMB', 465: 'SMTPS', 514: 'Syslog',
        587: 'SMTP', 636: 'LDAPS', 993: 'IMAPS', 995: 'POP3S',
        1433: 'MSSQL', 1521: 'Oracle', 1723: 'PPTP', 3306: 'MySQL',
        3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis',
        8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 27017: 'MongoDB'
    }
    
    # Top 100 most common ports
    TOP_100_PORTS = [
        21, 22, 23, 25, 42, 53, 69, 80, 110, 113, 135, 139, 143, 161, 389,
        443, 445, 465, 514, 587, 636, 993, 995, 1433, 1521, 1723, 3306,
        3389, 5432, 5900, 6379, 8080, 8443, 27017, 20, 119, 194, 8000,
        8888, 9000, 9080, 9999, 2222, 2200, 22222, 990, 989, 3307, 5985,
        5986, 50070, 8161, 1080, 1194, 1701, 1812, 1813, 2049, 2121,
        2375, 2376, 2483, 2484, 3000, 3001, 3128, 4444, 4662, 4672,
        4899, 5000, 5001, 5060, 5061, 5222, 5269, 5353, 5355, 5432,
        5672, 5984, 6000, 6001, 6379, 6667, 7000, 7001, 7777, 8000,
        8008, 8009, 8080, 8081, 8086, 8087, 8088, 8089, 8443, 8888,
        9000, 9001, 9080, 9090, 9200, 9300, 9999, 10000, 50000
    ]
    
    # High-value ports often targeted in security assessments
    HIGH_VALUE_PORTS = [
        22, 80, 443, 445, 3389, 1433, 3306, 5432, 6379, 27017,
        5900, 5985, 5986, 8080, 8443, 9200, 9300, 50070
    ]
    
    @staticmethod
    def get_common_ports() -> Dict[int, str]:
        """Get dictionary of common ports and their services."""
        return PortRange.COMMON_PORTS.copy()
    
    @staticmethod
    def get_top_ports(count: int = 100) -> List[int]:
        """
        Get list of top N most common ports.
        
        Args:
            count (int): Number of ports to return
            
        Returns:
            List[int]: List of port numbers
        """
        return PortRange.TOP_100_PORTS[:min(count, len(PortRange.TOP_100_PORTS))]
    
    @staticmethod
    def get_service_related_ports(known_services: List[str]) -> List[int]:
        """
        Get ports related to known services.
        
        Args:
            known_services (List[str]): List of known service names
            
        Returns:
            List[int]: List of related port numbers
        """
        related_ports = []
        
        for service in known_services:
            service_lower = service.lower()
            
            if 'http' in service_lower or 'web' in service_lower:
                related_ports.extend([8000, 8080, 8443, 8888, 9000, 9080, 9443])
            elif 'ssh' in service_lower:
                related_ports.extend([2222, 2200, 22222])
            elif 'ftp' in service_lower:
                related_ports.extend([20, 990, 989])
            elif 'database' in service_lower or 'db' in service_lower:
                related_ports.extend([3306, 3307, 5432, 1433, 1521, 27017])
        
        return list(set(related_ports))


class ScanMode:
    """
    Constants and utilities for different scanning modes.
    """
    
    QUICK = 'quick'
    SMART = 'smart'
    DEEP = 'deep'
    
    VALID_MODES = [QUICK, SMART, DEEP]
    
    @staticmethod
    def is_valid_mode(mode: str) -> bool:
        """Check if scan mode is valid."""
        return mode in ScanMode.VALID_MODES
    
    @staticmethod
    def get_mode_description(mode: str) -> str:
        """Get description for scan mode."""
        descriptions = {
            ScanMode.QUICK: "Quick scan of common ports only",
            ScanMode.SMART: "Smart scan with intelligent port selection and fuzzing",
            ScanMode.DEEP: "Deep scan using external tools and comprehensive port range"
        }
        return descriptions.get(mode, "Unknown scan mode")