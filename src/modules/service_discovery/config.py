#!/usr/bin/env python3
"""
Service Discovery Configuration Module

This module contains configuration classes and settings for service discovery operations.
It provides sensible defaults while allowing customization for different scanning modes and security requirements.

Author: Web Domain Scanner Project
License: See LICENSE file in project root
"""

import logging
import sys
import os

# Add src directory to Python path for module imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from common.constants import DEFAULT_TIMEOUT

# Configure module-level logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


class ServiceDiscoveryConfig:
    """
    Configuration management for service discovery parameters.
    
    This class encapsulates all configuration settings for service discovery
    operations, providing sensible defaults while allowing customization for
    different scanning modes and security requirements.
    
    Attributes:
        scan_timeout (float): Connection timeout for port scanning in seconds (default: 3.0)
        max_workers (int): Maximum number of concurrent workers (default: 20)
        rate_limit (int): Maximum requests per second (default: 50)
        retry_attempts (int): Number of retry attempts for failed connections (default: 2)
        banner_timeout (float): Timeout for banner grabbing in seconds (default: 2.0)
        scan_mode (str): Default scanning mode ('quick', 'smart', 'deep') (default: 'quick')
        enable_external_tools (bool): Enable external tools like nmap/rustscan (default: True)
        rustscan_timeout (int): Timeout for rustscan in seconds (default: 300)
        nmap_timeout (int): Timeout for nmap in seconds (default: 600)
        thread_safety (bool): Enable thread-safe operations (default: True)
    """
    
    def __init__(self):
        """Initialize configuration with secure default values."""
        logger.info("Initializing ServiceDiscoveryConfig with default values")
        
        # Basic scanning configuration
        self.scan_timeout = 3.0  # connection timeout for port scanning
        self.max_workers = 20  # concurrent workers for scanning
        self.rate_limit = 50  # requests per second - moderate default
        self.retry_attempts = 2  # number of retry attempts for failed connections
        
        # Banner grabbing configuration
        self.banner_timeout = 2.0  # timeout for banner grabbing
        self.banner_max_bytes = 1024  # maximum bytes to read for banner
        
        # Scanning mode configuration
        self.scan_mode = 'quick'  # default scanning mode
        self.quick_scan_ports = 100  # number of common ports for quick scan
        self.smart_scan_extensions = 200  # additional ports for smart scan
        self.deep_scan_range = 65535  # port range for deep scan
        
        # External tools configuration
        self.enable_external_tools = True  # enable nmap/rustscan
        self.rustscan_timeout = 300  # rustscan timeout in seconds (5 minutes)
        self.nmap_timeout = 600  # nmap timeout in seconds (10 minutes)
        self.prefer_rustscan = True  # prefer rustscan over nmap if available
        
        # Performance and safety settings
        self.thread_safety = True  # enable thread-safe operations
        self.memory_limit_mb = 512  # memory limit for operations in MB
        self.output_buffer_size = 8192  # buffer size for output processing
        
        # Advanced scanning options
        self.enable_stealth_mode = False  # enable stealth scanning techniques
        self.randomize_port_order = True  # randomize port scanning order
        self.adaptive_timeout = True  # adapt timeout based on network conditions
        
        logger.debug(f"ServiceDiscoveryConfig initialized: scan_timeout={self.scan_timeout}, "
                    f"max_workers={self.max_workers}, rate_limit={self.rate_limit}")
    
    def get_scan_config(self, scan_mode: str = None) -> dict:
        """
        Get configuration optimized for specific scan mode.
        
        Args:
            scan_mode (str): Scanning mode ('quick', 'smart', 'deep')
            
        Returns:
            dict: Configuration dictionary optimized for the scan mode
        """
        mode = scan_mode or self.scan_mode
        
        if mode == 'quick':
            return {
                'timeout': self.scan_timeout,
                'max_workers': min(self.max_workers, 10),
                'rate_limit': self.rate_limit,
                'port_range': self.quick_scan_ports,
                'enable_banner_grab': True,
                'enable_service_detection': False
            }
        elif mode == 'smart':
            return {
                'timeout': self.scan_timeout * 1.5,
                'max_workers': self.max_workers,
                'rate_limit': self.rate_limit,
                'port_range': self.quick_scan_ports + self.smart_scan_extensions,
                'enable_banner_grab': True,
                'enable_service_detection': True,
                'enable_fuzzing': True
            }
        elif mode == 'deep':
            return {
                'timeout': self.scan_timeout * 2,
                'max_workers': min(self.max_workers, 30),
                'rate_limit': self.rate_limit * 2,
                'port_range': self.deep_scan_range,
                'enable_banner_grab': True,
                'enable_service_detection': True,
                'enable_external_tools': self.enable_external_tools,
                'enable_fuzzing': True,
                'enable_advanced_detection': True
            }
        else:
            logger.warning(f"Unknown scan mode '{mode}', using default quick scan config")
            return self.get_scan_config('quick')
    
    def update_config(self, **kwargs):
        """
        Update configuration parameters.
        
        Args:
            **kwargs: Configuration parameters to update
        """
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)
                logger.debug(f"Updated config parameter: {key} = {value}")
            else:
                logger.warning(f"Unknown configuration parameter: {key}")
    
    def validate_config(self) -> bool:
        """
        Validate configuration parameters.
        
        Returns:
            bool: True if configuration is valid, False otherwise
        """
        try:
            # Validate timeout values
            if self.scan_timeout <= 0 or self.banner_timeout <= 0:
                logger.error("Timeout values must be positive")
                return False
            
            # Validate worker count
            if self.max_workers <= 0 or self.max_workers > 100:
                logger.error("max_workers must be between 1 and 100")
                return False
            
            # Validate rate limit
            if self.rate_limit <= 0:
                logger.error("rate_limit must be positive")
                return False
            
            # Validate scan mode
            valid_modes = ['quick', 'smart', 'deep']
            if self.scan_mode not in valid_modes:
                logger.error(f"scan_mode must be one of: {valid_modes}")
                return False
            
            # Validate port ranges
            if (self.quick_scan_ports <= 0 or 
                self.smart_scan_extensions < 0 or 
                self.deep_scan_range <= 0 or self.deep_scan_range > 65535):
                logger.error("Invalid port range configuration")
                return False
            
            logger.info("Configuration validation passed")
            return True
            
        except Exception as e:
            logger.error(f"Configuration validation failed: {e}")
            return False
    
    def __str__(self) -> str:
        """String representation of configuration."""
        return (f"ServiceDiscoveryConfig(scan_timeout={self.scan_timeout}, "
                f"max_workers={self.max_workers}, scan_mode='{self.scan_mode}', "
                f"enable_external_tools={self.enable_external_tools})")
    
    def to_dict(self) -> dict:
        """Convert configuration to dictionary."""
        return {
            'scan_timeout': self.scan_timeout,
            'max_workers': self.max_workers,
            'rate_limit': self.rate_limit,
            'retry_attempts': self.retry_attempts,
            'banner_timeout': self.banner_timeout,
            'banner_max_bytes': self.banner_max_bytes,
            'scan_mode': self.scan_mode,
            'quick_scan_ports': self.quick_scan_ports,
            'smart_scan_extensions': self.smart_scan_extensions,
            'deep_scan_range': self.deep_scan_range,
            'enable_external_tools': self.enable_external_tools,
            'rustscan_timeout': self.rustscan_timeout,
            'nmap_timeout': self.nmap_timeout,
            'prefer_rustscan': self.prefer_rustscan,
            'thread_safety': self.thread_safety,
            'memory_limit_mb': self.memory_limit_mb,
            'output_buffer_size': self.output_buffer_size,
            'enable_stealth_mode': self.enable_stealth_mode,
            'randomize_port_order': self.randomize_port_order,
            'adaptive_timeout': self.adaptive_timeout
        }