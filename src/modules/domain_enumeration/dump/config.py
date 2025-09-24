#!/usr/bin/env python3
"""
Domain Enumeration Configuration Module

This module contains configuration classes and settings for domain enumeration operations.
It provides sensible defaults while allowing customization for different use cases.

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


class EnumerationConfig:
    """
    Configuration management for enumeration parameters.
    
    This class encapsulates all configuration settings for domain enumeration
    operations, providing sensible defaults while allowing customization for
    different use cases and security requirements.
    
    Attributes:
        rate_limit (int): Maximum requests per second (default: 10)
        timeout (int): Request timeout in seconds 
        retry_attempts (int): Number of retry attempts for failed requests (default: 3)
        doh_fallback (bool): Enable DNS-over-HTTPS fallback (default: True)
        cdn_bypass (bool): Enable CDN bypass techniques (default: True)
        thread_count (int): Number of concurrent threads (default: 10)
        rate_limiting_enabled (bool): Enable/disable rate limiting (default: True)
    """
    
    def __init__(self):
        """Initialize configuration with secure default values."""
        logger.info("Initializing EnumerationConfig with default values")
        
        # Rate limiting configuration
        self.rate_limit = 10  # requests per second - conservative default
        self.timeout = DEFAULT_TIMEOUT  # request timeout from constants
        self.retry_attempts = 3  # number of retry attempts for failed requests
        
        # Advanced features
        self.doh_fallback = True  # enable DNS-over-HTTPS fallback
        self.cdn_bypass = True  # enable CDN bypass techniques
        
        # Performance settings
        self.thread_count = 10  # concurrent threads for enumeration
        self.rate_limiting_enabled = True  # enable rate limiting by default
        
        logger.debug(f"EnumerationConfig initialized: rate_limit={self.rate_limit}, "
                    f"timeout={self.timeout}, threads={self.thread_count}")