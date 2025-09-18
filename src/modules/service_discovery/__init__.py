#!/usr/bin/env python3
"""
Service Discovery Module

This package provides comprehensive service discovery capabilities including:
- Port scanning with multiple modes (quick, smart, deep)
- Service identification and fingerprinting
- Banner grabbing and analysis
- External tools integration (nmap, rustscan, masscan)
- Security analysis and reporting

Author: Web Domain Scanner Project
License: See LICENSE file in project root
"""

__version__ = "1.0.0"
__author__ = "Web Domain Scanner Project"

# Import main classes for easy access
from .main import ServiceDiscovery
from .config import ServiceDiscoveryConfig
from .base import (
    ServiceDiscoveryErrorHandler,
    NetworkUtils,
    ServiceResultsManager,
    PortRange,
    ScanMode,
    PortValidator
)
from .port_scanning.port_scanning import PortScanner
from .service_identification.service_identification import ServiceIdentifier, BannerGrabber
from .external_tools.external_tools import ExternalToolsManager, NmapScriptEngine

# Define what gets imported with "from service_discovery import *"
__all__ = [
    'ServiceDiscovery',
    'ServiceDiscoveryConfig',
    'PortScanner',
    'ServiceIdentifier',
    'BannerGrabber',
    'ExternalToolsManager',
    'NmapScriptEngine',
    'ServiceDiscoveryErrorHandler',
    'NetworkUtils',
    'ServiceResultsManager',
    'PortRange',
    'ScanMode',
    'PortValidator'
]

# Package metadata
__title__ = "service_discovery"
__description__ = "Comprehensive service discovery and port scanning module"
__url__ = "https://github.com/SahanWeerasiri/web-domain-scanner"
__license__ = "MIT"

# Version info tuple
VERSION_INFO = tuple(map(int, __version__.split('.')))

def get_version():
    """Get the package version string."""
    return __version__

def get_version_info():
    """Get the package version as a tuple."""
    return VERSION_INFO