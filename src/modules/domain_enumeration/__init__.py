"""
Domain Enumeration Module

This module provides comprehensive domain enumeration capabilities through
multiple specialized sub-modules.

Sub-modules:
- passive: Passive enumeration using external sources
- active: Active enumeration with brute force and intelligent techniques  
- dns: DNS record enumeration and analysis
- web_fingerprinting: Web technology fingerprinting

Main Classes:
- DomainEnumeration: Main orchestrator class
- EnumerationConfig: Configuration management
"""

from .main import DomainEnumeration
from .config import EnumerationConfig
from .base import ResultsManager, SubdomainValidator, EnumerationErrorHandler

__all__ = [
    'DomainEnumeration',
    'EnumerationConfig', 
    'ResultsManager',
    'SubdomainValidator',
    'EnumerationErrorHandler'
]