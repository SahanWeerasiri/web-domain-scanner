#!/usr/bin/env python3
"""
Configurable Passive Domain Enumeration Module

This module provides passive subdomain discovery using a modular source system.
Refactored to use individual source modules for better maintainability and testing.
"""

import logging
import time
import requests
import os
import sys
from typing import Dict, List, Set, Optional, Any
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Add parent directories to path for imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..')))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
try:
    from modules.domain_enumeration.config import EnumerationConfig
    from modules.domain_enumeration.base import EnumerationErrorHandler, SubdomainValidator
except ImportError:
    from config import EnumerationConfig
    from base import EnumerationErrorHandler, SubdomainValidator

# Import modular source system
from .sources.base_source import PassiveSourceManager
from .sources.ct_sources import CrtShSource, GoogleCTSource, CensysCTSource
from .sources.ssl_sources import (
    ShodanSSLSource, BinaryEdgeSSLSource, CensysSSLSource, 
    ZoomEyeSSLSource, RapidDNSSSLSource, SSLMateSource
)
from .sources.threat_intel_sources import (
    VirusTotalSource, ThreatCrowdSource, PassiveTotalSource,
    AlienVaultOTXSource, URLVoidSource, HybridAnalysisSource
)
from .sources.archive_sources import (
    WaybackMachineSource, CommonCrawlSource, ArchiveTodaySource,
    BingCacheSource, GoogleCacheSource, UKWebArchiveSource
)

logger = logging.getLogger(__name__)


class PassiveEnumerationConfig(EnumerationConfig):
    """Extended configuration for passive enumeration with method-specific parameters"""
    
    def __init__(self):
        super().__init__()
        
        # Source Categories Configuration
        self.enabled_source_categories = [
            'certificate_transparency',
            'ssl_certificates',
            'threat_intelligence', 
            'web_archives'
        ]
        
        # Individual Source Configuration
        self.enabled_ct_sources = ['crt_sh']  # Start with working source
        self.enabled_ssl_sources = []  # Disabled by default (require API keys)
        self.enabled_threat_intel_sources = ['threatcrowd']  # Free sources
        self.enabled_archive_sources = []  # Disabled by default (require implementation)
        
        # Certificate Transparency Configuration
        self.ct_max_pages = 5
        self.ct_page_delay = 2
        self.ct_timeout = 15
        
        # SSL Certificate Configuration  
        self.ssl_timeout = 15
        self.ssl_max_results = 1000
        
        # Threat Intelligence Configuration
        self.threat_intel_timeout = 10
        
        # Web Archive Configuration
        self.archive_timeout = 20
        self.archive_max_pages = 10
        
        # API Keys (from environment variables)
        self.api_keys = {
            'virustotal': os.getenv('VIRUSTOTAL_API_KEY'),
            'censys': os.getenv('CENSYS_API_KEY'),
            'shodan': os.getenv('SHODAN_API_KEY'),
            'binaryedge': os.getenv('BINARYEDGE_API_KEY'),
            'zoomeye': os.getenv('ZOOMEYE_API_KEY'),
            'sslmate': os.getenv('SSLMATE_API_KEY'),
            'threatcrowd': None,  # Free service
            'passivetotal': os.getenv('PASSIVETOTAL_API_KEY'),
            'alienvault': os.getenv('ALIENVAULT_API_KEY'),
            'urlvoid': os.getenv('URLVOID_API_KEY'),
            'hybrid_analysis': os.getenv('HYBRID_ANALYSIS_API_KEY')
        }
        
        # Performance Configuration
        self.max_concurrent_requests = 3
        self.request_delay = 1
        self.timeout = 15
        
        # DNS History Configuration
        self.dns_history_sources = ['whois_history', 'dnsdb', 'passive_dns']
        self.dns_history_days = 365
        self.dns_history_max_records = 500
        
        # Additional Sources Configuration
        self.additional_sources = [
            'dnsdumpster', 'rapiddns', 'sublist3r', 'threatminer'
        ]
        self.additional_timeout = 10
        
        # Performance Configuration
        self.max_concurrent_requests = 5
        self.request_delay = 0.5
        self.enable_caching = True
        self.cache_ttl = 3600  # 1 hour
        
        # Output Configuration
        self.verbose_output = False
        self.save_raw_data = False
        self.output_format = 'structured'


class ConfigurablePassiveEnumerator:
    """
    Enhanced passive enumerator using modular source system for better maintainability.
    """
    
    def __init__(self, domain: str, config: PassiveEnumerationConfig = None, **kwargs):
        """Initialize with modular source configuration"""
        self.domain = domain.lower().strip()
        self.config = config or PassiveEnumerationConfig()
        
        # Apply any keyword argument overrides
        self._apply_config_overrides(kwargs)
        
        self.error_handler = EnumerationErrorHandler()
        
        # Initialize modular source manager
        self.source_manager = PassiveSourceManager(self.domain, self.config)
        self._register_all_sources()
        
        logger.info(f"ConfigurablePassiveEnumerator initialized for domain: {self.domain}")
        self._log_configuration()
    
    def _apply_config_overrides(self, kwargs: Dict[str, Any]):
        """Apply configuration overrides from keyword arguments"""
        for key, value in kwargs.items():
            if hasattr(self.config, key):
                setattr(self.config, key, value)
                logger.debug(f"Overridden config.{key} = {value}")
    
    def _register_all_sources(self):
        """Register all available sources with the source manager"""
        
        # Register Certificate Transparency sources
        self.source_manager.register_source(CrtShSource, 'crt_sh')
        self.source_manager.register_source(GoogleCTSource, 'google_ct') 
        self.source_manager.register_source(CensysCTSource, 'censys_ct')
        
        # Register SSL Certificate sources
        self.source_manager.register_source(ShodanSSLSource, 'shodan_ssl')
        self.source_manager.register_source(BinaryEdgeSSLSource, 'binaryedge_ssl')
        self.source_manager.register_source(CensysSSLSource, 'censys_ssl')
        self.source_manager.register_source(ZoomEyeSSLSource, 'zoomeye_ssl')
        self.source_manager.register_source(RapidDNSSSLSource, 'rapiddns_ssl')
        self.source_manager.register_source(SSLMateSource, 'sslmate')
        
        # Register Threat Intelligence sources
        self.source_manager.register_source(VirusTotalSource, 'virustotal')
        self.source_manager.register_source(ThreatCrowdSource, 'threatcrowd')
        self.source_manager.register_source(PassiveTotalSource, 'passivetotal')
        self.source_manager.register_source(AlienVaultOTXSource, 'alienvault_otx')
        self.source_manager.register_source(URLVoidSource, 'urlvoid')
        self.source_manager.register_source(HybridAnalysisSource, 'hybrid_analysis')
        
        # Register Web Archive sources
        self.source_manager.register_source(WaybackMachineSource, 'wayback_machine')
        self.source_manager.register_source(CommonCrawlSource, 'commoncrawl')
        self.source_manager.register_source(ArchiveTodaySource, 'archive_today')
        self.source_manager.register_source(BingCacheSource, 'bing_cache')
        self.source_manager.register_source(GoogleCacheSource, 'google_cache')
        self.source_manager.register_source(UKWebArchiveSource, 'uk_web_archive')
    
    def _log_configuration(self):
        """Log the current configuration"""
        available_sources = self.source_manager.get_available_sources()
        logger.info("=== Passive Enumeration Configuration ===")
        logger.info(f"Domain: {self.domain}")
        logger.info(f"Enabled source categories: {', '.join(self.config.enabled_source_categories)}")
        logger.info(f"Available sources: {len(available_sources)}")
        logger.info(f"CT sources enabled: {', '.join(self.config.enabled_ct_sources)}")
        logger.info(f"Max concurrent requests: {self.config.max_concurrent_requests}")
        logger.info(f"Request delay: {self.config.request_delay}s")
        logger.info("==========================================")
    
    def run_comprehensive_enumeration(self) -> Dict[str, Any]:
        """
        Run comprehensive passive enumeration using modular sources.
        
        Returns:
            Dict containing all results, statistics, and metadata
        """
        start_time = time.time()
        
        results = {
            'domain': self.domain,
            'timestamp': time.time(),
            'configuration': self._get_config_summary(),
            'sources': {},
            'subdomains': set(),
            'statistics': {},
            'errors': {}
        }
        
        try:
            # Get enabled sources based on configuration
            enabled_sources = self._get_enabled_sources()
            
            if not enabled_sources:
                logger.warning("No sources enabled or available")
                return results
            
            logger.info(f"Running enumeration with {len(enabled_sources)} sources: {', '.join(enabled_sources)}")
            
            # Execute each enabled source
            for source_name in enabled_sources:
                source_start = time.time()
                try:
                    logger.debug(f"Executing source: {source_name}")
                    source_result = self.source_manager.enumerate_source(source_name)
                    results['sources'][source_name] = source_result
                    
                    source_duration = time.time() - source_start
                    subdomain_count = len(source_result.get('subdomains', []))
                    logger.info(f"{source_name}: found {subdomain_count} subdomains in {source_duration:.2f}s")
                    
                    # Apply rate limiting between sources
                    if self.config.request_delay > 0:
                        time.sleep(self.config.request_delay)
                    
                except Exception as e:
                    logger.error(f"Source {source_name} failed: {e}")
                    self.error_handler.handle_error(source_name, e)
                    results['sources'][source_name] = {'error': str(e), 'subdomains': []}
            
            # Extract and deduplicate all subdomains
            results['subdomains'] = self._extract_all_subdomains(results['sources'])
            
            # Compile statistics
            results['statistics'] = self._compile_statistics(results, start_time)
            results['errors'] = self.error_handler.get_errors()
            
            logger.info("=== Passive Enumeration Completed ===")
            
        except Exception as e:
            logger.error(f"Comprehensive enumeration failed: {e}")
            self.error_handler.handle_error("comprehensive_enumeration", e)
            results['errors']['comprehensive_enumeration'] = [str(e)]
        
        return results
    
    def _get_enabled_sources(self) -> List[str]:
        """Get list of enabled sources based on configuration"""
        enabled_sources = []
        
        # Certificate Transparency sources
        if 'certificate_transparency' in self.config.enabled_source_categories:
            enabled_sources.extend(self.config.enabled_ct_sources)
        
        # SSL Certificate sources
        if 'ssl_certificates' in self.config.enabled_source_categories:
            enabled_sources.extend(self.config.enabled_ssl_sources)
        
        # Threat Intelligence sources
        if 'threat_intelligence' in self.config.enabled_source_categories:
            enabled_sources.extend(self.config.enabled_threat_intel_sources)
        
        # Web Archive sources
        if 'web_archives' in self.config.enabled_source_categories:
            enabled_sources.extend(self.config.enabled_archive_sources)
        
        # Filter to only available sources
        available_sources = self.source_manager.get_available_sources()
        enabled_sources = [s for s in enabled_sources if s in available_sources]
        
        return enabled_sources
    
    def _get_config_summary(self) -> Dict[str, Any]:
        """Get a summary of the current configuration"""
        return {
            'enabled_source_categories': self.config.enabled_source_categories,
            'enabled_ct_sources': self.config.enabled_ct_sources,
            'enabled_ssl_sources': self.config.enabled_ssl_sources,
            'enabled_threat_intel_sources': self.config.enabled_threat_intel_sources,
            'enabled_archive_sources': self.config.enabled_archive_sources,
            'max_concurrent_requests': self.config.max_concurrent_requests,
            'request_delay': self.config.request_delay,
            'timeout': self.config.timeout
        }
    
    def _extract_all_subdomains(self, sources_data: Dict[str, Any]) -> List[str]:
        """Extract and deduplicate all subdomains from source results"""
        all_subdomains = set()
        
        for source_name, source_data in sources_data.items():
            if isinstance(source_data, dict) and 'subdomains' in source_data:
                subdomains = source_data['subdomains']
                if isinstance(subdomains, list):
                    all_subdomains.update(subdomains)
                elif isinstance(subdomains, set):
                    all_subdomains.update(subdomains)
        
        # Validate and clean subdomains
        validated_subdomains = []
        for subdomain in all_subdomains:
            if SubdomainValidator.is_valid_subdomain(subdomain, self.domain):
                validated_subdomains.append(subdomain)
        
        return sorted(validated_subdomains)
    
    def _compile_statistics(self, results: Dict[str, Any], start_time: float) -> Dict[str, Any]:
        """Compile comprehensive statistics from enumeration results"""
        total_duration = time.time() - start_time
        
        statistics = {
            'total_duration': round(total_duration, 2),
            'total_subdomains': len(results.get('subdomains', [])),
            'sources_executed': len(results.get('sources', {})),
            'sources_successful': 0,
            'sources_failed': 0,
            'source_breakdown': {}
        }
        
        # Analyze source results
        for source_name, source_data in results.get('sources', {}).items():
            if isinstance(source_data, dict):
                subdomain_count = len(source_data.get('subdomains', []))
                has_error = 'error' in source_data
                
                if has_error:
                    statistics['sources_failed'] += 1
                else:
                    statistics['sources_successful'] += 1
                
                statistics['source_breakdown'][source_name] = {
                    'subdomains_found': subdomain_count,
                    'has_error': has_error,
                    'error': source_data.get('error', None)
                }
        
        return statistics


# Legacy function for backward compatibility
def passive_enumeration(domain: str, config: PassiveEnumerationConfig = None, **kwargs) -> Dict[str, Any]:
    """
    Legacy function for backward compatibility.
    Use ConfigurablePassiveEnumerator directly for new implementations.
    """
    enumerator = ConfigurablePassiveEnumerator(domain, config, **kwargs)
    return enumerator.run_comprehensive_enumeration()


# Main execution function
def main():
    """Main function for command line execution"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Modular Passive Domain Enumeration")
    parser.add_argument("domain", help="Target domain to enumerate")
    parser.add_argument("--verbose", action='store_true', help="Enable verbose output")
    
    args = parser.parse_args()
    
    # Configure logging
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    # Create enumerator and run
    enumerator = ConfigurablePassiveEnumerator(args.domain)
    results = enumerator.run_comprehensive_enumeration()
    
    # Display results
    print(f"\n=== Passive Enumeration Results for {results['domain']} ===")
    print(f"Execution time: {results['statistics']['total_duration']:.2f} seconds")
    print(f"Total subdomains found: {len(results.get('subdomains', []))}")
    
    subdomains = results.get('subdomains', [])
    if subdomains:
        print(f"\n=== Discovered Subdomains ({len(subdomains)}) ===")
        for subdomain in sorted(subdomains):
            print(f"  - {subdomain}")
    
    if args.verbose:
        print(f"\n=== Source Details ===")
        for source_name, source_data in results.get('sources', {}).items():
            subdomain_count = len(source_data.get('subdomains', []))
            has_error = 'error' in source_data
            print(f"{source_name}: {subdomain_count} subdomains" + 
                  (f" (Error: {source_data['error']})" if has_error else ""))


if __name__ == "__main__":
    main()