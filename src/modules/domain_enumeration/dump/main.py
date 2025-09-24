#!/usr/bin/env python3
"""
Main Domain Enumeration Orchestrator

This module coordinates all domain enumeration sub-modules and provides a unified
interface for comprehensive domain reconnaissance. It combines passive enumeration,
active enumeration, DNS analysis, and web fingerprinting using enhanced execute functions.

Author: Web Domain Scanner Project
License: See LICENSE file in project root
"""

import logging
import time
import sys
import os
import argparse
import json
from pathlib import Path
from typing import Dict, List, Set, Optional, TYPE_CHECKING

# Add parent directories to path for imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '.')))

# Import configuration classes and execute functions from all sub-modules
try:
    # Try relative imports first (when used as module)
    from .config import EnumerationConfig
    from .base import ResultsManager, SubdomainValidator, EnumerationErrorHandler
    from .passive.passive_enumeration import PassiveEnumerationConfig, execute_passive_enumeration
    from .active.active_enumeration import EnhancedEnumerationConfig, execute_active_enumeration
    from .dns_enumeration_module.dns_enumeration import DNSEnumerationConfig, execute_dns_enumeration
    from .web_fingerprinting.web_fingerprinting import WebFingerprintingConfig, execute_fingerprinting
except ImportError:
    # Fallback to absolute imports (when run directly or when package context differs)
    try:
        from modules.domain_enumeration.config import EnumerationConfig
        from modules.domain_enumeration.base import ResultsManager, SubdomainValidator, EnumerationErrorHandler
        from modules.domain_enumeration.passive.passive_enumeration import PassiveEnumerationConfig, execute_passive_enumeration
        from modules.domain_enumeration.active.active_enumeration import EnhancedEnumerationConfig, execute_active_enumeration
        from modules.domain_enumeration.dns_enumeration_module.dns_enumeration import DNSEnumerationConfig, execute_dns_enumeration
        from modules.domain_enumeration.web_fingerprinting.web_fingerprinting import WebFingerprintingConfig, execute_fingerprinting
    except ImportError:
        # Last-resort: try direct imports for alternate execution contexts
        from config import EnumerationConfig
        from base import ResultsManager, SubdomainValidator, EnumerationErrorHandler
        from passive.passive_enumeration import PassiveEnumerationConfig, execute_passive_enumeration
        from active.active_enumeration import EnhancedEnumerationConfig, execute_active_enumeration
        from dns_enumeration_module.dns_enumeration import DNSEnumerationConfig, execute_dns_enumeration
        from web_fingerprinting.web_fingerprinting import WebFingerprintingConfig, execute_fingerprinting

# Import AI Integration module for enhanced enumeration
if TYPE_CHECKING:
    from ai_integration import AIIntegration

try:
    # Try different paths for AI integration
    try:
        sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
        from ai_integration import AIIntegration
    except ImportError:
        # Try alternative path
        sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../modules')))
        from ai_integration import AIIntegration
    AI_AVAILABLE = True
except ImportError:
    AI_AVAILABLE = False
    AIIntegration = None

logger = logging.getLogger(__name__)


class ComprehensiveEnumerationConfig:
    """
    Comprehensive configuration class that combines all sub-module configurations
    for unified domain enumeration operations.
    """
    
    def __init__(self):
        """Initialize with all sub-module configurations"""
        self.passive_config = PassiveEnumerationConfig()
        self.active_config = EnhancedEnumerationConfig()
        self.dns_config = DNSEnumerationConfig()
        self.web_config = WebFingerprintingConfig()
        
        # Global settings
        self.verbose = False
        self.output_format = 'detailed'  # detailed, summary, minimal
        self.save_results = True
        self.results_dir = 'results'
        
        # AI Integration settings
        self.enable_ai = AI_AVAILABLE
        self.ai_api_keys = {
            'gemini_api_key': os.getenv('GEMINI_API_KEY'),
            'openai_api_key': os.getenv('OPENAI_API_KEY'),
            'anthropic_api_key': os.getenv('ANTHROPIC_API_KEY')
        }


class DomainEnumeration:
    """
    Comprehensive domain enumeration orchestrator using enhanced execute functions.
    
    This class provides advanced subdomain discovery capabilities using multiple
    enumeration techniques including passive data collection, active probing,
    DNS enumeration, and web technology fingerprinting.
    
    Key Features:
    - Passive enumeration via Certificate Transparency logs
    - Active enumeration with intelligent wordlist generation  
    - DNS enumeration with multiple record types
    - Web technology fingerprinting
    - Rate limiting and error handling
    - Results correlation and validation
    - Configurable execution parameters
    
    Example:
        >>> config = ComprehensiveEnumerationConfig()
        >>> enumerator = DomainEnumeration("example.com", config)
        >>> results = enumerator.execute_comprehensive_enumeration()
    """
    
    def __init__(self, domain: str, config: Optional[ComprehensiveEnumerationConfig] = None):
        """
        Initialize DomainEnumeration instance with target domain and configuration.
        
        Args:
            domain (str): Target domain to enumerate (e.g., "example.com")
            config (ComprehensiveEnumerationConfig, optional): Configuration object.
                                                              If None, uses default configuration.
        
        Raises:
            ValueError: If domain is invalid.
        """
        # Validate domain input
        if not domain or not isinstance(domain, str):
            raise ValueError("Domain must be a non-empty string")
        
        self.domain = domain.lower().strip()
        logger.info(f"Initializing DomainEnumeration for domain: {self.domain}")
        
        # Handle config
        self.config = config or ComprehensiveEnumerationConfig()
        
        # Initialize AI integration if available and configured
        self.ai_integration = None
        if AI_AVAILABLE and self.config.enable_ai and any(self.config.ai_api_keys.values()):
            try:
                self.ai_integration = AIIntegration(**{k: v for k, v in self.config.ai_api_keys.items() if v})
                logger.info("AI integration initialized successfully")
            except Exception as e:
                logger.warning(f"Failed to initialize AI integration: {e}")
        
        # Initialize results manager
        self.results_manager = ResultsManager()
        self.error_handler = EnumerationErrorHandler()
        
        # Store enumeration results
        self.passive_results = {}
        self.active_results = {}
        self.dns_results = {}
        self.web_results = {}
        
        logger.info(f"DomainEnumeration initialized successfully for {self.domain}")
    
    def passive_enumeration(self) -> Dict:
        """
        Run passive enumeration using external sources with configured parameters.
        
        Returns:
            Dict: Passive enumeration results
        """
        logger.info("Starting passive enumeration")
        try:
            # Extract configuration parameters from passive config
            config = self.config.passive_config
            
            results = execute_passive_enumeration(
                domain=self.domain,
                sources=config.enabled_sources,
                ct_sources=config.ct_sources,
                concurrent_requests=config.max_concurrent_requests,
                request_delay=config.request_delay,
                timeout=config.ct_timeout,
                verbose=self.config.verbose
            )
            
            self.passive_results = results
            self.results_manager.add_passive_results(results)
            
            logger.info("Passive enumeration completed successfully")
            return results
        except Exception as e:
            logger.error(f"Passive enumeration failed: {e}")
            self.error_handler.handle_error("passive_enumeration", e)
            return {}
    
    def enhanced_active_enumeration(self, wordlist: Optional[List[str]] = None) -> Dict:
        """
        Run active enumeration with brute force and intelligent techniques using configured parameters.
        
        Args:
            wordlist: Custom wordlist for brute force. If None, uses default wordlists.
            
        Returns:
            Dict: Active enumeration results
        """
        logger.info("Starting active enumeration")
        try:
            # Extract configuration parameters from active config
            config = self.config.active_config
            
            results = execute_active_enumeration(
                domain=self.domain,
                threads=config.thread_count,
                rate_limit=config.rate_limit,
                timeout=config.bruteforce_timeout,
                bruteforce_retries=config.bruteforce_retries,
                permutation_depth=config.permutation_depth,
                dns_servers=config.cache_snoop_dns_servers,
                methods=config.enabled_methods,
                wordlist_file=None,  # Could be derived from wordlist parameter
                enable_ai=config.wordlist_ai_enabled and self.ai_integration is not None
            )
            
            self.active_results = results
            self.results_manager.add_active_results(results)
            
            logger.info("Active enumeration completed successfully")
            return results
        except Exception as e:
            logger.error(f"Active enumeration failed: {e}")
            self.error_handler.handle_error("active_enumeration", e)
            return {}
    
    def dns_enumeration(self) -> Dict:
        """
        Run DNS record enumeration and analysis with configured parameters.
        
        Returns:
            Dict: DNS enumeration results
        """
        logger.info("Starting DNS enumeration")
        try:
            # Extract configuration parameters from DNS config
            config = self.config.dns_config
            
            results = execute_dns_enumeration(
                domain=self.domain,
                dns_servers=config.dns_servers,
                timeout=config.query_timeout,
                retries=config.query_retries,
                record_types=config.record_types,
                include_parent_domain=config.include_parent_domain,
                perform_analysis=config.perform_infrastructure_analysis,
                query_additional_records=config.query_additional_records,
                verbose=self.config.verbose,
                txt_analysis_depth=config.txt_analysis_depth
            )
            
            self.dns_results = results
            self.results_manager.add_dns_results(results)
            
            logger.info("DNS enumeration completed successfully")
            return results
        except Exception as e:
            logger.error(f"DNS enumeration failed: {e}")
            self.error_handler.handle_error("dns_enumeration", e)
            return {}
    
    def web_fingerprinting(self, targets: Optional[List[str]] = None) -> Dict:
        """
        Run web technology fingerprinting with configured parameters.
        
        Args:
            targets: List of URLs to fingerprint. If None, uses default targets.
            
        Returns:
            Dict: Web fingerprinting results
        """
        logger.info("Starting web fingerprinting")
        try:
            # Extract configuration parameters from web config
            config = self.config.web_config
            
            results = execute_fingerprinting(
                domain=self.domain,
                targets=targets,
                include_http=config.include_http,
                include_www=config.include_www_variant,
                detection_methods=config.detection_methods,
                disable_wappalyzer=not config.enable_wappalyzer,
                disable_ai=not config.enable_ai_analysis,
                disable_security=not config.enable_security_analysis,
                timeout=config.request_timeout,
                concurrent=config.concurrent_requests,
                verbose=self.config.verbose,
                output_format=self.config.output_format
            )
            
            self.web_results = results
            self.results_manager.add_web_tech_results(results)
            
            logger.info("Web fingerprinting completed successfully")
            return results
        except Exception as e:
            logger.error(f"Web fingerprinting failed: {e}")
            self.error_handler.handle_error("web_fingerprinting", e)
            return {}
    
    def execute_comprehensive_enumeration(self, wordlist: Optional[List[str]] = None) -> Dict:
        """
        Execute comprehensive domain enumeration using all configured methods.
        
        Args:
            wordlist: Custom wordlist for active enumeration
            
        Returns:
            Dict: Comprehensive enumeration results from all methods
        """
        logger.info(f"Starting comprehensive domain enumeration for {self.domain}")
        start_time = time.time()
        
        comprehensive_results = {
            'domain': self.domain,
            'timestamp': start_time,
            'configuration': {
                'passive': {
                    'enabled_sources': self.config.passive_config.enabled_sources,
                    'ct_sources': self.config.passive_config.ct_sources
                },
                'active': {
                    'enabled_methods': self.config.active_config.enabled_methods,
                    'thread_count': self.config.active_config.thread_count,
                    'rate_limit': self.config.active_config.rate_limit
                },
                'dns': {
                    'record_types': self.config.dns_config.record_types,
                    'dns_servers': self.config.dns_config.dns_servers
                },
                'web': {
                    'detection_methods': self.config.web_config.detection_methods,
                    'timeout': self.config.web_config.request_timeout
                }
            }
        }
        
        # Step 1: Passive enumeration (stealth)
        logger.info("Phase 1: Passive enumeration")
        passive_results = self.passive_enumeration()
        comprehensive_results['passive'] = passive_results
        
        # Step 2: DNS enumeration
        logger.info("Phase 2: DNS enumeration")
        dns_results = self.dns_enumeration()
        comprehensive_results['dns'] = dns_results
        
        # Step 3: Active enumeration
        logger.info("Phase 3: Active enumeration")
        active_results = self.enhanced_active_enumeration(wordlist)
        comprehensive_results['active'] = active_results
        
        # Step 4: Web fingerprinting on discovered subdomains
        logger.info("Phase 4: Web technology fingerprinting")
        # Extract subdomains for web fingerprinting
        all_subdomains = self.correlate_results()
        web_targets = [f"https://{sub}" for sub in all_subdomains[:10]]  # Limit to first 10
        web_results = self.web_fingerprinting(web_targets)
        comprehensive_results['web_fingerprinting'] = web_results
        
        # Step 5: Generate final summary
        duration = time.time() - start_time
        comprehensive_results.update({
            'summary': {
                'total_duration': duration,
                'verified_subdomains': len(all_subdomains),
                'methods_executed': ['passive', 'dns', 'active', 'web_fingerprinting'],
                'completion_time': time.strftime('%Y-%m-%d %H:%M:%S')
            },
            'all_subdomains': all_subdomains,
            'errors': self.get_errors()
        })
        
        logger.info(f"Comprehensive enumeration completed in {duration:.2f} seconds")
        logger.info(f"Found {len(all_subdomains)} verified subdomains")
        
        return comprehensive_results
    
    def subdomain_discovery(self, wordlist: Optional[List[str]] = None) -> List[str]:
        """
        Comprehensive subdomain discovery combining all techniques.
        
        Args:
            wordlist: Custom wordlist for active enumeration.
            
        Returns:
            List[str]: Verified subdomains discovered through enumeration.
        """
        logger.info(f"Starting comprehensive subdomain discovery for domain: {self.domain}")
        start_time = time.time()
        
        # Step 1: Passive enumeration (stealth)
        logger.info("Phase 1: Passive enumeration")
        self.passive_enumeration()
        
        # Step 2: DNS enumeration
        logger.info("Phase 2: DNS enumeration")
        self.dns_enumeration()
        
        # Step 3: Active enumeration
        logger.info("Phase 3: Active enumeration")
        self.enhanced_active_enumeration(wordlist)
        
        # Step 4: Correlate and verify results
        logger.info("Phase 4: Results correlation and verification")
        verified_subdomains = self.correlate_results()
        
        duration = time.time() - start_time
        logger.info(f"Subdomain discovery completed in {duration:.2f} seconds")
        logger.info(f"Found {len(verified_subdomains)} verified subdomains")
        
        return verified_subdomains
    
    def correlate_results(self) -> List[str]:
        """
        Correlate findings from all sources and return verified subdomains.
        
        Returns:
            List[str]: Verified and deduplicated subdomains
        """
        logger.info("Correlating results from all enumeration sources")
        
        # Extract all subdomains from results manager
        all_subdomains = self.results_manager.extract_all_subdomains(self.domain)
        
        # Verify subdomains
        verified_subdomains = self._verify_subdomains(all_subdomains)
        
        # Update results with verified subdomains
        self.results_manager.results['subdomains'] = {
            'verified': verified_subdomains,
            'total_discovered': len(all_subdomains),
            'verification_rate': len(verified_subdomains) / len(all_subdomains) if all_subdomains else 0
        }
        
        logger.info(f"Correlation complete: {len(verified_subdomains)} verified from {len(all_subdomains)} discovered")
        return verified_subdomains
    
    def _verify_subdomains(self, subdomains: Set[str]) -> List[str]:
        """
        Verify that subdomains are actually resolvable.
        
        Args:
            subdomains: Set of subdomains to verify
            
        Returns:
            List of verified subdomains
        """
        verified = []
        
        logger.info(f"Verifying {len(subdomains)} discovered subdomains...")
        
        for subdomain in subdomains:
            if SubdomainValidator.verify_subdomain_dns(subdomain):
                verified.append(subdomain)
                logger.debug(f"Verified subdomain: {subdomain}")
        
        logger.info(f"Verification complete: {len(verified)}/{len(subdomains)} subdomains verified")
        return sorted(verified)
    
    def get_comprehensive_results(self) -> Dict:
        """
        Get all results from all enumeration methods.
        
        Returns:
            Dict: Complete results from all enumeration techniques
        """
        return self.results_manager.get_all_results()
    
    def get_errors(self) -> Dict:
        """
        Get all errors encountered during enumeration.
        
        Returns:
            Dict: Error information from all modules
        """
        all_errors = self.error_handler.get_errors()
        
        # Add errors from results manager
        results_errors = self.results_manager.get_all_results().get('errors', {})
        if results_errors:
            all_errors.update(results_errors)
        
        return all_errors
    
    def generate_report(self) -> Dict:
        """
        Generate a comprehensive enumeration report.
        
        Returns:
            Dict: Detailed report with statistics and findings
        """
        results = self.get_comprehensive_results()
        
        # Extract subdomains from each method
        passive_subdomains = len(self.results_manager.extract_all_subdomains(self.domain))
        verified_subdomains = results.get('subdomains', {}).get('verified', [])
        
        # Generate statistics
        report = {
            'domain': self.domain,
            'timestamp': time.time(),
            'summary': {
                'total_verified_subdomains': len(verified_subdomains),
                'total_discovered_subdomains': passive_subdomains,
                'verification_rate': results.get('subdomains', {}).get('verification_rate', 0),
                'methods_used': []
            },
            'subdomains': verified_subdomains,
            'detailed_results': results,
            'errors': self.get_errors()
        }
        
        # Determine which methods were used
        if results.get('passive_data'):
            report['summary']['methods_used'].append('passive_enumeration')
        if results.get('active_discovery'):
            report['summary']['methods_used'].append('active_enumeration')
        if results.get('dns_records'):
            report['summary']['methods_used'].append('dns_enumeration')
        if results.get('web_technologies'):
            report['summary']['methods_used'].append('web_fingerprinting')
        
        logger.info(f"Generated comprehensive report for {self.domain}")
        return report


def execute_domain_enumeration(
    domain: str,
    # Passive enumeration parameters
    passive_sources: Optional[List[str]] = None,
    ct_sources: Optional[List[str]] = None,
    passive_timeout: int = 10,
    passive_concurrent: int = 5,
    # Active enumeration parameters  
    active_methods: Optional[List[str]] = None,
    active_threads: int = 10,
    active_rate_limit: int = 10,
    active_timeout: int = 5,
    bruteforce_retries: int = 2,
    permutation_depth: int = 3,
    enable_ai_wordlist: bool = True,
    # DNS enumeration parameters
    dns_servers: Optional[List[str]] = None,
    dns_timeout: int = 5,
    dns_retries: int = 2,
    record_types: Optional[List[str]] = None,
    include_parent_domain: bool = True,
    perform_dns_analysis: bool = True,
    txt_analysis_depth: str = 'basic',
    # Web fingerprinting parameters
    web_detection_methods: Optional[List[str]] = None,
    web_timeout: int = 30,
    web_concurrent: int = 3,
    include_www: bool = False,
    include_http: bool = False,
    disable_wappalyzer: bool = False,
    disable_web_ai: bool = False,
    disable_security_analysis: bool = False,
    # Global parameters
    verbose: bool = False,
    output_format: str = 'detailed',
    custom_wordlist: Optional[List[str]] = None
) -> Dict:
    """
    Execute comprehensive domain enumeration with full parameter configuration.
    
    This function provides a unified interface for all domain enumeration methods
    with complete parameter customization for each sub-module.
    
    Args:
        domain: Target domain to enumerate
        
        # Passive enumeration configuration
        passive_sources: List of passive sources to enable
        ct_sources: Certificate transparency sources to use
        passive_timeout: Request timeout for passive enumeration
        passive_concurrent: Concurrent requests for passive enumeration
        
        # Active enumeration configuration
        active_methods: Active enumeration methods to enable
        active_threads: Number of threads for active enumeration
        active_rate_limit: Rate limit for active enumeration
        active_timeout: Timeout for active enumeration
        bruteforce_retries: Retry attempts for brute force
        permutation_depth: DNS permutation depth
        enable_ai_wordlist: Enable AI-enhanced wordlist generation
        
        # DNS enumeration configuration
        dns_servers: Custom DNS servers to use
        dns_timeout: DNS query timeout
        dns_retries: DNS query retry attempts
        record_types: DNS record types to query
        include_parent_domain: Include parent domain analysis
        perform_dns_analysis: Perform infrastructure analysis
        txt_analysis_depth: TXT record analysis depth
        
        # Web fingerprinting configuration
        web_detection_methods: Technology detection methods
        web_timeout: Web request timeout
        web_concurrent: Concurrent web requests
        include_www: Include www variant
        include_http: Include HTTP targets
        disable_wappalyzer: Disable Wappalyzer detection
        disable_web_ai: Disable AI-enhanced analysis
        disable_security_analysis: Disable security analysis
        
        # Global configuration
        verbose: Enable verbose output
        output_format: Output format (detailed, summary, minimal)
        custom_wordlist: Custom wordlist for active enumeration
        
    Returns:
        Dict: Comprehensive enumeration results from all methods
    """
    logger.info(f"Starting comprehensive domain enumeration for {domain}")
    
    # Create comprehensive configuration
    config = ComprehensiveEnumerationConfig()
    
    # Configure passive enumeration
    if passive_sources is not None:
        config.passive_config.enabled_sources = passive_sources
    if ct_sources is not None:
        config.passive_config.ct_sources = ct_sources
    config.passive_config.ct_timeout = passive_timeout
    config.passive_config.max_concurrent_requests = passive_concurrent
    
    # Configure active enumeration
    if active_methods is not None:
        config.active_config.enabled_methods = active_methods
    config.active_config.thread_count = active_threads
    config.active_config.rate_limit = active_rate_limit
    config.active_config.bruteforce_timeout = active_timeout
    config.active_config.bruteforce_retries = bruteforce_retries
    config.active_config.permutation_depth = permutation_depth
    config.active_config.wordlist_ai_enabled = enable_ai_wordlist
    
    # Configure DNS enumeration
    if dns_servers is not None:
        config.dns_config.dns_servers = dns_servers
    config.dns_config.query_timeout = dns_timeout
    config.dns_config.query_retries = dns_retries
    if record_types is not None:
        config.dns_config.record_types = record_types
    config.dns_config.include_parent_domain = include_parent_domain
    config.dns_config.perform_infrastructure_analysis = perform_dns_analysis
    config.dns_config.txt_analysis_depth = txt_analysis_depth
    
    # Configure web fingerprinting
    if web_detection_methods is not None:
        config.web_config.detection_methods = web_detection_methods
    config.web_config.request_timeout = web_timeout
    config.web_config.concurrent_requests = web_concurrent
    config.web_config.include_www_variant = include_www
    config.web_config.include_http = include_http
    config.web_config.enable_wappalyzer = not disable_wappalyzer
    config.web_config.enable_ai_analysis = not disable_web_ai
    config.web_config.enable_security_analysis = not disable_security_analysis
    
    # Configure global settings
    config.verbose = verbose
    config.output_format = output_format
    
    # Initialize and execute enumeration
    enumerator = DomainEnumeration(domain, config)
    results = enumerator.execute_comprehensive_enumeration(custom_wordlist)
    
    logger.info(f"Domain enumeration completed for {domain}")
    return results


# Main function for command-line usage
def main():
    """Enhanced main function for command-line execution with comprehensive parameter support"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Comprehensive Domain Enumeration with Full Configuration")
    parser.add_argument("domain", help="Target domain to enumerate")
    
    # Execution mode options
    parser.add_argument("--passive-only", action="store_true", help="Run only passive enumeration")
    parser.add_argument("--active-only", action="store_true", help="Run only active enumeration")
    parser.add_argument("--dns-only", action="store_true", help="Run only DNS enumeration")
    parser.add_argument("--web-only", action="store_true", help="Run only web fingerprinting")
    parser.add_argument("--comprehensive", action="store_true", default=True, help="Run comprehensive enumeration (default)")
    
    # Passive enumeration options
    parser.add_argument("--passive-sources", nargs='+', default=['certificate_transparency'], 
                       help="Passive sources to use (default: certificate_transparency)")
    parser.add_argument("--ct-sources", nargs='+', default=['crt_sh'],
                       help="Certificate transparency sources (default: crt_sh)")
    parser.add_argument("--passive-timeout", type=int, default=10, help="Passive enumeration timeout (default: 10)")
    parser.add_argument("--passive-concurrent", type=int, default=5, help="Passive concurrent requests (default: 5)")
    
    # Active enumeration options
    parser.add_argument("--active-methods", nargs='+', default=['bruteforce', 'dns_permutations'],
                       help="Active methods to use (default: bruteforce dns_permutations)")
    parser.add_argument("--threads", type=int, default=10, help="Number of threads for active enumeration (default: 10)")
    parser.add_argument("--rate-limit", type=int, default=10, help="Rate limit for active enumeration (default: 10)")
    parser.add_argument("--active-timeout", type=int, default=5, help="Active enumeration timeout (default: 5)")
    parser.add_argument("--retries", type=int, default=2, help="Brute force retry attempts (default: 2)")
    parser.add_argument("--permutation-depth", type=int, default=3, help="DNS permutation depth (default: 3)")
    parser.add_argument("--disable-ai-wordlist", action="store_true", help="Disable AI-enhanced wordlist generation")
    
    # DNS enumeration options
    parser.add_argument("--dns-servers", nargs='+', help="Custom DNS servers to use")
    parser.add_argument("--dns-timeout", type=int, default=5, help="DNS query timeout (default: 5)")
    parser.add_argument("--dns-retries", type=int, default=2, help="DNS query retries (default: 2)")
    parser.add_argument("--record-types", nargs='+', default=['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA'],
                       help="DNS record types to query")
    parser.add_argument("--no-parent-domain", action="store_true", help="Disable parent domain analysis")
    parser.add_argument("--no-dns-analysis", action="store_true", help="Disable DNS infrastructure analysis")
    parser.add_argument("--txt-depth", choices=['basic', 'advanced', 'deep'], default='basic',
                       help="TXT record analysis depth (default: basic)")
    
    # Web fingerprinting options
    parser.add_argument("--web-methods", nargs='+', default=['headers', 'content', 'url_patterns', 'wappalyzer'],
                       help="Web detection methods to use")
    parser.add_argument("--web-timeout", type=int, default=30, help="Web request timeout (default: 30)")
    parser.add_argument("--web-concurrent", type=int, default=3, help="Concurrent web requests (default: 3)")
    parser.add_argument("--include-www", action="store_true", help="Include www variant in web fingerprinting")
    parser.add_argument("--include-http", action="store_true", help="Include HTTP targets (not recommended)")
    parser.add_argument("--disable-wappalyzer", action="store_true", help="Disable Wappalyzer detection")
    parser.add_argument("--disable-web-ai", action="store_true", help="Disable AI-enhanced web analysis")
    parser.add_argument("--disable-security", action="store_true", help="Disable security analysis")
    
    # General options
    parser.add_argument("--wordlist", help="Custom wordlist file for active enumeration")
    parser.add_argument("--output", help="Output file for results (JSON format)")
    parser.add_argument("--output-format", choices=['detailed', 'summary', 'minimal'], default='detailed',
                       help="Output format (default: detailed)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose logging")
    
    args = parser.parse_args()
    
    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Load custom wordlist if provided
    custom_wordlist = None
    if args.wordlist:
        try:
            with open(args.wordlist, 'r') as f:
                custom_wordlist = [line.strip() for line in f if line.strip()]
            print(f"Loaded {len(custom_wordlist)} words from {args.wordlist}")
        except Exception as e:
            print(f"Error loading wordlist: {e}")
            return
    
    print(f"\n=== Comprehensive Domain Enumeration for {args.domain} ===")
    
    # Execute comprehensive enumeration with all configured parameters
    try:
        results = execute_domain_enumeration(
            domain=args.domain,
            # Passive enumeration parameters
            passive_sources=args.passive_sources if not (args.active_only or args.dns_only or args.web_only) else None,
            ct_sources=args.ct_sources,
            passive_timeout=args.passive_timeout,
            passive_concurrent=args.passive_concurrent,
            # Active enumeration parameters  
            active_methods=args.active_methods if not (args.passive_only or args.dns_only or args.web_only) else None,
            active_threads=args.threads,
            active_rate_limit=args.rate_limit,
            active_timeout=args.active_timeout,
            bruteforce_retries=args.retries,
            permutation_depth=args.permutation_depth,
            enable_ai_wordlist=not args.disable_ai_wordlist,
            # DNS enumeration parameters
            dns_servers=args.dns_servers,
            dns_timeout=args.dns_timeout,
            dns_retries=args.dns_retries,
            record_types=args.record_types if not (args.passive_only or args.active_only or args.web_only) else None,
            include_parent_domain=not args.no_parent_domain,
            perform_dns_analysis=not args.no_dns_analysis,
            txt_analysis_depth=args.txt_depth,
            # Web fingerprinting parameters
            web_detection_methods=args.web_methods if not (args.passive_only or args.active_only or args.dns_only) else None,
            web_timeout=args.web_timeout,
            web_concurrent=args.web_concurrent,
            include_www=args.include_www,
            include_http=args.include_http,
            disable_wappalyzer=args.disable_wappalyzer,
            disable_web_ai=args.disable_web_ai,
            disable_security_analysis=args.disable_security,
            # Global parameters
            verbose=args.verbose,
            output_format=args.output_format,
            custom_wordlist=custom_wordlist
        )
        
        # Extract key results
        all_subdomains = results.get('all_subdomains', [])
        summary = results.get('summary', {})
        
    except Exception as e:
        print(f"Error during domain enumeration: {e}")
        return
    
    print(f"\n{'='*60}")
    print(f"               COMPREHENSIVE RESULTS SUMMARY")
    print(f"{'='*60}")
    print(f"Domain: {args.domain}")
    print(f"Verified subdomains found: {len(all_subdomains)}")
    
    if all_subdomains:
        print(f"\n{'='*40}")
        print("           VERIFIED SUBDOMAINS")
        print(f"{'='*40}")
        for i, subdomain in enumerate(all_subdomains, 1):
            print(f"  {i:2d}. {subdomain}")
    
    # Display detailed results from each enumeration method
    print(f"\n{'='*50}")
    print("         DETAILED ENUMERATION RESULTS")
    print(f"{'='*50}")
    
    # Passive Enumeration Results
    passive_data = results.get('passive', {})
    if passive_data:
        print(f"\n🔍 PASSIVE ENUMERATION RESULTS:")
        print("-" * 40)
        total_passive = 0
        for source, data in passive_data.items():
            if isinstance(data, dict):
                subdomains_found = 0
                if 'subdomains' in data and isinstance(data['subdomains'], list):
                    subdomains_found = len(data['subdomains'])
                    total_passive += subdomains_found
                print(f"  📊 {source}: {subdomains_found} subdomains")
                
                # Show first few subdomains from each source
                if subdomains_found > 0 and isinstance(data['subdomains'], list):
                    display_count = min(3, subdomains_found)
                    for j, subdomain in enumerate(data['subdomains'][:display_count]):
                        print(f"      • {subdomain}")
                    if subdomains_found > display_count:
                        print(f"      ... and {subdomains_found - display_count} more")
        print(f"  📈 Total from passive sources: {total_passive} subdomains")
    
    # DNS Enumeration Results
    dns_records = results.get('dns', {})
    if dns_records:
        print(f"\n🌐 DNS ENUMERATION RESULTS:")
        print("-" * 40)
        for record_type, records in dns_records.items():
            if isinstance(records, list) and records:
                print(f"  📋 {record_type} Records ({len(records)} found):")
                display_count = min(5, len(records))
                for record in records[:display_count]:
                    print(f"      • {record}")
                if len(records) > display_count:
                    print(f"      ... and {len(records) - display_count} more")
    
    # Active Enumeration Results
    active_data = results.get('active', {})
    if active_data:
        print(f"\n⚔️  ACTIVE ENUMERATION RESULTS:")
        print("-" * 40)
        total_active = 0
        for method, subdomains in active_data.items():
            if isinstance(subdomains, list):
                method_count = len(subdomains)
                total_active += method_count
                print(f"  🎯 {method}: {method_count} subdomains")
                if method_count > 0:
                    display_count = min(3, method_count)
                    for subdomain in subdomains[:display_count]:
                        print(f"      • {subdomain}")
                    if method_count > display_count:
                        print(f"      ... and {method_count - display_count} more")
        print(f"  📈 Total from active methods: {total_active} subdomains")
    
    # Web Technology Results
    web_tech = results.get('web_fingerprinting', {})
    if web_tech:
        print(f"\n🌐 WEB TECHNOLOGY FINGERPRINTING:")
        print("-" * 40)
        for url, tech_data in web_tech.items():
            print(f"  🔗 {url}:")
            if isinstance(tech_data, dict):
                # Check for technology detection data
                tech_detection = tech_data.get('technology_detection', {})
                if tech_detection:
                    # Display Wappalyzer results
                    wappalyzer_techs = tech_detection.get('wappalyzer_detected', [])
                    if wappalyzer_techs:
                        print(f"      🔍 Wappalyzer detected:")
                        for tech in wappalyzer_techs:
                            print(f"         • {tech}")
                    
                    # Display AI detected results
                    ai_techs = tech_detection.get('ai_detected', [])
                    if ai_techs:
                        print(f"      🤖 AI detected:")
                        for tech in ai_techs:
                            print(f"         • {tech}")
                    
                    # Display header detected results
                    header_techs = tech_detection.get('header_detected', [])
                    if header_techs:
                        print(f"      📋 Header detected:")
                        for tech in header_techs:
                            print(f"         • {tech}")
                    
                    # Display content detected results
                    content_techs = tech_detection.get('content_detected', [])
                    if content_techs:
                        print(f"      📄 Content detected:")
                        for tech in content_techs:
                            print(f"         • {tech}")
                    
                    # Display URL pattern results
                    url_patterns = tech_detection.get('url_patterns', [])
                    if url_patterns:
                        print(f"      🔗 URL pattern detected:")
                        for tech in url_patterns:
                            print(f"         • {tech}")
                
                # Legacy check for direct technologies list
                if 'technologies' in tech_data and tech_data['technologies']:
                    print(f"      🔧 Other technologies:")
                    for tech in tech_data['technologies']:
                        print(f"         • {tech}")
                
                # Show additional info if available
                if 'server' in tech_data and tech_data['server']:
                    print(f"      🖥️  Server: {tech_data['server']}")
                if 'status_code' in tech_data:
                    print(f"      📊 Status Code: {tech_data['status_code']}")
                if 'response_time' in tech_data:
                    print(f"      ⏱️  Response Time: {tech_data['response_time']:.3f}s")
                
                # If no technologies were detected at all
                if not any([
                    tech_detection.get('wappalyzer_detected'),
                    tech_detection.get('ai_detected'),
                    tech_detection.get('header_detected'),
                    tech_detection.get('content_detected'),
                    tech_detection.get('url_patterns'),
                    tech_data.get('technologies')
                ]):
                    print("      • No specific technologies detected")
    
    # Subdomain Statistics
    subdomains_info = summary
    if subdomains_info:
        print(f"\n📊 ENUMERATION STATISTICS:")
        print("-" * 40)
        total_duration = subdomains_info.get('total_duration', 0)
        total_verified = subdomains_info.get('verified_subdomains', len(all_subdomains))
        completion_time = subdomains_info.get('completion_time', 'Unknown')
        
        print(f"  ⏱️  Total duration: {total_duration:.2f}s")
        print(f"  ✅ Total verified: {total_verified}")
        print(f"  � Completion: {completion_time}")
    
    # Display errors if any
    errors = results.get('errors', {})
    if errors:
        print(f"\n❌ ERROR SUMMARY:")
        print("-" * 40)
        total_errors = sum(len(error_list) for error_list in errors.values())
        print(f"  Total errors encountered: {total_errors}")
        
        for method, error_list in errors.items():
            if error_list:
                print(f"  🔴 {method}: {len(error_list)} errors")
                # Show first few errors
                display_count = min(2, len(error_list))
                for error in error_list[:display_count]:
                    print(f"      • {str(error)[:80]}...")
                if len(error_list) > display_count:
                    print(f"      ... and {len(error_list) - display_count} more errors")
    
    print(f"\n{'='*60}")
    print("              ENUMERATION COMPLETE")
    print(f"{'='*60}")
    
    # Save results if output file specified
    if args.output:
        try:
            import json
            
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            
            print(f"\n💾 Full detailed results saved to: {args.output}")
        except Exception as e:
            print(f"❌ Error saving results: {e}")


if __name__ == "__main__":
    main()