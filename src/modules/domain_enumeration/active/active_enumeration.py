#!/usr/bin/env python3
"""
Enhanced Active Domain Enumeration Module

This module provides configurable active subdomain discovery with comprehensive
parameter customization before execution.
"""

import logging
import time
import socket
import dns.resolver
import requests
import sys
import os
import argparse
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Set, Optional, Any, Union

# Add parent directories to path for imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..')))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
try:
    from modules.domain_enumeration.config import EnumerationConfig
    from modules.domain_enumeration.base import EnumerationErrorHandler, RateLimiter, SubdomainValidator
except ImportError:
    from config import EnumerationConfig
    from base import EnumerationErrorHandler, RateLimiter, SubdomainValidator

logger = logging.getLogger(__name__)

# Import AI Integration module
try:
    from modules.ai_integration import AIIntegration
    AI_AVAILABLE = True
except ImportError:
    try:
        # Try alternative import path
        sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))
        from ai_integration import AIIntegration
        AI_AVAILABLE = True
    except ImportError:
        AI_AVAILABLE = False
        AIIntegration = None


class EnhancedEnumerationConfig(EnumerationConfig):
    """Extended configuration with method-specific parameters"""
    
    def __init__(self):
        super().__init__()
        
        # Brute Force Configuration
        self.bruteforce_timeout = 5
        self.bruteforce_retries = 2
        self.bruteforce_validate_responses = True
        self.bruteforce_doh_priority = False  # Prefer DoH over traditional DNS
        
        # DNS Permutation Configuration
        self.permutation_depth = 3
        self.include_numeric_permutations = True
        self.include_regional_permutations = True
        self.include_environment_permutations = True
        self.custom_permutation_patterns = []
        
        # DNS Zone Transfer Configuration
        self.zone_transfer_timeout = 10
        self.zone_transfer_servers = []  # Specific nameservers to try
        self.zone_transfer_retries = 3
        
        # DNS Cache Snooping Configuration
        self.cache_snoop_dns_servers = [
            '8.8.8.8',      # Google
            '1.1.1.1',      # Cloudflare  
            '208.67.222.222',  # OpenDNS
            '9.9.9.9'       # Quad9
        ]
        self.cache_snoop_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'api', 'test', 'dev', 'staging',
            'blog', 'shop', 'support', 'vpn', 'remote', 'portal'
        ]
        self.cache_snoop_timeout = 2
        self.cache_snoop_concurrent_servers = 2
        
        # Wordlist Generation Configuration
        self.wordlist_ai_enabled = True
        self.wordlist_ai_max_terms = 50
        self.wordlist_include_common = True
        self.wordlist_include_permutations = True
        self.wordlist_custom_terms = []
        
        # General Enumeration Settings
        self.enabled_methods = ['bruteforce', 'dns_permutations', 'zone_transfer', 'cache_snooping']
        self.output_format = 'text'  # text, json, csv
        self.save_results = True
        self.results_filename = None


class ConfigurableActiveEnumerator:
    """
    Enhanced active enumerator with comprehensive pre-execution configuration.
    """
    
    def __init__(self, domain: str, config: EnhancedEnumerationConfig = None, 
                 ai_integration = None, **kwargs):
        """Initialize with full configuration"""
        self.domain = domain.lower().strip()
        self.config = config or EnhancedEnumerationConfig()
        
        # Override config with kwargs
        self._apply_config_overrides(kwargs)
        
        self.error_handler = EnumerationErrorHandler()
        self.rate_limiter = RateLimiter(self.config.rate_limit)
        
        # Initialize AI integration properly
        self.ai_integration = ai_integration
        if AI_AVAILABLE and not self.ai_integration:
            # Try to create AI integration with environment variables
            api_keys = {
                'gemini_api_key': os.getenv('GEMINI_API_KEY'),
                'openai_api_key': os.getenv('OPENAI_API_KEY'),
                'anthropic_api_key': os.getenv('ANTHROPIC_API_KEY')
            }
            if any(api_keys.values()):
                try:
                    self.ai_integration = AIIntegration(**{k: v for k, v in api_keys.items() if v})
                    logger.info("AI integration initialized for enhanced wordlist generation")
                except Exception as e:
                    logger.warning(f"Failed to initialize AI integration: {e}")
            else:
                logger.info("AI Integration module available but no API keys found in environment variables. Using fallback methods for wordlist generation.")
        elif not AI_AVAILABLE:
            logger.info("AI Integration module not available. Using fallback methods for wordlist generation.")
        
        # Set up HTTP session
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        logger.info(f"ConfigurableActiveEnumerator initialized for {self.domain}")
        self._log_configuration()
    
    def _apply_config_overrides(self, kwargs: Dict[str, Any]):
        """Apply configuration overrides from keyword arguments"""
        for key, value in kwargs.items():
            if hasattr(self.config, key):
                setattr(self.config, key, value)
                logger.debug(f"Overridden config.{key} = {value}")
    
    def _log_configuration(self):
        """Log the current configuration"""
        logger.info("=== Active Enumeration Configuration ===")
        logger.info(f"Domain: {self.domain}")
        logger.info(f"Enabled methods: {', '.join(self.config.enabled_methods)}")
        logger.info(f"Threads: {self.config.thread_count}, Rate limit: {self.config.rate_limit}/s")
        logger.info(f"Brute force: {self.config.bruteforce_timeout}s timeout, {self.config.bruteforce_retries} retries")
        logger.info(f"Permutations: depth={self.config.permutation_depth}")
        logger.info(f"Zone transfer: {len(self.config.zone_transfer_servers)} custom servers")
        logger.info(f"Cache snooping: {len(self.config.cache_snoop_dns_servers)} DNS servers")
        logger.info("=========================================")
    
    def run_comprehensive_enumeration(self, wordlist: List[str] = None, 
                                    page_content: Dict = None) -> Dict[str, Any]:
        """
        Run comprehensive enumeration with pre-configured parameters.
        
        Returns:
            Dict containing results, metrics, and configuration
        """
        start_time = time.time()
        results = {
            'domain': self.domain,
            'timestamp': time.time(),
            'configuration': self._get_config_summary(),
            'methods': {},
            'statistics': {},
            'errors': {}
        }
        
        # Generate wordlist if not provided
        if not wordlist:
            wordlist = self._generate_enhanced_wordlist(page_content)
        
        # Execute enabled methods
        for method in self.config.enabled_methods:
            method_start = time.time()
            try:
                if method == 'bruteforce':
                    results['methods'][method] = self._execute_bruteforce(wordlist)
                elif method == 'dns_permutations':
                    results['methods'][method] = self._execute_dns_permutations()
                elif method == 'zone_transfer':
                    results['methods'][method] = self._execute_zone_transfer()
                elif method == 'cache_snooping':
                    results['methods'][method] = self._execute_cache_snooping()
                else:
                    logger.warning(f"Unknown method: {method}")
                    continue
                
                method_duration = time.time() - method_start
                logger.info(f"{method}: found {len(results['methods'][method])} subdomains in {method_duration:.2f}s")
                
            except Exception as e:
                logger.error(f"Method {method} failed: {e}")
                results['methods'][method] = []
                self.error_handler.handle_error(method, e)
        
        # Compile results and statistics
        results['statistics'] = self._compile_statistics(results, start_time)
        results['errors'] = self.error_handler.get_errors()
        
        # Save results if configured
        if self.config.save_results:
            self._save_results(results)
        
        return results
    
    def _execute_bruteforce(self, wordlist: List[str]) -> List[str]:
        """Execute brute force with configured parameters"""
        logger.info(f"Executing brute force with {len(wordlist)} words")
        
        results = []
        successful = 0
        failed = 0
        
        with ThreadPoolExecutor(max_workers=self.config.thread_count) as executor:
            futures = []
            for word in wordlist:
                if self.config.rate_limiting_enabled:
                    self.rate_limiter.acquire()
                
                future = executor.submit(self._check_subdomain_enhanced, word)
                futures.append((word, future))
            
            for word, future in futures:
                try:
                    result = future.result(timeout=self.config.bruteforce_timeout)
                    if result:
                        results.append(result)
                        successful += 1
                        logger.debug(f"Found: {result}")
                    else:
                        failed += 1
                except Exception as e:
                    failed += 1
                    logger.debug(f"Brute force error for {word}: {e}")
        
        logger.info(f"Brute force completed: {successful} found, {failed} failed")
        return results
    
    def _check_subdomain_enhanced(self, subdomain: str) -> str:
        """Enhanced subdomain checking with retries and configurable DNS priority"""
        full_domain = f"{subdomain}.{self.domain}"
        
        for attempt in range(self.config.bruteforce_retries + 1):
            try:
                # Use DoH first if configured
                if self.config.bruteforce_doh_priority:
                    doh_result = self._doh_query(full_domain)
                    if doh_result:
                        return full_domain
                
                # Traditional DNS lookup
                result = socket.gethostbyname(full_domain)
                return full_domain
                
            except socket.gaierror:
                # Try fallback if traditional DNS failed and DoH not prioritized
                if not self.config.bruteforce_doh_priority and self.config.doh_fallback:
                    doh_result = self._doh_query(full_domain)
                    if doh_result:
                        return full_domain
            
            except Exception as e:
                logger.debug(f"Attempt {attempt + 1} failed for {full_domain}: {e}")
                
            if attempt < self.config.bruteforce_retries:
                time.sleep(0.1)  # Brief delay before retry
        
        return None
    
    def _execute_dns_permutations(self) -> List[str]:
        """Execute DNS permutation attack with configured parameters"""
        logger.info("Executing DNS permutation attack")
        
        # Generate permutations based on configuration
        permutations = self._generate_configured_permutations()
        logger.info(f"Generated {len(permutations)} permutation patterns")
        
        results = []
        with ThreadPoolExecutor(max_workers=self.config.thread_count) as executor:
            futures = []
            for pattern in permutations:
                if self.config.rate_limiting_enabled:
                    self.rate_limiter.acquire()
                future = executor.submit(self._check_subdomain_enhanced, pattern)
                futures.append(future)
            
            for future in futures:
                try:
                    result = future.result(timeout=self.config.timeout)
                    if result:
                        results.append(result)
                except Exception as e:
                    logger.debug(f"Permutation error: {e}")
        
        return results
    
    def _generate_configured_permutations(self) -> List[str]:
        """Generate permutations based on configuration"""
        permutations = set()
        domain_parts = self.domain.split('.')
        base_name = domain_parts[0] if len(domain_parts) > 1 else self.domain
        
        # Add custom patterns first
        permutations.update(self.config.custom_permutation_patterns)
        
        # Numeric permutations
        if self.config.include_numeric_permutations:
            for i in range(1, self.config.permutation_depth + 1):
                permutations.update([
                    f"{base_name}{i}", f"{base_name}-{i}", f"{base_name}_{i}",
                    f"{base_name}0{i}", f"{base_name}-0{i}", f"{base_name}_0{i}"
                ])
        
        # Regional permutations
        if self.config.include_regional_permutations:
            regions = ['us', 'eu', 'uk', 'asia', 'ca', 'au', 'in', 'jp', 'cn']
            for region in regions[:self.config.permutation_depth]:
                permutations.update([
                    f"{base_name}-{region}", f"{region}-{base_name}",
                    f"{base_name}_{region}", f"{base_name}{region}"
                ])
        
        # Environment permutations
        if self.config.include_environment_permutations:
            envs = ['dev', 'test', 'stage', 'prod', 'uat', 'qa', 'preprod']
            for env in envs[:self.config.permutation_depth]:
                permutations.update([
                    f"{env}-{base_name}", f"{base_name}-{env}",
                    f"{env}_{base_name}", f"{base_name}_{env}",
                    f"{env}{base_name}", f"{base_name}{env}"
                ])
        
        return list(permutations)
    
    def _execute_zone_transfer(self) -> List[str]:
        """Execute zone transfer with configured parameters"""
        logger.info("Executing DNS zone transfer")
        
        results = []
        nameservers = self.config.zone_transfer_servers
        
        # If no custom nameservers provided, discover them
        if not nameservers:
            try:
                ns_answers = dns.resolver.resolve(self.domain, 'NS')
                nameservers = [str(ns) for ns in ns_answers]
            except Exception as e:
                logger.warning(f"Failed to discover nameservers: {e}")
                return []
        
        for ns in nameservers:
            for attempt in range(self.config.zone_transfer_retries):
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(ns, self.domain, 
                                                          timeout=self.config.zone_transfer_timeout))
                    subdomains = [f"{name}.{self.domain}" for name in zone.nodes.keys()]
                    logger.info(f"Zone transfer successful from {ns}: {len(subdomains)} records")
                    results.extend(subdomains)
                    break  # Success, no need for retries
                except Exception as e:
                    logger.debug(f"Zone transfer attempt {attempt + 1} failed for {ns}: {e}")
                    if attempt < self.config.zone_transfer_retries - 1:
                        time.sleep(1)  # Wait before retry
        
        return list(set(results))  # Remove duplicates
    
    def _execute_cache_snooping(self) -> List[str]:
        """Execute DNS cache snooping with configured parameters"""
        logger.info("Executing DNS cache snooping")
        
        results = []
        
        # Use configured DNS servers and subdomains
        dns_servers = self.config.cache_snoop_dns_servers
        subdomains = self.config.cache_snoop_subdomains
        
        logger.info(f"Checking {len(subdomains)} subdomains on {len(dns_servers)} DNS servers")
        
        with ThreadPoolExecutor(max_workers=self.config.cache_snoop_concurrent_servers) as executor:
            futures = []
            for dns_server in dns_servers:
                future = executor.submit(self._snoop_dns_server, dns_server, subdomains)
                futures.append(future)
            
            for future in futures:
                try:
                    server_results = future.result(timeout=len(subdomains) * self.config.cache_snoop_timeout + 5)
                    results.extend(server_results)
                except Exception as e:
                    logger.debug(f"DNS cache snooping error: {e}")
        
        return list(set(results))
    
    def _snoop_dns_server(self, dns_server: str, subdomains: List[str]) -> List[str]:
        """Snoop a specific DNS server"""
        results = []
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [dns_server]
            resolver.timeout = self.config.cache_snoop_timeout
            resolver.lifetime = self.config.cache_snoop_timeout * 2
            
            for subdomain in subdomains:
                full_domain = f"{subdomain}.{self.domain}"
                try:
                    answer = resolver.resolve(full_domain, 'A')
                    if answer:
                        results.append(full_domain)
                        logger.debug(f"Found cached: {full_domain} on {dns_server}")
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                    continue
                except Exception as e:
                    logger.debug(f"Error checking {subdomain} on {dns_server}: {e}")
                    
        except Exception as e:
            logger.warning(f"Failed to setup resolver for {dns_server}: {e}")
        
        return results
    
    def _fetch_page_content(self) -> Dict:
        """Fetch page content from the target domain for AI analysis"""
        import base64
        
        urls_to_try = [
            f"https://{self.domain}",
            f"http://{self.domain}",
            f"https://www.{self.domain}",
            f"http://www.{self.domain}"
        ]
        
        for url in urls_to_try:
            try:
                logger.info(f"Fetching page content from {url}")
                response = self.session.get(url, timeout=10, allow_redirects=True)
                
                if response.status_code == 200:
                    # Encode content as base64 for AI processing
                    content_b64 = base64.b64encode(response.content).decode('utf-8')
                    
                    page_content = {
                        'url': url,
                        'status_code': response.status_code,
                        'headers': dict(response.headers),
                        'content_base64': content_b64,
                        'content_text': response.text[:10000],  # First 10KB of text
                        'content_length': len(response.content)
                    }
                    
                    logger.info(f"Successfully fetched page content: {len(response.content)} bytes")
                    return page_content
                    
            except Exception as e:
                logger.debug(f"Failed to fetch {url}: {e}")
                continue
        
        logger.warning(f"Could not fetch page content for {self.domain}")
        return None

    def _generate_enhanced_wordlist(self, page_content: Dict = None) -> List[str]:
        """Generate wordlist with configured options"""
        logger.info("Generating enhanced wordlist")
        
        wordlist_sources = {}
        
        # Common subdomains
        if self.config.wordlist_include_common:
            wordlist_sources['common'] = self._load_common_wordlist()
        
        # Fetch page content for AI if not provided
        if not page_content and self.config.wordlist_ai_enabled and self.ai_integration:
            page_content = self._fetch_page_content()
        
        # AI-generated terms
        if self.config.wordlist_ai_enabled and self.ai_integration and page_content:
            try:
                logger.info("Generating AI-based wordlist from page content")
                ai_terms = self.ai_integration.generate_target_specific_wordlist(
                    page_content=page_content,
                    domain=self.domain,
                    num_terms=self.config.wordlist_ai_max_terms
                )
                if ai_terms:
                    wordlist_sources['ai'] = ai_terms
                    logger.info(f"AI generated {len(ai_terms)} domain-specific terms")
                else:
                    logger.warning("AI integration returned no terms")
            except Exception as e:
                logger.warning(f"AI wordlist generation failed: {e}")
        
        # Permutations
        if self.config.wordlist_include_permutations:
            wordlist_sources['permutations'] = self._generate_llm_based_terms()
        
        # Custom terms
        if self.config.wordlist_custom_terms:
            wordlist_sources['custom'] = self.config.wordlist_custom_terms
        
        return self._merge_wordlists(wordlist_sources)
    
    def _get_config_summary(self) -> Dict[str, Any]:
        """Get configuration summary for results"""
        return {
            'enabled_methods': self.config.enabled_methods,
            'rate_limit': self.config.rate_limit,
            'thread_count': self.config.thread_count,
            'timeout': self.config.timeout,
            'bruteforce_retries': self.config.bruteforce_retries,
            'permutation_depth': self.config.permutation_depth
        }
    
    def _compile_statistics(self, results: Dict, start_time: float) -> Dict[str, Any]:
        """Compile execution statistics"""
        total_duration = time.time() - start_time
        total_subdomains = sum(len(method_results) for method_results in results['methods'].values())
        
        return {
            'total_duration': total_duration,
            'total_subdomains': total_subdomains,
            'methods_breakdown': {method: len(method_results) 
                                for method, method_results in results['methods'].items()},
            'completion_time': time.strftime('%Y-%m-%d %H:%M:%S')
        }
    
    def _save_results(self, results: Dict):
        """Save results to file"""
        filename = self.config.results_filename or f"enumeration_{self.domain}_{int(time.time())}.txt"
        try:
            with open(filename, 'w') as f:
                f.write(f"# Domain Enumeration Results for {self.domain}\n")
                f.write(f"# Generated at: {time.ctime(results['timestamp'])}\n")
                f.write(f"# Total subdomains found: {results['statistics']['total_subdomains']}\n\n")
                
                all_subdomains = set()
                for method, subdomains in results['methods'].items():
                    all_subdomains.update(subdomains)
                
                for subdomain in sorted(all_subdomains):
                    f.write(f"{subdomain}\n")
            
            logger.info(f"Results saved to: {filename}")
        except Exception as e:
            logger.error(f"Failed to save results: {e}")
    
    # Existing helper methods (keep from original)
    def _load_common_wordlist(self) -> List[str]:
        common_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test',
            'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn', 'ns3',
            'mail2', 'new', 'mysql', 'old', 'lists', 'support', 'mobile', 'mx', 'static',
            'docs', 'beta', 'shop', 'sql', 'secure', 'demo', 'cp', 'calendar', 'wiki',
            'web', 'media', 'email', 'images', 'img', 'www1', 'intranet', 'portal', 'video'
        ]
        return common_subdomains
    
    def _generate_llm_based_terms(self) -> List[str]:
        """Generate terms using intelligent analysis"""
        logger.info("Generating intelligent subdomain terms")
        
        llm_terms = []
        domain_parts = self.domain.split('.')
        if len(domain_parts) >= 2:
            organization = domain_parts[0]
            tld_context = domain_parts[-1]
            
            # Context-aware term generation based on domain characteristics
            if 'edu' in tld_context or 'university' in organization.lower() or 'college' in organization.lower():
                edu_terms = [
                    'student', 'faculty', 'library', 'research', 'academics', 'admissions',
                    'registrar', 'alumni', 'course', 'exam', 'grade', 'scholarship',
                    'campus', 'dorm', 'housing', 'dining', 'sports', 'clubs'
                ]
                llm_terms.extend(edu_terms)
                logger.info("Generated educational institution terms")
                
            elif 'gov' in tld_context or 'government' in organization.lower():
                gov_terms = [
                    'citizen', 'service', 'department', 'ministry', 'office', 'public',
                    'policy', 'legislation', 'court', 'justice', 'tax', 'welfare'
                ]
                llm_terms.extend(gov_terms)
                logger.info("Generated government terms")
                
            elif 'com' in tld_context or 'business' in organization.lower():
                business_terms = [
                    'customer', 'client', 'product', 'service', 'sales', 'marketing',
                    'support', 'billing', 'invoice', 'order', 'payment', 'checkout',
                    'dashboard', 'account', 'profile', 'settings'
                ]
                llm_terms.extend(business_terms)
                logger.info("Generated business terms")
            
            # Technology-related terms (common for most domains)
            tech_terms = [
                'api', 'rest', 'graphql', 'webhook', 'oauth', 'sso', 'auth',
                'cdn', 'cache', 'redis', 'db', 'database', 'backup',
                'monitor', 'status', 'health', 'metrics', 'logs'
            ]
            llm_terms.extend(tech_terms)
            
        logger.info(f"Generated {len(llm_terms)} intelligent terms")
        return llm_terms
    
    def _merge_wordlists(self, wordlist_sources: Dict) -> List[str]:
        all_words = set()
        for words in wordlist_sources.values():
            all_words.update(words)
        return list(all_words)
    
    def _doh_query(self, domain: str, record_type: str = 'A') -> str:
        """DNS-over-HTTPS query as fallback"""
        doh_servers = [
            'https://cloudflare-dns.com/dns-query',
            'https://dns.google/dns-query'
        ]
        
        for doh_server in doh_servers:
            try:
                params = {'name': domain, 'type': record_type}
                headers = {'accept': 'application/dns-json'}
                
                response = self.session.get(doh_server, params=params, headers=headers, timeout=self.config.timeout)
                logger.debug(f"DoH query for {domain}: HTTP {response.status_code}")
                
                if response.status_code == 200:
                    data = response.json()
                    logger.debug(f"DoH response for {domain}: {data}")
                    
                    # Check DNS response status
                    status = data.get('Status', -1)
                    if status == 0:  # NOERROR - successful DNS response
                        if 'Answer' in data and data['Answer']:
                            # Domain exists and has records
                            ip_address = data['Answer'][0].get('data', '')
                            logger.info(f"DoH found {domain} -> {ip_address}")
                            return ip_address
                        else:
                            # NOERROR but no Answer section - domain exists but no A record
                            logger.debug(f"DoH: {domain} exists but no A record")
                            return "exists"
                    elif status == 3:  # NXDOMAIN - domain doesn't exist
                        logger.debug(f"DoH: {domain} does not exist (NXDOMAIN)")
                        continue
                    else:
                        logger.debug(f"DoH: {domain} returned status {status}")
                        continue
                else:
                    logger.debug(f"DoH query failed with HTTP {response.status_code}")
            except Exception as e:
                logger.debug(f"DoH query failed for {doh_server}: {e}")
                continue
        
        return None


def create_enumeration_config_from_args(args) -> EnhancedEnumerationConfig:
    """Create configuration from command line arguments"""
    config = EnhancedEnumerationConfig()
    
    # Basic configuration
    if hasattr(args, 'threads'):
        config.thread_count = args.threads
    if hasattr(args, 'rate_limit'):
        config.rate_limit = args.rate_limit
    if hasattr(args, 'timeout'):
        config.timeout = args.timeout
    
    # Method-specific configuration
    if hasattr(args, 'bruteforce_retries'):
        config.bruteforce_retries = args.bruteforce_retries
    if hasattr(args, 'permutation_depth'):
        config.permutation_depth = args.permutation_depth
    if hasattr(args, 'dns_servers') and args.dns_servers is not None:
        config.cache_snoop_dns_servers = args.dns_servers
    
    # Enable/disable methods
    if hasattr(args, 'methods'):
        config.enabled_methods = args.methods
    
    return config

def execute_active_enumeration(domain, 
                                threads=10, 
                                rate_limit=10, 
                                timeout=5,
                                bruteforce_retries=2, 
                                permutation_depth=3, 
                                dns_servers=None,
                                methods=None, 
                                wordlist_file=None, 
                                enable_ai=True):
    """Enhanced enumeration function with direct parameter configuration
    
    Args:
        domain (str): Target domain to enumerate
        threads (int): Number of threads (default: 10)
        rate_limit (int): Requests per second (default: 10)
        timeout (int): Request timeout in seconds (default: 5)
        bruteforce_retries (int): Brute force retry attempts (default: 2)
        permutation_depth (int): DNS permutation depth (default: 3)
        dns_servers (list): Custom DNS servers for cache snooping (default: None)
        methods (list): Enumeration methods to enable (default: all methods)
        wordlist_file (str): Custom wordlist file path (default: None)
        enable_ai (bool): Enable AI wordlist generation (default: True)
    
    Returns:
        dict: Enumeration results with statistics and found subdomains
    """
    if not domain:
        raise ValueError("Domain parameter is required")
    
    # Set default methods if not provided
    if methods is None:
        methods = ['bruteforce', 'dns_permutations', 'zone_transfer', 'cache_snooping']
    
    # Configure logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    
    # Create configuration object
    config = EnhancedEnumerationConfig()
    
    # Apply parameters to configuration
    config.thread_count = threads
    config.rate_limit = rate_limit
    config.timeout = timeout
    config.bruteforce_retries = bruteforce_retries
    config.permutation_depth = permutation_depth
    config.enabled_methods = methods
    config.wordlist_ai_enabled = enable_ai
    
    # Set custom DNS servers if provided
    if dns_servers:
        config.cache_snoop_dns_servers = dns_servers
    
    # Load custom wordlist if provided
    custom_wordlist = None
    if wordlist_file:
        try:
            # Check if it's an absolute path or just a filename
            if os.path.isabs(wordlist_file):
                wordlist_path = wordlist_file
            else:
                # Construct path to wordlists directory
                base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
                wordlist_path = os.path.join(base_dir, '..', 'config', 'wordlists', wordlist_file)
            
            with open(wordlist_path, 'r') as f:
                custom_wordlist = [line.strip() for line in f if line.strip()]
            logger.info(f"Loaded {len(custom_wordlist)} words from {wordlist_path}")
        except Exception as e:
            logger.error(f"Error loading wordlist: {e}")
            raise
    
    # Create and run enumerator
    enumerator = ConfigurableActiveEnumerator(domain, config)
    results = enumerator.run_comprehensive_enumeration(custom_wordlist)
    
    # Display results
    print(f"\n=== Enumeration Results for {domain} ===")
    print(f"Total subdomains found: {results['statistics']['total_subdomains']}")
    print(f"Execution time: {results['statistics']['total_duration']:.2f} seconds")
    
    for method, subdomains in results['methods'].items():
        print(f"\n{method.upper()}: {len(subdomains)} subdomains")
        for subdomain in sorted(subdomains):
            print(f"  - {subdomain}")
    
    # Save results summary
    if results['errors']:
        print(f"\n=== Errors ===")
        for method, errors in results['errors'].items():
            print(f"{method}: {len(errors)} errors")
    
    return results


def main():
    """Enhanced main function with comprehensive configuration"""
    parser = argparse.ArgumentParser(description="Configurable Active Domain Enumeration")
    parser.add_argument("domain", help="Target domain to enumerate")
    
    # Basic configuration
    parser.add_argument("--threads", type=int, default=10, help="Number of threads")
    parser.add_argument("--rate-limit", type=int, default=10, help="Requests per second")
    parser.add_argument("--timeout", type=int, default=5, help="Request timeout in seconds")
    
    # Method-specific configuration
    parser.add_argument("--bruteforce-retries", type=int, default=2, help="Brute force retry attempts")
    parser.add_argument("--permutation-depth", type=int, default=3, help="DNS permutation depth")
    parser.add_argument("--dns-servers", nargs='+', help="Custom DNS servers for cache snooping")
    
    # Method selection
    parser.add_argument("--methods", nargs='+', 
                       choices=['bruteforce', 'dns_permutations', 'zone_transfer', 'cache_snooping'],
                       default=['bruteforce', 'dns_permutations', 'zone_transfer', 'cache_snooping'],
                       help="Enumeration methods to enable")
    
    # Wordlist options
    parser.add_argument("--wordlist", help="Custom wordlist file")
    parser.add_argument("--no-ai", action='store_true', help="Disable AI wordlist generation")
    
    args = parser.parse_args()
    
    # Configure logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    
    # Create configuration
    config = create_enumeration_config_from_args(args)
    config.wordlist_ai_enabled = not args.no_ai
    
    # Load custom wordlist if provided
    custom_wordlist = None
    if args.wordlist:
        try:
            # Check if it's an absolute path or just a filename
            if os.path.isabs(args.wordlist):
                wordlist_path = args.wordlist
            else:
                # Construct path to wordlists directory
                base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
                wordlist_path = os.path.join(base_dir, '..', 'config', 'wordlists', args.wordlist)
            
            with open(wordlist_path, 'r') as f:
                custom_wordlist = [line.strip() for line in f if line.strip()]
            print(f"Loaded {len(custom_wordlist)} words from {wordlist_path}")
        except Exception as e:
            print(f"Error loading wordlist: {e}")
            return
    
    # Create and run enumerator
    enumerator = ConfigurableActiveEnumerator(args.domain, config)
    results = enumerator.run_comprehensive_enumeration(custom_wordlist)
    
    # Display results
    print(f"\n=== Enumeration Results for {args.domain} ===")
    print(f"Total subdomains found: {results['statistics']['total_subdomains']}")
    print(f"Execution time: {results['statistics']['total_duration']:.2f} seconds")
    
    for method, subdomains in results['methods'].items():
        print(f"\n{method.upper()}: {len(subdomains)} subdomains")
        for subdomain in sorted(subdomains):
            print(f"  - {subdomain}")
    
    # Save results summary
    if results['errors']:
        print(f"\n=== Errors ===")
        for method, errors in results['errors'].items():
            print(f"{method}: {len(errors)} errors")


if __name__ == "__main__":
    main()