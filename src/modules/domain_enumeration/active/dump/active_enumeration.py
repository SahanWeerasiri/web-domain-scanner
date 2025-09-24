#!/usr/bin/env python3
"""
Active Domain Enumeration Module

This module provides active subdomain discovery capabilities using direct probing
techniques. It implements intelligent wordlist generation, brute force attacks,
DNS permutation techniques, and various advanced enumeration methods.

Key Features:
- Intelligent wordlist generation
- Rate-limited brute force attacks
- DNS permutation attacks
- Zone transfer attempts
- DNS cache snooping
- DNS-over-HTTPS fallback
- CDN bypass techniques

Author: Web Domain Scanner Project
License: See LICENSE file in project root
"""

import logging
import time
import socket
import dns.resolver
import requests
import sys
import os
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Set, Optional, TYPE_CHECKING

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

# Import AI Integration module for intelligent wordlist generation
if TYPE_CHECKING:
    from ai_integration import AIIntegration

try:
    from ai_integration import AIIntegration
    AI_AVAILABLE = True
    logger.info("AI Integration module loaded successfully")
except ImportError:
    AI_AVAILABLE = False
    AIIntegration = None  # Set to None for runtime
    logger.warning("AI Integration module not available. Using fallback methods for wordlist generation.")


class ActiveEnumerator:
    """
    Active domain enumeration class focusing on direct probing techniques.
    
    This class implements various active reconnaissance methods including
    brute force attacks, DNS enumeration, and intelligent wordlist generation.
    """
    
    def __init__(self, domain: str, config: EnumerationConfig = None, ai_integration = None):
        """Initialize active enumerator"""
        self.domain = domain.lower().strip()
        self.config = config or EnumerationConfig()
        self.error_handler = EnumerationErrorHandler()
        self.rate_limiter = RateLimiter(self.config.rate_limit)
        
        # Initialize AI integration if available
        self.ai_integration = ai_integration
        if AI_AVAILABLE and not self.ai_integration:
            # Try to create AI integration with environment variables
            api_keys = {
                'gemini_api_key': os.getenv('GEMINI_API_KEY'),
                'openai_api_key': os.getenv('OPENAI_API_KEY'),
                'anthropic_api_key': os.getenv('ANTHROPIC_API_KEY')
            }
            if any(api_keys.values()):
                self.ai_integration = AIIntegration(**{k: v for k, v in api_keys.items() if v})
                logger.info("AI integration initialized for enhanced wordlist generation")
        
        # Set up HTTP session
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                         '(KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        
        logger.info(f"ActiveEnumerator initialized for domain: {self.domain}")
    
    def run_active_enumeration(self, wordlist: List[str] = None, page_content: Dict = None) -> Dict:
        """
        Run comprehensive active enumeration.
        
        Args:
            wordlist: Custom wordlist for brute force. If None, generates dynamic wordlist.
            page_content: Page content from web crawling for AI-enhanced wordlist generation.
            
        Returns:
            Dict: Results from all active enumeration methods
        """
        logger.info("=== Starting Enhanced Active Enumeration ===")
        logger.info(f"Target domain: {self.domain}")
        logger.info(f"Rate limit: {self.config.rate_limit} requests/sec")
        logger.info(f"Timeout: {self.config.timeout} seconds")
        logger.info(f"Thread count: {self.config.thread_count}")
        
        start_time = time.time()
        
        # Generate or use provided wordlist
        if not wordlist:
            logger.info("No wordlist provided, generating dynamic wordlist")
            wordlist = self._generate_dynamic_wordlist(page_content)
        else:
            logger.info(f"Using provided wordlist with {len(wordlist)} entries")
        
        # Multi-method discovery
        methods = {}
        
        try:
            logger.info("--- Starting Brute Force Attack ---")
            bf_start = time.time()
            methods['bruteforce'] = self._bruteforce_with_rate_limiting(wordlist)
            bf_duration = time.time() - bf_start
            logger.info(f"Brute force completed in {bf_duration:.2f}s, found {len(methods['bruteforce'])} subdomains")
            
        except Exception as e:
            logger.error(f"Brute force attack failed: {e}")
            methods['bruteforce'] = []
            self.error_handler.handle_error("bruteforce", e)
        
        try:
            logger.info("--- Starting DNS Permutation Attack ---")
            perm_start = time.time()
            methods['dns_permutations'] = self._dns_permutation_attack()
            perm_duration = time.time() - perm_start
            logger.info(f"DNS permutations completed in {perm_duration:.2f}s, found {len(methods['dns_permutations'])} subdomains")
            
        except Exception as e:
            logger.error(f"DNS permutation attack failed: {e}")
            methods['dns_permutations'] = []
            self.error_handler.handle_error("dns_permutations", e)
        
        try:
            logger.info("--- Attempting DNS Zone Transfer ---")
            zt_start = time.time()
            methods['dns_zone_transfer'] = self._attempt_zone_transfer()
            zt_duration = time.time() - zt_start
            logger.info(f"Zone transfer attempt completed in {zt_duration:.2f}s, found {len(methods['dns_zone_transfer'])} subdomains")
            
        except Exception as e:
            logger.error(f"DNS zone transfer failed: {e}")
            methods['dns_zone_transfer'] = []
            self.error_handler.handle_error("dns_zone_transfer", e)
        
        try:
            logger.info("--- Starting DNS Cache Snooping ---")
            cs_start = time.time()
            methods['dns_cache_snooping'] = self._dns_cache_snooping()
            cs_duration = time.time() - cs_start
            logger.info(f"DNS cache snooping completed in {cs_duration:.2f}s, found {len(methods['dns_cache_snooping'])} subdomains")
            
        except Exception as e:
            logger.error(f"DNS cache snooping failed: {e}")
            methods['dns_cache_snooping'] = []
            self.error_handler.handle_error("dns_cache_snooping", e)
        
        total_duration = time.time() - start_time
        total_found = sum(len(results) for results in methods.values())
        
        logger.info("=== Active Enumeration Summary ===")
        logger.info(f"Total execution time: {total_duration:.2f} seconds")
        logger.info(f"Total subdomains found: {total_found}")
        for method, results in methods.items():
            logger.info(f"  {method}: {len(results)} subdomains")
        
        return methods
    
    def _bruteforce_with_rate_limiting(self, wordlist: List[str]) -> List[str]:
        """Rate-limited brute force with fallback mechanisms"""
        logger.info(f"Starting rate-limited brute force with {len(wordlist)} words")
        
        results = []
        successful_checks = 0
        failed_checks = 0
        
        with ThreadPoolExecutor(max_workers=self.config.thread_count) as executor:
            futures = []
            for word in wordlist:
                if self.config.rate_limiting_enabled:
                    self.rate_limiter.acquire()
                future = executor.submit(self._check_subdomain, word)
                futures.append((word, future))
            
            for word, future in futures:
                try:
                    result = future.result(timeout=self.config.timeout)
                    if result:
                        results.append(result)
                        successful_checks += 1
                        logger.info(f"✓ Found: {result}")
                    else:
                        failed_checks += 1
                        logger.debug(f"✗ Not found: {word}.{self.domain}")
                except Exception as e:
                    failed_checks += 1
                    logger.debug(f"Error in brute force thread for {word}: {e}")
        
        logger.info(f"Brute force summary: {successful_checks} found, {failed_checks} not found")
        return results
    
    def _check_subdomain(self, subdomain: str) -> str:
        """Check if subdomain exists with fallback to DoH"""
        full_domain = f"{subdomain}.{self.domain}"
        
        try:
            # Traditional DNS lookup
            result = socket.gethostbyname(full_domain)
            logger.info(f"Found subdomain: {full_domain} -> {result}")
            return full_domain
        except socket.gaierror as e:
            # Traditional DNS failed, try DNS-over-HTTPS fallback
            if self.config.doh_fallback:
                doh_result = self._doh_query(full_domain)
                if doh_result:
                    logger.info(f"Found subdomain via DoH: {full_domain} -> {doh_result}")
                    return full_domain
                else:
                    logger.debug(f"DoH also failed for {full_domain}")
            else:
                logger.debug(f"Traditional DNS failed for {full_domain}: {e}")
        except Exception as e:
            logger.debug(f"Error checking {full_domain}: {e}")
        return None
    
    def _dns_permutation_attack(self) -> List[str]:
        """Generate and check DNS permutations"""
        logger.info("Starting DNS permutation attack")
        
        results = []
        domain_parts = self.domain.split('.')
        base_name = domain_parts[0] if len(domain_parts) > 1 else self.domain
        
        # Common permutation patterns
        permutation_patterns = [
            # Character substitutions
            f"{base_name}1", f"{base_name}2", f"{base_name}01", f"{base_name}02",
            f"{base_name}-1", f"{base_name}-2", f"{base_name}_1", f"{base_name}_2",
            # Common prefixes/suffixes
            f"new-{base_name}", f"old-{base_name}", f"{base_name}-new", f"{base_name}-old",
            f"test-{base_name}", f"{base_name}-test", f"dev-{base_name}", f"{base_name}-dev",
            f"prod-{base_name}", f"{base_name}-prod", f"stage-{base_name}", f"{base_name}-stage",
            # Environment variations
            f"{base_name}-staging", f"{base_name}-production", f"{base_name}-development",
            # Regional variations
            f"{base_name}-us", f"{base_name}-eu", f"{base_name}-asia", f"{base_name}-uk",
            # Service variations
            f"api-{base_name}", f"{base_name}-api", f"app-{base_name}", f"{base_name}-app"
        ]
        
        logger.info(f"Generated {len(permutation_patterns)} permutation patterns")
        
        # Check each permutation
        with ThreadPoolExecutor(max_workers=self.config.thread_count) as executor:
            futures = []
            for pattern in permutation_patterns:
                if self.config.rate_limiting_enabled:
                    self.rate_limiter.acquire()
                future = executor.submit(self._check_subdomain, pattern)
                futures.append(future)
            
            for future in futures:
                try:
                    result = future.result(timeout=self.config.timeout)
                    if result:
                        results.append(result)
                except Exception as e:
                    logger.debug(f"Error in permutation thread: {e}")
        
        logger.info(f"DNS permutation attack found {len(results)} valid subdomains")
        return results
    
    def _attempt_zone_transfer(self) -> List[str]:
        """Attempt DNS zone transfer"""
        logger.info("Attempting DNS zone transfer")
        try:
            ns_answers = dns.resolver.resolve(self.domain, 'NS')
            nameservers = [str(ns) for ns in ns_answers]
            
            for ns in nameservers:
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(ns, self.domain))
                    subdomains = [name for name in zone.nodes.keys()]
                    logger.info(f"Zone transfer successful from {ns}: {len(subdomains)} records")
                    return [f"{sub}.{self.domain}" for sub in subdomains]
                except Exception:
                    logger.debug(f"Zone transfer failed for {ns}")
                    continue
        except Exception as e:
            logger.warning(f"Zone transfer failed: {e}")
        return []
    
    def _dns_cache_snooping(self) -> List[str]:
        """DNS cache snooping techniques"""
        logger.info("Attempting DNS cache snooping")
        
        results = []
        
        # Common public DNS servers to check
        public_dns_servers = [
            '8.8.8.8',      # Google
            '1.1.1.1',      # Cloudflare
            '208.67.222.222',  # OpenDNS
            '9.9.9.9'       # Quad9
        ]
        
        # Common subdomains to snoop for
        common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'api', 'test', 'dev', 'staging',
            'blog', 'shop', 'support', 'vpn', 'remote', 'portal'
        ]
        
        for dns_server in public_dns_servers:
            try:
                # Create a custom resolver for this DNS server
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [dns_server]
                resolver.timeout = 2
                resolver.lifetime = 5
                
                logger.info(f"Checking DNS cache on server: {dns_server}")
                
                for subdomain in common_subdomains:
                    try:
                        full_domain = f"{subdomain}.{self.domain}"
                        answer = resolver.resolve(full_domain, 'A')
                        if answer:
                            results.append(full_domain)
                            logger.info(f"Found cached subdomain: {full_domain}")
                    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                        continue
                    except Exception as e:
                        logger.debug(f"Error checking {subdomain} on {dns_server}: {e}")
                        
            except Exception as e:
                logger.warning(f"Failed to setup resolver for {dns_server}: {e}")
                continue
        
        # Remove duplicates
        results = list(set(results))
        logger.info(f"DNS cache snooping found {len(results)} potential subdomains")
        return results
    
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
    
    def _generate_dynamic_wordlist(self, page_content: Dict = None) -> List[str]:
        """Generate context-aware wordlists using various techniques including AI"""
        logger.info("Generating dynamic wordlist")
        
        wordlist_sources = {
            'common_subdomains': self._load_common_wordlist(),
            'target_specific': self._generate_target_specific_terms(),
            'permutations': self._generate_permutations()
        }
        
        # Use AI integration if available and page content is provided
        if self.ai_integration and page_content:
            try:
                logger.info("Using AI integration for enhanced wordlist generation")
                ai_terms = self.ai_integration.generate_target_specific_wordlist(
                    page_content=page_content,
                    domain=self.domain,
                    context=f"Active subdomain enumeration for {self.domain}",
                    num_terms=50
                )
                if ai_terms:
                    wordlist_sources['ai_generated'] = ai_terms
                    logger.info(f"AI generated {len(ai_terms)} intelligent subdomain terms")
            except Exception as e:
                logger.warning(f"AI wordlist generation failed: {e}")
                wordlist_sources['llm_generated'] = self._generate_llm_based_terms()
        else:
            # Fallback to rule-based intelligent generation
            wordlist_sources['llm_generated'] = self._generate_llm_based_terms()
        
        return self._merge_wordlists(wordlist_sources)
    
    def _load_common_wordlist(self) -> List[str]:
        """Load common subdomain wordlist"""
        common_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test',
            'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn', 'ns3',
            'mail2', 'new', 'mysql', 'old', 'lists', 'support', 'mobile', 'mx', 'static',
            'docs', 'beta', 'shop', 'sql', 'secure', 'demo', 'cp', 'calendar', 'wiki',
            'web', 'media', 'email', 'images', 'img', 'www1', 'intranet', 'portal', 'video'
        ]
        return common_subdomains
    
    def _generate_target_specific_terms(self) -> List[str]:
        """Generate target-specific terms based on domain analysis"""
        target_terms = []
        
        # Extract meaningful parts from domain
        domain_parts = self.domain.split('.')
        if len(domain_parts) >= 2:
            organization = domain_parts[0]
            
            # Generate variations based on organization name
            variations = [
                f"www{organization}", f"{organization}www",
                f"mail{organization}", f"{organization}mail",
                f"test{organization}", f"{organization}test",
                f"dev{organization}", f"{organization}dev",
                f"staging{organization}", f"{organization}staging"
            ]
            target_terms.extend(variations)
            
            # Add common organizational subdomains
            org_subdomains = [
                'admin', 'portal', 'intranet', 'extranet', 'vpn',
                'remote', 'access', 'login', 'auth', 'sso',
                'ldap', 'directory', 'hr', 'finance', 'it'
            ]
            target_terms.extend(org_subdomains)
        
        return target_terms
    
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
    
    def _generate_permutations(self) -> List[str]:
        """Generate subdomain permutations"""
        logger.info("Generating subdomain permutations")
        
        permutations = []
        domain_parts = self.domain.split('.')
        base_name = domain_parts[0] if len(domain_parts) > 1 else self.domain
        
        # Character manipulation permutations
        char_permutations = []
        
        # Add/remove characters
        if len(base_name) > 3:
            char_permutations.append(base_name[:-1])  # Remove last character
            char_permutations.append(base_name[1:])   # Remove first character
            
        # Add common characters
        for char in ['1', '2', '0', '-', '_']:
            char_permutations.extend([
                f"{base_name}{char}",
                f"{char}{base_name}",
                f"{base_name}{char}{base_name}"
            ])
        
        # Letter substitutions (common typos/variations)
        substitutions = {
            'o': '0', '0': 'o', 'i': '1', '1': 'i', 'l': '1', 
            's': '5', '5': 's', 'e': '3', '3': 'e'
        }
        
        for original, replacement in substitutions.items():
            if original in base_name:
                substituted = base_name.replace(original, replacement)
                char_permutations.append(substituted)
        
        # Common prefix/suffix combinations
        prefixes = ['new', 'old', 'beta', 'alpha', 'test', 'demo', 'temp']
        suffixes = ['new', 'old', 'beta', 'test', 'demo', 'backup', 'temp']
        
        for prefix in prefixes:
            char_permutations.extend([
                f"{prefix}{base_name}",
                f"{prefix}-{base_name}",
                f"{prefix}_{base_name}"
            ])
            
        for suffix in suffixes:
            char_permutations.extend([
                f"{base_name}{suffix}",
                f"{base_name}-{suffix}",
                f"{base_name}_{suffix}"
            ])
        
        # Remove duplicates and invalid entries
        char_permutations = list(set([p for p in char_permutations if p and len(p) > 1]))
        permutations.extend(char_permutations)
        
        logger.info(f"Generated {len(permutations)} character-based permutations")
        return permutations
    
    def _merge_wordlists(self, wordlist_sources: Dict) -> List[str]:
        """Merge and deduplicate wordlists"""
        all_words = set()
        for source_name, words in wordlist_sources.items():
            all_words.update(words)
            logger.info(f"Added {len(words)} words from {source_name}")
        
        final_list = list(all_words)
        logger.info(f"Final merged wordlist contains {len(final_list)} unique entries")
        return final_list
    
    def get_errors(self) -> Dict:
        """Get all errors encountered during active enumeration"""
        return self.error_handler.get_errors()


# Main function for testing
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Active Domain Enumeration")
    parser.add_argument("domain", help="Target domain to enumerate")
    parser.add_argument("--wordlist", help="Custom wordlist file", default=None)
    parser.add_argument("--threads", type=int, default=10, help="Number of threads")
    parser.add_argument("--rate-limit", type=int, default=10, help="Requests per second")
    
    args = parser.parse_args()
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create custom config
    config = EnumerationConfig()
    config.thread_count = args.threads
    config.rate_limit = args.rate_limit
    
    # Load custom wordlist if provided
    custom_wordlist = None
    if args.wordlist:
        try:
            with open(args.wordlist, 'r') as f:
                custom_wordlist = [line.strip() for line in f if line.strip()]
            print(f"Loaded {len(custom_wordlist)} words from {args.wordlist}")
        except Exception as e:
            print(f"Error loading wordlist: {e}")
    
    # Run active enumeration
    enumerator = ActiveEnumerator(args.domain, config)
    results = enumerator.run_active_enumeration(custom_wordlist)
    
    # Extract and display all found subdomains
    all_subdomains = set()
    for method, subdomains in results.items():
        all_subdomains.update(subdomains)
    
    print(f"\n=== Active Enumeration Results for {args.domain} ===")
    print(f"Found {len(all_subdomains)} unique subdomains:")
    for subdomain in sorted(all_subdomains):
        print(f"  - {subdomain}")
    
    # Display method breakdown
    print(f"\n=== Method Breakdown ===")
    for method, subdomains in results.items():
        print(f"{method}: {len(subdomains)} subdomains")
    
    # Display errors if any
    errors = enumerator.get_errors()
    if errors:
        print(f"\n=== Errors Encountered ===")
        for method, error_list in errors.items():
            print(f"{method}: {len(error_list)} errors")