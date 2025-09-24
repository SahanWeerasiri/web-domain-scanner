#!/usr/bin/env python3
"""
Configurable DNS Enumeration Module

This module provides comprehensive DNS record enumeration with full pre-execution configuration.
"""

import logging
import dns.resolver
import sys
import os
from typing import Dict, List, Set, Any, Optional

# Add parent directories to path for imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..')))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
try:
    from modules.domain_enumeration.config import EnumerationConfig
    from modules.domain_enumeration.base import EnumerationErrorHandler, SubdomainValidator
except ImportError:
    from config import EnumerationConfig
    from base import EnumerationErrorHandler, SubdomainValidator

logger = logging.getLogger(__name__)


class DNSEnumerationConfig(EnumerationConfig):
    """Extended configuration for DNS enumeration with method-specific parameters"""
    
    def __init__(self):
        super().__init__()
        
        # DNS Query Configuration
        self.dns_servers = []  # Custom DNS servers (empty = system default)
        self.query_timeout = 5
        self.query_retries = 2
        self.enable_doh = False  # DNS-over-HTTPS
        self.doh_servers = ['https://cloudflare-dns.com/dns-query']
        
        # Record Type Configuration
        self.record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        self.include_parent_domain = True
        self.parent_domain_depth = 2  # How many levels up to check
        
        # Subdomain Extraction Configuration
        self.extract_from_cname = True
        self.extract_from_mx = True
        self.extract_from_ns = True
        self.extract_from_txt = True
        self.txt_analysis_depth = 'basic'  # basic, advanced, deep
        
        # Analysis Configuration
        self.perform_infrastructure_analysis = True
        self.analyze_security_records = True
        self.analyze_txt_records = True
        self.query_additional_records = False
        
        # Performance Configuration
        self.parallel_queries = 5
        self.batch_size = 10
        self.enable_caching = True
        self.cache_ttl = 300  # 5 minutes
        
        # Output Configuration
        self.verbose_output = False
        self.save_raw_records = False
        self.output_format = 'structured'  # structured, minimal, detailed


class ConfigurableDNSEnumerator:
    """
    Enhanced DNS enumerator with comprehensive pre-execution configuration.
    """
    
    def __init__(self, domain: str, config: DNSEnumerationConfig = None, **kwargs):
        """Initialize with full configuration"""
        self.domain = domain.lower().strip()
        self.config = config or DNSEnumerationConfig()
        
        # Apply any keyword argument overrides
        self._apply_config_overrides(kwargs)
        
        self.error_handler = EnumerationErrorHandler()
        self._cache = {} if self.config.enable_caching else None
        
        # Setup custom resolver if DNS servers specified
        self.resolver = self._setup_resolver()
        
        logger.info(f"ConfigurableDNSEnumerator initialized for domain: {self.domain}")
        self._log_configuration()
    
    def _apply_config_overrides(self, kwargs: Dict[str, Any]):
        """Apply configuration overrides from keyword arguments"""
        for key, value in kwargs.items():
            if hasattr(self.config, key):
                setattr(self.config, key, value)
                logger.debug(f"Overridden config.{key} = {value}")
    
    def _log_configuration(self):
        """Log the current configuration"""
        logger.info("=== DNS Enumeration Configuration ===")
        logger.info(f"Domain: {self.domain}")
        logger.info(f"Record types: {', '.join(self.config.record_types)}")
        logger.info(f"DNS servers: {self.config.dns_servers or 'system default'}")
        logger.info(f"Timeout: {self.config.query_timeout}s, Retries: {self.config.query_retries}")
        logger.info(f"Parallel queries: {self.config.parallel_queries}")
        logger.info(f"Parent domain analysis: {self.config.include_parent_domain}")
        logger.info(f"Infrastructure analysis: {self.config.perform_infrastructure_analysis}")
        logger.info("======================================")
    
    def _setup_resolver(self) -> dns.resolver.Resolver:
        """Setup DNS resolver with configured parameters"""
        resolver = dns.resolver.Resolver()
        
        # Configure custom DNS servers if specified
        if self.config.dns_servers:
            resolver.nameservers = self.config.dns_servers
            logger.info(f"Using custom DNS servers: {self.config.dns_servers}")
        
        # Configure timeout and retries
        resolver.timeout = self.config.query_timeout
        resolver.lifetime = self.config.query_timeout * (self.config.query_retries + 1)
        
        return resolver
    
    def run_comprehensive_enumeration(self) -> Dict[str, Any]:
        """
        Run comprehensive DNS enumeration with pre-configured parameters.
        
        Returns:
            Dict containing all results, analysis, and metadata
        """
        import time
        start_time = time.time()
        
        results = {
            'domain': self.domain,
            'timestamp': time.time(),
            'configuration': self._get_config_summary(),
            'dns_records': {},
            'subdomains': set(),
            'analysis': {},
            'statistics': {},
            'errors': {}
        }
        
        try:
            # Step 1: DNS Record Enumeration
            logger.info("=== Starting DNS Record Enumeration ===")
            dns_records = self._enumerate_dns_records()
            results['dns_records'] = dns_records
            
            # Step 2: Subdomain Extraction
            logger.info("=== Extracting Subdomains from DNS Records ===")
            subdomains = self._extract_subdomains(dns_records)
            results['subdomains'] = subdomains
            
            # Step 3: Infrastructure Analysis
            if self.config.perform_infrastructure_analysis:
                logger.info("=== Performing Infrastructure Analysis ===")
                analysis = self._analyze_infrastructure(dns_records)
                results['analysis'] = analysis
            
            # Step 4: Additional Record Queries
            if self.config.query_additional_records and subdomains:
                logger.info("=== Querying Additional Records ===")
                additional = self._query_additional_records(subdomains)
                results['additional_records'] = additional
            
            # Compile statistics
            results['statistics'] = self._compile_statistics(results, start_time)
            results['errors'] = self.error_handler.get_errors()
            
            logger.info("=== DNS Enumeration Completed ===")
            
        except Exception as e:
            logger.error(f"Comprehensive enumeration failed: {e}")
            self.error_handler.handle_error("comprehensive_enumeration", e)
            results['errors']['comprehensive_enumeration'] = [str(e)]
        
        return results
    
    def _enumerate_dns_records(self) -> Dict[str, List[str]]:
        """Enumerate DNS records for target and parent domains"""
        dns_records = {}
        domains_to_check = self._get_domains_to_check()
        
        for domain in domains_to_check:
            logger.info(f"Enumerating DNS records for: {domain}")
            domain_records = self._query_domain_records(domain)
            
            # Merge records into main dictionary
            for record_type, records in domain_records.items():
                if record_type not in dns_records:
                    dns_records[record_type] = []
                dns_records[record_type].extend(records)
        
        # Remove duplicates
        for record_type in dns_records:
            dns_records[record_type] = list(set(dns_records[record_type]))
        
        return dns_records
    
    def _get_domains_to_check(self) -> List[str]:
        """Get list of domains to check based on configuration"""
        domains = [self.domain]
        
        if self.config.include_parent_domain:
            parent_domains = self._get_parent_domains(self.domain, self.config.parent_domain_depth)
            domains.extend(parent_domains)
        
        return list(set(domains))  # Remove duplicates
    
    def _get_parent_domains(self, domain: str, depth: int) -> List[str]:
        """Get parent domains up to specified depth"""
        parent_domains = []
        domain_parts = domain.split('.')
        
        for i in range(1, min(depth + 1, len(domain_parts))):
            parent_domain = '.'.join(domain_parts[i:])
            if len(parent_domain.split('.')) >= 2:  # Ensure valid domain
                parent_domains.append(parent_domain)
                logger.debug(f"Added parent domain: {parent_domain}")
        
        return parent_domains
    
    def _query_domain_records(self, domain: str) -> Dict[str, List[str]]:
        """Query DNS records for a specific domain"""
        domain_records = {}
        
        for record_type in self.config.record_types:
            try:
                records = self._query_record_with_retry(domain, record_type)
                if records:
                    domain_records[record_type] = records
                    if self.config.verbose_output:
                        logger.info(f"Found {len(records)} {record_type} records for {domain}")
                
            except Exception as e:
                error_msg = f"Error querying {record_type} for {domain}: {e}"
                self.error_handler.handle_error(f"dns_query_{record_type}", error_msg)
                logger.debug(error_msg)
        
        return domain_records
    
    def _query_record_with_retry(self, domain: str, record_type: str) -> List[str]:
        """Query DNS record with retry logic"""
        # Check cache first
        cache_key = f"{domain}_{record_type}"
        if self._cache and cache_key in self._cache:
            return self._cache[cache_key]
        
        for attempt in range(self.config.query_retries + 1):
            try:
                records = self._query_single_record(domain, record_type)
                
                # Cache successful results
                if self._cache is not None and records:
                    self._cache[cache_key] = records
                
                return records
                
            except Exception as e:
                if attempt < self.config.query_retries:
                    logger.debug(f"Attempt {attempt + 1} failed for {domain} {record_type}, retrying...")
                    continue
                else:
                    raise e
        
        return []
    
    def _query_single_record(self, domain: str, record_type: str) -> List[str]:
        """Query a single DNS record type"""
        records = []
        
        try:
            answers = self.resolver.resolve(domain, record_type)
            
            for answer in answers:
                record_value = self._clean_record_value(str(answer).strip(), record_type)
                if record_value:
                    records.append(record_value)
                    if self.config.verbose_output:
                        logger.debug(f"{record_type} record for {domain}: {record_value}")
        
        except dns.resolver.NXDOMAIN:
            logger.debug(f"Domain {domain} does not exist (NXDOMAIN)")
        except dns.resolver.NoAnswer:
            logger.debug(f"No {record_type} records found for {domain}")
        except dns.resolver.Timeout:
            logger.warning(f"DNS query timeout for {domain} {record_type}")
        except Exception as e:
            logger.warning(f"DNS query error for {domain} {record_type}: {e}")
            raise e
        
        return records
    
    def _clean_record_value(self, value: str, record_type: str) -> str:
        """Clean DNS record value based on record type"""
        if record_type == 'MX':
            parts = value.split()
            if len(parts) >= 2:
                return parts[1].rstrip('.')
        elif record_type in ['NS', 'CNAME']:
            return value.rstrip('.')
        elif record_type == 'TXT':
            return value.strip('"')
        
        return value
    
    def _extract_subdomains(self, dns_records: Dict[str, List[str]]) -> Set[str]:
        """Extract subdomains from DNS records based on configuration"""
        subdomains = set()
        
        if self.config.extract_from_cname:
            subdomains.update(self._extract_from_cname_records(dns_records.get('CNAME', [])))
        
        if self.config.extract_from_mx:
            subdomains.update(self._extract_from_mx_records(dns_records.get('MX', [])))
        
        if self.config.extract_from_ns:
            subdomains.update(self._extract_from_ns_records(dns_records.get('NS', [])))
        
        if self.config.extract_from_txt:
            subdomains.update(self._extract_from_txt_records(dns_records.get('TXT', [])))
        
        logger.info(f"Extracted {len(subdomains)} subdomains from DNS records")
        return subdomains
    
    def _extract_from_cname_records(self, cname_records: List[str]) -> Set[str]:
        """Extract subdomains from CNAME records"""
        subdomains = set()
        for cname in cname_records:
            if self._is_valid_subdomain(cname):
                subdomains.add(cname)
        return subdomains
    
    def _extract_from_mx_records(self, mx_records: List[str]) -> Set[str]:
        """Extract subdomains from MX records"""
        subdomains = set()
        for mx in mx_records:
            if self._is_valid_subdomain(mx):
                subdomains.add(mx)
        return subdomains
    
    def _extract_from_ns_records(self, ns_records: List[str]) -> Set[str]:
        """Extract subdomains from NS records"""
        subdomains = set()
        for ns in ns_records:
            if self._is_valid_subdomain(ns):
                subdomains.add(ns)
        return subdomains
    
    def _extract_from_txt_records(self, txt_records: List[str]) -> Set[str]:
        """Extract subdomains from TXT records"""
        subdomains = set()
        for txt in txt_records:
            discovered = self._extract_subdomains_from_txt(txt)
            subdomains.update(discovered)
        return subdomains
    
    def _is_valid_subdomain(self, candidate: str) -> bool:
        """Check if candidate is a valid subdomain of target domain"""
        return (isinstance(candidate, str) and 
                self.domain in candidate and 
                SubdomainValidator.is_valid_subdomain(candidate, self.domain))
    
    def _extract_subdomains_from_txt(self, txt_record: str) -> Set[str]:
        """Extract potential subdomains from TXT records"""
        subdomains = set()
        
        if self.config.txt_analysis_depth == 'basic':
            # Basic pattern matching
            words = txt_record.split()
            for word in words:
                if self.domain in word and '.' in word:
                    cleaned = self._clean_txt_word(word)
                    if self._is_valid_subdomain(cleaned):
                        subdomains.add(cleaned)
        
        elif self.config.txt_analysis_depth in ['advanced', 'deep']:
            # Advanced pattern matching with regex and known service patterns
            import re
            
            # Regex patterns for common subdomain formats in TXT records
            patterns = [
                # Standard domain patterns
                rf'(?:^|\s)([a-zA-Z0-9][-a-zA-Z0-9]*\.{re.escape(self.domain)})(?:\s|$)',
                # URL patterns
                rf'https?://([a-zA-Z0-9][-a-zA-Z0-9]*\.{re.escape(self.domain)})',
                # Email patterns
                rf'@([a-zA-Z0-9][-a-zA-Z0-9]*\.{re.escape(self.domain)})',
                # SPF include patterns
                rf'include:([a-zA-Z0-9][-a-zA-Z0-9]*\.{re.escape(self.domain)})',
                # Service verification patterns
                rf'(?:site-verification|domain-verification).*?([a-zA-Z0-9][-a-zA-Z0-9]*\.{re.escape(self.domain)})',
            ]
            
            for pattern in patterns:
                matches = re.finditer(pattern, txt_record, re.IGNORECASE)
                for match in matches:
                    subdomain = match.group(1).lower()
                    if self._is_valid_subdomain(subdomain):
                        subdomains.add(subdomain)
            
            if self.config.txt_analysis_depth == 'deep':
                # Deep analysis: Extract from known service patterns
                service_patterns = {
                    'google': [
                        rf'google-site-verification.*?([a-zA-Z0-9][-a-zA-Z0-9]*\.{re.escape(self.domain)})',
                        rf'_google\._domainkey\.([a-zA-Z0-9][-a-zA-Z0-9]*\.{re.escape(self.domain)})',
                    ],
                    'microsoft': [
                        rf'MS=.*?([a-zA-Z0-9][-a-zA-Z0-9]*\.{re.escape(self.domain)})',
                        rf'selector1\._domainkey\.([a-zA-Z0-9][-a-zA-Z0-9]*\.{re.escape(self.domain)})',
                    ],
                    'facebook': [
                        rf'facebook-domain-verification.*?([a-zA-Z0-9][-a-zA-Z0-9]*\.{re.escape(self.domain)})',
                    ],
                    'adobe': [
                        rf'adobe-idp-site-verification.*?([a-zA-Z0-9][-a-zA-Z0-9]*\.{re.escape(self.domain)})',
                    ],
                    'atlassian': [
                        rf'atlassian-domain-verification.*?([a-zA-Z0-9][-a-zA-Z0-9]*\.{re.escape(self.domain)})',
                    ]
                }
                
                for service, service_patterns_list in service_patterns.items():
                    for pattern in service_patterns_list:
                        matches = re.finditer(pattern, txt_record, re.IGNORECASE)
                        for match in matches:
                            subdomain = match.group(1).lower()
                            if self._is_valid_subdomain(subdomain):
                                subdomains.add(subdomain)
                                logger.debug(f"Found {service} service subdomain: {subdomain}")
                
                # Extract from DKIM selectors
                dkim_pattern = rf'([a-zA-Z0-9][-a-zA-Z0-9]*)\._domainkey\.{re.escape(self.domain)}'
                dkim_matches = re.finditer(dkim_pattern, txt_record, re.IGNORECASE)
                for match in dkim_matches:
                    selector = match.group(1)
                    dkim_subdomain = f"{selector}._domainkey.{self.domain}"
                    if self._is_valid_subdomain(dkim_subdomain):
                        subdomains.add(dkim_subdomain)
                        logger.debug(f"Found DKIM selector subdomain: {dkim_subdomain}")
        
        return subdomains
    
    def _clean_txt_word(self, word: str) -> str:
        """Clean word extracted from TXT record"""
        cleaned = word.lower()
        
        # Remove common prefixes/suffixes
        prefixes = ['http://', 'https://', 'ftp://']
        for prefix in prefixes:
            if cleaned.startswith(prefix):
                cleaned = cleaned[len(prefix):]
        
        # Remove paths and parameters
        separators = ['/', '?', ':', '#']
        for sep in separators:
            if sep in cleaned:
                cleaned = cleaned.split(sep)[0]
        
        return cleaned
    
    def _analyze_infrastructure(self, dns_records: Dict[str, List[str]]) -> Dict[str, Any]:
        """Analyze DNS infrastructure"""
        analysis = {
            'nameservers': dns_records.get('NS', []),
            'mail_servers': dns_records.get('MX', []),
            'ip_addresses': dns_records.get('A', []) + dns_records.get('AAAA', []),
            'cname_chain': dns_records.get('CNAME', [])
        }
        
        if self.config.analyze_txt_records:
            analysis['txt_analysis'] = self._analyze_txt_records(dns_records.get('TXT', []))
        
        if self.config.analyze_security_records:
            analysis['security'] = self._analyze_security_records(dns_records.get('TXT', []))
        
        return analysis
    
    def _analyze_txt_records(self, txt_records: List[str]) -> Dict[str, List[str]]:
        """Analyze TXT records for common configurations"""
        analysis = {
            'spf': [txt for txt in txt_records if txt.lower().startswith('v=spf')],
            'dmarc': [txt for txt in txt_records if txt.lower().startswith('v=dmarc')],
            'dkim': [txt for txt in txt_records if 'dkim' in txt.lower()],
            'verification': [txt for txt in txt_records if any(v in txt.lower() 
                            for v in ['google-site-verification', 'facebook-domain-verification'])],
            'other': []
        }
        
        # Categorize remaining records
        categorized = set()
        for category in ['spf', 'dmarc', 'dkim', 'verification']:
            categorized.update(analysis[category])
        
        analysis['other'] = [txt for txt in txt_records if txt not in categorized]
        
        return analysis
    
    def _analyze_security_records(self, txt_records: List[str]) -> Dict[str, bool]:
        """Analyze security-related DNS configurations"""
        security = {
            'has_spf': any(txt.lower().startswith('v=spf') for txt in txt_records),
            'has_dmarc': any(txt.lower().startswith('v=dmarc') for txt in txt_records),
            'has_dkim': any('dkim' in txt.lower() for txt in txt_records),
            'has_verification': any('verification' in txt.lower() for txt in txt_records)
        }
        return security
    
    def _query_additional_records(self, subdomains: Set[str]) -> Dict[str, Dict[str, List[str]]]:
        """Query additional DNS records for discovered subdomains"""
        additional_records = {}
        
        for subdomain in subdomains:
            subdomain_records = self._query_domain_records(subdomain)
            if subdomain_records:
                additional_records[subdomain] = subdomain_records
        
        return additional_records
    
    def _get_config_summary(self) -> Dict[str, Any]:
        """Get configuration summary for results"""
        return {
            'record_types': self.config.record_types,
            'dns_servers': self.config.dns_servers,
            'timeout': self.config.query_timeout,
            'retries': self.config.query_retries,
            'parent_domain_analysis': self.config.include_parent_domain
        }
    
    def _compile_statistics(self, results: Dict, start_time: float) -> Dict[str, Any]:
        """Compile execution statistics"""
        import time
        total_duration = time.time() - start_time
        
        total_records = sum(len(records) for records in results.get('dns_records', {}).values())
        total_subdomains = len(results.get('subdomains', []))
        
        return {
            'total_duration': total_duration,
            'total_records': total_records,
            'total_subdomains': total_subdomains,
            'record_types_found': list(results.get('dns_records', {}).keys()),
            'completion_time': time.strftime('%Y-%m-%d %H:%M:%S')
        }
    
    def get_errors(self) -> Dict:
        """Get all errors encountered during DNS enumeration"""
        return self.error_handler.get_errors()


def create_dns_config_from_args(args) -> DNSEnumerationConfig:
    """Create DNS configuration from command line arguments"""
    config = DNSEnumerationConfig()
    
    # Basic configuration
    if hasattr(args, 'dns_servers') and args.dns_servers:
        config.dns_servers = args.dns_servers
    
    if hasattr(args, 'timeout'):
        config.query_timeout = args.timeout
    
    if hasattr(args, 'retries'):
        config.query_retries = args.retries
    
    # Record type configuration
    if hasattr(args, 'record_types') and args.record_types:
        config.record_types = args.record_types
    
    if hasattr(args, 'no_parent_domain'):
        config.include_parent_domain = not args.no_parent_domain
    
    # Analysis configuration
    if hasattr(args, 'no_analysis'):
        config.perform_infrastructure_analysis = not args.no_analysis
    
    if hasattr(args, 'additional_records'):
        config.query_additional_records = args.additional_records
    
    # TXT analysis configuration
    if hasattr(args, 'txt_analysis'):
        config.txt_analysis_depth = args.txt_analysis
    
    # Output configuration
    if hasattr(args, 'verbose'):
        config.verbose_output = args.verbose
    
    return config

def execute_dns_enumeration(domain, 
                               dns_servers=None,
                               timeout=5,
                               retries=2,
                               record_types=None,
                               include_parent_domain=True,
                               perform_analysis=True,
                               query_additional_records=False,
                               verbose=False,
                               txt_analysis_depth='basic'):
    """Enhanced DNS enumeration function with direct parameter configuration
    
    Args:
        domain (str): Target domain to enumerate
        dns_servers (list): Custom DNS servers to use (default: None)
        timeout (int): DNS query timeout in seconds (default: 5)
        retries (int): Number of retry attempts (default: 2)
        record_types (list): DNS record types to query (default: all types)
        include_parent_domain (bool): Enable parent domain analysis (default: True)
        perform_analysis (bool): Enable infrastructure analysis (default: True)
        query_additional_records (bool): Query additional records for found subdomains (default: False)
        verbose (bool): Enable verbose output (default: False)
        txt_analysis_depth (str): TXT record analysis depth - 'basic', 'advanced', or 'deep' (default: 'basic')
    
    Returns:
        dict: DNS enumeration results with records, subdomains, and analysis
    """
    if not domain:
        raise ValueError("Domain parameter is required")
    
    # Set default record types if not provided
    if record_types is None:
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO if not verbose else logging.DEBUG,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    # Create configuration object
    config = DNSEnumerationConfig()
    
    # Apply parameters to configuration
    if dns_servers:
        config.dns_servers = dns_servers
    config.query_timeout = timeout
    config.query_retries = retries
    config.record_types = record_types
    config.include_parent_domain = include_parent_domain
    config.perform_infrastructure_analysis = perform_analysis
    config.query_additional_records = query_additional_records
    config.verbose_output = verbose
    config.txt_analysis_depth = txt_analysis_depth
    
    # Create and run enumerator
    enumerator = ConfigurableDNSEnumerator(domain, config)
    results = enumerator.run_comprehensive_enumeration()
    
    # Display results based on configuration
    _display_results(results, config)
    
    return results

def main():
    """Enhanced main function with comprehensive configuration"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Configurable DNS Domain Enumeration")
    parser.add_argument("domain", help="Target domain to enumerate")
    
    # DNS Configuration
    parser.add_argument("--dns-servers", nargs='+', help="Custom DNS servers to use")
    parser.add_argument("--timeout", type=int, default=5, help="DNS query timeout in seconds")
    parser.add_argument("--retries", type=int, default=2, help="Number of retry attempts")
    
    # Record Type Configuration
    parser.add_argument("--record-types", nargs='+', 
                       choices=['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA'],
                       default=['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA'],
                       help="DNS record types to query")
    
    # Analysis Configuration
    parser.add_argument("--no-parent-domain", action='store_true', 
                       help="Disable parent domain analysis")
    parser.add_argument("--no-analysis", action='store_true', 
                       help="Disable infrastructure analysis")
    parser.add_argument("--additional-records", action='store_true',
                       help="Query additional records for found subdomains")
    
    # TXT Analysis Configuration
    parser.add_argument("--txt-analysis", choices=['basic', 'advanced', 'deep'], 
                       default='basic', help="TXT record analysis depth")
    parser.add_argument("--deep", action='store_const', const='deep', dest='txt_analysis',
                       help="Enable deep TXT record analysis (same as --txt-analysis deep)")
    parser.add_argument("--advanced", action='store_const', const='advanced', dest='txt_analysis',
                       help="Enable advanced TXT record analysis (same as --txt-analysis advanced)")
    
    # Output Configuration
    parser.add_argument("--verbose", action='store_true', help="Enable verbose output")
    
    args = parser.parse_args()
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO if not args.verbose else logging.DEBUG,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    # Create configuration from arguments
    config = create_dns_config_from_args(args)
    
    # Create and run enumerator
    enumerator = ConfigurableDNSEnumerator(args.domain, config)
    results = enumerator.run_comprehensive_enumeration()
    
    # Display results based on configuration
    _display_results(results, config)


def _display_results(results: Dict, config: DNSEnumerationConfig):
    """Display results based on configuration"""
    print(f"\n=== DNS Enumeration Results for {results['domain']} ===")
    print(f"Execution time: {results['statistics']['total_duration']:.2f} seconds")
    print(f"Total records: {results['statistics']['total_records']}")
    print(f"Total subdomains: {results['statistics']['total_subdomains']}")
    
    # Display DNS records
    if config.output_format != 'minimal':
        print(f"\n=== DNS Records ===")
        for record_type, records in results['dns_records'].items():
            print(f"{record_type} ({len(records)} records):")
            for record in records[:10]:  # Show first 10 records
                print(f"  - {record}")
            if len(records) > 10:
                print(f"  ... and {len(records) - 10} more")
    
    # Display subdomains
    subdomains = results.get('subdomains', set())
    if subdomains:
        print(f"\n=== Discovered Subdomains ===")
        for subdomain in sorted(subdomains):
            print(f"  - {subdomain}")
    
    # Display analysis if performed
    if config.perform_infrastructure_analysis:
        analysis = results.get('analysis', {})
        if analysis:
            print(f"\n=== Infrastructure Analysis ===")
            if analysis.get('nameservers'):
                print(f"Nameservers: {len(analysis['nameservers'])}")
            if analysis.get('mail_servers'):
                print(f"Mail Servers: {len(analysis['mail_servers'])}")
            
            security = analysis.get('security', {})
            if security:
                print(f"\nSecurity Configuration:")
                for key, value in security.items():
                    print(f"  {key}: {'Yes' if value else 'No'}")
    
    # Display errors if any
    errors = results.get('errors', {})
    if errors:
        print(f"\n=== Errors ===")
        for method, error_list in errors.items():
            print(f"{method}: {len(error_list)} errors")


if __name__ == "__main__":
    main()