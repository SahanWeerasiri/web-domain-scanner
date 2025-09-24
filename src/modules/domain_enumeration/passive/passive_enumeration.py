#!/usr/bin/env python3
"""
Configurable Passive Domain Enumeration Module

This module provides passive subdomain discovery with full pre-execution configuration.
"""

import logging
import time
import requests
import os
import sys
from typing import Dict, List, Set, Optional, Any
from urllib.parse import urlparse
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

# Import AI Integration module
try:
    from ai_integration import AIIntegration
    AI_AVAILABLE = True
except ImportError:
    AI_AVAILABLE = False
    AIIntegration = None

logger = logging.getLogger(__name__)


class PassiveEnumerationConfig(EnumerationConfig):
    """Extended configuration for passive enumeration with method-specific parameters"""
    
    def __init__(self):
        super().__init__()
        
        # Source Configuration
        self.enabled_sources = [
            'certificate_transparency'
            # 'ssl_certificates',        # TODO: Implement SSL certificate sources
            # 'wayback_machine',         # TODO: Fix Wayback Machine API issues
            # 'threat_intelligence',     # TODO: Implement threat intelligence sources  
            # 'dns_history',            # TODO: Implement DNS history sources
            # 'additional_sources'      # TODO: Implement additional sources
        ]
        
        # Certificate Transparency Configuration
        self.ct_sources = [
            'crt_sh', 'google_ct', 'certspotter', 'facebook_ct', 
            'censys_ct', 'entrust_ct', 'spyse_ct'
        ]
        self.ct_timeout = 10
        self.ct_retries = 2
        self.ct_include_expired = True
        self.ct_include_subdomains = True
        
        # SSL Certificate Configuration
        self.ssl_sources = ['virustotal', 'censys', 'shodan']
        self.ssl_api_keys = {
            'virustotal': os.getenv('VIRUSTOTAL_API_KEY'),
            'censys': os.getenv('CENSYS_API_KEY'),
            'shodan': os.getenv('SHODAN_API_KEY')
        }
        self.ssl_timeout = 15
        self.ssl_max_results = 1000
        
        # Wayback Machine Configuration (Currently disabled - API issues)
        self.wayback_enabled = False  # TODO: Fix Wayback Machine API endpoint
        self.wayback_timeout = 20
        self.wayback_max_pages = 100
        self.wayback_collapse_urls = True
        
        # Threat Intelligence Configuration
        self.threat_intel_sources = ['alienvault', 'threatcrowd', 'securitytrails']
        self.threat_intel_api_keys = {
            'alienvault': os.getenv('ALIENVAULT_API_KEY'),
            'securitytrails': os.getenv('SECURITYTRAILS_API_KEY')
        }
        
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
    Enhanced passive enumerator with comprehensive pre-execution configuration.
    """
    
    def __init__(self, domain: str, config: PassiveEnumerationConfig = None, 
                 ai_integration = None, **kwargs):
        """Initialize with full configuration"""
        self.domain = domain.lower().strip()
        self.config = config or PassiveEnumerationConfig()
        
        # Apply any keyword argument overrides
        self._apply_config_overrides(kwargs)
        
        self.error_handler = EnumerationErrorHandler()
        self.ai_integration = ai_integration
        
        # Setup HTTP session with configured parameters
        self.session = self._setup_http_session()
        
        logger.info(f"ConfigurablePassiveEnumerator initialized for domain: {self.domain}")
        self._log_configuration()
    
    def _apply_config_overrides(self, kwargs: Dict[str, Any]):
        """Apply configuration overrides from keyword arguments"""
        for key, value in kwargs.items():
            if hasattr(self.config, key):
                setattr(self.config, key, value)
                logger.debug(f"Overridden config.{key} = {value}")
    
    def _log_configuration(self):
        """Log the current configuration"""
        logger.info("=== Passive Enumeration Configuration ===")
        logger.info(f"Domain: {self.domain}")
        logger.info(f"Enabled sources: {', '.join(self.config.enabled_sources)}")
        logger.info(f"CT sources: {len(self.config.ct_sources)}")
        logger.info(f"SSL sources: {len(self.config.ssl_sources)}")
        logger.info(f"Max concurrent requests: {self.config.max_concurrent_requests}")
        logger.info(f"Request delay: {self.config.request_delay}s")
        logger.info("==========================================")
    
    def _setup_http_session(self) -> requests.Session:
        """Setup HTTP session with configured parameters"""
        session = requests.Session()
        
        # Configure headers
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                         '(KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'application/json,text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        })
        
        # Configure retry strategy
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry
        
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        
        adapter = HTTPAdapter(
            max_retries=retry_strategy, 
            pool_connections=self.config.max_concurrent_requests,
            pool_maxsize=self.config.max_concurrent_requests * 2
        )
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        return session
    
    def run_comprehensive_enumeration(self) -> Dict[str, Any]:
        """
        Run comprehensive passive enumeration with pre-configured parameters.
        
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
            # Execute enabled sources
            for source in self.config.enabled_sources:
                source_start = time.time()
                try:
                    if source == 'certificate_transparency':
                        results['sources'][source] = self._execute_ct_enumeration()
                    elif source == 'ssl_certificates':
                        results['sources'][source] = self._execute_ssl_enumeration()
                    elif source == 'wayback_machine':
                        results['sources'][source] = self._execute_wayback_enumeration()
                    elif source == 'threat_intelligence':
                        results['sources'][source] = self._execute_threat_intel_enumeration()
                    elif source == 'dns_history':
                        results['sources'][source] = self._execute_dns_history_enumeration()
                    elif source == 'additional_sources':
                        results['sources'][source] = self._execute_additional_sources_enumeration()
                    
                    source_duration = time.time() - source_start
                    logger.info(f"{source}: completed in {source_duration:.2f}s")
                    
                except Exception as e:
                    logger.error(f"Source {source} failed: {e}")
                    self.error_handler.handle_error(source, e)
                    results['sources'][source] = {'error': str(e), 'subdomains': []}
            
            # Extract all subdomains
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
    
    def _execute_ct_enumeration(self) -> Dict[str, Any]:
        """Execute certificate transparency enumeration with configured parameters"""
        logger.info("Executing Certificate Transparency enumeration")
        
        ct_results = {}
        successful_sources = 0
        
        for ct_source in self.config.ct_sources:
            try:
                if self.config.request_delay > 0:
                    time.sleep(self.config.request_delay)
                
                if ct_source == 'crt_sh':
                    ct_results[ct_source] = self._query_crtsh_enhanced()
                elif ct_source == 'google_ct':
                    ct_results[ct_source] = self._query_google_ct()
                elif ct_source == 'certspotter':
                    ct_results[ct_source] = self._query_certspotter()
                elif ct_source == 'facebook_ct':
                    ct_results[ct_source] = self._query_facebook_ct()
                elif ct_source == 'censys_ct':
                    ct_results[ct_source] = self._query_censys_ct()
                elif ct_source == 'entrust_ct':
                    ct_results[ct_source] = self._query_entrust_ct()
                # elif ct_source == 'hackertarget':
                #     ct_results[ct_source] = self._query_hackertarget_ct()
                elif ct_source == 'spyse_ct':
                    ct_results[ct_source] = self._query_spyse_ct()
                
                if ct_results[ct_source].get('subdomains'):
                    successful_sources += 1
                    logger.debug(f"CT source {ct_source} contributed subdomains")
                    
            except Exception as e:
                logger.warning(f"CT source {ct_source} failed: {e}")
                ct_results[ct_source] = {'error': str(e), 'subdomains': []}
        
        logger.info(f"CT enumeration: {successful_sources}/{len(self.config.ct_sources)} sources successful")
        return ct_results
    
    def _execute_ssl_enumeration(self) -> Dict[str, Any]:
        """Execute SSL certificate enumeration with configured parameters"""
        logger.info("Executing SSL certificate enumeration")
        
        ssl_results = {}
        successful_sources = 0
        
        for ssl_source in self.config.ssl_sources:
            try:
                if self.config.request_delay > 0:
                    time.sleep(self.config.request_delay)
                
                if ssl_source == 'virustotal':
                    ssl_results[ssl_source] = self._query_virustotal_certs()
                elif ssl_source == 'censys':
                    ssl_results[ssl_source] = self._query_censys()
                elif ssl_source == 'shodan':
                    ssl_results[ssl_source] = self._query_shodan()
                
                if ssl_results[ssl_source].get('subdomains'):
                    successful_sources += 1
                    
            except Exception as e:
                logger.warning(f"SSL source {ssl_source} failed: {e}")
                ssl_results[ssl_source] = {'error': str(e), 'subdomains': []}
        
        logger.info(f"SSL enumeration: {successful_sources}/{len(self.config.ssl_sources)} sources successful")
        return ssl_results
    
    def _execute_wayback_enumeration(self) -> Dict[str, Any]:
        """Execute Wayback Machine enumeration with configured parameters"""
        if not self.config.wayback_enabled:
            return {'subdomains': [], 'disabled': True}
        
        logger.info("Executing Wayback Machine enumeration")
        
        try:
            return self._query_wayback_machine_enhanced()
        except Exception as e:
            logger.error(f"Wayback Machine enumeration failed: {e}")
            return {'error': str(e), 'subdomains': []}
    
    def _execute_threat_intel_enumeration(self) -> Dict[str, Any]:
        """Execute threat intelligence enumeration with configured parameters"""
        logger.info("Executing threat intelligence enumeration")
        
        threat_results = {}
        
        for threat_source in self.config.threat_intel_sources:
            try:
                if self.config.request_delay > 0:
                    time.sleep(self.config.request_delay)
                
                if threat_source == 'alienvault':
                    threat_results[threat_source] = self._query_alienvault()
                elif threat_source == 'threatcrowd':
                    threat_results[threat_source] = self._query_threatcrowd()
                elif threat_source == 'securitytrails':
                    threat_results[threat_source] = self._query_securitytrails()
                    
            except Exception as e:
                logger.warning(f"Threat intel source {threat_source} failed: {e}")
                threat_results[threat_source] = {'error': str(e), 'subdomains': []}
        
        return threat_results
    
    def _execute_dns_history_enumeration(self) -> Dict[str, Any]:
        """Execute DNS history enumeration with configured parameters"""
        logger.info("Executing DNS history enumeration")
        
        dns_history_results = {}
        
        for history_source in self.config.dns_history_sources:
            try:
                if self.config.request_delay > 0:
                    time.sleep(self.config.request_delay)
                
                if history_source == 'whois_history':
                    dns_history_results[history_source] = self._query_whois_history()
                elif history_source == 'dnsdb':
                    dns_history_results[history_source] = self._query_dnsdb()
                elif history_source == 'passive_dns':
                    dns_history_results[history_source] = self._query_passive_dns()
                    
            except Exception as e:
                logger.warning(f"DNS history source {history_source} failed: {e}")
                dns_history_results[history_source] = {'error': str(e), 'subdomains': []}
        
        return dns_history_results
    
    def _execute_additional_sources_enumeration(self) -> Dict[str, Any]:
        """Execute additional sources enumeration with configured parameters"""
        logger.info("Executing additional sources enumeration")
        
        additional_results = {}
        
        for additional_source in self.config.additional_sources:
            try:
                if self.config.request_delay > 0:
                    time.sleep(self.config.request_delay)
                
                if additional_source == 'dnsdumpster':
                    additional_results[additional_source] = self._query_dnsdumpster_ct()
                elif additional_source == 'rapiddns':
                    additional_results[additional_source] = self._query_rapid_dns()
                elif additional_source == 'sublist3r':
                    additional_results[additional_source] = self._query_sublist3r_sources()
                elif additional_source == 'threatminer':
                    additional_results[additional_source] = self._query_threatminer()
                    
            except Exception as e:
                logger.warning(f"Additional source {additional_source} failed: {e}")
                additional_results[additional_source] = {'error': str(e), 'subdomains': []}
        
        return additional_results
    
    # Enhanced query methods with configuration support
    def _query_crtsh_enhanced(self) -> Dict[str, Any]:
        """Enhanced crt.sh query with comprehensive certificate analysis"""
        logger.info("Querying crt.sh (enhanced with certificate details)")
        
        subdomains = set()
        certificate_details = {}
        
        # Step 1: Get general certificate list
        approaches = [
            {'url': f"https://crt.sh/?q=%.{self.domain}&output=json", 'desc': "wildcard"},
            {'url': f"https://crt.sh/?q={self.domain}&output=json", 'desc': "exact"},
        ]
        
        certificate_entries = []
        
        for approach in approaches:
            try:
                logger.debug(f"Trying crt.sh {approach['desc']} approach: {approach['url']}")
                response = self.session.get(approach['url'], timeout=self.config.ct_timeout)
                
                if response.status_code == 200 and response.text.strip():
                    try:
                        data = response.json()
                        if data:  # Ensure we got valid data
                            certificate_entries = data
                            logger.info(f"crt.sh {approach['desc']}: Found {len(certificate_entries)} certificates")
                            break  # Success with this approach
                    except ValueError as json_error:
                        logger.debug(f"JSON parsing failed for {approach['desc']}: {json_error}")
                        continue
                else:
                    logger.debug(f"crt.sh {approach['desc']}: HTTP {response.status_code}")
                    
            except Exception as e:
                logger.debug(f"crt.sh {approach['desc']} approach failed: {e}")
                continue
        
        if not certificate_entries:
            logger.warning("No certificate entries found from crt.sh")
            return {'subdomains': [], 'certificates': {}, 'source': 'crt.sh', 'error': 'No certificates found'}
        
        # Step 2: Extract subdomains from certificate list
        valid_certificate_ids = []
        
        for entry in certificate_entries:
            if isinstance(entry, dict) and 'name_value' in entry:
                # Extract subdomains from name_value field
                names = entry['name_value'].split('\n')
                for name in names:
                    name = name.strip().lower().lstrip('*.')
                    if name and self.domain in name:
                        if SubdomainValidator.is_valid_subdomain(name, self.domain):
                            subdomains.add(name)
                
                # Collect certificate ID for detailed analysis
                if 'id' in entry:
                    valid_certificate_ids.append(entry['id'])
        
        # Step 3: Get detailed information from the most recent/top certificate
        if valid_certificate_ids and len(valid_certificate_ids) > 0:
            # Get details from the first (most recent) certificate
            top_cert_id = valid_certificate_ids[0]
            logger.info(f"Getting detailed information for certificate ID: {top_cert_id}")
            
            try:
                cert_detail_url = f"https://crt.sh/?id={top_cert_id}"
                detail_response = self.session.get(cert_detail_url, timeout=self.config.ct_timeout)
                
                if detail_response.status_code == 200:
                    # Parse HTML response for comprehensive certificate details
                    cert_html = detail_response.text
                    import re
                    
                    # Debug: Log a portion of the HTML content
                    logger.debug(f"Certificate HTML length: {len(cert_html)} chars")
                    # Find key sections for debugging
                    if "Certificate Transparency" in cert_html:
                        logger.debug("Found Certificate Transparency section")
                    if "Subject Alternative Name" in cert_html:
                        logger.debug("Found Subject Alternative Name section")
                    
                    # Initialize certificate details structure
                    cert_info = {
                        'id': top_cert_id,
                        'detail_url': cert_detail_url,
                        'ct_logs': [],
                        'certificate_data': {},
                        'subject_alternative_names': [],
                        'additional_domains_found': 0
                    }
                    
                    # Extract CT Log entries with more flexible pattern
                    ct_log_patterns = [
                        r'<TD>([0-9-]+)&nbsp;\s*<FONT[^>]*>([0-9:]+\s+UTC)</FONT></TD>\s*<TD>([0-9]+)</TD>\s*<TD>([^<]+)</TD>\s*<TD>([^<]+)</TD>',
                        r'(\d{4}-\d{2}-\d{2})\s+<FONT[^>]*>(\d{2}:\d{2}:\d{2}\s+UTC)</FONT></TD>\s*<TD>(\d+)</TD>\s*<TD>([^<]+)</TD>\s*<TD>([^<]+)</TD>'
                    ]
                    
                    for pattern in ct_log_patterns:
                        ct_matches = re.findall(pattern, cert_html, re.IGNORECASE | re.DOTALL)
                        for match in ct_matches:
                            ct_entry = {
                                'date': match[0].strip(),
                                'time': match[1].strip(), 
                                'entry_number': match[2].strip(),
                                'log_operator': match[3].strip(),
                                'log_url': match[4].strip()
                            }
                            cert_info['ct_logs'].append(ct_entry)
                        if ct_matches:
                            break  # Use first pattern that works
                    
                    # If no matches with structured patterns, try a simpler approach
                    if not cert_info['ct_logs']:
                        # Look for Google, Sectigo, DigiCert, etc. patterns
                        simple_ct_pattern = r'<TD>([^<]+)</TD>\s*<TD>([^<]+)</TD>\s*<TD>(Google|Sectigo|DigiCert|Geomys|Let\'s Encrypt|IPng Networks)</TD>'
                        simple_matches = re.findall(simple_ct_pattern, cert_html, re.IGNORECASE)
                        for i, match in enumerate(simple_matches):
                            ct_entry = {
                                'date': 'N/A',
                                'time': 'N/A', 
                                'entry_number': match[1].strip() if match[1].isdigit() else str(i+1),
                                'log_operator': match[2].strip(),
                                'log_url': 'N/A'
                            }
                            cert_info['ct_logs'].append(ct_entry)
                    
                    logger.debug(f"Found {len(cert_info['ct_logs'])} CT log entries")
                    
                    # Extract certificate validity period
                    validity_pattern = r'Not Before:\s*([^<\n]+).*?Not After\s*:\s*([^<\n]+)'
                    validity_match = re.search(validity_pattern, cert_html, re.DOTALL)
                    if validity_match:
                        cert_info['certificate_data']['not_before'] = validity_match.group(1).strip()
                        cert_info['certificate_data']['not_after'] = validity_match.group(2).strip()
                    
                    # Extract issuer information
                    issuer_pattern = r'organizationName\s*=\s*([^<\n]+)'
                    issuer_match = re.search(issuer_pattern, cert_html)
                    if issuer_match:
                        cert_info['certificate_data']['issuer'] = issuer_match.group(1).strip()
                    
                    # Extract Subject Alternative Names (SANs) with multiple patterns
                    san_patterns = [
                        r'X509v3\s+Subject\s+Alternative\s+Name:.*?DNS:([^<\n]+)',
                        r'Subject\s+Alternative\s+Name:.*?DNS:([^<\n]+)',
                        r'DNS:([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*)',
                    ]
                    
                    for san_pattern in san_patterns:
                        san_matches = re.findall(san_pattern, cert_html, re.DOTALL | re.IGNORECASE)
                        for san in san_matches:
                            if isinstance(san, tuple):
                                clean_domain = san[0].strip()
                            else:
                                clean_domain = san.strip()
                            
                            # Handle multiple domains separated by commas
                            san_domains = clean_domain.split(',')
                            for domain in san_domains:
                                domain = domain.strip().replace('DNS:', '').strip()
                                if domain and SubdomainValidator.is_valid_subdomain(domain, self.domain):
                                    cert_info['subject_alternative_names'].append(domain)
                                    subdomains.add(domain)
                        if san_matches:
                            break  # Use first pattern that works
                    
                    # Extract certificate fingerprints
                    sha256_pattern = r'SHA-256</TH>\s*<TD><A[^>]*>([A-F0-9]+)</A></TD>'
                    sha1_pattern = r'SHA-1</TH>\s*<TD>([A-F0-9]+)</TD>'
                    
                    sha256_match = re.search(sha256_pattern, cert_html)
                    if sha256_match:
                        cert_info['certificate_data']['sha256_fingerprint'] = sha256_match.group(1).strip()
                    
                    sha1_match = re.search(sha1_pattern, cert_html)
                    if sha1_match:
                        cert_info['certificate_data']['sha1_fingerprint'] = sha1_match.group(1).strip()
                    
                    # Extract common name from subject
                    cn_pattern = r'commonName\s*=\s*([^<\n]+)'
                    cn_match = re.search(cn_pattern, cert_html)
                    if cn_match:
                        cert_info['certificate_data']['common_name'] = cn_match.group(1).strip()
                    
                    # Look for additional domain patterns in the entire certificate content
                    domain_patterns = [
                        rf'([a-zA-Z0-9]([a-zA-Z0-9\-]{{0,61}}[a-zA-Z0-9])?\.{re.escape(self.domain)})',
                        rf'(\*\.{re.escape(self.domain)})',  # Wildcard certificates
                    ]
                    
                    for pattern in domain_patterns:
                        matches = re.findall(pattern, cert_html, re.IGNORECASE)
                        for match in matches:
                            if isinstance(match, tuple):
                                domain_name = match[0].lower()
                            else:
                                domain_name = match.lower()
                            
                            # Clean wildcard notation
                            domain_name = domain_name.lstrip('*.')
                            
                            if domain_name and SubdomainValidator.is_valid_subdomain(domain_name, self.domain):
                                subdomains.add(domain_name)
                    
                    # Calculate additional domains found from certificate analysis
                    original_subdomains = set()
                    for entry in certificate_entries[:5]:  # Check first 5 entries
                        if isinstance(entry, dict) and 'name_value' in entry:
                            names = entry['name_value'].split('\n')
                            for name in names:
                                name = name.strip().lower().lstrip('*.')
                                if name and self.domain in name:
                                    original_subdomains.add(name)
                    
                    cert_info['additional_domains_found'] = len(subdomains - original_subdomains)
                    
                    certificate_details[top_cert_id] = cert_info
                    
                    logger.info(f"Certificate {top_cert_id} comprehensive analysis completed")
                    logger.debug(f"Found {len(cert_info['ct_logs'])} CT logs, {len(cert_info['subject_alternative_names'])} SANs")
                    
            except Exception as e:
                logger.debug(f"Failed to get certificate details for ID {top_cert_id}: {e}")
                certificate_details[top_cert_id] = {'error': str(e)}
        
        logger.info(f"crt.sh enhanced query completed: {len(subdomains)} subdomains found")
        
        return {
            'subdomains': list(subdomains), 
            'source': 'crt.sh',
            'certificates': certificate_details,
            'total_certificates': len(certificate_entries),
            'analyzed_certificate_id': valid_certificate_ids[0] if valid_certificate_ids else None
        }
    
    def _query_virustotal_certs(self) -> Dict[str, Any]:
        """Query VirusTotal with API key validation"""
        api_key = self.config.ssl_api_keys.get('virustotal')
        
        if not api_key:
            return {'subdomains': [], 'error': 'VirusTotal API key not configured'}
        
        try:
            url = "https://www.virustotal.com/vtapi/v2/domain/report"
            params = {'apikey': api_key, 'domain': self.domain}
            
            response = self.session.get(url, params=params, timeout=self.config.ssl_timeout)
            
            if response.status_code == 200:
                data = response.json()
                subdomains = set()
                
                if 'subdomains' in data:
                    for subdomain in data['subdomains']:
                        full_domain = f"{subdomain}.{self.domain}"
                        if SubdomainValidator.is_valid_subdomain(full_domain, self.domain):
                            subdomains.add(full_domain)
                
                return {'subdomains': list(subdomains), 'source': 'virustotal'}
            else:
                return {'subdomains': [], 'error': f"HTTP {response.status_code}"}
                
        except Exception as e:
            return {'subdomains': [], 'error': str(e)}
    
    def _query_wayback_machine_enhanced(self) -> Dict[str, Any]:
        """Enhanced Wayback Machine query with configuration"""
        try:
            url = f"http://web.archive.org/cdx/search/cdx"
            params = {
                'url': f"*.{self.domain}",
                'output': 'json',
                'fl': 'original',
                'collapse': 'urlkey' if self.config.wayback_collapse_urls else None,
                'page': self.config.wayback_max_pages
            }
            
            response = self.session.get(url, params=params, timeout=self.config.wayback_timeout)
            
            subdomains = set()
            if response.status_code == 200:
                data = response.json()
                for entry in data[1:]:  # Skip header
                    if entry and entry[0]:
                        archived_url = entry[0]
                        subdomain = SubdomainValidator.extract_subdomain_from_url(archived_url, self.domain)
                        if subdomain:
                            subdomains.add(subdomain)
            
            return {'subdomains': list(subdomains), 'source': 'wayback_machine'}
            
        except Exception as e:
            return {'subdomains': [], 'error': str(e)}
    
    # TODO: Implement additional sources - Currently commented out
    # 
    # # SSL Certificate Sources
    # def _query_censys(self) -> Dict[str, Any]:
    #     return {'subdomains': [], 'error': 'Censys not implemented'}
    # 
    # def _query_shodan(self) -> Dict[str, Any]:
    #     return {'subdomains': [], 'error': 'Shodan not implemented'}
    # 
    # # Additional Certificate Transparency Sources
    # def _query_certspotter(self) -> Dict[str, Any]:
    #     return {'subdomains': [], 'error': 'CertSpotter not implemented'}
    # 
    # def _query_google_ct(self) -> Dict[str, Any]:
    #     return {'subdomains': [], 'error': 'Google CT not implemented'}
    # 
    # def _query_facebook_ct(self) -> Dict[str, Any]:
    #     return {'subdomains': [], 'error': 'Facebook CT not implemented'}
    # 
    # def _query_censys_ct(self) -> Dict[str, Any]:
    #     return {'subdomains': [], 'error': 'Censys CT not implemented'}
    # 
    # def _query_entrust_ct(self) -> Dict[str, Any]:
    #     return {'subdomains': [], 'error': 'Entrust CT not implemented'}
    # 
    # def _query_hackertarget_ct(self) -> Dict[str, Any]:
    #     return {'subdomains': [], 'error': 'HackerTarget not implemented'}
    # 
    # def _query_spyse_ct(self) -> Dict[str, Any]:
    #     return {'subdomains': [], 'error': 'Spyse not implemented'}
    # 
    # # Threat Intelligence Sources
    # def _query_alienvault(self) -> Dict[str, Any]:
    #     return {'subdomains': [], 'error': 'AlienVault not implemented'}
    # 
    # def _query_threatcrowd(self) -> Dict[str, Any]:
    #     return {'subdomains': [], 'error': 'ThreatCrowd not implemented'}
    # 
    # def _query_securitytrails(self) -> Dict[str, Any]:
    #     return {'subdomains': [], 'error': 'SecurityTrails not implemented'}
    # 
    # # DNS History Sources
    # def _query_whois_history(self) -> Dict[str, Any]:
    #     return {'subdomains': [], 'error': 'WHOIS History not implemented'}
    # 
    # def _query_dnsdb(self) -> Dict[str, Any]:
    #     return {'subdomains': [], 'error': 'DNSDB not implemented'}
    # 
    # def _query_passive_dns(self) -> Dict[str, Any]:
    #     return {'subdomains': [], 'error': 'Passive DNS not implemented'}
    # 
    # # Additional Subdomain Sources
    # def _query_dnsdumpster_ct(self) -> Dict[str, Any]:
    #     return {'subdomains': [], 'error': 'DNSDumpster not implemented'}
    # 
    # def _query_rapid_dns(self) -> Dict[str, Any]:
    #     return {'subdomains': [], 'error': 'RapidDNS not implemented'}
    # 
    # def _query_sublist3r_sources(self) -> Dict[str, Any]:
    #     return {'subdomains': [], 'error': 'Sublist3r not implemented'}
    # 
    # def _query_threatminer(self) -> Dict[str, Any]:
    #     return {'subdomains': [], 'error': 'ThreatMiner not implemented'}
    
    def _extract_all_subdomains(self, sources_results: Dict[str, Any]) -> Set[str]:
        """Extract all subdomains from source results"""
        all_subdomains = set()
        
        for source_name, source_data in sources_results.items():
            if isinstance(source_data, dict):
                # Direct subdomains list
                if 'subdomains' in source_data and isinstance(source_data['subdomains'], list):
                    all_subdomains.update(source_data['subdomains'])
                
                # Nested sources (like CT sources)
                for key, value in source_data.items():
                    if isinstance(value, dict) and 'subdomains' in value:
                        if isinstance(value['subdomains'], list):
                            all_subdomains.update(value['subdomains'])
        
        return all_subdomains
    
    def _get_config_summary(self) -> Dict[str, Any]:
        """Get configuration summary for results"""
        return {
            'enabled_sources': self.config.enabled_sources,
            'ct_sources': self.config.ct_sources,
            'ssl_sources': self.config.ssl_sources,
            'max_concurrent_requests': self.config.max_concurrent_requests,
            'request_delay': self.config.request_delay
        }
    
    def _compile_statistics(self, results: Dict, start_time: float) -> Dict[str, Any]:
        """Compile execution statistics"""
        total_duration = time.time() - start_time
        total_subdomains = len(results.get('subdomains', []))
        
        # Count successful sources
        successful_sources = 0
        total_sources = 0
        
        for source_name, source_data in results.get('sources', {}).items():
            if isinstance(source_data, dict):
                total_sources += 1
                if source_data.get('subdomains'):
                    successful_sources += 1
        
        return {
            'total_duration': total_duration,
            'total_subdomains': total_subdomains,
            'successful_sources': successful_sources,
            'total_sources': total_sources,
            'success_rate': successful_sources / total_sources if total_sources > 0 else 0,
            'completion_time': time.strftime('%Y-%m-%d %H:%M:%S')
        }
    
    def get_errors(self) -> Dict:
        """Get all errors encountered during passive enumeration"""
        return self.error_handler.get_errors()


def create_passive_config_from_args(args) -> PassiveEnumerationConfig:
    """Create passive configuration from command line arguments"""
    config = PassiveEnumerationConfig()
    
    # Source configuration
    if hasattr(args, 'sources') and args.sources:
        config.enabled_sources = args.sources
    
    if hasattr(args, 'ct_sources') and args.ct_sources:
        config.ct_sources = args.ct_sources
    
    if hasattr(args, 'ssl_sources') and args.ssl_sources:
        config.ssl_sources = args.ssl_sources
    
    # Performance configuration
    if hasattr(args, 'concurrent_requests'):
        config.max_concurrent_requests = args.concurrent_requests
    
    if hasattr(args, 'request_delay'):
        config.request_delay = args.request_delay
    
    if hasattr(args, 'timeout'):
        config.ct_timeout = args.timeout
        config.ssl_timeout = args.timeout
    
    # Output configuration
    if hasattr(args, 'verbose'):
        config.verbose_output = args.verbose
    
    return config

def execute_passive_enumeration(domain: str, 
                               sources: List[str] = None,
                               ct_sources: List[str] = None,
                               concurrent_requests: int = 5,
                               request_delay: float = 0.5,
                               timeout: int = 10,
                               verbose: bool = False):
    """
    Enhanced passive enumeration function with direct parameter configuration
    
    Args:
        domain: Target domain to enumerate
        sources: List of passive sources to enable (default: ['certificate_transparency'])
        ct_sources: List of certificate transparency sources (default: ['crt_sh'])
        concurrent_requests: Maximum concurrent HTTP requests (default: 5)
        request_delay: Delay between requests in seconds (default: 0.5)
        timeout: Request timeout in seconds (default: 10)
        verbose: Enable verbose output (default: False)
    
    Returns:
        Dict: Complete enumeration results
    """
    # Set defaults if not provided
    if sources is None:
        sources = ['certificate_transparency']
    if ct_sources is None:
        ct_sources = ['crt_sh']
    
    # Configure logging
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    # Create configuration object
    config = PassiveEnumerationConfig()
    config.enabled_sources = sources
    config.ct_sources = ct_sources
    config.max_concurrent_requests = concurrent_requests
    config.request_delay = request_delay
    config.ct_timeout = timeout
    config.ssl_timeout = timeout
    config.verbose_output = verbose
    
    # Create and run enumerator
    enumerator = ConfigurablePassiveEnumerator(domain, config)
    results = enumerator.run_comprehensive_enumeration()
    
    # Display results
    _display_results(results, config)
    
    return results

def main():
    """Enhanced main function with comprehensive configuration"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Configurable Passive Domain Enumeration")
    parser.add_argument("domain", help="Target domain to enumerate")
    
    # Source Configuration
    parser.add_argument("--sources", nargs='+',
                       choices=['certificate_transparency', 'ssl_certificates', 'wayback_machine',
                               'threat_intelligence', 'dns_history', 'additional_sources'],
                       default=['certificate_transparency'],
                       help="Passive sources to enable (others currently disabled)")
    
    parser.add_argument("--ct-sources", nargs='+',
                       choices=['crt_sh', 'google_ct', 'certspotter'],
                       default=['crt_sh'],
                       help="Certificate transparency sources to use (only crt_sh is implemented)")
    
    # Performance Configuration
    parser.add_argument("--concurrent-requests", type=int, default=5,
                       help="Maximum concurrent HTTP requests")
    parser.add_argument("--request-delay", type=float, default=0.5,
                       help="Delay between requests in seconds")
    parser.add_argument("--timeout", type=int, default=10,
                       help="Request timeout in seconds")
    
    # Output Configuration
    parser.add_argument("--verbose", action='store_true',
                       help="Enable verbose output")
    
    args = parser.parse_args()
    
    # Configure logging
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    # Create configuration from arguments
    config = create_passive_config_from_args(args)
    
    # Create and run enumerator
    enumerator = ConfigurablePassiveEnumerator(args.domain, config)
    results = enumerator.run_comprehensive_enumeration()
    
    # Display results
    _display_results(results, config)


def _display_results(results: Dict, config: PassiveEnumerationConfig):
    """Display results based on configuration"""
    print(f"\n=== Passive Enumeration Results for {results['domain']} ===")
    print(f"Execution time: {results['statistics']['total_duration']:.2f} seconds")
    print(f"Total subdomains found: {results['statistics']['total_subdomains']}")
    print(f"Sources: {results['statistics']['successful_sources']}/{results['statistics']['total_sources']} successful")
    
    # Display subdomains
    subdomains = results.get('subdomains', set())
    if subdomains:
        print(f"\n=== Discovered Subdomains ({len(subdomains)}) ===")
        for subdomain in sorted(subdomains):
            print(f"  - {subdomain}")
    
    # Display source details if verbose
    if config.verbose_output:
        print(f"\n=== Source Details ===")
        for source_name, source_data in results.get('sources', {}).items():
            print(f"\n{source_name}:")
            if isinstance(source_data, dict):
                # Check if this is a nested structure with multiple sources
                if any(isinstance(v, dict) and 'subdomains' in v for v in source_data.values() if isinstance(v, dict)):
                    # This is certificate_transparency with nested sources
                    for sub_source, sub_data in source_data.items():
                        if isinstance(sub_data, dict) and 'subdomains' in sub_data:
                            print(f"  {sub_source}:")
                            subdomains = sub_data.get('subdomains', [])
                            print(f"    Subdomains: {len(subdomains)}")
                            if len(subdomains) > 0:
                                for subdomain in sorted(subdomains):
                                    print(f"      - {subdomain}")
                            
                            # Show certificate details if available
                            if 'certificates' in sub_data:
                                certificates = sub_data['certificates']
                                print(f"    Certificate Analysis:")
                                for cert_id, cert_info in certificates.items():
                                    print(f"      Certificate ID: {cert_id}")
                                    if isinstance(cert_info, dict):
                                        if 'error' in cert_info:
                                            print(f"        Error: {cert_info['error']}")
                                            continue
                                        
                                        # Certificate basic info
                                        if 'certificate_data' in cert_info:
                                            cert_data = cert_info['certificate_data']
                                            if 'common_name' in cert_data:
                                                print(f"        Common Name: {cert_data['common_name']}")
                                            if 'issuer' in cert_data:
                                                print(f"        Issuer: {cert_data['issuer']}")
                                            if 'not_before' in cert_data and 'not_after' in cert_data:
                                                print(f"        Validity: {cert_data['not_before']} to {cert_data['not_after']}")
                                            if 'sha256_fingerprint' in cert_data:
                                                print(f"        SHA-256: {cert_data['sha256_fingerprint'][:32]}...")
                                            if 'sha1_fingerprint' in cert_data:
                                                print(f"        SHA-1: {cert_data['sha1_fingerprint'][:32]}...")
                                        
                                        # Subject Alternative Names
                                        if 'subject_alternative_names' in cert_info and cert_info['subject_alternative_names']:
                                            print(f"        Subject Alternative Names: {len(cert_info['subject_alternative_names'])}")
                                            for san in cert_info['subject_alternative_names']:
                                                print(f"          - {san}")
                                        
                                        # CT Log entries
                                        if 'ct_logs' in cert_info and cert_info['ct_logs']:
                                            print(f"        Certificate Transparency Logs: {len(cert_info['ct_logs'])}")
                                            for i, ct_log in enumerate(cert_info['ct_logs'][:3]):  # Show first 3
                                                print(f"          {i+1}. {ct_log['log_operator']} ({ct_log['date']})")
                                            if len(cert_info['ct_logs']) > 3:
                                                print(f"          ... and {len(cert_info['ct_logs']) - 3} more CT logs")
                                        
                                        if 'additional_domains_found' in cert_info:
                                            print(f"        Additional domains from cert analysis: {cert_info['additional_domains_found']}")
                            
                            if 'total_certificates' in sub_data:
                                print(f"    Total certificates found: {sub_data['total_certificates']}")
                            
                            if 'error' in sub_data:
                                print(f"    Error: {sub_data['error']}")
                else:
                    # Regular source data structure
                    for key, value in source_data.items():
                        if key == 'subdomains' and isinstance(value, list):
                            print(f"  Subdomains: {len(value)}")
                            if len(value) > 0:
                                for subdomain in sorted(value):
                                    print(f"    - {subdomain}")
                        elif key == 'error':
                            print(f"  Error: {value}")
                        elif key == 'source':
                            print(f"  Source: {value}")
                        else:
                            if not isinstance(value, (dict, list)):
                                print(f"  {key}: {value}")
    
    # Display errors if any
    errors = results.get('errors', {})
    if errors:
        print(f"\n=== Errors ===")
        for method, error_list in errors.items():
            print(f"{method}: {len(error_list)} errors")


if __name__ == "__main__":
    main()