import socket
import dns.resolver
import dns.zone
import dns.query
import logging
import requests
from concurrent.futures import ThreadPoolExecutor
import time
from typing import List, Dict, Set
import random
import json
import base64

import os
import sys
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import modules.utils as utils

class EnumerationConfig:
    """Configuration management for enumeration parameters"""
    
    def __init__(self):
        self.rate_limit = 10  # requests per second
        self.timeout = 5      # seconds per request
        self.retry_attempts = 3
        self.doh_fallback = True
        self.cdn_bypass = True
        self.thread_count = 10
        self.rate_limiting_enabled = True

class DomainEnumeration:
    def subdomain_discovery(self, wordlist=None):
        """
        Public method to perform subdomain discovery and store results in self.results['subdomains'].
        Optionally accepts a wordlist for brute force.
        """
        # Use enhanced_active_enumeration if wordlist is provided, else passive + active
        discovered = set()
        if wordlist:
            discovered.update(self.enhanced_active_enumeration(wordlist))
        else:
            # Combine passive and active
            self.passive_enumeration()
            discovered.update(self._extract_subdomains_from_passive())
            discovered.update(self._extract_subdomains_from_active())
            discovered.update(self._extract_subdomains_from_dns())
        # Verify subdomains
        verified = self._verify_subdomains(discovered)
        self.results['subdomains'] = verified
        return verified
    def __init__(self, domain, config=None):
        self.domain = domain
        self.config = config or EnumerationConfig()
        self.results = {
            'subdomains': {},
            'dns_records': {},
            'passive_data': {},
            'active_discovery': {}
        }
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})
        self.rate_limiter = RateLimiter(self.config.rate_limit)
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    # === PASSIVE ENUMERATION METHODS ===
    
    def passive_enumeration(self):
        """Comprehensive passive data collection"""
        logging.info("Starting passive enumeration")
        self.results['passive_data'] = {
            'certificate_transparency': self._query_ct_logs(),
            'ssl_certificates': self._query_ssl_certificates(),
            'wayback_machine': self._query_wayback_machine(),
            'threat_intelligence': self._query_threat_intel_apis(),
            'dns_history': self._query_dns_history()
        }
        return self.results['passive_data']

    def _query_ct_logs(self) -> Dict:
        """Query multiple CT log sources"""
        sources = {
            'crt_sh': self._query_crtsh(),
            'google_ct': self._query_google_ct(),
            'certspotter': self._query_certspotter()
        }
        return sources

    def _query_crtsh(self) -> Dict:
        """Query crt.sh certificate transparency logs"""
        logging.info("Querying crt.sh")
        result = {}
        
        # Try multiple approaches
        approaches = [
            f"https://crt.sh/?q=%25.{self.domain}&output=json",  # Subdomains
            f"https://crt.sh/?q={self.domain}&output=json",      # Main domain
            f"https://crt.sh/?q=%.{self.domain}&output=json"     # Alternative wildcard
        ]
        
        subdomains = set()
        
        for url in approaches:
            try:
                response = requests.get(url, timeout=15)
                if response.status_code == 200:
                    data = response.json()
                    
                    for entry in data:
                        # Extract common name and alternative names
                        common_name = entry.get('common_name', '').strip()
                        name_value = entry.get('name_value', '').strip()
                        
                        # Process common name
                        if common_name and self.domain in common_name.lower():
                            clean_name = common_name.lower().replace('*.', '')
                            if clean_name.endswith(self.domain):
                                subdomains.add(clean_name)
                        
                        # Process alternative names
                        if name_value:
                            for name in name_value.split('\n'):
                                name = name.strip().lower().replace('*.', '')
                                if name and name.endswith(self.domain):
                                    subdomains.add(name)
                    
                    logging.info(f"Found {len(subdomains)} subdomains from crt.sh approach: {url}")
                    break  # Stop on first successful request
                    
            except requests.exceptions.Timeout:
                logging.warning(f"Timeout for crt.sh query: {url}")
                continue
            except Exception as e:
                logging.error(f"Error querying crt.sh with {url}: {str(e)}")
                continue
        
        result['subdomains'] = list(subdomains)
        logging.info(f"Total found {len(result['subdomains'])} unique subdomains from crt.sh")
        return result

    def _query_google_ct(self) -> Dict:
        """Query Google Certificate Transparency"""
        logging.info("Querying Google CT")
        # Implementation for Google CT via ct.googleapis.com
        url = f"https://ct.googleapis.com/logs/ct_log_list"
        # For now, return empty but could implement full CT log querying
        return {'subdomains': []}

    # def _query_google_ct(self) -> Dict:
    #     """Query Google Certificate Transparency with detailed logging"""
    #     logging.info("=== Starting Google CT query for domain: %s ===", self.domain)
        
    #     result = {'subdomains': []}
        
    #     try:
    #         url = (
    #             f"https://transparencyreport.google.com/transparencyreport/api/v3/httpsreport/ct/certsearch"
    #             f"?include_expired=true&include_subdomains=true&domain={self.domain}"
    #         )
    #         logging.info("[Google CT] Sending request to URL: %s", url)
            
    #         response = requests.get(url, timeout=self.config.timeout)
    #         logging.info("[Google CT] Received response with status code: %s", response.status_code)
            
    #         if response.status_code != 200:
    #             logging.warning("[Google CT] Non-200 response. Cannot fetch data.")
    #             return result
            
    #         content = response.text
            
    #         # Remove Google API anti-JSON prefix
    #         if content.startswith(")]}'\n"):
    #             content = content[5:]
    #             logging.debug("[Google CT] Removed anti-JSON prefix from response")
            
    #         try:
    #             data = json.loads(content)
    #             logging.info("[Google CT] JSON parsed successfully")
                
    #             if data and isinstance(data, list) and len(data) > 0 and isinstance(data[0], list) and len(data[0]) > 1:
    #                 entries = data[0][1]
    #                 logging.info("[Google CT] Found %d entries in response", len(entries))
                    
    #                 subdomains = set()
    #                 for i, entry in enumerate(entries, start=1):
    #                     if isinstance(entry, list) and len(entry) > 0:
    #                         domain_name = entry[0]
    #                         logging.debug("[Google CT] Entry %d: %s", i, domain_name)
    #                         if self.domain in domain_name and domain_name.endswith(self.domain):
    #                             subdomains.add(domain_name.lower())
                    
    #                 result['subdomains'] = list(subdomains)
    #                 logging.info("[Google CT] Total unique subdomains found: %d", len(result['subdomains']))
                    
    #                 if len(result['subdomains']) == 0:
    #                     logging.info("[Google CT] No subdomains matched the target domain in entries")
    #             else:
    #                 logging.info("[Google CT] Response structure does not contain entries")
            
    #         except json.JSONDecodeError as e:
    #             logging.error("[Google CT] JSON parsing failed: %s", str(e))
        
    #     except requests.exceptions.Timeout:
    #         logging.warning("[Google CT] Request timed out")
    #     except requests.exceptions.RequestException as e:
    #         logging.error("[Google CT] Request failed: %s", str(e))
    #     except Exception as e:
    #         logging.error("[Google CT] Unexpected error: %s", str(e))
        
    #     logging.info("=== Finished Google CT query for domain: %s ===", self.domain)
    #     logging.info("[Google CT] Subdomains returned: %s", result['subdomains'])
        
    #     return result


        

    def _query_certspotter(self) -> Dict:
        """Query CertSpotter API"""
        logging.info("Querying CertSpotter")
        # CertSpotter API requires authentication for detailed data
        # Using their free endpoint for basic subdomain enumeration
        url = f"https://api.certspotter.com/v1/issuances?domain={self.domain}&include_subdomains=true&expand=dns_names"
        
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                subdomains = set()
                
                for entry in data:
                    dns_names = entry.get('dns_names', [])
                    for name in dns_names:
                        if self.domain in name.lower() and not name.startswith('*.'):
                            subdomains.add(name.lower())
                
                return {'subdomains': list(subdomains)}
            else:
                logging.warning(f"CertSpotter returned status {response.status_code}")
                return {'subdomains': []}
        except Exception as e:
            logging.error(f"Error querying CertSpotter: {str(e)}")
            return {'subdomains': []}

    def _query_ssl_certificates(self) -> Dict:
        """Query SSL certificate databases"""
        apis = {
            'censys': self._query_censys(),
            'shodan': self._query_shodan(),
            'virustotal': self._query_virustotal_certs()
        }
        
        # Aggregate all subdomains from SSL certificate sources
        all_ssl_subdomains = set()
        for api_name, subdomains in apis.items():
            if isinstance(subdomains, list):
                all_ssl_subdomains.update(subdomains)
                logging.info(f"{api_name} contributed {len(subdomains)} subdomains")
        
        apis['aggregated_subdomains'] = list(all_ssl_subdomains)
        logging.info(f"Total SSL certificate subdomains: {len(all_ssl_subdomains)}")
        
        return apis

    def _query_censys(self) -> List[str]:
        """Query Censys SSL certificates"""
        logging.info("Querying Censys")
        # Implementation for Censys API
        return []

    def _query_shodan(self) -> List[str]:
        """Query Shodan SSL certificates"""
        logging.info("Querying Shodan")
        # Implementation for Shodan API
        return []

    def _query_virustotal_certs(self) -> List[str]:
        """Query VirusTotal certificates"""
        logging.info("Querying VirusTotal")
        
        api_key = os.getenv('VIRUSTOTAL_API_KEY')
        
        if not api_key:
            logging.warning("VirusTotal API key not found in environment variables")
            return []
        
        try:
            url = f"https://www.virustotal.com/vtapi/v2/domain/report"
            params = {
                'apikey': api_key,
                'domain': self.domain
            }
            
            response = requests.get(url, params=params, timeout=self.config.timeout)
            
            if response.status_code == 200:
                data = response.json()
                subdomains = set()
                
                # Extract subdomains from various fields
                subdomain_count_before = len(subdomains)
                if 'subdomains' in data and isinstance(data['subdomains'], list):
                    logging.info(f"VirusTotal: Processing {len(data['subdomains'])} subdomains from 'subdomains' field")
                    for subdomain in data['subdomains']:
                        if isinstance(subdomain, str) and self.domain in subdomain.lower():
                            subdomains.add(subdomain.lower())
                            logging.debug(f"VirusTotal: Added subdomain from 'subdomains': {subdomain.lower()}")
                
                subdomain_count_after_subdomains = len(subdomains)
                logging.info(f"VirusTotal: Found {subdomain_count_after_subdomains - subdomain_count_before} valid subdomains from 'subdomains' field")
                
                # Extract from detected URLs if available
                if 'detected_urls' in data and isinstance(data['detected_urls'], list):
                    logging.info(f"VirusTotal: Processing {len(data['detected_urls'])} detected URLs")
                    url_subdomains_count = 0
                    for url_data in data['detected_urls'][:50]:  # Limit to avoid too much data
                        if isinstance(url_data, dict) and 'url' in url_data:
                            url = url_data['url']
                            if '://' in url:
                                domain_part = url.split('://')[1].split('/')[0]
                                if self.domain in domain_part.lower() and domain_part.endswith(self.domain):
                                    if domain_part.lower() not in subdomains:  # Only log new ones
                                        logging.debug(f"VirusTotal: Added subdomain from URL: {domain_part.lower()}")
                                        url_subdomains_count += 1
                                    subdomains.add(domain_part.lower())
                    logging.info(f"VirusTotal: Found {url_subdomains_count} new subdomains from detected URLs")
                
                # Extract from detected samples if available
                if 'detected_communicating_samples' in data and isinstance(data['detected_communicating_samples'], list):
                    logging.info(f"VirusTotal: Processing {len(data['detected_communicating_samples'])} detected samples")
                    for sample in data['detected_communicating_samples'][:20]:  # Limit to avoid too much data
                        if isinstance(sample, dict) and 'sha256' in sample:
                            # Additional parsing could be done here for sample metadata
                            pass
                
                # Log all discovered subdomains
                subdomain_list = sorted(list(subdomains))
                logging.info(f"VirusTotal: Total found {len(subdomain_list)} subdomains")
                
                if len(subdomain_list) <= 20:
                    logging.info("VirusTotal: Discovered subdomains:")
                    for i, subdomain in enumerate(subdomain_list, 1):
                        logging.info(f"  {i:3d}. {subdomain}")
                else:
                    logging.info("VirusTotal: Discovered subdomains (showing first 20):")
                    for i, subdomain in enumerate(subdomain_list[:20], 1):
                        logging.info(f"  {i:3d}. {subdomain}")
                    logging.info(f"  ... and {len(subdomain_list) - 20} more subdomains")
                    
                    # Optionally show all if debug level is enabled
                    if logging.getLogger().isEnabledFor(logging.DEBUG):
                        logging.debug("VirusTotal: Complete subdomain list:")
                        for i, subdomain in enumerate(subdomain_list, 1):
                            logging.debug(f"  {i:3d}. {subdomain}")
                
                if len(subdomain_list) > 20:
                    logging.info(f"VirusTotal: Showing first 20 of {len(subdomain_list)} total subdomains")
                return list(subdomains)
            elif response.status_code == 204:
                logging.info("VirusTotal: No information available for this domain")
                return []
            elif response.status_code == 403:
                logging.error("VirusTotal: API key is invalid or access denied")
                return []
            elif response.status_code == 429:
                logging.warning("VirusTotal: Rate limit exceeded")
                return []
            else:
                logging.warning(f"VirusTotal API returned status {response.status_code}")
                return []
                
        except requests.exceptions.Timeout:
            logging.warning("VirusTotal request timed out")
            return []
        except requests.exceptions.RequestException as e:
            logging.error(f"VirusTotal request failed: {str(e)}")
            return []
        except Exception as e:
            logging.error(f"Error querying VirusTotal: {str(e)}")
            return []

    def _query_wayback_machine(self) -> Dict:
        """Extract historical subdomains from Wayback Machine"""
        logging.info("Querying Wayback Machine")
        
        try:
            # Query Wayback Machine for URLs
            url = f"http://web.archive.org/cdx/search/cdx?url=*.{self.domain}&output=json&fl=original&collapse=urlkey"
            response = requests.get(url, timeout=10)
            
            subdomains = set()
            if response.status_code == 200:
                data = response.json()
                for entry in data[1:]:  # Skip header row
                    if entry and len(entry) > 0:
                        original_url = entry[0]
                        if '://' in original_url:
                            domain_part = original_url.split('://')[1].split('/')[0]
                            if self.domain in domain_part and domain_part.endswith(self.domain):
                                subdomains.add(domain_part.lower())
            
            return {'subdomains': list(subdomains)}
            
        except Exception as e:
            logging.error(f"Error querying Wayback Machine: {str(e)}")
            return {'subdomains': []}

    def _query_threat_intel_apis(self) -> Dict:
        """Query threat intelligence APIs"""
        logging.info("Querying threat intelligence APIs")
        # Implementation for various threat intel sources
        return {}

    def _query_dns_history(self) -> Dict:
        """Query DNS historical records"""
        logging.info("Querying DNS history")
        # Implementation for DNS history services
        return {}

    # === ACTIVE ENUMERATION METHODS ===

    def enhanced_active_enumeration(self, wordlist=None):
        """Advanced active enumeration with multiple techniques"""
        logging.info("Starting enhanced active enumeration")
        
        # Dynamic wordlist generation
        if not wordlist:
            wordlist = self._generate_dynamic_wordlist()
        
        # Multi-method discovery
        methods = {
            'bruteforce': self._bruteforce_with_rate_limiting(wordlist),
            'dns_permutations': self._dns_permutation_attack(),
            'dns_zone_transfer': self._attempt_zone_transfer(),
            'dns_cache_snooping': self._dns_cache_snooping()
        }
        
        self.results['active_discovery'] = methods
        return self.results['active_discovery']

    def _bruteforce_with_rate_limiting(self, wordlist: List[str]) -> List[str]:
        """Rate-limited brute force with fallback mechanisms"""
        logging.info(f"Starting rate-limited brute force with {len(wordlist)} words")
        
        results = []
        with ThreadPoolExecutor(max_workers=self.config.thread_count) as executor:
            futures = []
            for word in wordlist:
                if self.config.rate_limiting_enabled:
                    self.rate_limiter.acquire()
                future = executor.submit(self._check_subdomain, word)
                futures.append(future)
            
            for future in futures:
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                except Exception as e:
                    self._handle_enumeration_errors("bruteforce", e)
        
        return results

    def _check_subdomain(self, subdomain: str) -> str:
        """Check if subdomain exists with fallback to DoH"""
        full_domain = f"{subdomain}.{self.domain}"
        
        try:
            # Traditional DNS lookup
            result = socket.gethostbyname(full_domain)
            logging.info(f"Found subdomain: {full_domain} -> {result}")
            return full_domain
        except socket.gaierror:
            # Fallback to DNS-over-HTTPS
            if self.config.doh_fallback:
                doh_result = self._doh_query(full_domain)
                if doh_result:
                    return full_domain
        except Exception as e:
            logging.debug(f"Error checking {full_domain}: {e}")
        return None

    def _dns_permutation_attack(self) -> List[str]:
        """Generate and check DNS permutations"""
        logging.info("Starting DNS permutation attack")
        # Implementation for various permutation techniques
        return []

    def _attempt_zone_transfer(self) -> List[str]:
        """Attempt DNS zone transfer"""
        logging.info("Attempting DNS zone transfer")
        try:
            ns_answers = dns.resolver.resolve(self.domain, 'NS')
            nameservers = [str(ns) for ns in ns_answers]
            
            for ns in nameservers:
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(ns, self.domain))
                    if zone:
                        return [name for name in zone.nodes.keys()]
                except Exception:
                    continue
        except Exception as e:
            logging.warning(f"Zone transfer failed: {e}")
        return []

    def _dns_cache_snooping(self) -> List[str]:
        """DNS cache snooping techniques"""
        logging.info("Attempting DNS cache snooping")
        # Implementation for cache snooping
        return []

    # === DNS-OVER-HTTPS INTEGRATION ===

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
                if response.status_code == 200:
                    data = response.json()
                    if data.get('Answer'):
                        logging.info(f"Found via DoH: {domain}")
                        return domain
            except Exception as e:
                logging.warning(f"DoH query failed for {doh_server}: {e}")
                continue
        
        return None

    # === INTELLIGENT WORDLIST GENERATION ===

    def _generate_dynamic_wordlist(self) -> List[str]:
        """Generate context-aware wordlists using various techniques"""
        logging.info("Generating dynamic wordlist")
        
        wordlist_sources = {
            'common_subdomains': self._load_common_wordlist(),
            'target_specific': self._generate_target_specific_terms(),
            'llm_generated': self._generate_llm_based_terms(),
            'permutations': self._generate_permutations()
        }
        
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
            organization = domain_parts[0]  # e.g., 'uom' from 'online.uom.lk'
            
            # Generate variations based on organization name
            variations = [
                f"www{organization}",
                f"{organization}www",
                f"mail{organization}",
                f"{organization}mail",
                f"test{organization}",
                f"{organization}test",
                f"dev{organization}",
                f"{organization}dev",
                f"staging{organization}",
                f"{organization}staging"
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
        """Generate terms using LLM-based approaches"""
        # Implementation for LLM integration
        return []

    def _generate_permutations(self) -> List[str]:
        """Generate subdomain permutations"""
        # Implementation for various permutation techniques
        return []

    def _merge_wordlists(self, wordlist_sources: Dict) -> List[str]:
        """Merge and deduplicate wordlists"""
        all_words = set()
        for source_name, words in wordlist_sources.items():
            all_words.update(words)
        return list(all_words)

    # === CDN BYPASS TECHNIQUES ===

    def _bypass_cdn_techniques(self) -> Dict:
        """Implement CDN bypass methods"""
        logging.info("Attempting CDN bypass techniques")
        
        techniques = {
            'dns_history': self._check_dns_history_for_origin(),
            'header_analysis': self._analyze_headers_for_origin(),
            'ip_range_scan': self._scan_known_hosting_ranges(),
            'selenium_crawling': self._selenium_based_discovery()
        }
        return techniques

    def _check_dns_history_for_origin(self) -> List[str]:
        """Check DNS history for origin IPs"""
        # Implementation for DNS history analysis
        return []

    def _analyze_headers_for_origin(self) -> Dict:
        """Analyze headers for origin server clues"""
        # Implementation for header analysis
        return {}

    def _scan_known_hosting_ranges(self) -> List[str]:
        """Scan known hosting IP ranges"""
        # Implementation for IP range scanning
        return []

    def _selenium_based_discovery(self) -> List[str]:
        """Use browser automation to bypass CDN protections"""
        logging.info("Starting Selenium-based discovery")
        # Implementation for Selenium automation
        return []

    # === DNS ENUMERATION (ORIGINAL) ===

    def dns_enumeration(self):
        """Enumerate DNS records"""
        logging.info("Starting DNS enumeration")
        self.results['dns_records'] = {}
        
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        
        # Try to get records for both the target domain and its parent domain
        domains_to_check = [self.domain]
        
        # Add parent domain if current domain has subdomain structure
        domain_parts = self.domain.split('.')
        if len(domain_parts) > 2:
            parent_domain = '.'.join(domain_parts[1:])
            domains_to_check.append(parent_domain)
            logging.info(f"Also checking parent domain: {parent_domain}")
        
        for check_domain in domains_to_check:
            for record in record_types:
                try:
                    answers = dns.resolver.resolve(check_domain, record)
                    records = [rdata.to_text() for rdata in answers]
                    
                    # Store with domain prefix to distinguish
                    key = f"{record}_{check_domain}" if check_domain != self.domain else record
                    self.results['dns_records'][key] = records
                    logging.info(f"Found {len(records)} {record} records for {check_domain}")
                    
                except Exception as e:
                    logging.debug(f"Failed to get {record} records for {check_domain}: {str(e)}")
        
        return self.results['dns_records']

    # === RESULTS CORRELATION ===

    def correlate_results(self) -> List[str]:
        """Correlate findings from all sources and remove duplicates"""
        logging.info("Correlating results from all sources")
        
        all_subdomains = set()
        
        # Extract from passive data
        passive_subs = self._extract_subdomains_from_passive()
        all_subdomains.update(passive_subs)
        
        # Extract from active discovery
        active_subs = self._extract_subdomains_from_active()
        all_subdomains.update(active_subs)
        
        # Extract from DNS records
        dns_subs = self._extract_subdomains_from_dns()
        all_subdomains.update(dns_subs)
        
        # Validate and verify all discovered subdomains
        verified = self._verify_subdomains(all_subdomains)
        
        logging.info(f"Total unique subdomains found: {len(verified)}")
        return sorted(verified)

    def _extract_subdomains_from_passive(self) -> Set[str]:
        """Extract subdomains from passive data"""
        subdomains = set()
        
        # Extract from certificate transparency logs
        ct_data = self.results.get('passive_data', {}).get('certificate_transparency', {})
        
        # From crt.sh results
        crtsh_data = ct_data.get('crt_sh', {})
        if isinstance(crtsh_data, dict) and 'subdomains' in crtsh_data:
            subdomains.update(crtsh_data['subdomains'])
        
        # From CertSpotter results
        certspotter_data = ct_data.get('certspotter', {})
        if isinstance(certspotter_data, dict) and 'subdomains' in certspotter_data:
            subdomains.update(certspotter_data['subdomains'])
        
        # From Google CT results
        google_ct_data = ct_data.get('google_ct', {})
        if isinstance(google_ct_data, dict) and 'subdomains' in google_ct_data:
            subdomains.update(google_ct_data['subdomains'])
        
        # From Wayback Machine results
        wayback_data = self.results.get('passive_data', {}).get('wayback_machine', {})
        if isinstance(wayback_data, dict) and 'subdomains' in wayback_data:
            subdomains.update(wayback_data['subdomains'])
        
        # From SSL certificate APIs
        ssl_data = self.results.get('passive_data', {}).get('ssl_certificates', {})
        if isinstance(ssl_data, dict) and 'aggregated_subdomains' in ssl_data:
            subdomains.update(ssl_data['aggregated_subdomains'])
        
        # Also extract from individual SSL sources if available
        if isinstance(ssl_data, dict):
            for source_name in ['virustotal', 'censys', 'shodan']:
                source_data = ssl_data.get(source_name, [])
                if isinstance(source_data, list):
                    subdomains.update(source_data)
        
        logging.info(f"Extracted {len(subdomains)} subdomains from passive sources")
        return subdomains

    def _extract_subdomains_from_active(self) -> Set[str]:
        """Extract subdomains from active discovery"""
        subdomains = set()
        
        active_data = self.results.get('active_discovery', {})
        
        # From brute force results
        bruteforce_results = active_data.get('bruteforce', [])
        if isinstance(bruteforce_results, list):
            subdomains.update(bruteforce_results)
        
        # From zone transfer results
        zone_transfer_results = active_data.get('dns_zone_transfer', [])
        if isinstance(zone_transfer_results, list):
            for domain in zone_transfer_results:
                if isinstance(domain, str) and self.domain in domain:
                    subdomains.add(f"{domain}.{self.domain}")
        
        logging.info(f"Extracted {len(subdomains)} subdomains from active discovery")
        return subdomains

    def _extract_subdomains_from_dns(self) -> Set[str]:
        """Extract subdomains from DNS records"""
        subdomains = set()
        
        dns_records = self.results.get('dns_records', {})
        
        # Extract from CNAME records
        cname_records = dns_records.get('CNAME', [])
        for cname in cname_records:
            if isinstance(cname, str) and self.domain in cname:
                subdomains.add(cname)
        
        # Extract from MX records (mail servers often reveal subdomains)
        mx_records = dns_records.get('MX', [])
        for mx in mx_records:
            if isinstance(mx, str):
                # MX records format: "priority domain"
                parts = mx.split()
                if len(parts) > 1 and self.domain in parts[1]:
                    subdomains.add(parts[1])
        
        # Extract from NS records
        ns_records = dns_records.get('NS', [])
        for ns in ns_records:
            if isinstance(ns, str) and self.domain in ns:
                subdomains.add(ns)
        
        logging.info(f"Extracted {len(subdomains)} subdomains from DNS records")
        return subdomains

    def _verify_subdomains(self, subdomains: Set[str]) -> List[str]:
        """Verify subdomains are actually resolvable"""
        verified = []
        
        logging.info(f"Verifying {len(subdomains)} discovered subdomains...")
        
        for subdomain in subdomains:
            try:
                # Try to resolve the domain
                result = socket.gethostbyname(subdomain)
                verified.append(subdomain)
                logging.info(f"Verified subdomain: {subdomain} -> {result}")
            except socket.gaierror:
                # Try with DoH as fallback
                if self.config.doh_fallback:
                    doh_result = self._doh_query(subdomain)
                    if doh_result:
                        verified.append(subdomain)
                        logging.info(f"Verified subdomain via DoH: {subdomain}")
                continue
        
        return verified

    # === ERROR HANDLING ===

    def _handle_enumeration_errors(self, method_name: str, exception: Exception):
        """Centralized error handling with appropriate logging"""
        logging.error(f"Error in {method_name}: {str(exception)}")
        
        # Implement specific error recovery strategies
        if "rate limit" in str(exception).lower():
            logging.warning("Rate limit detected, implementing backoff")
            time.sleep(random.randint(5, 15))
        elif "quota" in str(exception).lower():
            logging.warning("API quota exceeded, pausing operations")
            time.sleep(60)

class RateLimiter:
    """Token bucket rate limiter implementation"""
    
    def __init__(self, rate: int):
        self.rate = rate
        self.tokens = rate
        self.last_update = time.time()
    
    def acquire(self):
        while self.tokens < 1:
            self._add_tokens()
            time.sleep(0.1)
        self.tokens -= 1
    
    def _add_tokens(self):
        now = time.time()
        elapsed = now - self.last_update
        new_tokens = elapsed * self.rate
        self.tokens = min(self.rate, self.tokens + new_tokens)
        self.last_update = now

# === USAGE EXAMPLE ===
if __name__ == "__main__":
    domain = "online.uom.lk"
    enumerator = DomainEnumeration(domain)
    
    # Run comprehensive enumeration
    enumerator.passive_enumeration()
    enumerator.dns_enumeration()
    enumerator.enhanced_active_enumeration()
    
    # Get final results
    final_subdomains = enumerator.correlate_results()
    print(f"Found {len(final_subdomains)} subdomains:")
    for subdomain in final_subdomains:
        print(f"  - {subdomain}")