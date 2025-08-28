import socket
import dns.resolver
import logging
import requests
from concurrent.futures import ThreadPoolExecutor
import time
from typing import List, Dict, Set
import random

import os
import sys
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

    def _query_crtsh(self) -> List[str]:
        """Query crt.sh certificate transparency logs"""
        logging.info("Querying crt.sh")
        result = {}
        url_ca = f"https://crt.sh/?ca={self.domain}"
        url_identity = f"https://crt.sh/?identity={self.domain}"

        print("<===============CA data===============>")

        response = requests.get(url_ca)

        if response.status_code == 200:
            result['ca'] = utils.html_to_json(response.text, self.domain)
            logging.info(f"Found {len(result['ca'])} CAs in crt.sh for {self.domain}")
            logging.info(f"Found {len(result['ca'])} CAs in crt.sh for {self.domain}")
        else:
            result['ca'] = {"error": "Failed to retrieve data"}
            logging.error(f"Failed to retrieve CA data from crt.sh for {self.domain}")

        print("<===============Identity data===============>")

        response = requests.get(url_identity)

        if response.status_code == 200:
            result['identity'] = utils.html_to_json(response.text, self.domain)
            logging.info(f"Found {len(result['identity'])} identities in crt.sh for {self.domain}")
            logging.info(f"Found {len(result['identity'])} identities in crt.sh for {self.domain}")
        else:
            result['identity'] = {"error": "Failed to retrieve data"}
            logging.error(f"Failed to retrieve identity data from crt.sh for {self.domain}")

        return result

    def _query_google_ct(self) -> List[str]:
        """Query Google Certificate Transparency"""
        logging.info("Querying Google CT")
        # Implementation for Google CT
        return []

    def _query_certspotter(self) -> List[str]:
        """Query CertSpotter API"""
        logging.info("Querying CertSpotter")
        # Implementation for CertSpotter
        return []

    def _query_ssl_certificates(self) -> Dict:
        """Query SSL certificate databases"""
        apis = {
            'censys': self._query_censys(),
            'shodan': self._query_shodan(),
            'virustotal': self._query_virustotal_certs()
        }
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
        # Implementation for VirusTotal API
        return []

    def _query_wayback_machine(self) -> List[str]:
        """Extract historical subdomains from Wayback Machine"""
        logging.info("Querying Wayback Machine")
        # Implementation for Wayback Machine API
        return []

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
            socket.gethostbyname(full_domain)
            logging.info(f"Found subdomain: {full_domain}")
            return full_domain
        except socket.gaierror:
            # Fallback to DNS-over-HTTPS
            if self.config.doh_fallback:
                return self._doh_query(full_domain)
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
        # Implementation for target-specific term generation
        return []

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
        for record in record_types:
            try:
                answers = dns.resolver.resolve(self.domain, record)
                records = [rdata.to_text() for rdata in answers]
                self.results['dns_records'][record] = records
                logging.info(f"Found {len(records)} {record} records")
            except Exception as e:
                logging.warning(f"Failed to get {record} records: {str(e)}")
        
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
        # Implementation to parse passive data results
        return subdomains

    def _extract_subdomains_from_active(self) -> Set[str]:
        """Extract subdomains from active discovery"""
        subdomains = set()
        # Implementation to parse active discovery results
        return subdomains

    def _extract_subdomains_from_dns(self) -> Set[str]:
        """Extract subdomains from DNS records"""
        subdomains = set()
        # Implementation to parse DNS records
        return subdomains

    def _verify_subdomains(self, subdomains: Set[str]) -> List[str]:
        """Verify subdomains are actually resolvable"""
        verified = []
        for subdomain in subdomains:
            try:
                socket.gethostbyname(subdomain)
                verified.append(subdomain)
            except socket.gaierror:
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