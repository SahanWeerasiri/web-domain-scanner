#!/usr/bin/env python3
"""
Passive Domain Enumeration Module

This module provides passive subdomain discovery capabilities using external sources
without directly probing the target infrastructure. This approach is stealthier and
less likely to trigger detection systems.

Data Sources:
- Certificate Transparency logs (crt.sh, Google CT, CertSpotter)
- SSL certificate databases (Censys, Shodan, VirusTotal)
- Web archive data (Wayback Machine)
- Threat intelligence APIs
- DNS historical records

Author: Web Domain Scanner Project
License: See LICENSE file in project root
"""

import logging
import time
import requests
import os
import sys
from typing import Dict, List, Set, Optional, TYPE_CHECKING
from urllib.parse import urlparse
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Add parent directories to path for imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..')))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from config import EnumerationConfig
from base import EnumerationErrorHandler, SubdomainValidator

# Import AI Integration module for intelligent subdomain prediction
if TYPE_CHECKING:
    from ai_integration import AIIntegration

try:
    from ai_integration import AIIntegration
    AI_AVAILABLE = True
except ImportError:
    AI_AVAILABLE = False
    AIIntegration = None

logger = logging.getLogger(__name__)


class PassiveEnumerator:
    """
    Passive domain enumeration class focusing on stealth reconnaissance.
    
    This class collects subdomain information from third-party sources without
    directly interacting with the target infrastructure.
    """
    
    def __init__(self, domain: str, config: EnumerationConfig = None, ai_integration = None):
        """Initialize passive enumerator"""
        self.domain = domain.lower().strip()
        self.config = config or EnumerationConfig()
        self.error_handler = EnumerationErrorHandler()
        
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
                logger.info("AI integration initialized for intelligent subdomain prediction")
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                         '(KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        
        # Configure session for better performance and reliability
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry
        
        # Setup retry strategy
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=10, pool_maxsize=20)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        logger.info(f"PassiveEnumerator initialized for domain: {self.domain}")
    
    def run_passive_enumeration(self) -> Dict:
        """
        Run comprehensive passive enumeration.
        
        Returns:
            Dict: Results from all passive enumeration sources
        """
        logger.info(f"Starting passive enumeration for domain: {self.domain}")
        start_time = time.time()
        
        results = {
            'certificate_transparency': {},
            'ssl_certificates': {},
            'wayback_machine': {},
            'threat_intelligence': {},
            'dns_history': {}
        }
        
        try:
            # Step 1: Certificate Transparency logs
            logger.debug("Step 1: Querying Certificate Transparency logs")
            results['certificate_transparency'] = self._query_ct_logs()
            
            # Step 2: SSL certificate databases
            logger.debug("Step 2: Querying SSL certificate databases")
            results['ssl_certificates'] = self._query_ssl_certificates()
            
            # Step 3: Web archive data
            logger.debug("Step 3: Querying Wayback Machine archives")
            results['wayback_machine'] = self._query_wayback_machine()
            
            # Step 4: Threat intelligence APIs
            logger.debug("Step 4: Querying threat intelligence APIs")
            results['threat_intelligence'] = self._query_threat_intel_apis()
            
            # Step 5: DNS historical records
            logger.debug("Step 5: Querying DNS history services")
            results['dns_history'] = self._query_dns_history()
            
        except Exception as e:
            logger.error(f"Error during passive enumeration: {str(e)}")
            self.error_handler.handle_error("passive_enumeration", e)
        
        duration = time.time() - start_time
        total_subdomains = len(self._extract_all_subdomains(results))
        
        logger.info(f"Passive enumeration completed in {duration:.2f} seconds, "
                   f"discovered {total_subdomains} potential subdomains")
        return results
    
    def _query_ct_logs(self) -> Dict:
        """Query multiple Certificate Transparency log sources - focusing on working alternatives"""
        sources = {
            # Traditional CT sources disabled due to reliability issues
            # 'crt_sh': self._query_crtsh(),
            # 'google_ct': self._query_google_ct(),
            # 'certspotter': self._query_certspotter(),
            # 'facebook_ct': self._query_facebook_ct(),
            # 'censys_ct': self._query_censys_ct(),
            # 'entrust_ct': self._query_entrust_ct(),
            
            # Focus on working alternative sources
            'hackertarget': self._query_hackertarget_ct(),
            'additional_sources': self._query_additional_working_sources(),
            # 'alternative_sources': self._query_enhanced_alternative_sources(),  # Currently no working sources
            # 'crtsh_simple': self._query_crtsh_simple()  # Also failing with 502 errors
        }
        return sources
    
    def _query_crtsh(self) -> Dict:
        """Query crt.sh certificate transparency logs with improved error handling"""
        logger.info("Querying crt.sh")
        result = {}
        
        # Try different crt.sh endpoints and query methods
        approaches = [
            # Primary approach - most efficient
            {
                'url': f"https://crt.sh/?q=%.{self.domain}&output=json",
                'description': "Wildcard subdomain query"
            },
            # Fallback approach - exact domain
            {
                'url': f"https://crt.sh/?q={self.domain}&output=json", 
                'description': "Exact domain query"
            },
            # Alternative encoding
            {
                'url': f"https://crt.sh/?q=%25.{self.domain}&output=json",
                'description': "URL encoded wildcard query"
            }
        ]
        
        subdomains = set()
        success = False
        
        for i, approach in enumerate(approaches):
            if success:
                break
                
            url = approach['url']
            description = approach['description']
            
            try:
                logger.debug(f"Trying crt.sh {description}: {url}")
                
                # Make request with shorter timeout
                response = self.session.get(url, timeout=8)
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        
                        if not data:
                            logger.info(f"crt.sh returned empty data for {description}")
                            continue
                            
                        logger.info(f"crt.sh {description} returned {len(data)} certificate entries")
                        
                        # Process certificate entries
                        for entry in data:
                            if isinstance(entry, dict) and 'name_value' in entry:
                                names = entry['name_value'].split('\n')
                                for name in names:
                                    # Clean and normalize the name
                                    name = name.strip().lower()
                                    name = name.lstrip('*.')  # Remove wildcard prefix
                                    
                                    if name and self.domain in name:
                                        if SubdomainValidator.is_valid_subdomain(name, self.domain):
                                            subdomains.add(name)
                        
                        logger.info(f"Processed {description}, found {len(subdomains)} valid subdomains")
                        success = True
                        break
                        
                    except ValueError as e:
                        logger.warning(f"Failed to parse JSON from crt.sh {description}: {e}")
                        # Try to handle partial JSON or plain text response
                        if response.text:
                            logger.debug(f"Response preview: {response.text[:200]}...")
                        continue
                        
                elif response.status_code == 429:
                    logger.warning(f"crt.sh rate limit hit for {description}, waiting...")
                    time.sleep(3)
                    continue
                elif response.status_code == 404:
                    logger.info(f"crt.sh: No data found for {description}")
                    continue
                else:
                    logger.warning(f"crt.sh {description} returned status {response.status_code}")
                    continue
                                        
            except requests.exceptions.Timeout:
                logger.warning(f"Timeout (8s) for crt.sh {description}")
                continue
            except requests.exceptions.ConnectionError:
                logger.warning(f"Connection error for crt.sh {description}")
                continue
            except requests.exceptions.RequestException as e:
                logger.warning(f"Request error for crt.sh {description}: {e}")
                continue
            except Exception as e:
                logger.error(f"Unexpected error querying crt.sh {description}: {str(e)}")
                continue
        
        # Remove duplicates and sort
        unique_subdomains = sorted(list(subdomains))
        result['subdomains'] = unique_subdomains
        
        if success:
            logger.info(f"Successfully found {len(unique_subdomains)} unique subdomains from crt.sh")
        else:
            logger.warning("All crt.sh query attempts failed")
            
        return result
    
    def _query_google_ct(self) -> Dict:
        """Query Google Certificate Transparency API"""
        logger.info("Querying Google CT")
        
        try:
            # Use Google's CT API to search for certificates
            url = "https://transparencyreport.google.com/transparencyreport/api/v3/httpsct/certsearch"
            
            params = {
                'include_expired': 'true',
                'include_subdomains': 'true',
                'domain': self.domain
            }
            
            headers = {
                'Referer': 'https://transparencyreport.google.com/',
                'User-Agent': self.session.headers.get('User-Agent')
            }
            
            response = self.session.get(url, params=params, headers=headers, timeout=10)
            
            if response.status_code == 200:
                # Google's API returns data in a specific format
                text = response.text
                subdomains = set()
                
                # Extract domain names from the response
                import re
                domain_pattern = r'[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.?' + re.escape(self.domain)
                matches = re.findall(domain_pattern, text, re.IGNORECASE)
                
                for match in matches:
                    clean_domain = match.strip().lower()
                    if SubdomainValidator.is_valid_subdomain(clean_domain, self.domain):
                        subdomains.add(clean_domain)
                
                logger.info(f"Google CT found {len(subdomains)} subdomains")
                return {'subdomains': list(subdomains)}
            else:
                logger.warning(f"Google CT returned status {response.status_code}")
                return {'subdomains': []}
                
        except Exception as e:
            logger.warning(f"Error querying Google CT: {str(e)}")
            return {'subdomains': []}
    
    def _query_facebook_ct(self) -> Dict:
        """Query Facebook CT Monitor API"""
        logger.info("Querying Facebook CT Monitor")
        
        try:
            # Facebook CT Monitor API
            url = f"https://developers.facebook.com/tools/ct/search/"
            
            params = {
                'domain': self.domain
            }
            
            response = self.session.get(url, params=params, timeout=10)
            
            if response.status_code == 200:
                subdomains = set()
                
                # Parse HTML response for certificate data
                import re
                # Look for domain patterns in the response
                domain_pattern = rf'[a-zA-Z0-9]([a-zA-Z0-9\-]{{0,61}}[a-zA-Z0-9])?\.{re.escape(self.domain)}'
                matches = re.findall(domain_pattern, response.text, re.IGNORECASE)
                
                for match in matches:
                    if SubdomainValidator.is_valid_subdomain(match, self.domain):
                        subdomains.add(match.lower())
                
                logger.info(f"Facebook CT found {len(subdomains)} subdomains")
                return {'subdomains': list(subdomains)}
            else:
                logger.warning(f"Facebook CT returned status {response.status_code}")
                return {'subdomains': []}
                
        except Exception as e:
            logger.warning(f"Error querying Facebook CT: {str(e)}")
            return {'subdomains': []}
    
    def _query_censys_ct(self) -> Dict:
        """Query Censys Certificate Search"""
        logger.info("Querying Censys CT")
        
        try:
            # Censys certificate search (free tier available)
            url = "https://search.censys.io/api/v2/certificates/search"
            
            # Basic search without API key (limited results)
            search_query = f"names: {self.domain}"
            
            params = {
                'q': search_query,
                'per_page': 100
            }
            
            response = self.session.get(url, params=params, timeout=10)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    subdomains = set()
                    
                    if 'result' in data and 'hits' in data['result']:
                        for hit in data['result']['hits']:
                            if 'names' in hit:
                                for name in hit['names']:
                                    clean_name = name.strip('*.').lower()
                                    if SubdomainValidator.is_valid_subdomain(clean_name, self.domain):
                                        subdomains.add(clean_name)
                    
                    logger.info(f"Censys CT found {len(subdomains)} subdomains")
                    return {'subdomains': list(subdomains)}
                except ValueError:
                    logger.warning("Failed to parse Censys CT response")
                    return {'subdomains': []}
            else:
                logger.warning(f"Censys CT returned status {response.status_code}")
                return {'subdomains': []}
                
        except Exception as e:
            logger.warning(f"Error querying Censys CT: {str(e)}")
            return {'subdomains': []}
    
    def _query_entrust_ct(self) -> Dict:
        """Query Entrust CT Log Search"""
        logger.info("Querying Entrust CT")
        
        try:
            # Entrust CT log search
            url = "https://ui.ctsearch.entrust.com/api/v1/certificates"
            
            params = {
                'fields': 'subjectDN,issuerDN,subjectAltNames',
                'domain': self.domain,
                'includeSubdomains': 'true',
                'exactMatch': 'false'
            }
            
            response = self.session.get(url, params=params, timeout=10)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    subdomains = set()
                    
                    if isinstance(data, list):
                        for cert in data:
                            # Extract from subject alternative names
                            if 'subjectAltNames' in cert:
                                for san in cert['subjectAltNames']:
                                    if san.get('type') == 'DNS':
                                        name = san.get('value', '').strip('*.').lower()
                                        if SubdomainValidator.is_valid_subdomain(name, self.domain):
                                            subdomains.add(name)
                    
                    logger.info(f"Entrust CT found {len(subdomains)} subdomains")
                    return {'subdomains': list(subdomains)}
                except ValueError:
                    logger.warning("Failed to parse Entrust CT response")
                    return {'subdomains': []}
            else:
                logger.warning(f"Entrust CT returned status {response.status_code}")
                return {'subdomains': []}
                
        except Exception as e:
            logger.warning(f"Error querying Entrust CT: {str(e)}")
            return {'subdomains': []}
    
    def _query_alternative_ct_sources(self) -> Dict:
        """Legacy method - now redirects to enhanced alternatives"""
        logger.info("Redirecting to enhanced alternative sources")
        return self._query_enhanced_alternative_sources()
    
    def _query_hackertarget_ct(self) -> Dict:
        """Enhanced HackerTarget query for subdomain information"""
        logger.info("Querying HackerTarget (Enhanced)")
        
        try:
            # Try multiple HackerTarget endpoints
            endpoints = [
                f"https://api.hackertarget.com/hostsearch/?q={self.domain}",
                f"https://api.hackertarget.com/findshareddns/?q={self.domain}",
                f"https://api.hackertarget.com/reverseiplookup/?q={self.domain}"
            ]
            
            all_subdomains = set()
            
            for endpoint in endpoints:
                try:
                    response = self.session.get(endpoint, timeout=10)
                    
                    if response.status_code == 200 and response.text.strip():
                        lines = response.text.strip().split('\n')
                        
                        for line in lines:
                            line = line.strip()
                            
                            # Handle different response formats
                            if ',' in line:
                                # Format: subdomain,ip
                                subdomain = line.split(',')[0].strip().lower()
                            elif '\t' in line:
                                # Format: subdomain\tip
                                subdomain = line.split('\t')[0].strip().lower()
                            else:
                                # Single subdomain per line
                                subdomain = line.lower()
                            
                            # Validate and add subdomain
                            if subdomain and SubdomainValidator.is_valid_subdomain(subdomain, self.domain):
                                all_subdomains.add(subdomain)
                    
                    # Small delay between requests to be respectful
                    time.sleep(0.5)
                    
                except Exception as e:
                    logger.debug(f"Error with HackerTarget endpoint {endpoint}: {str(e)}")
                    continue
            
            logger.info(f"HackerTarget (Enhanced) found {len(all_subdomains)} subdomains")
            return {'subdomains': list(all_subdomains)}
                
        except Exception as e:
            logger.warning(f"Error querying HackerTarget (Enhanced): {str(e)}")
            return {'subdomains': []}
    
    def _query_spyse_ct(self) -> Dict:
        """Query Spyse for subdomain information"""
        logger.info("Querying Spyse")
        
        try:
            # Spyse free API endpoint
            url = f"https://api.spyse.com/v4/data/domain/{self.domain}/subdomains"
            
            headers = {
                'Accept': 'application/json'
            }
            
            response = self.session.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    subdomains = set()
                    
                    if 'data' in data and 'items' in data['data']:
                        for item in data['data']['items']:
                            if 'name' in item:
                                subdomain = item['name'].lower()
                                if SubdomainValidator.is_valid_subdomain(subdomain, self.domain):
                                    subdomains.add(subdomain)
                    
                    logger.info(f"Spyse found {len(subdomains)} subdomains")
                    return {'subdomains': list(subdomains)}
                except ValueError:
                    logger.warning("Failed to parse Spyse response")
                    return {'subdomains': []}
            else:
                logger.warning(f"Spyse returned status {response.status_code}")
                return {'subdomains': []}
                
        except Exception as e:
            logger.warning(f"Error querying Spyse: {str(e)}")
            return {'subdomains': []}
    
    def _query_dnsdumpster_ct(self) -> Dict:
        """Query DNSDumpster for subdomain information"""
        logger.info("Querying DNSDumpster")
        
        try:
            # DNSDumpster requires a session and CSRF token
            session_url = "https://dnsdumpster.com/"
            search_url = "https://dnsdumpster.com/"
            
            # Get the initial page to extract CSRF token
            response = self.session.get(session_url, timeout=10)
            
            if response.status_code == 200:
                import re
                csrf_token = None
                
                # Extract CSRF token
                csrf_match = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', response.text)
                if csrf_match:
                    csrf_token = csrf_match.group(1)
                
                if csrf_token:
                    # Submit search form
                    data = {
                        'csrfmiddlewaretoken': csrf_token,
                        'targetip': self.domain,
                        'user': 'free'
                    }
                    
                    headers = {
                        'Referer': session_url,
                        'Content-Type': 'application/x-www-form-urlencoded'
                    }
                    
                    search_response = self.session.post(search_url, data=data, headers=headers, timeout=15)
                    
                    if search_response.status_code == 200:
                        subdomains = set()
                        
                        # Parse HTML response for subdomains
                        domain_pattern = rf'[a-zA-Z0-9]([a-zA-Z0-9\-]{{0,61}}[a-zA-Z0-9])?\.{re.escape(self.domain)}'
                        matches = re.findall(domain_pattern, search_response.text, re.IGNORECASE)
                        
                        for match in matches:
                            clean_domain = match.lower()
                            if SubdomainValidator.is_valid_subdomain(clean_domain, self.domain):
                                subdomains.add(clean_domain)
                        
                        logger.info(f"DNSDumpster found {len(subdomains)} subdomains")
                        return {'subdomains': list(subdomains)}
                    else:
                        logger.warning(f"DNSDumpster search returned status {search_response.status_code}")
                        return {'subdomains': []}
                else:
                    logger.warning("Could not extract CSRF token from DNSDumpster")
                    return {'subdomains': []}
            else:
                logger.warning(f"DNSDumpster initial request returned status {response.status_code}")
                return {'subdomains': []}
                
        except Exception as e:
            logger.warning(f"Error querying DNSDumpster: {str(e)}")
            return {'subdomains': []}
    
    def _query_crtsh_simple(self) -> Dict:
        """Simple crt.sh query with minimal error handling"""
        logger.info("Querying crt.sh (simple)")
        
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            
            response = self.session.get(url, timeout=5)
            
            if response.status_code == 200 and response.text.strip():
                try:
                    data = response.json()
                    subdomains = set()
                    
                    for entry in data:
                        if isinstance(entry, dict) and 'name_value' in entry:
                            names = entry['name_value'].split('\n')
                            for name in names:
                                name = name.strip().lower().lstrip('*.')
                                if name and self.domain in name:
                                    if SubdomainValidator.is_valid_subdomain(name, self.domain):
                                        subdomains.add(name)
                    
                    logger.info(f"crt.sh (simple) found {len(subdomains)} subdomains")
                    return {'subdomains': list(subdomains)}
                except:
                    pass
            
            logger.info("crt.sh (simple) found no results")
            return {'subdomains': []}
                
        except Exception as e:
            logger.info(f"crt.sh (simple) unavailable: {str(e)}")
            return {'subdomains': []}
    
    def _query_enhanced_alternative_sources(self) -> Dict:
        """Enhanced alternative sources with better parsing and more endpoints - focusing on working sources"""
        logger.info("Querying enhanced alternative sources (working sources only)")
        
        alternative_sources = [
            # Only include working sources
            # self._query_threatcrowd(),  # SSL certificate issues
            # self._query_sublist3r_sources(),  # Timeouts and DNS resolution failures
            # self._query_security_trails(),  # Returns 403 forbidden
            # self._query_rapid_dns()  # Returns no results
        ]
        
        all_subdomains = set()
        
        for source_result in alternative_sources:
            if isinstance(source_result, dict) and 'subdomains' in source_result:
                subdomains = source_result['subdomains']
                logger.info(f"Alternative source contributed {len(subdomains)} subdomains")
                all_subdomains.update(subdomains)
        
        logger.info(f"Enhanced alternatives found {len(all_subdomains)} total subdomains")
        return {'subdomains': list(all_subdomains)}
    
    def _query_threatcrowd(self) -> Dict:
        """Query ThreatCrowd for subdomain information"""
        logger.info("Querying ThreatCrowd")
        
        try:
            url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/"
            
            params = {
                'domain': self.domain
            }
            
            response = self.session.get(url, params=params, timeout=8)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    subdomains = set()
                    
                    if 'subdomains' in data and isinstance(data['subdomains'], list):
                        for subdomain in data['subdomains']:
                            clean_subdomain = subdomain.strip().lower()
                            if SubdomainValidator.is_valid_subdomain(clean_subdomain, self.domain):
                                subdomains.add(clean_subdomain)
                    
                    logger.info(f"ThreatCrowd found {len(subdomains)} subdomains")
                    return {'subdomains': list(subdomains)}
                except ValueError:
                    logger.warning("Failed to parse ThreatCrowd response")
                    return {'subdomains': []}
            else:
                logger.warning(f"ThreatCrowd returned status {response.status_code}")
                return {'subdomains': []}
                
        except Exception as e:
            logger.warning(f"Error querying ThreatCrowd: {str(e)}")
            return {'subdomains': []}
    
    def _query_sublist3r_sources(self) -> Dict:
        """Query various sources used by Sublist3r tool"""
        logger.info("Querying Sublist3r-style sources")
        
        sources = [
            f"https://crt.sh/?q=%.{self.domain}",
            f"https://dnsdumpster.com/",
            f"https://findsubdomains.com/subdomains-of/{self.domain}",
        ]
        
        subdomains = set()
        
        for url in sources:
            try:
                response = self.session.get(url, timeout=8)
                if response.status_code == 200:
                    # Extract domain patterns from HTML
                    import re
                    domain_pattern = rf'([a-zA-Z0-9]([a-zA-Z0-9\-]{{0,61}}[a-zA-Z0-9])?\.{re.escape(self.domain)})'
                    matches = re.findall(domain_pattern, response.text, re.IGNORECASE)
                    
                    for match in matches:
                        if isinstance(match, tuple):
                            subdomain = match[0].lower()
                        else:
                            subdomain = match.lower()
                        
                        if SubdomainValidator.is_valid_subdomain(subdomain, self.domain):
                            subdomains.add(subdomain)
            except Exception as e:
                logger.debug(f"Error querying {url}: {str(e)}")
                continue
        
        logger.info(f"Sublist3r sources found {len(subdomains)} subdomains")
        return {'subdomains': list(subdomains)}
    
    def _query_security_trails(self) -> Dict:
        """Query SecurityTrails (public endpoint)"""
        logger.info("Querying SecurityTrails")
        
        try:
            # Using public search page
            url = f"https://securitytrails.com/domain/{self.domain}/dns"
            
            response = self.session.get(url, timeout=10)
            
            if response.status_code == 200:
                subdomains = set()
                
                # Extract subdomains from HTML content
                import re
                domain_pattern = rf'([a-zA-Z0-9]([a-zA-Z0-9\-]{{0,61}}[a-zA-Z0-9])?\.{re.escape(self.domain)})'
                matches = re.findall(domain_pattern, response.text, re.IGNORECASE)
                
                for match in matches:
                    if isinstance(match, tuple):
                        subdomain = match[0].lower()
                    else:
                        subdomain = match.lower()
                    
                    if SubdomainValidator.is_valid_subdomain(subdomain, self.domain):
                        subdomains.add(subdomain)
                
                logger.info(f"SecurityTrails found {len(subdomains)} subdomains")
                return {'subdomains': list(subdomains)}
            else:
                logger.warning(f"SecurityTrails returned status {response.status_code}")
                return {'subdomains': []}
                
        except Exception as e:
            logger.warning(f"Error querying SecurityTrails: {str(e)}")
            return {'subdomains': []}
    
    def _query_rapid_dns(self) -> Dict:
        """Query RapidDNS for subdomain information"""
        logger.info("Querying RapidDNS")
        
        try:
            url = f"https://rapiddns.io/subdomain/{self.domain}"
            
            response = self.session.get(url, timeout=10)
            
            if response.status_code == 200:
                subdomains = set()
                
                # Extract subdomains from table rows
                import re
                # Look for subdomain patterns in the response
                domain_pattern = rf'([a-zA-Z0-9]([a-zA-Z0-9\-]{{0,61}}[a-zA-Z0-9])?\.{re.escape(self.domain)})'
                matches = re.findall(domain_pattern, response.text, re.IGNORECASE)
                
                for match in matches:
                    if isinstance(match, tuple):
                        subdomain = match[0].lower()
                    else:
                        subdomain = match.lower()
                    
                    if SubdomainValidator.is_valid_subdomain(subdomain, self.domain):
                        subdomains.add(subdomain)
                
                logger.info(f"RapidDNS found {len(subdomains)} subdomains")
                return {'subdomains': list(subdomains)}
            else:
                logger.warning(f"RapidDNS returned status {response.status_code}")
                return {'subdomains': []}
                
        except Exception as e:
            logger.warning(f"Error querying RapidDNS: {str(e)}")
            return {'subdomains': []}
    
    def _query_additional_working_sources(self) -> Dict:
        """Query additional working subdomain sources"""
        logger.info("Querying additional working sources")
        
        try:
            subdomains = set()
            
            # Try subdomain center
            try:
                url = f"https://www.subdomain.center/?domain={self.domain}"
                response = self.session.get(url, timeout=10)
                if response.status_code == 200:
                    import re
                    domain_pattern = rf'([a-zA-Z0-9]([a-zA-Z0-9\-]{{0,61}}[a-zA-Z0-9])?\.{re.escape(self.domain)})'
                    matches = re.findall(domain_pattern, response.text, re.IGNORECASE)
                    
                    for match in matches:
                        if isinstance(match, tuple):
                            subdomain = match[0].lower()
                        else:
                            subdomain = match.lower()
                        
                        if SubdomainValidator.is_valid_subdomain(subdomain, self.domain):
                            subdomains.add(subdomain)
                    
                    logger.info(f"Subdomain Center contributed {len(subdomains)} subdomains")
            except Exception as e:
                logger.debug(f"Error with Subdomain Center: {str(e)}")
            
            # Try VirusTotal public interface (no API key needed)
            try:
                time.sleep(1)  # Be respectful with requests
                url = f"https://www.virustotal.com/gui/domain/{self.domain}/relations"
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                }
                response = self.session.get(url, headers=headers, timeout=10)
                if response.status_code == 200:
                    import re
                    domain_pattern = rf'([a-zA-Z0-9]([a-zA-Z0-9\-]{{0,61}}[a-zA-Z0-9])?\.{re.escape(self.domain)})'
                    matches = re.findall(domain_pattern, response.text, re.IGNORECASE)
                    
                    vt_subdomains = set()
                    for match in matches:
                        if isinstance(match, tuple):
                            subdomain = match[0].lower()
                        else:
                            subdomain = match.lower()
                        
                        if SubdomainValidator.is_valid_subdomain(subdomain, self.domain):
                            vt_subdomains.add(subdomain)
                    
                    subdomains.update(vt_subdomains)
                    logger.info(f"VirusTotal public contributed {len(vt_subdomains)} subdomains")
            except Exception as e:
                logger.debug(f"Error with VirusTotal public: {str(e)}")
            
            logger.info(f"Additional sources found {len(subdomains)} total subdomains")
            return {'subdomains': list(subdomains)}
            
        except Exception as e:
            logger.warning(f"Error querying additional sources: {str(e)}")
            return {'subdomains': []}
    
    def _query_certspotter(self) -> Dict:
        """Query CertSpotter API"""
        logger.info("Querying CertSpotter")
        url = f"https://api.certspotter.com/v1/issuances?domain={self.domain}&include_subdomains=true&expand=dns_names"
        
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                subdomains = set()
                
                for entry in data:
                    if 'dns_names' in entry:
                        for name in entry['dns_names']:
                            if SubdomainValidator.is_valid_subdomain(name, self.domain):
                                subdomains.add(name)
                
                return {'subdomains': list(subdomains)}
            else:
                logger.warning(f"CertSpotter returned status {response.status_code}")
                return {'subdomains': []}
        except Exception as e:
            logger.error(f"Error querying CertSpotter: {str(e)}")
            return {'subdomains': []}
    
    def _query_ssl_certificates(self) -> Dict:
        """Query SSL certificate databases - currently disabled due to no working sources"""
        logger.info("SSL certificate queries disabled - no working sources available")
        
        # Commented out until API keys are available or free alternatives are found
        apis = {
            # 'censys': self._query_censys(),  # Requires API key
            # 'shodan': self._query_shodan(),  # Requires API key  
            # 'virustotal': self._query_virustotal_certs()  # Requires API key
        }
        
        # Return empty results to avoid processing overhead
        apis['aggregated_subdomains'] = []
        logger.info("SSL certificate enumeration skipped - no API keys configured")
        
        return apis
    
    def _query_censys(self) -> List[str]:
        """Query Censys SSL certificates"""
        logger.info("Querying Censys")
        # TODO: Implement Censys API integration
        return []
    
    def _query_shodan(self) -> List[str]:
        """Query Shodan SSL certificates"""
        logger.info("Querying Shodan")
        # TODO: Implement Shodan API integration
        return []
    
    def _query_virustotal_certs(self) -> List[str]:
        """Query VirusTotal certificates"""
        logger.info("Querying VirusTotal")
        
        api_key = os.getenv('VIRUSTOTAL_API_KEY')
        
        if not api_key:
            logger.warning("VirusTotal API key not found in environment variables")
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
                if 'subdomains' in data and isinstance(data['subdomains'], list):
                    for subdomain in data['subdomains']:
                        full_subdomain = f"{subdomain}.{self.domain}"
                        if SubdomainValidator.is_valid_subdomain(full_subdomain, self.domain):
                            subdomains.add(full_subdomain)
                
                # Extract from detected URLs
                if 'detected_urls' in data and isinstance(data['detected_urls'], list):
                    for url_entry in data['detected_urls']:
                        if 'url' in url_entry:
                            subdomain = SubdomainValidator.extract_subdomain_from_url(
                                url_entry['url'], self.domain
                            )
                            if subdomain:
                                subdomains.add(subdomain)
                
                logger.info(f"VirusTotal: Found {len(subdomains)} subdomains")
                return list(subdomains)
                
            elif response.status_code == 204:
                logger.info("VirusTotal: No information available for this domain")
                return []
            elif response.status_code == 403:
                logger.error("VirusTotal: API key is invalid or access denied")
                return []
            elif response.status_code == 429:
                logger.warning("VirusTotal: Rate limit exceeded")
                return []
            else:
                logger.warning(f"VirusTotal API returned status {response.status_code}")
                return []
                
        except requests.exceptions.Timeout:
            logger.warning("VirusTotal request timed out")
            return []
        except Exception as e:
            logger.error(f"Error querying VirusTotal: {str(e)}")
            return []
    
    def _query_wayback_machine(self) -> Dict:
        """Extract historical subdomains from Wayback Machine"""
        logger.info("Querying Wayback Machine")
        
        try:
            url = f"http://web.archive.org/cdx/search/cdx?url=*.{self.domain}&output=json&fl=original&collapse=urlkey"
            response = requests.get(url, timeout=10)
            
            subdomains = set()
            if response.status_code == 200:
                data = response.json()
                for entry in data[1:]:  # Skip header
                    if entry and len(entry) > 0:
                        archived_url = entry[0]
                        subdomain = SubdomainValidator.extract_subdomain_from_url(
                            archived_url, self.domain
                        )
                        if subdomain:
                            subdomains.add(subdomain)
            
            return {'subdomains': list(subdomains)}
            
        except Exception as e:
            logger.error(f"Error querying Wayback Machine: {str(e)}")
            return {'subdomains': []}
    
    def _query_threat_intel_apis(self) -> Dict:
        """Query threat intelligence APIs"""
        logger.info("Querying threat intelligence APIs")
        # TODO: Implement threat intelligence API integrations
        return {}
    
    def _query_dns_history(self) -> Dict:
        """Query DNS historical records"""
        logger.info("Querying DNS history")
        # TODO: Implement DNS history service integrations
        return {}
    
    def _extract_all_subdomains(self, results: Dict) -> Set[str]:
        """Extract all subdomains from passive enumeration results"""
        all_subdomains = set()
        
        for source, data in results.items():
            if isinstance(data, dict):
                for key, value in data.items():
                    if key == 'subdomains' and isinstance(value, list):
                        all_subdomains.update(value)
                    elif isinstance(value, dict) and 'subdomains' in value:
                        if isinstance(value['subdomains'], list):
                            all_subdomains.update(value['subdomains'])
        
        return all_subdomains
    
    def get_errors(self) -> Dict:
        """Get all errors encountered during passive enumeration"""
        return self.error_handler.get_errors()


# Main function for testing
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Passive Domain Enumeration")
    parser.add_argument("domain", help="Target domain to enumerate")
    parser.add_argument("--config", help="Custom configuration file", default=None)
    
    args = parser.parse_args()
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Run passive enumeration
    enumerator = PassiveEnumerator(args.domain)
    results = enumerator.run_passive_enumeration()
    
    # Extract and display all found subdomains
    all_subdomains = enumerator._extract_all_subdomains(results)
    
    print(f"\n=== Passive Enumeration Results for {args.domain} ===")
    print(f"Found {len(all_subdomains)} unique subdomains:")
    for subdomain in sorted(all_subdomains):
        print(f"  - {subdomain}")
    
    # Display errors if any
    errors = enumerator.get_errors()
    if errors:
        print(f"\n=== Errors Encountered ===")
        for method, error_list in errors.items():
            print(f"{method}: {len(error_list)} errors")