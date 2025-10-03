#!/usr/bin/env python3
"""
Certificate Transparency (CT) enumeration source
Extracted from original passive_enumeration.py for better modularity and testing
"""

import json
import logging
import re
import time
from typing import Dict, List, Set, Any, Optional
from urllib.parse import quote

from .base_source import CertificateTransparencySource

logger = logging.getLogger(__name__)


class CrtShSource(CertificateTransparencySource):
    """Certificate Transparency enumeration using crt.sh"""
    
    def __init__(self, domain: str, config: Any = None, session=None):
        super().__init__(domain, config, session)
        self.base_url = "https://crt.sh"
        self.max_pages = getattr(config, 'ct_max_pages', 5) if config else 5
        self.delay_between_pages = getattr(config, 'ct_page_delay', 2) if config else 2
    
    def get_source_name(self) -> str:
        return "crt.sh"
    
    def query_ct_source(self) -> Dict[str, Any]:
        """Enhanced CT enumeration with pagination and comprehensive parsing"""
        all_subdomains = set()
        metadata = {
            'pages_processed': 0,
            'total_certificates': 0,
            'unique_subdomains': 0,
            'errors': []
        }
        
        self.logger.info(f"Starting enhanced CT enumeration for {self.domain}")
        
        try:
            # Process multiple pages for comprehensive coverage
            for page in range(self.max_pages):
                page_subdomains = self._query_crtsh_page(page)
                
                if not page_subdomains:
                    self.logger.debug(f"No results on page {page + 1}, stopping pagination")
                    break
                
                all_subdomains.update(page_subdomains)
                metadata['pages_processed'] = page + 1
                
                self.logger.debug(f"Page {page + 1}: Found {len(page_subdomains)} subdomains")
                
                # Rate limiting between pages
                if page < self.max_pages - 1:
                    time.sleep(self.delay_between_pages)
            
            # Additional enhanced queries for better coverage
            enhanced_subdomains = self._perform_enhanced_queries()
            all_subdomains.update(enhanced_subdomains)
            
            # Final processing and validation
            validated_subdomains = self._validate_and_clean_subdomains(all_subdomains)
            
            metadata.update({
                'total_certificates': len(all_subdomains),
                'unique_subdomains': len(validated_subdomains)
            })
            
            self.logger.info(f"CT enumeration complete: {len(validated_subdomains)} unique subdomains found")
            
            return {
                'subdomains': sorted(validated_subdomains),
                'source': self.get_source_name(),
                'metadata': metadata
            }
            
        except Exception as e:
            self.logger.error(f"Enhanced CT enumeration failed: {e}")
            return {
                'subdomains': list(all_subdomains),
                'source': self.get_source_name(),
                'error': str(e),
                'metadata': metadata
            }
    
    def _query_crtsh_page(self, page: int = 0) -> Set[str]:
        """Query a specific page of crt.sh results"""
        subdomains = set()
        
        try:
            # Multiple query variations for comprehensive coverage
            queries = [
                f"%.{self.domain}",
                f"{self.domain}",
                f"%.%.{self.domain}"
            ]
            
            for query in queries:
                url = f"{self.base_url}/?q={quote(query)}&output=json"
                if page > 0:
                    url += f"&skip={page * 100}"
                
                try:
                    response = self._make_request(url, timeout=15)
                    certificates = response.json()
                    
                    if not certificates:
                        continue
                    
                    for cert in certificates:
                        # Extract subdomains from name_value field
                        if 'name_value' in cert:
                            names = cert['name_value'].split('\n')
                            for name in names:
                                name = name.strip().lower()
                                if self._is_valid_subdomain_for_domain(name):
                                    subdomains.add(name)
                        
                        # Extract from common_name if available
                        if 'common_name' in cert and cert['common_name']:
                            name = cert['common_name'].strip().lower()
                            if self._is_valid_subdomain_for_domain(name):
                                subdomains.add(name)
                    
                    # Small delay between queries
                    time.sleep(0.5)
                    
                except Exception as e:
                    self.logger.warning(f"Query '{query}' failed: {e}")
                    continue
        
        except Exception as e:
            self.logger.error(f"Page {page} query failed: {e}")
        
        return subdomains
    
    def _perform_enhanced_queries(self) -> Set[str]:
        """Perform additional enhanced queries for better coverage"""
        enhanced_subdomains = set()
        
        try:
            # Wildcard queries for different patterns
            enhanced_queries = [
                f"*.{self.domain}",
                f"*.*.{self.domain}",
                f"*.*.*.{self.domain}"
            ]
            
            for query in enhanced_queries:
                try:
                    url = f"{self.base_url}/?q={quote(query)}&output=json"
                    response = self._make_request(url, timeout=10)
                    certificates = response.json()
                    
                    if not certificates:
                        continue
                    
                    for cert in certificates[:50]:  # Limit to avoid overwhelming
                        if 'name_value' in cert:
                            names = cert['name_value'].split('\n')
                            for name in names:
                                name = name.strip().lower()
                                if self._is_valid_subdomain_for_domain(name):
                                    enhanced_subdomains.add(name)
                    
                    time.sleep(1)  # Rate limiting
                    
                except Exception as e:
                    self.logger.debug(f"Enhanced query '{query}' failed: {e}")
                    continue
        
        except Exception as e:
            self.logger.warning(f"Enhanced queries failed: {e}")
        
        return enhanced_subdomains
    
    def _is_valid_subdomain_for_domain(self, subdomain: str) -> bool:
        """Validate if subdomain belongs to target domain and is properly formatted"""
        try:
            # Basic format validation
            if not subdomain or len(subdomain) > 253:
                return False
            
            # Remove wildcard prefixes
            subdomain = re.sub(r'^\*\.', '', subdomain)
            
            # Check if it belongs to our domain
            if not (subdomain == self.domain or subdomain.endswith(f'.{self.domain}')):
                return False
            
            # Additional format validation
            if '..' in subdomain or subdomain.startswith('.') or subdomain.endswith('.'):
                return False
            
            # Check for valid characters (basic validation)
            if not re.match(r'^[a-zA-Z0-9.-]+$', subdomain):
                return False
            
            # Avoid obviously invalid entries
            invalid_patterns = [
                r'^\d+\.\d+\.\d+\.\d+',  # IP addresses
                r'[<>{}|\\^`]',          # Invalid characters
                r'[\s]',                 # Whitespace
                r'^-',                   # Starting with hyphen
                r'-$',                   # Ending with hyphen
            ]
            
            for pattern in invalid_patterns:
                if re.search(pattern, subdomain):
                    return False
            
            return True
            
        except Exception:
            return False
    
    def _validate_and_clean_subdomains(self, subdomains: Set[str]) -> List[str]:
        """Final validation and cleaning of discovered subdomains"""
        validated = []
        
        for subdomain in subdomains:
            try:
                # Clean the subdomain
                cleaned = subdomain.strip().lower()
                
                # Remove common prefixes that might be artifacts
                cleaned = re.sub(r'^\*\.', '', cleaned)
                
                # Validate using parent class method
                if self.validate_subdomain(cleaned):
                    validated.append(cleaned)
                    
            except Exception as e:
                self.logger.debug(f"Validation failed for '{subdomain}': {e}")
                continue
        
        # Remove duplicates and sort
        return sorted(list(set(validated)))


class GoogleCTSource(CertificateTransparencySource):
    """Certificate Transparency enumeration using Google CT (placeholder)"""
    
    def get_source_name(self) -> str:
        return "google_ct"
    
    def query_ct_source(self) -> Dict[str, Any]:
        """Google CT implementation placeholder"""
        # TODO: Implement Google Certificate Transparency API
        self.logger.warning("Google CT source not yet implemented")
        return {
            'subdomains': [],
            'source': self.get_source_name(),
            'error': 'Not implemented yet'
        }


class CensysCTSource(CertificateTransparencySource):
    """Certificate Transparency enumeration using Censys (placeholder)"""
    
    def __init__(self, domain: str, config: Any = None, session=None):
        super().__init__(domain, config, session)
        self.api_key = self._get_api_key()
    
    def _get_api_key(self) -> Optional[str]:
        """Get Censys API key from config"""
        if self.config and hasattr(self.config, 'censys_api_key'):
            return self.config.censys_api_key
        return None
    
    def get_source_name(self) -> str:
        return "censys_ct"
    
    def is_available(self) -> bool:
        """Check if API key is configured"""
        return self.api_key is not None
    
    def query_ct_source(self) -> Dict[str, Any]:
        """Censys CT implementation placeholder"""
        if not self.is_available():
            return {
                'subdomains': [],
                'source': self.get_source_name(),
                'error': 'Censys API key not configured'
            }
        
        # TODO: Implement Censys CT API
        self.logger.warning("Censys CT source not yet implemented")
        return {
            'subdomains': [],
            'source': self.get_source_name(),
            'error': 'Not implemented yet'
        }