"""
Domain enumeration module for passive and active subdomain discovery
"""
import subprocess
import json
import requests
import dns.resolver
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

class DomainEnumerator:
    def __init__(self, target, max_threads=10, rate_limit=5, ai_integration=None):
        self.target = target
        self.max_threads = max_threads
        self.rate_limit = rate_limit
        self.ai_integration = ai_integration
        self.results = {
            'passive': [],
            'active': []
        }
    
    def passive_enumeration(self):
        """Perform passive subdomain enumeration using various sources"""
        logging.info("Starting passive subdomain enumeration")
        
        # Use Sublist3r for initial passive discovery
        try:
            subprocess.run([
                'sublist3r', '-d', self.target, '-o', 'sublist3r_results.json', '-j'
            ], check=True, timeout=300, capture_output=True)
            
            with open('sublist3r_results.json', 'r') as f:
                data = json.load(f)
                self.results['passive'].extend(data.get('subdomains', []))
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
            logging.warning("Sublist3r not available or failed, using alternative methods")
            # Add some basic subdomains as fallback
            self.results['passive'].extend([f"www.{self.target}", f"mail.{self.target}"])
        
        return self.results
    
    def active_enumeration(self):
        """Perform active subdomain enumeration using DNS brute force"""
        logging.info("Starting active subdomain enumeration")
        
        # Generate or load wordlist
        wordlist = self._generate_wordlist()
        
        # DNS brute force with rate limiting
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {
                executor.submit(self._check_subdomain, subdomain): subdomain 
                for subdomain in wordlist
            }
            
            for future in as_completed(futures):
                subdomain = futures[future]
                try:
                    result = future.result()
                    if result:
                        self.results['active'].append(result)
                except Exception as e:
                    logging.error(f"Error checking {subdomain}: {str(e)}")
        
        return self.results
    
    def get_all_subdomains(self):
        """Get all discovered subdomains (passive + active) as a single list"""
        all_subdomains = self.results['passive'] + self.results['active']
        return list(set(all_subdomains))  # Remove duplicates
    
    def _generate_wordlist(self):
        """Generate subdomain wordlist, potentially using AI"""
        base_wordlist = self._load_base_wordlist()
        
        if self.ai_integration and self.ai_integration.is_enabled():
            # Use AI to enhance the wordlist based on target context
            enhanced_wordlist = self.ai_integration.enhance_subdomain_wordlist(
                self.target, base_wordlist
            )
            return list(set(base_wordlist + enhanced_wordlist))
        
        return base_wordlist
    
    def _load_base_wordlist(self):
        """Load the base subdomain wordlist from file"""
        try:
            with open('../config/wordlists/subdomains.txt', 'r') as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            # Fallback to common subdomains
            return ['www', 'mail', 'ftp', 'admin', 'api', 'test', 'dev', 'staging', 'prod', 
                   'blog', 'shop', 'support', 'news', 'app', 'cdn', 'static', 'assets']
    
    def _check_subdomain(self, subdomain):
        """Check if a subdomain exists via DNS resolution"""
        full_domain = f"{subdomain}.{self.target}"
        try:
            dns.resolver.resolve(full_domain, 'A')
            logging.info(f"Found subdomain: {full_domain}")
            return full_domain
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
            return None
        except Exception as e:
            logging.debug(f"DNS resolution failed for {full_domain}: {str(e)}")
            return None