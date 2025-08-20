import socket
import dns.resolver
import logging
from concurrent.futures import ThreadPoolExecutor

class DomainEnumeration:
    def __init__(self, domain):
        self.domain = domain
        self.results = {}

    def subdomain_discovery(self, common_subdomains):
        """Discover subdomains using multiple methods"""
        logging.info("Starting subdomain discovery")
        self.results['subdomains'] = {}
        
        # DNS brute force
        found = []
        for sub in common_subdomains:
            full_domain = f"{sub}.{self.domain}"
            try:
                socket.gethostbyname(full_domain)
                found.append(full_domain)
            except socket.gaierror:
                continue
        
        if found:
            self.results['subdomains']['bruteforce'] = found
            logging.info(f"Found {len(found)} subdomains via brute force")
        
        return self.results['subdomains']

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