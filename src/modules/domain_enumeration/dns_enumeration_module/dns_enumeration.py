#!/usr/bin/env python3
"""
DNS Enumeration Module

This module provides comprehensive DNS record enumeration and analysis capabilities.
It queries various DNS record types and extracts subdomain information from DNS responses.

Key Features:
- Multiple DNS record type enumeration (A, AAAA, MX, NS, TXT, CNAME, SOA)
- Subdomain extraction from DNS records
- Support for both target domain and parent domain queries
- Error handling and logging
- Integration with DNS-over-HTTPS (DoH)

Author: Web Domain Scanner Project
License: See LICENSE file in project root
"""

import logging
import dns.resolver
import sys
import os
from typing import Dict, List, Set

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


class DNSEnumerator:
    """
    DNS enumeration class focusing on DNS record analysis and subdomain extraction.
    
    This class queries various DNS record types to discover subdomains and
    analyze DNS infrastructure of target domains.
    """
    
    def __init__(self, domain: str, config: EnumerationConfig = None):
        """Initialize DNS enumerator"""
        self.domain = domain.lower().strip()
        self.config = config or EnumerationConfig()
        self.error_handler = EnumerationErrorHandler()
        
        logger.info(f"DNSEnumerator initialized for domain: {self.domain}")
    
    def run_dns_enumeration(self) -> Dict:
        """
        Run comprehensive DNS enumeration.
        
        Returns:
            Dict: DNS records organized by record type
        """
        logger.info("Starting DNS enumeration")
        
        dns_records = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        
        # Determine domains to check
        domains_to_check = [self.domain]
        
        # Add parent domain if current domain has subdomain structure
        domain_parts = self.domain.split('.')
        if len(domain_parts) > 2:
            parent_domain = '.'.join(domain_parts[1:])
            domains_to_check.append(parent_domain)
            logger.info(f"Also checking parent domain: {parent_domain}")
        
        # Query each record type for each domain
        for check_domain in domains_to_check:
            logger.info(f"Enumerating DNS records for: {check_domain}")
            
            for record_type in record_types:
                try:
                    records = self._query_dns_record(check_domain, record_type)
                    if records:
                        if record_type not in dns_records:
                            dns_records[record_type] = []
                        dns_records[record_type].extend(records)
                        logger.info(f"Found {len(records)} {record_type} records for {check_domain}")
                    
                except Exception as e:
                    self.error_handler.handle_error(f"dns_{record_type.lower()}", e)
                    logger.debug(f"Error querying {record_type} for {check_domain}: {e}")
        
        # Remove duplicates from all record types
        for record_type in dns_records:
            dns_records[record_type] = list(set(dns_records[record_type]))
        
        logger.info(f"DNS enumeration completed. Found records: {list(dns_records.keys())}")
        return dns_records
    
    def _query_dns_record(self, domain: str, record_type: str) -> List[str]:
        """
        Query specific DNS record type for a domain.
        
        Args:
            domain: Domain to query
            record_type: DNS record type (A, AAAA, MX, etc.)
            
        Returns:
            List of record values
        """
        records = []
        
        try:
            # Create resolver with timeout
            resolver = dns.resolver.Resolver()
            resolver.timeout = self.config.timeout
            resolver.lifetime = self.config.timeout * 2
            
            # Query the record type
            answers = resolver.resolve(domain, record_type)
            
            for answer in answers:
                record_value = str(answer).strip()
                
                # Clean up record based on type
                if record_type == 'MX':
                    # MX records have priority, extract just the domain
                    parts = record_value.split()
                    if len(parts) >= 2:
                        record_value = parts[1].rstrip('.')
                elif record_type in ['NS', 'CNAME']:
                    # Remove trailing dot
                    record_value = record_value.rstrip('.')
                elif record_type == 'TXT':
                    # Remove quotes from TXT records
                    record_value = record_value.strip('"')
                
                records.append(record_value)
                logger.debug(f"{record_type} record for {domain}: {record_value}")
        
        except dns.resolver.NXDOMAIN:
            logger.debug(f"Domain {domain} does not exist")
        except dns.resolver.NoAnswer:
            logger.debug(f"No {record_type} records found for {domain}")
        except dns.resolver.Timeout:
            logger.warning(f"DNS query timeout for {domain} {record_type}")
        except Exception as e:
            logger.warning(f"DNS query error for {domain} {record_type}: {e}")
            self.error_handler.handle_error(f"dns_query_{record_type}", e)
        
        return records
    
    def extract_subdomains_from_dns_records(self, dns_records: Dict) -> Set[str]:
        """
        Extract subdomains from DNS records.
        
        Args:
            dns_records: Dictionary of DNS records by type
            
        Returns:
            Set of discovered subdomains
        """
        subdomains = set()
        
        # Extract from CNAME records
        cname_records = dns_records.get('CNAME', [])
        for cname in cname_records:
            if isinstance(cname, str) and self.domain in cname:
                if SubdomainValidator.is_valid_subdomain(cname, self.domain):
                    subdomains.add(cname)
                    logger.debug(f"Subdomain from CNAME: {cname}")
        
        # Extract from MX records (mail servers often reveal subdomains)
        mx_records = dns_records.get('MX', [])
        for mx in mx_records:
            if isinstance(mx, str) and self.domain in mx:
                if SubdomainValidator.is_valid_subdomain(mx, self.domain):
                    subdomains.add(mx)
                    logger.debug(f"Subdomain from MX: {mx}")
        
        # Extract from NS records
        ns_records = dns_records.get('NS', [])
        for ns in ns_records:
            if isinstance(ns, str) and self.domain in ns:
                if SubdomainValidator.is_valid_subdomain(ns, self.domain):
                    subdomains.add(ns)
                    logger.debug(f"Subdomain from NS: {ns}")
        
        # Analyze TXT records for subdomain hints
        txt_records = dns_records.get('TXT', [])
        for txt in txt_records:
            if isinstance(txt, str):
                discovered = self._extract_subdomains_from_txt(txt)
                subdomains.update(discovered)
        
        logger.info(f"Extracted {len(subdomains)} subdomains from DNS records")
        return subdomains
    
    def _extract_subdomains_from_txt(self, txt_record: str) -> Set[str]:
        """
        Extract potential subdomains from TXT records.
        
        TXT records sometimes contain subdomain references in SPF, DKIM, or other records.
        
        Args:
            txt_record: TXT record content
            
        Returns:
            Set of potential subdomains
        """
        subdomains = set()
        
        # Look for domain references in TXT records
        words = txt_record.split()
        for word in words:
            # Check for subdomain patterns
            if self.domain in word and '.' in word:
                # Clean up the word (remove protocols, paths, etc.)
                cleaned = word.lower()
                
                # Remove common prefixes/suffixes
                for prefix in ['http://', 'https://', 'ftp://']:
                    if cleaned.startswith(prefix):
                        cleaned = cleaned[len(prefix):]
                
                # Remove paths and parameters
                if '/' in cleaned:
                    cleaned = cleaned.split('/')[0]
                if '?' in cleaned:
                    cleaned = cleaned.split('?')[0]
                if ':' in cleaned and not cleaned.startswith('http'):
                    cleaned = cleaned.split(':')[0]
                
                # Validate as subdomain
                if SubdomainValidator.is_valid_subdomain(cleaned, self.domain):
                    subdomains.add(cleaned)
                    logger.debug(f"Subdomain from TXT record: {cleaned}")
        
        return subdomains
    
    def analyze_dns_infrastructure(self, dns_records: Dict) -> Dict:
        """
        Analyze DNS infrastructure for additional intelligence.
        
        Args:
            dns_records: Dictionary of DNS records by type
            
        Returns:
            Dictionary with infrastructure analysis
        """
        analysis = {
            'nameservers': [],
            'mail_servers': [],
            'ip_addresses': [],
            'cname_targets': [],
            'txt_analysis': {},
            'security_records': {}
        }
        
        # Analyze nameservers
        ns_records = dns_records.get('NS', [])
        analysis['nameservers'] = ns_records
        
        # Analyze mail servers
        mx_records = dns_records.get('MX', [])
        analysis['mail_servers'] = mx_records
        
        # Collect IP addresses
        a_records = dns_records.get('A', [])
        aaaa_records = dns_records.get('AAAA', [])
        analysis['ip_addresses'] = a_records + aaaa_records
        
        # Analyze CNAME targets
        cname_records = dns_records.get('CNAME', [])
        analysis['cname_targets'] = cname_records
        
        # Analyze TXT records for security and configuration
        txt_records = dns_records.get('TXT', [])
        analysis['txt_analysis'] = self._analyze_txt_records(txt_records)
        
        # Look for security-related records
        analysis['security_records'] = self._identify_security_records(dns_records)
        
        logger.info("DNS infrastructure analysis completed")
        return analysis
    
    def _analyze_txt_records(self, txt_records: List[str]) -> Dict:
        """Analyze TXT records for common configurations"""
        analysis = {
            'spf_records': [],
            'dkim_records': [],
            'dmarc_records': [],
            'verification_records': [],
            'other_records': []
        }
        
        for txt in txt_records:
            txt_lower = txt.lower()
            
            if txt_lower.startswith('v=spf'):
                analysis['spf_records'].append(txt)
            elif 'dkim' in txt_lower or txt_lower.startswith('k='):
                analysis['dkim_records'].append(txt)
            elif txt_lower.startswith('v=dmarc'):
                analysis['dmarc_records'].append(txt)
            elif any(verifier in txt_lower for verifier in ['google-site-verification', 'ms=', 'facebook-domain-verification']):
                analysis['verification_records'].append(txt)
            else:
                analysis['other_records'].append(txt)
        
        return analysis
    
    def _identify_security_records(self, dns_records: Dict) -> Dict:
        """Identify security-related DNS configurations"""
        security = {
            'has_spf': False,
            'has_dmarc': False,
            'has_dkim': False,
            'dnssec_enabled': False,
            'caa_records': []
        }
        
        # Check TXT records for email security
        txt_records = dns_records.get('TXT', [])
        for txt in txt_records:
            txt_lower = txt.lower()
            if txt_lower.startswith('v=spf'):
                security['has_spf'] = True
            elif txt_lower.startswith('v=dmarc'):
                security['has_dmarc'] = True
            elif 'dkim' in txt_lower:
                security['has_dkim'] = True
        
        # Check for CAA records (if available)
        caa_records = dns_records.get('CAA', [])
        security['caa_records'] = caa_records
        
        return security
    
    def query_additional_records(self, subdomains: Set[str]) -> Dict:
        """
        Query additional DNS records for discovered subdomains.
        
        Args:
            subdomains: Set of subdomains to query
            
        Returns:
            Dictionary with additional DNS information
        """
        additional_records = {}
        
        for subdomain in subdomains:
            logger.debug(f"Querying additional records for: {subdomain}")
            subdomain_records = {}
            
            # Query A and AAAA records for IP addresses
            for record_type in ['A', 'AAAA']:
                try:
                    records = self._query_dns_record(subdomain, record_type)
                    if records:
                        subdomain_records[record_type] = records
                except Exception as e:
                    logger.debug(f"Error querying {record_type} for {subdomain}: {e}")
            
            if subdomain_records:
                additional_records[subdomain] = subdomain_records
        
        logger.info(f"Queried additional records for {len(additional_records)} subdomains")
        return additional_records
    
    def get_errors(self) -> Dict:
        """Get all errors encountered during DNS enumeration"""
        return self.error_handler.get_errors()


# Main function for testing
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="DNS Domain Enumeration")
    parser.add_argument("domain", help="Target domain to enumerate")
    parser.add_argument("--analyze", action="store_true", help="Perform infrastructure analysis")
    parser.add_argument("--additional", action="store_true", help="Query additional records for found subdomains")
    
    args = parser.parse_args()
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Run DNS enumeration
    enumerator = DNSEnumerator(args.domain)
    dns_records = enumerator.run_dns_enumeration()
    
    # Extract subdomains from DNS records
    subdomains = enumerator.extract_subdomains_from_dns_records(dns_records)
    
    print(f"\n=== DNS Enumeration Results for {args.domain} ===")
    
    # Display DNS records by type
    print(f"\n=== DNS Records ===")
    for record_type, records in dns_records.items():
        print(f"{record_type}: {len(records)} records")
        for record in records[:5]:  # Show first 5 records
            print(f"  - {record}")
        if len(records) > 5:
            print(f"  ... and {len(records) - 5} more")
    
    # Display discovered subdomains
    print(f"\n=== Subdomains from DNS Records ===")
    print(f"Found {len(subdomains)} subdomains:")
    for subdomain in sorted(subdomains):
        print(f"  - {subdomain}")
    
    # Perform infrastructure analysis if requested
    if args.analyze:
        analysis = enumerator.analyze_dns_infrastructure(dns_records)
        
        print(f"\n=== DNS Infrastructure Analysis ===")
        print(f"Nameservers: {len(analysis['nameservers'])}")
        for ns in analysis['nameservers']:
            print(f"  - {ns}")
        
        print(f"Mail Servers: {len(analysis['mail_servers'])}")
        for mx in analysis['mail_servers']:
            print(f"  - {mx}")
        
        print(f"IP Addresses: {len(analysis['ip_addresses'])}")
        for ip in analysis['ip_addresses'][:10]:  # Show first 10 IPs
            print(f"  - {ip}")
        
        # Security analysis
        security = analysis['security_records']
        print(f"\n=== Security Configuration ===")
        print(f"SPF Record: {'Yes' if security['has_spf'] else 'No'}")
        print(f"DMARC Record: {'Yes' if security['has_dmarc'] else 'No'}")
        print(f"DKIM Records: {'Yes' if security['has_dkim'] else 'No'}")
    
    # Query additional records if requested
    if args.additional and subdomains:
        additional = enumerator.query_additional_records(subdomains)
        
        print(f"\n=== Additional Records for Subdomains ===")
        for subdomain, records in additional.items():
            print(f"{subdomain}:")
            for record_type, values in records.items():
                print(f"  {record_type}: {', '.join(values)}")
    
    # Display errors if any
    errors = enumerator.get_errors()
    if errors:
        print(f"\n=== Errors Encountered ===")
        for method, error_list in errors.items():
            print(f"{method}: {len(error_list)} errors")