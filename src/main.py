import os
import logging
import json
from datetime import datetime
from urllib.parse import urlparse
import re

import requests
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# Import modules
from modules.domain_enumeration import DomainEnumeration
from modules.service_discovery import ServiceDiscovery
from modules.web_crawling import WebCrawler
from modules.ai_integration import AIIntegration
from modules.cloud_detection import CloudDetector
from modules.utils import sanitize_domain, create_output_directory, create_web_wordlist
from output.report_generator import ReportGenerator

# Import config
from config.settings import (
    COMMON_PORTS, COMMON_SUBDOMAINS, REQUEST_HEADERS,
    CDN_INDICATORS, COMMON_S3_BUCKETS, GEMINI_API_KEY
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('reconnaissance.log'),
        logging.StreamHandler()
    ]
)

class DomainRecon:
    def __init__(self, domain_or_url, gemini_api_key=None):
        # Extract domain from URL if provided
        self.domain, self.sanitized_domain = sanitize_domain(domain_or_url)
        
        self.results = {}
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.output_dir = create_output_directory(self.domain, self.timestamp)
        
        # Initialize modules
        self.domain_enum = DomainEnumeration(self.domain)
        self.service_disc = ServiceDiscovery(self.domain)
        self.web_crawler = WebCrawler(self.domain)
        self.ai_integration = AIIntegration(gemini_api_key or GEMINI_API_KEY)
        self.cloud_detector = CloudDetector(self.domain)
        
    def run_all(self):
        """Run all reconnaissance modules"""
        logging.info(f"Starting comprehensive reconnaissance for {self.domain}")
        
        try:
            self.subdomain_discovery()
            self.dns_enumeration()
            self.service_discovery()
            self.web_fingerprinting()
            self.directory_bruteforce()
            self.api_discovery()
            self.cloud_detection()
            
            logging.info(f"Reconnaissance completed. Results saved in {self.output_dir}")
            self.save_final_report()
        except Exception as e:
            logging.error(f"Reconnaissance failed: {str(e)}")
        
    def subdomain_discovery(self):
        """Discover subdomains"""
        self.results['subdomains'] = self.domain_enum.subdomain_discovery(COMMON_SUBDOMAINS)
    
    def dns_enumeration(self):
        """Enumerate DNS records"""
        self.results['dns_records'] = self.domain_enum.dns_enumeration()
    
    def service_discovery(self):
        """Discover open ports and services"""
        self.results['services'] = self.service_disc.discover_services(COMMON_PORTS)
    
    def web_fingerprinting(self):
        """Fingerprint web technologies"""
        self.results['web_technologies'] = self.web_crawler.web_fingerprinting()
    
    def directory_bruteforce(self):
        """Brute force common web directories"""
        wordlist_path = create_web_wordlist(self.output_dir)
        self.results['directories'] = self.web_crawler.directory_bruteforce(wordlist_path)
    
    def api_discovery(self):
        """Discover common API endpoints"""
        logging.info("Starting API discovery")
        self.results['api_endpoints'] = []
        
        # Default common endpoints
        common_endpoints = [
            'api', 'api/v1', 'rest', 'graphql', 
            'swagger', 'swagger.json', 'api-docs',
            'graphiql', 'v1', 'v2', 'oauth', 'calculator'
        ]
        
        base_urls = [
            f"http://{self.domain}",
            f"https://{self.domain}",
            f"http://www.{self.domain}",
            f"https://www.{self.domain}"
        ]
        
        # Try to scrape content and generate AI-powered endpoints
        ai_endpoints = []
        successful_scrape = False
        
        if self.ai_integration.gemini_api_key:
            for base_url in base_urls:
                page_content = self.web_crawler.scrape_page_content(base_url, headers=REQUEST_HEADERS)
                if page_content:
                    successful_scrape = True
                    ai_endpoints = self.ai_integration.generate_ai_endpoints(page_content, self.domain)
                    if ai_endpoints:
                        logging.info(f"Generated {len(ai_endpoints)} endpoints from {base_url} (AI or fallback analysis)")
                        break
                    else:
                        logging.warning(f"No endpoints generated from {base_url}")
                else:
                    logging.warning(f"Failed to scrape {base_url}")
        else:
            # Even without API key, try intelligent fallback analysis
            for base_url in base_urls:
                page_content = self.web_crawler.scrape_page_content(base_url, headers=REQUEST_HEADERS)
                if page_content:
                    successful_scrape = True
                    ai_endpoints = self.ai_integration.generate_intelligent_fallback_endpoints(page_content)
                    if ai_endpoints:
                        logging.info(f"Generated {len(ai_endpoints)} endpoints from {base_url} using content analysis")
                        break
                else:
                    logging.warning(f"Failed to scrape {base_url}")
            
            if not successful_scrape:
                logging.info("No content could be scraped for intelligent endpoint generation")
        
        # Combine default and AI-generated endpoints
        all_endpoints = list(set(common_endpoints + ai_endpoints))
        ai_count = len(ai_endpoints)
        default_count = len(common_endpoints)
        total_count = len(all_endpoints)
        
        logging.info(f"Testing {total_count} total endpoints ({ai_count} from analysis, {default_count} default)")
        
        found_endpoints = []
        for base_url in base_urls:
            for endpoint in all_endpoints:
                url = f"{base_url}/{endpoint}"
                try:
                    response = requests.get(url, timeout=3, verify=False if 'netlify.app' in url else True)
                    if response.status_code < 400:
                        endpoint_info = {
                            'url': url,
                            'status': response.status_code,
                            'content_type': response.headers.get('Content-Type'),
                            'source': 'content_analysis' if endpoint in ai_endpoints else 'default'
                        }
                        found_endpoints.append(endpoint_info)
                        source_type = 'analyzed' if endpoint in ai_endpoints else 'default'
                        logging.info(f"Found {source_type} endpoint: {url} ({response.status_code})")
                except requests.RequestException:
                    continue
        
        self.results['api_endpoints'] = found_endpoints
    
    def cloud_detection(self):
        """Detect cloud services and CDNs"""
        self.results['cloud_services'] = self.cloud_detector.detect_cloud_services(
            COMMON_S3_BUCKETS, CDN_INDICATORS
        )
    
    # Update the save_final_report method
    def save_final_report(self):
        """Save all results to JSON and HTML reports"""
        report_generator = ReportGenerator(self.results, self.output_dir, self.domain)

        # Generate JSON report
        json_report_path = report_generator.generate_json_report()
        logging.info(f"JSON report saved to {json_report_path}")
        
        # Generate HTML report
        html_report_path = report_generator.generate_html_report()
        logging.info(f"HTML report saved to {html_report_path}")
        
        # Generate summary
        summary = report_generator.generate_summary()
        logging.info(f"Reconnaissance summary: {summary}")

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Comprehensive Domain Reconnaissance Tool")
    parser.add_argument("domain", help="Domain to investigate")
    parser.add_argument("--gemini-key", help="Gemini API key for AI-powered endpoint discovery")
    args = parser.parse_args()
    
    recon = DomainRecon(args.domain, args.gemini_key)
    recon.run_all()