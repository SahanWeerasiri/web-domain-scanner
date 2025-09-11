import os
import logging
import asyncio
import requests
from datetime import datetime
from pathlib import Path
import sys

# Add project root to path for imports
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
sys.path.insert(0, project_root)
sys.path.insert(0, current_dir)

# Import modules
from modules.domain_enumeration import DomainEnumeration
from modules.service_discovery import ServiceDiscovery
from modules.web_crawling import WebCrawler
from modules.ai_integration import AIIntegration
from modules.cloud_detection import CloudDetector
from modules.utils import sanitize_domain, create_output_directory, create_web_wordlist
from output.report_generator import ReportGenerator
from common.network_utils import NetworkUtils

# Import config
from config.settings import (
    COMMON_PORTS, COMMON_SUBDOMAINS, REQUEST_HEADERS,
    CDN_INDICATORS, COMMON_S3_BUCKETS, GEMINI_API_KEY,
    OPENAI_API_KEY, ANTHROPIC_API_KEY
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
    def __init__(self, domain_or_url, gemini_api_key=None, openai_api_key=None, anthropic_api_key=None, use_async=False):
        # Extract domain from URL if provided
        self.domain, self.sanitized_domain = sanitize_domain(domain_or_url)
        
        self.results = {}
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.output_dir = create_output_directory(self.domain, self.timestamp)
        self.use_async = use_async
        
        # Setup feedback database path
        self.feedback_db_path = os.path.join(project_root, "data", "endpoint_feedback.json")
        Path(os.path.join(project_root, "data")).mkdir(exist_ok=True)
        
        # Use provided keys or fall back to environment variables
        gemini_key = gemini_api_key or GEMINI_API_KEY
        openai_key = openai_api_key or OPENAI_API_KEY
        anthropic_key = anthropic_api_key or ANTHROPIC_API_KEY
        
        # Initialize modules
        self.domain_enum = DomainEnumeration(self.domain)
        self.service_disc = ServiceDiscovery(self.domain)
        self.web_crawler = WebCrawler(self.domain)
        self.ai_integration = AIIntegration(
            gemini_api_key=gemini_key,
            openai_api_key=openai_key,
            anthropic_api_key=anthropic_key,
            cache_size=128,
            feedback_db_path=self.feedback_db_path
        )
        self.cloud_detector = CloudDetector(self.domain)
        
    def run_all(self, scan_mode='quick'):
        """Run all reconnaissance modules"""
        logging.info(f"Starting comprehensive reconnaissance for {self.domain}")
        
        try:
            self.subdomain_discovery()
            self.dns_enumeration()
            self.service_discovery(scan_mode)
            self.web_fingerprinting()
            # self.directory_bruteforce()
            # self.api_discovery()
            # self.cloud_detection()
            
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
    
    def service_discovery(self, scan_mode='quick'):
        """
        Discover open ports and services with different scanning modes
        
        Args:
            scan_mode (str): 'quick', 'smart', or 'deep'
        """
        self.results['services'] = self.service_disc.discover_services(COMMON_PORTS, scan_mode)
    
    def web_crawl(self, crawl_level: str = 'smart', wordlist_path: str = None):
        """Run web crawling, directory bruteforce, and API discovery using WebCrawler.run_crawl_level"""
        logging.info(f"Starting web crawl for {self.domain} (level: {crawl_level})")
        crawl_results = self.web_crawler.run_crawl_level(crawl_level, wordlist_path)
        self.results['web_crawl'] = crawl_results
    def web_fingerprinting(self):
        """Fingerprint web technologies with AI enhancement"""
        logging.info("Starting web technology fingerprinting")

        # Run web fingerprinting and assign results correctly
        self.domain_enum.web_fingerprinting()
        self.results['web_technologies'] = self.domain_enum.results.get('web_technologies', {})

        # Try to enhance with AI technology detection for additional insights
        base_urls = [
            # f"https://{self.domain}",
            f"http://{self.domain}",
            # f"https://www.{self.domain}",
            # f"http://www.{self.domain}"
        ]

        ai_detected_tech = []
        for base_url in base_urls:
            page_content = self.web_crawler.scrape_page_content(base_url, headers=REQUEST_HEADERS)
            if page_content:
                # Use AI integration to detect technologies
                ai_tech = self.ai_integration.detect_technology(page_content)
                if ai_tech:
                    logging.info(f"AI detected additional technologies: {', '.join(ai_tech)}")
                    ai_detected_tech.extend(ai_tech)
                break

        # Add AI-detected technologies as additional metadata if found
        if ai_detected_tech:
            self.results['ai_detected_technologies'] = list(set(ai_detected_tech))
    
    def directory_bruteforce(self):
        """Brute force common web directories"""
        wordlist_path = create_web_wordlist(self.output_dir)
        self.results['directories'] = self.web_crawler.directory_bruteforce(wordlist_path)
    
    def api_discovery(self):
        """Discover common API endpoints using multiple AI providers with fallback"""
        logging.info("Starting API discovery")
        self.results['api_endpoints'] = []
        
        # Default common endpoints
        common_endpoints = [
            'api', 'api/v1', 'rest', 'graphql', 
            'swagger', 'swagger.json', 'api-docs',
            'graphiql', 'v1', 'v2', 'oauth', 'calculator'
        ]
        
        base_urls = [
            # f"http://{self.domain}",
            f"https://{self.domain}",
            # f"http://www.{self.domain}",
            # f"https://www.{self.domain}"
        ]
        
        # Try to scrape content and generate AI-powered endpoints
        ai_endpoints = []
        successful_scrape = False
        
        if self.ai_integration.available_providers:
            # Log available providers
            providers_str = ", ".join(self.ai_integration.available_providers)
            logging.info(f"Using AI providers for endpoint discovery: {providers_str}")
            
            for base_url in base_urls:
                page_content = self.web_crawler.scrape_page_content(base_url, headers=REQUEST_HEADERS)
                if page_content:
                    successful_scrape = True
                    
                    # Use async or sync method based on configuration
                    if self.use_async:
                        # Run async endpoint generation in a sync context
                        try:
                            loop = asyncio.get_event_loop()
                        except RuntimeError:
                            # Create new event loop if none exists
                            loop = asyncio.new_event_loop()
                            asyncio.set_event_loop(loop)
                            
                        ai_endpoints = loop.run_until_complete(
                            self.ai_integration.generate_ai_endpoints_async(page_content, self.domain)
                        )
                        logging.info(f"Generated endpoints using async AI integration")
                    else:
                        # Use synchronous endpoint generation
                        ai_endpoints = self.ai_integration.generate_ai_endpoints(page_content, self.domain)
                    
                    if ai_endpoints:
                        logging.info(f"Generated {len(ai_endpoints)} endpoints from {base_url} using AI analysis")
                        break
                    else:
                        logging.warning(f"No endpoints generated from {base_url}")
                else:
                    logging.warning(f"Failed to scrape {base_url}")
        else:
            # Even without API keys, try intelligent fallback analysis
            logging.info("No AI providers configured. Using fallback content analysis for endpoint discovery")
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
                        
                        # Record successful endpoint discovery for learning
                        if endpoint in ai_endpoints:
                            self.ai_integration.save_feedback(self.domain, endpoint, True)
                except requests.RequestException:
                    # Record unsuccessful endpoint prediction for learning
                    if endpoint in ai_endpoints:
                        self.ai_integration.save_feedback(self.domain, endpoint, False)
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
    
    # Scan mode arguments
    scan_group = parser.add_argument_group('Port Scanning Options')
    scan_group.add_argument("--scan-mode", choices=['quick', 'smart', 'deep'], 
                           default='quick', help="Port scanning mode: 'quick' (common ports), 'smart' (fuzzing), 'deep' (nmap/rustscan)")
    
    # AI provider arguments
    ai_group = parser.add_argument_group('AI Integration Options')
    ai_group.add_argument("--gemini-key", help="Gemini API key for AI-powered endpoint discovery")
    ai_group.add_argument("--openai-key", help="OpenAI API key for AI-powered endpoint discovery")
    ai_group.add_argument("--anthropic-key", help="Anthropic Claude API key for AI-powered endpoint discovery")
    ai_group.add_argument("--async", dest="use_async", action="store_true", help="Use asynchronous processing for AI endpoint generation")
    
    args = parser.parse_args()
    
    print(f"🎯 Starting reconnaissance for {args.domain}")
    print(f"📊 Port scan mode: {args.scan_mode.upper()}")
    if args.scan_mode == 'quick':
        print("   - Scanning common ports only (fastest)")
    elif args.scan_mode == 'smart':
        print("   - Intelligent fuzzing and extended port discovery")
    elif args.scan_mode == 'deep':
        print("   - Comprehensive scan using external tools (nmap/rustscan)")
    print()
    
    recon = DomainRecon(
        args.domain, 
        gemini_api_key=args.gemini_key,
        openai_api_key=args.openai_key,
        anthropic_api_key=args.anthropic_key,
        use_async=args.use_async
    )
    recon.run_all(args.scan_mode)