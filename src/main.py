import os
import logging
import asyncio
import requests
import json
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
    def __init__(self, domain_or_url, gemini_api_key=None, openai_api_key=None, anthropic_api_key=None, use_async=False,
                 module_config=None):
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
        
        # Default module configurations
        default_config = {
            'domain_enum': {},
            'service_disc': {},
            'web_crawler': {},
            'ai_integration': {
                'cache_size': 128,
            },
            'cloud_detector': {}
        }
        
        # Merge with provided configuration if available
        self.config = default_config
        if module_config:
            for module, params in module_config.items():
                if module in self.config:
                    self.config[module].update(params)
        
        # Initialize modules with advanced configurations
        # Create proper EnumerationConfig for domain_enum
        domain_enum_config = self.config.get('domain_enum', {})
        self.domain_enum = DomainEnumeration(self.domain, config=domain_enum_config)
        
        self.service_disc = ServiceDiscovery(self.domain)
        self.web_crawler = WebCrawler(self.domain)
        self.ai_integration = AIIntegration(
            gemini_api_key=gemini_key,
            openai_api_key=openai_key,
            anthropic_api_key=anthropic_key,
            cache_size=self.config['ai_integration'].get('cache_size', 128),
            feedback_db_path=self.feedback_db_path
        )
        self.cloud_detector = CloudDetector(self.domain)
        
    def run_all(self, scan_mode='quick', modules_to_run=None):
        """
        Run all or selected reconnaissance modules
        
        Args:
            scan_mode (str): 'quick', 'smart', or 'deep' scan mode
            modules_to_run (list): List of module names to run. If None, run all modules.
        """
        logging.info(f"Starting comprehensive reconnaissance for {self.domain} in {scan_mode} mode")
        
        # If no specific modules are specified, run all
        if not modules_to_run:
            modules_to_run = ['subdomain_discovery', 'dns_enumeration', 'service_discovery', 
                             'web_crawl', 'web_fingerprinting', 'directory_bruteforce', 
                             'api_discovery', 'cloud_detection']
                             
        # Run specified modules
        for module in modules_to_run:
            if module == 'subdomain_discovery' and hasattr(self, 'subdomain_discovery'):
                self.subdomain_discovery()
            elif module == 'dns_enumeration' and hasattr(self, 'dns_enumeration'):
                self.dns_enumeration()
            elif module == 'service_discovery' and hasattr(self, 'service_discovery'):
                self.service_discovery(scan_mode=scan_mode)
            elif module == 'web_crawl' and hasattr(self, 'web_crawl'):
                self.web_crawl(crawl_level=scan_mode)
            elif module == 'web_fingerprinting' and hasattr(self, 'web_fingerprinting'):
                self.web_fingerprinting()
            elif module == 'directory_bruteforce' and hasattr(self, 'directory_bruteforce'):
                self.directory_bruteforce()
            elif module == 'api_discovery' and hasattr(self, 'api_discovery'):
                self.api_discovery()
            elif module == 'cloud_detection' and hasattr(self, 'cloud_detection'):
                self.cloud_detection()
        
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
        
    def subdomain_discovery(self, wordlist=None):
        """Discover subdomains with optional custom wordlist"""
        # Get domain enum config
        domain_config = self.config.get('domain_enum', {})
        wordlist_param = wordlist or domain_config.get('wordlist')
        
        if wordlist_param:
            self.results['subdomains'] = self.domain_enum.subdomain_discovery(wordlist=wordlist_param)
        else:
            self.results['subdomains'] = self.domain_enum.subdomain_discovery(COMMON_SUBDOMAINS)
    
    def dns_enumeration(self):
        """Enumerate DNS records"""
        self.results['dns_records'] = self.domain_enum.dns_enumeration()
    
    def service_discovery(self, scan_mode='quick', **kwargs):
        """
        Discover open ports and services with different scanning modes
        
        Args:
            scan_mode (str): 'quick', 'smart', or 'deep'
            **kwargs: Additional service discovery parameters
        """
        # Get service discovery config and merge with kwargs
        service_config = self.config.get('service_disc', {}).copy()
        
        # Override scan_mode from config if provided, but remove it from service_config
        # to prevent duplicate parameter passing
        config_scan_mode = service_config.pop('scan_mode', scan_mode)
        
        # Merge kwargs with service_config, with kwargs taking precedence
        merged_params = {**service_config, **kwargs}
        
        # Pass additional parameters to service discovery
        self.results['services'] = self.service_disc.discover_services(
            COMMON_PORTS, 
            scan_mode=config_scan_mode,
            **merged_params
        )
    
    def web_crawl(self, crawl_level: str = 'smart', wordlist_path: str = None, **kwargs):
        """Run web crawling, directory bruteforce, and API discovery using WebCrawler.run_crawl_level"""
        logging.info(f"Starting web crawl for {self.domain} (level: {crawl_level})")
        
        # Get web crawler config
        crawler_config = self.config.get('web_crawler', {})
        
        # Override parameters from config
        config_crawl_level = crawler_config.get('crawl_level', crawl_level)
        config_wordlist_path = crawler_config.get('wordlist_path', wordlist_path)
        
        # Apply additional crawler configuration to the WebCrawler instance
        if crawler_config:
            # Update crawl levels if custom values are provided
            if 'max_pages' in crawler_config or 'wordlist_size' in crawler_config or 'recursive' in crawler_config or 'use_ai' in crawler_config:
                if config_crawl_level in self.web_crawler.crawl_levels:
                    level_config = self.web_crawler.crawl_levels[config_crawl_level].copy()
                    level_config.update({k: v for k, v in crawler_config.items() 
                                       if k in ['max_pages', 'wordlist_size', 'recursive', 'use_ai']})
                    self.web_crawler.crawl_levels[config_crawl_level] = level_config
        
        crawl_results = self.web_crawler.run_crawl_level(config_crawl_level, config_wordlist_path)
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
    
    def directory_bruteforce(self, wordlist_path=None, extensions=None, recursive=False, depth=2, **kwargs):
        """Brute force common web directories with configurable parameters"""
        # Get directory bruteforce config
        dir_config = self.config.get('directory_bruteforce', {})
        
        # Use config values if not overridden
        final_wordlist_path = wordlist_path or dir_config.get('wordlist_path')
        final_extensions = extensions or dir_config.get('extensions')
        final_recursive = dir_config.get('recursive', recursive)
        final_depth = dir_config.get('depth', depth)
        
        # Use provided wordlist or create default one
        if not final_wordlist_path:
            final_wordlist_path = create_web_wordlist(self.output_dir)
        
        self.results['directories'] = self.web_crawler.directory_bruteforce(
            final_wordlist_path, 
            extensions=final_extensions,
            recursive=final_recursive,
            depth=final_depth,
            **kwargs
        )
    
    def api_discovery(self, custom_paths=None, wordlist_path=None, max_endpoints=500, **kwargs):
        """Discover common API endpoints using multiple AI providers with fallback"""
        logging.info("Starting API discovery")
        
        # Get API discovery config
        api_config = self.config.get('api_discovery', {})
        
        # Use config values if not overridden
        final_custom_paths = custom_paths or api_config.get('custom_paths', [])
        final_wordlist_path = wordlist_path or api_config.get('wordlist_path')
        final_max_endpoints = api_config.get('max_endpoints', max_endpoints)
        use_ai = api_config.get('use_ai', True)
        
        self.results['api_endpoints'] = []
        
        # Default common endpoints
        common_endpoints = [
            'api', 'api/v1', 'rest', 'graphql', 
            'swagger', 'swagger.json', 'api-docs',
            'graphiql', 'v1', 'v2', 'oauth', 'calculator'
        ]
        
        # Add custom paths to common endpoints
        if final_custom_paths:
            common_endpoints.extend(final_custom_paths)
        
        # Load additional endpoints from wordlist if provided
        if final_wordlist_path and os.path.exists(final_wordlist_path):
            try:
                with open(final_wordlist_path, 'r') as f:
                    wordlist_endpoints = [line.strip() for line in f.readlines() if line.strip()]
                common_endpoints.extend(wordlist_endpoints)
                logging.info(f"Loaded {len(wordlist_endpoints)} endpoints from wordlist: {final_wordlist_path}")
            except Exception as e:
                logging.warning(f"Failed to load wordlist {final_wordlist_path}: {e}")
        
        base_urls = [
            f"https://{self.domain}",
        ]
        
        # Try to scrape content and generate AI-powered endpoints
        ai_endpoints = []
        successful_scrape = False
        
        if use_ai and self.ai_integration.available_providers:
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
        elif use_ai:
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
        
        # Limit endpoints to max_endpoints
        if len(all_endpoints) > final_max_endpoints:
            all_endpoints = all_endpoints[:final_max_endpoints]
            logging.info(f"Limited endpoint testing to {final_max_endpoints} endpoints")
        
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
    
    def cloud_detection(self, common_buckets_patterns=None, cdn_indicators=None, **kwargs):
        """Detect cloud services and CDNs with configurable parameters"""
        # Get cloud detection config
        cloud_config = self.config.get('cloud_detector', {})
        
        # Use provided parameters or defaults from config or global defaults
        buckets = (common_buckets_patterns or 
                  cloud_config.get('common_buckets_patterns') or 
                  COMMON_S3_BUCKETS)
        indicators = (cdn_indicators or 
                     cloud_config.get('cdn_indicators') or 
                     CDN_INDICATORS)
        
        self.results['cloud_services'] = self.cloud_detector.detect_cloud_services(
            buckets, indicators, **kwargs
        )
        
        return self.results['cloud_services']
    
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
        
        return {
            'json_report': json_report_path,
            'html_report': html_report_path,
            'summary': summary
        }
        
    def run_module(self, module_name, **module_params):
        """
        Run a single module with custom parameters
        
        Args:
            module_name (str): Name of the module to run
            module_params (dict): Custom parameters for the module
        
        Returns:
            dict: Module execution results
        """
        logging.info(f"Running module '{module_name}' for {self.domain}")
        
        module_result = None
        
        if module_name == 'subdomain_discovery':
            wordlist = module_params.get('wordlist')
            module_result = self.subdomain_discovery(wordlist=wordlist)
        
        elif module_name == 'dns_enumeration':
            module_result = self.dns_enumeration()
        
        elif module_name == 'service_discovery':
            # Extract scan_mode from module_params to avoid duplicate parameter
            module_params_copy = module_params.copy()
            scan_mode = module_params_copy.pop('scan_mode', 'quick')
            module_result = self.service_discovery(scan_mode=scan_mode, **module_params_copy)
        
        elif module_name == 'web_crawl':
            # Extract parameters to avoid duplicates
            module_params_copy = module_params.copy()
            crawl_level = module_params_copy.pop('crawl_level', 'smart')
            wordlist_path = module_params_copy.pop('wordlist_path', None)
            module_result = self.web_crawl(crawl_level=crawl_level, wordlist_path=wordlist_path, **module_params_copy)
        
        elif module_name == 'web_fingerprinting':
            module_result = self.web_fingerprinting()
        
        elif module_name == 'directory_bruteforce':
            wordlist_path = module_params.get('wordlist_path')
            extensions = module_params.get('extensions', None)
            recursive = module_params.get('recursive', False)
            depth = module_params.get('depth', 2)
            max_urls = module_params.get('max_urls')
            module_result = self.directory_bruteforce(
                wordlist_path=wordlist_path, 
                extensions=extensions, 
                recursive=recursive, 
                depth=depth,
                max_urls=max_urls,
                **{k: v for k, v in module_params.items() 
                   if k not in ['wordlist_path', 'extensions', 'recursive', 'depth', 'max_urls']}
            )
        
        elif module_name == 'api_discovery':
            custom_paths = module_params.get('custom_paths', None)
            wordlist_path = module_params.get('wordlist_path', None)
            max_endpoints = module_params.get('max_endpoints', 500)
            module_result = self.api_discovery(
                custom_paths=custom_paths, 
                wordlist_path=wordlist_path, 
                max_endpoints=max_endpoints,
                **{k: v for k, v in module_params.items() 
                   if k not in ['custom_paths', 'wordlist_path', 'max_endpoints']}
            )
        
        elif module_name == 'cloud_detection':
            common_buckets_patterns = module_params.get('common_buckets_patterns', None)
            cdn_indicators = module_params.get('cdn_indicators', None)
            module_result = self.cloud_detection(
                common_buckets_patterns=common_buckets_patterns, 
                cdn_indicators=cdn_indicators,
                **{k: v for k, v in module_params.items() 
                   if k not in ['common_buckets_patterns', 'cdn_indicators']}
            )
        
        else:
            logging.warning(f"Unknown module name: {module_name}")
            return {"error": f"Unknown module name: {module_name}"}
        
        # Save partial results to the output directory
        partial_report_path = os.path.join(self.output_dir, f"{module_name}_report.json")
        with open(partial_report_path, 'w') as f:
            json.dump(module_result, f, indent=4)
        
        return module_result

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Comprehensive Domain Reconnaissance Tool")
    parser.add_argument("domain", help="Domain to investigate")
    
    # Mode selection (pipeline or single module)
    parser.add_argument("--mode", choices=['pipeline', 'module'], default='pipeline',
                       help="Run mode: 'pipeline' for full scan, 'module' for individual module")
    parser.add_argument("--module", choices=[
                         'subdomain_discovery', 'dns_enumeration', 'service_discovery',
                         'web_crawl', 'web_fingerprinting', 'directory_bruteforce',
                         'api_discovery', 'cloud_detection'
                       ], help="Module to run when in 'module' mode")
    parser.add_argument("--modules", nargs='+', help="Specific modules to run in pipeline mode")
    
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
    ai_group.add_argument("--cache-size", type=int, default=128, help="Size of AI response cache")
    
    # Module-specific arguments
    module_group = parser.add_argument_group('Module-Specific Options')
    module_group.add_argument("--wordlist-path", help="Path to wordlist file for subdomain discovery or directory bruteforce")
    module_group.add_argument("--crawl-level", choices=['quick', 'smart', 'deep'], 
                             default='smart', help="Level of web crawling")
    module_group.add_argument("--recursive", action="store_true", help="Enable recursive directory scanning")
    module_group.add_argument("--max-depth", type=int, default=2, help="Maximum recursion depth for directory bruteforce")
    module_group.add_argument("--max-endpoints", type=int, default=500, help="Maximum number of API endpoints to test")
    module_group.add_argument("--extensions", nargs='+', help="File extensions to check in directory bruteforce")
    
    # Advanced configuration
    advanced_group = parser.add_argument_group('Advanced Configuration')
    advanced_group.add_argument("--config-file", help="Path to JSON configuration file for advanced settings")
    
    args = parser.parse_args()
    
    # Load advanced configuration from file if provided
    module_config = None
    if args.config_file and os.path.exists(args.config_file):
        try:
            with open(args.config_file, 'r') as f:
                module_config = json.load(f)
            print(f"📋 Loaded configuration from {args.config_file}")
        except json.JSONDecodeError:
            print(f"⚠️ Error parsing configuration file. Using default settings.")
    
    print(f"🎯 Starting reconnaissance for {args.domain}")
    
    if args.mode == 'pipeline':
        print(f"🔄 Running pipeline mode")
        print(f"📊 Port scan mode: {args.scan_mode.upper()}")
        if args.scan_mode == 'quick':
            print("   - Scanning common ports only (fastest)")
        elif args.scan_mode == 'smart':
            print("   - Intelligent fuzzing and extended port discovery")
        elif args.scan_mode == 'deep':
            print("   - Comprehensive scan using external tools (nmap/rustscan)")
        
        # Initialize and run pipeline
        recon = DomainRecon(
            args.domain, 
            gemini_api_key=args.gemini_key,
            openai_api_key=args.openai_key,
            anthropic_api_key=args.anthropic_key,
            use_async=args.use_async,
            module_config=module_config
        )
        
        if args.modules:
            print(f"🧩 Running selected modules: {', '.join(args.modules)}")
            recon.run_all(args.scan_mode, modules_to_run=args.modules)
        else:
            print(f"🧩 Running all modules")
            recon.run_all(args.scan_mode)
            
    elif args.mode == 'module':
        if not args.module:
            parser.error("--module is required when using --mode=module")
        
        print(f"🧩 Running individual module: {args.module}")
        
        # Prepare module-specific parameters
        module_params = {}
        
        if args.module == 'subdomain_discovery':
            if args.wordlist_path:
                module_params['wordlist'] = args.wordlist_path
                
        elif args.module == 'service_discovery':
            module_params['scan_mode'] = args.scan_mode
            
        elif args.module == 'web_crawl':
            module_params['crawl_level'] = args.crawl_level
            if args.wordlist_path:
                module_params['wordlist_path'] = args.wordlist_path
                
        elif args.module == 'directory_bruteforce':
            if args.wordlist_path:
                module_params['wordlist_path'] = args.wordlist_path
            module_params['recursive'] = args.recursive
            module_params['depth'] = args.max_depth
            if args.extensions:
                module_params['extensions'] = args.extensions
                
        elif args.module == 'api_discovery':
            if args.wordlist_path:
                module_params['wordlist_path'] = args.wordlist_path
            module_params['max_endpoints'] = args.max_endpoints
        
        # Initialize and run individual module
        recon = DomainRecon(
            args.domain, 
            gemini_api_key=args.gemini_key,
            openai_api_key=args.openai_key,
            anthropic_api_key=args.anthropic_key,
            use_async=args.use_async,
            module_config=module_config
        )
        
        # Run the module and display results
        result = recon.run_module(args.module, **module_params)
        print(f"✅ Module execution complete. Results saved to {recon.output_dir}/{args.module}_report.json")