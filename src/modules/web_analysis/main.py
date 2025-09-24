# main.py
"""
Main Reconnaissance Toolkit
---------------------------
Combines CDN detection and web crawling into a unified tool.
"""

import argparse
import logging
import json
import os
from browser_manager.browser_manager import BrowserManager
from cdn_detector.cdn_detector import CDNDetector
from web_crawler.web_crawler import WebCrawler

class ReconToolkit:
    def __init__(self, domain: str):
        self.domain = domain
        self.results = {}
        
    def run(self, bypass_cdn: bool = True, deep_crawl: bool = False):
        """
        Run the complete reconnaissance process
        
        Args:
            bypass_cdn: Whether to attempt CDN bypass if detected
            deep_crawl: Whether to perform deep crawling after CDN bypass
        """
        logging.info(f"Starting reconnaissance for {self.domain}")
        
        # Step 1: CDN Detection
        logging.info("=" * 50)
        logging.info("CDN DETECTION")
        logging.info("=" * 50)
        
        cdn_detector = CDNDetector(self.domain)
        try:
            cdn_results = cdn_detector.detect_cdn()
            self.results['cdn_detection'] = cdn_results
            
            # Step 2: Check for blocking content if CDN is detected
            if cdn_results['cdn_detected']:
                logging.info("\n" + "=" * 50)
                logging.info("CHECKING FOR CDN BLOCKING")
                logging.info("=" * 50)
                
                blocking_check = cdn_detector.check_for_blocking_content()
                # Store blocking check but remove internal content field
                self.results['blocking_check'] = {
                    k: v for k, v in blocking_check.items() if k != '_content'
                }
                
                # Step 3: Only attempt CDN bypass if content is actually blocked
                if bypass_cdn and blocking_check['is_blocked']:
                    logging.info("\n" + "=" * 50)
                    logging.info("CDN BYPASS (Content is blocked)")
                    logging.info("=" * 50)
                    
                    bypass_results = cdn_detector.bypass_cdn()
                    self.results['cdn_bypass'] = bypass_results
                    
                    # Always perform API discovery when CDN bypass is attempted
                    if bypass_results.get('bypass_successful', False):
                        logging.info("\n" + "=" * 50)
                        logging.info("API ENDPOINT DISCOVERY WITH CDN BYPASS")
                        logging.info("=" * 50)
                        
                        web_crawler = WebCrawler(self.domain)
                        try:
                            # Get fresh bypassed content for analysis
                            bypassed_content = cdn_detector.get_bypassed_content()
                            
                            # Pass the bypass driver to web crawler for endpoint testing
                            bypass_driver = cdn_detector.get_bypass_driver()
                            if bypass_driver:
                                # Set the bypass driver in web crawler for testing endpoints
                                web_crawler._bypass_driver = bypass_driver
                            
                            crawl_results = web_crawler.crawl_with_cdn_bypass(bypassed_content)
                            
                            # Clean up content from results
                            if 'pages' in crawl_results:
                                for page in crawl_results['pages']:
                                    if 'content' in page:
                                        del page['content']
                                    if 'text_content' in page:
                                        page['text_content'] = page['text_content'][:200] + "..." if len(page['text_content']) > 200 else page['text_content']
                            
                            self.results['web_crawl'] = crawl_results
                            
                            # Log API discovery results
                            api_discovery = crawl_results.get('api_discovery', {})
                            total_apis = sum(len(v) if isinstance(v, list) else 0 for v in api_discovery.values())
                            logging.info(f"API Discovery completed: {total_apis} endpoints found")
                            
                        finally:
                            web_crawler.close()
                            # Close the bypass driver after endpoint testing is complete
                            cdn_detector.close_bypass_driver()
                    
                    # Additional deep crawling if requested
                    if deep_crawl and bypass_results.get('bypass_successful', False):
                        logging.info("\n" + "=" * 50)
                        logging.info("DEEP WEB CRAWLING WITH CDN BYPASS")
                        logging.info("=" * 50)
                        
                        web_crawler = WebCrawler(self.domain)
                        try:
                            # Get fresh bypassed content for deep crawling
                            bypassed_content = cdn_detector.get_bypassed_content()
                            
                            deep_crawl_results = web_crawler.run_crawl_level('deep', bypassed_content)
                            
                            # Clean up content from deep crawl results
                            if 'pages' in deep_crawl_results:
                                for page in deep_crawl_results['pages']:
                                    if 'content' in page:
                                        del page['content']
                                    if 'text_content' in page:
                                        page['text_content'] = page['text_content'][:200] + "..." if len(page['text_content']) > 200 else page['text_content']
                            
                            # Merge results
                            if 'web_crawl' in self.results:
                                self.results['web_crawl']['deep_crawl'] = deep_crawl_results
                            else:
                                self.results['web_crawl'] = deep_crawl_results
                        finally:
                            web_crawler.close()
                            
                elif bypass_cdn and not blocking_check['is_blocked']:
                    logging.info("\n" + "=" * 50)
                    logging.info("CDN BYPASS SKIPPED (Content is accessible)")
                    logging.info("=" * 50)
                    logging.info("CDN detected but content is not blocked. Using normal content.")
                    
                    # Store the normal content as if it was from bypass (but don't include content in results)
                    self.results['cdn_bypass'] = {
                        'bypass_attempted': False,
                        'bypass_successful': True,
                        'method': 'normal_request'
                    }
                    
                    # Always perform API discovery when CDN is detected (regardless of deep_crawl flag)
                    logging.info("\n" + "=" * 50)
                    logging.info("API ENDPOINT DISCOVERY")
                    logging.info("=" * 50)
                    
                    web_crawler = WebCrawler(self.domain)
                    try:
                        # Use the content we already obtained from blocking check
                        content_from_blocking_check = blocking_check.get('_content')
                        
                        # Perform API discovery using the already obtained content
                        crawl_results = web_crawler.crawl_with_cdn_bypass(content_from_blocking_check)
                        
                        # Remove content from results to keep them clean
                        if 'pages' in crawl_results:
                            for page in crawl_results['pages']:
                                if 'content' in page:
                                    del page['content']
                                if 'text_content' in page:
                                    # Keep only a short summary for debugging, not full content
                                    page['text_content'] = page['text_content'][:200] + "..." if len(page['text_content']) > 200 else page['text_content']
                        
                        self.results['web_crawl'] = crawl_results
                        
                        # Log API discovery results
                        api_discovery = crawl_results.get('api_discovery', {})
                        total_apis = sum(len(v) if isinstance(v, list) else 0 for v in api_discovery.values())
                        logging.info(f"API Discovery completed: {total_apis} endpoints found")
                        
                    finally:
                        web_crawler.close()
                        
                    # Additional deep crawling if requested
                    if deep_crawl:
                        logging.info("\n" + "=" * 50)
                        logging.info("DEEP WEB CRAWLING WITH NORMAL CONTENT")
                        logging.info("=" * 50)
                        
                        web_crawler = WebCrawler(self.domain)
                        try:
                            # Use the same content for deep crawling to avoid another request
                            content_from_blocking_check = blocking_check.get('_content')
                            
                            # Perform deeper crawling for more comprehensive results
                            deep_crawl_results = web_crawler.run_crawl_level('deep', content_from_blocking_check)
                            
                            # Clean up content from deep crawl results
                            if 'pages' in deep_crawl_results:
                                for page in deep_crawl_results['pages']:
                                    if 'content' in page:
                                        del page['content']
                                    if 'text_content' in page:
                                        page['text_content'] = page['text_content'][:200] + "..." if len(page['text_content']) > 200 else page['text_content']
                            
                            # Merge results
                            if 'web_crawl' in self.results:
                                self.results['web_crawl']['deep_crawl'] = deep_crawl_results
                            else:
                                self.results['web_crawl'] = deep_crawl_results
                        finally:
                            web_crawler.close()
            
            # If no CDN detected, always perform API discovery
            else:
                logging.info("\n" + "=" * 50)
                logging.info("API ENDPOINT DISCOVERY (No CDN detected)")
                logging.info("=" * 50)
                
                web_crawler = WebCrawler(self.domain)
                try:
                    # Perform API discovery using smart level by default
                    crawl_results = web_crawler.run_crawl_level('smart')
                    
                    # Clean up content from results
                    if 'pages' in crawl_results:
                        for page in crawl_results['pages']:
                            if 'content' in page:
                                del page['content']
                            if 'text_content' in page:
                                page['text_content'] = page['text_content'][:200] + "..." if len(page['text_content']) > 200 else page['text_content']
                    
                    self.results['web_crawl'] = crawl_results
                    
                    # Log API discovery results
                    api_discovery = crawl_results.get('api_discovery', {})
                    total_apis = sum(len(v) if isinstance(v, list) else 0 for v in api_discovery.values())
                    logging.info(f"API Discovery completed: {total_apis} endpoints found")
                    
                finally:
                    web_crawler.close()
                    
                # Additional deep crawling if requested
                if deep_crawl:
                    logging.info("\n" + "=" * 50)
                    logging.info("DEEP WEB CRAWLING (No CDN detected)")
                    logging.info("=" * 50)
                    
                    web_crawler = WebCrawler(self.domain)
                    try:
                        deep_crawl_results = web_crawler.run_crawl_level('deep')
                        
                        # Clean up content from deep crawl results
                        if 'pages' in deep_crawl_results:
                            for page in deep_crawl_results['pages']:
                                if 'content' in page:
                                    del page['content']
                                if 'text_content' in page:
                                    page['text_content'] = page['text_content'][:200] + "..." if len(page['text_content']) > 200 else page['text_content']
                        
                        # Merge results
                        if 'web_crawl' in self.results:
                            self.results['web_crawl']['deep_crawl'] = deep_crawl_results
                        else:
                            self.results['web_crawl'] = deep_crawl_results
                    finally:
                        web_crawler.close()
                        
        finally:
            cdn_detector.close()
            
        return self.results
        
    def save_results(self, output_dir: str = "results"):
        """Save results to JSON file"""
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
        safe_domain = self.domain.replace('.', '_')
        filename = f"{output_dir}/{safe_domain}_recon.json"
        
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
            
        logging.info(f"Results saved to {filename}")
        return filename

def execute_web_analysis(domain: str, bypass_cdn: bool = True, deep_crawl: bool = False, 
                        output_dir: str = "results", save_to_file: bool = False, 
                        verbose: bool = True, setup_logging: bool = True):
    """
    Execute comprehensive web analysis including CDN detection and web crawling
    
    Args:
        domain: Domain to analyze
        bypass_cdn: Whether to attempt CDN bypass if detected (default: True)
        deep_crawl: Whether to perform deep crawling (default: False)
        output_dir: Output directory for results (default: "results")
        save_to_file: Whether to save results to JSON file (default: False)
        verbose: Whether to print verbose output (default: True)
        setup_logging: Whether to set up logging configuration (default: True)
        
    Returns:
        Dict: Complete analysis results including CDN detection, bypass, and crawling
    """
    # Set up logging if requested
    if setup_logging:
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('recon_toolkit.log'),
                logging.StreamHandler()
            ]
        )
    
    try:
        # Run the toolkit
        toolkit = ReconToolkit(domain)
        results = toolkit.run(
            bypass_cdn=bypass_cdn,
            deep_crawl=deep_crawl
        )
        
        # Add execution metadata
        results['execution_info'] = {
            'domain': domain,
            'bypass_cdn': bypass_cdn,
            'deep_crawl': deep_crawl,
            'output_dir': output_dir,
            'save_to_file': save_to_file
        }
        
        # Print detailed results in JSON format if verbose
        if verbose:
            print("\n" + "=" * 60)
            print("DETAILED RESULTS (JSON)")
            print("=" * 60)
            print(json.dumps(results, indent=2, default=str))
        
        # Optionally save results to file
        output_file = None
        if save_to_file:
            output_file = toolkit.save_results(output_dir)
            results['output_file'] = output_file
            if verbose:
                print(f"\n💾 Results also saved to: {output_file}")
        
        # Print summary if verbose
        if verbose:
            print("\n" + "=" * 50)
            print("RECONNAISSANCE SUMMARY")
            print("=" * 50)
            print(f"Domain: {domain}")
            print(f"CDN Detected: {results['cdn_detection']['cdn_detected']}")
            
            if results['cdn_detection']['cdn_detected']:
                print(f"CDN Name: {results['cdn_detection']['cdn_name']}")
                print(f"Detection Method: {results['cdn_detection']['detection_method']}")
                
                if 'blocking_check' in results:
                    print(f"Content Blocked: {results['blocking_check']['is_blocked']}")
                    if results['blocking_check']['is_blocked']:
                        print(f"Blocked Phrases: {', '.join(results['blocking_check']['blocked_phrases'])}")
                
                if 'cdn_bypass' in results:
                    bypass_method = results['cdn_bypass'].get('method', 'browser_automation')
                    print(f"Bypass Method: {bypass_method}")
                    
                    if bypass_method == 'normal_request':
                        print("Bypass Status: Skipped (content accessible via normal request)")
                    else:
                        print(f"Bypass Attempted: {results['cdn_bypass'].get('bypass_attempted', False)}")
                        print(f"Bypass Successful: {results['cdn_bypass'].get('bypass_successful', False)}")
                    
                    if 'web_crawl' in results:
                        web_crawl = results['web_crawl']
                        pages_count = len(web_crawl.get('pages', []))
                        apis_count = len(web_crawl.get('apis', []))
                        urls_count = len(web_crawl.get('discovered_urls', []))
                        
                        print(f"Pages Crawled: {pages_count}")
                        print(f"APIs Discovered: {apis_count}")
                        print(f"URLs Found: {urls_count}")
                        
                        # Display API discovery details
                        api_discovery = web_crawl.get('api_discovery', {})
                        if api_discovery:
                            rest_apis = len(api_discovery.get('rest_apis', []))
                            graphql_apis = len(api_discovery.get('graphql_endpoints', []))
                            swagger_apis = len(api_discovery.get('swagger_endpoints', []))
                            other_apis = len(api_discovery.get('other_apis', []))
                            
                            total_discovered = rest_apis + graphql_apis + swagger_apis + other_apis
                            print(f"Total API Endpoints Found: {total_discovered}")
                            if rest_apis > 0:
                                print(f"  - REST APIs: {rest_apis}")
                            if graphql_apis > 0:
                                print(f"  - GraphQL Endpoints: {graphql_apis}")
                            if swagger_apis > 0:
                                print(f"  - Swagger/OpenAPI: {swagger_apis}")
                            if other_apis > 0:
                                print(f"  - Other APIs: {other_apis}")
                                
                            # Show some example endpoints
                            all_endpoints = []
                            for category, endpoints in api_discovery.items():
                                if isinstance(endpoints, list) and endpoints:
                                    all_endpoints.extend([ep.get('url', ep) if isinstance(ep, dict) else ep for ep in endpoints[:3]])
                            
                            if all_endpoints:
                                print(f"Sample Endpoints:")
                                for i, endpoint in enumerate(all_endpoints[:5], 1):
                                    print(f"  {i}. {endpoint}")
            
            elif 'web_crawl' in results:
                web_crawl = results['web_crawl']
                pages_count = len(web_crawl.get('pages', []))
                apis_count = len(web_crawl.get('apis', []))
                urls_count = len(web_crawl.get('discovered_urls', []))
                
                print(f"Pages Crawled: {pages_count}")
                print(f"APIs Discovered: {apis_count}")
                print(f"URLs Found: {urls_count}")
                
                # Display API discovery details
                api_discovery = web_crawl.get('api_discovery', {})
                if api_discovery:
                    rest_apis = len(api_discovery.get('rest_apis', []))
                    graphql_apis = len(api_discovery.get('graphql_endpoints', []))
                    swagger_apis = len(api_discovery.get('swagger_endpoints', []))
                    other_apis = len(api_discovery.get('other_apis', []))
                    
                    total_discovered = rest_apis + graphql_apis + swagger_apis + other_apis
                    print(f"Total API Endpoints Found: {total_discovered}")
                    if rest_apis > 0:
                        print(f"  - REST APIs: {rest_apis}")
                    if graphql_apis > 0:
                        print(f"  - GraphQL Endpoints: {graphql_apis}")
                    if swagger_apis > 0:
                        print(f"  - Swagger/OpenAPI: {swagger_apis}")
                    if other_apis > 0:
                        print(f"  - Other APIs: {other_apis}")
                        
                    # Show some example endpoints
                    all_endpoints = []
                    for category, endpoints in api_discovery.items():
                        if isinstance(endpoints, list) and endpoints:
                            all_endpoints.extend([ep.get('url', ep) if isinstance(ep, dict) else ep for ep in endpoints[:3]])
                    
                    if all_endpoints:
                        print(f"Sample Endpoints:")
                        for i, endpoint in enumerate(all_endpoints[:5], 1):
                            print(f"  {i}. {endpoint}")
        
        # Mark as successful
        results['success'] = True
        return results
        
    except Exception as e:
        error_msg = f"Web analysis failed: {str(e)}"
        logging.error(error_msg)
        if verbose:
            print(f"Error: {str(e)}")
        
        # Return error result
        return {
            'success': False,
            'error': str(e),
            'execution_info': {
                'domain': domain,
                'bypass_cdn': bypass_cdn,
                'deep_crawl': deep_crawl,
                'output_dir': output_dir,
                'save_to_file': save_to_file
            }
        }

if __name__ == "__main__":
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('recon_toolkit.log'),
            logging.StreamHandler()
        ]
    )
    
    # Parse arguments
    parser = argparse.ArgumentParser(description="Comprehensive reconnaissance toolkit")
    parser.add_argument("domain", help="Domain to analyze")
    parser.add_argument("--no-bypass", action="store_true", help="Skip CDN bypass even if CDN is detected")
    parser.add_argument("--deep-crawl", action="store_true", help="Perform deep crawling after CDN bypass")
    parser.add_argument("--output-dir", default="results", help="Output directory for results")
    parser.add_argument("--save-to-file", action="store_true", help="Save results to JSON file in addition to printing")
    
    args = parser.parse_args()
    
    # Run the toolkit
    toolkit = ReconToolkit(args.domain)
    results = toolkit.run(
        bypass_cdn=not args.no_bypass,
        deep_crawl=args.deep_crawl
    )
    
    # Print detailed results in JSON format
    print("\n" + "=" * 60)
    print("DETAILED RESULTS (JSON)")
    print("=" * 60)
    print(json.dumps(results, indent=2, default=str))
    
    # Optionally save results to file
    if args.save_to_file:
        output_file = toolkit.save_results(args.output_dir)
        print(f"\n💾 Results also saved to: {output_file}")
    
    # Print summary
    print("\n" + "=" * 50)
    print("RECONNAISSANCE SUMMARY")
    print("=" * 50)
    print(f"Domain: {args.domain}")
    print(f"CDN Detected: {results['cdn_detection']['cdn_detected']}")
    
    if results['cdn_detection']['cdn_detected']:
        print(f"CDN Name: {results['cdn_detection']['cdn_name']}")
        print(f"Detection Method: {results['cdn_detection']['detection_method']}")
        
        if 'blocking_check' in results:
            print(f"Content Blocked: {results['blocking_check']['is_blocked']}")
            if results['blocking_check']['is_blocked']:
                print(f"Blocked Phrases: {', '.join(results['blocking_check']['blocked_phrases'])}")
        
        if 'cdn_bypass' in results:
            bypass_method = results['cdn_bypass'].get('method', 'browser_automation')
            print(f"Bypass Method: {bypass_method}")
            
            if bypass_method == 'normal_request':
                print("Bypass Status: Skipped (content accessible via normal request)")
            else:
                print(f"Bypass Attempted: {results['cdn_bypass'].get('bypass_attempted', False)}")
                print(f"Bypass Successful: {results['cdn_bypass'].get('bypass_successful', False)}")
            
            if 'web_crawl' in results:
                web_crawl = results['web_crawl']
                pages_count = len(web_crawl.get('pages', []))
                apis_count = len(web_crawl.get('apis', []))
                urls_count = len(web_crawl.get('discovered_urls', []))
                
                print(f"Pages Crawled: {pages_count}")
                print(f"APIs Discovered: {apis_count}")
                print(f"URLs Found: {urls_count}")
                
                # Display API discovery details
                api_discovery = web_crawl.get('api_discovery', {})
                if api_discovery:
                    rest_apis = len(api_discovery.get('rest_apis', []))
                    graphql_apis = len(api_discovery.get('graphql_endpoints', []))
                    swagger_apis = len(api_discovery.get('swagger_endpoints', []))
                    other_apis = len(api_discovery.get('other_apis', []))
                    
                    total_discovered = rest_apis + graphql_apis + swagger_apis + other_apis
                    print(f"Total API Endpoints Found: {total_discovered}")
                    if rest_apis > 0:
                        print(f"  - REST APIs: {rest_apis}")
                    if graphql_apis > 0:
                        print(f"  - GraphQL Endpoints: {graphql_apis}")
                    if swagger_apis > 0:
                        print(f"  - Swagger/OpenAPI: {swagger_apis}")
                    if other_apis > 0:
                        print(f"  - Other APIs: {other_apis}")
                        
                    # Show some example endpoints
                    all_endpoints = []
                    for category, endpoints in api_discovery.items():
                        if isinstance(endpoints, list) and endpoints:
                            all_endpoints.extend([ep.get('url', ep) if isinstance(ep, dict) else ep for ep in endpoints[:3]])
                    
                    if all_endpoints:
                        print(f"Sample Endpoints:")
                        for i, endpoint in enumerate(all_endpoints[:5], 1):
                            print(f"  {i}. {endpoint}")
    
    elif 'web_crawl' in results:
        web_crawl = results['web_crawl']
        pages_count = len(web_crawl.get('pages', []))
        apis_count = len(web_crawl.get('apis', []))
        urls_count = len(web_crawl.get('discovered_urls', []))
        
        print(f"Pages Crawled: {pages_count}")
        print(f"APIs Discovered: {apis_count}")
        print(f"URLs Found: {urls_count}")
        
        # Display API discovery details
        api_discovery = web_crawl.get('api_discovery', {})
        if api_discovery:
            rest_apis = len(api_discovery.get('rest_apis', []))
            graphql_apis = len(api_discovery.get('graphql_endpoints', []))
            swagger_apis = len(api_discovery.get('swagger_endpoints', []))
            other_apis = len(api_discovery.get('other_apis', []))
            
            total_discovered = rest_apis + graphql_apis + swagger_apis + other_apis
            print(f"Total API Endpoints Found: {total_discovered}")
            if rest_apis > 0:
                print(f"  - REST APIs: {rest_apis}")
            if graphql_apis > 0:
                print(f"  - GraphQL Endpoints: {graphql_apis}")
            if swagger_apis > 0:
                print(f"  - Swagger/OpenAPI: {swagger_apis}")
            if other_apis > 0:
                print(f"  - Other APIs: {other_apis}")
                
            # Show some example endpoints
            all_endpoints = []
            for category, endpoints in api_discovery.items():
                if isinstance(endpoints, list) and endpoints:
                    all_endpoints.extend([ep.get('url', ep) if isinstance(ep, dict) else ep for ep in endpoints[:3]])
            
            if all_endpoints:
                print(f"Sample Endpoints:")
                for i, endpoint in enumerate(all_endpoints[:5], 1):
                    print(f"  {i}. {endpoint}")