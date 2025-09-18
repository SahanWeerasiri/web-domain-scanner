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
            
            # Step 2: CDN Bypass if needed
            if bypass_cdn and cdn_results['cdn_detected']:
                logging.info("\n" + "=" * 50)
                logging.info("CDN BYPASS")
                logging.info("=" * 50)
                
                bypass_results = cdn_detector.bypass_cdn()
                self.results['cdn_bypass'] = bypass_results
                
                # Step 3: Web Crawling with bypassed content
                if deep_crawl and bypass_results.get('bypass_successful', False):
                    logging.info("\n" + "=" * 50)
                    logging.info("WEB CRAWLING WITH CDN BYPASS")
                    logging.info("=" * 50)
                    
                    web_crawler = WebCrawler(self.domain)
                    try:
                        crawl_results = web_crawler.crawl_with_cdn_bypass(
                            bypass_results.get('content')
                        )
                        self.results['web_crawl'] = crawl_results
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
    
    args = parser.parse_args()
    
    # Run the toolkit
    toolkit = ReconToolkit(args.domain)
    results = toolkit.run(
        bypass_cdn=not args.no_bypass,
        deep_crawl=args.deep_crawl
    )
    
    # Save results
    output_file = toolkit.save_results(args.output_dir)
    
    # Print summary
    print("\n" + "=" * 50)
    print("RECONNAISSANCE SUMMARY")
    print("=" * 50)
    print(f"Domain: {args.domain}")
    print(f"CDN Detected: {results['cdn_detection']['cdn_detected']}")
    
    if results['cdn_detection']['cdn_detected']:
        print(f"CDN Name: {results['cdn_detection']['cdn_name']}")
        print(f"Detection Method: {results['cdn_detection']['detection_method']}")
        
        if 'cdn_bypass' in results:
            print(f"Bypass Attempted: {results['cdn_bypass']['bypass_attempted']}")
            print(f"Bypass Successful: {results['cdn_bypass']['bypass_successful']}")
            
            if 'web_crawl' in results:
                print(f"Pages Crawled: {len(results['web_crawl']['pages'])}")
                print(f"APIs Discovered: {len(results['web_crawl']['apis'])}")
                print(f"URLs Found: {len(results['web_crawl']['discovered_urls'])}")
    
    print(f"\nDetailed results saved to: {output_file}")