#!/usr/bin/env python3
"""
Main entry point for the Web Domain Scanner & Service Discovery Module
"""
import argparse
import logging
from datetime import datetime
import os
import sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from modules.domain_enumeration import DomainEnumerator
from modules.service_discovery import ServiceDiscoverer
# from src.modules.web_crawling import WebCrawler
# from src.modules.cloud_detection import CloudDetector
from modules.ai_integration import AIIntegration
# from src.output.report_generator import ReportGenerator

def setup_logging():
    """Configure logging for the application"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(f'scanner_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'),
            logging.StreamHandler()
        ]
    )

def main():
    """Main function to run the scanner"""
    parser = argparse.ArgumentParser(description='Web Domain Scanner & Service Discovery Module')
    parser.add_argument('target', help='Target domain or URL to scan')
    parser.add_argument('-o', '--output', help='Output directory for results', default='results')
    parser.add_argument('--passive-only', action='store_true', help='Perform only passive reconnaissance')
    parser.add_argument('--no-ai', action='store_true', help='Disable AI-powered features')
    parser.add_argument('--threads', type=int, default=10, help='Number of threads to use')
    parser.add_argument('--rate-limit', type=int, default=5, help='Requests per second limit')
    
    args = parser.parse_args()
    setup_logging()
    
    # Initialize modules
    ai_integration = AIIntegration(not args.no_ai)
    domain_enum = DomainEnumerator(args.target, args.threads, args.rate_limit, ai_integration)
    service_disc = ServiceDiscoverer(args.target, args.threads)
    # web_crawler = WebCrawler(args.target, args.threads, args.rate_limit, ai_integration)
    # cloud_detector = CloudDetector(args.target)
    
    # Perform reconnaissance
    results = {}
    
    try:
        logging.info(f"Starting reconnaissance on {args.target}")
        
        # Domain enumeration - FIXED THIS PART
        passive_results = domain_enum.passive_enumeration()
        if not args.passive_only:
            active_results = domain_enum.active_enumeration()
            # Combine passive and active results
            results['subdomains'] = {
                'passive': passive_results['passive'],
                'active': active_results['active'],
                'all': domain_enum.get_all_subdomains()
            }
        else:
            results['subdomains'] = {
                'passive': passive_results['passive'],
                'active': [],
                'all': passive_results['passive']
            }
        
        # Service discovery
        results['services'] = service_disc.discover_services()
        
        # Web crawling and fuzzing
        # results['web_technologies'] = web_crawler.fingerprint_technologies()
        # results['directories'] = web_crawler.directory_bruteforce()
        # results['api_endpoints'] = web_crawler.api_discovery()
        
        # Cloud detection
        # results['cloud_services'] = cloud_detector.detect_cloud_services()
        
        # Generate report
        # report_gen = ReportGenerator(results, args.target, args.output)
        # report_path = report_gen.generate_report()
        
        # logging.info(f"Reconnaissance completed. Report saved to {report_path}")
        
    except KeyboardInterrupt:
        logging.info("Scan interrupted by user")
    except Exception as e:
        logging.error(f"Scan failed: {str(e)}")
        import traceback
        logging.error(traceback.format_exc())

if __name__ == "__main__":
    main()