#!/usr/bin/env python3
"""
Unified Web Domain Scanner - Main Module
========================================

This module combines all reconnaissance modules into a unified interface:
- Domain Enumeration (Passive, Active, DNS, Web Fingerprinting)
- Service Discovery (Port Scanning, Service Identification)
- Web Analysis (CDN Detection, Bypass, Web Crawling)

Author: Web Domain Scanner Project
License: See LICENSE file in project root
"""

import argparse
import sys
import os
import json
import logging
import time
from typing import Dict, List, Any, Optional
from datetime import datetime

# Add module paths
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(current_dir)
sys.path.append(os.path.join(current_dir, 'domain_enumeration'))
sys.path.append(os.path.join(current_dir, 'service_discovery'))
sys.path.append(os.path.join(current_dir, 'web_analysis'))

# Import execute functions from each module
try:
    from domain_enumeration.main import execute_domain_enumeration, DomainEnumerationConfig, create_config_from_args as create_domain_config
    DOMAIN_ENUMERATION_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Domain enumeration not available: {e}")
    DOMAIN_ENUMERATION_AVAILABLE = False

try:
    from service_discovery.main import execute_service_discovery
    SERVICE_DISCOVERY_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Service discovery not available: {e}")
    SERVICE_DISCOVERY_AVAILABLE = False

try:
    from web_analysis.main import execute_web_analysis
    WEB_ANALYSIS_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Web analysis not available: {e}")
    WEB_ANALYSIS_AVAILABLE = False

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class UnifiedScannerConfig:
    """Unified configuration for all scanner modules"""
    
    def __init__(self):
        # Global settings
        self.target_domain = None
        self.verbose = False
        self.output_dir = "results"
        self.save_results = True
        self.enabled_modules = ['domain_enumeration', 'service_discovery', 'web_analysis']
        
        # Domain Enumeration settings
        self.domain_enum_modules = ['passive', 'active', 'dns', 'fingerprinting']
        self.domain_output_file = None
        
        # Passive enumeration
        self.passive_timeout = 10
        self.passive_concurrent = 5
        
        # Active enumeration
        self.active_threads = 10
        self.active_rate_limit = 10
        self.active_timeout = 5
        self.wordlist = None
        self.no_ai = False
        
        # DNS enumeration
        self.dns_timeout = 5
        self.dns_retries = 3
        self.record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        
        # Fingerprinting
        self.fingerprint_timeout = 30
        self.fingerprint_concurrent = 5
        self.include_http = True
        self.include_www = True
        
        # Service Discovery settings
        self.scan_mode = 'smart'
        self.ports = None
        self.service_output_format = 'json'
        
        # Web Analysis settings
        self.bypass_cdn = True
        self.deep_crawl = False
        self.setup_logging = True


def execute_unified_scan(config: UnifiedScannerConfig) -> Dict[str, Any]:
    """
    Execute comprehensive scan using all available modules.
    
    Args:
        config: UnifiedScannerConfig object with all settings
        
    Returns:
        Dict containing results from all executed modules
    """
    start_time = time.time()
    results = {
        'target_domain': config.target_domain,
        'scan_timestamp': datetime.now().isoformat(),
        'enabled_modules': config.enabled_modules,
        'modules': {},
        'summary': {},
        'execution_time': 0
    }
    
    if config.verbose:
        logger.info(f"Starting unified scan for domain: {config.target_domain}")
        logger.info(f"Enabled modules: {', '.join(config.enabled_modules)}")
    
    # 1. Domain Enumeration
    if 'domain_enumeration' in config.enabled_modules and DOMAIN_ENUMERATION_AVAILABLE:
        try:
            if config.verbose:
                logger.info("=" * 60)
                logger.info("STARTING DOMAIN ENUMERATION")
                logger.info("=" * 60)
            
            # Create domain enumeration configuration
            domain_config = DomainEnumerationConfig()
            domain_config.domain = config.target_domain
            domain_config.verbose = config.verbose
            domain_config.output_file = config.domain_output_file
            domain_config.enabled_modules = config.domain_enum_modules
            
            # Passive configuration
            domain_config.passive_config['timeout'] = config.passive_timeout
            domain_config.passive_config['concurrent_requests'] = config.passive_concurrent
            
            # Active configuration
            domain_config.active_config['max_threads'] = config.active_threads
            domain_config.active_config['rate_limit'] = config.active_rate_limit
            domain_config.active_config['timeout'] = config.active_timeout
            if config.wordlist:
                domain_config.active_config['wordlist_file'] = config.wordlist
            domain_config.active_config['disable_ai'] = config.no_ai
            
            # DNS configuration
            domain_config.dns_config['timeout'] = config.dns_timeout
            domain_config.dns_config['retries'] = config.dns_retries
            domain_config.dns_config['record_types'] = config.record_types
            
            # Fingerprinting configuration
            domain_config.fingerprinting_config['timeout'] = config.fingerprint_timeout
            domain_config.fingerprinting_config['concurrent'] = config.fingerprint_concurrent
            domain_config.fingerprinting_config['include_http'] = config.include_http
            domain_config.fingerprinting_config['include_www'] = config.include_www
            
            # Execute domain enumeration
            domain_results = execute_domain_enumeration(domain_config)
            results['modules']['domain_enumeration'] = domain_results
            
            if config.verbose:
                total_subdomains = len(domain_results.get('all_subdomains', []))
                logger.info(f"Domain enumeration completed. Found {total_subdomains} subdomains")
                
        except Exception as e:
            logger.error(f"Domain enumeration failed: {e}")
            results['modules']['domain_enumeration'] = {
                'success': False,
                'error': str(e)
            }
    
    # 2. Service Discovery
    if 'service_discovery' in config.enabled_modules and SERVICE_DISCOVERY_AVAILABLE:
        try:
            if config.verbose:
                logger.info("=" * 60)
                logger.info("STARTING SERVICE DISCOVERY")
                logger.info("=" * 60)
            
            # Execute service discovery
            service_results = execute_service_discovery(
                scan_mode=config.scan_mode,
                target=config.target_domain,
                ports=config.ports,
                output_format=config.service_output_format,
                verbose=config.verbose
            )
            results['modules']['service_discovery'] = service_results
            
            if config.verbose:
                if service_results.get('success', False):
                    open_ports = service_results.get('summary', {}).get('open_ports_count', 0)
                    logger.info(f"Service discovery completed. Found {open_ports} open ports")
                else:
                    logger.error(f"Service discovery failed: {service_results.get('error', 'Unknown error')}")
                    
        except Exception as e:
            logger.error(f"Service discovery failed: {e}")
            results['modules']['service_discovery'] = {
                'success': False,
                'error': str(e)
            }
    
    # 3. Web Analysis
    if 'web_analysis' in config.enabled_modules and WEB_ANALYSIS_AVAILABLE:
        try:
            if config.verbose:
                logger.info("=" * 60)
                logger.info("STARTING WEB ANALYSIS")
                logger.info("=" * 60)
            
            # Execute web analysis
            web_results = execute_web_analysis(
                domain=config.target_domain,
                bypass_cdn=config.bypass_cdn,
                deep_crawl=config.deep_crawl,
                output_dir=config.output_dir,
                save_to_file=config.save_results,
                verbose=config.verbose,
                setup_logging=config.setup_logging
            )
            results['modules']['web_analysis'] = web_results
            
            if config.verbose:
                if web_results.get('success', False):
                    cdn_detected = web_results.get('cdn_detection', {}).get('cdn_detected', False)
                    logger.info(f"Web analysis completed. CDN detected: {cdn_detected}")
                else:
                    logger.error(f"Web analysis failed: {web_results.get('error', 'Unknown error')}")
                    
        except Exception as e:
            logger.error(f"Web analysis failed: {e}")
            results['modules']['web_analysis'] = {
                'success': False,
                'error': str(e)
            }
    
    # Compile summary
    results['execution_time'] = time.time() - start_time
    results['summary'] = compile_unified_summary(results)
    
    if config.verbose:
        logger.info("=" * 60)
        logger.info("UNIFIED SCAN COMPLETED")
        logger.info("=" * 60)
        logger.info(f"Total execution time: {results['execution_time']:.2f} seconds")
    
    return results


def execute_unified_scan_with_params(target_domain: str, 
                                   enabled_modules: List[str] = None,
                                   verbose: bool = False,
                                   output_dir: str = "results",
                                   save_results: bool = True,
                                   # Domain enumeration params
                                   domain_enum_modules: List[str] = None,
                                   passive_timeout: int = 10,
                                   active_threads: int = 10,
                                   dns_timeout: int = 5,
                                   fingerprint_timeout: int = 30,
                                   wordlist: str = None,
                                   no_ai: bool = False,
                                   # Service discovery params
                                   scan_mode: str = 'smart',
                                   ports: str = None,
                                   service_output_format: str = 'json',
                                   # Web analysis params
                                   bypass_cdn: bool = True,
                                   deep_crawl: bool = False,
                                   setup_logging: bool = True) -> Dict[str, Any]:
    """
    Execute unified scan with function parameters instead of command line arguments.
    
    Args:
        target_domain: Domain to scan
        enabled_modules: List of modules to run ['domain_enumeration', 'service_discovery', 'web_analysis']
        verbose: Enable verbose logging
        output_dir: Output directory for results
        save_results: Whether to save results to files
        domain_enum_modules: Domain enumeration sub-modules to run
        passive_timeout: Timeout for passive enumeration
        active_threads: Number of threads for active enumeration
        dns_timeout: DNS query timeout
        fingerprint_timeout: Web fingerprinting timeout
        wordlist: Custom wordlist file for active enumeration
        no_ai: Disable AI-enhanced enumeration
        scan_mode: Port scanning mode ('quick', 'smart', 'deep')
        ports: Specific ports to scan
        service_output_format: Service discovery output format
        bypass_cdn: Whether to attempt CDN bypass
        deep_crawl: Whether to perform deep web crawling
        setup_logging: Whether to set up logging configuration
        
    Returns:
        Dict containing comprehensive scan results
    """
    # Create configuration
    config = UnifiedScannerConfig()
    config.target_domain = target_domain
    config.enabled_modules = enabled_modules or ['domain_enumeration', 'service_discovery', 'web_analysis']
    config.verbose = verbose
    config.output_dir = output_dir
    config.save_results = save_results
    
    # Domain enumeration settings
    config.domain_enum_modules = domain_enum_modules or ['passive', 'active', 'dns', 'fingerprinting']
    config.passive_timeout = passive_timeout
    config.active_threads = active_threads
    config.dns_timeout = dns_timeout
    config.fingerprint_timeout = fingerprint_timeout
    config.wordlist = wordlist
    config.no_ai = no_ai
    
    # Service discovery settings
    config.scan_mode = scan_mode
    config.ports = ports
    config.service_output_format = service_output_format
    
    # Web analysis settings
    config.bypass_cdn = bypass_cdn
    config.deep_crawl = deep_crawl
    config.setup_logging = setup_logging
    
    return execute_unified_scan(config)


def compile_unified_summary(results: Dict[str, Any]) -> Dict[str, Any]:
    """Compile summary statistics from all modules"""
    summary = {
        'total_modules_run': 0,
        'successful_modules': 0,
        'failed_modules': 0,
        'total_subdomains': 0,
        'total_open_ports': 0,
        'cdn_detected': False,
        'technologies_detected': 0,
        'apis_discovered': 0
    }
    
    modules = results.get('modules', {})
    
    # Domain enumeration summary
    if 'domain_enumeration' in modules:
        summary['total_modules_run'] += 1
        domain_result = modules['domain_enumeration']
        
        if domain_result.get('statistics', {}).get('modules_executed', 0) > 0:
            summary['successful_modules'] += 1
            summary['total_subdomains'] = len(domain_result.get('all_subdomains', []))
            summary['technologies_detected'] = len(
                domain_result.get('modules', {}).get('fingerprinting', {}).get('summary', {}).get('unique_technologies', [])
            )
        else:
            summary['failed_modules'] += 1
    
    # Service discovery summary
    if 'service_discovery' in modules:
        summary['total_modules_run'] += 1
        service_result = modules['service_discovery']
        
        if service_result.get('success', False):
            summary['successful_modules'] += 1
            summary['total_open_ports'] = service_result.get('summary', {}).get('open_ports_count', 0)
        else:
            summary['failed_modules'] += 1
    
    # Web analysis summary
    if 'web_analysis' in modules:
        summary['total_modules_run'] += 1
        web_result = modules['web_analysis']
        
        if web_result.get('success', False):
            summary['successful_modules'] += 1
            summary['cdn_detected'] = web_result.get('cdn_detection', {}).get('cdn_detected', False)
            
            # Count API endpoints discovered
            web_crawl = web_result.get('web_crawl', {})
            if web_crawl:
                summary['apis_discovered'] = len(web_crawl.get('apis', []))
        else:
            summary['failed_modules'] += 1
    
    return summary


def print_unified_results(results: Dict[str, Any], format_type: str = 'text') -> None:
    """Print unified scan results in specified format"""
    
    if format_type == 'json':
        print(json.dumps(results, indent=2, default=str))
        return
    
    # Text format output
    print("\n" + "="*80)
    print(f"     UNIFIED WEB DOMAIN SCANNER RESULTS")
    print(f"{'='*80}")
    print(f"Target Domain: {results['target_domain']}")
    print(f"Scan Timestamp: {results['scan_timestamp']}")
    print(f"Total Execution Time: {results['execution_time']:.2f} seconds")
    print(f"{'='*80}")
    
    # Summary statistics
    summary = results['summary']
    print(f"\n📊 OVERALL SUMMARY:")
    print(f"   • Total Modules Run: {summary['total_modules_run']}")
    print(f"   • Successful Modules: {summary['successful_modules']}")
    print(f"   • Failed Modules: {summary['failed_modules']}")
    print(f"   • Total Subdomains Found: {summary['total_subdomains']}")
    print(f"   • Total Open Ports: {summary['total_open_ports']}")
    print(f"   • CDN Detected: {'Yes' if summary['cdn_detected'] else 'No'}")
    print(f"   • Technologies Detected: {summary['technologies_detected']}")
    print(f"   • API Endpoints Discovered: {summary['apis_discovered']}")
    
    # Module-specific results
    modules = results.get('modules', {})
    
    # Domain Enumeration Results
    if 'domain_enumeration' in modules:
        domain_result = modules['domain_enumeration']
        print(f"\n🔍 DOMAIN ENUMERATION:")
        
        if 'statistics' in domain_result:
            stats = domain_result['statistics']
            print(f"   • Modules Executed: {stats.get('modules_executed', 0)}")
            print(f"   • Total Subdomains: {stats.get('total_subdomains', 0)}")
            print(f"   • Total Execution Time: {stats.get('total_execution_time', 0):.2f}s")
        
        if 'all_subdomains' in domain_result and len(domain_result['all_subdomains']) > 0:
            print(f"   • Top Subdomains: {', '.join(domain_result['all_subdomains'][:5])}")
            if len(domain_result['all_subdomains']) > 5:
                print(f"     (and {len(domain_result['all_subdomains']) - 5} more...)")
    
    # Service Discovery Results
    if 'service_discovery' in modules:
        service_result = modules['service_discovery']
        print(f"\n🎯 SERVICE DISCOVERY:")
        
        if service_result.get('success', False):
            summary_stats = service_result.get('summary', {})
            print(f"   • Scan Mode: {service_result.get('scan_mode', 'Unknown')}")
            print(f"   • Open Ports: {summary_stats.get('open_ports_count', 0)}")
            print(f"   • Services Identified: {summary_stats.get('services_identified', 0)}")
            print(f"   • Scan Duration: {summary_stats.get('scan_duration', 0):.2f}s")
            
            # Show some open ports
            service_data = service_result.get('service_results', {})
            if 'services' in service_data and service_data['services']:
                ports_list = list(service_data['services'].keys())[:3]
                print(f"   • Sample Open Ports: {', '.join(map(str, ports_list))}")
        else:
            print(f"   • Status: Failed - {service_result.get('error', 'Unknown error')}")
    
    # Web Analysis Results
    if 'web_analysis' in modules:
        web_result = modules['web_analysis']
        print(f"\n🌐 WEB ANALYSIS:")
        
        if web_result.get('success', False):
            cdn_info = web_result.get('cdn_detection', {})
            print(f"   • CDN Detected: {cdn_info.get('cdn_detected', False)}")
            if cdn_info.get('cdn_detected', False):
                print(f"   • CDN Name: {cdn_info.get('cdn_name', 'Unknown')}")
                print(f"   • Detection Method: {cdn_info.get('detection_method', 'Unknown')}")
            
            # Web crawl results
            web_crawl = web_result.get('web_crawl', {})
            if web_crawl:
                pages = len(web_crawl.get('pages', []))
                apis = len(web_crawl.get('apis', []))
                urls = len(web_crawl.get('discovered_urls', []))
                print(f"   • Pages Crawled: {pages}")
                print(f"   • APIs Discovered: {apis}")
                print(f"   • Total URLs Found: {urls}")
        else:
            print(f"   • Status: Failed - {web_result.get('error', 'Unknown error')}")
    
    print(f"\n{'='*80}")


def save_unified_results(results: Dict[str, Any], output_dir: str = "results") -> str:
    """Save unified results to JSON file"""
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    domain_safe = results['target_domain'].replace('.', '_')
    filename = os.path.join(output_dir, f"unified_scan_{domain_safe}_{timestamp}.json")
    
    try:
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        logger.info(f"Results saved to {filename}")
        return filename
    except Exception as e:
        logger.error(f"Failed to save results: {e}")
        return None


def main():
    """Main entry point for command-line interface"""
    parser = argparse.ArgumentParser(
        description="Unified Web Domain Scanner - Comprehensive reconnaissance toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py example.com
  python main.py example.com --verbose --output-dir ./results
  python main.py example.com --modules domain_enumeration service_discovery
  python main.py example.com --scan-mode deep --bypass-cdn --deep-crawl
  python main.py example.com --ports 80,443,8080 --active-threads 20
        """
    )
    
    # Required arguments
    parser.add_argument('domain', help='Target domain to scan')
    
    # Global options
    parser.add_argument('--modules', nargs='+', 
                       choices=['domain_enumeration', 'service_discovery', 'web_analysis'],
                       default=['domain_enumeration', 'service_discovery', 'web_analysis'],
                       help='Modules to run (default: all)')
    parser.add_argument('--verbose', '-v', action='store_true', 
                       help='Enable verbose output')
    parser.add_argument('--output-dir', default='results',
                       help='Output directory for results')
    parser.add_argument('--format', choices=['text', 'json'], default='text',
                       help='Output format (default: text)')
    parser.add_argument('--save-results', action='store_true', default=True,
                       help='Save results to JSON file')
    
    # Domain enumeration options
    parser.add_argument('--domain-modules', nargs='+',
                       choices=['passive', 'active', 'dns', 'fingerprinting'],
                       default=['passive', 'active', 'dns', 'fingerprinting'],
                       help='Domain enumeration modules to run')
    parser.add_argument('--passive-timeout', type=int, default=10,
                       help='Passive enumeration timeout (default: 10)')
    parser.add_argument('--active-threads', type=int, default=10,
                       help='Active enumeration threads (default: 10)')
    parser.add_argument('--dns-timeout', type=int, default=5,
                       help='DNS enumeration timeout (default: 5)')
    parser.add_argument('--fingerprint-timeout', type=int, default=30,
                       help='Web fingerprinting timeout (default: 30)')
    parser.add_argument('--wordlist', help='Custom wordlist for active enumeration')
    parser.add_argument('--no-ai', action='store_true',
                       help='Disable AI-enhanced enumeration')
    
    # Service discovery options
    parser.add_argument('--scan-mode', choices=['quick', 'smart', 'deep'], default='smart',
                       help='Port scanning mode (default: smart)')
    parser.add_argument('--ports', help='Specific ports to scan (e.g., 80,443,22 or 1-1000)')
    
    # Web analysis options
    parser.add_argument('--no-bypass-cdn', action='store_true',
                       help='Skip CDN bypass even if detected')
    parser.add_argument('--deep-crawl', action='store_true',
                       help='Perform deep web crawling')
    
    args = parser.parse_args()
    
    # Create configuration
    config = UnifiedScannerConfig()
    config.target_domain = args.domain
    config.enabled_modules = args.modules
    config.verbose = args.verbose
    config.output_dir = args.output_dir
    config.save_results = args.save_results
    
    # Domain enumeration settings
    config.domain_enum_modules = args.domain_modules
    config.passive_timeout = args.passive_timeout
    config.active_threads = args.active_threads
    config.dns_timeout = args.dns_timeout
    config.fingerprint_timeout = args.fingerprint_timeout
    config.wordlist = args.wordlist
    config.no_ai = args.no_ai
    
    # Service discovery settings
    config.scan_mode = args.scan_mode
    config.ports = args.ports
    
    # Web analysis settings
    config.bypass_cdn = not args.no_bypass_cdn
    config.deep_crawl = args.deep_crawl
    
    print(f"🔍 Starting unified scan for domain: {args.domain}")
    print(f"📋 Enabled modules: {', '.join(args.modules)}")
    
    # Execute unified scan
    results = execute_unified_scan(config)
    
    # Display results
    print_unified_results(results, args.format)
    
    # Save results if requested
    if args.save_results:
        output_file = save_unified_results(results, args.output_dir)
        if output_file:
            print(f"\n💾 Results saved to: {output_file}")
    
    # Exit with appropriate code
    success_modules = results['summary']['successful_modules']
    total_modules = results['summary']['total_modules_run']
    
    if success_modules == total_modules and total_modules > 0:
        print(f"\n✅ All {total_modules} modules completed successfully!")
        sys.exit(0)
    elif success_modules > 0:
        print(f"\n⚠️  {success_modules}/{total_modules} modules completed successfully")
        sys.exit(1)
    else:
        print(f"\n❌ All modules failed to execute")
        sys.exit(2)


if __name__ == "__main__":
    main()
