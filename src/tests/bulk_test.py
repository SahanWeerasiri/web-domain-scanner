#!/usr/bin/env python3
"""
Bulk Test Script for Unified Web Domain Scanner
===============================================

This script runs the unified scanner on multiple domains for testing purposes.
It imports the unified module from main.py and executes quick scans on a list of domains.

Author: Web Domain Scanner Project
"""

import os
import sys
import json
import time
from datetime import datetime
from typing import List, Dict, Any

# Add the modules path to import the unified scanner
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
modules_dir = os.path.join(parent_dir, 'modules')
sys.path.append(modules_dir)

# Import the unified scanner
try:
    from main import execute_unified_scan_with_params
    print("✅ Successfully imported unified scanner from main.py")
except ImportError as e:
    print(f"❌ Failed to import unified scanner: {e}")
    sys.exit(1)

# List of approximately 50 domains for bulk testing
TEST_DOMAINS = [
    # Popular websites
    "google.com",
    "youtube.com",
    "facebook.com",
    "twitter.com",
    "instagram.com",
    "linkedin.com",
    "github.com",
    "stackoverflow.com",
    "reddit.com",
    "wikipedia.org",
    
    # Tech companies
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "netflix.com",
    "adobe.com",
    "oracle.com",
    "salesforce.com",
    "dropbox.com",
    "zoom.us",
    "slack.com",
    
    # News and media
    "bbc.com",
    "cnn.com",
    "nytimes.com",
    "reuters.com",
    "bloomberg.com",
    "forbes.com",
    "techcrunch.com",
    "wired.com",
    "theverge.com",
    "ars-technica.com",
    
    # E-commerce
    "ebay.com",
    "etsy.com",
    "shopify.com",
    "paypal.com",
    "stripe.com",
    "square.com",
    "walmart.com",
    "target.com",
    "bestbuy.com",
    "homedepot.com",
    
    # Educational and research
    "coursera.org",
    "edx.org",
    "mit.edu",
    "stanford.edu",
    "harvard.edu",
    "berkeley.edu",
    "arxiv.org",
    "researchgate.net",
    "academia.edu",
    "scholar.google.com"
]

def run_bulk_test(domains: List[str], 
                  output_dir: str = "bulk_test_results",
                  verbose: bool = False,
                  save_individual_results: bool = True) -> Dict[str, Any]:
    """
    Run bulk tests on multiple domains using the unified scanner.
    
    Args:
        domains: List of domains to test
        output_dir: Directory to save results
        verbose: Enable verbose logging for individual scans
        save_individual_results: Save results for each domain individually
        
    Returns:
        Dict containing bulk test summary and results
    """
    start_time = time.time()
    
    # Create output directory
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # Initialize results tracking
    bulk_results = {
        'test_timestamp': datetime.now().isoformat(),
        'total_domains': len(domains),
        'domains_tested': [],
        'successful_scans': 0,
        'failed_scans': 0,
        'individual_results': {},
        'summary_statistics': {},
        'execution_time': 0
    }
    
    print(f"🚀 Starting bulk test for {len(domains)} domains")
    print(f"📁 Results will be saved to: {output_dir}")
    print(f"⚙️  Quick scan mode enabled for all domains")
    print("=" * 80)
    
    # Process each domain
    for i, domain in enumerate(domains, 1):
        print(f"\n[{i}/{len(domains)}] Testing domain: {domain}")
        
        try:
            # Execute unified scan with quick/smart settings
            domain_results = execute_unified_scan_with_params(
                target_domain=domain,
                enabled_modules=['domain_enumeration', 'service_discovery', 'web_analysis'],
                verbose=verbose,
                output_dir=output_dir,
                save_results=save_individual_results,
                
                # Domain enumeration - quick settings
                domain_enum_modules=['passive', 'dns', 'fingerprinting'],  # Skip active and fingerprinting for speed
                passive_timeout=5,  # Reduced timeout
                dns_timeout=3,      # Reduced timeout
                no_ai=False,         # Disable AI for speed
                
                # Service discovery - quick settings  
                scan_mode='quick',  # Quick scan mode
                ports='80,443,22,21,25,53,110,143,993,995',  # Common ports only
                
                # Web analysis - quick settings
                bypass_cdn=False,   # Skip CDN bypass for speed
                deep_crawl=False,   # Skip deep crawling
                setup_logging=False # Disable individual logging
            )
            
            # Track results
            bulk_results['domains_tested'].append(domain)
            bulk_results['individual_results'][domain] = domain_results
            
            # Save full unified scan result for each domain
            domain_filename = os.path.join(output_dir, f"{domain.replace('.', '_')}_fullscan.json")
            with open(domain_filename, "w") as f:
                json.dump(domain_results, f, indent=2, default=str)
            # Check if scan was successful
            successful_modules = domain_results.get('summary', {}).get('successful_modules', 0)
            total_modules = domain_results.get('summary', {}).get('total_modules_run', 0)
            
            if successful_modules > 0:
                bulk_results['successful_scans'] += 1
                status = f"✅ Success ({successful_modules}/{total_modules} modules)"
            else:
                bulk_results['failed_scans'] += 1
                status = "❌ Failed (all modules failed)"
            
            execution_time = domain_results.get('execution_time', 0)
            print(f"   Status: {status}")
            print(f"   Execution time: {execution_time:.2f}s")
            
            # Brief summary of findings
            summary = domain_results.get('summary', {})
            if summary.get('total_subdomains', 0) > 0:
                print(f"   Subdomains found: {summary['total_subdomains']}")
            if summary.get('total_open_ports', 0) > 0:
                print(f"   Open ports: {summary['total_open_ports']}")
            if summary.get('cdn_detected', False):
                print(f"   CDN detected: Yes")
                
        except Exception as e:
            print(f"   ❌ Error: {str(e)}")
            bulk_results['failed_scans'] += 1
            bulk_results['individual_results'][domain] = {
                'success': False,
                'error': str(e),
                'execution_time': 0
            }
    
    # Calculate final statistics
    bulk_results['execution_time'] = time.time() - start_time
    bulk_results['summary_statistics'] = compile_bulk_statistics(bulk_results)
    
    # Save bulk results summary
    save_bulk_summary(bulk_results, output_dir)
    
    return bulk_results

def compile_bulk_statistics(bulk_results: Dict[str, Any]) -> Dict[str, Any]:
    """Compile summary statistics from all bulk test results"""
    
    stats = {
        'success_rate': 0.0,
        'average_execution_time': 0.0,
        'total_subdomains_found': 0,
        'total_open_ports_found': 0,
        'domains_with_cdn': 0,
        'total_technologies_detected': 0,
        'fastest_scan': {'domain': None, 'time': float('inf')},
        'slowest_scan': {'domain': None, 'time': 0},
        'most_subdomains': {'domain': None, 'count': 0},
        'most_open_ports': {'domain': None, 'count': 0}
    }
    
    if bulk_results['total_domains'] > 0:
        stats['success_rate'] = (bulk_results['successful_scans'] / bulk_results['total_domains']) * 100
    
    total_time = 0
    valid_scans = 0
    
    # Analyze individual results
    for domain, result in bulk_results['individual_results'].items():
        if not isinstance(result, dict) or result.get('success') == False:
            continue
            
        execution_time = result.get('execution_time', 0)
        if execution_time > 0:
            total_time += execution_time
            valid_scans += 1
            
            # Track fastest/slowest scans
            if execution_time < stats['fastest_scan']['time']:
                stats['fastest_scan'] = {'domain': domain, 'time': execution_time}
            if execution_time > stats['slowest_scan']['time']:
                stats['slowest_scan'] = {'domain': domain, 'time': execution_time}
        
        summary = result.get('summary', {})
        
        # Aggregate findings
        stats['total_subdomains_found'] += summary.get('total_subdomains', 0)
        stats['total_open_ports_found'] += summary.get('total_open_ports', 0)
        stats['total_technologies_detected'] += summary.get('technologies_detected', 0)
        
        if summary.get('cdn_detected', False):
            stats['domains_with_cdn'] += 1
        
        # Track domains with most findings
        subdomain_count = summary.get('total_subdomains', 0)
        if subdomain_count > stats['most_subdomains']['count']:
            stats['most_subdomains'] = {'domain': domain, 'count': subdomain_count}
            
        port_count = summary.get('total_open_ports', 0)
        if port_count > stats['most_open_ports']['count']:
            stats['most_open_ports'] = {'domain': domain, 'count': port_count}
    
    if valid_scans > 0:
        stats['average_execution_time'] = total_time / valid_scans
    
    return stats

def save_bulk_summary(bulk_results: Dict[str, Any], output_dir: str) -> str:
    """Save bulk test summary to JSON file"""
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    summary_file = os.path.join(output_dir, f"bulk_test_summary_{timestamp}.json")
    
    try:
        with open(summary_file, 'w') as f:
            json.dump(bulk_results, f, indent=2, default=str)
        print(f"\n📊 Bulk test summary saved to: {summary_file}")
        return summary_file
    except Exception as e:
        print(f"\n❌ Failed to save bulk summary: {e}")
        return None

def print_bulk_summary(bulk_results: Dict[str, Any]) -> None:
    """Print formatted bulk test summary"""
    
    print("\n" + "=" * 80)
    print("         BULK TEST SUMMARY")
    print("=" * 80)
    
    # Basic statistics
    print(f"Total domains tested: {bulk_results['total_domains']}")
    print(f"Successful scans: {bulk_results['successful_scans']}")
    print(f"Failed scans: {bulk_results['failed_scans']}")
    print(f"Total execution time: {bulk_results['execution_time']:.2f} seconds")
    
    # Detailed statistics
    stats = bulk_results['summary_statistics']
    print(f"\n📈 PERFORMANCE METRICS:")
    print(f"   Success rate: {stats['success_rate']:.1f}%")
    print(f"   Average scan time: {stats['average_execution_time']:.2f} seconds")
    print(f"   Fastest scan: {stats['fastest_scan']['domain']} ({stats['fastest_scan']['time']:.2f}s)")
    print(f"   Slowest scan: {stats['slowest_scan']['domain']} ({stats['slowest_scan']['time']:.2f}s)")
    
    print(f"\n🔍 DISCOVERY SUMMARY:")
    print(f"   Total subdomains found: {stats['total_subdomains_found']}")
    print(f"   Total open ports found: {stats['total_open_ports_found']}")
    print(f"   Domains with CDN: {stats['domains_with_cdn']}")
    print(f"   Technologies detected: {stats['total_technologies_detected']}")
    
    print(f"\n🏆 TOP PERFORMERS:")
    print(f"   Most subdomains: {stats['most_subdomains']['domain']} ({stats['most_subdomains']['count']} subdomains)")
    print(f"   Most open ports: {stats['most_open_ports']['domain']} ({stats['most_open_ports']['count']} ports)")
    
    print("=" * 80)

def main():
    """Main entry point for bulk testing"""
    
    print("🧪 Web Domain Scanner - Bulk Test Mode")
    print("=" * 50)
    
    # Run bulk test on predefined domains
    bulk_results = run_bulk_test(
        domains=TEST_DOMAINS,
        output_dir="bulk_test_results",
        verbose=False,  # Set to True for detailed output per domain
        save_individual_results=True
    )
    
    # Display summary
    print_bulk_summary(bulk_results)
    
    # Final status
    success_rate = bulk_results['summary_statistics']['success_rate']
    if success_rate >= 80:
        print(f"\n✅ Bulk test completed with {success_rate:.1f}% success rate!")
    elif success_rate >= 50:
        print(f"\n⚠️  Bulk test completed with {success_rate:.1f}% success rate")
    else:
        print(f"\n❌ Bulk test completed with low {success_rate:.1f}% success rate")

if __name__ == "__main__":
    main()
