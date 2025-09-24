#!/usr/bin/env python3
"""
Service Discovery Main Module

This module provides the main interface for running port scans and service identification.
It includes both programmatic function interface and command-line interface.

Author: Web Domain Scanner Project
License: See LICENSE file in project root
"""

import argparse
import sys
import json
import logging
from typing import Dict, List, Optional

from port_scanning.port_scanner import scan_target
from service_identification.service_identification import identify_services_from_scanner


def execute_service_discovery(scan_mode: str, target: str, ports: Optional[str] = None, 
                         output_format: str = 'json', verbose: bool = False) -> Dict:
    """
    Run complete service discovery including port scanning and service identification.
    
    Args:
        scan_mode (str): Scanning mode ('quick', 'smart', 'deep')
        target (str): Target IP address or hostname
        ports (str, optional): Port range or comma-separated ports
        output_format (str): Output format ('json', 'text')
        verbose (bool): Enable verbose logging
        
    Returns:
        Dict: Complete service discovery results
    """
    if verbose:
        logging.basicConfig(level=logging.DEBUG, force=True)
    else:
        logging.basicConfig(level=logging.INFO, force=True)
    
    logger = logging.getLogger(__name__)
    
    try:
        # Run port scan
        logger.info(f"Starting {scan_mode} port scan on {target}")
        if ports:
            raw_scan_output = scan_target(scan_mode, target, custom_ports=ports)
        else:
            raw_scan_output = scan_target(scan_mode, target)
        
        if not raw_scan_output or raw_scan_output.startswith("Error:") or raw_scan_output.startswith("Exception:"):
            logger.error(f"Port scan failed: {raw_scan_output}")
            return {
                'success': False,
                'error': f'Port scan failed: {raw_scan_output}',
                'scan_results': None,
                'service_results': None
            }
        
        # Convert raw scan output to structured format for service identification
        scan_results_dict = {
            'method': scan_mode,
            'target': target,
            'output': raw_scan_output,
            'raw_output': raw_scan_output
        }
        
        # Identify services on open ports
        logger.info("Starting service identification")
        service_results = identify_services_from_scanner(target, scan_results_dict)
        
        # Extract scan duration from nmap output if available
        scan_duration = 0
        for line in raw_scan_output.split('\n'):
            if 'seconds' in line and 'done' in line.lower():
                try:
                    import re
                    match = re.search(r'(\d+\.\d+)\s*seconds', line)
                    if match:
                        scan_duration = float(match.group(1))
                        break
                except:
                    pass
        
        # Compile complete results
        complete_results = {
            'success': True,
            'target': target,
            'scan_mode': scan_mode,
            'ports_scanned': ports or 'default',
            'scan_results': {
                'method': scan_mode,
                'raw_output': raw_scan_output,
                'scan_duration': scan_duration
            },
            'service_results': service_results,
            'summary': {
                'open_ports_count': service_results.get('open_ports_count', 0),
                'services_identified': len(service_results.get('services', {})),
                'scan_duration': scan_duration
            }
        }
        
        logger.info(f"Service discovery completed. Found {complete_results['summary']['open_ports_count']} open ports")
        return complete_results
        
    except Exception as e:
        logger.error(f"Service discovery failed: {e}")
        return {
            'success': False,
            'error': str(e),
            'scan_results': None,
            'service_results': None
        }


def print_results(results: Dict, format_type: str = 'text') -> None:
    """
    Print results in specified format.
    
    Args:
        results (Dict): Service discovery results
        format_type (str): Output format ('text', 'json')
    """
    if not results['success']:
        print(f"❌ Service discovery failed: {results.get('error', 'Unknown error')}")
        return
    
    if format_type == 'json':
        print(json.dumps(results, indent=2))
        return
    
    # Text format output
    service_results = results['service_results']
    summary = results['summary']
    
    print(f"\n{'='*60}")
    print(f"     SERVICE DISCOVERY RESULTS - {results['target'].upper()}")
    print(f"{'='*60}")
    print(f"Scan Mode: {results['scan_mode']}")
    print(f"Ports Scanned: {results['ports_scanned']}")
    print(f"Scan Duration: {summary['scan_duration']:.2f}s")
    print(f"{'='*60}")
    
    if summary['open_ports_count'] > 0:
        print(f"\n🎯 Found {summary['open_ports_count']} open ports with {summary['services_identified']} identified services:")
        print(f"{'-'*60}")
        
        for port, service in service_results['services'].items():
            service_name = service.get('service', 'Unknown')
            banner = service.get('banner', '')
            confidence = service.get('confidence', 'Unknown')
            
            print(f"  Port {port:>5}: {service_name:<20} [Confidence: {confidence}]")
            if banner and banner != 'No banner':
                print(f"         Banner: {banner[:80]}{'...' if len(banner) > 80 else ''}")
    else:
        print("\n❌ No open ports found")
    
    print(f"\n{'='*60}")


def main():
    """
    Main function for command-line interface.
    """
    parser = argparse.ArgumentParser(
        description="Service Discovery - Port Scanning and Service Identification",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py example.com
  python main.py 192.168.1.1 --mode quick --ports 80,443,22
  python main.py example.com --mode deep --output results.json
  python main.py 192.168.1.1 --mode smart --ports 1-1000 --format json
        """
    )
    
    parser.add_argument(
        'target',
        help='Target IP address or hostname to scan'
    )
    
    parser.add_argument(
        '--mode',
        choices=['quick', 'smart', 'deep'],
        default='smart',
        help='Scanning mode (default: smart)'
    )
    
    parser.add_argument(
        '--ports',
        help='Port range (e.g., 1-1000) or comma-separated ports (e.g., 80,443,22)'
    )
    
    parser.add_argument(
        '--format',
        choices=['text', 'json'],
        default='text',
        help='Output format (default: text)'
    )
    
    parser.add_argument(
        '--output',
        help='Output file to save results (JSON format)'
    )
    
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )
    
    args = parser.parse_args()
    
    print(f"🔍 Starting service discovery on {args.target}...")
    
    # Run service discovery
    results = execute_service_discovery(
        scan_mode=args.mode,
        target=args.target,
        ports=args.ports,
        output_format=args.format,
        verbose=args.verbose
    )
    
    # Display results
    print_results(results, args.format)
    
    # Save to file if specified
    if args.output:
        try:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"\n💾 Results saved to {args.output}")
        except Exception as e:
            print(f"\n❌ Failed to save results: {e}")
    
    # Exit with appropriate code
    sys.exit(0 if results['success'] else 1)


if __name__ == "__main__":
    main()