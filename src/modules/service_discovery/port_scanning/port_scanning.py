#!/usr/bin/env python3
"""
Port Scanning Module for Service Discovery

This module contains the core port scanning functionality including quick, smart, and deep
scanning modes. It provides different scanning strategies optimized for various use cases.

Author: Web Domain Scanner Project
License: See LICENSE file in project root
"""

import socket
import logging
import time
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple, Set

# Import base utilities and configuration
try:
    from ..base import (
        ServiceDiscoveryRateLimiter, ServiceDiscoveryErrorHandler,
        PortValidator, NetworkUtils, ServiceResultsManager, PortRange, ScanMode
    )
    from ..config import ServiceDiscoveryConfig
except ImportError:
    # Fallback for direct execution - add parent directory to path
    import sys
    import os
    parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sys.path.insert(0, parent_dir)
    
    try:
        from base import (
            ServiceDiscoveryRateLimiter, ServiceDiscoveryErrorHandler,
            PortValidator, NetworkUtils, ServiceResultsManager, PortRange, ScanMode
        )
        from config import ServiceDiscoveryConfig
    except ImportError:
        # Last resort fallback
        print("Error: Could not import required modules. Please run from the service_discovery directory or ensure the module is properly installed.")
        sys.exit(1)

logger = logging.getLogger(__name__)


class PortScanner:
    """
    Core port scanning functionality with support for different scanning modes.
    """
    
    def __init__(self, target_ip: str, config: Optional[ServiceDiscoveryConfig] = None):
        """
        Initialize port scanner.
        
        Args:
            target_ip (str): Target IP address to scan
            config (ServiceDiscoveryConfig): Configuration object
        """
        self.target_ip = target_ip
        self.config = config or ServiceDiscoveryConfig()
        self.error_handler = ServiceDiscoveryErrorHandler()
        self.results_manager = ServiceResultsManager()
        
        # Initialize rate limiter if enabled
        if hasattr(self.config, 'rate_limit'):
            self.rate_limiter = ServiceDiscoveryRateLimiter(self.config.rate_limit)
        else:
            self.rate_limiter = None
        
        logger.info(f"PortScanner initialized for {target_ip}")
    
    def scan_ports(self, ports: List[int], scan_mode: str = 'quick', **kwargs) -> Dict:
        """
        Scan specified ports using the given scan mode.
        
        Args:
            ports (List[int]): List of ports to scan
            scan_mode (str): Scanning mode ('quick', 'smart', 'deep')
            **kwargs: Additional configuration parameters
            
        Returns:
            Dict: Scan results
        """
        if not ScanMode.is_valid_mode(scan_mode):
            logger.warning(f"Invalid scan mode '{scan_mode}', using 'quick'")
            scan_mode = ScanMode.QUICK
        
        logger.info(f"Starting {scan_mode} port scan of {len(ports)} ports on {self.target_ip}")
        
        # Get configuration for this scan mode
        scan_config = self.config.get_scan_config(scan_mode)
        
        # Store scan information
        self.results_manager.add_scan_info({
            'target_ip': self.target_ip,
            'scan_mode': scan_mode,
            'total_ports': len(ports),
            'scan_config': scan_config,
            'start_time': time.time()
        })
        
        if scan_mode == ScanMode.QUICK:
            return self._quick_scan(ports, scan_config)
        elif scan_mode == ScanMode.SMART:
            return self._smart_scan(ports, scan_config)
        elif scan_mode == ScanMode.DEEP:
            return self._deep_scan(ports, scan_config)
        else:
            return self._quick_scan(ports, scan_config)
    
    def _quick_scan(self, ports: List[int], scan_config: Dict) -> Dict:
        """
        Quick port scan implementation.
        
        Args:
            ports (List[int]): Ports to scan
            scan_config (Dict): Scan configuration
            
        Returns:
            Dict: Scan results
        """
        logger.info(f"[QUICK SCAN] Scanning {len(ports)} ports")
        
        start_time = time.time()
        timeout = scan_config.get('timeout', 3.0)
        max_workers = scan_config.get('max_workers', 10)
        
        def check_single_port(port: int) -> Optional[Tuple[int, Dict]]:
            """Check a single port."""
            try:
                if self.rate_limiter:
                    self.rate_limiter.acquire()
                
                if NetworkUtils.check_port(self.target_ip, port, timeout):
                    # Basic service detection
                    service = PortRange.COMMON_PORTS.get(port, 'Unknown')
                    
                    # Get banner if enabled
                    banner = "No banner"
                    if scan_config.get('enable_banner_grab', True):
                        banner = NetworkUtils.get_banner(
                            self.target_ip, port, 
                            self.config.banner_timeout, 
                            self.config.banner_max_bytes
                        )
                    
                    port_info = {
                        'service': service,
                        'banner': banner,
                        'state': 'open',
                        'scan_method': 'quick',
                        'response_time': time.time() - start_time
                    }
                    
                    return port, port_info
                    
            except Exception as e:
                self.error_handler.handle_error('quick_scan', e, f"port {port}")
            
            return None
        
        # Execute concurrent port scanning
        open_ports = {}
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_port = {executor.submit(check_single_port, port): port for port in ports}
            completed = 0
            
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                completed += 1
                
                try:
                    result = future.result()
                    if result:
                        port_num, port_info = result
                        open_ports[port_num] = port_info
                        self.results_manager.add_open_port(port_num, port_info)
                        
                        logger.info(f"  [+] Port {port_num}/{port_info['service']} is OPEN")
                    
                    # Progress indication
                    if completed % 10 == 0 or completed == len(ports):
                        progress = (completed / len(ports)) * 100
                        logger.debug(f"Quick scan progress: {completed}/{len(ports)} ({progress:.1f}%)")
                        
                except Exception as e:
                    self.error_handler.handle_error('quick_scan_result', e, f"port {port}")
        
        scan_duration = time.time() - start_time
        
        # Store scan statistics
        stats = {
            'scan_duration': round(scan_duration, 2),
            'ports_scanned': len(ports),
            'open_ports_found': len(open_ports),
            'scan_rate': round(len(ports) / scan_duration, 2)
        }
        self.results_manager.add_scan_statistics(stats)
        
        logger.info(f"[QUICK SCAN] Completed in {scan_duration:.2f}s - Found {len(open_ports)} open ports")
        
        return {
            'open_ports': open_ports,
            'scan_statistics': stats,
            'scan_mode': 'quick'
        }
    
    def _smart_scan(self, ports: List[int], scan_config: Dict) -> Dict:
        """
        Smart port scan with intelligent techniques.
        
        Args:
            ports (List[int]): Ports to scan
            scan_config (Dict): Scan configuration
            
        Returns:
            Dict: Scan results
        """
        logger.info(f"[SMART SCAN] Scanning {len(ports)} ports with intelligent techniques")
        
        start_time = time.time()
        
        # First, run a quick scan on common ports
        common_ports = [p for p in ports if p in PortRange.COMMON_PORTS]
        quick_results = self._quick_scan(common_ports, scan_config)
        
        # Analyze results and generate additional ports to scan
        extended_ports = self._generate_smart_port_extensions(
            quick_results.get('open_ports', {}), 
            ports
        )
        
        if extended_ports:
            logger.info(f"[SMART SCAN] Extending scan to {len(extended_ports)} additional ports")
            
            # Scan extended ports with enhanced detection
            extended_results = self._scan_extended_ports(extended_ports, scan_config)
            
            # Merge results
            all_open_ports = quick_results.get('open_ports', {}).copy()
            all_open_ports.update(extended_results.get('open_ports', {}))
        else:
            all_open_ports = quick_results.get('open_ports', {})
            extended_results = {'open_ports': {}}
        
        # Perform service fingerprinting on open ports
        if scan_config.get('enable_service_detection', True):
            self._enhance_service_detection(all_open_ports)
        
        scan_duration = time.time() - start_time
        
        # Compile comprehensive statistics
        stats = {
            'scan_duration': round(scan_duration, 2),
            'total_ports_scanned': len(ports) + len(extended_ports),
            'common_ports_scanned': len(common_ports),
            'extended_ports_scanned': len(extended_ports),
            'open_ports_found': len(all_open_ports),
            'scan_rate': round((len(ports) + len(extended_ports)) / scan_duration, 2),
            'intelligence_used': True
        }
        self.results_manager.add_scan_statistics(stats)
        
        logger.info(f"[SMART SCAN] Completed in {scan_duration:.2f}s - Found {len(all_open_ports)} open ports")
        
        return {
            'open_ports': all_open_ports,
            'scan_statistics': stats,
            'scan_mode': 'smart',
            'extended_scan_performed': len(extended_ports) > 0
        }
    
    def _deep_scan(self, ports: List[int], scan_config: Dict) -> Dict:
        """
        Deep port scan with comprehensive analysis.
        
        Args:
            ports (List[int]): Ports to scan
            scan_config (Dict): Scan configuration
            
        Returns:
            Dict: Scan results
        """
        logger.info(f"[DEEP SCAN] Comprehensive scan of {len(ports)} ports")
        
        start_time = time.time()
        
        # For deep scan, we use a more thorough approach
        timeout = scan_config.get('timeout', 6.0)
        max_workers = scan_config.get('max_workers', 30)
        
        # Randomize port order for stealth
        if self.config.randomize_port_order:
            scan_ports = ports.copy()
            random.shuffle(scan_ports)
        else:
            scan_ports = ports
        
        def check_port_deep(port: int) -> Optional[Tuple[int, Dict]]:
            """Deep check of a single port."""
            try:
                if self.rate_limiter:
                    self.rate_limiter.acquire()
                
                # Multiple connection attempts for reliability
                is_open = False
                for attempt in range(self.config.retry_attempts):
                    if NetworkUtils.check_port(self.target_ip, port, timeout):
                        is_open = True
                        break
                    elif attempt < self.config.retry_attempts - 1:
                        time.sleep(0.5)  # Brief pause between attempts
                
                if is_open:
                    # Enhanced service detection
                    service = PortRange.COMMON_PORTS.get(port, 'Unknown')
                    
                    # Enhanced banner grabbing
                    banner = NetworkUtils.get_banner(
                        self.target_ip, port,
                        self.config.banner_timeout * 2,  # Longer timeout for deep scan
                        self.config.banner_max_bytes
                    )
                    
                    # Additional service fingerprinting could go here
                    port_info = {
                        'service': service,
                        'banner': banner,
                        'state': 'open',
                        'scan_method': 'deep',
                        'response_time': timeout,
                        'verified': True  # Deep scan provides verification
                    }
                    
                    return port, port_info
                    
            except Exception as e:
                self.error_handler.handle_error('deep_scan', e, f"port {port}")
            
            return None
        
        # Execute deep scanning
        open_ports = {}
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_port = {executor.submit(check_port_deep, port): port for port in scan_ports}
            completed = 0
            
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                completed += 1
                
                try:
                    result = future.result()
                    if result:
                        port_num, port_info = result
                        open_ports[port_num] = port_info
                        self.results_manager.add_open_port(port_num, port_info)
                        
                        logger.info(f"  [+] [DEEP] Port {port_num}/{port_info['service']} is OPEN")
                    
                    # Progress indication
                    if completed % 25 == 0 or completed == len(scan_ports):
                        progress = (completed / len(scan_ports)) * 100
                        logger.debug(f"Deep scan progress: {completed}/{len(scan_ports)} ({progress:.1f}%)")
                        
                except Exception as e:
                    self.error_handler.handle_error('deep_scan_result', e, f"port {port}")
        
        # Enhanced service analysis for deep scan
        if scan_config.get('enable_advanced_detection', True):
            self._advanced_service_analysis(open_ports)
        
        scan_duration = time.time() - start_time
        
        # Comprehensive statistics
        stats = {
            'scan_duration': round(scan_duration, 2),
            'ports_scanned': len(ports),
            'open_ports_found': len(open_ports),
            'scan_rate': round(len(ports) / scan_duration, 2),
            'verification_performed': True,
            'advanced_detection': True
        }
        self.results_manager.add_scan_statistics(stats)
        
        logger.info(f"[DEEP SCAN] Completed in {scan_duration:.2f}s - Found {len(open_ports)} open ports")
        
        return {
            'open_ports': open_ports,
            'scan_statistics': stats,
            'scan_mode': 'deep'
        }
    
    def _generate_smart_port_extensions(self, open_ports: Dict, original_ports: List[int]) -> List[int]:
        """
        Generate additional ports to scan based on discovered services.
        
        Args:
            open_ports (Dict): Currently discovered open ports
            original_ports (List[int]): Originally scanned ports
            
        Returns:
            List[int]: Additional ports to scan
        """
        extended_ports = set()
        
        for port, info in open_ports.items():
            service = info.get('service', '').lower()
            
            # Service-specific port extensions
            if 'http' in service or port in [80, 443]:
                extended_ports.update([8000, 8080, 8443, 8888, 9000, 9080, 9443])
            elif 'ssh' in service or port == 22:
                extended_ports.update([2222, 2200, 22222])
            elif 'ftp' in service or port == 21:
                extended_ports.update([20, 990, 989])
            elif any(db in service for db in ['mysql', 'database', 'sql']):
                extended_ports.update([3306, 3307, 5432, 1433, 1521, 27017])
        
        # Add high-value ports not in original scan
        extended_ports.update(PortRange.HIGH_VALUE_PORTS)
        
        # Remove already scanned ports
        extended_ports = extended_ports - set(original_ports)
        
        # Limit to reasonable number
        return list(extended_ports)[:50]
    
    def _scan_extended_ports(self, ports: List[int], scan_config: Dict) -> Dict:
        """
        Scan extended ports discovered during smart scanning.
        
        Args:
            ports (List[int]): Extended ports to scan
            scan_config (Dict): Scan configuration
            
        Returns:
            Dict: Scan results for extended ports
        """
        logger.debug(f"Scanning {len(ports)} extended ports")
        
        timeout = scan_config.get('timeout', 3.0)
        max_workers = min(scan_config.get('max_workers', 20), 15)  # Limit for extended scan
        
        open_ports = {}
        
        def check_extended_port(port: int) -> Optional[Tuple[int, Dict]]:
            """Check an extended port."""
            try:
                if self.rate_limiter:
                    self.rate_limiter.acquire()
                
                if NetworkUtils.check_port(self.target_ip, port, timeout):
                    service = PortRange.COMMON_PORTS.get(port, 'Unknown')
                    banner = NetworkUtils.get_banner(self.target_ip, port)
                    
                    port_info = {
                        'service': service,
                        'banner': banner,
                        'state': 'open',
                        'scan_method': 'smart_extended',
                        'discovered_by': 'smart_scan'
                    }
                    
                    return port, port_info
                    
            except Exception as e:
                self.error_handler.handle_error('extended_scan', e, f"port {port}")
            
            return None
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_port = {executor.submit(check_extended_port, port): port for port in ports}
            
            for future in as_completed(future_to_port):
                try:
                    result = future.result()
                    if result:
                        port_num, port_info = result
                        open_ports[port_num] = port_info
                        self.results_manager.add_open_port(port_num, port_info)
                        
                        logger.info(f"  [+] [SMART EXT] Port {port_num}/{port_info['service']} is OPEN")
                        
                except Exception as e:
                    self.error_handler.handle_error('extended_scan_result', e)
        
        return {'open_ports': open_ports}
    
    def _enhance_service_detection(self, open_ports: Dict) -> None:
        """
        Enhance service detection for open ports.
        
        Args:
            open_ports (Dict): Dictionary of open ports to enhance
        """
        logger.debug("Enhancing service detection for open ports")
        
        for port, info in open_ports.items():
            try:
                banner = info.get('banner', '')
                if banner and banner != 'No banner':
                    # Improve service identification based on banner
                    enhanced_service = self._identify_service_from_banner(port, banner)
                    if enhanced_service != info.get('service', ''):
                        info['service'] = enhanced_service
                        info['service_enhanced'] = True
                        logger.debug(f"Enhanced service detection for port {port}: {enhanced_service}")
                        
            except Exception as e:
                self.error_handler.handle_error('service_enhancement', e, f"port {port}")
    
    def _identify_service_from_banner(self, port: int, banner: str) -> str:
        """
        Identify service based on port and banner information.
        
        Args:
            port (int): Port number
            banner (str): Banner string
            
        Returns:
            str: Identified service name
        """
        banner_lower = banner.lower()
        
        # Common banner patterns
        if 'ssh' in banner_lower:
            return f'SSH ({banner.split()[0] if banner.split() else "SSH"})'
        elif 'http' in banner_lower or 'server:' in banner_lower:
            return 'HTTP'
        elif 'ftp' in banner_lower:
            return 'FTP'
        elif 'mysql' in banner_lower:
            return 'MySQL'
        elif 'microsoft' in banner_lower and 'sql' in banner_lower:
            return 'MSSQL'
        elif 'postgresql' in banner_lower:
            return 'PostgreSQL'
        elif 'redis' in banner_lower:
            return 'Redis'
        elif 'mongodb' in banner_lower:
            return 'MongoDB'
        elif 'nginx' in banner_lower:
            return 'nginx'
        elif 'apache' in banner_lower:
            return 'Apache'
        else:
            # Fallback to port-based identification
            return PortRange.COMMON_PORTS.get(port, 'Unknown')
    
    def _advanced_service_analysis(self, open_ports: Dict) -> None:
        """
        Perform advanced service analysis for deep scans.
        
        Args:
            open_ports (Dict): Dictionary of open ports to analyze
        """
        logger.debug("Performing advanced service analysis")
        
        for port, info in open_ports.items():
            try:
                # Add confidence scoring
                confidence = self._calculate_service_confidence(port, info)
                info['confidence'] = confidence
                
                # Add security implications
                security_notes = self._get_security_implications(port, info.get('service', ''))
                if security_notes:
                    info['security_notes'] = security_notes
                
            except Exception as e:
                self.error_handler.handle_error('advanced_analysis', e, f"port {port}")
    
    def _calculate_service_confidence(self, port: int, info: Dict) -> str:
        """Calculate confidence level for service identification."""
        banner = info.get('banner', '')
        service = info.get('service', '')
        
        if banner and banner != 'No banner' and service != 'Unknown':
            return 'High'
        elif service in PortRange.COMMON_PORTS.values():
            return 'Medium'
        else:
            return 'Low'
    
    def _get_security_implications(self, port: int, service: str) -> List[str]:
        """Get security implications for the service."""
        implications = []
        
        if port == 22 or 'ssh' in service.lower():
            implications.append("SSH service - ensure strong authentication")
        elif port in [80, 443] or 'http' in service.lower():
            implications.append("Web service - check for vulnerabilities")
        elif port == 3389 or 'rdp' in service.lower():
            implications.append("RDP service - high-value target")
        elif 'database' in service.lower() or port in [3306, 5432, 1433]:
            implications.append("Database service - protect access")
        
        return implications
    
    def get_results(self) -> Dict:
        """Get all scan results."""
        return self.results_manager.get_all_results()
    
    def get_errors(self) -> Dict:
        """Get all errors encountered during scanning."""
        return self.error_handler.get_errors()


def main():
    """
    Standalone main function for port scanning module.
    Usage: python port_scanning.py <target> [--ports <ports>] [--mode <mode>]
    """
    import argparse
    import json
    import sys
    import time
    
    # Set up argument parser
    parser = argparse.ArgumentParser(
        description="Service Discovery - Port Scanning Module",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python port_scanning.py example.com
  python port_scanning.py 192.168.1.1 --ports 80,443,22
  python port_scanning.py example.com --mode quick --output results.json
  python port_scanning.py 192.168.1.0/24 --mode deep
        """
    )
    
    parser.add_argument(
        'target',
        help='Target IP address, hostname, or CIDR range to scan'
    )
    
    parser.add_argument(
        '--ports',
        default='1-1000',
        help='Port range or comma-separated ports (default: 1-1000)'
    )
    
    parser.add_argument(
        '--mode',
        choices=['quick', 'smart', 'deep'],
        default='smart',
        help='Scanning mode (default: smart)'
    )
    
    parser.add_argument(
        '--workers',
        type=int,
        default=100,
        help='Number of concurrent workers (default: 100)'
    )
    
    parser.add_argument(
        '--timeout',
        type=int,
        default=3,
        help='Connection timeout in seconds (default: 3)'
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
    
    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    print(f"{'='*60}")
    print("     SERVICE DISCOVERY - PORT SCANNING MODULE")
    print(f"{'='*60}")
    print(f"Target: {args.target}")
    print(f"Ports: {args.ports}")
    print(f"Mode: {args.mode}")
    print(f"Workers: {args.workers}")
    print(f"Timeout: {args.timeout}s")
    print(f"{'='*60}")
    
    try:
        # Import required classes
        try:
            from ..config import ServiceDiscoveryConfig
            from ..base import NetworkUtils
        except ImportError:
            # Fallback for direct execution - add parent directory to path
            import sys
            import os
            parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            sys.path.insert(0, parent_dir)
            
            try:
                from config import ServiceDiscoveryConfig
                from base import NetworkUtils
            except ImportError:
                print("Error: Could not import required modules. Please run from the service_discovery directory.")
                sys.exit(1)
        
        # Create configuration
        config = ServiceDiscoveryConfig()
        config.max_workers = args.workers
        config.scan_timeout = args.timeout
        
        # Initialize scanner
        scanner = PortScanner(args.target, config)
        
        # Parse port range
        if '-' in args.ports:
            start_port, end_port = map(int, args.ports.split('-'))
            ports = list(range(start_port, end_port + 1))
        else:
            ports = [int(p.strip()) for p in args.ports.split(',')]
        
        start_time = time.time()
        
        # Perform scan
        print(f"\n🔍 Starting {args.mode} port scan...")
        results = scanner.scan_ports(ports, args.mode)
        
        elapsed_time = time.time() - start_time
        
        # Display results
        if results:
            open_ports = results.get('open_ports', {})
            scan_stats = results.get('scan_statistics', {})
            
            print(f"\n{'='*50}")
            print("              SCAN RESULTS")
            print(f"{'='*50}")
            
            if open_ports:
                print(f"\n✅ Open Ports Found: {len(open_ports)}")
                for port, port_info in open_ports.items():
                    service = port_info.get('service', 'Unknown')
                    state = port_info.get('state', 'open')
                    banner = port_info.get('banner', '')
                    confidence = port_info.get('confidence', 'Unknown')
                    
                    print(f"  📡 Port {port}/tcp - {service} ({state})")
                    if banner and banner != 'No banner':
                        banner_preview = banner[:60] + '...' if len(banner) > 60 else banner
                        print(f"     Banner: {banner_preview}")
                    if confidence != 'Unknown':
                        print(f"     Confidence: {confidence}")
                    
                    # Show security notes if available
                    security_notes = port_info.get('security_notes', [])
                    if security_notes:
                        for note in security_notes:
                            print(f"     ⚠️  {note}")
            else:
                print("\n❌ No open ports found")
            
            # Display scan statistics
            if scan_stats:
                print(f"\n{'='*50}")
                print("            SCAN STATISTICS")
                print(f"{'='*50}")
                
                ports_scanned = scan_stats.get('ports_scanned', len(ports))
                print(f"  Total Ports Scanned: {ports_scanned}")
                print(f"  Open Ports Found: {len(open_ports)}")
                print(f"  Scan Duration: {elapsed_time:.2f} seconds")
                print(f"  Scan Mode: {args.mode}")
                print(f"  Scan Rate: {scan_stats.get('scan_rate', 0):.1f} ports/sec")
                
                if scan_stats.get('intelligence_used'):
                    print(f"  Intelligence Used: Yes")
                if scan_stats.get('verification_performed'):
                    print(f"  Verification Performed: Yes")
                if scan_stats.get('advanced_detection'):
                    print(f"  Advanced Detection: Yes")
        else:
            print("\n❌ Scan failed or no results returned")
        
        # Show errors if any
        errors = scanner.get_errors()
        if errors:
            total_errors = sum(len(error_list) for error_list in errors.values())
            if total_errors > 0:
                print(f"\n⚠️  Errors encountered: {total_errors}")
                for module, error_list in errors.items():
                    if error_list:
                        print(f"  {module}: {len(error_list)} errors")
        
        print(f"\n{'='*60}")
        print("              SCAN COMPLETE")
        print(f"{'='*60}")
        
        # Save results if output file specified
        if args.output and results:
            try:
                with open(args.output, 'w') as f:
                    json.dump(results, f, indent=2, default=str)
                
                print(f"\n💾 Results saved to: {args.output}")
            except Exception as e:
                print(f"❌ Error saving results: {e}")
        
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        logging.info("Port scan interrupted by user")
    except Exception as e:
        print(f"\n[-] Scan failed: {e}")
        logging.error(f"Port scan failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()