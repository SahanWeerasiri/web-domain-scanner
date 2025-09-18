#!/usr/bin/env python3
"""
Main Service Discovery Orchestrator

This module coordinates all service discovery sub-modules and provides a unified
interface for comprehensive service discovery. It combines port scanning, service
identification, and external tools integration.

Author: Web Domain Scanner Project
License: See LICENSE file in project root
"""

import logging
import time
import sys
import os
import argparse
import json
from typing import Dict, List, Optional

# Add parent directories to path for imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '.')))

# Import sub-modules with fallback for both relative and absolute imports
try:
    # Try relative imports first (when used as module)
    from .config import ServiceDiscoveryConfig
    from .base import (
        ServiceDiscoveryErrorHandler, NetworkUtils, ServiceResultsManager,
        PortRange, ScanMode
    )
    from .port_scanning.port_scanning import PortScanner
    from .service_identification.service_identification import ServiceIdentifier, BannerGrabber
    from .external_tools.external_tools import ExternalToolsManager, NmapScriptEngine
except ImportError:
    # Fallback to absolute imports (when run directly)
    from config import ServiceDiscoveryConfig
    from base import (
        ServiceDiscoveryErrorHandler, NetworkUtils, ServiceResultsManager,
        PortRange, ScanMode, PortValidator
    )
    from modules.service_discovery.port_scanning.port_scanning import PortScanner
    from modules.service_discovery.service_identification.service_identification import ServiceIdentifier, BannerGrabber
    from modules.service_discovery.external_tools.external_tools import ExternalToolsManager, NmapScriptEngine

logger = logging.getLogger(__name__)


class ServiceDiscovery:
    """
    Comprehensive service discovery orchestrator.
    
    This class provides advanced service discovery capabilities using multiple
    scanning techniques including port scanning, service identification, and
    external tools integration.
    
    Key Features:
    - Multiple scanning modes (quick, smart, deep)
    - Advanced service identification and fingerprinting
    - External tools integration (nmap, rustscan, masscan)
    - Comprehensive banner grabbing and analysis
    - Rate limiting and error handling
    - Results correlation and validation
    
    Example:
        >>> config = ServiceDiscoveryConfig()
        >>> scanner = ServiceDiscovery("example.com", config)
        >>> results = scanner.discover_services()
    """
    
    def __init__(self, domain: str, config: Optional[ServiceDiscoveryConfig] = None):
        """
        Initialize ServiceDiscovery instance with target domain and configuration.
        
        Args:
            domain (str): Target domain to scan (e.g., "example.com")
            config (ServiceDiscoveryConfig, optional): Configuration object.
                                                     If None, uses default configuration.
        
        Raises:
            ValueError: If domain is invalid or cannot be resolved.
        """
        # Validate domain input
        if not domain or not isinstance(domain, str):
            raise ValueError("Domain must be a non-empty string")
        
        self.domain = domain.lower().strip()
        logger.info(f"Initializing ServiceDiscovery for domain: {self.domain}")
        
        # Handle config
        self.config = config or ServiceDiscoveryConfig()
        
        # Resolve domain to IP
        self.target_ip = NetworkUtils.resolve_domain(self.domain)
        if not self.target_ip:
            raise ValueError(f"Could not resolve domain: {self.domain}")
        
        logger.info(f"Resolved {self.domain} to IP: {self.target_ip}")
        
        # Initialize components
        self.error_handler = ServiceDiscoveryErrorHandler()
        self.results_manager = ServiceResultsManager()
        
        # Initialize sub-modules
        self.port_scanner = PortScanner(self.target_ip, self.config)
        self.service_identifier = ServiceIdentifier(self.config)
        self.banner_grabber = BannerGrabber(self.config)
        self.external_tools = ExternalToolsManager(self.config)
        self.nmap_scripts = NmapScriptEngine(self.config)
        
        # Store basic scan information
        self.results_manager.add_scan_info({
            'domain': self.domain,
            'target_ip': self.target_ip,
            'scan_config': self.config.to_dict(),
            'initialization_time': time.time()
        })
        
        logger.info(f"ServiceDiscovery initialized successfully for {self.domain} ({self.target_ip})")
    
    def discover_services(self, common_ports: Dict[int, str] = None, scan_mode: str = 'quick', **kwargs) -> Dict:
        """
        Comprehensive service discovery combining all techniques.
        
        Args:
            common_ports (Dict[int, str]): Dictionary of ports and their services
            scan_mode (str): 'quick', 'smart', or 'deep'
            **kwargs: Additional configuration parameters
        
        Returns:
            Dict: Complete service discovery results
        """
        logger.info(f"Starting comprehensive service discovery for {self.domain} in '{scan_mode}' mode")
        start_time = time.time()
        
        # Use provided ports or get default common ports
        if common_ports is None:
            common_ports = PortRange.get_common_ports()
        
        # Store scan information
        self.results_manager.add_scan_info({
            'scan_start_time': start_time,
            'scan_mode': scan_mode,
            'total_ports_to_scan': len(common_ports),
            'scan_parameters': kwargs
        })
        
        try:
            if scan_mode == ScanMode.QUICK:
                return self._quick_discovery(common_ports, **kwargs)
            elif scan_mode == ScanMode.SMART:
                return self._smart_discovery(common_ports, **kwargs)
            elif scan_mode == ScanMode.DEEP:
                return self._deep_discovery(common_ports, **kwargs)
            else:
                logger.warning(f"Unknown scan mode '{scan_mode}', defaulting to 'quick'")
                return self._quick_discovery(common_ports, **kwargs)
                
        except Exception as e:
            logger.error(f"Service discovery failed: {e}")
            self.error_handler.handle_error('service_discovery', e)
            return self._get_error_results(e)
    
    def _quick_discovery(self, common_ports: Dict[int, str], **kwargs) -> Dict:
        """
        Quick service discovery using common ports only.
        
        Args:
            common_ports (Dict[int, str]): Ports to scan
            **kwargs: Additional parameters
            
        Returns:
            Dict: Quick discovery results
        """
        logger.info("[QUICK DISCOVERY] Starting quick service discovery")
        
        # Extract port numbers
        port_list = list(common_ports.keys())
        
        # Phase 1: Port scanning
        logger.info("Phase 1: Port scanning")
        scan_results = self.port_scanner.scan_ports(port_list, ScanMode.QUICK, **kwargs)
        
        open_ports = scan_results.get('open_ports', {})
        
        # Phase 2: Basic service identification
        logger.info("Phase 2: Basic service identification")
        enhanced_results = self._enhance_port_information(open_ports)
        
        # Compile results
        final_results = {
            'services': {
                'scan_mode': 'quick',
                'open_ports': enhanced_results,
                'scan_statistics': scan_results.get('scan_statistics', {}),
                'discovery_summary': self._generate_discovery_summary(enhanced_results)
            }
        }
        
        # Store results
        self.results_manager.add_scan_statistics(scan_results.get('scan_statistics', {}))
        for port, info in enhanced_results.items():
            self.results_manager.add_open_port(port, info)
        
        logger.info(f"[QUICK DISCOVERY] Completed - Found {len(enhanced_results)} open ports")
        return final_results
    
    def _smart_discovery(self, common_ports: Dict[int, str], **kwargs) -> Dict:
        """
        Smart service discovery with intelligent techniques.
        
        Args:
            common_ports (Dict[int, str]): Ports to scan
            **kwargs: Additional parameters
            
        Returns:
            Dict: Smart discovery results
        """
        logger.info("[SMART DISCOVERY] Starting smart service discovery")
        
        # Extract port numbers
        port_list = list(common_ports.keys())
        
        # Phase 1: Smart port scanning
        logger.info("Phase 1: Smart port scanning")
        scan_results = self.port_scanner.scan_ports(port_list, ScanMode.SMART, **kwargs)
        
        open_ports = scan_results.get('open_ports', {})
        
        # Phase 2: Enhanced service identification
        logger.info("Phase 2: Enhanced service identification")
        enhanced_results = self._enhance_port_information(open_ports, detailed=True)
        
        # Phase 3: Additional banner grabbing for new ports
        if scan_results.get('extended_scan_performed'):
            logger.info("Phase 3: Additional banner analysis for extended ports")
            self._perform_additional_banner_analysis(enhanced_results)
        
        # Compile results
        final_results = {
            'services': {
                'scan_mode': 'smart',
                'open_ports': enhanced_results,
                'scan_statistics': scan_results.get('scan_statistics', {}),
                'extended_scan_performed': scan_results.get('extended_scan_performed', False),
                'discovery_summary': self._generate_discovery_summary(enhanced_results),
                'intelligence_used': True
            }
        }
        
        # Store results
        self.results_manager.add_scan_statistics(scan_results.get('scan_statistics', {}))
        for port, info in enhanced_results.items():
            self.results_manager.add_open_port(port, info)
        
        logger.info(f"[SMART DISCOVERY] Completed - Found {len(enhanced_results)} open ports")
        return final_results
    
    def _deep_discovery(self, common_ports: Dict[int, str], **kwargs) -> Dict:
        """
        Deep service discovery using external tools and comprehensive analysis.
        
        Args:
            common_ports (Dict[int, str]): Initial ports to scan
            **kwargs: Additional parameters
            
        Returns:
            Dict: Deep discovery results
        """
        logger.info("[DEEP DISCOVERY] Starting deep service discovery")
        
        # Check if external tools are enabled and available
        use_external_tools = (self.config.enable_external_tools and 
                            len(self.external_tools.get_available_tools()) > 0)
        
        if use_external_tools:
            # Phase 1: External tools scanning
            logger.info("Phase 1: External tools comprehensive scanning")
            external_results = self.external_tools.scan_with_external_tools(
                self.target_ip, ScanMode.DEEP
            )
            
            open_ports = external_results.get('open_ports', {})
            scan_stats = external_results.get('scan_details', {})
        else:
            # Fallback to internal deep scanning
            logger.info("Phase 1: Internal deep port scanning (external tools not available)")
            port_list = list(common_ports.keys())
            scan_results = self.port_scanner.scan_ports(port_list, ScanMode.DEEP, **kwargs)
            
            open_ports = scan_results.get('open_ports', {})
            scan_stats = scan_results.get('scan_statistics', {})
        
        # Phase 2: Comprehensive service identification
        logger.info("Phase 2: Comprehensive service identification")
        enhanced_results = self._enhance_port_information(open_ports, detailed=True, comprehensive=True)
        
        # Phase 3: Advanced service analysis
        logger.info("Phase 3: Advanced service analysis")
        self._perform_advanced_service_analysis(enhanced_results)
        
        # Phase 4: Security implications analysis
        logger.info("Phase 4: Security implications analysis")
        self._analyze_security_implications(enhanced_results)
        
        # Compile comprehensive results
        final_results = {
            'services': {
                'scan_mode': 'deep',
                'open_ports': enhanced_results,
                'scan_statistics': scan_stats,
                'external_tools_used': use_external_tools,
                'tools_info': self.external_tools.get_tool_info() if use_external_tools else {},
                'discovery_summary': self._generate_discovery_summary(enhanced_results),
                'security_analysis': True,
                'comprehensive_analysis': True
            }
        }
        
        # Store results
        self.results_manager.add_scan_statistics(scan_stats)
        for port, info in enhanced_results.items():
            self.results_manager.add_open_port(port, info)
        
        logger.info(f"[DEEP DISCOVERY] Completed - Found {len(enhanced_results)} open ports")
        return final_results
    
    def _enhance_port_information(self, open_ports: Dict, detailed: bool = False, comprehensive: bool = False) -> Dict:
        """
        Enhance port information with service identification.
        
        Args:
            open_ports (Dict): Basic open ports information
            detailed (bool): Perform detailed analysis
            comprehensive (bool): Perform comprehensive analysis
            
        Returns:
            Dict: Enhanced port information
        """
        enhanced_ports = {}
        
        for port, basic_info in open_ports.items():
            try:
                logger.debug(f"Enhancing information for port {port}")
                
                # Start with basic information
                enhanced_info = basic_info.copy()
                
                # Get current banner or grab new one
                current_banner = basic_info.get('banner', '')
                if not current_banner or current_banner == 'No banner':
                    current_banner = self.banner_grabber.grab_banner(self.target_ip, port)
                    enhanced_info['banner'] = current_banner
                
                # Perform service identification
                if detailed or comprehensive:
                    service_info = self.service_identifier.identify_service(
                        self.target_ip, port, current_banner
                    )
                    
                    # Merge service identification results
                    enhanced_info.update({
                        'service_detailed': service_info.get('service', enhanced_info.get('service')),
                        'version': service_info.get('version'),
                        'product': service_info.get('product'),
                        'confidence': service_info.get('confidence', 'Medium'),
                        'identification_methods': service_info.get('identification_methods', []),
                        'additional_info': service_info.get('additional_info', {})
                    })
                
                # Add timestamp
                enhanced_info['last_analyzed'] = time.time()
                
                enhanced_ports[port] = enhanced_info
                
            except Exception as e:
                logger.error(f"Error enhancing port {port}: {e}")
                self.error_handler.handle_error('port_enhancement', e, f"port {port}")
                enhanced_ports[port] = basic_info  # Keep basic info on error
        
        return enhanced_ports
    
    def _perform_additional_banner_analysis(self, enhanced_results: Dict) -> None:
        """
        Perform additional banner analysis for smart discovery.
        
        Args:
            enhanced_results (Dict): Enhanced port results to analyze
        """
        logger.debug("Performing additional banner analysis")
        
        for port, info in enhanced_results.items():
            try:
                banner = info.get('banner', '')
                if banner and banner != 'No banner':
                    # Perform additional analysis on banners
                    analysis = self._analyze_banner_content(banner)
                    if analysis:
                        info['banner_analysis'] = analysis
                        
            except Exception as e:
                logger.debug(f"Error in additional banner analysis for port {port}: {e}")
    
    def _perform_advanced_service_analysis(self, enhanced_results: Dict) -> None:
        """
        Perform advanced service analysis for deep discovery.
        
        Args:
            enhanced_results (Dict): Enhanced port results to analyze
        """
        logger.debug("Performing advanced service analysis")
        
        # Group services by type for analysis
        service_groups = self._group_services_by_type(enhanced_results)
        
        for service_type, ports in service_groups.items():
            try:
                # Perform service-specific analysis
                if service_type == 'web':
                    self._analyze_web_services(ports, enhanced_results)
                elif service_type == 'database':
                    self._analyze_database_services(ports, enhanced_results)
                elif service_type == 'remote_access':
                    self._analyze_remote_access_services(ports, enhanced_results)
                    
            except Exception as e:
                logger.debug(f"Error in advanced analysis for {service_type} services: {e}")
    
    def _analyze_security_implications(self, enhanced_results: Dict) -> None:
        """
        Analyze security implications of discovered services.
        
        Args:
            enhanced_results (Dict): Enhanced port results to analyze
        """
        logger.debug("Analyzing security implications")
        
        for port, info in enhanced_results.items():
            try:
                service = info.get('service', '').lower()
                security_notes = []
                risk_level = 'Low'
                
                # Assess risk based on service type
                if port in [22, 3389] or 'ssh' in service or 'rdp' in service:
                    security_notes.append("Remote access service - ensure strong authentication")
                    risk_level = 'High'
                elif port in [80, 443, 8080, 8443] or 'http' in service:
                    security_notes.append("Web service - check for vulnerabilities")
                    risk_level = 'Medium'
                elif port in [3306, 5432, 1433, 27017] or 'database' in service:
                    security_notes.append("Database service - protect access and data")
                    risk_level = 'High'
                elif port == 21 or 'ftp' in service:
                    security_notes.append("FTP service - consider secure alternatives")
                    risk_level = 'Medium'
                elif port == 23 or 'telnet' in service:
                    security_notes.append("Telnet service - unencrypted, high risk")
                    risk_level = 'Critical'
                
                # Check for default/weak configurations
                banner = info.get('banner', '').lower()
                if 'default' in banner or 'admin' in banner:
                    security_notes.append("Possible default configuration detected")
                    risk_level = 'High'
                
                # Store security analysis
                if security_notes:
                    info['security_analysis'] = {
                        'risk_level': risk_level,
                        'security_notes': security_notes,
                        'recommendations': self._get_security_recommendations(service, port)
                    }
                    
            except Exception as e:
                logger.debug(f"Error in security analysis for port {port}: {e}")
    
    def _generate_discovery_summary(self, enhanced_results: Dict) -> Dict:
        """
        Generate summary of discovery results.
        
        Args:
            enhanced_results (Dict): Enhanced port results
            
        Returns:
            Dict: Discovery summary
        """
        summary = {
            'total_open_ports': len(enhanced_results),
            'services_by_type': {},
            'high_value_services': [],
            'security_concerns': []
        }
        
        # Categorize services
        for port, info in enhanced_results.items():
            service = info.get('service', 'Unknown')
            service_type = self._categorize_service(service, port)
            
            if service_type not in summary['services_by_type']:
                summary['services_by_type'][service_type] = []
            summary['services_by_type'][service_type].append(port)
            
            # Identify high-value services
            if port in PortRange.HIGH_VALUE_PORTS:
                summary['high_value_services'].append({
                    'port': port,
                    'service': service
                })
            
            # Collect security concerns
            security_analysis = info.get('security_analysis', {})
            if security_analysis.get('risk_level') in ['High', 'Critical']:
                summary['security_concerns'].append({
                    'port': port,
                    'service': service,
                    'risk_level': security_analysis.get('risk_level')
                })
        
        return summary
    
    def _analyze_banner_content(self, banner: str) -> Optional[Dict]:
        """Analyze banner content for additional information."""
        analysis = {}
        
        # Look for version information
        version_patterns = [
            r'(\d+\.\d+\.\d+)',
            r'v(\d+\.\d+)',
            r'version\s+(\d+\.\d+\.\d+)'
        ]
        
        for pattern in version_patterns:
            import re
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                analysis['detected_version'] = match.group(1)
                break
        
        # Look for software names
        if 'apache' in banner.lower():
            analysis['software'] = 'Apache'
        elif 'nginx' in banner.lower():
            analysis['software'] = 'nginx'
        elif 'openssh' in banner.lower():
            analysis['software'] = 'OpenSSH'
        
        return analysis if analysis else None
    
    def _group_services_by_type(self, enhanced_results: Dict) -> Dict:
        """Group services by type for analysis."""
        groups = {
            'web': [],
            'database': [],
            'remote_access': [],
            'file_transfer': [],
            'other': []
        }
        
        for port, info in enhanced_results.items():
            service = info.get('service', '').lower()
            
            if port in [80, 443, 8080, 8443] or 'http' in service:
                groups['web'].append(port)
            elif port in [3306, 5432, 1433, 27017] or 'database' in service or 'sql' in service:
                groups['database'].append(port)
            elif port in [22, 3389] or 'ssh' in service or 'rdp' in service:
                groups['remote_access'].append(port)
            elif port in [21, 22] or 'ftp' in service:
                groups['file_transfer'].append(port)
            else:
                groups['other'].append(port)
        
        return groups
    
    def _analyze_web_services(self, ports: List[int], enhanced_results: Dict) -> None:
        """Analyze web services specifically."""
        for port in ports:
            if port in enhanced_results:
                # Add web-specific analysis
                enhanced_results[port]['service_category'] = 'web'
                enhanced_results[port]['web_analysis'] = {
                    'protocol': 'HTTPS' if port in [443, 8443] else 'HTTP',
                    'potential_vulnerabilities': ['XSS', 'SQL Injection', 'CSRF']
                }
    
    def _analyze_database_services(self, ports: List[int], enhanced_results: Dict) -> None:
        """Analyze database services specifically."""
        for port in ports:
            if port in enhanced_results:
                enhanced_results[port]['service_category'] = 'database'
                enhanced_results[port]['database_analysis'] = {
                    'security_priority': 'High',
                    'common_attacks': ['SQL Injection', 'Privilege Escalation']
                }
    
    def _analyze_remote_access_services(self, ports: List[int], enhanced_results: Dict) -> None:
        """Analyze remote access services specifically."""
        for port in ports:
            if port in enhanced_results:
                enhanced_results[port]['service_category'] = 'remote_access'
                enhanced_results[port]['remote_access_analysis'] = {
                    'security_priority': 'Critical',
                    'common_attacks': ['Brute Force', 'Credential Stuffing']
                }
    
    def _categorize_service(self, service: str, port: int) -> str:
        """Categorize service type."""
        service_lower = service.lower()
        
        if port in [80, 443, 8080, 8443] or 'http' in service_lower:
            return 'Web Services'
        elif port in [3306, 5432, 1433, 27017] or 'database' in service_lower:
            return 'Database Services'
        elif port in [22, 3389] or 'ssh' in service_lower or 'rdp' in service_lower:
            return 'Remote Access'
        elif port in [21, 22] or 'ftp' in service_lower:
            return 'File Transfer'
        elif port in [25, 465, 587] or 'smtp' in service_lower:
            return 'Email Services'
        else:
            return 'Other Services'
    
    def _get_security_recommendations(self, service: str, port: int) -> List[str]:
        """Get security recommendations for service."""
        recommendations = []
        
        if 'ssh' in service.lower() or port == 22:
            recommendations.extend([
                "Use key-based authentication",
                "Disable root login",
                "Change default port",
                "Implement fail2ban"
            ])
        elif 'http' in service.lower():
            recommendations.extend([
                "Use HTTPS",
                "Implement security headers",
                "Regular security testing",
                "Keep software updated"
            ])
        elif 'database' in service.lower():
            recommendations.extend([
                "Use strong authentication",
                "Restrict network access",
                "Regular security updates",
                "Encrypt sensitive data"
            ])
        
        return recommendations
    
    def _get_error_results(self, error: Exception) -> Dict:
        """Generate error results structure."""
        return {
            'services': {
                'scan_mode': 'error',
                'error': str(error),
                'open_ports': {},
                'scan_statistics': {'error': True}
            }
        }
    
    def get_comprehensive_results(self) -> Dict:
        """
        Get all results from service discovery.
        
        Returns:
            Dict: Complete results from all discovery methods
        """
        return self.results_manager.get_all_results()
    
    def get_errors(self) -> Dict:
        """
        Get all errors encountered during discovery.
        
        Returns:
            Dict: Error information from all modules
        """
        all_errors = self.error_handler.get_errors()
        
        # Collect errors from sub-modules
        sub_module_errors = {
            'port_scanner': self.port_scanner.get_errors(),
            'service_identifier': self.service_identifier.error_handler.get_errors(),
            'banner_grabber': self.banner_grabber.get_errors(),
            'external_tools': self.external_tools.get_errors()
        }
        
        # Merge all errors
        for module, errors in sub_module_errors.items():
            if errors:
                all_errors[module] = errors
        
        return all_errors
    
    def generate_report(self) -> Dict:
        """
        Generate a comprehensive service discovery report.
        
        Returns:
            Dict: Detailed report with statistics and findings
        """
        results = self.get_comprehensive_results()
        errors = self.get_errors()
        
        # Generate comprehensive report
        report = {
            'target': {
                'domain': self.domain,
                'ip_address': self.target_ip
            },
            'scan_info': results.get('scan_info', {}),
            'timestamp': time.time(),
            'summary': {
                'total_open_ports': self.results_manager.get_port_count(),
                'services_discovered': self.results_manager.get_services_summary(),
                'scan_duration': 0,  # Will be calculated
                'tools_used': []
            },
            'open_ports': self.results_manager.get_open_ports(),
            'detailed_results': results,
            'errors': errors,
            'configuration': self.config.to_dict()
        }
        
        # Calculate scan duration
        scan_info = results.get('scan_info', {})
        start_time = scan_info.get('scan_start_time')
        if start_time:
            report['summary']['scan_duration'] = round(time.time() - start_time, 2)
        
        logger.info(f"Generated comprehensive service discovery report for {self.domain}")
        return report


# Main function for command-line usage
def main():
    """Main function for command-line execution"""
    parser = argparse.ArgumentParser(description="Comprehensive Service Discovery")
    parser.add_argument("domain", help="Target domain to scan")
    parser.add_argument("--mode", choices=['quick', 'smart', 'deep'], 
                       default='quick', help="Scanning mode (default: quick)")
    parser.add_argument("--output", help="Output file for results (JSON format)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose logging")
    parser.add_argument("--timeout", type=float, help="Scan timeout in seconds")
    parser.add_argument("--max-workers", type=int, help="Maximum concurrent workers")
    parser.add_argument("--no-external-tools", action="store_true", 
                       help="Disable external tools (nmap/rustscan)")
    
    args = parser.parse_args()
    
    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create configuration
    config = ServiceDiscoveryConfig()
    
    # Apply command line overrides
    if args.timeout:
        config.scan_timeout = args.timeout
    if args.max_workers:
        config.max_workers = args.max_workers
    if args.no_external_tools:
        config.enable_external_tools = False
    
    print(f"\n=== Service Discovery for {args.domain} ===")
    print(f"Mode: {args.mode.upper()}")
    print(f"Configuration: timeout={config.scan_timeout}s, workers={config.max_workers}")
    print(f"External tools: {'Enabled' if config.enable_external_tools else 'Disabled'}")
    print("="*60)
    
    try:
        # Initialize service discovery
        scanner = ServiceDiscovery(args.domain, config)
        
        # Run discovery
        results = scanner.discover_services(scan_mode=args.mode)
        
        # Display results with enhanced detail
        print(f"\n{'='*60}")
        print(f"        SERVICE DISCOVERY RESULTS - {args.domain.upper()}")
        print(f"{'='*60}")
        
        services = results.get('services', {})
        open_ports = services.get('open_ports', {})
        
        # Main service summary
        print(f"\n🔍 SCAN SUMMARY")
        print(f"{'='*40}")
        print(f"  Target Domain: {args.domain}")
        print(f"  IP Address: {scanner.target_ip}")
        print(f"  Scan Mode: {services.get('scan_mode', 'unknown').upper()}")
        print(f"  Open Ports Found: {len(open_ports)}")
        
        if open_ports:
            print(f"\n📡 DISCOVERED SERVICES")
            print(f"{'='*40}")
            
            # Group services by category for better organization
            services_by_category = {}
            for port, info in open_ports.items():
                service = info.get('service', 'Unknown')
                category = _categorize_service(service)
                if category not in services_by_category:
                    services_by_category[category] = []
                services_by_category[category].append((port, info))
            
            # Display services by category
            for category, port_list in services_by_category.items():
                if port_list:
                    print(f"\n  {category.upper().replace('_', ' ')} SERVICES:")
                    for port, info in sorted(port_list, key=lambda x: int(x[0])):
                        service = info.get('service', 'Unknown')
                        banner = info.get('banner', 'No banner')
                        confidence = info.get('confidence', 'Unknown')
                        state = info.get('state', 'unknown')
                        
                        print(f"\n    [+] Port {port:>5} - {service}")
                        print(f"        State: {state}")
                        
                        # Show banner with better formatting
                        if banner and banner != 'No banner':
                            banner_preview = (banner[:60] + '...') if len(banner) > 60 else banner
                            print(f"        Banner: {banner_preview}")
                        
                        print(f"        Confidence: {confidence}")
                        
                        # Show version information
                        version = info.get('version')
                        if version:
                            print(f"        Version: {version}")
                        
                        # Show protocol-specific information
                        protocol_info = info.get('protocol_info', {})
                        if protocol_info:
                            for key, value in protocol_info.items():
                                if isinstance(value, dict):
                                    print(f"        {key.title()}:")
                                    for sub_key, sub_value in value.items():
                                        print(f"          {sub_key}: {sub_value}")
                                else:
                                    print(f"        {key.title()}: {value}")
                        
                        # Enhanced security analysis display
                        if 'security_analysis' in info:
                            sec_analysis = info['security_analysis']
                            risk_level = sec_analysis.get('risk_level', 'Unknown')
                            print(f"        🔒 Risk Level: {risk_level}")
                            
                            security_notes = sec_analysis.get('security_notes', [])
                            if security_notes:
                                print(f"        Security Notes:")
                                for note in security_notes[:3]:  # Show first 3 notes
                                    print(f"          ⚠️  {note}")
                        
                        # Show SSL/TLS information if available
                        ssl_info = info.get('ssl_info')
                        if ssl_info:
                            ssl_version = ssl_info.get('ssl_version', 'Unknown')
                            cipher = ssl_info.get('cipher_suite', 'Unknown')
                            print(f"        🔐 SSL Version: {ssl_version}")
                            print(f"        🔐 Cipher: {cipher}")
                            
                            # Certificate information
                            subject = ssl_info.get('subject', {})
                            if subject:
                                cn = subject.get('commonName', 'Unknown')
                                print(f"        🔐 Certificate CN: {cn}")
                        
                        # Show detected technologies for web services
                        technologies = info.get('technologies', [])
                        if technologies:
                            print(f"        🛠️  Technologies: {', '.join(technologies)}")
        
        else:
            print(f"\n❌ NO OPEN PORTS FOUND")
            print(f"   All scanned ports appear to be closed or filtered")
        
        # Enhanced scan statistics
        scan_stats = services.get('scan_statistics', {})
        if scan_stats:
            print(f"\n📊 SCAN STATISTICS")
            print(f"{'='*40}")
            
            if 'scan_duration' in scan_stats:
                print(f"  Scan Duration: {scan_stats['scan_duration']} seconds")
            if 'ports_scanned' in scan_stats:
                print(f"  Ports Scanned: {scan_stats['ports_scanned']}")
            if 'scan_rate' in scan_stats:
                print(f"  Scan Rate: {scan_stats['scan_rate']} ports/sec")
            if 'tools_used' in services and services['tools_used']:
                print(f"  External Tools: {', '.join(services['tools_used'])}")
            
            # Additional stats if available
            if 'total_time' in scan_stats:
                print(f"  Total Processing Time: {scan_stats['total_time']} seconds")
            if 'intelligence_used' in scan_stats:
                print(f"  Intelligence Mode: {'Yes' if scan_stats['intelligence_used'] else 'No'}")
        
        # Enhanced discovery summary
        discovery_summary = services.get('discovery_summary', {})
        if discovery_summary:
            print(f"\n🔍 DISCOVERY INSIGHTS")
            print(f"{'='*40}")
            
            services_by_type = discovery_summary.get('services_by_type', {})
            for service_type, ports in services_by_type.items():
                if ports:
                    print(f"  {service_type.title()}: {len(ports)} service(s)")
            
            # High-value services with enhanced display
            high_value = discovery_summary.get('high_value_services', [])
            if high_value:
                print(f"\n  🎯 HIGH-VALUE TARGETS:")
                for service in high_value:
                    port = service.get('port', 'Unknown')
                    service_name = service.get('service', 'Unknown')
                    reason = service.get('reason', 'High-value service')
                    print(f"    • Port {port} ({service_name}) - {reason}")
            
            # Enhanced security concerns
            security_concerns = discovery_summary.get('security_concerns', [])
            if security_concerns:
                print(f"\n  ⚠️  SECURITY CONCERNS:")
                for concern in security_concerns:
                    port = concern.get('port', 'Unknown')
                    risk = concern.get('risk_level', 'Unknown')
                    description = concern.get('description', 'Security concern identified')
                    print(f"    • Port {port} - {risk.upper()} risk: {description}")
            
            # Service diversity analysis
            if services_by_type:
                total_categories = len([t for t, p in services_by_type.items() if p])
                total_services = sum(len(ports) for ports in services_by_type.values())
                print(f"\n  📈 SERVICE DIVERSITY:")
                print(f"    Service Categories: {total_categories}")
                print(f"    Total Services: {total_services}")
                
                # Most common service type
                if total_services > 0:
                    most_common = max(services_by_type.items(), key=lambda x: len(x[1]))
                    if most_common[1]:
                        print(f"    Dominant Category: {most_common[0]} ({len(most_common[1])} services)")
        
        # Enhanced error reporting with context
        errors = scanner.get_errors()
        if errors:
            print(f"\n⚠️  ERROR ANALYSIS")
            print(f"{'='*40}")
            
            total_errors = sum(len(error_list) for error_list in errors.values())
            print(f"  Total Errors: {total_errors}")
            
            for module, error_list in errors.items():
                if error_list:
                    print(f"  {module.title().replace('_', ' ')}: {len(error_list)} error(s)")
                    
                    # Show sample errors for debugging (if verbose)
                    if args.verbose and len(error_list) > 0:
                        print(f"    Recent errors:")
                        for i, error in enumerate(error_list[-2:], 1):  # Show last 2 errors
                            error_str = str(error)[:80] + '...' if len(str(error)) > 80 else str(error)
                            print(f"      {i}. {error_str}")
        
        # Final completion summary
        print(f"\n{'='*60}")
        print(f"           SERVICE DISCOVERY COMPLETE")
        print(f"{'='*60}")
        
        # Results summary line
        if open_ports:
            port_count = len(open_ports)
            service_categories = len(set(_categorize_service(info.get('service', '')) 
                                       for info in open_ports.values()))
            print(f"✅ Successfully identified {port_count} open port(s) across {service_categories} service categories")
        else:
            print(f"❌ No open ports identified on {args.domain}")
        
        # Performance summary
        total_time = scan_stats.get('scan_duration', 0) if scan_stats else 0
        if total_time:
            rate = len(open_ports) / total_time if total_time > 0 else 0
            print(f"⏱️  Discovery completed in {total_time:.2f} seconds ({rate:.1f} services/sec)")
        
        print(f"{'='*60}")
        
        # Save results if output file specified
        if args.output:
            try:
                report = scanner.generate_report()
                
                with open(args.output, 'w') as f:
                    json.dump(report, f, indent=2, default=str)
                
                print(f"\n💾 Full detailed results saved to: {args.output}")
                print(f"   Report includes raw scan data, errors, and metadata")
            except Exception as e:
                print(f"❌ Error saving results: {e}")
        
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        logging.info("Scan interrupted by user")
    except Exception as e:
        print(f"\n[-] Scan failed: {e}")
        logging.error(f"Scan failed: {e}")
        sys.exit(1)


def _categorize_service(service_name: str) -> str:
    """
    Categorize service by type for better organization.
    
    Args:
        service_name (str): Service name to categorize
        
    Returns:
        str: Service category
    """
    if not service_name:
        return 'other'
        
    service_lower = service_name.lower()
    
    # Web services
    if any(web in service_lower for web in ['http', 'https', 'web', 'nginx', 'apache']):
        return 'web'
    
    # Database services  
    elif any(db in service_lower for db in ['mysql', 'postgres', 'mssql', 'oracle', 'mongo', 'redis', 'database']):
        return 'database'
    
    # Remote access services
    elif any(remote in service_lower for remote in ['ssh', 'rdp', 'vnc', 'telnet']):
        return 'remote_access'
    
    # File services
    elif any(file in service_lower for file in ['ftp', 'sftp', 'smb', 'nfs', 'file']):
        return 'file_transfer'
    
    # Mail services
    elif any(mail in service_lower for mail in ['smtp', 'pop3', 'imap', 'mail']):
        return 'mail'
    
    # Security services
    elif any(sec in service_lower for sec in ['ssl', 'tls', 'https', 'ldaps']):
        return 'security'
    
    # Network services
    elif any(net in service_lower for net in ['dns', 'dhcp', 'snmp', 'ldap']):
        return 'network'
    
    # Default category
    else:
        return 'other'
        
    # The following code block is unreachable and should be removed.
    # It is a duplicate of the main() function's output logic.