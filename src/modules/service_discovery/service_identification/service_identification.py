#!/usr/bin/env python3
"""
Service Identification Module for Service Discovery

This module provides advanced service identification capabilities including banner grabbing,
service fingerprinting, and version detection.

Author: Web Domain Scanner Project
License: See LICENSE file in project root
"""

import socket
import logging
import re
import time
import ssl
import threading
from typing import Dict, List, Optional, Tuple, Any
from urllib.parse import urlparse

# Import base utilities
try:
    from ..base import (
        ServiceDiscoveryErrorHandler, NetworkUtils, PortRange
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
            ServiceDiscoveryErrorHandler, NetworkUtils, PortRange
        )
        from config import ServiceDiscoveryConfig
    except ImportError:
        # Last resort fallback
        print("Error: Could not import required modules. Please run from the service_discovery directory or ensure the module is properly installed.")
        sys.exit(1)

logger = logging.getLogger(__name__)


class ServiceIdentifier:
    """
    Advanced service identification and fingerprinting.
    """
    
    def __init__(self, config: Optional[ServiceDiscoveryConfig] = None):
        """
        Initialize service identifier.
        
        Args:
            config (ServiceDiscoveryConfig): Configuration object
        """
        self.config = config or ServiceDiscoveryConfig()
        self.error_handler = ServiceDiscoveryErrorHandler()
        
        # Service fingerprint patterns
        self.service_patterns = self._load_service_patterns()
        
        logger.debug("ServiceIdentifier initialized")
    
    def identify_service(self, ip: str, port: int, banner: str = None) -> Dict:
        """
        Comprehensive service identification for a port.
        
        Args:
            ip (str): Target IP address
            port (int): Target port
            banner (str): Optional pre-obtained banner
            
        Returns:
            Dict: Service identification results
        """
        try:
            logger.debug(f"Identifying service on {ip}:{port}")
            
            # Get banner if not provided
            if banner is None:
                banner = self.grab_banner(ip, port)
            
            # Perform identification
            identification = {
                'port': port,
                'ip': ip,
                'banner': banner,
                'service': 'Unknown',
                'version': None,
                'product': None,
                'confidence': 'Low',
                'identification_methods': [],
                'additional_info': {}
            }
            
            # Port-based identification
            port_service = self._identify_by_port(port)
            if port_service:
                identification['service'] = port_service
                identification['confidence'] = 'Medium'
                identification['identification_methods'].append('port_based')
            
            # Banner-based identification
            if banner and banner != 'No banner':
                banner_result = self._identify_by_banner(banner, port)
                if banner_result:
                    identification.update(banner_result)
                    identification['identification_methods'].append('banner_analysis')
                    if identification['confidence'] == 'Medium':
                        identification['confidence'] = 'High'
            
            # Protocol-specific probing
            protocol_result = self._probe_protocol(ip, port)
            if protocol_result:
                identification['additional_info'].update(protocol_result)
                identification['identification_methods'].append('protocol_probing')
            
            # SSL/TLS detection
            if self._is_ssl_port(port) or 'ssl' in banner.lower() or 'tls' in banner.lower():
                ssl_info = self._analyze_ssl(ip, port)
                if ssl_info:
                    identification['additional_info']['ssl'] = ssl_info
                    identification['identification_methods'].append('ssl_analysis')
            
            logger.debug(f"Service identification complete for {ip}:{port}: {identification['service']}")
            return identification
            
        except Exception as e:
            self.error_handler.handle_error('service_identification', e, f"{ip}:{port}")
            return {
                'port': port,
                'ip': ip,
                'banner': banner or 'No banner',
                'service': 'Unknown',
                'error': str(e)
            }
    
    def grab_banner(self, ip: str, port: int, timeout: float = None) -> str:
        """
        Grab service banner from a port.
        
        Args:
            ip (str): Target IP address
            port (int): Target port
            timeout (float): Connection timeout
            
        Returns:
            str: Service banner or 'No banner'
        """
        timeout = timeout or self.config.banner_timeout
        max_bytes = self.config.banner_max_bytes
        
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                sock.connect((ip, port))
                
                # Send protocol-specific probes
                probe_data = self._get_probe_data(port)
                if probe_data:
                    sock.send(probe_data.encode())
                
                # Receive banner
                banner = sock.recv(max_bytes).decode('utf-8', errors='ignore').strip()
                
                if banner:
                    # Clean and normalize banner
                    banner = self._clean_banner(banner)
                    logger.debug(f"Banner grabbed from {ip}:{port}: {banner[:100]}...")
                    return banner
                else:
                    return "No banner"
                    
        except socket.timeout:
            logger.debug(f"Banner grab timeout for {ip}:{port}")
            return "No banner (timeout)"
        except Exception as e:
            logger.debug(f"Error grabbing banner from {ip}:{port}: {e}")
            return "No banner"
    
    def _identify_by_port(self, port: int) -> Optional[str]:
        """
        Identify service based on port number.
        
        Args:
            port (int): Port number
            
        Returns:
            Optional[str]: Service name if identified
        """
        return PortRange.COMMON_PORTS.get(port)
    
    def _identify_by_banner(self, banner: str, port: int) -> Optional[Dict]:
        """
        Identify service based on banner analysis.
        
        Args:
            banner (str): Service banner
            port (int): Port number
            
        Returns:
            Optional[Dict]: Service identification results
        """
        banner_lower = banner.lower()
        
        # Check against known patterns
        for service_name, patterns in self.service_patterns.items():
            for pattern in patterns:
                if isinstance(pattern, str):
                    if pattern.lower() in banner_lower:
                        version = self._extract_version(banner, service_name)
                        return {
                            'service': service_name,
                            'version': version,
                            'confidence': 'High'
                        }
                elif isinstance(pattern, dict) and 'regex' in pattern:
                    match = re.search(pattern['regex'], banner, re.IGNORECASE)
                    if match:
                        version = match.group(1) if match.groups() else None
                        return {
                            'service': service_name,
                            'version': version,
                            'product': pattern.get('product'),
                            'confidence': 'High'
                        }
        
        return None
    
    def _probe_protocol(self, ip: str, port: int) -> Optional[Dict]:
        """
        Perform protocol-specific probing.
        
        Args:
            ip (str): Target IP address
            port (int): Target port
            
        Returns:
            Optional[Dict]: Protocol-specific information
        """
        try:
            # HTTP/HTTPS probing
            if port in [80, 443, 8080, 8443] or self._is_web_port(port):
                return self._probe_http(ip, port)
            
            # SSH probing
            elif port == 22:
                return self._probe_ssh(ip, port)
            
            # FTP probing
            elif port == 21:
                return self._probe_ftp(ip, port)
            
            # SMTP probing
            elif port == 25:
                return self._probe_smtp(ip, port)
            
        except Exception as e:
            logger.debug(f"Protocol probing error for {ip}:{port}: {e}")
        
        return None
    
    def _probe_http(self, ip: str, port: int) -> Optional[Dict]:
        """
        Probe HTTP service for additional information.
        
        Args:
            ip (str): Target IP address
            port (int): Target port
            
        Returns:
            Optional[Dict]: HTTP service information
        """
        try:
            import requests
            
            protocol = 'https' if port in [443, 8443] else 'http'
            url = f"{protocol}://{ip}:{port}"
            
            response = requests.get(url, timeout=5, verify=False, 
                                  allow_redirects=False)
            
            info = {
                'status_code': response.status_code,
                'server': response.headers.get('Server', 'Unknown'),
                'content_type': response.headers.get('Content-Type', 'Unknown'),
                'headers': dict(response.headers)
            }
            
            # Try to identify web technologies
            if response.text:
                tech_info = self._identify_web_technologies(response.text, response.headers)
                if tech_info:
                    info['technologies'] = tech_info
            
            return info
            
        except Exception as e:
            logger.debug(f"HTTP probing error for {ip}:{port}: {e}")
            return None
    
    def _probe_ssh(self, ip: str, port: int) -> Optional[Dict]:
        """
        Probe SSH service for version information.
        
        Args:
            ip (str): Target IP address
            port (int): Target port
            
        Returns:
            Optional[Dict]: SSH service information
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(5)
                sock.connect((ip, port))
                
                # SSH banner is sent immediately
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                
                if banner.startswith('SSH-'):
                    parts = banner.split()
                    return {
                        'ssh_version': parts[0] if parts else 'Unknown',
                        'ssh_banner': banner,
                        'protocol_versions': self._parse_ssh_version(banner)
                    }
                    
        except Exception as e:
            logger.debug(f"SSH probing error for {ip}:{port}: {e}")
        
        return None
    
    def _probe_ftp(self, ip: str, port: int) -> Optional[Dict]:
        """
        Probe FTP service for information.
        
        Args:
            ip (str): Target IP address
            port (int): Target port
            
        Returns:
            Optional[Dict]: FTP service information
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(5)
                sock.connect((ip, port))
                
                # FTP sends welcome banner
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                
                if '220' in banner:  # FTP welcome code
                    return {
                        'ftp_banner': banner,
                        'ftp_code': '220',
                        'welcome_message': banner[4:] if len(banner) > 4 else banner
                    }
                    
        except Exception as e:
            logger.debug(f"FTP probing error for {ip}:{port}: {e}")
        
        return None
    
    def _probe_smtp(self, ip: str, port: int) -> Optional[Dict]:
        """
        Probe SMTP service for information.
        
        Args:
            ip (str): Target IP address
            port (int): Target port
            
        Returns:
            Optional[Dict]: SMTP service information
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(5)
                sock.connect((ip, port))
                
                # SMTP sends greeting
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                
                if '220' in banner:  # SMTP greeting code
                    return {
                        'smtp_banner': banner,
                        'smtp_code': '220',
                        'greeting': banner[4:] if len(banner) > 4 else banner
                    }
                    
        except Exception as e:
            logger.debug(f"SMTP probing error for {ip}:{port}: {e}")
        
        return None
    
    def _analyze_ssl(self, ip: str, port: int) -> Optional[Dict]:
        """
        Analyze SSL/TLS configuration.
        
        Args:
            ip (str): Target IP address
            port (int): Target port
            
        Returns:
            Optional[Dict]: SSL/TLS information
        """
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((ip, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=ip) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    
                    ssl_info = {
                        'ssl_version': ssock.version(),
                        'cipher_suite': cipher[0] if cipher else 'Unknown',
                        'cipher_strength': cipher[2] if cipher and len(cipher) > 2 else 'Unknown'
                    }
                    
                    if cert:
                        ssl_info.update({
                            'subject': dict(x[0] for x in cert.get('subject', [])),
                            'issuer': dict(x[0] for x in cert.get('issuer', [])),
                            'version': cert.get('version'),
                            'not_before': cert.get('notBefore'),
                            'not_after': cert.get('notAfter')
                        })
                    
                    return ssl_info
                    
        except Exception as e:
            logger.debug(f"SSL analysis error for {ip}:{port}: {e}")
        
        return None
    
    def _identify_web_technologies(self, html_content: str, headers: Dict) -> List[str]:
        """
        Identify web technologies from HTML content and headers.
        
        Args:
            html_content (str): HTML content
            headers (Dict): HTTP headers
            
        Returns:
            List[str]: Identified technologies
        """
        technologies = []
        
        # Check headers
        server = headers.get('Server', '').lower()
        if 'nginx' in server:
            technologies.append('nginx')
        elif 'apache' in server:
            technologies.append('Apache')
        elif 'iis' in server:
            technologies.append('IIS')
        
        powered_by = headers.get('X-Powered-By', '').lower()
        if 'php' in powered_by:
            technologies.append('PHP')
        elif 'asp.net' in powered_by:
            technologies.append('ASP.NET')
        
        # Check HTML content
        html_lower = html_content.lower()
        
        # Framework detection
        if 'wordpress' in html_lower or 'wp-content' in html_lower:
            technologies.append('WordPress')
        elif 'joomla' in html_lower:
            technologies.append('Joomla')
        elif 'drupal' in html_lower:
            technologies.append('Drupal')
        
        # JavaScript frameworks
        if 'jquery' in html_lower:
            technologies.append('jQuery')
        if 'bootstrap' in html_lower:
            technologies.append('Bootstrap')
        if 'angular' in html_lower:
            technologies.append('Angular')
        if 'react' in html_lower:
            technologies.append('React')
        
        return technologies
    
    def _load_service_patterns(self) -> Dict[str, List]:
        """
        Load service identification patterns.
        
        Returns:
            Dict[str, List]: Service patterns dictionary
        """
        return {
            'SSH': [
                {'regex': r'SSH-(\d+\.\d+)', 'product': 'OpenSSH'},
                'openssh',
                'ssh'
            ],
            'HTTP': [
                {'regex': r'Server:\s*(.+)', 'product': 'Web Server'},
                'http/',
                'server:'
            ],
            'FTP': [
                {'regex': r'220.*FTP.*?(\d+\.\d+)', 'product': 'FTP Server'},
                '220',
                'ftp'
            ],
            'SMTP': [
                {'regex': r'220.*SMTP.*?(\d+\.\d+)', 'product': 'SMTP Server'},
                '220',
                'smtp'
            ],
            'MySQL': [
                {'regex': r'(\d+\.\d+\.\d+)', 'product': 'MySQL'},
                'mysql',
                'mariadb'
            ],
            'PostgreSQL': [
                {'regex': r'PostgreSQL\s+(\d+\.\d+)', 'product': 'PostgreSQL'},
                'postgresql',
                'postgres'
            ],
            'Redis': [
                {'regex': r'Redis\s+server\s+v=(\d+\.\d+\.\d+)', 'product': 'Redis'},
                'redis_version',
                'redis'
            ],
            'MongoDB': [
                {'regex': r'MongoDB\s+(\d+\.\d+\.\d+)', 'product': 'MongoDB'},
                'mongodb',
                'mongo'
            ],
            'nginx': [
                {'regex': r'nginx/(\d+\.\d+\.\d+)', 'product': 'nginx'},
                'nginx'
            ],
            'Apache': [
                {'regex': r'Apache/(\d+\.\d+\.\d+)', 'product': 'Apache'},
                'apache'
            ]
        }
    
    def _extract_version(self, banner: str, service: str) -> Optional[str]:
        """
        Extract version information from banner.
        
        Args:
            banner (str): Service banner
            service (str): Service name
            
        Returns:
            Optional[str]: Version string if found
        """
        # Generic version patterns
        version_patterns = [
            r'(\d+\.\d+\.\d+)',
            r'(\d+\.\d+)',
            r'v(\d+\.\d+\.\d+)',
            r'version\s+(\d+\.\d+\.\d+)',
        ]
        
        for pattern in version_patterns:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None
    
    def _clean_banner(self, banner: str) -> str:
        """
        Clean and normalize banner text.
        
        Args:
            banner (str): Raw banner text
            
        Returns:
            str: Cleaned banner text
        """
        # Remove control characters and normalize whitespace
        cleaned = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', banner)
        cleaned = ' '.join(cleaned.split())
        
        # Limit length
        if len(cleaned) > 200:
            cleaned = cleaned[:200] + '...'
        
        return cleaned
    
    def _get_probe_data(self, port: int) -> Optional[str]:
        """
        Get protocol-specific probe data.
        
        Args:
            port (int): Target port
            
        Returns:
            Optional[str]: Probe data to send
        """
        if port in [80, 8080]:
            return "GET / HTTP/1.0\r\n\r\n"
        elif port in [21]:
            return "USER anonymous\r\n"
        elif port in [25]:
            return "HELO test\r\n"
        
        return None
    
    def _is_ssl_port(self, port: int) -> bool:
        """Check if port typically uses SSL/TLS."""
        ssl_ports = [443, 993, 995, 465, 636, 8443, 9443]
        return port in ssl_ports
    
    def _is_web_port(self, port: int) -> bool:
        """Check if port is typically used for web services."""
        web_ports = [80, 443, 8000, 8080, 8443, 8888, 9000, 9080, 9443]
        return port in web_ports
    
    def _parse_ssh_version(self, banner: str) -> Dict[str, str]:
        """Parse SSH version information from banner."""
        try:
            if banner.startswith('SSH-'):
                parts = banner.split('-', 2)
                if len(parts) >= 2:
                    return {
                        'protocol_version': parts[1],
                        'software_version': parts[2] if len(parts) > 2 else 'Unknown'
                    }
        except Exception:
            pass
        
        return {'protocol_version': 'Unknown', 'software_version': 'Unknown'}


class BannerGrabber:
    """
    Specialized banner grabbing functionality.
    """
    
    def __init__(self, config: Optional[ServiceDiscoveryConfig] = None):
        """
        Initialize banner grabber.
        
        Args:
            config (ServiceDiscoveryConfig): Configuration object
        """
        self.config = config or ServiceDiscoveryConfig()
        self.error_handler = ServiceDiscoveryErrorHandler()
        
    def grab_banners(self, ip: str, ports: List[int]) -> Dict[int, str]:
        """
        Grab banners from multiple ports.
        
        Args:
            ip (str): Target IP address
            ports (List[int]): List of ports to grab banners from
            
        Returns:
            Dict[int, str]: Dictionary mapping ports to banners
        """
        banners = {}
        
        for port in ports:
            try:
                banner = self._grab_single_banner(ip, port)
                banners[port] = banner
                logger.debug(f"Banner grabbed from {ip}:{port}")
            except Exception as e:
                self.error_handler.handle_error('banner_grab', e, f"{ip}:{port}")
                banners[port] = "No banner"
        
        return banners
    
    def _grab_single_banner(self, ip: str, port: int) -> str:
        """Grab banner from a single port."""
        timeout = self.config.banner_timeout
        max_bytes = self.config.banner_max_bytes
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip, port))
            
            # Send probe if needed
            probe = self._get_probe_for_port(port)
            if probe:
                sock.send(probe.encode())
            
            # Receive banner
            banner = sock.recv(max_bytes).decode('utf-8', errors='ignore').strip()
            return banner if banner else "No banner"
    
    def _get_probe_for_port(self, port: int) -> Optional[str]:
        """Get appropriate probe for port."""
        probes = {
            80: "GET / HTTP/1.0\r\n\r\n",
            8080: "GET / HTTP/1.0\r\n\r\n",
            21: "USER anonymous\r\n",
            25: "HELO test\r\n"
        }
        return probes.get(port)
    
    def get_errors(self) -> Dict:
        """Get banner grabbing errors."""
        return self.error_handler.get_errors()


def main():
    """
    Standalone main function for service identification module.
    Usage: python service_identification.py <target> --port <port>
    """
    import argparse
    import json
    import sys
    import time
    
    # Set up argument parser
    parser = argparse.ArgumentParser(
        description="Service Discovery - Service Identification Module",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python service_identification.py example.com --port 80
  python service_identification.py 192.168.1.1 --port 443 --ssl
  python service_identification.py example.com --port 22 --verbose
  python service_identification.py 192.168.1.1 --port 21 --output results.json
        """
    )
    
    parser.add_argument(
        'target',
        help='Target IP address or hostname'
    )
    
    parser.add_argument(
        '--port',
        type=int,
        required=True,
        help='Port number to identify service on'
    )
    
    parser.add_argument(
        '--ssl',
        action='store_true',
        help='Force SSL/TLS analysis'
    )
    
    parser.add_argument(
        '--banner-only',
        action='store_true',
        help='Only grab banner, skip advanced identification'
    )
    
    parser.add_argument(
        '--timeout',
        type=int,
        default=5,
        help='Connection timeout in seconds (default: 5)'
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
    print("   SERVICE DISCOVERY - SERVICE IDENTIFICATION MODULE")
    print(f"{'='*60}")
    print(f"Target: {args.target}")
    print(f"Port: {args.port}")
    print(f"SSL Analysis: {'Yes' if args.ssl else 'Auto-detect'}")
    print(f"Mode: {'Banner Only' if args.banner_only else 'Full Identification'}")
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
        config.banner_timeout = args.timeout
        # service_detection_timeout is not a standard config attribute, using scan_timeout instead
        config.scan_timeout = args.timeout
        
        start_time = time.time()
        
        if args.banner_only:
            # Just grab banner
            print(f"\n🔍 Grabbing banner from {args.target}:{args.port}...")
            banner_grabber = BannerGrabber(config)
            banners = banner_grabber.grab_banners(args.target, [args.port])
            banner = banners.get(args.port, "No banner")
            
            results = {
                'target': args.target,
                'port': args.port,
                'banner': banner,
                'mode': 'banner_only'
            }
        else:
            # Full service identification
            print(f"\n🔍 Identifying service on {args.target}:{args.port}...")
            identifier = ServiceIdentifier(config)
            service_info = identifier.identify_service(args.target, args.port)
            
            results = {
                'target': args.target,
                'port': args.port,
                'service_info': service_info,
                'mode': 'full_identification'
            }
        
        elapsed_time = time.time() - start_time
        
        # Display results
        print(f"\n{'='*50}")
        print("           IDENTIFICATION RESULTS")
        print(f"{'='*50}")
        
        if args.banner_only:
            if banner and banner != "No banner":
                print(f"\n✅ Banner Retrieved:")
                print(f"  📡 Port {args.port}: {banner}")
                
                # Try basic service identification from banner
                if 'ssh' in banner.lower():
                    print(f"  🔍 Detected Service: SSH")
                elif 'http' in banner.lower() or 'server:' in banner.lower():
                    print(f"  🔍 Detected Service: HTTP")
                elif 'ftp' in banner.lower():
                    print(f"  🔍 Detected Service: FTP")
                elif 'smtp' in banner.lower():
                    print(f"  🔍 Detected Service: SMTP")
            else:
                print(f"\n❌ No banner retrieved from port {args.port}")
        else:
            if service_info:
                print(f"\n✅ Service Identified:")
                service_name = service_info.get('service', 'Unknown')
                print(f"  📡 Service: {service_name}")
                
                # Display banner
                banner = service_info.get('banner', '')
                if banner and banner != 'No banner':
                    banner_preview = banner[:80] + '...' if len(banner) > 80 else banner
                    print(f"  📄 Banner: {banner_preview}")
                
                # Display version if detected
                version = service_info.get('version')
                if version:
                    print(f"  🔖 Version: {version}")
                
                # Display confidence
                confidence = service_info.get('confidence', 'Unknown')
                print(f"  📊 Confidence: {confidence}")
                
                # Display additional protocol info
                additional_info = service_info.get('additional_info', {})
                if additional_info:
                    print(f"\n📋 Additional Information:")
                    for key, value in additional_info.items():
                        if isinstance(value, dict):
                            print(f"  {key.title()}:")
                            for sub_key, sub_value in value.items():
                                if isinstance(sub_value, (dict, list)):
                                    print(f"    {sub_key}: {str(sub_value)[:100]}...")
                                else:
                                    print(f"    {sub_key}: {sub_value}")
                        elif isinstance(value, list):
                            print(f"  {key.title()}: {', '.join(map(str, value))}")
                        else:
                            print(f"  {key.title()}: {value}")
                
                # Display SSL information if available
                ssl_info = additional_info.get('ssl')
                if ssl_info:
                    print(f"\n🔒 SSL/TLS Information:")
                    ssl_version = ssl_info.get('ssl_version', 'Unknown')
                    cipher = ssl_info.get('cipher_suite', 'Unknown')
                    print(f"  Version: {ssl_version}")
                    print(f"  Cipher: {cipher}")
                    
                    # Certificate info
                    subject = ssl_info.get('subject', {})
                    if subject:
                        cn = subject.get('commonName', 'Unknown')
                        print(f"  Certificate CN: {cn}")
                
                # Display technologies if detected (for web services)
                technologies = additional_info.get('technologies', [])
                if technologies:
                    print(f"\n🛠️  Technologies Detected:")
                    for tech in technologies:
                        print(f"  • {tech}")
            else:
                print(f"\n❌ Could not identify service on port {args.port}")
        
        print(f"\n{'='*50}")
        print("           IDENTIFICATION STATISTICS")
        print(f"{'='*50}")
        print(f"  Target: {args.target}:{args.port}")
        print(f"  Analysis Duration: {elapsed_time:.2f} seconds")
        print(f"  Mode: {results['mode']}")
        
        # Check for errors
        if not args.banner_only:
            identifier_errors = identifier.error_handler.get_errors()
            total_errors = sum(len(error_list) for error_list in identifier_errors.values())
            if total_errors > 0:
                print(f"\n⚠️  Errors encountered: {total_errors}")
                for module, error_list in identifier_errors.items():
                    if error_list:
                        print(f"  {module}: {len(error_list)} errors")
        
        print(f"\n{'='*60}")
        print("         IDENTIFICATION COMPLETE")
        print(f"{'='*60}")
        
        # Save results if output file specified
        if args.output:
            try:
                with open(args.output, 'w') as f:
                    json.dump(results, f, indent=2, default=str)
                
                print(f"\n💾 Results saved to: {args.output}")
            except Exception as e:
                print(f"❌ Error saving results: {e}")
        
    except KeyboardInterrupt:
        print("\n[!] Identification interrupted by user")
        logging.info("Service identification interrupted by user")
    except Exception as e:
        print(f"\n[-] Identification failed: {e}")
        logging.error(f"Service identification failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()