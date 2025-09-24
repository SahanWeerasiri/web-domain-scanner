#!/usr/bin/env python3
"""
Simple Service Identification Module
Uses port scanner results to identify services on open ports
"""

import socket
import ssl
import json
import logging
from typing import Dict, List, Optional, Any

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class SimpleServiceIdentifier:
    """
    Simple service identification using port scanner results
    """
    
    # Common service ports mapping
    COMMON_SERVICES = {
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        143: 'IMAP',
        443: 'HTTPS',
        993: 'IMAPS',
        995: 'POP3S',
        3306: 'MySQL',
        3389: 'RDP',
        5432: 'PostgreSQL',
        5900: 'VNC',
        6379: 'Redis',
        27017: 'MongoDB'
    }
    
    def __init__(self, timeout: int = 5):
        """
        Initialize service identifier
        
        Args:
            timeout: Connection timeout in seconds
        """
        self.timeout = timeout
    
    def identify_services(self, target: str, ports: List[int]) -> Dict[int, Dict[str, Any]]:
        """
        Identify services on multiple ports
        
        Args:
            target: IP address or hostname
            ports: List of port numbers
            
        Returns:
            Dictionary mapping ports to service information
        """
        results = {}
        
        for port in ports:
            try:
                logger.info(f"Identifying service on {target}:{port}")
                service_info = self._identify_single_service(target, port)
                results[port] = service_info
            except Exception as e:
                logger.error(f"Error identifying service on port {port}: {e}")
                results[port] = {
                    'port': port,
                    'service': 'Unknown',
                    'banner': 'Error during identification',
                    'error': str(e)
                }
        
        return results
    
    def _identify_single_service(self, target: str, port: int) -> Dict[str, Any]:
        """
        Identify service on a single port
        
        Args:
            target: IP address or hostname
            port: Port number
            
        Returns:
            Service information dictionary
        """
        result = {
            'port': port,
            'service': self._guess_service_by_port(port),
            'banner': None,
            'version': None,
            'ssl': False,
            'protocol_info': {}
        }
        
        # Try to grab banner
        banner = self._grab_banner(target, port)
        if banner and banner != "No banner":
            result['banner'] = banner
            result['service'] = self._identify_by_banner(banner, port)
            result['version'] = self._extract_version(banner)
        
        # Check for SSL/TLS
        if self._is_ssl_service(port) or self._check_ssl(target, port):
            result['ssl'] = True
            ssl_info = self._get_ssl_info(target, port)
            if ssl_info:
                result['protocol_info']['ssl'] = ssl_info
        
        # Get additional protocol info for common services
        if port in [80, 443, 8080, 8443]:
            http_info = self._get_http_info(target, port)
            if http_info:
                result['protocol_info']['http'] = http_info
        
        return result
    
    def _guess_service_by_port(self, port: int) -> str:
        """Guess service based on port number"""
        return self.COMMON_SERVICES.get(port, 'Unknown')
    
    def _grab_banner(self, target: str, port: int) -> str:
        """Grab service banner from port"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                sock.connect((target, port))
                
                # Send appropriate probe based on port
                probe = self._get_probe_data(port)
                if probe:
                    sock.send(probe.encode())
                
                # Receive banner
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                return banner if banner else "No banner"
                
        except socket.timeout:
            return "No banner (timeout)"
        except Exception as e:
            return f"No banner ({str(e)})"
    
    def _identify_by_banner(self, banner: str, port: int) -> str:
        """Identify service based on banner content"""
        banner_lower = banner.lower()
        
        if any(x in banner_lower for x in ['ssh', 'openssh']):
            return 'SSH'
        elif any(x in banner_lower for x in ['http', 'server:', 'apache', 'nginx']):
            return 'HTTP' if port != 443 else 'HTTPS'
        elif any(x in banner_lower for x in ['ftp', '220']):
            return 'FTP'
        elif any(x in banner_lower for x in ['smtp', '220']):
            return 'SMTP'
        elif any(x in banner_lower for x in ['mysql', 'mariadb']):
            return 'MySQL'
        elif 'postgresql' in banner_lower:
            return 'PostgreSQL'
        elif 'redis' in banner_lower:
            return 'Redis'
        
        return self._guess_service_by_port(port)
    
    def _extract_version(self, banner: str) -> Optional[str]:
        """Extract version number from banner"""
        import re
        
        # Common version patterns
        patterns = [
            r'(\d+\.\d+\.\d+)',
            r'(\d+\.\d+)',
            r'v(\d+\.\d+\.\d+)',
            r'version\s+(\d+\.\d+\.\d+)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, banner)
            if match:
                return match.group(1)
        
        return None
    
    def _is_ssl_service(self, port: int) -> bool:
        """Check if port typically uses SSL/TLS"""
        ssl_ports = [443, 993, 995, 465, 636, 8443, 9443]
        return port in ssl_ports
    
    def _check_ssl(self, target: str, port: int) -> bool:
        """Check if service supports SSL/TLS"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((target, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    return True
        except:
            return False
    
    def _get_ssl_info(self, target: str, port: int) -> Optional[Dict[str, Any]]:
        """Get SSL/TLS information"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((target, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    cipher = ssock.cipher()
                    cert = ssock.getpeercert()
                    
                    ssl_info = {
                        'version': ssock.version(),
                        'cipher': cipher[0] if cipher else 'Unknown',
                    }
                    
                    if cert:
                        # Extract common name from certificate
                        subjects = dict(x[0] for x in cert.get('subject', []))
                        ssl_info['subject'] = subjects.get('commonName', 'Unknown')
                    
                    return ssl_info
        except Exception as e:
            logger.debug(f"SSL info error: {e}")
            return None
    
    def _get_http_info(self, target: str, port: int) -> Optional[Dict[str, Any]]:
        """Get HTTP service information"""
        try:
            import urllib.request
            import urllib.error
            
            protocol = 'https' if port in [443, 8443] else 'http'
            url = f"{protocol}://{target}:{port}"
            
            # Create custom opener to avoid SSL verification issues
            opener = urllib.request.build_opener(
                urllib.request.HTTPHandler(),
                urllib.request.HTTPSHandler(context=ssl._create_unverified_context())
            )
            urllib.request.install_opener(opener)
            
            req = urllib.request.Request(url, method='HEAD')
            response = urllib.request.urlopen(req, timeout=self.timeout)
            
            return {
                'status_code': response.getcode(),
                'server': response.headers.get('Server', 'Unknown'),
                'content_type': response.headers.get('Content-Type', 'Unknown')
            }
            
        except Exception as e:
            logger.debug(f"HTTP info error: {e}")
            return None
    
    def _get_probe_data(self, port: int) -> Optional[str]:
        """Get protocol-specific probe data to send"""
        probes = {
            80: "GET / HTTP/1.0\r\n\r\n",
            443: "GET / HTTP/1.0\r\n\r\n",
            8080: "GET / HTTP/1.0\r\n\r\n",
            8443: "GET / HTTP/1.0\r\n\r\n",
            21: "USER anonymous\r\n",
            25: "HELO test\r\n",
            22: "\r\n",  # SSH usually sends banner without probe
        }
        return probes.get(port)

def identify_services_from_scanner(target: str, scan_results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Identify services using port scanner results
    
    Args:
        target: Target IP/hostname
        scan_results: Results from port scanner
        
    Returns:
        Combined results with service identification
    """
    identifier = SimpleServiceIdentifier()
    
    # Extract open ports from scan results
    open_ports = []
    
    # Handle different result formats from the port scanner
    if 'open_ports' in scan_results:
        open_ports = scan_results['open_ports']
    elif 'results' in scan_results:
        # Try to parse nmap output format
        for line in scan_results['results'].split('\n'):
            if '/tcp' in line and 'open' in line:
                try:
                    port = int(line.split('/')[0])
                    open_ports.append(port)
                except (ValueError, IndexError):
                    continue
    elif 'output' in scan_results:
        # Parse nmap command output
        for line in scan_results['output'].split('\n'):
            if '/tcp' in line and 'open' in line:
                try:
                    port = int(line.split('/')[0])
                    open_ports.append(port)
                except (ValueError, IndexError):
                    continue
    
    logger.info(f"Found {len(open_ports)} open ports to identify")
    
    # Identify services on open ports
    service_results = identifier.identify_services(target, open_ports)
    
    return {
        'target': target,
        'scan_type': scan_results.get('method', 'unknown'),
        'open_ports_count': len(open_ports),
        'services': service_results,
        'summary': _create_summary(service_results)
    }

def _create_summary(services: Dict[int, Dict]) -> Dict[str, Any]:
    """Create summary of identified services"""
    service_counts = {}
    ssl_services = []
    
    for port, info in services.items():
        service = info.get('service', 'Unknown')
        service_counts[service] = service_counts.get(service, 0) + 1
        
        if info.get('ssl'):
            ssl_services.append(f"{service} (port {port})")
    
    return {
        'service_distribution': service_counts,
        'ssl_services': ssl_services,
        'total_services': len(services)
    }

def main():
    """Command line interface for service identification"""
    import argparse
    import sys
    
    parser = argparse.ArgumentParser(description='Simple Service Identification')
    parser.add_argument('target', help='Target IP address or hostname')
    parser.add_argument('-p', '--ports', help='Ports to scan (e.g., "80,443,1-100")')
    parser.add_argument('-t', '--timeout', type=int, default=5, help='Timeout in seconds')
    parser.add_argument('-o', '--output', help='Output file (JSON format)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Create mock scan results for demonstration
    # In real usage, this would come from the actual port scanner
    if args.ports:
        # Parse ports from argument
        ports = []
        for part in args.ports.split(','):
            if '-' in part:
                start, end = map(int, part.split('-'))
                ports.extend(range(start, end + 1))
            else:
                ports.append(int(part))
        
        mock_scan_results = {
            'method': 'custom',
            'open_ports': ports,  # For demo, assuming all are open
            'output': f"Mock scan of ports: {args.ports}"
        }
    else:
        # Default to common ports
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 3389, 5432, 5900]
        mock_scan_results = {
            'method': 'quick',
            'open_ports': common_ports,  # For demo, assuming all are open
            'output': f"Mock quick scan of common ports"
        }
    
    print(f"Service Identification for: {args.target}")
    print("=" * 50)
    
    try:
        results = identify_services_from_scanner(args.target, mock_scan_results)
        
        # Display results
        print(f"\n📊 Scan Summary:")
        print(f"  Target: {results['target']}")
        print(f"  Scan Type: {results['scan_type']}")
        print(f"  Open Ports: {results['open_ports_count']}")
        
        print(f"\n🔍 Identified Services:")
        for port, service_info in results['services'].items():
            service = service_info.get('service', 'Unknown')
            banner = service_info.get('banner', 'No banner')
            ssl = "🔒" if service_info.get('ssl') else "🔓"
            
            print(f"  Port {port}: {service} {ssl}")
            
            if banner and banner != "No banner":
                banner_preview = banner[:60] + '...' if len(banner) > 60 else banner
                print(f"        Banner: {banner_preview}")
            
            version = service_info.get('version')
            if version:
                print(f"        Version: {version}")
        
        print(f"\n📈 Summary:")
        summary = results['summary']
        for service, count in summary['service_distribution'].items():
            print(f"  {service}: {count} port(s)")
        
        if summary['ssl_services']:
            print(f"\n🔒 SSL/TLS Services:")
            for service in summary['ssl_services']:
                print(f"  • {service}")
        
        # Save to file if requested
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"\n💾 Results saved to: {args.output}")
    
    except Exception as e:
        logger.error(f"Service identification failed: {e}")
        sys.exit(1)

# Example usage with port scanner integration
def example_usage():
    """Example of how to use with the port scanner"""
    
    # Mock port scanner results (replace with actual port scanner output)
    port_scan_results = {
        'method': 'quick',
        'open_ports': [22, 80, 443, 3306],
        'output': "Nmap scan results would be here..."
    }
    
    target = "example.com"
    
    # Identify services on scanned ports
    service_results = identify_services_from_scanner(target, port_scan_results)
    
    print("Service Identification Results:")
    print(json.dumps(service_results, indent=2))

if __name__ == "__main__":
    main()