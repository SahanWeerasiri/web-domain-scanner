"""
Service discovery module for port scanning and service fingerprinting
"""
from asyncio import as_completed
import logging
import subprocess
import nmap
import socket
from concurrent.futures import ThreadPoolExecutor

class ServiceDiscoverer:
    def __init__(self, target, max_threads=10):
        self.target = target
        self.max_threads = max_threads
        self.nm = nmap.PortScanner()
    
    def discover_services(self):
        """Discover open ports and services on target"""
        logging.info("Starting service discovery")
        
        results = {}
        
        # Fast scan with RustScan (if available) or Nmap
        try:
            # Try using RustScan for faster scanning
            rustscan_result = self._rustscan_ports()
            if rustscan_result:
                results['open_ports'] = rustscan_result
            else:
                # Fallback to Nmap
                results['open_ports'] = self._nmap_scan()
        except Exception as e:
            logging.error(f"Port scanning failed: {str(e)}")
            results['open_ports'] = self._simple_port_scan()
        
        # Service version detection
        results['service_versions'] = self._service_version_detection(results.get('open_ports', []))
        
        return results
    
    def _rustscan_ports(self):
        """Use RustScan for fast port scanning"""
        try:
            # RustScan is much faster than Nmap for initial port discovery
            result = subprocess.run([
                'rustscan', '-a', self.target, '--', '-sV', '--version-intensity', '5'
            ], capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                return self._parse_rustscan_output(result.stdout)
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
            logging.warning("RustScan not available, falling back to Nmap")
        
        return None
    
    def _nmap_scan(self):
        """Perform Nmap port scanning"""
        try:
            # First do a quick scan of common ports
            self.nm.scan(self.target, arguments='-F --open')
            
            # If we found open ports, do a more detailed scan
            if self.nm[self.target].all_tcp():
                self.nm.scan(self.target, arguments='-sV --version-intensity 5')
            
            return self._parse_nmap_output()
        except Exception as e:
            logging.error(f"Nmap scan failed: {str(e)}")
            return self._simple_port_scan()
    
    def _simple_port_scan(self):
        """Fallback simple port scan using socket"""
        common_ports = [21, 22, 80, 443, 3306, 3389, 8080, 8443]
        open_ports = []
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(self._check_port, port): port for port in common_ports}
            
            for future in as_completed(futures):
                port = futures[future]
                try:
                    if future.result():
                        open_ports.append(port)
                except Exception:
                    pass
        
        return open_ports
    
    def _check_port(self, port):
        """Check if a port is open"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                result = sock.connect_ex((self.target, port))
                return result == 0
        except Exception:
            return False
    
    def _service_version_detection(self, open_ports):
        """Detect service versions on open ports"""
        if not open_ports:
            return {}
        
        # This would be implemented with more detailed Nmap scanning
        # or banner grabbing
        return {}