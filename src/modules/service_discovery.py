"""
Service discovery module for port scanning and service fingerprinting
"""
from concurrent.futures import as_completed
import logging
import socket
from concurrent.futures import ThreadPoolExecutor

class ServiceDiscoverer:
    def __init__(self, target, max_threads=10):
        self.target = target
        self.max_threads = max_threads
    
    def discover_services(self):
        """Discover open ports and services on target"""
        logging.info("Starting service discovery")
        
        results = {}
        
        # Only use simple socket scan
        try:
            results['open_ports'] = self._simple_port_scan()
        except Exception as e:
            logging.error(f"Port scanning failed: {str(e)}")
            results['open_ports'] = []
        
        # Service version detection
        results['service_versions'] = self._service_version_detection(results.get('open_ports', []))
        
        return results
    

    

    
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