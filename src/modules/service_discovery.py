import socket
import logging
from concurrent.futures import ThreadPoolExecutor

class ServiceDiscovery:
    def __init__(self, domain):
        self.domain = domain
        self.results = {}

    def discover_services(self, common_ports):
        """Discover open ports and services"""
        logging.info("Starting service discovery")
        self.results['services'] = {}
        target_ip = socket.gethostbyname(self.domain)
        
        def check_port(port):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(1)
                    result = sock.connect_ex((target_ip, port))
                    if result == 0:
                        try:
                            banner = sock.recv(1024).decode().strip()
                            return port, banner
                        except:
                            return port, "No banner"
            except:
                return None
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            results = executor.map(check_port, common_ports.keys())
        
        open_ports = {}
        for result in results:
            if result:
                port, banner = result
                service = common_ports.get(port, 'Unknown')
                open_ports[port] = {
                    'service': service,
                    'banner': banner
                }
                logging.info(f"Port {port} ({service}) is open. Banner: {banner}")
        
        self.results['services']['open_ports'] = open_ports
        return self.results['services']