import socket
import logging
import subprocess
import threading
import time
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

class ServiceDiscovery:
    def __init__(self, domain):
        self.domain = domain
        self.results = {}
        self.target_ip = None
        
        # Resolve domain to IP
        try:
            self.target_ip = socket.gethostbyname(self.domain)
            logging.info(f"[+] Resolved {self.domain} to IP: {self.target_ip}")
        except socket.gaierror as e:
            logging.error(f"[-] Failed to resolve domain {self.domain}: {e}")
            raise

    def discover_services(self, common_ports, scan_mode='quick'):
        """
        Discover open ports and services with different scanning modes
        
        Args:
            common_ports (dict): Dictionary of ports and their services
            scan_mode (str): 'quick', 'smart', or 'deep'
        
        Returns:
            dict: Service discovery results
        """
        logging.info(f"[*] Starting service discovery for {self.domain} ({self.target_ip}) in '{scan_mode}' mode")
        
        if scan_mode == 'quick':
            return self._quick_scan(common_ports)
        elif scan_mode == 'smart':
            return self._smart_scan(common_ports)
        elif scan_mode == 'deep':
            return self._deep_scan()
        else:
            logging.warning(f"⚠️ Unknown scan mode '{scan_mode}', defaulting to 'quick'")
            return self._quick_scan(common_ports)

    def _quick_scan(self, common_ports):
        """Quick scan using commonly used ports"""
        logging.info("[*] Running QUICK scan - checking common ports only")
        print(f"[QUICK SCAN] Scanning {len(common_ports)} common ports on {self.domain}")
        
        self.results['services'] = {
            'scan_mode': 'quick',
            'ports_scanned': len(common_ports),
            'open_ports': {}
        }
        
        def check_port(port):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(2)
                    result = sock.connect_ex((self.target_ip, port))
                    if result == 0:
                        try:
                            banner = sock.recv(1024).decode().strip()
                            return port, banner
                        except:
                            return port, "No banner"
            except Exception as e:
                logging.debug(f"Error checking port {port}: {e}")
                return None
        
        start_time = time.time()
        with ThreadPoolExecutor(max_workers=20) as executor:
            future_to_port = {executor.submit(check_port, port): port for port in common_ports.keys()}
            completed = 0
            
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                completed += 1
                
                try:
                    result = future.result()
                    if result:
                        port_num, banner = result
                        service = common_ports.get(port_num, 'Unknown')
                        self.results['services']['open_ports'][port_num] = {
                            'service': service,
                            'banner': banner,
                            'state': 'open'
                        }
                        print(f"  [+] Port {port_num}/{service} is OPEN - Banner: {banner}")
                        logging.info(f"[+] Port {port_num} ({service}) is open. Banner: {banner}")
                    
                    # Progress indicator
                    if completed % 5 == 0 or completed == len(common_ports):
                        progress = (completed / len(common_ports)) * 100
                        print(f"  Progress: {completed}/{len(common_ports)} ports ({progress:.1f}%)")
                        
                except Exception as e:
                    logging.error(f"[-] Error scanning port {port}: {e}")
        
        scan_time = time.time() - start_time
        self.results['services']['scan_duration'] = round(scan_time, 2)
        
        open_count = len(self.results['services']['open_ports'])
        print(f"[QUICK SCAN] Completed in {scan_time:.2f}s - Found {open_count} open ports")
        logging.info(f"[*] Quick scan completed in {scan_time:.2f}s - Found {open_count} open ports")
        
        return self.results['services']

    def _smart_scan(self, common_ports):
        """Smart scan using port fuzzing and intelligent detection"""
        logging.info("[*] Running SMART scan - using fuzzing techniques and intelligent detection")
        print(f"[SMART SCAN] Scanning {self.domain} with intelligent fuzzing")
        
        # Start with quick scan results
        quick_results = self._quick_scan(common_ports)
        
        # Extended port ranges for smart scanning
        extended_ports = self._generate_smart_port_list(quick_results['open_ports'])
        
        print(f"[SMART SCAN] Extending scan to {len(extended_ports)} additional ports based on findings")
        logging.info(f"[*] Smart scan extending to {len(extended_ports)} additional ports")
        
        self.results['services'].update({
            'scan_mode': 'smart',
            'extended_ports_scanned': len(extended_ports),
            'total_ports_scanned': len(common_ports) + len(extended_ports)
        })
        
        # Scan extended ports
        if extended_ports:
            start_time = time.time()
            
            def check_extended_port(port):
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                        sock.settimeout(1.5)
                        result = sock.connect_ex((self.target_ip, port))
                        if result == 0:
                            try:
                                banner = sock.recv(1024).decode().strip()
                                return port, banner
                            except:
                                return port, "No banner"
                except:
                    return None
            
            with ThreadPoolExecutor(max_workers=30) as executor:
                future_to_port = {executor.submit(check_extended_port, port): port for port in extended_ports}
                completed = 0
                
                for future in as_completed(future_to_port):
                    port = future_to_port[future]
                    completed += 1
                    
                    try:
                        result = future.result()
                        if result:
                            port_num, banner = result
                            service = self._identify_service(port_num, banner)
                            self.results['services']['open_ports'][port_num] = {
                                'service': service,
                                'banner': banner,
                                'state': 'open',
                                'discovered_by': 'smart_scan'
                            }
                            print(f"  [+] [SMART] Port {port_num}/{service} is OPEN - Banner: {banner}")
                            logging.info(f"[+] [SMART] Port {port_num} ({service}) discovered. Banner: {banner}")
                        
                        # Progress indicator
                        if completed % 20 == 0 or completed == len(extended_ports):
                            progress = (completed / len(extended_ports)) * 100
                            print(f"  Smart scan progress: {completed}/{len(extended_ports)} ports ({progress:.1f}%)")
                            
                    except Exception as e:
                        logging.error(f"[-] Error in smart scan of port {port}: {e}")
            
            smart_scan_time = time.time() - start_time
            logging.info(f"[*] Smart scan extension completed in {smart_scan_time:.2f}s")
        
        total_open = len(self.results['services']['open_ports'])
        print(f"[SMART SCAN] Completed - Total {total_open} open ports discovered")
        logging.info(f"[*] Smart scan completed - Total {total_open} open ports discovered")
        
        return self.results['services']

    def _deep_scan(self):
        """Deep scan using external tools like nmap or rustscan"""
        logging.info("[*] Running DEEP scan - using external tools (nmap/rustscan)")
        print(f"[DEEP SCAN] Comprehensive scan of {self.domain} using external tools")
        
        self.results['services'] = {
            'scan_mode': 'deep',
            'open_ports': {},
            'scan_details': {}
        }
        
        # Try rustscan first (faster), fallback to nmap
        deep_scan_result = None
        
        if self._check_tool_availability('rustscan'):
            deep_scan_result = self._run_rustscan()
        elif self._check_tool_availability('nmap'):
            deep_scan_result = self._run_nmap()
        else:
            logging.warning("[!] Neither rustscan nor nmap available, falling back to comprehensive Python scan")
            print("[DEEP SCAN] External tools not available, using comprehensive Python scan")
            return self._comprehensive_python_scan()
        
        if deep_scan_result:
            self.results['services'].update(deep_scan_result)
        
        total_open = len(self.results['services']['open_ports'])
        print(f"[DEEP SCAN] Completed - Found {total_open} open ports")
        logging.info(f"[*] Deep scan completed - Found {total_open} open ports")
        
        return self.results['services']

    def _generate_smart_port_list(self, open_ports):
        """Generate intelligent port list based on discovered services"""
        extended_ports = set()
        
        # Service-specific port extensions
        for port, info in open_ports.items():
            service = info.get('service', '').lower()
            
            if 'http' in service or port in [80, 443]:
                # Web services - check alternative HTTP ports
                extended_ports.update([8000, 8080, 8443, 8888, 9000, 9080, 9443])
                logging.info("[*] Web service detected - adding HTTP alternative ports")
                
            elif 'ssh' in service or port == 22:
                # SSH - check alternative SSH ports
                extended_ports.update([2222, 2200, 22222])
                logging.info("[*] SSH service detected - adding alternative SSH ports")
                
            elif 'ftp' in service or port == 21:
                # FTP - check related ports
                extended_ports.update([20, 990, 989])
                logging.info("[*] FTP service detected - adding FTP-related ports")
                
            elif 'mysql' in service or port == 3306:
                # Database - check other database ports
                extended_ports.update([3307, 5432, 1433, 1521, 27017])
                logging.info("[*] Database service detected - adding database ports")
        
        # Common high-value ports
        high_value_ports = [
            1433, 1521, 3389, 5432, 5900, 5985, 5986,  # Database, RDP, VNC, WinRM
            6379, 27017, 9200, 9300,  # Redis, MongoDB, Elasticsearch
            50070, 8161, 9999  # Hadoop, ActiveMQ, etc.
        ]
        extended_ports.update(high_value_ports)
        
        # Remove already scanned ports
        extended_ports = extended_ports - set(open_ports.keys())
        
        return list(extended_ports)

    def _identify_service(self, port, banner):
        """Identify service based on port and banner"""
        common_services = {
            20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'TELNET',
            25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3',
            143: 'IMAP', 443: 'HTTPS', 993: 'IMAPS', 995: 'POP3S',
            1433: 'MSSQL', 1521: 'ORACLE', 3306: 'MYSQL', 3389: 'RDP',
            5432: 'POSTGRESQL', 5900: 'VNC', 6379: 'REDIS', 27017: 'MONGODB'
        }
        
        service = common_services.get(port, 'Unknown')
        
        # Enhance identification using banner
        if banner and banner != "No banner":
            banner_lower = banner.lower()
            if 'ssh' in banner_lower:
                service = f'SSH ({banner.split()[0] if banner.split() else "SSH"})'
            elif 'http' in banner_lower:
                service = 'HTTP'
            elif 'ftp' in banner_lower:
                service = 'FTP'
            elif 'mysql' in banner_lower:
                service = 'MySQL'
        
        return service

    def _check_tool_availability(self, tool_name):
        """Check if external tool is available"""
        try:
            result = subprocess.run([tool_name, '--version'], 
                                  capture_output=True, text=True, timeout=5)
            available = result.returncode == 0
            if available:
                print(f"  [+] {tool_name} is available")
                logging.info(f"[+] External tool {tool_name} is available")
            return available
        except (subprocess.TimeoutExpired, FileNotFoundError):
            print(f"  [-] {tool_name} is not available")
            logging.info(f"[-] External tool {tool_name} is not available")
            return False

    def _run_rustscan(self):
        """Run rustscan for deep port scanning"""
        print("  Running rustscan for comprehensive port discovery...")
        logging.info("[*] Running rustscan for deep scan")
        
        try:
            cmd = ['rustscan', '-a', self.target_ip, '--ulimit', '5000', '--timeout', '3000']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                return self._parse_rustscan_output(result.stdout)
            else:
                logging.error(f"[-] Rustscan failed with return code {result.returncode}")
                logging.error(f"Error output: {result.stderr}")
                return None
                
        except subprocess.TimeoutExpired:
            logging.error("[-] Rustscan timed out after 5 minutes")
            return None
        except Exception as e:
            logging.error(f"[-] Error running rustscan: {e}")
            return None

    def _run_nmap(self):
        """Run nmap for deep port scanning"""
        print("  Running nmap for comprehensive port discovery...")
        logging.info("[*] Running nmap for deep scan")
        
        try:
            cmd = ['nmap', '-sS', '-O', '-sV', '--top-ports', '1000', self.target_ip]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            if result.returncode == 0:
                return self._parse_nmap_output(result.stdout)
            else:
                logging.error(f"[-] Nmap failed with return code {result.returncode}")
                logging.error(f"Error output: {result.stderr}")
                return None
                
        except subprocess.TimeoutExpired:
            logging.error("[-] Nmap timed out after 10 minutes")
            return None
        except Exception as e:
            logging.error(f"[-] Error running nmap: {e}")
            return None

    def _parse_rustscan_output(self, output):
        """Parse rustscan output"""
        open_ports = {}
        scan_details = {'tool': 'rustscan', 'raw_output': output}
        
        for line in output.split('\n'):
            if 'Open' in line and '->' in line:
                try:
                    port_info = line.split('->')[1].strip()
                    port = int(port_info.split('/')[0])
                    service = self._identify_service(port, "")
                    
                    open_ports[port] = {
                        'service': service,
                        'state': 'open',
                        'banner': 'Detected by rustscan',
                        'tool': 'rustscan'
                    }
                    print(f"  [+] [RUSTSCAN] Port {port}/{service} is OPEN")
                    
                except (ValueError, IndexError):
                    continue
        
        logging.info(f"[*] Rustscan found {len(open_ports)} open ports")
        return {'open_ports': open_ports, 'scan_details': scan_details}

    def _parse_nmap_output(self, output):
        """Parse nmap output"""
        open_ports = {}
        scan_details = {'tool': 'nmap', 'raw_output': output}
        
        lines = output.split('\n')
        for line in lines:
            if '/tcp' in line and 'open' in line:
                try:
                    parts = line.split()
                    port_protocol = parts[0]
                    port = int(port_protocol.split('/')[0])
                    state = parts[1]
                    service = parts[2] if len(parts) > 2 else 'unknown'
                    
                    if state == 'open':
                        open_ports[port] = {
                            'service': service,
                            'state': 'open',
                            'banner': f'Detected by nmap as {service}',
                            'tool': 'nmap'
                        }
                        print(f"  [+] [NMAP] Port {port}/{service} is OPEN")
                        
                except (ValueError, IndexError):
                    continue
        
        logging.info(f"[*] Nmap found {len(open_ports)} open ports")
        return {'open_ports': open_ports, 'scan_details': scan_details}

    def _comprehensive_python_scan(self):
        """Comprehensive Python-based port scan as fallback"""
        logging.info("[*] Running comprehensive Python port scan")
        print("  Running comprehensive Python-based port scan...")
        
        # Scan top 1000 ports
        top_ports = [
            1, 3, 4, 6, 7, 9, 13, 17, 19, 20, 21, 22, 23, 24, 25, 26, 30, 32, 33, 37, 42, 43, 49, 53, 70, 79, 80, 81, 82, 83, 84, 85, 88, 89, 90, 99, 100, 106, 109, 110, 111, 113, 119, 125, 135, 139, 143, 144, 146, 161, 163, 179, 199, 211, 212, 222, 254, 255, 256, 259, 264, 280, 301, 306, 311, 340, 366, 389, 406, 407, 416, 417, 425, 427, 443, 444, 445, 458, 464, 465, 481, 497, 500, 512, 513, 514, 515, 524, 541, 543, 544, 545, 548, 554, 555, 563, 587, 593, 616, 617, 625, 631, 636, 646, 648, 666, 667, 668, 683, 687, 691, 700, 705, 711, 714, 720, 722, 726, 749, 765, 777, 783, 787, 800, 801, 808, 843, 873, 880, 888, 898, 900, 901, 902, 903, 911, 912, 981, 987, 990, 992, 993, 995, 999, 1000, 1001, 1002, 1007, 1009, 1010, 1011, 1021, 1022, 1023, 1024, 1025, 1026, 1027, 1028, 1029, 1030, 1031, 1032, 1033, 1034, 1035, 1036, 1037, 1038, 1039, 1040, 1041, 1042, 1043, 1044, 1045, 1046, 1047, 1048, 1049, 1050, 1051, 1052, 1053, 1054, 1055, 1056, 1057, 1058, 1059, 1060, 1061, 1062, 1063, 1064, 1065, 1066, 1067, 1068, 1069, 1070, 1071, 1072, 1073, 1074, 1075, 1076, 1077, 1078, 1079, 1080, 1081, 1082, 1083, 1084, 1085, 1086, 1087, 1088, 1089, 1090, 1091, 1092, 1093, 1094, 1095, 1096, 1097, 1098, 1099, 1100
        ]
        
        open_ports = {}
        start_time = time.time()
        
        def check_port(port):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(1)
                    result = sock.connect_ex((self.target_ip, port))
                    if result == 0:
                        try:
                            banner = sock.recv(1024).decode().strip()
                            return port, banner
                        except:
                            return port, "No banner"
            except:
                return None
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            future_to_port = {executor.submit(check_port, port): port for port in top_ports}
            completed = 0
            
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                completed += 1
                
                try:
                    result = future.result()
                    if result:
                        port_num, banner = result
                        service = self._identify_service(port_num, banner)
                        open_ports[port_num] = {
                            'service': service,
                            'banner': banner,
                            'state': 'open',
                            'tool': 'python_comprehensive'
                        }
                        print(f"  [+] [PYTHON] Port {port_num}/{service} is OPEN - Banner: {banner}")
                        logging.info(f"[+] [PYTHON] Port {port_num} ({service}) is open. Banner: {banner}")
                    
                    # Progress indicator
                    if completed % 50 == 0 or completed == len(top_ports):
                        progress = (completed / len(top_ports)) * 100
                        print(f"  Comprehensive scan progress: {completed}/{len(top_ports)} ports ({progress:.1f}%)")
                        
                except Exception as e:
                    logging.error(f"[-] Error in comprehensive scan of port {port}: {e}")
        
        scan_time = time.time() - start_time
        logging.info(f"[*] Comprehensive Python scan completed in {scan_time:.2f}s - Found {len(open_ports)} open ports")
        
        return {
            'open_ports': open_ports,
            'scan_details': {'tool': 'python_comprehensive', 'scan_duration': scan_time, 'ports_scanned': len(top_ports)},
            'ports_scanned': len(top_ports),
            'scan_duration': round(scan_time, 2)
        }


if __name__ == "__main__":
    import argparse
    import json
    
    # Configure logging for standalone mode
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('service_discovery_test.log'),
            logging.StreamHandler()
        ]
    )
    
    # Common ports for testing
    COMMON_PORTS = {
        20: 'FTP-DATA',
        21: 'FTP',
        22: 'SSH',
        23: 'TELNET',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        143: 'IMAP',
        443: 'HTTPS',
        993: 'IMAPS',
        995: 'POP3S',
        1433: 'MSSQL',
        1521: 'ORACLE',
        3306: 'MySQL',
        3389: 'RDP',
        5432: 'PostgreSQL',
        5900: 'VNC',
        6379: 'Redis',
        8080: 'HTTP-Alt',
        8443: 'HTTPS-Alt',
        27017: 'MongoDB'
    }
    
    parser = argparse.ArgumentParser(description="Service Discovery Tool - Test scanning modes independently")
    parser.add_argument("domain", help="Domain or IP address to scan")
    parser.add_argument("--mode", choices=['quick', 'smart', 'deep'], 
                       default='quick', help="Scanning mode (default: quick)")
    parser.add_argument("--output", help="Output file for results (JSON format)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    print("="*60)
    print("[*] SERVICE DISCOVERY TOOL - STANDALONE MODE")
    print("="*60)
    print(f"Target: {args.domain}")
    print(f"Mode: {args.mode.upper()}")
    print(f"Verbose: {'Enabled' if args.verbose else 'Disabled'}")
    print("="*60)
    print()
    
    try:
        # Initialize service discovery
        service_disc = ServiceDiscovery(args.domain)
        
        # Run the scan
        print(f"[*] Starting {args.mode} scan...")
        results = service_disc.discover_services(COMMON_PORTS, args.mode)
        
        print("\n" + "="*60)
        print("[*] SCAN RESULTS SUMMARY")
        print("="*60)
        
        # Display results
        if 'open_ports' in results and results['open_ports']:
            print(f"[+] Found {len(results['open_ports'])} open ports:")
            print()
            
            for port, info in sorted(results['open_ports'].items()):
                service = info.get('service', 'Unknown')
                banner = info.get('banner', 'No banner')
                tool = info.get('tool', 'socket')
                discovered_by = info.get('discovered_by', 'initial_scan')
                
                print(f"  [+] Port {port:>5} - {service:<15} - {banner}")
                if tool != 'socket':
                    print(f"      └─ Discovered by: {tool}")
                if discovered_by != 'initial_scan':
                    print(f"      └─ Method: {discovered_by}")
        else:
            print("[-] No open ports found")
        
        print()
        
        # Display scan statistics
        if 'scan_duration' in results:
            print(f"[*] Scan Duration: {results['scan_duration']} seconds")
        
        if 'ports_scanned' in results:
            print(f"[*] Ports Scanned: {results['ports_scanned']}")
        
        if 'extended_ports_scanned' in results:
            print(f"[*] Extended Ports: {results['extended_ports_scanned']}")
        
        if 'total_ports_scanned' in results:
            print(f"[*] Total Ports: {results['total_ports_scanned']}")
        
        # Display tool information for deep scans
        if 'scan_details' in results and 'tool' in results['scan_details']:
            tool_used = results['scan_details']['tool']
            print(f"[*] Tool Used: {tool_used}")
        
        print("\n" + "="*60)
        
        # Save results to file if specified
        if args.output:
            try:
                with open(args.output, 'w') as f:
                    json.dump({
                        'target': args.domain,
                        'scan_mode': args.mode,
                        'results': results,
                        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
                    }, f, indent=2)
                print(f"[*] Results saved to: {args.output}")
            except Exception as e:
                logging.error(f"Failed to save results: {e}")
        
        print("[+] Scan completed successfully!")
        
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        logging.info("Scan interrupted by user")
    except Exception as e:
        print(f"\n[-] Scan failed: {e}")
        logging.error(f"Scan failed: {e}")
        sys.exit(1)