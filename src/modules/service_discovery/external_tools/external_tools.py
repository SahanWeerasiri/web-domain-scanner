#!/usr/bin/env python3
"""
External Tools Integration Module for Service Discovery

This module provides integration with external scanning tools like nmap and rustscan
for comprehensive port scanning and service detection capabilities.

Author: Web Domain Scanner Project
License: See LICENSE file in project root
"""

import subprocess
import logging
import time
import json
import re
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Tuple, Any

# Import base utilities
try:
    from ..base import (
        ServiceDiscoveryErrorHandler, PortRange
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
            ServiceDiscoveryErrorHandler, PortRange
        )
        from config import ServiceDiscoveryConfig
    except ImportError:
        # Last resort fallback
        print("Error: Could not import required modules. Please run from the service_discovery directory or ensure the module is properly installed.")
        sys.exit(1)

logger = logging.getLogger(__name__)


class ExternalToolsManager:
    """
    Manager for external scanning tools integration.
    """
    
    def __init__(self, config: Optional[ServiceDiscoveryConfig] = None):
        """
        Initialize external tools manager.
        
        Args:
            config (ServiceDiscoveryConfig): Configuration object
        """
        self.config = config or ServiceDiscoveryConfig()
        self.error_handler = ServiceDiscoveryErrorHandler()
        
        # Check tool availability
        self.tool_availability = {
            'nmap': self._check_tool_availability('nmap'),
            'rustscan': self._check_tool_availability('rustscan'),
            'masscan': self._check_tool_availability('masscan')
        }
        
        logger.info(f"External tools availability: {self.tool_availability}")
    
    def scan_with_external_tools(self, target_ip: str, scan_mode: str = 'deep', tool_choice: str = None) -> Dict:
        """
        Perform scanning using external tools.
        
        Args:
            target_ip (str): Target IP address
            scan_mode (str): Scanning mode
            tool_choice (str): Specific tool to use (optional)
            
        Returns:
            Dict: Scan results from external tools
        """
        logger.info(f"Starting external tools scan of {target_ip} in {scan_mode} mode")
        
        results = {
            'target_ip': target_ip,
            'scan_mode': scan_mode,
            'tools_used': [],
            'open_ports': {},
            'scan_details': {},
            'errors': []
        }
        
        # Choose best available tool
        if tool_choice and tool_choice != 'auto':
            # Use specific tool if requested and available
            if tool_choice == 'rustscan' and self.tool_availability['rustscan']:
                rustscan_result = self._run_rustscan(target_ip, scan_mode)
                if rustscan_result:
                    results.update(rustscan_result)
                    results['tools_used'].append('rustscan')
            elif tool_choice == 'nmap' and self.tool_availability['nmap']:
                nmap_result = self._run_nmap(target_ip, scan_mode)
                if nmap_result:
                    results.update(nmap_result)
                    results['tools_used'].append('nmap')
            elif tool_choice == 'masscan' and self.tool_availability['masscan']:
                masscan_result = self._run_masscan(target_ip, scan_mode)
                if masscan_result:
                    results.update(masscan_result)
                    results['tools_used'].append('masscan')
            else:
                logger.warning(f"Requested tool '{tool_choice}' is not available")
                results['errors'].append(f"Requested tool '{tool_choice}' is not available")
        elif self.config.prefer_rustscan and self.tool_availability['rustscan']:
            rustscan_result = self._run_rustscan(target_ip, scan_mode)
            if rustscan_result:
                results.update(rustscan_result)
                results['tools_used'].append('rustscan')
        elif self.tool_availability['nmap']:
            nmap_result = self._run_nmap(target_ip, scan_mode)
            if nmap_result:
                results.update(nmap_result)
                results['tools_used'].append('nmap')
        elif self.tool_availability['masscan']:
            masscan_result = self._run_masscan(target_ip, scan_mode)
            if masscan_result:
                results.update(masscan_result)
                results['tools_used'].append('masscan')
        else:
            logger.warning("No external tools available for scanning")
            results['errors'].append("No external scanning tools available")
        
        return results
    
    def _run_rustscan(self, target_ip: str, scan_mode: str) -> Optional[Dict]:
        """
        Run rustscan for port discovery.
        
        Args:
            target_ip (str): Target IP address
            scan_mode (str): Scanning mode
            
        Returns:
            Optional[Dict]: Rustscan results
        """
        logger.info("Running rustscan for port discovery")
        
        try:
            # Build rustscan command based on scan mode
            cmd = self._build_rustscan_command(target_ip, scan_mode)
            
            logger.debug(f"Executing rustscan command: {' '.join(cmd)}")
            
            start_time = time.time()
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=self.config.rustscan_timeout
            )
            scan_duration = time.time() - start_time
            
            if result.returncode == 0:
                parsed_results = self._parse_rustscan_output(result.stdout)
                parsed_results['scan_details'] = {
                    'tool': 'rustscan',
                    'duration': round(scan_duration, 2),
                    'command': ' '.join(cmd),
                    'raw_output': result.stdout
                }
                
                logger.info(f"Rustscan completed in {scan_duration:.2f}s - Found {len(parsed_results.get('open_ports', {}))} open ports")
                return parsed_results
            else:
                logger.error(f"Rustscan failed with return code {result.returncode}")
                logger.error(f"Error output: {result.stderr}")
                return None
                
        except subprocess.TimeoutExpired:
            logger.error(f"Rustscan timed out after {self.config.rustscan_timeout} seconds")
            self.error_handler.handle_error('rustscan', Exception("Timeout"), target_ip)
            return None
        except Exception as e:
            logger.error(f"Error running rustscan: {e}")
            self.error_handler.handle_error('rustscan', e, target_ip)
            return None
    
    def _run_nmap(self, target_ip: str, scan_mode: str) -> Optional[Dict]:
        """
        Run nmap for comprehensive scanning.
        
        Args:
            target_ip (str): Target IP address
            scan_mode (str): Scanning mode
            
        Returns:
            Optional[Dict]: Nmap results
        """
        logger.info("Running nmap for comprehensive scanning")
        
        try:
            # Build nmap command based on scan mode
            cmd = self._build_nmap_command(target_ip, scan_mode)
            
            logger.debug(f"Executing nmap command: {' '.join(cmd)}")
            
            start_time = time.time()
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=self.config.nmap_timeout
            )
            scan_duration = time.time() - start_time
            
            if result.returncode == 0:
                parsed_results = self._parse_nmap_output(result.stdout)
                parsed_results['scan_details'] = {
                    'tool': 'nmap',
                    'duration': round(scan_duration, 2),
                    'command': ' '.join(cmd),
                    'raw_output': result.stdout
                }
                
                logger.info(f"Nmap completed in {scan_duration:.2f}s - Found {len(parsed_results.get('open_ports', {}))} open ports")
                return parsed_results
            else:
                logger.error(f"Nmap failed with return code {result.returncode}")
                logger.error(f"Error output: {result.stderr}")
                return None
                
        except subprocess.TimeoutExpired:
            logger.error(f"Nmap timed out after {self.config.nmap_timeout} seconds")
            self.error_handler.handle_error('nmap', Exception("Timeout"), target_ip)
            return None
        except Exception as e:
            logger.error(f"Error running nmap: {e}")
            self.error_handler.handle_error('nmap', e, target_ip)
            return None
    
    def _run_masscan(self, target_ip: str, scan_mode: str) -> Optional[Dict]:
        """
        Run masscan for high-speed port scanning.
        
        Args:
            target_ip (str): Target IP address
            scan_mode (str): Scanning mode
            
        Returns:
            Optional[Dict]: Masscan results
        """
        logger.info("Running masscan for high-speed port scanning")
        
        try:
            # Build masscan command
            cmd = self._build_masscan_command(target_ip, scan_mode)
            
            logger.debug(f"Executing masscan command: {' '.join(cmd)}")
            
            start_time = time.time()
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=300  # Masscan is typically fast
            )
            scan_duration = time.time() - start_time
            
            if result.returncode == 0:
                parsed_results = self._parse_masscan_output(result.stdout)
                parsed_results['scan_details'] = {
                    'tool': 'masscan',
                    'duration': round(scan_duration, 2),
                    'command': ' '.join(cmd),
                    'raw_output': result.stdout
                }
                
                logger.info(f"Masscan completed in {scan_duration:.2f}s - Found {len(parsed_results.get('open_ports', {}))} open ports")
                return parsed_results
            else:
                logger.error(f"Masscan failed with return code {result.returncode}")
                logger.error(f"Error output: {result.stderr}")
                return None
                
        except subprocess.TimeoutExpired:
            logger.error("Masscan timed out after 300 seconds")
            self.error_handler.handle_error('masscan', Exception("Timeout"), target_ip)
            return None
        except Exception as e:
            logger.error(f"Error running masscan: {e}")
            self.error_handler.handle_error('masscan', e, target_ip)
            return None
    
    def _build_rustscan_command(self, target_ip: str, scan_mode: str) -> List[str]:
        """
        Build rustscan command based on scan mode.
        
        Args:
            target_ip (str): Target IP address
            scan_mode (str): Scanning mode
            
        Returns:
            List[str]: Command arguments
        """
        cmd = ['rustscan', '-a', target_ip]
        
        if scan_mode == 'quick':
            cmd.extend(['--ulimit', '1000', '--timeout', '1000'])
        elif scan_mode == 'smart':
            cmd.extend(['--ulimit', '3000', '--timeout', '2000'])
        elif scan_mode == 'deep':
            cmd.extend(['--ulimit', '5000', '--timeout', '3000'])
            cmd.extend(['--range', '1-65535'])
        
        # Add output format
        cmd.extend(['--greppable'])
        
        return cmd
    
    def _build_nmap_command(self, target_ip: str, scan_mode: str) -> List[str]:
        """
        Build nmap command based on scan mode.
        
        Args:
            target_ip (str): Target IP address
            scan_mode (str): Scanning mode
            
        Returns:
            List[str]: Command arguments
        """
        cmd = ['nmap']
        
        if scan_mode == 'quick':
            cmd.extend(['-F', '--top-ports', '100'])  # Fast scan of top 100 ports
        elif scan_mode == 'smart':
            cmd.extend(['--top-ports', '1000', '-sV'])  # Top 1000 ports with version detection
        elif scan_mode == 'deep':
            cmd.extend(['-p-', '-sV', '-sC', '-O'])  # Full port range with scripts and OS detection
        
        # Common options
        cmd.extend(['-T4', '--open'])  # Aggressive timing, only show open ports
        cmd.append(target_ip)
        
        return cmd
    
    def _build_masscan_command(self, target_ip: str, scan_mode: str) -> List[str]:
        """
        Build masscan command based on scan mode.
        
        Args:
            target_ip (str): Target IP address
            scan_mode (str): Scanning mode
            
        Returns:
            List[str]: Command arguments
        """
        cmd = ['masscan']
        
        if scan_mode == 'quick':
            cmd.extend(['-p', '1-1000'])  # First 1000 ports
            cmd.extend(['--rate', '1000'])
        elif scan_mode == 'smart':
            cmd.extend(['-p', '1-10000'])  # First 10000 ports
            cmd.extend(['--rate', '2000'])
        elif scan_mode == 'deep':
            cmd.extend(['-p', '1-65535'])  # All ports
            cmd.extend(['--rate', '5000'])
        
        cmd.append(target_ip)
        
        return cmd
    
    def _parse_rustscan_output(self, output: str) -> Dict:
        """
        Parse rustscan output.
        
        Args:
            output (str): Raw rustscan output
            
        Returns:
            Dict: Parsed results
        """
        open_ports = {}
        
        # Rustscan typically outputs in format: "Open IP:PORT"
        for line in output.split('\n'):
            line = line.strip()
            
            # Look for open port indicators
            if 'Open' in line or '->' in line:
                try:
                    # Extract port information
                    if '->' in line:
                        port_info = line.split('->')[1].strip()
                        if '/' in port_info:
                            port = int(port_info.split('/')[0])
                        else:
                            port = int(port_info)
                    else:
                        # Look for port numbers in the line
                        port_match = re.search(r':(\d+)', line)
                        if port_match:
                            port = int(port_match.group(1))
                        else:
                            continue
                    
                    service = PortRange.COMMON_PORTS.get(port, 'Unknown')
                    
                    open_ports[port] = {
                        'service': service,
                        'state': 'open',
                        'banner': 'Detected by rustscan',
                        'tool': 'rustscan'
                    }
                    
                except (ValueError, IndexError) as e:
                    logger.debug(f"Error parsing rustscan line '{line}': {e}")
                    continue
        
        return {'open_ports': open_ports}
    
    def _parse_nmap_output(self, output: str) -> Dict:
        """
        Parse nmap output.
        
        Args:
            output (str): Raw nmap output
            
        Returns:
            Dict: Parsed results
        """
        open_ports = {}
        additional_info = {}
        
        lines = output.split('\n')
        for line in lines:
            line = line.strip()
            
            # Parse open ports
            if '/tcp' in line and 'open' in line:
                try:
                    parts = line.split()
                    if len(parts) >= 3:
                        port_protocol = parts[0]
                        port = int(port_protocol.split('/')[0])
                        state = parts[1]
                        service = parts[2] if len(parts) > 2 else 'unknown'
                        
                        if state == 'open':
                            # Look for version information
                            version_info = ''
                            if len(parts) > 3:
                                version_info = ' '.join(parts[3:])
                            
                            open_ports[port] = {
                                'service': service,
                                'state': 'open',
                                'banner': f'Nmap detected: {service}' + (f' {version_info}' if version_info else ''),
                                'tool': 'nmap'
                            }
                            
                            if version_info:
                                open_ports[port]['version_info'] = version_info
                                
                except (ValueError, IndexError) as e:
                    logger.debug(f"Error parsing nmap line '{line}': {e}")
                    continue
            
            # Extract additional information
            elif 'OS:' in line:
                additional_info['os_detection'] = line
            elif 'Service Info:' in line:
                additional_info['service_info'] = line
        
        result = {'open_ports': open_ports}
        if additional_info:
            result['additional_info'] = additional_info
        
        return result
    
    def _parse_masscan_output(self, output: str) -> Dict:
        """
        Parse masscan output.
        
        Args:
            output (str): Raw masscan output
            
        Returns:
            Dict: Parsed results
        """
        open_ports = {}
        
        # Masscan output format: "Discovered open port PORT/tcp on IP"
        for line in output.split('\n'):
            line = line.strip()
            
            if 'Discovered open port' in line:
                try:
                    # Extract port from format like "443/tcp"
                    match = re.search(r'port (\d+)/(tcp|udp)', line)
                    if match:
                        port = int(match.group(1))
                        protocol = match.group(2)
                        
                        service = PortRange.COMMON_PORTS.get(port, 'Unknown')
                        
                        open_ports[port] = {
                            'service': service,
                            'state': 'open',
                            'protocol': protocol,
                            'banner': 'Detected by masscan',
                            'tool': 'masscan'
                        }
                        
                except (ValueError, IndexError) as e:
                    logger.debug(f"Error parsing masscan line '{line}': {e}")
                    continue
        
        return {'open_ports': open_ports}
    
    def _check_tool_availability(self, tool_name: str) -> bool:
        """
        Check if external tool is available.
        
        Args:
            tool_name (str): Name of the tool to check
            
        Returns:
            bool: True if tool is available, False otherwise
        """
        try:
            # Try to run the tool with version flag
            version_flags = {
                'nmap': '--version',
                'rustscan': '--version',
                'masscan': '--version'
            }
            
            flag = version_flags.get(tool_name, '--version')
            result = subprocess.run(
                [tool_name, flag], 
                capture_output=True, 
                text=True, 
                timeout=10
            )
            
            available = result.returncode == 0
            if available:
                logger.debug(f"External tool {tool_name} is available")
            else:
                logger.debug(f"External tool {tool_name} is not available")
            
            return available
            
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
            logger.debug(f"External tool {tool_name} is not available")
            return False
    
    def get_available_tools(self) -> List[str]:
        """
        Get list of available external tools.
        
        Returns:
            List[str]: List of available tool names
        """
        return [tool for tool, available in self.tool_availability.items() if available]
    
    def is_tool_available(self, tool_name: str) -> bool:
        """
        Check if specific tool is available.
        
        Args:
            tool_name (str): Tool name to check
            
        Returns:
            bool: True if tool is available
        """
        return self.tool_availability.get(tool_name, False)
    
    def get_tool_info(self) -> Dict:
        """
        Get detailed information about tool availability.
        
        Returns:
            Dict: Tool availability and configuration information
        """
        return {
            'availability': self.tool_availability.copy(),
            'preferred_tool': self._get_preferred_tool(),
            'configuration': {
                'prefer_rustscan': self.config.prefer_rustscan,
                'rustscan_timeout': self.config.rustscan_timeout,
                'nmap_timeout': self.config.nmap_timeout
            }
        }
    
    def _get_preferred_tool(self) -> Optional[str]:
        """Get the preferred tool based on availability and configuration."""
        if self.config.prefer_rustscan and self.tool_availability['rustscan']:
            return 'rustscan'
        elif self.tool_availability['nmap']:
            return 'nmap'
        elif self.tool_availability['masscan']:
            return 'masscan'
        else:
            return None
    
    def get_errors(self) -> Dict:
        """Get errors from external tools operations."""
        return self.error_handler.get_errors()


class NmapScriptEngine:
    """
    Advanced nmap script engine integration for detailed service analysis.
    """
    
    def __init__(self, config: Optional[ServiceDiscoveryConfig] = None):
        """
        Initialize nmap script engine.
        
        Args:
            config (ServiceDiscoveryConfig): Configuration object
        """
        self.config = config or ServiceDiscoveryConfig()
        self.error_handler = ServiceDiscoveryErrorHandler()
        
    def run_nmap_scripts(self, target_ip: str, ports: List[int], script_categories: List[str] = None) -> Dict:
        """
        Run nmap scripts against specific ports.
        
        Args:
            target_ip (str): Target IP address
            ports (List[int]): List of ports to scan
            script_categories (List[str]): Script categories to run
            
        Returns:
            Dict: Script execution results
        """
        if not script_categories:
            script_categories = ['default', 'safe']
        
        logger.info(f"Running nmap scripts against {target_ip} ports {ports}")
        
        try:
            # Build nmap script command
            port_spec = ','.join(map(str, ports))
            script_spec = ','.join(script_categories)
            
            cmd = [
                'nmap', '-p', port_spec, '--script', script_spec,
                '--script-args', 'safe=1', target_ip
            ]
            
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=300
            )
            
            if result.returncode == 0:
                return self._parse_nmap_script_output(result.stdout)
            else:
                logger.error(f"Nmap script execution failed: {result.stderr}")
                return {}
                
        except Exception as e:
            logger.error(f"Error running nmap scripts: {e}")
            self.error_handler.handle_error('nmap_scripts', e, target_ip)
            return {}
    
    def _parse_nmap_script_output(self, output: str) -> Dict:
        """Parse nmap script output."""
        # This would parse nmap script output
        # Implementation depends on specific script output formats
        return {'script_results': output}
    
    def get_errors(self) -> Dict:
        """Get script engine errors."""
        return self.error_handler.get_errors()


def main():
    """
    Standalone main function for external tools module.
    Usage: python external_tools.py <target> [--tool <tool>] [--mode <mode>]
    """
    import argparse
    import json
    import sys
    import time
    
    # Set up argument parser
    parser = argparse.ArgumentParser(
        description="Service Discovery - External Tools Module",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python external_tools.py example.com
  python external_tools.py 192.168.1.1 --tool nmap --mode deep
  python external_tools.py example.com --tool rustscan --output results.json
  python external_tools.py 192.168.1.1 --check-tools
        """
    )
    
    parser.add_argument(
        'target',
        nargs='?',
        help='Target IP address or hostname'
    )
    
    parser.add_argument(
        '--tool',
        choices=['nmap', 'rustscan', 'masscan', 'auto'],
        default='auto',
        help='External tool to use (default: auto)'
    )
    
    parser.add_argument(
        '--mode',
        choices=['quick', 'smart', 'deep'],
        default='smart',
        help='Scanning mode (default: smart)'
    )
    
    parser.add_argument(
        '--check-tools',
        action='store_true',
        help='Check availability of external tools and exit'
    )
    
    parser.add_argument(
        '--scripts',
        action='store_true',
        help='Run nmap scripts (requires nmap and open ports)'
    )
    
    parser.add_argument(
        '--timeout',
        type=int,
        default=300,
        help='Scan timeout in seconds (default: 300)'
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
    
    try:
        # Import required classes
        try:
            from ..config import ServiceDiscoveryConfig
            from ..base import PortRange
        except ImportError:
            # Fallback for direct execution - add parent directory to path
            import sys
            import os
            parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            sys.path.insert(0, parent_dir)
            
            try:
                from config import ServiceDiscoveryConfig
                from base import PortRange
            except ImportError:
                print("Error: Could not import required modules. Please run from the service_discovery directory.")
                sys.exit(1)
        
        # Create configuration
        config = ServiceDiscoveryConfig()
        config.nmap_timeout = args.timeout
        config.rustscan_timeout = args.timeout
        
        # Initialize external tools manager
        tools_manager = ExternalToolsManager(config)
        
        if args.check_tools:
            # Check tool availability mode
            print(f"{'='*60}")
            print("      EXTERNAL TOOLS AVAILABILITY CHECK")
            print(f"{'='*60}")
            
            tool_info = tools_manager.get_tool_info()
            availability = tool_info['availability']
            
            print(f"\n🔍 Tool Availability:")
            for tool, available in availability.items():
                status = "✅ Available" if available else "❌ Not Available"
                print(f"  {tool.title()}: {status}")
            
            available_tools = tools_manager.get_available_tools()
            if available_tools:
                print(f"\n✅ Available Tools: {', '.join(available_tools)}")
                preferred = tool_info.get('preferred_tool')
                if preferred:
                    print(f"🎯 Preferred Tool: {preferred}")
            else:
                print(f"\n❌ No external tools available")
            
            print(f"\n📋 Configuration:")
            config_info = tool_info['configuration']
            for key, value in config_info.items():
                print(f"  {key}: {value}")
            
            sys.exit(0)
        
        if not args.target:
            print("Error: Target is required unless using --check-tools")
            parser.print_help()
            sys.exit(1)
        
        print(f"{'='*60}")
        print("      SERVICE DISCOVERY - EXTERNAL TOOLS MODULE")
        print(f"{'='*60}")
        print(f"Target: {args.target}")
        print(f"Tool: {args.tool}")
        print(f"Mode: {args.mode}")
        print(f"Scripts: {'Yes' if args.scripts else 'No'}")
        print(f"Timeout: {args.timeout}s")
        print(f"{'='*60}")
        
        # Check tool availability first
        available_tools = tools_manager.get_available_tools()
        if not available_tools:
            print(f"\n❌ No external tools available!")
            print(f"   Please install nmap, rustscan, or masscan")
            sys.exit(1)
        
        start_time = time.time()
        
        # Perform scan
        print(f"\n🔍 Starting external tool scan...")
        if args.tool == 'auto':
            print(f"   Using automatic tool selection")
        else:
            print(f"   Using {args.tool}")
        
        results = tools_manager.scan_with_external_tools(args.target, args.mode, args.tool if args.tool != 'auto' else None)
        
        elapsed_time = time.time() - start_time
        
        # Display results
        print(f"\n{'='*50}")
        print("              SCAN RESULTS")
        print(f"{'='*50}")
        
        if results:
            open_ports = results.get('open_ports', {})
            scan_details = results.get('scan_details', {})
            tool_used = scan_details.get('tool', 'Unknown')
            
            print(f"\n✅ Tool Used: {tool_used.title()}")
            
            if open_ports:
                print(f"✅ Open Ports Found: {len(open_ports)}")
                for port, port_info in open_ports.items():
                    service = port_info.get('service', 'Unknown')
                    state = port_info.get('state', 'open')
                    banner = port_info.get('banner', '')
                    tool = port_info.get('tool', tool_used)
                    
                    print(f"  📡 Port {port}/tcp - {service} ({state})")
                    if banner and banner != 'No banner':
                        banner_preview = banner[:60] + '...' if len(banner) > 60 else banner
                        print(f"     Info: {banner_preview}")
                    print(f"     Detected by: {tool}")
                    
                    # Show version info if available
                    version_info = port_info.get('version_info')
                    if version_info:
                        print(f"     Version: {version_info}")
            else:
                print(f"\n❌ No open ports found")
            
            # Show additional information
            additional_info = results.get('additional_info', {})
            if additional_info:
                print(f"\n📋 Additional Information:")
                for key, value in additional_info.items():
                    print(f"  {key.replace('_', ' ').title()}: {value}")
            
            # Run nmap scripts if requested and ports are found
            if args.scripts and open_ports and tools_manager.is_tool_available('nmap'):
                print(f"\n🔧 Running nmap scripts...")
                script_engine = NmapScriptEngine(config)
                script_results = script_engine.run_nmap_scripts(
                    args.target, 
                    list(open_ports.keys()),
                    ['default', 'safe']
                )
                
                if script_results:
                    print(f"✅ Nmap scripts completed")
                    # Add script results to main results
                    results['script_results'] = script_results
                else:
                    print(f"❌ Nmap scripts failed or returned no results")
            
            # Display scan statistics
            print(f"\n{'='*50}")
            print("            SCAN STATISTICS")
            print(f"{'='*50}")
            
            print(f"  Tool Used: {tool_used.title()}")
            print(f"  Open Ports Found: {len(open_ports)}")
            print(f"  Scan Duration: {elapsed_time:.2f} seconds")
            print(f"  Scan Mode: {args.mode}")
            
            if scan_details:
                tool_duration = scan_details.get('duration')
                if tool_duration:
                    print(f"  Tool Execution Time: {tool_duration} seconds")
                
                command = scan_details.get('command')
                if command and args.verbose:
                    print(f"  Command Executed: {command}")
        else:
            print(f"\n❌ External tool scan failed or returned no results")
            tool_used = 'Unknown'
        
        # Show errors if any
        errors = tools_manager.get_errors()
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
        
        # Prepare final results
        final_results = {
            'target': args.target,
            'tool_used': tool_used,
            'scan_mode': args.mode,
            'results': results,
            'available_tools': available_tools,
            'scan_duration': elapsed_time
        }
        
        # Save results if output file specified
        if args.output:
            try:
                with open(args.output, 'w') as f:
                    json.dump(final_results, f, indent=2, default=str)
                
                print(f"\n💾 Results saved to: {args.output}")
            except Exception as e:
                print(f"❌ Error saving results: {e}")
        
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        logging.info("External tools scan interrupted by user")
    except Exception as e:
        print(f"\n[-] Scan failed: {e}")
        logging.error(f"External tools scan failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()