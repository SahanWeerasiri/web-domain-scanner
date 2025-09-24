#!/usr/bin/env python3
"""
Simplified NMAP Port Scanner
"""

import subprocess
import sys
import argparse
from typing import Optional

class SimplePortScanner:
    def __init__(self, target: str):
        self.target = target
    
    def quick(self, custom_ports: Optional[str] = None) -> str:
        """Quick scan - top 100 ports"""
        ports = custom_ports if custom_ports else "--top-ports 100"
        cmd = f"nmap -T4 -sS -Pn --open {ports} {self.target}"
        return self._run_scan(cmd)
    
    def smart(self, custom_ports: Optional[str] = None) -> str:
        """Smart scan - top 1000 ports with service detection"""
        ports = custom_ports if custom_ports else "--top-ports 1000"
        cmd = f"nmap -T4 -sS -sV -O --script default -Pn --open {ports} {self.target}"
        return self._run_scan(cmd)
    
    def deep(self, custom_ports: Optional[str] = None) -> str:
        """Deep scan - all ports comprehensive"""
        ports = f"-p {custom_ports}" if custom_ports else "-p-"
        cmd = f"nmap -T4 -sS -sV -sC -O --script vuln -Pn --open --reason {ports} {self.target}"
        return self._run_scan(cmd)
    
    def _run_scan(self, cmd: str) -> str:
        """Execute nmap command"""
        try:
            print(f"Running: {cmd}")
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=1800)
            return result.stdout if result.returncode == 0 else f"Error: {result.stderr}"
        except Exception as e:
            return f"Exception: {str(e)}"

def scan_target(method: str, target: str, custom_ports: Optional[str] = None) -> str:
    """Function to run scans without command line arguments"""
    scanner = SimplePortScanner(target)
    
    if method == "quick":
        return scanner.quick(custom_ports)
    elif method == "smart":
        return scanner.smart(custom_ports)
    elif method == "deep":
        return scanner.deep(custom_ports)
    else:
        return "Error: Unknown method. Use 'quick', 'smart', or 'deep'."

def main():
    """Command line interface"""
    parser = argparse.ArgumentParser(description="Simple Port Scanner")
    parser.add_argument("target", help="Target to scan")
    parser.add_argument("method", choices=["quick", "smart", "deep"], help="Scan method")
    parser.add_argument("-p", "--ports", help="Custom ports")
    
    args = parser.parse_args()
    
    result = scan_target(args.method, args.target, args.ports)
    print(result)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        main()
    else:
        # Demo
        print("Demo: Quick scan of scanme.nmap.org")
        print(scan_target("quick", "scanme.nmap.org"))