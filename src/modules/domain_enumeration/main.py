#!/usr/bin/env python3
"""
Main Domain Enumeration Module

This module orchestrates all domain enumeration techniques including:
- Passive enumeration (Certificate Transparency, SSL certificates)
- Active enumeration (Brute force, DNS permutations, zone transfers)
- DNS record enumeration (A, AAAA, MX, NS, TXT, CNAME, SOA)
- Web fingerprinting (Technology detection, security analysis)
"""

import sys
import os
import argparse
import logging
import json
import time
import threading
from typing import Dict, List, Set, Any, Optional
from datetime import datetime

# Add parent directories to path for imports
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(current_dir)
sys.path.append(os.path.join(current_dir, 'passive'))
sys.path.append(os.path.join(current_dir, 'active'))
sys.path.append(os.path.join(current_dir, 'dns_enumeration_module'))
sys.path.append(os.path.join(current_dir, 'web_fingerprinting'))

# Import execute functions from each module
try:
    from passive.passive_enumeration import execute_passive_enumeration
    PASSIVE_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Passive enumeration not available: {e}")
    PASSIVE_AVAILABLE = False

try:
    from active.active_enumeration import execute_active_enumeration
    ACTIVE_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Active enumeration not available: {e}")
    ACTIVE_AVAILABLE = False

try:
    from dns_enumeration_module.dns_enumeration import execute_dns_enumeration
    DNS_AVAILABLE = True
except ImportError as e:
    print(f"Warning: DNS enumeration not available: {e}")
    DNS_AVAILABLE = False

try:
    from web_fingerprinting.web_fingerprinting import execute_fingerprinting
    FINGERPRINTING_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Web fingerprinting not available: {e}")
    FINGERPRINTING_AVAILABLE = False

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class DomainEnumerationConfig:
    """Comprehensive configuration for all enumeration methods"""
    
    def __init__(self):
        # Global settings
        self.domain = None
        self.verbose = False
        self.output_file = None
        self.enabled_modules = ['passive', 'active', 'dns', 'fingerprinting']
        
        # Passive enumeration configuration
        self.passive_config = {
            'sources': ['certificate_transparency'],
            'ct_sources': ['crt_sh'],
            'concurrent_requests': 5,
            'request_delay': 0.5,
            'timeout': 10,
            'verbose': False
        }
        
        # Active enumeration configuration
        self.active_config = {
            'threads': 10,
            'rate_limit': 10,
            'timeout': 5,
            'bruteforce_retries': 2,
            'permutation_depth': 3,
            'dns_servers': None,
            'methods': ['bruteforce', 'dns_permutations', 'zone_transfer', 'cache_snooping'],
            'wordlist_file': None,
            'enable_ai': True
        }
        
        # DNS enumeration configuration
        self.dns_config = {
            'dns_servers': None,
            'timeout': 5,
            'retries': 2,
            'record_types': ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA'],
            'include_parent_domain': True,
            'perform_analysis': True,
            'query_additional_records': False,
            'verbose': False,
            'txt_analysis_depth': 'basic'
        }
        
        # Web fingerprinting configuration
        self.fingerprinting_config = {
            'targets': None,
            'include_http': False,
            'include_www': False,
            'detection_methods': ['headers', 'content', 'url_patterns', 'wappalyzer'],
            'disable_wappalyzer': False,
            'disable_ai': False,
            'disable_security': False,
            'timeout': 30,
            'concurrent': 3,
            'verbose': False,
            'output_format': 'detailed'
        }


class DomainEnumerationOrchestrator:
    """Main orchestrator for domain enumeration"""
    
    def __init__(self, config: DomainEnumerationConfig):
        self.config = config
        self.results = {}
        self.start_time = time.time()
        
    def run_comprehensive_enumeration(self) -> Dict[str, Any]:
        """Execute all enabled enumeration modules in parallel"""
        logger.info(f"Starting comprehensive enumeration for domain: {self.config.domain}")
        
        self.results = {
            'domain': self.config.domain,
            'timestamp': datetime.now().isoformat(),
            'modules': {},
            'summary': {},
            'all_subdomains': set(),
            'statistics': {}
        }
        
        # Thread-safe storage for module results
        module_results = {}
        module_errors = {}
        completed_count = {'value': 0}
        modules_lock = threading.Lock()
        
        # Get enabled and available modules
        enabled_modules = []
        if 'passive' in self.config.enabled_modules and PASSIVE_AVAILABLE:
            enabled_modules.append('passive')
        if 'active' in self.config.enabled_modules and ACTIVE_AVAILABLE:
            enabled_modules.append('active')
        if 'dns' in self.config.enabled_modules and DNS_AVAILABLE:
            enabled_modules.append('dns')
        if 'fingerprinting' in self.config.enabled_modules and FINGERPRINTING_AVAILABLE:
            enabled_modules.append('fingerprinting')
        
        if not enabled_modules:
            logger.warning("No modules are enabled or available")
            return self.results
        
        logger.info(f"Running {len(enabled_modules)} modules in parallel: {', '.join(enabled_modules)}")
        
        # Module execution function
        def execute_module(module_name: str):
            """Execute a single enumeration module in its own thread"""
            logger.info(f"Starting {module_name} enumeration...")
            
            try:
                if module_name == 'passive':
                    result = self._run_passive_enumeration_threaded()
                elif module_name == 'active':
                    result = self._run_active_enumeration_threaded()
                elif module_name == 'dns':
                    result = self._run_dns_enumeration_threaded()
                elif module_name == 'fingerprinting':
                    result = self._run_fingerprinting_threaded()
                
                # Store successful result thread-safely
                with modules_lock:
                    module_results[module_name] = result
                    completed_count['value'] += 1
                    
                logger.info(f"Completed {module_name} enumeration ({completed_count['value']}/{len(enabled_modules)})")
                
            except Exception as e:
                logger.error(f"{module_name} enumeration failed: {str(e)}")
                
                # Store error result thread-safely
                with modules_lock:
                    module_errors[module_name] = str(e)
                    module_results[module_name] = {
                        'status': 'failed',
                        'error': str(e),
                        'subdomains': [],
                        'statistics': {'total_duration': 0}
                    }
                    completed_count['value'] += 1
        
        # Start all modules in parallel threads
        module_threads = []
        for module_name in enabled_modules:
            thread = threading.Thread(target=execute_module, args=(module_name,))
            thread.daemon = True
            thread.start()
            module_threads.append((module_name, thread))
        
        # Wait for all modules to complete
        for module_name, thread in module_threads:
            thread.join()  # Wait for this module to finish
            logger.info(f"Thread for {module_name} completed")
        
        # Compile results from all modules
        for module_name, result in module_results.items():
            if result and result.get('status') != 'failed':
                self.results['modules'][module_name] = result
                
                # Extract subdomains thread-safely
                if 'subdomains' in result:
                    self.results['all_subdomains'].update(result['subdomains'])
        
        # Compile final results
        self._compile_final_results()
        
        logger.info(f"Parallel enumeration completed. Total subdomains found: {len(self.results['all_subdomains'])}")
        
        return self.results
    
    def _compile_final_results(self):
        """Compile comprehensive final results and statistics"""
        # Convert set to sorted list
        self.results['all_subdomains'] = sorted(list(self.results['all_subdomains']))
        
        # Calculate comprehensive statistics
        total_time = time.time() - self.start_time
        total_certificates = 0
        total_technologies = 0
        total_dns_records = 0
        total_security_issues = 0
        total_queries = 0
        total_http_requests = 0
        
        # Extract detailed metrics from each module
        if 'passive' in self.results['modules']:
            passive_stats = self.results['modules']['passive'].get('statistics', {})
            total_certificates = passive_stats.get('certificates_analyzed', 0)
        
        if 'active' in self.results['modules']:
            active_stats = self.results['modules']['active'].get('statistics', {})
            total_queries += active_stats.get('queries_attempted', 0)
        
        if 'dns' in self.results['modules']:
            dns_stats = self.results['modules']['dns'].get('statistics', {})
            total_dns_records = dns_stats.get('total_records', 0)
            total_queries += dns_stats.get('queries_performed', 0)
        
        if 'fingerprinting' in self.results['modules']:
            fingerprint_module = self.results['modules']['fingerprinting']
            if 'targets' in fingerprint_module:
                total_technologies = len(fingerprint_module.get('summary', {}).get('unique_technologies', []))
                total_security_issues = len(fingerprint_module.get('summary', {}).get('common_issues', []))
                total_http_requests += len(fingerprint_module.get('targets', {}))
        
        self.results['statistics'] = {
            'total_subdomains': len(self.results['all_subdomains']),
            'unique_subdomains': len(self.results['all_subdomains']),
            'modules_executed': len([m for m in self.results['modules'] if self.results['modules'][m].get('status') != 'failed']),
            'modules_failed': len([m for m in self.results['modules'] if self.results['modules'][m].get('status') == 'failed']),
            'total_execution_time': round(total_time, 2),
            'certificates_analyzed': total_certificates,
            'dns_queries': total_queries,
            'http_requests': total_http_requests,
            'technologies_detected': total_technologies,
            'security_issues_found': total_security_issues,
            'enabled_modules': self.config.enabled_modules
        }
        
        # Create enhanced summary by module
        self.results['summary'] = {}
        for module_name, module_results in self.results['modules'].items():
            if module_results.get('status') != 'failed':
                base_summary = {
                    'status': 'success',
                    'subdomains_found': len(module_results.get('subdomains', [])),
                }
                
                # Add module-specific summary data
                if module_name == 'passive':
                    base_summary.update({
                        'certificates_analyzed': module_results.get('statistics', {}).get('certificates_analyzed', 0),
                        'ct_logs_processed': module_results.get('statistics', {}).get('ct_logs_processed', 0)
                    })
                elif module_name == 'active':
                    base_summary.update({
                        'queries_attempted': module_results.get('statistics', {}).get('queries_attempted', 0),
                        'success_rate': module_results.get('statistics', {}).get('success_rate', 0)
                    })
                elif module_name == 'dns':
                    base_summary.update({
                        'records_found': module_results.get('statistics', {}).get('total_records', 0),
                        'queries_performed': module_results.get('statistics', {}).get('queries_performed', 0)
                    })
                elif module_name == 'fingerprinting':
                    base_summary.update({
                        'targets_analyzed': module_results.get('summary', {}).get('total_targets', 0),
                        'technologies_identified': len(module_results.get('summary', {}).get('unique_technologies', []))
                    })
                
                self.results['summary'][module_name] = base_summary
            else:
                self.results['summary'][module_name] = {
                    'status': 'failed',
                    'error': module_results.get('error', 'Unknown error'),
                    'subdomains_found': 0
                }

    def _run_passive_enumeration_threaded(self):
        """Execute passive enumeration and return results (thread-safe version)"""
        try:
            logger.info("Running passive enumeration...")
            passive_results = execute_passive_enumeration(
                domain=self.config.domain,
                **self.config.passive_config
            )
            
            # Extract comprehensive certificate data (same logic as before)
            certificates = {}
            ct_logs_processed = 0
            
            if 'sources' in passive_results and 'certificate_transparency' in passive_results['sources']:
                ct_data = passive_results['sources']['certificate_transparency']
                if 'crt_sh' in ct_data:
                    crt_sh_data = ct_data['crt_sh']
                    if isinstance(crt_sh_data, dict):
                        if 'certificates' in crt_sh_data:
                            certificates = crt_sh_data['certificates']
                        if 'total_certificates' in crt_sh_data:
                            ct_logs_processed = crt_sh_data['total_certificates']
            
            if not certificates and 'certificates' in passive_results:
                certificates = passive_results['certificates']
            
            # Structure comprehensive passive results
            structured_result = {
                "domain": self.config.domain,
                "timestamp": time.time(),
                "configuration": {
                    "enabled_sources": self.config.passive_config.get('sources', ['certificate_transparency']),
                    "ct_sources": self.config.passive_config.get('ct_sources', ['crt_sh']),
                    "concurrent_requests": self.config.passive_config.get('concurrent_requests', 5),
                    "timeout": self.config.passive_config.get('timeout', 10)
                },
                "sources": passive_results.get('sources', {}),
                "certificates": certificates,
                "subdomains": list(passive_results.get('subdomains', [])),
                "statistics": {
                    "total_duration": passive_results.get('statistics', {}).get('total_duration', 0),
                    "total_subdomains": len(passive_results.get('subdomains', [])),
                    "certificates_analyzed": len(certificates),
                    "ct_logs_processed": ct_logs_processed,
                    "successful_sources": len([s for s in passive_results.get('sources', {}) 
                                             if passive_results['sources'][s].get('success', True)]),
                    "success_rate": passive_results.get('statistics', {}).get('success_rate', 100.0)
                },
                "errors": passive_results.get('errors', {})
            }
            
            logger.info(f"Passive enumeration completed. Found {len(passive_results.get('subdomains', []))} subdomains")
            return structured_result
            
        except Exception as e:
            logger.error(f"Passive enumeration failed: {str(e)}")
            return {
                'status': 'failed',
                'error': str(e),
                'subdomains': [],
                'certificates': {},
                'statistics': {'total_duration': 0, 'total_subdomains': 0, 'certificates_analyzed': 0}
            }

    def _run_active_enumeration_threaded(self):
        """Execute active enumeration and return results (thread-safe version)"""
        try:
            logger.info("Running active enumeration...")
            active_results = execute_active_enumeration(
                domain=self.config.domain,
                **self.config.active_config
            )
            
            # Structure comprehensive active results
            structured_result = {
                "domain": self.config.domain,
                "timestamp": time.time(),
                "configuration": {
                    "enabled_methods": self.config.active_config.get('methods', ['bruteforce', 'dns_permutations', 'zone_transfer', 'cache_snooping']),
                    "thread_count": self.config.active_config.get('threads', 10),
                    "rate_limit": self.config.active_config.get('rate_limit', 10),
                    "timeout": self.config.active_config.get('timeout', 5),
                    "ai_enabled": self.config.active_config.get('enable_ai', True)
                },
                "methods": active_results.get('methods', {}),
                "statistics": {
                    "total_duration": active_results.get('statistics', {}).get('total_duration', 0),
                    "total_subdomains": active_results.get('statistics', {}).get('total_subdomains', 0),
                    "methods_breakdown": active_results.get('statistics', {}).get('methods_breakdown', {}),
                    "queries_attempted": active_results.get('statistics', {}).get('queries_attempted', 0),
                    "success_rate": active_results.get('statistics', {}).get('success_rate', 0),
                    "ai_wordlist_generated": active_results.get('statistics', {}).get('ai_wordlist_generated', 0)
                },
                "errors": active_results.get('errors', {})
            }
            
            # Extract subdomains from all methods for return
            all_subdomains = []
            if 'methods' in active_results:
                for method, method_results in active_results['methods'].items():
                    if isinstance(method_results, list):
                        all_subdomains.extend(method_results)
                    elif isinstance(method_results, dict) and 'subdomains' in method_results:
                        all_subdomains.extend(method_results['subdomains'])
            
            structured_result['subdomains'] = list(set(all_subdomains))  # Remove duplicates
            
            logger.info(f"Active enumeration completed. Found {len(structured_result['subdomains'])} subdomains")
            return structured_result
            
        except Exception as e:
            logger.error(f"Active enumeration failed: {str(e)}")
            return {
                'status': 'failed',
                'error': str(e),
                'methods': {},
                'subdomains': [],
                'statistics': {'total_duration': 0, 'total_subdomains': 0, 'queries_attempted': 0, 'success_rate': 0}
            }

    def _run_dns_enumeration_threaded(self):
        """Execute DNS enumeration and return results (thread-safe version)"""
        try:
            logger.info("Running DNS enumeration...")
            dns_results = execute_dns_enumeration(
                domain=self.config.domain,
                **self.config.dns_config
            )
            
            # Structure comprehensive DNS results
            structured_result = {
                "domain": self.config.domain,
                "timestamp": time.time(),
                "configuration": {
                    "dns_servers": self.config.dns_config.get('dns_servers', ['8.8.8.8', '1.1.1.1']),
                    "timeout": self.config.dns_config.get('timeout', 5),
                    "record_types": self.config.dns_config.get('record_types', ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']),
                    "analysis_enabled": self.config.dns_config.get('perform_analysis', True)
                },
                "dns_records": dns_results.get('dns_records', {}),
                "subdomains": list(dns_results.get('subdomains', [])),
                "analysis": {
                    "infrastructure": dns_results.get('analysis', {}).get('infrastructure', {}),
                    "security_records": dns_results.get('analysis', {}).get('security_records', {}),
                    "txt_analysis": dns_results.get('analysis', {}).get('txt_analysis', {})
                },
                "statistics": {
                    "total_duration": dns_results.get('statistics', {}).get('total_duration', 0),
                    "total_records": dns_results.get('statistics', {}).get('total_records', 0),
                    "total_subdomains": len(dns_results.get('subdomains', [])),
                    "queries_performed": dns_results.get('statistics', {}).get('queries_performed', 0),
                    "successful_queries": dns_results.get('statistics', {}).get('successful_queries', 0),
                    "failed_queries": dns_results.get('statistics', {}).get('failed_queries', 0)
                },
                "errors": dns_results.get('errors', {})
            }
            
            logger.info(f"DNS enumeration completed. Found {len(dns_results.get('subdomains', []))} subdomains")
            return structured_result
            
        except Exception as e:
            logger.error(f"DNS enumeration failed: {str(e)}")
            return {
                'status': 'failed',
                'error': str(e),
                'dns_records': {},
                'subdomains': [],
                'analysis': {},
                'statistics': {'total_duration': 0, 'total_records': 0, 'total_subdomains': 0, 'queries_performed': 0}
            }

    def _run_fingerprinting_threaded(self):
        """Execute web fingerprinting and return results (thread-safe version)"""
        try:
            logger.info("Running web fingerprinting...")
            fingerprinting_results = execute_fingerprinting(
                domain=self.config.domain,
                **self.config.fingerprinting_config
            )
            
            # Structure comprehensive fingerprinting results
            structured_result = {
                "domain": self.config.domain,
                "timestamp": time.time(),
                "configuration": {
                    "detection_methods": self.config.fingerprinting_config.get('detection_methods', ['headers', 'content', 'url_patterns', 'wappalyzer']),
                    "timeout": self.config.fingerprinting_config.get('timeout', 30),
                    "include_www": self.config.fingerprinting_config.get('include_www', False),
                    "security_analysis": not self.config.fingerprinting_config.get('disable_security', False)
                },
                "targets": fingerprinting_results.get('targets', {}),
                "summary": {
                    "total_targets": len(fingerprinting_results.get('targets', {})),
                    "successful_scans": len([t for t in fingerprinting_results.get('targets', {}).values() 
                                           if 'error' not in t]),
                    "unique_technologies": list(set([
                        tech for target in fingerprinting_results.get('targets', {}).values()
                        if 'technology_detection' in target
                        for tech_list in target['technology_detection'].values()
                        if isinstance(tech_list, list)
                        for tech in tech_list
                    ])),
                    "security_score_avg": sum([
                        target.get('security_analysis', {}).get('security_score', 0)
                        for target in fingerprinting_results.get('targets', {}).values()
                        if 'security_analysis' in target
                    ]) / max(len(fingerprinting_results.get('targets', {})), 1),
                    "common_issues": list(set([
                        header for target in fingerprinting_results.get('targets', {}).values()
                        if 'security_analysis' in target and 'missing_headers' in target['security_analysis']
                        for header in target['security_analysis']['missing_headers']
                    ]))
                },
                "statistics": {
                    "total_duration": fingerprinting_results.get('statistics', {}).get('total_duration', 0),
                    "success_rate": fingerprinting_results.get('statistics', {}).get('success_rate', 0)
                },
                "errors": fingerprinting_results.get('errors', {})
            }
            
            # Extract any additional subdomains discovered during fingerprinting
            discovered_subdomains = []
            if 'targets' in fingerprinting_results:
                for target_url in fingerprinting_results['targets'].keys():
                    from urllib.parse import urlparse
                    parsed = urlparse(target_url)
                    if parsed.hostname and parsed.hostname != self.config.domain:
                        discovered_subdomains.append(parsed.hostname)
            
            structured_result['subdomains'] = list(set(discovered_subdomains))
            
            logger.info(f"Web fingerprinting completed. Analyzed {len(fingerprinting_results.get('targets', {}))} targets")
            return structured_result
            
        except Exception as e:
            logger.error(f"Web fingerprinting failed: {str(e)}")
            return {
                'status': 'failed',
                'error': str(e),
                'targets': {},
                'subdomains': [],
                'summary': {'total_targets': 0, 'successful_scans': 0, 'unique_technologies': [], 'security_score_avg': 0},
                'statistics': {'total_duration': 0, 'success_rate': 0}
            }


def display_results(results: Dict[str, Any], verbose: bool = False):
    """Display enumeration results in a formatted manner"""
    
    print("\n" + "="*80)
    print(f"DOMAIN ENUMERATION RESULTS FOR: {results['domain']}")
    print("="*80)
    
    # Display summary statistics
    stats = results.get('statistics', {})
    print(f"\n📊 SUMMARY STATISTICS:")
    print(f"   • Total Subdomains Found: {stats.get('total_subdomains', 0)}")
    print(f"   • Modules Executed: {stats.get('modules_executed', 0)}")
    print(f"   • Modules Failed: {stats.get('modules_failed', 0)}")
    print(f"   • Total Execution Time: {stats.get('total_execution_time', 0)} seconds")
    
    # Display module-wise summary
    print(f"\n🔍 MODULE SUMMARY:")
    summary = results.get('summary', {})
    for module_name, module_summary in summary.items():
        status_icon = "✅" if module_summary['status'] == 'success' else "❌"
        print(f"   {status_icon} {module_name.upper()}: {module_summary['subdomains_found']} subdomains")
        if module_summary['status'] == 'failed':
            print(f"      Error: {module_summary['error']}")
    
    # Display all discovered subdomains
    all_subdomains = results.get('all_subdomains', [])
    if all_subdomains:
        print(f"\n🎯 ALL DISCOVERED SUBDOMAINS ({len(all_subdomains)}):")
        for i, subdomain in enumerate(all_subdomains, 1):
            print(f"   {i:3d}. {subdomain}")
    
    # Display detailed results if verbose
    if verbose:
        print(f"\n📋 DETAILED RESULTS:")
        
        # Passive enumeration details
        if 'passive' in results['modules'] and results['modules']['passive'].get('status') != 'failed':
            passive_results = results['modules']['passive']
            print(f"\n   🔍 PASSIVE ENUMERATION:")
            print(f"      • Certificate Transparency (crt.sh): {len(passive_results.get('subdomains', []))} subdomains from {passive_results.get('statistics', {}).get('certificates_analyzed', 0)} certificates")
            if 'certificates' in passive_results and passive_results['certificates']:
                print(f"      • Certificate Analysis:")
                print(f"        - SHA256 Fingerprints: {len(passive_results['certificates'])} unique certificates analyzed")
                print(f"        - CT Log Entries: {passive_results.get('statistics', {}).get('ct_logs_processed', 0)} CT log entries processed")
            sources = passive_results.get('configuration', {}).get('enabled_sources', ['certificate_transparency'])
            print(f"      • Sources: {', '.join(sources)}")
            print(f"      • Total Duration: {passive_results.get('statistics', {}).get('total_duration', 0):.2f} seconds")
        
        # Active enumeration details  
        if 'active' in results['modules'] and results['modules']['active'].get('status') != 'failed':
            active_results = results['modules']['active']
            print(f"\n   ⚡ ACTIVE ENUMERATION:")
            methods_breakdown = active_results.get('statistics', {}).get('methods_breakdown', {})
            for method, count in methods_breakdown.items():
                method_name = method.replace('_', ' ').title()
                if method == 'bruteforce':
                    success_rate = active_results.get('statistics', {}).get('success_rate', 0)
                    queries = active_results.get('statistics', {}).get('queries_attempted', 0)
                    print(f"      • {method_name}: {count} subdomains discovered ({queries} attempts, {success_rate:.1f}% success rate)")
                else:
                    print(f"      • {method_name}: {count} subdomains")
            
            ai_wordlist = active_results.get('statistics', {}).get('ai_wordlist_generated', 0)
            if ai_wordlist > 0:
                print(f"      • AI-Enhanced Wordlist: Generated {ai_wordlist} context-aware subdomains")
            print(f"      • Total Duration: {active_results.get('statistics', {}).get('total_duration', 0):.2f} seconds")
        
        # DNS enumeration details
        if 'dns' in results['modules'] and results['modules']['dns'].get('status') != 'failed':
            dns_results = results['modules']['dns']
            print(f"\n   🌐 DNS ENUMERATION:")
            print(f"      • DNS Records Found:")
            dns_records = dns_results.get('dns_records', {})
            for record_type, records in dns_records.items():
                if isinstance(records, list) and records:
                    print(f"        - {record_type} Records: {len(records)} {record_type.lower()} addresses" if record_type in ['A', 'AAAA'] else f"        - {record_type} Records: {len(records)} {record_type.lower()} records")
            
            analysis = dns_results.get('analysis', {})
            if 'infrastructure' in analysis:
                infra = analysis['infrastructure']
                if 'nameservers' in infra and infra['nameservers']:
                    print(f"      • Infrastructure Analysis:")
                    print(f"        - Nameservers: {', '.join(infra['nameservers'][:2])}{'...' if len(infra['nameservers']) > 2 else ''}")
                if 'mail_servers' in infra and infra['mail_servers']:
                    print(f"        - Mail Servers: {', '.join(infra['mail_servers'][:2])}{'...' if len(infra['mail_servers']) > 2 else ''}")
            
            if 'security_records' in analysis:
                security = analysis['security_records']
                spf_enabled = security.get('spf_enabled', False)
                dmarc_enabled = security.get('dmarc_enabled', False)
                dmarc_policy = security.get('dmarc_policy', 'none')
                print(f"        - Security Records: SPF {'enabled' if spf_enabled else 'disabled'}, DMARC {'policy=' + dmarc_policy if dmarc_enabled else 'disabled'}")
            
            print(f"      • Total Duration: {dns_results.get('statistics', {}).get('total_duration', 0):.2f} seconds")
        
        # Web fingerprinting details
        if 'fingerprinting' in results['modules'] and results['modules']['fingerprinting'].get('status') != 'failed':
            fingerprinting_results = results['modules']['fingerprinting']
            print(f"\n   🔧 WEB FINGERPRINTING:")
            targets = fingerprinting_results.get('targets', {})
            for target_url, target_data in targets.items():
                if 'error' not in target_data:
                    status_code = target_data.get('response_analysis', {}).get('status_code', 'N/A')
                    server = target_data.get('header_analysis', {}).get('server', 'Unknown')
                    technologies = target_data.get('technology_detection', {}).get('wappalyzer_detected', [])
                    security_score = target_data.get('security_analysis', {}).get('security_score', 0)
                    response_time = target_data.get('performance_metrics', {}).get('response_time', 0)
                    
                    print(f"      • Target: {target_url}")
                    print(f"        - Status Code: {status_code}")
                    print(f"        - Server: {server}")
                    print(f"        - Technologies: {', '.join(technologies[:5])}{'...' if len(technologies) > 5 else ''}")
                    print(f"        - Security Score: {security_score:.0f}%")
                    print(f"        - Response Time: {response_time:.2f} seconds")
            
            summary = fingerprinting_results.get('summary', {})
            unique_techs = len(summary.get('unique_technologies', []))
            print(f"      • Total Duration: {fingerprinting_results.get('statistics', {}).get('total_duration', 0):.2f} seconds")
            if unique_techs > 0:
                print(f"      • Unique Technologies Detected: {unique_techs}")


def save_results(results: Dict[str, Any], output_file: str):
    """Save results to JSON file"""
    try:
        # Convert sets to lists for JSON serialization
        results_copy = json.loads(json.dumps(results, default=str))
        
        with open(output_file, 'w') as f:
            json.dump(results_copy, f, indent=2, default=str)
        
        print(f"\n💾 Results saved to: {output_file}")
        
    except Exception as e:
        logger.error(f"Failed to save results: {str(e)}")


def create_config_from_args(args) -> DomainEnumerationConfig:
    """Create configuration from command line arguments"""
    config = DomainEnumerationConfig()
    
    # Global settings
    config.domain = args.domain
    config.verbose = args.verbose
    config.output_file = args.output
    
    if args.modules:
        config.enabled_modules = args.modules
    
    # Passive configuration
    if args.passive_timeout:
        config.passive_config['timeout'] = args.passive_timeout
    if args.passive_concurrent:
        config.passive_config['concurrent_requests'] = args.passive_concurrent
    
    # Active configuration
    if args.active_threads:
        config.active_config['threads'] = args.active_threads
    if args.active_rate_limit:
        config.active_config['rate_limit'] = args.active_rate_limit
    if args.active_timeout:
        config.active_config['timeout'] = args.active_timeout
    if args.wordlist:
        config.active_config['wordlist_file'] = args.wordlist
    if args.no_ai:
        config.active_config['enable_ai'] = False
    
    # DNS configuration
    if args.dns_timeout:
        config.dns_config['timeout'] = args.dns_timeout
    if args.dns_retries:
        config.dns_config['retries'] = args.dns_retries
    if args.record_types:
        config.dns_config['record_types'] = args.record_types
    
    # Fingerprinting configuration
    if args.fingerprint_timeout:
        config.fingerprinting_config['timeout'] = args.fingerprint_timeout
    if args.fingerprint_concurrent:
        config.fingerprinting_config['concurrent'] = args.fingerprint_concurrent
    if args.include_http:
        config.fingerprinting_config['include_http'] = True
    if args.include_www:
        config.fingerprinting_config['include_www'] = True
    
    # Apply verbose to all modules
    if args.verbose:
        config.passive_config['verbose'] = True
        config.dns_config['verbose'] = True
        config.fingerprinting_config['verbose'] = True
    
    return config


def execute_domain_enumeration(config: DomainEnumerationConfig) -> Dict[str, Any]:
    """
    Execute domain enumeration with provided configuration.
    
    Args:
        config: DomainEnumerationConfig object with all settings
        
    Returns:
        Dict containing enumeration results
    """
    # Validate configuration
    if not config.domain:
        raise ValueError("Domain must be specified in configuration")
    
    # Check if any modules are available
    available_modules = []
    if PASSIVE_AVAILABLE:
        available_modules.append('passive')
    if ACTIVE_AVAILABLE:
        available_modules.append('active')
    if DNS_AVAILABLE:
        available_modules.append('dns')
    if FINGERPRINTING_AVAILABLE:
        available_modules.append('fingerprinting')
    
    if not available_modules:
        raise RuntimeError("No enumeration modules are available. Please check your installation.")
    
    if config.verbose:
        print(f"🚀 Available modules: {', '.join(available_modules)}")
    
    # Filter enabled modules to only include available ones
    config.enabled_modules = [m for m in config.enabled_modules if m in available_modules]
    
    if not config.enabled_modules:
        raise ValueError("No enabled modules are available.")
    
    if config.verbose:
        print(f"📋 Enabled modules: {', '.join(config.enabled_modules)}")
    
    # Run enumeration
    orchestrator = DomainEnumerationOrchestrator(config)
    results = orchestrator.run_comprehensive_enumeration()
    
    # Display results if verbose
    if config.verbose:
        display_results(results, verbose=config.verbose)
    
    # Save results if output file specified
    if config.output_file:
        save_results(results, config.output_file)
        if config.verbose:
            print(f"\n💾 Results saved to: {config.output_file}")
    
    if config.verbose:
        print(f"\n✅ Enumeration completed successfully!")
    
    return results

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Comprehensive Domain Enumeration Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py example.com
  python main.py example.com --verbose --output results.json
  python main.py example.com --modules passive active --no-ai
  python main.py example.com --active-threads 20 --dns-timeout 10
        """
    )
    
    # Required arguments
    parser.add_argument('domain', help='Target domain to enumerate')
    
    # Global options
    parser.add_argument('--verbose', '-v', action='store_true', 
                       help='Enable verbose output')
    parser.add_argument('--output', '-o', 
                       help='Output file for results (JSON format)')
    parser.add_argument('--modules', nargs='+', 
                       choices=['passive', 'active', 'dns', 'fingerprinting'],
                       help='Enumeration modules to run')
    
    # Passive enumeration options
    parser.add_argument('--passive-timeout', type=int, default=10,
                       help='Passive enumeration timeout (default: 10)')
    parser.add_argument('--passive-concurrent', type=int, default=5,
                       help='Passive enumeration concurrent requests (default: 5)')
    
    # Active enumeration options
    parser.add_argument('--active-threads', type=int, default=10,
                       help='Active enumeration threads (default: 10)')
    parser.add_argument('--active-rate-limit', type=int, default=10,
                       help='Active enumeration rate limit (default: 10)')
    parser.add_argument('--active-timeout', type=int, default=5,
                       help='Active enumeration timeout (default: 5)')
    parser.add_argument('--wordlist', 
                       help='Custom wordlist file for active enumeration')
    parser.add_argument('--no-ai', action='store_true',
                       help='Disable AI-enhanced wordlist generation')
    
    # DNS enumeration options
    parser.add_argument('--dns-timeout', type=int, default=5,
                       help='DNS enumeration timeout (default: 5)')
    parser.add_argument('--dns-retries', type=int, default=2,
                       help='DNS enumeration retries (default: 2)')
    parser.add_argument('--record-types', nargs='+',
                       choices=['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA'],
                       help='DNS record types to query')
    
    # Web fingerprinting options
    parser.add_argument('--fingerprint-timeout', type=int, default=30,
                       help='Web fingerprinting timeout (default: 30)')
    parser.add_argument('--fingerprint-concurrent', type=int, default=3,
                       help='Web fingerprinting concurrent requests (default: 3)')
    parser.add_argument('--include-http', action='store_true',
                       help='Include HTTP targets in fingerprinting')
    parser.add_argument('--include-www', action='store_true',
                       help='Include www variant in fingerprinting')
    
    args = parser.parse_args()
    
    # Create configuration from arguments
    config = create_config_from_args(args)
    
    # Check if any modules are available
    available_modules = []
    if PASSIVE_AVAILABLE:
        available_modules.append('passive')
    if ACTIVE_AVAILABLE:
        available_modules.append('active')
    if DNS_AVAILABLE:
        available_modules.append('dns')
    if FINGERPRINTING_AVAILABLE:
        available_modules.append('fingerprinting')
    
    if not available_modules:
        print("❌ No enumeration modules are available. Please check your installation.")
        sys.exit(1)
    
    print(f"🚀 Available modules: {', '.join(available_modules)}")
    
    # Filter enabled modules to only include available ones
    config.enabled_modules = [m for m in config.enabled_modules if m in available_modules]
    
    if not config.enabled_modules:
        print("❌ No enabled modules are available.")
        sys.exit(1)
    
    print(f"📋 Enabled modules: {', '.join(config.enabled_modules)}")
    
    # Run enumeration
    orchestrator = DomainEnumerationOrchestrator(config)
    results = orchestrator.run_comprehensive_enumeration()
    
    # Display results
    display_results(results, verbose=config.verbose)
    
    # Save results if output file specified
    if config.output_file:
        save_results(results, config.output_file)
    
    print(f"\n✅ Enumeration completed successfully!")


if __name__ == "__main__":
    main()
