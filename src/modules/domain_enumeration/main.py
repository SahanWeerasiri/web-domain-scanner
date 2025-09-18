#!/usr/bin/env python3
"""
Main Domain Enumeration Orchestrator

This module coordinates all domain enumeration sub-modules and provides a unified
interface for comprehensive domain reconnaissance. It combines passive enumeration,
active enumeration, DNS analysis, and web fingerprinting.

Author: Web Domain Scanner Project
License: See LICENSE file in project root
"""

import logging
import time
import sys
import os
from typing import Dict, List, Set, Optional, TYPE_CHECKING

# Add parent directories to path for imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '.')))

# Import sub-modules with fallback for both relative and absolute imports
try:
    # Try relative imports first (when used as module)
    from .config import EnumerationConfig
    from .base import ResultsManager, SubdomainValidator, EnumerationErrorHandler
    from .passive.passive_enumeration import PassiveEnumerator
    from .active.active_enumeration import ActiveEnumerator
    from .dns_enumeration_module.dns_enumeration import DNSEnumerator
    from .web_fingerprinting.web_fingerprinting import WebFingerprinter
except ImportError:
    # Fallback to absolute imports (when run directly or when package context differs)
    # Prefer the full package path to avoid colliding with the top-level `config` package
    try:
        from modules.domain_enumeration.config import EnumerationConfig
        from modules.domain_enumeration.base import ResultsManager, SubdomainValidator, EnumerationErrorHandler
        from modules.domain_enumeration.passive.passive_enumeration import PassiveEnumerator
        from modules.domain_enumeration.active.active_enumeration import ActiveEnumerator
        from modules.domain_enumeration.dns_enumeration_module.dns_enumeration import DNSEnumerator
        from modules.domain_enumeration.web_fingerprinting.web_fingerprinting import WebFingerprinter
    except ImportError:
        # Last-resort: try the plain module paths (useful for some execution contexts)
        try:
            from modules.domain_enumeration.config import EnumerationConfig
            from modules.domain_enumeration.base import ResultsManager, SubdomainValidator, EnumerationErrorHandler
            from modules.domain_enumeration.passive.passive_enumeration import PassiveEnumerator
            from modules.domain_enumeration.active.active_enumeration import ActiveEnumerator
            from modules.domain_enumeration.dns_enumeration_module.dns_enumeration import DNSEnumerator
            from modules.domain_enumeration.web_fingerprinting.web_fingerprinting import WebFingerprinter
        except ImportError:
            # Fallback to plain imports for alternate execution contexts
            from config import EnumerationConfig
            from base import ResultsManager, SubdomainValidator, EnumerationErrorHandler
            from passive.passive_enumeration import PassiveEnumerator
            from active.active_enumeration import ActiveEnumerator
            from dns_enumeration_module.dns_enumeration import DNSEnumerator
            from web_fingerprinting.web_fingerprinting import WebFingerprinter

# Import AI Integration module for enhanced enumeration
if TYPE_CHECKING:
    from ai_integration import AIIntegration

try:
    # Try different paths for AI integration
    try:
        sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
        from ai_integration import AIIntegration
    except ImportError:
        # Try alternative path
        sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../modules')))
        from ai_integration import AIIntegration
    AI_AVAILABLE = True
except ImportError:
    AI_AVAILABLE = False
    AIIntegration = None

logger = logging.getLogger(__name__)


class DomainEnumeration:
    """
    Comprehensive domain enumeration orchestrator.
    
    This class provides advanced subdomain discovery capabilities using multiple
    enumeration techniques including passive data collection, active probing,
    DNS enumeration, and web technology fingerprinting.
    
    Key Features:
    - Passive enumeration via Certificate Transparency logs
    - Active enumeration with intelligent wordlist generation
    - DNS enumeration with multiple record types
    - Web technology fingerprinting
    - Rate limiting and error handling
    - Results correlation and validation
    
    Example:
        >>> config = EnumerationConfig()
        >>> enumerator = DomainEnumeration("example.com", config)
        >>> results = enumerator.correlate_results()
    """
    
    def __init__(self, domain: str, config: Optional[EnumerationConfig] = None, ai_integration = None):
        """
        Initialize DomainEnumeration instance with target domain and configuration.
        
        Args:
            domain (str): Target domain to enumerate (e.g., "example.com")
            config (EnumerationConfig, optional): Configuration object.
                                                If None, uses default configuration.
            ai_integration (AIIntegration, optional): AI integration instance for enhanced enumeration.
        
        Raises:
            ValueError: If domain is invalid.
        """
        # Validate domain input
        if not domain or not isinstance(domain, str):
            raise ValueError("Domain must be a non-empty string")
        
        self.domain = domain.lower().strip()
        logger.info(f"Initializing DomainEnumeration for domain: {self.domain}")
        
        # Handle config
        self.config = config or EnumerationConfig()
        
        # Initialize AI integration if available
        self.ai_integration = ai_integration
        if AI_AVAILABLE and not self.ai_integration:
            # Try to create AI integration with environment variables
            api_keys = {
                'gemini_api_key': os.getenv('GEMINI_API_KEY'),
                'openai_api_key': os.getenv('OPENAI_API_KEY'),
                'anthropic_api_key': os.getenv('ANTHROPIC_API_KEY')
            }
            if any(api_keys.values()):
                self.ai_integration = AIIntegration(**{k: v for k, v in api_keys.items() if v})
                logger.info("AI integration initialized for enhanced domain enumeration")
        
        # Initialize results manager
        self.results_manager = ResultsManager()
        self.error_handler = EnumerationErrorHandler()
        
        # Initialize sub-modules with AI integration
        self.passive_enumerator = PassiveEnumerator(self.domain, self.config, self.ai_integration)
        self.active_enumerator = ActiveEnumerator(self.domain, self.config, self.ai_integration)
        self.dns_enumerator = DNSEnumerator(self.domain, self.config)  # DNS enumeration doesn't need AI for now
        self.web_fingerprinter = WebFingerprinter(self.domain, self.config, self.ai_integration)
        
        logger.info(f"DomainEnumeration initialized successfully for {self.domain}")
    
    def passive_enumeration(self) -> Dict:
        """
        Run passive enumeration using external sources.
        
        Returns:
            Dict: Passive enumeration results
        """
        logger.info("Starting passive enumeration")
        try:
            results = self.passive_enumerator.run_passive_enumeration()
            self.results_manager.add_passive_results(results)
            
            # Collect errors
            errors = self.passive_enumerator.get_errors()
            if errors:
                self.results_manager.add_errors({'passive': errors})
            
            logger.info("Passive enumeration completed successfully")
            return results
        except Exception as e:
            logger.error(f"Passive enumeration failed: {e}")
            self.error_handler.handle_error("passive_enumeration", e)
            return {}
    
    def enhanced_active_enumeration(self, wordlist: Optional[List[str]] = None, page_content: Optional[Dict] = None) -> Dict:
        """
        Run active enumeration with brute force and intelligent techniques.
        
        Args:
            wordlist: Custom wordlist for brute force. If None, generates dynamic wordlist.
            page_content: Page content from web crawling for AI-enhanced wordlist generation.
            
        Returns:
            Dict: Active enumeration results
        """
        logger.info("Starting active enumeration")
        try:
            # If AI integration is available and no page content provided, try to collect it
            if self.ai_integration and not page_content:
                try:
                    # Quick web probe to get page content for AI analysis
                    import requests
                    session = requests.Session()
                    session.headers.update({
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                    })
                    
                    for protocol in ['https', 'http']:
                        try:
                            response = session.get(f"{protocol}://{self.domain}", timeout=10)
                            if response.status_code == 200:
                                page_content = {
                                    'html': response.text,
                                    'headers': dict(response.headers),
                                    'status_code': response.status_code,
                                    'url': response.url
                                }
                                logger.info(f"Collected page content from {protocol}://{self.domain} for AI analysis")
                                break
                        except:
                            continue
                except Exception as e:
                    logger.debug(f"Could not collect page content for AI analysis: {e}")
            
            results = self.active_enumerator.run_active_enumeration(wordlist, page_content)
            self.results_manager.add_active_results(results)
            
            # Collect errors
            errors = self.active_enumerator.get_errors()
            if errors:
                self.results_manager.add_errors({'active': errors})
            
            logger.info("Active enumeration completed successfully")
            return results
        except Exception as e:
            logger.error(f"Active enumeration failed: {e}")
            self.error_handler.handle_error("active_enumeration", e)
            return {}
    
    def dns_enumeration(self) -> Dict:
        """
        Run DNS record enumeration and analysis.
        
        Returns:
            Dict: DNS enumeration results
        """
        logger.info("Starting DNS enumeration")
        try:
            results = self.dns_enumerator.run_dns_enumeration()
            self.results_manager.add_dns_results(results)
            
            # Collect errors
            errors = self.dns_enumerator.get_errors()
            if errors:
                self.results_manager.add_errors({'dns': errors})
            
            logger.info("DNS enumeration completed successfully")
            return results
        except Exception as e:
            logger.error(f"DNS enumeration failed: {e}")
            self.error_handler.handle_error("dns_enumeration", e)
            return {}
    
    def web_fingerprinting(self, targets: Optional[List[str]] = None) -> Dict:
        """
        Run web technology fingerprinting.
        
        Args:
            targets: List of URLs to fingerprint. If None, uses default targets.
            
        Returns:
            Dict: Web fingerprinting results
        """
        logger.info("Starting web fingerprinting")
        try:
            results = self.web_fingerprinter.run_web_fingerprinting(targets)
            self.results_manager.add_web_tech_results(results)
            
            # Collect errors
            errors = self.web_fingerprinter.get_errors()
            if errors:
                self.results_manager.add_errors({'web_fingerprinting': errors})
            
            logger.info("Web fingerprinting completed successfully")
            return results
        except Exception as e:
            logger.error(f"Web fingerprinting failed: {e}")
            self.error_handler.handle_error("web_fingerprinting", e)
            return {}
    
    def subdomain_discovery(self, wordlist: Optional[List[str]] = None) -> List[str]:
        """
        Comprehensive subdomain discovery combining all techniques.
        
        Args:
            wordlist: Custom wordlist for active enumeration.
            
        Returns:
            List[str]: Verified subdomains discovered through enumeration.
        """
        logger.info(f"Starting comprehensive subdomain discovery for domain: {self.domain}")
        start_time = time.time()
        
        # Step 1: Passive enumeration (stealth)
        logger.info("Phase 1: Passive enumeration")
        self.passive_enumeration()
        
        # Step 2: DNS enumeration
        logger.info("Phase 2: DNS enumeration")
        self.dns_enumeration()
        
        # Step 3: Active enumeration
        logger.info("Phase 3: Active enumeration")
        self.enhanced_active_enumeration(wordlist)
        
        # Step 4: Correlate and verify results
        logger.info("Phase 4: Results correlation and verification")
        verified_subdomains = self.correlate_results()
        
        duration = time.time() - start_time
        logger.info(f"Subdomain discovery completed in {duration:.2f} seconds")
        logger.info(f"Found {len(verified_subdomains)} verified subdomains")
        
        return verified_subdomains
    
    def correlate_results(self) -> List[str]:
        """
        Correlate findings from all sources and return verified subdomains.
        
        Returns:
            List[str]: Verified and deduplicated subdomains
        """
        logger.info("Correlating results from all enumeration sources")
        
        # Extract all subdomains from results manager
        all_subdomains = self.results_manager.extract_all_subdomains(self.domain)
        
        # Verify subdomains
        verified_subdomains = self._verify_subdomains(all_subdomains)
        
        # Update results with verified subdomains
        self.results_manager.results['subdomains'] = {
            'verified': verified_subdomains,
            'total_discovered': len(all_subdomains),
            'verification_rate': len(verified_subdomains) / len(all_subdomains) if all_subdomains else 0
        }
        
        logger.info(f"Correlation complete: {len(verified_subdomains)} verified from {len(all_subdomains)} discovered")
        return verified_subdomains
    
    def _verify_subdomains(self, subdomains: Set[str]) -> List[str]:
        """
        Verify that subdomains are actually resolvable.
        
        Args:
            subdomains: Set of subdomains to verify
            
        Returns:
            List of verified subdomains
        """
        verified = []
        
        logger.info(f"Verifying {len(subdomains)} discovered subdomains...")
        
        for subdomain in subdomains:
            if SubdomainValidator.verify_subdomain_dns(subdomain):
                verified.append(subdomain)
                logger.debug(f"Verified subdomain: {subdomain}")
        
        logger.info(f"Verification complete: {len(verified)}/{len(subdomains)} subdomains verified")
        return sorted(verified)
    
    def get_comprehensive_results(self) -> Dict:
        """
        Get all results from all enumeration methods.
        
        Returns:
            Dict: Complete results from all enumeration techniques
        """
        return self.results_manager.get_all_results()
    
    def get_errors(self) -> Dict:
        """
        Get all errors encountered during enumeration.
        
        Returns:
            Dict: Error information from all modules
        """
        all_errors = self.error_handler.get_errors()
        
        # Add errors from results manager
        results_errors = self.results_manager.get_all_results().get('errors', {})
        if results_errors:
            all_errors.update(results_errors)
        
        return all_errors
    
    def generate_report(self) -> Dict:
        """
        Generate a comprehensive enumeration report.
        
        Returns:
            Dict: Detailed report with statistics and findings
        """
        results = self.get_comprehensive_results()
        
        # Extract subdomains from each method
        passive_subdomains = len(self.results_manager.extract_all_subdomains(self.domain))
        verified_subdomains = results.get('subdomains', {}).get('verified', [])
        
        # Generate statistics
        report = {
            'domain': self.domain,
            'timestamp': time.time(),
            'summary': {
                'total_verified_subdomains': len(verified_subdomains),
                'total_discovered_subdomains': passive_subdomains,
                'verification_rate': results.get('subdomains', {}).get('verification_rate', 0),
                'methods_used': []
            },
            'subdomains': verified_subdomains,
            'detailed_results': results,
            'errors': self.get_errors()
        }
        
        # Determine which methods were used
        if results.get('passive_data'):
            report['summary']['methods_used'].append('passive_enumeration')
        if results.get('active_discovery'):
            report['summary']['methods_used'].append('active_enumeration')
        if results.get('dns_records'):
            report['summary']['methods_used'].append('dns_enumeration')
        if results.get('web_technologies'):
            report['summary']['methods_used'].append('web_fingerprinting')
        
        logger.info(f"Generated comprehensive report for {self.domain}")
        return report


# Backward compatibility - maintain the original class structure
# Note: This is not needed since we import EnumerationConfig directly above


# Main function for command-line usage
def main():
    """Main function for command-line execution"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Comprehensive Domain Enumeration")
    parser.add_argument("domain", help="Target domain to enumerate")
    parser.add_argument("--passive-only", action="store_true", help="Run only passive enumeration")
    parser.add_argument("--active-only", action="store_true", help="Run only active enumeration")
    parser.add_argument("--dns-only", action="store_true", help="Run only DNS enumeration")
    parser.add_argument("--web-only", action="store_true", help="Run only web fingerprinting")
    parser.add_argument("--wordlist", help="Custom wordlist file for active enumeration")
    parser.add_argument("--output", help="Output file for results (JSON format)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose logging")
    
    args = parser.parse_args()
    
    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Load custom wordlist if provided
    custom_wordlist = None
    if args.wordlist:
        try:
            with open(args.wordlist, 'r') as f:
                custom_wordlist = [line.strip() for line in f if line.strip()]
            print(f"Loaded {len(custom_wordlist)} words from {args.wordlist}")
        except Exception as e:
            print(f"Error loading wordlist: {e}")
            return
    
    # Initialize enumerator
    enumerator = DomainEnumeration(args.domain)
    
    print(f"\n=== Domain Enumeration for {args.domain} ===")
    
    # Run specific enumeration methods
    if args.passive_only:
        print("Running passive enumeration only...")
        enumerator.passive_enumeration()
    elif args.active_only:
        print("Running active enumeration only...")
        enumerator.enhanced_active_enumeration(custom_wordlist)
    elif args.dns_only:
        print("Running DNS enumeration only...")
        enumerator.dns_enumeration()
    elif args.web_only:
        print("Running web fingerprinting only...")
        enumerator.web_fingerprinting()
    else:
        print("Running comprehensive enumeration...")
        # Run comprehensive enumeration
        subdomains = enumerator.subdomain_discovery(custom_wordlist)
        
        # Run web fingerprinting on discovered subdomains
        web_targets = [f"https://{sub}" for sub in subdomains[:10]]  # Limit to first 10
        enumerator.web_fingerprinting(web_targets)
    
    # Get final results
    final_subdomains = enumerator.correlate_results()
    comprehensive_results = enumerator.get_comprehensive_results()
    
    print(f"\n{'='*60}")
    print(f"               COMPREHENSIVE RESULTS SUMMARY")
    print(f"{'='*60}")
    print(f"Domain: {args.domain}")
    print(f"Verified subdomains found: {len(final_subdomains)}")
    
    if final_subdomains:
        print(f"\n{'='*40}")
        print("           VERIFIED SUBDOMAINS")
        print(f"{'='*40}")
        for i, subdomain in enumerate(final_subdomains, 1):
            print(f"  {i:2d}. {subdomain}")
    
    # Display detailed results from each enumeration method
    print(f"\n{'='*50}")
    print("         DETAILED ENUMERATION RESULTS")
    print(f"{'='*50}")
    
    # Passive Enumeration Results
    passive_data = comprehensive_results.get('passive_data', {})
    if passive_data:
        print(f"\n🔍 PASSIVE ENUMERATION RESULTS:")
        print("-" * 40)
        total_passive = 0
        for source, data in passive_data.items():
            if isinstance(data, dict):
                subdomains_found = 0
                if 'subdomains' in data and isinstance(data['subdomains'], list):
                    subdomains_found = len(data['subdomains'])
                    total_passive += subdomains_found
                print(f"  📊 {source}: {subdomains_found} subdomains")
                
                # Show first few subdomains from each source
                if subdomains_found > 0 and isinstance(data['subdomains'], list):
                    display_count = min(3, subdomains_found)
                    for j, subdomain in enumerate(data['subdomains'][:display_count]):
                        print(f"      • {subdomain}")
                    if subdomains_found > display_count:
                        print(f"      ... and {subdomains_found - display_count} more")
        print(f"  📈 Total from passive sources: {total_passive} subdomains")
    
    # DNS Enumeration Results
    dns_records = comprehensive_results.get('dns_records', {})
    if dns_records:
        print(f"\n🌐 DNS ENUMERATION RESULTS:")
        print("-" * 40)
        for record_type, records in dns_records.items():
            if isinstance(records, list) and records:
                print(f"  📋 {record_type} Records ({len(records)} found):")
                display_count = min(5, len(records))
                for record in records[:display_count]:
                    print(f"      • {record}")
                if len(records) > display_count:
                    print(f"      ... and {len(records) - display_count} more")
    
    # Active Enumeration Results
    active_data = comprehensive_results.get('active_discovery', {})
    if active_data:
        print(f"\n⚔️  ACTIVE ENUMERATION RESULTS:")
        print("-" * 40)
        total_active = 0
        for method, subdomains in active_data.items():
            if isinstance(subdomains, list):
                method_count = len(subdomains)
                total_active += method_count
                print(f"  🎯 {method}: {method_count} subdomains")
                if method_count > 0:
                    display_count = min(3, method_count)
                    for subdomain in subdomains[:display_count]:
                        print(f"      • {subdomain}")
                    if method_count > display_count:
                        print(f"      ... and {method_count - display_count} more")
        print(f"  📈 Total from active methods: {total_active} subdomains")
    
    # Web Technology Results
    web_tech = comprehensive_results.get('web_technologies', {})
    if web_tech:
        print(f"\n🌐 WEB TECHNOLOGY FINGERPRINTING:")
        print("-" * 40)
        for url, tech_data in web_tech.items():
            print(f"  🔗 {url}:")
            if isinstance(tech_data, dict):
                # Check for technology detection data
                tech_detection = tech_data.get('technology_detection', {})
                if tech_detection:
                    # Display Wappalyzer results
                    wappalyzer_techs = tech_detection.get('wappalyzer_detected', [])
                    if wappalyzer_techs:
                        print(f"      🔍 Wappalyzer detected:")
                        for tech in wappalyzer_techs:
                            print(f"         • {tech}")
                    
                    # Display AI detected results
                    ai_techs = tech_detection.get('ai_detected', [])
                    if ai_techs:
                        print(f"      🤖 AI detected:")
                        for tech in ai_techs:
                            print(f"         • {tech}")
                    
                    # Display header detected results
                    header_techs = tech_detection.get('header_detected', [])
                    if header_techs:
                        print(f"      📋 Header detected:")
                        for tech in header_techs:
                            print(f"         • {tech}")
                    
                    # Display content detected results
                    content_techs = tech_detection.get('content_detected', [])
                    if content_techs:
                        print(f"      📄 Content detected:")
                        for tech in content_techs:
                            print(f"         • {tech}")
                    
                    # Display URL pattern results
                    url_patterns = tech_detection.get('url_patterns', [])
                    if url_patterns:
                        print(f"      🔗 URL pattern detected:")
                        for tech in url_patterns:
                            print(f"         • {tech}")
                
                # Legacy check for direct technologies list
                if 'technologies' in tech_data and tech_data['technologies']:
                    print(f"      🔧 Other technologies:")
                    for tech in tech_data['technologies']:
                        print(f"         • {tech}")
                
                # Show additional info if available
                if 'server' in tech_data and tech_data['server']:
                    print(f"      🖥️  Server: {tech_data['server']}")
                if 'status_code' in tech_data:
                    print(f"      📊 Status Code: {tech_data['status_code']}")
                if 'response_time' in tech_data:
                    print(f"      ⏱️  Response Time: {tech_data['response_time']:.3f}s")
                
                # If no technologies were detected at all
                if not any([
                    tech_detection.get('wappalyzer_detected'),
                    tech_detection.get('ai_detected'),
                    tech_detection.get('header_detected'),
                    tech_detection.get('content_detected'),
                    tech_detection.get('url_patterns'),
                    tech_data.get('technologies')
                ]):
                    print("      • No specific technologies detected")
    
    # Subdomain Statistics
    subdomains_info = comprehensive_results.get('subdomains', {})
    if subdomains_info:
        print(f"\n📊 SUBDOMAIN VERIFICATION STATISTICS:")
        print("-" * 40)
        total_discovered = subdomains_info.get('total_discovered', 0)
        total_verified = len(subdomains_info.get('verified', []))
        verification_rate = subdomains_info.get('verification_rate', 0)
        
        print(f"  📈 Total discovered: {total_discovered}")
        print(f"  ✅ Total verified: {total_verified}")
        print(f"  📊 Verification rate: {verification_rate:.1%}")
    
    # Display errors if any
    errors = enumerator.get_errors()
    if errors:
        print(f"\n❌ ERROR SUMMARY:")
        print("-" * 40)
        total_errors = sum(len(error_list) for error_list in errors.values())
        print(f"  Total errors encountered: {total_errors}")
        
        for method, error_list in errors.items():
            if error_list:
                print(f"  🔴 {method}: {len(error_list)} errors")
                # Show first few errors
                display_count = min(2, len(error_list))
                for error in error_list[:display_count]:
                    print(f"      • {str(error)[:80]}...")
                if len(error_list) > display_count:
                    print(f"      ... and {len(error_list) - display_count} more errors")
    
    print(f"\n{'='*60}")
    print("              ENUMERATION COMPLETE")
    print(f"{'='*60}")
    
    # Save results if output file specified
    if args.output:
        try:
            import json
            report = enumerator.generate_report()
            
            with open(args.output, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            
            print(f"\n💾 Full detailed results saved to: {args.output}")
        except Exception as e:
            print(f"❌ Error saving results: {e}")


if __name__ == "__main__":
    main()