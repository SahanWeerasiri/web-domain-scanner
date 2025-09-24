# modules/cdn_detector.py
"""
CDN Detector Module
-------------------
Detects CDN services and attempts to bypass them when detected.
Uses the BrowserManager for efficient CDN bypass operations.
"""

import requests
import logging
from typing import Dict, Any, Optional
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from browser_manager.browser_manager import BrowserManager

class CDNDetector:
    def __init__(self, domain: str):
        self.domain = domain
        self.results: Dict[str, Any] = {}
        self.browser_manager = BrowserManager()
        self._bypassed_content = None  # Store bypassed content internally
        
        # CDN indicators
        self.cdn_indicators = {
            "Cloudflare": ["cloudflare"],
            "Akamai": ["akamai", "akamaighost"],
            "Fastly": ["fastly"],
            "Amazon CloudFront": ["cloudfront"],
            "Google CDN": ["gws", "google"],
            "Azure CDN": ["azure"]
        }
        
        # Block phrases to detect CDN challenges - be specific to avoid false positives
        self.block_phrases = [
            "just a moment", "checking your browser", "attention required", 
            "security check", "challenge platform", "enable javascript and cookies", 
            "cf-ray", "__cf_chl_", "cloudflare ray id", "completing security check",
            "browser verification", "ddos protection"
        ]
        
    def detect_cdn_via_headers(self, timeout: int = 3) -> Optional[str]:
        """
        Detect CDN by examining HTTP headers
        
        Args:
            timeout: Request timeout in seconds
            
        Returns:
            Detected CDN name or None
        """
        try:
            url = f"https://{self.domain}"
            response = requests.head(url, timeout=timeout, allow_redirects=True)
            
            server = response.headers.get('Server', '').lower()
            via = response.headers.get('Via', '').lower()
            x_powered_by = response.headers.get('X-Powered-By', '').lower()
            
            logging.info(f"Server header: {server}")
            logging.info(f"Via header: {via}")
            logging.info(f"X-Powered-By: {x_powered_by}")
            
            for cdn, indicators in self.cdn_indicators.items():
                for indicator in indicators:
                    if (indicator in server or 
                        indicator in via or 
                        indicator in x_powered_by):
                        logging.info(f"Detected CDN in headers: {cdn}")
                        return cdn
                        
        except requests.RequestException as e:
            logging.warning(f"Failed to detect CDN via headers: {str(e)}")
            
        return None
        
    def detect_cdn_via_content(self, timeout: int = 8) -> Optional[str]:
        """
        Detect CDN by examining page content
        
        Args:
            timeout: Request timeout in seconds
            
        Returns:
            Detected CDN name or None
        """
        try:
            url = f"https://{self.domain}"
            response = requests.get(url, timeout=timeout, allow_redirects=True)
            content = response.text.lower()
            
            # Check for CDN indicators in content
            for cdn, indicators in self.cdn_indicators.items():
                for indicator in indicators:
                    if indicator in content:
                        logging.info(f"Detected CDN in content: {cdn}")
                        return cdn
                        
            # Check for block phrases
            for phrase in self.block_phrases:
                if phrase in content:
                    logging.info(f"Detected CDN block phrase: {phrase}")
                    return "CDN (Unknown)"
                    
        except requests.RequestException as e:
            logging.warning(f"Failed to detect CDN via content: {str(e)}")
            
        return None
        
    def check_for_blocking_content(self, timeout: int = 8) -> Dict[str, Any]:
        """
        Check if CDN is actually blocking content with a normal request
        
        Args:
            timeout: Request timeout in seconds
            
        Returns:
            Dictionary with blocking check results
        """
        try:
            url = f"https://{self.domain}"
            response = requests.get(url, timeout=timeout, allow_redirects=True)
            content = response.text.lower()
            
            # Check for block phrases that indicate CDN interference
            blocked_phrases = []
            for phrase in self.block_phrases:
                if phrase in content:
                    blocked_phrases.append(phrase)
                    
            is_blocked = len(blocked_phrases) > 0
            
            result = {
                'is_blocked': is_blocked,
                'blocked_phrases': blocked_phrases,
                'status_code': response.status_code,
                '_content': response.text  # Store content internally for reuse
            }
            
            if is_blocked:
                logging.info(f"Content appears to be blocked. Found phrases: {blocked_phrases}")
            else:
                logging.info("Content appears to be accessible without CDN bypass")
                
            return result
            
        except requests.RequestException as e:
            logging.warning(f"Failed to check for blocking content: {str(e)}")
            return {
                'is_blocked': True,  # Assume blocked if we can't get content
                'blocked_phrases': [],
                'content': None,
                'status_code': None,
                'error': str(e)
            }
        
    def get_content_for_analysis(self, timeout: int = 8) -> Optional[str]:
        """
        Get page content for AI analysis without storing it in results
        
        Args:
            timeout: Request timeout in seconds
            
        Returns:
            Page content as string or None
        """
        # First check if we have bypassed content from a successful CDN bypass
        if hasattr(self, '_bypassed_content') and self._bypassed_content:
            logging.info("Using bypassed content for analysis")
            return self._bypassed_content
            
        # Otherwise, try normal request
        try:
            url = f"https://{self.domain}"
            response = requests.get(url, timeout=timeout, allow_redirects=True)
            return response.text
        except requests.RequestException as e:
            logging.warning(f"Failed to get content for analysis: {str(e)}")
            return None
        
    def detect_cdn(self, timeout: int = 5) -> Dict[str, Any]:
        """
        Comprehensive CDN detection using multiple methods
        
        Args:
            timeout: Request timeout in seconds
            
        Returns:
            Dictionary with CDN detection results
        """
        logging.info(f"Starting CDN detection for {self.domain}")
        
        self.results = {
            'cdn_detected': False,
            'cdn_name': None,
            'detection_method': None,
            'bypass_attempted': False,
            'bypass_successful': False,
            'content': None
        }
        
        # Try header-based detection first
        cdn_name = self.detect_cdn_via_headers(timeout)
        if cdn_name:
            self.results.update({
                'cdn_detected': True,
                'cdn_name': cdn_name,
                'detection_method': 'headers'
            })
            return self.results
            
        # Try content-based detection
        cdn_name = self.detect_cdn_via_content(timeout + 5)
        if cdn_name:
            self.results.update({
                'cdn_detected': True,
                'cdn_name': cdn_name,
                'detection_method': 'content'
            })
            return self.results
            
        logging.info("No CDN detected")
        return self.results
        
    def bypass_cdn(self) -> Dict[str, Any]:
        """
        Attempt to bypass CDN using browser automation
        
        Returns:
            Updated results with bypass attempt information
        """
        if not self.results.get('cdn_detected', False):
            logging.info("No CDN detected, bypass not needed")
            return self.results
            
        logging.info(f"Attempting to bypass {self.results['cdn_name']} CDN")
        self.results['bypass_attempted'] = True
        
        try:
            # ============= PROVEN WORKING METHOD =============
            # This exact approach works reliably for CDN bypass
            from seleniumbase import Driver
            self._bypass_driver = Driver(uc=True, headless=True)  # Store driver for later use
            url = f"https://{self.domain}" if not self.domain.startswith("http") else self.domain
            print(f"[BYPASS] Navigating to URL: {url}")
            self._bypass_driver.get(url)
            print("[BYPASS] Waiting for page to load and CDN challenge to pass...")
            import time
            time.sleep(8)  # Proven timing - don't change this
            print("[BYPASS] Fetching page source...")
            page_source = self._bypass_driver.page_source
            print("[BYPASS] Driver ready for endpoint testing...")
            # Note: NOT quitting driver here - keeping it for endpoint testing
            # ============= END PROVEN METHOD =============
            
            if page_source:
                # Check if bypass was successful by looking for blocking phrases
                blocking_phrases_found = []
                for phrase in self.block_phrases:
                    if phrase in page_source.lower():
                        blocking_phrases_found.append(phrase)
                
                # Consider bypass successful if no blocking phrases are found
                bypass_successful = len(blocking_phrases_found) == 0
                
                # Store content internally for later retrieval (not in final results)
                self._bypassed_content = page_source
                        
                self.results.update({
                    'bypass_successful': bypass_successful,
                    'remaining_blocking_phrases': blocking_phrases_found if blocking_phrases_found else []
                })
                
                if bypass_successful:
                    logging.info("CDN bypass successful - no blocking phrases detected")
                else:
                    logging.warning(f"CDN bypass may not have been fully successful. Found phrases: {blocking_phrases_found}")
                    
            else:
                logging.error("Failed to retrieve content during bypass attempt")
                self.results['bypass_successful'] = False
                
        except Exception as e:
            logging.error(f"CDN bypass failed: {str(e)}")
            self.results['bypass_successful'] = False
            
        return self.results
    
    def get_bypass_driver(self):
        """Return the active bypass driver for endpoint testing"""
        return getattr(self, '_bypass_driver', None)
    
    def close_bypass_driver(self):
        """Close the bypass driver when done with endpoint testing"""
        if hasattr(self, '_bypass_driver') and self._bypass_driver:
            try:
                print("[BYPASS] Closing driver after endpoint testing...")
                self._bypass_driver.quit()
                logging.info("Bypass driver closed successfully")
            except Exception as e:
                logging.error(f"Error closing bypass driver: {str(e)}")
            
        return self.results
            
        return self.results
        
    def get_bypassed_content(self) -> Optional[str]:
        """
        Get the last bypassed content for analysis (without storing in results)
        
        Returns:
            Bypassed content as string or None
        """
        if not self.results.get('bypass_successful', False):
            return None
            
        try:
            url = f"https://{self.domain}"
            content = self.browser_manager.get_page_content(url)
            return content
        except Exception as e:
            logging.error(f"Failed to get bypassed content: {str(e)}")
            return None
        
    def close(self):
        """Clean up resources"""
        self.browser_manager.close_browser()
        
if __name__ == "__main__":
    import argparse
    import json
    
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    # Parse arguments
    parser = argparse.ArgumentParser(description="CDN detection and bypass tool")
    parser.add_argument("domain", help="Domain to check for CDN")
    parser.add_argument("--timeout", type=int, default=5, help="Request timeout in seconds")
    parser.add_argument("--bypass", action="store_true", help="Attempt CDN bypass if detected")
    args = parser.parse_args()
    
    # Run detection
    detector = CDNDetector(args.domain)
    try:
        results = detector.detect_cdn(args.timeout)
        
        if args.bypass and results['cdn_detected']:
            results = detector.bypass_cdn()
            
        print(json.dumps(results, indent=2))
        
    finally:
        detector.close()