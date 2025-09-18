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
        
        # CDN indicators
        self.cdn_indicators = {
            "Cloudflare": ["cloudflare"],
            "Akamai": ["akamai", "akamaighost"],
            "Fastly": ["fastly"],
            "Amazon CloudFront": ["cloudfront"],
            "Google CDN": ["gws", "google"],
            "Azure CDN": ["azure"]
        }
        
        # Block phrases to detect CDN challenges
        self.block_phrases = [
            "just a moment", "checking your browser", "cloudflare",
            "attention required", "security check", "challenge platform",
            "enable javascript and cookies", "cf-ray", "__cf_chl_"
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
            url = f"https://{self.domain}"
            content = self.browser_manager.get_page_content(url)
            
            if content:
                # Check if bypass was successful
                bypass_successful = True
                for phrase in self.block_phrases:
                    if phrase in content.lower():
                        bypass_successful = False
                        break
                        
                self.results.update({
                    'bypass_successful': bypass_successful,
                    'content': content
                })
                
                # Save content to file
                safe_domain = self.domain.replace('.', '_')
                filename = f"results/{safe_domain}_bypassed.html"
                self.browser_manager.save_page_content(content, filename)
                
                if bypass_successful:
                    logging.info("CDN bypass successful")
                else:
                    logging.warning("CDN bypass may not have been fully successful")
                    
            else:
                logging.error("Failed to retrieve content during bypass attempt")
                self.results['bypass_successful'] = False
                
        except Exception as e:
            logging.error(f"CDN bypass failed: {str(e)}")
            self.results['bypass_successful'] = False
            
        return self.results
        
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