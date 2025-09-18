import time
from seleniumbase import Driver
from typing import Optional

class CDNBypass:
    """
    A module to bypass CDN challenges using SeleniumBase with undetected-chromedriver.
    """
    
    def __init__(self, headless: bool = True, timeout: int = 30):
        """
        Initialize the CDN bypass module.
        
        Args:
            headless (bool): Whether to run browser in headless mode
            timeout (int): Default timeout for operations in seconds
        """
        self.headless = headless
        self.timeout = timeout
        self.driver = None
    
    def bypass_cdn(self, domain: str, wait_time: int = 8) -> Optional[str]:
        """
        Bypass CDN protection for a given domain.
        
        Args:
            domain (str): The domain/URL to access
            wait_time (int): Time to wait for CDN challenge to complete
            
        Returns:
            Optional[str]: The page source if successful, None otherwise
        """
        try:
            # Format the URL correctly
            url = f"https://{domain}" if not domain.startswith(("http://", "https://")) else domain
            
            print(f"[CDN BYPASS] Initializing driver for: {url}")
            
            # Initialize the driver with UC mode
            self.driver = Driver(uc=True, headless=self.headless)
            
            print(f"[CDN BYPASS] Navigating to URL: {url}")
            self.driver.get(url)
            
            print("[CDN BYPASS] Waiting for page to load and CDN challenge to pass...")
            time.sleep(wait_time)  # Proven timing

            #########################################################
            # Add the tasks to be done
            #########################################################
            
            print("[CDN BYPASS] Fetching page source...")
            page_source = self.driver.page_source
            
            # Basic validation to check if we successfully bypassed the CDN
            if self._is_bypass_successful(page_source):
                print("[CDN BYPASS] Successfully bypassed CDN protection")
                return page_source
            else:
                print("[CDN BYPASS] CDN bypass may have failed - content appears to be challenge page")
                return page_source
                
        except Exception as e:
            print(f"[CDN BYPASS] Error during CDN bypass: {str(e)}")
            return None
        finally:
            self._cleanup()
    
    def _is_bypass_successful(self, page_source: str) -> bool:
        """
        Basic heuristic to check if CDN bypass was successful.
        
        Args:
            page_source (str): The page source to check
            
        Returns:
            bool: True if bypass appears successful
        """
        # Common CDN challenge indicators that suggest we're still blocked
        challenge_indicators = [
            "Just a moment", "Checking your browser", "Cloudflare",
            "Attention Required", "Security Check", "Challenge Platform",
        ]
        
        page_source_lower = page_source.lower()
        
        # If we detect many challenge indicators, bypass may have failed
        indicator_count = sum(1 for indicator in challenge_indicators if indicator in page_source_lower)
        
        # Also check if we have reasonable content length
        content_length = len(page_source)
        
        # If we have few challenge indicators and reasonable content length, assume success
        return indicator_count < 3 and content_length > 2000
    
    def _cleanup(self):
        """Clean up the driver resources."""
        if self.driver:
            print("[CDN BYPASS] Quitting driver...")
            self.driver.quit()
            self.driver = None
    
    def __del__(self):
        """Destructor to ensure cleanup."""
        self._cleanup()


# Example usage and test function
def test_cdn_bypass():
    """Test the CDN bypass module."""
    # Example domains that might have CDN protection
    test_domains = [
        "example.com",  # Replace with actual domain you need to bypass
        # "cloudflare-protected-site.com",
    ]
    
    bypass = CDNBypass(headless=True)
    
    for domain in test_domains:
        print(f"\n=== Testing CDN bypass for: {domain} ===")
        page_source = bypass.bypass_cdn(domain)
        
        if page_source:
            print(f"Successfully retrieved content (length: {len(page_source)} characters)")
            # You can now parse the page_source with BeautifulSoup or other tools
        else:
            print("Failed to bypass CDN")


if __name__ == "__main__":
    test_cdn_bypass()