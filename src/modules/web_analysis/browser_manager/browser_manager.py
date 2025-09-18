# modules/browser_manager.py
"""
Browser Manager Module
---------------------
Manages a single browser instance for CDN bypass and web crawling operations.
This ensures we don't need to restart the browser for each request, saving time.
"""

from seleniumbase import Driver
import logging
import time

class BrowserManager:
    def __init__(self, headless=True, uc=True):
        self.driver = None
        self.headless = headless
        self.uc = uc
        self.is_active = False
        
    def start_browser(self):
        """Initialize the browser driver"""
        if not self.is_active:
            try:
                logging.info("Starting browser instance...")
                self.driver = Driver(uc=self.uc, headless=self.headless)
                self.is_active = True
                logging.info("Browser started successfully")
            except Exception as e:
                logging.error(f"Failed to start browser: {str(e)}")
                raise
                
    def close_browser(self):
        """Close the browser instance"""
        if self.is_active and self.driver:
            try:
                self.driver.quit()
                self.is_active = False
                logging.info("Browser closed successfully")
            except Exception as e:
                logging.error(f"Error closing browser: {str(e)}")
                
    def get_page_content(self, url, wait_time=8):
        """
        Navigate to a URL and return page content
        
        Args:
            url: URL to navigate to
            wait_time: Time to wait for page to load
            
        Returns:
            Page source content
        """
        if not self.is_active:
            self.start_browser()
            
        try:
            logging.info(f"Navigating to: {url}")
            self.driver.get(url)
            logging.info(f"Waiting {wait_time} seconds for page to load...")
            time.sleep(wait_time)
            
            content = self.driver.page_source
            logging.info(f"Successfully retrieved content from {url}")
            return content
        except Exception as e:
            logging.error(f"Failed to get page content: {str(e)}")
            return None
            
    def save_page_content(self, content, filename):
        """
        Save page content to a file
        
        Args:
            content: HTML content to save
            filename: Output filename
        """
        try:
            with open(filename, "w", encoding="utf-8") as f:
                f.write(content)
            logging.info(f"Content saved to {filename}")
        except Exception as e:
            logging.error(f"Failed to save content: {str(e)}")