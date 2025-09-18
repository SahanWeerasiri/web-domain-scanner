import requests
import logging
import time
import argparse
import os
import sys

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from common.network_utils import NetworkUtils
from common.constants import CDN_BLOCK_PHRASES

class CloudDetector:
    def __init__(self, domain):
        self.domain = domain
        self.results = {}

    def detect_cloud_services(self, common_buckets_patterns, cdn_indicators, **kwargs):
        """Detect cloud services and CDNs with configurable parameters"""
        logging.info("Starting cloud/CDN detection")
        print("[STEP] Initializing cloud/CDN detection...")
        self.results['cloud_services'] = {}
        
        # Extract additional configuration parameters
        request_timeout = kwargs.get('timeout', 3)
        max_buckets = kwargs.get('max_buckets', None)
        
        print("[STEP] Generating common bucket patterns...")
        common_buckets = [
            pattern.format(domain=self.domain) for pattern in common_buckets_patterns
        ]
        
        # Limit buckets if max_buckets is specified
        if max_buckets and len(common_buckets) > max_buckets:
            common_buckets = common_buckets[:max_buckets]
            print(f"[STEP] Limited bucket testing to {max_buckets} buckets")
            
        print(f"[STEP] Common buckets generated: {common_buckets}")
        s3_buckets = []
        for bucket in common_buckets:
            url = f"http://{bucket}.s3.amazonaws.com"
            print(f"[STEP] Checking S3 bucket: {url}")
            try:
                response = requests.head(url, timeout=request_timeout)
                print(f"[STEP] S3 response for {url}: {response.status_code}")
                if response.status_code in [200, 403]:
                    s3_buckets.append({
                        'url': url,
                        'status': response.status_code,
                        'public': response.status_code == 200
                    })
                    logging.info(f"Found S3 bucket: {url} ({'public' if response.status_code == 200 else 'private'})")
                    print(f"[STEP] Found S3 bucket: {url} ({'public' if response.status_code == 200 else 'private'})")
            except requests.RequestException as e:
                print(f"[STEP] Exception checking S3 bucket {url}: {str(e)}")
                continue
        if s3_buckets:
            print(f"[STEP] S3 buckets found: {s3_buckets}")
            self.results['cloud_services']['aws_s3'] = s3_buckets
        
        # Detect CDN
        try:
            # Get web content via requests (without bypass)
            try:
                direct_url = f"https://{self.domain}" if not self.domain.startswith("http") else self.domain
                print(f"[STEP] Getting direct web content from: {direct_url}")
                direct_response = requests.get(direct_url, timeout=request_timeout + 5)  # Longer timeout for content retrieval
                direct_content = direct_response.text
                safe_domain = self.domain.replace('https://', '').replace('http://', '').replace('/', '_')
                direct_html_filename = f"results/direct_{safe_domain}.html"
                print(f"[STEP] Saving direct web content to: {direct_html_filename}")
                with open(direct_html_filename, "w", encoding="utf-8") as f:
                    f.write(direct_content)
                logging.info(f"Direct web content saved to {direct_html_filename}")
                self.results['cloud_services']['web_content_direct'] = direct_content
                block_phrases = [
                    "just a moment", "checking your browser", "cloudflare",
                    "attention required", "security check", "challenge platform",
                    "enable javascript and cookies", "cf-ray", "__cf_chl_"
                ]
                detected_cdn_content = None
                print(f"[STEP] Checking direct content for CDN indicators and block phrases...")
                for cdn, indicators in cdn_indicators.items():
                    if any(indicator in direct_content.lower() for indicator in indicators):
                        detected_cdn_content = cdn
                        print(f"[STEP] CDN indicator found in content: {cdn}")
                        break
                if not detected_cdn_content:
                    if any(phrase in direct_content.lower() for phrase in block_phrases):
                        detected_cdn_content = "Cloudflare"
                        print(f"[STEP] Block phrase found in content: Cloudflare")
                if detected_cdn_content:
                    self.results['cloud_services']['cdn_content'] = detected_cdn_content
                    logging.info(f"Detected CDN from content: {detected_cdn_content}")
                    print(f"[STEP] Detected CDN from content: {detected_cdn_content}")
            except Exception as direct_err:
                logging.warning(f"Failed to get/save direct web content: {str(direct_err)}")
                print(f"[STEP] Exception getting/saving direct web content: {str(direct_err)}")

            print(f"[STEP] Checking CDN via headers for: https://{self.domain}")
            response = requests.head(f"https://{self.domain}", timeout=request_timeout)
            server = response.headers.get('Server', '').lower()
            via = response.headers.get('Via', '').lower()
            print(f"[STEP] Server header: {server}")
            print(f"[STEP] Via header: {via}")
            detected_cdn = None
            for cdn, indicators in cdn_indicators.items():
                if any(indicator in server or indicator in via for indicator in indicators):
                    detected_cdn = cdn
                    print(f"[STEP] CDN indicator found in headers: {cdn}")
                    break

            # If CDN detected in headers or content, always attempt bypass
            print(f"[STEP] CDN detection results: detected_cdn={detected_cdn}, cdn_content={self.results['cloud_services'].get('cdn_content')}")
            cdn_content_detected = self.results['cloud_services'].get('cdn_content')
            if detected_cdn is not None or cdn_content_detected is not None:
                if detected_cdn is not None:
                    self.results['cloud_services']['cdn'] = detected_cdn
                    logging.info(f"Detected CDN: {detected_cdn}")
                    print(f"[STEP] Detected CDN in headers: {detected_cdn}")
                if cdn_content_detected is not None:
                    print(f"[STEP] Detected CDN in content: {cdn_content_detected}")
                print("[STEP] Attempting to bypass CDN using SeleniumBase...")
                html_content = self.bypass_cdn_and_get_content()
                self.results['cloud_services']['web_content_bypassed'] = html_content
                print("[STEP] Bypass attempt complete. See logs and output files for details.")
            else:
                logging.info("No major CDN detected")
                print("[STEP] No major CDN detected. Bypass not attempted.")

        except requests.RequestException as e:
            logging.warning(f"Failed to detect CDN: {str(e)}")

        return self.results['cloud_services']
    def bypass_cdn_and_get_content(self):
        """
        Use SeleniumBase to bypass CDN and get real web content.
        
        This method uses the proven working approach:
        - SeleniumBase with undetected Chrome (uc=True)
        - Headless mode for efficiency
        - 8-second wait (proven timing)
        - Clean driver management
        """
        try:
            print("[BYPASS] Importing SeleniumBase and initializing driver...")
            
            # ============= PROVEN WORKING METHOD =============
            # This exact approach works reliably for CDN bypass
            from seleniumbase import Driver
            driver = Driver(uc=True, headless=True)
            url = f"https://{self.domain}" if not self.domain.startswith("http") else self.domain
            print(f"[BYPASS] Navigating to URL: {url}")
            driver.get(url)
            print("[BYPASS] Waiting for page to load and CDN challenge to pass...")
            import time
            time.sleep(8)  # Proven timing - don't change this
            print("[BYPASS] Fetching page source...")
            page_source = driver.page_source
            print("[BYPASS] Quitting driver...")
            driver.quit()
            # ============= END PROVEN METHOD =============
            block_phrases = [
                "just a moment", "checking your browser", "cloudflare",
                "attention required", "security check", "challenge platform",
                "enable javascript and cookies", "cf-ray", "__cf_chl_"
            ]
            safe_domain = self.domain.replace('https://', '').replace('http://', '').replace('/', '_')
            html_filename = f"results/downloaded_{safe_domain}.html"
            print(f"[BYPASS] Saving bypassed HTML to {html_filename}")
            try:
                with open(html_filename, "w", encoding="utf-8") as f:
                    f.write(page_source)
                logging.info(f"Web content saved to {html_filename}")
            except Exception as file_err:
                print(f"[BYPASS] Failed to save HTML file: {str(file_err)}")
                logging.warning(f"Failed to save HTML file: {str(file_err)}")
            if any(phrase in page_source.lower() for phrase in block_phrases):
                print("[BYPASS] CDN challenge detected in bypassed content, unable to bypass fully.")
                logging.warning("CDN challenge detected in bypassed content, unable to bypass fully.")
                failed_filename = f"results/bypass_failed_{safe_domain}.html"
                print(f"[BYPASS] Saving failed bypass HTML to {failed_filename}")
                try:
                    with open(failed_filename, "w", encoding="utf-8") as f:
                        f.write(page_source)
                    logging.info(f"Bypass failed content saved to {failed_filename}")
                except Exception as file_err:
                    print(f"[BYPASS] Failed to save failed bypass HTML file: {str(file_err)}")
                    logging.warning(f"Failed to save failed bypass HTML file: {str(file_err)}")
            print("[BYPASS] Bypass process complete.")
            return page_source
        except Exception as e:
            print(f"[BYPASS] SeleniumBase failed: {str(e)}")
            logging.warning(f"SeleniumBase failed: {str(e)}")
            return None
    
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Cloud and CDN detection for a domain.")
    parser.add_argument("domain", help="Domain to scan for cloud services and CDN")
    args = parser.parse_args()

    # Example patterns and indicators
    common_buckets_patterns = [
        "{domain}",
        "www.{domain}",
        "static.{domain}",
        "media.{domain}",
        "cdn.{domain}"
    ]
    cdn_indicators = {
        "Cloudflare": ["cloudflare"],
        "Akamai": ["akamai", "akamaighost"],
        "Fastly": ["fastly"],
        "Amazon CloudFront": ["cloudfront"],
        "Google CDN": ["gws", "google"],
        "Azure CDN": ["azure"]
    }

    detector = CloudDetector(args.domain)
    results = detector.detect_cloud_services(common_buckets_patterns, cdn_indicators)
    print("Detection Results:")
    print(results['cdn_content'])