import requests
import logging

class CloudDetector:
    def __init__(self, domain):
        self.domain = domain
        self.results = {}

    def detect_cloud_services(self, common_buckets_patterns, cdn_indicators):
        """Detect cloud services and CDNs"""
        logging.info("Starting cloud/CDN detection")
        self.results['cloud_services'] = {}
        
        # Check for AWS S3 buckets
        common_buckets = [
            pattern.format(domain=self.domain) for pattern in common_buckets_patterns
        ]
        
        s3_buckets = []
        for bucket in common_buckets:
            url = f"http://{bucket}.s3.amazonaws.com"
            try:
                response = requests.head(url, timeout=3)
                if response.status_code in [200, 403]:
                    s3_buckets.append({
                        'url': url,
                        'status': response.status_code,
                        'public': response.status_code == 200
                    })
                    logging.info(f"Found S3 bucket: {url} ({'public' if response.status_code == 200 else 'private'})")
            except requests.RequestException:
                continue
        
        if s3_buckets:
            self.results['cloud_services']['aws_s3'] = s3_buckets
        
        # Detect CDN
        try:
            response = requests.head(f"https://{self.domain}", timeout=3)
            server = response.headers.get('Server', '').lower()
            via = response.headers.get('Via', '').lower()
            
            detected_cdn = None
            for cdn, indicators in cdn_indicators.items():
                if any(indicator in server or indicator in via for indicator in indicators):
                    detected_cdn = cdn
                    break
            
            if detected_cdn:
                self.results['cloud_services']['cdn'] = detected_cdn
                logging.info(f"Detected CDN: {detected_cdn}")
            else:
                logging.info("No major CDN detected")
                
        except requests.RequestException as e:
            logging.warning(f"Failed to detect CDN: {str(e)}")
        
        return self.results['cloud_services']