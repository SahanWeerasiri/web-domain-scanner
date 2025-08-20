import os
from dotenv import load_dotenv

load_dotenv()

# API Keys
GEMINI_API_KEY = os.getenv('GEMINI_API_KEY')

# Common ports for service discovery
COMMON_PORTS = {
    21: 'FTP',
    22: 'SSH',
    80: 'HTTP',
    443: 'HTTPS',
    3306: 'MySQL',
    3389: 'RDP',
    8080: 'HTTP-Alt'
}

# Common subdomains for brute force
COMMON_SUBDOMAINS = ['www', 'mail', 'ftp', 'admin', 'api', 'test']

# Request headers
REQUEST_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
}

# CDN detection patterns
CDN_INDICATORS = {
    'cloudflare': ['cloudflare', 'cf-ray'],
    'akamai': ['akamai', 'akamaighost'],
    'fastly': ['fastly'],
    'aws': ['amazon', 'cloudfront']
}

# API endpoint patterns
API_PATTERNS = [
    r'/api/[^\s"\'<>]+',
    r'/rest/[^\s"\'<>]+',
    r'/graphql[^\s"\'<>]*',
    r'/v\d+/[^\s"\'<>]+',
    r'\.json[^\s"\'<>]*',
    r'/oauth[^\s"\'<>]*'
]

# Common S3 bucket patterns
COMMON_S3_BUCKETS = [
    "{domain}-assets",
    "{domain}-backup",
    "www.{domain}",
    "assets.{domain}",
    "media.{domain}"
]