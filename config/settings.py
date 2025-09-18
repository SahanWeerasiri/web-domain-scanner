import os
from dotenv import load_dotenv

load_dotenv()

# API Keys
GEMINI_API_KEY = os.getenv('GEMINI_API_KEY')
OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')
ANTHROPIC_API_KEY = os.getenv('ANTHROPIC_API_KEY')


# Common ports for service discovery
COMMON_PORTS = {
    20: 'FTP-DATA',
    21: 'FTP',
    22: 'SSH',
    23: 'TELNET',
    25: 'SMTP',
    53: 'DNS',
    80: 'HTTP',
    110: 'POP3',
    143: 'IMAP',
    443: 'HTTPS',
    993: 'IMAPS',
    995: 'POP3S',
    1433: 'MSSQL',
    1521: 'ORACLE',
    3306: 'MySQL',
    3389: 'RDP',
    5432: 'PostgreSQL',
    5900: 'VNC',
    6379: 'Redis',
    8080: 'HTTP-Alt',
    8443: 'HTTPS-Alt',
    27017: 'MongoDB'
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