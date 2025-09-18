"""
Constants and shared configuration values
"""

# Network configuration
DEFAULT_TIMEOUT = 5
DEFAULT_USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
MAX_WORKERS = 20
REQUEST_TIMEOUT = 10

# SSL verification exceptions
SSL_VERIFY_EXCEPTIONS = [
    'netlify.app', 'herokuapp.com', 'github.io', 
    'gitlab.io', 'firebaseapp.com'
]

# CDN detection phrases
CDN_BLOCK_PHRASES = [
    "just a moment", "checking your browser", "cloudflare",
    "attention required", "security check", "challenge platform",
    "enable javascript and cookies", "cf-ray", "__cf_chl_"
]

# Common file extensions for web scanning
WEB_EXTENSIONS = ['php', 'html', 'jsp', 'asp', 'aspx', 'json', 'xml', 'txt']

# Common web technology patterns
TECH_PATTERNS = {
    'wordpress': ['wp-content', 'wp-includes', 'wordpress'],
    'drupal': ['drupal.org', 'Drupal.settings'],
    'joomla': ['joomla', 'Joomla!'],
    'magento': ['magento', 'Mage.'],
    'laravel': ['laravel', 'csrf-token'],
    'django': ['csrfmiddlewaretoken', 'django'],
    'react': ['react', 'reactjs', 'createElement'],
    'angular': ['ng-', 'angular'],
    'vue': ['vue.js', 'Vue.'],
    'bootstrap': ['bootstrap'],
    'jquery': ['jquery'],
    'shopify': ['shopify', 'Shopify'],
    'woocommerce': ['woocommerce']
}

# Common API endpoints
COMMON_API_ENDPOINTS = [
    '/api', '/api/v1', '/api/v2', '/graphql', '/graphiql', 
    '/swagger', '/swagger-ui.html', '/swagger.json', 
    '/openapi', '/openapi.json', '/api-docs', '/rest', '/soap'
]

# Base technology-specific endpoints for intelligent scanning
BASE_ENDPOINTS = [
    'admin', 'api', 'dashboard', 'console', 'backend', 'portal',
    'secure', 'private', 'internal', 'system', 'control', 'manage',
    'auth', 'oauth', 'token', 'session', 'user', 'users', 'account',
    'config', 'settings', 'health', 'status', 'ping', 'test', 'debug',
    'log', 'logs', 'monitor', 'metrics', 'stats', 'statistics'
]

# Port service mapping
COMMON_SERVICES = {
    20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'TELNET',
    25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3',
    143: 'IMAP', 443: 'HTTPS', 993: 'IMAPS', 995: 'POP3S',
    1433: 'MSSQL', 1521: 'ORACLE', 3306: 'MYSQL', 3389: 'RDP',
    5432: 'POSTGRESQL', 5900: 'VNC', 6379: 'REDIS', 27017: 'MONGODB'
}
