#!/usr/bin/env python3
"""
Configurable Web Fingerprinting Module

This module provides comprehensive web technology fingerprinting with full pre-execution configuration.
"""

import logging
import time
import requests
import sys
import os
from typing import Dict, List, Set, Optional, Any
from urllib.parse import urlparse

# Add parent directories to path for imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..')))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
try:
    from modules.domain_enumeration.config import EnumerationConfig
    from modules.domain_enumeration.base import EnumerationErrorHandler, RateLimiter
except ImportError:
    from config import EnumerationConfig
    from base import EnumerationErrorHandler, RateLimiter

# Try to import Wappalyzer if available
try:
    import warnings
    warnings.filterwarnings("ignore", category=UserWarning, module="Wappalyzer")
    warnings.filterwarnings("ignore", category=UserWarning, message=".*pkg_resources.*")
    
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))
    import modules.domain_enumeration.utils.fingerprinting_wapplyzer as fingerprinting_wapplyzer
    WAPPALYZER_AVAILABLE = True
except ImportError:
    WAPPALYZER_AVAILABLE = False

# Import AI Integration module
try:
    from ai_integration import AIIntegration
    AI_AVAILABLE = True
except ImportError:
    AI_AVAILABLE = False
    AIIntegration = None

logger = logging.getLogger(__name__)


class WebFingerprintingConfig(EnumerationConfig):
    """Extended configuration for web fingerprinting with method-specific parameters"""
    
    def __init__(self):
        super().__init__()
        
        # Target Configuration
        self.default_targets = ['https://{domain}']
        self.include_www_variant = False  # Disabled by default to avoid DNS errors
        self.include_http = False  # Security: HTTP disabled by default
        self.custom_targets = []
        
        # Request Configuration
        self.follow_redirects = True
        self.max_redirects = 10
        self.verify_ssl = True
        self.user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        self.accept_language = 'en-US,en;q=0.9'
        
        # Analysis Configuration
        self.enable_wappalyzer = WAPPALYZER_AVAILABLE
        self.enable_ai_analysis = AI_AVAILABLE
        self.enable_security_analysis = True
        self.enable_performance_metrics = True
        self.enable_technology_insights = True
        self.content_analysis_limit = 1000  # Characters to analyze
        
        # Technology Detection Configuration
        self.detection_methods = ['headers', 'content', 'url_patterns', 'wappalyzer', 'ai']
        self.technology_categories = {
            'web_servers': True,
            'programming_languages': True,
            'frameworks': True,
            'cms': True,
            'javascript_libraries': True,
            'cdn': True,
            'analytics': True
        }
        
        # Security Analysis Configuration
        self.check_security_headers = True
        self.analyze_cookies = True
        self.ssl_analysis = True
        self.security_score_threshold = 70  # Percentage
        
        # Performance Configuration
        self.concurrent_requests = 3
        self.request_timeout = 30
        self.retry_attempts = 2
        self.retry_delay = 1
        
        # Output Configuration
        self.verbose_output = False
        self.save_raw_responses = False
        self.generate_summary = True
        self.output_format = 'detailed'  # detailed, summary, minimal


class ConfigurableWebFingerprinter:
    """
    Enhanced web fingerprinter with comprehensive pre-execution configuration.
    """
    
    def __init__(self, domain: str, config: WebFingerprintingConfig = None, 
                 ai_integration = None, **kwargs):
        """Initialize with full configuration"""
        self.domain = domain.lower().strip()
        self.config = config or WebFingerprintingConfig()
        
        # Apply any keyword argument overrides
        self._apply_config_overrides(kwargs)
        
        self.error_handler = EnumerationErrorHandler()
        self.rate_limiter = RateLimiter(self.config.rate_limit)
        self.ai_integration = ai_integration
        
        # Setup HTTP session with configured parameters
        self.session = self._setup_http_session()
        
        logger.info(f"ConfigurableWebFingerprinter initialized for domain: {self.domain}")
        self._log_configuration()
    
    def _apply_config_overrides(self, kwargs: Dict[str, Any]):
        """Apply configuration overrides from keyword arguments"""
        for key, value in kwargs.items():
            if hasattr(self.config, key):
                setattr(self.config, key, value)
                logger.debug(f"Overridden config.{key} = {value}")
    
    def _log_configuration(self):
        """Log the current configuration"""
        logger.info("=== Web Fingerprinting Configuration ===")
        logger.info(f"Domain: {self.domain}")
        logger.info(f"Detection methods: {', '.join(self.config.detection_methods)}")
        logger.info(f"Security analysis: {self.config.enable_security_analysis}")
        logger.info(f"Wappalyzer: {self.config.enable_wappalyzer}")
        logger.info(f"AI analysis: {self.config.enable_ai_analysis}")
        logger.info(f"Timeout: {self.config.request_timeout}s")
        logger.info(f"Concurrent requests: {self.config.concurrent_requests}")
        logger.info("========================================")
    
    def _setup_http_session(self) -> requests.Session:
        """Setup HTTP session with configured parameters"""
        session = requests.Session()
        
        # Configure headers
        session.headers.update({
            'User-Agent': self.config.user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': self.config.accept_language,
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        
        # Configure session options
        session.max_redirects = self.config.max_redirects
        session.verify = self.config.verify_ssl
        
        # Configure retry strategy
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry
        
        retry_strategy = Retry(
            total=self.config.retry_attempts,
            backoff_factor=self.config.retry_delay,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=self.config.concurrent_requests,
            pool_maxsize=self.config.concurrent_requests * 2
        )
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        return session
    
    def run_comprehensive_fingerprinting(self, custom_targets: List[str] = None) -> Dict[str, Any]:
        """
        Run comprehensive web fingerprinting with pre-configured parameters.
        
        Args:
            custom_targets: Optional list of specific URLs to fingerprint
            
        Returns:
            Dict containing all fingerprinting results, statistics, and metadata
        """
        start_time = time.time()
        
        results = {
            'domain': self.domain,
            'timestamp': time.time(),
            'configuration': self._get_config_summary(),
            'targets': {},
            'summary': {},
            'statistics': {},
            'errors': {}
        }
        
        try:
            # Generate targets
            targets = self._generate_targets(custom_targets)
            logger.info(f"Generated {len(targets)} targets for fingerprinting")
            
            # Fingerprint each target
            for target in targets:
                target_start = time.time()
                try:
                    if self.config.rate_limiting_enabled:
                        self.rate_limiter.acquire()
                    
                    target_result = self._fingerprint_single_target(target)
                    results['targets'][target] = target_result
                    
                    target_duration = time.time() - target_start
                    logger.info(f"Fingerprinted {target} in {target_duration:.2f}s")
                    
                except Exception as e:
                    logger.error(f"Failed to fingerprint {target}: {e}")
                    self.error_handler.handle_error("target_fingerprinting", e)
                    results['targets'][target] = {'error': str(e), 'timestamp': time.time()}
            
            # Generate summary if enabled
            if self.config.generate_summary:
                results['summary'] = self._generate_fingerprint_summary(results['targets'])
            
            # Compile statistics
            results['statistics'] = self._compile_statistics(results, start_time)
            results['errors'] = self.error_handler.get_errors()
            
            logger.info("=== Web Fingerprinting Completed ===")
            
        except Exception as e:
            logger.error(f"Comprehensive fingerprinting failed: {e}")
            self.error_handler.handle_error("comprehensive_fingerprinting", e)
            results['errors']['comprehensive_fingerprinting'] = [str(e)]
        
        return results
    
    def _generate_targets(self, custom_targets: List[str] = None) -> List[str]:
        """Generate targets based on configuration with DNS validation"""
        if custom_targets:
            return self._validate_targets(custom_targets)
        
        targets = []
        
        # Add default targets with domain substitution
        for target_template in self.config.default_targets:
            target = target_template.format(domain=self.domain)
            targets.append(target)
        
        # Add www variant if enabled (with DNS validation)
        if self.config.include_www_variant:
            www_target = f"https://www.{self.domain}"
            if self._can_resolve_domain(f"www.{self.domain}"):
                targets.append(www_target)
            else:
                logger.debug(f"Skipping www.{self.domain} - DNS resolution failed")
        
        # Add HTTP targets if enabled (not recommended for security)
        if self.config.include_http:
            http_targets = [
                f"http://{self.domain}",
            ]
            # Only add www HTTP if DNS resolves
            if self._can_resolve_domain(f"www.{self.domain}"):
                http_targets.append(f"http://www.{self.domain}")
            
            targets.extend(http_targets)
        
        # Add custom targets
        targets.extend(self.config.custom_targets)
        
        # Remove duplicates and validate
        unique_targets = list(set(targets))
        return self._validate_targets(unique_targets)
    
    def _can_resolve_domain(self, domain: str) -> bool:
        """Check if a domain can be resolved via DNS"""
        try:
            import socket
            socket.gethostbyname(domain)
            return True
        except (socket.gaierror, socket.error):
            return False
    
    def _validate_targets(self, targets: List[str]) -> List[str]:
        """Validate targets by checking DNS resolution"""
        validated_targets = []
        
        for target in targets:
            try:
                # Extract domain from URL
                from urllib.parse import urlparse
                parsed = urlparse(target)
                domain = parsed.netloc
                
                # Skip validation for localhost and IP addresses
                if domain in ['localhost', '127.0.0.1'] or domain.replace('.', '').isdigit():
                    validated_targets.append(target)
                    continue
                
                # Check DNS resolution
                if self._can_resolve_domain(domain):
                    validated_targets.append(target)
                else:
                    logger.debug(f"Skipping {target} - DNS resolution failed for {domain}")
                    
            except Exception as e:
                logger.debug(f"Error validating target {target}: {e}")
                # Include target anyway if validation fails
                validated_targets.append(target)
        
        return validated_targets
    
    def _fingerprint_single_target(self, target: str) -> Dict[str, Any]:
        """
        Perform comprehensive fingerprinting on a single target.
        
        Args:
            target: URL to fingerprint
            
        Returns:
            Dict: Comprehensive fingerprinting results
        """
        result = {
            'url': target,
            'timestamp': time.time(),
            'response_analysis': {},
            'header_analysis': {},
            'technology_detection': {},
            'security_analysis': {},
            'performance_metrics': {}
        }
        
        start_time = time.time()
        
        try:
            # Make HTTP request with configured parameters
            response = self.session.get(
                target, 
                timeout=self.config.request_timeout, 
                allow_redirects=self.config.follow_redirects
            )
            
            # Analyze response
            result['response_analysis'] = self._analyze_response(response)
            
            # Analyze headers
            result['header_analysis'] = self._analyze_headers(response.headers)
            
            # Detect technologies based on configured methods
            result['technology_detection'] = self._detect_technologies(target, response)
            
            # Analyze technology insights if enabled
            if self.config.enable_technology_insights:
                result['technology_insights'] = self._analyze_technology_insights(result['technology_detection'])
            
            # Analyze security if enabled
            if self.config.enable_security_analysis:
                result['security_analysis'] = self._analyze_security(response)
            
            # Performance metrics if enabled
            if self.config.enable_performance_metrics:
                result['performance_metrics'] = {
                    'response_time': time.time() - start_time,
                    'content_length': len(response.content),
                    'status_code': response.status_code,
                    'redirect_count': len(response.history)
                }
            
        except requests.RequestException as e:
            logger.warning(f"Request failed for {target}: {str(e)}")
            result['error'] = str(e)
            self.error_handler.handle_error("http_request", e)
        
        return result
    
    def _analyze_response(self, response: requests.Response) -> Dict[str, Any]:
        """Analyze HTTP response for basic information"""
        analysis = {
            'status_code': response.status_code,
            'reason': response.reason,
            'encoding': response.encoding,
            'content_type': response.headers.get('Content-Type', ''),
            'content_length': len(response.content),
            'url': response.url,
            'redirect_chain': [r.url for r in response.history],
            'is_redirect': len(response.history) > 0,
            'final_url': response.url
        }
        
        # Analyze content if it's text-based and within limit
        content_type = analysis['content_type'].lower()
        if 'text' in content_type or 'html' in content_type:
            try:
                content = response.text[:self.config.content_analysis_limit]
                analysis['content_preview'] = content[:200] + '...' if len(content) > 200 else content
                analysis['has_html'] = '<html' in content.lower()
                analysis['has_javascript'] = '<script' in content.lower()
                analysis['has_css'] = '<style' in content.lower() or '.css' in content.lower()
                analysis['title'] = self._extract_title(content)
                analysis['meta_info'] = self._extract_meta_info(content)
            except Exception as e:
                logger.debug(f"Error analyzing content: {e}")
        
        return analysis
    
    def _analyze_headers(self, headers: Dict) -> Dict[str, Any]:
        """Analyze HTTP headers for server and technology information"""
        analysis = {
            'server': headers.get('Server', 'Not found'),
            'x_powered_by': headers.get('X-Powered-By', 'Not found'),
            'x_generator': headers.get('X-Generator', 'Not found'),
            'x_frame_options': headers.get('X-Frame-Options', 'Not found'),
            'content_security_policy': headers.get('Content-Security-Policy', 'Not found'),
            'strict_transport_security': headers.get('Strict-Transport-Security', 'Not found'),
            'x_content_type_options': headers.get('X-Content-Type-Options', 'Not found'),
            'x_xss_protection': headers.get('X-XSS-Protection', 'Not found'),
            'set_cookie': headers.get('Set-Cookie', 'Not found'),
            'cache_control': headers.get('Cache-Control', 'Not found'),
            'expires': headers.get('Expires', 'Not found'),
            'last_modified': headers.get('Last-Modified', 'Not found'),
            'etag': headers.get('ETag', 'Not found')
        }
        
        # Detect server technology from Server header
        server_info = self._parse_server_header(analysis['server'])
        analysis['server_info'] = server_info
        
        # Detect framework from X-Powered-By
        framework_info = self._parse_powered_by_header(analysis['x_powered_by'])
        analysis['framework_info'] = framework_info
        
        return analysis
    
    def _detect_technologies(self, url: str, response: requests.Response) -> Dict[str, Any]:
        """Detect web technologies using configured methods"""
        technologies = {}
        
        # Wappalyzer detection if enabled and available
        if 'wappalyzer' in self.config.detection_methods and self.config.enable_wappalyzer and WAPPALYZER_AVAILABLE:
            try:
                wappalyzer_result = fingerprinting_wapplyzer.fingerprint_technology(url)
                if isinstance(wappalyzer_result, (list, set)):
                    technologies['wappalyzer_detected'] = list(wappalyzer_result)
                elif wappalyzer_result:
                    technologies['wappalyzer_detected'] = [str(wappalyzer_result)]
            except Exception as e:
                logger.warning(f"Wappalyzer detection failed: {e}")
                technologies['wappalyzer_error'] = str(e)
        
        # AI-enhanced technology detection if enabled
        if 'ai' in self.config.detection_methods and self.config.enable_ai_analysis and self.ai_integration:
            try:
                page_content = {
                    'html': response.text if hasattr(response, 'text') else '',
                    'headers': dict(response.headers),
                    'status_code': response.status_code,
                    'url': url
                }
                ai_detected = self.ai_integration.detect_technology(page_content)
                if ai_detected:
                    technologies['ai_detected'] = list(ai_detected)
            except Exception as e:
                logger.warning(f"AI technology detection failed: {e}")
                technologies['ai_error'] = str(e)
        
        # Header-based detection
        if 'headers' in self.config.detection_methods:
            technologies['header_detected'] = self._detect_from_headers(response.headers)
        
        # Content-based detection
        if 'content' in self.config.detection_methods and hasattr(response, 'text'):
            technologies['content_detected'] = self._detect_from_content(response.text)
        
        # URL pattern detection
        if 'url_patterns' in self.config.detection_methods and hasattr(response, 'text'):
            technologies['url_patterns'] = self._detect_from_url_patterns(response.text)
        
        return technologies
    
    def _analyze_security(self, response: requests.Response) -> Dict[str, Any]:
        """Analyze security headers and configurations"""
        if not self.config.enable_security_analysis:
            return {'disabled': True}
        
        security = {
            'security_headers': {},
            'ssl_info': {},
            'cookie_security': {},
            'security_score': 0,
            'missing_headers': [],
            'recommendations': []
        }
        
        headers = response.headers
        
        # Security headers analysis if enabled
        if self.config.check_security_headers:
            security_headers = {
                'X-Frame-Options': headers.get('X-Frame-Options'),
                'Content-Security-Policy': headers.get('Content-Security-Policy'),
                'Strict-Transport-Security': headers.get('Strict-Transport-Security'),
                'X-Content-Type-Options': headers.get('X-Content-Type-Options'),
                'X-XSS-Protection': headers.get('X-XSS-Protection'),
                'Referrer-Policy': headers.get('Referrer-Policy'),
                'Permissions-Policy': headers.get('Permissions-Policy')
            }
            
            security['security_headers'] = security_headers
            
            # Calculate security score
            score = 0
            missing_headers = []
            
            for header, value in security_headers.items():
                if value and value != 'Not found':
                    score += 1
                else:
                    missing_headers.append(header)
            
            security['security_score'] = (score / len(security_headers)) * 100
            security['missing_headers'] = missing_headers
            
            # Generate recommendations
            recommendations = []
            if 'X-Frame-Options' in missing_headers:
                recommendations.append("Add X-Frame-Options header to prevent clickjacking")
            if 'Content-Security-Policy' in missing_headers:
                recommendations.append("Implement Content-Security-Policy to prevent XSS")
            if 'Strict-Transport-Security' in missing_headers:
                recommendations.append("Add HSTS header to enforce HTTPS")
            
            security['recommendations'] = recommendations
        
        # Cookie security analysis if enabled
        if self.config.analyze_cookies:
            set_cookie = headers.get('Set-Cookie', '')
            security['cookie_security'] = {
                'has_secure': 'Secure' in set_cookie,
                'has_httponly': 'HttpOnly' in set_cookie,
                'has_samesite': 'SameSite' in set_cookie,
                'recommendations': []
            }
        
        # SSL information if enabled
        if self.config.ssl_analysis:
            if response.url.startswith('https://'):
                security['ssl_info'] = {
                    'uses_ssl': True,
                    'url_scheme': 'https',
                    'ssl_grade': 'Good' if security.get('security_score', 0) >= self.config.security_score_threshold else 'Needs Improvement'
                }
            else:
                security['ssl_info'] = {
                    'uses_ssl': False,
                    'url_scheme': 'http',
                    'ssl_grade': 'Poor - No SSL'
                }
                security['recommendations'].append("Enable HTTPS/SSL for secure communication")
        
        return security
    
    def _parse_server_header(self, server_header: str) -> Dict[str, Any]:
        """Parse Server header for technology information"""
        if not server_header or server_header == 'Not found':
            return {'name': 'Unknown', 'version': 'Unknown', 'components': []}
        
        server_patterns = {
            'nginx': 'Nginx',
            'apache': 'Apache',
            'iis': 'Microsoft IIS',
            'cloudflare': 'Cloudflare',
            'lighttpd': 'Lighttpd',
            'tomcat': 'Apache Tomcat',
            'jetty': 'Eclipse Jetty'
        }
        
        server_lower = server_header.lower()
        detected_server = 'Unknown'
        
        for pattern, name in server_patterns.items():
            if pattern in server_lower:
                detected_server = name
                break
        
        return {
            'name': detected_server,
            'raw_header': server_header,
            'components': server_header.split() if ' ' in server_header else [server_header]
        }
    
    def _parse_powered_by_header(self, powered_by_header: str) -> Dict[str, Any]:
        """Parse X-Powered-By header for framework information"""
        if not powered_by_header or powered_by_header == 'Not found':
            return {'framework': 'Unknown', 'version': 'Unknown'}
        
        framework_patterns = {
            'php': 'PHP',
            'asp.net': 'ASP.NET',
            'express': 'Express.js',
            'django': 'Django',
            'rails': 'Ruby on Rails',
            'flask': 'Flask',
            'laravel': 'Laravel'
        }
        
        powered_by_lower = powered_by_header.lower()
        detected_framework = 'Unknown'
        
        for pattern, name in framework_patterns.items():
            if pattern in powered_by_lower:
                detected_framework = name
                break
        
        return {
            'framework': detected_framework,
            'raw_header': powered_by_header
        }
    
    def _detect_from_headers(self, headers: Dict) -> List[str]:
        """Detect technologies from HTTP headers"""
        detected = []
        
        technology_headers = {
            'X-Powered-By': ['PHP', 'ASP.NET', 'Express'],
            'Server': ['Nginx', 'Apache', 'IIS', 'Cloudflare'],
            'X-Generator': ['WordPress', 'Drupal', 'Joomla'],
            'X-Framework': ['Laravel', 'Django', 'Rails']
        }
        
        for header_name, technologies in technology_headers.items():
            header_value = headers.get(header_name, '').lower()
            for tech in technologies:
                if tech.lower() in header_value:
                    detected.append(tech)
        
        return detected
    
    def _detect_from_content(self, content: str) -> List[str]:
        """Detect technologies from page content"""
        detected = []
        
        if not content:
            return detected
        
        content_lower = content.lower()
        
        content_patterns = {
            'wordpress': ['wp-content', 'wp-includes', 'wordpress'],
            'drupal': ['drupal.js', 'drupal.settings', 'sites/default'],
            'joomla': ['joomla!', 'index.php?option=com_'],
            'react': ['react.js', 'reactjs', '__react'],
            'angular': ['angular.js', 'ng-app', 'angular'],
            'vue': ['vue.js', 'vuejs', '__vue'],
            'jquery': ['jquery.js', 'jquery.min.js', '$jquery'],
            'bootstrap': ['bootstrap.css', 'bootstrap.js', 'bootstrap'],
            'font awesome': ['font-awesome', 'fontawesome'],
            'google analytics': ['google-analytics', 'gtag', 'ga(']
        }
        
        for technology, patterns in content_patterns.items():
            for pattern in patterns:
                if pattern in content_lower:
                    detected.append(technology.title())
                    break
        
        return list(set(detected))
    
    def _detect_from_url_patterns(self, content: str) -> List[str]:
        """Detect technologies from URL patterns in content"""
        detected = []
        
        if not content:
            return detected
        
        url_patterns = {
            'CDN': ['cdn.', 'cloudflare', 'amazonaws', 'azure'],
            'Google Services': ['googleapis.com', 'googletagmanager', 'google-analytics'],
            'jQuery': ['ajax.googleapis.com/ajax/libs/jquery'],
            'Font Awesome': ['fontawesome.com', 'font-awesome'],
            'Bootstrap': ['maxcdn.bootstrapcdn.com', 'bootstrap']
        }
        
        content_lower = content.lower()
        
        for technology, patterns in url_patterns.items():
            for pattern in patterns:
                if pattern in content_lower:
                    detected.append(technology)
                    break
        
        return list(set(detected))
    
    def _extract_title(self, content: str) -> str:
        """Extract page title from HTML content"""
        try:
            import re
            title_match = re.search(r'<title[^>]*>([^<]+)</title>', content, re.IGNORECASE)
            if title_match:
                return title_match.group(1).strip()
        except Exception:
            pass
        return 'Not found'
    
    def _extract_meta_info(self, content: str) -> Dict[str, Any]:
        """Extract meta information from HTML content"""
        meta_info = {
            'generator': 'Not found',
            'description': 'Not found',
            'keywords': 'Not found'
        }
        
        try:
            import re
            
            generator_match = re.search(r'<meta[^>]*name=["\']generator["\'][^>]*content=["\']([^"\']+)["\']', content, re.IGNORECASE)
            if generator_match:
                meta_info['generator'] = generator_match.group(1)
            
            desc_match = re.search(r'<meta[^>]*name=["\']description["\'][^>]*content=["\']([^"\']+)["\']', content, re.IGNORECASE)
            if desc_match:
                meta_info['description'] = desc_match.group(1)[:100]
            
            keywords_match = re.search(r'<meta[^>]*name=["\']keywords["\'][^>]*content=["\']([^"\']+)["\']', content, re.IGNORECASE)
            if keywords_match:
                meta_info['keywords'] = keywords_match.group(1)
                
        except Exception as e:
            logger.debug(f"Error extracting meta info: {e}")
        
        return meta_info
    
    def _analyze_technology_insights(self, technologies: Dict) -> Dict[str, Any]:
        """Analyze detected technologies and provide insights"""
        if not self.config.enable_technology_insights:
            return {'disabled': True}
        
        insights = {
            'technology_stack': {
                'web_server': [],
                'programming_language': [],
                'framework': [],
                'cms': [],
                'javascript_libraries': [],
                'cdn': [],
                'analytics': []
            },
            'security_implications': [],
            'performance_notes': []
        }
        
        # Categorize technologies
        all_techs = []
        for method, tech_list in technologies.items():
            if isinstance(tech_list, list):
                all_techs.extend(tech_list)
        
        for tech in set(all_techs):
            tech_lower = tech.lower()
            
            # Categorize based on configured categories
            if self.config.technology_categories['web_servers'] and any(server in tech_lower for server in ['apache', 'nginx', 'iis', 'cloudflare']):
                insights['technology_stack']['web_server'].append(tech)
            
            if self.config.technology_categories['programming_languages'] and any(lang in tech_lower for lang in ['php', 'python', 'java', 'asp.net', 'node.js']):
                insights['technology_stack']['programming_language'].append(tech)
            
            if self.config.technology_categories['frameworks'] and any(fw in tech_lower for fw in ['django', 'flask', 'laravel', 'express', 'rails']):
                insights['technology_stack']['framework'].append(tech)
            
            if self.config.technology_categories['cms'] and any(cms in tech_lower for cms in ['wordpress', 'drupal', 'joomla', 'moodle']):
                insights['technology_stack']['cms'].append(tech)
            
            if self.config.technology_categories['javascript_libraries'] and any(js in tech_lower for js in ['jquery', 'react', 'angular', 'vue']):
                insights['technology_stack']['javascript_libraries'].append(tech)
            
            if self.config.technology_categories['cdn'] and any(cdn in tech_lower for cdn in ['cloudflare', 'jsdelivr', 'cdnjs', 'amazonaws']):
                insights['technology_stack']['cdn'].append(tech)
            
            if self.config.technology_categories['analytics'] and any(analytics in tech_lower for analytics in ['google analytics', 'gtag']):
                insights['technology_stack']['analytics'].append(tech)
        
        return insights
    
    def _generate_fingerprint_summary(self, targets_results: Dict) -> Dict[str, Any]:
        """Generate a summary of fingerprinting results"""
        summary = {
            'total_targets': len(targets_results),
            'successful_scans': 0,
            'failed_scans': 0,
            'unique_technologies': set(),
            'common_servers': {},
            'security_score_avg': 0,
            'ssl_enabled': 0
        }
        
        security_scores = []
        
        for target, result in targets_results.items():
            if 'error' in result:
                summary['failed_scans'] += 1
                continue
            
            summary['successful_scans'] += 1
            
            # Collect technologies
            tech_detection = result.get('technology_detection', {})
            for method, technologies in tech_detection.items():
                if isinstance(technologies, list):
                    summary['unique_technologies'].update(technologies)
            
            # Server information
            header_analysis = result.get('header_analysis', {})
            server_info = header_analysis.get('server_info', {})
            server_name = server_info.get('name', 'Unknown')
            
            if server_name not in summary['common_servers']:
                summary['common_servers'][server_name] = 0
            summary['common_servers'][server_name] += 1
            
            # Security analysis
            security_analysis = result.get('security_analysis', {})
            security_score = security_analysis.get('security_score', 0)
            security_scores.append(security_score)
            
            ssl_info = security_analysis.get('ssl_info', {})
            if ssl_info.get('uses_ssl', False):
                summary['ssl_enabled'] += 1
        
        # Calculate averages
        if security_scores:
            summary['security_score_avg'] = sum(security_scores) / len(security_scores)
        
        summary['unique_technologies'] = list(summary['unique_technologies'])
        
        return summary
    
    def _get_config_summary(self) -> Dict[str, Any]:
        """Get configuration summary for results"""
        return {
            'detection_methods': self.config.detection_methods,
            'technology_categories': self.config.technology_categories,
            'security_analysis': self.config.enable_security_analysis,
            'wappalyzer_enabled': self.config.enable_wappalyzer,
            'ai_analysis_enabled': self.config.enable_ai_analysis
        }
    
    def _compile_statistics(self, results: Dict, start_time: float) -> Dict[str, Any]:
        """Compile execution statistics"""
        total_duration = time.time() - start_time
        total_targets = len(results.get('targets', {}))
        
        successful_targets = 0
        for target_result in results.get('targets', {}).values():
            if 'error' not in target_result:
                successful_targets += 1
        
        return {
            'total_duration': total_duration,
            'total_targets': total_targets,
            'successful_targets': successful_targets,
            'success_rate': (successful_targets / total_targets * 100) if total_targets > 0 else 0,
            'completion_time': time.strftime('%Y-%m-%d %H:%M:%S')
        }
    
    def get_errors(self) -> Dict:
        """Get all errors encountered during web fingerprinting"""
        return self.error_handler.get_errors()


def create_fingerprinting_config_from_args(args) -> WebFingerprintingConfig:
    """Create fingerprinting configuration from command line arguments"""
    config = WebFingerprintingConfig()
    
    # Target configuration
    if hasattr(args, 'targets') and args.targets:
        config.custom_targets = args.targets
    
    if hasattr(args, 'include_http'):
        config.include_http = args.include_http
    
    if hasattr(args, 'include_www'):
        config.include_www_variant = args.include_www
    
    # Detection configuration
    if hasattr(args, 'detection_methods') and args.detection_methods:
        config.detection_methods = args.detection_methods
    
    if hasattr(args, 'disable_wappalyzer'):
        config.enable_wappalyzer = not args.disable_wappalyzer
    
    if hasattr(args, 'disable_ai'):
        config.enable_ai_analysis = not args.disable_ai
    
    if hasattr(args, 'disable_security'):
        config.enable_security_analysis = not args.disable_security
    
    # Performance configuration
    if hasattr(args, 'timeout'):
        config.request_timeout = args.timeout
    
    if hasattr(args, 'concurrent'):
        config.concurrent_requests = args.concurrent
    
    # Output configuration
    if hasattr(args, 'verbose'):
        config.verbose_output = args.verbose
    
    if hasattr(args, 'output_format'):
        config.output_format = args.output_format
    
    return config

def execute_fingerprinting(domain: str,
                          targets: List[str] = None,
                          include_http: bool = False,
                          include_www: bool = False,
                          detection_methods: List[str] = None,
                          disable_wappalyzer: bool = False,
                          disable_ai: bool = False,
                          disable_security: bool = False,
                          timeout: int = 30,
                          concurrent: int = 3,
                          verbose: bool = False,
                          output_format: str = 'detailed'):
    """
    Enhanced fingerprinting function with direct parameter configuration
    
    Args:
        domain: Target domain to fingerprint
        targets: Specific URLs to fingerprint (default: None - auto-generate)
        include_http: Include HTTP targets (default: False - not recommended)
        include_www: Include www variant (default: False - avoid DNS errors)
        detection_methods: Technology detection methods (default: ['headers', 'content', 'url_patterns', 'wappalyzer'])
        disable_wappalyzer: Disable Wappalyzer detection (default: False)
        disable_ai: Disable AI analysis (default: False)
        disable_security: Disable security analysis (default: False)
        timeout: Request timeout in seconds (default: 30)
        concurrent: Concurrent requests (default: 3)
        verbose: Enable verbose output (default: False)
        output_format: Output format - 'detailed', 'summary', or 'minimal' (default: 'detailed')
    
    Returns:
        Dict: Complete fingerprinting results
    """
    # Set defaults if not provided
    if detection_methods is None:
        detection_methods = ['headers', 'content', 'url_patterns', 'wappalyzer']
    
    # Configure logging
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    # Create configuration object
    config = WebFingerprintingConfig()
    config.custom_targets = targets or []
    config.include_http = include_http
    config.include_www_variant = include_www
    config.detection_methods = detection_methods
    config.enable_wappalyzer = not disable_wappalyzer
    config.enable_ai_analysis = not disable_ai
    config.enable_security_analysis = not disable_security
    config.request_timeout = timeout
    config.concurrent_requests = concurrent
    config.verbose_output = verbose
    config.output_format = output_format
    
    # Create and run fingerprinter
    fingerprinter = ConfigurableWebFingerprinter(domain, config)
    results = fingerprinter.run_comprehensive_fingerprinting(targets)
    
    # Display results based on output format
    _display_results(results, config)
    
    return results


def main():
    """Enhanced main function with comprehensive configuration"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Configurable Web Technology Fingerprinting")
    parser.add_argument("domain", help="Target domain to fingerprint")
    
    # Target Configuration
    parser.add_argument("--targets", nargs='+', help="Specific URLs to fingerprint")
    parser.add_argument("--include-http", action='store_true', help="Include HTTP targets (not recommended)")
    parser.add_argument("--include-www", action='store_true', default=True, help="Include www variant")
    
    # Detection Configuration
    parser.add_argument("--detection-methods", nargs='+',
                       choices=['headers', 'content', 'url_patterns', 'wappalyzer', 'ai'],
                       default=['headers', 'content', 'url_patterns', 'wappalyzer'],
                       help="Technology detection methods to use")
    
    parser.add_argument("--disable-wappalyzer", action='store_true', help="Disable Wappalyzer detection")
    parser.add_argument("--disable-ai", action='store_true', help="Disable AI analysis")
    parser.add_argument("--disable-security", action='store_true', help="Disable security analysis")
    
    # Performance Configuration
    parser.add_argument("--timeout", type=int, default=30, help="Request timeout in seconds")
    parser.add_argument("--concurrent", type=int, default=3, help="Concurrent requests")
    
    # Output Configuration
    parser.add_argument("--verbose", action='store_true', help="Enable verbose output")
    parser.add_argument("--output-format", choices=['detailed', 'summary', 'minimal'], 
                       default='detailed', help="Output format")
    
    args = parser.parse_args()
    
    # Configure logging
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    # Create configuration from arguments
    config = create_fingerprinting_config_from_args(args)
    
    # Create and run fingerprinter
    fingerprinter = ConfigurableWebFingerprinter(args.domain, config)
    results = fingerprinter.run_comprehensive_fingerprinting(args.targets)
    
    # Display results based on output format
    _display_results(results, config)


def _display_results(results: Dict, config: WebFingerprintingConfig):
    """Display results based on configuration"""
    output_format = config.output_format
    
    if output_format == 'minimal':
        _display_minimal_results(results)
    elif output_format == 'summary':
        _display_summary_results(results)
    else:  # detailed
        _display_detailed_results(results)


def _display_minimal_results(results: Dict):
    """Display minimal results"""
    domain = results['domain']
    targets = results.get('targets', {})
    
    print(f"\n=== Web Fingerprinting Results for {domain} ===")
    print(f"Targets scanned: {len(targets)}")
    
    for target, result in targets.items():
        status = "✓" if 'error' not in result else "✗"
        tech_count = 0
        if 'error' not in result:
            tech_detection = result.get('technology_detection', {})
            for tech_list in tech_detection.values():
                if isinstance(tech_list, list):
                    tech_count += len(tech_list)
        
        print(f"{status} {target}: {tech_count} technologies")


def _display_summary_results(results: Dict):
    """Display summary results"""
    domain = results['domain']
    summary = results.get('summary', {})
    statistics = results.get('statistics', {})
    
    print(f"\n=== Web Fingerprinting Summary for {domain} ===")
    print(f"Execution time: {statistics.get('total_duration', 0):.2f}s")
    print(f"Success rate: {statistics.get('success_rate', 0):.1f}%")
    print(f"Unique technologies: {len(summary.get('unique_technologies', []))}")
    print(f"Average security score: {summary.get('security_score_avg', 0):.1f}%")
    
    if summary.get('common_servers'):
        print("\nCommon Servers:")
        for server, count in summary['common_servers'].items():
            print(f"  {server}: {count}")


def _display_detailed_results(results: Dict):
    """Display detailed results"""
    domain = results['domain']
    targets = results.get('targets', {})
    
    print(f"\n=== Web Fingerprinting Results for {domain} ===")
    
    for target, result in targets.items():
        print(f"\n--- {target} ---")
        
        if 'error' in result:
            print(f"Error: {result['error']}")
            continue
        
        # Basic info
        response_analysis = result.get('response_analysis', {})
        print(f"Status: {response_analysis.get('status_code', 'Unknown')}")
        print(f"Server: {result.get('header_analysis', {}).get('server', 'Unknown')}")
        
        # Technologies
        tech_detection = result.get('technology_detection', {})
        all_techs = set()
        for tech_list in tech_detection.values():
            if isinstance(tech_list, list):
                all_techs.update(tech_list)
        
        print(f"Technologies: {', '.join(all_techs) if all_techs else 'None'}")
        
        # Security
        security = result.get('security_analysis', {})
        if security and not security.get('disabled'):
            print(f"Security Score: {security.get('security_score', 0):.1f}%")
            print(f"SSL: {'Enabled' if security.get('ssl_info', {}).get('uses_ssl') else 'Disabled'}")


if __name__ == "__main__":
    main()