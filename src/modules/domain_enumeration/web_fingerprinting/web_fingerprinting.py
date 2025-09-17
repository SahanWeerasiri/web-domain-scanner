#!/usr/bin/env python3
"""
Web Fingerprinting Module

This module provides comprehensive web technology fingerprinting capabilities.
It analyzes HTTP responses, headers, and content to identify web technologies,
frameworks, servers, and security configurations.

Key Features:
- HTTP header analysis
- Server software identification
- Web framework detection
- Wappalyzer integration for technology detection
- Security header analysis
- Response code and content analysis

Author: Web Domain Scanner Project
License: See LICENSE file in project root
"""

import logging
import time
import requests
import sys
import os
from typing import Dict, List, Set, Optional, TYPE_CHECKING
from urllib.parse import urlparse

# Add parent directories to path for imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..')))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from config import EnumerationConfig
from base import EnumerationErrorHandler, RateLimiter

# Try to import Wappalyzer if available
try:
    # Suppress deprecation warnings for pkg_resources
    import warnings
    warnings.filterwarnings("ignore", category=UserWarning, module="Wappalyzer")
    warnings.filterwarnings("ignore", category=UserWarning, message=".*pkg_resources.*")
    
    # Add the path where fingerprinting_wapplyzer module might be located
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))
    import fingerprinting_wapplyzer
    WAPPALYZER_AVAILABLE = True
except ImportError:
    WAPPALYZER_AVAILABLE = False
    logger = logging.getLogger(__name__)
    logger.warning("Wappalyzer module not available. Technology detection will be limited.")

# Import AI Integration module for enhanced technology detection
if TYPE_CHECKING:
    from ai_integration import AIIntegration

try:
    from ai_integration import AIIntegration
    AI_AVAILABLE = True
except ImportError:
    AI_AVAILABLE = False
    AIIntegration = None

logger = logging.getLogger(__name__)


class WebFingerprinter:
    """
    Web technology fingerprinting class.
    
    This class analyzes web responses to identify technologies, frameworks,
    server software, and security configurations.
    """
    
    def __init__(self, domain: str, config: EnumerationConfig = None, ai_integration = None):
        """Initialize web fingerprinter"""
        self.domain = domain.lower().strip()
        self.config = config or EnumerationConfig()
        self.error_handler = EnumerationErrorHandler()
        self.rate_limiter = RateLimiter(self.config.rate_limit)
        
        # Initialize AI integration if available
        self.ai_integration = ai_integration
        if AI_AVAILABLE and not self.ai_integration:
            # Try to create AI integration with environment variables
            api_keys = {
                'gemini_api_key': os.getenv('GEMINI_API_KEY'),
                'openai_api_key': os.getenv('OPENAI_API_KEY'),
                'anthropic_api_key': os.getenv('ANTHROPIC_API_KEY')
            }
            if any(api_keys.values()):
                self.ai_integration = AIIntegration(**{k: v for k, v in api_keys.items() if v})
                logger.info("AI integration initialized for enhanced technology detection")
        
        # Set up HTTP session
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                         '(KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        
        logger.info(f"WebFingerprinter initialized for domain: {self.domain}")
    
    def run_web_fingerprinting(self, targets: List[str] = None) -> Dict:
        """
        Run comprehensive web fingerprinting.
        
        Args:
            targets: List of URLs/domains to fingerprint. If None, uses default targets.
            
        Returns:
            Dict: Fingerprinting results for each target
        """
        logger.info(f"Starting web fingerprinting for domain: {self.domain}")
        
        if not targets:
            targets = self._generate_default_targets()
        
        results = {}
        
        for target in targets:
            logger.debug(f"Fingerprinting target: {target}")
            
            try:
                # Apply rate limiting
                if self.config.rate_limiting_enabled:
                    self.rate_limiter.acquire()
                
                # Perform fingerprinting
                fingerprint_result = self._fingerprint_target(target)
                results[target] = fingerprint_result
                
                logger.info(f"Fingerprinting completed for {target}")
                
            except Exception as e:
                logger.warning(f"Failed to fingerprint {target}: {str(e)}")
                self.error_handler.handle_error("web_fingerprinting", e)
                results[target] = {
                    'error': str(e),
                    'timestamp': time.time()
                }
        
        logger.info(f"Web fingerprinting completed for {len(results)} targets")
        return results
    
    def _generate_default_targets(self) -> List[str]:
        """Generate default targets for fingerprinting"""
        targets = [
            f"https://{self.domain}",
        ]
        
        # Only add www variant if it's likely to exist
        # Check if www subdomain was found in passive enumeration
        try:
            www_domain = f"www.{self.domain}"
            # Do a quick DNS check before adding to targets
            import socket
            try:
                socket.gethostbyname(www_domain)
                targets.append(f"https://{www_domain}")
                logger.debug(f"Added www variant: {www_domain}")
            except socket.gaierror:
                logger.debug(f"Skipping www variant - DNS resolution failed for {www_domain}")
        except Exception as e:
            logger.debug(f"Error checking www variant: {e}")
        
        # Note: HTTP targets commented out for security
        # f"http://{self.domain}",
        # f"http://www.{self.domain}"
        
        logger.debug(f"Generated {len(targets)} default targets")
        return targets
    
    def _fingerprint_target(self, target: str) -> Dict:
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
            # Make HTTP request
            response = self.session.get(target, timeout=self.config.timeout, allow_redirects=True)
            
            # Analyze response
            result['response_analysis'] = self._analyze_response(response)
            
            # Analyze headers
            result['header_analysis'] = self._analyze_headers(response.headers)
            
            # Detect technologies
            result['technology_detection'] = self._detect_technologies(target, response)
            
            # Analyze technology insights
            result['technology_insights'] = self._analyze_technology_insights(result['technology_detection'])
            
            # Analyze security
            result['security_analysis'] = self._analyze_security(response)
            
            # Performance metrics
            result['performance_metrics'] = {
                'response_time': time.time() - start_time,
                'content_length': len(response.content),
                'status_code': response.status_code
            }
            
        except requests.RequestException as e:
            logger.warning(f"Request failed for {target}: {str(e)}")
            result['error'] = str(e)
            self.error_handler.handle_error("http_request", e)
        
        return result
    
    def _analyze_response(self, response: requests.Response) -> Dict:
        """Analyze HTTP response for basic information"""
        analysis = {
            'status_code': response.status_code,
            'reason': response.reason,
            'encoding': response.encoding,
            'content_type': response.headers.get('Content-Type', ''),
            'content_length': len(response.content),
            'url': response.url,
            'redirect_chain': [r.url for r in response.history],
            'is_redirect': len(response.history) > 0
        }
        
        # Analyze content if it's text-based
        if 'text' in analysis['content_type'].lower() or 'html' in analysis['content_type'].lower():
            try:
                content = response.text[:1000]  # First 1000 chars for analysis
                analysis['has_html'] = '<html' in content.lower()
                analysis['has_javascript'] = '<script' in content.lower()
                analysis['has_css'] = '<style' in content.lower() or '.css' in content.lower()
                analysis['title'] = self._extract_title(content)
                analysis['meta_info'] = self._extract_meta_info(content)
            except Exception as e:
                logger.debug(f"Error analyzing content: {e}")
        
        return analysis
    
    def _analyze_headers(self, headers: Dict) -> Dict:
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
    
    def _detect_technologies(self, url: str, response: requests.Response) -> Dict:
        """Detect web technologies using various methods"""
        technologies = {
            'wappalyzer_detected': [],
            'header_detected': [],
            'content_detected': [],
            'url_patterns': []
        }
        
        # Wappalyzer detection if available
        if WAPPALYZER_AVAILABLE:
            try:
                wappalyzer_result = fingerprinting_wapplyzer.fingerprint_technology(url)
                if isinstance(wappalyzer_result, (list, set)):
                    technologies['wappalyzer_detected'] = list(wappalyzer_result)
                elif wappalyzer_result:
                    technologies['wappalyzer_detected'] = [str(wappalyzer_result)]
                
                logger.info(f"Wappalyzer detected technologies: {technologies['wappalyzer_detected']}")
            except Exception as e:
                logger.warning(f"Wappalyzer detection failed: {e}")
        
        # AI-enhanced technology detection if available
        if self.ai_integration:
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
                    logger.info(f"AI detected technologies: {technologies['ai_detected']}")
            except Exception as e:
                logger.warning(f"AI technology detection failed: {e}")
        
        # Header-based detection
        technologies['header_detected'] = self._detect_from_headers(response.headers)
        
        # Content-based detection
        if hasattr(response, 'text'):
            technologies['content_detected'] = self._detect_from_content(response.text)
        
        # URL pattern detection
        technologies['url_patterns'] = self._detect_from_url_patterns(response.text if hasattr(response, 'text') else '')
        
        return technologies
    
    def _analyze_security(self, response: requests.Response) -> Dict:
        """Analyze security headers and configurations"""
        security = {
            'security_headers': {},
            'ssl_info': {},
            'cookie_security': {},
            'security_score': 0,
            'missing_headers': [],
            'recommendations': []
        }
        
        headers = response.headers
        
        # Security headers analysis
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
        
        # Calculate security score and track missing headers
        score = 0
        missing_headers = []
        recommendations = []
        
        for header, value in security_headers.items():
            if value and value != 'Not found':
                score += 1
            else:
                missing_headers.append(header)
                
                # Add specific recommendations
                if header == 'X-Frame-Options':
                    recommendations.append("Add X-Frame-Options header to prevent clickjacking attacks")
                elif header == 'Content-Security-Policy':
                    recommendations.append("Implement Content-Security-Policy to prevent XSS attacks")
                elif header == 'Strict-Transport-Security':
                    recommendations.append("Add HSTS header to enforce HTTPS connections")
                elif header == 'X-Content-Type-Options':
                    recommendations.append("Add X-Content-Type-Options: nosniff to prevent MIME type sniffing")
                elif header == 'X-XSS-Protection':
                    recommendations.append("Add X-XSS-Protection header for legacy browser protection")
        
        security['security_score'] = (score / len(security_headers)) * 100
        security['missing_headers'] = missing_headers
        security['recommendations'] = recommendations
        
        # Cookie security analysis
        set_cookie = headers.get('Set-Cookie', '')
        security['cookie_security'] = {
            'has_secure': 'Secure' in set_cookie,
            'has_httponly': 'HttpOnly' in set_cookie,
            'has_samesite': 'SameSite' in set_cookie,
            'recommendations': []
        }
        
        # Cookie recommendations
        if not security['cookie_security']['has_secure']:
            security['cookie_security']['recommendations'].append("Add Secure flag to cookies")
        if not security['cookie_security']['has_httponly']:
            security['cookie_security']['recommendations'].append("Add HttpOnly flag to cookies")
        if not security['cookie_security']['has_samesite']:
            security['cookie_security']['recommendations'].append("Add SameSite attribute to cookies")
        
        # SSL information
        if response.url.startswith('https://'):
            security['ssl_info'] = {
                'uses_ssl': True,
                'url_scheme': 'https',
                'ssl_grade': 'Good' if len(missing_headers) < 3 else 'Needs Improvement'
            }
        else:
            security['ssl_info'] = {
                'uses_ssl': False,
                'url_scheme': 'http',
                'ssl_grade': 'Poor - No SSL'
            }
            recommendations.append("Enable HTTPS/SSL for secure communication")
        
        return security
    
    def _parse_server_header(self, server_header: str) -> Dict:
        """Parse Server header for technology information"""
        if not server_header or server_header == 'Not found':
            return {'name': 'Unknown', 'version': 'Unknown', 'components': []}
        
        # Common server patterns
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
    
    def _parse_powered_by_header(self, powered_by_header: str) -> Dict:
        """Parse X-Powered-By header for framework information"""
        if not powered_by_header or powered_by_header == 'Not found':
            return {'framework': 'Unknown', 'version': 'Unknown'}
        
        # Common framework patterns
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
        
        # Check for specific technology headers
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
        
        # Content-based technology detection
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
        
        return list(set(detected))  # Remove duplicates
    
    def _detect_from_url_patterns(self, content: str) -> List[str]:
        """Detect technologies from URL patterns in content"""
        detected = []
        
        if not content:
            return detected
        
        # URL pattern-based detection
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
    
    def _extract_meta_info(self, content: str) -> Dict:
        """Extract meta information from HTML content"""
        meta_info = {
            'generator': 'Not found',
            'description': 'Not found',
            'keywords': 'Not found'
        }
        
        try:
            import re
            
            # Extract generator
            generator_match = re.search(r'<meta[^>]*name=["\']generator["\'][^>]*content=["\']([^"\']+)["\']', content, re.IGNORECASE)
            if generator_match:
                meta_info['generator'] = generator_match.group(1)
            
            # Extract description
            desc_match = re.search(r'<meta[^>]*name=["\']description["\'][^>]*content=["\']([^"\']+)["\']', content, re.IGNORECASE)
            if desc_match:
                meta_info['description'] = desc_match.group(1)[:100]  # Limit length
            
            # Extract keywords
            keywords_match = re.search(r'<meta[^>]*name=["\']keywords["\'][^>]*content=["\']([^"\']+)["\']', content, re.IGNORECASE)
            if keywords_match:
                meta_info['keywords'] = keywords_match.group(1)
                
        except Exception as e:
            logger.debug(f"Error extracting meta info: {e}")
        
        return meta_info
    
    def _analyze_technology_insights(self, technologies: Dict) -> Dict:
        """Analyze detected technologies and provide insights"""
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
            'performance_notes': [],
            'version_info': {}
        }
        
        # Categorize technologies
        all_techs = []
        for method, tech_list in technologies.items():
            if isinstance(tech_list, list):
                all_techs.extend(tech_list)
        
        for tech in set(all_techs):
            tech_lower = tech.lower()
            
            # Web servers
            if any(server in tech_lower for server in ['apache', 'nginx', 'iis', 'cloudflare']):
                insights['technology_stack']['web_server'].append(tech)
            
            # Programming languages
            elif any(lang in tech_lower for lang in ['php', 'python', 'java', 'asp.net', 'node.js']):
                insights['technology_stack']['programming_language'].append(tech)
            
            # Frameworks
            elif any(fw in tech_lower for fw in ['django', 'flask', 'laravel', 'express', 'rails']):
                insights['technology_stack']['framework'].append(tech)
            
            # CMS
            elif any(cms in tech_lower for cms in ['wordpress', 'drupal', 'joomla', 'moodle']):
                insights['technology_stack']['cms'].append(tech)
                if 'moodle' in tech_lower:
                    insights['security_implications'].append("Moodle CMS - ensure regular updates for security")
            
            # JavaScript libraries
            elif any(js in tech_lower for js in ['jquery', 'react', 'angular', 'vue', 'mathjax', 'requirejs']):
                insights['technology_stack']['javascript_libraries'].append(tech)
            
            # CDN
            elif any(cdn in tech_lower for cdn in ['cloudflare', 'jsdelivr', 'cdnjs', 'amazonaws']):
                insights['technology_stack']['cdn'].append(tech)
                insights['performance_notes'].append(f"Using {tech} CDN for improved performance")
            
            # Analytics
            elif any(analytics in tech_lower for analytics in ['google analytics', 'gtag']):
                insights['technology_stack']['analytics'].append(tech)
        
        # Add security implications based on detected technologies
        if any('php' in tech.lower() for tech in all_techs):
            insights['security_implications'].append("PHP detected - ensure latest version for security")
        
        if any('apache' in tech.lower() for tech in all_techs):
            insights['security_implications'].append("Apache server - review security modules and configuration")
        
        return insights
    
    def generate_fingerprint_summary(self, results: Dict) -> Dict:
        """Generate a summary of fingerprinting results"""
        summary = {
            'total_targets': len(results),
            'successful_scans': 0,
            'failed_scans': 0,
            'unique_technologies': set(),
            'common_servers': {},
            'security_score_avg': 0,
            'ssl_enabled': 0
        }
        
        security_scores = []
        
        for target, result in results.items():
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
        
        # Convert set to list for JSON serialization
        summary['unique_technologies'] = list(summary['unique_technologies'])
        
        return summary
    
    def get_errors(self) -> Dict:
        """Get all errors encountered during web fingerprinting"""
        return self.error_handler.get_errors()


# Main function for testing
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Web Technology Fingerprinting")
    parser.add_argument("domain", help="Target domain to fingerprint")
    parser.add_argument("--targets", nargs='+', help="Specific URLs to fingerprint")
    parser.add_argument("--summary", action="store_true", help="Generate summary report")
    
    args = parser.parse_args()
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Run web fingerprinting
    fingerprinter = WebFingerprinter(args.domain)
    
    if args.targets:
        results = fingerprinter.run_web_fingerprinting(args.targets)
    else:
        results = fingerprinter.run_web_fingerprinting()
    
    print(f"\n=== Web Fingerprinting Results for {args.domain} ===")
    
    for target, result in results.items():
        print(f"\n--- {target} ---")
        
        if 'error' in result:
            print(f"Error: {result['error']}")
            continue
        
        # Response analysis
        response_analysis = result.get('response_analysis', {})
        print(f"Status: {response_analysis.get('status_code', 'Unknown')}")
        print(f"Content Type: {response_analysis.get('content_type', 'Unknown')}")
        print(f"Title: {response_analysis.get('title', 'Unknown')}")
        
        # Server information
        header_analysis = result.get('header_analysis', {})
        print(f"Server: {header_analysis.get('server', 'Unknown')}")
        print(f"X-Powered-By: {header_analysis.get('x_powered_by', 'Unknown')}")
        
        # Technologies
        tech_detection = result.get('technology_detection', {})
        tech_insights = result.get('technology_insights', {})
        
        wappalyzer_techs = tech_detection.get('wappalyzer_detected', [])
        header_techs = tech_detection.get('header_detected', [])
        content_techs = tech_detection.get('content_detected', [])
        
        all_techs = set(wappalyzer_techs + header_techs + content_techs)
        print(f"Technologies: {', '.join(all_techs) if all_techs else 'None detected'}")
        
        # Show technology stack categorization
        tech_stack = tech_insights.get('technology_stack', {})
        for category, techs in tech_stack.items():
            if techs:
                category_name = category.replace('_', ' ').title()
                print(f"{category_name}: {', '.join(techs)}")
        
        # AI detected technologies if available
        ai_techs = tech_detection.get('ai_detected', [])
        if ai_techs:
            print(f"AI Detected: {', '.join(ai_techs)}")
        
        # Security
        security_analysis = result.get('security_analysis', {})
        security_score = security_analysis.get('security_score', 0)
        uses_ssl = security_analysis.get('ssl_info', {}).get('uses_ssl', False)
        ssl_grade = security_analysis.get('ssl_info', {}).get('ssl_grade', 'Unknown')
        missing_headers = security_analysis.get('missing_headers', [])
        recommendations = security_analysis.get('recommendations', [])
        
        print(f"Security Score: {security_score:.1f}%")
        print(f"SSL Enabled: {'Yes' if uses_ssl else 'No'}")
        print(f"SSL Grade: {ssl_grade}")
        
        if missing_headers:
            print(f"Missing Security Headers: {', '.join(missing_headers)}")
        
        if recommendations:
            print("Security Recommendations:")
            for i, rec in enumerate(recommendations[:3], 1):  # Show top 3
                print(f"  {i}. {rec}")
        
        # AI detected technologies if available
        ai_techs = tech_detection.get('ai_detected', [])
        if ai_techs:
            print(f"AI Detected: {', '.join(ai_techs)}")
    
    # Generate summary if requested
    if args.summary:
        summary = fingerprinter.generate_fingerprint_summary(results)
        
        print(f"\n=== Fingerprinting Summary ===")
        print(f"Total Targets: {summary['total_targets']}")
        print(f"Successful Scans: {summary['successful_scans']}")
        print(f"Failed Scans: {summary['failed_scans']}")
        print(f"Unique Technologies: {len(summary['unique_technologies'])}")
        print(f"Average Security Score: {summary['security_score_avg']:.1f}%")
        print(f"SSL Enabled Sites: {summary['ssl_enabled']}/{summary['successful_scans']}")
        
        if summary['unique_technologies']:
            print(f"Technologies Found: {', '.join(summary['unique_technologies'])}")
        
        if summary['common_servers']:
            print("Common Servers:")
            for server, count in summary['common_servers'].items():
                print(f"  {server}: {count}")
    
    # Display errors if any
    errors = fingerprinter.get_errors()
    if errors:
        print(f"\n=== Errors Encountered ===")
        for method, error_list in errors.items():
            print(f"{method}: {len(error_list)} errors")