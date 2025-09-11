import time
import requests
import logging
import re
import json
import os
import sys
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from typing import List, Dict, Any, Optional
import urllib3

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from modules.ai_integration import AIIntegration
from common.network_utils import NetworkUtils
from common.constants import SSL_VERIFY_EXCEPTIONS, WEB_EXTENSIONS, COMMON_API_ENDPOINTS

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class WebCrawler:
    def __init__(self, domain: str):
        self.domain = domain
        self.session = NetworkUtils.create_session()
        self.discovered_urls = set()
        self.discovered_apis = set()

        # Initialize AI integration
        self.ai_integration = AIIntegration()
        
        # Define crawl levels
        self.crawl_levels = {
            'quick': {
                'max_pages': 10,
                'wordlist_size': 20,
                'recursive': False,
                'use_ai': False
            },
            'smart': {
                'max_pages': 30,
                'wordlist_size': 50,
                'recursive': True,
                'use_ai': True
            },
            'deep': {
                'max_pages': 100,
                'wordlist_size': 0,  # 0 means use full wordlist
                'recursive': True,
                'use_ai': True
            }
        }
        
    def _get_base_urls(self) -> List[str]:
        """Generate all possible base URLs for the domain"""
        return [
            f"http://{self.domain}",
            f"https://{self.domain}",
            f"http://www.{self.domain}",
            f"https://www.{self.domain}"
        ]
    
    def web_fingerprinting(self) -> Dict[str, Any]:
        """Fingerprint web technologies"""
        logging.info("Starting web fingerprinting")
        results = {}
        
        for url in self._get_base_urls():
            response = NetworkUtils.safe_request(url, session=self.session)
            if response:
                server = response.headers.get('Server', 'Not found')
                tech = response.headers.get('X-Powered-By', 'Not found')
                
                results[url] = {
                    'server': server,
                    'x_powered_by': tech,
                    'status_code': response.status_code,
                    'content_type': response.headers.get('Content-Type'),
                    'headers': dict(response.headers)
                }
                
                logging.info(f"Web fingerprint for {url}: Server={server}, Tech={tech}")
            else:
                logging.warning(f"Failed to fingerprint {url}")
        
        return results

    def directory_bruteforce(self, wordlist_path: str, extensions: List[str] = None, 
                            recursive: bool = False, depth: int = 2, max_urls: int = None, visited: set = None) -> List[Dict[str, Any]]:
        """
        Brute force common web directories with extensions and recursive scanning
        
        Args:
            wordlist_path: Path to the wordlist file
            extensions: List of extensions to try (e.g., ['php', 'html', 'json'])
            recursive: Whether to recursively scan discovered directories
            depth: Maximum recursion depth
            max_urls: Maximum number of URLs to test
        """
        logging.info("Starting directory brute-forcing")
        found_dirs = []
        if visited is None:
            visited = set()

        if extensions is None:
            extensions = ['php', 'html', 'aspx', 'jsp', 'json']

        # Generate target-specific terms based on domain and year
        current_year = str(time.localtime().tm_year)
        target_specific_terms = [
            f"admin-{current_year}",
            f"api-{current_year}",
            f"dashboard-{current_year}",
            f"console-{current_year}",
            f"admin{current_year}",
            f"api{current_year}",
        ]

        for base_url in self._get_base_urls():
            try:
                with open(wordlist_path, 'r') as f:
                    directories = f.read().splitlines()

                # Add target-specific terms to the wordlist
                directories.extend(target_specific_terms)

                # Scan with extensions
                for directory in directories:
                    # Try without extension first
                    urls_to_try = [f"{base_url}/{directory}"]

                    # Try with extensions
                    for ext in extensions:
                        urls_to_try.append(f"{base_url}/{directory}.{ext}")

                    for url in urls_to_try:
                        # Remove URL limit: do not check tested_urls or max_urls
                        # Avoid revisiting the same URL
                        if url in visited:
                            continue
                        visited.add(url)

                        try:
                            response = NetworkUtils.safe_request(
                                url, 
                                timeout=3,
                                session=self.session
                            )

                            if response and response.status_code < 400:
                                found_item = {
                                    'url': url,
                                    'status': response.status_code,
                                    'size': len(response.content),
                                    'content_type': response.headers.get('Content-Type', '')
                                }
                                found_dirs.append(found_item)
                                logging.info(f"Found accessible directory: {url} ({response.status_code})")

                                # If recursive scanning is enabled and this is a directory
                                if (recursive and depth > 0 and 
                                    response.status_code == 200 and
                                    'text/html' in response.headers.get('Content-Type', '') and
                                    not url.endswith(tuple(f'.{ext}' for ext in extensions))):
                                    # Recursively scan this directory, but only if not already visited and depth > 0
                                    recursive_dirs = self.directory_bruteforce(
                                        wordlist_path, 
                                        extensions, 
                                        recursive=True, 
                                        depth=depth-1,
                                        max_urls=max_urls,
                                        visited=visited
                                    )
                                    found_dirs.extend(recursive_dirs)

                        except requests.RequestException:
                            continue
            except IOError as e:
                logging.error(f"Failed to read wordlist: {str(e)}")
                break

        return found_dirs

    def api_discovery(self, custom_paths: List[str] = None, wordlist_path: str = None, 
                     max_endpoints: int = 500) -> Dict[str, Any]:
        """
        Discover APIs and web endpoints including GraphQL and Swagger
        
        Args:
            custom_paths: Additional custom paths to check for APIs
            wordlist_path: Path to API endpoints wordlist file
            max_endpoints: Maximum number of endpoints to test
        """
        logging.info("Starting API discovery")
        results = {
            'graphql': [],
            'swagger': [],
            'rest_apis': [],
            'other_endpoints': []
        }
        
        # Common API endpoints to check
        api_endpoints = [
            '/api', '/api/v1', '/api/v2', '/graphql', '/graphiql', 
            '/swagger', '/swagger-ui.html', '/swagger.json', 
            '/openapi', '/openapi.json', '/api-docs', '/rest', '/soap'
        ]
        
        # Add custom paths if provided
        if custom_paths:
            api_endpoints.extend(custom_paths)
        
        # Load API endpoints from wordlist file if provided
        wordlist_endpoints = []
        if wordlist_path:
            try:
                with open(wordlist_path, 'r') as f:
                    wordlist_endpoints = [line.strip() for line in f.readlines() if line.strip()]
                
                # Add wordlist endpoints (with and without leading slash)
                for endpoint in wordlist_endpoints:
                    if endpoint and endpoint not in api_endpoints:
                        # Add both with and without leading slash
                        if not endpoint.startswith('/'):
                            api_endpoints.append(f'/{endpoint}')
                            api_endpoints.append(f'/{endpoint.lower()}')
                        else:
                            api_endpoints.append(endpoint)
                            api_endpoints.append(endpoint.lower())
                
                logging.info(f"Loaded {len(wordlist_endpoints)} endpoints from wordlist")
            except FileNotFoundError:
                logging.warning(f"Wordlist file not found: {wordlist_path}")
            except Exception as e:
                logging.warning(f"Error reading wordlist file: {str(e)}")
        
        # Remove duplicates and sort for consistent testing
        api_endpoints = sorted(list(set(api_endpoints)))
        
        # Limit the number of endpoints based on max_endpoints
        if len(api_endpoints) > max_endpoints:
            api_endpoints = api_endpoints[:max_endpoints]
            
        logging.info(f"Testing {len(api_endpoints)} API endpoints")
        
        for base_url in self._get_base_urls():
            for endpoint in api_endpoints:
                url = f"{base_url}{endpoint}"
                try:
                    response = NetworkUtils.safe_request(
                        url, 
                        timeout=3,
                        session=self.session
                    )
                    
                    if response and response.status_code < 400:
                        endpoint_info = {
                            'url': url,
                            'status': response.status_code,
                            'content_type': response.headers.get('Content-Type', ''),
                            'size': len(response.content),
                            'response_time': response.elapsed.total_seconds()
                        }
                        
                        # Additional checks based on content
                        content_lower = response.text.lower()
                        
                        # Check for GraphQL endpoints
                        if ('graphql' in endpoint.lower() or 
                            'graphql' in content_lower or 
                            'query' in content_lower and 'mutation' in content_lower):
                            
                            # Try GraphQL introspection
                            introspection_queries = [
                                {"query": "__schema{queryType{name}}"},
                                {"query": "{__schema{types{name}}}"}
                            ]
                            
                            for i, query in enumerate(introspection_queries):
                                try:
                                    introspection_response = NetworkUtils.safe_request(
                                        url,
                                        method='POST',
                                        json=query,
                                        timeout=3,
                                        session=self.session
                                    )
                                    if introspection_response and introspection_response.status_code == 200:
                                        # Check if response contains GraphQL schema data
                                        intro_content = introspection_response.text.lower()
                                        if ('__schema' in intro_content or 
                                            'querytype' in intro_content or 
                                            'mutationtype' in intro_content):
                                            endpoint_info[f'introspection_vulnerable_{i}'] = True
                                            logging.warning(f"GraphQL introspection may be enabled at {url}")
                                except:
                                    pass
                                    
                            results['graphql'].append(endpoint_info)
                            logging.info(f"Found GraphQL endpoint: {url} (Status: {response.status_code})")
                        
                        # Check for Swagger/OpenAPI endpoints
                        elif (any(term in endpoint.lower() for term in ['swagger', 'openapi', 'api-docs']) or
                            'swagger' in content_lower or 'openapi' in content_lower):
                            
                            # Try to access common Swagger files
                            swagger_paths = ['/swagger.json', '/openapi.json', '/swagger.yaml', '/openapi.yaml']
                            for swagger_path in swagger_paths:
                                swagger_url = f"{base_url}{swagger_path}"
                                try:
                                    swagger_response = NetworkUtils.safe_request(swagger_url, timeout=2, session=self.session)
                                    if swagger_response and swagger_response.status_code == 200:
                                        endpoint_info['swagger_files'] = endpoint_info.get('swagger_files', [])
                                        endpoint_info['swagger_files'].append({
                                            'url': swagger_url,
                                            'status': swagger_response.status_code
                                        })
                                except:
                                    pass
                                    
                            results['swagger'].append(endpoint_info)
                            logging.info(f"Found Swagger/OpenAPI endpoint: {url} (Status: {response.status_code})")
                        
                        # Check for REST API endpoints
                        elif ('api' in endpoint.lower() or 
                            'api' in content_lower or
                            response.headers.get('Content-Type', '').startswith('application/json') or
                            'json' in content_lower):
                            
                            # Try common HTTP methods for APIs
                            http_methods = ['POST', 'PUT', 'DELETE', 'PATCH']
                            endpoint_info['supported_methods'] = ['GET']  # We know GET works
                            
                            for method in http_methods:
                                try:
                                    method_response = NetworkUtils.safe_request(
                                        url, method=method, timeout=2, session=self.session
                                    )
                                    if method_response and method_response.status_code != 405:  # Method Not Allowed
                                        endpoint_info['supported_methods'].append(method)
                                except:
                                    pass
                                    
                            results['rest_apis'].append(endpoint_info)
                            logging.info(f"Found REST API endpoint: {url} (Status: {response.status_code})")
                        
                        # Other endpoints
                        else:
                            results['other_endpoints'].append(endpoint_info)
                            logging.info(f"Found other endpoint: {url} (Status: {response.status_code})")
                            
                except requests.RequestException as e:
                    continue
                except Exception as e:
                    logging.debug(f"Error testing {url}: {str(e)}")
        
        return results

    def scrape_page_content(self, url: str, max_content_length: int = 5000, headers: dict = None) -> Optional[Dict[str, Any]]:
        """Scrape and extract meaningful content from a webpage"""
        try:
            req_headers = self.session.headers.copy()
            if headers:
                req_headers.update(headers)
            response = NetworkUtils.safe_request(
                url, 
                timeout=10,
                headers=req_headers,
                session=self.session
            )
            
            if not response:
                return None
                
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Extract various elements
            content_info = {
                'title': soup.title.string if soup.title else '',
                'meta_description': '',
                'links': [],
                'forms': [],
                'api_references': [],
                'javascript_files': [],
                'text_content': '',
                'potential_endpoints': []
            }
            
            # Get meta description
            meta_desc = soup.find('meta', attrs={'name': 'description'})
            if meta_desc:
                content_info['meta_description'] = meta_desc.get('content', '')
            
            # Extract links
            for link in soup.find_all('a', href=True):
                href = link['href']
                full_url = urljoin(url, href)
                content_info['links'].append(full_url)
                
                # Add to discovered URLs for later crawling
                if self.domain in full_url and full_url not in self.discovered_urls:
                    self.discovered_urls.add(full_url)
            
            # Extract form actions
            for form in soup.find_all('form', action=True):
                action_url = urljoin(url, form['action'])
                content_info['forms'].append(action_url)
                
                # Check if this might be an API endpoint
                if any(term in action_url.lower() for term in ['api', 'json', 'xml', 'rest']):
                    content_info['potential_endpoints'].append(action_url)
                    if action_url not in self.discovered_apis:
                        self.discovered_apis.add(action_url)
            
            # Look for API references in JavaScript and text
            text_content = soup.get_text()
            
            # Extract JavaScript files and look for API endpoints
            for script in soup.find_all('script'):
                src = script.get('src', '')
                if src:
                    full_src = urljoin(url, src)
                    content_info['javascript_files'].append(full_src)
                    
                    # Check if this might be an API-related JS file
                    if any(term in full_src.lower() for term in ['api', 'graphql', 'rest']):
                        content_info['potential_endpoints'].append(full_src)
                
                # Look for API endpoints in inline JavaScript
                if script.string:
                    script_text = script.string
                    # Look for common API patterns in JavaScript
                    api_patterns = [
                        r'fetch\(["\']([^"\']+api[^"\']*)["\']\)',
                        r'axios\.(get|post|put|delete)\(["\']([^"\']+api[^"\']*)["\']\)',
                        r'\.ajax\([^}]*url:\s*["\']([^"\']+api[^"\']*)["\']',
                        r'\/api\/[a-zA-Z0-9_\/-]+',
                        r'\/graphql',
                    ]
                    
                    for pattern in api_patterns:
                        matches = re.findall(pattern, script_text, re.IGNORECASE)
                        for match in matches:
                            if isinstance(match, tuple):
                                match = match[1]  # Get the URL from the capture group
                            full_api_url = urljoin(url, match)
                            if full_api_url not in content_info['api_references']:
                                content_info['api_references'].append(full_api_url)
                            if full_api_url not in self.discovered_apis:
                                self.discovered_apis.add(full_api_url)
            
            # Look for API patterns in HTML attributes
            for tag in soup.find_all(True):  # All tags
                for attr in ['data-url', 'data-api', 'data-endpoint']:
                    attr_value = tag.get(attr, '')
                    if attr_value and any(term in attr_value.lower() for term in ['api', 'graphql']):
                        full_api_url = urljoin(url, attr_value)
                        if full_api_url not in content_info['api_references']:
                            content_info['api_references'].append(full_api_url)
                        if full_api_url not in self.discovered_apis:
                            self.discovered_apis.add(full_api_url)
            
            # Get clean text content
            text_content = soup.get_text(separator=' ', strip=True)
            content_info['text_content'] = text_content[:max_content_length]
            
            logging.info(f"Successfully scraped content from {url}")
            return content_info
            
        except requests.RequestException as e:
            logging.warning(f"Failed to scrape {url}: {str(e)}")
            return None
        except Exception as e:
            logging.warning(f"Error parsing content from {url}: {str(e)}")
            return None

    def crawl_site(self, max_pages: int = 50) -> Dict[str, Any]:
        """
        Crawl the website to discover pages and APIs
        
        Args:
            max_pages: Maximum number of pages to crawl
        """
        logging.info(f"Starting site crawl for {self.domain}, max pages: {max_pages}")
        
        results = {
            'pages': [],
            'apis': list(self.discovered_apis),
            'discovered_urls': list(self.discovered_urls)
        }
        
        # Start with the base URLs
        to_crawl = self._get_base_urls()
        crawled = set()
        
        while to_crawl and len(crawled) < max_pages:
            url = to_crawl.pop(0)
            
            if url in crawled:
                continue
                
            logging.info(f"Crawling: {url}")
            
            # Scrape the page content
            content = self.scrape_page_content(url)
            if content:
                page_info = {
                    'url': url,
                    'content': content
                }
                results['pages'].append(page_info)
                
                # Add newly discovered URLs to the crawl list
                for link in content['links']:
                    if (self.domain in link and 
                        link not in crawled and 
                        link not in to_crawl and
                        len(to_crawl) < max_pages * 2):  # Limit the queue size
                        to_crawl.append(link)
            
            crawled.add(url)
        
        results['apis'] = list(self.discovered_apis)
        results['discovered_urls'] = list(self.discovered_urls)
        
        return results

    def generate_target_specific_wordlist(self, context: str = None, num_terms: int = 20, 
                                    use_ai: bool = False, scraped_content: Dict[str, Any] = None) -> List[str]:
        """
        Generate target-specific terms for directory bruteforcing with AI enhancement
        
        Args:
            context: Context about the target (if available)
            num_terms: Number of terms to generate
            use_ai: Whether to use AI for enhanced wordlist generation
            scraped_content: Scraped page content for AI analysis
        
        Returns:
            List of target-specific directory/file names to test
        """
        logging.info("Generating target-specific wordlist")
        
        # Use AI-powered generation if available and requested
        if use_ai and hasattr(self, 'ai_integration') and scraped_content:
            try:
                ai_terms = self.ai_integration.generate_target_specific_wordlist(
                    page_content=scraped_content,
                    domain=self.domain,
                    context=context,
                    num_terms=num_terms
                )
                if ai_terms:
                    logging.info(f"Generated {len(ai_terms)} AI-powered target-specific terms")
                    return ai_terms
            except Exception as e:
                logging.warning(f"AI wordlist generation failed, using fallback: {str(e)}")
        
        # Fallback to intelligent pattern-based generation
        return self._generate_intelligent_wordlist_fallback(context, num_terms)

    def _generate_intelligent_wordlist_fallback(self, context: str = None, num_terms: int = 20) -> List[str]:
        """
        Intelligent fallback for target-specific wordlist generation
        
        Args:
            context: Context about the target
            num_terms: Number of terms to generate
        
        Returns:
            List of intelligent target-specific terms
        """
        # Get current and previous years
        current_year = str(time.localtime().tm_year)
        previous_year = str(int(current_year) - 1)
        two_years_ago = str(int(current_year) - 2)
        
        # Comprehensive base terms covering various categories
        base_terms = [
            # Administrative interfaces
            'admin', 'administrator', 'dashboard', 'console', 'control', 'manage',
            'panel', 'backend', 'portal', 'system', 'cp', 'manager',
            
            # API endpoints
            'api', 'rest', 'graphql', 'soap', 'endpoint', 'v1', 'v2', 'v3',
            'json', 'xml', 'rpc', 'service', 'webservice',
            
            # Authentication
            'auth', 'authentication', 'login', 'signin', 'logout', 'signout',
            'register', 'signup', 'oauth', 'sso', 'token', 'session', 'jwt',
            
            # User management
            'user', 'users', 'account', 'profile', 'member', 'customer', 'client',
            
            # Content management
            'content', 'cms', 'posts', 'articles', 'blog', 'news', 'media',
            'upload', 'download', 'files', 'assets', 'images', 'documents',
            
            # System & configuration
            'config', 'configuration', 'settings', 'setup', 'install', 'update',
            'backup', 'restore', 'migrate', 'export', 'import',
            
            # Monitoring & debugging
            'status', 'health', 'ping', 'monitor', 'metrics', 'stats', 'statistics',
            'log', 'logs', 'debug', 'test', 'dev', 'development', 'stage', 'staging',
            
            # Security
            'secure', 'security', 'private', 'internal', 'protected', 'hidden',
            'secret', 'keys', 'cert', 'ssl', 'tls',
            
            # Database
            'db', 'database', 'sql', 'nosql', 'redis', 'mongo', 'mysql', 'postgres',
            
            # Common application paths
            'app', 'application', 'webapp', 'mobile', 'desktop', 'client', 'server',
            
            # E-commerce
            'shop', 'store', 'cart', 'checkout', 'order', 'orders', 'product', 'products',
            'invoice', 'payment', 'payments', 'billing', 'subscription',
            
            # Communication
            'contact', 'support', 'help', 'faq', 'about', 'team', 'careers',
            'message', 'messages', 'chat', 'notification', 'notifications',
            
            # Search & discovery
            'search', 'find', 'query', 'filter', 'discover', 'explore', 'browse',
            
            # Geographic
            'geo', 'location', 'map', 'maps', 'regional', 'country', 'city',
            
            # Social features
            'social', 'community', 'forum', 'forums', 'discussion', 'comment', 'comments',
            'like', 'likes', 'share', 'rating', 'ratings', 'review', 'reviews'
        ]
        
        # Year-based terms (current year, previous year, two years ago)
        year_terms = []
        for term in base_terms:
            year_terms.extend([
                f"{term}-{current_year}", f"{term}{current_year}",
                f"{term}-{previous_year}", f"{term}{previous_year}",
                f"{term}-{two_years_ago}", f"{term}{two_years_ago}"
            ])
        
        # Domain-specific terms
        domain_parts = self.domain.split('.')
        domain_name = domain_parts[0] if len(domain_parts) > 1 else self.domain
        
        domain_terms = []
        for term in base_terms:
            domain_terms.extend([
                f"{term}-{domain_name}", f"{domain_name}-{term}",
                f"{term}_{domain_name}", f"{domain_name}_{term}",
                f"{term}.{domain_name}", f"{domain_name}.{term}"
            ])
        
        # Common technology patterns
        tech_patterns = [
            'wp-admin', 'wp-content', 'wp-includes', 'wp-json', 'wp-login',
            'administrator', 'phpmyadmin', 'mysql-admin', 'webmin',
            '_admin', '_api', '_rest', '_v1', '_v2', '_v3',
            'admin-interface', 'api-gateway', 'rest-service',
            'console-admin', 'control-panel', 'management-console'
        ]
        
        # Common file extensions to test
        extensions = ['', '.php', '.html', '.aspx', '.jsp', '.json', '.xml', '.yaml', '.yml']
        
        # Combine all base terms
        all_terms = set(base_terms + year_terms + domain_terms + tech_patterns)
        
        # Add variations with common extensions
        extended_terms = []
        for term in all_terms:
            for ext in extensions:
                if ext:  # Add both with and without extension
                    extended_terms.append(f"{term}{ext}")
                extended_terms.append(term)  # Keep original term
        
        all_terms.update(extended_terms)
        
        # If context is provided, add context-specific terms
        context_terms = set()
        if context:
            # Extract meaningful keywords from context
            keywords = re.findall(r'\b[a-zA-Z]{3,15}\b', context.lower())
            meaningful_keywords = []
            
            # Filter out common words and keep relevant ones
            common_words = {'the', 'and', 'for', 'with', 'this', 'that', 'from', 'have', 'has', 'was', 'were'}
            for keyword in keywords:
                if (keyword not in common_words and 
                    len(keyword) > 2 and 
                    not keyword.isdigit() and
                    keyword not in meaningful_keywords):
                    meaningful_keywords.append(keyword)
            
            # Use top 8 most relevant keywords
            for keyword in meaningful_keywords[:8]:
                for term in base_terms:
                    context_terms.update([
                        f"{term}-{keyword}", f"{keyword}-{term}",
                        f"{term}_{keyword}", f"{keyword}_{term}",
                        f"{term}.{keyword}", f"{keyword}.{term}",
                        f"{keyword}{current_year}", f"{keyword}-{current_year}",
                        f"{keyword}{previous_year}", f"{keyword}-{previous_year}"
                    ])
        
        all_terms.update(context_terms)
        
        # Add common numeric patterns
        numeric_patterns = []
        for term in list(all_terms)[:50]:  # Add patterns to first 50 terms
            numeric_patterns.extend([
                f"{term}1", f"{term}2", f"{term}3",
                f"{term}01", f"{term}02", f"{term}03",
                f"{term}-test", f"{term}-dev", f"{term}-prod",
                f"{term}-backup", f"{term}-old", f"{term}-new"
            ])
        
        all_terms.update(numeric_patterns)
        
        # Clean and filter terms
        cleaned_terms = []
        for term in all_terms:
            if isinstance(term, str) and term:
                term = term.strip().strip('/').lower()
                # Validate term length and content
                if (1 <= len(term) <= 50 and
                    not term.startswith(('.', '-', '_')) and
                    not any(char in term for char in [' ', '\t', '\n', '\r']) and
                    not term.startswith(('javascript:', 'mailto:', 'tel:', '#')) and
                    not term.endswith(('.exe', '.dll', '.bin')) and
                    not term in ['', 'www', 'http', 'https', 'ftp']):
                    cleaned_terms.append(term)
        
        # Remove duplicates and sort by relevance
        unique_terms = list(set(cleaned_terms))
        
        # Prioritize shorter, more common terms first
        unique_terms.sort(key=lambda x: (
            len(x),  # Shorter terms first
            not any(char in x for char in ['-', '_', '.']),  # Simple terms first
            x.count('/'),  # Fewer slashes first
            x  # Alphabetical as tiebreaker
        ))
        
        # Ensure we don't exceed the requested number of terms
        result = unique_terms[:num_terms]
        logging.info(f"Generated {len(result)} intelligent target-specific terms")
        
        return result

    def run_crawl_level(self, level: str, wordlist_path: str = None) -> Dict[str, Any]:
        """
        Run a specific crawl level (quick, smart, or deep)
        
        Args:
            level: The crawl level to run ('quick', 'smart', or 'deep')
            wordlist_path: Path to the wordlist file for directory bruteforcing
        
        Returns:
            Dictionary containing results from all operations
        """
        if level not in self.crawl_levels:
            raise ValueError(f"Invalid crawl level: {level}. Must be one of: {list(self.crawl_levels.keys())}")
        
        config = self.crawl_levels[level]
        logging.info(f"Starting {level.upper()} level crawl")
        
        results = {}
        
        # 1. Web Fingerprinting
        logging.info("=" * 50)
        logging.info("WEB FINGERPRINTING")
        logging.info("=" * 50)
        results['fingerprinting'] = self.web_fingerprinting()
        
        # 2. Directory Bruteforcing
        logging.info("\n" + "=" * 50)
        logging.info("DIRECTORY BRUTEFORCING")
        logging.info("=" * 50)
        
        if level == 'quick':
            # For quick scan, use a small custom list
            custom_terms = self.generate_target_specific_wordlist(
                context=f"Quick scan of {self.domain}",
                num_terms=config['wordlist_size'],
                use_ai=config['use_ai']
            )
            
            # Create a temporary wordlist file
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
                f.write('\n'.join(custom_terms))
                temp_wordlist_path = f.name
            
            dir_results = self.directory_bruteforce(
                temp_wordlist_path, 
                extensions=['php', 'html', 'json'],
                recursive=config['recursive'],
                max_urls=100  # Limit for quick scan
            )
            
            # Clean up temporary file
            import os
            os.unlink(temp_wordlist_path)
            
        elif level == 'smart':
            # For smart scan, use AI-generated list
            # First scrape some content to inform the AI
            base_url = f"https://{self.domain}"
            scraped_content = self.scrape_page_content(base_url)
            
            custom_terms = self.generate_target_specific_wordlist(
                context=f"Smart scan of {self.domain}",
                num_terms=config['wordlist_size'],
                use_ai=config['use_ai'],
                scraped_content=scraped_content
            )
            
            # Create a temporary wordlist file
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
                f.write('\n'.join(custom_terms))
                temp_wordlist_path = f.name
            
            dir_results = self.directory_bruteforce(
                temp_wordlist_path, 
                extensions=['php', 'html', 'json', 'aspx', 'jsp'],
                recursive=config['recursive'],
                max_urls=500  # Moderate limit for smart scan
            )
            
            # Clean up temporary file
            import os
            os.unlink(temp_wordlist_path)
            
        else:  # deep
            # For deep scan, use the full wordlist
            if not wordlist_path:
                # Default wordlist path if not provided
                wordlist_path = "../../config/wordlists/common_directories.txt"
            
            dir_results = self.directory_bruteforce(
                wordlist_path, 
                extensions=['php', 'html', 'json', 'aspx', 'jsp', 'xml', 'yaml', 'yml'],
                recursive=config['recursive'],
                max_urls=2000  # Higher limit for deep scan
            )
        
        results['directory_bruteforce'] = dir_results
        
        # 3. API Discovery
        logging.info("\n" + "=" * 50)
        logging.info("API DISCOVERY")
        logging.info("=" * 50)
        
        # Adjust API discovery based on level
        max_endpoints = 100 if level == 'quick' else 300 if level == 'smart' else 1000
        api_wordlist_path = None if level == 'quick' else '../config/wordlists/api_endpoints.txt'

        api_results = self.api_discovery(
            wordlist_path=api_wordlist_path,
            max_endpoints=max_endpoints
        )
        results['api_discovery'] = api_results
        
        # 4. Site Crawling
        logging.info("\n" + "=" * 50)
        logging.info("SITE CRAWLING")
        logging.info("=" * 50)
        
        crawl_results = self.crawl_site(max_pages=config['max_pages'])
        results['crawl'] = crawl_results
        
        # 5. Generate target-specific wordlist for reporting
        logging.info("\n" + "=" * 50)
        logging.info("TARGET-SPECIFIC WORDLIST GENERATION")
        logging.info("=" * 50)
        
        custom_terms = self.generate_target_specific_wordlist(
            context=f"{level} scan of {self.domain}",
            num_terms=config['wordlist_size'] if config['wordlist_size'] > 0 else 100,
            use_ai=config['use_ai']
        )
        results['target_specific_terms'] = custom_terms
        return results
    
if __name__ == "__main__":
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('web_crawler.log'),
            logging.StreamHandler()
        ]
    )
    
    # Initialize the crawler
    domain = "online.uom.lk"  # Replace with your target domain
    crawler = WebCrawler(domain)
    
    try:
        # Choose crawl level: 'quick', 'smart', or 'deep'
        crawl_level = 'smart'  # Change as needed
        wordlist_path = "../../config/wordlists/common_directories.txt"  # Or set a custom wordlist path for 'deep'

        results = crawler.run_crawl_level(crawl_level, wordlist_path)

        # Print summary of results
        print(f"\nCrawl Level: {crawl_level}")
        print("\n[1] Web Fingerprinting Results:")
        for url, info in results['fingerprinting'].items():
            print(f"  {url}:")
            print(f"    Server: {info['server']}")
            print(f"    X-Powered-By: {info['x_powered_by']}")
            print(f"    Status: {info['status_code']}")

        print(f"\n[2] Directory Bruteforce Results ({len(results['directory_bruteforce'])} found):")
        for result in results['directory_bruteforce']:
            print(f"  {result['url']} - Status: {result['status']}")

        print("\n[3] API Discovery Results:")
        for category, endpoints in results['api_discovery'].items():
            if endpoints:
                print(f"  {category.upper()}:")
                for endpoint in endpoints:
                    print(f"    {endpoint['url']} - Status: {endpoint['status']}")

        print(f"\n[4] Site Crawl: Crawled {len(results['crawl']['pages'])} pages:")
        for page in results['crawl']['pages']:
            print(f"  {page['url']}")
        if results['crawl']['apis']:
            print(f"\nDiscovered {len(results['crawl']['apis'])} API endpoints:")
            for api in results['crawl']['apis']:
                print(f"  {api}")

        print(f"\n[5] Target-Specific Wordlist ({len(results['target_specific_terms'])} terms):")
        for term in results['target_specific_terms']:
            print(f"  {term}")

        # Save results to JSON file
        with open('crawler_results.json', 'w') as f:
            import json
            json.dump(results, f, indent=2)
        print("\nResults saved to crawler_results.json")

    except Exception as e:
        logging.error(f"Error during test run: {str(e)}")
        import traceback
        traceback.print_exc()