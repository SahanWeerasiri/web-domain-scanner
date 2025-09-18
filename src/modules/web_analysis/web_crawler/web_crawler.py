# modules/web_crawler.py
"""
Web Crawler Module
------------------
Performs web crawling and content analysis, with CDN awareness.
Can use pre-bypassed content from CDN detector when available.
"""

import time
import requests
import logging
import re
import json
from typing import Dict, Any, List, Optional
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from browser_manager.browser_manager import BrowserManager
from ai_integration import AIIntegration

class WebCrawler:
    def __init__(self, domain: str):
        self.domain = domain
        self.discovered_urls = set()
        self.discovered_apis = set()
        self.browser_manager = BrowserManager()
        
        # Initialize AI integration
        self.ai_integration = AIIntegration()
        
        # Define crawl levels similar to web_crawling.py
        self.crawl_levels = {
            'quick': {
                'max_pages': 10,
                'max_api_endpoints': 50,
                'use_ai': False
            },
            'smart': {
                'max_pages': 30,
                'max_api_endpoints': 100,
                'use_ai': True
            },
            'deep': {
                'max_pages': 100,
                'max_api_endpoints': 200,
                'use_ai': True
            }
        }
        
    def crawl_with_cdn_bypass(self, content: str = None, crawl_level: str = 'smart') -> Dict[str, Any]:
        """
        Perform web crawling using CDN-bypassed content with AI-enhanced API discovery
        
        Args:
            content: Pre-bypassed HTML content (optional)
            crawl_level: Level of crawling ('quick', 'smart', 'deep')
            
        Returns:
            Crawling results including AI-discovered endpoints
        """
        results = {
            'pages': [],
            'apis': [],
            'discovered_urls': [],
            'api_discovery': {}
        }
        
        # If content is provided, use it directly
        if content:
            logging.info("Using provided CDN-bypassed content for analysis")
            page_info = self.analyze_page_content(content, f"https://{self.domain}")
            if page_info:
                results['pages'].append(page_info)
                results['apis'].extend(page_info.get('api_references', []))
                results['discovered_urls'].extend(page_info.get('links', []))
        else:
            # Use browser to get content (with CDN bypass if needed)
            logging.info("Using browser to retrieve content for analysis")
            url = f"https://{self.domain}"
            content = self.browser_manager.get_page_content(url)
            
            if content:
                page_info = self.analyze_page_content(content, url)
                if page_info:
                    results['pages'].append(page_info)
                    results['apis'].extend(page_info.get('api_references', []))
                    results['discovered_urls'].extend(page_info.get('links', []))
        
        # Perform AI-enhanced API discovery
        logging.info(f"Starting AI-enhanced API discovery with {crawl_level} level")
        api_discovery_results = self.discover_api_endpoints(crawl_level=crawl_level)
        results['api_discovery'] = api_discovery_results
        
        # Combine all discovered APIs
        all_apis = set(results['apis'])
        for category in api_discovery_results.values():
            if isinstance(category, list):
                for endpoint in category:
                    if isinstance(endpoint, dict) and 'url' in endpoint:
                        all_apis.add(endpoint['url'])
        
        results['apis'] = list(all_apis)
        results['discovered_urls'] = list(set(results['discovered_urls']))
        
        return results
        
    def analyze_page_content(self, html_content: str, url: str) -> Optional[Dict[str, Any]]:
        """
        Analyze HTML content to extract useful information
        
        Args:
            html_content: HTML content to analyze
            url: Source URL of the content
            
        Returns:
            Dictionary with extracted information
        """
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Extract various elements
            content_info = {
                'url': url,
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
                
                # Add to discovered URLs
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
            content_info['text_content'] = text_content[:5000]  # Limit length
            
            logging.info(f"Successfully analyzed content from {url}")
            return content_info
            
        except Exception as e:
            logging.warning(f"Error analyzing content from {url}: {str(e)}")
            return None
    
    def discover_api_endpoints(self, crawl_level: str = 'smart', custom_endpoints: List[str] = None) -> Dict[str, Any]:
        """
        Discover API endpoints using AI-generated suggestions and common patterns
        
        Args:
            crawl_level: Level of crawling ('quick', 'smart', 'deep')
            custom_endpoints: Additional custom endpoints to test
            
        Returns:
            Dictionary containing discovered API endpoints
        """
        logging.info(f"Starting API endpoint discovery with {crawl_level} level")
        
        results = {
            'rest_apis': [],
            'graphql_endpoints': [],
            'swagger_endpoints': [],
            'other_apis': []
        }
        
        # Common API endpoints to check
        api_endpoints = [
            '/api', '/api/v1', '/api/v2', '/api/v3',
            '/graphql', '/graphiql', 
            '/swagger', '/swagger-ui.html', '/swagger.json', 
            '/openapi', '/openapi.json', '/api-docs', 
            '/rest', '/soap', '/rpc'
        ]
        
        # Add custom endpoints if provided
        if custom_endpoints:
            api_endpoints.extend(custom_endpoints)
        
        # For smart and deep modes, generate intelligent API endpoints using AI
        if crawl_level in ['smart', 'deep'] and hasattr(self, 'ai_integration') and self.ai_integration:
            logging.info(f"Generating intelligent API endpoints for {crawl_level} mode")
            try:
                # Get scraped content for AI-enhanced generation
                scraped_content = None
                url = f"https://{self.domain}"
                try:
                    scraped_content = self._scrape_single_page(url)
                except:
                    try:
                        url = f"http://{self.domain}"
                        scraped_content = self._scrape_single_page(url)
                    except:
                        logging.warning("Could not scrape content for AI analysis")
                        scraped_content = None
                
                # Generate intelligent API endpoints using AI
                if scraped_content:
                    try:
                        # Use the AI integration's target-specific wordlist for API endpoints
                        ai_endpoints = self.ai_integration.generate_target_specific_wordlist(
                            page_content=scraped_content,
                            domain=self.domain,
                            context="API endpoint discovery",
                            num_terms=30 if crawl_level == 'smart' else 50
                        )
                        if ai_endpoints:
                            # Convert to API-style paths and add leading slash if needed
                            api_style_endpoints = []
                            for ep in ai_endpoints:
                                # Clean the endpoint and ensure proper formatting
                                clean_ep = ep.strip('/')
                                # Add API-specific prefixes
                                api_style_endpoints.extend([
                                    f"/api/{clean_ep}",
                                    f"/api/v1/{clean_ep}",
                                    f"/api/v2/{clean_ep}",
                                    f"/{clean_ep}",
                                    f"/rest/{clean_ep}",
                                    f"/services/{clean_ep}"
                                ])
                            
                            limit = 30 if crawl_level == 'smart' else 50
                            api_endpoints.extend(api_style_endpoints[:limit])
                            logging.info(f"Generated {len(api_style_endpoints[:limit])} intelligent API endpoints from content analysis")
                    except Exception as e:
                        logging.warning(f"AI endpoint generation failed: {str(e)}")
            except Exception as e:
                logging.warning(f"Intelligent API endpoint generation failed: {str(e)}")
        
        # Test each endpoint
        max_endpoints = self.crawl_levels[crawl_level]['max_api_endpoints']
        endpoints_to_test = list(set(api_endpoints))[:max_endpoints]  # Remove duplicates and limit
        
        logging.info(f"Testing {len(endpoints_to_test)} API endpoints")
        
        # Debug: Show first few endpoints being tested
        if logging.getLogger().isEnabledFor(logging.DEBUG):
            logging.debug(f"Sample endpoints to test: {endpoints_to_test[:10]}")
        
        tested_count = 0
        found_count = 0
        
        for base_url in [f"https://{self.domain}", f"http://{self.domain}"]:
            for endpoint in endpoints_to_test:
                full_url = f"{base_url}{endpoint}"
                tested_count += 1
                try:
                    response = requests.head(full_url, timeout=5, allow_redirects=True)
                    
                    # Log response for debugging (only for non-404s or if debug enabled)
                    if response.status_code != 404 or logging.getLogger().isEnabledFor(logging.DEBUG):
                        logging.debug(f"Tested {full_url} -> Status: {response.status_code}")
                    
                    # Check for successful responses or specific status codes that indicate API presence
                    if response.status_code in [200, 401, 403, 405, 429]:  # API-like responses
                        found_count += 1
                        endpoint_info = {
                            'url': full_url,
                            'status_code': response.status_code,
                            'headers': dict(response.headers),
                            'content_type': response.headers.get('Content-Type', ''),
                            'server': response.headers.get('Server', '')
                        }
                        
                        # Enhanced categorization logic for better endpoint classification
                        content_type = response.headers.get('Content-Type', '').lower()
                        endpoint_path = endpoint.lower()
                        
                        # Check for GraphQL endpoints
                        if 'graphql' in endpoint_path or 'graphiql' in endpoint_path:
                            results['graphql_endpoints'].append(endpoint_info)
                        # Check for API documentation endpoints
                        elif any(term in endpoint_path for term in ['swagger', 'openapi', 'api-docs']):
                            results['swagger_endpoints'].append(endpoint_info)
                        # Enhanced REST API detection
                        elif (any(term in endpoint_path for term in ['api', 'rest']) or
                              # Common REST API endpoints without explicit 'api' keyword
                              any(term in endpoint_path for term in ['auth', 'login', 'oauth', 'token', 'user', 'users', 'admin']) or
                              # JSON response indicates likely API
                              'application/json' in content_type or
                              # XML response indicates likely API
                              'application/xml' in content_type or 'text/xml' in content_type):
                            results['rest_apis'].append(endpoint_info)
                        else:
                            results['other_apis'].append(endpoint_info)
                        
                        # Add to discovered APIs
                        self.discovered_apis.add(full_url)
                        logging.info(f"Found API endpoint: {full_url} (Status: {response.status_code})")
                        
                except requests.RequestException:
                    # Skip failed requests silently
                    continue
                except Exception as e:
                    logging.debug(f"Error testing endpoint {full_url}: {str(e)}")
                    continue
        
        total_found = len(results['rest_apis']) + len(results['graphql_endpoints']) + len(results['swagger_endpoints']) + len(results['other_apis'])
        logging.info(f"API discovery completed. Found {total_found} endpoints out of {tested_count} tested")
        logging.info(f"Endpoint breakdown - REST: {len(results['rest_apis'])}, GraphQL: {len(results['graphql_endpoints'])}, Swagger: {len(results['swagger_endpoints'])}, Other: {len(results['other_apis'])}")
        
        return results
    
    def _scrape_single_page(self, url: str) -> Optional[Dict[str, Any]]:
        """
        Scrape content from a single page for AI analysis
        
        Args:
            url: URL to scrape
            
        Returns:
            Dict containing page content suitable for AI analysis
        """
        try:
            content = self.browser_manager.get_page_content(url)
            if content:
                return self.analyze_page_content(content, url)
            else:
                # Fallback to requests
                response = requests.get(url, timeout=10)
                if response.status_code == 200:
                    return self.analyze_page_content(response.text, url)
        except Exception as e:
            logging.warning(f"Failed to scrape page {url}: {str(e)}")
        
        return None
            
    def run_crawl_level(self, level: str, content: str = None) -> Dict[str, Any]:
        """
        Run a specific crawl level (quick, smart, or deep)
        
        Args:
            level: The crawl level to run ('quick', 'smart', or 'deep')
            content: Pre-bypassed HTML content (optional)
        
        Returns:
            Dictionary containing results from all operations
        """
        if level not in self.crawl_levels:
            raise ValueError(f"Invalid crawl level: {level}. Must be one of {list(self.crawl_levels.keys())}")
        
        logging.info(f"Starting {level.upper()} level crawl for {self.domain}")
        
        # Perform crawling with AI-enhanced API discovery
        results = self.crawl_with_cdn_bypass(content=content, crawl_level=level)
        
        # Add crawl level information to results
        results['crawl_level'] = level
        results['crawl_config'] = self.crawl_levels[level]
        
        # Log summary
        total_apis = len(results.get('apis', []))
        total_urls = len(results.get('discovered_urls', []))
        pages_analyzed = len(results.get('pages', []))
        
        api_discovery = results.get('api_discovery', {})
        rest_apis = len(api_discovery.get('rest_apis', []))
        graphql_endpoints = len(api_discovery.get('graphql_endpoints', []))
        swagger_endpoints = len(api_discovery.get('swagger_endpoints', []))
        
        logging.info(f"Crawl completed - Pages: {pages_analyzed}, APIs: {total_apis}, URLs: {total_urls}")
        logging.info(f"API Discovery - REST: {rest_apis}, GraphQL: {graphql_endpoints}, Swagger: {swagger_endpoints}")
        
        return results
            
    def close(self):
        """Clean up resources"""
        self.browser_manager.close_browser()
        
if __name__ == "__main__":
    import argparse
    
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    # Parse arguments
    parser = argparse.ArgumentParser(description="Web crawler with CDN bypass support and AI-enhanced API discovery")
    parser.add_argument("domain", help="Domain to crawl")
    parser.add_argument("--content-file", help="Path to pre-fetched HTML content file")
    parser.add_argument("--crawl-level", choices=['quick', 'smart', 'deep'], default='smart',
                        help="Crawl level: quick (basic), smart (AI-enhanced), deep (comprehensive)")
    args = parser.parse_args()
    
    # Initialize crawler
    crawler = WebCrawler(args.domain)
    
    try:
        # Load content from file if provided
        content = None
        if args.content_file and os.path.exists(args.content_file):
            with open(args.content_file, 'r', encoding='utf-8') as f:
                content = f.read()
                logging.info(f"Loaded content from {args.content_file}")
                
        # Perform crawling with specified level
        results = crawler.run_crawl_level(args.crawl_level, content)
        
        # Print summary results
        print(f"\n=== CRAWL RESULTS ({args.crawl_level.upper()} LEVEL) ===")
        print(f"Domain: {args.domain}")
        print(f"Pages analyzed: {len(results.get('pages', []))}")
        print(f"Total URLs discovered: {len(results.get('discovered_urls', []))}")
        print(f"Total APIs discovered: {len(results.get('apis', []))}")
        
        # Print API discovery breakdown
        api_discovery = results.get('api_discovery', {})
        print(f"\n=== API DISCOVERY BREAKDOWN ===")
        print(f"REST APIs: {len(api_discovery.get('rest_apis', []))}")
        print(f"GraphQL endpoints: {len(api_discovery.get('graphql_endpoints', []))}")
        print(f"Swagger/OpenAPI: {len(api_discovery.get('swagger_endpoints', []))}")
        print(f"Other APIs: {len(api_discovery.get('other_apis', []))}")
        
        # Print some example endpoints if found
        if api_discovery.get('rest_apis'):
            print(f"\n=== SAMPLE REST API ENDPOINTS ===")
            for i, endpoint in enumerate(api_discovery['rest_apis'][:5]):
                print(f"{i+1}. {endpoint['url']} (Status: {endpoint['status_code']})")
        
        # Save results to file
        output_filename = f'results/{args.domain.replace(".", "_")}_crawl_{args.crawl_level}.json'
        os.makedirs('results', exist_ok=True)
        with open(output_filename, 'w') as f:
            json.dump(results, f, indent=2, default=str)
            
        print(f"\nResults saved to {output_filename}")
        
    except Exception as e:
        logging.error(f"Crawl failed: {str(e)}")
        print(f"Error: {str(e)}")
        
    finally:
        crawler.close()