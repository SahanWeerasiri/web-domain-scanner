import os
import time
from typing import List
import requests
import logging
import re
import ast
from dotenv import load_dotenv

load_dotenv()

class AIIntegration:
    def __init__(self, gemini_api_key=None):
        self.gemini_api_key = os.getenv("GEMINI_API_KEY")
        if self.gemini_api_key:
            self.gemini_base_url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash-lite:generateContent?key=" + self.gemini_api_key
            logging.info("Gemini API key configured for requests-based integration")
        else:
            logging.warning("Gemini API key not provided. AI-powered endpoint discovery will be disabled.")

    def generate_target_specific_wordlist(self, page_content=None, domain=None, context: str = None, num_terms: int = 25) -> List[str]:
        """
        Generate target-specific terms for directory bruteforcing using AI analysis
        
        Args:
            page_content: Scraped page content for AI analysis
            domain: Target domain for context
            context: Additional context about the target
            num_terms: Number of terms to generate
        """
        if self.gemini_api_key and page_content:
            return self._generate_ai_wordlist(page_content, domain, context, num_terms)
        else:
            return self._generate_intelligent_wordlist(page_content, domain, context, num_terms)

    def _generate_ai_wordlist(self, page_content, domain, context, num_terms):
        """Use Gemini AI to generate intelligent endpoint suggestions"""
        try:
            # Prepare the prompt for targeted wordlist generation
            prompt = f"""
            Analyze the following website content and domain to generate a targeted wordlist for directory bruteforcing.
            
            Domain: {domain}
            Additional Context: {context or 'None provided'}
            
            Website Title: {page_content.get('title', 'N/A')}
            Meta Description: {page_content.get('meta_description', 'N/A')}
            
            Found Links (sample): {page_content.get('links', [])[:15]}
            Form Actions: {page_content.get('forms', [])[:10]}
            Detected API References: {page_content.get('api_references', [])[:10]}
            JavaScript Files (sample): {page_content.get('javascript_files', [])[:8]}
            
            Content Sample: {page_content.get('text_content', '')[:1500]}

            Based on this analysis, suggest {num_terms} potential directories, endpoints, and admin panels that might exist on this domain.
            Focus on:
            1. Technology-specific paths (based on detected frameworks)
            2. Business-specific paths (based on content analysis)
            3. Common administrative interfaces
            4. API endpoints and versioned paths
            5. Any unique patterns you identify
            
            Return ONLY a Python list of strings, no explanations.
            Example format: ['api/v1', 'admin', 'wp-admin', 'dashboard', 'api/users', 'rest/auth', 'control-panel']
            """
            
            # Prepare the request payload
            gemini_request = {
                "contents": [
                    {
                        "parts": [
                            {
                                "text": prompt
                            }
                        ]
                    }
                ]
            }
            
            # Make the request to Gemini API
            url = f"{self.gemini_base_url}"
            headers = {"Content-Type": "application/json"}
            
            response = requests.post(url, json=gemini_request, headers=headers, timeout=30)
            response.raise_for_status()
            response_data = response.json()
            
            if 'candidates' in response_data and len(response_data['candidates']) > 0:
                candidate = response_data['candidates'][0]
                if 'content' in candidate and 'parts' in candidate['content']:
                    response_text = candidate['content']['parts'][0]['text'].strip()
                    
                    # Parse the AI response
                    endpoints = self._parse_ai_response(response_text)
                    
                    if endpoints:
                        logging.info(f"Generated {len(endpoints)} AI-powered target-specific terms")
                        return endpoints[:num_terms]
            
            # Fallback if AI response parsing fails
            return self._generate_intelligent_wordlist(page_content, domain, context, num_terms)
                    
        except Exception as e:
            logging.warning(f"Failed to generate AI wordlist: {str(e)}")
            return self._generate_intelligent_wordlist(page_content, domain, context, num_terms)

    def _parse_ai_response(self, response_text):
        """Parse the AI response to extract endpoints"""
        try:
            if response_text.startswith('[') and response_text.endswith(']'):
                return ast.literal_eval(response_text)
            else:
                # Try to find a list pattern in the response
                list_match = re.search(r'\[(.*?)\]', response_text, re.DOTALL)
                if list_match:
                    list_content = '[' + list_match.group(1) + ']'
                    return ast.literal_eval(list_content)
                else:
                    # Extract lines that look like endpoints
                    lines = response_text.split('\n')
                    endpoints = []
                    for line in lines:
                        line = line.strip().strip("'\"").strip(',')
                        if (line and not line.startswith('#') and 
                            len(line) < 100 and not line.startswith('http')):
                            endpoints.append(line)
                    return endpoints
        except (ValueError, SyntaxError) as e:
            logging.warning(f"Failed to parse AI response: {str(e)}")
            return []

    def _generate_intelligent_wordlist(self, page_content, domain, context, num_terms):
        """Generate intelligent endpoint suggestions based on scraped content analysis"""
        endpoints = set()
        
        # Get current and previous years
        current_year = str(time.localtime().tm_year)
        previous_year = str(int(current_year) - 1)
        two_years_ago = str(int(current_year) - 2)
        
        # Base technology-specific endpoints
        base_endpoints = [
            'admin', 'api', 'dashboard', 'console', 'backend', 'portal',
            'secure', 'private', 'internal', 'system', 'control', 'manage',
            'auth', 'oauth', 'token', 'session', 'user', 'users', 'account',
            'config', 'settings', 'health', 'status', 'ping', 'test', 'debug',
            'log', 'logs', 'monitor', 'metrics', 'stats', 'statistics'
        ]
        endpoints.update(base_endpoints)
        
        # Year-based terms
        for term in base_endpoints:
            endpoints.update([
                f"{term}-{current_year}", f"{term}{current_year}",
                f"{term}-{previous_year}", f"{term}{previous_year}",
                f"{term}-{two_years_ago}", f"{term}{two_years_ago}"
            ])
        
        # Domain-specific terms
        if domain:
            domain_parts = domain.split('.')
            domain_name = domain_parts[0] if len(domain_parts) > 1 else domain
            
            for term in base_endpoints:
                endpoints.update([
                    f"{term}-{domain_name}", f"{domain_name}-{term}",
                    f"{term}_{domain_name}", f"{domain_name}_{term}"
                ])
        
        # Analyze page content if available
        if page_content:
            # Technology detection from content
            title = page_content.get('title', '').lower()
            content = page_content.get('text_content', '').lower()
            
            # Framework-specific endpoints
            if any(tech in title or tech in content for tech in ['wordpress', 'wp']):
                endpoints.update(['wp-admin', 'wp-content', 'wp-includes', 'wp-json', 'wp-login'])
            if any(tech in title or tech in content for tech in ['drupal']):
                endpoints.update(['node', 'admin', 'user', 'sites/default', 'sites/all'])
            if any(tech in title or tech in content for tech in ['django']):
                endpoints.update(['admin', 'api', 'static', 'media', 'accounts'])
            if any(tech in title or tech in content for tech in ['laravel', 'php']):
                endpoints.update(['admin', 'api', 'storage', 'public', 'resources'])
            if any(tech in title or tech in content for tech in ['react', 'vue', 'angular']):
                endpoints.update(['assets', 'static', 'build', 'dist', 'public'])
            if any(tech in title or tech in content for tech in ['next.js', 'nextjs']):
                endpoints.update(['_next', '_next/data', 'api', 'static'])
            if any(tech in title or tech in content for tech in ['nuxt']):
                endpoints.update(['_nuxt', 'api', 'static'])
            
            # Content-based endpoints
            content_indicators = {
                'login': ['login', 'signin', 'sign-in', 'auth', 'authenticate', 'session'],
                'register': ['register', 'signup', 'sign-up', 'create-account', 'join'],
                'dashboard': ['dashboard', 'home', 'main', 'overview', 'console'],
                'profile': ['profile', 'account', 'me', 'user', 'settings', 'preferences'],
                'upload': ['upload', 'files', 'media', 'assets', 'images', 'documents'],
                'download': ['download', 'files', 'assets', 'resources', 'exports'],
                'search': ['search', 'find', 'query', 'filter', 'discover'],
                'contact': ['contact', 'support', 'help', 'faq', 'about'],
                'blog': ['blog', 'posts', 'articles', 'news', 'stories', 'content'],
                'shop': ['products', 'shop', 'store', 'cart', 'checkout', 'orders'],
                'api': ['api', 'rest', 'graphql', 'endpoint', 'v1', 'v2', 'v3']
            }
            
            for indicator, terms in content_indicators.items():
                if indicator in content:
                    endpoints.update(terms)
            
            # Extract keywords from context if provided
            if context:
                keywords = re.findall(r'\b[a-zA-Z]{4,}\b', context.lower())
                for keyword in keywords[:8]:  # Use top keywords
                    for term in base_endpoints:
                        endpoints.update([
                            f"{term}-{keyword}", f"{keyword}-{term}",
                            f"{term}_{keyword}", f"{keyword}_{term}"
                        ])
        
        # Clean and filter endpoints
        cleaned_endpoints = []
        for endpoint in endpoints:
            if isinstance(endpoint, str) and endpoint:
                endpoint = endpoint.strip().strip('/').lower()
                if (len(endpoint) > 0 and len(endpoint) < 30 and 
                    endpoint not in ['', 'www', 'http', 'https'] and
                    not endpoint.startswith(('javascript:', 'mailto:', '#'))):
                    cleaned_endpoints.append(endpoint)
        
        # Remove duplicates and sort
        unique_endpoints = list(set(cleaned_endpoints))
        unique_endpoints.sort(key=lambda x: (len(x), x))
        
        result = unique_endpoints[:num_terms]
        logging.info(f"Generated {len(result)} intelligent target-specific terms")
        return result

    def generate_ai_endpoints(self, page_content, domain):
        """Use Gemini AI with requests to generate intelligent endpoint suggestions"""
        if not self.gemini_api_key or not page_content:
            return self.generate_intelligent_fallback_endpoints(page_content)
        
        try:
            # Prepare the prompt for Gemini
            prompt = f"""
            Analyze the following website content and suggest potential API endpoints, admin panels, and interesting directories that might exist on this domain ({domain}).

            Website Title: {page_content.get('title', 'N/A')}
            Meta Description: {page_content.get('meta_description', 'N/A')}
            
            Found Links: {page_content.get('links', [])[:20]}
            Form Actions: {page_content.get('forms', [])}
            Detected API References: {page_content.get('api_references', [])}
            JavaScript Files: {page_content.get('javascript_files', [])[:10]}
            
            Sample Content: {page_content.get('text_content', '')[:1000]}

            Based on this analysis, suggest 15-25 potential endpoints that might exist on this domain.
            Return ONLY a Python list of strings, no explanations.
            Example format: ['api/v1', 'admin', 'login', 'dashboard', 'api/users', 'rest/auth']
            """
            
            # Prepare the request payload
            gemini_request = {
                "contents": [
                    {
                        "parts": [
                            {
                                "text": prompt
                            }
                        ]
                    }
                ]
            }
            
            # Make the request to Gemini API with retry logic
            max_retries = 2
            for attempt in range(max_retries):
                try:
                    url = f"{self.gemini_base_url}"
                    headers = {
                        "Content-Type": "application/json"
                    }
                    
                    response = requests.post(url, json=gemini_request, headers=headers, timeout=30)
                    
                    if response.status_code == 503:
                        logging.warning(f"Gemini API service unavailable (attempt {attempt + 1}/{max_retries}). Using intelligent fallback.")
                        if attempt == max_retries - 1:
                            return self.generate_intelligent_fallback_endpoints(page_content)
                        continue
                    
                    response.raise_for_status()
                    response_data = response.json()
                    
                    if 'candidates' in response_data and len(response_data['candidates']) > 0:
                        candidate = response_data['candidates'][0]
                        if 'content' in candidate and 'parts' in candidate['content']:
                            response_text = candidate['content']['parts'][0]['text'].strip()
                            
                            # Parse the response
                            try:
                                if response_text.startswith('[') and response_text.endswith(']'):
                                    endpoints = ast.literal_eval(response_text)
                                else:
                                    list_match = re.search(r'\[(.*?)\]', response_text, re.DOTALL)
                                    if list_match:
                                        list_content = '[' + list_match.group(1) + ']'
                                        endpoints = ast.literal_eval(list_content)
                                    else:
                                        lines = response_text.split('\n')
                                        endpoints = []
                                        for line in lines:
                                            line = line.strip().strip("'\"").strip(',')
                                            if line and not line.startswith('#') and len(line) < 100:
                                                endpoints.append(line)
                                
                                # Clean up the endpoints
                                cleaned_endpoints = []
                                for endpoint in endpoints:
                                    if isinstance(endpoint, str):
                                        endpoint = endpoint.strip().strip("'\"").strip('/')
                                        if endpoint and len(endpoint) > 0 and len(endpoint) < 100:
                                            cleaned_endpoints.append(endpoint)
                                
                                logging.info(f"Generated {len(cleaned_endpoints)} AI-powered endpoints")
                                return cleaned_endpoints[:25]
                                
                            except (ValueError, SyntaxError) as e:
                                logging.warning(f"Failed to parse AI response: {str(e)}")
                                return self.generate_intelligent_fallback_endpoints(page_content)
                    break
                    
                except requests.RequestException as e:
                    if attempt == max_retries - 1:
                        logging.warning(f"Failed to make request to Gemini API after {max_retries} attempts: {str(e)}")
                        return self.generate_intelligent_fallback_endpoints(page_content)
                    logging.warning(f"Gemini API request failed (attempt {attempt + 1}/{max_retries}): {str(e)}")
                    
        except Exception as e:
            logging.warning(f"Failed to generate AI endpoints: {str(e)}")
            return self.generate_intelligent_fallback_endpoints(page_content)
        
        return self.generate_intelligent_fallback_endpoints(page_content)

    def generate_intelligent_fallback_endpoints(self, page_content):
        """Generate intelligent endpoint suggestions based on scraped content analysis"""
        if not page_content:
            return []
        
        endpoints = set()
        
        # Base technology-specific endpoints
        base_endpoints = [
            'api', 'api/v1', 'api/v2', 'rest', 'graphql', 'swagger', 'docs',
            'admin', 'login', 'dashboard', 'panel', 'manage', 'control',
            'auth', 'oauth', 'token', 'session', 'user', 'users',
            'config', 'settings', 'health', 'status', 'ping', 'test'
        ]
        endpoints.update(base_endpoints)
        
        # Analyze title for technology indicators
        title = page_content.get('title', '').lower()
        if 'react' in title or 'vue' in title or 'angular' in title:
            endpoints.update(['assets', 'static', 'build', 'dist', 'public'])
        if 'wordpress' in title or 'wp' in title:
            endpoints.update(['wp-admin', 'wp-content', 'wp-includes', 'wp-json'])
        if 'drupal' in title:
            endpoints.update(['node', 'admin', 'user', 'sites/default'])
        if 'django' in title:
            endpoints.update(['admin', 'api', 'static', 'media'])
        if 'laravel' in title or 'php' in title:
            endpoints.update(['admin', 'api', 'storage', 'public'])
        
        # Analyze links for patterns
        links = page_content.get('links', [])
        for link in links:
            if isinstance(link, str):
                path_parts = [part for part in link.split('/') if part and len(part) > 1]
                for part in path_parts[:3]:
                    if part not in ['http:', 'https:', 'www'] and len(part) < 20:
                        endpoints.add(part.lower())
        
        # Analyze form actions
        forms = page_content.get('forms', [])
        for form_action in forms:
            if isinstance(form_action, str) and form_action.startswith('/'):
                path_parts = form_action.strip('/').split('/')
                if path_parts and len(path_parts[0]) > 1:
                    endpoints.add(path_parts[0])
        
        # Look for API references in the content
        api_refs = page_content.get('api_references', [])
        for ref in api_refs:
            if isinstance(ref, str):
                clean_ref = ref.strip('/').split('?')[0]
                if clean_ref and len(clean_ref) < 50:
                    endpoints.add(clean_ref)
        
        # Analyze JavaScript files for common patterns
        js_files = page_content.get('javascript_files', [])
        js_indicators = {
            'react': ['components', 'hooks', 'context', 'redux'],
            'vue': ['components', 'store', 'router'],
            'angular': ['services', 'components', 'modules'],
            'node': ['routes', 'controllers', 'middleware'],
            'express': ['routes', 'public', 'views']
        }
        
        for js_file in js_files:
            if isinstance(js_file, str):
                js_lower = js_file.lower()
                for tech, indicators in js_indicators.items():
                    if tech in js_lower:
                        endpoints.update(indicators)
                        break
        
        # Content-based analysis
        content = page_content.get('text_content', '').lower()
        
        # Look for common web app terms
        if 'login' in content or 'sign in' in content:
            endpoints.update(['login', 'signin', 'auth', 'authenticate'])
        if 'register' in content or 'sign up' in content:
            endpoints.update(['register', 'signup', 'create-account'])
        if 'dashboard' in content:
            endpoints.update(['dashboard', 'home', 'main'])
        if 'profile' in content or 'account' in content:
            endpoints.update(['profile', 'account', 'me', 'user'])
        if 'upload' in content:
            endpoints.update(['upload', 'files', 'media', 'assets'])
        if 'download' in content:
            endpoints.update(['download', 'files', 'assets'])
        if 'search' in content:
            endpoints.update(['search', 'find', 'query'])
        if 'contact' in content:
            endpoints.update(['contact', 'support', 'help'])
        if 'blog' in content or 'post' in content:
            endpoints.update(['blog', 'posts', 'articles', 'news'])
        if 'product' in content or 'shop' in content:
            endpoints.update(['products', 'shop', 'store', 'cart'])
        if 'documentation' in content or 'docs' in content:
            endpoints.update(['docs', 'documentation', 'help', 'guide'])
        
        # Technology-specific endpoints based on content
        if 'rest' in content or 'restful' in content:
            endpoints.update(['api/rest', 'rest/v1', 'restapi'])
        if 'graphql' in content:
            endpoints.update(['graphql', 'graphiql', 'api/graphql'])
        if 'websocket' in content or 'socket.io' in content:
            endpoints.update(['socket.io', 'ws', 'websocket'])
        if 'oauth' in content:
            endpoints.update(['oauth', 'oauth2', 'auth/oauth'])
        if 'jwt' in content or 'token' in content:
            endpoints.update(['auth/token', 'api/token', 'token'])
        
        # Framework-specific patterns
        if 'next.js' in content or 'nextjs' in content:
            endpoints.update(['_next', 'api', 'static'])
        if 'nuxt' in content:
            endpoints.update(['_nuxt', 'api'])
        if 'gatsby' in content:
            endpoints.update(['static', 'public'])
        
        # Convert to list and clean up
        cleaned_endpoints = []
        for endpoint in endpoints:
            if isinstance(endpoint, str) and endpoint:
                endpoint = endpoint.strip().strip('/').lower()
                if (len(endpoint) > 0 and len(endpoint) < 30 and 
                    endpoint not in ['', 'www', 'http', 'https'] and
                    not endpoint.startswith('javascript:') and
                    not endpoint.startswith('mailto:')):
                    cleaned_endpoints.append(endpoint)
        
        # Remove duplicates and sort
        unique_endpoints = list(set(cleaned_endpoints))
        unique_endpoints.sort(key=lambda x: (len(x), x))
        
        result = unique_endpoints[:20]
        logging.info(f"Generated {len(result)} intelligent fallback endpoints from content analysis")
        return result