import requests
import logging
import re
import ast
import hashlib
from functools import lru_cache
import json
import aiohttp
import asyncio
from pathlib import Path

class AIIntegration:
    def __init__(self, gemini_api_key=None, openai_api_key=None, anthropic_api_key=None, cache_size=128, feedback_db_path=None):
        """
        Initialize the AI Integration module with multiple provider support
        
        Args:
            gemini_api_key (str, optional): API key for Google's Gemini
            openai_api_key (str, optional): API key for OpenAI
            anthropic_api_key (str, optional): API key for Anthropic
            cache_size (int, optional): Maximum size of the LRU cache
            feedback_db_path (str, optional): Path to the feedback database file
        """
        self.gemini_api_key = gemini_api_key
        self.openai_api_key = openai_api_key
        self.anthropic_api_key = anthropic_api_key
        self.cache_size = cache_size
        self.feedback_db_path = feedback_db_path
        
        self.available_providers = []
        
        if self.gemini_api_key:
            self.gemini_base_url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash-lite:generateContent?key=" + self.gemini_api_key
            self.available_providers.append("gemini")
            logging.info("Gemini API key configured")
            
        if self.openai_api_key:
            self.available_providers.append("openai")
            logging.info("OpenAI API key configured")
            
        if self.anthropic_api_key:
            self.available_providers.append("anthropic")
            logging.info("Anthropic API key configured")
        
        if not self.available_providers:
            logging.warning("No AI provider keys configured. Using fallback endpoint discovery only.")
            
        # Initialize feedback data
        self.feedback_data = self._load_feedback_data() if feedback_db_path else {}
        
    def _load_feedback_data(self):
        """Load historical feedback data about successful endpoint discoveries"""
        try:
            with open(self.feedback_db_path, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}
    
    def save_feedback(self, domain, endpoint, success):
        """Record feedback about endpoint discovery success"""
        if not self.feedback_db_path:
            return
            
        if domain not in self.feedback_data:
            self.feedback_data[domain] = {}
            
        # Record the success/failure
        self.feedback_data[domain][endpoint] = success
        
        # Save to disk
        with open(self.feedback_db_path, 'w') as f:
            json.dump(self.feedback_data, f)
            
    def detect_technology(self, page_content):
        """Detect technologies used by the website"""
        detected = set()
        
        # Analyze HTML content
        html_content = str(page_content.get('html', ''))
        
        # Framework detection patterns
        tech_patterns = {
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
        
        for tech, patterns in tech_patterns.items():
            if any(pattern.lower() in html_content.lower() for pattern in patterns):
                detected.add(tech)
        
        # Check for JS frameworks in script tags
        scripts = page_content.get('javascript_files', [])
        for script in scripts:
            if isinstance(script, str):
                script_lower = script.lower()
                if 'react' in script_lower or 'jsx' in script_lower:
                    detected.add('react')
                if 'vue' in script_lower:
                    detected.add('vue')
                if 'angular' in script_lower:
                    detected.add('angular')
        
        return detected
        
    def enhance_endpoints_with_learning(self, endpoints, domain):
        """Use historical data to prioritize endpoints that worked on similar domains"""
        if not self.feedback_data:
            return endpoints
            
        # Get domain TLD for finding similar domains
        tld = domain.split('.')[-1]
        similar_domains = [d for d in self.feedback_data.keys() if d.endswith('.' + tld)]
        
        # Count successful endpoints across similar domains
        success_counts = {}
        for d in similar_domains:
            for endpoint, success in self.feedback_data[d].items():
                if success:
                    success_counts[endpoint] = success_counts.get(endpoint, 0) + 1
        
        # Add successful endpoints from similar domains
        for endpoint, count in success_counts.items():
            if endpoint not in endpoints and count > 1:
                endpoints.append(endpoint)
                
        return endpoints

    def generate_ai_endpoints(self, page_content, domain):
        """Use available AI providers to generate intelligent endpoint suggestions"""
        if not self.available_providers or not page_content:
            return self.generate_intelligent_fallback_endpoints(page_content)
        
        # Create a hash of the content to use as cache key
        content_str = str(page_content)
        content_hash = hashlib.md5(content_str.encode()).hexdigest()
        
        # Try providers in order with fallback
        for provider in self.available_providers:
            try:
                if provider == "gemini":
                    endpoints = self._generate_with_gemini(page_content, domain, content_hash)
                elif provider == "openai":
                    endpoints = self._generate_with_openai(page_content, domain, content_hash)
                elif provider == "anthropic":
                    endpoints = self._generate_with_anthropic(page_content, domain, content_hash)
                else:
                    continue
                
                if endpoints:
                    # Score and validate endpoints
                    scored_endpoints = self.validate_and_score_endpoints(endpoints, domain, page_content)
                    # Apply learning from previous scans
                    enhanced_endpoints = self.enhance_endpoints_with_learning(scored_endpoints, domain)
                    return enhanced_endpoints
            except Exception as e:
                logging.warning(f"Provider {provider} failed: {str(e)}. Trying next provider.")
        
        # If all providers fail, use fallback
        return self.generate_intelligent_fallback_endpoints(page_content)
    
    def validate_and_score_endpoints(self, endpoints, domain, page_content):
        """Score and validate the generated endpoints based on likelihood"""
        scored_endpoints = []
        
        # Technology detection
        detected_tech = self.detect_technology(page_content)
        
        for endpoint in endpoints:
            score = 10  # Base score
            
            # Check for common patterns that are less likely
            if len(endpoint) > 50 or len(endpoint) < 2:
                score -= 5
                
            # Boost score for endpoints that match detected technology
            if any(tech in endpoint for tech in detected_tech):
                score += 5
                
            # Check if endpoint appears in page content
            if endpoint in str(page_content).lower():
                score += 3
                
            # Custom scoring rules for different endpoint types
            if 'api' in endpoint:
                score += 2
            if 'admin' in endpoint:
                score += 2
                
            scored_endpoints.append((endpoint, score))
        
        # Sort by score (highest first) and return
        return [ep for ep, score in sorted(scored_endpoints, key=lambda x: x[1], reverse=True)]
    
    @lru_cache(maxsize=128)
    def _cached_ai_request(self, provider, content_hash, domain):
        """Cached version of AI requests to avoid duplicate processing"""
        # This is a placeholder - the actual implementation depends on provider methods
        pass
        
    def _generate_with_gemini(self, page_content, domain, content_hash=None):
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
        
    def _generate_with_openai(self, page_content, domain, content_hash=None):
        """Generate endpoints using OpenAI"""
        if not self.openai_api_key:
            return None
            
        try:
            import openai  # Import here to make it optional
            
            # Set the API key
            openai.api_key = self.openai_api_key
            
            # Prepare the prompt
            prompt = f"""
            Analyze the following website content and suggest potential API endpoints, admin panels, and interesting directories 
            that might exist on this domain ({domain}).

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
            
            # Make the request to OpenAI
            response = openai.ChatCompletion.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "You are a cybersecurity tool that suggests potential endpoints for reconnaissance."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.7,
                max_tokens=1000
            )
            
            # Extract and parse response
            response_text = response.choices[0].message.content.strip()
            
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
                
                logging.info(f"Generated {len(cleaned_endpoints)} OpenAI-powered endpoints")
                return cleaned_endpoints[:25]
                
            except (ValueError, SyntaxError) as e:
                logging.warning(f"Failed to parse OpenAI response: {str(e)}")
                return None
                
        except Exception as e:
            logging.warning(f"OpenAI API error: {str(e)}")
            return None
        
    def _generate_with_anthropic(self, page_content, domain, content_hash=None):
        """Generate endpoints using Anthropic Claude"""
        if not self.anthropic_api_key:
            return None
            
        try:
            import anthropic  # Import here to make it optional
            
            # Initialize the Anthropic client
            client = anthropic.Anthropic(api_key=self.anthropic_api_key)
            
            # Prepare the prompt
            prompt = f"""
            Analyze the following website content and suggest potential API endpoints, admin panels, and interesting directories 
            that might exist on this domain ({domain}).

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
            
            # Make the request to Anthropic
            response = client.messages.create(
                model="claude-3-opus-20240229",
                max_tokens=1000,
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )
            
            # Extract and parse response
            response_text = response.content[0].text
            
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
                
                logging.info(f"Generated {len(cleaned_endpoints)} Anthropic-powered endpoints")
                return cleaned_endpoints[:25]
                
            except (ValueError, SyntaxError) as e:
                logging.warning(f"Failed to parse Anthropic response: {str(e)}")
                return None
                
        except Exception as e:
            logging.warning(f"Anthropic API error: {str(e)}")
            return None
            
    async def generate_ai_endpoints_async(self, page_content, domain):
        """Asynchronous version of endpoint generation using all available providers"""
        if not self.available_providers or not page_content:
            return self.generate_intelligent_fallback_endpoints(page_content)
        
        # Create a hash of the content to use as cache key
        content_str = str(page_content)
        content_hash = hashlib.md5(content_str.encode()).hexdigest()
        
        # Try each provider asynchronously
        for provider in self.available_providers:
            try:
                if provider == "gemini":
                    endpoints = await self._generate_with_gemini_async(page_content, domain, content_hash)
                elif provider == "openai":
                    endpoints = await self._generate_with_openai_async(page_content, domain, content_hash)
                elif provider == "anthropic":
                    endpoints = await self._generate_with_anthropic_async(page_content, domain, content_hash)
                else:
                    continue
                
                if endpoints:
                    # Score and validate endpoints
                    scored_endpoints = self.validate_and_score_endpoints(endpoints, domain, page_content)
                    # Apply learning from previous scans
                    enhanced_endpoints = self.enhance_endpoints_with_learning(scored_endpoints, domain)
                    return enhanced_endpoints
            except Exception as e:
                logging.warning(f"Provider {provider} failed: {str(e)}. Trying next provider.")
        
        # If all providers fail, use fallback
        return self.generate_intelligent_fallback_endpoints(page_content)
        
    async def _generate_with_gemini_async(self, page_content, domain, content_hash=None):
        """Asynchronous version of Gemini endpoint generation"""
        if not self.gemini_api_key:
            return None
            
        try:
            # Prepare the prompt for Gemini (same as before)
            prompt = f"""
            Analyze the following website content and suggest potential API endpoints, admin panels, and interesting directories 
            that might exist on this domain ({domain}).

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
                "contents": [{"parts": [{"text": prompt}]}]
            }
            
            # Make the request to Gemini API with retry logic
            max_retries = 2
            for attempt in range(max_retries):
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.post(
                            self.gemini_base_url,
                            json=gemini_request,
                            headers={"Content-Type": "application/json"},
                            timeout=30
                        ) as response:
                            if response.status == 503:
                                logging.warning(f"Gemini API service unavailable (attempt {attempt + 1}/{max_retries})")
                                if attempt == max_retries - 1:
                                    return self.generate_intelligent_fallback_endpoints(page_content)
                                await asyncio.sleep(1)  # Brief delay before retry
                                continue
                                
                            response_data = await response.json()
                            
                            if 'candidates' in response_data and len(response_data['candidates']) > 0:
                                candidate = response_data['candidates'][0]
                                if 'content' in candidate and 'parts' in candidate['content']:
                                    response_text = candidate['content']['parts'][0]['text'].strip()
                                    
                                    # Parse the response (same as synchronous version)
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
                                        
                                        logging.info(f"Generated {len(cleaned_endpoints)} AI-powered endpoints (async)")
                                        return cleaned_endpoints[:25]
                                        
                                    except (ValueError, SyntaxError) as e:
                                        logging.warning(f"Failed to parse AI response: {str(e)}")
                                        return self.generate_intelligent_fallback_endpoints(page_content)
                    
                except aiohttp.ClientError as e:
                    logging.warning(f"Gemini API request failed: {str(e)}")
                    if attempt == max_retries - 1:
                        return self.generate_intelligent_fallback_endpoints(page_content)
                    await asyncio.sleep(1)  # Brief delay before retry
            
        except Exception as e:
            logging.warning(f"Failed to generate AI endpoints: {str(e)}")
            return self.generate_intelligent_fallback_endpoints(page_content)
            
        return self.generate_intelligent_fallback_endpoints(page_content)
        
    async def _generate_with_openai_async(self, page_content, domain, content_hash=None):
        """Asynchronous version of OpenAI endpoint generation"""
        if not self.openai_api_key:
            return None
            
        try:
            import openai  # Import here to make it optional
            
            # Set the API key
            openai.api_key = self.openai_api_key
            
            # Prepare the prompt
            prompt = f"""
            Analyze the following website content and suggest potential API endpoints, admin panels, and interesting directories 
            that might exist on this domain ({domain}).

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
            
            # Make the request to OpenAI asynchronously if available (depends on OpenAI library version)
            try:
                # Try using the async client if available
                response = await openai.ChatCompletion.acreate(
                    model="gpt-3.5-turbo",
                    messages=[
                        {"role": "system", "content": "You are a cybersecurity tool that suggests potential endpoints for reconnaissance."},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=0.7,
                    max_tokens=1000
                )
                response_text = response.choices[0].message.content.strip()
            except AttributeError:
                # Fall back to sync version if async not available
                response = openai.ChatCompletion.create(
                    model="gpt-3.5-turbo",
                    messages=[
                        {"role": "system", "content": "You are a cybersecurity tool that suggests potential endpoints for reconnaissance."},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=0.7,
                    max_tokens=1000
                )
                response_text = response.choices[0].message.content.strip()
            
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
                
                logging.info(f"Generated {len(cleaned_endpoints)} OpenAI-powered endpoints (async)")
                return cleaned_endpoints[:25]
                
            except (ValueError, SyntaxError) as e:
                logging.warning(f"Failed to parse OpenAI response: {str(e)}")
                return None
                
        except Exception as e:
            logging.warning(f"OpenAI API error: {str(e)}")
            return None
            
    async def _generate_with_anthropic_async(self, page_content, domain, content_hash=None):
        """Asynchronous version of Anthropic endpoint generation"""
        if not self.anthropic_api_key:
            return None
            
        try:
            import anthropic  # Import here to make it optional
            
            # Initialize the Anthropic client
            client = anthropic.Anthropic(api_key=self.anthropic_api_key)
            
            # Prepare the prompt
            prompt = f"""
            Analyze the following website content and suggest potential API endpoints, admin panels, and interesting directories 
            that might exist on this domain ({domain}).

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
            
            # Make the request to Anthropic (synchronous since their Python library doesn't currently support async)
            response = client.messages.create(
                model="claude-3-opus-20240229",
                max_tokens=1000,
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )
            
            # Extract and parse response
            response_text = response.content[0].text
            
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
                
                logging.info(f"Generated {len(cleaned_endpoints)} Anthropic-powered endpoints (async)")
                return cleaned_endpoints[:25]
                
            except (ValueError, SyntaxError) as e:
                logging.warning(f"Failed to parse Anthropic response: {str(e)}")
                return None
                
        except Exception as e:
            logging.warning(f"Anthropic API error: {str(e)}")
            return None

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