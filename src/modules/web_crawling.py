import requests
import logging
from bs4 import BeautifulSoup
import re
from urllib.parse import urlparse
import urllib3

class WebCrawler:
    def __init__(self, domain):
        self.domain = domain

    def web_fingerprinting(self):
        """Fingerprint web technologies"""
        logging.info("Starting web fingerprinting")
        results = {}
        
        urls_to_check = [
            f"http://{self.domain}",
            f"https://{self.domain}",
            f"http://www.{self.domain}",
            f"https://www.{self.domain}"
        ]
        
        for url in urls_to_check:
            try:
                response = requests.get(url, timeout=5, allow_redirects=True)
                server = response.headers.get('Server', 'Not found')
                tech = response.headers.get('X-Powered-By', 'Not found')
                
                results[url] = {
                    'server': server,
                    'x_powered_by': tech,
                    'status_code': response.status_code,
                    'content_type': response.headers.get('Content-Type')
                }
                
                logging.info(f"Web fingerprint for {url}: Server={server}, Tech={tech}")
                
            except requests.RequestException as e:
                logging.warning(f"Failed to fingerprint {url}: {str(e)}")
        
        return results

    def directory_bruteforce(self, wordlist_path):
        """Brute force common web directories"""
        logging.info("Starting directory brute-forcing")
        found_dirs = []
        
        base_urls = [
            f"http://{self.domain}",
            f"https://{self.domain}",
            f"http://www.{self.domain}",
            f"https://www.{self.domain}"
        ]
        
        for base_url in base_urls:
            try:
                with open(wordlist_path, 'r') as f:
                    directories = f.read().splitlines()
                
                for directory in directories:
                    url = f"{base_url}/{directory}"
                    try:
                        response = requests.get(url, timeout=3)
                        if response.status_code < 400:
                            found_dirs.append({
                                'url': url,
                                'status': response.status_code,
                                'size': len(response.content)
                            })
                            logging.info(f"Found accessible directory: {url} ({response.status_code})")
                    except requests.RequestException:
                        continue
            except IOError as e:
                logging.error(f"Failed to read wordlist: {str(e)}")
                break
        
        return found_dirs

    def scrape_page_content(self, url, max_content_length=5000, headers=None):
        """Scrape and extract meaningful content from a webpage"""
        try:
            if headers is None:
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
                }
            
            # Configure session
            session = requests.Session()
            session.headers.update(headers)
            
            # Handle SSL certificate issues
            verify_ssl = True
            if 'netlify.app' in url or 'herokuapp.com' in url:
                verify_ssl = False
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            
            response = session.get(url, timeout=10, allow_redirects=True, verify=verify_ssl)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Extract various elements
            content_info = {
                'title': soup.title.string if soup.title else '',
                'meta_description': '',
                'links': [],
                'forms': [],
                'api_references': [],
                'javascript_files': [],
                'text_content': ''
            }
            
            # Get meta description
            meta_desc = soup.find('meta', attrs={'name': 'description'})
            if meta_desc:
                content_info['meta_description'] = meta_desc.get('content', '')
            
            # Extract links
            for link in soup.find_all('a', href=True):
                href = link['href']
                if href.startswith('/') or self.domain in href:
                    content_info['links'].append(href)
            
            # Extract form actions
            for form in soup.find_all('form', action=True):
                content_info['forms'].append(form['action'])
            
            # Look for API references in text
            text_content = soup.get_text()
            
            # Extract JavaScript files
            for script in soup.find_all('script', src=True):
                content_info['javascript_files'].append(script['src'])
            
            # Get clean text content
            text_content = soup.get_text(separator=' ', strip=True)
            content_info['text_content'] = text_content[:max_content_length]
            
            logging.info(f"Successfully scraped content from {url}")
            return content_info
            
        except requests.exceptions.SSLError as e:
            # Retry with SSL verification disabled
            try:
                logging.warning(f"SSL error for {url}, retrying without verification: {str(e)}")
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                
                response = requests.get(url, timeout=10, headers=headers, allow_redirects=True, verify=False)
                response.raise_for_status()
                
                soup = BeautifulSoup(response.content, 'html.parser')
                
                # Simplified extraction for retry
                content_info = {
                    'title': soup.title.string if soup.title else '',
                    'meta_description': '',
                    'links': [link['href'] for link in soup.find_all('a', href=True) if link['href'].startswith('/') or self.domain in link['href']],
                    'forms': [form['action'] for form in soup.find_all('form', action=True)],
                    'api_references': [],
                    'javascript_files': [script['src'] for script in soup.find_all('script', src=True)],
                    'text_content': soup.get_text(separator=' ', strip=True)[:max_content_length]
                }
                
                logging.info(f"Successfully scraped content from {url} (SSL verification disabled)")
                return content_info
                
            except Exception as retry_e:
                logging.warning(f"Failed to scrape {url} even without SSL verification: {str(retry_e)}")
                return None
                
        except requests.RequestException as e:
            logging.warning(f"Failed to scrape {url}: {str(e)}")
            return None
        except Exception as e:
            logging.warning(f"Error parsing content from {url}: {str(e)}")
            return None