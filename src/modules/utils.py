import os
import re
import logging
from urllib.parse import urlparse

def sanitize_domain(domain_or_url):
    """Extract and sanitize domain for filesystem use"""
    if '://' in domain_or_url:
        parsed = urlparse(domain_or_url)
        domain = parsed.netloc
        if domain.startswith('www.'):
            domain = domain[4:]
    else:
        domain = domain_or_url
    
    # Sanitize domain for filesystem use
    sanitized_domain = re.sub(r'[^a-zA-Z0-9-]', '_', domain)
    return domain, sanitized_domain

def create_output_directory(domain, timestamp):
    """Create output directory for results"""
    sanitized_domain = re.sub(r'[^a-zA-Z0-9-]', '_', domain)
    output_dir = f"recon_results_{sanitized_domain}_{timestamp}"
    os.makedirs(output_dir, exist_ok=True)
    return output_dir

def create_web_wordlist(output_dir, common_dirs=None):
    """Create a default web wordlist if none exists"""
    if common_dirs is None:
        common_dirs = [
            'admin', 'login', 'wp-admin', 'wp-login', 
            'api', 'test', 'backup', 'assets', 'images'
        ]
    
    wordlist_path = os.path.join(output_dir, 'web_wordlist.txt')
    if not os.path.exists(wordlist_path):
        with open(wordlist_path, 'w') as f:
            f.write('\n'.join(common_dirs))
    
    return wordlist_path