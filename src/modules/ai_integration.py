"""
AI integration module for LLM-powered optimizations
"""
import logging
import os
import requests
import json
import re
from typing import List

class AIIntegration:
    def __init__(self, enabled=True):
        self.enabled = enabled
        self.api_key = os.getenv('GEMINI_API_KEY')
        self.base_url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent"
    
    def is_enabled(self):
        return self.enabled and self.api_key
    
    def enhance_subdomain_wordlist(self, target, base_wordlist):
        """Use AI to generate target-specific subdomain suggestions"""
        if not self.is_enabled():
            return []
        
        try:
            prompt = f"""
            Based on the target domain {target}, suggest additional subdomains that might exist.
            Consider common patterns, industry-specific terms, and geographic locations.
            Return only a JSON array of subdomain suggestions without any explanations.
            """
            
            response = self._query_gemini(prompt)
            suggestions = json.loads(response)
            return [s for s in suggestions if s not in base_wordlist]
        except Exception as e:
            logging.warning(f"AI wordlist enhancement failed: {str(e)}")
            return []
    
    def generate_directory_wordlist(self, target, content_analysis):
        """Generate intelligent directory wordlist based on content analysis"""
        if not self.is_enabled():
            return []
        
        try:
            prompt = f"""
            Analyze this website content and suggest directory paths that might exist:
            {json.dumps(content_analysis, indent=2)}
            
            Return only a JSON array of directory paths without any explanations.
            Focus on admin panels, API endpoints, and sensitive files.
            """
            
            response = self._query_gemini(prompt)
            return json.loads(response)
        except Exception as e:
            logging.warning(f"AI directory generation failed: {str(e)}")
            return []
    
    def filter_noise(self, results):
        """Filter out noise and low-value targets using AI"""
        if not self.is_enabled():
            return results
        
        try:
            prompt = f"""
            Analyze these reconnaissance results and identify low-value or noisy targets:
            {json.dumps(results, indent=2)}
            
            Return a JSON object with two arrays: 'keep' (high-value targets) and 'filter' (low-value targets).
            Consider CDN subdomains, mail servers, and common infrastructure as potential noise.
            """
            
            response = self._query_gemini(prompt)
            filtered = json.loads(response)
            return filtered.get('keep', results)
        except Exception as e:
            logging.warning(f"AI noise filtering failed: {str(e)}")
            return results
    
    def _query_gemini(self, prompt):
        """Query the Gemini API"""
        headers = {
            'Content-Type': 'application/json',
        }
        
        data = {
            "contents": [{
                "parts": [{
                    "text": prompt
                }]
            }]
        }
        
        response = requests.post(
            f"{self.base_url}?key={self.api_key}",
            headers=headers,
            json=data,
            timeout=30
        )
        
        response.raise_for_status()
        result = response.json()
        
        return result['candidates'][0]['content']['parts'][0]['text']