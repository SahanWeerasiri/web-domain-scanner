#!/usr/bin/env python3

import unittest
import logging
import sys
import os
from unittest.mock import patch, MagicMock, Mock
import socket
import dns.resolver
import dns.zone
import requests

# Add the src directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

try:
    from modules.domain_enumeration import DomainEnumeration, EnumerationConfig, RateLimiter
except ImportError as e:
    print(f"Import error: {e}")
    print(f"Current path: {sys.path}")
    print(f"Looking for modules in: {os.path.join(os.path.dirname(__file__), '..', 'src')}")
    sys.exit(1)

class TestDomainEnumeration(unittest.TestCase):
    """Test suite for domain enumeration functionality"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.test_domain = "example.com"
        self.config = EnumerationConfig()
        self.config.rate_limit = 100  # Faster for testing
        self.config.timeout = 1
        self.config.thread_count = 2
        self.enumerator = DomainEnumeration(self.test_domain, self.config)
        
        # Set up logging to capture logs during tests
        self.log_messages = []
        self.test_handler = logging.Handler()
        self.test_handler.emit = lambda record: self.log_messages.append(record.getMessage())
        logging.getLogger().addHandler(self.test_handler)
        logging.getLogger().setLevel(logging.INFO)
    
    def tearDown(self):
        """Clean up after tests"""
        logging.getLogger().removeHandler(self.test_handler)
    
    def test_initialization(self):
        """Test proper initialization of DomainEnumeration"""
        self.assertEqual(self.enumerator.domain, self.test_domain)
        self.assertIsInstance(self.enumerator.config, EnumerationConfig)
        self.assertIn('subdomains', self.enumerator.results)
        self.assertIn('dns_records', self.enumerator.results)
        self.assertIn('passive_data', self.enumerator.results)
        self.assertIn('active_discovery', self.enumerator.results)
        
    def test_rate_limiter(self):
        """Test rate limiter functionality"""
        rate_limiter = RateLimiter(rate=10)
        
        # Test initial state
        self.assertEqual(rate_limiter.rate, 10)
        
        # Test token acquisition
        start_time = time.time()
        rate_limiter.acquire()
        end_time = time.time()
        
        # Should be near instantaneous for first call
        self.assertLess(end_time - start_time, 0.1)
    
    @patch('socket.gethostbyname')
    def test_check_subdomain_success(self, mock_gethostbyname):
        """Test successful subdomain checking"""
        # Mock successful DNS resolution
        mock_gethostbyname.return_value = '1.2.3.4'
        
        result = self.enumerator._check_subdomain('www')
        
        self.assertEqual(result, f'www.{self.test_domain}')
        mock_gethostbyname.assert_called_once_with(f'www.{self.test_domain}')
        
        # Check logging
        self.assertTrue(any('Found subdomain: www.example.com' in msg for msg in self.log_messages))
    
    @patch('socket.gethostbyname')
    @patch.object(DomainEnumeration, '_doh_query')
    def test_check_subdomain_with_doh_fallback(self, mock_doh_query, mock_gethostbyname):
        """Test subdomain checking with DoH fallback"""
        # Mock DNS failure and DoH success
        mock_gethostbyname.side_effect = socket.gaierror("DNS resolution failed")
        mock_doh_query.return_value = f'test.{self.test_domain}'
        
        self.enumerator.config.doh_fallback = True
        result = self.enumerator._check_subdomain('test')
        
        self.assertEqual(result, f'test.{self.test_domain}')
        mock_doh_query.assert_called_once_with(f'test.{self.test_domain}')
    
    @patch('socket.gethostbyname')
    def test_check_subdomain_failure(self, mock_gethostbyname):
        """Test subdomain checking failure"""
        # Mock DNS failure
        mock_gethostbyname.side_effect = socket.gaierror("DNS resolution failed")
        
        self.enumerator.config.doh_fallback = False
        result = self.enumerator._check_subdomain('nonexistent')
        
        self.assertIsNone(result)
    
    def test_generate_dynamic_wordlist(self):
        """Test dynamic wordlist generation"""
        wordlist = self.enumerator._generate_dynamic_wordlist()
        
        self.assertIsInstance(wordlist, list)
        self.assertGreater(len(wordlist), 0)
        
        # Check that common subdomains are included
        common_terms = ['www', 'mail', 'api', 'admin']
        for term in common_terms:
            self.assertIn(term, wordlist)
    
    def test_generate_target_specific_terms(self):
        """Test target-specific term generation"""
        terms = self.enumerator._generate_target_specific_terms()
        
        self.assertIsInstance(terms, list)
        self.assertGreater(len(terms), 0)
        
        # Should contain organization-specific terms
        org_name = self.test_domain.split('.')[0]  # 'example'
        self.assertTrue(any(org_name in term for term in terms))
    
    def test_generate_llm_based_terms(self):
        """Test LLM-based term generation"""
        # Test with educational domain
        edu_enumerator = DomainEnumeration("university.edu", self.config)
        edu_terms = edu_enumerator._generate_llm_based_terms()
        
        self.assertIsInstance(edu_terms, list)
        self.assertGreater(len(edu_terms), 0)
        
        # Should contain educational terms
        edu_keywords = ['student', 'faculty', 'library', 'research']
        self.assertTrue(any(keyword in edu_terms for keyword in edu_keywords))
        
        # Test with government domain
        gov_enumerator = DomainEnumeration("agency.gov", self.config)
        gov_terms = gov_enumerator._generate_llm_based_terms()
        
        self.assertIsInstance(gov_terms, list)
        self.assertGreater(len(gov_terms), 0)
        
        # Should contain government terms
        gov_keywords = ['citizen', 'service', 'department']
        self.assertTrue(any(keyword in gov_terms for keyword in gov_keywords))
    
    def test_generate_permutations(self):
        """Test subdomain permutation generation"""
        permutations = self.enumerator._generate_permutations()
        
        self.assertIsInstance(permutations, list)
        self.assertGreater(len(permutations), 0)
        
        # Check for expected permutation patterns
        base_name = self.test_domain.split('.')[0]  # 'example'
        expected_patterns = [f'{base_name}1', f'new{base_name}', f'{base_name}-test']
        
        # At least some expected patterns should be present
        found_patterns = sum(1 for pattern in expected_patterns if pattern in permutations)
        self.assertGreater(found_patterns, 0)
    
    @patch.object(DomainEnumeration, '_check_subdomain')
    def test_dns_permutation_attack(self, mock_check_subdomain):
        """Test DNS permutation attack"""
        # Mock some successful responses
        mock_check_subdomain.side_effect = lambda x: f'{x}.{self.test_domain}' if x.endswith('1') else None
        
        results = self.enumerator._dns_permutation_attack()
        
        self.assertIsInstance(results, list)
        # Should have found some permutations ending with '1'
        self.assertTrue(any('1.example.com' in result for result in results))
    
    @patch('dns.resolver.resolve')
    def test_attempt_zone_transfer(self, mock_resolve):
        """Test DNS zone transfer attempt"""
        # Mock nameserver discovery
        mock_ns_record = Mock()
        mock_ns_record.__str__ = Mock(return_value='ns1.example.com')
        mock_resolve.return_value = [mock_ns_record]
        
        # Mock zone transfer failure (expected behavior)
        with patch('dns.query.xfr') as mock_xfr:
            mock_xfr.side_effect = Exception("Zone transfer refused")
            
            results = self.enumerator._attempt_zone_transfer()
            
            self.assertIsInstance(results, list)
            # Zone transfer should typically fail
            self.assertEqual(len(results), 0)
    
    @patch('dns.resolver.Resolver')
    def test_dns_cache_snooping(self, mock_resolver_class):
        """Test DNS cache snooping"""
        # Mock resolver
        mock_resolver = Mock()
        mock_resolver_class.return_value = mock_resolver
        
        # Mock successful resolution for some subdomains
        mock_answer = Mock()
        mock_resolver.resolve.side_effect = lambda domain, record_type: mock_answer if 'www' in domain else dns.resolver.NXDOMAIN()
        
        results = self.enumerator._dns_cache_snooping()
        
        self.assertIsInstance(results, list)
        # Should find www subdomain
        self.assertTrue(any('www' in result for result in results))
    
    @patch.object(DomainEnumeration, '_bruteforce_with_rate_limiting')
    @patch.object(DomainEnumeration, '_dns_permutation_attack')
    @patch.object(DomainEnumeration, '_attempt_zone_transfer')
    @patch.object(DomainEnumeration, '_dns_cache_snooping')
    @patch.object(DomainEnumeration, '_generate_dynamic_wordlist')
    def test_enhanced_active_enumeration(self, mock_wordlist, mock_cache_snoop, 
                                       mock_zone_transfer, mock_permutation, mock_bruteforce):
        """Test complete enhanced active enumeration"""
        # Mock all methods
        mock_wordlist.return_value = ['www', 'mail', 'api']
        mock_bruteforce.return_value = ['www.example.com', 'mail.example.com']
        mock_permutation.return_value = ['example1.example.com']
        mock_zone_transfer.return_value = []
        mock_cache_snoop.return_value = ['api.example.com']
        
        results = self.enumerator.enhanced_active_enumeration()
        
        self.assertIsInstance(results, dict)
        self.assertIn('bruteforce', results)
        self.assertIn('dns_permutations', results)
        self.assertIn('dns_zone_transfer', results)
        self.assertIn('dns_cache_snooping', results)
        
        # Verify all methods were called
        mock_wordlist.assert_called_once()
        mock_bruteforce.assert_called_once()
        mock_permutation.assert_called_once()
        mock_zone_transfer.assert_called_once()
        mock_cache_snoop.assert_called_once()
        
        # Check logging messages
        self.assertTrue(any('Starting Enhanced Active Enumeration' in msg for msg in self.log_messages))
        self.assertTrue(any('Active Enumeration Summary' in msg for msg in self.log_messages))
    
    @patch.object(DomainEnumeration, '_check_subdomain')
    def test_bruteforce_with_rate_limiting(self, mock_check_subdomain):
        """Test brute force with rate limiting"""
        # Mock responses
        mock_check_subdomain.side_effect = lambda x: f'{x}.{self.test_domain}' if x in ['www', 'mail'] else None
        
        wordlist = ['www', 'mail', 'nonexistent1', 'nonexistent2']
        results = self.enumerator._bruteforce_with_rate_limiting(wordlist)
        
        self.assertIsInstance(results, list)
        self.assertEqual(len(results), 2)  # www and mail
        self.assertIn('www.example.com', results)
        self.assertIn('mail.example.com', results)
    
    def test_error_handling(self):
        """Test error handling functionality"""
        # Test error handling
        test_error = Exception("Test error")
        self.enumerator._handle_enumeration_errors("test_method", test_error)
        
        # Check that error was logged and stored
        self.assertIn('errors', self.enumerator.results)
        self.assertIn('test_method', self.enumerator.results['errors'])
        self.assertIn('Test error', self.enumerator.results['errors']['test_method'])
    
    @patch('requests.get')
    def test_doh_query(self, mock_get):
        """Test DNS-over-HTTPS query"""
        # Mock successful DoH response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'Answer': [{'data': '1.2.3.4'}]
        }
        mock_get.return_value = mock_response
        
        result = self.enumerator._doh_query('test.example.com')
        
        self.assertEqual(result, 'test.example.com')
        mock_get.assert_called()
    
    def test_merge_wordlists(self):
        """Test wordlist merging functionality"""
        wordlist_sources = {
            'common': ['www', 'mail', 'api'],
            'target_specific': ['mail', 'admin', 'portal'],  # 'mail' is duplicate
            'permutations': ['www1', 'mail2']
        }
        
        merged = self.enumerator._merge_wordlists(wordlist_sources)
        
        self.assertIsInstance(merged, list)
        # Should contain all unique entries
        expected_entries = {'www', 'mail', 'api', 'admin', 'portal', 'www1', 'mail2'}
        self.assertEqual(set(merged), expected_entries)


class TestIntegration(unittest.TestCase):
    """Integration tests for domain enumeration"""
    
    def setUp(self):
        """Set up for integration tests"""
        # Use a real domain for integration testing, but with safe methods only
        self.test_domain = "example.com"
        self.config = EnumerationConfig()
        self.config.rate_limit = 5  # Be conservative with real requests
        self.config.timeout = 3
        self.config.thread_count = 2
        self.enumerator = DomainEnumeration(self.test_domain, self.config)
    
    def test_wordlist_loading(self):
        """Test loading wordlist from file"""
        wordlist_path = os.path.join(
            os.path.dirname(__file__), '..', 'config', 'wordlists', 'subdomains.txt'
        )
        
        if os.path.exists(wordlist_path):
            with open(wordlist_path, 'r') as f:
                wordlist = [line.strip() for line in f if line.strip()]
            
            self.assertGreater(len(wordlist), 0)
            self.assertIn('www', wordlist)
            self.assertIn('mail', wordlist)
    
    @unittest.skipIf(os.getenv('SKIP_NETWORK_TESTS') == '1', "Network tests disabled")
    def test_real_domain_enumeration(self):
        """Test enumeration against a real domain (example.com)"""
        # Only test safe methods that don't cause load
        config = EnumerationConfig()
        config.rate_limit = 1  # Very conservative
        config.timeout = 5
        config.thread_count = 1
        
        enumerator = DomainEnumeration("example.com", config)
        
        # Test DNS enumeration (safe)
        dns_results = enumerator.dns_enumeration()
        self.assertIsInstance(dns_results, dict)
        
        # Test wordlist generation (safe, no network requests)
        wordlist = enumerator._generate_dynamic_wordlist()
        self.assertIsInstance(wordlist, list)
        self.assertGreater(len(wordlist), 0)


if __name__ == '__main__':
    # Set up test environment
    import time
    
    # Run tests
    print("Starting Domain Enumeration Tests...")
    print("=" * 50)
    
    # Run tests with unittest's default test discovery
    unittest.main(verbosity=2, exit=True)
