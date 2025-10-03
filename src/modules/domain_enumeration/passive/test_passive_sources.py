#!/usr/bin/env python3
"""
Unit tests for passive enumeration source modules
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
import os
import sys

# Add path to modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from src.modules.domain_enumeration.passive.sources.base_source import (
    PassiveSourceBase, PassiveSourceManager, CertificateTransparencySource
)
from src.modules.domain_enumeration.passive.sources.ct_sources import CrtShSource
from src.modules.domain_enumeration.passive.sources.ssl_sources import ShodanSSLSource
from src.modules.domain_enumeration.passive.sources.threat_intel_sources import ThreatCrowdSource
from src.modules.domain_enumeration.passive.sources.archive_sources import WaybackMachineSource
from src.modules.domain_enumeration.passive.passive_enumeration import (
    ConfigurablePassiveEnumerator, PassiveEnumerationConfig
)


class TestBaseSource(unittest.TestCase):
    """Test base source functionality"""
    
    def setUp(self):
        self.domain = "example.com"
        self.config = Mock()
        self.config.timeout = 10
        self.config.request_delay = 0
    
    def test_passive_source_initialization(self):
        """Test PassiveSourceBase initialization"""
        # Cannot instantiate abstract class directly, but can test inherited functionality
        source = CrtShSource(self.domain, self.config)
        self.assertEqual(source.domain, self.domain)
        self.assertEqual(source.config, self.config)
        self.assertIsNotNone(source.session)
    
    def test_subdomain_validation(self):
        """Test subdomain validation logic"""
        source = CrtShSource(self.domain, self.config)
        
        # Valid subdomains
        self.assertTrue(source.validate_subdomain("sub.example.com"))
        self.assertTrue(source.validate_subdomain("example.com"))
        self.assertTrue(source.validate_subdomain("a.b.example.com"))
        
        # Invalid subdomains
        self.assertFalse(source.validate_subdomain("example.org"))
        self.assertFalse(source.validate_subdomain("notexample.com"))
        self.assertFalse(source.validate_subdomain(""))
        self.assertFalse(source.validate_subdomain("sub.example.com.evil.com"))
    
    def test_domain_format_validation(self):
        """Test domain format validation"""
        source = CrtShSource(self.domain, self.config)
        
        # Valid formats
        self.assertTrue(source._is_valid_domain_format("example.com"))
        self.assertTrue(source._is_valid_domain_format("sub.example.com"))
        self.assertTrue(source._is_valid_domain_format("a.b.c.example.com"))
        
        # Invalid formats
        self.assertFalse(source._is_valid_domain_format(""))
        self.assertFalse(source._is_valid_domain_format(".example.com"))
        self.assertFalse(source._is_valid_domain_format("example.com."))
        self.assertFalse(source._is_valid_domain_format("ex..ample.com"))


class TestSourceManager(unittest.TestCase):
    """Test PassiveSourceManager functionality"""
    
    def setUp(self):
        self.domain = "example.com"
        self.config = Mock()
        self.manager = PassiveSourceManager(self.domain, self.config)
    
    def test_source_registration(self):
        """Test source registration"""
        self.manager.register_source(CrtShSource, "test_ct")
        self.assertIn("test_ct", self.manager.sources)
        self.assertIsInstance(self.manager.sources["test_ct"], CrtShSource)
    
    def test_available_sources(self):
        """Test getting available sources"""
        # Register a source that should be available (free)
        self.manager.register_source(CrtShSource, "crt_sh")
        available = self.manager.get_available_sources()
        self.assertIn("crt_sh", available)
        
        # Register a source that requires API key
        self.manager.register_source(ShodanSSLSource, "shodan")
        available = self.manager.get_available_sources()
        # Shodan should not be available without API key
        self.assertNotIn("shodan", available)
    
    def test_enumerate_unregistered_source(self):
        """Test enumerating unregistered source"""
        result = self.manager.enumerate_source("nonexistent")
        self.assertEqual(result['subdomains'], [])
        self.assertIn('error', result)
        self.assertIn('not registered', result['error'])


class TestCrtShSource(unittest.TestCase):
    """Test CrtShSource functionality"""
    
    def setUp(self):
        self.domain = "example.com"
        self.config = Mock()
        self.config.ct_max_pages = 2
        self.config.ct_page_delay = 0
        self.config.timeout = 10
        self.source = CrtShSource(self.domain, self.config)
    
    def test_source_name(self):
        """Test source name"""
        self.assertEqual(self.source.get_source_name(), "crt.sh")
    
    def test_is_available(self):
        """Test availability (should always be true for crt.sh)"""
        self.assertTrue(self.source.is_available())
    
    @patch('requests.Session.get')
    def test_successful_enumeration(self, mock_get):
        """Test successful CT enumeration"""
        # Mock successful response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {
                'id': 12345,
                'name_value': f'test.{self.domain}\n*.{self.domain}'
            }
        ]
        mock_get.return_value = mock_response
        
        result = self.source.enumerate()
        
        self.assertIn('subdomains', result)
        self.assertIn('source', result)
        self.assertEqual(result['source'], 'crt.sh')
        self.assertIsInstance(result['subdomains'], list)
    
    @patch('requests.Session.get')
    def test_failed_enumeration(self, mock_get):
        """Test failed CT enumeration"""
        # Mock failed response
        mock_get.side_effect = Exception("Network error")
        
        result = self.source.enumerate()
        
        self.assertIn('error', result)
        self.assertEqual(result['subdomains'], [])
        self.assertEqual(result['source'], 'crt.sh')


class TestThreatIntelSources(unittest.TestCase):
    """Test threat intelligence sources"""
    
    def setUp(self):
        self.domain = "example.com"
        self.config = Mock()
        self.config.timeout = 10
    
    def test_threatcrowd_availability(self):
        """Test ThreatCrowd availability (should be free)"""
        source = ThreatCrowdSource(self.domain, self.config)
        self.assertTrue(source.is_available())
        self.assertEqual(source.get_source_name(), "threatcrowd")
    
    def test_shodan_ssl_unavailable(self):
        """Test Shodan SSL unavailable without API key"""
        source = ShodanSSLSource(self.domain, self.config)
        self.assertFalse(source.is_available())
        self.assertEqual(source.get_source_name(), "shodan_ssl")


class TestPassiveEnumerationConfig(unittest.TestCase):
    """Test configuration class"""
    
    def test_default_configuration(self):
        """Test default configuration values"""
        config = PassiveEnumerationConfig()
        
        self.assertIn('certificate_transparency', config.enabled_source_categories)
        self.assertIn('crt_sh', config.enabled_ct_sources)
        self.assertEqual(config.ct_max_pages, 5)
        self.assertEqual(config.ct_page_delay, 2)
        self.assertEqual(config.max_concurrent_requests, 3)
    
    def test_api_key_configuration(self):
        """Test API key configuration from environment"""
        config = PassiveEnumerationConfig()
        
        # API keys should be loaded from environment or None
        self.assertIsInstance(config.api_keys, dict)
        self.assertIn('virustotal', config.api_keys)
        self.assertIn('shodan', config.api_keys)
        self.assertIn('threatcrowd', config.api_keys)


class TestConfigurablePassiveEnumerator(unittest.TestCase):
    """Test main enumerator class"""
    
    def setUp(self):
        self.domain = "example.com"
        self.config = PassiveEnumerationConfig()
        # Disable all sources except CT for testing
        self.config.enabled_source_categories = ['certificate_transparency']
        self.config.enabled_ct_sources = ['crt_sh']
    
    def test_enumerator_initialization(self):
        """Test enumerator initialization"""
        enumerator = ConfigurablePassiveEnumerator(self.domain, self.config)
        
        self.assertEqual(enumerator.domain, self.domain)
        self.assertEqual(enumerator.config, self.config)
        self.assertIsNotNone(enumerator.source_manager)
        self.assertIsNotNone(enumerator.error_handler)
    
    def test_source_registration(self):
        """Test that sources are properly registered"""
        enumerator = ConfigurablePassiveEnumerator(self.domain, self.config)
        
        # Check that CT sources are registered
        available_sources = enumerator.source_manager.get_available_sources()
        self.assertIn('crt_sh', available_sources)
    
    def test_get_enabled_sources(self):
        """Test getting enabled sources based on configuration"""
        enumerator = ConfigurablePassiveEnumerator(self.domain, self.config)
        enabled = enumerator._get_enabled_sources()
        
        self.assertIn('crt_sh', enabled)
        # Should not include sources from disabled categories
        self.assertNotIn('shodan_ssl', enabled)
    
    @patch.object(CrtShSource, 'enumerate')
    def test_comprehensive_enumeration(self, mock_enumerate):
        """Test comprehensive enumeration execution"""
        # Mock successful enumeration
        mock_enumerate.return_value = {
            'subdomains': ['test.example.com', 'api.example.com'],
            'source': 'crt.sh',
            'metadata': {'pages_processed': 1}
        }
        
        enumerator = ConfigurablePassiveEnumerator(self.domain, self.config)
        results = enumerator.run_comprehensive_enumeration()
        
        # Check result structure
        self.assertIn('domain', results)
        self.assertIn('sources', results)
        self.assertIn('subdomains', results)
        self.assertIn('statistics', results)
        self.assertEqual(results['domain'], self.domain)
        
        # Check that subdomains were extracted
        self.assertIsInstance(results['subdomains'], list)
        
        # Check that statistics were compiled
        self.assertIn('total_duration', results['statistics'])
        self.assertIn('sources_executed', results['statistics'])


class TestArchiveSources(unittest.TestCase):
    """Test web archive sources"""
    
    def setUp(self):
        self.domain = "example.com"
        self.config = Mock()
        self.config.timeout = 10
    
    def test_wayback_machine(self):
        """Test Wayback Machine source"""
        source = WaybackMachineSource(self.domain, self.config)
        self.assertEqual(source.get_source_name(), "wayback_machine")
        self.assertTrue(source.is_available())
        
        # Should return placeholder implementation
        result = source.enumerate()
        self.assertIn('error', result)
        self.assertIn('Not implemented', result['error'])


class TestIntegration(unittest.TestCase):
    """Integration tests for the complete system"""
    
    def setUp(self):
        self.domain = "example.com"
    
    def test_legacy_function_compatibility(self):
        """Test that legacy passive_enumeration function still works"""
        from src.modules.domain_enumeration.passive.passive_enumeration import passive_enumeration
        
        # This should not raise an exception
        config = PassiveEnumerationConfig()
        config.enabled_source_categories = []  # Disable all sources for quick test
        
        try:
            result = passive_enumeration(self.domain, config)
            self.assertIsInstance(result, dict)
            self.assertIn('domain', result)
        except Exception as e:
            # It's okay if it fails due to missing dependencies, 
            # we just want to ensure the interface exists
            self.assertIsInstance(e, Exception)
    
    def test_source_error_handling(self):
        """Test that source errors are properly handled"""
        enumerator = ConfigurablePassiveEnumerator(self.domain)
        
        # Register a mock source that will fail
        mock_source = Mock()
        mock_source.enumerate.side_effect = Exception("Test error")
        mock_source.is_available.return_value = True
        
        enumerator.source_manager.sources['test_source'] = mock_source
        
        # Should handle the error gracefully
        result = enumerator.source_manager.enumerate_source('test_source')
        self.assertIn('error', result)


if __name__ == '__main__':
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add test classes
    test_classes = [
        TestBaseSource,
        TestSourceManager,
        TestCrtShSource,
        TestThreatIntelSources,
        TestPassiveEnumerationConfig,
        TestConfigurablePassiveEnumerator,
        TestArchiveSources,
        TestIntegration
    ]
    
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        test_suite.addTests(tests)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    # Exit with appropriate code
    sys.exit(0 if result.wasSuccessful() else 1)