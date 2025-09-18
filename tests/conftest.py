"""
Pytest configuration and shared fixtures for web-domain-scanner tests.
"""

import pytest
import logging
import sys
import os
from unittest.mock import Mock, MagicMock
from typing import Dict, List

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from src.modules.domain_enumeration import DomainEnumeration, EnumerationConfig


@pytest.fixture
def test_domain():
    """Standard test domain for all tests."""
    return "example.com"


@pytest.fixture
def test_config():
    """Test configuration with fast settings."""
    config = EnumerationConfig()
    config.rate_limit = 100  # Fast for testing
    config.timeout = 1
    config.thread_count = 2
    config.retry_attempts = 1
    return config


@pytest.fixture
def domain_enumerator(test_domain, test_config):
    """Pre-configured domain enumerator for testing."""
    return DomainEnumeration(test_domain, test_config)


@pytest.fixture
def mock_requests_session():
    """Mock requests session for API calls."""
    session = Mock()
    response = Mock()
    response.status_code = 200
    response.json.return_value = {'test': 'data'}
    response.text = '{"test": "data"}'
    session.get.return_value = response
    session.post.return_value = response
    return session


@pytest.fixture
def mock_dns_resolver():
    """Mock DNS resolver for testing."""
    resolver = Mock()
    # Mock different record types
    answer = Mock()
    answer.__str__ = Mock(return_value='1.2.3.4')
    resolver.resolve.return_value = [answer]
    return resolver


@pytest.fixture
def sample_subdomains():
    """Sample subdomain list for testing."""
    return [
        'www.example.com',
        'mail.example.com',
        'api.example.com',
        'admin.example.com',
        'test.example.com'
    ]


@pytest.fixture
def sample_dns_records():
    """Sample DNS records for testing."""
    return {
        'A': ['1.2.3.4', '5.6.7.8'],
        'AAAA': ['2001:db8::1'],
        'MX': ['10 mail.example.com'],
        'NS': ['ns1.example.com', 'ns2.example.com'],
        'TXT': ['v=spf1 include:_spf.example.com ~all'],
        'SOA': ['ns1.example.com admin.example.com 2023091701 3600 1800 604800 86400']
    }


@pytest.fixture
def sample_ct_response():
    """Sample Certificate Transparency response."""
    return {
        'subdomains': [
            'www.example.com',
            'api.example.com',
            'mail.example.com'
        ]
    }


@pytest.fixture
def capture_logs():
    """Capture log messages during tests."""
    log_messages = []
    handler = logging.Handler()
    handler.emit = lambda record: log_messages.append(record.getMessage())
    
    logger = logging.getLogger()
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    
    yield log_messages
    
    logger.removeHandler(handler)


@pytest.fixture(autouse=True)
def suppress_network_warnings():
    """Suppress network-related warnings during tests."""
    import warnings
    warnings.filterwarnings('ignore', category=UserWarning)


# Markers for test categorization
pytestmark = pytest.mark.unit


class TestHelpers:
    """Helper methods for tests."""
    
    @staticmethod
    def create_mock_response(status_code=200, json_data=None, text=None):
        """Create a mock HTTP response."""
        response = Mock()
        response.status_code = status_code
        response.json.return_value = json_data or {}
        response.text = text or ''
        return response
    
    @staticmethod
    def create_mock_dns_answer(records: List[str]):
        """Create mock DNS answer with records."""
        answers = []
        for record in records:
            answer = Mock()
            answer.__str__ = Mock(return_value=record)
            answers.append(answer)
        return answers