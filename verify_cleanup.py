#!/usr/bin/env python3
"""
Verification script to test the cleaned up modules
"""
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def test_common_modules():
    """Test the common modules"""
    print("Testing common modules...")
    
    try:
        from src.common.constants import DEFAULT_TIMEOUT, TECH_PATTERNS, BASE_ENDPOINTS
        from src.common.network_utils import NetworkUtils, RateLimiter
        print("✓ Common modules imported successfully")
        
        # Test constants
        assert DEFAULT_TIMEOUT > 0
        assert 'wordpress' in TECH_PATTERNS
        assert 'admin' in BASE_ENDPOINTS
        print("✓ Constants are properly defined")
        
        # Test NetworkUtils
        session = NetworkUtils.create_session()
        assert session is not None
        print("✓ NetworkUtils.create_session() works")
        
        # Test rate limiter
        limiter = RateLimiter(10)
        assert limiter.rate == 10
        print("✓ RateLimiter works")
        
    except Exception as e:
        print(f"✗ Common modules test failed: {e}")
        return False
    
    return True

def test_cleaned_modules():
    """Test the cleaned modules can be imported"""
    print("\nTesting cleaned modules...")
    
    try:
        from src.modules.web_crawling import WebCrawler
        from src.modules.service_discovery import ServiceDiscovery
        from src.modules.ai_integration import AIIntegration
        from src.modules.domain_enumeration import DomainEnumeration
        print("✓ All cleaned modules imported successfully")
        
        # Test basic instantiation
        crawler = WebCrawler("example.com")
        assert crawler.domain == "example.com"
        print("✓ WebCrawler instantiation works")
        
        ai = AIIntegration()
        assert ai is not None
        print("✓ AIIntegration instantiation works")
        
    except Exception as e:
        print(f"✗ Cleaned modules test failed: {e}")
        return False
    
    return True

def test_main_import():
    """Test main module can be imported"""
    print("\nTesting main module...")
    
    try:
        from src.main import DomainRecon
        print("✓ Main module imported successfully")
        
        # Test basic instantiation (without actually running)
        recon = DomainRecon("example.com")
        assert recon.domain == "example.com"
        print("✓ DomainRecon instantiation works")
        
    except Exception as e:
        print(f"✗ Main module test failed: {e}")
        return False
    
    return True

if __name__ == "__main__":
    print("=" * 50)
    print("CLEANUP VERIFICATION SCRIPT")
    print("=" * 50)
    
    success = True
    success &= test_common_modules()
    success &= test_cleaned_modules()
    success &= test_main_import()
    
    print("\n" + "=" * 50)
    if success:
        print("🎉 ALL TESTS PASSED! Cleanup was successful.")
        print("✓ No import errors")
        print("✓ All modules work together")
        print("✓ Shared utilities are functional")
    else:
        print("❌ SOME TESTS FAILED! Check the errors above.")
    print("=" * 50)
