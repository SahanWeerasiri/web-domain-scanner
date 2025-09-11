#!/usr/bin/env python3

"""
Test script for active enumeration functionality with logging
"""

import sys
import os
import logging
import time

# Setup path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from modules.domain_enumeration import DomainEnumeration, EnumerationConfig

def setup_logging():
    """Setup detailed logging for testing"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler('test_enumeration.log')
        ]
    )

def test_active_enumeration():
    """Test the active enumeration functionality"""
    print("=" * 60)
    print("TESTING ACTIVE ENUMERATION FUNCTIONALITY")
    print("=" * 60)
    
    # Use a test domain that's safe to test against
    test_domain = "example.com"
    
    # Create configuration for testing
    config = EnumerationConfig()
    config.rate_limit = 5  # Conservative rate limiting
    config.timeout = 3
    config.thread_count = 2
    config.rate_limiting_enabled = True
    config.doh_fallback = True
    
    print(f"Target Domain: {test_domain}")
    print(f"Configuration:")
    print(f"  - Rate Limit: {config.rate_limit} requests/sec")
    print(f"  - Timeout: {config.timeout} seconds")
    print(f"  - Thread Count: {config.thread_count}")
    print(f"  - DoH Fallback: {config.doh_fallback}")
    print("-" * 60)
    
    # Initialize enumerator
    enumerator = DomainEnumeration(test_domain, config)
    
    # Test 1: Dynamic Wordlist Generation
    print("\n🔍 TEST 1: Dynamic Wordlist Generation")
    start_time = time.time()
    wordlist = enumerator._generate_dynamic_wordlist()
    duration = time.time() - start_time
    
    print(f"✅ Generated {len(wordlist)} words in {duration:.2f}s")
    print(f"Sample words: {wordlist[:10]}")
    
    # Test 2: Target-Specific Terms
    print("\n🎯 TEST 2: Target-Specific Terms")
    start_time = time.time()
    target_terms = enumerator._generate_target_specific_terms()
    duration = time.time() - start_time
    
    print(f"✅ Generated {len(target_terms)} target-specific terms in {duration:.2f}s")
    print(f"Sample terms: {target_terms[:10]}")
    
    # Test 3: LLM-Based Terms
    print("\n🧠 TEST 3: LLM-Based Terms")
    start_time = time.time()
    llm_terms = enumerator._generate_llm_based_terms()
    duration = time.time() - start_time
    
    print(f"✅ Generated {len(llm_terms)} LLM-based terms in {duration:.2f}s")
    print(f"Sample terms: {llm_terms[:10]}")
    
    # Test 4: Permutations
    print("\n🔄 TEST 4: Permutation Generation")
    start_time = time.time()
    permutations = enumerator._generate_permutations()
    duration = time.time() - start_time
    
    print(f"✅ Generated {len(permutations)} permutations in {duration:.2f}s")
    print(f"Sample permutations: {permutations[:10]}")
    
    # Test 5: DNS Zone Transfer (safe test)
    print("\n🌐 TEST 5: DNS Zone Transfer Attempt")
    start_time = time.time()
    zone_results = enumerator._attempt_zone_transfer()
    duration = time.time() - start_time
    
    print(f"✅ Zone transfer test completed in {duration:.2f}s")
    print(f"Results: {len(zone_results)} domains (expected: 0 for example.com)")
    
    # Test 6: Limited Brute Force (with very small wordlist)
    print("\n💥 TEST 6: Limited Brute Force Test")
    small_wordlist = ['www', 'mail', 'nonexistent123']
    start_time = time.time()
    
    print(f"Testing with wordlist: {small_wordlist}")
    brute_results = enumerator._bruteforce_with_rate_limiting(small_wordlist)
    duration = time.time() - start_time
    
    print(f"✅ Brute force test completed in {duration:.2f}s")
    print(f"Found subdomains: {brute_results}")
    
    # Test 7: DNS Permutation Attack (safe)
    print("\n🔀 TEST 7: DNS Permutation Attack")
    start_time = time.time()
    perm_results = enumerator._dns_permutation_attack()
    duration = time.time() - start_time
    
    print(f"✅ Permutation attack completed in {duration:.2f}s")
    print(f"Found subdomains: {perm_results}")
    
    # Test 8: DNS Cache Snooping
    print("\n👀 TEST 8: DNS Cache Snooping")
    start_time = time.time()
    cache_results = enumerator._dns_cache_snooping()
    duration = time.time() - start_time
    
    print(f"✅ Cache snooping completed in {duration:.2f}s")
    print(f"Found subdomains: {cache_results}")
    
    # Test 9: Complete Enhanced Active Enumeration
    print("\n🚀 TEST 9: Complete Enhanced Active Enumeration")
    start_time = time.time()
    
    # Use a very small custom wordlist for testing
    test_wordlist = ['www', 'mail', 'api', 'admin']
    active_results = enumerator.enhanced_active_enumeration(test_wordlist)
    duration = time.time() - start_time
    
    print(f"✅ Enhanced active enumeration completed in {duration:.2f}s")
    print("\nResults Summary:")
    for method, results in active_results.items():
        print(f"  {method}: {len(results)} subdomains found")
        if results:
            print(f"    Sample: {results[:3]}")
    
    # Test 10: Error Handling
    print("\n⚠️  TEST 10: Error Handling")
    test_error = Exception("Test error for logging")
    enumerator._handle_enumeration_errors("test_method", test_error)
    
    if 'errors' in enumerator.results and 'test_method' in enumerator.results['errors']:
        print("✅ Error handling working correctly")
        print(f"Stored error: {enumerator.results['errors']['test_method'][0]}")
    else:
        print("❌ Error handling not working")
    
    print("\n" + "=" * 60)
    print("ACTIVE ENUMERATION TESTING COMPLETED")
    print("=" * 60)
    
    return active_results

def test_educational_domain():
    """Test with an educational domain to test LLM-based terms"""
    print("\n📚 EDUCATIONAL DOMAIN TEST")
    print("-" * 40)
    
    config = EnumerationConfig()
    config.rate_limit = 2
    config.timeout = 2
    config.thread_count = 1
    
    # Test with a .edu domain pattern
    edu_enumerator = DomainEnumeration("university.edu", config)
    edu_terms = edu_enumerator._generate_llm_based_terms()
    
    print(f"Educational terms generated: {len(edu_terms)}")
    print(f"Sample edu terms: {edu_terms[:15]}")
    
    # Check for educational keywords
    edu_keywords = ['student', 'faculty', 'library', 'research', 'admissions']
    found_keywords = [term for term in edu_terms if term in edu_keywords]
    print(f"Found educational keywords: {found_keywords}")

def test_government_domain():
    """Test with a government domain to test LLM-based terms"""
    print("\n🏛️  GOVERNMENT DOMAIN TEST")
    print("-" * 40)
    
    config = EnumerationConfig()
    config.rate_limit = 2
    config.timeout = 2
    config.thread_count = 1
    
    # Test with a .gov domain pattern
    gov_enumerator = DomainEnumeration("agency.gov", config)
    gov_terms = gov_enumerator._generate_llm_based_terms()
    
    print(f"Government terms generated: {len(gov_terms)}")
    print(f"Sample gov terms: {gov_terms[:15]}")
    
    # Check for government keywords
    gov_keywords = ['citizen', 'service', 'department', 'ministry', 'public']
    found_keywords = [term for term in gov_terms if term in gov_keywords]
    print(f"Found government keywords: {found_keywords}")

def main():
    """Main test function"""
    setup_logging()
    
    logging.info("Starting Active Enumeration Tests")
    
    try:
        # Main test
        results = test_active_enumeration()
        
        # Additional domain-specific tests
        test_educational_domain()
        test_government_domain()
        
        print("\n✅ ALL TESTS COMPLETED SUCCESSFULLY!")
        
        # Save results to file
        import json
        with open('test_results.json', 'w') as f:
            # Convert results to JSON serializable format
            json_results = {}
            for method, subdomains in results.items():
                json_results[method] = subdomains if isinstance(subdomains, list) else []
            
            json.dump({
                'timestamp': time.time(),
                'test_domain': 'example.com',
                'results': json_results
            }, f, indent=2)
        
        print("📁 Test results saved to test_results.json")
        print("📁 Detailed logs saved to test_enumeration.log")
        
    except Exception as e:
        logging.error(f"Test failed with error: {e}")
        print(f"❌ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
