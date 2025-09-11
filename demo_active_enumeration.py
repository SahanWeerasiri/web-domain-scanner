#!/usr/bin/env python3

"""
Demonstration of Active Enumeration with Logging and Testing
=====================================================

This script demonstrates the complete active enumeration functionality
implemented in the domain enumeration module with comprehensive logging.
"""

import sys
import os
import logging
import time
import json

# Setup path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from modules.domain_enumeration import DomainEnumeration, EnumerationConfig

def setup_detailed_logging():
    """Setup comprehensive logging configuration"""
    
    # Create logs directory if it doesn't exist
    if not os.path.exists('logs'):
        os.makedirs('logs')
    
    # Configure logging with multiple handlers
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
    
    logging.basicConfig(
        level=logging.INFO,
        format=log_format,
        handlers=[
            logging.FileHandler('logs/active_enumeration.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    # Create separate loggers for different components
    enum_logger = logging.getLogger('enumeration')
    test_logger = logging.getLogger('testing')
    
    return enum_logger, test_logger

def demonstrate_active_enumeration():
    """Comprehensive demonstration of active enumeration features"""
    
    enum_logger, test_logger = setup_detailed_logging()
    
    print("="*80)
    print("ACTIVE ENUMERATION DEMONSTRATION")
    print("="*80)
    
    # Test domains for different scenarios
    test_scenarios = [
        {
            'domain': 'example.com',
            'description': 'Basic test domain (safe for testing)',
            'config': {
                'rate_limit': 3,
                'timeout': 3,
                'thread_count': 2,
                'rate_limiting_enabled': True
            }
        },
        {
            'domain': 'university.edu',
            'description': 'Educational domain (LLM-based terms test)',
            'config': {
                'rate_limit': 2,
                'timeout': 2,
                'thread_count': 1,
                'rate_limiting_enabled': True
            }
        }
    ]
    
    results_summary = {}
    
    for i, scenario in enumerate(test_scenarios, 1):
        print(f"\n{'='*20} SCENARIO {i}: {scenario['description']} {'='*20}")
        
        # Create configuration
        config = EnumerationConfig()
        for key, value in scenario['config'].items():
            setattr(config, key, value)
        
        print(f"Target Domain: {scenario['domain']}")
        print(f"Configuration: {scenario['config']}")
        
        # Initialize enumerator
        enumerator = DomainEnumeration(scenario['domain'], config)
        
        test_logger.info(f"Starting enumeration for {scenario['domain']}")
        
        # Track timing and results for each scenario
        scenario_start = time.time()
        scenario_results = {}
        
        try:
            # 1. Dynamic Wordlist Generation
            print(f"\n🔍 Generating Dynamic Wordlist...")
            start_time = time.time()
            wordlist = enumerator._generate_dynamic_wordlist()
            duration = time.time() - start_time
            
            scenario_results['wordlist_generation'] = {
                'count': len(wordlist),
                'duration': duration,
                'sample': wordlist[:10]
            }
            
            enum_logger.info(f"Generated {len(wordlist)} words in {duration:.2f}s")
            print(f"   ✅ Generated {len(wordlist)} words in {duration:.2f}s")
            
            # 2. Test specific enumeration techniques
            techniques = {
                'Target-Specific Terms': enumerator._generate_target_specific_terms,
                'LLM-Based Terms': enumerator._generate_llm_based_terms,
                'Permutations': enumerator._generate_permutations,
                'Zone Transfer': enumerator._attempt_zone_transfer,
                'Cache Snooping': enumerator._dns_cache_snooping
            }
            
            for technique_name, technique_func in techniques.items():
                print(f"\n🔧 Testing {technique_name}...")
                start_time = time.time()
                
                try:
                    result = technique_func()
                    duration = time.time() - start_time
                    
                    scenario_results[technique_name.lower().replace(' ', '_')] = {
                        'count': len(result) if isinstance(result, list) else 0,
                        'duration': duration,
                        'sample': result[:5] if isinstance(result, list) else result
                    }
                    
                    enum_logger.info(f"{technique_name} completed: {len(result) if isinstance(result, list) else 0} results in {duration:.2f}s")
                    print(f"   ✅ {technique_name}: {len(result) if isinstance(result, list) else 0} results in {duration:.2f}s")
                    
                except Exception as e:
                    enum_logger.error(f"{technique_name} failed: {e}")
                    print(f"   ❌ {technique_name} failed: {e}")
                    scenario_results[technique_name.lower().replace(' ', '_')] = {
                        'error': str(e),
                        'duration': time.time() - start_time
                    }
            
            # 3. Limited Active Enumeration (safe for testing)
            print(f"\n🚀 Running Limited Active Enumeration...")
            test_wordlist = ['www', 'mail', 'api', 'test']
            
            start_time = time.time()
            active_results = enumerator.enhanced_active_enumeration(test_wordlist)
            duration = time.time() - start_time
            
            # Process active enumeration results
            active_summary = {}
            total_found = 0
            
            for method, subdomains in active_results.items():
                count = len(subdomains) if isinstance(subdomains, list) else 0
                total_found += count
                active_summary[method] = {
                    'count': count,
                    'subdomains': subdomains[:3] if isinstance(subdomains, list) else []
                }
                enum_logger.info(f"Active enumeration - {method}: {count} subdomains")
                print(f"   📊 {method}: {count} subdomains")
            
            scenario_results['active_enumeration'] = {
                'total_found': total_found,
                'duration': duration,
                'methods': active_summary
            }
            
            print(f"   ✅ Active enumeration completed: {total_found} total subdomains in {duration:.2f}s")
            
            # 4. Test Error Handling
            print(f"\n⚠️  Testing Error Handling...")
            test_error = Exception("Test error for demonstration")
            enumerator._handle_enumeration_errors("demo_method", test_error)
            
            if 'errors' in enumerator.results and 'demo_method' in enumerator.results['errors']:
                print(f"   ✅ Error handling working correctly")
                scenario_results['error_handling'] = 'success'
            else:
                print(f"   ❌ Error handling issues detected")
                scenario_results['error_handling'] = 'failed'
            
        except Exception as e:
            test_logger.error(f"Scenario {i} failed: {e}")
            print(f"   ❌ Scenario failed: {e}")
            scenario_results['error'] = str(e)
        
        scenario_duration = time.time() - scenario_start
        scenario_results['total_duration'] = scenario_duration
        
        results_summary[scenario['domain']] = scenario_results
        
        print(f"\n📊 Scenario {i} Summary:")
        print(f"   Total Duration: {scenario_duration:.2f}s")
        print(f"   Status: {'✅ Success' if 'error' not in scenario_results else '❌ Failed'}")
    
    return results_summary

def generate_report(results_summary):
    """Generate a comprehensive report of the testing results"""
    
    print(f"\n{'='*80}")
    print("ACTIVE ENUMERATION TEST REPORT")
    print(f"{'='*80}")
    
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    print(f"Report Generated: {timestamp}")
    
    total_scenarios = len(results_summary)
    successful_scenarios = sum(1 for result in results_summary.values() if 'error' not in result)
    
    print(f"\nOverview:")
    print(f"  • Total Scenarios Tested: {total_scenarios}")
    print(f"  • Successful Scenarios: {successful_scenarios}")
    print(f"  • Success Rate: {(successful_scenarios/total_scenarios)*100:.1f}%")
    
    for domain, results in results_summary.items():
        print(f"\n📋 Domain: {domain}")
        print(f"   Duration: {results.get('total_duration', 0):.2f}s")
        
        if 'active_enumeration' in results:
            active_results = results['active_enumeration']
            print(f"   Active Enumeration: {active_results['total_found']} subdomains found")
            
            for method, method_results in active_results['methods'].items():
                if method_results['count'] > 0:
                    print(f"     • {method}: {method_results['count']} subdomains")
                    if method_results['subdomains']:
                        print(f"       Examples: {', '.join(method_results['subdomains'])}")
        
        if 'wordlist_generation' in results:
            wl_results = results['wordlist_generation']
            print(f"   Wordlist Generation: {wl_results['count']} terms in {wl_results['duration']:.2f}s")
    
    # Save detailed results to JSON
    report_data = {
        'timestamp': timestamp,
        'summary': {
            'total_scenarios': total_scenarios,
            'successful_scenarios': successful_scenarios,
            'success_rate': (successful_scenarios/total_scenarios)*100
        },
        'detailed_results': results_summary
    }
    
    with open('logs/active_enumeration_report.json', 'w') as f:
        json.dump(report_data, f, indent=2, default=str)
    
    print(f"\n📁 Detailed report saved to: logs/active_enumeration_report.json")
    print(f"📁 Execution logs saved to: logs/active_enumeration.log")

def main():
    """Main execution function"""
    
    try:
        print("Starting Active Enumeration Demonstration...")
        
        # Run comprehensive testing
        results = demonstrate_active_enumeration()
        
        # Generate report
        generate_report(results)
        
        print(f"\n{'='*80}")
        print("✅ ACTIVE ENUMERATION DEMONSTRATION COMPLETED SUCCESSFULLY!")
        print(f"{'='*80}")
        
        return True
        
    except Exception as e:
        print(f"\n❌ DEMONSTRATION FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
