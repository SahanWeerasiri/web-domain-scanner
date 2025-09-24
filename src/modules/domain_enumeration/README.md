# Domain Enumeration Main Module

## Overview
A comprehensive domain enumeration tool that orchestrates multiple enumeration techniques including passive reconnaissance, active enumeration, DNS analysis, and web fingerprinting. This main module integrates four specialized enumeration modules:
- **Passive Enumeration**: Certificate Transparency, SSL certificates, Wayback Machine
- **Active Enumeration**: Brute force, DNS permutations, zone transfers, cache snooping
- **DNS Enumeration**: Comprehensive DNS record analysis and subdomain extraction
- **Web Fingerprinting**: Technology detection, security analysis, and server fingerprinting

## Features

- 🔍 **Multi-Module Integration**: Seamlessly combines all enumeration techniques
- ⚙️ **Comprehensive Configuration**: Individual module configurations with extensive customization
- 📊 **Detailed Results**: Structured output with statistics, summaries, and detailed findings
- 💾 **JSON Export**: Save results in JSON format for further analysis
- 🎯 **Selective Execution**: Choose which modules to run based on your needs
- 🔧 **Flexible Parameters**: Customize timeouts, concurrency, rate limits, and more
- 📋 **Verbose Logging**: Detailed execution logs for debugging and monitoring

## Installation

### Prerequisites
- Python 3.7+
- Required Python packages (install via requirements.txt in project root)
- dnspython for DNS functionality
- requests for HTTP operations
- Optional: AI API keys for enhanced wordlist generation

### Installation Steps
1. Ensure all enumeration modules are properly installed
2. Install dependencies: `pip install -r requirements.txt`
3. Run from the domain_enumeration directory

## Usage

### Basic Usage
```bash
# Run all modules with default settings
python main.py example.com

# Run with verbose output
python main.py example.com --verbose

# Save results to JSON file
python main.py example.com --output results.json
```

### Advanced Usage
```bash
# Run only specific modules
python main.py example.com --modules passive dns

# Custom settings for comprehensive scan
python main.py example.com \
    --verbose \
    --output comprehensive_results.json \
    --modules passive active dns fingerprinting \
    --passive-timeout 20 \
    --active-threads 15 \
    --active-rate-limit 12 \
    --dns-timeout 8 \
    --fingerprint-timeout 35 \
    --include-www
```

### Programmatic Usage
```python
from main import DomainEnumerationOrchestrator, DomainEnumerationConfig

# Create configuration
config = DomainEnumerationConfig()
config.domain = "example.com"
config.enabled_modules = ['passive', 'dns']
config.verbose = True

# Run enumeration
orchestrator = DomainEnumerationOrchestrator(config)
results = orchestrator.run_comprehensive_enumeration()
print(f"Found {len(results['all_subdomains'])} subdomains")
```

## Configuration

### Configuration Options
- `--verbose, -v`: Enable verbose output and detailed logging
- `--output, -o`: Output file for results (JSON format)
- `--modules`: Specify which enumeration modules to run
- `--passive-timeout`: Request timeout in seconds (default: 10)
- `--passive-concurrent`: Maximum concurrent requests (default: 5)
- `--active-threads`: Number of concurrent threads (default: 10)
- `--active-rate-limit`: Requests per second limit (default: 10)
- `--active-timeout`: DNS query timeout (default: 5)
- `--wordlist`: Custom wordlist file for brute force
- `--no-ai`: Disable AI-enhanced wordlist generation
- `--dns-timeout`: DNS query timeout (default: 5)
- `--dns-retries`: Number of retry attempts (default: 2)
- `--record-types`: DNS record types to query (A, AAAA, MX, NS, TXT, CNAME, SOA)
- `--fingerprint-timeout`: HTTP request timeout (default: 30)
- `--fingerprint-concurrent`: Concurrent requests (default: 3)
- `--include-http`: Include HTTP targets in addition to HTTPS
- `--include-www`: Include www variant in fingerprinting

### Configuration File
```python
from main import DomainEnumerationConfig

config = DomainEnumerationConfig()
config.domain = "example.com"
config.enabled_modules = ['passive', 'active', 'dns', 'fingerprinting']
config.verbose = True
config.output_file = "results.json"

# Module-specific configurations
config.passive_config['timeout'] = 15
config.active_config['threads'] = 20
config.dns_config['timeout'] = 8
config.fingerprinting_config['timeout'] = 45
```

## Methods

### run_comprehensive_enumeration()
Executes all enabled enumeration modules with configured parameters, returning comprehensive results including DNS records, subdomains, analysis, and statistics.

### _run_passive_enumeration()
Executes passive reconnaissance using Certificate Transparency, SSL certificates, and other passive sources without directly probing the target.

### _run_active_enumeration()
Performs active subdomain discovery using brute force attacks, DNS permutations, zone transfers, and cache snooping techniques.

### _run_dns_enumeration()
Conducts comprehensive DNS record analysis including A, AAAA, MX, NS, TXT, CNAME, and SOA records with subdomain extraction.

### _run_fingerprinting()
Analyzes web technologies, security configurations, and server information through HTTP requests and response analysis.

## Output

### Output Format
The tool provides comprehensive structured output showcasing detailed findings from each enumeration module:
- **Summary Statistics**: Total subdomains, modules executed, execution time, success rates
- **Module Summary**: Success status and subdomain count per module with error details
- **All Discovered Subdomains**: Comprehensive deduplicated list of unique subdomains
- **Detailed Results**: Rich module-specific findings including certificates, DNS records, technologies, and security analysis

**Console Output Example:**
```
================================================================================
DOMAIN ENUMERATION RESULTS FOR: online.uom.lk
================================================================================

📊 SUMMARY STATISTICS:
   • Total Subdomains Found: 15
   • Modules Executed: 4
   • Modules Failed: 0
   • Total Execution Time: 78.34 seconds

🔍 MODULE SUMMARY:
   ✅ PASSIVE: 12 subdomains
   ✅ ACTIVE: 8 subdomains  
   ✅ DNS: 3 subdomains
   ✅ FINGERPRINTING: 2 subdomains

🎯 ALL DISCOVERED SUBDOMAINS (15):
     1. api.online.uom.lk
     2. dev-online.uom.lk
     3. dns.online.uom.lk
     4. ftp.online.uom.lk
     5. mail.online.uom.lk
     6. moodle.online.uom.lk
     7. ns1.online.uom.lk
     8. ns2.online.uom.lk
     9. online.uom.lk
    10. portal.online.uom.lk
    11. secure.online.uom.lk
    12. staff.online.uom.lk
    13. student.online.uom.lk
    14. test.online.uom.lk
    15. www.online.uom.lk

📋 DETAILED RESULTS:

   🔍 PASSIVE ENUMERATION:
      • Certificate Transparency (crt.sh): 12 subdomains from 47 certificates
      • Certificate Analysis: 
        - SHA256 Fingerprints: 8 unique certificates analyzed
        - Subject Alternative Names: 23 SANs extracted
        - Certificate Transparency Logs: 15 CT log entries processed
      • Sources: certificate_transparency, ssl_certificates
      • Total Duration: 18.45 seconds

   ⚡ ACTIVE ENUMERATION:
      • Brute Force: 5 subdomains discovered (2,847 attempts, 87% success rate)
      • DNS Permutations: 2 subdomains (numeric and regional patterns)
      • Zone Transfer: 1 successful transfer from ns1.online.uom.lk
      • Cache Snooping: 3 subdomains from public DNS servers
      • AI-Enhanced Wordlist: Generated 156 context-aware subdomains
      • Total Duration: 34.12 seconds

   🌐 DNS ENUMERATION:
      • DNS Records Found:
        - A Records: 8 IPv4 addresses
        - AAAA Records: 2 IPv6 addresses  
        - MX Records: 3 mail servers (priorities: 10, 20, 30)
        - NS Records: 4 nameservers
        - TXT Records: 7 records (SPF, DMARC, verification)
        - CNAME Records: 5 canonical names
        - SOA Record: 1 Start of Authority record
      • Infrastructure Analysis:
        - Nameservers: ns1.online.uom.lk, ns2.online.uom.lk, dns1.uom.lk, dns2.uom.lk
        - Mail Servers: mail.online.uom.lk, backup-mail.uom.lk
        - Security Records: SPF enabled, DMARC policy=quarantine
      • Total Duration: 12.67 seconds

   🔧 WEB FINGERPRINTING:
      • Target: https://online.uom.lk
        - Status Code: 200 OK
        - Server: Apache/2.4.62 (Rocky Linux) OpenSSL/3.2.2
        - Technologies: Apache, PHP/8.1.29, Moodle 4.1, Font Awesome, jQuery
        - Security Score: 45% (Missing CSP, X-Frame-Options)
        - Response Time: 2.34 seconds
      • Target: https://moodle.online.uom.lk  
        - Status Code: 200 OK
        - Server: nginx/1.22.1
        - Technologies: Nginx, PHP/8.2.12, Moodle 4.3, Bootstrap 5
        - Security Score: 78% (Good security headers)
        - Response Time: 1.12 seconds
      • Total Duration: 13.10 seconds
```

**Complete JSON Output Format:**
```json
{
  "domain": "online.uom.lk",
  "timestamp": "2025-09-24T15:30:45.123456",
  "modules": {
    "passive": {
      "domain": "online.uom.lk",
      "timestamp": 1695551445.123,
      "configuration": {
        "enabled_sources": ["certificate_transparency"],
        "ct_sources": ["crt_sh"],
        "concurrent_requests": 5,
        "timeout": 10
      },
      "sources": {
        "certificate_transparency": {
          "crt_sh": {
            "subdomains": ["api.online.uom.lk", "moodle.online.uom.lk", "www.online.uom.lk"],
            "certificates": {
              "12345678": {
                "sha256_fingerprint": "A1B2C3D4E5F6...",
                "ct_logs": ["Google Xenon 2024", "Cloudflare Nimbus 2024"],
                "subject_alternative_names": ["*.online.uom.lk", "online.uom.lk"],
                "not_before": "2024-01-15",
                "not_after": "2025-01-15",
                "issuer": "Let's Encrypt Authority X3"
              }
            },
            "total_certificates": 47
          }
        }
      },
      "subdomains": ["api.online.uom.lk", "moodle.online.uom.lk", "portal.online.uom.lk"],
      "statistics": {
        "total_duration": 18.45,
        "total_subdomains": 12,
        "successful_sources": 1,
        "success_rate": 100.0
      }
    },
    "active": {
      "domain": "online.uom.lk", 
      "timestamp": 1695551463.678,
      "configuration": {
        "enabled_methods": ["bruteforce", "dns_permutations", "zone_transfer", "cache_snooping"],
        "thread_count": 10,
        "rate_limit": 10,
        "timeout": 5
      },
      "methods": {
        "bruteforce": ["staff.online.uom.lk", "student.online.uom.lk", "test.online.uom.lk"],
        "dns_permutations": ["dev-online.uom.lk", "online-prod.uom.lk"], 
        "zone_transfer": ["ns1.online.uom.lk"],
        "cache_snooping": ["api.online.uom.lk", "secure.online.uom.lk"]
      },
      "statistics": {
        "total_duration": 34.12,
        "total_subdomains": 8,
        "methods_breakdown": {
          "bruteforce": 3,
          "dns_permutations": 2, 
          "zone_transfer": 1,
          "cache_snooping": 2
        },
        "queries_attempted": 2847,
        "success_rate": 87.3,
        "ai_wordlist_generated": 156
      }
    },
    "dns": {
      "domain": "online.uom.lk",
      "timestamp": 1695551497.890,
      "configuration": {
        "dns_servers": ["8.8.8.8", "1.1.1.1"],
        "timeout": 5,
        "record_types": ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"],
        "analysis_enabled": true
      },
      "dns_records": {
        "A": ["192.248.8.100", "192.248.8.101"],
        "AAAA": ["2001:db8:85a3::8a2e:370:7334"],
        "MX": ["10 mail.online.uom.lk", "20 backup-mail.uom.lk", "30 mx3.uom.lk"],
        "NS": ["ns1.online.uom.lk", "ns2.online.uom.lk", "dns1.uom.lk", "dns2.uom.lk"],
        "TXT": [
          "v=spf1 include:_spf.google.com include:mailgun.org ~all",
          "v=DMARC1; p=quarantine; rua=mailto:dmarc@uom.lk",
          "google-site-verification=abcd1234efgh5678ijkl9012mnop3456"
        ],
        "CNAME": ["www.online.uom.lk", "portal.online.uom.lk"],
        "SOA": ["ns1.online.uom.lk admin.uom.lk 2024092401 3600 1800 604800 86400"]
      },
      "subdomains": ["mail.online.uom.lk", "ns1.online.uom.lk", "ns2.online.uom.lk"],
      "analysis": {
        "infrastructure": {
          "nameservers": ["ns1.online.uom.lk", "ns2.online.uom.lk"],
          "mail_servers": ["mail.online.uom.lk", "backup-mail.uom.lk"],
          "cdn_detection": {"cloudflare": false, "aws_cloudfront": false},
          "cloud_services": []
        },
        "security_records": {
          "spf_enabled": true,
          "dmarc_enabled": true,
          "dmarc_policy": "quarantine",
          "dkim_enabled": false
        },
        "txt_analysis": {
          "verification_records": ["google-site-verification=abcd1234efgh5678ijkl9012mnop3456"],
          "service_records": ["v=spf1 include:_spf.google.com include:mailgun.org ~all"]
        }
      },
      "statistics": {
        "total_duration": 12.67,
        "total_records": 25,
        "total_subdomains": 3,
        "queries_performed": 42,
        "successful_queries": 39,
        "failed_queries": 3
      }
    },
    "fingerprinting": {
      "domain": "online.uom.lk",
      "timestamp": 1695551510.123,
      "configuration": {
        "detection_methods": ["headers", "content", "url_patterns", "wappalyzer"],
        "timeout": 30,
        "include_www": true,
        "security_analysis": true
      },
      "targets": {
        "https://online.uom.lk": {
          "url": "https://online.uom.lk",
          "timestamp": 1695551510.456,
          "response_analysis": {
            "status_code": 200,
            "content_type": "text/html; charset=UTF-8", 
            "content_length": 47234,
            "title": "University of Moratuwa - Online Portal",
            "has_html": true,
            "redirect_chain": ["http://online.uom.lk"]
          },
          "header_analysis": {
            "server": "Apache/2.4.62 (Rocky Linux) OpenSSL/3.2.2",
            "server_info": {
              "name": "Apache",
              "version": "2.4.62",
              "components": ["Rocky Linux", "OpenSSL/3.2.2"]
            },
            "framework_info": {"framework": "PHP"},
            "x_powered_by": "PHP/8.1.29"
          },
          "technology_detection": {
            "wappalyzer_detected": ["Apache", "PHP", "Moodle", "jQuery", "Font Awesome"],
            "header_detected": ["Apache", "PHP"],
            "content_detected": ["Moodle 4.1", "Bootstrap 4", "Font Awesome 5"],
            "url_patterns": ["Google Analytics", "jQuery CDN"]
          },
          "security_analysis": {
            "security_score": 45.0,
            "missing_headers": [
              "Content-Security-Policy",
              "X-Frame-Options", 
              "X-Content-Type-Options",
              "Referrer-Policy"
            ],
            "present_headers": [
              "Strict-Transport-Security",
              "X-XSS-Protection"
            ],
            "ssl_info": {
              "uses_ssl": true,
              "ssl_grade": "Needs Improvement",
              "certificate_authority": "Let's Encrypt"
            }
          },
          "performance_metrics": {
            "response_time": 2.34,
            "content_length": 47234,
            "redirect_count": 1
          },
          "technology_insights": {
            "technology_stack": {
              "web_server": ["Apache"],
              "programming_language": ["PHP"],
              "cms": ["Moodle"],
              "javascript_library": ["jQuery"],
              "css_framework": ["Bootstrap"],
              "font_library": ["Font Awesome"]
            },
            "security_implications": {
              "high_priority": ["Missing Content-Security-Policy"],
              "medium_priority": ["Missing X-Frame-Options"],
              "recommendations": ["Implement CSP header", "Add clickjacking protection"]
            }
          }
        },
        "https://moodle.online.uom.lk": {
          "url": "https://moodle.online.uom.lk",
          "response_analysis": {
            "status_code": 200,
            "content_type": "text/html; charset=UTF-8",
            "title": "Moodle LMS - University of Moratuwa"
          },
          "technology_detection": {
            "wappalyzer_detected": ["Nginx", "PHP", "Moodle"],
            "content_detected": ["Moodle 4.3", "Bootstrap 5"]
          },
          "security_analysis": {
            "security_score": 78.0,
            "present_headers": [
              "Content-Security-Policy",
              "X-Frame-Options",
              "Strict-Transport-Security"
            ]
          }
        }
      },
      "summary": {
        "total_targets": 2,
        "successful_scans": 2,
        "unique_technologies": ["Apache", "Nginx", "PHP", "Moodle", "jQuery", "Bootstrap"],
        "security_score_avg": 61.5,
        "common_issues": ["Missing security headers", "Outdated software versions"]
      },
      "statistics": {
        "total_duration": 13.10,
        "success_rate": 100.0
      }
    }
  },
  "summary": {
    "passive": {"status": "success", "subdomains_found": 12, "certificates_analyzed": 47},
    "active": {"status": "success", "subdomains_found": 8, "queries_attempted": 2847},
    "dns": {"status": "success", "subdomains_found": 3, "records_found": 25},
    "fingerprinting": {"status": "success", "targets_analyzed": 2, "technologies_identified": 15}
  },
  "all_subdomains": [
    "api.online.uom.lk", "dev-online.uom.lk", "dns.online.uom.lk", 
    "ftp.online.uom.lk", "mail.online.uom.lk", "moodle.online.uom.lk",
    "ns1.online.uom.lk", "ns2.online.uom.lk", "online.uom.lk",
    "portal.online.uom.lk", "secure.online.uom.lk", "staff.online.uom.lk",
    "student.online.uom.lk", "test.online.uom.lk", "www.online.uom.lk"
  ],
  "statistics": {
    "total_subdomains": 15,
    "unique_subdomains": 15,
    "modules_executed": 4,
    "modules_failed": 0,
    "total_execution_time": 78.34,
    "certificates_analyzed": 47,
    "dns_queries": 42,
    "http_requests": 2849,
    "technologies_detected": 15,
    "security_issues_found": 8
  }
}
```

### Results Interpretation
- **all_subdomains**: Deduplicated comprehensive list of discovered subdomains from all modules
- **modules**: Detailed individual results from each enumeration technique with rich metadata
- **passive module**: Certificate analysis, CT logs, SHA fingerprints, and certificate transparency data
- **active module**: Brute force success rates, DNS permutations, zone transfers, and AI-enhanced wordlists  
- **dns module**: Complete DNS infrastructure mapping, security record analysis, and nameserver details
- **fingerprinting module**: Technology stack detection, security analysis, performance metrics, and insights
- **summary**: Quick module overview with key performance indicators
- **statistics**: Comprehensive performance metrics and execution summary including detailed counters

## Examples

### Example 1: Quick Passive Scan
```bash
python main.py example.com --modules passive --verbose
```

### Example 2: Comprehensive Security Assessment
```bash
python main.py example.com \
    --verbose \
    --output security_assessment.json \
    --dns-timeout 10 \
    --fingerprint-timeout 45 \
    --include-www
```

### Example 3: High-Performance Active Scan
```bash
python main.py example.com \
    --modules active \
    --active-threads 25 \
    --active-rate-limit 20 \
    --wordlist /path/to/custom_wordlist.txt \
    --verbose
```

### Example 4: Focused DNS Analysis
```bash
python main.py example.com \
    --modules dns \
    --record-types A AAAA MX NS TXT \
    --dns-timeout 8 \
    --dns-retries 3 \
    --verbose
```