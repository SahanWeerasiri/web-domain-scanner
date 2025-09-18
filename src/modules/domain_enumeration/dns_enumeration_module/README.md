# DNS Domain Enumeration Module

This module provides comprehensive DNS record enumeration and analysis to discover subdomains through various DNS record types and infrastructure analysis.

## Features

- **Multiple DNS Record Types**: A, AAAA, MX, NS, TXT, CNAME, SOA record queries
- **Subdomain Extraction**: Automatic subdomain discovery from DNS responses
- **Infrastructure Analysis**: DNS infrastructure mapping and configuration analysis
- **Security Assessment**: Analysis of DNS security configurations (SPF, DMARC, DKIM)
- **Additional Record Queries**: Deep analysis of discovered subdomains

## Usage

### Basic DNS Enumeration
```python
from dns_enumeration import DNSEnumerator

# Create enumerator instance
enumerator = DNSEnumerator("example.com")

# Run DNS enumeration
dns_records = enumerator.run_dns_enumeration()

# Extract subdomains from DNS records
subdomains = enumerator.extract_subdomains_from_dns_records(dns_records)

print(f"Found {len(subdomains)} subdomains from DNS records")
```

### With Infrastructure Analysis
```python
# Perform infrastructure analysis
analysis = enumerator.analyze_dns_infrastructure(dns_records)

print(f"Nameservers: {analysis['nameservers']}")
print(f"Mail servers: {analysis['mail_servers']}")
print(f"Security records: {analysis['security_records']}")
```

### Command Line Usage
```bash
# Basic DNS enumeration
python dns_enumeration.py example.com

# With infrastructure analysis
python dns_enumeration.py example.com --analyze
```

## Configuration

### Basic Configuration
```python
from config import EnumerationConfig

config = EnumerationConfig()
config.timeout = 10  # DNS query timeout in seconds
```

### Available Settings
- `timeout`: DNS query timeout in seconds (default: 10)

## Results Structure

```python
{
    'A': ['192.168.1.1', '10.0.0.1'],
    'AAAA': ['2001:db8::1'],
    'MX': ['mail.example.com', 'backup-mail.example.com'],
    'NS': ['ns1.example.com', 'ns2.example.com'],
    'TXT': ['v=spf1 include:_spf.google.com ~all'],
    'CNAME': ['www.example.com'],
    'SOA': ['ns1.example.com admin.example.com ...']
}
```

## DNS Record Analysis

### Record Types Queried
- **A Records**: IPv4 addresses
- **AAAA Records**: IPv6 addresses  
- **MX Records**: Mail exchange servers
- **NS Records**: Name servers
- **TXT Records**: Text records (SPF, DKIM, DMARC, verification)
- **CNAME Records**: Canonical name records
- **SOA Records**: Start of authority records

### Subdomain Extraction
The module extracts subdomains from multiple sources:
- CNAME record targets
- MX record mail servers
- NS record name servers
- Domain references in TXT records

### Security Analysis
Analyzes DNS security configurations:
- **SPF Records**: Email sender policy framework
- **DMARC Records**: Domain-based message authentication
- **DKIM Records**: DomainKeys identified mail
- **DNSSEC**: DNS security extensions (when available)

## Error Handling

```python
# Get errors encountered during enumeration
errors = enumerator.get_errors()
for method, error_list in errors.items():
    print(f"{method}: {len(error_list)} errors")
```

Common error types handled:
- **NXDOMAIN**: Domain does not exist
- **NoAnswer**: No records of requested type
- **Timeout**: DNS query timeout
- **ServerFailure**: DNS server errors

## Dependencies

Required packages:
- `dnspython`: DNS operations and record parsing