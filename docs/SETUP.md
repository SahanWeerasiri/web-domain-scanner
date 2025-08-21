# Web Domain Scanner Setup Guide

A comprehensive Python-based web domain reconnaissance tool that performs security scanning including subdomain discovery, service enumeration, web crawling, API endpoint discovery, and cloud service detection with AI-powered endpoint discovery.

## Features

- **Subdomain Discovery**: DNS brute force enumeration
- **Service Discovery**: Port scanning and service identification
- **Web Technology Fingerprinting**: Server and technology detection
- **Directory Brute Force**: Common directory discovery
- **API Endpoint Discovery**: AI-powered and traditional endpoint detection
- **Cloud Service Detection**: AWS S3 buckets and CDN identification
- **DNS Record Enumeration**: Complete DNS record analysis
- **HTML & JSON Reports**: Professional reporting with security assessment

## Prerequisites

- **Python**: 3.7 or higher
- **Operating System**: Linux (Kali Linux recommended), macOS, or Windows with WSL
- **System Tools**: nmap, dnsutils (dig, nslookup)
- **Internet Connection**: Required for domain scanning
- **Gemini API Key**: Optional but recommended for AI-powered endpoint discovery

## Quick Setup

### Option 1: Automated Setup (Recommended)

```bash
# Clone the repository (if not already done)
cd /path/to/web-domain-scanner

# Run the automated setup script
./scripts/setup_environment.sh
```

### Option 2: Manual Setup

1. **Install System Dependencies:**

   ```bash
   # On Debian/Ubuntu/Kali Linux:
   sudo apt update && sudo apt install -y nmap dnsutils python3 python3-venv

   # On macOS:
   brew install nmap python3

   # On CentOS/RHEL:
   sudo yum install -y nmap bind-utils python3
   ```

2. **Create Virtual Environment:**

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. **Install Python Dependencies:**

   ```bash
   pip install --upgrade pip
   pip install -r requirements.txt
   ```

4. **Configure Environment:**
   ```bash
   cp .env.example .env
   # Edit .env file and add your Gemini API key
   ```

## Configuration

### Environment Variables (.env file)

```env
# Gemini AI API Key (Optional - for AI-powered endpoint discovery)
GEMINI_API_KEY=your_gemini_api_key_here

# Scanner Configuration
MAX_THREADS=15
RATE_LIMIT=5
REQUEST_TIMEOUT=10
SCAN_TIMEOUT=300

# Output Settings
OUTPUT_DIR=scan_results
LOG_LEVEL=INFO

# SSL Verification
VERIFY_SSL=true
```

### Getting a Gemini API Key

1. Visit [Google AI Studio](https://aistudio.google.com/apikey)
2. Sign in with your Google account
3. Create a new API key
4. Add the key to your `.env` file

## Usage

### Basic Usage

```bash
# Activate virtual environment
source .venv/bin/activate

# Run basic scan
python src/main.py example.com

# Run with AI-powered endpoint discovery
python src/main.py example.com --gemini-key YOUR_API_KEY
```

### Quick Start Scripts

```bash
# Run complete scan with auto-environment setup
./scripts/run_scan.sh example.com

# With Gemini API key
./scripts/run_scan.sh example.com YOUR_GEMINI_API_KEY
```

### Command Line Options

```bash
python src/main.py <domain> [--gemini-key API_KEY]

Arguments:
  domain              Target domain to scan (e.g., example.com)
  --gemini-key       Gemini API key for AI-powered endpoint discovery
```

## What the Scanner Does

1. **Subdomain Discovery**

   - DNS brute force using common subdomain wordlist
   - Passive enumeration techniques

2. **DNS Record Enumeration**

   - A, AAAA, MX, NS, TXT, CNAME, SOA records
   - Complete DNS infrastructure mapping

3. **Service Discovery**

   - Port scanning for common services (21, 22, 80, 443, etc.)
   - Service banner grabbing and identification

4. **Web Technology Fingerprinting**

   - Server identification (Apache, Nginx, IIS)
   - Technology stack detection (PHP, Node.js, etc.)
   - Response header analysis

5. **Directory Discovery**

   - Common web directory brute force
   - Admin panels, backup files, sensitive directories

6. **API Endpoint Discovery**

   - AI-powered endpoint generation based on website content
   - Common API patterns (REST, GraphQL, Swagger)
   - JavaScript file analysis for endpoint hints

7. **Cloud Service Detection**
   - AWS S3 bucket enumeration
   - CDN detection (CloudFlare, Akamai, etc.)
   - Public cloud service exposure

## Output and Reports

The scanner generates comprehensive reports in multiple formats:

### Generated Files

- `recon_results_<domain>_<timestamp>/`
  - `final_report.json` - Complete JSON report
  - `recon_report.html` - Professional HTML report
  - `web_wordlist.txt` - Generated wordlist
  - `reconnaissance.log` - Scan logs

### HTML Report Features

- Executive summary with risk assessment
- Interactive security findings
- Technology stack visualization
- Service and port analysis
- API endpoint documentation
- Cloud service detection results

## Troubleshooting

### Common Issues

1. **Permission Denied on Scripts**

   ```bash
   chmod +x scripts/*.sh
   ```

2. **nmap Command Not Found**

   ```bash
   sudo apt install nmap  # Linux
   brew install nmap      # macOS
   ```

3. **DNS Resolution Errors**

   - Check internet connection
   - Verify domain exists
   - Try with `www.` prefix

4. **SSL Certificate Errors**

   - Set `VERIFY_SSL=false` in .env for self-signed certificates

5. **Python Import Errors**
   - Ensure virtual environment is activated
   - Reinstall dependencies: `pip install -r requirements.txt`

### Debug Mode

For detailed debugging:

```bash
# Enable debug logging
export LOG_LEVEL=DEBUG
python src/main.py example.com
```

## Security Considerations

⚠️ **IMPORTANT**: This tool is for educational and authorized security testing only.

- Only scan domains you own or have explicit permission to test
- Respect rate limits and target server resources
- Some scanning activities may trigger security alerts
- Always follow responsible disclosure practices

## Advanced Usage

### Custom Wordlists

Replace default wordlists in `config/wordlists/`:

- `subdomains.txt` - Subdomain enumeration
- `common_directories.txt` - Directory brute force
- `api_endpoints.txt` - API endpoint patterns

### Proxy Support

Configure proxies in `.env`:

```env
HTTP_PROXY=http://proxy.example.com:8080
HTTPS_PROXY=https://proxy.example.com:8080
```

### Rate Limiting

Adjust scan speed in `config/settings.py`:

- Increase `RATE_LIMIT` for faster scans
- Decrease for gentler scanning

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

This project is for educational purposes only. Users are responsible for complying with all applicable laws and regulations.

## Support

For issues and questions:

1. Check the troubleshooting section
2. Review the logs in `reconnaissance.log`
3. Ensure all dependencies are correctly installed
4. Verify the target domain is accessible

---

**Remember**: Always obtain proper authorization before scanning any domain you don't own.
