# Web Domain Scanner

A comprehensive Python-based web domain reconnaissance tool that performs security scanning including subdomain discovery, service enumeration, web crawling, API endpoint discovery, and cloud service detection with advanced multi-provider AI-powered endpoint discovery.

## 🚀 Quick Start

```bash
# 1. Clone and setup
git clone <repository-url>
cd web-domain-scanner

# 2. Run automated setup
./scripts/setup_environment.sh

# 3. Configure API keys (optional)
nano .env  # Add your AI provider API keys

# 4. Run a scan
./scripts/run_scan.sh example.com
```

## ✨ Features

- **🔍 Subdomain Discovery** - DNS brute force enumeration
- **🌐 Service Discovery** - Port scanning and service identification
- **🛠️ Web Fingerprinting** - AI-enhanced technology stack detection
- **📁 Directory Brute Force** - Common directory discovery
- **🤖 Multi-Provider AI API Discovery** - Intelligent endpoint detection with multiple AI models
  - Supports Google Gemini
  - Supports OpenAI GPT models
  - Supports Anthropic Claude
  - Includes feedback-based learning system
  - Fallback to rule-based discovery when AI is unavailable
- **☁️ Cloud Service Detection** - AWS S3 buckets and CDN identification
- **📊 Professional Reports** - HTML and JSON output with security assessment
- **⚡ Asynchronous Processing** - Optional async API for improved performance

## 📋 Prerequisites

- Python 3.7+
- nmap and dnsutils
- Internet connection
- API keys (optional, for enhanced AI features):
  - Google Gemini API key
  - OpenAI API key
  - Anthropic API key

## 🛠️ Installation

### Automated Setup (Recommended)

```bash
./scripts/setup_environment.sh
```

### Manual Setup

1. **System dependencies:**

   ```bash
   sudo apt update && sudo apt install -y nmap dnsutils python3 python3-venv
   ```

2. **Python environment:**

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

3. **Configuration:**
   ```bash
   cp .env.example .env
   # Edit .env and add your Gemini API key
   ```

## 🎯 Usage

### Basic Scanning

```bash
# Activate environment
source .venv/bin/activate

# Basic scan
python src/main.py example.com

# With AI-powered endpoint discovery (multiple options)
python src/main.py example.com --gemini-key YOUR_GEMINI_KEY
python src/main.py example.com --openai-key YOUR_OPENAI_KEY
python src/main.py example.com --anthropic-key YOUR_CLAUDE_KEY

# Use multiple AI providers with asynchronous processing
python src/main.py example.com --gemini-key YOUR_GEMINI_KEY --openai-key YOUR_OPENAI_KEY --async
```

### Quick Start Scripts

```bash
# Complete scan with environment setup
./scripts/run_scan.sh example.com

# With specific API key
./scripts/run_scan.sh example.com --gemini-key YOUR_GEMINI_KEY
```

## 📊 Sample Output

The scanner performs comprehensive reconnaissance:

1. **Subdomain Discovery** - Find hidden subdomains
2. **Service Enumeration** - Identify open ports and services
3. **Web Technology Detection** - Server and framework identification
4. **Directory Discovery** - Common paths and admin panels
5. **API Endpoint Discovery** - REST, GraphQL, and custom APIs
6. **Cloud Service Detection** - S3 buckets, CDNs, and cloud resources
7. **Security Assessment** - Risk analysis and recommendations

### Generated Reports

- **HTML Report**: Professional security assessment report
- **JSON Report**: Machine-readable results for integration
- **Logs**: Detailed scan progress and debug information

## 🔧 Configuration

### Environment Variables (.env)

```env
# AI Provider API Keys
GEMINI_API_KEY=your_gemini_api_key_here
OPENAI_API_KEY=your_openai_api_key_here
ANTHROPIC_API_KEY=your_anthropic_api_key_here

# Scanner Configuration
MAX_THREADS=15
RATE_LIMIT=5
REQUEST_TIMEOUT=10

# Output Settings
OUTPUT_DIR=scan_results
LOG_LEVEL=INFO

# SSL Settings
VERIFY_SSL=true
```

### Get AI Provider API Keys

1. **Google Gemini API Key**: Visit [Google AI Studio](https://aistudio.google.com/apikey)
2. **OpenAI API Key**: Get from [OpenAI Platform](https://platform.openai.com/api-keys)
3. **Anthropic Claude API Key**: Get from [Anthropic Console](https://console.anthropic.com/keys)
4. Add to your `.env` file

## 🛡️ Security Notice

⚠️ **IMPORTANT**: This tool is for educational and authorized security testing only.

- Only scan domains you own or have explicit permission to test
- Respect rate limits and server resources
- Follow responsible disclosure practices
- Some activities may trigger security monitoring

## 🐛 Troubleshooting

### Common Issues

**Permission denied:**

```bash
chmod +x scripts/*.sh
```

**Missing nmap:**

```bash
sudo apt install nmap
```

**SSL errors:**

```bash
# Set in .env file
VERIFY_SSL=false
```

**Import errors:**

```bash
source .venv/bin/activate
pip install -r requirements.txt
```

## 🔍 What Gets Scanned

- **DNS Records**: A, AAAA, MX, NS, TXT, CNAME, SOA
- **Common Ports**: 21, 22, 80, 443, 3306, 3389, 8080
- **Web Technologies**: Server headers, frameworks, CMS
- **Common Directories**: admin, api, backup, test, login
- **API Endpoints**: REST, GraphQL, Swagger, custom APIs
- **Cloud Services**: S3 buckets, CDNs, cloud indicators

## 📁 Project Structure

```
web-domain-scanner/
├── src/
│   ├── main.py                 # Main scanner entry point
│   ├── modules/                # Core scanning modules
│   │   ├── domain_enumeration.py
│   │   ├── service_discovery.py
│   │   ├── web_crawling.py
│   │   ├── ai_integration.py
│   │   └── cloud_detection.py
│   └── output/                 # Report generation
├── config/                     # Configuration files
├── scripts/                    # Setup and utility scripts
├── docs/                       # Documentation
└── requirements.txt            # Python dependencies
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📄 License

This project is for educational purposes only. Users are responsible for complying with all applicable laws and regulations.

---

**Happy scanning! 🔍** Remember to always scan responsibly and with proper authorization.
