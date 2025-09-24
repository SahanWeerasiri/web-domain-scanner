# Streamlit Web UI for Web Domain Scanner

A comprehensive web interface for the Web Domain Scanner Flask API, built with Streamlit.

## 🚀 Features

### Core Functionality
- **Interactive Scan Configuration**: Easy-to-use forms for setting up domain reconnaissance scans
- **Real-time Progress Tracking**: Live monitoring of scan progress with auto-refresh
- **Comprehensive Results Display**: Rich visualizations and detailed results analysis  
- **Job Management**: Full history and status tracking for all scan jobs
- **Export Capabilities**: Download results in JSON or CSV format

### User Interface
- **Responsive Design**: Works on desktop, tablet, and mobile devices
- **Dark/Light Mode**: Automatic theme detection and manual toggle
- **Interactive Charts**: Plotly-powered visualizations for better data insights
- **Real-time Updates**: Auto-refreshing status and progress indicators
- **Intuitive Navigation**: Tab-based interface with clear sections

### Advanced Features
- **Module Selection**: Choose specific scanning modules to run
- **Parameter Customization**: Fine-tune all scanning parameters
- **Progress Visualization**: Real-time progress bars and module status
- **Result Analysis**: Interactive charts for subdomains, ports, and services
- **API Integration**: Seamless communication with Flask backend

## 📦 Installation

### Prerequisites
- Python 3.8+ 
- Flask API Server running (see main project README)
- Required Python packages (installed automatically)

### Quick Start

1. **Install Streamlit dependencies:**
   ```bash
   pip install -r streamlit_requirements.txt
   ```

2. **Start the Flask API server first:**
   ```bash
   cd src
   python main.py
   ```

3. **Launch Streamlit UI:**
   ```bash
   streamlit run src/streamlit_ui.py
   ```

### Full Stack Launch (Recommended)

Use the provided launcher scripts to start both servers:

**Windows:**
```bash
launch_fullstack.bat
```

**Linux/macOS:**
```bash
chmod +x launch_fullstack.sh
./launch_fullstack.sh
```

## 🖥️ Interface Overview

### 1. New Scan Tab 🚀
Configure and submit new domain reconnaissance scans:

- **Basic Settings**: Domain input, module selection, verbosity
- **Domain Enumeration**: Passive/active techniques, threading, timeouts
- **Service Discovery**: Port scan modes, custom port ranges
- **Web Analysis**: CDN bypass, deep crawling options
- **Advanced Settings**: Custom wordlists, AI integration settings

### 2. Monitor Jobs Tab 📊  
Track active and recent scans in real-time:

- **Auto-refresh**: 3-second intervals for live updates
- **Progress Tracking**: Visual progress bars and percentage completion
- **Module Status**: Current executing module and completion status
- **Live Logs**: Real-time verbose logging output
- **Detailed Results**: Interactive result visualization when complete

### 3. Job History Tab 📚
Manage and review all previous scans:

- **Sortable Table**: Filter and sort jobs by status, date, domain
- **Quick Actions**: View details, refresh status, copy job IDs  
- **Statistics**: Visual charts for job trends and success rates
- **Bulk Management**: Mass operations on multiple jobs

## 📊 Result Visualizations

### Domain Enumeration Results
- **Subdomain Lists**: Sortable tables with all discovered subdomains
- **Distribution Charts**: Pie charts showing subdomain type breakdown
- **Statistics Dashboard**: Execution times, success rates, module performance

### Service Discovery Results  
- **Port Tables**: Detailed service information, banners, confidence scores
- **Port Distribution**: Scatter plots showing open port ranges
- **Service Analysis**: Charts for common services and protocols

### Web Analysis Results
- **CDN Detection**: Status indicators and provider identification
- **API Discovery**: Lists of discovered API endpoints and paths
- **Technology Stack**: Detected web technologies and frameworks
- **Crawl Summary**: Pages discovered and crawling statistics

## 🔧 Configuration

### API Connection Settings
The UI connects to the Flask API server at `http://localhost:5000` by default. 

To change the API endpoint, modify the `API_BASE_URL` constant in `src/streamlit_ui.py`:

```python
API_BASE_URL = "http://your-api-server:5000"
```

### Auto-refresh Settings
Adjust the refresh interval by modifying:

```python
REFRESH_INTERVAL = 3  # seconds
MAX_LOG_LINES = 20    # number of log lines to display
```

### Visual Customization
The UI uses custom CSS styling. Modify the styles in the `st.markdown()` section at the top of the file to customize:

- Color schemes
- Card layouts  
- Typography
- Spacing and margins

## 🛠️ API Integration

The Streamlit UI communicates with the Flask API through the `APIClient` class:

### Key Methods
- `health_check()`: Verify API server status
- `submit_scan()`: Submit new scan jobs
- `get_job_status()`: Retrieve job progress and results
- `list_jobs()`: Get all job history

### Error Handling
- Connection timeouts with user-friendly messages
- API error parsing and display
- Graceful degradation when API is unavailable
- Retry mechanisms for transient failures

## 📱 Usage Examples

### Basic Domain Scan
1. Go to "New Scan" tab
2. Enter domain: `example.com`
3. Select modules: `domain_enumeration`, `service_discovery`
4. Click "Start Scan"
5. Monitor progress in "Monitor Jobs" tab

### Advanced Custom Scan  
1. Configure custom port range: `80,443,8080-8090`
2. Set scan mode to "deep" for comprehensive port scanning
3. Upload custom wordlist for domain enumeration
4. Enable CDN bypass and deep crawling
5. Adjust thread counts and timeouts for performance

### Result Analysis
1. View completed jobs in "Job History"
2. Click "View Details" for comprehensive results
3. Use interactive charts to analyze findings
4. Export results in JSON or CSV format
5. Copy specific findings for further investigation

## 🔒 Security Considerations

- **Local Development**: Default configuration for localhost development
- **Production Deployment**: Secure API endpoints with authentication
- **Data Privacy**: Scan results stored temporarily in browser session
- **Network Security**: Ensure API server is properly secured

## 🐛 Troubleshooting

### Common Issues

**Streamlit Won't Start:**
```bash
# Check Python version
python --version

# Install missing dependencies
pip install -r streamlit_requirements.txt

# Run with verbose output
streamlit run src/streamlit_ui.py --logger.level debug
```

**API Connection Errors:**
```bash
# Verify Flask server is running
curl http://localhost:5000/api/health

# Check firewall settings
netstat -an | grep 5000
```

**Progress Not Updating:**
- Enable auto-refresh toggle
- Check browser console for JavaScript errors
- Verify WebSocket connections are allowed

### Performance Tips
- **Large Results**: Use pagination for datasets with >1000 items
- **Memory Usage**: Clear old job data periodically
- **Network**: Reduce auto-refresh interval on slow connections
- **Browser**: Use Chrome/Firefox for best compatibility

## 🤝 Contributing

Contributions are welcome! Areas for improvement:

- **Mobile Responsiveness**: Enhanced mobile layouts
- **Additional Charts**: More visualization types for results
- **Export Options**: Additional export formats (PDF, Excel)
- **Bulk Operations**: Mass job management features  
- **User Preferences**: Persistent UI settings and preferences

## 📄 License

This project is licensed under the same license as the main Web Domain Scanner project.

---

🔍 **Web Domain Scanner Streamlit UI** - Making domain reconnaissance accessible and visual!