# 🔍 Web Domain Scanner - Streamlit UI

A beautiful and interactive web interface for the Web Domain Scanner built with Streamlit.

## Features

### 🎯 **Real-time Scanning**
- Live progress tracking with animated progress bars
- Real-time metrics updates every second
- Interactive status monitoring

### 📊 **Rich Data Visualization**
- Interactive charts for subdomains, services, and endpoints
- Plotly-powered visualizations
- Responsive design for all screen sizes

### 🔍 **Comprehensive Results Display**
- **Subdomains Tab**: Visual charts and detailed subdomain lists
- **Services Tab**: Open ports analysis with service identification
- **Web Technologies Tab**: Technology fingerprinting results
- **API Endpoints Tab**: Discovered APIs with source tracking
- **Cloud Services Tab**: CDN and cloud service detection
- **Raw Data Tab**: Complete JSON results with download option

### 📱 **User-Friendly Interface**
- Clean, modern design with custom CSS styling
- Responsive layout for desktop and mobile
- Intuitive navigation with tabbed results
- Real-time status indicators

### 📈 **Advanced Features**
- Scan history tracking
- Results download in JSON format
- Optional Gemini API integration for enhanced discovery
- Auto-refresh for active scans

## Installation

### Prerequisites
- Python 3.8 or higher
- FastAPI server running (from the main project)

### Quick Start

1. **Install dependencies:**
   ```bash
   pip install -r requirements_ui.txt
   ```

2. **Start the FastAPI server** (in another terminal):
   ```bash
   cd ../src
   python server.py
   ```

3. **Launch the Streamlit UI:**
   ```bash
   streamlit run streamlit_app.py
   ```

### Automated Startup

Use the provided startup scripts to launch both server and UI together:

**Windows:**
```cmd
start_scanner.bat
```

**Linux/Mac:**
```bash
./start_scanner.sh
```

## Usage

### Starting a Scan

1. **Enter Domain**: Input the target domain (without http/https)
2. **API Key** (Optional): Add your Gemini API key for enhanced endpoint discovery
3. **Click "Start Scan"**: Begin the reconnaissance process

### Monitoring Progress

- **Progress Bar**: Visual indication of scan completion
- **Live Metrics**: Real-time count of discovered assets
- **Status Updates**: Current scan phase and messages
- **Auto-refresh**: Page updates every 2 seconds during active scans

### Viewing Results

Once a scan completes, explore results across multiple tabs:

#### 📍 Subdomains Tab
- Visual bar chart of discovered subdomains
- Searchable table with all subdomain details
- Export functionality

#### 🔌 Services Tab  
- Horizontal bar chart of open ports
- Detailed service information table
- Banner information and service identification

#### 🌐 Web Technologies Tab
- Technology fingerprinting results
- Server information and frameworks
- HTTP headers analysis

#### 🔗 API Endpoints Tab
- Discovered API endpoints
- Source tracking (AI-generated vs default)
- Response codes and content types
- Pie chart showing discovery methods

#### ☁️ Cloud Services Tab
- CDN detection results
- Cloud service identification
- S3 bucket discoveries

#### 📄 Raw Data Tab
- Complete JSON results
- Download button for offline analysis
- Formatted JSON viewer

## Configuration

### API Integration
The UI connects to the FastAPI server at `http://localhost:8000` by default. To change this:

```python
# In streamlit_app.py
API_BASE_URL = "http://your-server:port"
```

### UI Customization
Modify the custom CSS in `streamlit_app.py` to change the appearance:

```python
st.markdown("""
<style>
    .main-header {
        color: #your-color;
        /* Add your custom styles */
    }
</style>
""", unsafe_allow_html=True)
```

## API Endpoints Used

The UI communicates with these FastAPI endpoints:

- `GET /api/data?domain={domain}&gemini_key={key}` - Start a new scan
- `GET /api/status/{request_id}` - Get scan status and results

## Screenshots

### Main Interface
![Main Interface](docs/screenshots/main_interface.png)

### Real-time Progress
![Progress Tracking](docs/screenshots/progress_tracking.png)

### Results Dashboard
![Results Dashboard](docs/screenshots/results_dashboard.png)

## Troubleshooting

### Common Issues

1. **"Failed to start scan" Error**
   - Ensure the FastAPI server is running on port 8000
   - Check if the domain is entered correctly (without http/https)

2. **"Failed to get status" Error**
   - Server connection issue
   - Check server logs for errors

3. **UI Not Loading**
   - Ensure all dependencies are installed
   - Try refreshing the browser page

4. **Charts Not Displaying**
   - Update Plotly: `pip install --upgrade plotly`
   - Clear browser cache

### Debug Mode

Run with debug output:
```bash
streamlit run streamlit_app.py --logger.level debug
```

## Development

### Project Structure
```
ui/
├── streamlit_app.py      # Main UI application
├── launcher.py           # Simple launcher/status checker
├── requirements_ui.txt   # UI-specific dependencies
└── README.md            # This file
```

### Adding New Features

1. **New Visualization**: Add to the appropriate display function
2. **New Tab**: Add to the tabs section in main()
3. **New Metric**: Update the display_metrics() function

### Custom Components

The UI uses several custom functions for different visualizations:
- `display_subdomains_chart()` - Subdomain visualization
- `display_services_chart()` - Service/port charts  
- `display_web_technologies()` - Technology tables
- `display_api_endpoints()` - API endpoint analysis
- `display_cloud_services()` - Cloud service detection

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add your improvements
4. Test with various scan results
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For issues and questions:
1. Check the troubleshooting section
2. Review server logs
3. Open an issue on GitHub

---

*Built with ❤️ using Streamlit, Plotly, and FastAPI*
