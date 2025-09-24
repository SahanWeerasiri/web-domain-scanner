#!/usr/bin/env python3
"""
Streamlit Web UI for Unified Web Domain Scanner
==============================================

This Streamlit application provides a user-friendly web interface for the 
Flask-based domain reconnaissance API server.

Features:
- Submit scan jobs with customizable parameters
- Real-time progress tracking with auto-refresh
- View detailed results and export data
- Job history and management
- Interactive charts and visualizations

Author: Web Domain Scanner Project  
License: See LICENSE file in project root
"""

import streamlit as st
import requests
import json
import time
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import uuid

# Page configuration
st.set_page_config(
    page_title="Web Domain Scanner",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Global configuration
API_BASE_URL = "http://localhost:5000"
REFRESH_INTERVAL = 3  # seconds
MAX_LOG_LINES = 20

# CSS styling
st.markdown("""
<style>
    .main-header {
        font-size: 3rem;
        color: #2E86AB;
        text-align: center;
        margin-bottom: 2rem;
    }
    .scan-card {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #2E86AB;
        margin: 1rem 0;
    }
    .success-box {
        background-color: #d4edda;
        color: #155724;
        padding: 1rem;
        border-radius: 0.5rem;
        border: 1px solid #c3e6cb;
    }
    .error-box {
        background-color: #f8d7da;
        color: #721c24;
        padding: 1rem;
        border-radius: 0.5rem;
        border: 1px solid #f5c6cb;
    }
    .info-box {
        background-color: #cce7ff;
        color: #004085;
        padding: 1rem;
        border-radius: 0.5rem;
        border: 1px solid #bee5eb;
    }
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 1rem;
        border-radius: 0.5rem;
        color: white;
        text-align: center;
    }
</style>
""", unsafe_allow_html=True)


class APIClient:
    """Client for interacting with the Flask API server"""
    
    def __init__(self, base_url: str = API_BASE_URL):
        self.base_url = base_url
    
    def health_check(self) -> Dict[str, Any]:
        """Check if the API server is healthy"""
        try:
            response = requests.get(f"{self.base_url}/api/health", timeout=5)
            return {
                'status': 'healthy' if response.status_code == 200 else 'unhealthy',
                'data': response.json() if response.status_code == 200 else None,
                'error': None
            }
        except Exception as e:
            return {'status': 'error', 'data': None, 'error': str(e)}
    
    def submit_scan(self, scan_params: Dict[str, Any]) -> Dict[str, Any]:
        """Submit a new scan job"""
        try:
            response = requests.post(
                f"{self.base_url}/api/scan",
                json=scan_params,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            
            if response.status_code in [200, 202]:
                return {'success': True, 'data': response.json(), 'error': None}
            else:
                return {'success': False, 'data': None, 'error': response.json().get('error', 'Unknown error')}
        except Exception as e:
            return {'success': False, 'data': None, 'error': str(e)}
    
    def get_job_status(self, job_id: str) -> Dict[str, Any]:
        """Get status of a specific job"""
        try:
            response = requests.get(f"{self.base_url}/api/status/{job_id}", timeout=10)
            
            if response.status_code == 200:
                return {'success': True, 'data': response.json(), 'error': None}
            else:
                return {'success': False, 'data': None, 'error': response.json().get('error', 'Job not found')}
        except Exception as e:
            return {'success': False, 'data': None, 'error': str(e)}
    
    def list_jobs(self) -> Dict[str, Any]:
        """List all jobs"""
        try:
            response = requests.get(f"{self.base_url}/api/jobs", timeout=10)
            
            if response.status_code == 200:
                return {'success': True, 'data': response.json(), 'error': None}
            else:
                return {'success': False, 'data': None, 'error': 'Failed to list jobs'}
        except Exception as e:
            return {'success': False, 'data': None, 'error': str(e)}


def initialize_session_state():
    """Initialize Streamlit session state variables"""
    if 'api_client' not in st.session_state:
        st.session_state.api_client = APIClient()
    
    if 'active_jobs' not in st.session_state:
        st.session_state.active_jobs = {}
    
    if 'job_history' not in st.session_state:
        st.session_state.job_history = []
    
    if 'auto_refresh' not in st.session_state:
        st.session_state.auto_refresh = False
    
    if 'selected_job_id' not in st.session_state:
        st.session_state.selected_job_id = None


def render_header():
    """Render the main header and server status"""
    st.markdown('<h1 class="main-header">🔍 Web Domain Scanner</h1>', unsafe_allow_html=True)
    
    # Server health check
    health = st.session_state.api_client.health_check()
    
    col1, col2, col3 = st.columns([2, 1, 1])
    
    with col1:
        if health['status'] == 'healthy':
            st.markdown('<div class="success-box">✅ Server is running and healthy</div>', unsafe_allow_html=True)
        else:
            st.markdown(f'<div class="error-box">❌ Server is not available: {health["error"]}</div>', unsafe_allow_html=True)
    
    with col2:
        if health['status'] == 'healthy' and health['data']:
            st.metric("Scanner Status", "Available" if health['data'].get('scanner_available') else "Unavailable")
    
    with col3:
        if health['status'] == 'healthy' and health['data']:
            st.metric("Server Version", health['data'].get('version', 'Unknown'))


def render_scan_form():
    """Render the scan configuration form"""
    st.header("🚀 New Scan Configuration")
    
    with st.form("scan_form"):
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Basic Settings")
            
            # Domain input (required)
            domain = st.text_input(
                "Target Domain *",
                placeholder="example.com",
                help="Enter the domain you want to scan (required)"
            )
            
            # Module selection
            enabled_modules = st.multiselect(
                "Select Modules to Run",
                ['domain_enumeration', 'service_discovery', 'web_analysis'],
                default=['domain_enumeration', 'service_discovery', 'web_analysis'],
                help="Choose which scanning modules to execute"
            )
            
            # Verbose output
            verbose = st.checkbox("Verbose Output", value=True, help="Enable detailed logging")
            
            # Service discovery settings
            st.subheader("Service Discovery")
            scan_mode = st.selectbox(
                "Port Scan Mode",
                ['quick', 'smart', 'deep'],
                index=1,
                help="Quick: Top 100 ports, Smart: Top 1000 ports, Deep: All 65535 ports"
            )
            
            ports = st.text_input(
                "Custom Ports (Optional)",
                placeholder="80,443,8080 or 1-1000",
                help="Specify custom ports to scan (overrides scan mode)"
            )
        
        with col2:
            st.subheader("Domain Enumeration")
            
            # Domain enumeration modules
            domain_enum_modules = st.multiselect(
                "Domain Enumeration Techniques",
                ['passive', 'active', 'dns', 'fingerprinting'],
                default=['passive', 'active', 'dns', 'fingerprinting'],
                help="Select domain enumeration techniques to use"
            )
            
            # Advanced settings
            st.subheader("Advanced Settings")
            
            col2a, col2b = st.columns(2)
            with col2a:
                active_threads = st.slider("Active Threads", 1, 50, 10, help="Number of threads for active enumeration")
                dns_timeout = st.slider("DNS Timeout (s)", 1, 30, 5, help="DNS query timeout in seconds")
            
            with col2b:
                passive_timeout = st.slider("Passive Timeout (s)", 5, 60, 10, help="Passive enumeration timeout")
                fingerprint_timeout = st.slider("Fingerprint Timeout (s)", 10, 120, 30, help="Web fingerprinting timeout")
            
            # Web analysis settings
            st.subheader("Web Analysis")
            bypass_cdn = st.checkbox("CDN Bypass", value=True, help="Attempt to bypass CDN if detected")
            deep_crawl = st.checkbox("Deep Crawl", value=False, help="Perform deep web crawling")
            
            # File settings
            wordlist = st.file_uploader("Custom Wordlist (Optional)", type=['txt'], help="Upload custom wordlist for active enumeration")
            no_ai = st.checkbox("Disable AI", value=False, help="Disable AI-enhanced enumeration")
        
        # Submit button
        submit_button = st.form_submit_button("🔍 Start Scan", type="primary", use_container_width=True)
        
        if submit_button:
            if not domain:
                st.error("Please enter a target domain")
                return
            
            if not enabled_modules:
                st.error("Please select at least one module to run")
                return
            
            # Prepare scan parameters
            scan_params = {
                'domain': domain.strip(),
                'enabled_modules': enabled_modules,
                'verbose': verbose,
                'scan_mode': scan_mode,
                'bypass_cdn': bypass_cdn,
                'deep_crawl': deep_crawl,
                'active_threads': active_threads,
                'passive_timeout': passive_timeout,
                'dns_timeout': dns_timeout,
                'fingerprint_timeout': fingerprint_timeout,
                'no_ai': no_ai,
                'domain_enum_modules': domain_enum_modules
            }
            
            if ports:
                scan_params['ports'] = ports
            
            # Submit scan
            result = st.session_state.api_client.submit_scan(scan_params)
            
            if result['success']:
                job_data = result['data']
                job_id = job_data['job_id']
                
                # Store job in session state
                st.session_state.active_jobs[job_id] = {
                    'id': job_id,
                    'domain': domain,
                    'submitted_at': datetime.now(),
                    'status': job_data['status'],
                    'parameters': scan_params
                }
                
                st.session_state.selected_job_id = job_id
                
                st.success(f"✅ Scan submitted successfully!\nJob ID: `{job_id}`")
                st.balloons()
                
                # Auto-refresh for new jobs
                st.session_state.auto_refresh = True
                
            else:
                st.error(f"❌ Failed to submit scan: {result['error']}")


def render_job_status():
    """Render job status and progress tracking"""
    st.header("📊 Job Status & Progress")
    
    # Auto-refresh toggle
    col1, col2, col3 = st.columns([2, 1, 1])
    with col1:
        auto_refresh = st.checkbox("Auto-refresh (3s)", value=st.session_state.auto_refresh)
        st.session_state.auto_refresh = auto_refresh
    
    with col2:
        if st.button("🔄 Refresh Now"):
            st.rerun()
    
    with col3:
        refresh_placeholder = st.empty()
    
    # Get all jobs from server
    jobs_result = st.session_state.api_client.list_jobs()
    
    if jobs_result['success'] and jobs_result['data']['jobs']:
        jobs = jobs_result['data']['jobs']
        
        # Job selector
        job_options = [f"{job['domain']} - {job['job_id'][:8]}... ({job['status']})" for job in jobs]
        
        if jobs:
            selected_idx = st.selectbox(
                "Select Job to Monitor",
                range(len(jobs)),
                format_func=lambda x: job_options[x],
                index=0
            )
            
            selected_job = jobs[selected_idx]
            job_id = selected_job['job_id']
            
            # Get detailed job status
            status_result = st.session_state.api_client.get_job_status(job_id)
            
            if status_result['success']:
                job_data = status_result['data']
                
                # Job overview
                col1, col2, col3, col4 = st.columns(4)
                
                with col1:
                    st.metric("Status", job_data['status'].title())
                
                with col2:
                    if job_data.get('progress'):
                        st.metric("Progress", f"{job_data['progress'].get('percentage', 0)}%")
                
                with col3:
                    if job_data.get('current_module'):
                        st.metric("Current Module", job_data['current_module'].replace('_', ' ').title())
                
                with col4:
                    if job_data.get('running_time_seconds'):
                        st.metric("Running Time", f"{job_data['running_time_seconds']:.1f}s")
                    elif job_data.get('execution_time_seconds'):
                        st.metric("Execution Time", f"{job_data['execution_time_seconds']:.1f}s")
                
                # Progress bar
                if job_data.get('progress'):
                    progress = job_data['progress']
                    progress_percentage = progress.get('percentage', 0)
                    
                    st.progress(progress_percentage / 100)
                    st.caption(f"Completed {progress.get('completed_modules', 0)}/{progress.get('total_modules', 0)} modules")
                
                # Status-specific displays
                if job_data['status'] == 'running':
                    st.info(f"🔄 {job_data.get('message', 'Job is running...')}")
                    
                    # Real-time logs
                    if job_data.get('verbose_logs'):
                        st.subheader("📝 Recent Logs")
                        for log in job_data['verbose_logs'][-MAX_LOG_LINES:]:
                            st.code(log, language=None)
                
                elif job_data['status'] == 'completed':
                    st.success("✅ Job completed successfully!")
                    
                    # Display results
                    if job_data.get('results'):
                        render_job_results(job_data['results'])
                
                elif job_data['status'] == 'failed':
                    st.error(f"❌ Job failed: {job_data.get('error', 'Unknown error')}")
                
                elif job_data['status'] == 'pending':
                    st.info("⏳ Job is waiting to start...")
                
            else:
                st.error(f"Failed to get job status: {status_result['error']}")
    
    else:
        st.info("No jobs found. Submit a new scan to get started!")
    
    # Auto-refresh implementation
    if st.session_state.auto_refresh:
        with refresh_placeholder:
            for i in range(REFRESH_INTERVAL, 0, -1):
                st.caption(f"Auto-refreshing in {i}s...")
                time.sleep(1)
        st.rerun()


def render_job_results(results: Dict[str, Any]):
    """Render detailed job results with visualizations"""
    st.header("📈 Scan Results")
    
    # Summary metrics
    summary = results.get('summary', {})
    
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total Subdomains", summary.get('total_subdomains', 0))
    with col2:
        st.metric("Open Ports", summary.get('total_open_ports', 0))
    with col3:
        st.metric("Technologies", summary.get('technologies_detected', 0))
    with col4:
        st.metric("APIs Found", summary.get('apis_discovered', 0))
    
    # Module results tabs
    modules = results.get('modules', {})
    
    if modules:
        tab_names = []
        tab_data = []
        
        for module_name, module_data in modules.items():
            tab_names.append(module_name.replace('_', ' ').title())
            tab_data.append((module_name, module_data))
        
        tabs = st.tabs(tab_names)
        
        for i, (module_name, module_data) in enumerate(tab_data):
            with tabs[i]:
                render_module_results(module_name, module_data)
    
    # Export options
    st.subheader("📥 Export Results")
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("📋 Copy JSON"):
            st.code(json.dumps(results, indent=2), language='json')
    
    with col2:
        # Prepare CSV data
        csv_data = prepare_csv_data(results)
        if csv_data:
            st.download_button(
                "📊 Download CSV",
                data=csv_data,
                file_name=f"scan_results_{results.get('target_domain', 'domain')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )


def render_module_results(module_name: str, module_data: Dict[str, Any]):
    """Render results for a specific module"""
    
    if module_name == 'domain_enumeration':
        # Subdomains found
        subdomains = module_data.get('all_subdomains', [])
        if subdomains:
            st.subheader(f"🔍 Discovered Subdomains ({len(subdomains)})")
            
            # Create DataFrame for better display
            df = pd.DataFrame(subdomains, columns=['Subdomain'])
            st.dataframe(df, use_container_width=True)
            
            # Subdomain distribution chart
            if len(subdomains) > 1:
                subdomain_types = [s.split('.')[0] for s in subdomains if '.' in s]
                type_counts = pd.Series(subdomain_types).value_counts()
                
                fig = px.pie(values=type_counts.values, names=type_counts.index, 
                           title="Subdomain Type Distribution")
                st.plotly_chart(fig, use_container_width=True)
        
        # Module statistics
        stats = module_data.get('statistics', {})
        if stats:
            st.subheader("📊 Statistics")
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.metric("Modules Executed", stats.get('modules_executed', 0))
            with col2:
                st.metric("Total Execution Time", f"{stats.get('total_execution_time', 0):.2f}s")
            with col3:
                st.metric("Modules Failed", stats.get('modules_failed', 0))
    
    elif module_name == 'service_discovery':
        if module_data.get('success'):
            services = module_data.get('service_results', {}).get('services', {})
            
            if services:
                st.subheader(f"🎯 Open Ports & Services ({len(services)})")
                
                # Create services DataFrame
                service_list = []
                for port, service_info in services.items():
                    service_list.append({
                        'Port': port,
                        'Service': service_info.get('service', 'Unknown'),
                        'Banner': service_info.get('banner', 'No banner')[:50] + '...' if len(service_info.get('banner', '')) > 50 else service_info.get('banner', 'No banner'),
                        'Confidence': service_info.get('confidence', 'Unknown')
                    })
                
                df = pd.DataFrame(service_list)
                st.dataframe(df, use_container_width=True)
                
                # Port distribution chart
                port_numbers = [int(p) for p in services.keys() if p.isdigit()]
                if port_numbers:
                    fig = go.Figure(data=go.Scatter(x=port_numbers, y=[1]*len(port_numbers), mode='markers', marker=dict(size=10)))
                    fig.update_layout(title="Open Ports Distribution", xaxis_title="Port Number", yaxis_title="", showlegend=False)
                    st.plotly_chart(fig, use_container_width=True)
        else:
            st.error(f"Service discovery failed: {module_data.get('error', 'Unknown error')}")
    
    elif module_name == 'web_analysis':
        if module_data.get('success'):
            # CDN Detection
            cdn_info = module_data.get('cdn_detection', {})
            if cdn_info:
                st.subheader("🌐 CDN Detection")
                col1, col2 = st.columns(2)
                
                with col1:
                    st.metric("CDN Detected", "Yes" if cdn_info.get('cdn_detected') else "No")
                
                with col2:
                    if cdn_info.get('cdn_detected'):
                        st.metric("CDN Provider", cdn_info.get('cdn_name', 'Unknown'))
            
            # API Discovery
            web_crawl = module_data.get('web_crawl', {})
            if web_crawl:
                apis = web_crawl.get('apis', [])
                if apis:
                    st.subheader(f"🔗 API Endpoints ({len(apis)})")
                    
                    api_df = pd.DataFrame(apis, columns=['API Endpoint'])
                    st.dataframe(api_df, use_container_width=True)
                
                # Pages crawled
                pages = web_crawl.get('pages', [])
                if pages:
                    st.subheader(f"📄 Crawled Pages ({len(pages)})")
                    with st.expander("View crawled pages"):
                        for page in pages[:10]:  # Show first 10
                            st.text(page)
                        if len(pages) > 10:
                            st.caption(f"... and {len(pages) - 10} more pages")
        else:
            st.error(f"Web analysis failed: {module_data.get('error', 'Unknown error')}")


def prepare_csv_data(results: Dict[str, Any]) -> str:
    """Prepare results data for CSV export"""
    rows = []
    
    # Add summary row
    summary = results.get('summary', {})
    rows.append([
        "Summary",
        results.get('target_domain', ''),
        summary.get('total_subdomains', 0),
        summary.get('total_open_ports', 0),
        summary.get('technologies_detected', 0),
        summary.get('apis_discovered', 0)
    ])
    
    # Add subdomain rows
    modules = results.get('modules', {})
    if 'domain_enumeration' in modules:
        subdomains = modules['domain_enumeration'].get('all_subdomains', [])
        for subdomain in subdomains:
            rows.append(["Subdomain", subdomain, "", "", "", ""])
    
    # Add service rows
    if 'service_discovery' in modules:
        services = modules['service_discovery'].get('service_results', {}).get('services', {})
        for port, service_info in services.items():
            rows.append([
                "Service",
                f"Port {port}",
                service_info.get('service', ''),
                service_info.get('banner', ''),
                service_info.get('confidence', ''),
                ""
            ])
    
    # Convert to CSV
    import io
    output = io.StringIO()
    import csv
    writer = csv.writer(output)
    writer.writerow(["Type", "Value", "Service", "Banner", "Confidence", "Extra"])
    writer.writerows(rows)
    
    return output.getvalue()


def render_job_history():
    """Render job history and management"""
    st.header("📚 Job History")
    
    # Get all jobs
    jobs_result = st.session_state.api_client.list_jobs()
    
    if jobs_result['success'] and jobs_result['data']['jobs']:
        jobs = jobs_result['data']['jobs']
        
        # Create DataFrame for job history
        job_list = []
        for job in jobs:
            job_list.append({
                'Job ID': job['job_id'][:12] + '...',
                'Domain': job['domain'],
                'Status': job['status'].title(),
                'Created': datetime.fromisoformat(job['created_at']).strftime('%Y-%m-%d %H:%M'),
                'Started': datetime.fromisoformat(job['started_at']).strftime('%Y-%m-%d %H:%M') if job['started_at'] else 'Not started',
                'Completed': datetime.fromisoformat(job['completed_at']).strftime('%Y-%m-%d %H:%M') if job['completed_at'] else 'Not completed',
                'Full ID': job['job_id']
            })
        
        df = pd.DataFrame(job_list)
        
        # Display with selection
        selected_rows = st.dataframe(
            df.drop('Full ID', axis=1),
            use_container_width=True,
            on_select="rerun",
            selection_mode="single-row"
        )
        
        # Job actions
        if selected_rows['selection']['rows']:
            selected_idx = selected_rows['selection']['rows'][0]
            selected_job_id = df.iloc[selected_idx]['Full ID']
            
            col1, col2, col3 = st.columns(3)
            
            with col1:
                if st.button("📊 View Details"):
                    st.session_state.selected_job_id = selected_job_id
                    st.rerun()
            
            with col2:
                if st.button("🔄 Refresh Status"):
                    status_result = st.session_state.api_client.get_job_status(selected_job_id)
                    if status_result['success']:
                        st.success("Status refreshed!")
                    else:
                        st.error(f"Failed to refresh: {status_result['error']}")
            
            with col3:
                if st.button("📋 Copy Job ID"):
                    st.code(selected_job_id)
        
        # Job statistics
        st.subheader("📈 Statistics")
        
        # Status distribution
        status_counts = df['Status'].value_counts()
        col1, col2 = st.columns(2)
        
        with col1:
            fig = px.pie(values=status_counts.values, names=status_counts.index, title="Job Status Distribution")
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # Jobs over time
            df['Date'] = pd.to_datetime(df['Created']).dt.date
            daily_counts = df.groupby('Date').size().reset_index(name='Count')
            
            fig = px.line(daily_counts, x='Date', y='Count', title="Jobs Created Over Time")
            st.plotly_chart(fig, use_container_width=True)
    
    else:
        st.info("No job history available.")


def main():
    """Main Streamlit application"""
    initialize_session_state()
    
    # Render header
    render_header()
    
    # Main navigation
    tab1, tab2, tab3 = st.tabs(["🚀 New Scan", "📊 Monitor Jobs", "📚 Job History"])
    
    with tab1:
        render_scan_form()
    
    with tab2:
        render_job_status()
    
    with tab3:
        render_job_history()
    
    # Footer
    st.markdown("---")
    st.markdown(
        """
        <div style='text-align: center; color: #666;'>
            <p>🔍 Web Domain Scanner | Built with Streamlit & Flask | 
            <a href='https://github.com/SahanWeerasiri/web-domain-scanner' target='_blank'>GitHub</a></p>
        </div>
        """, 
        unsafe_allow_html=True
    )


if __name__ == "__main__":
    main()