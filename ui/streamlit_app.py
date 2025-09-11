import streamlit as st
import requests
import time
import json
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
import base64

# Configuration
API_BASE_URL = "http://localhost:8000"

# Page configuration
st.set_page_config(
    page_title="Web Domain Scanner",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        text-align: center;
        color: #1f77b4;
        font-size: 3rem;
        font-weight: bold;
        margin-bottom: 2rem;
    }
    .scan-card {
        background-color: #f0f2f6;
        padding: 1.5rem;
        border-radius: 10px;
        border-left: 5px solid #1f77b4;
        margin: 1rem 0;
    }
    .metric-card {
        background-color: #ffffff;
        padding: 1rem;
        border-radius: 8px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        text-align: center;
        margin: 0.5rem;
    }
    .status-running {
        color: #ff6b35;
        font-weight: bold;
    }
    .status-completed {
        color: #28a745;
        font-weight: bold;
    }
    .status-error {
        color: #dc3545;
        font-weight: bold;
    }
    .status-pending {
        color: #ffc107;
        font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)

def get_status_color(status):
    colors = {
        'pending': '#ffc107',
        'running': '#ff6b35', 
        'completed': '#28a745',
        'error': '#dc3545'
    }
    return colors.get(status, '#6c757d')

def format_results_data(results):
    """Format the results data for display"""
    if not results:
        return {}
    
    formatted = {}
    
    # Subdomains
    if 'subdomains' in results:
        subdomains = results['subdomains']
        if isinstance(subdomains, list):
            formatted['subdomains'] = subdomains
        else:
            formatted['subdomains'] = []
    
    # DNS Records
    if 'dns_records' in results:
        formatted['dns_records'] = results['dns_records']
    
    # Services
    if 'services' in results:
        services = results['services']
        if isinstance(services, dict) and 'open_ports' in services:
            formatted['services'] = services['open_ports']
        else:
            formatted['services'] = services or {}
    
    # Web crawl results
    if 'web_crawl' in results:
        web_crawl = results['web_crawl']
        formatted['web_crawl'] = web_crawl
        
        if isinstance(web_crawl, dict):
            # Directory bruteforce results
            if 'directory_bruteforce' in web_crawl:
                formatted['directories'] = web_crawl['directory_bruteforce']
            
            # Fingerprinting results
            if 'fingerprinting' in web_crawl:
                formatted['web_fingerprinting'] = web_crawl['fingerprinting']
            
            # API discovery results
            if 'api_discovery' in web_crawl:
                formatted['api_endpoints'] = web_crawl['api_discovery']
            
            # Web crawling results
            if 'crawl' in web_crawl:
                formatted['crawl_results'] = web_crawl['crawl']
    
    # Cloud services
    if 'cloud_services' in results:
        formatted['cloud_services'] = results['cloud_services']
    
    # Target specific terms (for endpoint discovery)
    if 'target_specific_terms' in results:
        formatted['target_specific_terms'] = results['target_specific_terms']
    
    return formatted

def start_scan(domain, gemini_key=None):
    """Start a new scan"""
    try:
        params = {'domain': domain}
        if gemini_key:
            params['gemini_key'] = gemini_key
            
        response = requests.get(f"{API_BASE_URL}/api/data", params=params)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        st.error(f"Failed to start scan: {e}")
        return None

def get_scan_status(request_id):
    """Get the status of a scan"""
    try:
        response = requests.get(f"{API_BASE_URL}/api/status/{request_id}")
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        st.error(f"Failed to get status: {e}")
        return None

def display_progress_bar(progress, status, message):
    """Display a custom progress bar"""
    progress_normalized = progress / 100.0
    color = get_status_color(status)
    
    st.markdown(f"""
    <div style="background-color: #e9ecef; border-radius: 10px; padding: 5px;">
        <div style="background-color: {color}; width: {progress}%; height: 20px; border-radius: 5px; transition: width 0.3s;"></div>
    </div>
    <p style="text-align: center; margin-top: 10px; font-weight: bold;">{message} - {progress:.1f}%</p>
    """, unsafe_allow_html=True)

def display_metrics(found_data):
    """Display metrics in cards"""
    col1, col2, col3, col4, col5 = st.columns(5)
    
    with col1:
        subdomains_count = found_data.get('subdomains', 0)
        st.metric("Subdomains", subdomains_count, delta=None)
    
    with col2:
        services_count = found_data.get('services', 0)
        st.metric("Open Ports", services_count, delta=None)
    
    with col3:
        dns_count = found_data.get('dns_records', 0)
        st.metric("DNS Records", dns_count, delta=None)
    
    with col4:
        # Count directories from web crawl results
        directories_count = 0
        if 'directories' in found_data or 'web_crawl' in found_data:
            directories_count = found_data.get('directories', 0)
        st.metric("Directories", directories_count, delta=None)
    
    with col5:
        # Count API endpoints
        api_count = 0
        if 'api_endpoints' in found_data:
            api_data = found_data.get('api_endpoints', {})
            if isinstance(api_data, dict):
                for category in api_data.values():
                    if isinstance(category, list):
                        api_count += len(category)
        st.metric("API Endpoints", api_count, delta=None)

def display_subdomains_chart(subdomains):
    """Display subdomains in a chart"""
    if not subdomains:
        st.info("No subdomains found")
        return
    
    # Create a simple chart showing subdomain count
    subdomain_df = pd.DataFrame({
        'Subdomain': subdomains,
        'Status': ['Active'] * len(subdomains)
    })
    
    fig = px.bar(
        subdomain_df, 
        x='Subdomain', 
        title=f"Discovered Subdomains ({len(subdomains)} total)",
        color_discrete_sequence=['#1f77b4']
    )
    fig.update_layout(xaxis_tickangle=-45)
    st.plotly_chart(fig, use_container_width=True)

def display_services_chart(services):
    """Display open ports/services in a chart"""
    if not services:
        st.info("No open ports found")
        return
    
    # Convert services dict to DataFrame
    services_data = []
    for port, info in services.items():
        if isinstance(info, dict):
            service_name = info.get('service', 'Unknown')
            banner = info.get('banner', 'No banner')
        else:
            service_name = str(info)
            banner = 'No banner'
        
        services_data.append({
            'Port': int(port),
            'Service': service_name,
            'Banner': banner[:50] + '...' if len(banner) > 50 else banner
        })
    
    services_df = pd.DataFrame(services_data)
    
    # Create a horizontal bar chart
    fig = px.bar(
        services_df, 
        x='Port', 
        y='Service',
        title=f"Open Ports and Services ({len(services)} total)",
        orientation='h',
        color_discrete_sequence=['#ff7f0e']
    )
    st.plotly_chart(fig, use_container_width=True)
    
    # Display detailed table
    st.subheader("Detailed Service Information")
    st.dataframe(services_df, use_container_width=True)

def display_dns_records(dns_records):
    """Display DNS records"""
    if not dns_records:
        st.info("No DNS records found")
        return
    
    st.subheader("DNS Records")
    
    dns_data = []
    for record_type, records in dns_records.items():
        if isinstance(records, list):
            for record in records:
                dns_data.append({
                    'Type': record_type,
                    'Value': record
                })
        else:
            dns_data.append({
                'Type': record_type,
                'Value': str(records)
            })
    
    if dns_data:
        dns_df = pd.DataFrame(dns_data)
        st.dataframe(dns_df, use_container_width=True)
        
        # Chart showing DNS record types
        type_counts = dns_df['Type'].value_counts()
        fig = px.pie(
            values=type_counts.values,
            names=type_counts.index,
            title="DNS Record Types Distribution"
        )
        st.plotly_chart(fig, use_container_width=True)

def display_directory_bruteforce(directories):
    """Display directory bruteforce results"""
    if not directories:
        st.info("No directories found")
        return
    
    st.subheader("Directory Bruteforce Results")
    
    dir_data = []
    for directory in directories:
        if isinstance(directory, dict):
            dir_data.append({
                'URL': directory.get('url', ''),
                'Status Code': directory.get('status', ''),
                'Size (bytes)': directory.get('size', 0),
                'Content Type': directory.get('content_type', '')
            })
    
    if dir_data:
        dir_df = pd.DataFrame(dir_data)
        st.dataframe(dir_df, use_container_width=True)
        
        # Chart showing status codes
        status_counts = dir_df['Status Code'].value_counts()
        fig = px.bar(
            x=status_counts.values,
            y=status_counts.index,
            orientation='h',
            title="HTTP Status Codes Distribution",
            labels={'x': 'Count', 'y': 'Status Code'}
        )
        st.plotly_chart(fig, use_container_width=True)

def display_crawl_results(crawl_results):
    """Display web crawling results"""
    if not crawl_results:
        st.info("No crawl results found")
        return
    
    st.subheader("Web Crawling Results")
    
    if 'pages' in crawl_results:
        pages = crawl_results['pages']
        
        # Summary
        st.write(f"**Total Pages Crawled:** {len(pages)}")
        
        # Page details
        for i, page in enumerate(pages):
            with st.expander(f"Page {i+1}: {page.get('url', 'Unknown URL')}"):
                if 'content' in page:
                    content = page['content']
                    
                    col1, col2 = st.columns(2)
                    with col1:
                        st.write(f"**Title:** {content.get('title', 'No title')}")
                        st.write(f"**Links Found:** {len(content.get('links', []))}")
                        st.write(f"**Forms Found:** {len(content.get('forms', []))}")
                    
                    with col2:
                        st.write(f"**JS Files:** {len(content.get('javascript_files', []))}")
                        st.write(f"**API References:** {len(content.get('api_references', []))}")
                        st.write(f"**Potential Endpoints:** {len(content.get('potential_endpoints', []))}")
                    
                    # Show some content
                    if content.get('text_content'):
                        st.write("**Page Content Preview:**")
                        preview = content['text_content'][:500] + "..." if len(content['text_content']) > 500 else content['text_content']
                        st.text(preview)
                    
                    # Show links
                    if content.get('links'):
                        st.write("**Links Found:**")
                        links_df = pd.DataFrame({'Links': content['links'][:20]})  # Show first 20
                        st.dataframe(links_df, use_container_width=True)
                        if len(content['links']) > 20:
                            st.write(f"... and {len(content['links']) - 20} more links")

def display_api_discovery(api_discovery):
    """Display API discovery results"""
    if not api_discovery:
        st.info("No API endpoints discovered")
        return
    
    st.subheader("API Discovery Results")
    
    # GraphQL endpoints
    if 'graphql' in api_discovery and api_discovery['graphql']:
        st.write("**GraphQL Endpoints:**")
        graphql_df = pd.DataFrame(api_discovery['graphql'])
        st.dataframe(graphql_df, use_container_width=True)
    
    # Swagger/OpenAPI endpoints
    if 'swagger' in api_discovery and api_discovery['swagger']:
        st.write("**Swagger/OpenAPI Endpoints:**")
        swagger_df = pd.DataFrame(api_discovery['swagger'])
        st.dataframe(swagger_df, use_container_width=True)
    
    # REST APIs
    if 'rest_apis' in api_discovery and api_discovery['rest_apis']:
        st.write("**REST API Endpoints:**")
        rest_data = []
        for api in api_discovery['rest_apis']:
            if isinstance(api, dict):
                rest_data.append({
                    'URL': api.get('url', ''),
                    'Status Code': api.get('status', ''),
                    'Content Type': api.get('content_type', ''),
                    'Size (bytes)': api.get('size', 0),
                    'Response Time (s)': api.get('response_time', 0),
                    'Supported Methods': ', '.join(api.get('supported_methods', []))
                })
        
        if rest_data:
            rest_df = pd.DataFrame(rest_data)
            st.dataframe(rest_df, use_container_width=True)
    
    # Other endpoints
    if 'other_endpoints' in api_discovery and api_discovery['other_endpoints']:
        st.write("**Other Endpoints:**")
        other_df = pd.DataFrame(api_discovery['other_endpoints'])
        st.dataframe(other_df, use_container_width=True)

def display_web_technologies(web_tech):
    """Display web technologies"""
    if not web_tech:
        st.info("No web technologies detected")
        return
    
    st.subheader("Web Technology Fingerprinting")
    
    tech_data = []
    for url, tech_info in web_tech.items():
        if isinstance(tech_info, dict):
            headers = tech_info.get('headers', {})
            tech_data.append({
                'URL': url,
                'Server': tech_info.get('server', 'Unknown'),
                'X-Powered-By': tech_info.get('x_powered_by', 'Not found'),
                'Status Code': tech_info.get('status_code', 'Unknown'),
                'Content Type': tech_info.get('content_type', 'Unknown'),
                'Security Headers': len([h for h in headers.keys() if 'security' in h.lower() or 'x-' in h.lower()])
            })
    
    if tech_data:
        tech_df = pd.DataFrame(tech_data)
        st.dataframe(tech_df, use_container_width=True)
        
        # Chart showing server distribution
        server_counts = tech_df['Server'].value_counts()
        if len(server_counts) > 0:
            fig = px.pie(
                values=server_counts.values,
                names=server_counts.index,
                title="Web Server Distribution"
            )
            st.plotly_chart(fig, use_container_width=True)

def display_api_endpoints(api_endpoints):
    """Display discovered API endpoints - wrapper for API discovery"""
    if not api_endpoints:
        st.info("No API endpoints found")
        return
    
    display_api_discovery(api_endpoints)

def display_cloud_services(cloud_services):
    """Display cloud services information"""
    if not cloud_services:
        st.info("No cloud services detected")
        return
    
    st.subheader("Cloud Services & CDN Detection")
    
    # Display different cloud service categories
    for service_type, service_data in cloud_services.items():
        if service_data:
            st.write(f"**{service_type.replace('_', ' ').title()}:**")
            if isinstance(service_data, list):
                for item in service_data:
                    st.write(f"- {item}")
            elif isinstance(service_data, dict):
                st.json(service_data)
            else:
                st.write(f"- {service_data}")
        
        # Special handling for web content
        if service_type == 'web_content_direct' and service_data:
            with st.expander("View Web Content Sample"):
                # Show first 1000 chars of web content
                content_preview = str(service_data)[:1000] + "..." if len(str(service_data)) > 1000 else str(service_data)
                st.text(content_preview)

def display_target_terms(target_terms):
    """Display target-specific terms found"""
    if not target_terms:
        st.info("No target-specific terms found")
        return
    
    st.subheader("Target-Specific Terms Discovery")
    
    if isinstance(target_terms, list):
        # Group terms by categories for better display
        terms_df = pd.DataFrame({
            'Term': target_terms,
            'Category': ['Endpoint/Directory'] * len(target_terms)
        })
        
        st.dataframe(terms_df, use_container_width=True)
        
        # Word cloud style visualization
        if len(target_terms) > 0:
            term_counts = pd.Series(target_terms).value_counts()
            fig = px.bar(
                x=term_counts.values[:20],  # Top 20
                y=term_counts.index[:20],
                orientation='h',
                title="Most Common Target Terms",
                labels={'x': 'Frequency', 'y': 'Terms'}
            )
            st.plotly_chart(fig, use_container_width=True)

def main():
    # Header
    st.markdown('<h1 class="main-header">🔍 Web Domain Scanner</h1>', unsafe_allow_html=True)
    st.markdown("Comprehensive reconnaissance tool for web domains")
    
    # Sidebar
    st.sidebar.header("🛠️ Scan Configuration")
    
    # Domain input
    domain = st.sidebar.text_input(
        "Enter Domain", 
        placeholder="example.com",
        help="Enter the domain you want to scan (without http/https)"
    )
    
    # API key input
    gemini_key = st.sidebar.text_input(
        "Gemini API Key (Optional)", 
        type="password",
        help="Enter your Google Gemini API key for enhanced endpoint discovery"
    )
    
    # Start scan button
    start_scan_btn = st.sidebar.button("🚀 Start Scan", type="primary", use_container_width=True)
    
    # Initialize session state
    if 'current_scan' not in st.session_state:
        st.session_state.current_scan = None
    if 'scan_history' not in st.session_state:
        st.session_state.scan_history = []
    
    # Handle scan start
    if start_scan_btn and domain:
        if domain.startswith(('http://', 'https://')):
            st.sidebar.error("Please enter domain without http/https prefix")
        else:
            result = start_scan(domain, gemini_key if gemini_key else None)
            if result:
                st.session_state.current_scan = {
                    'request_id': result['request_id'],
                    'domain': domain,
                    'start_time': datetime.now()
                }
                st.sidebar.success(f"Scan started! Request ID: {result['request_id'][:8]}...")
                st.rerun()
    
    # Display current scan status
    if st.session_state.current_scan:
        request_id = st.session_state.current_scan['request_id']
        domain = st.session_state.current_scan['domain']
        
        st.markdown(f'<div class="scan-card">', unsafe_allow_html=True)
        st.subheader(f"🎯 Scanning: {domain}")
        
        # Get current status
        status_data = get_scan_status(request_id)
        
        if status_data:
            # Display progress
            display_progress_bar(
                status_data['progress'], 
                status_data['state'], 
                status_data['message']
            )
            
            # Display metrics
            if status_data['found']:
                st.subheader("📊 Live Metrics")
                display_metrics(status_data['found'])
            
            # Display status info
            col1, col2, col3 = st.columns(3)
            with col1:
                status_class = f"status-{status_data['state']}"
                st.markdown(f'<p class="{status_class}">Status: {status_data["state"].upper()}</p>', unsafe_allow_html=True)
            with col2:
                st.write(f"**Progress:** {status_data['progress']:.1f}%")
            with col3:
                st.write(f"**Request ID:** {request_id[:12]}...")
            
            # If scan is completed, display results
            if status_data['state'] == 'completed' and status_data['result']:
                st.success("🎉 Scan completed successfully!")
                
                # Add to history
                if request_id not in [scan.get('request_id') for scan in st.session_state.scan_history]:
                    st.session_state.scan_history.append({
                        'request_id': request_id,
                        'domain': domain,
                        'completion_time': datetime.now(),
                        'results': status_data['result']
                    })
                
                # Display scan summary
                results = format_results_data(status_data['result'])
                
                # Comprehensive Summary Section
                st.subheader("📊 Scan Summary")
                
                # Key metrics in columns
                col1, col2, col3, col4, col5 = st.columns(5)
                with col1:
                    subdomain_count = len(results.get('subdomains', []))
                    st.metric("🌐 Subdomains", subdomain_count)
                with col2:
                    dns_count = len(results.get('dns_records', {}))
                    st.metric("📋 DNS Records", dns_count)
                with col3:
                    service_count = len(results.get('services', {}))
                    st.metric("🔌 Open Ports", service_count)
                with col4:
                    dir_count = len(results.get('directories', []))
                    st.metric("📁 Directories", dir_count)
                with col5:
                    # Count total API endpoints
                    api_count = 0
                    if 'web_crawl' in results and 'api_discovery' in results['web_crawl']:
                        api_data = results['web_crawl']['api_discovery']
                        for category in ['graphql', 'swagger', 'rest_apis', 'other_endpoints']:
                            if category in api_data:
                                api_count += len(api_data[category])
                    st.metric("🔗 API Endpoints", api_count)
                
                # Scan statistics
                if 'services' in status_data['result'] and 'scan_duration' in status_data['result']['services']:
                    scan_duration = status_data['result']['services']['scan_duration']
                    st.write(f"**⏱️ Total Scan Duration:** {scan_duration:.2f} seconds")
                
                # Key findings highlight
                st.subheader("🔍 Key Findings")
                findings_col1, findings_col2 = st.columns(2)
                
                with findings_col1:
                    # High-value findings
                    findings = []
                    if subdomain_count > 0:
                        findings.append(f"✅ Found {subdomain_count} subdomains")
                    if service_count > 0:
                        findings.append(f"✅ Discovered {service_count} open ports/services")
                    if dir_count > 0:
                        findings.append(f"✅ Located {dir_count} accessible directories")
                    if api_count > 0:
                        findings.append(f"✅ Identified {api_count} API endpoints")
                    
                    for finding in findings:
                        st.write(finding)
                
                with findings_col2:
                    # Security-relevant information
                    security_info = []
                    
                    # Check for common security-related directories/endpoints
                    if 'directories' in results:
                        security_dirs = [d for d in results['directories'] if 
                                       any(term in str(d).lower() for term in ['admin', 'login', 'auth', 'config', 'debug'])]
                        if security_dirs:
                            security_info.append(f"⚠️ Found {len(security_dirs)} security-relevant directories")
                    
                    # Check for technologies
                    if 'web_crawl' in results and 'fingerprinting' in results['web_crawl']:
                        tech_count = len(results['web_crawl']['fingerprinting'])
                        if tech_count > 0:
                            security_info.append(f"🔧 Identified {tech_count} web technologies")
                    
                    # Check for cloud services
                    if 'cloud_services' in results and results['cloud_services']:
                        cloud_count = len([k for k, v in results['cloud_services'].items() if v])
                        if cloud_count > 0:
                            security_info.append(f"☁️ Detected {cloud_count} cloud service indicators")
                    
                    for info in security_info:
                        st.write(info)
                
                st.markdown("---")
                
                # Display detailed results in tabs
                results = format_results_data(status_data['result'])
                
                # Create tabs for different result categories
                tab1, tab2, tab3, tab4, tab5, tab6, tab7, tab8, tab9 = st.tabs([
                    "📍 Subdomains", 
                    "🌐 DNS Records",
                    "🔌 Services", 
                    "🕷️ Web Crawl", 
                    "📁 Directories",
                    "🔗 API Discovery", 
                    "🎯 Target Terms",
                    "☁️ Cloud Services",
                    "📄 Raw Data"
                ])
                
                with tab1:
                    if 'subdomains' in results:
                        display_subdomains_chart(results['subdomains'])
                        
                        if results['subdomains']:
                            st.subheader("Subdomain List")
                            subdomain_df = pd.DataFrame({
                                'Subdomain': results['subdomains'],
                                'Index': range(1, len(results['subdomains']) + 1)
                            })
                            st.dataframe(subdomain_df, use_container_width=True)
                    else:
                        st.info("No subdomains discovered")
                
                with tab2:
                    if 'dns_records' in results:
                        display_dns_records(results['dns_records'])
                    else:
                        st.info("No DNS records found")
                
                with tab3:
                    if 'services' in results:
                        display_services_chart(results['services'])
                    else:
                        st.info("No services discovered")
                
                with tab4:
                    # Web crawl tab - comprehensive crawling results
                    if 'web_crawl' in results:
                        web_crawl = results['web_crawl']
                        
                        # Web fingerprinting
                        if 'fingerprinting' in web_crawl:
                            display_web_technologies(web_crawl['fingerprinting'])
                        
                        # Crawl results
                        if 'crawl' in web_crawl:
                            display_crawl_results(web_crawl['crawl'])
                        
                        # Show discovered URLs summary
                        if 'discovered_urls' in web_crawl:
                            st.subheader("Discovered URLs Summary")
                            st.write(f"**Total URLs discovered:** {len(web_crawl['discovered_urls'])}")
                            
                            if web_crawl['discovered_urls']:
                                urls_df = pd.DataFrame({
                                    'URL': web_crawl['discovered_urls'][:50],  # Show first 50
                                    'Index': range(1, min(51, len(web_crawl['discovered_urls']) + 1))
                                })
                                st.dataframe(urls_df, use_container_width=True)
                                
                                if len(web_crawl['discovered_urls']) > 50:
                                    st.write(f"... and {len(web_crawl['discovered_urls']) - 50} more URLs")
                    else:
                        st.info("No web crawling results")
                
                with tab5:
                    if 'web_crawl' in results and 'directory_bruteforce' in results['web_crawl']:
                        display_directory_bruteforce(results['web_crawl']['directory_bruteforce'])
                    else:
                        st.info("No directory bruteforce results")
                
                with tab6:
                    if 'web_crawl' in results and 'api_discovery' in results['web_crawl']:
                        display_api_discovery(results['web_crawl']['api_discovery'])
                    else:
                        st.info("No API endpoints discovered")
                
                with tab7:
                    if 'target_specific_terms' in results:
                        display_target_terms(results['target_specific_terms'])
                    else:
                        st.info("No target-specific terms found")
                
                with tab8:
                    if 'cloud_services' in results:
                        display_cloud_services(results['cloud_services'])
                    else:
                        st.info("No cloud services detected")
                
                with tab9:
                    st.subheader("Complete Raw Results")
                    st.json(status_data['result'])
                    
                    # Download button for results
                    json_str = json.dumps(status_data['result'], indent=2)
                    st.download_button(
                        label="📥 Download Results (JSON)",
                        data=json_str,
                        file_name=f"scan_results_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                        mime="application/json"
                    )
                
                # Clear current scan button
                if st.button("🆕 Start New Scan"):
                    st.session_state.current_scan = None
                    st.rerun()
            
            elif status_data['state'] == 'error':
                st.error(f"❌ Scan failed: {status_data['message']}")
                if st.button("🆕 Start New Scan"):
                    st.session_state.current_scan = None
                    st.rerun()
            
            elif status_data['state'] in ['pending', 'running']:
                # Auto-refresh every 2 seconds for active scans
                time.sleep(2)
                st.rerun()
        
        st.markdown('</div>', unsafe_allow_html=True)
    
    else:
        # Welcome screen
        st.markdown("""
        ### 👋 Welcome to Web Domain Scanner
        
        This tool performs comprehensive reconnaissance on web domains including:
        
        - 🔍 **Subdomain Discovery** - Find all subdomains
        - 🔌 **Service Discovery** - Scan for open ports and services  
        - 🌐 **Web Technology Fingerprinting** - Identify web technologies
        - 🔗 **API Endpoint Discovery** - Find API endpoints and GraphQL
        - ☁️ **Cloud Service Detection** - Detect CDNs and cloud services
        - 🛡️ **Security Analysis** - Comprehensive security assessment
        
        **To get started:**
        1. Enter a domain in the sidebar
        2. Optionally add your Gemini API key for enhanced discovery
        3. Click "Start Scan"
        4. Watch the real-time progress and results!
        """)
        
        # Display scan history if available
        if st.session_state.scan_history:
            st.subheader("📋 Scan History")
            
            for i, scan in enumerate(reversed(st.session_state.scan_history[-5:])):  # Show last 5
                with st.expander(f"🎯 {scan['domain']} - {scan['completion_time'].strftime('%Y-%m-%d %H:%M:%S')}"):
                    col1, col2 = st.columns(2)
                    with col1:
                        st.write(f"**Domain:** {scan['domain']}")
                        st.write(f"**Completed:** {scan['completion_time'].strftime('%Y-%m-%d %H:%M:%S')}")
                    with col2:
                        results = format_results_data(scan['results'])
                        st.write(f"**Subdomains:** {len(results.get('subdomains', []))}")
                        st.write(f"**Services:** {len(results.get('services', {}))}")
                    
                    if st.button(f"View Results", key=f"view_{i}"):
                        st.session_state.current_scan = {
                            'request_id': scan['request_id'],
                            'domain': scan['domain'],
                            'start_time': scan['completion_time']
                        }
                        st.rerun()

    # Footer
    st.markdown("---")
    st.markdown("*Built with ❤️ using Streamlit and FastAPI*")

if __name__ == "__main__":
    main()
