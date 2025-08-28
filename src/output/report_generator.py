import json
import os
from datetime import datetime
from jinja2 import Template
import logging

class ReportGenerator:
    def __init__(self, results, output_dir, target_domain):
        self.results = results
        self.output_dir = output_dir
        self.target_domain = target_domain
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
    def generate_json_report(self):
        """Generate JSON report"""
        report_path = os.path.join(self.output_dir, 'final_report.json')
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2)
        return report_path
    
    def generate_html_report(self):
        """Generate HTML report using the template, embedding all JSON data for portability"""
        # Prepare data for the template
        template_data = self._prepare_template_data()

        # Load HTML template
        template_path = os.path.join(os.path.dirname(__file__), 'templates', 'html_report.html')

        try:
            with open(template_path, 'r', encoding='utf-8') as f:
                template_content = f.read()
        except FileNotFoundError:
            template_content = self._get_fallback_template()
            logging.warning("HTML template file not found, using fallback template")

        # Embed the full JSON data as a <script> tag for the JS to use
        json_data = json.dumps(self.results, ensure_ascii=False)
        # Replace or inject the reportData variable in the template
        if 'const reportData =' in template_content:
            import re
            template_content = re.sub(
                r'const reportData = [^;]+;',
                f'const reportData = {json_data};',
                template_content
            )
        else:
            # Try to inject at the top of the first <script> tag
            if '<script>' in template_content:
                template_content = template_content.replace(
                    '<script>',
                    f'<script>\nconst reportData = {json_data};\n',
                    1
                )
            elif '</body>' in template_content:
                # If no <script> tag, inject before </body>
                template_content = template_content.replace(
                    '</body>',
                    f'<script>const reportData = {json_data};</script>\n</body>'
                )
            else:
                # As a last resort, append at the end
                template_content += f'\n<script>const reportData = {json_data};</script>'

        # Render template with data (for Jinja2 variables)
        template = Template(template_content)
        html_content = template.render(**template_data)

        # Save HTML report
        html_report_path = os.path.join(self.output_dir, 'recon_report.html')
        with open(html_report_path, 'w', encoding='utf-8') as f:
            f.write(html_content)

        logging.info(f"HTML report generated: {html_report_path}")
        return html_report_path
    
    def _prepare_template_data(self):
        """Prepare data for the HTML template, including all new web-crawler fields"""
        # Legacy fields
        subdomains_obj = self.results.get('subdomains', {})
        if isinstance(subdomains_obj, dict):
            subdomains_count = sum(len(subdomains) for subdomains in subdomains_obj.values())
        elif isinstance(subdomains_obj, list):
            subdomains_count = len(subdomains_obj)
        else:
            subdomains_count = 0
        open_ports_count = len(self.results.get('services', {}).get('open_ports', {}))
        directories_count = len(self.results.get('directories', []))
        api_endpoints_count = len(self.results.get('api_endpoints', []))

        # Prepare subdomain data
        subdomains = self.results.get('subdomains', {})
        if isinstance(subdomains, dict):
            passive_subdomains = subdomains.get('passive', [])
            active_subdomains = subdomains.get('bruteforce', [])
        elif isinstance(subdomains, list):
            passive_subdomains = subdomains
            active_subdomains = []
        else:
            passive_subdomains = []
            active_subdomains = []

        # Prepare services data with better structure
        services_data = {}
        open_ports = self.results.get('services', {}).get('open_ports', {})
        for port, info in open_ports.items():
            services_data[port] = {
                'service': info.get('service', 'Unknown'),
                'banner': info.get('banner', 'No banner')
            }

        # --- Web Crawler Results ---
        web_crawl = self.results.get('web_crawl', {})
        # Web fingerprinting
        fingerprinting = web_crawl.get('fingerprinting', {})
        # Directory bruteforce
        directory_bruteforce = web_crawl.get('directory_bruteforce', [])
        # API discovery
        api_discovery = web_crawl.get('api_discovery', {})
        # Site crawl
        crawl = web_crawl.get('crawl', {})
        crawl_pages = crawl.get('pages', [])
        crawl_apis = crawl.get('apis', [])
        # Target-specific wordlist
        target_specific_terms = web_crawl.get('target_specific_terms', [])

        # For backward compatibility, keep legacy fields, but add all new fields for template
        return {
            'target': self.target_domain,
            'timestamp': self.timestamp,
            'subdomains_count': subdomains_count,
            'open_ports_count': open_ports_count,
            'directories_count': directories_count,
            'api_endpoints_count': api_endpoints_count,
            'subdomains': {
                'passive': passive_subdomains,
                'active': active_subdomains
            },
            'passive_subdomains_count': len(passive_subdomains),
            'active_subdomains_count': len(active_subdomains),
            'services': {
                'open_ports': open_ports,
                'service_versions': services_data
            },
            'web_technologies': self.results.get('web_technologies', {}),
            'directories': self.results.get('directories', []),
            'api_endpoints': self.results.get('api_endpoints', []),
            'cloud_services': self.results.get('cloud_services', {}),
            'dns_records': self.results.get('dns_records', {}),
            # --- Web Crawler fields ---
            'web_crawl': web_crawl,
            'fingerprinting': fingerprinting,
            'directory_bruteforce': directory_bruteforce,
            'api_discovery': api_discovery,
            'crawl': crawl,
            'crawl_pages': crawl_pages,
            'crawl_apis': crawl_apis,
            'target_specific_terms': target_specific_terms,
        }
    
    def _get_fallback_template(self):
        """Return fallback HTML template if file is missing"""
        return """<!DOCTYPE html>
<html lang=\"en\">
<head>
    <meta charset=\"UTF-8\">
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">
    <title>Reconnaissance Report - {{ target }}</title>
    <style>
        :root {
            --primary-color: #3498db;
            --secondary-color: #2c3e50;
            --success-color: #27ae60;
            --warning-color: #f39c12;
            --danger-color: #e74c3c;
            --light-bg: #f8f9fa;
            --dark-bg: #343a40;
            --border-color: #dee2e6;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; background-color: #f4f4f4; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, var(--secondary-color), var(--primary-color)); color: white; padding: 2rem; text-align: center; border-radius: 10px; margin-bottom: 2rem; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); }
        .header h1 { font-size: 2.5rem; margin-bottom: 0.5rem; }
        .header .timestamp { font-size: 0.9rem; opacity: 0.9; }
        .summary-cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 1.5rem; margin-bottom: 2rem; }
        .card { background: white; border-radius: 10px; padding: 1.5rem; box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1); transition: transform 0.3s ease; }
        .card:hover { transform: translateY(-5px); box-shadow: 0 6px 12px rgba(0, 0, 0, 0.15); }
        .card-header { display: flex; align-items: center; margin-bottom: 1rem; }
        .card-icon { font-size: 1.5rem; margin-right: 0.75rem; color: var(--primary-color); }
        .card-title { font-size: 1.2rem; font-weight: 600; color: var(--secondary-color); }
        .card-value { font-size: 2rem; font-weight: bold; color: var(--primary-color); text-align: center; margin: 1rem 0; }
        .card-description { color: #666; font-size: 0.9rem; }
        .section { background: white; border-radius: 10px; padding: 1.5rem; margin-bottom: 2rem; box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1); }
        .section-header { display: flex; align-items: center; margin-bottom: 1.5rem; padding-bottom: 0.75rem; border-bottom: 2px solid var(--light-bg); }
        .section-icon { font-size: 1.5rem; margin-right: 0.75rem; color: var(--primary-color); }
        .section-title { font-size: 1.5rem; font-weight: 600; color: var(--secondary-color); }
        .table { width: 100%; border-collapse: collapse; margin-top: 1rem; }
        .table th, .table td { padding: 0.75rem; text-align: left; border-bottom: 1px solid var(--border-color); }
        .table th { background-color: var(--light-bg); font-weight: 600; color: var(--secondary-color); }
        .table tr:hover { background-color: rgba(52, 152, 219, 0.05); }
        .badge { display: inline-block; padding: 0.25rem 0.5rem; border-radius: 15px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; }
        .badge-success { background-color: var(--success-color); color: white; }
        .badge-warning { background-color: var(--warning-color); color: white; }
        .badge-danger { background-color: var(--danger-color); color: white; }
        .badge-info { background-color: var(--primary-color); color: white; }
        .subdomain-list { list-style: none; }
        .subdomain-item { padding: 0.5rem; margin: 0.25rem 0; background: var(--light-bg); border-radius: 5px; border-left: 4px solid var(--primary-color); }
        .tech-stack { display: flex; flex-wrap: wrap; gap: 0.5rem; }
        .tech-item { background: linear-gradient(135deg, var(--primary-color), #2980b9); color: white; padding: 0.5rem 1rem; border-radius: 20px; font-size: 0.85rem; }
        .footer { text-align: center; padding: 2rem; color: #666; font-size: 0.9rem; margin-top: 2rem; border-top: 1px solid var(--border-color); }
        .risk-level { display: inline-block; padding: 0.5rem 1rem; border-radius: 5px; font-weight: bold; margin-left: 1rem; }
        .risk-low { background-color: var(--success-color); color: white; }
        .risk-medium { background-color: var(--warning-color); color: white; }
        .risk-high { background-color: var(--danger-color); color: white; }
        @media (max-width: 768px) {
            .summary-cards { grid-template-columns: 1fr; }
            .header h1 { font-size: 2rem; }
        }
    </style>
</head>
<body>
    <div class=\"container\">
        <!-- Web Crawler Results Section -->
        <div class="section">
            <div class="section-header">
                <span class="section-icon">🤖</span>
                <h2 class="section-title">Web Crawler Results</h2>
            </div>
            <!-- Web Fingerprinting -->
            <h3>Web Fingerprinting</h3>
            {% if fingerprinting %}
            <table class="table">
                <thead>
                    <tr><th>URL</th><th>Server</th><th>X-Powered-By</th><th>Status</th></tr>
                </thead>
                <tbody>
                {% for url, info in fingerprinting.items() %}
                    <tr>
                        <td>{{ url }}</td>
                        <td>{{ info.server }}</td>
                        <td>{{ info.x_powered_by }}</td>
                        <td>{{ info.status_code }}</td>
                    </tr>
                {% endfor %}
                </tbody>
            </table>
            {% else %}<p>No web fingerprinting data.</p>{% endif %}

            <!-- Directory Bruteforce -->
            <h3 style="margin-top:2rem;">Directory Bruteforce</h3>
            {% if directory_bruteforce %}
            <table class="table">
                <thead><tr><th>URL</th><th>Status</th><th>Size</th></tr></thead>
                <tbody>
                {% for entry in directory_bruteforce %}
                    <tr>
                        <td>{{ entry.url }}</td>
                        <td>{{ entry.status }}</td>
                        <td>{{ entry.size }}</td>
                    </tr>
                {% endfor %}
                </tbody>
            </table>
            {% else %}<p>No directory bruteforce results.</p>{% endif %}

            <!-- API Discovery -->
            <h3 style="margin-top:2rem;">API Discovery</h3>
            {% if api_discovery %}
            {% for category, endpoints in api_discovery.items() %}
                <h4>{{ category|capitalize }}</h4>
                {% if endpoints %}
                <ul>
                    {% for endpoint in endpoints %}
                    <li>{{ endpoint.url }} (Status: {{ endpoint.status }})</li>
                    {% endfor %}
                </ul>
                {% else %}<p>No endpoints found for {{ category }}.</p>{% endif %}
            {% endfor %}
            {% else %}<p>No API discovery results.</p>{% endif %}

            <!-- Site Crawl -->
            <h3 style="margin-top:2rem;">Site Crawl</h3>
            {% if crawl_pages %}
            <ul>
                {% for page in crawl_pages %}
                <li>{{ page.url }}</li>
                {% endfor %}
            </ul>
            {% else %}<p>No crawl pages found.</p>{% endif %}
            {% if crawl_apis %}
            <h4>APIs found during crawl:</h4>
            <ul>
                {% for api in crawl_apis %}
                <li>{{ api }}</li>
                {% endfor %}
            </ul>
            {% endif %}

            <!-- Target-Specific Wordlist -->
            <h3 style="margin-top:2rem;">Target-Specific Wordlist</h3>
            {% if target_specific_terms %}
            <ul>
                {% for term in target_specific_terms %}
                <li>{{ term }}</li>
                {% endfor %}
            </ul>
            {% else %}<p>No target-specific wordlist generated.</p>{% endif %}
        </div>
        <div class="header">
            <h1>🛡️ Web Domain Reconnaissance Report</h1>
            <p class="timestamp">Generated on: {{ timestamp }}</p>
            <p>Target: <strong>{{ target }}</strong></p>
        </div>

        <!-- Summary Cards -->
        <div class="summary-cards">
            <div class="card">
                <div class="card-header">
                    <span class="card-icon">🌐</span>
                    <h3 class="card-title">Subdomains Found</h3>
                </div>
                <div class="card-value">{{ subdomains_count }}</div>
                <p class="card-description">Total discovered subdomains including passive and active enumeration</p>
            </div>

            <div class="card">
                <div class="card-header">
                    <span class="card-icon">🔍</span>
                    <h3 class="card-title">Open Ports</h3>
                </div>
                <div class="card-value">{{ open_ports_count }}</div>
                <p class="card-description">Services exposed to the network</p>
            </div>

            <div class="card">
                <div class="card-header">
                    <span class="card-icon">📁</span>
                    <h3 class="card-title">Directories</h3>
                </div>
                <div class="card-value">{{ directories_count }}</div>
                <p class="card-description">Accessible directories discovered</p>
            </div>

            <div class="card">
                <div class="card-header">
                    <span class="card-icon">🔌</span>
                    <h3 class="card-title">API Endpoints</h3>
                </div>
                <div class="card-value">{{ api_endpoints_count }}</div>
                <p class="card-description">API endpoints and interfaces found</p>
            </div>
        </div>

        <!-- Subdomains Section -->
        <div class="section">
            <div class="section-header">
                <span class="section-icon">🌐</span>
                <h2 class="section-title">Subdomain Discovery</h2>
            </div>

            {% if subdomains.passive %}
            <h3>Passive Enumeration ({{ passive_subdomains_count }})</h3>
            <ul class="subdomain-list">
                {% for subdomain in subdomains.passive %}
                <li class="subdomain-item">{{ subdomain }}</li>
                {% endfor %}
            </ul>
            {% endif %}

            {% if subdomains.active %}
            <h3 style="margin-top: 1.5rem;">Active Enumeration ({{ active_subdomains_count }})</h3>
            <ul class="subdomain-list">
                {% for subdomain in subdomains.active %}
                <li class="subdomain-item">{{ subdomain }}</li>
                {% endfor %}
            </ul>
            {% endif %}

            {% if not subdomains.passive and not subdomains.active %}
            <p>No subdomains discovered.</p>
            {% endif %}
        </div>

        <!-- Service Discovery Section -->
        <div class="section">
            <div class="section-header">
                <span class="section-icon">🔍</span>
                <h2 class="section-title">Service Discovery</h2>
            </div>

            {% if services.open_ports %}
            <h3>Open Ports</h3>
            <table class="table">
                <thead>
                    <tr>
                        <th>Port</th>
                        <th>Service</th>
                        <th>Banner</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    {% for port, info in services.service_versions.items() %}
                    <tr>
                        <td>{{ port }}</td>
                        <td>{{ info.service }}</td>
                        <td>{{ info.banner|truncate(50) }}</td>
                        <td><span class="badge badge-success">OPEN</span></td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            {% else %}
            <p>No open ports found on common services.</p>
            {% endif %}
        </div>

        <!-- Web Technologies Section -->
        <div class="section">
            <div class="section-header">
                <span class="section-icon">🛠️</span>
                <h2 class="section-title">Web Technologies</h2>
            </div>

            {% if web_technologies %}
            <div class="tech-stack">
                {% for url, tech in web_technologies.items() %}
                {% if tech.server and tech.server != 'Not found' %}
                <span class="tech-item">Server: {{ tech.server }}</span>
                {% endif %}
                {% if tech.x_powered_by and tech.x_powered_by != 'Not found' %}
                <span class="tech-item">Powered By: {{ tech.x_powered_by }}</span>
                {% endif %}
                {% endfor %}
            </div>

            <table class="table" style="margin-top: 1.5rem;">
                <thead>
                    <tr>
                        <th>URL</th>
                        <th>Status</th>
                        <th>Server</th>
                        <th>Technology</th>
                    </tr>
                </thead>
                <tbody>
                    {% for url, tech in web_technologies.items() %}
                    <tr>
                        <td>{{ url }}</td>
                        <td>
                            {% if tech.status_code == 200 %}
                            <span class="badge badge-success">{{ tech.status_code }}</span>
                            {% else %}
                            <span class="badge badge-warning">{{ tech.status_code }}</span>
                            {% endif %}
                        </td>
                        <td>{{ tech.server }}</td>
                        <td>{{ tech.x_powered_by }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            {% else %}
            <p>No web technologies information available.</p>
            {% endif %}
        </div>

        <!-- Directory Discovery Section -->
        <div class="section">
            <div class="section-header">
                <span class="section-icon">📁</span>
                <h2 class="section-title">Directory Discovery</h2>
            </div>

            {% if directories %}
            <table class="table">
                <thead>
                    <tr>
                        <th>URL</th>
                        <th>Status</th>
                        <th>Size</th>
                    </tr>
                </thead>
                <tbody>
                    {% for directory in directories %}
                    <tr>
                        <td>{{ directory.url }}</td>
                        <td>
                            {% if directory.status == 200 %}
                            <span class="badge badge-success">{{ directory.status }}</span>
                            {% else %}
                            <span class="badge badge-warning">{{ directory.status }}</span>
                            {% endif %}
                        </td>
                        <td>{{ directory.size }} bytes</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            {% else %}
            <p>No directories discovered.</p>
            {% endif %}
        </div>

        <!-- API Endpoints Section -->
        <div class="section">
            <div class="section-header">
                <span class="section-icon">🔌</span>
                <h2 class="section-title">API Endpoints</h2>
            </div>

            {% if api_endpoints %}
            <table class="table">
                <thead>
                    <tr>
                        <th>Endpoint</th>
                        <th>Status</th>
                        <th>Content Type</th>
                        <th>Source</th>
                    </tr>
                </thead>
                <tbody>
                    {% for endpoint in api_endpoints %}
                    <tr>
                        <td>{{ endpoint.url }}</td>
                        <td>
                            {% if endpoint.status == 200 %}
                            <span class="badge badge-success">{{ endpoint.status }}</span>
                            {% else %}
                            <span class="badge badge-warning">{{ endpoint.status }}</span>
                            {% endif %}
                        </td>
                        <td>{{ endpoint.content_type }}</td>
                        <td>
                            <span class="badge badge-info">{{ endpoint.source }}</span>
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            {% else %}
            <p>No API endpoints discovered.</p>
            {% endif %}
        </div>

        <!-- Cloud Services Section -->
        <div class="section">
            <div class="section-header">
                <span class="section-icon">☁️</span>
                <h2 class="section-title">Cloud Services Detection</h2>
            </div>

            {% if cloud_services %}
            {% if cloud_services.aws_s3 %}
            <h3>AWS S3 Buckets</h3>
            <table class="table">
                <thead>
                    <tr>
                        <th>Bucket URL</th>
                        <th>Status</th>
                        <th>Access</th>
                    </tr>
                </thead>
                <tbody>
                    {% for bucket in cloud_services.aws_s3 %}
                    <tr>
                        <td>{{ bucket.url }}</td>
                        <td>{{ bucket.status }}</td>
                        <td>
                            {% if bucket.public %}
                            <span class="badge badge-danger">PUBLIC</span>
                            {% else %}
                            <span class="badge badge-warning">PRIVATE</span>
                            {% endif %}
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            {% endif %}

            {% if cloud_services.cdn %}
            <h3>Content Delivery Network</h3>
            <p>Detected CDN: <strong>{{ cloud_services.cdn }}</strong></p>
            {% endif %}

            {% if not cloud_services.aws_s3 and not cloud_services.cdn %}
            <p>No cloud services detected.</p>
            {% endif %}
            {% else %}
            <p>No cloud services detected.</p>
            {% endif %}
        </div>

        <!-- DNS Records Section -->
        <div class="section">
            <div class="section-header">
                <span class="section-icon">📝</span>
                <h2 class="section-title">DNS Records</h2>
            </div>

            {% if dns_records %}
            {% for record_type, records in dns_records.items() %}
            {% if records %}
            <h3>{{ record_type }} Records</h3>
            <ul class="subdomain-list">
                {% for record in records %}
                <li class="subdomain-item">{{ record }}</li>
                {% endfor %}
            </ul>
            {% endif %}
            {% endfor %}
            {% else %}
            <p>No DNS records information available.</p>
            {% endif %}
        </div>

        <!-- Security Assessment -->
        <div class="section">
            <div class="section-header">
                <span class="section-icon">⚠️</span>
                <h2 class="section-title">Security Assessment</h2>
            </div>

            <div class="risk-assessment">
                {% set risk_level = 'risk-medium' %}
                {% if open_ports_count > 5 or directories_count > 10 or api_endpoints_count > 5 %}
                {% set risk_level = 'risk-high' %}
                {% elif open_ports_count <= 2 and directories_count <= 3 and api_endpoints_count <= 2 %}
                {% set risk_level = 'risk-low' %}
                {% endif %}

                <h3>Overall Risk Level: <span class="risk-level {{ risk_level }}">
                    {% if risk_level == 'risk-high' %}High
                    {% elif risk_level == 'risk-medium' %}Medium
                    {% else %}Low
                    {% endif %}
                </span></h3>

                <h4 style="margin-top: 1.5rem;">Findings:</h4>
                <ul style="margin-left: 1.5rem; margin-top: 0.5rem;">
                    {% if open_ports_count > 3 %}
                    <li>Multiple services ({{ open_ports_count }}) exposed to the network</li>
                    {% endif %}
                    {% if directories_count > 0 %}
                    <li>{{ directories_count }} sensitive directories accessible</li>
                    {% endif %}
                    {% if api_endpoints_count > 0 %}
                    <li>{{ api_endpoints_count }} API endpoints discovered that may require authentication</li>
                    {% endif %}
                    {% if cloud_services.aws_s3 %}
                    <li>AWS S3 buckets detected (potential data exposure risk)</li>
                    {% endif %}
                </ul>

                <h4 style="margin-top: 1.5rem;">Recommendations:</h4>
                <ul style="margin-left: 1.5rem; margin-top: 0.5rem;">
                    <li>Review exposed services and close unnecessary ports</li>
                    <li>Implement proper access controls for sensitive directories</li>
                    <li>Secure API endpoints with authentication and rate limiting</li>
                    <li>Regularly update and patch all services</li>
                    <li>Conduct regular security assessments and penetration testing</li>
                </ul>
            </div>
        </div>

        <div class="footer">
            <p>Generated by Web Domain Scanner & Service Discovery Module</p>
            <p>This report is for educational and authorized security assessment purposes only.</p>
            <p>© 2025 Security Research Team</p>
        </div>
    </div>

    <script>
        // Simple collapsible functionality
        document.querySelectorAll('.collapsible').forEach(button => {
            button.addEventListener('click', function () {
                this.classList.toggle('active');
                const content = this.nextElementSibling;
                if (content.style.display === 'block') {
                    content.style.display = 'none';
                } else {
                    content.style.display = 'block';
                }
            });
        });
    </script>
</body>
</html>"""
    
    def generate_summary(self):
        """Generate a summary of findings"""
        subdomains_obj = self.results.get('subdomains', {})
        if isinstance(subdomains_obj, dict):
            subdomains_found = sum(len(subdomains) for subdomains in subdomains_obj.values())
        elif isinstance(subdomains_obj, list):
            subdomains_found = len(subdomains_obj)
        else:
            subdomains_found = 0
        summary = {
            'timestamp': datetime.now().isoformat(),
            'domain': self.target_domain,
            'subdomains_found': subdomains_found,
            'open_ports': len(self.results.get('services', {}).get('open_ports', {})),
            'directories_found': len(self.results.get('directories', [])),
            'api_endpoints_found': len(self.results.get('api_endpoints', [])),
            'cloud_services_detected': bool(self.results.get('cloud_services', {}))
        }
        return summary