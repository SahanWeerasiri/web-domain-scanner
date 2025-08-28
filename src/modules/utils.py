import os
import re
import logging
import time
from urllib.parse import urlparse
import json
from bs4 import BeautifulSoup
from typing import List, Dict, Any

def sanitize_domain(domain_or_url):
    """Extract and sanitize domain for filesystem use"""
    if '://' in domain_or_url:
        parsed = urlparse(domain_or_url)
        domain = parsed.netloc
        if domain.startswith('www.'):
            domain = domain[4:]
    else:
        domain = domain_or_url
    
    # Sanitize domain for filesystem use
    sanitized_domain = re.sub(r'[^a-zA-Z0-9-]', '_', domain)
    return domain, sanitized_domain

def create_output_directory(domain, timestamp):
    """Create output directory for results"""
    sanitized_domain = re.sub(r'[^a-zA-Z0-9-]', '_', domain)
    output_dir = f"recon_results_{sanitized_domain}_{timestamp}"
    os.makedirs(output_dir, exist_ok=True)
    return output_dir

def create_web_wordlist(output_dir, common_dirs=None):
    """Create a default web wordlist if none exists"""
    if common_dirs is None:
        common_dirs = [
            'admin', 'login', 'wp-admin', 'wp-login', 
            'api', 'test', 'backup', 'assets', 'images'
        ]
    
    wordlist_path = os.path.join(output_dir, 'web_wordlist.txt')
    if not os.path.exists(wordlist_path):
        with open(wordlist_path, 'w') as f:
            f.write('\n'.join(common_dirs))
    
    return wordlist_path

## HTML table to JSON

def extract_table_data_from_html(html_content: str, domain: str) -> List[Dict[str, Any]]:
    """
    Extract table data from HTML response and convert to JSON.
    
    Args:
        html_content: HTML response content
        domain: Target domain for context
    
    Returns:
        List of dictionaries representing table rows
    """
    try:
        soup = BeautifulSoup(html_content, 'html.parser')
        results = []
        
        # Find all tables with class 'outer' or similar
        tables = soup.find_all('table', class_='outer')
        
        if not tables:
            logging.warning(f"No tables found in HTML response for {domain}")
            return []
        
        for table in tables:
            table_data = _parse_table(table, domain)
            if table_data:
                results.extend(table_data)
        
        return results
        
    except Exception as e:
        logging.error(f"Error parsing HTML table data: {str(e)}")
        return []

def _parse_table(table, domain: str) -> List[Dict[str, Any]]:
    """Parse individual table and extract data"""
    table_data = []
    
    # Get table headers (th elements)
    headers = []
    header_cells = table.find_all('th')
    for cell in header_cells:
        header_text = cell.get_text(strip=True)
        if header_text and header_text not in headers:
            headers.append(header_text.lower().replace(' ', '_'))
    
    # If no headers found, use generic ones
    if not headers:
        headers = ['column_1', 'column_2']
    
    # Get table rows
    rows = table.find_all('tr')
    
    for row in rows:
        # Skip header rows
        if row.find('th'):
            continue
            
        row_data = {}
        cells = row.find_all('td')
        
        for i, cell in enumerate(cells):
            header_name = headers[i] if i < len(headers) else f'column_{i+1}'
            cell_text = cell.get_text(strip=True)
            
            # Skip empty cells or placeholder text
            if not cell_text or cell_text.lower() in ['none found', 'n/a', '-']:
                continue
                
            row_data[header_name] = cell_text
        
        # Only add row if it contains data
        if row_data:
            # Add domain context
            row_data['domain'] = domain
            row_data['source'] = 'crt.sh'
            table_data.append(row_data)
    
    return table_data

def extract_certificate_data(html_content: str, domain: str) -> List[Dict[str, Any]]:
    """
    Specialized function for extracting certificate data from crt.sh
    
    Args:
        html_content: HTML response from crt.sh
        domain: Target domain
    
    Returns:
        List of certificate records
    """
    try:
        soup = BeautifulSoup(html_content, 'html.parser')
        certificates = []

        # Find all tables in the HTML
        tables = soup.find_all('table')
        expected_headers = [
            'crt.sh id', 'logged at', 'not before', 'not after', 'common name', 'matching identities', 'issuer name'
        ]

        results_table = None
        headers = []

        # Find the table with the expected certificate headers
        for table in tables:
            header_row = table.find('tr')
            if not header_row:
                continue
            ths = header_row.find_all('th')
            header_texts = [th.get_text(strip=True).lower() for th in ths]
            # Check if at least 4 of the expected headers are present (robust match)
            match_count = sum(any(eh in ht for ht in header_texts) for eh in expected_headers)
            if match_count >= 4:
                results_table = table
                headers = [th.get_text(strip=True).lower().replace(' ', '_') for th in ths]
                break

        if not results_table:
            logging.info(f"No certificate results found for {domain} in crt.sh")
            return []

        # If no headers found, use common crt.sh column names
        if not headers:
            headers = ['id', 'logged_at', 'not_before', 'not_after', 'common_name', 'matching_identities', 'issuer_name']

        # Extract data rows (skip header row)
        rows = results_table.find_all('tr')[1:]

        for row in rows:
            certificate = {'domain': domain, 'source': 'crt.sh'}
            cells = row.find_all('td')

            for i, cell in enumerate(cells):
                if i < len(headers):
                    header_name = headers[i]
                    cell_text = cell.get_text(strip=True)

                    # Extract links if present
                    links = cell.find_all('a')
                    if links:
                        certificate[f'{header_name}_links'] = [
                            {'text': link.get_text(strip=True), 'href': link.get('href', '')}
                            for link in links
                        ]

                    if cell_text and cell_text not in ['', 'N/A']:
                        certificate[header_name] = cell_text

            # Only add if we found data (at least one header field)
            if any(k in certificate for k in headers):
                certificates.append(certificate)

        return certificates

    except Exception as e:
        logging.error(f"Error extracting certificate data: {str(e)}")
        return []

def html_to_json(html_content: str, domain: str, output_file: str = None) -> str:
    """
    Convert HTML table data to JSON format
    
    Args:
        html_content: HTML response content
        domain: Target domain
        output_file: Optional file path to save JSON
    
    Returns:
        JSON string of extracted data
    """
    # Extract data using both general and specialized methods
    general_data = extract_table_data_from_html(html_content, domain)
    cert_data = extract_certificate_data(html_content, domain)
    
    # Combine results
    all_data = {
        'metadata': {
            'domain': domain,
            'source': 'crt.sh',
            'extraction_timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'general_tables_count': len(general_data),
            'certificate_records_count': len(cert_data)
        },
        'general_tables': general_data,
        'certificate_records': cert_data
    }
    
    # Convert to JSON
    json_output = json.dumps(all_data, indent=2, ensure_ascii=False)
    
    # Save to file if requested
    if output_file:
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(json_output)
            logging.info(f"JSON data saved to {output_file}")
        except Exception as e:
            logging.error(f"Error saving JSON to file: {str(e)}")
    
    return json_output