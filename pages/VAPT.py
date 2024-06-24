import streamlit as st
import socket
import concurrent.futures
import requests
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import ssl
import OpenSSL
import time
import re

# [Previous helper functions remain unchanged: is_valid_url, get_ip_from_url, scan_port, check_http_headers, check_ssl_tls, rate_limited_request]

def scan_ports(ip, start_port, end_port):
    open_ports = []
    total_ports = end_port - start_port + 1
    progress_bar = st.progress(0)
    status_text = st.empty()

    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        future_to_port = {executor.submit(scan_port, ip, port): port for port in range(start_port, end_port + 1)}
        for i, future in enumerate(concurrent.futures.as_completed(future_to_port)):
            result = future.result()
            if result:
                open_ports.append(result)
            # Update progress
            progress = (i + 1) / total_ports
            progress_bar.progress(progress)
            status_text.text(f"Scanned {i + 1}/{total_ports} ports")

    progress_bar.empty()
    status_text.empty()
    return open_ports

def crawl_website(url, max_pages=10):
    visited = set()
    to_visit = [url]
    pages = []

    progress_bar = st.progress(0)
    status_text = st.empty()

    while to_visit and len(pages) < max_pages:
        current_url = to_visit.pop(0)
        if current_url not in visited:
            try:
                response = requests.get(current_url, timeout=5)
                visited.add(current_url)
                pages.append(current_url)

                soup = BeautifulSoup(response.text, 'html.parser')
                for link in soup.find_all('a', href=True):
                    absolute_link = urljoin(current_url, link['href'])
                    if absolute_link.startswith(url) and absolute_link not in visited:
                        to_visit.append(absolute_link)
                
                # Update progress
                progress = len(pages) / max_pages
                progress_bar.progress(progress)
                status_text.text(f"Crawled {len(pages)}/{max_pages} pages")
            except:
                pass

    progress_bar.empty()
    status_text.empty()
    return pages

def check_common_vulnerabilities(url):
    vulnerabilities = []
    try:
        response = requests.get(url, timeout=5)
        
        # Check for SQL Injection vulnerability (very basic check)
        if "SQL syntax" in response.text:
            vulnerabilities.append("Potential SQL Injection vulnerability detected")
        
        # Check for XSS vulnerability (very basic check)
        if "<script>" in response.text:
            vulnerabilities.append("Potential XSS vulnerability detected")
        
        # Check for sensitive information disclosure
        patterns = [
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # email
            r'\b(?:\d{1,3}\.){3}\d{1,3}\b',  # IP address
        ]
        for pattern in patterns:
            if re.search(pattern, response.text):
                vulnerabilities.append(f"Potential sensitive information disclosure: {pattern}")
        
    except:
        pass
    return vulnerabilities

def main():
    st.title("Advanced Web Vulnerability Assessment Tool")
    
    target_url = st.text_input("Enter target URL (include http:// or https://):")
    
    if not is_valid_url(target_url):
        st.error("Please enter a valid URL (e.g., https://example.com)")
        return

    ip_address = get_ip_from_url(target_url)
    if not ip_address:
        st.error("Unable to resolve the domain. Please check the URL and try again.")
        return

    st.info(f"Resolved IP address: {ip_address}")

    scan_type = st.selectbox("Select scan type:", ["Passive", "Active"])
    
    if scan_type == "Active":
        start_port = st.number_input("Start Port", min_value=1, max_value=65535, value=1)
        end_port = st.number_input("End Port", min_value=1, max_value=65535, value=1000)
    
    max_pages = st.number_input("Maximum pages to crawl", min_value=1, max_value=100, value=10)

    if st.button("Start Scan"):
        st.write("## Scan Results")

        # Port Scanning (Active scan only)
        if scan_type == "Active":
            st.write("### Port Scanning")
            open_ports = scan_ports(ip_address, start_port, end_port)
            if open_ports:
                st.success(f"Open ports: {', '.join(map(str, open_ports))}")
            else:
                st.info("No open ports found in the specified range.")

        # HTTP Header Analysis
        st.write("### HTTP Headers Analysis")
        headers, final_url = check_http_headers(target_url)
        if headers:
            st.json(dict(headers))
            if final_url != target_url:
                st.warning(f"Redirected to: {final_url}")
            if 'Server' in headers:
                st.warning(f"Server software disclosed: {headers['Server']}")
            if not headers.get('X-Frame-Options'):
                st.warning("X-Frame-Options header missing. Potential clickjacking vulnerability.")
            if not headers.get('Strict-Transport-Security'):
                st.warning("HSTS header missing. Potential downgrade attacks possible.")
            if headers.get('X-Powered-By'):
                st.warning(f"X-Powered-By header discloses: {headers['X-Powered-By']}")
        else:
            st.error("Unable to retrieve HTTP headers.")

        # SSL/TLS Analysis
        st.write("### SSL/TLS Analysis")
        ssl_info = check_ssl_tls(target_url)
        if ssl_info:
            st.json(ssl_info)
            for issue in ssl_info['issues']:
                st.warning(issue)
        else:
            st.error("Unable to perform SSL/TLS analysis.")

        # Web Crawling and Vulnerability Scanning
        st.write("### Web Crawling and Vulnerability Scanning")
        pages = crawl_website(target_url, max_pages)
        
        st.write(f"Crawled {len(pages)} pages.")
        
        vulnerability_progress = st.progress(0)
        vulnerability_status = st.empty()

        for i, page in enumerate(pages):
            st.write(f"Scanning: {page}")
            vulnerabilities = check_common_vulnerabilities(page)
            if vulnerabilities:
                for vuln in vulnerabilities:
                    st.warning(vuln)
            else:
                st.success("No common vulnerabilities detected on this page.")
            
            # Update vulnerability scanning progress
            progress = (i + 1) / len(pages)
            vulnerability_progress.progress(progress)
            vulnerability_status.text(f"Scanned {i + 1}/{len(pages)} pages for vulnerabilities")

        vulnerability_progress.empty()
        vulnerability_status.empty()

    st.warning("Note: This tool is for educational purposes only. Always obtain explicit permission before scanning any website or system you do not own.")

if __name__ == "__main__":
    main()
    