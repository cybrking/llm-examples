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
import subprocess
import json
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from io import BytesIO

def is_valid_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False

def get_ip_from_url(url):
    try:
        domain = urlparse(url).netloc
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None

def scan_port(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex((ip, port))
            if result == 0:
                return port
    except:
        pass
    return None

def scan_ports(ip, start_port, end_port):
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        future_to_port = {executor.submit(scan_port, ip, port): port for port in range(start_port, end_port + 1)}
        for future in concurrent.futures.as_completed(future_to_port):
            result = future.result()
            if result:
                open_ports.append(result)
    return open_ports

def check_http_headers(url):
    try:
        response = requests.head(url, timeout=5, allow_redirects=True)
        return response.headers, response.url
    except:
        return None, None

def check_ssl_tls(url):
    try:
        hostname = urlparse(url).netloc
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as secure_sock:
                cert = secure_sock.getpeercert()
        
        return {
            "issuer": dict(x[0] for x in cert['issuer']),
            "subject": dict(x[0] for x in cert['subject']),
            "version": cert['version'],
            "serialNumber": cert['serialNumber'],
            "notBefore": cert['notBefore'],
            "notAfter": cert['notAfter'],
        }
    except Exception as e:
        return {"error": str(e)}

def generate_pdf_report(scan_results):
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    # Title
    story.append(Paragraph("Web Vulnerability Assessment Report", styles['Title']))
    story.append(Spacer(1, 12))

    # Target Information
    story.append(Paragraph("Target Information", styles['Heading2']))
    story.append(Paragraph(f"URL: {scan_results['target_url']}", styles['Normal']))
    story.append(Paragraph(f"IP Address: {scan_results['ip_address']}", styles['Normal']))
    story.append(Spacer(1, 12))

    # Add other sections based on your scan results
    if 'open_ports' in scan_results:
        story.append(Paragraph("Open Ports", styles['Heading2']))
        if scan_results['open_ports']:
            story.append(Paragraph(f"Open ports: {', '.join(map(str, scan_results['open_ports']))}", styles['Normal']))
        else:
            story.append(Paragraph("No open ports found in the specified range.", styles['Normal']))
        story.append(Spacer(1, 12))

    # Add more sections for HTTP headers, SSL/TLS analysis, vulnerabilities, etc.

    doc.build(story)
    buffer.seek(0)
    return buffer

def main():
    st.title("Advanced Web Vulnerability Assessment Tool")
    
    target_url = st.text_input("Enter target URL (include http:// or https://):")
    
    if not target_url:
        st.warning("Please enter a URL to scan.")
        return

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

        scan_results = {
            "target_url": target_url,
            "ip_address": ip_address,
            "vulnerabilities": {}
        }

        # Perform scans and populate scan_results
        if scan_type == "Active":
            with st.spinner("Scanning ports..."):
                open_ports = scan_ports(ip_address, start_port, end_port)
                scan_results["open_ports"] = open_ports
                if open_ports:
                    st.success(f"Open ports: {', '.join(map(str, open_ports))}")
                else:
                    st.info("No open ports found in the specified range.")

        with st.spinner("Checking HTTP headers..."):
            headers, final_url = check_http_headers(target_url)
            scan_results["http_headers"] = headers
            if headers:
                st.json(dict(headers))
            else:
                st.error("Unable to retrieve HTTP headers.")

        with st.spinner("Performing SSL/TLS analysis..."):
            ssl_info = check_ssl_tls(target_url)
            scan_results["ssl_info"] = ssl_info
            if "error" not in ssl_info:
                st.json(ssl_info)
            else:
                st.error(f"Unable to perform SSL/TLS analysis: {ssl_info['error']}")

        # Generate and offer PDF report for download
        pdf_buffer = generate_pdf_report(scan_results)
        st.download_button(
            label="Download PDF Report",
            data=pdf_buffer,
            file_name="vulnerability_assessment_report.pdf",
            mime="application/pdf"
        )

    st.warning("Note: This tool is for educational purposes only. Always obtain explicit permission before scanning any website or system you do not own.")

if __name__ == "__main__":
    main()