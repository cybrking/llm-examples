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

# [Previous functions remain unchanged: is_valid_url, get_ip_from_url, scan_port, scan_ports, check_http_headers, crawl_website, check_common_vulnerabilities, check_ssl_tls, check_ssl_tls_extended]

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

    # Port Scanning Results
    if 'open_ports' in scan_results:
        story.append(Paragraph("Open Ports", styles['Heading2']))
        if scan_results['open_ports']:
            story.append(Paragraph(f"Open ports: {', '.join(map(str, scan_results['open_ports']))}", styles['Normal']))
        else:
            story.append(Paragraph("No open ports found in the specified range.", styles['Normal']))
        story.append(Spacer(1, 12))

    # HTTP Headers
    story.append(Paragraph("HTTP Headers Analysis", styles['Heading2']))
    if scan_results['http_headers']:
        for key, value in scan_results['http_headers'].items():
            story.append(Paragraph(f"{key}: {value}", styles['Normal']))
    else:
        story.append(Paragraph("Unable to retrieve HTTP headers.", styles['Normal']))
    story.append(Spacer(1, 12))

    # SSL/TLS Analysis
    story.append(Paragraph("SSL/TLS Analysis", styles['Heading2']))
    if 'error' not in scan_results['ssl_info']:
        for key, value in scan_results['ssl_info'].items():
            if key != 'issues':
                story.append(Paragraph(f"{key}: {value}", styles['Normal']))
        if scan_results['ssl_info']['issues']:
            story.append(Paragraph("Issues:", styles['Heading3']))
            for issue in scan_results['ssl_info']['issues']:
                story.append(Paragraph(f"• {issue}", styles['Normal']))
    else:
        story.append(Paragraph(f"Unable to perform SSL/TLS analysis: {scan_results['ssl_info']['error']}", styles['Normal']))
    story.append(Spacer(1, 12))

    # Extended SSL/TLS Analysis
    story.append(Paragraph("Extended SSL/TLS Analysis", styles['Heading2']))
    if 'error' not in scan_results['extended_ssl_info']:
        if scan_results['extended_ssl_info']['issues']:
            story.append(Paragraph("Issues:", styles['Heading3']))
            for issue in scan_results['extended_ssl_info']['issues']:
                story.append(Paragraph(f"• {issue}", styles['Normal']))
        else:
            story.append(Paragraph("No major issues detected.", styles['Normal']))
    else:
        story.append(Paragraph(f"Unable to perform extended SSL/TLS analysis: {scan_results['extended_ssl_info']['error']}", styles['Normal']))
    story.append(Spacer(1, 12))

    # Vulnerabilities
    story.append(Paragraph("Vulnerabilities Detected", styles['Heading2']))
    if scan_results['vulnerabilities']:
        for url, vulns in scan_results['vulnerabilities'].items():
            story.append(Paragraph(f"URL: {url}", styles['Heading3']))
            for vuln in vulns:
                story.append(Paragraph(f"• {vuln}", styles['Normal']))
            story.append(Spacer(1, 6))
    else:
        story.append(Paragraph("No vulnerabilities detected.", styles['Normal']))

    doc.build(story)
    buffer.seek(0)
    return buffer

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

        scan_results = {
            "target_url": target_url,
            "ip_address": ip_address,
            "vulnerabilities": {}
        }

        # Port Scanning (Active scan only)
        if scan_type == "Active":
            st.write("### Port Scanning")
            open_ports = scan_ports(ip_address, start_port, end_port)
            scan_results["open_ports"] = open_ports
            if open_ports:
                st.success(f"Open ports: {', '.join(map(str, open_ports))}")
            else:
                st.info("No open ports found in the specified range.")

        # HTTP Header Analysis
        st.write("### HTTP Headers Analysis")
        headers, final_url = check_http_headers(target_url)
        scan_results["http_headers"] = headers
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
        scan_results["ssl_info"] = ssl_info
        if "error" not in ssl_info:
            st.json(ssl_info)
            for issue in ssl_info['issues']:
                st.warning(issue)
        else:
            st.error(f"Unable to perform SSL/TLS analysis: {ssl_info['error']}")

        # Extended SSL/TLS Analysis
        st.write("### Extended SSL/TLS Analysis")
        extended_ssl_info = check_ssl_tls_extended(target_url)
        scan_results["extended_ssl_info"] = extended_ssl_info
        if "error" not in extended_ssl_info:
            for issue in extended_ssl_info['issues']:
                st.warning(issue)
            with st.expander("View Detailed SSL/TLS Results"):
                st.json(extended_ssl_info['detailed_results'])
        else:
            st.error(f"Unable to perform extended SSL/TLS analysis: {extended_ssl_info['error']}")

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
                scan_results["vulnerabilities"][page] = vulnerabilities
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

        # Generate PDF Report
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