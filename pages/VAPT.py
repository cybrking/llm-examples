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

# [All other functions remain unchanged: get_ip_from_url, scan_port, scan_ports, check_http_headers, crawl_website, check_common_vulnerabilities, check_ssl_tls, check_ssl_tls_extended, generate_pdf_report]

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

        # [Rest of the main function remains unchanged]

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