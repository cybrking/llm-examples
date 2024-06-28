import streamlit as st
import requests
from urllib.parse import urlparse, urljoin
import pandas as pd

def check_sql_injection(url):
    payloads = ["'", "\"", "1 OR '1'='1", "1' OR '1'='1", "1 UNION SELECT NULL"]
    for payload in payloads:
        try:
            response = requests.get(f"{url}?id={payload}", timeout=5)
            if any(error in response.text.lower() for error in ["sql syntax", "mysql error", "oracle error", "sql server error"]):
                return "Potentially vulnerable", f"Suspicious response with payload: {payload}"
        except requests.RequestException:
            pass
    return "Not detected", "No SQL Injection vulnerability detected with basic payloads"

def check_xss(url):
    payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>", "javascript:alert('XSS')"]
    for payload in payloads:
        try:
            response = requests.get(f"{url}?q={payload}", timeout=5)
            if payload in response.text:
                return "Potentially vulnerable", f"XSS payload reflected in response: {payload}"
        except requests.RequestException:
            pass
    return "Not detected", "No XSS vulnerability detected with basic payloads"

def check_csrf(url):
    try:
        response = requests.get(url, timeout=5)
        if 'csrf' not in response.text.lower() and 'token' not in response.text.lower():
            return "Potentially vulnerable", "No CSRF token detected in the response"
        return "Not detected", "CSRF token or similar protection mechanism detected"
    except requests.RequestException:
        return "Error", "Failed to check for CSRF vulnerability"

def check_remote_code_execution(url):
    payloads = [";ls", "& dir", "|whoami", "$(cat /etc/passwd)"]
    for payload in payloads:
        try:
            response = requests.get(f"{url}?cmd={payload}", timeout=5)
            if any(sign in response.text for sign in ["root:", "Directory of", "Current user"]):
                return "Potentially vulnerable", f"Suspicious response with payload: {payload}"
        except requests.RequestException:
            pass
    return "Not detected", "No Remote Code Execution vulnerability detected with basic payloads"

def check_file_inclusion(url):
    payloads = ["../../etc/passwd", "../../windows/win.ini", "php://filter/convert.base64-encode/resource=index.php"]
    for payload in payloads:
        try:
            response = requests.get(f"{url}?file={payload}", timeout=5)
            if any(sign in response.text for sign in ["root:", "[extensions]", "<?php"]):
                return "Potentially vulnerable", f"Suspicious response with payload: {payload}"
        except requests.RequestException:
            pass
    return "Not detected", "No File Inclusion vulnerability detected with basic payloads"

def check_http_headers(url):
    try:
        response = requests.head(url, allow_redirects=True)
        headers = response.headers
        checks = [
            ("X-Frame-Options", headers.get("X-Frame-Options", "Not Set"),
             "Protects against clickjacking attacks"),
            ("X-XSS-Protection", headers.get("X-XSS-Protection", "Not Set"),
             "Enables browser's built-in XSS protection"),
            ("Content-Security-Policy", headers.get("Content-Security-Policy", "Not Set"),
             "Mitigates various attacks including XSS and injection attacks"),
            ("Strict-Transport-Security", headers.get("Strict-Transport-Security", "Not Set"),
             "Enforces HTTPS connections"),
            ("X-Content-Type-Options", headers.get("X-Content-Type-Options", "Not Set"),
             "Prevents MIME type sniffing"),
        ]
        return checks
    except requests.RequestException as e:
        return [("Error", str(e), "Failed to retrieve headers")]

def main():
    st.title("Comprehensive Web Vulnerability Scanner")

    url = st.text_input("Enter a URL to scan:")
    if st.button("Scan for Vulnerabilities"):
        if url:
            with st.spinner("Scanning for vulnerabilities..."):
                vulnerabilities = [
                    ("SQL Injection", *check_sql_injection(url)),
                    ("Cross-Site Scripting (XSS)", *check_xss(url)),
                    ("Cross-Site Request Forgery (CSRF)", *check_csrf(url)),
                    ("Remote Code Execution", *check_remote_code_execution(url)),
                    ("File Inclusion", *check_file_inclusion(url)),
                ]
                
                st.write("### Vulnerability Scan Results")
                df = pd.DataFrame(vulnerabilities, columns=["Vulnerability", "Status", "Details"])
                st.table(df)
                
                st.write("### HTTP Header Analysis")
                header_checks = check_http_headers(url)
                for header, value, description in header_checks:
                    with st.expander(f"{header}"):
                        st.write(f"**Value:** {value}")
                        st.write(f"**Description:** {description}")
                        if value == "Not Set":
                            st.warning("This header is not set, which may pose a security risk.")
                        else:
                            st.success("This header is set.")

            st.warning("Note: This tool provides basic vulnerability scanning and may not detect all vulnerabilities. It should be used for educational purposes only. Always obtain explicit permission before scanning any website or system you do not own.")
        else:
            st.error("Please enter a valid URL")

if __name__ == "__main__":
    main()