import streamlit as st
import socket
import concurrent.futures
import requests
from urllib.parse import urlparse

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

def main():
    st.title("Basic Web Vulnerability Assessment Tool")
    
    target_url = st.text_input("Enter target URL (include http:// or https://):")
    
    if not is_valid_url(target_url):
        st.error("Please enter a valid URL (e.g., https://example.com)")
        return

    ip_address = get_ip_from_url(target_url)
    if not ip_address:
        st.error("Unable to resolve the domain. Please check the URL and try again.")
        return

    st.info(f"Resolved IP address: {ip_address}")

    start_port = st.number_input("Start Port", min_value=1, max_value=65535, value=1)
    end_port = st.number_input("End Port", min_value=1, max_value=65535, value=1000)

    if st.button("Start Scan"):
        with st.spinner("Scanning ports..."):
            open_ports = scan_ports(ip_address, start_port, end_port)
        
        if open_ports:
            st.success(f"Open ports: {', '.join(map(str, open_ports))}")
            
            st.write("Checking HTTP headers...")
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
                st.info("Unable to retrieve HTTP headers.")
        else:
            st.info("No open ports found in the specified range.")

    st.warning("Note: This tool is for educational purposes only. Always obtain explicit permission before scanning any website or system you do not own.")

if __name__ == "__main__":
    main()