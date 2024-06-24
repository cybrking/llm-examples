import streamlit as st
import socket
import ipaddress
import concurrent.futures
import requests

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

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

def check_http_headers(ip, port):
    try:
        response = requests.head(f"http://{ip}:{port}", timeout=2)
        return response.headers
    except:
        return None

def main():
    st.title("Basic Vulnerability Assessment and Penetration Testing Tool")
    
    target_ip = st.text_input("Enter target IP address:")
    
    if not is_valid_ip(target_ip):
        st.error("Please enter a valid IP address.")
        return

    start_port = st.number_input("Start Port", min_value=1, max_value=65535, value=1)
    end_port = st.number_input("End Port", min_value=1, max_value=65535, value=1000)

    if st.button("Start Scan"):
        with st.spinner("Scanning ports..."):
            open_ports = scan_ports(target_ip, start_port, end_port)
        
        if open_ports:
            st.success(f"Open ports: {', '.join(map(str, open_ports))}")
            
            for port in open_ports:
                st.write(f"Checking HTTP headers for port {port}...")
                headers = check_http_headers(target_ip, port)
                if headers:
                    st.json(dict(headers))
                    if 'Server' in headers:
                        st.warning(f"Server software disclosed: {headers['Server']}")
                    if not headers.get('X-Frame-Options'):
                        st.warning("X-Frame-Options header missing. Potential clickjacking vulnerability.")
                    if not headers.get('Strict-Transport-Security'):
                        st.warning("HSTS header missing. Potential downgrade attacks possible.")
                else:
                    st.info(f"No HTTP service detected on port {port}")
        else:
            st.info("No open ports found in the specified range.")

    st.warning("Note: This tool is for educational purposes only. Always obtain explicit permission before scanning any network or system you do not own.")

if __name__ == "__main__":
    main()