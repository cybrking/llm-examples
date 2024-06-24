import streamlit as st
import requests
from urllib.parse import urlparse
import ipaddress

def is_valid_url_or_ip(input_string):
    # Check if it's a valid URL
    try:
        result = urlparse(input_string)
        return all([result.scheme, result.netloc])
    except ValueError:
        pass
    
    # Check if it's a valid IP address
    try:
        ipaddress.ip_address(input_string)
        return True
    except ValueError:
        return False

def check_http_headers(url):
    try:
        response = requests.head(url, timeout=5, allow_redirects=True)
        return response.headers, response.url
    except requests.RequestException as e:
        return None, str(e)

def main():
    st.title("HTTP Header Check Tool")
    
    # Auto-fill input box with https://
    target = st.text_input("Enter target URL or IP address:", value="https://")
    
    if not target:
        st.warning("Please enter a URL or IP address to scan.")
        return

    if not is_valid_url_or_ip(target):
        st.error("Please enter a valid URL (e.g., https://example.com) or IP address.")
        return

    # If it's just an IP address, prepend http://
    if ipaddress.ip_address(target.split('://')[-1]):
        target = f"http://{target}"

    if st.button("Check Headers"):
        st.write("## HTTP Header Analysis")
        
        with st.spinner("Checking HTTP headers..."):
            headers, final_url = check_http_headers(target)
            
            if headers:
                st.success("Headers retrieved successfully!")
                
                if final_url != target:
                    st.warning(f"Redirected to: {final_url}")
                
                st.json(dict(headers))
                
                # Security header checks
                if 'Server' in headers:
                    st.warning(f"Server software disclosed: {headers['Server']}")
                if not headers.get('X-Frame-Options'):
                    st.warning("X-Frame-Options header missing. Potential clickjacking vulnerability.")
                if not headers.get('Strict-Transport-Security'):
                    st.warning("HSTS header missing. Potential downgrade attacks possible.")
                if headers.get('X-Powered-By'):
                    st.warning(f"X-Powered-By header discloses: {headers['X-Powered-By']}")
                if not headers.get('X-XSS-Protection'):
                    st.warning("X-XSS-Protection header missing. XSS protection not enabled.")
                if not headers.get('X-Content-Type-Options'):
                    st.warning("X-Content-Type-Options header missing. MIME type sniffing possible.")
                
            else:
                st.error(f"Unable to retrieve HTTP headers. Error: {final_url}")

    st.warning("Note: This tool is for educational purposes only. Always obtain explicit permission before scanning any website or system you do not own.")

if __name__ == "__main__":
    main()