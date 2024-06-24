import streamlit as st
import requests
from urllib.parse import urlparse
import ipaddress
import pandas as pd

def is_valid_url_or_ip(input_string):
    try:
        result = urlparse(input_string)
        return all([result.scheme, result.netloc])
    except ValueError:
        pass
    
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

def perform_header_checks(headers):
    checks = [
        ("Server Disclosure", 'Server' not in headers),
        ("X-Frame-Options Present", 'X-Frame-Options' in headers),
        ("Strict-Transport-Security (HSTS) Present", 'Strict-Transport-Security' in headers),
        ("X-Powered-By Absent", 'X-Powered-By' not in headers),
        ("X-XSS-Protection Present", 'X-XSS-Protection' in headers),
        ("X-Content-Type-Options Present", 'X-Content-Type-Options' in headers),
        ("Referrer-Policy Present", 'Referrer-Policy' in headers),
        ("Content-Security-Policy Present", 'Content-Security-Policy' in headers),
    ]
    return checks

def main():
    st.title("HTTP Header Security Check Tool")
    
    target = st.text_input("Enter target URL or IP address:", value="https://")
    
    if not target:
        st.warning("Please enter a URL or IP address to scan.")
        return

    if not is_valid_url_or_ip(target):
        st.error("Please enter a valid URL (e.g., https://example.com) or IP address.")
        return

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
                
                # Display all headers
                with st.expander("View All Headers"):
                    st.json(dict(headers))
                
                # Perform checks and display results
                checks = perform_header_checks(headers)
                
                # Prepare data for the DataFrame
                df_data = {
                    "Check": [check[0] for check in checks],
                    "Result": ["Pass" if check[1] else "Fail" for check in checks]
                }
                df = pd.DataFrame(df_data)
                
                # Apply color styling
                def color_result(val):
                    color = 'green' if val == 'Pass' else 'red'
                    return f'color: {color}'
                
                st.write("### Security Header Checks")
                st.dataframe(df.style.applymap(color_result, subset=['Result']))
                
                # Display specific warnings for failed checks
                st.write("### Warnings and Recommendations")
                for check, result in checks:
                    if not result:
                        if check == "Server Disclosure":
                            st.warning(f"Server header discloses: {headers['Server']}")
                        elif check == "X-Frame-Options Present":
                            st.warning("X-Frame-Options header missing. Potential clickjacking vulnerability.")
                        elif check == "Strict-Transport-Security (HSTS) Present":
                            st.warning("HSTS header missing. Potential downgrade attacks possible.")
                        elif check == "X-Powered-By Absent":
                            st.warning(f"X-Powered-By header discloses: {headers['X-Powered-By']}")
                        elif check == "X-XSS-Protection Present":
                            st.warning("X-XSS-Protection header missing. XSS protection not enabled.")
                        elif check == "X-Content-Type-Options Present":
                            st.warning("X-Content-Type-Options header missing. MIME type sniffing possible.")
                        elif check == "Referrer-Policy Present":
                            st.warning("Referrer-Policy header missing. Potential privacy concerns.")
                        elif check == "Content-Security-Policy Present":
                            st.warning("Content-Security-Policy header missing. Potential XSS vulnerabilities.")
                
            else:
                st.error(f"Unable to retrieve HTTP headers. Error: {final_url}")

    st.warning("Note: This tool is for educational purposes only. Always obtain explicit permission before scanning any website or system you do not own.")

if __name__ == "__main__":
    main()