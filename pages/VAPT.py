import streamlit as st
import requests
from urllib.parse import urlparse
import ipaddress
import pandas as pd

def is_valid_input(input_string):
    # Check if it's a valid URL
    try:
        result = urlparse(input_string)
        if all([result.scheme, result.netloc]):
            return True, "url"
    except ValueError:
        pass
    
    # Check if it's a valid IP address
    try:
        ipaddress.ip_address(input_string)
        return True, "ip"
    except ValueError:
        pass
    
    # Check if it's a domain name without scheme
    if '.' in input_string and ' ' not in input_string:
        return True, "domain"
    
    return False, None

def format_url(input_string, input_type):
    if input_type == "url":
        return input_string
    elif input_type == "ip":
        return f"http://{input_string}"
    elif input_type == "domain":
        return f"http://{input_string}"
    return input_string

def check_http_headers(url):
    try:
        response = requests.head(url, timeout=5, allow_redirects=True)
        return response.headers, response.url
    except requests.RequestException as e:
        return None, str(e)

def perform_header_checks(headers):
    checks = [
        ("Server Disclosure", 'Server' not in headers, 
         "Server header discloses software information. This can be used by attackers to identify vulnerabilities."),
        ("X-Frame-Options Present", 'X-Frame-Options' in headers, 
         "X-Frame-Options header missing. This can lead to clickjacking vulnerabilities."),
        ("Strict-Transport-Security (HSTS) Present", 'Strict-Transport-Security' in headers, 
         "HSTS header missing. This can make the site vulnerable to protocol downgrade attacks."),
        ("X-Powered-By Absent", 'X-Powered-By' not in headers, 
         "X-Powered-By header present. This discloses technology stack information."),
        ("X-XSS-Protection Present", 'X-XSS-Protection' in headers, 
         "X-XSS-Protection header missing. This can make the site more vulnerable to XSS attacks."),
        ("X-Content-Type-Options Present", 'X-Content-Type-Options' in headers, 
         "X-Content-Type-Options header missing. This can lead to MIME type sniffing vulnerabilities."),
        ("Referrer-Policy Present", 'Referrer-Policy' in headers, 
         "Referrer-Policy header missing. This can lead to privacy concerns and information leakage."),
        ("Content-Security-Policy Present", 'Content-Security-Policy' in headers, 
         "Content-Security-Policy header missing. This can make the site more vulnerable to various attacks including XSS."),
    ]
    return checks

def main():
    st.title("HTTP Header Security Check Tool")
    
    target = st.text_input("Enter target URL, IP address, or domain name:", value="")
    
    if not target:
        st.warning("Please enter a URL, IP address, or domain name to scan.")
        return

    is_valid, input_type = is_valid_input(target)
    if not is_valid:
        st.error("Please enter a valid URL, IP address, or domain name.")
        return

    formatted_target = format_url(target, input_type)

    if st.button("Check Headers"):
        st.write("## HTTP Header Analysis")
        
        with st.spinner("Checking HTTP headers..."):
            headers, final_url = check_http_headers(formatted_target)
            
            if headers:
                st.success("Headers retrieved successfully!")
                
                if final_url != formatted_target:
                    st.warning(f"Redirected to: {final_url}")
                
                # Display all headers
                with st.expander("View All Headers"):
                    st.json(dict(headers))
                
                # Perform checks and display results
                checks = perform_header_checks(headers)
                
                # Prepare data for the DataFrame
                df_data = {
                    "Check": [check[0] for check in checks],
                    "Result": ["Pass" if check[1] else "Fail" for check in checks],
                    "Warning/Recommendation": [check[2] if not check[1] else "" for check in checks]
                }
                df = pd.DataFrame(df_data)
                
                # Apply color styling
                def color_result(val):
                    color = 'green' if val == 'Pass' else 'red'
                    return f'color: {color}'
                
                st.write("### Security Header Checks")
                st.dataframe(df.style.applymap(color_result, subset=['Result']), width=1000)
                
            else:
                st.error(f"Unable to retrieve HTTP headers. Error: {final_url}")

    st.warning("Note: This tool is for educational purposes only. Always obtain explicit permission before scanning any website or system you do not own.")

if __name__ == "__main__":
    main()