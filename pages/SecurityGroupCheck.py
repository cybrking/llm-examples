import streamlit as st
import json

def check_public_ingress(security_group):
    issues = []
    group_name = security_group.get('GroupName', 'Unknown Group')
    
    for rule in security_group.get('IpPermissions', []):
        from_port = rule.get('FromPort', 0)
        to_port = rule.get('ToPort', 65535)
        
        for ip_range in rule.get('IpRanges', []):
            cidr = ip_range.get('CidrIp', '')
            if cidr == '0.0.0.0/0':
                issues.append(f"Public ingress detected in {group_name}: "
                              f"Ports {from_port}-{to_port} are open to the world (0.0.0.0/0)")
    
    return issues

def parse_security_group_json(json_data):
    try:
        data = json.loads(json_data)
        if isinstance(data, list):
            return data
        elif isinstance(data, dict) and 'SecurityGroups' in data:
            return data['SecurityGroups']
        elif isinstance(data, dict):
            return [data]  # Single security group
        else:
            st.error("Invalid JSON format. Expected a security group, list of security groups, or a dict with 'SecurityGroups' key.")
            return None
    except json.JSONDecodeError:
        st.error("Invalid JSON. Please check your input.")
        return None

def main():
    st.title("Simple Security Group Public Ingress Checker")

    json_data = st.text_area("Paste your Security Group JSON data here:", height=300)
    
    if st.button("Analyze Security Group"):
        if json_data:
            security_groups = parse_security_group_json(json_data)
            if security_groups:
                all_issues = []
                for sg in security_groups:
                    issues = check_public_ingress(sg)
                    all_issues.extend(issues)
                
                if all_issues:
                    st.warning("Public ingress rules found:")
                    for issue in all_issues:
                        st.write(issue)
                else:
                    st.success("No public ingress rules found.")
        else:
            st.error("Please enter some JSON data.")

if __name__ == "__main__":
    main()