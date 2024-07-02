import streamlit as st
import json
import yaml

def check_public_ingress(security_group):
    issues = []
    group_name = security_group.get('GroupName', security_group.get('group_name', 'Unknown Group'))
    
    ingress_rules = security_group.get('IpPermissions', security_group.get('ingress', []))
    if not isinstance(ingress_rules, list):
        ingress_rules = [ingress_rules]

    for rule in ingress_rules:
        from_port = rule.get('FromPort', rule.get('from_port'))
        to_port = rule.get('ToPort', rule.get('to_port'))
        
        ip_ranges = rule.get('IpRanges', rule.get('cidr_blocks', []))
        if not isinstance(ip_ranges, list):
            ip_ranges = [ip_ranges]

        for ip_range in ip_ranges:
            cidr = ip_range.get('CidrIp', ip_range) if isinstance(ip_range, dict) else ip_range
            if isinstance(cidr, str) and cidr.strip() == '0.0.0.0/0':
                port_range = f"{from_port}-{to_port}" if from_port != to_port else str(from_port)
                protocol = rule.get('IpProtocol', rule.get('protocol', 'All'))
                
                issue = f"Public ingress detected in {group_name}: "
                if protocol.lower() == '-1' or protocol.lower() == 'all':
                    issue += f"All traffic "
                else:
                    issue += f"Protocol {protocol} "
                
                if from_port is None and to_port is None:
                    issue += "on all ports "
                else:
                    issue += f"on port(s) {port_range} "
                
                issue += "is open to the world (0.0.0.0/0)"
                issues.append(issue)

    return issues

def parse_input(data):
    try:
        # Try parsing as JSON
        parsed = json.loads(data)
    except json.JSONDecodeError:
        try:
            # If JSON fails, try parsing as YAML
            parsed = yaml.safe_load(data)
        except yaml.YAMLError:
            st.error("Invalid input. Please ensure it's valid JSON or YAML.")
            return None

    if isinstance(parsed, list):
        return parsed
    elif isinstance(parsed, dict):
        if 'SecurityGroups' in parsed:
            return parsed['SecurityGroups']
        else:
            return [parsed]
    else:
        st.error("Invalid input structure. Expected a security group, list of security groups, or a dict with 'SecurityGroups' key.")
        return None

def main():
    st.title("Security Group Public Ingress Checker")
    st.write("Supports JSON and YAML formats")

    input_data = st.text_area("Paste your Security Group configuration here:", height=300)
    
    if st.button("Analyze Security Group"):
        if input_data:
            security_groups = parse_input(input_data)
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
            st.error("Please enter some configuration data.")

if __name__ == "__main__":
    main()