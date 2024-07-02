import streamlit as st
import yaml

def check_public_ingress(security_group):
    issues = []
    debug_info = []
    group_name = security_group.get('Properties', {}).get('GroupName', 'Unknown Group')
    debug_info.append(f"Analyzing group: {group_name}")
    
    ingress_rules = security_group.get('Properties', {}).get('SecurityGroupIngress', [])
    if not isinstance(ingress_rules, list):
        ingress_rules = [ingress_rules]
    
    debug_info.append(f"Found {len(ingress_rules)} ingress rules")

    for i, rule in enumerate(ingress_rules):
        debug_info.append(f"Analyzing rule {i+1}:")
        debug_info.append(f"Rule content: {rule}")
        
        from_port = rule.get('FromPort')
        to_port = rule.get('ToPort')
        protocol = rule.get('IpProtocol')
        cidr = rule.get('CidrIp')
        
        debug_info.append(f"Ports: {from_port} - {to_port}")
        debug_info.append(f"Protocol: {protocol}")
        debug_info.append(f"CIDR: {cidr}")

        if cidr == '0.0.0.0/0':
            port_range = f"{from_port}-{to_port}" if from_port != to_port else str(from_port)
            
            issue = f"Public ingress detected in {group_name}: "
            if protocol == '-1':
                issue += "All traffic "
            else:
                issue += f"Protocol {protocol} "
            
            if from_port == 0 and to_port == 65535:
                issue += "on all ports "
            else:
                issue += f"on port(s) {port_range} "
            
            issue += "is open to the world (0.0.0.0/0)"
            issues.append(issue)
            debug_info.append(f"Issue found: {issue}")
        else:
            debug_info.append("No public ingress in this rule")

    return issues, debug_info

def parse_input(data):
    try:
        parsed = yaml.safe_load(data)
        st.info("Input parsed as YAML")
        
        if 'Resources' in parsed:
            security_groups = []
            for resource_name, resource in parsed['Resources'].items():
                if resource.get('Type') == 'AWS::EC2::SecurityGroup':
                    security_groups.append(resource)
            
            st.info(f"Found {len(security_groups)} security group(s) in the CloudFormation template")
            return security_groups
        else:
            st.error("No 'Resources' section found in the CloudFormation template")
            return None
    except yaml.YAMLError:
        st.error("Invalid YAML. Please ensure it's a valid CloudFormation template.")
        return None

def main():
    st.title("CloudFormation Security Group Public Ingress Checker")
    st.write("Paste your CloudFormation template (YAML format) below")

    input_data = st.text_area("CloudFormation Template:", height=300)
    
    if st.button("Analyze Security Group"):
        if input_data:
            security_groups = parse_input(input_data)
            if security_groups:
                all_issues = []
                all_debug_info = []
                for sg in security_groups:
                    issues, debug_info = check_public_ingress(sg)
                    all_issues.extend(issues)
                    all_debug_info.extend(debug_info)
                
                st.subheader("Debug Information")
                for info in all_debug_info:
                    st.text(info)
                
                st.subheader("Analysis Results")
                if all_issues:
                    st.warning("Public ingress rules found:")
                    for issue in all_issues:
                        st.write(issue)
                else:
                    st.success("No public ingress rules found.")
        else:
            st.error("Please enter a CloudFormation template.")

if __name__ == "__main__":
    main()