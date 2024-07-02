import streamlit as st
import yaml
import pandas as pd
import re

def check_security_group(security_group):
    issues = []
    group_name = security_group.get('Properties', {}).get('GroupName', 'Unknown Group')
    
    ingress_rules = security_group.get('Properties', {}).get('SecurityGroupIngress', [])
    egress_rules = security_group.get('Properties', {}).get('SecurityGroupEgress', [])
    
    if not isinstance(ingress_rules, list):
        ingress_rules = [ingress_rules]
    if not isinstance(egress_rules, list):
        egress_rules = [egress_rules]

    # Check for default security group
    if group_name.lower() == 'default':
        issues.append({
            "Group Name": group_name,
            "Issue": "Using default security group",
            "Recommendation": "Create a new security group instead of using the default one",
            "Risk": "High"
        })

    # Check ingress rules
    for rule in ingress_rules:
        check_rule(rule, 'ingress', group_name, issues)

    # Check egress rules
    for rule in egress_rules:
        check_rule(rule, 'egress', group_name, issues)

    # Check for large port ranges
    check_large_port_ranges(ingress_rules + egress_rules, group_name, issues)

    return issues

def check_rule(rule, direction, group_name, issues):
    from_port = rule.get('FromPort')
    to_port = rule.get('ToPort')
    protocol = rule.get('IpProtocol')
    cidr = rule.get('CidrIp')
    source_sg = rule.get('SourceSecurityGroupId')

    # Check for overly permissive rules
    if cidr == '0.0.0.0/0':
        issues.append({
            "Group Name": group_name,
            "Issue": f"Overly permissive {direction} rule",
            "Details": f"Protocol: {protocol}, Ports: {from_port}-{to_port}, Source: {cidr}",
            "Recommendation": "Restrict to specific IP ranges or use security groups as sources",
            "Risk": "High"
        })

    # Check for all ports open
    if from_port == 0 and to_port == 65535:
        issues.append({
            "Group Name": group_name,
            "Issue": f"All ports open in {direction} rule",
            "Details": f"Protocol: {protocol}, Source: {cidr or source_sg}",
            "Recommendation": "Specify required ports instead of allowing all",
            "Risk": "High"
        })

    # Check for security groups as sources (best practice)
    if direction == 'ingress' and not source_sg:
        issues.append({
            "Group Name": group_name,
            "Issue": "IP range used instead of security group",
            "Details": f"Protocol: {protocol}, Ports: {from_port}-{to_port}, Source: {cidr}",
            "Recommendation": "Use security groups as sources where applicable",
            "Risk": "Medium"
        })

def check_large_port_ranges(rules, group_name, issues):
    for rule in rules:
        from_port = rule.get('FromPort')
        to_port = rule.get('ToPort')
        if from_port and to_port and (to_port - from_port) > 100:
            issues.append({
                "Group Name": group_name,
                "Issue": "Large port range",
                "Details": f"Ports: {from_port}-{to_port}",
                "Recommendation": "Minimize port range to necessary ports only",
                "Risk": "Medium"
            })

def parse_input(data):
    try:
        parsed = yaml.safe_load(data)
        
        if 'Resources' in parsed:
            security_groups = []
            for resource_name, resource in parsed['Resources'].items():
                if resource.get('Type') == 'AWS::EC2::SecurityGroup':
                    resource['Properties']['GroupName'] = resource_name
                    security_groups.append(resource)
            
            return security_groups
        else:
            st.error("No 'Resources' section found in the CloudFormation template")
            return None
    except yaml.YAMLError:
        st.error("Invalid YAML. Please ensure it's a valid CloudFormation template.")
        return None

def main():
    st.set_page_config(page_title="AWS Security Group Best Practices Analyzer", layout="wide")
    
    st.title("AWS Security Group Best Practices Analyzer")
    st.write("Paste your CloudFormation template (YAML format) below")

    input_data = st.text_area("CloudFormation Template:", height=300)
    
    if st.button("Analyze Security Groups"):
        if input_data:
            security_groups = parse_input(input_data)
            if security_groups:
                all_issues = []
                for sg in security_groups:
                    issues = check_security_group(sg)
                    all_issues.extend(issues)
                
                st.subheader("Analysis Results")
                
                if all_issues:
                    df = pd.DataFrame(all_issues)
                    
                    # Apply color to the Risk column
                    def color_risk(val):
                        color = 'red' if val == 'High' else 'orange' if val == 'Medium' else 'green'
                        return f'background-color: {color}; color: white'

                    styled_df = df.style.applymap(color_risk, subset=['Risk'])
                    
                    st.table(styled_df)
                    
                    st.warning(f"Found {len(all_issues)} potential issues that may not align with best practices.")
                    
                    # Export results
                    csv = df.to_csv(index=False)
                    st.download_button(
                        label="Download Results as CSV",
                        data=csv,
                        file_name="security_group_analysis.csv",
                        mime="text/csv",
                    )
                else:
                    st.success("No issues found. Your security groups appear to follow best practices.")
        else:
            st.error("Please enter a CloudFormation template.")

if __name__ == "__main__":
    main()