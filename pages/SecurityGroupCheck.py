import streamlit as st
import yaml
import pandas as pd
import re

def check_security_group(security_group):
    issues = []
    group_name = security_group.get('Properties', {}).get('GroupName', 'Unknown Group')
    group_description = security_group.get('Properties', {}).get('GroupDescription', '')
    
    ingress_rules = security_group.get('Properties', {}).get('SecurityGroupIngress', [])
    egress_rules = security_group.get('Properties', {}).get('SecurityGroupEgress', [])
    
    if not isinstance(ingress_rules, list):
        ingress_rules = [ingress_rules]
    if not isinstance(egress_rules, list):
        egress_rules = [egress_rules]

    # Check naming and documentation
    check_naming_and_documentation(group_name, group_description, issues)

    # Check ingress rules
    for rule in ingress_rules:
        check_ingress_rule(rule, group_name, issues)

    # Check egress rules
    for rule in egress_rules:
        check_egress_rule(rule, group_name, issues)

    # Context-aware checks
    check_context_aware_rules(ingress_rules, egress_rules, group_name, issues)

    return issues

def check_naming_and_documentation(group_name, group_description, issues):
    if len(group_name) < 5 or not re.match(r'^[a-zA-Z]', group_name):
        issues.append({
            "Group Name": group_name,
            "Issue": "Non-descriptive naming",
            "Recommendation": "Use clear, descriptive names for security groups",
            "Risk": "Low"
        })
    
    if not group_description or len(group_description) < 10:
        issues.append({
            "Group Name": group_name,
            "Issue": "Insufficient documentation",
            "Recommendation": "Provide a detailed description for the security group",
            "Risk": "Low"
        })

def check_ingress_rule(rule, group_name, issues):
    from_port = rule.get('FromPort')
    to_port = rule.get('ToPort')
    protocol = rule.get('IpProtocol')
    cidr = rule.get('CidrIp')
    source_sg = rule.get('SourceSecurityGroupId')

    if cidr == '0.0.0.0/0':
        if from_port not in [80, 443]:
            issues.append({
                "Group Name": group_name,
                "Issue": "Overly permissive ingress rule",
                "Details": f"Protocol: {protocol}, Ports: {from_port}-{to_port}, Source: {cidr}",
                "Recommendation": "Restrict to specific IP ranges or use security groups as sources",
                "Risk": "High"
            })
    
    if from_port == 22 and cidr == '0.0.0.0/0':
        issues.append({
            "Group Name": group_name,
            "Issue": "SSH open to the world",
            "Recommendation": "Restrict SSH access to specific IP ranges (e.g., corporate IP addresses)",
            "Risk": "High"
        })

def check_egress_rule(rule, group_name, issues):
    from_port = rule.get('FromPort')
    to_port = rule.get('ToPort')
    protocol = rule.get('IpProtocol')
    cidr = rule.get('CidrIp')

    if cidr == '0.0.0.0/0' and protocol == '-1':
        issues.append({
            "Group Name": group_name,
            "Issue": "Unrestricted egress traffic",
            "Recommendation": "Limit outbound traffic to required destinations and protocols",
            "Risk": "Medium"
        })

def check_context_aware_rules(ingress_rules, egress_rules, group_name, issues):
    # Web Application checks
    web_ports = [rule for rule in ingress_rules if rule.get('FromPort') in [80, 443]]
    if not web_ports:
        issues.append({
            "Group Name": group_name,
            "Issue": "Web ports not open",
            "Recommendation": "For web applications, allow HTTP (80) and HTTPS (443) traffic",
            "Risk": "Medium"
        })

    # Database Instance checks
    db_ports = [3306, 5432, 1433]  # MySQL, PostgreSQL, MSSQL
    for port in db_ports:
        if any(rule.get('FromPort') == port and rule.get('CidrIp') == '0.0.0.0/0' for rule in ingress_rules):
            issues.append({
                "Group Name": group_name,
                "Issue": f"Database port {port} open to the world",
                "Recommendation": "Restrict database access to specific application servers",
                "Risk": "High"
            })

    # Microservices checks
    if len(ingress_rules) > 10:
        issues.append({
            "Group Name": group_name,
            "Issue": "High number of ingress rules",
            "Recommendation": "For microservices, consider using separate security groups for different services",
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
    st.set_page_config(page_title="Comprehensive AWS Security Group Best Practices Analyzer", layout="wide")
    
    st.title("Comprehensive AWS Security Group Best Practices Analyzer")
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
                        color = 'red' if val == 'High' else 'orange' if val == 'Medium' else 'yellow'
                        return f'background-color: {color}; color: black'

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