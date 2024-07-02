import streamlit as st
import json
import yaml
import hcl2
import re

def check_public_ingress(security_group):
    issues = []
    group_name = security_group.get('name', security_group.get('group_name', 'Unknown Group'))
    
    ingress_rules = security_group.get('ingress', [])
    if isinstance(ingress_rules, dict):
        ingress_rules = [ingress_rules]

    for rule in ingress_rules:
        from_port = rule.get('from_port', 0)
        to_port = rule.get('to_port', 65535)
        cidr_blocks = rule.get('cidr_blocks', [])
        
        if isinstance(cidr_blocks, str):
            cidr_blocks = [cidr_blocks]
        
        for cidr in cidr_blocks:
            if cidr == '0.0.0.0/0':
                issues.append(f"Public ingress detected in {group_name}: "
                              f"Ports {from_port}-{to_port} are open to the world (0.0.0.0/0)")
    
    return issues

def parse_json(data):
    try:
        parsed = json.loads(data)
        if isinstance(parsed, list):
            return parsed
        elif isinstance(parsed, dict):
            if 'SecurityGroups' in parsed:
                return parsed['SecurityGroups']
            else:
                return [parsed]
    except json.JSONDecodeError:
        st.error("Invalid JSON. Please check your input.")
    return None

def parse_yaml(data):
    try:
        parsed = yaml.safe_load(data)
        if isinstance(parsed, list):
            return parsed
        elif isinstance(parsed, dict):
            if 'SecurityGroups' in parsed:
                return parsed['SecurityGroups']
            else:
                return [parsed]
    except yaml.YAMLError:
        st.error("Invalid YAML. Please check your input.")
    return None

def parse_terraform(data):
    try:
        parsed = hcl2.loads(data)
        security_groups = []
        for resource in parsed.get('resource', []):
            if 'aws_security_group' in resource:
                for sg_name, sg_config in resource['aws_security_group'].items():
                    security_groups.append(sg_config)
        return security_groups
    except Exception as e:
        st.error(f"Error parsing Terraform: {str(e)}")
    return None

def detect_format(data):
    # Check for JSON
    try:
        json.loads(data)
        return 'json'
    except json.JSONDecodeError:
        pass

    # Check for YAML
    try:
        yaml.safe_load(data)
        return 'yaml'
    except yaml.YAMLError:
        pass

    # Check for Terraform
    if 'resource "aws_security_group"' in data:
        return 'terraform'

    return 'unknown'

def parse_input(data):
    format = detect_format(data)
    if format == 'json':
        return parse_json(data)
    elif format == 'yaml':
        return parse_yaml(data)
    elif format == 'terraform':
        return parse_terraform(data)
    else:
        st.error("Unable to detect the input format. Please ensure it's valid JSON, YAML, or Terraform.")
        return None

def main():
    st.title("Security Group Public Ingress Checker")
    st.write("Supports JSON, YAML, and Terraform formats")

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