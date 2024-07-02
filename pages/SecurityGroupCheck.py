import streamlit as st
import yaml
import pandas as pd
import re
from transformers import pipeline

# Load the Hugging Face model for zero-shot classification
@st.cache_resource
def load_classifier():
    return pipeline("zero-shot-classification", model="facebook/bart-large-mnli")

classifier = load_classifier()

def analyze_security_group(security_group):
    classification = {
        'public_ports': set(),
        'internal_rules': 0,
        'total_rules': 0,
        'name_clues': set(),
        'tags': {},
    }
    
    group_name = security_group.get('Properties', {}).get('GroupName', '')
    group_description = security_group.get('Properties', {}).get('GroupDescription', '')
    
    # Use Hugging Face model to classify the group based on name and description
    text_to_classify = f"{group_name} {group_description}"
    candidate_labels = ["public web server", "internal database", "load balancer", "application server", "bastion host"]
    result = classifier(text_to_classify, candidate_labels)
    classification['hf_classification'] = result['labels'][0]
    classification['hf_score'] = result['scores'][0]
    
    # Analyze tags
    tags = security_group.get('Properties', {}).get('Tags', [])
    for tag in tags:
        if isinstance(tag, dict):
            key = tag.get('Key', '').lower()
            value = tag.get('Value', '').lower()
            classification['tags'][key] = value
    
    # Analyze ingress rules
    ingress_rules = security_group.get('Properties', {}).get('SecurityGroupIngress', [])
    if not isinstance(ingress_rules, list):
        ingress_rules = [ingress_rules]
    
    for rule in ingress_rules:
        classification['total_rules'] += 1
        if rule.get('CidrIp') == '0.0.0.0/0':
            from_port = rule.get('FromPort')
            to_port = rule.get('ToPort')
            if from_port == to_port:
                classification['public_ports'].add(from_port)
            else:
                classification['public_ports'].update(range(from_port, to_port + 1))
        elif 'SourceSecurityGroupId' in rule:
            classification['internal_rules'] += 1
    
    return classify_security_group(classification)

def classify_security_group(classification):
    hf_class = classification['hf_classification']
    hf_score = classification['hf_score']
    
    if hf_score > 0.7:  # High confidence in Hugging Face classification
        if hf_class == "public web server":
            return "Fully External"
        elif hf_class == "internal database":
            return "Fully Internal"
        elif hf_class == "load balancer":
            return "Limited External Access"
        elif hf_class == "application server":
            return "Mixed Access"
        elif hf_class == "bastion host":
            return "DMZ"
    
    # Fall back to rule-based classification if Hugging Face confidence is low
    if len(classification['public_ports']) == 0:
        return "Fully Internal"
    elif len(classification['public_ports']) <= 2 and classification['internal_rules'] > 0:
        return "Limited External Access"
    elif len(classification['public_ports']) > 2:
        return "Fully External"
    elif 'dmz' in classification['tags'].values():
        return "DMZ"
    else:
        return "Mixed Access"

def check_security_group(security_group, context):
    issues = []
    group_name = security_group.get('Properties', {}).get('GroupName', 'Unknown Group')
    
    classification = analyze_security_group(security_group)
    
    ingress_rules = security_group.get('Properties', {}).get('SecurityGroupIngress', [])
    egress_rules = security_group.get('Properties', {}).get('SecurityGroupEgress', [])
    
    if not isinstance(ingress_rules, list):
        ingress_rules = [ingress_rules]
    if not isinstance(egress_rules, list):
        egress_rules = [egress_rules]

    check_naming_and_documentation(security_group, issues)

    for rule in ingress_rules:
        check_ingress_rule(rule, group_name, classification, context, issues)

    for rule in egress_rules:
        check_egress_rule(rule, group_name, classification, context, issues)

    check_context_aware_rules(ingress_rules, egress_rules, group_name, classification, context, issues)

    return issues, classification

# ... (keep the rest of the functions as they were in the previous version)

def main():
    st.set_page_config(page_title="Hugging Face Enhanced AWS Security Group Analyzer", layout="wide")
    
    st.title("Hugging Face Enhanced AWS Security Group Analyzer")
    st.write("Paste your CloudFormation template (YAML format) below")

    input_data = st.text_area("CloudFormation Template:", height=300)
    
    # Context inputs
    st.subheader("Application Context")
    environment = st.selectbox("Environment", ["Development", "Staging", "Production"])
    data_sensitivity = st.selectbox("Data Sensitivity", ["Public", "Internal", "Confidential", "Highly Sensitive"])
    compliance = st.multiselect("Compliance Requirements", ["PCI DSS", "HIPAA", "GDPR", "None"])

    context = {
        "environment": environment,
        "data_sensitivity": data_sensitivity,
        "compliance": compliance
    }
    
    if st.button("Analyze Security Groups"):
        if input_data:
            security_groups = parse_input(input_data)
            if security_groups:
                all_issues = []
                for sg in security_groups:
                    issues, classification = check_security_group(sg, context)
                    all_issues.extend(issues)
                    st.subheader(f"Security Group: {sg['Properties']['GroupName']}")
                    st.write(f"Classification: {classification}")
                    if issues:
                        st.write("Issues:")
                        for issue in issues:
                            st.write(f"- {issue['Issue']} (Risk: {issue['Risk']})")
                    else:
                        st.success("No issues found for this security group.")
                    st.write("---")
                
                st.subheader("Overall Analysis Results")
                
                if all_issues:
                    df = pd.DataFrame(all_issues)
                    
                    def color_risk(val):
                        color = 'red' if val == 'High' else 'orange' if val == 'Medium' else 'yellow'
                        return f'background-color: {color}; color: black'

                    styled_df = df.style.applymap(color_risk, subset=['Risk'])
                    
                    st.table(styled_df)
                    
                    st.warning(f"Found {len(all_issues)} potential issues based on the provided context.")
                    
                    csv = df.to_csv(index=False)
                    st.download_button(
                        label="Download Results as CSV",
                        data=csv,
                        file_name="security_group_analysis.csv",
                        mime="text/csv",
                    )
                else:
                    st.success("No issues found based on the provided context.")
        else:
            st.error("Please enter a CloudFormation template.")

if __name__ == "__main__":
    main()