import streamlit as st
import pandas as pd
import altair as alt
from typing import Dict, List, Any
import json


# Function to gather application context
def gather_application_context():
    st.subheader("Application Context")
    
    context = {}
    
    context['app_type'] = st.selectbox(
        "Application Type",
        ["Internal", "External", "Hybrid"]
    )
    
    context['environment'] = st.selectbox(
        "Environment",
        ["Development", "Testing/Staging", "Production"]
    )
    
    context['data_sensitivity'] = st.selectbox(
        "Data Sensitivity",
        ["Public", "Internal Use Only", "Confidential", "Highly Sensitive"]
    )
    
    context['compliance'] = st.multiselect(
        "Compliance Requirements",
        ["GDPR", "HIPAA", "PCI DSS", "SOC 2", "None"]
    )
    
    return context

# Base rules for security group analysis
BASE_RULES = {
    "open_internet": {"severity": "HIGH", "ports": []},
    "sensitive_ports": {
        "severity": "HIGH",
        "ports": [22, 3389]  # SSH and RDP
    },
    "database_ports": {
        "severity": "MEDIUM",
        "ports": [1433, 3306, 5432]  # MSSQL, MySQL, PostgreSQL
    },
    "http_ports": {
        "severity": "LOW",
        "ports": [80, 443]  # HTTP and HTTPS
    }
}

def adjust_rules_by_context(context: Dict[str, Any]) -> Dict[str, Any]:
    rules = BASE_RULES.copy()
    
    if context['app_type'] == "Internal":
        rules["open_internet"]["severity"] = "CRITICAL"
    elif context['app_type'] == "External":
        rules["http_ports"]["severity"] = "INFO"
    
    if context['environment'] == "Production":
        rules["open_internet"]["severity"] = "CRITICAL"
    
    if context['data_sensitivity'] in ["Confidential", "Highly Sensitive"]:
        rules["open_internet"]["severity"] = "CRITICAL"
        rules["sensitive_ports"]["severity"] = "CRITICAL"
        rules["database_ports"]["severity"] = "HIGH"
    
    if "PCI DSS" in context['compliance']:
        rules["open_internet"]["severity"] = "CRITICAL"
        rules["database_ports"]["severity"] = "CRITICAL"
    
    return rules

class ContextAwareSecurityGroupAnalyzer:
    def __init__(self, context: Dict[str, Any]):
        self.context = context
        self.rules = adjust_rules_by_context(context)
        self.issues = []

    def _add_issue(self, severity: str, message: str, recommendation: str):
        self.issues.append({
            'severity': severity,
            'message': message,
            'recommendation': recommendation
        })

    def _check_rule(self, rule: Dict[str, Any], direction: str, group_name: str, from_port: int, to_port: int, cidr: str):
        if cidr == '0.0.0.0/0':
            if from_port == 0 and to_port == 65535:
                self._add_issue(
                    self.rules["open_internet"]["severity"],
                    f"{group_name} allows all {direction} traffic from the internet",
                    "Restrict traffic to necessary ports and IP ranges only."
                )
            elif from_port in self.rules["sensitive_ports"]["ports"] or to_port in self.rules["sensitive_ports"]["ports"]:
                self._add_issue(
                    self.rules["sensitive_ports"]["severity"],
                    f"{group_name} allows {direction} to sensitive port(s) from the internet",
                    "Restrict access to these ports to specific, trusted IP ranges."
                )
            elif from_port in self.rules["database_ports"]["ports"] or to_port in self.rules["database_ports"]["ports"]:
                self._add_issue(
                    self.rules["database_ports"]["severity"],
                    f"{group_name} allows {direction} to database port(s) from the internet",
                    "Database ports should not be exposed to the internet. Use a bastion host or VPN for access."
                )
            elif (from_port in self.rules["http_ports"]["ports"] or to_port in self.rules["http_ports"]["ports"]) and self.context['app_type'] != "External":
                self._add_issue(
                    self.rules["http_ports"]["severity"],
                    f"{group_name} allows {direction} HTTP/HTTPS traffic from the internet for a non-external app",
                    "Ensure this is intended. Consider using a load balancer or API gateway for external access."
                )

    def analyze_security_group(self, group: Dict[str, Any]):
        for rule in group.get('IpPermissions', []):
            from_port = rule.get('FromPort', 0)
            to_port = rule.get('ToPort', 65535)
            for ip_range in rule.get('IpRanges', []):
                cidr = ip_range.get('CidrIp', '')
                self._check_rule(rule, 'ingress', group['GroupName'], from_port, to_port, cidr)
        
        for rule in group.get('IpPermissionsEgress', []):
            from_port = rule.get('FromPort', 0)
            to_port = rule.get('ToPort', 65535)
            for ip_range in rule.get('IpRanges', []):
                cidr = ip_range.get('CidrIp', '')
                self._check_rule(rule, 'egress', group['GroupName'], from_port, to_port, cidr)

def display_results(issues, context):
    if not issues:
        st.success("No security issues found.")
    else:
        st.warning(f"Found {len(issues)} security issues:")
        
        df = pd.DataFrame(issues)
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Issues", len(issues))
        with col2:
            st.metric("Critical Issues", len(df[df['severity'] == 'CRITICAL']))
        with col3:
            st.metric("High Severity Issues", len(df[df['severity'] == 'HIGH']))
        
        chart = alt.Chart(df).mark_bar().encode(
            x='severity:N',
            y='count():Q',
            color='severity:N'
        ).properties(
            title='Issues by Severity'
        )
        st.altair_chart(chart, use_container_width=True)
        
        with st.expander("See detailed results"):
            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
                severity_issues = df[df['severity'] == severity]
                if not severity_issues.empty:
                    st.subheader(f"{severity} Issues")
                    for _, issue in severity_issues.iterrows():
                        st.markdown(f"**{issue['message']}**")
                        st.markdown(f"*Recommendation:* {issue['recommendation']}")
                        st.markdown("---")
        
        csv = df.to_csv(index=False)
        st.download_button(
            label="Download results as CSV",
            data=csv,
            file_name="security_group_analysis.csv",
            mime="text/csv",
        )
        
        st.subheader("Analysis Context")
        st.json(context)

def parse_security_group_json(json_data):
    try:
        data = json.loads(json_data)
        if isinstance(data, list):
            return data
        elif isinstance(data, dict) and 'SecurityGroups' in data:
            return data['SecurityGroups']
        else:
            st.error("Invalid JSON format. Expected a list of security groups or a dict with 'SecurityGroups' key.")
            return None
    except json.JSONDecodeError:
        st.error("Invalid JSON. Please check your input.")
        return None

def main():
    st.title("Context-Aware Cloud Security Group Analyzer")

    current_context = gather_application_context()

    st.header("Security Group Input")
    input_method = st.radio("Choose input method:", ["Upload JSON file", "Paste JSON data", "Use AWS API"])

    security_groups = None

    if input_method == "Upload JSON file":
        uploaded_file = st.file_uploader("Choose a JSON file", type="json")
        if uploaded_file is not None:
            json_data = uploaded_file.getvalue().decode("utf-8")
            security_groups = parse_security_group_json(json_data)

    elif input_method == "Paste JSON data":
        json_data = st.text_area("Paste your Security Group JSON data here:")
        if json_data:
            security_groups = parse_security_group_json(json_data)

    elif input_method == "Use AWS API":
        region_name = st.text_input("Enter AWS Region Name", "us-west-2")
        if st.button("Fetch and Analyze AWS Security Groups"):
            try:
                import boto3
            except ImportError:
                st.error("boto3 is not installed. Please install it using 'pip install boto3'")
                return

            try:
                ec2 = boto3.client('ec2', region_name=region_name)
                response = ec2.describe_security_groups()
                security_groups = response['SecurityGroups']
            except Exception as e:
                st.error(f"Error fetching AWS security groups: {str(e)}")
                st.info("Make sure your AWS credentials are properly configured.")
                return

    if security_groups:
        analyzer = ContextAwareSecurityGroupAnalyzer(current_context)
        for group in security_groups:
            analyzer.analyze_security_group(group)
        
        display_results(analyzer.issues, current_context)

if __name__ == "__main__":
    main()


def main():
    st.title("Context-Aware Cloud Security Group Analyzer")

    current_context = gather_application_context()

    cloud_provider = st.selectbox("Select Cloud Provider", ["AWS", "Azure", "GCP"])

    if cloud_provider == "AWS":
        region_name = st.text_input("Enter AWS Region Name", "us-west-2")
        if st.button("Analyze AWS Security Groups"):
            try:
                import boto3
                ec2 = boto3.client('ec2', region_name=region_name)
                response = ec2.describe_security_groups()
                
                analyzer = ContextAwareSecurityGroupAnalyzer(current_context)
                for group in response['SecurityGroups']:
                    analyzer.analyze_security_group(group)
                
                display_results(analyzer.issues, current_context)
            except Exception as e:
                st.error(f"Error analyzing AWS security groups: {str(e)}")

    # Placeholder for Azure and GCP (not implemented in this example)
    elif cloud_provider in ["Azure", "GCP"]:
        st.info(f"{cloud_provider} analysis not implemented in this example.")

if __name__ == "__main__":
    main()