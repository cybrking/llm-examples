import streamlit as st
import pandas as pd
import boto3
from azure.identity import DefaultAzureCredential
from azure.mgmt.network import NetworkManagementClient
from google.cloud import compute_v1
import json

class SecurityGroupAnalyzer:
    def __init__(self):
        self.issues = []

    def _add_issue(self, severity, message, recommendation):
        self.issues.append({
            'severity': severity,
            'message': message,
            'recommendation': recommendation
        })

    def _check_rule(self, rule, direction, group_name):
        if rule.get('IpProtocol') == '-1':  # All traffic
            self._add_issue('HIGH', 
                f"{group_name} allows all {direction} traffic",
                "Restrict traffic to necessary protocols and ports only.")
        
        cidr = rule.get('CidrIp')
        if cidr == '0.0.0.0/0':
            self._add_issue('CRITICAL', 
                f"{group_name} allows {direction} from any IP",
                "Restrict access to specific IP ranges or security groups.")
        
        if cidr:
            try:
                network = ipaddress.ip_network(cidr)
                if network.num_addresses > 1000:
                    self._add_issue('MEDIUM', 
                        f"{group_name} allows {direction} from a large IP range: {cidr}",
                        "Consider narrowing down the IP range if possible.")
            except ValueError:
                self._add_issue('ERROR', 
                    f"Invalid CIDR in {group_name}: {cidr}",
                    "Correct the CIDR notation.")

        port_range = rule.get('FromPort', rule.get('ToPort'))
        if port_range in [22, 3389]:  # SSH or RDP
            self._add_issue('HIGH', 
                f"{group_name} allows {direction} to sensitive port {port_range}",
                "Restrict access to these ports to specific, trusted IP ranges.")

class AWSAnalyzer(SecurityGroupAnalyzer):
    def analyze(self, region_name):
        ec2 = boto3.client('ec2', region_name=region_name)
        response = ec2.describe_security_groups()
        for group in response['SecurityGroups']:
            for rule in group.get('IpPermissions', []):
                self._check_rule(rule, 'ingress', group['GroupName'])
            for rule in group.get('IpPermissionsEgress', []):
                self._check_rule(rule, 'egress', group['GroupName'])

class AzureAnalyzer(SecurityGroupAnalyzer):
    def analyze(self, subscription_id):
        credential = DefaultAzureCredential()
        network_client = NetworkManagementClient(credential, subscription_id)
        for group in network_client.network_security_groups.list_all():
            for rule in group.security_rules:
                direction = 'ingress' if rule.direction == 'Inbound' else 'egress'
                self._check_rule({
                    'IpProtocol': rule.protocol,
                    'FromPort': rule.destination_port_range,
                    'ToPort': rule.destination_port_range,
                    'CidrIp': rule.source_address_prefix
                }, direction, group.name)

class GCPAnalyzer(SecurityGroupAnalyzer):
    def analyze(self, project_id):
        client = compute_v1.FirewallsClient()
        for firewall in client.list(project=project_id):
            direction = 'ingress' if firewall.direction == 'INGRESS' else 'egress'
            for rule in firewall.allowed:
                self._check_rule({
                    'IpProtocol': rule.IPProtocol,
                    'FromPort': rule.ports[0] if rule.ports else None,
                    'ToPort': rule.ports[-1] if rule.ports else None,
                    'CidrIp': firewall.source_ranges[0] if firewall.source_ranges else None
                }, direction, firewall.name)

def main():
    st.title("Cloud Security Group Analyzer")

    cloud_provider = st.selectbox("Select Cloud Provider", ["AWS", "Azure", "GCP"])

    if cloud_provider == "AWS":
        region_name = st.text_input("Enter AWS Region Name", "us-west-2")
        if st.button("Analyze AWS Security Groups"):
            analyzer = AWSAnalyzer()
            analyzer.analyze(region_name)
            display_results(analyzer.issues)

    elif cloud_provider == "Azure":
        subscription_id = st.text_input("Enter Azure Subscription ID")
        if st.button("Analyze Azure Security Groups"):
            analyzer = AzureAnalyzer()
            analyzer.analyze(subscription_id)
            display_results(analyzer.issues)

    elif cloud_provider == "GCP":
        project_id = st.text_input("Enter GCP Project ID")
        if st.button("Analyze GCP Firewall Rules"):
            analyzer = GCPAnalyzer()
            analyzer.analyze(project_id)
            display_results(analyzer.issues)

def display_results(issues):
    if not issues:
        st.success("No security issues found.")
    else:
        st.warning(f"Found {len(issues)} security issues:")
        df = pd.DataFrame(issues)
        st.dataframe(df)
        
        # Allow downloading results as CSV
        csv = df.to_csv(index=False)
        st.download_button(
            label="Download results as CSV",
            data=csv,
            file_name="security_group_analysis.csv",
            mime="text/csv",
        )

if __name__ == "__main__":
    main()