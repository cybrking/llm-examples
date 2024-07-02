import streamlit as st
import yaml
import pandas as pd
import plotly.graph_objects as go

def check_public_ingress(security_group):
    issues = []
    group_name = security_group.get('Properties', {}).get('GroupName', 'Unknown Group')
    
    ingress_rules = security_group.get('Properties', {}).get('SecurityGroupIngress', [])
    if not isinstance(ingress_rules, list):
        ingress_rules = [ingress_rules]

    for rule in ingress_rules:
        from_port = rule.get('FromPort')
        to_port = rule.get('ToPort')
        protocol = rule.get('IpProtocol')
        cidr = rule.get('CidrIp')

        if cidr == '0.0.0.0/0':
            port_range = f"{from_port}-{to_port}" if from_port != to_port else str(from_port)
            
            issue = {
                "Group Name": group_name,
                "Protocol": "All" if protocol == '-1' else protocol,
                "Port Range": "All" if (from_port == 0 and to_port == 65535) else port_range,
                "Source": cidr,
                "Severity": "High" if protocol == '-1' else "Medium"
            }
            issues.append(issue)

    return issues

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

def create_issues_table(all_issues):
    if all_issues:
        df = pd.DataFrame(all_issues)
        st.dataframe(df, use_container_width=True)
    else:
        st.success("No public ingress rules found.")

def create_issues_chart(all_issues):
    if all_issues:
        df = pd.DataFrame(all_issues)
        severity_counts = df['Severity'].value_counts()
        
        fig = go.Figure(data=[go.Pie(labels=severity_counts.index, values=severity_counts.values, hole=.3)])
        fig.update_layout(title_text="Issues by Severity")
        st.plotly_chart(fig, use_container_width=True)

def main():
    st.set_page_config(page_title="CloudFormation Security Group Analyzer", layout="wide")
    
    st.title("CloudFormation Security Group Public Ingress Checker")
    st.write("Paste your CloudFormation template (YAML format) below")

    input_data = st.text_area("CloudFormation Template:", height=300)
    
    if st.button("Analyze Security Group"):
        if input_data:
            security_groups = parse_input(input_data)
            if security_groups:
                all_issues = []
                for sg in security_groups:
                    issues = check_public_ingress(sg)
                    all_issues.extend(issues)
                
                st.subheader("Analysis Results")
                
                col1, col2 = st.columns([2, 1])
                
                with col1:
                    st.subheader("Detected Issues")
                    create_issues_table(all_issues)
                
                with col2:
                    st.subheader("Issues by Severity")
                    create_issues_chart(all_issues)
                
                if all_issues:
                    st.warning(f"Found {len(all_issues)} public ingress rules that may pose security risks.")
                    
                    # Export results
                    csv = pd.DataFrame(all_issues).to_csv(index=False)
                    st.download_button(
                        label="Download Results as CSV",
                        data=csv,
                        file_name="security_group_analysis.csv",
                        mime="text/csv",
                    )
                else:
                    st.success("No public ingress rules found. Your security groups appear to be properly configured.")
        else:
            st.error("Please enter a CloudFormation template.")

if __name__ == "__main__":
    main()