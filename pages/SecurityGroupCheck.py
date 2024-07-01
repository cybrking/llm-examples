import streamlit as st
import pandas as pd
import altair as alt

def display_results(issues):
    if not issues:
        st.success("No security issues found.")
    else:
        st.warning(f"Found {len(issues)} security issues:")
        
        # Convert issues to a DataFrame for easier manipulation
        df = pd.DataFrame(issues)
        
        # Display summary statistics
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Issues", len(issues))
        with col2:
            st.metric("Critical Issues", len(df[df['severity'] == 'CRITICAL']))
        with col3:
            st.metric("High Severity Issues", len(df[df['severity'] == 'HIGH']))
        
        # Create a bar chart of issues by severity
        chart = alt.Chart(df).mark_bar().encode(
            x='severity:N',
            y='count():Q',
            color='severity:N'
        ).properties(
            title='Issues by Severity'
        )
        st.altair_chart(chart, use_container_width=True)
        
        # Display detailed results in an expandable section
        with st.expander("See detailed results"):
            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
                severity_issues = df[df['severity'] == severity]
                if not severity_issues.empty:
                    st.subheader(f"{severity} Issues")
                    for _, issue in severity_issues.iterrows():
                        st.markdown(f"**{issue['message']}**")
                        st.markdown(f"*Recommendation:* {issue['recommendation']}")
                        st.markdown("---")
        
        # Allow downloading results as CSV
        csv = df.to_csv(index=False)
        st.download_button(
            label="Download results as CSV",
            data=csv,
            file_name="security_group_analysis.csv",
            mime="text/csv",
        )
        
        # Provide a summary of the analysis context
        st.subheader("Analysis Context")
        st.json(current_context)  # Assuming current_context is a global variable storing the context

def main():
    st.title("Context-Aware Cloud Security Group Analyzer")

    # Gather application context
    global current_context  # Make this global so we can access it in display_results
    current_context = gather_application_context()

    # Cloud provider selection and credentials input
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
                
                display_results(analyzer.issues)
            except Exception as e:
                st.error(f"Error analyzing AWS security groups: {str(e)}")

    # (Add similar blocks for Azure and GCP)

if __name__ == "__main__":
    main()