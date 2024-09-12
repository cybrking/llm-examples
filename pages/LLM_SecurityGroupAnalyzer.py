import streamlit as st
from transformers import AutoTokenizer, AutoModelForCausalLM
import torch
import json

# Load the model and tokenizer
@st.cache_resource
def load_model():
    model_name = "EleutherAI/gpt-neo-1.3B"  # You can change this to Meta-Llama if you have access
    tokenizer = AutoTokenizer.from_pretrained(model_name)
    model = AutoModelForCausalLM.from_pretrained(model_name)
    return tokenizer, model

tokenizer, model = load_model()

def analyze_with_llm(sg_config):
    formatted_rules = format_rules_for_llm(sg_config)
    
    prompt = f"""
    Analyze the following AWS security group rules and provide insights on potential vulnerabilities or misconfigurations. 
    Also suggest improvements based on best practices. Be concise but thorough.

    Security Group Rules:
    {formatted_rules}

    Please provide your analysis in the following format:
    1. Potential Vulnerabilities:
    2. Misconfigurations:
    3. Suggested Improvements:
    """

    inputs = tokenizer(prompt, return_tensors="pt", max_length=512, truncation=True)
    
    with torch.no_grad():
        outputs = model.generate(
            inputs.input_ids,
            max_length=1000,
            num_return_sequences=1,
            temperature=0.7,
        )
    
    response = tokenizer.decode(outputs[0], skip_special_tokens=True)
    
    # Extract the analysis part from the response
    analysis_start = response.find("1. Potential Vulnerabilities:")
    if analysis_start != -1:
        analysis = response[analysis_start:]
    else:
        analysis = "Unable to generate a structured analysis. Here's the raw output:\n" + response

    return analysis

def format_rules_for_llm(sg_config):
    formatted_rules = "Inbound Rules:\n"
    for rule in sg_config.get("IpPermissions", []):
        protocol = rule.get("IpProtocol", "All")
        from_port = rule.get("FromPort", "Any")
        to_port = rule.get("ToPort", "Any")
        for ip_range in rule.get("IpRanges", []):
            cidr = ip_range.get("CidrIp", "Any")
            formatted_rules += f"- {protocol} {from_port}-{to_port} from {cidr}\n"
    
    formatted_rules += "\nOutbound Rules:\n"
    for rule in sg_config.get("IpPermissionsEgress", []):
        protocol = rule.get("IpProtocol", "All")
        from_port = rule.get("FromPort", "Any")
        to_port = rule.get("ToPort", "Any")
        for ip_range in rule.get("IpRanges", []):
            cidr = ip_range.get("CidrIp", "Any")
            formatted_rules += f"- {protocol} {from_port}-{to_port} to {cidr}\n"
    
    return formatted_rules

def llm_analyzer_page():
    st.title("LLM-Powered Security Group Analyzer")

    uploaded_file = st.file_uploader("Choose a security group configuration file", type=["json"])
    
    if uploaded_file is not None:
        file_contents = uploaded_file.getvalue().decode("utf-8")
        try:
            sg_config = json.loads(file_contents)
            
            st.subheader(f"Security Group: {sg_config.get('GroupName', 'Unnamed')}")
            
            if st.button("Analyze Security Group with LLM"):
                with st.spinner("Analyzing security group with LLM..."):
                    llm_analysis = analyze_with_llm(sg_config)
                st.subheader("LLM Analysis")
                st.write(llm_analysis)

        except Exception as e:
            st.error(f"An error occurred while processing the file: {str(e)}")

if __name__ == "__main__":
    llm_analyzer_page()