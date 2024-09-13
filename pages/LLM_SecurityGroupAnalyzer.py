import streamlit as st
import random
import re
import json
import requests
from datetime import datetime
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Hugging Face API setup
HUGGINGFACE_API_TOKEN = os.getenv("HUGGINGFACE_API_TOKEN")
API_URL = "https://api-inference.huggingface.co/models/gpt2-large"
headers = {"Authorization": f"Bearer {HUGGINGFACE_API_TOKEN}"}

def query_huggingface(payload):
    try:
        response = requests.post(API_URL, headers=headers, json=payload)
        response.raise_for_status()  # Raises a HTTPError if the status is 4xx, 5xx
        return response.json()
    except requests.exceptions.RequestException as e:
        st.error(f"Error querying Hugging Face API: {str(e)}")
        return None

# Define patterns and responses
patterns = {
    'hi|hello|hey': ["Hello! How can I assist you with security group analysis today?", "Hi there! Ready to analyze some security groups?"],
    'bye|goodbye': ["Goodbye! Feel free to return if you have more security questions.", "Take care! Security is an ongoing process."],
    'security group': ["Security groups act as a virtual firewall for your AWS instances. What would you like to know about them?", "Security groups control inbound and outbound traffic. Do you have any specific questions?"],
    'inbound rules': ["Inbound rules control the incoming traffic to your AWS resources. Would you like to know how to set them up safely?", "Inbound rules are crucial for securing your instances. What specifically do you want to know?"],
    'outbound rules': ["Outbound rules manage the traffic leaving your AWS resources. Do you need help configuring them?", "Properly set outbound rules can prevent data exfiltration. What questions do you have about them?"],
    'best practices': ["Some security group best practices include: limiting open ports, using specific IP ranges, and regularly auditing rules. Would you like more details on any of these?", "It's important to follow the principle of least privilege when setting up security groups. What specific best practices are you interested in?"],
    'common mistakes': ["Common mistakes in security groups include leaving SSH open to the world and using overly permissive rules. Would you like to learn how to avoid these?", "Many people forget to restrict their database ports. Are you concerned about any specific misconfigurations?"],
    'analyze': ["To analyze a security group, I'll need to see its configuration. Can you provide the JSON for your security group?", "Sure, I can help analyze a security group. Do you have the configuration ready to share?"],
}

def get_response(user_input):
    # First, check if we have a pre-defined response
    user_input = user_input.lower()
    for pattern, responses in patterns.items():
        if re.search(pattern, user_input):
            return random.choice(responses)
    
    # If not, use Hugging Face model
    payload = {
        "inputs": f"Human: {user_input}\nAI: Let me help you with that. In the context of AWS security groups,",
        "max_length": 100,
        "temperature": 0.7,
        "top_p": 0.9,
    }
    response = query_huggingface(payload)
    if response is None or not isinstance(response, list) or len(response) == 0:
        return "I'm sorry, I couldn't generate a response at this time. Can you try asking your question in a different way?"
    
    generated_text = response[0].get('generated_text', '')
    ai_response = generated_text.split("AI: ")[-1] if "AI: " in generated_text else generated_text
    return ai_response

def analyze_security_group(config):
    try:
        sg = json.loads(config)
        analysis = []
        
        # Check for overly permissive inbound rules
        for rule in sg.get("IpPermissions", []):
            if any(ip.get("CidrIp") == "0.0.0.0/0" for ip in rule.get("IpRanges", [])):
                analysis.append(f"Warning: Overly permissive inbound rule found for protocol {rule.get('IpProtocol')} on ports {rule.get('FromPort')}-{rule.get('ToPort')}.")
        
        # Check for all traffic allowed outbound
        for rule in sg.get("IpPermissionsEgress", []):
            if rule.get("IpProtocol") == "-1" and any(ip.get("CidrIp") == "0.0.0.0/0" for ip in rule.get("IpRanges", [])):
                analysis.append("Warning: All outbound traffic is allowed. Consider restricting this.")
        
        if not analysis:
            analysis.append("No obvious issues found. Remember to always follow the principle of least privilege.")
        
        return "\n".join(analysis)
    except json.JSONDecodeError:
        return "Error: Invalid JSON. Please provide a valid security group configuration."
    except Exception as e:
        return f"An error occurred during analysis: {str(e)}"

def main():
    st.title("Advanced Security Group Analysis Chatbot")

    if "messages" not in st.session_state:
        st.session_state.messages = []

    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])

    if prompt := st.chat_input("What would you like to know about security groups?"):
        st.chat_message("user").markdown(prompt)
        st.session_state.messages.append({"role": "user", "content": prompt})

        if "analyze" in prompt.lower() and "{" in prompt and "}" in prompt:
            # Extract JSON-like content from the prompt
            start = prompt.index("{")
            end = prompt.rindex("}") + 1
            config = prompt[start:end]
            response = analyze_security_group(config)
        else:
            response = get_response(prompt)

        with st.chat_message("assistant"):
            st.markdown(response)
        st.session_state.messages.append({"role": "assistant", "content": response})

if __name__ == "__main__":
    main()