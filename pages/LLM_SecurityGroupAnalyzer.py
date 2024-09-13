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
API_URL = "https://api-inference.huggingface.co/models/gpt2-large"  # We're using GPT-2 Large, but you can change this to another model
headers = {"Authorization": f"Bearer {HUGGINGFACE_API_TOKEN}"}

def query_huggingface(payload):
    response = requests.post(API_URL, headers=headers, json=payload)
    return response.json()

# ... [Keep the existing patterns dictionary] ...

def get_response(user_input):
    # First, check if we have a pre-defined response
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
    ai_response = response[0]['generated_text'].split("AI: ")[-1]
    return ai_response

def analyze_security_group(config):
    # ... [Keep the existing analyze_security_group function] ...

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