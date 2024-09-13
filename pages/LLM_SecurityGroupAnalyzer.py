import streamlit as st
import json
import requests
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Hugging Face API setup
HUGGINGFACE_API_TOKEN = os.getenv("HUGGINGFACE_API_TOKEN")
API_URL = "https://api-inference.huggingface.co/models/deepseek-ai/deepseek-coder-6.7b-instruct"
headers = {"Authorization": f"Bearer {HUGGINGFACE_API_TOKEN}"}

def query_huggingface(payload):
    try:
        response = requests.post(API_URL, headers=headers, json=payload)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        st.error(f"Error querying Hugging Face API: {str(e)}")
        return None

def get_response(user_input):
    prompt = f"""Human: In the context of AWS security groups, {user_input}"""
    payload = {"inputs": prompt}
    response = query_huggingface(payload)
    if response:
        return response[0]['generated_text']
    return None

# Streamlit app
st.title("Chat with Hugging Face Model")

# File uploader
uploaded_file = st.file_uploader("Upload a file", type=["txt", "py", "json", "md"])

# Text area for copy and paste
user_text = st.text_area("Or paste your text here")

if uploaded_file:
    file_content = uploaded_file.read().decode("utf-8")
    st.write("File content:")
    st.code(file_content)
elif user_text:
    file_content = user_text
    st.write("Pasted content:")
    st.code(file_content)

if uploaded_file or user_text:
    # Get user input for the prompt
    user_input = st.text_input("Enter your prompt:")
    
    if user_input:
        response = get_response(user_input)
        if response:
            st.write("Model response:")
            st.write(response)
        else:
            st.write("No response from the model.")