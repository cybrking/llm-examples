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

# Get user input for the file path
file_path = st.text_input("Enter the file path:")

if file_path:
    try:
        with open(file_path, 'r') as file:
            file_content = file.read()
            st.write("File content:")
            st.code(file_content)
            
            # Get user input for the prompt
            user_input = st.text_input("Enter your prompt:")
            
            if user_input:
                response = get_response(user_input)
                if response:
                    st.write("Model response:")
                    st.write(response)
                else:
                    st.write("No response from the model.")
    except FileNotFoundError:
        st.error(f"File not found: {file_path}")
    except Exception as e:
        st.error(f"An error occurred: {str(e)}")