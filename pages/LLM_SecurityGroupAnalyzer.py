import streamlit as st
from transformers import AutoTokenizer, AutoModelForCausalLM
import torch

# Load model directly
model_name = "meta-llama/Meta-Llama-3.1-8B-Instruct"
tokenizer = AutoTokenizer.from_pretrained(model_name)
model = AutoModelForCausalLM.from_pretrained(model_name)

def get_response(user_input):
    inputs = tokenizer(user_input, return_tensors="pt")
    outputs = model.generate(**inputs)
    response = tokenizer.decode(outputs[0], skip_special_tokens=True)
    return response

# Streamlit app
st.title("Chat with Meta-Llama Model")

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