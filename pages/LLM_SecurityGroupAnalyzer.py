import streamlit as st
from transformers import AutoTokenizer, AutoModelForCausalLM, pipeline
from langchain import LLMChain, PromptTemplate
from langchain.llms import HuggingFacePipeline

import torch

# Load model directly
model_name = "mattshumer/Reflection-Llama-3.1-70B"
tokenizer = AutoTokenizer.from_pretrained(model_name)
model = AutoModelForCausalLM.from_pretrained(model_name)

# Create a pipeline for text generation
def create_pipeline():
    pipe = pipeline(
        "text-generation",
        model=model,
        tokenizer=tokenizer,
        max_length=50
    )
    return HuggingFacePipeline(pipeline=pipe)

# Define a prompt template
prompt_template = PromptTemplate(
    input_variables=["user_input"],
    template="Human: In the context of AWS security groups, {user_input}"
)

# Create an LLMChain
llm_chain = LLMChain(
    llm=create_pipeline(),
    prompt=prompt_template
)

def get_response(user_input):
    response = llm_chain.run(user_input)
    return response

# Streamlit app
st.title("Chat with Reflection-Llama-3.1-70B Model using LangChain")

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