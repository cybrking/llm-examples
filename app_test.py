import streamlit as st
from transformers import pipeline

# Load a pre-trained model for conversational tasks
generator = pipeline('conversational', model='microsoft/DialoGPT-medium')

def generate_response(prompt):
    # Generate a response using the model
    response = generator(prompt, max_length=100, num_return_sequences=1)
    return response[0]['generated_text']

def main():
    st.title("Simple Chatbot using Hugging Face Model")
    
    # User input
    user_input = st.text_input("You:", "")
    
    if user_input:
        # Generate response
        response = generate_response(user_input)
        st.text_area("Chatbot:", value=response, height=200)

if __name__ == "__main__":
    main()