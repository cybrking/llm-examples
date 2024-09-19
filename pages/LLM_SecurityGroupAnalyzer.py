import streamlit as st
from transformers import pipeline

# Load a pre-trained model for text generation
generator = pipeline('text-generation', model='microsoft/DialoGPT-medium')

def generate_response(prompt):
    # Generate a response using the model
    response = generator(prompt, max_length=100, num_return_sequences=1)
    return response[0]['generated_text']

def main():
    st.title("Simple Chatbot using Hugging Face Model")
    
    # Initialize session state for chat history
    if 'chat_history' not in st.session_state:
        st.session_state.chat_history = []

    # User input
    user_input = st.text_input("You:", "")
    
    if user_input:
        try:
            # Generate response
            response = generate_response(user_input)
            st.session_state.chat_history.append(("You", user_input))
            st.session_state.chat_history.append(("Chatbot", response))
        except Exception as e:
            st.error(f"An error occurred: {e}")

    # Display chat history
    for sender, message in st.session_state.chat_history:
        st.write(f"{sender}: {message}")

if __name__ == "__main__":
    main()