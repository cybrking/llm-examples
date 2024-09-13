import streamlit as st
import random

# Define some patterns and responses
patterns = {
    r'hi|hello|hey': ['Hello!', 'Hi there!', 'Hey!'],
    r'how are you': ['I'm doing well, thanks!', 'I'm fine, how about you?'],
    r'your name': ['I'm a simple chatbot.', 'You can call me ChatBot.'],
    r'bye|goodbye': ['Goodbye!', 'See you later!', 'Bye!'],
}

def get_response(user_input):
    user_input = user_input.lower()
    for pattern, responses in patterns.items():
        if any(keyword in user_input for keyword in pattern.split('|')):
            return random.choice(responses)
    return "I'm not sure how to respond to that."

def main():
    st.title("Simple Chatbot")

    # Initialize chat history
    if "messages" not in st.session_state:
        st.session_state.messages = []

    # Display chat messages from history on app rerun
    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])

    # React to user input
    if prompt := st.chat_input("What is your message?"):
        # Display user message in chat message container
        st.chat_message("user").markdown(prompt)
        # Add user message to chat history
        st.session_state.messages.append({"role": "user", "content": prompt})

        response = get_response(prompt)
        # Display assistant response in chat message container
        with st.chat_message("assistant"):
            st.markdown(response)
        # Add assistant response to chat history
        st.session_state.messages.append({"role": "assistant", "content": response})

if __name__ == "__main__":
    main()