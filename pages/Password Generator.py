import streamlit as st
import random
import string
import pyperclip

def generate_password(length):
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    digits = string.digits
    symbols = string.punctuation

    password = [
        random.choice(lowercase),
        random.choice(uppercase),
        random.choice(digits),
        random.choice(symbols)
    ]

    for _ in range(length - 4):
        password.append(random.choice(lowercase + uppercase + digits + symbols))

    random.shuffle(password)
    return ''.join(password)

def main():
    st.title("Complex Password Generator")
    st.write("Generate a strong, complex password with alphanumeric and special characters.")

    length = st.slider("Password Length", min_value=20, max_value=40, value=30)

    if 'password' not in st.session_state:
        st.session_state.password = ""
    if 'copied' not in st.session_state:
        st.session_state.copied = False

    if st.button("Generate Password"):
        st.session_state.password = generate_password(length)
        st.session_state.copied = False

    if st.session_state.password:
        st.success("Your generated password is:")
        st.code(st.session_state.password, language=None)

        if st.button("Copy Password"):
            pyperclip.copy(st.session_state.password)
            st.session_state.copied = True

        if st.session_state.copied:
            st.success("Copied to clipboard!")

    st.write("Note: Always store your passwords securely and never share them with others.")

if __name__ == "__main__":
    main()