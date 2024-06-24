import streamlit as st
import random
import string

def generate_password(length):
    # Define the character sets
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    digits = string.digits
    symbols = string.punctuation

    # Ensure at least one character from each set
    password = [
        random.choice(lowercase),
        random.choice(uppercase),
        random.choice(digits),
        random.choice(symbols)
    ]

    # Fill the rest of the password
    for _ in range(length - 4):
        password.append(random.choice(lowercase + uppercase + digits + symbols))

    # Shuffle the password to ensure randomness
    random.shuffle(password)

    return ''.join(password)

def main():
    st.title("Complex Password Generator")
    st.write("Generate a strong, complex password with alphanumeric and special characters.")

    # Password length slider
    length = st.slider("Password Length", min_value=20, max_value=32, value=20)

    if st.button("Generate Password"):
        password = generate_password(length)
        st.success("Your generated password is:")
        st.code(password, language=None)

    st.write("Note: Always store your passwords securely and never share them with others.")

if __name__ == "__main__":
    main()