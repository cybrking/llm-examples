import streamlit as st
import random
import string

def generate_password(length, use_lowercase, use_uppercase, use_digits, use_special):
    character_set = ""
    if use_lowercase:
        character_set += string.ascii_lowercase
    if use_uppercase:
        character_set += string.ascii_uppercase
    if use_digits:
        character_set += string.digits
    if use_special:
        character_set += string.punctuation

    if not character_set:
        return "Please select at least one character type."

    password = ''.join(random.choice(character_set) for _ in range(length))
    return password

st.title("Secure Password Generator")

password_length = st.slider("Password Length", min_value=8, max_value=32, value=16, step=1)

col1, col2 = st.columns(2)
with col1:
    use_lowercase = st.checkbox("Lowercase Letters", value=True)
    use_uppercase = st.checkbox("Uppercase Letters", value=True)
with col2:
    use_digits = st.checkbox("Digits", value=True)
    use_special = st.checkbox("Special Characters", value=True)

if st.button("Generate Password"):
    password = generate_password(password_length, use_lowercase, use_uppercase, use_digits, use_special)
    st.success(f"Generated Password: {password}")

st.markdown("---")
st.write("This app generates secure passwords based on your preferences.")
st.write("For maximum security, use a long password with all character types enabled.")