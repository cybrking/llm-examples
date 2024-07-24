import streamlit as st
from transformers import AutoModelForCausalLM, AutoTokenizer
import sqlite3
import torch

# Load model and tokenizer
@st.cache_resource
def load_model():
    model = AutoModelForCausalLM.from_pretrained("deepseek-ai/DeepSeek-V2-Lite-Chat", trust_remote_code=True)
    tokenizer = AutoTokenizer.from_pretrained("deepseek-ai/DeepSeek-V2-Lite-Chat", trust_remote_code=True)
    return model, tokenizer

model, tokenizer = load_model()

# Initialize SQLite database
conn = sqlite3.connect('ideas.db')
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS ideas 
             (id INTEGER PRIMARY KEY, idea TEXT, response TEXT)''')
conn.commit()

# Function to generate response
def generate_response(prompt):
    inputs = tokenizer(prompt, return_tensors="pt")
    with torch.no_grad():
        outputs = model.generate(**inputs, max_length=200, num_return_sequences=1)
    response = tokenizer.decode(outputs[0], skip_special_tokens=True)
    return response

# Streamlit App
st.title('Cybersecurity Idea Analysis')

# Idea Submission Form
idea = st.text_area("Submit Your Cybersecurity Idea")
if st.button('Analyze'):
    if idea:
        # Generate response
        prompt = f"Analyze this cybersecurity idea and provide feedback: {idea}"
        response = generate_response(prompt)
        
        # Store in database
        c.execute("INSERT INTO ideas (idea, response) VALUES (?, ?)", (idea, response))
        conn.commit()
        
        st.success("Idea analyzed successfully!")
        st.write("Analysis:")
        st.write(response)
    else:
        st.warning("Please enter an idea.")

# Display stored ideas
st.subheader("Previously Analyzed Ideas")
for row in c.execute("SELECT idea, response FROM ideas"):
    st.write(f"Idea: {row[0]}")
    st.write(f"Analysis: {row[1]}")
    st.write("---")

# Close the database connection
conn.close()