import streamlit as st
from transformers import GPT2LMHeadModel, GPT2Tokenizer
import sqlite3

# Load model and tokenizer
@st.cache_resource
def load_model():
    model = GPT2LMHeadModel.from_pretrained("gpt2")
    tokenizer = GPT2Tokenizer.from_pretrained("gpt2")
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
    inputs = tokenizer.encode(prompt, return_tensors="pt")
    outputs = model.generate(inputs, max_length=150, num_return_sequences=1, no_repeat_ngram_size=2)
    response = tokenizer.decode(outputs[0], skip_special_tokens=True)
    return response

# Streamlit App
st.title('Cybersecurity Idea Analysis')

# Idea Submission Form
idea = st.text_area("Submit Your Cybersecurity Idea")
if st.button('Analyze'):
    if idea:
        # Generate response
        prompt = f"Analyze this cybersecurity idea: {idea}\nAnalysis:"
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