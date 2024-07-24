import streamlit as st
from transformers import pipeline, AutoTokenizer, AutoModelForCausalLM
import sqlite3
import os
from dotenv import load_dotenv


# Use the DeepSeek-V2-Lite-Chat model
model_name = "deepseek-ai/DeepSeek-V2-Lite-Chat"

# Initialize the model
try:
    tokenizer = AutoTokenizer.from_pretrained(model_name, token=token, trust_remote_code=True)
    model = AutoModelForCausalLM.from_pretrained(model_name, token=token, trust_remote_code=True)
    generator = pipeline("text-generation", model=model, tokenizer=tokenizer)
except Exception as e:
    st.error(f"Error loading the model: {str(e)}")
    st.stop()

# Initialize SQLite database
conn = sqlite3.connect('ideas.db')
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS ideas 
             (id INTEGER PRIMARY KEY, idea TEXT, response TEXT)''')
conn.commit()

# Streamlit App
st.title('Cybersecurity Idea Analysis App')

# Idea Submission Form
idea = st.text_area("Submit Your Cybersecurity Idea")
if st.button('Analyze'):
    if idea:
        # Generate response
        prompt = f"Analyze this cybersecurity idea and provide feedback: {idea}"
        response = generator(prompt, max_length=200, num_return_sequences=1)[0]['generated_text']
        
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