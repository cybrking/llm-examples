import streamlit as st
from transformers import pipeline
import sqlite3
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Retrieve the token from the environment variables
token = os.getenv("HUGGINGFACE_TOKEN")
if not token:
    st.error("Hugging Face token not found in environment variables")
    st.stop()

# Use a publicly available model
model_name = "deepseek-ai/DeepSeek-V2-Lite-Chat"

# Initialize the model
try:
    model = pipeline("text-generation", model=model_name, token=token)
except Exception as e:
    st.error(f"Error loading the model: {str(e)}")
    st.stop()

# Initialize SQLite database
conn = sqlite3.connect('ideas.db')
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS ideas 
             (id INTEGER PRIMARY KEY, idea TEXT, sentiment TEXT)''')
conn.commit()

# Streamlit App
st.title('Idea Sentiment Analysis App')

# Idea Submission Form
idea = st.text_area("Submit Your Idea")
if st.button('Submit'):
    if idea:
        # Analyze sentiment
        result = model(idea)[0]
        sentiment = result['label']
        
        # Store in database
        c.execute("INSERT INTO ideas (idea, sentiment) VALUES (?, ?)", (idea, sentiment))
        conn.commit()
        
        st.success(f"Idea submitted successfully! Sentiment: {sentiment}")
    else:
        st.warning("Please enter an idea.")

# Display stored ideas
st.subheader("Submitted Ideas")
for row in c.execute("SELECT idea, sentiment FROM ideas"):
    st.write(f"Idea: {row[0]}")
    st.write(f"Sentiment: {row[1]}")
    st.write("---")

# Close the database connection
conn.close()