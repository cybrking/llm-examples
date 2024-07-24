import streamlit as st
from transformers import pipeline
import sqlite3

# Use a publicly available model that doesn't require authentication
model_name = "distilbert-base-uncased-finetuned-sst-2-english"

# Initialize the model
try:
    classifier = pipeline("sentiment-analysis", model=model_name)
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
st.title('Cybersecurity Idea Sentiment Analysis')

# Idea Submission Form
idea = st.text_area("Submit Your Cybersecurity Idea")
if st.button('Analyze'):
    if idea:
        # Analyze sentiment
        result = classifier(idea)[0]
        sentiment = result['label']
        score = result['score']
        
        # Store in database
        c.execute("INSERT INTO ideas (idea, sentiment) VALUES (?, ?)", (idea, sentiment))
        conn.commit()
        
        st.success("Idea analyzed successfully!")
        st.write(f"Sentiment: {sentiment}")
        st.write(f"Confidence: {score:.2f}")
    else:
        st.warning("Please enter an idea.")

# Display stored ideas
st.subheader("Previously Analyzed Ideas")
for row in c.execute("SELECT idea, sentiment FROM ideas"):
    st.write(f"Idea: {row[0]}")
    st.write(f"Sentiment: {row[1]}")
    st.write("---")

# Close the database connection
conn.close()