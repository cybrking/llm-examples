import streamlit as st
from transformers import pipeline

# Initialize the RAG AI model
rag_model = pipeline('text-generation', model='cmeta-llama/Meta-Llama-3-8B')

# Initialize SQLite database
conn = sqlite3.connect('ideas.db')
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS ideas (id INTEGER PRIMARY KEY, idea TEXT)''')
conn.commit()

# Streamlit App
st.title('Cybersecurity Guidance App')

# Idea Submission Form
idea = st.text_area("Submit Your Idea")
if st.button('Submit'):
    if idea:
        c.execute("INSERT INTO ideas (idea) VALUES (?)", (idea,))
        conn.commit()
        st.success("Idea submitted successfully!")
    else:
        st.warning("Please enter an idea.")

# Generate Cybersecurity Guidance
if st.button('Generate Guidance'):
    if idea:
        guidance = rag_model(idea, max_length=100, num_return_sequences=1)
        st.write("Cybersecurity Guidance:")
        st.write(guidance[0]['generated_text'])
    else:
        st.warning("Please submit an idea first.")

# Close the database connection
conn.close()