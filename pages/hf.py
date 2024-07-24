import streamlit as st
from transformers import GPT2LMHeadModel, GPT2Tokenizer
import sqlite3

# Load model and tokenizer
@st.cache_resource
def load_model():
    model = GPT2LMHeadModel.from_pretrained("gpt2-medium")  # Using a slightly larger model
    tokenizer = GPT2Tokenizer.from_pretrained("gpt2-medium")
    return model, tokenizer

model, tokenizer = load_model()

# Initialize SQLite database
conn = sqlite3.connect('ideas.db')
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS ideas 
             (id INTEGER PRIMARY KEY, idea TEXT, response TEXT)''')
conn.commit()

# Cybersecurity expert prompt
EXPERT_PROMPT = """
You are a highly experienced cybersecurity expert with decades of experience in the field. 
Your knowledge spans across various domains including network security, cryptography, 
threat intelligence, incident response, and emerging technologies like AI in cybersecurity.

When analyzing cybersecurity ideas, consider the following aspects:
1. Potential impact on overall security posture
2. Feasibility of implementation
3. Potential vulnerabilities or weaknesses
4. Alignment with current cybersecurity best practices
5. Scalability and long-term viability
6. Compliance with relevant regulations (e.g., GDPR, HIPAA)
7. Cost-effectiveness and ROI

Provide a comprehensive analysis that covers these points, offering constructive feedback 
and suggestions for improvement where applicable.

Cybersecurity Idea to Analyze: {idea}

Expert Analysis:
"""

# Function to generate response
def generate_response(idea):
    prompt = EXPERT_PROMPT.format(idea=idea)
    inputs = tokenizer.encode(prompt, return_tensors="pt", max_length=1024, truncation=True)
    outputs = model.generate(inputs, max_length=512, num_return_sequences=1, no_repeat_ngram_size=2, temperature=0.7)
    response = tokenizer.decode(outputs[0], skip_special_tokens=True)
    # Extract only the generated part, not the prompt
    return response.split("Expert Analysis:")[-1].strip()

# Streamlit App
st.title('Cybersecurity Expert Idea Analysis')

# Idea Submission Form
idea = st.text_area("Submit Your Cybersecurity Idea")
if st.button('Analyze'):
    if idea:
        # Generate response
        response = generate_response(idea)
        
        # Store in database
        c.execute("INSERT INTO ideas (idea, response) VALUES (?, ?)", (idea, response))
        conn.commit()
        
        st.success("Idea analyzed successfully!")
        st.write("Expert Analysis:")
        st.write(response)
    else:
        st.warning("Please enter an idea.")

# Display stored ideas
st.subheader("Previously Analyzed Ideas")
for row in c.execute("SELECT idea, response FROM ideas"):
    st.write(f"Idea: {row[0]}")
    st.write(f"Expert Analysis: {row[1]}")
    st.write("---")

# Close the database connection
conn.close()