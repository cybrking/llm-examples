import streamlit as st
from transformers import GPT2LMHeadModel, GPT2Tokenizer
import sqlite3
import time

# Load model and tokenizer
@st.cache_resource
def load_model():
    model = GPT2LMHeadModel.from_pretrained("gpt2-medium")
    tokenizer = GPT2Tokenizer.from_pretrained("gpt2-medium")
    tokenizer.pad_token = tokenizer.eos_token
    return model, tokenizer

model, tokenizer = load_model()

# Initialize SQLite database
def init_db():
    conn = sqlite3.connect('ideas.db')
    c = conn.cursor()
    c.execute('''DROP TABLE IF EXISTS ideas''')  # Drop the table if it exists
    c.execute('''CREATE TABLE ideas 
                 (id INTEGER PRIMARY KEY, idea TEXT, guidance TEXT)''')
    conn.commit()
    return conn, c

# Cybersecurity expert guidance prompt
EXPERT_PROMPT = """
As a cybersecurity expert, provide guidance on the following idea:

{idea}

Provide your guidance in the following format:
1. Initial assessment:
2. Potential benefits:
3. Potential risks:
4. Implementation considerations:
5. Recommendations:

Guidance:
"""

# Function to generate guidance
def generate_guidance(idea):
    prompt = EXPERT_PROMPT.format(idea=idea)
    inputs = tokenizer(prompt, return_tensors="pt", max_length=1024, truncation=True, padding=True)
    outputs = model.generate(
        inputs.input_ids, 
        max_length=1024, 
        num_return_sequences=1, 
        no_repeat_ngram_size=2, 
        temperature=0.7,
        pad_token_id=tokenizer.eos_token_id
    )
    guidance = tokenizer.decode(outputs[0], skip_special_tokens=True)
    # Extract only the generated part, not the prompt
    return guidance.split("Guidance:")[-1].strip()

# Streamlit App
st.title('Cybersecurity Expert Guidance')

# Idea Submission Form
idea = st.text_area("Submit Your Cybersecurity Idea or Question")
if st.button('Get Guidance'):
    if idea:
        with st.spinner("Generating guidance..."):
            try:
                guidance = generate_guidance(idea)
                conn, c = init_db()
                c.execute("INSERT INTO ideas (idea, guidance) VALUES (?, ?)", (idea, guidance))
                conn.commit()
                st.success("Guidance generated successfully!")
                st.write("Expert Guidance:")
                st.write(guidance)
            except Exception as e:
                st.error(f"An error occurred: {e}")
            finally:
                conn.close()
    else:
        st.warning("Please enter an idea or question.")

# Display stored ideas
st.subheader("Previously Submitted Ideas")
try:
    conn, c = init_db()
    for row in c.execute("SELECT idea, guidance FROM ideas"):
        st.write(f"Idea: {row[0]}")
        st.write(f"Expert Guidance: {row[1]}")
        st.write("---")
finally:
    conn.close()