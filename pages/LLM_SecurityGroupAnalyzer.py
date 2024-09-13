import streamlit as st
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import json

@st.cache_resource
def load_model():
    model_name = "distilbert-base-uncased-finetuned-sst-2-english"
    
    try:
        tokenizer = AutoTokenizer.from_pretrained(model_name)
        model = AutoModelForSequenceClassification.from_pretrained(model_name)
        return tokenizer, model
    except Exception as e:
        st.error(f"Error loading model: {str(e)}")
        return None, None

def analyze_security_group(config, tokenizer, model):
    # Convert config to a string representation
    config_str = json.dumps(config, indent=2)
    
    # Prepare prompts for different aspects of security analysis
    prompts = [
        f"The following security group configuration has overly permissive rules: {config_str}",
        f"The following security group configuration has unusual open ports: {config_str}",
        f"The following security group configuration has potential misconfigurations: {config_str}",
        f"The following security group configuration violates best practices: {config_str}"
    ]
    
    results = []
    for prompt in prompts:
        inputs = tokenizer(prompt, return_tensors="pt", truncation=True, max_length=512)
        with torch.no_grad():
            outputs = model(**inputs)
        
        # Get the predicted class (0: negative, 1: positive)
        predicted_class = outputs.logits.argmax().item()
        
        # Convert to a meaningful result
        result = "Yes" if predicted_class == 1 else "No"
        results.append(result)
    
    return results

def main():
    st.title("Security Group Analyzer")

    tokenizer, model = load_model()
    if not tokenizer or not model:
        st.stop()

    security_group_config = st.text_area("Enter your security group configuration (JSON format):")

    if st.button("Analyze"):
        if security_group_config:
            try:
                config = json.loads(security_group_config)
                with st.spinner("Analyzing..."):
                    results = analyze_security_group(config, tokenizer, model)
                
                st.subheader("Analysis Results:")
                st.write("Overly permissive rules detected:", results[0])
                st.write("Unusual open ports detected:", results[1])
                st.write("Potential misconfigurations detected:", results[2])
                st.write("Best practice violations detected:", results[3])
                
                st.write("\nNote: This analysis is based on a general sentiment model and should be used as a preliminary check only. Always verify results manually.")
            except json.JSONDecodeError:
                st.error("Invalid JSON format. Please check your input.")
        else:
            st.warning("Please enter a security group configuration.")

if __name__ == "__main__":
    main()