import streamlit as st
import json
import torch
from transformers import AutoTokenizer, AutoModelForCausalLM

# Load model directly
@st.cache_resource
def load_model():
    tokenizer = AutoTokenizer.from_pretrained("meta-llama/Llama-2-7b-chat-hf")
    model = AutoModelForCausalLM.from_pretrained("meta-llama/Llama-2-7b-chat-hf", torch_dtype=torch.float16, device_map="auto")
    return tokenizer, model

tokenizer, model = load_model()

def analyze_security_groups(security_groups):
    prompt = """<s>[INST] Analyze the following AWS security group configurations for anomalies and potential risks. Identify unusual patterns or risky configurations across the groups:

    """
    
    for i, sg in enumerate(security_groups):
        prompt += f"Security Group {i+1}:\n"
        prompt += json.dumps(sg, indent=2) + "\n\n"
    
    prompt += """Provide a detailed analysis of anomalies and risks, focusing on:
    1. Unusual open ports or protocols
    2. Overly permissive rules (e.g., 0.0.0.0/0)
    3. Inconsistencies across security groups
    4. Potential misconfigurations
    5. Deviations from best practices

    [/INST]
    """

    inputs = tokenizer(prompt, return_tensors="pt").to(model.device)
    
    with torch.no_grad():
        outputs = model.generate(
            inputs.input_ids, 
            max_length=2000, 
            num_return_sequences=1, 
            temperature=0.7,
            do_sample=True
        )
    
    analysis = tokenizer.decode(outputs[0], skip_special_tokens=True)
    analysis = analysis.split("[/INST]")[-1].strip()

    return analysis

def main():
    st.set_page_config(page_title="Security Group Anomaly Detector", layout="wide")
    st.title("Security Group Anomaly Detector")

    st.write("Analyze multiple AWS security group configurations to detect anomalies and potential risks.")

    uploaded_file = st.file_uploader("Upload JSON file with Security Group Configurations", type=["json"])

    if uploaded_file is not None:
        try:
            security_groups = json.load(uploaded_file)
            st.subheader("Uploaded Security Group Configurations:")
            st.json(security_groups)

            if st.button("Analyze Security Groups"):
                with st.spinner("Analyzing security groups..."):
                    analysis = analyze_security_groups(security_groups)
                
                st.subheader("Anomaly Detection Analysis:")
                st.write(analysis)

        except json.JSONDecodeError:
            st.error("Error: Invalid JSON file. Please upload a valid JSON file.")
        except Exception as e:
            st.error(f"An error occurred: {str(e)}")

    # Example JSON input
    st.subheader("Example JSON Input:")
    example_json = '''
    [
      {
        "GroupName": "WebServerSG",
        "IpPermissions": [
          {
            "IpProtocol": "tcp",
            "FromPort": 80,
            "ToPort": 80,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
          },
          {
            "IpProtocol": "tcp",
            "FromPort": 22,
            "ToPort": 22,
            "IpRanges": [{"CidrIp": "10.0.0.0/8"}]
          }
        ]
      },
      {
        "GroupName": "DatabaseSG",
        "IpPermissions": [
          {
            "IpProtocol": "tcp",
            "FromPort": 3306,
            "ToPort": 3306,
            "IpRanges": [{"CidrIp": "10.0.0.0/16"}]
          }
        ]
      },
      {
        "GroupName": "UnusualSG",
        "IpPermissions": [
          {
            "IpProtocol": "-1",
            "FromPort": -1,
            "ToPort": -1,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
          }
        ]
      }
    ]
    '''
    st.code(example_json, language="json")

if __name__ == "__main__":
    main()