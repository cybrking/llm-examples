import streamlit as st
from PIL import Image
import requests
from transformers import AutoProcessor, AutoModel
import torch

@st.cache_resource
def load_model():
    processor = AutoProcessor.from_pretrained("microsoft/florence-2-large", trust_remote_code=True)
    model = AutoModel.from_pretrained("microsoft/florence-2-large", trust_remote_code=True)
    return processor, model

def process_image_and_text(image, text, processor, model):
    inputs = processor(images=image, text=text, return_tensors="pt")
    with torch.no_grad():
        outputs = model(**inputs)
    return outputs.text_embeds, outputs.image_embeds

st.title("Florence-2-large Image Q&A")
st.write("Upload an image and ask a question about it!")

processor, model = load_model()

uploaded_file = st.file_uploader("Choose an image...", type=["jpg", "jpeg", "png"])
question = st.text_input("Ask a question about the image:")

if uploaded_file is not None:
    image = Image.open(uploaded_file)
    st.image(image, caption='Uploaded Image.', use_column_width=True)

    if question and st.button("Get Answer"):
        text_embeds, image_embeds = process_image_and_text(image, question, processor, model)
        
        # Calculate similarity between text and image embeddings
        similarity = torch.nn.functional.cosine_similarity(text_embeds, image_embeds)
        
        st.write(f"Similarity score: {similarity.item():.4f}")
        st.write("Note: This score indicates how well the question relates to the image content. Higher scores suggest the question is more relevant to the image.")

st.write("Please note: This app doesn't generate textual answers. It calculates a similarity score between the question and the image content.")