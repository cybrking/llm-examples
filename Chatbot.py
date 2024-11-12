import streamlit as st
from langchain_community.vectorstores import FAISS
from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain_community.document_loaders import PyPDFLoader, TextLoader
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain.memory import ConversationBufferMemory
from langchain_core.prompts import PromptTemplate
from langchain_openai import ChatOpenAI
from langchain.chains import ConversationalRetrievalChain
import tempfile
import os

# Page configuration
st.set_page_config(page_title="Document Q&A", layout="wide")
st.title("📚 Document Q&A System")

# Initialize session state variables
if "conversation" not in st.session_state:
    st.session_state.conversation = None
if "chat_history" not in st.session_state:
    st.session_state.chat_history = []
if "vectorstore" not in st.session_state:
    st.session_state.vectorstore = None

# Initialize OpenAI API key input
openai_api_key = st.sidebar.text_input("OpenAI API Key", type="password")
if not openai_api_key:
    st.info("Please enter your OpenAI API key to continue.")
    st.stop()

# Document processing function
def process_documents(uploaded_files):
    # Initialize text splitter
    text_splitter = RecursiveCharacterTextSplitter(
        chunk_size=1000,
        chunk_overlap=200,
        length_function=len
    )
    
    documents = []
    
    for uploaded_file in uploaded_files:
        # Create a temporary file to store the uploaded content
        with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
            tmp_file.write(uploaded_file.getvalue())
            file_path = tmp_file.name
            
        # Process based on file type
        if uploaded_file.name.endswith('.pdf'):
            loader = PyPDFLoader(file_path)
        else:
            loader = TextLoader(file_path)
            
        documents.extend(loader.load())
        
        # Clean up temporary file
        os.unlink(file_path)
    
    # Split documents into chunks
    document_chunks = text_splitter.split_documents(documents)
    
    # Create embeddings and vectorstore
    embeddings = HuggingFaceEmbeddings(model_name="sentence-transformers/all-MiniLM-L6-v2")
    vectorstore = FAISS.from_documents(document_chunks, embeddings)
    
    return vectorstore

# Initialize conversation chain
def initialize_conversation_chain(vectorstore):
    # Create llm
    llm = ChatOpenAI(
        temperature=0.7,
        model_name='gpt-3.5-turbo',
        openai_api_key=openai_api_key
    )
    
    # Create memory
    memory = ConversationBufferMemory(
        memory_key='chat_history',
        return_messages=True
    )
    
    # Create prompt template
    prompt_template = """Using the following conversation and context, answer the user's question to the best of your ability. 
    If you're unsure of the answer, say so - don't try to make up an answer.

    Context: {context}
    
    Chat History: {chat_history}
    
    User Question: {question}
    
    Answer:"""
    
    PROMPT = PromptTemplate(
        input_variables=["context", "chat_history", "question"],
        template=prompt_template
    )
    
    # Create conversation chain
    conversation_chain = ConversationalRetrievalChain.from_llm(
        llm=llm,
        retriever=vectorstore.as_retriever(),
        memory=memory,
        combine_docs_chain_kwargs={"prompt": PROMPT}
    )
    
    return conversation_chain

# Sidebar file upload
uploaded_files = st.sidebar.file_uploader(
    "Upload your documents",
    type=["pdf", "txt"],
    accept_multiple_files=True
)

if uploaded_files:
    with st.spinner("Processing documents..."):
        st.session_state.vectorstore = process_documents(uploaded_files)
        st.session_state.conversation = initialize_conversation_chain(st.session_state.vectorstore)
    st.sidebar.success("Documents processed successfully!")

# Main chat interface
if st.session_state.conversation:
    user_question = st.text_input("Ask a question about your documents:")
    
    if user_question:
        with st.spinner("Thinking..."):
            response = st.session_state.conversation.invoke({"question": user_question})
            st.session_state.chat_history.append((user_question, response["answer"]))

    # Display chat history
    if st.session_state.chat_history:
        for i, (question, answer) in enumerate(st.session_state.chat_history):
            st.write(f"Question {i+1}: {question}")
            st.write(f"Answer {i+1}: {answer}")
            st.write("---")
else:
    st.info("Please upload documents to start asking questions.")

# Add reset button
if st.sidebar.button("Reset Conversation"):
    st.session_state.conversation = None
    st.session_state.chat_history = []
    st.session_state.vectorstore = None
    st.experimental_rerun()