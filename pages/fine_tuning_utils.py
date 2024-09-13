# fine_tuning_utils.py

import pandas as pd
from transformers import AutoTokenizer, AutoModelForSequenceClassification, TrainingArguments, Trainer
from datasets import Dataset
import torch

def preprocess_data(data):
    # Convert pandas DataFrame to Hugging Face Dataset
    dataset = Dataset.from_pandas(data)
    
    # Tokenize the data
    tokenizer = AutoTokenizer.from_pretrained("distilbert-base-uncased")
    
    def tokenize_function(examples):
        return tokenizer(examples["text"], padding="max_length", truncation=True)
    
    tokenized_dataset = dataset.map(tokenize_function, batched=True)
    return tokenized_dataset

def fine_tune_model(data, learning_rate, num_epochs, progress_callback=None, status_callback=None):
    model = AutoModelForSequenceClassification.from_pretrained("distilbert-base-uncased")
    
    training_args = TrainingArguments(
        output_dir="./results",
        num_train_epochs=num_epochs,
        per_device_train_batch_size=8,
        learning_rate=learning_rate,
        weight_decay=0.01,
    )
    
    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=data,
    )
    
    trainer.train()
    
    return model

def evaluate_model(model, data):
    # Simple accuracy calculation
    model.eval()
    correct = 0
    total = 0
    
    with torch.no_grad():
        for item in data:
            outputs = model(**item)
            _, predicted = torch.max(outputs.logits, 1)
            total += 1
            correct += (predicted == item['labels']).sum().item()
    
    accuracy = correct / total
    return {"accuracy": accuracy}