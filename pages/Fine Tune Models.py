import streamlit as st
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score

def main():
    st.title("Fine-Tuning App")

    # Example: Load a dataset
    data = pd.read_csv('your_dataset.csv')
    X = data.drop('target', axis=1)
    y = data['target']

    # Split the data
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # Allow user to adjust parameters
    st.sidebar.header("Fine-Tuning Parameters")
    n_estimators = st.sidebar.slider("Number of Estimators", 10, 200, 100)
    max_depth = st.sidebar.slider("Max Depth", 1, 20, 10)

    # Train the model
    model = RandomForestClassifier(n_estimators=n_estimators, max_depth=max_depth)
    model.fit(X_train, y_train)

    # Evaluate the model
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)

    # Display results
    st.write(f"Accuracy: {accuracy:.2f}")

if __name__ == "__main__":
    main()