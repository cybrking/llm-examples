import os
import requests
from dotenv import load_dotenv

load_dotenv()

class SecurityGroupAnalyzer:
    def __init__(self):
        self.api_url = "https://api-inference.huggingface.co/models/t5-base"
        self.headers = {"Authorization": f"Bearer {os.getenv('HUGGINGFACE_API_TOKEN')}"}

    def analyze(self, config):
        input_text = f"analyze security group: {config}"
        response = requests.post(self.api_url, headers=self.headers, json={"inputs": input_text})
        
        if response.status_code != 200:
            return f"Error: {response.status_code}, {response.text}"

        return response.json()[0]['generated_text']

