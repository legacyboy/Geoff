#!/usr/bin/env python3
"""Test Ollama API directly."""

import requests
import json

# Test Ollama API
response = requests.post(
    "http://127.0.0.1:11434/api/generate",
    json={
        "model": "qwen2.5-coder:14b",
        "prompt": "Write a hello world program in Python. Keep it simple.",
        "stream": False
    }
)

if response.status_code == 200:
    result = response.json()
    print("SUCCESS! Ollama API is working.")
    print("\nResponse:")
    print(result.get('response', 'No response'))
else:
    print(f"Failed: {response.status_code}")
    print(response.text)