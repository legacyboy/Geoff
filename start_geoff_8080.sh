#!/bin/bash
# Run this ON THE GEOFF VM (ssh sansforensics@localhost -p 2222)

cd ~

# Create Geoff service on port 8080
cat > geoff_8080.py << 'PYEOF'
#!/usr/bin/env python3
import json, requests
from flask import Flask, request, jsonify
app = Flask(__name__)

@app.route('/')
def index():
    return jsonify({"status": "Geoff Ready", "model": "gemma4:31b-cloud", "endpoints": ["/chat", "/status"]})

@app.route('/status')
def status():
    return jsonify({"status": "ready", "model": "gemma4:31b-cloud"})

@app.route('/chat', methods=['POST'])
def chat():
    data = request.json or {}
    msg = data.get('message', '')
    try:
        r = requests.post('http://localhost:11434/api/generate', json={
            'model': 'gemma4:31b-cloud',
            'system': 'You are Geoff, a digital forensics investigator. Be thorough and methodical.',
            'prompt': msg, 'stream': False
        }, timeout=120)
        return jsonify({'status': 'ok', 'response': r.json().get('response', 'No response')})
    except Exception as e:
        return jsonify({'status': 'error', 'error': str(e)}), 500

if __name__ == '__main__':
    print("Starting Geoff on port 8080...")
    app.run(host='0.0.0.0', port=8080)
PYEOF

# Kill old processes
pkill -f geoff_8080.py
pkill -f "python3.*app.py"
sleep 2

# Start Geoff on 8080
nohup python3 geoff_8080.py > geoff_8080.log 2>&1 &
sleep 3

# Test it
echo "Testing Geoff on port 8080..."
curl -s -X POST http://localhost:8080/chat \
  -H "Content-Type: application/json" \
  -d '{"message":"hi"}' | python3 -m json.tool

echo ""
echo "Geoff is now running on http://localhost:8080"
echo "Test with: curl -X POST http://localhost:8080/chat -H 'Content-Type: application/json' -d '{\"message\":\"hi\"}'"
