#!/usr/bin/env python3
import re
import urllib.request
import ssl

# Disable SSL verification for simplicity
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

url = "https://2025.holidayhackchallenge.com/js/main/christmasmagic.js"
try:
    response = urllib.request.urlopen(url, context=ctx)
    content = response.read().decode('utf-8', errors='ignore')
    
    # Find API endpoints
    patterns = [
        r'/api/[^"\s\']+',
        r'/ws/[^"\s\']+',
        r'/challenge[^"\s\']*',
        r'https?://[^"\s\']+holidayhack[^"\s\']*',
        r'"GET [^"]+"',
        r'"POST [^"]+"',
    ]
    
    print("=== Potential API Endpoints ===")
    for pattern in patterns:
        matches = set(re.findall(pattern, content))
        if matches:
            print(f"\nPattern: {pattern}")
            for match in sorted(matches)[:20]:  # Limit output
                print(f"  {match}")
    
    # Look for challenge related strings
    print("\n=== Challenge References ===")
    challenge_patterns = [
        r'challengeurl',
        r'terminal[^"\s\']*',
        r'challenge[^"\s\']*',
    ]
    
    for pattern in challenge_patterns:
        matches = set(re.findall(pattern, content, re.IGNORECASE))
        if matches:
            print(f"\nPattern: {pattern}")
            for match in sorted(matches)[:20]:
                print(f"  {match}")
                
except Exception as e:
    print(f"Error: {e}")
