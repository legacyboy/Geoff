#!/usr/bin/env python3
"""
Fetch the challenge page source to analyze the JavaScript
"""

import requests
import re

# The challenge URL
url = "https://its-all-about-defang.holidayhackchallenge.com/"

print("[*] Fetching challenge page source...\n")
resp = requests.get(url, timeout=30)

# Save the source
with open('/home/claw/.openclaw/workspace/sans-challenge/challenge_source.html', 'w') as f:
    f.write(resp.text)

print(f"[+] Fetched {len(resp.text)} bytes\n")

# Find script tags
scripts = re.findall(r'<script[^>]*>(.*?)</script>', resp.text, re.DOTALL)
print(f"[*] Found {len(scripts)} script blocks\n")

# Look for the submit/send handler
for i, script in enumerate(scripts):
    if 'send-iocs' in script or 'defangedIOCs' in script or 'submit' in script.lower():
        print(f"=" * 70)
        print(f"SCRIPT BLOCK {i} (relevant)")
        print("=" * 70)
        print(script[:3000])
        print("\n")
        
# Also look for inline event handlers
print("=" * 70)
print("LOOKING FOR SUBMIT HANDLER")
print("=" * 70 + "\n")

# Find onclick handlers
onclick_handlers = re.findall(r'onclick="([^"]*)"', resp.text)
for handler in onclick_handlers:
    if 'send' in handler.lower() or 'submit' in handler.lower():
        print(f"Found onclick handler: {handler[:500]}")
        print()

# Find the main app.js file
js_files = re.findall(r'src="([^"]*\.js)"', resp.text)
print("=" * 70)
print("JAVASCRIPT FILES")
print("=" * 70 + "\n")
for js_file in js_files:
    print(f"  - {js_file}")

print("\n[+] Saved full source to challenge_source.html")
