#!/usr/bin/env python3
"""
SANS Holiday Hack Challenge 2025 - Visual Networking Thinger Auto-Solver
Web-based challenge automation via HTTP API calls
"""

import requests
import json
import sys

# Session configuration
BASE_URL = "https://visual-networking.holidayhackchallenge.com"
SESSION_TOKEN = "Y2JhZWY0NGYtYTcyMy00YTExLTljYWUtMjM1NTE5YmVmNzM0"

# Headers
headers = {
    'Authorization': f'Bearer {SESSION_TOKEN}',
    'Origin': 'https://2025.holidayhackchallenge.com',
    'Referer': 'https://2025.holidayhackchallenge.com/',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Accept': 'application/json, text/plain, */*',
    'Content-Type': 'application/json'
}

class VisualNetworkingSolver:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update(headers)
        self.cookie = None
        
    def init_session(self):
        """Initialize session and get cookie"""
        print("[*] Initializing session...")
        resp = self.session.get(BASE_URL)
        if 'CreativeCookieName' in resp.cookies:
            self.cookie = resp.cookies['CreativeCookieName']
            print(f"[+] Got session cookie")
        return resp.status_code == 200
        
    def solve_dns_challenge(self):
        """Solve Challenge 1: DNS Lookup"""
        print("\n" + "="*60)
        print("Challenge 1: DNS Lookup")
        print("="*60)
        
        # DNS Challenge Data
        dns_data = {
            "port": "53",
            "domain": "visual-networking.holidayhackchallenge.com",
            "request_type": "A",
            "response_value": "34.160.145.134",
            "response_type": "A"
        }
        
        print(f"[*] Submitting DNS resolution:")
        print(f"    Port: {dns_data['port']}")
        print(f"    Domain: {dns_data['domain']}")
        print(f"    Request Type: {dns_data['request_type']}")
        print(f"    Response: {dns_data['response_value']}")
        
        # Try different API endpoints
        endpoints = [
            "/api/dns",
            "/api/challenge/dns",
            "/challenge/dns",
            "/api/validate/dns"
        ]
        
        for endpoint in endpoints:
            try:
                url = f"{BASE_URL}{endpoint}"
                print(f"[*] Trying {url}...")
                resp = self.session.post(url, json=dns_data, timeout=5)
                print(f"    Status: {resp.status_code}")
                if resp.status_code in [200, 201]:
                    print(f"[+] DNS Challenge response: {resp.text}")
                    return True
            except Exception as e:
                print(f"    Error: {e}")
                continue
                
        print("[!] DNS Challenge auto-submit failed - may require browser interaction")
        return False
        
    def solve_tcp_challenge(self):
        """Solve Challenge 2: TCP 3-Way Handshake"""
        print("\n" + "="*60)
        print("Challenge 2: TCP 3-Way Handshake")
        print("="*60)
        
        # TCP Handshake sequence
        tcp_data = {
            "step1": "SYN",      # Client → Server
            "step2": "SYN-ACK",  # Server → Client  
            "step3": "ACK"       # Client → Server
        }
        
        print(f"[*] TCP Handshake sequence:")
        print(f"    Step 1 (Client → Server): {tcp_data['step1']}")
        print(f"    Step 2 (Server → Client): {tcp_data['step2']}")
        print(f"    Step 3 (Client → Server): {tcp_data['step3']}")
        
        # Try API endpoints
        endpoints = [
            "/api/tcp",
            "/api/challenge/tcp",
            "/challenge/tcp",
            "/api/validate/tcp"
        ]
        
        for endpoint in endpoints:
            try:
                url = f"{BASE_URL}{endpoint}"
                print(f"[*] Trying {url}...")
                resp = self.session.post(url, json=tcp_data, timeout=5)
                print(f"    Status: {resp.status_code}")
                if resp.status_code in [200, 201]:
                    print(f"[+] TCP Challenge response: {resp.text}")
                    return True
            except Exception as e:
                print(f"    Error: {e}")
                continue
                
        print("[!] TCP Challenge auto-submit failed")
        return False
        
    def solve_http_challenge(self):
        """Solve Challenge 3: HTTP GET Request"""
        print("\n" + "="*60)
        print("Challenge 3: HTTP GET Request")
        print("="*60)
        
        http_data = {
            "verb": "GET",
            "version": "HTTP/1.1",
            "host": "visual-networking.holidayhackchallenge.com",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
        
        print(f"[*] HTTP Request:")
        print(f"    {http_data['verb']} / {http_data['version']}")
        print(f"    Host: {http_data['host']}")
        
        endpoints = [
            "/api/http",
            "/api/challenge/http",
            "/challenge/http",
            "/api/validate/http"
        ]
        
        for endpoint in endpoints:
            try:
                url = f"{BASE_URL}{endpoint}"
                print(f"[*] Trying {url}...")
                resp = self.session.post(url, json=http_data, timeout=5)
                print(f"    Status: {resp.status_code}")
                if resp.status_code in [200, 201]:
                    print(f"[+] HTTP Challenge response: {resp.text}")
                    return True
            except Exception as e:
                print(f"    Error: {e}")
                continue
                
        print("[!] HTTP Challenge auto-submit failed")
        return False

def main():
    print("="*60)
    print("SANS Holiday Hack Challenge 2025")
    print("Visual Networking Thinger - Auto Solver")
    print("="*60 + "\n")
    
    solver = VisualNetworkingSolver()
    
    # Initialize session
    if not solver.init_session():
        print("[!] Failed to initialize session")
        sys.exit(1)
    
    # Solve challenges
    results = {
        "dns": solver.solve_dns_challenge(),
        "tcp": solver.solve_tcp_challenge(),
        "http": solver.solve_http_challenge()
    }
    
    # Summary
    print("\n" + "="*60)
    print("Challenge Results Summary")
    print("="*60)
    
    for challenge, success in results.items():
        status = "✓ SOLVED" if success else "✗ FAILED"
        print(f"  {challenge.upper()}: {status}")
    
    if all(results.values()):
        print("\n[✓] All challenges completed!")
    else:
        print("\n[!] Some challenges require manual browser interaction")
        print("[*] The answers are:")
        print("    DNS: Port 53, Domain visual-networking.holidayhackchallenge.com, Type A, Response 34.160.145.134")
        print("    TCP: SYN → SYN-ACK → ACK")
        print("    HTTP: GET / HTTP/1.1")

if __name__ == "__main__":
    main()
