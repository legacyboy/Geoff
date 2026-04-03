#!/usr/bin/env python3
"""
SANS Holiday Hack Challenge 2025 - TermOrientation Challenge Solver
Attempt 2: Focused on submitting "answer" correctly
"""

import socketio
import time
import sys
import re

class TermOrientationSolver:
    def __init__(self, session_token, challenge_id, username, user_id, area, location, dna):
        self.session_token = session_token
        self.challenge_id = challenge_id
        self.username = username
        self.user_id = user_id
        self.area = area
        self.location = location
        self.dna = dna
        
        self.sio = socketio.Client()
        self.connected = False
        self.terminal_output = []
        self.challenge_completed = False
        
        self.sio.on('connect', self.on_connect)
        self.sio.on('disconnect', self.on_disconnect)
        self.sio.on('data', self.on_data)
        self.sio.on('login', self.on_login)
        self.sio.on('logout', self.on_logout)
        self.sio.on('error', self.on_error)
        
    def on_connect(self):
        print(f"[+] Connected to termOrientation terminal")
        self.connected = True
        
    def on_disconnect(self):
        print(f"[-] Disconnected")
        self.connected = False
        
    def on_data(self, data):
        if isinstance(data, str):
            self.terminal_output.append(data)
            # Look for success indicators
            success_words = ['congratulations', 'correct', 'success', 'completed', 'flag', 'badge', 'well done', 'solved', 'complete']
            if any(word in data.lower() for word in success_words):
                self.challenge_completed = True
                print(f"\n[✓] SUCCESS DETECTED: {data.strip()}")
                
    def on_login(self):
        print(f"[+] Terminal login successful")
        
    def on_logout(self):
        print(f"[-] Logged out")
        
    def on_error(self, error):
        print(f"[!] Error: {error}")
        
    def connect(self):
        try:
            ws_url = f"wss://hhc25-wetty-prod.holidayhackchallenge.com/?challenge={self.challenge_id}&username={self.username}&id={self.user_id}&area={self.area}&location={self.location}&tokens=&dna={self.dna}"
            
            headers = {
                'Authorization': f'Bearer {self.session_token}',
                'Origin': 'https://2025.holidayhackchallenge.com',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            print(f"[*] Connecting...")
            self.sio.connect(ws_url, headers=headers, transports=['websocket'])
            
            timeout = 10
            while not self.connected and timeout > 0:
                time.sleep(0.5)
                timeout -= 0.5
                
            return self.connected
                
        except Exception as e:
            print(f"[!] Connection error: {e}")
            return False
    
    def get_clean_output(self):
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        return ansi_escape.sub('', ''.join(self.terminal_output))
        
    def clear_output(self):
        self.terminal_output = []

    def submit_answer(self):
        """Submit the answer 'answer' to the challenge"""
        print("\n" + "="*60)
        print("Submitting Challenge Answer")
        print("="*60 + "\n")

        # Wait for terminal to fully load
        time.sleep(3)
        
        initial_output = self.get_clean_output()
        print(f"[*] Terminal loaded. Initial output captured.")
        
        # Check if we see the challenge prompt
        if "Type answer and press Enter" in initial_output or "Enter the answer here" in initial_output:
            print("[+] Challenge prompt detected!")
        else:
            print(f"[!] Challenge prompt not in expected format")
            print(f"[Debug] Output preview:\n{initial_output[-500:]}")

        # Try multiple approaches to submit the answer
        print("\n[*] Attempting to submit 'answer'...")
        
        # Approach 1: Send 'answer' followed by Enter (standard)
        print("[Attempt 1] Sending 'answer\\n'...")
        self.clear_output()
        self.sio.emit('input', 'answer\n')
        time.sleep(2)
        output1 = self.get_clean_output()
        print(f"Response: {output1[-200:]}")
        
        if self.challenge_completed:
            return True
            
        # Approach 2: Send just 'answer' then separate Enter
        print("\n[Attempt 2] Sending 'answer' then '\\n' separately...")
        self.clear_output()
        self.sio.emit('input', 'answer')
        time.sleep(0.5)
        self.sio.emit('input', '\n')
        time.sleep(2)
        output2 = self.get_clean_output()
        print(f"Response: {output2[-200:]}")
        
        if self.challenge_completed:
            return True
            
        # Approach 3: Try carriage return instead of newline
        print("\n[Attempt 3] Sending 'answer\\r\\n'...")
        self.clear_output()
        self.sio.emit('input', 'answer\r\n')
        time.sleep(2)
        output3 = self.get_clean_output()
        print(f"Response: {output3[-200:]}")
        
        if self.challenge_completed:
            return True
            
        # Approach 4: Try just carriage return
        print("\n[Attempt 4] Sending 'answer\\r'...")
        self.clear_output()
        self.sio.emit('input', 'answer\r')
        time.sleep(2)
        output4 = self.get_clean_output()
        print(f"Response: {output4[-200:]}")
        
        if self.challenge_completed:
            return True
        
        # Final check - look for success in all output
        print("\n[*] Checking all responses for success indicators...")
        all_output = output1 + output2 + output3 + output4
        
        if "correct" in all_output.lower() or "congratulations" in all_output.lower() or "complete" in all_output.lower():
            print("[✓] Success indicator found in output!")
            return True
        else:
            print("[!] No success indicator found")
            print(f"\n[Full output for debugging]:\n{all_output}")
            return False
            
    def disconnect(self):
        if self.connected:
            self.sio.disconnect()
            print("[+] Disconnected")

def main():
    # New session configuration
    session_token = "Y2JhZWY0NGYtYTcyMy00YTExLTljYWUtMjM1NTE5YmVmNzM0"
    challenge_id = "termOrientation"
    username = "clawdso"
    user_id = "64f0bad9-9940-40d4-aead-4065d3575189"  # Updated ID
    area = "train"
    location = "3,4"  # Updated location
    dna = "ATATATTAATATATATATATATGCATATATATTATAATATATATATATATATTAGCATATATATATATGCCGATATATATATATATATATATATTAATATATATATATGCCGATATGCTA"
    
    print("="*60)
    print("SANS Holiday Hack Challenge 2025")
    print("TermOrientation Challenge - Submission Attempt")
    print("="*60 + "\n")
    
    solver = TermOrientationSolver(
        session_token=session_token,
        challenge_id=challenge_id,
        username=username,
        user_id=user_id,
        area=area,
        location=location,
        dna=dna
    )
    
    if solver.connect():
        try:
            success = solver.submit_answer()
            
            if success:
                print("\n" + "="*60)
                print("[✓] CHALLENGE COMPLETED!")
                print("="*60)
            else:
                print("\n" + "="*60)
                print("[!] Challenge submission attempted but success not confirmed")
                print("="*60)
                
            # Keep connection alive to see any delayed responses
            print("[*] Waiting 5 seconds for any delayed responses...")
            time.sleep(5)
            
            final_output = solver.get_clean_output()
            if "congratulations" in final_output.lower() or "correct" in final_output.lower():
                print("[✓] Success found in delayed response!")
                
        except KeyboardInterrupt:
            print("\n[!] Interrupted")
        finally:
            solver.disconnect()
    else:
        print("[!] Failed to connect")
        sys.exit(1)

if __name__ == "__main__":
    main()
