#!/usr/bin/env python3
"""
SANS Holiday Hack Challenge 2025 - WeTTy Terminal Automation
Socket.IO client for interacting with challenge terminals
"""

import socketio
import time
import sys
import json
import re
import os

class HolidayHackTerminal:
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
        
        # Set up event handlers
        self.sio.on('connect', self.on_connect)
        self.sio.on('disconnect', self.on_disconnect)
        self.sio.on('data', self.on_data)
        self.sio.on('login', self.on_login)
        self.sio.on('logout', self.on_logout)
        self.sio.on('error', self.on_error)
        
    def on_connect(self):
        print(f"[+] Connected to terminal")
        self.connected = True
        
    def on_disconnect(self):
        print(f"[-] Disconnected from terminal")
        self.connected = False
        
    def on_data(self, data):
        """Receive terminal output"""
        if isinstance(data, str):
            self.terminal_output.append(data)
            # Check for completion indicators
            indicators = ['congratulations', 'correct', 'success', 'completed', 'flag', 'badge', 'well done', 'solved']
            if any(ind in data.lower() for ind in indicators):
                self.challenge_completed = True
                
    def on_login(self):
        print(f"[+] Terminal login successful")
        
    def on_logout(self):
        print(f"[-] Terminal logged out")
        
    def on_error(self, error):
        print(f"[!] Error: {error}")
        
    def connect(self):
        """Connect to the WeTTy WebSocket"""
        try:
            ws_url = f"wss://hhc25-wetty-prod.holidayhackchallenge.com/?challenge={self.challenge_id}&username={self.username}&id={self.user_id}&area={self.area}&location={self.location}&tokens=&dna={self.dna}"
            
            headers = {
                'Authorization': f'Bearer {self.session_token}',
                'Origin': 'https://2025.holidayhackchallenge.com',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            print(f"[*] Connecting to terminal...")
            self.sio.connect(ws_url, headers=headers, transports=['websocket'])
            
            timeout = 10
            while not self.connected and timeout > 0:
                time.sleep(0.5)
                timeout -= 0.5
                
            if self.connected:
                print(f"[+] Connected successfully!")
                return True
            else:
                print(f"[!] Connection timeout")
                return False
                
        except Exception as e:
            print(f"[!] Connection error: {e}")
            return False
    
    def send_input(self, text, wait=2):
        """Send input to terminal"""
        self.sio.emit('input', text)
        time.sleep(wait)
        
    def get_output(self):
        """Get accumulated terminal output"""
        return ''.join(self.terminal_output)
        
    def get_clean_output(self):
        """Get output with ANSI escape codes stripped"""
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        return ansi_escape.sub('', self.get_output())
        
    def clear_output(self):
        """Clear output buffer"""
        self.terminal_output = []

    def run_command(self, cmd, wait=2):
        """Run a command and return clean output"""
        self.clear_output()
        self.send_input(cmd + '\n', wait)
        return self.get_clean_output()
        
    def solve_orientation_challenge(self):
        """Solve the termOrientation challenge"""
        print("\n" + "="*60)
        print("Solving termOrientation Challenge")
        print("="*60 + "\n")

        # Wait for terminal to fully load
        time.sleep(3)

        # Check what challenge we're dealing with
        full_output = self.get_clean_output()
        
        if "Type answer and press Enter" in full_output:
            print("[+] Challenge identified: Type 'answer' and press Enter")
            print("[*] Exploring challenge mechanism...\n")

            # Step 1: Look at filesystem
            print("[Step 1] Checking current directory...")
            output = self.run_command('ls -la', wait=2)
            print(f"Files found:\n{output}\n")

            # Step 2: Check for challenge-related files
            print("[Step 2] Searching for challenge scripts...")
            output = self.run_command('find /home -type f 2>/dev/null | head -20', wait=3)
            print(f"Home files:\n{output}\n")

            # Step 3: Check environment variables
            print("[Step 3] Checking environment...")
            output = self.run_command('env | grep -i challenge', wait=2)
            print(f"Challenge env vars:\n{output}\n")

            # Step 4: Try the answer
            print("[Step 4] Submitting answer...")
            self.clear_output()
            
            # Send 'answer' - try as if typing in upper pane
            self.send_input('answer\r', wait=1)
            self.send_input('\n', wait=2)
            
            response = self.get_clean_output()
            print(f"Response: {response}\n")

            # Check for success
            if self.challenge_completed:
                print("[✓] Challenge completed!")
                return True
            elif 'congratulations' in response.lower() or 'correct' in response.lower():
                print("[✓] Challenge completed!")
                return True
            else:
                print("[!] Standard approach didn't work")
                print("[*] Trying alternative methods...")
                
                # Try checking if there's a submission script
                output = self.run_command('which answer 2>/dev/null || echo "no answer command"', wait=1)
                print(f"Answer command check: {output}")
                
                # Look for submission mechanism
                output = self.run_command('cat /etc/motd 2>/dev/null || cat ~/.bashrc 2>/dev/null | head -20', wait=2)
                print(f"MOTD/Bashrc:\n{output}")
                
                print("\n[!] Challenge may require manual interaction")
                print("[*] The terminal is connected - you can now type 'answer' in the upper input pane")
                return False
        else:
            print("[!] Challenge instructions not recognized")
            print(f"[Debug] Clean output:\n{full_output[-500:]}")
            return False
            
    def disconnect(self):
        """Disconnect from terminal"""
        if self.connected:
            self.sio.disconnect()
            print("[+] Disconnected")

def main():
    # Session configuration
    session_token = "Y2JhZWY0NGYtYTcyMy00YTExLTljYWUtMjM1NTE5YmVmNzM0"
    challenge_id = "termOrientation"
    username = "clawdso"
    user_id = "68a46926-b91d-425b-a564-2849eb20d074"
    area = "train"
    location = "2,3"
    dna = "ATATATTAATATATATATATATGCATATATATTATAATATATATATATATATTAGCATATATATATATGCCGATATATATATATATATATATATTAATATATATATATGCCGATATGCTA"
    
    # Create terminal instance
    terminal = HolidayHackTerminal(
        session_token=session_token,
        challenge_id=challenge_id,
        username=username,
        user_id=user_id,
        area=area,
        location=location,
        dna=dna
    )
    
    # Connect to terminal
    if terminal.connect():
        try:
            # Solve the challenge
            success = terminal.solve_orientation_challenge()
            
            if success:
                print("\n[✓] Challenge 1 (termOrientation) SOLVED!")
                # Ensure loot directory exists
                os.makedirs('/home/claw/.openclaw/workspace/sans-challenge/loot', exist_ok=True)
                with open('/home/claw/.openclaw/workspace/sans-challenge/loot/termOrientation.flag', 'w') as f:
                    f.write('termOrientation: SOLVED\n')
            else:
                print("\n[!] Challenge requires manual verification")
                print("[*] Terminal is active - check the game window")
                
            # Keep connection alive briefly
            time.sleep(5)
                
        except KeyboardInterrupt:
            print("\n[!] Interrupted by user")
        finally:
            terminal.disconnect()
    else:
        print("[!] Failed to connect to terminal")
        sys.exit(1)

if __name__ == "__main__":
    main()
