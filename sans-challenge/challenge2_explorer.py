#!/usr/bin/env python3
"""
SANS Holiday Hack Challenge 2025 - Challenge 2 Solver
"""

import socketio
import time
import sys
import re

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
        if isinstance(data, str):
            self.terminal_output.append(data)
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
        try:
            ws_url = f"wss://hhc25-wetty-prod.holidayhackchallenge.com/?challenge={self.challenge_id}&username={self.username}&id={self.user_id}&area={self.area}&location={self.location}&tokens=&dna={self.dna}"
            
            headers = {
                'Authorization': f'Bearer {self.session_token}',
                'Origin': 'https://2025.holidayhackchallenge.com',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            print(f"[*] Connecting to {self.challenge_id}...")
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
        self.sio.emit('input', text)
        time.sleep(wait)
        
    def get_output(self):
        return ''.join(self.terminal_output)
        
    def get_clean_output(self):
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        return ansi_escape.sub('', self.get_output())
        
    def clear_output(self):
        self.terminal_output = []

    def run_command(self, cmd, wait=2):
        self.clear_output()
        self.send_input(cmd + '\n', wait)
        return self.get_clean_output()
        
    def explore_and_solve(self):
        """Explore the challenge and attempt to solve it"""
        print("\n" + "="*60)
        print(f"Solving Challenge: {self.challenge_id}")
        print("="*60 + "\n")

        # Wait for terminal to fully load
        time.sleep(3)

        # Get initial output
        full_output = self.get_clean_output()
        print(f"[*] Initial terminal output:\n{full_output[:1000]}\n")

        # Check /etc/motd for challenge instructions
        print("[Step 1] Reading challenge instructions...")
        motd = self.run_command('cat /etc/motd', wait=2)
        print(f"Challenge Instructions:\n{motd}\n")

        # List files
        print("[Step 2] Exploring filesystem...")
        files = self.run_command('ls -la', wait=2)
        print(f"Files in current directory:\n{files}\n")

        # Check home directory
        print("[Step 3] Checking home directory...")
        home = self.run_command('ls -la ~/', wait=2)
        print(f"Home directory:\n{home}\n")

        # Look for challenge scripts or binaries
        print("[Step 4] Looking for challenge executables...")
        bins = self.run_command('find /home /opt /usr/local -type f -executable 2>/dev/null | head -20', wait=3)
        print(f"Executables found:\n{bins}\n")

        # Try to determine challenge type from environment
        print("[Step 5] Checking environment variables...")
        env = self.run_command('env', wait=1)
        print(f"Environment:\n{env}\n")

        print("[!] Challenge exploration complete - manual analysis needed")
        print("[*] Review the output above to understand the challenge")
        return False
            
    def disconnect(self):
        if self.connected:
            self.sio.disconnect()
            print("[+] Disconnected")

def main():
    # Session configuration - need to find challenge 2
    session_token = "Y2JhZWY0NGYtYTcyMy00YTExLTljYWUtMjM1NTE5YmVmNzM0"
    
    # Try to discover available challenges
    # Common challenge IDs in SANS HHC
    challenge_candidates = [
        "curling", "linux1", "linux2", "nmap", "sudo", "privesc",
        "web1", "web2", "sqlmap", "crypto1", "crypto2",
        "elf1", "elf2", "elf3"
    ]
    
    print("[*] Attempting to discover Challenge 2...")
    print("[*] Please provide the terminal URL for Challenge 2")
    print("[*] Or I can try common challenge IDs...")
    
    # For now, let's try a common next challenge
    challenge_id = "linux1"  # or user can specify
    
    # If user provided a different URL, parse it
    # For now using placeholder - user should provide actual Challenge 2 URL
    
    username = "clawdso"
    user_id = "68a46926-b91d-425b-a564-2849eb20d074"
    area = "train"
    location = "2,3"
    dna = "ATATATTAATATATATATATATGCATATATATTATAATATATATATATATATTAGCATATATATATATGCCGATATATATATATATATATATATTAATATATATATATGCCGATATGCTA"
    
    terminal = HolidayHackTerminal(
        session_token=session_token,
        challenge_id=challenge_id,
        username=username,
        user_id=user_id,
        area=area,
        location=location,
        dna=dna
    )
    
    if terminal.connect():
        try:
            terminal.explore_and_solve()
            time.sleep(2)
        except KeyboardInterrupt:
            print("\n[!] Interrupted by user")
        finally:
            terminal.disconnect()
    else:
        print("[!] Failed to connect to terminal")
        print("[*] Challenge ID may be different - please provide Challenge 2 URL")
        sys.exit(1)

if __name__ == "__main__":
    main()
