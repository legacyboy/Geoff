#!/usr/bin/env python3
"""
SANS Holiday Hack Challenge 2025 - Visual Networking Thinger Solver
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
            
            print(f"[*] Connecting to challenge '{self.challenge_id}'...")
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
        
    def solve_visual_networking(self):
        """Solve the Visual Networking Thinger challenge"""
        print("\n" + "="*60)
        print("Solving Challenge: Visual Networking Thinger")
        print("="*60 + "\n")

        # Wait for terminal to fully load
        time.sleep(3)

        # Get initial output
        full_output = self.get_clean_output()
        print(f"[*] Initial terminal output:\n{full_output}\n")

        # Read challenge instructions
        print("[Step 1] Reading challenge instructions...")
        motd = self.run_command('cat /etc/motd 2>/dev/null || cat README* 2>/dev/null || ls', wait=2)
        print(f"Challenge Info:\n{motd}\n")

        # List files
        print("[Step 2] Exploring filesystem...")
        files = self.run_command('ls -la', wait=2)
        print(f"Files:\n{files}\n")

        # Check home
        print("[Step 3] Checking home directory...")
        home = self.run_command('ls -la ~/', wait=2)
        print(f"Home:\n{home}\n")

        # Look for network-related files or tools
        print("[Step 4] Looking for network tools and files...")
        
        # Check for common network challenge files
        net_files = self.run_command('find /home /opt /root -type f 2>/dev/null | grep -E "(net|ip|route|ping|nmap)" | head -20', wait=3)
        print(f"Network files:\n{net_files}\n")
        
        # Check what tools are available
        print("[Step 5] Checking available network tools...")
        tools = self.run_command('which ip netstat route ping nmap nc telnet 2>/dev/null', wait=2)
        print(f"Available tools:\n{tools}\n")
        
        # Check network interfaces
        print("[Step 6] Checking network configuration...")
        netconfig = self.run_command('ip addr 2>/dev/null || ifconfig 2>/dev/null', wait=2)
        print(f"Network config:\n{netconfig}\n")
        
        # Check routing table
        print("[Step 7] Checking routing table...")
        routes = self.run_command('ip route 2>/dev/null || route 2>/dev/null', wait=2)
        print(f"Routes:\n{routes}\n")

        print("[!] Exploration complete - analysis needed")
        return False
            
    def disconnect(self):
        if self.connected:
            self.sio.disconnect()
            print("[+] Disconnected")

def main():
    # Session configuration
    session_token = "Y2JhZWY0NGYtYTcyMy00YTExLTljYWUtMjM1NTE5YmVmNzM0"
    challenge_id = "visualnetwork"  # Guessed ID for "Visual Networking Thinger"
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
            terminal.solve_visual_networking()
            time.sleep(2)
        except KeyboardInterrupt:
            print("\n[!] Interrupted by user")
        finally:
            terminal.disconnect()
    else:
        print("[!] Failed to connect - challenge ID may be different")
        print("[*] Please provide the exact terminal URL")
        sys.exit(1)

if __name__ == "__main__":
    main()
