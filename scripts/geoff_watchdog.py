#!/usr/bin/env python3
"""
G.E.O.F.F. Watchdog
Monitors Geoff service and restarts if 8080 is down
"""

import subprocess
import time
import sys
from datetime import datetime
import requests

def check_geoff():
    """Check if Geoff is responding on port 8080"""
    try:
        response = requests.get('http://localhost:8080/cases', timeout=10)
        return response.status_code == 200
    except:
        return False

def restart_geoff():
    """Restart Geoff service"""
    print(f"[{datetime.now()}] Restarting Geoff...")
    
    # Kill any existing Geoff processes
    subprocess.run(['pkill', '-9', '-f', 'geoff_web.py'], capture_output=True)
    time.sleep(2)
    
    # Start Geoff with environment
    env = {
        'GEOFF_LOGS_DIR': '/home/sansforensics/geoff-logs',
        'GEOFF_GIT_DIR': '/home/sansforensics/geoff-git',
        'GEOFF_EVIDENCE_PATH': '/home/sansforensics/evidence-storage/cases',
        'GEOFF_PORT': '8080',
        'OLLAMA_URL': 'http://192.168.1.31:11434',
        'GEOFF_MODEL': 'qwen3-coder-next:cloud'
    }
    
    subprocess.Popen(
        ['python3', '/home/sansforensics/geoff_web.py'],
        env=env,
        stdout=open('/home/sansforensics/geoff.log', 'a'),
        stderr=subprocess.STDOUT
    )
    
    time.sleep(3)
    
    if check_geoff():
        print(f"[{datetime.now()}] Geoff restarted successfully")
        return True
    else:
        print(f"[{datetime.now()}] Failed to restart Geoff")
        return False

def main():
    """Main watchdog loop"""
    print(f"[{datetime.now()}] G.E.O.F.F. Watchdog started")
    print(f"[{datetime.now()}] Monitoring port 8080...")
    
    fail_count = 0
    max_fails = 3
    
    while True:
        if not check_geoff():
            fail_count += 1
            print(f"[{datetime.now()}] Geoff not responding (fail {fail_count}/{max_fails})")
            
            if fail_count >= max_fails:
                restart_geoff()
                fail_count = 0
        else:
            fail_count = 0
        
        time.sleep(30)  # Check every 30 seconds

if __name__ == '__main__':
    main()
