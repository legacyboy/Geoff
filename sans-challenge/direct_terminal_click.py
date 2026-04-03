#!/usr/bin/env python3
"""
SANS HHC 2025 - Direct Game Terminal Access
Clicks on the specific terminal element in the game world
"""

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.common.action_chains import ActionChains
import time
import os

EMAIL = "danoclawnor@gmail.com"
PASSWORD = "hWu}2!dY?~JY8rc"

def solve():
    print("="*60)
    print("SANS HHC 2025 - Direct Terminal Click")
    print("="*60 + "\n")
    
    options = Options()
    options.add_argument("--width=1400")
    options.add_argument("--height=900")
    os.environ['DISPLAY'] = ':0'
    
    driver = webdriver.Firefox(options=options)
    
    try:
        # Login
        print("[*] Logging in...")
        driver.get("https://account.counterhack.com?ref=hhc25")
        time.sleep(2)
        
        driver.find_element(By.CSS_SELECTOR, "input[type='email']").send_keys(EMAIL)
        driver.find_element(By.CSS_SELECTOR, "input[type='password']").send_keys(PASSWORD + Keys.RETURN)
        time.sleep(5)
        print(f"[+] Logged in: {driver.current_url}")
        
        # Go to game
        print("\n[*] Loading game world...")
        driver.get("https://2025.holidayhackchallenge.com/")
        time.sleep(20)  # Long wait for React to fully render
        
        print("[+] Game loaded")
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/game_ready.png")
        
        # From the screenshot, I can see a terminal icon
        # Let's try to find and click it by looking for terminal elements
        print("\n[*] Searching for terminal...")
        
        # Get all clickable elements
        clickable = driver.find_elements(By.CSS_SELECTOR, "[class*='terminal'], [class*='ent'], div[onclick], button, a")
        print(f"[+] Found {len(clickable)} clickable elements")
        
        # Try clicking on elements that might be terminals
        for i, elem in enumerate(clickable[:20]):
            try:
                class_name = elem.get_attribute('class') or ''
                if 'terminal' in class_name.lower() or 'termOrientation' in class_name.lower():
                    print(f"[*] Clicking element {i}: {class_name[:50]}")
                    
                    # Scroll into view
                    driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", elem)
                    time.sleep(1)
                    
                    # Click
                    try:
                        elem.click()
                    except:
                        driver.execute_script("arguments[0].click();", elem)
                    
                    time.sleep(10)  # Wait for terminal
                    
                    # Check if terminal opened
                    if "wetty" in driver.current_url:
                        print("[+] Terminal opened!")
                        break
                    else:
                        print(f"  URL after click: {driver.current_url}")
            except Exception as e:
                continue
        
        # If terminal opened, solve it
        if "wetty" in driver.current_url:
            print("\n[*] Solving challenge...")
            time.sleep(10)
            
            try:
                # Find and use textarea
                textarea = driver.find_element(By.CSS_SELECTOR, "textarea.xterm-helper-textarea")
                textarea.click()
                time.sleep(1)
                textarea.send_keys("answer")
                time.sleep(1)
                textarea.send_keys(Keys.RETURN)
                time.sleep(5)
                print("[+] Answer submitted")
            except Exception as e:
                print(f"[!] Error: {e}")
        
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/game_terminal_attempt.png")
        print("\n[+] Screenshot saved")
        
    except Exception as e:
        print(f"[!] Error: {e}")
    
    finally:
        input("\nPress Enter to close...")
        driver.quit()

if __name__ == "__main__":
    solve()
