#!/usr/bin/env python3
"""
SANS HHC 2025 - Proper Terminal Launch
Click the "Open Terminal: First Terminal" button correctly
"""

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time
import os

EMAIL = "danoclawnor@gmail.com"
PASSWORD = "hWu}2!dY?~JY8rc"

def solve():
    print("="*60)
    print("SANS HHC 2025 - Proper Terminal Launch")
    print("="*60 + "\n")
    
    options = Options()
    options.add_argument("--width=1400")
    options.add_argument("--height=900")
    os.environ['DISPLAY'] = ':0'
    
    driver = webdriver.Firefox(options=options)
    wait = WebDriverWait(driver, 15)
    
    try:
        # Login
        print("[*] Logging in...")
        driver.get("https://account.counterhack.com?ref=hhc25")
        time.sleep(2)
        driver.find_element(By.CSS_SELECTOR, "input[type='email']").send_keys(EMAIL)
        driver.find_element(By.CSS_SELECTOR, "input[type='password']").send_keys(PASSWORD + Keys.RETURN)
        time.sleep(5)
        print("[+] Logged in")
        
        # Enter game
        print("\n[*] Entering game...")
        driver.find_element(By.XPATH, "//button[contains(text(), 'Play Now')]").click()
        time.sleep(15)
        print("[+] In game")
        
        # Settings
        print("\n[*] Opening Settings...")
        driver.get("https://2025.holidayhackchallenge.com/badge?section=setting")
        time.sleep(5)
        
        # Enable CTF
        print("[*] Enabling CTF...")
        try:
            ctf = wait.until(EC.element_to_be_clickable((By.XPATH, "//*[contains(text(), 'CTF Style')]")))
            ctf.click()
            print("[+] CTF enabled")
            time.sleep(3)
        except:
            print("[!] CTF button issue")
        
        # Objectives
        print("\n[*] Opening Objectives...")
        driver.get("https://2025.holidayhackchallenge.com/badge?section=objective")
        time.sleep(10)
        print("[+] Objectives loaded")
        
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/before_terminal_click.png")
        
        # Find and click terminal button
        print("\n[*] Finding terminal button...")
        
        # Look for the "Open Terminal" button
        try:
            # Method 1: By button text
            term_btn = wait.until(EC.element_to_be_clickable((By.XPATH, "//button[contains(text(), 'Open Terminal')]")))
            print("[+] Found 'Open Terminal' button by text")
        except:
            try:
                # Method 2: By class
                term_btn = wait.until(EC.element_to_be_clickable((By.CSS_SELECTOR, "button.terminal-btn")))
                print("[+] Found terminal button by class")
            except:
                try:
                    # Method 3: Any button in terminal section
                    term_btn = driver.find_element(By.CSS_SELECTOR, "[class*='terminal'] button")
                    print("[+] Found button in terminal section")
                except:
                    print("[!] Could not find terminal button")
                    term_btn = None
        
        if term_btn:
            print("[*] Clicking terminal button...")
            
            # Scroll into view
            driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", term_btn)
            time.sleep(2)
            
            # Click
            term_btn.click()
            print("[+] Clicked terminal button")
            
            # Wait for new window/tab
            time.sleep(10)
            
            # Check if new window opened
            print(f"[*] Window handles: {len(driver.window_handles)}")
            
            if len(driver.window_handles) > 1:
                # Switch to new window
                driver.switch_to.window(driver.window_handles[-1])
                print("[+] Switched to terminal window")
            
            print(f"[*] Current URL: {driver.current_url}")
            time.sleep(10)  # Wait for terminal to fully load
        
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/terminal_after_proper_click.png")
        
        # Solve
        if "wetty" in driver.current_url:
            print("\n[*] Solving challenge...")
            time.sleep(10)
            
            try:
                textarea = driver.find_element(By.CSS_SELECTOR, "textarea.xterm-helper-textarea")
                textarea.click()
                time.sleep(2)
                textarea.send_keys("answer")
                time.sleep(2)
                textarea.send_keys(Keys.RETURN)
                time.sleep(10)
                print("[+] Submitted")
                
                # Check success
                text = driver.find_element(By.TAG_NAME, "body").text
                if any(word in text.lower() for word in ['congratulations', 'correct', 'completed', 'success']):
                    print("\n[✓] CHALLENGE SOLVED!")
                else:
                    print("\n[!] Check screenshot")
                    
            except Exception as e:
                print(f"[!] Error: {e}")
        else:
            print(f"[!] Terminal not opened: {driver.current_url}")
        
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/final_terminal.png")
        print("\n[+] Done")
        
    except Exception as e:
        print(f"[!] Error: {e}")
    
    finally:
        input("\nPress Enter to close...")
        driver.quit()

if __name__ == "__main__":
    solve()
