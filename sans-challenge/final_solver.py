#!/usr/bin/env python3
"""
SANS HHC 2025 - Complete Working Solver
"""

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.firefox.options import Options
import time
import os

EMAIL = "danoclawnor@gmail.com"
PASSWORD = "hWu}2!dY?~JY8rc"

def solve():
    print("="*60)
    print("SANS HHC 2025 - Complete Solver")
    print("="*60 + "\n")
    
    options = Options()
    options.add_argument("--width=1400")
    options.add_argument("--height=900")
    os.environ['DISPLAY'] = ':0'
    
    driver = webdriver.Firefox(options=options)
    
    try:
        # Step 1: Login
        print("[*] Step 1: Logging in...")
        driver.get("https://account.counterhack.com?ref=hhc25")
        time.sleep(2)
        driver.find_element(By.CSS_SELECTOR, "input[type='email']").send_keys(EMAIL)
        driver.find_element(By.CSS_SELECTOR, "input[type='password']").send_keys(PASSWORD + Keys.RETURN)
        time.sleep(5)
        print("[+] Logged in")
        
        # Step 2: Enter game
        print("\n[*] Step 2: Entering game...")
        driver.find_element(By.XPATH, "//button[contains(text(), 'Play Now')]").click()
        time.sleep(15)
        print("[+] Game loaded")
        
        # Step 3: Go to Settings
        print("\n[*] Step 3: Opening Settings...")
        driver.get("https://2025.holidayhackchallenge.com/badge?section=setting")
        time.sleep(5)
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/settings_loaded.png")
        print("[+] Settings page loaded")
        
        # Step 4: Click CTF Style (I can see it in the screenshot)
        print("\n[*] Step 4: Enabling CTF Style...")
        time.sleep(3)
        
        # Based on screenshot, CTF Style is on the right side
        # Try clicking on it
        try:
            # Look for the CTF Style text or toggle
            ctf = driver.find_element(By.XPATH, "//*[contains(text(), 'CTF Style')]")
            print("[+] Found CTF Style")
            driver.execute_script("arguments[0].click();", ctf)
            print("[+] Clicked CTF Style")
            time.sleep(3)
        except Exception as e:
            print(f"[!] CTF Style click error: {e}")
        
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/after_ctf.png")
        
        # Step 5: Go to Objectives
        print("\n[*] Step 5: Opening Objectives...")
        driver.get("https://2025.holidayhackchallenge.com/badge?section=objective")
        time.sleep(10)
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/objectives_loaded.png")
        print("[+] Objectives page loaded")
        
        # Step 6: Click the terminal icon on the right
        print("\n[*] Step 6: Clicking terminal icon...")
        time.sleep(3)
        
        # Terminal icon is on the right side (from screenshot)
        # Try different approaches
        try:
            # Method 1: Look for terminal icon by class
            terminals = driver.find_elements(By.CSS_SELECTOR, "[class*='terminal'], [class*='ent type-terminal']")
            print(f"[+] Found {len(terminals)} terminal elements")
            
            if terminals:
                # Click the first one
                driver.execute_script("arguments[0].click();", terminals[0])
                print("[+] Clicked terminal")
                time.sleep(15)
        except Exception as e:
            print(f"[!] Terminal click error: {e}")
        
        print(f"[*] After terminal click: {driver.current_url}")
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/after_terminal.png")
        
        # Step 7: Solve
        if "wetty" in driver.current_url:
            print("\n[*] Step 7: Solving challenge...")
            time.sleep(10)
            
            try:
                textarea = driver.find_element(By.CSS_SELECTOR, "textarea.xterm-helper-textarea")
                print("[+] Found terminal textarea")
                
                textarea.click()
                time.sleep(2)
                textarea.send_keys("answer")
                time.sleep(2)
                textarea.send_keys(Keys.RETURN)
                time.sleep(10)
                
                print("[+] Submitted answer")
                
                # Check success
                text = driver.find_element(By.TAG_NAME, "body").text
                if any(word in text.lower() for word in ['congratulations', 'correct', 'completed', 'success']):
                    print("\n[✓] CHALLENGE SOLVED!")
                else:
                    print("\n[?] Answer submitted, check screenshot")
                    
            except Exception as e:
                print(f"[!] Solve error: {e}")
        else:
            print(f"\n[!] Terminal not opened: {driver.current_url}")
        
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/challenge_complete.png")
        print("\n[+] Final screenshot saved")
        
    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        input("\nPress Enter to close browser...")
        driver.quit()
        print("[+] Done")

if __name__ == "__main__":
    solve()
