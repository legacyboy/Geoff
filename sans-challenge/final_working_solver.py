#!/usr/bin/env python3
"""
SANS HHC 2025 - Final Working Solver
Properly clicks "Open Terminal" button from Objectives
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
    print("SANS HHC 2025 - Final Working Solver")
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
        
        # Step 3: Settings → CTF Mode
        print("\n[*] Step 3: Enabling CTF Mode...")
        driver.get("https://2025.holidayhackchallenge.com/badge?section=setting")
        time.sleep(5)
        
        try:
            ctf = driver.find_element(By.XPATH, "//*[contains(text(), 'CTF Style')]")
            driver.execute_script("arguments[0].click();", ctf)
            print("[+] CTF Mode enabled")
            time.sleep(3)
        except:
            print("[!] CTF button not found")
        
        # Step 4: Objectives
        print("\n[*] Step 4: Opening Objectives...")
        driver.get("https://2025.holidayhackchallenge.com/badge?section=objective")
        time.sleep(10)
        print("[+] Objectives loaded")
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/obj_before_terminal.png")
        
        # Step 5: Click "Open Terminal" button
        print("\n[*] Step 5: Clicking terminal button...")
        time.sleep(3)
        
        try:
            # Find the terminal button by class
            term_btn = driver.find_element(By.CSS_SELECTOR, "button.terminal-btn")
            print("[+] Found terminal button")
            driver.execute_script("arguments[0].click();", term_btn)
            print("[+] Clicked terminal button")
            time.sleep(15)  # Wait for terminal to fully load
        except Exception as e:
            print(f"[!] Terminal button error: {e}")
            # Fallback: direct URL
            print("[*] Falling back to direct URL...")
            driver.get("https://hhc25-wetty-prod.holidayhackchallenge.com/?challenge=termOrientation&username=clawdso&id=YTQyNmJiODUtYzY4MC00NTk5LWEyZjYtNTM4MjZmNzdhMDA0&area=train&location=3,4&tokens=&dna=ATATATTAATATATATATATATGCATATATATTATAATATATATATATATATTAGCATATATATATATGCCGATATATATATATATATATATATTAATATATATATATGCCGATATGCTA")
            time.sleep(15)
        
        print(f"[*] Current URL: {driver.current_url}")
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/terminal_opened.png")
        
        # Step 6: Solve
        if "wetty" in driver.current_url:
            print("\n[*] Step 6: Solving challenge...")
            time.sleep(10)
            
            try:
                textarea = driver.find_element(By.CSS_SELECTOR, "textarea.xterm-helper-textarea")
                print("[+] Found terminal textarea")
                
                # Clear any existing content first
                textarea.clear()
                time.sleep(1)
                
                # Type and submit
                print("[*] Typing 'answer'...")
                textarea.send_keys("answer")
                time.sleep(2)
                print("[*] Submitting...")
                textarea.send_keys(Keys.RETURN)
                time.sleep(10)
                
                print("[+] Answer submitted")
                
                # Check for success indicators
                text = driver.find_element(By.TAG_NAME, "body").text
                if any(word in text.lower() for word in ['congratulations', 'correct', 'completed', 'success', 'badge', 'award', 'finished']):
                    print("\n" + "="*60)
                    print("[✓] CHALLENGE SOLVED!")
                    print("="*60)
                else:
                    print("\n[!] Check screenshot for result")
                    
            except Exception as e:
                print(f"[!] Solve error: {e}")
        else:
            print(f"\n[!] Terminal not in URL: {driver.current_url}")
        
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/challenge_result.png")
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
